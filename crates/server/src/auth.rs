use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

/// Bearer credentials for /v1/* routes: a shared token (any host) plus
/// per-host tokens that pin the presenter to a host.
#[derive(Clone)]
pub struct Auth {
    pub shared: String,
    pub hosts: Arc<HashMap<String, String>>,
}

/// Resolve the presenter's host_id: shared token → None (payload decides);
/// a per-host token → Some(host_id).
pub fn resolve_host_id(auth: &Auth, bearer: &str) -> Option<String> {
    if token_eq(bearer, &auth.shared) {
        return None;
    }
    auth.hosts
        .iter()
        .find(|(_, t)| token_eq(bearer, t))
        .map(|(h, _)| h.clone())
}

/// Constant-time token comparison (a plain `==` short-circuits on the first
/// differing byte, leaking how much of a guess was right). An empty
/// configured token never matches.
fn token_eq(presented: &str, configured: &str) -> bool {
    !configured.is_empty() && crate::notify::constant_time_eq(presented, configured)
}

/// True only for the configured shared token or one of the configured
/// per-host tokens. `None` from `resolve_host_id` is ambiguous: it means
/// either the shared token or an unknown token, so callers must not use it
/// as an authentication decision by itself.
fn is_authorized(auth: &Auth, bearer: &str, resolved_host: &Option<String>) -> bool {
    token_eq(bearer, &auth.shared) || resolved_host.is_some()
}

/// Host identity resolved from the bearer token (None = shared token).
#[derive(Clone, Debug)]
pub struct ResolvedHost(pub Option<String>);

/// Bearer-token gate. Rejects missing, empty, or wrong credentials.
pub async fn require_token(
    State(auth): State<Auth>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let bearer = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match bearer {
        Some(tok) if !tok.is_empty() => {
            let host = resolve_host_id(&auth, tok);
            if !is_authorized(&auth, tok, &host) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            // attach the resolved host to the extensions for the handlers
            request.extensions_mut().insert(ResolvedHost(host));
            Ok(next.run(request).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth() -> Auth {
        let mut hosts = HashMap::new();
        hosts.insert("host-a".to_string(), "token-a".to_string());
        Auth {
            shared: "shared-token".into(),
            hosts: Arc::new(hosts),
        }
    }

    #[test]
    fn shared_token_is_anonymous() {
        assert_eq!(resolve_host_id(&auth(), "shared-token"), None);
    }

    #[test]
    fn per_host_token_resolves_host() {
        assert_eq!(
            resolve_host_id(&auth(), "token-a").as_deref(),
            Some("host-a")
        );
        assert_eq!(resolve_host_id(&auth(), "unknown"), None);
    }

    #[test]
    fn unknown_token_is_not_authorized() {
        let auth = auth();
        let host = resolve_host_id(&auth, "unknown");
        assert!(!is_authorized(&auth, "unknown", &host));
    }
}
