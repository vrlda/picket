use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Response;

/// Bearer credentials for /v1/* routes: a shared token (any host) plus
/// per-host tokens that pin the presenter to a host, per-source tokens for
/// applications posting events, and runner tokens for agent runners.
#[derive(Clone, Default)]
pub struct Auth {
    pub shared: String,
    pub hosts: Arc<HashMap<String, String>>,
    /// `[event_sources.<name>]` — token → pinned source/environment.
    pub sources: Arc<HashMap<String, crate::config::EventSourceConfig>>,
    /// `[runners.<id>]` — runner id → config (token, labels).
    pub runners: Arc<HashMap<String, crate::dispatch::RunnerConfig>>,
}

/// Source identity pinned by a per-source token: the payload's `source`
/// (and `environment`, when configured) is overridden — spoofing another
/// application requires its token.
#[derive(Clone, Debug)]
pub struct ResolvedSource {
    pub source: String,
    pub environment: String,
}

/// Runner identity (runner routes only).
#[derive(Clone, Debug)]
pub struct ResolvedRunner(pub String);

/// The source a per-source token pins, if `bearer` is one.
pub fn resolve_source(auth: &Auth, bearer: &str) -> Option<ResolvedSource> {
    auth.sources
        .iter()
        .find(|(_, s)| token_eq(bearer, &s.token))
        .map(|(name, s)| ResolvedSource {
            source: if s.source.is_empty() {
                name.clone()
            } else {
                s.source.clone()
            },
            environment: s.environment.clone(),
        })
}

/// Runner id for a runner token.
pub fn resolve_runner(auth: &Auth, bearer: &str) -> Option<String> {
    auth.runners
        .iter()
        .find(|(_, r)| token_eq(bearer, &r.token))
        .map(|(id, _)| id.clone())
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
pub(crate) fn token_eq(presented: &str, configured: &str) -> bool {
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

fn bearer(request: &Request) -> Option<&str> {
    request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| !t.is_empty())
}

/// Bearer-token gate for the main API. Rejects missing, empty, or wrong
/// credentials. Per-source tokens may only post events/errors (403
/// elsewhere); runner tokens are not valid here.
pub async fn require_token(
    State(auth): State<Auth>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let tok = bearer(&request)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();
    let host = resolve_host_id(&auth, &tok);
    if is_authorized(&auth, &tok, &host) {
        // attach the resolved host to the extensions for the handlers
        request.extensions_mut().insert(ResolvedHost(host));
        return Ok(next.run(request).await);
    }
    if let Some(source) = resolve_source(&auth, &tok) {
        let path = request.uri().path();
        let ingest = request.method() == axum::http::Method::POST
            && (path == "/v1/events" || path == "/v1/errors");
        if !ingest {
            return Err(StatusCode::FORBIDDEN);
        }
        request.extensions_mut().insert(ResolvedHost(None));
        request.extensions_mut().insert(source);
        return Ok(next.run(request).await);
    }
    Err(StatusCode::UNAUTHORIZED)
}

/// Bearer-token gate for runner routes: only `[runners.<id>]` tokens.
pub async fn require_runner(
    State(auth): State<Auth>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let tok = bearer(&request)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();
    let runner = resolve_runner(&auth, &tok).ok_or(StatusCode::UNAUTHORIZED)?;
    request.extensions_mut().insert(ResolvedRunner(runner));
    Ok(next.run(request).await)
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
            ..Default::default()
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
