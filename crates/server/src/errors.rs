//! In-app exception capture: wire format, fingerprinting, level mapping,
//! the POST /v1/errors handler.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use picket_common::{AgentEvent, EventKind, Evidence, Severity};

/// Max accepted error-payload size (1 MiB — exceptions carry stack traces,
/// not payloads).
const MAX_ERROR_BODY: usize = 1024 * 1024;

/// Per-process sequence for event ids. Two IDENTICAL exceptions in the same
/// millisecond would otherwise collide on `ex-{host}-{ts}-{short}` and the
/// INSERT OR IGNORE in store_events would silently drop the second — the
/// endpoint test relies on one row per POST.
static EVENT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// One stack frame from an SDK.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Frame {
    pub file: String,
    pub line: u32,
    #[serde(default)]
    pub function: String,
}

/// The exception payload from an SDK.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Exception {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub frames: Vec<Frame>,
}

/// The /v1/errors request body.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ErrorEvent {
    pub host_id: String,
    #[serde(default)]
    pub service: String,
    #[serde(default)]
    pub environment: String,
    pub exception: Exception,
}

/// FNV-1a 64-bit (no external hash dep). A collision merely merges two
/// incidents — acceptable at this scale.
fn fnv1a(input: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in input {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Grouping key: service + exception type + first 3 frames' file:line.
/// Deterministic across SDKs and restarts — the same bug always lands in
/// the same incident.
pub fn fingerprint(service: &str, exception_type: &str, frames: &[(String, u32)]) -> String {
    let mut input = String::new();
    input.push_str(service);
    input.push('\0');
    input.push_str(exception_type);
    input.push('\0');
    for (file, line) in frames.iter().take(3) {
        input.push_str(file);
        input.push(':');
        input.push_str(&line.to_string());
        input.push(';');
    }
    format!("{:016x}", fnv1a(input.as_bytes()))
}

/// Exception level → incident severity (fatal/error → Critical, warning →
/// Warning, info/debug → Info; unknown/empty levels are loud).
pub fn severity_for(level: &str) -> Severity {
    match level.to_lowercase().as_str() {
        "fatal" | "error" | "" => Severity::Critical,
        "warning" => Severity::Warning,
        "info" | "debug" => Severity::Info,
        _ => Severity::Critical,
    }
}

/// Handler for POST /v1/errors. Builds ONE AppException event, stores it;
/// the correlation scan groups by fingerprint. 400 malformed, 401 bad auth
/// (middleware), 413 oversized, 200 accept.
pub async fn handle_errors(
    State(state): State<crate::app::AppState>,
    request: Request,
) -> Result<Response, StatusCode> {
    let host_override = request
        .extensions()
        .get::<crate::auth::ResolvedHost>()
        .and_then(|h| h.0.clone());
    let Ok(body_bytes) = axum::body::to_bytes(request.into_body(), MAX_ERROR_BODY + 1).await else {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    };
    if body_bytes.len() > MAX_ERROR_BODY {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let payload: ErrorEvent =
        serde_json::from_slice(&body_bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut host_id = payload.host_id.clone();
    if let Some(host) = host_override {
        host_id = host;
    }
    let frame_pairs: Vec<(String, u32)> = payload
        .exception
        .frames
        .iter()
        .map(|f| (f.file.clone(), f.line))
        .collect();
    let key = format!(
        "ex:{}:{}",
        payload.service,
        fingerprint(&payload.service, &payload.exception.kind, &frame_pairs)
    );
    let fp = key.rsplit(':').next().unwrap_or("").to_string();
    let severity = severity_for(&payload.exception.level);
    let trace = payload
        .exception
        .frames
        .iter()
        .map(|f| {
            let loc = format!("{}:{}", f.file, f.line);
            if f.function.is_empty() {
                loc
            } else {
                format!("{} in {}", loc, f.function)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    let ts = crate::ingest::now_ms();
    let short = &key[key.len().saturating_sub(8)..];
    let ev = AgentEvent {
        id: format!(
            "ex-{}-{}-{}-{}",
            host_id,
            ts,
            short,
            EVENT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ),
        ts,
        host_id,
        key,
        kind: EventKind::AppException.into(),
        severity,
        summary: if payload.exception.message.is_empty() {
            payload.exception.kind.clone()
        } else {
            payload.exception.message.clone()
        },
        evidence: vec![
            Evidence {
                ts,
                source: "exception".into(),
                detail: trace,
            },
            Evidence {
                ts,
                source: "exception".into(),
                detail: format!(
                    "Type={} Service={} Env={} Level={}",
                    payload.exception.kind,
                    payload.service,
                    payload.environment,
                    payload.exception.level
                ),
            },
        ],
        // structured context, so rules can group/filter exceptions like
        // any custom event (group_by = ["service"], ...)
        source: payload.service.clone(),
        environment: payload.environment.clone(),
        attributes: {
            let mut a = serde_json::Map::new();
            a.insert(
                "exception_type".into(),
                payload.exception.kind.clone().into(),
            );
            a.insert("level".into(), payload.exception.level.clone().into());
            a.insert("fingerprint".into(), fp.into());
            a
        },
        ..Default::default()
    };
    crate::ingest::store_events(&state.pool, &[ev])
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_common::Severity;

    use crate::app::{build_app, AppState};

    #[test]
    fn fingerprint_is_deterministic_and_discriminating() {
        let f1 = fingerprint(
            "api",
            "ValueError",
            &[("app.py".into(), 42), ("app.py".into(), 10)],
        );
        let f2 = fingerprint(
            "api",
            "ValueError",
            &[("app.py".into(), 42), ("app.py".into(), 10)],
        );
        assert_eq!(f1, f2, "same exception → same fingerprint");
        let f3 = fingerprint(
            "api",
            "ValueError",
            &[("app.py".into(), 41), ("app.py".into(), 10)],
        );
        assert_ne!(f1, f3, "different line → different fingerprint");
        let f4 = fingerprint(
            "web",
            "ValueError",
            &[("app.py".into(), 42), ("app.py".into(), 10)],
        );
        assert_ne!(f1, f4, "different service → different fingerprint");
        let f5 = fingerprint(
            "api",
            "TypeError",
            &[("app.py".into(), 42), ("app.py".into(), 10)],
        );
        assert_ne!(f1, f5, "different type → different fingerprint");
        assert!(f1.len() >= 16, "readable hash");
    }

    #[test]
    fn fingerprint_uses_first_three_frames() {
        let a = fingerprint(
            "s",
            "T",
            &[("f1".into(), 1), ("f2".into(), 2), ("f3".into(), 3)],
        );
        let b = fingerprint(
            "s",
            "T",
            &[
                ("f1".into(), 1),
                ("f2".into(), 2),
                ("f3".into(), 3),
                ("f4".into(), 99),
            ],
        );
        assert_eq!(a, b, "frames beyond the first 3 don't matter");
    }

    #[test]
    fn level_maps_to_severity() {
        assert_eq!(severity_for("fatal"), Severity::Critical);
        assert_eq!(severity_for("error"), Severity::Critical);
        assert_eq!(severity_for("warning"), Severity::Warning);
        assert_eq!(severity_for("info"), Severity::Info);
        assert_eq!(severity_for("debug"), Severity::Info);
        assert_eq!(
            severity_for("unknown-level"),
            Severity::Critical,
            "unknown → loud"
        );
        assert_eq!(severity_for(""), Severity::Critical);
    }

    #[tokio::test]
    async fn errors_rejects_oversized_body() {
        let app = build_app(AppState::for_tests().await).await;
        let big = "x".repeat(2 * 1024 * 1024);
        assert!(big.len() > MAX_ERROR_BODY, "body must exceed the cap");
        let (status, _) = crate::test_util::post(&app, "/v1/errors", &big).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }
}
