//! POST /v1/events — generic application/business events.
//!
//! /v1/telemetry stays the host agent's batch endpoint and /v1/errors the
//! exception shortcut; this endpoint takes one structured event with an
//! open-ended custom kind ("payment.request_failed").

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use picket_common::{AgentEvent, EventType, Evidence, Severity};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::app::AppState;

/// Max request body (one event).
const MAX_EVENT_BODY: usize = 256 * 1024;
const MAX_SUMMARY: usize = 2000;
const MAX_FIELD: usize = 256;
const MAX_ATTRIBUTES: usize = 64;
const MAX_MEASUREMENTS: usize = 64;

/// Wire shape. Only `kind` and `summary` are required.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventIn {
    pub kind: String,
    pub summary: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub ts: Option<i64>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub environment: String,
    #[serde(default)]
    pub subject: String,
    /// Optional host the event concerns (defaults to `source`).
    #[serde(default)]
    pub host_id: String,
    /// Optional dedup key (defaults to `subject`, else the kind).
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub attributes: Map<String, Value>,
    #[serde(default)]
    pub measurements: Map<String, Value>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

fn parse_severity(s: &str) -> Result<Severity, String> {
    match s.to_ascii_lowercase().as_str() {
        "info" | "debug" => Ok(Severity::Info),
        "warning" | "warn" => Ok(Severity::Warning),
        "critical" | "error" | "fatal" => Ok(Severity::Critical),
        other => Err(format!("unknown severity {other:?}")),
    }
}

fn check_len(name: &str, v: &str, max: usize) -> Result<(), String> {
    if v.chars().count() > max {
        return Err(format!("{name} longer than {max} characters"));
    }
    Ok(())
}

/// Validate and normalize a posted event. `host_override` (per-host token)
/// and `source_override` (per-source token) win over the payload.
pub fn build_event(
    input: EventIn,
    host_override: Option<String>,
    source_override: Option<&crate::auth::ResolvedSource>,
    now: i64,
) -> Result<AgentEvent, String> {
    let kind = EventType::parse(&input.kind)?;
    if !kind.is_custom() {
        return Err(format!(
            "{:?} is a built-in Picket kind; custom events use a dotted name like \"payment.request_failed\"",
            input.kind
        ));
    }
    if input.summary.trim().is_empty() {
        return Err("summary is required".into());
    }
    check_len("summary", &input.summary, MAX_SUMMARY)?;
    for (name, v) in [
        ("source", &input.source),
        ("environment", &input.environment),
        ("subject", &input.subject),
        ("host_id", &input.host_id),
        ("key", &input.key),
    ] {
        check_len(name, v, MAX_FIELD)?;
    }
    if input.attributes.len() > MAX_ATTRIBUTES {
        return Err(format!("at most {MAX_ATTRIBUTES} attributes"));
    }
    if input.measurements.len() > MAX_MEASUREMENTS {
        return Err(format!("at most {MAX_MEASUREMENTS} measurements"));
    }
    let mut measurements = std::collections::BTreeMap::new();
    for (k, v) in &input.measurements {
        match v.as_f64() {
            Some(n) if n.is_finite() => {
                measurements.insert(k.clone(), n);
            }
            _ => return Err(format!("measurement {k:?} must be a finite number")),
        }
    }
    let severity = match &input.severity {
        Some(s) => parse_severity(s)?,
        None => Severity::Info,
    };
    let id = match input.id {
        Some(id) if !id.trim().is_empty() => {
            check_len("id", &id, MAX_FIELD)?;
            id
        }
        _ => format!("evt_{}", uuid::Uuid::new_v4().simple()),
    };
    let (source, environment) = match source_override {
        Some(s) => (
            s.source.clone(),
            if s.environment.is_empty() {
                input.environment
            } else {
                s.environment.clone()
            },
        ),
        None => (input.source, input.environment),
    };
    let host_id = host_override.unwrap_or_else(|| {
        if !input.host_id.is_empty() {
            input.host_id
        } else if !source.is_empty() {
            source.clone()
        } else {
            "app".into()
        }
    });
    let key = if !input.key.is_empty() {
        input.key
    } else if !input.subject.is_empty() {
        input.subject.clone()
    } else {
        input.kind.clone()
    };
    Ok(AgentEvent {
        id,
        ts: input.ts.unwrap_or(now),
        host_id,
        key,
        kind,
        severity,
        summary: input.summary,
        evidence: input.evidence,
        source,
        environment,
        subject: input.subject,
        attributes: input.attributes,
        measurements,
    })
}

/// Handler for POST /v1/events. 200 {"id", "accepted"} (accepted=false
/// for a duplicate id — idempotent), 400 invalid, 413 too large.
pub async fn ingest_event(State(state): State<AppState>, request: Request) -> Response {
    let host = request
        .extensions()
        .get::<crate::auth::ResolvedHost>()
        .and_then(|h| h.0.clone());
    let source = request
        .extensions()
        .get::<crate::auth::ResolvedSource>()
        .cloned();
    let Ok(bytes) = axum::body::to_bytes(request.into_body(), MAX_EVENT_BODY).await else {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({ "error": "body too large" })),
        )
            .into_response();
    };
    let input: EventIn = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("invalid event: {e}") })),
            )
                .into_response()
        }
    };
    let ev = match build_event(input, host, source.as_ref(), crate::ingest::now_ms()) {
        Ok(ev) => ev,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    };
    match crate::ingest::store_events(&state.pool, std::slice::from_ref(&ev)).await {
        Ok((accepted, _)) => {
            Json(json!({ "id": ev.id, "accepted": accepted == 1 })).into_response()
        }
        Err(e) => {
            eprintln!("event store failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "store failed" })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::build_app;

    async fn post(app: &axum::Router, token: &str, body: Value) -> (StatusCode, Value) {
        let body = body.to_string();
        crate::test_util::call(app, "POST", "/v1/events", Some(token), Some(&body)).await
    }

    use crate::test_util::get_ok as get;

    fn sample() -> Value {
        json!({
            "kind": "payment.request_failed",
            "source": "payment-api",
            "environment": "production",
            "subject": "merchant:mer_123",
            "summary": "Payment creation failed",
            "severity": "warning",
            "attributes": { "merchant_id": "mer_123", "endpoint": "/v1/payments", "status_code": 500 },
            "measurements": { "latency_ms": 812 }
        })
    }

    #[tokio::test]
    async fn custom_event_is_stored_and_queryable() {
        let app = build_app(AppState::for_tests().await).await;
        let (status, body) = post(&app, "test-token", sample()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["accepted"], true);
        let id = body["id"].as_str().unwrap().to_string();
        assert!(id.starts_with("evt_"));
        let list = get(
            &app,
            "/v1/events?kind=payment.request_failed&subject=merchant:mer_123",
        )
        .await;
        let ev = &list["events"][0];
        assert_eq!(ev["id"], id);
        assert_eq!(ev["source"], "payment-api");
        assert_eq!(ev["environment"], "production");
        assert_eq!(ev["severity"], "Warning");
        assert_eq!(ev["host_id"], "payment-api", "host defaults to the source");
        assert_eq!(ev["attributes"]["merchant_id"], "mer_123");
        assert_eq!(ev["measurements"]["latency_ms"], 812.0);
        // attribute filters (text match, numbers included)
        assert_eq!(
            get(&app, "/v1/events?attr.merchant_id=mer_123").await["events"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            get(&app, "/v1/events?attr.status_code=500").await["events"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(
            get(&app, "/v1/events?attr.merchant_id=mer_999").await["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(get(&app, "/v1/events?source=other").await["events"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn duplicate_id_is_idempotent() {
        let app = build_app(AppState::for_tests().await).await;
        let mut ev = sample();
        ev["id"] = json!("evt_fixed");
        assert_eq!(
            post(&app, "test-token", ev.clone()).await.1["accepted"],
            true
        );
        let (status, body) = post(&app, "test-token", ev).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["accepted"], false);
        assert_eq!(
            get(&app, "/v1/events?kind=payment.request_failed").await["events"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn malformed_events_are_rejected() {
        let app = build_app(AppState::for_tests().await).await;
        for (bad, why) in [
            (json!({ "summary": "x" }), "missing kind"),
            (json!({ "kind": "payment.failed" }), "missing summary"),
            (
                json!({ "kind": "payment.failed", "summary": " " }),
                "blank summary",
            ),
            (
                json!({ "kind": "ServiceFailed", "summary": "x" }),
                "built-in kind",
            ),
            (
                json!({ "kind": "Payment.Failed", "summary": "x" }),
                "uppercase",
            ),
            (json!({ "kind": "nodot", "summary": "x" }), "no namespace"),
            (
                json!({ "kind": "a.b", "summary": "x", "severity": "loud" }),
                "bad severity",
            ),
            (
                json!({ "kind": "a.b", "summary": "x", "measurements": { "m": "high" } }),
                "non-numeric measurement",
            ),
            (
                json!({ "kind": "a.b", "summary": "x", "surprise": 1 }),
                "unknown field",
            ),
            (
                json!({ "kind": "a".repeat(127) + ".b", "summary": "x" }),
                "kind too long",
            ),
        ] {
            let (status, body) = post(&app, "test-token", bad).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{why}: {body}");
        }
    }

    #[tokio::test]
    async fn source_token_pins_source_and_is_ingest_only() {
        let mut state = AppState::for_tests().await;
        state.cfg.event_sources.insert(
            "payment_api".into(),
            crate::config::EventSourceConfig {
                token: "src-token".into(),
                source: "payment-api".into(),
                environment: "production".into(),
            },
        );
        let app = build_app(state).await;
        let mut ev = sample();
        ev["source"] = json!("billing-api"); // impersonation attempt
        ev["environment"] = json!("staging");
        let (status, _) = post(&app, "src-token", ev).await;
        assert_eq!(status, StatusCode::OK);
        let list = get(&app, "/v1/events?kind=payment.request_failed").await;
        assert_eq!(list["events"][0]["source"], "payment-api");
        assert_eq!(list["events"][0]["environment"], "production");
        // a source token cannot read
        let (status, _) =
            crate::test_util::call(&app, "GET", "/v1/events", Some("src-token"), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn builtin_telemetry_unchanged() {
        // a host-agent payload round-trips with no context fields
        let ev: AgentEvent = serde_json::from_str(
            r#"{"id":"e","ts":1,"host_id":"h","key":"k","kind":"ServiceFailed","severity":"Critical","summary":"s","evidence":[]}"#,
        )
        .unwrap();
        assert_eq!(ev.kind, picket_common::EventKind::ServiceFailed);
        assert_eq!(
            serde_json::to_string(&ev).unwrap(),
            r#"{"id":"e","ts":1,"host_id":"h","key":"k","kind":"ServiceFailed","severity":"Critical","summary":"s","evidence":[]}"#
        );
    }
}
