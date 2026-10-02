use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use wt_common::{AgentEvent, EventType, Severity};

use crate::api::TelemetryPayload;
#[cfg(test)]
use crate::app::build_app;
use crate::app::AppState;

/// Must fit the agent's maximum spool file (10 MB) plus envelope — a
/// smaller cap would make the drain POST 400 and the agent would drop
/// the whole file as "permanent".
pub(crate) const MAX_BODY_BYTES: usize = 12 * 1024 * 1024;

/// POST /v1/telemetry — idempotent per event id (INSERT OR IGNORE), so agent
/// retries and spool re-drains never double-count.
pub async fn ingest(State(state): State<AppState>, request: Request) -> Response {
    let host = request
        .extensions()
        .get::<crate::auth::ResolvedHost>()
        .and_then(|h| h.0.clone());
    let (_, body) = request.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, state.max_body_bytes).await else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "body too large" })),
        )
            .into_response();
    };
    let Ok(payload) = serde_json::from_slice::<TelemetryPayload>(&bytes) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid payload" })),
        )
            .into_response();
    };
    if payload.batch.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "empty batch" })),
        )
            .into_response();
    }
    let mut batch = payload.batch;
    if let Some(host) = host {
        for ev in &mut batch {
            ev.host_id = host.clone();
        }
    }
    match store_events(&state.pool, &batch).await {
        Ok((accepted, duplicates)) => {
            Json(json!({ "accepted": accepted, "duplicates": duplicates })).into_response()
        }
        Err(e) => {
            eprintln!("ingest failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "store failed" })),
            )
                .into_response()
        }
    }
}

pub async fn store_events(
    pool: &sqlx::AnyPool,
    batch: &[AgentEvent],
) -> Result<(u64, u64), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let mut accepted = 0u64;
    let pg = crate::db::is_postgres(pool);
    for ev in batch {
        if insert_event(&mut tx, pg, ev).await? {
            accepted += 1;
        }
    }
    tx.commit().await?;
    let total = batch.len() as u64;
    Ok((accepted, total.saturating_sub(accepted)))
}

/// Insert one event unless its id already exists (idempotent per id).
/// Returns true when a row was written. Shared by ingest and incident
/// linking so every event row carries the same columns.
pub(crate) async fn insert_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    postgres: bool,
    ev: &AgentEvent,
) -> Result<bool, sqlx::Error> {
    let sql = if postgres {
        "INSERT INTO events (id, ts, host_id, key, kind, severity, summary, evidence_json,
             source, environment, subject, attributes_json, measurements_json, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
         ON CONFLICT (id) DO NOTHING"
    } else {
        "INSERT OR IGNORE INTO events (id, ts, host_id, key, kind, severity, summary, evidence_json,
             source, environment, subject, attributes_json, measurements_json, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)"
    };
    let res = sqlx::query(sql)
        .bind(&ev.id)
        .bind(ev.ts)
        .bind(&ev.host_id)
        .bind(&ev.key)
        .bind(kind_wire(&ev.kind))
        .bind(severity_wire(ev.severity))
        .bind(&ev.summary)
        .bind(serde_json::to_string(&ev.evidence).unwrap_or_else(|_| "[]".into()))
        .bind(&ev.source)
        .bind(&ev.environment)
        .bind(&ev.subject)
        .bind(serde_json::to_string(&ev.attributes).unwrap_or_else(|_| "{}".into()))
        .bind(serde_json::to_string(&ev.measurements).unwrap_or_else(|_| "{}".into()))
        .bind(now_ms())
        .execute(&mut **tx)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Wire string of an event kind: PascalCase for built-ins (identical to the
/// serde JSON representation), the name itself for custom kinds.
pub(crate) fn kind_wire(kind: &EventType) -> String {
    kind.to_string()
}

pub(crate) fn severity_wire(sev: Severity) -> String {
    serde_json::to_string(&sev)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string()
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{call, post};
    use axum::http::StatusCode;

    fn batch_body(n: usize) -> String {
        let batch: Vec<serde_json::Value> = (0..n)
            .map(|i| {
                serde_json::json!({
                    "id": format!("e-{}", i),
                    "ts": 1000 + i,
                    "host_id": "h-1",
                    "key": format!("k-{}", i),
                    "kind": "ServiceFailed",
                    "severity": "Warning",
                    "summary": format!("event {}", i),
                    "evidence": []
                })
            })
            .collect();
        serde_json::json!({ "batch": batch }).to_string()
    }

    #[tokio::test]
    async fn ingest_stores_events_and_returns_counts() {
        let app = build_app(AppState::for_tests().await).await;
        let (status, json) = post(&app, "/v1/telemetry", &batch_body(2)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["accepted"], 2);
        assert_eq!(json["duplicates"], 0);
    }

    #[tokio::test]
    async fn ingest_deduplicates_by_event_id() {
        let app = build_app(AppState::for_tests().await).await;
        let (_, first) = post(&app, "/v1/telemetry", &batch_body(1)).await;
        assert_eq!(first["accepted"], 1);
        let (status, second) = post(&app, "/v1/telemetry", &batch_body(1)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second["accepted"], 0);
        assert_eq!(second["duplicates"], 1);
    }

    #[tokio::test]
    async fn per_host_token_forces_host_id() {
        let state = AppState::for_tests().await;
        let pool = state.pool.clone();
        let app = build_app(state).await;
        let (status, _) = call(
            &app,
            "POST",
            "/v1/telemetry",
            Some("host-a-token"),
            Some(&batch_body(1)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let row: (String,) = sqlx::query_as("SELECT host_id FROM events WHERE id = 'e-0'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row.0, "host-a");
    }

    #[tokio::test]
    async fn ingest_rejects_missing_or_unknown_token() {
        let app = build_app(AppState::for_tests().await).await;
        for token in [None, Some("wrong-token")] {
            let (status, _) =
                call(&app, "POST", "/v1/telemetry", token, Some(&batch_body(1))).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{token:?}");
        }
    }

    #[tokio::test]
    async fn ingest_rejects_empty_batch() {
        let app = build_app(AppState::for_tests().await).await;
        let (status, _) = post(&app, "/v1/telemetry", r#"{"batch":[]}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ingest_rejects_oversized_body() {
        let app = build_app(AppState::for_tests().await).await;
        let big = serde_json::json!({
            "batch": (0..200).map(|i| serde_json::json!({
                "id": format!("big-{}", i),
                "ts": 1000,
                "host_id": "h-1",
                "key": format!("k-{}", i),
                "kind": "ServiceFailed",
                "severity": "Warning",
                "summary": "x".repeat(100),
                "evidence": []
            })).collect::<Vec<_>>()
        })
        .to_string();
        assert!(big.len() > 4096, "test body must exceed the test cap");
        let (status, _) = post(&app, "/v1/telemetry", &big).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
