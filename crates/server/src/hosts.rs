use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use picket_common::Heartbeat;
use serde::Deserialize;
use serde_json::json;

use crate::app::AppState;

/// POST /v1/heartbeat — upsert host, keep version, refresh last-seen. Seen-times
/// are server-side facts (liveness); the agent's clock is not trusted. The
/// watchdog (missing heartbeat → incident) is M4.
pub async fn heartbeat(
    State(state): State<AppState>,
    Extension(resolved_host): Extension<crate::auth::ResolvedHost>,
    Json(mut hb): Json<Heartbeat>,
) -> Response {
    if let Some(host_id) = resolved_host.0 {
        hb.host_id = host_id;
    }
    match upsert_host(&state.pool, &hb).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => {
            eprintln!("heartbeat store failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "store failed" })),
            )
                .into_response()
        }
    }
}

pub async fn upsert_host(pool: &sqlx::AnyPool, hb: &Heartbeat) -> Result<(), sqlx::Error> {
    // seen-times are server-side facts (liveness); the agent's clock is not
    // trusted for these — a skewed host would break the M4 watchdog.
    let seen = crate::ingest::now_ms();
    sqlx::query(
        "INSERT INTO hosts (host_id, first_seen, last_seen, version, queue_len)
         VALUES ($1, $2, $2, $3, $4)
         ON CONFLICT(host_id) DO UPDATE SET last_seen = $2, version = $3, queue_len = $4",
    )
    .bind(&hb.host_id)
    .bind(seen)
    .bind(&hb.version)
    .bind(hb.queue_len as i64)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Deserialize)]
pub struct HostQuery {
    #[serde(default)]
    host: Option<String>,
}

/// GET /v1/hosts — host registry.
pub async fn list_hosts(
    State(state): State<AppState>,
    Query(q): Query<HostQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let hosts = fetch_hosts(&state.pool, q.host.as_deref())
        .await
        .map_err(|e| {
            eprintln!("hosts list failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(Json(json!({ "hosts": hosts })))
}

pub async fn fetch_hosts(
    pool: &sqlx::AnyPool,
    host: Option<&str>,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, i64, i64, String, i64)>(
        "SELECT host_id, first_seen, last_seen, version, queue_len
         FROM hosts
         WHERE ($1 IS NULL OR host_id = $1)
         ORDER BY host_id",
    )
    .bind(host)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(host_id, first_seen, last_seen, version, queue_len)| {
            json!({
                "host_id": host_id,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "version": version,
                "queue_len": queue_len,
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::build_app;
    use crate::test_util::{call, get_ok, post};
    use axum::http::StatusCode;

    fn hb_body(host: &str, ts: i64, queue: u64) -> String {
        json!({ "host_id": host, "ts": ts, "version": "0.1.0", "queue_len": queue }).to_string()
    }

    #[tokio::test]
    async fn heartbeat_registers_host_and_lists_it() {
        let app = build_app(AppState::for_tests().await).await;
        let before = crate::ingest::now_ms();
        assert_eq!(
            post(&app, "/v1/heartbeat", &hb_body("h-1", 1000, 0))
                .await
                .0,
            StatusCode::OK
        );
        assert_eq!(
            post(&app, "/v1/heartbeat", &hb_body("h-1", 2000, 2))
                .await
                .0,
            StatusCode::OK
        );
        let json = get_ok(&app, "/v1/hosts").await;
        let hosts = json["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0]["host_id"], "h-1");
        let (first, last) = (
            hosts[0]["first_seen"].as_i64().unwrap(),
            hosts[0]["last_seen"].as_i64().unwrap(),
        );
        assert!(first >= before);
        assert!(last >= first && last - first < 5000);
        assert_eq!(
            hosts[0]["queue_len"], 2,
            "queue_len round-trips (last POST wins)"
        );
    }

    #[tokio::test]
    async fn hosts_list_requires_auth() {
        let app = build_app(AppState::for_tests().await).await;
        assert_eq!(
            call(&app, "GET", "/v1/hosts", None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn per_host_token_overrides_heartbeat_host_id() {
        let state = AppState::for_tests().await;
        let pool = state.pool.clone();
        let app = build_app(state).await;
        let body = hb_body("spoofed-host", 1000, 0);
        let (status, _) = call(
            &app,
            "POST",
            "/v1/heartbeat",
            Some("host-a-token"),
            Some(&body),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let host: (String,) = sqlx::query_as("SELECT host_id FROM hosts")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(host.0, "host-a");
    }
}
