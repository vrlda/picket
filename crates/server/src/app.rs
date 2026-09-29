use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::api_incidents;
use crate::auth::{require_token, Auth};
use crate::config::ServerConfig;
use crate::correlation::{merged_rules, Rule};
use crate::db;
use crate::events;
use crate::hosts;
use crate::ingest;
use crate::notifier::NOTIFY_QUEUE_CAP;
use crate::probes::Checker;

pub struct AppState {
    pub pool: sqlx::AnyPool,
    pub cfg: ServerConfig,
    pub checker: Checker,
    /// Effective correlation rules (config merged over built-in defaults).
    pub rules: Vec<Rule>,
    /// Max request body bytes accepted by ingest. Must fit the agent's
    /// maximum spool file (10 MB) plus envelope — a smaller cap would make
    /// the drain POST 400 and the agent would drop the whole file as
    /// "permanent".
    pub max_body_bytes: usize,
    pub notify: crate::notify::NotifyConfig,
    /// Undelivered notifications awaiting retry (drained by the retry loop).
    pub notify_queue: std::sync::Arc<std::sync::Mutex<crate::notify::RetryQueue>>,
    /// Incident JSON enqueued by the correlation runner for the notifier task.
    pub notify_tx: tokio::sync::mpsc::Sender<serde_json::Value>,
    /// Receiver taken by main to spawn the notifier; None after spawn.
    pub notify_rx: Option<tokio::sync::mpsc::Receiver<serde_json::Value>>,
    /// Per-host watchdog episode state (heartbeat-missing emission dedup).
    pub watchdog: std::sync::Arc<std::sync::Mutex<crate::watchdog::WatchdogState>>,
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        AppState {
            pool: self.pool.clone(),
            cfg: self.cfg.clone(),
            checker: self.checker.clone(),
            rules: self.rules.clone(),
            max_body_bytes: self.max_body_bytes,
            notify: self.notify.clone(),
            notify_queue: self.notify_queue.clone(),
            notify_tx: self.notify_tx.clone(),
            // The receiver is single-use (spawned once by main); clones
            // carry a None so the original keeps the only receiver.
            notify_rx: None,
            watchdog: self.watchdog.clone(),
        }
    }
}

impl AppState {
    pub async fn new(pool: sqlx::AnyPool, cfg: ServerConfig) -> Self {
        db::init_schema(&pool).await.expect("schema init failed");
        let rules = merged_rules(&cfg.rules);
        let checker = Checker::new();
        let watchdog = std::sync::Arc::new(std::sync::Mutex::new(
            crate::watchdog::WatchdogState::default(),
        ));
        let (notify_tx, notify_rx) = tokio::sync::mpsc::channel(NOTIFY_QUEUE_CAP);
        AppState {
            notify: cfg.notify.clone(),
            notify_queue: std::sync::Arc::new(std::sync::Mutex::new(
                crate::notify::RetryQueue::new(3),
            )),
            notify_tx,
            notify_rx: Some(notify_rx),
            pool,
            cfg,
            checker,
            rules,
            max_body_bytes: crate::ingest::MAX_BODY_BYTES,
            watchdog,
        }
    }

    /// Test helper: in-memory pool + default config. Intentionally NOT
    /// `#[cfg(test)]` — integration tests (crates/server/tests) compile the
    /// lib without that cfg and need it.
    pub async fn for_tests() -> Self {
        crate::db::ensure_any_drivers();
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory db");
        let mut state = AppState::new(
            pool,
            ServerConfig {
                auth_token: "test-token".into(),
                host_tokens: std::collections::HashMap::from([(
                    "host-a".into(),
                    "host-a-token".into(),
                )]),
                ..Default::default()
            },
        )
        .await;
        state.max_body_bytes = 4096;
        state
    }
}

pub async fn build_app(state: AppState) -> Router {
    let auth = Auth {
        shared: state.cfg.auth_token.clone(),
        hosts: std::sync::Arc::new(state.cfg.host_tokens.clone()),
    };
    Router::new()
        .route("/v1/ping", get(ping))
        .route("/v1/telemetry", post(ingest::ingest))
        .route("/v1/errors", post(crate::errors::handle_errors))
        .route("/v1/heartbeat", post(hosts::heartbeat))
        .route("/v1/hosts", get(hosts::list_hosts))
        .route("/v1/events", get(events::list_events))
        .route("/v1/incidents", get(api_incidents::list_incidents))
        .route("/v1/incidents/{id}", get(api_incidents::get_incident))
        .route(
            "/v1/incidents/{id}/{action}",
            post(api_incidents::set_status_route),
        )
        .layer(middleware::from_fn_with_state(auth, require_token))
        .with_state(state)
}

async fn ping() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "service": "watchtower-server" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn ping_returns_ok() {
        let app = build_app(AppState::for_tests().await).await;
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/ping")
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn errors_endpoint_stores_and_keys_exception() {
        let state = AppState::for_tests().await;
        let pool = state.pool.clone();
        let app = build_app(state).await;
        let body = r#"{
            "host_id": "web-1",
            "service": "api",
            "environment": "prod",
            "exception": {
                "type": "ValueError",
                "message": "bad input",
                "level": "error",
                "frames": [{"file": "app.py", "line": 42, "function": "validate"}]
            }
        }"#;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/errors")
            .header("content-type", "application/json")
            .header("authorization", "Bearer test-token")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let row: (String, String, String) =
            sqlx::query_as("SELECT key, severity, kind FROM events WHERE host_id = 'web-1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        let fp = crate::errors::fingerprint("api", "ValueError", &[("app.py".into(), 42)]);
        assert_eq!(row.0, format!("ex:api:{}", fp), "key = fingerprint");
        assert_eq!(row.1, "Critical", "error level → Critical");
        assert_eq!(row.2, "AppException");
        // second identical exception → same key (server-side dedup + grouping)
        let resp2 = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/errors")
                    .header("content-type", "application/json")
                    .header("authorization", "Bearer test-token")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM events WHERE host_id = 'web-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 2, "two distinct event rows (unique ids), same key");
    }

    #[tokio::test]
    async fn errors_endpoint_auth_and_bad_body() {
        let state = AppState::for_tests().await;
        let app = build_app(state).await;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/errors")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"host_id":"h","exception":{"type":"T"}}"#))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "no bearer → 401");
        let req2 = Request::builder()
            .method("POST")
            .uri("/v1/errors")
            .header("content-type", "application/json")
            .header("authorization", "Bearer test-token")
            .body(Body::from("not json"))
            .unwrap();
        let resp2 = app.oneshot(req2).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::BAD_REQUEST,
            "malformed body → 400"
        );
    }
}
