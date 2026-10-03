use axum::middleware;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::api_incidents;
use crate::api_runner;
use crate::auth::{require_runner, require_token, Auth};
use crate::config::ServerConfig;
use crate::correlation::{merged_rules, Rule};
use crate::db;
use crate::events;
use crate::hosts;
use crate::ingest;
use crate::notifier::NOTIFY_QUEUE_CAP;
use crate::probes::Checker;

#[derive(Clone)]
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
    /// Undelivered notifications awaiting retry (drained by the retry loop).
    pub notify_queue: std::sync::Arc<std::sync::Mutex<crate::notify::RetryQueue>>,
    /// Incident JSON enqueued by the correlation runner for the notifier task.
    pub notify_tx: tokio::sync::mpsc::Sender<serde_json::Value>,
    /// Receiver for the notifier task — taken once (`take_notify_rx`).
    notify_rx:
        std::sync::Arc<std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<serde_json::Value>>>>,
    /// Per-host watchdog episode state (heartbeat-missing emission dedup).
    pub watchdog: std::sync::Arc<std::sync::Mutex<crate::watchdog::WatchdogState>>,
    /// Woken when an agent task is queued (runner long-polls wait on it).
    pub task_notify: std::sync::Arc<tokio::sync::Notify>,
}

impl AppState {
    /// The notifier's receiver; Some exactly once per state (and its clones).
    pub fn take_notify_rx(&self) -> Option<tokio::sync::mpsc::Receiver<serde_json::Value>> {
        self.notify_rx.lock().unwrap().take()
    }

    pub async fn new(pool: sqlx::AnyPool, cfg: ServerConfig) -> Self {
        db::init_schema(&pool).await.expect("schema init failed");
        let rules = merged_rules(&cfg.rules);
        let checker = Checker::new();
        let watchdog = std::sync::Arc::new(std::sync::Mutex::new(
            crate::watchdog::WatchdogState::default(),
        ));
        let (notify_tx, notify_rx) = tokio::sync::mpsc::channel(NOTIFY_QUEUE_CAP);
        AppState {
            notify_queue: std::sync::Arc::new(std::sync::Mutex::new(
                crate::notify::RetryQueue::new(3),
            )),
            notify_tx,
            notify_rx: std::sync::Arc::new(std::sync::Mutex::new(Some(notify_rx))),
            pool,
            cfg,
            checker,
            rules,
            max_body_bytes: crate::ingest::MAX_BODY_BYTES,
            watchdog,
            task_notify: Default::default(),
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
        sources: std::sync::Arc::new(state.cfg.event_sources.clone()),
        runners: std::sync::Arc::new(state.cfg.runners.clone()),
    };
    let api = Router::new()
        .route("/v1/ping", get(ping))
        .route("/v1/telemetry", post(ingest::ingest))
        .route("/v1/errors", post(crate::errors::handle_errors))
        .route("/v1/heartbeat", post(hosts::heartbeat))
        .route("/v1/hosts", get(hosts::list_hosts))
        .route(
            "/v1/events",
            get(events::list_events).post(crate::custom_events::ingest_event),
        )
        .route("/v1/incidents", get(api_incidents::list_incidents))
        .route("/v1/incidents/{id}", get(api_incidents::get_incident))
        .route(
            "/v1/incidents/{id}/events",
            get(api_incidents::incident_events),
        )
        .route(
            "/v1/incidents/{id}/{action}",
            post(api_incidents::set_status_route),
        )
        .layer(middleware::from_fn_with_state(auth.clone(), require_token));
    // runners: outbound-only long-poll protocol, runner tokens only
    let runner = Router::new()
        .route("/v1/runners/register", post(api_runner::hello))
        .route("/v1/runners/heartbeat", post(api_runner::hello))
        .route("/v1/agent-tasks/next", get(api_runner::next))
        .route(
            "/v1/agent-tasks/{id}/heartbeat",
            post(api_runner::task_heartbeat),
        )
        .route("/v1/agent-tasks/{id}/started", post(api_runner::started))
        .route("/v1/agent-tasks/{id}/complete", post(api_runner::complete))
        .route("/v1/agent-tasks/{id}/fail", post(api_runner::fail))
        .layer(middleware::from_fn_with_state(auth, require_runner));
    // the working agent: per-task context tokens (checked in the handlers)
    let context = Router::new()
        .route("/v1/agent-tasks/{id}/context", get(api_runner::context))
        .route(
            "/v1/agent-tasks/{id}/events",
            get(api_runner::context_events),
        );
    api.merge(runner).merge(context).with_state(state)
}

async fn ping() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "service": "picket-server" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{call, get_ok, post};
    use http::StatusCode;

    #[tokio::test]
    async fn ping_returns_ok() {
        let app = build_app(AppState::for_tests().await).await;
        assert_eq!(get_ok(&app, "/v1/ping").await["ok"], true);
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
        assert_eq!(post(&app, "/v1/errors", body).await.0, StatusCode::OK);
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
        assert_eq!(post(&app, "/v1/errors", body).await.0, StatusCode::OK);
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM events WHERE host_id = 'web-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 2, "two distinct event rows (unique ids), same key");
    }

    #[tokio::test]
    async fn errors_endpoint_auth_and_bad_body() {
        let app = build_app(AppState::for_tests().await).await;
        let body = r#"{"host_id":"h","exception":{"type":"T"}}"#;
        let (status, _) = call(&app, "POST", "/v1/errors", None, Some(body)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no bearer → 401");
        let (status, _) = post(&app, "/v1/errors", "not json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "malformed body → 400");
    }
}
