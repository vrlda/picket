use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::app::AppState;
use crate::incidents::{self, IncidentStatus};

#[derive(Deserialize, Default)]
pub struct IncidentQuery {
    status: Option<String>,
    severity: Option<String>,
    host: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
}

fn default_limit() -> i64 {
    100
}

/// GET /v1/incidents — newest first.
pub async fn list_incidents(
    State(state): State<AppState>,
    Query(q): Query<IncidentQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let incidents = incidents::list(
        &state.pool,
        &q.status,
        &q.severity,
        q.host.as_deref(),
        q.limit.clamp(1, 1000),
    )
    .await
    .map_err(|e| {
        eprintln!("incidents list failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(json!({ "incidents": incidents })))
}

/// GET /v1/incidents/{id} — full detail with timeline.
pub async fn get_incident(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let inc = incidents::fetch_incident(&state.pool, &id)
        .await
        .map_err(|e| {
            eprintln!("incident fetch failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(incident_json(&inc)))
}

/// POST /v1/incidents/{id}/ack | /resolve
pub async fn set_status_route(
    State(state): State<AppState>,
    Path((id, action)): Path<(String, String)>,
) -> Response {
    let status = match action.as_str() {
        "ack" => IncidentStatus::Acknowledged,
        "resolve" => IncidentStatus::Resolved,
        _ => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "unknown action" })),
            )
                .into_response()
        }
    };
    match incidents::set_status(&state.pool, &id, status).await {
        Ok(true) => Json(json!({ "ok": true })).into_response(),
        Ok(false) => match incidents::fetch_incident(&state.pool, &id).await {
            Ok(Some(inc)) => (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": format!(
                        "cannot {} an incident that is {:?}",
                        action, inc.status
                    )
                    .to_lowercase(),
                })),
            )
                .into_response(),
            _ => (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "incident not found" })),
            )
                .into_response(),
        },
        Err(e) => {
            eprintln!("set status failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "store failed" })),
            )
                .into_response()
        }
    }
}

/// Canonical incident JSON — the notifier and UI both use this shape.
pub fn incident_json(inc: &incidents::Incident) -> serde_json::Value {
    json!({
        "id": inc.id,
        "key": inc.key,
        "host_id": inc.host_id,
        "severity": inc.severity,
        "status": format!("{:?}", inc.status).to_lowercase(),
        "headline": inc.headline,
        "cause": inc.cause,
        "actions": inc.actions,
        "affected": inc.affected,
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
        "acked_at": inc.acked_at,
        "resolved_at": inc.resolved_at,
        "timeline": inc.timeline.iter().map(|e| json!({
            "id": e.id,
            "ts": e.ts,
            "host_id": e.host_id,
            "kind": e.kind,
            "severity": e.severity,
            "summary": e.summary,
            "evidence": e.evidence,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::build_app;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    use wt_common::{AgentEvent, EventKind, Severity};

    async fn seed_incident(state: &AppState) -> String {
        let evs = vec![
            AgentEvent {
                id: "e-1".into(),
                ts: 999_999_700_000,
                host_id: "h-1".into(),
                key: "fim:/etc/myapp/config.yml".into(),
                kind: EventKind::FileChanged,
                severity: Severity::Warning,
                summary: "config changed".into(),
                evidence: vec![],
            },
            AgentEvent {
                id: "e-2".into(),
                ts: 999_999_800_000,
                host_id: "h-1".into(),
                key: "svc:myapp.service".into(),
                kind: EventKind::ServiceFailed,
                severity: Severity::Critical,
                summary: "myapp failed".into(),
                evidence: vec![],
            },
        ];
        crate::ingest::store_events(&state.pool, &evs)
            .await
            .unwrap();
        let rules = crate::correlation::default_rules();
        let incs = crate::correlation::scan_and_absorb(&state.pool, &rules, 1_000_000_000_000)
            .await
            .unwrap();
        assert_eq!(incs.len(), 1, "config-change incident only");
        incs[0].id.clone()
    }

    async fn get_json(app: &axum::Router, uri: &str) -> serde_json::Value {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn lists_incidents_with_status_filter() {
        let state = AppState::for_tests().await;
        seed_incident(&state).await;
        let app = build_app(state).await;
        let json = get_json(&app, "/v1/incidents").await;
        let list = json["incidents"].as_array().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["status"], "open");
        assert_eq!(list[0]["severity"], "Critical");
        assert_eq!(
            list[0]["headline"],
            "myapp.service became unhealthy after a configuration change"
        );
    }

    #[tokio::test]
    async fn incident_detail_includes_timeline() {
        let state = AppState::for_tests().await;
        let id = seed_incident(&state).await;
        let app = build_app(state).await;
        let json = get_json(&app, &format!("/v1/incidents/{}", id)).await;
        assert_eq!(json["id"], id);
        assert!(!json["timeline"].as_array().unwrap().is_empty());
        assert!(!json["actions"].as_array().unwrap().is_empty());
        assert!(!json["affected"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ack_and_resolve_update_status() {
        let state = AppState::for_tests().await;
        let id = seed_incident(&state).await;
        let app = build_app(state).await;
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/incidents/{}/ack", id))
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = get_json(&app, &format!("/v1/incidents/{}", id)).await;
        assert_eq!(json["status"], "acknowledged");
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/incidents/{}/resolve", id))
                    .header("authorization", "Bearer test-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = get_json(&app, &format!("/v1/incidents/{}", id)).await;
        assert_eq!(json["status"], "resolved");
        assert!(json["resolved_at"].is_number());
    }

    #[tokio::test]
    async fn resolved_incident_is_final() {
        let state = AppState::for_tests().await;
        let id = seed_incident(&state).await;
        let app = build_app(state).await;
        let post = |path: String| {
            let app = app.clone();
            async move {
                app.oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .header("authorization", "Bearer test-token")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
            }
        };
        assert_eq!(
            post(format!("/v1/incidents/{}/resolve", id)).await,
            StatusCode::OK
        );
        let resolved_at =
            get_json(&app, &format!("/v1/incidents/{}", id)).await["resolved_at"].clone();
        assert_eq!(
            post(format!("/v1/incidents/{}/ack", id)).await,
            StatusCode::CONFLICT,
            "ack must not re-open a resolved incident"
        );
        assert_eq!(
            post(format!("/v1/incidents/{}/resolve", id)).await,
            StatusCode::CONFLICT
        );
        let json = get_json(&app, &format!("/v1/incidents/{}", id)).await;
        assert_eq!(json["status"], "resolved");
        assert_eq!(
            json["resolved_at"], resolved_at,
            "cooldown anchor unchanged"
        );
        assert_eq!(
            post("/v1/incidents/nope/ack".into()).await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn lifecycle_requires_auth() {
        let app = build_app(AppState::for_tests().await).await;
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/incidents")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
