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
    let mut json = incident_json(&inc);
    let db_err = |e: sqlx::Error| {
        eprintln!("incident fetch failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    };
    json["activity"] = serde_json::Value::Array(
        crate::dispatch::fetch_activity(&state.pool, &id)
            .await
            .map_err(db_err)?,
    );
    json["agent_tasks"] = serde_json::Value::Array(
        crate::agent_tasks::tasks_for_incident(&state.pool, &id)
            .await
            .map_err(db_err)?,
    );
    Ok(Json(json))
}

/// GET /v1/incidents/{id}/events — the incident's events with the same
/// filters as /v1/events (kind, subject, attr.<name>, since, until, limit).
pub async fn incident_events(
    State(state): State<AppState>,
    Path(id): Path<String>,
    axum::extract::Query(mut params): axum::extract::Query<
        std::collections::HashMap<String, String>,
    >,
) -> Response {
    match incidents::fetch_incident(&state.pool, &id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "incident not found" })),
            )
                .into_response()
        }
        Err(e) => {
            eprintln!("incident fetch failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }
    params.insert("incident_id".into(), id);
    let q = match crate::events::EventQuery::from_params(&params) {
        Ok(q) => q,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    };
    match crate::events::fetch_events(&state.pool, &q).await {
        Ok(events) => Json(json!({ "events": events })).into_response(),
        Err(e) => {
            eprintln!("incident events failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
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
        Ok(true) => {
            let _ = crate::dispatch::record_activity(
                &state.pool,
                &id,
                "human",
                "api",
                &format!(
                    "{} via API",
                    if action == "ack" {
                        "Acknowledged"
                    } else {
                        "Resolved"
                    }
                ),
                json!({}),
            )
            .await;
            Json(json!({ "ok": true })).into_response()
        }
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

/// Canonical incident JSON — the notifier and the API both use this shape.
/// Derived fields (event kinds, first/last seen, sources, subjects) are
/// computed from the timeline rather than stored.
pub fn incident_json(inc: &incidents::Incident) -> serde_json::Value {
    let mut kinds: std::collections::BTreeMap<&str, usize> = Default::default();
    let mut sources: Vec<&str> = Vec::new();
    let mut environments: Vec<&str> = Vec::new();
    let mut subjects: Vec<&str> = Vec::new();
    for e in &inc.timeline {
        *kinds.entry(e.kind.as_str()).or_default() += 1;
        for (list, v) in [
            (&mut sources, &e.source),
            (&mut environments, &e.environment),
            (&mut subjects, &e.subject),
        ] {
            if !v.is_empty() && !list.contains(&v.as_str()) {
                list.push(v);
            }
        }
    }
    json!({
        "id": inc.id,
        "key": inc.key,
        "rule_id": inc.rule_id,
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
        "event_count": inc.timeline.len(),
        "event_kinds": kinds,
        "first_seen": inc.timeline.iter().map(|e| e.ts).min(),
        "last_seen": inc.timeline.iter().map(|e| e.ts).max(),
        "sources": sources,
        "environments": environments,
        "subjects": subjects,
        "timeline": inc.timeline.iter().map(|e| {
            let mut v = json!({
                "id": e.id,
                "ts": e.ts,
                "host_id": e.host_id,
                "kind": e.kind,
                "severity": e.severity,
                "summary": e.summary,
                "evidence": e.evidence,
            });
            for (k, val) in [("source", &e.source), ("environment", &e.environment), ("subject", &e.subject)] {
                if !val.is_empty() {
                    v[k] = json!(val);
                }
            }
            if !e.attributes.is_empty() {
                v["attributes"] = json!(e.attributes);
            }
            if !e.measurements.is_empty() {
                v["measurements"] = json!(e.measurements);
            }
            v
        }).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::build_app;
    use crate::test_util::{call, get_ok as get_json};
    use axum::http::StatusCode;
    use picket_common::{AgentEvent, EventKind, Severity};

    async fn seed_incident(state: &AppState) -> String {
        let evs = vec![
            AgentEvent {
                id: "e-1".into(),
                ts: 999_999_700_000,
                host_id: "h-1".into(),
                key: "fim:/etc/myapp/config.yml".into(),
                kind: EventKind::FileChanged.into(),
                severity: Severity::Warning,
                summary: "config changed".into(),
                evidence: vec![],
                ..Default::default()
            },
            AgentEvent {
                id: "e-2".into(),
                ts: 999_999_800_000,
                host_id: "h-1".into(),
                key: "svc:myapp.service".into(),
                kind: EventKind::ServiceFailed.into(),
                severity: Severity::Critical,
                summary: "myapp failed".into(),
                evidence: vec![],
                ..Default::default()
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

    async fn post_status(app: &axum::Router, path: &str) -> StatusCode {
        crate::test_util::call(app, "POST", path, Some("test-token"), None)
            .await
            .0
    }

    #[tokio::test]
    async fn ack_and_resolve_update_status() {
        let state = AppState::for_tests().await;
        let id = seed_incident(&state).await;
        let app = build_app(state).await;
        assert_eq!(
            post_status(&app, &format!("/v1/incidents/{id}/ack")).await,
            StatusCode::OK
        );
        let json = get_json(&app, &format!("/v1/incidents/{id}")).await;
        assert_eq!(json["status"], "acknowledged");
        assert_eq!(
            post_status(&app, &format!("/v1/incidents/{id}/resolve")).await,
            StatusCode::OK
        );
        let json = get_json(&app, &format!("/v1/incidents/{id}")).await;
        assert_eq!(json["status"], "resolved");
        assert!(json["resolved_at"].is_number());
    }

    #[tokio::test]
    async fn resolved_incident_is_final() {
        let state = AppState::for_tests().await;
        let id = seed_incident(&state).await;
        let app = build_app(state).await;
        let (ack, resolve) = (
            format!("/v1/incidents/{id}/ack"),
            format!("/v1/incidents/{id}/resolve"),
        );
        assert_eq!(post_status(&app, &resolve).await, StatusCode::OK);
        let resolved_at =
            get_json(&app, &format!("/v1/incidents/{id}")).await["resolved_at"].clone();
        assert_eq!(
            post_status(&app, &ack).await,
            StatusCode::CONFLICT,
            "ack must not re-open a resolved incident"
        );
        assert_eq!(post_status(&app, &resolve).await, StatusCode::CONFLICT);
        let json = get_json(&app, &format!("/v1/incidents/{id}")).await;
        assert_eq!(json["status"], "resolved");
        assert_eq!(
            json["resolved_at"], resolved_at,
            "cooldown anchor unchanged"
        );
        assert_eq!(
            post_status(&app, "/v1/incidents/nope/ack").await,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn lifecycle_requires_auth() {
        let app = build_app(AppState::for_tests().await).await;
        assert_eq!(
            call(&app, "GET", "/v1/incidents", None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
}
