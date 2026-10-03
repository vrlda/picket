use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use picket_common::AgentEvent;
use serde_json::json;

use crate::app::AppState;

/// Canonical event column list (table alias `e`) — every event SELECT uses
/// it, and `EventRow` matches its order exactly.
pub(crate) const EVENT_COLS: &str = "e.id, e.ts, e.host_id, e.key, e.kind, e.severity, e.summary, \
     e.evidence_json, e.source, e.environment, e.subject, e.attributes_json, e.measurements_json";

pub(crate) type EventRow = (
    String,
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

/// Row → event. None when the stored kind/severity no longer parses (never
/// expected; such rows are skipped rather than failing the whole query).
pub(crate) fn row_to_event(r: EventRow) -> Option<AgentEvent> {
    let (
        id,
        ts,
        host_id,
        key,
        kind,
        severity,
        summary,
        evidence_json,
        source,
        environment,
        subject,
        attributes_json,
        measurements_json,
    ) = r;
    Some(AgentEvent {
        id,
        ts,
        host_id,
        key,
        kind: picket_common::EventType::parse(&kind).ok()?,
        severity: serde_json::from_value(json!(severity)).ok()?,
        summary,
        evidence: serde_json::from_str(&evidence_json).unwrap_or_default(),
        source,
        environment,
        subject,
        attributes: serde_json::from_str(&attributes_json).unwrap_or_default(),
        measurements: serde_json::from_str(&measurements_json).unwrap_or_default(),
    })
}

/// API shape of an event. Context fields appear only when set, so built-in
/// host events keep their original shape.
pub fn event_json(ev: &AgentEvent) -> serde_json::Value {
    let mut v = json!({
        "id": ev.id,
        "ts": ev.ts,
        "host_id": ev.host_id,
        "key": ev.key,
        "kind": ev.kind.to_string(),
        "severity": crate::ingest::severity_wire(ev.severity),
        "summary": ev.summary,
        "evidence": ev.evidence,
    });
    for (k, val) in [
        ("source", &ev.source),
        ("environment", &ev.environment),
        ("subject", &ev.subject),
    ] {
        if !val.is_empty() {
            v[k] = json!(val);
        }
    }
    if !ev.attributes.is_empty() {
        v["attributes"] = json!(ev.attributes);
    }
    if !ev.measurements.is_empty() {
        v["measurements"] = json!(ev.measurements);
    }
    v
}

/// Event query filters. `attrs` = `attr.<name>=<value>` query parameters
/// (exact match on a top-level attribute, compared as text).
#[derive(Default, Debug)]
pub struct EventQuery {
    pub host: Option<String>,
    pub kind: Option<String>,
    pub severity: Option<String>,
    pub source: Option<String>,
    pub environment: Option<String>,
    pub subject: Option<String>,
    pub incident_id: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub attrs: Vec<(String, String)>,
    pub limit: i64,
}

impl EventQuery {
    /// Parse raw query parameters. Err = a malformed number or attribute name.
    pub fn from_params(p: &HashMap<String, String>) -> Result<Self, String> {
        let num = |k: &str| -> Result<Option<i64>, String> {
            p.get(k)
                .map(|v| {
                    v.parse::<i64>()
                        .map_err(|_| format!("{k} must be an integer"))
                })
                .transpose()
        };
        let mut attrs = Vec::new();
        for (k, v) in p {
            if let Some(name) = k.strip_prefix("attr.") {
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                {
                    return Err(format!("invalid attribute filter {k:?}"));
                }
                attrs.push((name.to_string(), v.clone()));
            }
        }
        attrs.sort();
        Ok(EventQuery {
            host: p.get("host").cloned(),
            kind: p.get("kind").cloned(),
            severity: p.get("severity").cloned(),
            source: p.get("source").cloned(),
            environment: p.get("environment").cloned(),
            subject: p.get("subject").cloned(),
            incident_id: p.get("incident_id").cloned(),
            since: num("since")?,
            until: num("until")?,
            attrs,
            limit: num("limit")?.unwrap_or(100),
        })
    }
}

/// GET /v1/events — timeline. Order is (ts DESC, id) — NEVER arrival order:
/// agent batches contain non-monotonic, duplicate ts values (M1 final review
/// constraint); created_at must never be used for ordering.
pub async fn list_events(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let q = EventQuery::from_params(&params)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))))?;
    let events = fetch_events(&state.pool, &q).await.map_err(|e| {
        eprintln!("events list failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "query failed" })),
        )
    })?;
    Ok(Json(json!({ "events": events })))
}

pub async fn fetch_events(
    pool: &sqlx::AnyPool,
    q: &EventQuery,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    // dynamic WHERE: one numbered placeholder per present filter
    let mut sql = format!("SELECT {EVENT_COLS} FROM events e WHERE 1 = 1");
    let mut binds: Vec<String> = Vec::new();
    let mut ints: Vec<(usize, i64)> = Vec::new();
    let mut n = 0usize;
    // text filter: `{}` in `cond` becomes the next placeholder
    fn text(sql: &mut String, binds: &mut Vec<String>, n: &mut usize, cond: &str, v: &str) {
        *n += 1;
        sql.push_str(&format!(" AND {}", cond.replace("{}", &format!("${n}"))));
        binds.push(v.to_string());
    }
    for (col, val) in [
        ("e.host_id = {}", &q.host),
        ("e.kind = {}", &q.kind),
        ("e.severity = {}", &q.severity),
        ("e.source = {}", &q.source),
        ("e.environment = {}", &q.environment),
        ("e.subject = {}", &q.subject),
        (
            "e.id IN (SELECT event_id FROM incident_events WHERE incident_id = {})",
            &q.incident_id,
        ),
    ] {
        if let Some(v) = val {
            text(&mut sql, &mut binds, &mut n, col, v);
        }
    }
    let postgres = crate::db::is_postgres(pool);
    for (name, value) in &q.attrs {
        // name is restricted to [A-Za-z0-9_-] by from_params
        let expr = if postgres {
            format!("(e.attributes_json::jsonb ->> '{name}') = {{}}")
        } else {
            format!("CAST(json_extract(e.attributes_json, '$.\"{name}\"') AS TEXT) = {{}}")
        };
        text(&mut sql, &mut binds, &mut n, &expr, value);
    }
    for (cond, val) in [("e.ts >= ", q.since), ("e.ts <= ", q.until)] {
        if let Some(v) = val {
            n += 1;
            sql.push_str(&format!(" AND {cond}${n}"));
            ints.push((n, v));
        }
    }
    n += 1;
    sql.push_str(&format!(" ORDER BY e.ts DESC, e.id LIMIT ${n}"));
    let mut query = sqlx::query_as::<_, EventRow>(&sql);
    // placeholders were numbered text-first, then ints, then the limit
    for b in &binds {
        query = query.bind(b.clone());
    }
    for (_, v) in &ints {
        query = query.bind(*v);
    }
    query = query.bind(q.limit.clamp(1, 1000));
    let rows = query.fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .filter_map(row_to_event)
        .map(|e| event_json(&e))
        .collect())
}

/// Raw events since `since_ms`, oldest first — used by the correlation scan.
pub async fn fetch_events_simple(
    pool: &sqlx::AnyPool,
    since_ms: i64,
) -> Result<Vec<AgentEvent>, sqlx::Error> {
    let rows = sqlx::query_as::<_, EventRow>(&format!(
        "SELECT {EVENT_COLS} FROM events e WHERE e.ts >= $1 ORDER BY e.ts ASC, e.id"
    ))
    .bind(since_ms)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().filter_map(row_to_event).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::build_app;
    use crate::test_util::{call, get_ok};
    use axum::http::StatusCode;
    use picket_common::{AgentEvent, EventKind, Severity};

    async fn seed(state: &AppState, id: &str, ts: i64, kind: EventKind, sev: Severity) {
        let ev = AgentEvent {
            id: id.into(),
            ts,
            host_id: "h-1".into(),
            key: format!("k:{}", id),
            kind: kind.into(),
            severity: sev,
            summary: format!("event {}", id),
            evidence: vec![picket_common::Evidence {
                ts,
                source: "test".into(),
                detail: "d".into(),
            }],
            ..Default::default()
        };
        crate::ingest::store_events(&state.pool, &[ev])
            .await
            .unwrap();
    }

    async fn seeded_app() -> axum::Router {
        let state = AppState::for_tests().await;
        seed(
            &state,
            "e-1",
            1000,
            EventKind::ServiceFailed,
            Severity::Critical,
        )
        .await;
        seed(&state, "e-2", 2000, EventKind::CpuSpike, Severity::Warning).await;
        seed(&state, "e-3", 1500, EventKind::MemHigh, Severity::Warning).await;
        build_app(state).await
    }

    fn ids(json: &serde_json::Value) -> Vec<&str> {
        json["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["id"].as_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn events_list_orders_by_ts_desc_and_returns_evidence() {
        let json = get_ok(&seeded_app().await, "/v1/events").await;
        assert_eq!(ids(&json), ["e-2", "e-3", "e-1"], "newest first");
        assert_eq!(json["events"][0]["evidence"][0]["source"], "test");
    }

    #[tokio::test]
    async fn events_filters_by_kind_and_limit() {
        let app = seeded_app().await;
        assert_eq!(
            ids(&get_ok(&app, "/v1/events?kind=CpuSpike&limit=10").await),
            ["e-2"]
        );
        assert_eq!(ids(&get_ok(&app, "/v1/events?limit=1").await), ["e-2"]);
    }

    #[tokio::test]
    async fn events_respect_since_and_host_filter() {
        let app = seeded_app().await;
        assert_eq!(
            ids(&get_ok(&app, "/v1/events?host=h-1&since=1600").await),
            ["e-2"]
        );
        assert_eq!(ids(&get_ok(&app, "/v1/events?until=1200").await), ["e-1"]);
        assert!(ids(&get_ok(&app, "/v1/events?host=other").await).is_empty());
    }

    #[tokio::test]
    async fn events_requires_auth_and_valid_filters() {
        let app = seeded_app().await;
        assert_eq!(
            call(&app, "GET", "/v1/events", None, None).await.0,
            StatusCode::UNAUTHORIZED
        );
        let bad = call(
            &app,
            "GET",
            "/v1/events?since=soon",
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(bad.0, StatusCode::BAD_REQUEST);
        let bad = call(
            &app,
            "GET",
            "/v1/events?attr.a'b=1",
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(
            bad.0,
            StatusCode::BAD_REQUEST,
            "attribute names are validated"
        );
    }
}
