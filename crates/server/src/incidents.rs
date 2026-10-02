use serde::{Deserialize, Serialize};
use uuid::Uuid;
use wt_common::AgentEvent;

use crate::ingest::now_ms;

/// Canonical incident column list — every SELECT uses it, every tuple
/// destructure matches its order exactly.
const INCIDENT_COLS: &str = "id, key, host_id, severity, headline, cause, actions_json, affected_json, created_at, updated_at, acked_at, resolved_at, status";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IncidentStatus {
    Open,
    Acknowledged,
    Resolved,
}

#[derive(Debug, Clone)]
pub struct IncidentEvent {
    pub id: String,
    pub ts: i64,
    pub host_id: String,
    pub kind: String,
    pub severity: String,
    pub summary: String,
    pub evidence: Vec<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub id: String,
    pub key: String,
    pub host_id: String,
    pub severity: String,
    pub status: IncidentStatus,
    pub headline: String,
    pub cause: String,
    pub actions: Vec<String>,
    pub affected: Vec<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub acked_at: Option<i64>,
    pub resolved_at: Option<i64>,
    pub timeline: Vec<IncidentEvent>,
}

/// Row tuple order MUST match incident_select() column order:
/// (id, key, host_id, severity, headline, cause, actions_json, affected_json,
///  created_at, updated_at, acked_at, resolved_at, status).
type IncidentRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    Option<i64>,
    Option<i64>,
    String,
);

fn row_to_incident(r: IncidentRow) -> Incident {
    let status = match r.12.as_str() {
        "acknowledged" => IncidentStatus::Acknowledged,
        "resolved" => IncidentStatus::Resolved,
        _ => IncidentStatus::Open,
    };
    Incident {
        id: r.0,
        key: r.1,
        host_id: r.2,
        severity: r.3,
        headline: r.4,
        cause: r.5,
        actions: serde_json::from_str(&r.6).unwrap_or_default(),
        affected: serde_json::from_str(&r.7).unwrap_or_default(),
        created_at: r.8,
        updated_at: r.9,
        acked_at: r.10,
        resolved_at: r.11,
        status,
        timeline: vec![],
    }
}

fn incident_select() -> String {
    format!("SELECT {} FROM incidents", INCIDENT_COLS)
}

/// Open a new incident, or ABSORB into the open incident with the same key
/// (dedup while open). Returns the incident to operate on — the caller then
/// re-links events (idempotent) and touches updated_at only when new events
/// were linked.
#[allow(clippy::too_many_arguments)] // signature spec'd by M4 plan; Task 4 depends on it
pub async fn create_incident(
    pool: &sqlx::AnyPool,
    key: &str,
    host_id: &str,
    severity: &str,
    headline: &str,
    cause: &str,
    actions: &[String],
    affected: &[String],
) -> Result<Incident, sqlx::Error> {
    if let Some(existing) = find_open_by_key(pool, key).await? {
        return Ok(existing);
    }
    let now = now_ms();
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO incidents
         (id, key, host_id, severity, status, headline, cause, actions_json, affected_json, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'open', $5, $6, $7, $8, $9, $9)",
    )
    .bind(&id)
    .bind(key)
    .bind(host_id)
    .bind(severity)
    .bind(headline)
    .bind(cause)
    .bind(serde_json::to_string(actions).unwrap_or_else(|_| "[]".into()))
    .bind(serde_json::to_string(affected).unwrap_or_else(|_| "[]".into()))
    .bind(now)
    .execute(pool)
    .await?;
    Ok(Incident {
        id,
        key: key.into(),
        host_id: host_id.into(),
        severity: severity.into(),
        status: IncidentStatus::Open,
        headline: headline.into(),
        cause: cause.into(),
        actions: actions.to_vec(),
        affected: affected.to_vec(),
        created_at: now,
        updated_at: now,
        acked_at: None,
        resolved_at: None,
        timeline: vec![],
    })
}

/// Find an open/acknowledged incident by key (absorb target).
pub async fn find_open_by_key(
    pool: &sqlx::AnyPool,
    key: &str,
) -> Result<Option<Incident>, sqlx::Error> {
    let query = format!(
        "{} WHERE key = $1 AND status != 'resolved' LIMIT 1",
        incident_select()
    );
    let row = sqlx::query_as::<_, IncidentRow>(&query)
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(row_to_incident))
}

/// Link events to an incident. Idempotent: returns the count of NEW links.
/// Events are persisted into `events` too (INSERT OR IGNORE) so the timeline
/// JOIN works even for events the engine passes directly; pre-stored events
/// make this a no-op.
pub async fn link_events(
    pool: &sqlx::AnyPool,
    incident_id: &str,
    events: &[AgentEvent],
) -> Result<usize, sqlx::Error> {
    let mut new = 0usize;
    let mut tx = pool.begin().await?;
    let events_sql = if crate::db::is_postgres(pool) {
        "INSERT INTO events (id, ts, host_id, key, kind, severity, summary, evidence_json, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (id) DO NOTHING"
    } else {
        "INSERT OR IGNORE INTO events (id, ts, host_id, key, kind, severity, summary, evidence_json, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
    };
    let links_sql = if crate::db::is_postgres(pool) {
        "INSERT INTO incident_events (incident_id, event_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
    } else {
        "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES ($1, $2)"
    };
    for ev in events {
        let evidence = serde_json::to_string(&ev.evidence).unwrap_or_else(|_| "[]".into());
        sqlx::query(events_sql)
            .bind(&ev.id)
            .bind(ev.ts)
            .bind(&ev.host_id)
            .bind(&ev.key)
            .bind(crate::ingest::kind_wire(&ev.kind))
            .bind(crate::ingest::severity_wire(ev.severity))
            .bind(&ev.summary)
            .bind(evidence)
            .bind(now_ms())
            .execute(&mut *tx)
            .await?;
        let res = sqlx::query(links_sql)
            .bind(incident_id)
            .bind(&ev.id)
            .execute(&mut *tx)
            .await?;
        if res.rows_affected() > 0 {
            new += 1;
        }
    }
    tx.commit().await?;
    Ok(new)
}

/// Bump updated_at; returns the new updated_at.
pub async fn touch_incident(pool: &sqlx::AnyPool, incident_id: &str) -> Result<i64, sqlx::Error> {
    let now = now_ms();
    sqlx::query("UPDATE incidents SET updated_at = $1 WHERE id = $2")
        .bind(now)
        .bind(incident_id)
        .execute(pool)
        .await?;
    Ok(now)
}

/// Raise the incident severity if `severity` is higher (never lower).
pub async fn raise_severity(
    pool: &sqlx::AnyPool,
    id: &str,
    severity: &str,
) -> Result<(), sqlx::Error> {
    // severity strings are the wire values; compare via CASE on the stored
    // order: Critical > Warning > Info
    sqlx::query(
        "UPDATE incidents SET severity = $2, updated_at = $3
         WHERE id = $1 AND (
            (severity = 'Info' AND $2 != 'Info')
            OR (severity = 'Warning' AND $2 = 'Critical')
         )",
    )
    .bind(id)
    .bind(severity)
    .bind(now_ms())
    .execute(pool)
    .await?;
    Ok(())
}

/// Ack or resolve an incident at an explicit timestamp: sets the status,
/// stamps the ack/resolve time, and bumps updated_at. Returns true when a
/// row was updated (unknown id, or a transition that is not allowed → false).
///
/// Allowed transitions: open → acknowledged, open/acknowledged → resolved.
/// A resolved incident is final: acking it would move it back into the
/// "not resolved" set and collide with a newer open incident for the same
/// key (unique index), and re-resolving it would push its resolved_at (and
/// so the re-open cooldown) forward.
pub async fn set_status_at(
    pool: &sqlx::AnyPool,
    id: &str,
    status: IncidentStatus,
    now: i64,
) -> Result<bool, sqlx::Error> {
    if status == IncidentStatus::Open {
        return Ok(false);
    }
    let (wire, col, from) = match status {
        IncidentStatus::Acknowledged => ("acknowledged", "acked_at", "status = 'open'"),
        IncidentStatus::Resolved => ("resolved", "resolved_at", "status != 'resolved'"),
        IncidentStatus::Open => unreachable!(),
    };
    let query = format!(
        "UPDATE incidents SET status = $1, {col} = $2, updated_at = $2 WHERE id = $3 AND {from}"
    );
    let res = sqlx::query(&query)
        .bind(wire)
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Ack or resolve an incident at now: sets the status, stamps the
/// ack/resolve time, and bumps updated_at. Returns true when a row was
/// updated (unknown id → false).
pub async fn set_status(
    pool: &sqlx::AnyPool,
    id: &str,
    status: IncidentStatus,
) -> Result<bool, sqlx::Error> {
    set_status_at(pool, id, status, now_ms()).await
}

/// List summaries (no timelines), newest first.
pub async fn list(
    pool: &sqlx::AnyPool,
    status: &Option<String>,
    severity: &Option<String>,
    host: Option<&str>,
    limit: i64,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, String, String, i64, i64, Option<i64>, Option<i64>)>(
        "SELECT id, key, host_id, severity, headline, status, cause, created_at, updated_at, acked_at, resolved_at
         FROM incidents
         WHERE ($1 IS NULL OR status = $1)
           AND ($2 IS NULL OR severity = $2)
           AND ($3 IS NULL OR host_id = $3)
         ORDER BY created_at DESC
         LIMIT $4",
    )
    .bind(status.as_deref())
    .bind(severity.as_deref())
    .bind(host)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                key,
                host_id,
                severity,
                headline,
                status,
                cause,
                created_at,
                updated_at,
                acked_at,
                resolved_at,
            )| {
                serde_json::json!({
                    "id": id,
                    "key": key,
                    "host_id": host_id,
                    "severity": severity,
                    "headline": headline,
                    "status": status,
                    "cause": cause,
                    "created_at": created_at,
                    "updated_at": updated_at,
                    "acked_at": acked_at,
                    "resolved_at": resolved_at,
                })
            },
        )
        .collect())
}

/// Full incident with timeline, ordered (ts DESC, id) — NEVER arrival order.
pub async fn fetch_incident(
    pool: &sqlx::AnyPool,
    id: &str,
) -> Result<Option<Incident>, sqlx::Error> {
    let query = format!("{} WHERE id = $1", incident_select());
    let row = sqlx::query_as::<_, IncidentRow>(&query)
        .bind(id)
        .fetch_optional(pool)
        .await?;
    let Some(r) = row else { return Ok(None) };
    let mut inc = row_to_incident(r);
    inc.timeline = fetch_timeline(pool, id).await?;
    Ok(Some(inc))
}

pub async fn fetch_timeline(
    pool: &sqlx::AnyPool,
    incident_id: &str,
) -> Result<Vec<IncidentEvent>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, i64, String, String, String, String, String)>(
        "SELECT e.id, e.ts, e.host_id, e.kind, e.severity, e.summary, e.evidence_json
         FROM incident_events ie JOIN events e ON e.id = ie.event_id
         WHERE ie.incident_id = $1
         ORDER BY e.ts DESC, e.id",
    )
    .bind(incident_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, ts, host_id, kind, severity, summary, evidence_json)| IncidentEvent {
                id,
                ts,
                host_id,
                kind: kind.into(),
                severity,
                summary,
                evidence: serde_json::from_str(&evidence_json).unwrap_or_default(),
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wt_common::{AgentEvent, EventKind, Severity};

    async fn pool() -> sqlx::AnyPool {
        crate::db::ensure_any_drivers();
        let p = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        crate::db::init_schema(&p).await.unwrap();
        p
    }

    fn event(id: &str, ts: i64, kind: EventKind, sev: Severity) -> AgentEvent {
        AgentEvent {
            id: id.into(),
            ts,
            host_id: "h-1".into(),
            key: format!("k:{}", id),
            kind: kind.into(),
            severity: sev,
            summary: format!("event {}", id),
            evidence: vec![],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn create_and_fetch_incident_with_timeline() {
        let p = pool().await;
        let inc = create_incident(
            &p,
            "rule:cfg:h-1",
            "h-1",
            "Critical",
            "Service became unhealthy after a configuration change",
            "A config change caused the failure.",
            &["Review the change".to_string()],
            &["h-1".to_string()],
        )
        .await
        .unwrap();
        link_events(
            &p,
            &inc.id,
            &[
                event("e-1", 1000, EventKind::FileChanged, Severity::Warning),
                event("e-2", 2000, EventKind::ServiceFailed, Severity::Critical),
            ],
        )
        .await
        .unwrap();
        let got = fetch_incident(&p, &inc.id)
            .await
            .unwrap()
            .expect("incident");
        assert_eq!(
            got.headline,
            "Service became unhealthy after a configuration change"
        );
        assert_eq!(got.status, IncidentStatus::Open);
        assert_eq!(got.timeline.len(), 2);
        assert_eq!(got.timeline[0].id, "e-2"); // (ts, id) order — ts desc
        assert_eq!(got.timeline[1].id, "e-1");
    }

    #[tokio::test]
    async fn linking_is_idempotent_per_event() {
        let p = pool().await;
        let inc = create_incident(&p, "key-1", "h-1", "Warning", "h", "c", &[], &[])
            .await
            .unwrap();
        link_events(
            &p,
            &inc.id,
            &[event("e-1", 1000, EventKind::CpuSpike, Severity::Warning)],
        )
        .await
        .unwrap();
        let n = link_events(
            &p,
            &inc.id,
            &[event("e-1", 1000, EventKind::CpuSpike, Severity::Warning)],
        )
        .await
        .unwrap();
        assert_eq!(n, 0, "duplicate link is a no-op");
        let got = fetch_incident(&p, &inc.id).await.unwrap().unwrap();
        assert_eq!(got.timeline.len(), 1);
    }

    #[tokio::test]
    async fn open_incident_with_same_key_is_returned() {
        let p = pool().await;
        create_incident(&p, "key-1", "h-1", "Warning", "h1", "c", &[], &[])
            .await
            .unwrap();
        let open = find_open_by_key(&p, "key-1").await.unwrap();
        assert!(open.is_some());
        let inc = create_incident(&p, "key-1", "h-1", "Warning", "h2", "c", &[], &[])
            .await
            .unwrap();
        let all: Vec<(String, String)> =
            sqlx::query_as("SELECT id, headline FROM incidents WHERE key = 'key-1'")
                .fetch_all(&p)
                .await
                .unwrap();
        assert_eq!(all.len(), 1, "absorb — no duplicate rows");
        assert_eq!(all[0].1, "h1", "existing incident is kept");
        assert_eq!(
            inc.headline, "h1",
            "create returns the EXISTING incident for the caller"
        );
    }
}
