//! Durable agent tasks: creation from incidents (with dedup and loop
//! limits), runner claims with leases, results, retries, escalation,
//! verification of fixes against observed recovery, and the pipeline's own
//! health alerts.
//!
//! Task lifecycle:
//!   queued → claimed → running → succeeded | needs_human | failed
//!                              ↘ awaiting_verification → succeeded | failed
//! Execution failures (runner crash, timeout, lease lost) retry up to
//! `max_attempts`; an agent's own "needs a human" verdict never retries.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::app::AppState;
use crate::dispatch::{status, AgentProfile, Moment};
use crate::incidents::{self, Incident, IncidentStatus};
use crate::ingest::now_ms;

/// Columns of a task row, in `TaskRow` order.
const TASK_COLS: &str = "id, incident_id, profile, runner_id, status, attempt, max_attempts, \
     lease_expires_at, payload_json, result_json, error, created_at, claimed_at, started_at, \
     finished_at, alerted";

type TaskTuple = (
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    Option<i64>,
    String,
    String,
    String,
    i64,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    i64,
);

#[derive(Debug, Clone)]
pub struct TaskRow {
    pub id: String,
    pub incident_id: String,
    pub profile: String,
    pub runner_id: String,
    pub status: String,
    pub attempt: i64,
    pub max_attempts: i64,
    pub lease_expires_at: Option<i64>,
    pub payload: Value,
    pub result: Value,
    pub error: String,
    pub created_at: i64,
    pub claimed_at: Option<i64>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
    pub alerted: bool,
}

impl From<TaskTuple> for TaskRow {
    fn from(t: TaskTuple) -> Self {
        TaskRow {
            id: t.0,
            incident_id: t.1,
            profile: t.2,
            runner_id: t.3,
            status: t.4,
            attempt: t.5,
            max_attempts: t.6,
            lease_expires_at: t.7,
            payload: serde_json::from_str(&t.8).unwrap_or_default(),
            result: serde_json::from_str(&t.9).unwrap_or(Value::Null),
            error: t.10,
            created_at: t.11,
            claimed_at: t.12,
            started_at: t.13,
            finished_at: t.14,
            alerted: t.15 != 0,
        }
    }
}

impl TaskRow {
    pub fn summary_json(&self) -> Value {
        json!({
            "id": self.id,
            "incident_id": self.incident_id,
            "profile": self.profile,
            "runner_id": self.runner_id,
            "status": self.status,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "error": self.error,
            "result": self.result,
            "created_at": self.created_at,
            "claimed_at": self.claimed_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        })
    }
}

pub async fn get_task(pool: &sqlx::AnyPool, id: &str) -> Result<Option<TaskRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, TaskTuple>(&format!(
        "SELECT {TASK_COLS} FROM agent_tasks WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(TaskRow::from))
}

async fn tasks_where(
    pool: &sqlx::AnyPool,
    cond: &str,
    bind: &str,
) -> Result<Vec<TaskRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, TaskTuple>(&format!(
        "SELECT {TASK_COLS} FROM agent_tasks WHERE {cond} ORDER BY created_at ASC, id"
    ))
    .bind(bind)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(TaskRow::from).collect())
}

/// Task summaries for an incident, oldest first (API).
pub async fn tasks_for_incident(
    pool: &sqlx::AnyPool,
    incident_id: &str,
) -> Result<Vec<Value>, sqlx::Error> {
    Ok(tasks_where(pool, "incident_id = $1", incident_id)
        .await?
        .iter()
        .map(TaskRow::summary_json)
        .collect())
}

// ---------- dispatch ----------

#[derive(Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    Created(String),
    AlreadyActive,
    /// Autonomous handling refused; the reason is for humans.
    Limited(String),
    UnknownProfile,
}

/// Task payload (§ agent context): enough to orient the agent; the agent
/// pulls the rest through the task context API.
pub fn task_payload(task_id: &str, profile: &str, inc: &Value) -> Value {
    json!({
        "task_id": task_id,
        "incident_id": inc["id"],
        "profile": profile,
        "rule_id": inc["rule_id"],
        "severity": inc["severity"],
        "headline": inc["headline"],
        "cause": inc["cause"],
        "host_id": inc["host_id"],
        "sources": inc["sources"],
        "environments": inc["environments"],
        "subjects": inc["subjects"],
        "affected": inc["affected"],
        "event_summary": inc["event_kinds"],
        "event_count": inc["event_count"],
        "time_window": { "first_seen": inc["first_seen"], "last_seen": inc["last_seen"] },
        "recommended_actions": inc["actions"],
    })
}

/// True when some configured runner may take this profile's tasks.
pub fn profile_has_runner(state: &AppState, profile: &AgentProfile) -> bool {
    state
        .cfg
        .runners
        .iter()
        .any(|(id, r)| runner_matches(profile, id, &r.labels))
}

fn runner_matches(profile: &AgentProfile, runner_id: &str, labels: &[String]) -> bool {
    if !profile.runner.is_empty() && profile.runner != runner_id {
        return false;
    }
    profile.labels.iter().all(|l| labels.contains(l))
}

async fn count(pool: &sqlx::AnyPool, sql: &str, a: &str, b: i64) -> Result<i64, sqlx::Error> {
    let (n,): (i64,) = sqlx::query_as(sql).bind(a).bind(b).fetch_one(pool).await?;
    Ok(n)
}

async fn has_activity(pool: &sqlx::AnyPool, incident_id: &str, kind: &str) -> bool {
    sqlx::query_as::<_, (i64,)>(
        "SELECT count(*) FROM incident_activity WHERE incident_id = $1 AND type = $2",
    )
    .bind(incident_id)
    .bind(kind)
    .fetch_one(pool)
    .await
    .map(|(n,)| n > 0)
    .unwrap_or(false)
}

/// Queue an agent task for an incident unless one is active, a human is
/// already needed, or a loop limit is hit.
pub async fn dispatch_agent(
    state: &AppState,
    inc: &Incident,
    profile_name: &str,
) -> Result<DispatchOutcome, sqlx::Error> {
    let pool = &state.pool;
    let Some(profile) = state.cfg.agent_profiles.get(profile_name) else {
        eprintln!(
            "dispatch: rule {} references unknown agent profile {profile_name:?}",
            inc.rule_id
        );
        return Ok(DispatchOutcome::UnknownProfile);
    };
    if inc.status == IncidentStatus::Resolved {
        return Ok(DispatchOutcome::Limited("incident is resolved".into()));
    }
    let tasks = tasks_where(pool, "incident_id = $1", &inc.id).await?;
    if tasks
        .iter()
        .any(|t| status::ACTIVE_SQL.contains(&format!("'{}'", t.status)))
    {
        return Ok(DispatchOutcome::AlreadyActive);
    }
    if tasks
        .last()
        .is_some_and(|t| t.status == status::NEEDS_HUMAN)
    {
        return Ok(DispatchOutcome::Limited(
            "the agent asked for a human; not re-dispatching".into(),
        ));
    }
    if tasks.len() as u32 >= profile.max_tasks_per_incident.max(1) {
        return Ok(DispatchOutcome::Limited(format!(
            "{} agent task(s) already ran for this incident (max_tasks_per_incident)",
            tasks.len()
        )));
    }
    let hour_ago = now_ms() - 3_600_000;
    let recent = count(
        pool,
        "SELECT count(*) FROM agent_tasks WHERE profile = $1 AND created_at >= $2",
        profile_name,
        hour_ago,
    )
    .await?;
    if recent >= profile.max_tasks_per_hour.max(1) as i64 {
        return Ok(DispatchOutcome::Limited(format!(
            "profile {profile_name} hit max_tasks_per_hour ({})",
            profile.max_tasks_per_hour
        )));
    }
    let id = format!("agt_{}", uuid::Uuid::new_v4().simple());
    let full = incidents::fetch_incident(pool, &inc.id)
        .await?
        .unwrap_or_else(|| inc.clone());
    let payload = task_payload(
        &id,
        profile_name,
        &crate::api_incidents::incident_json(&full),
    );
    let now = now_ms();
    let res = sqlx::query(
        "INSERT INTO agent_tasks (id, incident_id, profile, status, attempt, max_attempts,
             payload_json, created_at, updated_at)
         VALUES ($1, $2, $3, 'queued', 0, $4, $5, $6, $6)",
    )
    .bind(&id)
    .bind(&inc.id)
    .bind(profile_name)
    .bind(profile.max_attempts.max(1) as i64)
    .bind(payload.to_string())
    .bind(now)
    .execute(pool)
    .await;
    match res {
        Ok(_) => {}
        // the partial unique index lost a race: someone else queued one
        Err(sqlx::Error::Database(e)) if e.message().to_lowercase().contains("unique") => {
            return Ok(DispatchOutcome::AlreadyActive)
        }
        Err(e) => return Err(e),
    }
    let note = if profile_has_runner(state, profile) {
        format!("Agent task queued (profile {profile_name})")
    } else {
        format!("Agent task queued (profile {profile_name}) — but no configured runner matches this profile")
    };
    crate::dispatch::record_activity(
        pool,
        &inc.id,
        "agent",
        "watchtower",
        &note,
        json!({ "task_id": id }),
    )
    .await?;
    state.task_notify.notify_waiters();
    Ok(DispatchOutcome::Created(id))
}

/// Run every agent dispatch action of the incident's rule. Returns a notice
/// for the incident notification ("Autonomous response: ...") and whether
/// it is news (a task was just queued or autonomy just stopped).
pub async fn dispatch_for_incident(state: &AppState, inc: &Incident) -> Option<(String, bool)> {
    let rule = state.rules.iter().find(|r| r.id == inc.rule_id)?;
    let mut notes = Vec::new();
    let mut news = false;
    for action in &rule.dispatch {
        let crate::dispatch::DispatchAction::Agent { profile } = action else {
            continue;
        };
        match dispatch_agent(state, inc, profile).await {
            Ok(DispatchOutcome::Created(_)) => {
                news = true;
                notes.push(format!(
                    "🤖 Autonomous response: agent assigned (profile {profile}), waiting for a runner"
                ));
            }
            Ok(DispatchOutcome::AlreadyActive) => {
                notes.push("🤖 Autonomous response: an agent is already on this incident".into());
            }
            Ok(DispatchOutcome::Limited(reason)) => {
                if !has_activity(&state.pool, &inc.id, "autonomy_stopped").await {
                    news = true;
                    let _ = crate::dispatch::record_activity(
                        &state.pool,
                        &inc.id,
                        "autonomy_stopped",
                        "watchtower",
                        &format!("Autonomous handling stopped: {reason}"),
                        json!({}),
                    )
                    .await;
                    notes.push(format!(
                        "⚠️ Autonomous handling stopped: {reason} — a human is needed"
                    ));
                }
            }
            Ok(DispatchOutcome::UnknownProfile) => {
                notes.push(format!("⚠️ Agent profile {profile:?} is not configured"));
            }
            Err(e) => eprintln!("dispatch failed for incident {}: {e}", inc.id),
        }
    }
    (!notes.is_empty()).then(|| (notes.join("\n"), news))
}

// ---------- notifications ----------

/// Notify the channels the incident's rule routes for this moment, with a
/// notice line on top of the incident summary.
pub async fn notify_moment(state: &AppState, incident_id: &str, moment: Moment, notice: &str) {
    let Ok(Some(inc)) = incidents::fetch_incident(&state.pool, incident_id).await else {
        return;
    };
    let mut json = crate::api_incidents::incident_json(&inc);
    let actions = state
        .rules
        .iter()
        .find(|r| r.id == inc.rule_id)
        .map(|r| r.dispatch.clone())
        .unwrap_or_default();
    let severity_channels = crate::notify::channels_for(&state.notify, &inc.severity);
    let channels = crate::dispatch::channels_for_moment(&actions, &severity_channels, moment);
    if channels.is_empty() {
        return;
    }
    json["_channels"] = json!(channels);
    json["_notice"] = json!({ "moment": moment, "text": notice });
    if let Err(e) = state.notify_tx.try_send(json) {
        eprintln!("notify queue full/closed — dropping {moment:?} notice for {incident_id}: {e}");
    }
}

// ---------- runner side ----------

pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn new_token() -> String {
    format!(
        "wtc_{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// Record a runner check-in (register + heartbeat).
pub async fn touch_runner(
    pool: &sqlx::AnyPool,
    runner_id: &str,
    version: &str,
    labels: &[String],
    capabilities: &[String],
) -> Result<(), sqlx::Error> {
    let now = now_ms();
    sqlx::query(
        "INSERT INTO agent_runners (id, labels_json, capabilities_json, version, last_seen, created_at)
         VALUES ($1, $2, $3, $4, $5, $5)
         ON CONFLICT(id) DO UPDATE SET labels_json = $2, capabilities_json = $3,
             version = $4, last_seen = $5",
    )
    .bind(runner_id)
    .bind(json!(labels).to_string())
    .bind(json!(capabilities).to_string())
    .bind(version)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// A task handed to a runner.
#[derive(Debug, Serialize)]
pub struct Claimed {
    pub task_id: String,
    pub incident_id: String,
    pub profile: String,
    pub attempt: i64,
    pub max_attempts: i64,
    pub lease_secs: i64,
    /// Bearer token for this task's context endpoints only; valid while the
    /// task is claimed/running.
    pub context_token: String,
    pub payload: Value,
}

/// Atomically claim the oldest queued task this runner may take.
pub async fn claim_next(state: &AppState, runner_id: &str) -> Result<Option<Claimed>, sqlx::Error> {
    let labels = state
        .cfg
        .runners
        .get(runner_id)
        .map(|r| r.labels.clone())
        .unwrap_or_default();
    let eligible: Vec<(&String, &AgentProfile)> = state
        .cfg
        .agent_profiles
        .iter()
        .filter(|(_, p)| runner_matches(p, runner_id, &labels))
        .collect();
    if eligible.is_empty() {
        return Ok(None);
    }
    let queued = sqlx::query_as::<_, (String, String, String, i64, i64, String)>(
        "SELECT id, incident_id, profile, attempt, max_attempts, payload_json
         FROM agent_tasks WHERE status = 'queued' ORDER BY created_at ASC, id LIMIT 50",
    )
    .fetch_all(&state.pool)
    .await?;
    for (id, incident_id, profile_name, attempt, max_attempts, payload) in queued {
        let Some((_, profile)) = eligible.iter().find(|(n, _)| **n == profile_name) else {
            continue;
        };
        let token = new_token();
        let now = now_ms();
        let res = sqlx::query(
            "UPDATE agent_tasks SET status = 'claimed', runner_id = $2, attempt = attempt + 1,
                 claimed_at = $3, started_at = NULL, lease_expires_at = $4,
                 context_token_hash = $5, error = '', updated_at = $3
             WHERE id = $1 AND status = 'queued'",
        )
        .bind(&id)
        .bind(runner_id)
        .bind(now)
        .bind(now + profile.lease_secs.max(30) * 1000)
        .bind(hash_token(&token))
        .execute(&state.pool)
        .await?;
        if res.rows_affected() != 1 {
            continue; // another runner won it
        }
        let _ = crate::dispatch::record_activity(
            &state.pool,
            &incident_id,
            "agent",
            runner_id,
            &format!("{runner_id} claimed agent task (attempt {})", attempt + 1),
            json!({ "task_id": id }),
        )
        .await;
        return Ok(Some(Claimed {
            task_id: id,
            incident_id,
            profile: profile_name,
            attempt: attempt + 1,
            max_attempts,
            lease_secs: profile.lease_secs.max(30),
            context_token: token,
            payload: serde_json::from_str(&payload).unwrap_or_default(),
        }));
    }
    Ok(None)
}

/// Long-poll: claim a task or wait (up to `timeout_secs`) for one.
pub async fn next_task(
    state: &AppState,
    runner_id: &str,
    timeout_secs: u64,
) -> Result<Option<Claimed>, sqlx::Error> {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs.min(60));
    loop {
        if let Some(t) = claim_next(state, runner_id).await? {
            return Ok(Some(t));
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        // wake on a new task, or re-check every 2s (requeued leases)
        let wait = (deadline - now).min(std::time::Duration::from_secs(2));
        let _ = tokio::time::timeout(wait, state.task_notify.notified()).await;
    }
}

/// Errors of runner-side task operations (mapped to HTTP statuses).
#[derive(Debug, PartialEq, Eq)]
pub enum TaskOpError {
    NotFound,
    /// Not this runner's task, or no longer claimed/running (lease lost,
    /// cancelled). The runner must stop working on it.
    Conflict(String),
    Db,
}

impl From<sqlx::Error> for TaskOpError {
    fn from(e: sqlx::Error) -> Self {
        eprintln!("agent task db error: {e}");
        TaskOpError::Db
    }
}

async fn owned_task(
    pool: &sqlx::AnyPool,
    id: &str,
    runner_id: &str,
) -> Result<TaskRow, TaskOpError> {
    let t = get_task(pool, id).await?.ok_or(TaskOpError::NotFound)?;
    if t.runner_id != runner_id {
        return Err(TaskOpError::Conflict(
            "task is not claimed by this runner".into(),
        ));
    }
    if t.status != status::CLAIMED && t.status != status::RUNNING {
        return Err(TaskOpError::Conflict(format!("task is {}", t.status)));
    }
    Ok(t)
}

fn profile_of(state: &AppState, t: &TaskRow) -> AgentProfile {
    state
        .cfg
        .agent_profiles
        .get(&t.profile)
        .cloned()
        .unwrap_or_default()
}

/// Renew the lease (runner heartbeat while the agent works).
pub async fn renew_lease(state: &AppState, id: &str, runner_id: &str) -> Result<i64, TaskOpError> {
    let t = owned_task(&state.pool, id, runner_id).await?;
    let lease = profile_of(state, &t).lease_secs.max(30);
    let until = now_ms() + lease * 1000;
    sqlx::query("UPDATE agent_tasks SET lease_expires_at = $2, updated_at = $3 WHERE id = $1")
        .bind(id)
        .bind(until)
        .bind(now_ms())
        .execute(&state.pool)
        .await?;
    Ok(lease)
}

/// The runner started the agent.
pub async fn mark_started(
    state: &AppState,
    id: &str,
    runner_id: &str,
    agent: &str,
) -> Result<(), TaskOpError> {
    let t = owned_task(&state.pool, id, runner_id).await?;
    let now = now_ms();
    sqlx::query(
        "UPDATE agent_tasks SET status = 'running', started_at = $2, updated_at = $2 WHERE id = $1",
    )
    .bind(id)
    .bind(now)
    .execute(&state.pool)
    .await?;
    let agent = if agent.is_empty() { "agent" } else { agent };
    let note = format!("{agent} investigation started on {runner_id}");
    crate::dispatch::record_activity(
        &state.pool,
        &t.incident_id,
        "agent",
        runner_id,
        &note,
        json!({ "task_id": id }),
    )
    .await?;
    notify_moment(
        state,
        &t.incident_id,
        Moment::AgentStarted,
        &format!("🤖 {note}"),
    )
    .await;
    Ok(())
}

/// Structured agent result (all fields optional except `outcome`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentResult {
    /// "fixed" (changes made/deployed), "no_change" (diagnosed, nothing to
    /// change: e.g. a merchant integration problem) or "needs_human".
    pub outcome: String,
    /// platform_bug | configuration | infrastructure | client_integration |
    /// invalid_input | external_provider | other
    pub classification: String,
    pub summary: String,
    pub root_cause: String,
    pub actions: Vec<String>,
    pub needs_human_reason: String,
    pub changes: Value,
    pub tests: Value,
    pub deployment: Value,
    /// Advisory only — never a control.
    pub confidence: Option<f64>,
}

const MAX_RESULT_BYTES: usize = 64 * 1024;

/// The agent finished. A "fixed" outcome on a rule with recovery waits for
/// Watchtower to observe recovery; the incident itself is never resolved
/// on the agent's word.
pub async fn complete(
    state: &AppState,
    id: &str,
    runner_id: &str,
    result: AgentResult,
) -> Result<String, TaskOpError> {
    let t = owned_task(&state.pool, id, runner_id).await?;
    let mut result_json = serde_json::to_value(&result).unwrap_or_default();
    if result_json.to_string().len() > MAX_RESULT_BYTES {
        result_json = json!({
            "outcome": result.outcome,
            "classification": result.classification,
            "summary": crate::notify::truncate_chars(&result.summary, 4000),
            "truncated": true,
        });
    }
    let inc = incidents::fetch_incident(&state.pool, &t.incident_id).await?;
    let has_recovery = inc
        .as_ref()
        .and_then(|i| state.rules.iter().find(|r| r.id == i.rule_id))
        .is_some_and(|r| r.recovery.is_some());
    let resolved = inc
        .as_ref()
        .is_some_and(|i| i.status == IncidentStatus::Resolved);
    let (new_status, moment) = match result.outcome.as_str() {
        "needs_human" => (status::NEEDS_HUMAN, Moment::Escalation),
        "fixed" if has_recovery && !resolved => {
            (status::AWAITING_VERIFICATION, Moment::AgentSucceeded)
        }
        _ => (status::SUCCEEDED, Moment::AgentSucceeded),
    };
    let now = now_ms();
    sqlx::query(
        "UPDATE agent_tasks SET status = $2, result_json = $3, finished_at = $4, updated_at = $4,
             lease_expires_at = NULL
         WHERE id = $1",
    )
    .bind(id)
    .bind(new_status)
    .bind(result_json.to_string())
    .bind(now)
    .execute(&state.pool)
    .await?;
    let mut lines = vec![];
    let head = match new_status {
        status::NEEDS_HUMAN => "🙋 Agent needs a human",
        status::AWAITING_VERIFICATION => {
            "🛠 Agent reports a fix — waiting for Watchtower to observe recovery"
        }
        _ if result.outcome == "fixed" => "🛠 Agent reports a fix",
        _ => "🔎 Agent finished its investigation",
    };
    lines.push(head.to_string());
    if !result.classification.is_empty() {
        lines.push(format!("classification: {}", result.classification));
    }
    for (label, v) in [
        ("diagnosis", &result.summary),
        ("root cause", &result.root_cause),
    ] {
        if !v.is_empty() {
            lines.push(format!(
                "{label}: {}",
                crate::notify::truncate_chars(v, 600)
            ));
        }
    }
    for a in result.actions.iter().take(8) {
        lines.push(format!(" • {}", crate::notify::truncate_chars(a, 200)));
    }
    if new_status == status::NEEDS_HUMAN && !result.needs_human_reason.is_empty() {
        lines.push(format!(
            "needed from you: {}",
            crate::notify::truncate_chars(&result.needs_human_reason, 600)
        ));
    }
    let notice = lines.join("\n");
    crate::dispatch::record_activity(
        &state.pool,
        &t.incident_id,
        "agent",
        runner_id,
        &notice,
        json!({ "task_id": id, "result": result_json }),
    )
    .await?;
    notify_moment(state, &t.incident_id, moment, &notice).await;
    Ok(new_status.to_string())
}

/// Execution failed. Retryable failures (runner/infra problems) requeue
/// until max_attempts; the rest fail the task and tell a human.
pub async fn fail(
    state: &AppState,
    id: &str,
    runner_id: &str,
    error: &str,
    retryable: bool,
) -> Result<String, TaskOpError> {
    let t = owned_task(&state.pool, id, runner_id).await?;
    let error = crate::notify::truncate_chars(error, 2000);
    finish_failed(state, &t, &error, retryable, runner_id).await
}

async fn finish_failed(
    state: &AppState,
    t: &TaskRow,
    error: &str,
    retryable: bool,
    actor: &str,
) -> Result<String, TaskOpError> {
    let now = now_ms();
    if retryable && t.attempt < t.max_attempts {
        sqlx::query(
            "UPDATE agent_tasks SET status = 'queued', runner_id = '', lease_expires_at = NULL,
                 context_token_hash = '', error = $2, updated_at = $3
             WHERE id = $1",
        )
        .bind(&t.id)
        .bind(error)
        .bind(now)
        .execute(&state.pool)
        .await?;
        crate::dispatch::record_activity(
            &state.pool,
            &t.incident_id,
            "agent",
            actor,
            &format!("Agent attempt {} failed ({error}); retrying", t.attempt),
            json!({ "task_id": t.id }),
        )
        .await?;
        state.task_notify.notify_waiters();
        return Ok(status::QUEUED.into());
    }
    sqlx::query(
        "UPDATE agent_tasks SET status = 'failed', error = $2, finished_at = $3, updated_at = $3,
             lease_expires_at = NULL, context_token_hash = ''
         WHERE id = $1",
    )
    .bind(&t.id)
    .bind(error)
    .bind(now)
    .execute(&state.pool)
    .await?;
    let notice = format!(
        "❌ Autonomous response failed after {} attempt(s): {error}",
        t.attempt.max(1)
    );
    crate::dispatch::record_activity(
        &state.pool,
        &t.incident_id,
        "agent",
        actor,
        &notice,
        json!({ "task_id": t.id }),
    )
    .await?;
    notify_moment(state, &t.incident_id, Moment::AgentFailed, &notice).await;
    Ok(status::FAILED.into())
}

/// Resolve a task context token to its (active) task.
pub async fn task_for_context_token(
    pool: &sqlx::AnyPool,
    id: &str,
    token: &str,
) -> Result<Option<TaskRow>, sqlx::Error> {
    let Some(t) = get_task(pool, id).await? else {
        return Ok(None);
    };
    let (hash,): (String,) =
        sqlx::query_as("SELECT context_token_hash FROM agent_tasks WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await?;
    let active = t.status == status::CLAIMED || t.status == status::RUNNING;
    if active && !hash.is_empty() && crate::auth::token_eq(&hash_token(token), &hash) {
        Ok(Some(t))
    } else {
        Ok(None)
    }
}

// ---------- sweeper: leases, stuck tasks, verification, recovery ----------

pub fn spawn_sweeper(state: AppState) {
    tokio::spawn(crate::supervise::spawn_supervised(
        "agent-tasks",
        move || sweep_loop(state.clone()),
    ));
}

async fn sweep_loop(state: AppState) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));
    loop {
        ticker.tick().await;
        if let Err(e) = sweep(&state, now_ms()).await {
            eprintln!("agent task sweep failed: {e}");
        }
    }
}

/// One maintenance pass (public for tests).
pub async fn sweep(state: &AppState, now: i64) -> Result<(), sqlx::Error> {
    let pool = &state.pool;
    let active = tasks_where(
        pool,
        "status IN ('queued', 'claimed', 'running', 'awaiting_verification') AND id != $1",
        "",
    )
    .await?;
    let mut incidents_cache: HashMap<String, Option<Incident>> = HashMap::new();
    for t in &active {
        let inc = match incidents_cache.get(&t.incident_id) {
            Some(i) => i.clone(),
            None => {
                let i = incidents::fetch_incident(pool, &t.incident_id).await?;
                incidents_cache.insert(t.incident_id.clone(), i.clone());
                i
            }
        };
        let resolved = inc
            .as_ref()
            .is_none_or(|i| i.status == IncidentStatus::Resolved);
        let profile = profile_of(state, t);
        match t.status.as_str() {
            // a human resolved the incident: stop autonomous work
            s if resolved && s != status::AWAITING_VERIFICATION => {
                sqlx::query(
                    "UPDATE agent_tasks SET status = 'cancelled', finished_at = $2, updated_at = $2,
                         lease_expires_at = NULL, context_token_hash = '', error = 'incident resolved'
                     WHERE id = $1",
                )
                .bind(&t.id)
                .bind(now)
                .execute(pool)
                .await?;
                let _ = crate::dispatch::record_activity(
                    pool,
                    &t.incident_id,
                    "agent",
                    "watchtower",
                    "Agent task cancelled: incident resolved",
                    json!({ "task_id": t.id }),
                )
                .await;
            }
            status::CLAIMED | status::RUNNING if t.lease_expires_at.is_some_and(|l| l < now) => {
                let _ = finish_failed(
                    state,
                    t,
                    "runner lease expired (runner offline or crashed)",
                    true,
                    "watchtower",
                )
                .await;
            }
            status::QUEUED
                if !t.alerted
                    && now - t.created_at > profile.unclaimed_alert_secs.max(30) * 1000 =>
            {
                sqlx::query("UPDATE agent_tasks SET alerted = 1 WHERE id = $1")
                    .bind(&t.id)
                    .execute(pool)
                    .await?;
                let why = if profile_has_runner(state, &profile) {
                    "no runner has picked it up — is the runner offline?"
                } else {
                    "no configured runner matches its profile"
                };
                let notice = format!(
                    "⚠️ Agent task waiting {} min: {why}",
                    (now - t.created_at) / 60_000
                );
                let _ = crate::dispatch::record_activity(
                    pool,
                    &t.incident_id,
                    "agent",
                    "watchtower",
                    &notice,
                    json!({ "task_id": t.id }),
                )
                .await;
                notify_moment(state, &t.incident_id, Moment::AgentFailed, &notice).await;
            }
            status::AWAITING_VERIFICATION => {
                let finished = t.finished_at.unwrap_or(t.created_at);
                if resolved {
                    // recovery pass below marks it; a manual resolve counts too
                    mark_verified(state, t, "incident resolved").await?;
                } else if now - finished > profile.verify_timeout_secs.max(60) * 1000 {
                    sqlx::query(
                        "UPDATE agent_tasks SET status = 'failed', error = $2, updated_at = $3 WHERE id = $1",
                    )
                    .bind(&t.id)
                    .bind("fix not verified: recovery was not observed")
                    .bind(now)
                    .execute(pool)
                    .await?;
                    let notice = format!(
                        "❌ Agent's fix not verified: the problem was still observed {} min after it reported success",
                        (now - finished) / 60_000
                    );
                    let _ = crate::dispatch::record_activity(
                        pool,
                        &t.incident_id,
                        "agent",
                        "watchtower",
                        &notice,
                        json!({ "task_id": t.id }),
                    )
                    .await;
                    notify_moment(state, &t.incident_id, Moment::AgentFailed, &notice).await;
                }
            }
            _ => {}
        }
    }
    recovery_pass(state, now).await
}

async fn mark_verified(state: &AppState, t: &TaskRow, why: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE agent_tasks SET status = 'succeeded', updated_at = $2 WHERE id = $1 AND status = 'awaiting_verification'")
        .bind(&t.id)
        .bind(now_ms())
        .execute(&state.pool)
        .await?;
    let _ = crate::dispatch::record_activity(
        &state.pool,
        &t.incident_id,
        "agent",
        "watchtower",
        &format!("Agent fix verified ({why})"),
        json!({ "task_id": t.id }),
    )
    .await;
    Ok(())
}

/// Resolve open incidents whose rule has `[rule.recovery]` once no linked
/// event arrived for the recovery window — the observed-state check that
/// turns an agent's "fixed" into a verified fix.
async fn recovery_pass(state: &AppState, now: i64) -> Result<(), sqlx::Error> {
    let with_recovery: Vec<(&str, i64)> = state
        .rules
        .iter()
        .filter_map(|r| {
            r.recovery
                .as_ref()
                .map(|rc| (r.id.as_str(), rc.window_secs.max(1)))
        })
        .collect();
    for (rule_id, window) in with_recovery {
        let open = sqlx::query_as::<_, (String, Option<i64>)>(
            "SELECT i.id, (SELECT max(e.ts) FROM incident_events ie JOIN events e ON e.id = ie.event_id
                           WHERE ie.incident_id = i.id)
             FROM incidents i WHERE i.rule_id = $1 AND i.status != 'resolved'",
        )
        .bind(rule_id)
        .fetch_all(&state.pool)
        .await?;
        for (incident_id, last_seen) in open {
            let Some(last_seen) = last_seen else { continue };
            if now - last_seen < window * 1000 {
                continue;
            }
            if !incidents::set_status_at(&state.pool, &incident_id, IncidentStatus::Resolved, now)
                .await?
            {
                continue;
            }
            let note = format!(
                "✅ Recovery verified: no matching events for {window}s — incident resolved"
            );
            crate::dispatch::record_activity(
                &state.pool,
                &incident_id,
                "incident",
                "watchtower",
                &note,
                json!({}),
            )
            .await?;
            for t in tasks_where(&state.pool, "incident_id = $1", &incident_id).await? {
                if t.status == status::AWAITING_VERIFICATION {
                    mark_verified(state, &t, "recovery observed").await?;
                }
            }
            notify_moment(state, &incident_id, Moment::VerifiedResolution, &note).await;
        }
    }
    Ok(())
}
