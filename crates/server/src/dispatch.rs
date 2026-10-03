//! Dispatch: what happens once an incident exists. Notifications (Telegram,
//! Slack, webhook) and agent tasks are both dispatch actions.
//!
//! Agent tasks are durable rows in `agent_tasks`. Watchtower only queues
//! them; an external `watchtower-runner` (outbound HTTPS long-poll) claims
//! and executes them. Watchtower never runs agent code itself.

use serde::{Deserialize, Serialize};

/// One `[[rule.dispatch]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DispatchAction {
    /// Notify a channel ("telegram" | "slack" | "webhook") when `policy`
    /// says so.
    Notify {
        channel: String,
        #[serde(default)]
        policy: NotifyPolicy,
    },
    /// Queue an agent task for the named `[agent_profiles.<name>]`.
    Agent { profile: String },
}

/// When a notify action fires.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifyPolicy {
    /// Every incident change (throttled) and every agent milestone.
    #[default]
    Always,
    /// Incident opened / changed (the classic behaviour).
    OnOpen,
    OnAgentStart,
    /// Any agent outcome: success, failure or escalation.
    OnAgentResult,
    OnAgentSuccess,
    OnAgentFailure,
    OnEscalation,
    OnVerifiedResolution,
    Never,
}

/// Lifecycle moments a notification can be about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Moment {
    /// Incident opened or absorbed new events.
    Incident,
    AgentStarted,
    AgentSucceeded,
    AgentFailed,
    Escalation,
    VerifiedResolution,
}

impl NotifyPolicy {
    pub fn fires_on(self, m: Moment) -> bool {
        use Moment::*;
        match self {
            NotifyPolicy::Always => true,
            NotifyPolicy::Never => false,
            NotifyPolicy::OnOpen => m == Incident,
            NotifyPolicy::OnAgentStart => m == AgentStarted,
            NotifyPolicy::OnAgentResult => {
                matches!(m, AgentSucceeded | AgentFailed | Escalation)
            }
            NotifyPolicy::OnAgentSuccess => m == AgentSucceeded,
            NotifyPolicy::OnAgentFailure => matches!(m, AgentFailed | Escalation),
            NotifyPolicy::OnEscalation => m == Escalation,
            NotifyPolicy::OnVerifiedResolution => m == VerifiedResolution,
        }
    }
}

/// Channels to notify for a moment. Rules with notify actions route
/// explicitly; rules without them use the severity routing — except that an
/// agent-handled incident's own milestones (start, success) stay quiet
/// unless asked for, while failures, escalations and verified recovery
/// always reach a human.
pub fn channels_for_moment(
    actions: &[DispatchAction],
    severity_channels: &[String],
    m: Moment,
) -> Vec<String> {
    let explicit: Vec<&DispatchAction> = actions
        .iter()
        .filter(|a| matches!(a, DispatchAction::Notify { .. }))
        .collect();
    if explicit.is_empty() {
        let quiet = matches!(m, Moment::AgentStarted | Moment::AgentSucceeded);
        return if quiet {
            vec![]
        } else {
            severity_channels.to_vec()
        };
    }
    let mut out = Vec::new();
    for a in explicit {
        if let DispatchAction::Notify { channel, policy } = a {
            if policy.fires_on(m) && !out.contains(channel) {
                out.push(channel.clone());
            }
        }
    }
    out
}

/// `[auto_agent]`: hand every incident whose rule has no agent dispatch of
/// its own to one profile — autonomous response for the built-in incidents
/// (service down, disk full, ...) without writing rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoAgent {
    /// Agent profile ("" = off).
    pub profile: String,
    /// Lowest severity handed to the agent: "Info", "Warning" or "Critical".
    pub min_severity: String,
}

impl Default for AutoAgent {
    fn default() -> Self {
        AutoAgent {
            profile: String::new(),
            min_severity: "Warning".into(),
        }
    }
}

impl AutoAgent {
    /// The profile for an incident of this severity, if any.
    pub fn profile_for(&self, severity: &str) -> Option<&str> {
        let rank = |s: &str| match s {
            "Critical" => 2,
            "Warning" => 1,
            _ => 0,
        };
        (!self.profile.is_empty() && rank(severity) >= rank(&self.min_severity))
            .then_some(self.profile.as_str())
    }
}

/// Server-side `[agent_profiles.<name>]`: routing and loop limits only.
/// How the agent runs (adapter, workspace, prompt, allowed tools, blocked
/// paths) is configured on the runner machine — Watchtower never sends
/// commands or paths to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentProfile {
    /// Runner id that may take these tasks ("" = any runner with `labels`).
    pub runner: String,
    /// Labels a runner must all carry to take these tasks.
    pub labels: Vec<String>,
    /// Execution attempts per task (runner crash, timeout, lease expiry).
    pub max_attempts: u32,
    /// Agent tasks per incident before autonomous handling stops and a
    /// human is asked (fix → new failure → fix ... loop guard).
    pub max_tasks_per_incident: u32,
    /// Tasks per profile per hour before autonomous handling pauses.
    pub max_tasks_per_hour: u32,
    /// Seconds a claim stays valid without a lease renewal.
    pub lease_secs: i64,
    /// Seconds a queued task may wait for a runner before a human is told.
    pub unclaimed_alert_secs: i64,
    /// Seconds after an agent reported a fix within which recovery must be
    /// observed, else the fix counts as not verified.
    pub verify_timeout_secs: i64,
    /// Redact secrets (tokens, cookies, card numbers, ...) from the context
    /// given to the agent.
    pub redact: bool,
}

impl Default for AgentProfile {
    fn default() -> Self {
        AgentProfile {
            runner: String::new(),
            labels: Vec::new(),
            max_attempts: 2,
            max_tasks_per_incident: 2,
            max_tasks_per_hour: 6,
            lease_secs: 300,
            unclaimed_alert_secs: 300,
            verify_timeout_secs: 1800,
            redact: true,
        }
    }
}

/// `[runners.<id>]`: a runner allowed to connect.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RunnerConfig {
    pub token: String,
    pub labels: Vec<String>,
}

/// Task statuses. Active = queued | claimed | running |
/// awaiting_verification (at most one active task per incident).
pub mod status {
    pub const QUEUED: &str = "queued";
    pub const CLAIMED: &str = "claimed";
    pub const RUNNING: &str = "running";
    pub const AWAITING_VERIFICATION: &str = "awaiting_verification";
    pub const SUCCEEDED: &str = "succeeded";
    pub const NEEDS_HUMAN: &str = "needs_human";
    pub const FAILED: &str = "failed";
    pub const CANCELLED: &str = "cancelled";
    pub const ACTIVE_SQL: &str = "('queued', 'claimed', 'running', 'awaiting_verification')";
}

/// Dispatch tables. Idempotent; called from db::init_schema.
pub async fn init_schema(conn: &mut sqlx::AnyConnection, pg: bool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS agent_runners (
            id         TEXT PRIMARY KEY,
            labels_json TEXT NOT NULL DEFAULT '[]',
            capabilities_json TEXT NOT NULL DEFAULT '[]',
            version    TEXT NOT NULL DEFAULT '',
            last_seen  BIGINT NOT NULL,
            created_at BIGINT NOT NULL
        )",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS agent_tasks (
            id          TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            profile     TEXT NOT NULL,
            runner_id   TEXT NOT NULL DEFAULT '',
            status      TEXT NOT NULL,
            attempt     BIGINT NOT NULL DEFAULT 0,
            max_attempts BIGINT NOT NULL DEFAULT 2,
            lease_expires_at BIGINT,
            context_token_hash TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL DEFAULT '{}',
            result_json TEXT NOT NULL DEFAULT '',
            error       TEXT NOT NULL DEFAULT '',
            created_at  BIGINT NOT NULL,
            claimed_at  BIGINT,
            started_at  BIGINT,
            finished_at BIGINT,
            updated_at  BIGINT NOT NULL,
            alerted     BIGINT NOT NULL DEFAULT 0
        )",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query(&format!(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_tasks_active
         ON agent_tasks (incident_id) WHERE status IN {}",
        status::ACTIVE_SQL
    ))
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_agent_tasks_status ON agent_tasks (status, created_at)",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS incident_activity (
            id          TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            ts          BIGINT NOT NULL,
            type        TEXT NOT NULL,
            actor       TEXT NOT NULL DEFAULT '',
            summary     TEXT NOT NULL,
            data_json   TEXT NOT NULL DEFAULT '{}'
        )",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_incident_activity ON incident_activity (incident_id, ts)",
    )
    .execute(&mut *conn)
    .await?;
    crate::db::ensure_column(conn, pg, "incidents", "rule_id", "TEXT NOT NULL DEFAULT ''").await?;
    Ok(())
}

/// Append a system-generated entry to an incident's activity log (agent
/// lifecycle, human actions, notifications) — kept apart from monitored
/// events so the two are never confused.
pub async fn record_activity(
    pool: &sqlx::AnyPool,
    incident_id: &str,
    kind: &str,
    actor: &str,
    summary: &str,
    data: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO incident_activity (id, incident_id, ts, type, actor, summary, data_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(incident_id)
    .bind(crate::ingest::now_ms())
    .bind(kind)
    .bind(actor)
    .bind(summary)
    .bind(data.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Activity entries for an incident, oldest first.
pub async fn fetch_activity(
    pool: &sqlx::AnyPool,
    incident_id: &str,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (i64, String, String, String, String)>(
        "SELECT ts, type, actor, summary, data_json FROM incident_activity
         WHERE incident_id = $1 ORDER BY ts ASC, id",
    )
    .bind(incident_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(ts, kind, actor, summary, data)| {
            serde_json::json!({
                "ts": ts,
                "type": kind,
                "actor": actor,
                "summary": summary,
                "data": serde_json::from_str::<serde_json::Value>(&data).unwrap_or_default(),
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_actions_parse_from_toml() {
        #[derive(Deserialize)]
        struct R {
            dispatch: Vec<DispatchAction>,
        }
        let r: R = toml::from_str(
            r#"
            [[dispatch]]
            type = "agent"
            profile = "payment_api"
            [[dispatch]]
            type = "notify"
            channel = "telegram"
            policy = "on_agent_failure"
            [[dispatch]]
            type = "notify"
            channel = "slack"
            "#,
        )
        .unwrap();
        assert_eq!(
            r.dispatch[0],
            DispatchAction::Agent {
                profile: "payment_api".into()
            }
        );
        assert_eq!(
            r.dispatch[1],
            DispatchAction::Notify {
                channel: "telegram".into(),
                policy: NotifyPolicy::OnAgentFailure
            }
        );
        assert_eq!(
            r.dispatch[2],
            DispatchAction::Notify {
                channel: "slack".into(),
                policy: NotifyPolicy::Always
            }
        );
    }

    #[test]
    fn moment_routing() {
        let sev = vec!["telegram".to_string()];
        // no notify actions → severity routing; quiet agent milestones
        assert_eq!(channels_for_moment(&[], &sev, Moment::Incident), sev);
        assert!(channels_for_moment(&[], &sev, Moment::AgentSucceeded).is_empty());
        assert_eq!(channels_for_moment(&[], &sev, Moment::Escalation), sev);
        // explicit actions decide
        let actions = vec![
            DispatchAction::Agent {
                profile: "p".into(),
            },
            DispatchAction::Notify {
                channel: "telegram".into(),
                policy: NotifyPolicy::OnAgentFailure,
            },
        ];
        assert!(channels_for_moment(&actions, &sev, Moment::Incident).is_empty());
        assert_eq!(
            channels_for_moment(&actions, &sev, Moment::AgentFailed),
            vec!["telegram".to_string()]
        );
        assert_eq!(
            channels_for_moment(&actions, &sev, Moment::Escalation),
            vec!["telegram".to_string()]
        );
    }
}
