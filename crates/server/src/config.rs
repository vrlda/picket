use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::probes::ProbeConfig;

/// TOML intermediate for `ServerConfig`: accepts both `[[probe]]` and
/// `[[probes]]` keys and merges them, so older docs keep working and no
/// config is silently dropped.
#[derive(Debug, Clone, Deserialize)]
struct ServerConfigToml {
    listen: Option<String>,
    db_url: Option<String>,
    auth_token: Option<String>,
    host_tokens: Option<HashMap<String, String>>,
    #[serde(default)]
    probe: Vec<ProbeConfig>,
    #[serde(default)]
    probes: Vec<ProbeConfig>,
    scan_interval_secs: Option<i64>,
    notify_min_interval_secs: Option<i64>,
    #[serde(default)]
    rule: Vec<crate::correlation::Rule>,
    rules: Option<Vec<crate::correlation::Rule>>,
    notify: Option<crate::notify::NotifyConfig>,
    watchdog_heartbeat_grace_secs: Option<i64>,
    watchdog_queue_threshold: Option<i64>,
    #[serde(default)]
    event_sources: HashMap<String, EventSourceConfig>,
    #[serde(default)]
    runners: HashMap<String, crate::dispatch::RunnerConfig>,
    #[serde(default)]
    agent_profiles: HashMap<String, crate::dispatch::AgentProfile>,
}

/// `[event_sources.<name>]`: an application allowed to post events with its
/// own token. `source` defaults to the table name; a non-empty
/// `environment` overrides the payload's.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EventSourceConfig {
    pub token: String,
    pub source: String,
    pub environment: String,
}

impl From<ServerConfigToml> for ServerConfig {
    fn from(t: ServerConfigToml) -> Self {
        let defaults = ServerConfig::default();
        let mut probes = t.probe;
        probes.extend(t.probes);
        let mut rules = t.rule;
        rules.extend(t.rules.unwrap_or_default());
        ServerConfig {
            listen: t.listen.unwrap_or(defaults.listen),
            db_url: t.db_url.unwrap_or(defaults.db_url),
            auth_token: t.auth_token.unwrap_or(defaults.auth_token),
            host_tokens: t.host_tokens.unwrap_or(defaults.host_tokens),
            probes,
            scan_interval_secs: t.scan_interval_secs.unwrap_or(defaults.scan_interval_secs),
            notify_min_interval_secs: t
                .notify_min_interval_secs
                .unwrap_or(defaults.notify_min_interval_secs),
            rules,
            notify: t.notify.unwrap_or(defaults.notify),
            watchdog_heartbeat_grace_secs: t
                .watchdog_heartbeat_grace_secs
                .unwrap_or(defaults.watchdog_heartbeat_grace_secs),
            watchdog_queue_threshold: t
                .watchdog_queue_threshold
                .unwrap_or(defaults.watchdog_queue_threshold),
            event_sources: t.event_sources,
            runners: t.runners,
            agent_profiles: t.agent_profiles,
        }
    }
}

/// Server configuration. SQLite in dev; Postgres later via the same sqlx API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "ServerConfigToml")]
pub struct ServerConfig {
    /// Socket address to listen on (agent ingest + API). Default localhost
    /// only; expose it through an HTTPS reverse proxy for remote agents.
    pub listen: String,
    /// sqlx database URL. "sqlite::memory:" works only for tests.
    pub db_url: String,
    /// Shared bearer token agents must present.
    pub auth_token: String,
    /// Per-host bearer tokens: presenting one attributes the agent to that
    /// host (its payload host_id is overridden — spoofing requires the token).
    #[serde(default)]
    pub host_tokens: HashMap<String, String>,
    /// External endpoints to probe for reachability. Accepts both
    /// `[[probe]]` and `[[probes]]` TOML keys (alias for docs compatibility).
    pub probes: Vec<ProbeConfig>,
    /// Correlation scan interval (seconds).
    #[serde(default = "default_scan_interval")]
    pub scan_interval_secs: i64,
    /// Minimum seconds between notifications per incident (absorb re-notify
    /// throttle).
    #[serde(default = "default_notify_min_interval")]
    pub notify_min_interval_secs: i64,
    /// Correlation rules; entries override built-in defaults by id.
    #[serde(default)]
    pub rules: Vec<crate::correlation::Rule>,
    /// Notification channels and per-severity routing.
    #[serde(default)]
    pub notify: crate::notify::NotifyConfig,
    /// Seconds a host may go without a heartbeat before the watchdog fires.
    #[serde(default = "default_heartbeat_grace")]
    pub watchdog_heartbeat_grace_secs: i64,
    /// Spool queue length that triggers AgentQueueGrowing.
    #[serde(default = "default_queue_threshold")]
    pub watchdog_queue_threshold: i64,
    /// Applications with their own event tokens (anti-spoofing).
    #[serde(default)]
    pub event_sources: HashMap<String, EventSourceConfig>,
    /// Agent runners allowed to connect, by runner id.
    #[serde(default)]
    pub runners: HashMap<String, crate::dispatch::RunnerConfig>,
    /// Agent profiles referenced by `[[rule.dispatch]] type = "agent"`.
    #[serde(default)]
    pub agent_profiles: HashMap<String, crate::dispatch::AgentProfile>,
}

fn default_heartbeat_grace() -> i64 {
    90
}

fn default_queue_threshold() -> i64 {
    100
}

fn default_scan_interval() -> i64 {
    10
}

fn default_notify_min_interval() -> i64 {
    60
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: "127.0.0.1:8787".into(),
            db_url: "sqlite:///var/lib/watchtower/watchtower.db".into(),
            auth_token: String::new(),
            host_tokens: HashMap::new(),
            probes: Vec::new(),
            scan_interval_secs: default_scan_interval(),
            notify_min_interval_secs: default_notify_min_interval(),
            rules: Vec::new(),
            notify: crate::notify::NotifyConfig::default(),
            watchdog_heartbeat_grace_secs: default_heartbeat_grace(),
            watchdog_queue_threshold: default_queue_threshold(),
            event_sources: HashMap::new(),
            runners: HashMap::new(),
            agent_profiles: HashMap::new(),
        }
    }
}

/// Apply the Telegram env overrides (the "1-2 line" setup):
/// TELEGRAM_BOT_TOKEN (required for the channel), the optional
/// TELEGRAM_CHAT_ID (pins the target chat; without it, the chat is
/// auto-discovered from the bot's updates), and the optional
/// TELEGRAM_BOT_PASSWORD (requires the password handshake before a chat
/// can register).
pub fn apply_telegram_env(
    cfg: &mut ServerConfig,
    token: Option<String>,
    chat: Option<String>,
    password: Option<String>,
) {
    if let Some(t) = token {
        cfg.notify.telegram_token = Some(t);
    }
    if let Some(c) = chat {
        match c.trim().parse::<i64>() {
            Ok(id) => cfg.notify.telegram_chat_id = Some(id),
            Err(_) => eprintln!("invalid TELEGRAM_CHAT_ID {:?} — ignoring", c),
        }
    }
    if let Some(p) = password {
        cfg.notify.telegram_password = Some(p);
    }
}

pub fn load(path: &PathBuf) -> ServerConfig {
    let mut cfg = match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).unwrap_or_else(|e| {
            eprintln!("invalid config {}: {}; using defaults", path.display(), e);
            ServerConfig::default()
        }),
        Err(e) => {
            eprintln!("no config at {} ({}); using defaults", path.display(), e);
            ServerConfig::default()
        }
    };
    apply_telegram_env(
        &mut cfg,
        std::env::var("TELEGRAM_BOT_TOKEN").ok(),
        std::env::var("TELEGRAM_CHAT_ID").ok(),
        std::env::var("TELEGRAM_BOT_PASSWORD").ok(),
    );
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_parses_with_defaults() {
        let raw = "listen = \"0.0.0.0:9999\"\nauth_token = \"tok\"\n";
        let cfg: ServerConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:9999");
        assert_eq!(cfg.auth_token, "tok");
        assert!(cfg.db_url.contains("watchtower.db"));
    }

    #[test]
    fn legacy_ui_base_url_is_ignored() {
        // configs written for the removed web UI must keep loading
        let raw = "auth_token = \"tok\"\nui_base_url = \"http://x\"\n";
        let cfg: ServerConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.auth_token, "tok");
    }

    #[test]
    fn probes_accept_both_toml_keys() {
        let raw = "[[probe]]\nurl = \"http://a\"\n[[probes]]\nurl = \"http://b\"\n";
        let cfg: ServerConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.probes.len(), 2);
        assert_eq!(cfg.probes[0].url, "http://a");
        assert_eq!(cfg.probes[1].url, "http://b");
    }

    #[test]
    fn rules_accept_both_toml_keys() {
        let raw = "[[rule]]\nid = \"a\"\ntrigger = \"CpuSpike\"\nseverity = \"Warning\"\nheadline = \"x\"\n[[rules]]\nid = \"b\"\ntrigger = \"CpuSpike\"\nseverity = \"Warning\"\nheadline = \"y\"\n";
        let cfg: ServerConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.rules.len(), 2);
        assert_eq!(cfg.rules[0].id, "a");
        assert_eq!(cfg.rules[1].id, "b");
    }

    #[test]
    fn telegram_env_overrides_apply() {
        let mut cfg = ServerConfig::default();
        apply_telegram_env(
            &mut cfg,
            Some("tok".into()),
            Some("12345".into()),
            Some("pw".into()),
        );
        assert_eq!(cfg.notify.telegram_token.as_deref(), Some("tok"));
        assert_eq!(cfg.notify.telegram_chat_id, Some(12345));
        assert_eq!(cfg.notify.telegram_password.as_deref(), Some("pw"));
        let mut cfg2 = ServerConfig::default();
        apply_telegram_env(&mut cfg2, Some("tok".into()), Some("abc".into()), None);
        assert_eq!(cfg2.notify.telegram_chat_id, None);
        assert_eq!(cfg2.notify.telegram_password, None);
    }
}
