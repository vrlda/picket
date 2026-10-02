use serde::{Deserialize, Serialize};

pub mod civil;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    #[default]
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EventKind {
    Reboot,
    ServiceFailed,
    ServiceCrashLoop,
    DiskHigh,
    InodeHigh,
    CpuSpike,
    MemHigh,
    LoadHigh,
    SwapHigh,
    NetDevErrors,
    /// Emitted by the server's uptime checker, not the agent.
    HostUnreachable,
    /// SSH login that succeeded (Info; Warning on a first-seen source IP).
    SshLogin,
    /// A failed SSH authentication attempt (Warning; episodes escalate to
    /// SshBruteForce).
    SshFailed,
    /// >= threshold failed SSH logins for one (user, ip) within a window.
    SshBruteForce,
    /// A login as root over ssh or su (Warning; Critical on first-seen IP).
    RootLogin,
    /// A successful sudo invocation (Info — timeline context).
    SudoUsed,
    /// A configured important file changed (Warning).
    FileChanged,
    /// A new listening port appeared (Warning).
    NewListeningPort,
    /// A connection to a previously unseen remote IP (Warning).
    NewOutboundConnection,
    /// Established-connection rate deviated from the rolling baseline (Warning).
    ConnectionRateSpike,
    /// Many distinct new remote connections within a short window — likely
    /// a port scan (Warning).
    PortScanSpike,
    /// A systemd unit transitioned to active (Info — timeline context).
    /// Emitted by the agent's journald sensor.
    ServiceRestarted,
    /// Server-generated: a host's heartbeat stopped arriving within the
    /// grace period (Critical).
    AgentHeartbeatMissing,
    /// Server-generated: a host's telemetry spool queue is growing (Warning).
    AgentQueueGrowing,
    /// Error-pattern count in application logs exceeded the threshold
    /// within the window (Warning).
    ErrorRateSpike,
    /// A tracked container stopped or exited (Warning).
    ContainerStopped,
    /// A container is crash-looping (restarting repeatedly) (Critical).
    ContainerCrashLoop,
    /// A TLS certificate is nearing expiry or expired (Warning/Critical).
    CertExpiring,
    /// The kernel OOM killer terminated a process (Critical).
    OomKill,
    /// Kernel panic evidence in the journal (Critical).
    KernelPanic,
    /// A mounted filesystem went read-only (Critical).
    FsReadOnly,
    /// The system clock was adjusted (NTP step) (Warning).
    ClockChange,
    /// Request volume from access logs exceeded the threshold within the
    /// window (Warning).
    RequestRateSpike,
    /// A user account was created/modified/deleted (Warning).
    NewUser,
    /// A package was installed, upgraded, or removed (Info).
    PackageInstalled,
    /// Cron or systemd unit files under /etc changed (Warning).
    PersistenceChanged,
    /// A process executed from a suspicious location or with reverse-shell
    /// characteristics (Critical).
    SuspiciousExec,
    /// An executable from a non-system path not seen in the baseline (Warning).
    UnexpectedExec,
    /// An in-app exception captured from an SDK via POST /v1/errors (severity
    /// derived from the exception level; incidents grouped by fingerprint).
    AppException,
}

/// Event type: a built-in Watchtower kind (closed set, PascalCase on the
/// wire, e.g. "ServiceFailed") or an application-defined custom kind (open
/// set, dotted lowercase, e.g. "payment.request_failed"). Serialized as a
/// plain string either way.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventType {
    Builtin(EventKind),
    Custom(String),
}

/// Max length of a custom event kind.
pub const MAX_CUSTOM_KIND_LEN: usize = 128;

/// Validate a custom event kind: 1..=128 chars of `[a-z0-9._-]`, starting
/// with a letter or digit, containing at least one '.' (a namespace, e.g.
/// "payment.failed"). The required dot also guarantees a custom kind can
/// never collide with — or impersonate — a built-in PascalCase kind.
pub fn validate_custom_kind(s: &str) -> Result<(), String> {
    if s.is_empty() || s.len() > MAX_CUSTOM_KIND_LEN {
        return Err(format!(
            "custom kind must be 1..={MAX_CUSTOM_KIND_LEN} characters"
        ));
    }
    if !s.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return Err("custom kind must start with a lowercase letter or digit".into());
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err("custom kind may only contain a-z, 0-9, '.', '_' and '-'".into());
    }
    if !s.contains('.') {
        return Err("custom kind needs a namespace, e.g. \"payment.failed\"".into());
    }
    Ok(())
}

impl EventType {
    /// Parse a wire string: a built-in kind name, else a valid custom kind.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Ok(k) = serde_json::from_value::<EventKind>(serde_json::Value::String(s.into())) {
            return Ok(EventType::Builtin(k));
        }
        validate_custom_kind(s).map_err(|e| format!("unknown event kind {s:?}: {e}"))?;
        Ok(EventType::Custom(s.to_string()))
    }

    pub fn is_custom(&self) -> bool {
        matches!(self, EventType::Custom(_))
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::Builtin(k) => {
                let v = serde_json::to_value(k).map_err(|_| std::fmt::Error)?;
                f.write_str(v.as_str().unwrap_or_default())
            }
            EventType::Custom(s) => f.write_str(s),
        }
    }
}

impl From<EventKind> for EventType {
    fn from(k: EventKind) -> Self {
        EventType::Builtin(k)
    }
}

impl PartialEq<EventKind> for EventType {
    fn eq(&self, other: &EventKind) -> bool {
        matches!(self, EventType::Builtin(k) if k == other)
    }
}

impl Default for EventType {
    fn default() -> Self {
        EventType::Builtin(EventKind::ServiceFailed)
    }
}

impl Serialize for EventType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for EventType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        EventType::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// unix millis
    pub ts: i64,
    pub source: String,
    pub detail: String,
}

/// One event. Host agents send built-in kinds; applications send custom
/// kinds (POST /v1/events) with optional structured context. The context
/// fields are omitted from the wire when empty, so host-agent payloads are
/// unchanged.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentEvent {
    pub id: String,
    /// unix millis
    pub ts: i64,
    pub host_id: String,
    /// Dedup key within a kind, e.g. "svc:nginx" or "mount:/".
    pub key: String,
    pub kind: EventType,
    pub severity: Severity,
    pub summary: String,
    pub evidence: Vec<Evidence>,
    /// Producing application/service, e.g. "payment-api".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// Deployment environment, e.g. "production".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub environment: String,
    /// What the event is about, e.g. "merchant:mer_123".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub subject: String,
    /// Dimensions/context (merchant_id, endpoint, provider, ...).
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub attributes: serde_json::Map<String, serde_json::Value>,
    /// Numeric values rules can evaluate (failure_rate, attempts, ...).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub measurements: std::collections::BTreeMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    pub host_id: String,
    /// unix millis
    pub ts: i64,
    pub version: String,
    pub queue_len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub host_id: String,
    pub server_url: String,
    pub token: String,
    pub poll_interval_secs: u64,
    pub heartbeat_secs: u64,
    pub dedup_secs: i64,
    pub disk_warn_pct: f64,
    pub disk_crit_pct: f64,
    pub inode_crit_pct: f64,
    pub load_warn_ratio: f64,
    pub load_crit_ratio: f64,
    pub cpu_spike_ratio: f64,
    pub mem_warn_pct: f64,
    pub swap_warn_pct: f64,
    pub spool_dir: String,
    /// Files (absolute paths) watched for modification by the FIM sensor.
    #[serde(default)]
    pub watch_paths: Vec<String>,
    /// Auto-watch authorized_keys files (root + /home/*) for modification.
    pub watch_authorized_keys: bool,
    /// Regex patterns counted as application errors in journald lines.
    #[serde(default)]
    pub error_patterns: Vec<String>,
    /// Seconds window for error counting.
    pub error_window_secs: i64,
    /// Errors within the window that trigger an ErrorRateSpike.
    pub error_threshold: u32,
    /// Watch Docker container states (docker binary required).
    pub docker_enabled: bool,
    /// Certificate paths (files or globs) to scan for expiry. Defaults to
    /// common locations when empty.
    #[serde(default)]
    pub cert_paths: Vec<String>,
    /// Days before expiry that raise a Warning.
    pub cert_warn_days: i64,
    /// Days before expiry that raise a Critical.
    pub cert_crit_days: i64,
    /// Seconds between certificate scans (they spawn openssl per cert).
    pub cert_scan_interval_secs: i64,
    /// Failed logins for one (user, ip) within the window that constitute a
    /// brute-force episode.
    pub ssh_brute_threshold: u32,
    /// Seconds window for brute-force counting.
    pub ssh_brute_window_secs: u64,
    /// Access log files (nginx/apache combined format) to tail for 5xx and
    /// request-rate signals. Empty = sensor off.
    #[serde(default)]
    pub access_log_paths: Vec<String>,
    /// Requests within the window that trigger a RequestRateSpike.
    pub request_rate_threshold: u32,
    /// Seconds window for request-rate counting.
    pub request_rate_window_secs: i64,
    /// Distinct remote connections within the window that indicate a port
    /// scan.
    pub scan_threshold: u32,
    /// Seconds window for scan counting.
    pub scan_window_secs: i64,
    /// Seconds between process-snapshot scans (suspicious exec detection).
    pub process_scan_interval_secs: i64,
    /// Agent state file (seen-IPs, journal cursor, baselines) — persisted
    /// across restarts. Empty = no persistence.
    #[serde(default = "default_state_file")]
    pub state_file: String,
}

/// Default agent state path (matches the install layout).
fn default_state_file() -> String {
    "/var/lib/watchtower/agent-state.json".into()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            host_id: "auto".into(),
            server_url: String::new(),
            token: String::new(),
            poll_interval_secs: 15,
            heartbeat_secs: 30,
            dedup_secs: 300,
            disk_warn_pct: 80.0,
            disk_crit_pct: 90.0,
            inode_crit_pct: 90.0,
            load_warn_ratio: 2.0,
            load_crit_ratio: 4.0,
            cpu_spike_ratio: 2.5,
            mem_warn_pct: 85.0,
            swap_warn_pct: 50.0,
            spool_dir: "/var/lib/watchtower/spool".into(),
            watch_paths: Vec::new(),
            watch_authorized_keys: true,
            error_patterns: Vec::new(),
            error_window_secs: 300,
            error_threshold: 10,
            docker_enabled: true,
            cert_paths: Vec::new(),
            cert_warn_days: 14,
            cert_crit_days: 3,
            cert_scan_interval_secs: 3600,
            ssh_brute_threshold: 5,
            ssh_brute_window_secs: 300,
            access_log_paths: Vec::new(),
            request_rate_threshold: 200,
            request_rate_window_secs: 60,
            scan_threshold: 25,
            scan_window_secs: 10,
            process_scan_interval_secs: 30,
            state_file: "/var/lib/watchtower/agent-state.json".into(),
        }
    }
}

impl Config {
    pub fn host_id_valid(&self) -> bool {
        !self.host_id.trim().is_empty() && !self.host_id.trim().eq_ignore_ascii_case("auto")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes_to_expected_json_shape() {
        let ev = AgentEvent {
            id: "e-1".into(),
            ts: 1000,
            host_id: "h-1".into(),
            key: "svc:nginx".into(),
            kind: EventKind::ServiceFailed.into(),
            severity: Severity::Critical,
            summary: "nginx.service entered failed state".into(),
            evidence: vec![Evidence {
                ts: 999,
                source: "systemd".into(),
                detail: "ActiveState=failed".into(),
            }],
            ..Default::default()
        };
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["kind"], "ServiceFailed");
        assert_eq!(v["severity"], "Critical");
        assert_eq!(v["evidence"][0]["source"], "systemd");
    }

    #[test]
    fn host_unreachable_kind_serializes() {
        let v: serde_json::Value = serde_json::to_value(EventKind::HostUnreachable).unwrap();
        assert_eq!(v, "HostUnreachable");
    }

    #[test]
    fn severity_ordering_critical_gt_warning_gt_info() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
    }

    #[test]
    fn heartbeat_serializes() {
        let hb = Heartbeat {
            host_id: "h-1".into(),
            ts: 5,
            version: "0.1.0".into(),
            queue_len: 2,
        };
        let v: serde_json::Value = serde_json::to_value(&hb).unwrap();
        assert_eq!(v["queue_len"], 2);
    }

    #[test]
    fn config_parses_with_defaults() {
        let raw = "server_url = \"https://ctl.example.com\"\ntoken = \"abc\"\n";
        let cfg: Config = toml::from_str(raw).unwrap();
        assert_eq!(cfg.server_url, "https://ctl.example.com");
        assert_eq!(cfg.poll_interval_secs, 15);
        assert_eq!(cfg.disk_crit_pct, 90.0);
    }

    #[test]
    fn state_file_defaults_to_install_path() {
        let cfg: Config =
            toml::from_str("server_url = \"https://ctl.example.com\"\ntoken = \"abc\"\n").unwrap();
        assert_eq!(cfg.state_file, "/var/lib/watchtower/agent-state.json");
        let cfg: Config = toml::from_str(
            "server_url = \"https://ctl.example.com\"\ntoken = \"abc\"\n\
             state_file = \"/tmp/agent-state.json\"\n",
        )
        .unwrap();
        assert_eq!(cfg.state_file, "/tmp/agent-state.json");
    }

    #[test]
    fn host_id_auto_is_invalid_for_shipping() {
        let cfg = Config::default();
        assert!(!cfg.host_id_valid());
    }

    #[test]
    fn host_id_valid_accepts_real_id_rejects_whitespace() {
        let cfg = Config {
            host_id: "abc123".into(),
            ..Config::default()
        };
        assert!(cfg.host_id_valid());
        let cfg = Config {
            host_id: "  ".into(),
            ..Config::default()
        };
        assert!(!cfg.host_id_valid());
        let cfg = Config {
            host_id: "Auto".into(),
            ..Config::default()
        };
        assert!(!cfg.host_id_valid());
    }

    #[test]
    fn security_kinds_serialize() {
        for (kind, expected) in [
            (EventKind::SshLogin, "SshLogin"),
            (EventKind::SshFailed, "SshFailed"),
            (EventKind::SshBruteForce, "SshBruteForce"),
            (EventKind::RootLogin, "RootLogin"),
            (EventKind::SudoUsed, "SudoUsed"),
            (EventKind::FileChanged, "FileChanged"),
            (EventKind::NewListeningPort, "NewListeningPort"),
            (EventKind::NewOutboundConnection, "NewOutboundConnection"),
            (EventKind::ConnectionRateSpike, "ConnectionRateSpike"),
        ] {
            let v: serde_json::Value = serde_json::to_value(kind).unwrap();
            assert_eq!(v, expected);
        }
    }

    #[test]
    fn config_has_security_fields() {
        let cfg = Config::default();
        assert_eq!(cfg.ssh_brute_threshold, 5);
        assert_eq!(cfg.ssh_brute_window_secs, 300);
        assert!(cfg.watch_paths.is_empty());
    }

    #[test]
    fn m4_kinds_serialize() {
        for (kind, expected) in [
            (EventKind::ServiceRestarted, "ServiceRestarted"),
            (EventKind::AgentHeartbeatMissing, "AgentHeartbeatMissing"),
            (EventKind::AgentQueueGrowing, "AgentQueueGrowing"),
        ] {
            let v: serde_json::Value = serde_json::to_value(kind).unwrap();
            assert_eq!(v, expected);
        }
    }

    #[test]
    fn m5_kinds_serialize() {
        for (kind, expected) in [
            (EventKind::ErrorRateSpike, "ErrorRateSpike"),
            (EventKind::ContainerStopped, "ContainerStopped"),
            (EventKind::ContainerCrashLoop, "ContainerCrashLoop"),
            (EventKind::CertExpiring, "CertExpiring"),
            (EventKind::OomKill, "OomKill"),
            (EventKind::KernelPanic, "KernelPanic"),
            (EventKind::FsReadOnly, "FsReadOnly"),
            (EventKind::ClockChange, "ClockChange"),
        ] {
            let v: serde_json::Value = serde_json::to_value(kind).unwrap();
            assert_eq!(v, expected);
        }
    }

    #[test]
    fn config_has_m5_fields() {
        let cfg = Config::default();
        assert!(cfg.error_patterns.is_empty());
        assert_eq!(cfg.error_window_secs, 300);
        assert_eq!(cfg.error_threshold, 10);
        assert!(cfg.docker_enabled);
        assert_eq!(cfg.cert_warn_days, 14);
        assert_eq!(cfg.cert_crit_days, 3);
        assert_eq!(cfg.cert_scan_interval_secs, 3600);
    }

    #[test]
    fn p2t5_kind_serializes() {
        let v: serde_json::Value = serde_json::to_value(EventKind::RequestRateSpike).unwrap();
        assert_eq!(v, "RequestRateSpike");
    }

    #[test]
    fn config_has_accesslog_fields() {
        let cfg = Config::default();
        assert!(cfg.access_log_paths.is_empty());
        assert_eq!(cfg.request_rate_threshold, 200);
        assert_eq!(cfg.request_rate_window_secs, 60);
    }

    #[test]
    fn p2t6_kind_serializes() {
        let v: serde_json::Value = serde_json::to_value(EventKind::PortScanSpike).unwrap();
        assert_eq!(v, "PortScanSpike");
    }

    #[test]
    fn config_has_scan_fields() {
        let cfg = Config::default();
        assert_eq!(cfg.scan_threshold, 25);
        assert_eq!(cfg.scan_window_secs, 10);
    }

    #[test]
    fn p3t7_kinds_serialize() {
        for (kind, expected) in [
            (EventKind::NewUser, "NewUser"),
            (EventKind::PackageInstalled, "PackageInstalled"),
            (EventKind::PersistenceChanged, "PersistenceChanged"),
        ] {
            let v: serde_json::Value = serde_json::to_value(kind).unwrap();
            assert_eq!(v, expected);
        }
    }

    #[test]
    fn config_has_p3t7_fields() {
        let cfg = Config::default();
        assert!(cfg.watch_authorized_keys);
        let cfg: Config =
            toml::from_str("server_url = \"x\"\nwatch_authorized_keys = false\n").unwrap();
        assert!(!cfg.watch_authorized_keys);
    }

    #[test]
    fn p3t8_kinds_serialize() {
        for (kind, expected) in [
            (EventKind::SuspiciousExec, "SuspiciousExec"),
            (EventKind::UnexpectedExec, "UnexpectedExec"),
        ] {
            let v: serde_json::Value = serde_json::to_value(kind).unwrap();
            assert_eq!(v, expected);
        }
    }

    #[test]
    fn config_has_p3t8_fields() {
        let cfg = Config::default();
        assert_eq!(cfg.process_scan_interval_secs, 30);
    }

    #[test]
    fn exception_kind_serializes() {
        let v: serde_json::Value = serde_json::to_value(EventKind::AppException).unwrap();
        assert_eq!(v, "AppException");
    }
}
