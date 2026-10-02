use std::collections::HashMap;

use crate::cmd::CommandRunner;
use wt_common::{AgentEvent, EventKind, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Active,
    Failed,
    Other,
}

/// Parse `systemctl list-units --type=service --all --no-legend --plain` output
/// into unit -> state. Non-.service lines are ignored.
pub fn systemctl_list_units(
    runner: &dyn CommandRunner,
) -> Result<HashMap<String, ServiceState>, String> {
    let out = runner.run(&[
        "list-units",
        "--type=service",
        "--all",
        "--no-legend",
        "--plain",
    ])?;
    let mut map = HashMap::new();
    for line in out.lines() {
        let mut parts = line.split_whitespace();
        let unit = parts.next().unwrap_or("").to_string();
        let active = parts.nth(1).unwrap_or("").to_string();
        if !unit.is_empty() && unit.ends_with(".service") {
            let state = match active.as_str() {
                "active" => ServiceState::Active,
                "failed" => ServiceState::Failed,
                _ => ServiceState::Other,
            };
            map.insert(unit, state);
        }
    }
    Ok(map)
}

/// Tracks service transitions to emit ServiceFailed and ServiceCrashLoop events.
/// Restart counting is transition-aware: only a change INTO the failed state
/// from a non-failed state counts as a restart, so a unit that merely stays
/// failed cannot accumulate fake restarts.
pub struct CrashTracker {
    window_secs: u64,
    restarts: HashMap<String, Vec<u64>>,
    last_state: HashMap<String, Option<ServiceState>>,
}

impl CrashTracker {
    pub fn new(window_secs: u64) -> Self {
        CrashTracker {
            window_secs,
            restarts: HashMap::new(),
            last_state: HashMap::new(),
        }
    }

    /// Observe one unit state at `ts` (unix seconds). Emits:
    /// - ServiceFailed (Warning) on a transition into Failed, or on the first
    ///   ever observation being Failed (no restart counted for the first sighting)
    /// - ServiceCrashLoop (Critical) when >=3 restart transitions happen
    ///   within the window
    pub fn observe(
        &mut self,
        unit: &str,
        state: ServiceState,
        ts: u64,
        host: &str,
        evs: &mut Vec<AgentEvent>,
    ) {
        let prev = *self.last_state.entry(unit.to_string()).or_insert(None);
        self.last_state.insert(unit.to_string(), Some(state));

        if state == ServiceState::Failed {
            let first_sighting = prev.is_none();
            let fresh_failure =
                prev == Some(ServiceState::Active) || prev == Some(ServiceState::Other);
            if first_sighting || fresh_failure {
                let list = self.restarts.entry(unit.to_string()).or_default();
                if !first_sighting {
                    list.push(ts);
                }
                list.retain(|t| *t + self.window_secs >= ts);
                let is_loop = !first_sighting && list.len() >= 3;
                evs.push(AgentEvent {
                    id: format!("{}-{}-{}", unit, host, ts),
                    ts: ts as i64 * 1000,
                    host_id: host.into(),
                    key: format!("svc:{}", unit),
                    kind: if is_loop {
                        EventKind::ServiceCrashLoop
                    } else {
                        EventKind::ServiceFailed
                    }
                    .into(),
                    severity: if is_loop {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    },
                    summary: format!(
                        "{} {} ({} restarts in {}s)",
                        unit,
                        if is_loop {
                            "crash-looping"
                        } else {
                            "entered failed state"
                        },
                        list.len(),
                        self.window_secs
                    ),
                    evidence: vec![wt_common::Evidence {
                        ts: ts as i64 * 1000,
                        source: "systemd".into(),
                        detail: format!("ActiveState=failed at t={}", ts),
                    }],
                    ..Default::default()
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "\
sshd.service        loaded active running sshd
nginx.service       loaded failed  failed  nginx
cron.service        loaded active running cron
";

    #[test]
    fn parses_service_states_from_list_units_output() {
        let states = systemctl_list_units(&crate::cmd::FakeCli(LIST.into())).unwrap();
        assert_eq!(states["sshd.service"], ServiceState::Active);
        assert_eq!(states["nginx.service"], ServiceState::Failed);
        assert_eq!(states["cron.service"], ServiceState::Active);
    }

    #[test]
    fn active_to_failed_transition_emits_service_failed_event() {
        let mut m = CrashTracker::new(120);
        let mut evs = Vec::new();
        m.observe("nginx.service", ServiceState::Active, 1000, "h-1", &mut evs);
        assert!(evs.is_empty());
        m.observe("nginx.service", ServiceState::Failed, 1015, "h-1", &mut evs);
        assert_eq!(evs[0].kind, EventKind::ServiceFailed);
        assert_eq!(evs[0].key, "svc:nginx.service");
        assert_eq!(evs[0].severity, Severity::Warning);
        assert_eq!(evs[0].host_id, "h-1");
    }

    #[test]
    fn three_restarts_within_window_is_crash_loop() {
        let mut m = CrashTracker::new(120);
        let mut evs = Vec::new();
        for ts in [1000, 1010, 1020, 1030, 1040, 1050] {
            m.observe("flaky.service", ServiceState::Active, ts, "h-1", &mut evs);
            m.observe(
                "flaky.service",
                ServiceState::Failed,
                ts + 5,
                "h-1",
                &mut evs,
            );
        }
        let crash = evs
            .iter()
            .filter(|e| e.kind == EventKind::ServiceCrashLoop)
            .count();
        assert!(crash >= 1, "expected crash-loop event, got {evs:?}");
    }

    #[test]
    fn restarts_older_than_window_do_not_crash_loop() {
        let mut m = CrashTracker::new(10);
        let mut evs = Vec::new();
        for ts in [1000u64, 2000, 2010, 2020] {
            m.observe("ok.service", ServiceState::Active, ts, "h-1", &mut evs);
            m.observe("ok.service", ServiceState::Failed, ts + 5, "h-1", &mut evs);
        }
        assert!(!evs.iter().any(|e| e.kind == EventKind::ServiceCrashLoop));
    }

    #[test]
    fn staying_failed_does_not_accumulate_restarts() {
        let mut m = CrashTracker::new(120);
        let mut evs = Vec::new();
        for ts in [1000u64, 1015, 1030] {
            m.observe("stuck.service", ServiceState::Failed, ts, "h-1", &mut evs);
        }
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, EventKind::ServiceFailed);
        assert!(!evs.iter().any(|e| e.kind == EventKind::ServiceCrashLoop));
    }
}
