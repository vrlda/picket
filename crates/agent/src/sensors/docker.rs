use std::collections::HashMap;

use picket_common::{AgentEvent, EventKind, Evidence, Severity};
use serde::Deserialize;

/// One `docker ps` line (--format '{{json .}}').
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DockerPsLine {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "Names")]
    pub names: String,
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "Status")]
    pub status: String,
}

/// Reduced container state for tracking.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerState {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
}

/// Parse `docker ps --format '{{json .}}'` output: one JSON object per line.
/// Non-JSON lines are skipped (fail-open).
pub fn parse_docker_ps(out: &str) -> Result<Vec<ContainerState>, String> {
    let mut containers = Vec::new();
    for line in out.lines() {
        let Ok(v) = serde_json::from_str::<DockerPsLine>(line) else {
            continue;
        };
        containers.push(ContainerState {
            id: v.id,
            name: v.names,
            image: v.image,
            state: v.state,
            status: v.status,
        });
    }
    Ok(containers)
}

/// "Restarting (4) 1 second ago" → 4; anything else → None.
fn restart_count(status: &str) -> Option<u32> {
    let rest = status.strip_prefix("Restarting (")?;
    let n = rest.split(')').next()?;
    n.trim().parse().ok()
}

/// Per-container transition tracker: running→exited = stopped (Warning);
/// N consecutive "restarting" observations within a window = crash loop
/// (Critical, episode resets on emit).
#[derive(Default)]
pub struct ContainerTracker {
    prev: HashMap<String, String>,
    restarting_count: HashMap<String, u32>,
    prev_restart_n: HashMap<String, u32>,
}

impl ContainerTracker {
    pub fn observe(
        &mut self,
        containers: &[ContainerState],
        ts: i64,
        host_id: &str,
        evs: &mut Vec<AgentEvent>,
    ) {
        let mut seen: std::collections::HashSet<String> = Default::default();
        for c in containers {
            seen.insert(c.name.clone());
            let prev_state = self.prev.insert(c.name.clone(), c.state.clone());
            match (prev_state.as_deref(), c.state.as_str()) {
                (Some("running"), "exited") | (Some("running"), "dead") => {
                    evs.push(AgentEvent {
                        id: format!("dstop-{}-{}", c.name, ts),
                        ts,
                        host_id: host_id.into(),
                        key: format!("docker:{}", c.name),
                        kind: EventKind::ContainerStopped.into(),
                        severity: Severity::Warning,
                        summary: format!("container {} stopped ({})", c.name, c.image),
                        evidence: vec![Evidence {
                            ts,
                            source: "docker".into(),
                            detail: format!("Container={} State={}", c.name, c.state),
                        }],
                        ..Default::default()
                    });
                    self.restarting_count.remove(&c.name);
                }
                _ => {}
            }
            if c.state == "restarting" {
                let n = self.restarting_count.entry(c.name.clone()).or_insert(0);
                *n += 1;
                if *n >= 3 {
                    evs.push(AgentEvent {
                        id: format!("dloop-{}-{}", c.name, ts),
                        ts,
                        host_id: host_id.into(),
                        key: format!("docker:{}", c.name),
                        kind: EventKind::ContainerCrashLoop.into(),
                        severity: Severity::Critical,
                        summary: format!("container {} is crash-looping", c.name),
                        evidence: vec![Evidence {
                            ts,
                            source: "docker".into(),
                            detail: format!("Container={} RestartCount={}", c.name, n),
                        }],
                        ..Default::default()
                    });
                    self.restarting_count.remove(&c.name); // episode resets
                }
            } else if let Some(n) = restart_count(&c.status) {
                // fast crash loops: the Status "Restarting (N)" counter climbs
                // even when the sampled state is "running" between attempts
                // (else-if of the state path: a "restarting" sample must not
                // count through both paths)
                let prev_n = self.prev_restart_n.entry(c.name.clone()).or_insert(0);
                let delta = n.saturating_sub(*prev_n);
                *prev_n = n;
                if delta > 0 {
                    let restarts = self.restarting_count.entry(c.name.clone()).or_insert(0);
                    *restarts = restarts.saturating_add(delta);
                    if *restarts >= 3 {
                        evs.push(AgentEvent {
                            id: format!("dloop-{}-{}", c.name, ts),
                            ts,
                            host_id: host_id.into(),
                            key: format!("docker:{}", c.name),
                            kind: EventKind::ContainerCrashLoop.into(),
                            severity: Severity::Critical,
                            summary: format!("container {} is crash-looping", c.name),
                            evidence: vec![Evidence {
                                ts,
                                source: "docker".into(),
                                detail: format!("Container={} RestartCount={}", c.name, *restarts),
                            }],
                            ..Default::default()
                        });
                        self.restarting_count.remove(&c.name);
                        self.prev_restart_n.remove(&c.name);
                    }
                }
            } else {
                // stable status (e.g. "Up ...") resets the counters
                self.restarting_count.remove(&c.name);
                self.prev_restart_n.remove(&c.name);
            }
        }
        // containers that vanished entirely (removed) — stop tracking
        self.prev.retain(|name, _| seen.contains(name));
        self.prev_restart_n.retain(|name, _| seen.contains(name));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_common::{EventKind, Severity};
    use std::path::PathBuf;

    fn fixture() -> String {
        std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/docker/ps.jsonl"),
        )
        .unwrap()
    }

    #[test]
    fn parses_ps_json_lines() {
        let containers = parse_docker_ps(&fixture()).unwrap();
        assert_eq!(containers.len(), 3);
        let web = containers.iter().find(|c| c.name == "web").unwrap();
        assert_eq!(web.state, "running");
        let worker = containers.iter().find(|c| c.name == "worker").unwrap();
        assert_eq!(worker.state, "restarting");
        let cache = containers.iter().find(|c| c.name == "cache").unwrap();
        assert_eq!(cache.state, "exited");
    }

    #[test]
    fn skips_non_json_lines() {
        let out = "not json\n\n{\"State\":\"running\",\"Names\":\"x\",\"ID\":\"1\",\"Image\":\"i\",\"Status\":\"Up\"}\n";
        let containers = parse_docker_ps(out).unwrap();
        assert_eq!(containers.len(), 1);
    }

    #[test]
    fn running_to_exited_emits_stopped() {
        let mut t = ContainerTracker::default();
        let mut evs = Vec::new();
        t.observe(&[container("web", "running")], 1000, "h-1", &mut evs);
        assert!(evs.is_empty());
        t.observe(&[container("web", "exited")], 2000, "h-1", &mut evs);
        let stopped = evs.iter().find(|e| e.kind == EventKind::ContainerStopped);
        assert!(stopped.is_some());
        assert_eq!(stopped.unwrap().severity, Severity::Warning);
        assert_eq!(stopped.unwrap().key, "docker:web");
    }

    #[test]
    fn restarting_state_counts_as_crash_loop() {
        let mut t = ContainerTracker::default();
        let mut evs = Vec::new();
        t.observe(&[container("worker", "restarting")], 1000, "h-1", &mut evs);
        t.observe(&[container("worker", "restarting")], 2000, "h-1", &mut evs);
        t.observe(&[container("worker", "restarting")], 3000, "h-1", &mut evs);
        let loop_ev = evs.iter().find(|e| e.kind == EventKind::ContainerCrashLoop);
        assert!(loop_ev.is_some());
        assert_eq!(loop_ev.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn steady_running_is_quiet() {
        let mut t = ContainerTracker::default();
        let mut evs = Vec::new();
        for ts in [1000, 2000, 3000] {
            t.observe(&[container("web", "running")], ts, "h-1", &mut evs);
        }
        assert!(evs.is_empty());
    }

    fn container(name: &str, state: &str) -> ContainerState {
        container_status(name, state, "Up 1 second")
    }

    fn container_status(name: &str, state: &str, status: &str) -> ContainerState {
        ContainerState {
            id: format!("id-{}", name),
            name: name.to_string(),
            image: String::new(),
            state: state.to_string(),
            status: status.to_string(),
        }
    }

    #[test]
    fn restart_counter_jumps_detect_fast_crash_loops() {
        // a sub-poll crash loop mostly samples "running" but the Status
        // counter climbs — the N jumps must accumulate into a crash loop
        let mut t = ContainerTracker::default();
        let mut evs = Vec::new();
        t.observe(
            &[container_status(
                "web",
                "running",
                "Restarting (1) 1 second ago",
            )],
            1000,
            "h-1",
            &mut evs,
        );
        t.observe(
            &[container_status(
                "web",
                "running",
                "Restarting (2) 1 second ago",
            )],
            2000,
            "h-1",
            &mut evs,
        );
        assert!(
            evs.is_empty(),
            "deltas 1+1 = 2 restarts, under the threshold"
        );
        t.observe(
            &[container_status(
                "web",
                "running",
                "Restarting (3) 1 second ago",
            )],
            3000,
            "h-1",
            &mut evs,
        );
        let loop_ev = evs.iter().find(|e| e.kind == EventKind::ContainerCrashLoop);
        assert!(loop_ev.is_some(), "N jumps 1→2→3 = 3 restarts ≥ 3");
    }

    #[test]
    fn restart_counter_resets_on_stable_status() {
        let mut t = ContainerTracker::default();
        let mut evs = Vec::new();
        t.observe(
            &[container_status(
                "web",
                "running",
                "Restarting (2) 1 second ago",
            )],
            1000,
            "h-1",
            &mut evs,
        );
        t.observe(
            &[container_status("web", "running", "Up 2 hours")],
            2000,
            "h-1",
            &mut evs,
        );
        assert!(evs.is_empty(), "seeding + stable status emit nothing");
        // a FRESH restart counter (post-reset) with N ≥ 3 is a crash loop
        t.observe(
            &[container_status(
                "web",
                "running",
                "Restarting (8) 1 second ago",
            )],
            3000,
            "h-1",
            &mut evs,
        );
        assert!(
            evs.iter().any(|e| e.kind == EventKind::ContainerCrashLoop),
            "8 restarts is a crash loop"
        );
    }
}
