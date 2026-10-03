use std::collections::{HashSet, VecDeque};

use crate::engine::SpikeDetector;
use crate::procfs::{ProcFs, TcpEntry};
use picket_common::{AgentEvent, EventKind, Evidence, Severity};

/// Snapshot state for network monitoring: previous listen/remote sets and a
/// rolling detector on the established-connection count.
pub struct NetState {
    prev_listen: HashSet<String>,
    prev_udp_listen: HashSet<String>,
    prev_remote: HashSet<String>,
    prev_scan_pairs: HashSet<String>,
    recent_connects: VecDeque<(i64, String)>,
    prev_count: usize,
    rate_detector: SpikeDetector,
}

impl Default for NetState {
    fn default() -> Self {
        NetState {
            prev_listen: HashSet::new(),
            prev_udp_listen: HashSet::new(),
            prev_remote: HashSet::new(),
            prev_scan_pairs: HashSet::new(),
            recent_connects: VecDeque::new(),
            prev_count: 0,
            rate_detector: SpikeDetector::new(20, 2.5),
        }
    }
}

/// Pure: does the recent-connect deque contain >= `threshold` distinct
/// (ip:port) pairs within `window_ms` of `now`? The caller clears the deque
/// when this fires.
pub fn scan_fires(
    recent: &VecDeque<(i64, String)>,
    now: i64,
    window_ms: i64,
    threshold: u32,
) -> bool {
    let distinct: HashSet<&String> = recent
        .iter()
        .filter(|(t, _)| *t + window_ms >= now)
        .map(|(_, p)| p)
        .collect();
    distinct.len() >= threshold as usize
}

impl NetState {
    /// Observe the current network state at ts_ms; emit events for changes.
    pub fn observe(
        &mut self,
        p: &ProcFs,
        ts: i64,
        host_id: &str,
        scan_threshold: u32,
        scan_window_ms: i64,
    ) -> Vec<AgentEvent> {
        let mut evs = Vec::new();
        let listen: HashSet<String> = entries(p, "LISTEN")
            .into_iter()
            .map(|e| format!("tcp:{}:{}", e.local_ip, e.local_port))
            .collect();
        let remote: HashSet<String> = entries(p, "ESTABLISHED")
            .into_iter()
            .map(|e| e.remote_ip.clone())
            .filter(|ip| ip != "0.0.0.0" && ip != "::")
            .collect();
        let count = entries(p, "ESTABLISHED").len();

        for new in listen.difference(&self.prev_listen) {
            evs.push(AgentEvent {
                id: format!("port-{}-{}", new, ts),
                ts,
                host_id: host_id.into(),
                key: format!("port:{}", new),
                kind: EventKind::NewListeningPort.into(),
                severity: Severity::Warning,
                summary: format!("new listening port: {}", new),
                evidence: vec![Evidence {
                    ts,
                    source: "netflow".into(),
                    detail: format!("Entry={}", new),
                }],
                ..Default::default()
            });
        }
        let mut udp_now = HashSet::new();
        let min = p.udp_ephemeral_min();
        for (ip, port) in p
            .udp_entries()
            .unwrap_or_default()
            .into_iter()
            .chain(p.udp6_entries().unwrap_or_default())
        {
            if port >= min {
                continue; // ephemeral source socket — not a real listener
            }
            let key = format!("udp:{}:{}", ip, port);
            udp_now.insert(key.clone());
            if self.prev_udp_listen.insert(key.clone()) {
                evs.push(AgentEvent {
                    id: format!("port-{}-{}", key, ts),
                    ts,
                    host_id: host_id.into(),
                    key: format!("port:{}", key),
                    kind: EventKind::NewListeningPort.into(),
                    severity: Severity::Warning,
                    summary: format!("new listening port: {}", key),
                    evidence: vec![Evidence {
                        ts,
                        source: "netflow".into(),
                        detail: format!("Entry={}", key),
                    }],
                    ..Default::default()
                });
            }
        }
        self.prev_udp_listen.retain(|k| udp_now.contains(k));
        for new in remote.difference(&self.prev_remote) {
            evs.push(AgentEvent {
                id: format!("out-{}-{}", new, ts),
                ts,
                host_id: host_id.into(),
                key: format!("net:out:{}", new),
                kind: EventKind::NewOutboundConnection.into(),
                severity: Severity::Warning,
                summary: format!("new outbound connection to {}", new),
                evidence: vec![Evidence {
                    ts,
                    source: "netflow".into(),
                    detail: format!("RemoteIp={}", new),
                }],
                ..Default::default()
            });
        }

        self.rate_detector.push(count as f64);
        if self.prev_count > 0 && self.rate_detector.is_spike(count as f64) {
            evs.push(AgentEvent {
                id: format!("rate-{}", ts),
                ts,
                host_id: host_id.into(),
                key: "net:rate".into(),
                kind: EventKind::ConnectionRateSpike.into(),
                severity: Severity::Warning,
                summary: format!("established-connection count spiked to {}", count),
                evidence: vec![Evidence {
                    ts,
                    source: "netflow".into(),
                    detail: format!("Established={}", count),
                }],
                ..Default::default()
            });
        }

        // port-scan proxy: distinct NEW remote (ip:port) pairs within the window
        let new_pairs: Vec<String> = entries(p, "ESTABLISHED")
            .into_iter()
            .filter(|e| e.remote_ip != "0.0.0.0" && e.remote_ip != "::")
            .map(|e| format!("{}:{}", e.remote_ip, e.remote_port))
            .collect();
        for pair in new_pairs {
            if self.prev_scan_pairs.insert(pair.clone()) {
                self.recent_connects.push_back((ts, pair));
            }
        }
        self.recent_connects
            .retain(|(t, _)| *t + scan_window_ms >= ts);
        if scan_fires(&self.recent_connects, ts, scan_window_ms, scan_threshold) {
            let distinct = self.recent_connects.len();
            self.recent_connects.clear();
            evs.push(AgentEvent {
                id: format!("scan-{}", ts),
                ts,
                host_id: host_id.into(),
                key: "net:scan".into(),
                kind: EventKind::PortScanSpike.into(),
                severity: Severity::Warning,
                summary: format!(
                    "{} distinct remote connections within {}s — possible port scan",
                    distinct,
                    scan_window_ms / 1000
                ),
                evidence: vec![Evidence {
                    ts,
                    source: "netflow".into(),
                    detail: format!("DistinctPairs={} WindowMs={}", distinct, scan_window_ms),
                }],
                ..Default::default()
            });
        }

        self.prev_listen = listen;
        self.prev_remote = remote;
        self.prev_count = count;
        evs
    }
}

fn entries(p: &ProcFs, state: &str) -> Vec<TcpEntry> {
    let mut out = Vec::new();
    for e in p
        .tcp_entries()
        .unwrap_or_default()
        .into_iter()
        .chain(p.tcp6_entries().unwrap_or_default())
    {
        if e.state == state {
            out.push(e);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_common::{EventKind, Severity};
    use std::path::PathBuf;

    fn procfs() -> crate::procfs::ProcFs {
        crate::procfs::ProcFs::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"),
        )
    }

    #[test]
    fn new_listening_port_and_outbound_emitted_then_quiet() {
        let p = procfs();
        let mut state = NetState::default();
        let evs = state.observe(&p, 1000, "h-1", 25, 10_000);
        let port_ev = evs
            .iter()
            .find(|e| e.key == "port:tcp:127.0.0.1:8080")
            .expect("port event");
        assert_eq!(port_ev.kind, EventKind::NewListeningPort);
        assert_eq!(port_ev.severity, Severity::Warning);
        let out_ev = evs
            .iter()
            .find(|e| e.key == "net:out:93.184.216.47")
            .expect("outbound event");
        assert_eq!(out_ev.kind, EventKind::NewOutboundConnection);
        assert_eq!(out_ev.severity, Severity::Warning);
        assert!(evs.iter().any(|e| e.key == "net:out:127.0.0.1"));
        // second observation with identical state: nothing new
        let evs = state.observe(&p, 2000, "h-1", 25, 10_000);
        assert!(evs.is_empty());
    }

    #[test]
    fn udp_listens_emitted_as_new_listening_ports() {
        let p = procfs();
        let mut state = NetState::default();
        let evs = state.observe(&p, 1000, "h-1", 25, 10_000);
        let ev = evs
            .iter()
            .find(|e| e.key == "port:udp:0.0.0.0:5353")
            .expect("udp mDNS listen event");
        assert_eq!(ev.kind, EventKind::NewListeningPort);
        assert_eq!(ev.severity, Severity::Warning);
        assert!(evs.iter().any(|e| e.key == "port:udp:127.0.0.1:53"));
        assert!(evs.iter().any(|e| e.key == "port:udp::::5353"));
        // no repeats on the next observation
        let evs = state.observe(&p, 2000, "h-1", 25, 10_000);
        assert!(evs.iter().all(|e| e.kind != EventKind::NewListeningPort));
    }

    #[test]
    fn udp_ephemeral_ports_not_reported() {
        let p = procfs();
        let mut state = NetState::default();
        let evs = state.observe(&p, 1000, "h-1", 25, 10_000);
        // real listeners still fire
        assert!(evs.iter().any(|e| e.key == "port:udp:0.0.0.0:5353"));
        assert!(evs.iter().any(|e| e.key == "port:udp:127.0.0.1:53"));
        // the fixture's ephemeral source sockets (40000, 50000 >= 32768)
        // must not fire
        assert!(
            evs.iter()
                .all(|e| !e.key.contains(":40000") && !e.key.contains(":50000")),
            "ephemeral UDP ports must not fire: {:?}",
            evs.iter().map(|e| e.key.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn scan_fires_when_threshold_distinct_pairs_in_window() {
        let mut recent: VecDeque<(i64, String)> = VecDeque::new();
        for i in 0..30 {
            recent.push_back((1000, format!("10.0.0.{}:{}", i, 1000 + i)));
        }
        assert!(scan_fires(&recent, 1000, 10_000, 25));
    }

    #[test]
    fn scan_does_not_fire_below_threshold() {
        let mut recent: VecDeque<(i64, String)> = VecDeque::new();
        for i in 0..3 {
            recent.push_back((1000, format!("10.0.0.{}:80", i)));
        }
        assert!(!scan_fires(&recent, 1000, 10_000, 25));
    }

    #[test]
    fn scan_stale_pairs_pruned_from_window() {
        let mut recent: VecDeque<(i64, String)> = VecDeque::new();
        for i in 0..30 {
            recent.push_back((0, format!("10.0.0.{}:{}", i, 1000 + i)));
        }
        assert!(!scan_fires(&recent, 20_000, 10_000, 25));
        // a mix of fresh and stale pairs counts only the fresh ones
        let mut recent: VecDeque<(i64, String)> = VecDeque::new();
        for i in 0..25 {
            recent.push_back((0, format!("10.0.0.{}:80", i)));
        }
        recent.push_back((19_000, "10.9.9.9:80".into()));
        assert!(!scan_fires(&recent, 20_000, 10_000, 25));
    }

    #[test]
    fn connection_rate_spike_detected() {
        let mut det = SpikeDetector::new(6, 2.0);
        for _ in 0..6 {
            det.push(10.0);
        }
        assert!(det.is_spike(30.0));
    }
}
