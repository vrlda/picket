use std::collections::HashMap;

use crate::procfs::{MemInfo, NetDevErrors, ProcFs};
use picket_common::{AgentEvent, Config, EventKind, Evidence, Severity};

/// Percentage of CPU time spent busy, given deltas between two samples.
pub fn cpu_usage_pct(busy_delta: u64, total_delta: u64) -> f64 {
    if total_delta == 0 {
        return 0.0;
    }
    busy_delta as f64 / total_delta as f64 * 100.0
}

/// Sample cpu ticks and compute usage vs the previous sample.
/// Returns (new_total, new_busy, usage_pct).
pub fn cpu_usage_now(p: &ProcFs, prev_total: u64, prev_busy: u64) -> (u64, u64, f64) {
    let (total, idle) = match p.cpu_ticks() {
        Ok(v) => v,
        Err(_) => {
            eprintln!("sensor procfs.cpu_ticks failed");
            (prev_total, prev_total.saturating_sub(prev_busy))
        }
    };
    let busy = total.saturating_sub(idle);
    if prev_total == 0 {
        return (total, busy, 0.0);
    }
    let (d_total, d_busy) = (
        total.saturating_sub(prev_total),
        busy.saturating_sub(prev_busy),
    );
    (total, busy, cpu_usage_pct(d_busy, d_total))
}

fn event(
    ts: i64,
    host: &str,
    key: String,
    kind: EventKind,
    sev: Severity,
    summary: String,
    detail: String,
) -> AgentEvent {
    AgentEvent {
        id: format!("{}-{}-{}", host, ts, key),
        ts,
        host_id: host.into(),
        key,
        kind: kind.into(),
        severity: sev,
        summary,
        evidence: vec![Evidence {
            ts,
            source: "procfs".into(),
            detail,
        }],
        ..Default::default()
    }
}

pub fn mem_events(m: MemInfo, cfg: &Config, host: &str, ts: i64) -> Vec<AgentEvent> {
    let mut out = Vec::new();
    if m.mem_used_pct >= cfg.mem_warn_pct {
        out.push(event(
            ts,
            host,
            "mem:used".into(),
            EventKind::MemHigh,
            Severity::Warning,
            format!("Memory usage at {:.0}%", m.mem_used_pct),
            format!("MemUsedPct={:.1}", m.mem_used_pct),
        ));
    }
    out
}

pub fn swap_events(m: MemInfo, cfg: &Config, host: &str, ts: i64) -> Vec<AgentEvent> {
    let mut out = Vec::new();
    if m.swap_used_pct >= cfg.swap_warn_pct {
        out.push(event(
            ts,
            host,
            "mem:swap".into(),
            EventKind::SwapHigh,
            Severity::Warning,
            format!("Swap usage at {:.0}%", m.swap_used_pct),
            format!("SwapUsedPct={:.1}", m.swap_used_pct),
        ));
    }
    out
}

pub fn load_events(load: f64, ncpu: usize, cfg: &Config, host: &str, ts: i64) -> Vec<AgentEvent> {
    let mut out = Vec::new();
    let ncpu = ncpu.max(1) as f64;
    let ratio = load / ncpu;
    if ratio >= cfg.load_crit_ratio {
        out.push(event(
            ts,
            host,
            "load:1m".into(),
            EventKind::LoadHigh,
            Severity::Critical,
            format!("Load {} is {:.1}x the {} cores", load, ratio, ncpu),
            format!("LoadOneMin={:.2} Ncpu={:.0}", load, ncpu),
        ));
    } else if ratio >= cfg.load_warn_ratio {
        out.push(event(
            ts,
            host,
            "load:1m".into(),
            EventKind::LoadHigh,
            Severity::Warning,
            format!("Load {} is {:.1}x the {} cores", load, ratio, ncpu),
            format!("LoadOneMin={:.2} Ncpu={:.0}", load, ncpu),
        ));
    }
    out
}

pub fn netdev_events(errs: &HashMap<String, NetDevErrors>, host: &str, ts: i64) -> Vec<AgentEvent> {
    let mut out = Vec::new();
    for (iface, e) in errs {
        if e.rx > 0 || e.tx > 0 {
            out.push(event(
                ts,
                host,
                format!("netdev:{}", iface),
                EventKind::NetDevErrors,
                Severity::Warning,
                format!(
                    "{} reports interface errors (rx {}, tx {})",
                    iface, e.rx, e.tx
                ),
                format!("RxErrors={} TxErrors={}", e.rx, e.tx),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_common::{EventKind, Severity};
    use std::path::PathBuf;

    fn cfg() -> Config {
        Config {
            mem_warn_pct: 70.0,
            swap_warn_pct: 40.0,
            load_warn_ratio: 2.0,
            load_crit_ratio: 4.0,
            ..Default::default()
        }
    }

    #[test]
    fn cpu_usage_is_percentage_of_busy_over_total_delta() {
        assert_eq!(cpu_usage_pct(50, 100), 50.0);
        assert_eq!(cpu_usage_pct(0, 100), 0.0);
        assert_eq!(cpu_usage_pct(200, 200), 100.0);
        assert_eq!(cpu_usage_pct(10, 0), 0.0);
    }

    #[test]
    fn memory_over_threshold_emits_warning() {
        let evs = mem_events(
            MemInfo {
                mem_used_pct: 85.0,
                swap_used_pct: 0.0,
            },
            &cfg(),
            "h-1",
            1,
        );
        assert_eq!(evs[0].kind, EventKind::MemHigh);
        assert_eq!(evs[0].severity, Severity::Warning);
    }

    #[test]
    fn memory_under_threshold_emits_nothing() {
        let evs = mem_events(
            MemInfo {
                mem_used_pct: 30.0,
                swap_used_pct: 0.0,
            },
            &cfg(),
            "h-1",
            1,
        );
        assert!(evs.is_empty());
    }

    #[test]
    fn swap_over_threshold_emits_warning() {
        let evs = swap_events(
            MemInfo {
                mem_used_pct: 0.0,
                swap_used_pct: 60.0,
            },
            &cfg(),
            "h-1",
            1,
        );
        assert_eq!(evs[0].kind, EventKind::SwapHigh);
    }

    #[test]
    fn load_over_crit_ratio_is_critical() {
        let evs = load_events(8.0, 2, &cfg(), "h-1", 1);
        assert_eq!(evs[0].severity, Severity::Critical);
        let evs = load_events(5.0, 2, &cfg(), "h-1", 1);
        assert_eq!(evs[0].severity, Severity::Warning);
    }

    #[test]
    fn netdev_tx_errors_emit_warning() {
        let mut map = std::collections::HashMap::new();
        map.insert("eth0".to_string(), NetDevErrors { rx: 0, tx: 7 });
        let evs = netdev_events(&map, "h-1", 1);
        assert_eq!(evs[0].kind, EventKind::NetDevErrors);
        assert_eq!(evs[0].key, "netdev:eth0");
    }

    #[test]
    fn procfs_integration_produces_mem_events() {
        let p = ProcFs::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"));
        let m = p.meminfo().unwrap();
        let evs = mem_events(m, &cfg(), "h-1", 1);
        assert!(!evs.is_empty());
    }

    #[test]
    fn cpu_ticks_from_fixture_parses() {
        let p = ProcFs::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"));
        let (total, idle) = p.cpu_ticks().unwrap();
        assert!(total > idle);
        assert!(idle > 0);
    }

    #[test]
    fn cpu_usage_now_returns_stable_zeros_on_first_call() {
        let p = ProcFs::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc"));
        // first call establishes baseline; no divide-by-zero, pct is 0.0
        let (t1, b1, pct1) = cpu_usage_now(&p, 0, 0);
        let (_t2, _b2, pct2) = cpu_usage_now(&p, t1, b1);
        assert_eq!(pct1, 0.0);
        assert!(pct2 >= 0.0);
    }

    #[test]
    fn netdev_rx_errors_emit_warning() {
        let mut map = std::collections::HashMap::new();
        map.insert("eth1".to_string(), NetDevErrors { rx: 7, tx: 0 });
        let evs = netdev_events(&map, "h-1", 1);
        assert_eq!(evs[0].kind, EventKind::NetDevErrors);
        assert_eq!(evs[0].key, "netdev:eth1");
    }
}
