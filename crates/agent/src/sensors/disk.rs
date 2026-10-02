//! Disk and inode usage via statvfs (libc) — the M1 gap finally closed:
//! DiskHigh/InodeHigh kinds existed but nothing emitted them.

use crate::procfs::ProcFs;
use std::collections::HashMap;
use wt_common::{AgentEvent, Config, EventKind, Evidence, Severity};

/// Used percentage of a capacity.
pub fn usage_pct(total: u64, free: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let used = total.saturating_sub(free);
    used as f64 / total as f64 * 100.0
}

pub fn disk_severity(pct: f64, cfg: &Config) -> Severity {
    if pct >= cfg.disk_crit_pct {
        Severity::Critical
    } else if pct >= cfg.disk_warn_pct {
        Severity::Warning
    } else {
        Severity::Info
    }
}

pub fn inode_severity(pct: f64, cfg: &Config) -> Severity {
    if pct >= cfg.inode_crit_pct {
        Severity::Critical
    } else {
        Severity::Info
    }
}

/// statvfs one mount (via libc): (total_bytes, avail_bytes, total_inodes,
/// free_inodes, read_only).
/// f_bavail (unprivileged-available) counts reserved blocks as used — matches
/// what the agent's non-root user can actually see.
// statvfs field widths differ per platform (u64 on Linux, u32/c_ulong on
// macOS) — the casts are needed there even though they are no-ops here.
#[allow(clippy::unnecessary_cast)]
fn stat_mount(mount_point: &str) -> Option<(u64, u64, u64, u64, bool)> {
    let path = std::ffi::CString::new(mount_point).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let read_only = (s.f_flag & libc::ST_RDONLY) != 0;
    Some((
        (s.f_blocks as u64).saturating_mul(s.f_frsize as u64),
        (s.f_bavail as u64).saturating_mul(s.f_frsize as u64),
        s.f_files as u64,
        s.f_ffree as u64,
        read_only,
    ))
}

/// Pure: update the RO baseline for `mount` and report whether a FsReadOnly
/// event should fire. First sight seeds the baseline (no event — a boot-time
/// ro mount like a systemd bind-mount is normal); a rw→ro flip fires;
/// ro→ro is quiet. The baseline always reflects the last seen flag, so a
/// ro→rw→ro sequence re-fires.
pub fn ro_transition(baseline: &mut HashMap<String, bool>, mount: &str, read_only: bool) -> bool {
    let before = baseline.insert(mount.to_string(), read_only);
    read_only && before == Some(false)
}

/// Emit disk/inode events for all mounts at `ts`. Fail-open: unreadable
/// mounts or a missing /proc are skipped.
pub fn disk_events(
    p: &ProcFs,
    cfg: &Config,
    ts: i64,
    host_id: &str,
    ro_baseline: &mut HashMap<String, bool>,
) -> Vec<AgentEvent> {
    let mut evs = Vec::new();
    let Ok(mounts) = p.mounts() else { return evs };
    for m in &mounts {
        let Some((total, free, files, ffree, read_only)) = stat_mount(&m.mount_point) else {
            continue;
        };
        let disk = usage_pct(total, free);
        let sev = disk_severity(disk, cfg);
        if sev != Severity::Info {
            evs.push(AgentEvent {
                id: format!("disk-{}-{}", m.mount_point, ts),
                ts,
                host_id: host_id.into(),
                key: format!("disk:{}", m.mount_point),
                kind: EventKind::DiskHigh.into(),
                severity: sev,
                summary: format!("disk usage at {:.0}% on {}", disk, m.mount_point),
                evidence: vec![Evidence {
                    ts,
                    source: "disk".into(),
                    detail: format!(
                        "Mount={} UsedPct={:.1} TotalBytes={}",
                        m.mount_point, disk, total
                    ),
                }],
                ..Default::default()
            });
        }
        let inodes = usage_pct(files, ffree);
        if inode_severity(inodes, cfg) == Severity::Critical {
            evs.push(AgentEvent {
                id: format!("inode-{}-{}", m.mount_point, ts),
                ts,
                host_id: host_id.into(),
                key: format!("inode:{}", m.mount_point),
                kind: EventKind::InodeHigh.into(),
                severity: Severity::Critical,
                summary: format!("inode usage at {:.0}% on {}", inodes, m.mount_point),
                evidence: vec![Evidence {
                    ts,
                    source: "disk".into(),
                    detail: format!("Mount={} InodePct={:.1}", m.mount_point, inodes),
                }],
                ..Default::default()
            });
        }
        if ro_transition(ro_baseline, &m.mount_point, read_only) {
            evs.push(AgentEvent {
                id: format!("fsro-{}-{}", m.mount_point, ts),
                ts,
                host_id: host_id.into(),
                key: format!("fsro:{}", m.mount_point),
                kind: EventKind::FsReadOnly.into(),
                severity: Severity::Critical,
                summary: format!("filesystem {} went read-only", m.mount_point),
                evidence: vec![Evidence {
                    ts,
                    source: "disk".into(),
                    detail: format!("Mount={}", m.mount_point),
                }],
                ..Default::default()
            });
        }
    }
    evs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_pct_math() {
        assert_eq!(usage_pct(100, 25), 75.0);
        assert_eq!(usage_pct(100, 0), 100.0);
        assert_eq!(usage_pct(0, 0), 0.0);
        assert_eq!(usage_pct(100, 150), 0.0, "free > total clamps to 0");
    }

    #[test]
    fn disk_severity_by_thresholds() {
        let cfg = Config::default(); // warn 80, crit 90
        assert_eq!(disk_severity(70.0, &cfg), Severity::Info);
        assert_eq!(disk_severity(85.0, &cfg), Severity::Warning);
        assert_eq!(disk_severity(95.0, &cfg), Severity::Critical);
    }

    #[test]
    fn inode_severity_by_threshold() {
        let cfg = Config::default(); // inode crit 90
        assert_eq!(inode_severity(50.0, &cfg), Severity::Info);
        assert_eq!(inode_severity(95.0, &cfg), Severity::Critical);
    }

    #[test]
    fn ro_transition_first_sight_seeds_no_event() {
        let mut b = HashMap::new();
        assert!(!ro_transition(&mut b, "/run/systemd", true));
        assert_eq!(b.get("/run/systemd"), Some(&true));
    }

    #[test]
    fn ro_transition_fires_only_on_rw_to_ro_flip() {
        let mut b = HashMap::new();
        assert!(!ro_transition(&mut b, "/data", false)); // seed rw
        assert!(!ro_transition(&mut b, "/data", false)); // rw→rw quiet
        assert!(ro_transition(&mut b, "/data", true)); // rw→ro fires
        assert!(!ro_transition(&mut b, "/data", true)); // ro→ro quiet
        assert!(!ro_transition(&mut b, "/data", false)); // ro→rw quiet
        assert!(ro_transition(&mut b, "/data", true)); // rw→ro re-fires
    }
}
