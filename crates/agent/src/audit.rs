//! Startup permission audit: probes each runner once and the spool dir, so
//! a mis-configured install fails loudly instead of running blind.

use std::path::Path;

use crate::cmd::Runners;

/// One audit row.
pub struct AuditRow {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

/// Probe every external dependency the agent uses at runtime.
pub fn audit(runners: &Runners, spool: &Path) -> Vec<AuditRow> {
    let mut rows = Vec::new();

    // the same commands the sensors actually run
    let sys = runners.sys.run(&[
        "list-units",
        "--type=service",
        "--all",
        "--no-legend",
        "--plain",
        "-n",
        "1",
    ]);
    rows.push(match sys {
        Ok(_) => AuditRow {
            name: "systemctl",
            ok: true,
            detail: "service states readable".into(),
        },
        Err(e) => AuditRow {
            name: "systemctl",
            ok: false,
            detail: format!("failed: {}", e),
        },
    });

    let journal = runners
        .journal
        .run(&["--no-pager", "-o", "json", "-n", "1"]);
    rows.push(match journal {
        Ok(_) => AuditRow {
            name: "journalctl",
            ok: true,
            detail: "journal readable".into(),
        },
        Err(e) => AuditRow {
            name: "journalctl",
            ok: false,
            detail: format!("failed: {}", e),
        },
    });

    let docker = runners.docker.run(&["ps", "-q"]);
    rows.push(match docker {
        Ok(_) => AuditRow {
            name: "docker",
            ok: true,
            detail: "docker reachable".into(),
        },
        Err(e) => AuditRow {
            name: "docker",
            ok: false,
            detail: format!("failed: {}", e),
        },
    });

    // spool writability
    let probe = spool.join(".audit-probe");
    let ok = std::fs::write(&probe, b"ok").is_ok() && std::fs::remove_file(&probe).is_ok();
    rows.push(AuditRow {
        name: "spool",
        ok,
        detail: if ok {
            "spool writable".into()
        } else {
            "failed: spool dir unreadable".into()
        },
    });

    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audits_runners_and_spool() {
        let runners = crate::cmd::Runners::with_fakes(
            Box::new(crate::cmd::FakeCli("running".into())),
            Box::new(crate::cmd::FakeCli("{}".into())),
            Box::new(crate::cmd::FakeCli("".into())),
            Box::new(crate::cmd::FakeCli("".into())),
        );
        let spool = std::env::temp_dir().join(format!("wt-audit-{}", std::process::id()));
        std::fs::create_dir_all(&spool).unwrap();
        let results = audit(&runners, &spool);
        let sys = results.iter().find(|r| r.name == "systemctl").unwrap();
        assert!(sys.ok);
        let journal = results.iter().find(|r| r.name == "journalctl").unwrap();
        assert!(journal.ok);
        let docker = results.iter().find(|r| r.name == "docker").unwrap();
        assert!(!docker.ok, "empty docker output → Err → not ok");
        let spool_check = results.iter().find(|r| r.name == "spool").unwrap();
        assert!(spool_check.ok, "temp spool is writable");
        std::fs::remove_dir_all(&spool).ok();
    }

    #[test]
    fn audit_reports_failures() {
        let runners = crate::cmd::Runners::with_fakes(
            Box::new(crate::cmd::FakeCli("".into())),
            Box::new(crate::cmd::FakeCli("".into())),
            Box::new(crate::cmd::FakeCli("".into())),
            Box::new(crate::cmd::FakeCli("".into())),
        );
        let spool = std::env::temp_dir().join(format!("wt-audit2-{}", std::process::id()));
        let results = audit(&runners, &spool);
        assert!(results.iter().all(|r| r.detail.contains("failed")));
        std::fs::remove_dir_all(&spool).ok();
    }
}
