use std::path::Path;

use picket_common::{AgentEvent, Config, EventKind, Evidence, Severity};

/// "notAfter=Sep 16 12:00:00 2026 GMT" → unix seconds (via picket_common::civil).
pub fn parse_enddate(line: &str) -> Option<i64> {
    let rest = line.strip_prefix("notAfter=")?;
    let date = rest.strip_suffix(" GMT")?;
    picket_common::civil::parse_gm_date(date)
}

/// Warning when expiring within warn_days, Critical within crit_days or
/// already expired; Info (no event) otherwise.
pub fn cert_severity(not_after: i64, now: i64, cfg: &Config) -> Severity {
    let secs_left = not_after - now;
    let crit = cfg.cert_crit_days.max(1) * 86400;
    let warn = cfg.cert_warn_days.max(crit / 86400) * 86400;
    if secs_left < crit {
        Severity::Critical
    } else if secs_left < warn {
        Severity::Warning
    } else {
        Severity::Info
    }
}

/// Expand a config path (file or glob) into concrete cert paths.
pub fn expand_paths(raw: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for p in raw {
        if p.contains('*') {
            if let Ok(entries) = glob::glob(p) {
                for e in entries.flatten() {
                    out.push(e.to_string_lossy().into_owned());
                }
            }
        } else if Path::new(p).is_file() {
            out.push(p.clone());
        }
    }
    out
}

/// Default certificate locations scanned when cert_paths is empty.
pub fn default_cert_paths() -> Vec<String> {
    vec![
        "/etc/letsencrypt/live/*/cert.pem".into(),
        "/etc/ssl/private/*.pem".into(),
        "/etc/nginx/*.pem".into(),
    ]
}

/// Scan certs; emit CertExpiring events for those past the thresholds.
pub fn scan_certs(
    certs: &[String],
    cfg: &Config,
    now: i64,
    ts: i64,
    host_id: &str,
    runner: &dyn crate::cmd::CommandRunner,
) -> Vec<AgentEvent> {
    let mut evs = Vec::new();
    for path in certs {
        let Ok(out) = runner.run(&["x509", "-enddate", "-noout", "-in", path]) else {
            continue; // unreadable / not a cert — fail-open
        };
        let Some(not_after) = out.lines().find_map(parse_enddate) else {
            continue;
        };
        let sev = cert_severity(not_after, now, cfg);
        if sev == Severity::Info {
            continue;
        }
        let days_left = (not_after - now) / 86400;
        evs.push(AgentEvent {
            id: format!("cert-{}-{}", path, ts),
            ts,
            host_id: host_id.into(),
            key: format!("cert:{}", path),
            kind: EventKind::CertExpiring.into(),
            severity: sev,
            summary: format!("certificate {} expires in {} days", path, days_left),
            evidence: vec![Evidence {
                ts,
                source: "certs".into(),
                detail: format!(
                    "Path={} NotAfter={} DaysLeft={}",
                    path, not_after, days_left
                ),
            }],
            ..Default::default()
        });
    }
    evs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(paths: Vec<String>) -> Config {
        Config {
            cert_paths: paths,
            cert_warn_days: 14,
            cert_crit_days: 3,
            ..Default::default()
        }
    }

    #[test]
    fn parses_openssl_enddate() {
        let got = parse_enddate("notAfter=Sep 16 12:00:00 2026 GMT");
        assert!(got.is_some());
        let expected = picket_common::civil::parse_gm_date("Sep 16 12:00:00 2026").unwrap();
        assert_eq!(got.unwrap(), expected);
    }

    #[test]
    fn enddate_parse_rejects_garbage() {
        assert!(parse_enddate("notAfter=foo").is_none());
        assert!(parse_enddate("").is_none());
    }

    #[test]
    fn severity_by_remaining_days() {
        let cfg = cfg_with(vec![]);
        let now = picket_common::civil::parse_gm_date("Sep 1 00:00:00 2026").unwrap();
        let expires_in_10d = picket_common::civil::parse_gm_date("Sep 11 00:00:00 2026").unwrap();
        assert_eq!(cert_severity(expires_in_10d, now, &cfg), Severity::Warning);
        let expires_in_2d = picket_common::civil::parse_gm_date("Sep 3 00:00:00 2026").unwrap();
        assert_eq!(cert_severity(expires_in_2d, now, &cfg), Severity::Critical);
        let expires_in_30d = picket_common::civil::parse_gm_date("Oct 1 00:00:00 2026").unwrap();
        assert_eq!(cert_severity(expires_in_30d, now, &cfg), Severity::Info);
        let expired = picket_common::civil::parse_gm_date("Aug 1 00:00:00 2026").unwrap();
        assert_eq!(cert_severity(expired, now, &cfg), Severity::Critical);
    }

    #[test]
    fn expand_paths_resolves_globs_and_files() {
        let dir = std::env::temp_dir().join(format!("certs-expand-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("live/example.com")).unwrap();
        let cert = dir.join("live/example.com/cert.pem");
        std::fs::write(&cert, "-----BEGIN CERTIFICATE-----\n").unwrap();
        let glob = dir.join("live/*/cert.pem");
        let paths = expand_paths(&[
            glob.to_string_lossy().into_owned(),
            "/definitely/missing.pem".into(),
        ]);
        assert_eq!(paths, vec![cert.to_string_lossy().into_owned()]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scan_emits_for_expiring_cert() {
        let runner = crate::cmd::FakeCli("notAfter=Sep 10 00:00:00 2026 GMT\n".into());
        let cfg = cfg_with(vec!["/etc/test/cert.pem".to_string()]);
        let now = picket_common::civil::parse_gm_date("Sep 1 00:00:00 2026").unwrap();
        let evs = scan_certs(
            &["/etc/test/cert.pem".to_string()],
            &cfg,
            now,
            1000,
            "h-1",
            &runner,
        );
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, EventKind::CertExpiring);
        assert_eq!(evs[0].severity, Severity::Warning);
        assert_eq!(evs[0].key, "cert:/etc/test/cert.pem");
    }
}
