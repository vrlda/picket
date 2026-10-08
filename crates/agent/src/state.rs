//! Agent state persisted across restarts (JSON). Written periodically; a
//! crash loses at most the last interval.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)] // a field added later must not discard an older state file
pub struct PersistedState {
    pub seen_ips: Vec<String>,
    pub journal_cursor_ms: i64,
    pub last_cert_scan: i64,
    pub known_exes: Vec<String>,
    /// Netflow baseline: listening ports and outbound destinations ever seen.
    pub seen_listen: Vec<String>,
    pub seen_remote: Vec<String>,
}

pub fn load(path: &Path) -> PersistedState {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save(path: &Path, s: &PersistedState) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string(s) {
        let _ = std::fs::write(path, json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let p = std::env::temp_dir().join(format!("wt-state-{}", std::process::id()));
        let s = PersistedState {
            seen_ips: vec!["1.2.3.4".into()],
            journal_cursor_ms: 123,
            last_cert_scan: 456,
            known_exes: vec!["/usr/bin/x".into()],
            ..Default::default()
        };
        save(&p, &s);
        let loaded = load(&p);
        assert_eq!(loaded.seen_ips, s.seen_ips);
        assert_eq!(loaded.journal_cursor_ms, 123);
        assert_eq!(loaded.known_exes, s.known_exes);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn state_file_from_an_older_version_still_loads() {
        // v0.6.0 files have no netflow fields; they must not reset ssh/exec state
        let p = std::env::temp_dir().join(format!("wt-state-old-{}", std::process::id()));
        std::fs::write(
            &p,
            r#"{"seen_ips":["1.2.3.4"],"journal_cursor_ms":5,"last_cert_scan":0,"known_exes":[]}"#,
        )
        .unwrap();
        let loaded = load(&p);
        assert_eq!(loaded.seen_ips, vec!["1.2.3.4".to_string()]);
        assert!(loaded.seen_remote.is_empty());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn missing_file_is_default() {
        let p = std::env::temp_dir().join("definitely-missing-wt-state");
        assert_eq!(load(&p), PersistedState::default());
    }

    #[test]
    fn corrupt_file_is_default() {
        let p = std::env::temp_dir().join(format!("wt-state-bad-{}", std::process::id()));
        std::fs::write(&p, "not json").unwrap();
        assert_eq!(load(&p), PersistedState::default());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn save_creates_missing_parent_dir() {
        let dir = std::env::temp_dir()
            .join(format!("wt-absent-{}", std::process::id()))
            .join("nested");
        let p = dir.join("wt-state-test");
        let _ = std::fs::remove_dir_all(&dir);
        save(&p, &PersistedState::default());
        assert!(dir.exists(), "parent dir must be created");
        assert!(p.exists(), "state file must exist after save");
        assert_eq!(load(&p), PersistedState::default());
        std::fs::remove_dir_all(&dir).ok();
    }
}
