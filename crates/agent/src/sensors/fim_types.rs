use std::path::{Path, PathBuf};

use picket_common::{AgentEvent, EventKind, Evidence, Severity};

/// One watched file. The PARENT directory is watched so atomic-replace
/// (rename over) edits are caught; events are filtered by filename.
#[derive(Debug, Clone)]
// watched files are wired on linux (main.rs + fim.rs); on other targets the
// watcher is compiled out so the type would be dead
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct WatchedFile {
    pub path: PathBuf,
    file_name: String,
}

impl WatchedFile {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn new(path: &str) -> Self {
        let p = PathBuf::from(path);
        let file_name = p
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        WatchedFile { path: p, file_name }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn parent(&self) -> PathBuf {
        self.path.parent().unwrap_or(Path::new("/")).to_path_buf()
    }

    /// Does an inotify name event concern the watched file?
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn relevant(&self, name: Option<&std::ffi::OsStr>) -> bool {
        name.map(|n| n.to_string_lossy() == self.file_name)
            .unwrap_or(false)
    }
}

/// A raw change observed by the watcher thread.
#[derive(Debug, Clone, PartialEq)]
pub struct FimEvent {
    pub path: String,
    pub action: String,
}

/// Build the agent event for a FimEvent.
pub fn change_event(path: &str, action: &str, ts: i64, host_id: &str) -> AgentEvent {
    AgentEvent {
        id: format!("fim-{}-{}", path, ts),
        ts,
        host_id: host_id.into(),
        key: format!("fim:{}", path),
        kind: EventKind::FileChanged.into(),
        severity: Severity::Warning,
        summary: format!("{} changed ({})", path, action),
        evidence: vec![Evidence {
            ts,
            source: "fim".into(),
            detail: format!("Action={}", action),
        }],
        ..Default::default()
    }
}

/// Human-readable name for the masks we care about (inotify event bits).
// used by the inotify watcher (linux) and unit tests
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn mask_name(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x8 != 0 {
        parts.push("CLOSE_WRITE");
    }
    if flags & 0x80 != 0 {
        parts.push("MOVED_TO");
    }
    if flags & 0x200 != 0 {
        parts.push("DELETE");
    }
    if flags & 0x2 != 0 {
        parts.push("MODIFY");
    }
    if parts.is_empty() {
        parts.push("OTHER");
    }
    parts.join("|")
}

#[cfg(test)]
mod tests {
    use super::*;
    use picket_common::{EventKind, Severity};

    #[test]
    fn relevant_matches_only_target_filename() {
        let watcher = WatchedFile::new("/etc/myapp/config.yml");
        assert!(watcher.relevant(Some(std::ffi::OsStr::new("config.yml"))));
        assert!(!watcher.relevant(Some(std::ffi::OsStr::new("config.yml.swp"))));
        assert!(!watcher.relevant(Some(std::ffi::OsStr::new("other.conf"))));
        assert!(!watcher.relevant(None));
    }

    #[test]
    fn change_event_formatting() {
        let ev = change_event("/etc/myapp/config.yml", "CLOSE_WRITE", 1234, "h");
        assert_eq!(ev.kind, EventKind::FileChanged);
        assert_eq!(ev.severity, Severity::Warning);
        assert_eq!(ev.key, "fim:/etc/myapp/config.yml");
        assert_eq!(ev.summary, "/etc/myapp/config.yml changed (CLOSE_WRITE)");
        assert_eq!(ev.evidence[0].source, "fim");
    }

    #[test]
    fn mask_name_maps_bits() {
        assert_eq!(mask_name(0x8), "CLOSE_WRITE");
        assert_eq!(mask_name(0x80), "MOVED_TO");
        assert_eq!(mask_name(0x200), "DELETE");
        assert_eq!(mask_name(0x2), "MODIFY");
        assert_eq!(mask_name(0x8 | 0x80), "CLOSE_WRITE|MOVED_TO");
        assert_eq!(mask_name(0), "OTHER");
    }
}
