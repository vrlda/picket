//! watchtower-runner: takes agent tasks from Watchtower and runs a local
//! coding agent on them.
//!
//! Connectivity is outbound HTTPS only (long-poll), so the runner works
//! from behind NAT on a machine with no public address. Watchtower sends a
//! profile name and incident context — never commands or paths: how the
//! agent runs is decided by this machine's config.

pub mod config;
pub mod prompt;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use config::{Autonomy, Isolation, Profile, RunnerConfig};
use prompt::AgentResult;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------- HTTP client ----------

pub struct Client {
    base: String,
    token: String,
    agent: ureq::Agent,
}

#[derive(Debug)]
pub enum ApiError {
    /// HTTP status + server message.
    Status(u16, String),
    Transport(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Status(c, m) => write!(f, "http {c}: {m}"),
            ApiError::Transport(m) => write!(f, "transport: {m}"),
        }
    }
}

impl Client {
    pub fn new(cfg: &RunnerConfig) -> Self {
        Client {
            base: cfg.server_url.trim_end_matches('/').to_string(),
            token: cfg.token.clone(),
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(15))
                // long-poll requests stay open for poll_timeout_secs
                .timeout_read(Duration::from_secs(cfg.poll_timeout_secs + 30))
                .build(),
        }
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> Result<(u16, Value), ApiError> {
        let req = self
            .agent
            .request(method, &format!("{}{}", self.base, path))
            .set("Authorization", &format!("Bearer {token}"));
        let res = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match res {
            Ok(resp) => {
                let status = resp.status();
                let v = resp.into_json::<Value>().unwrap_or(Value::Null);
                Ok((status, v))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let v = resp.into_json::<Value>().unwrap_or(Value::Null);
                Err(ApiError::Status(
                    code,
                    v["error"].as_str().unwrap_or("").to_string(),
                ))
            }
            // never include the URL: keep logs tidy (no secrets in URLs here, but consistent with the server)
            Err(ureq::Error::Transport(t)) => Err(ApiError::Transport(
                t.message()
                    .map(String::from)
                    .unwrap_or_else(|| t.kind().to_string()),
            )),
        }
    }

    fn runner(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<(u16, Value), ApiError> {
        self.send(method, path, &self.token, body)
    }

    pub fn register(&self, labels: &[String], capabilities: &[String]) -> Result<(), ApiError> {
        self.runner(
            "POST",
            "/v1/runners/register",
            Some(json!({ "version": VERSION, "labels": labels, "capabilities": capabilities })),
        )
        .map(|_| ())
    }

    /// Long-poll for a task (claims it). None = nothing within the timeout.
    pub fn next(&self, timeout_secs: u64) -> Result<Option<Value>, ApiError> {
        let (status, v) = self.runner(
            "GET",
            &format!("/v1/agent-tasks/next?timeout={timeout_secs}"),
            None,
        )?;
        Ok((status == 200).then(|| v["task"].clone()))
    }

    pub fn heartbeat(&self, task_id: &str) -> Result<(), ApiError> {
        self.runner(
            "POST",
            &format!("/v1/agent-tasks/{task_id}/heartbeat"),
            None,
        )
        .map(|_| ())
    }

    pub fn started(&self, task_id: &str, agent: &str) -> Result<(), ApiError> {
        self.runner(
            "POST",
            &format!("/v1/agent-tasks/{task_id}/started"),
            Some(json!({ "agent": agent })),
        )
        .map(|_| ())
    }

    pub fn complete(&self, task_id: &str, result: &AgentResult) -> Result<Value, ApiError> {
        self.runner(
            "POST",
            &format!("/v1/agent-tasks/{task_id}/complete"),
            Some(serde_json::to_value(result).unwrap_or_default()),
        )
        .map(|(_, v)| v)
    }

    pub fn fail(&self, task_id: &str, error: &str, retryable: bool) -> Result<Value, ApiError> {
        self.runner(
            "POST",
            &format!("/v1/agent-tasks/{task_id}/fail"),
            Some(json!({ "error": error, "retryable": retryable })),
        )
        .map(|(_, v)| v)
    }

    /// Task context with the task-scoped token.
    pub fn context(&self, task_id: &str, context_token: &str) -> Result<Value, ApiError> {
        self.send(
            "GET",
            &format!("/v1/agent-tasks/{task_id}/context"),
            context_token,
            None,
        )
        .map(|(_, v)| v)
    }
}

// ---------- git workspace ----------

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Where the agent works for one task.
pub struct Workspace {
    pub dir: PathBuf,
    pub repo: PathBuf,
    /// Commit the task started from (git workspaces).
    pub base: Option<String>,
    pub branch: Option<String>,
    pub worktree: bool,
}

/// Task id → a safe path/branch component.
fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub fn prepare_workspace(
    cfg: &RunnerConfig,
    profile: &Profile,
    task_id: &str,
) -> Result<Workspace, String> {
    let repo = profile.workspace.clone();
    if !repo.is_dir() {
        return Err(format!("workspace {} does not exist", repo.display()));
    }
    let base = git(&repo, &["rev-parse", "HEAD"]).ok();
    let isolate = profile.isolation == Isolation::Worktree && profile.autonomy.modifies();
    if !isolate {
        return Ok(Workspace {
            dir: repo.clone(),
            repo,
            base,
            branch: None,
            worktree: false,
        });
    }
    let base = base.ok_or_else(|| {
        format!(
            "workspace {} is not a git repository (worktree isolation needs git; set isolation = \"none\" to work in place)",
            repo.display()
        )
    })?;
    let name = sanitize(task_id);
    let branch = format!("watchtower/{name}");
    let dir = cfg.work_dir.join("worktrees").join(&name);
    std::fs::create_dir_all(dir.parent().unwrap()).map_err(|e| format!("work_dir: {e}"))?;
    if dir.exists() {
        // a retry of the same task: start clean
        let _ = git(
            &repo,
            &["worktree", "remove", "--force", &dir.to_string_lossy()],
        );
        let _ = git(&repo, &["branch", "-D", &branch]);
    }
    git(
        &repo,
        &[
            "worktree",
            "add",
            "-b",
            &branch,
            &dir.to_string_lossy(),
            &base,
        ],
    )?;
    Ok(Workspace {
        dir,
        repo,
        base: Some(base),
        branch: Some(branch),
        worktree: true,
    })
}

/// Files the agent changed: committed since `base`, staged, unstaged and
/// untracked. Err when git is unavailable.
pub fn changed_files(ws: &Workspace) -> Result<Vec<String>, String> {
    let Some(base) = &ws.base else {
        return Ok(Vec::new());
    };
    let mut files: Vec<String> = Vec::new();
    for out in [
        git(&ws.dir, &["diff", "--name-only", base])?,
        git(&ws.dir, &["ls-files", "--others", "--exclude-standard"])?,
    ] {
        for f in out.lines().filter(|l| !l.is_empty()) {
            if !files.iter().any(|x| x == f) {
                files.push(f.to_string());
            }
        }
    }
    files.sort();
    Ok(files)
}

pub fn matching(files: &[String], globs: &[String]) -> Vec<String> {
    let pats: Vec<glob::Pattern> = globs
        .iter()
        .filter_map(|g| glob::Pattern::new(g).ok())
        .collect();
    files
        .iter()
        .filter(|f| pats.iter().any(|p| p.matches(f)))
        .cloned()
        .collect()
}

/// Runner-side policy enforcement after the agent ran: autonomy level and
/// path rules are checked against what actually changed, independent of
/// what the agent claims. Violations turn the result into an escalation;
/// worktree changes stay on their branch for a human to inspect.
pub fn enforce(profile: &Profile, ws: &Workspace, mut result: AgentResult) -> AgentResult {
    let files = match changed_files(ws) {
        Ok(f) => f,
        Err(e) => {
            result.outcome = "needs_human".into();
            result.needs_human_reason = format!("runner could not verify the changes: {e}");
            return result;
        }
    };
    let commits = ws
        .base
        .as_ref()
        .and_then(|b| git(&ws.dir, &["rev-list", "--count", &format!("{b}..HEAD")]).ok())
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(0);
    let mut violations = Vec::new();
    if !profile.autonomy.modifies() && !files.is_empty() {
        violations.push(format!(
            "autonomy is investigate but files changed: {}",
            files.join(", ")
        ));
    }
    if profile.autonomy == Autonomy::Patch && commits > 0 {
        violations.push(format!(
            "autonomy is patch but {commits} commit(s) were made"
        ));
    }
    let blocked = matching(&files, &profile.blocked_paths);
    if !blocked.is_empty() {
        violations.push(format!(
            "changes touch blocked paths: {}",
            blocked.join(", ")
        ));
    }
    let approval = matching(&files, &profile.require_human_approval_paths);
    if !approval.is_empty() {
        violations.push(format!(
            "changes need human approval: {}",
            approval.join(", ")
        ));
    }
    let mut changes = json!({
        "files": files,
        "commits": commits,
        "branch": ws.branch,
        "worktree": ws.worktree.then(|| ws.dir.display().to_string()),
        "base": ws.base,
    });
    if commits > 0 {
        changes["head"] = json!(git(&ws.dir, &["rev-parse", "HEAD"]).ok());
    }
    if let Some(agent_changes) = result.changes.as_object() {
        changes["reported"] = json!(agent_changes);
    }
    result.changes = changes;
    if !violations.is_empty() {
        let reason = violations.join("; ");
        result.needs_human_reason = if result.needs_human_reason.is_empty() {
            format!("runner policy check: {reason}")
        } else {
            format!(
                "{} (runner policy check: {reason})",
                result.needs_human_reason
            )
        };
        result.outcome = "needs_human".into();
    } else if result.outcome == "fixed" && files.is_empty() && commits == 0 && ws.base.is_some() {
        // claimed a fix but nothing changed in the workspace (a deploy-only
        // or config fix is still possible — keep it, but say so)
        result
            .actions
            .push("runner: no file changes detected in the workspace".into());
    }
    result
}

/// Remove a worktree that holds no changes (kept otherwise, for review).
pub fn cleanup(ws: &Workspace, result: &AgentResult) {
    if !ws.worktree {
        return;
    }
    let empty = result.changes["files"]
        .as_array()
        .is_none_or(|f| f.is_empty())
        && result.changes["commits"].as_u64().unwrap_or(0) == 0;
    if empty {
        let _ = git(
            &ws.repo,
            &["worktree", "remove", "--force", &ws.dir.to_string_lossy()],
        );
        if let Some(b) = &ws.branch {
            let _ = git(&ws.repo, &["branch", "-D", b]);
        }
    }
}

// ---------- adapters ----------

/// argv for a profile. The prompt reaches `command` adapters on stdin; the
/// claude-code preset gets it as the -p argument.
pub fn adapter_argv(profile: &Profile, prompt: &str) -> Vec<String> {
    if profile.adapter == "command" {
        let mut argv = profile.command.clone();
        argv.extend(profile.extra_args.iter().cloned());
        return argv;
    }
    let mut argv = vec![
        profile.claude_bin.clone(),
        "-p".into(),
        prompt.into(),
        "--output-format".into(),
        "json".into(),
    ];
    let (mode, default_tools): (&str, &[&str]) = match profile.autonomy {
        Autonomy::Investigate => ("plan", &["Read", "Grep", "Glob", "WebFetch"]),
        _ => (
            "acceptEdits",
            &["Read", "Grep", "Glob", "Edit", "Write", "Bash"],
        ),
    };
    argv.extend(["--permission-mode".into(), mode.into()]);
    let tools: Vec<String> = if profile.allowed_tools.is_empty() {
        default_tools.iter().map(|s| s.to_string()).collect()
    } else {
        profile.allowed_tools.clone()
    };
    argv.push("--allowedTools".into());
    argv.push(tools.join(","));
    if !profile.model.is_empty() {
        argv.extend(["--model".into(), profile.model.clone()]);
    }
    argv.extend(profile.extra_args.iter().cloned());
    argv
}

pub struct RunOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
    pub timed_out: bool,
    pub cancelled: bool,
}

/// Run argv in `dir` with env, killing it on timeout or cancel.
pub fn run_process(
    argv: &[String],
    dir: &Path,
    env: &[(String, String)],
    stdin_text: Option<&str>,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<RunOutput, String> {
    let (prog, args) = argv.split_first().ok_or("empty command")?;
    let mut child = Command::new(prog)
        .args(args)
        .current_dir(dir)
        .envs(env.iter().cloned())
        .stdin(if stdin_text.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start {prog}: {e}"))?;
    if let (Some(text), Some(mut stdin)) = (stdin_text, child.stdin.take()) {
        let text = text.to_string();
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = stdin.write_all(text.as_bytes());
        });
    }
    // drain pipes on threads so a chatty agent can't deadlock on a full pipe
    let read = |pipe: Option<Box<dyn std::io::Read + Send>>| {
        std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_string(&mut s);
            }
            s
        })
    };
    let out = read(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
    );
    let err = read(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn std::io::Read + Send>),
    );
    let start = Instant::now();
    let (mut timed_out, mut cancelled) = (false, false);
    let status = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break Some(s);
        }
        if start.elapsed() > timeout {
            timed_out = true;
        } else if cancel.load(Ordering::SeqCst) {
            cancelled = true;
        }
        if timed_out || cancelled {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    Ok(RunOutput {
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
        success: status.is_some_and(|s| s.success()),
        timed_out,
        cancelled,
    })
}

// ---------- one task ----------

fn tail(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    chars[chars.len().saturating_sub(n)..].iter().collect()
}

/// What happened to a task (for logs/tests).
#[derive(Debug, PartialEq, Eq)]
pub enum TaskOutcome {
    Completed(String),
    Failed(String),
    /// Lease lost / cancelled server-side.
    Abandoned,
}

/// Report an execution failure (retryable: runner/CLI/infra problem).
fn fail_task(client: &Client, id: &str, error: &str, retryable: bool) -> TaskOutcome {
    eprintln!("task {id}: failed: {error}");
    let _ = client.fail(id, error, retryable);
    TaskOutcome::Failed(error.to_string())
}

/// Execute one claimed task end to end and report it.
pub fn run_task(cfg: &RunnerConfig, client: &Client, task: &Value) -> TaskOutcome {
    let id = task["task_id"].as_str().unwrap_or_default().to_string();
    let profile_name = task["profile"].as_str().unwrap_or_default();
    let Some(profile) = cfg.profiles.get(profile_name) else {
        return fail_task(
            client,
            &id,
            &format!(
                "profile {profile_name:?} is not configured on runner {}",
                cfg.runner_id
            ),
            false,
        );
    };
    // keep the lease alive while the agent works; a 409 means we lost it
    let cancel = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let lease = task["lease_secs"].as_u64().unwrap_or(300).max(30);
    let hb = {
        let (cancel, done) = (cancel.clone(), done.clone());
        let hb_client = Client::new(cfg);
        let id = id.clone();
        std::thread::spawn(move || {
            let every = Duration::from_secs((lease / 3).max(5));
            let mut last = Instant::now();
            while !done.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(250));
                if last.elapsed() < every {
                    continue;
                }
                last = Instant::now();
                if let Err(ApiError::Status(409 | 404, msg)) = hb_client.heartbeat(&id) {
                    eprintln!("task {id}: lease lost ({msg}) — stopping the agent");
                    cancel.store(true, Ordering::SeqCst);
                    return;
                }
            }
        })
    };
    let outcome = execute(cfg, client, task, &id, profile_name, profile, &cancel);
    done.store(true, Ordering::SeqCst);
    let _ = hb.join();
    outcome
}

fn execute(
    cfg: &RunnerConfig,
    client: &Client,
    task: &Value,
    id: &str,
    profile_name: &str,
    profile: &Profile,
    cancel: &AtomicBool,
) -> TaskOutcome {
    let token = task["context_token"].as_str().unwrap_or_default();
    let context = match client.context(id, token) {
        Ok(c) => c,
        Err(e) => return fail_task(client, id, &format!("cannot fetch task context: {e}"), true),
    };
    let ws = match prepare_workspace(cfg, profile, id) {
        Ok(ws) => ws,
        Err(e) => return fail_task(client, id, &e, false),
    };
    let extra = profile
        .prompt_file
        .as_ref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .unwrap_or_default();
    let prompt = prompt::build_prompt(&prompt::PromptInput {
        task_id: id,
        attempt: task["attempt"].as_i64().unwrap_or(1),
        max_attempts: task["max_attempts"].as_i64().unwrap_or(1),
        profile_name,
        profile,
        server_url: &cfg.server_url,
        context: &context,
        branch: ws.branch.as_deref(),
        extra: &extra,
    });
    let logs = cfg.work_dir.join("logs");
    let _ = std::fs::create_dir_all(&logs);
    let prompt_path = logs.join(format!("{}.prompt.txt", sanitize(id)));
    let _ = std::fs::write(&prompt_path, &prompt);
    let agent_name = if profile.adapter == "claude-code" {
        "Claude Code"
    } else {
        "agent"
    };
    if let Err(e) = client.started(id, agent_name) {
        if matches!(e, ApiError::Status(409 | 404, _)) {
            return TaskOutcome::Abandoned;
        }
    }
    eprintln!("task {id}: running {agent_name} in {}", ws.dir.display());
    let env = vec![
        ("WATCHTOWER_URL".to_string(), cfg.server_url.clone()),
        ("WATCHTOWER_TASK_ID".to_string(), id.to_string()),
        ("WATCHTOWER_TASK_TOKEN".to_string(), token.to_string()),
        (
            "WATCHTOWER_PROMPT_FILE".to_string(),
            prompt_path.display().to_string(),
        ),
        (
            "WATCHTOWER_AUTONOMY".to_string(),
            format!("{:?}", profile.autonomy).to_lowercase(),
        ),
    ];
    let argv = adapter_argv(profile, &prompt);
    let stdin = (profile.adapter == "command").then_some(prompt.as_str());
    let run = run_process(
        &argv,
        &ws.dir,
        &env,
        stdin,
        Duration::from_secs(profile.timeout_secs.max(60)),
        cancel,
    );
    let run = match run {
        Ok(r) => r,
        Err(e) => return fail_task(client, id, &e, false),
    };
    let _ = std::fs::write(
        logs.join(format!("{}.log", sanitize(id))),
        format!(
            "--- stdout ---\n{}\n--- stderr ---\n{}\n",
            run.stdout, run.stderr
        ),
    );
    if run.cancelled {
        return TaskOutcome::Abandoned;
    }
    if run.timed_out {
        return fail_task(
            client,
            id,
            &format!("agent timed out after {}s", profile.timeout_secs),
            true,
        );
    }
    let text = if profile.adapter == "claude-code" {
        match prompt::unwrap_claude_output(&run.stdout) {
            Ok(t) => t,
            Err(e) => return fail_task(client, id, &e, true),
        }
    } else {
        run.stdout.clone()
    };
    let result = match prompt::parse_result(&text) {
        Some(r) => r,
        None if !run.success => {
            return fail_task(
                client,
                id,
                &format!(
                    "agent exited with an error: {}",
                    tail(run.stderr.trim(), 500)
                ),
                true,
            )
        }
        // the agent finished but gave no structured verdict: hand its
        // words to a human rather than guessing
        None => AgentResult {
            outcome: "needs_human".into(),
            summary: tail(text.trim(), 1500),
            needs_human_reason: "the agent finished without a structured result".into(),
            ..Default::default()
        },
    };
    let result = enforce(profile, &ws, result);
    cleanup(&ws, &result);
    match client.complete(id, &result) {
        Ok(v) => {
            let status = v["status"].as_str().unwrap_or("").to_string();
            eprintln!("task {id}: completed ({}) → {status}", result.outcome);
            TaskOutcome::Completed(status)
        }
        Err(ApiError::Status(409 | 404, _)) => TaskOutcome::Abandoned,
        Err(e) => TaskOutcome::Failed(format!("could not report the result: {e}")),
    }
}

/// One poll: wait for a task and run it. Returns the outcome, or None when
/// no task arrived.
pub fn poll_once(cfg: &RunnerConfig, client: &Client) -> Result<Option<TaskOutcome>, ApiError> {
    match client.next(cfg.poll_timeout_secs)? {
        Some(task) => Ok(Some(run_task(cfg, client, &task))),
        None => Ok(None),
    }
}

/// Run forever: register, then long-poll for tasks with backoff on errors.
pub fn run_forever(cfg: &RunnerConfig) -> ! {
    let client = Client::new(cfg);
    let capabilities: Vec<String> = cfg.profiles.keys().cloned().collect();
    let mut backoff = 2u64;
    loop {
        match client.register(&cfg.labels, &capabilities) {
            Ok(()) => break,
            Err(e) => {
                eprintln!("register failed ({e}); retrying in {backoff}s");
                std::thread::sleep(Duration::from_secs(backoff));
                backoff = (backoff * 2).min(60);
            }
        }
    }
    eprintln!(
        "watchtower-runner {VERSION}: {} connected to {}",
        cfg.runner_id, cfg.server_url
    );
    backoff = 2;
    loop {
        match poll_once(cfg, &client) {
            Ok(_) => backoff = 2,
            Err(ApiError::Status(401, _)) => {
                eprintln!("runner token rejected — check runner_id/token against the server's [runners.{}]", cfg.runner_id);
                std::thread::sleep(Duration::from_secs(60));
            }
            Err(e) => {
                eprintln!("poll failed ({e}); retrying in {backoff}s");
                std::thread::sleep(Duration::from_secs(backoff));
                backoff = (backoff * 2).min(60);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_argv_follows_autonomy() {
        let mut p = Profile::default();
        let argv = adapter_argv(&p, "PROMPT");
        assert_eq!(&argv[..3], &["claude", "-p", "PROMPT"]);
        let joined = argv.join(" ");
        assert!(joined.contains("--permission-mode plan"));
        assert!(!joined.contains("Bash"), "investigate gets no shell");
        p.autonomy = Autonomy::Patch;
        p.model = "claude-opus-5-5".into();
        let joined = adapter_argv(&p, "x").join(" ");
        assert!(joined.contains("--permission-mode acceptEdits"));
        assert!(joined.contains("Edit,Write,Bash"));
        assert!(joined.contains("--model claude-opus-5-5"));
        p.allowed_tools = vec!["Read".into(), "Bash(cargo test:*)".into()];
        assert!(adapter_argv(&p, "x")
            .join(" ")
            .contains("--allowedTools Read,Bash(cargo test:*)"));
        let cmd = Profile {
            adapter: "command".into(),
            command: vec!["agent".into(), "--json".into()],
            ..Default::default()
        };
        assert_eq!(adapter_argv(&cmd, "x"), vec!["agent", "--json"]);
    }

    #[test]
    fn process_timeout_and_cancel() {
        let cancel = AtomicBool::new(false);
        let out = run_process(
            &["sh".into(), "-c".into(), "cat; echo done".into()],
            Path::new("."),
            &[],
            Some("hi "),
            Duration::from_secs(10),
            &cancel,
        )
        .unwrap();
        assert!(out.success);
        assert_eq!(out.stdout.trim(), "hi done");
        let slow = run_process(
            &["sleep".into(), "5".into()],
            Path::new("."),
            &[],
            None,
            Duration::from_millis(300),
            &cancel,
        )
        .unwrap();
        assert!(slow.timed_out && !slow.success);
        cancel.store(true, Ordering::SeqCst);
        let c = run_process(
            &["sleep".into(), "5".into()],
            Path::new("."),
            &[],
            None,
            Duration::from_secs(10),
            &cancel,
        )
        .unwrap();
        assert!(c.cancelled);
    }

    #[test]
    fn glob_matching() {
        let files = vec!["src/ledger/post.rs".to_string(), "src/api/x.rs".to_string()];
        assert_eq!(
            matching(&files, &["src/ledger/**".into()]),
            vec!["src/ledger/post.rs".to_string()]
        );
        assert!(matching(&files, &["migrations/**".into()]).is_empty());
    }
}
