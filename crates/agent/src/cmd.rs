use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub trait CommandRunner {
    fn run(&self, args: &[&str]) -> Result<String, String>;
}

/// An external CLI (systemctl, journalctl, docker, openssl), run with a
/// timeout; a non-zero exit is an error carrying stderr.
pub struct Cli(pub &'static str);

impl CommandRunner for Cli {
    fn run(&self, args: &[&str]) -> Result<String, String> {
        let out = run_with_timeout(self.0, args).map_err(|e| e.to_string())?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "{} exited {}: {}",
                self.0,
                out.status,
                stderr.trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// Test double: returns `.0`, or fails ("exit 1") when it is empty.
#[cfg(test)]
pub struct FakeCli(pub String);

#[cfg(test)]
impl CommandRunner for FakeCli {
    fn run(&self, _args: &[&str]) -> Result<String, String> {
        if self.0.is_empty() {
            Err("exit 1".into())
        } else {
            Ok(self.0.clone())
        }
    }
}

/// The external programs the agent spawns, bundled so `run_once` takes one
/// parameter instead of growing args.
pub struct Runners {
    pub sys: Box<dyn CommandRunner>,
    pub journal: Box<dyn CommandRunner>,
    pub docker: Box<dyn CommandRunner>,
    pub openssl: Box<dyn CommandRunner>,
}

impl Runners {
    pub fn real() -> Self {
        Runners {
            sys: Box::new(Cli("systemctl")),
            journal: Box::new(Cli("journalctl")),
            docker: Box::new(Cli("docker")),
            openssl: Box::new(Cli("openssl")),
        }
    }

    #[cfg(test)]
    pub fn with_fakes(
        sys: Box<dyn CommandRunner>,
        journal: Box<dyn CommandRunner>,
        docker: Box<dyn CommandRunner>,
        openssl: Box<dyn CommandRunner>,
    ) -> Self {
        Runners {
            sys,
            journal,
            docker,
            openssl,
        }
    }
}

/// Spawn `program` with stdout/stderr captured and kill it after TIMEOUT.
/// Reader threads drain the pipes so a verbose child cannot deadlock us.
fn run_with_timeout(program: &str, args: &[&str]) -> Result<Output, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;

    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).ok();
        buf
    });
    let err_reader = thread::spawn(move || {
        let mut buf = Vec::new();
        stderr.read_to_end(&mut buf).ok();
        buf
    });

    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
            break st;
        }
        if start.elapsed() >= TIMEOUT {
            child.kill().ok();
            child.wait().ok();
            let err = err_reader.join().unwrap_or_default();
            let stderr = String::from_utf8_lossy(&err);
            return Err(format!(
                "{} timed out after 10s: {}",
                program,
                stderr.trim()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    };

    Ok(Output {
        status,
        stdout: out_reader.join().unwrap_or_default(),
        stderr: err_reader.join().unwrap_or_default(),
    })
}

const TIMEOUT: Duration = Duration::from_secs(10);
