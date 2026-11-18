//! `thorn _run <key>`: runs inside the session's tmux pane, as the session
//! user, and keeps Claude Code running.
//!
//! - claude exits 0 (you typed /exit): the session ends; `thorn start`
//!   brings it back, and so does the next boot.
//! - claude exits with an error or is killed: wait, then resume the same
//!   conversation, backing off up to five minutes.

use crate::paths;
use crate::render::Launch;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

pub fn run(key: &str) -> Result<()> {
    let launch_path = paths::launch_file(key);
    let home = paths::session_home(key);
    let mut failures: u32 = 0;
    loop {
        // Re-read every time: an administrator may have changed the args.
        let text = std::fs::read_to_string(&launch_path)
            .with_context(|| format!("reading {}", launch_path.display()))?;
        let launch: Launch = toml::from_str(&text)?;
        let args = claude_args(&launch, conversation_exists(&home, &launch.conversation));

        println!(
            "blackthorn: starting session {} ({})",
            launch.name, launch.rc_name
        );
        let started = Instant::now();
        let status = Command::new(&launch.claude_bin)
            .args(&args)
            .env("SSH_AUTH_SOCK", paths::agent_socket(key))
            .env("DISABLE_AUTOUPDATER", "1")
            .env("HOME", &home)
            .status();

        match status {
            Ok(s) if s.success() => {
                println!(
                    "blackthorn: claude exited normally; session {} ends.",
                    launch.name
                );
                println!(
                    "blackthorn: start it again with: sudo thorn start {}",
                    launch.name
                );
                return Ok(());
            }
            Ok(s) => eprintln!("blackthorn: claude exited with {s}"),
            Err(e) => eprintln!("blackthorn: could not run {}: {e}", launch.claude_bin),
        }
        if started.elapsed() > Duration::from_secs(600) {
            failures = 0;
        }
        failures += 1;
        let wait = backoff(failures);
        eprintln!("blackthorn: restarting in {}s", wait.as_secs());
        std::thread::sleep(wait);
    }
}

pub fn claude_args(launch: &Launch, resume: bool) -> Vec<String> {
    let mut args = Vec::new();
    if resume {
        args.push("--resume".to_string());
    } else {
        // First start: create the conversation under our id.
        args.push("--session-id".to_string());
    }
    args.push(launch.conversation.clone());
    args.push("--remote-control".to_string());
    args.push(launch.rc_name.clone());
    args.extend(launch.args.iter().cloned());
    args
}

pub fn backoff(failures: u32) -> Duration {
    let secs = match failures {
        0 | 1 => 5,
        2 => 15,
        3 => 30,
        4 => 60,
        _ => 300,
    };
    Duration::from_secs(secs)
}

/// Claude Code keeps each conversation in ~/.claude/projects/<dir>/<id>.jsonl.
fn conversation_exists(home: &Path, id: &str) -> bool {
    let projects = home.join(".claude").join("projects");
    let Ok(dirs) = std::fs::read_dir(projects) else {
        return false;
    };
    dirs.flatten()
        .any(|d| d.path().join(format!("{id}.jsonl")).is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch() -> Launch {
        Launch {
            name: "ops".into(),
            conversation: "c0ffee00-0000-4000-8000-000000000000".into(),
            rc_name: "ops-hub".into(),
            claude_bin: "/usr/local/bin/claude".into(),
            args: vec!["--permission-mode".into(), "acceptEdits".into()],
        }
    }

    #[test]
    fn first_start_creates_then_resumes() {
        let first = claude_args(&launch(), false);
        assert_eq!(
            first,
            vec![
                "--session-id",
                "c0ffee00-0000-4000-8000-000000000000",
                "--remote-control",
                "ops-hub",
                "--permission-mode",
                "acceptEdits"
            ]
        );
        assert_eq!(claude_args(&launch(), true)[0], "--resume");
    }

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff(1).as_secs(), 5);
        assert!(backoff(3) > backoff(2));
        assert_eq!(backoff(50).as_secs(), 300);
    }

    #[test]
    fn finds_conversation_in_any_project_dir() {
        let home = tempfile::tempdir().unwrap();
        let id = "c0ffee00-0000-4000-8000-000000000000";
        assert!(!conversation_exists(home.path(), id));
        let dir = home
            .path()
            .join(".claude/projects/-var-lib-blackthorn-sessions-x-work");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{id}.jsonl")), "{}").unwrap();
        assert!(conversation_exists(home.path(), id));
    }
}
