//! `thorn _run <key>`: runs inside the space's tmux pane, as the space user,
//! and keeps the agent running.
//!
//! - Claude, server mode: `claude remote-control` serves many chats. When it
//!   stops for any reason it is started again in the same directory, which
//!   brings back the chats it was serving (Claude Code keeps them for about
//!   four hours).
//! - Claude, single mode: one conversation. Exit 0 (you typed /exit) ends
//!   the space until `thorn start` or the next boot; an error resumes the
//!   same conversation.
//! - Claude without Remote Control: one local conversation, like single
//!   mode, reached only through the hub's terminal.
//! - Other agents: restarted whenever they exit.
//!
//! Restarts back off from 5 seconds up to five minutes.

use crate::paths;
use crate::render::{Launch, LaunchKind};
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

pub fn run(key: &str) -> Result<()> {
    let launch_path = paths::launch_file(key);
    let home = paths::space_home(key);
    let mut failures: u32 = 0;
    loop {
        // Re-read every time: an administrator may have changed the args.
        let text = std::fs::read_to_string(&launch_path)
            .with_context(|| format!("reading {}", launch_path.display()))?;
        let launch: Launch = toml::from_str(&text)?;
        let mut args = agent_args(&launch, conversation_exists(&home, &launch.conversation));
        if launch.kind == LaunchKind::ClaudeServer
            && launch.remote_control
            && !knows_option(&launch.bin, &home, "create-session-in-dir")
        {
            // An older Claude Code: it makes the empty chat in the folder,
            // so give it the Remote Control name.
            args.retain(|a| a != "--no-create-session-in-dir");
            args.insert(1, "--name".into());
            args.insert(2, launch.rc_name.clone());
        }

        println!("blackthorn: starting space {}", launch.name);
        let started = Instant::now();
        // The unit starts in the home; the work folder is named after the
        // Remote Control name (spaces from before v0.6: "work").
        let workdir = if launch.workdir.is_empty() {
            home.join("work")
        } else {
            launch.workdir.clone().into()
        };
        let status = Command::new(&launch.bin)
            .current_dir(&workdir)
            .args(&args)
            .env("SSH_AUTH_SOCK", paths::agent_socket(key))
            .env("DISABLE_AUTOUPDATER", "1")
            .env("HOME", &home)
            .status();

        match status {
            Ok(s) if s.success() && one_conversation(&launch) => {
                println!(
                    "blackthorn: claude exited normally; space {} ends.",
                    launch.name
                );
                println!(
                    "blackthorn: start it again with: sudo thorn start {}",
                    launch.name
                );
                return Ok(());
            }
            Ok(s) => eprintln!("blackthorn: {} exited with {s}", launch.bin),
            Err(e) => eprintln!("blackthorn: could not run {}: {e}", launch.bin),
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

/// Claude with one conversation: single mode, or without Remote Control.
fn one_conversation(launch: &Launch) -> bool {
    launch.kind == LaunchKind::ClaudeSingle
        || (launch.kind == LaunchKind::ClaudeServer && !launch.remote_control)
}

pub fn agent_args(launch: &Launch, resume: bool) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    match launch.kind {
        LaunchKind::ClaudeServer | LaunchKind::ClaudeSingle if !launch.remote_control => {
            args.push(if resume { "--resume" } else { "--session-id" }.into());
            args.push(launch.conversation.clone());
            name_new(&mut args, launch, resume);
        }
        LaunchKind::ClaudeServer => {
            // No empty chat made at start: chats come from the Claude app
            // (named by Claude) and from the hub (named there). The
            // environment in the app is named after the folder.
            args.extend(["remote-control".into(), "--no-create-session-in-dir".into()]);
            args.extend(["--spawn".into(), "same-dir".into()]);
            args.extend(["--capacity".into(), launch.capacity.to_string()]);
            args.extend(remote_control_prefix(launch));
        }
        LaunchKind::ClaudeSingle => {
            // First start: create the conversation under our id.
            args.push(if resume { "--resume" } else { "--session-id" }.into());
            args.push(launch.conversation.clone());
            name_new(&mut args, launch, resume);
            args.push("--remote-control".into());
            args.extend(remote_control_prefix(launch));
        }
        LaunchKind::Command => {}
    }
    args.extend(launch.args.iter().cloned());
    args
}

/// `--remote-control NAME` would fix the chat's name in the Claude app to
/// NAME, whatever it is called. Without it the app shows the chat's own
/// name (given with --name or renamed later), else Claude's title for it,
/// else "<space's Remote Control name>-<random>" until there is one.
pub fn remote_control_prefix(launch: &Launch) -> [String; 2] {
    [
        "--remote-control-session-name-prefix".into(),
        launch.rc_name.clone(),
    ]
}

/// Whether `claude remote-control --help` mentions an option. Waits at most
/// ten seconds.
fn knows_option(bin: &str, home: &Path, option: &str) -> bool {
    use std::io::Read;
    let Ok(mut child) = Command::new(bin)
        .args(["remote-control", "--help"])
        .env("HOME", home)
        .env("DISABLE_AUTOUPDATER", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return false;
    };
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(100));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
    let mut text = String::new();
    child
        .stdout
        .take()
        .is_some_and(|mut o| o.read_to_string(&mut text).is_ok())
        && text.contains(option)
}

/// A new conversation starts with the name it was given, if any.
fn name_new(args: &mut Vec<String>, launch: &Launch, resume: bool) {
    if !resume && !launch.title.is_empty() {
        args.extend(["--name".into(), launch.title.clone()]);
    }
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

    fn launch(kind: LaunchKind) -> Launch {
        Launch {
            name: "fig-claude".into(),
            kind,
            bin: "/usr/local/bin/claude".into(),
            rc_name: "fig-claude".into(),
            remote_control: true,
            conversation: "c0ffee00-0000-4000-8000-000000000000".into(),
            capacity: 8,
            args: vec!["--permission-mode".into(), "acceptEdits".into()],
            workdir: "/var/lib/blackthorn/spaces/k/fig-claude".into(),
            title: String::new(),
        }
    }

    #[test]
    fn server_mode() {
        assert_eq!(
            agent_args(&launch(LaunchKind::ClaudeServer), false),
            vec![
                "remote-control",
                "--no-create-session-in-dir",
                "--spawn",
                "same-dir",
                "--capacity",
                "8",
                "--remote-control-session-name-prefix",
                "fig-claude",
                "--permission-mode",
                "acceptEdits"
            ]
        );
    }

    #[test]
    fn single_mode_creates_then_resumes() {
        let l = launch(LaunchKind::ClaudeSingle);
        assert_eq!(
            agent_args(&l, false),
            vec![
                "--session-id",
                "c0ffee00-0000-4000-8000-000000000000",
                "--remote-control",
                "--remote-control-session-name-prefix",
                "fig-claude",
                "--permission-mode",
                "acceptEdits"
            ]
        );
        assert_eq!(agent_args(&l, true)[0], "--resume");
        let mut named = l.clone();
        named.title = "disk usage".into();
        assert_eq!(agent_args(&named, false)[2..4], ["--name", "disk usage"]);
        assert!(!agent_args(&named, true).contains(&"--name".to_string()));
        // The chat's own name shows in the Claude app, not the space's.
        let a = agent_args(&named, false);
        let rc = a.iter().position(|x| x == "--remote-control").unwrap();
        assert!(a[rc + 1].starts_with("--"));
    }

    #[test]
    fn without_remote_control_one_local_conversation() {
        for kind in [LaunchKind::ClaudeServer, LaunchKind::ClaudeSingle] {
            let mut l = launch(kind);
            l.remote_control = false;
            assert_eq!(
                agent_args(&l, true),
                vec![
                    "--resume",
                    "c0ffee00-0000-4000-8000-000000000000",
                    "--permission-mode",
                    "acceptEdits"
                ]
            );
            assert!(one_conversation(&l));
        }
        assert!(!one_conversation(&launch(LaunchKind::ClaudeServer)));
    }

    #[test]
    fn other_agents_get_only_their_args() {
        assert_eq!(
            agent_args(&launch(LaunchKind::Command), false),
            vec!["--permission-mode", "acceptEdits"]
        );
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
            .join(".claude/projects/-var-lib-blackthorn-spaces-x-work");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{id}.jsonl")), "{}").unwrap();
        assert!(conversation_exists(home.path(), id));
    }
}
