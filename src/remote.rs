//! What blackthorn sets up on a managed machine, and how root on the hub
//! logs in to it (for `host check` and `host readonly`; spaces log in
//! through their own ssh-agent instead).
//!
//! `thorn host readonly NAME` gives a machine a second login that may only
//! look: an unprivileged user (default "blackthorn") in the groups that read
//! logs, with sudo for a short list of read-only Docker commands. Both of
//! blackthorn's keys there get a forced command that writes every command to
//! the machine's system log before running it, where a space cannot erase
//! it (the read-only user cannot; the admin login is root and could).

use crate::state::Host;
use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// The forced command: logs, then runs what was asked. SSH puts the
/// requested command in SSH_ORIGINAL_COMMAND; sftp arrives as the subsystem's
/// program; no command is an interactive shell.
pub const LOGGER: &str = r#"#!/bin/sh
# Installed by blackthorn (thorn host readonly). Every SSH session with a
# blackthorn key runs this first: it records the command in the system log
# (tag "blackthorn": journalctl -t blackthorn), then runs it.
c=${SSH_ORIGINAL_COMMAND:-}
logger -t blackthorn -p auth.notice -- "$(id -un) from ${SSH_CLIENT%% *}: ${c:-(interactive shell)}" 2>/dev/null || true
# A user's own services and rootless Docker (thorn host setup).
r="/run/user/$(id -u)"
[ -d "$r" ] && export XDG_RUNTIME_DIR="$r"
[ -S "$r/docker.sock" ] && export DOCKER_HOST="unix://$r/docker.sock"
case $c in
  '') exec "${SHELL:-/bin/sh}" -l ;;
  internal-sftp | */sftp-server)
    for p in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server /usr/libexec/sftp-server; do
      [ -x "$p" ] && exec "$p"
    done
    echo "blackthorn: no sftp-server on this machine" >&2
    exit 1 ;;
esac
exec "${SHELL:-/bin/sh}" -c "$c"
"#;

/// The Docker commands the read-only login may run with sudo. Each only
/// reads. Left out on purpose, because they amount to root or reveal
/// secrets: exec, run, cp, inspect (environment variables hold passwords),
/// compose, and the docker group itself.
pub const DOCKER_READ: &[&str] = &[
    "ps",
    "ps *",
    "logs *",
    "stats --no-stream",
    "stats --no-stream *",
    "images",
    "images *",
    "system df",
    "system df *",
    "top *",
];

/// Root on the hub logging in to a machine with one of its keys, outside
/// any space (the space firewall does not apply to root). `input` goes to
/// the command's standard input.
pub fn ssh(
    name: &str,
    h: &Host,
    key: &Path,
    user: &str,
    command: &str,
    input: Option<&str>,
) -> Result<Output> {
    let known = known_hosts(name, h)?;
    let child = ssh_command(name, h, key, user, &known)
        .arg(command)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let out = finish(child, input);
    let _ = std::fs::remove_file(&known);
    out
}

/// A known_hosts file with the machine's recorded keys, of its own for
/// each connection (several may be open at once). Remove it afterwards.
pub fn known_hosts(name: &str, h: &Host) -> Result<PathBuf> {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let known = PathBuf::from(format!(
        "/run/blackthorn-ssh-{name}-{}-{n}.known_hosts",
        std::process::id()
    ));
    let lines: String = h
        .host_keys
        .iter()
        .map(|k| format!("blackthorn-{name} {k}\n"))
        .collect();
    crate::sys::write_file(&known, &lines, 0o600, None)?;
    Ok(known)
}

/// ssh to the machine with one of root's keys, without the command yet.
pub fn ssh_command(name: &str, h: &Host, key: &Path, user: &str, known: &Path) -> Command {
    let mut c = Command::new("ssh");
    c.args([
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
    ])
    .args(["-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10"])
    .args([
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
    ])
    .arg("-o")
    .arg(format!("UserKnownHostsFile={}", known.display()))
    .arg("-o")
    .arg(format!("HostKeyAlias=blackthorn-{name}"))
    .arg("-i")
    .arg(key)
    .args(["-p", &h.port.to_string()])
    .arg(format!("{user}@{}", h.address));
    c
}

fn finish(child: std::io::Result<std::process::Child>, input: Option<&str>) -> Result<Output> {
    let mut child = child.context("running ssh")?;
    if let Some(text) = input {
        let mut stdin = child.stdin.take().context("ssh stdin")?;
        stdin.write_all(text.as_bytes())?;
    }
    Ok(child.wait_with_output()?)
}
