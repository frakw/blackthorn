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

use crate::paths;
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

pub struct Setup<'a> {
    /// The read-only user to create.
    pub user: &'a str,
    /// Its authorized_keys line (with the forced command).
    pub ro_line: &'a str,
    /// The admin login, whose key line gets the forced command too.
    pub admin_user: &'a str,
    /// The admin key's base64, to find its line.
    pub admin_key: &'a str,
    pub admin_line: &'a str,
}

/// The script that sets a machine up, run as root there. Safe to run again.
pub fn setup_script(s: &Setup) -> String {
    let docker: Vec<String> = DOCKER_READ.iter().map(|a| format!("$d {a}")).collect();
    format!(
        r#"#!/bin/sh
# blackthorn: a read-only login on this machine (thorn host readonly).
# Run as root. Safe to run again.
set -eu
u='{user}'
ro_line='{ro_line}'
admin_user='{admin_user}'
admin_key='{admin_key}'
admin_line='{admin_line}'

[ "$(id -u)" = 0 ] || {{ echo "run this as root" >&2; exit 1; }}
[ "$(uname -s)" = Linux ] || {{ echo "only Linux machines get a read-only login for now" >&2; exit 1; }}
have() {{ command -v "$1" >/dev/null 2>&1; }}
home_of() {{ awk -F: -v u="$1" '$1 == u {{ print $6 }}' /etc/passwd; }}

# 1. The logger every blackthorn key runs first.
mkdir -p /usr/local/libexec
cat >{logger}.tmp <<'BLACKTHORN_LOGGER'
{logger_text}BLACKTHORN_LOGGER
chmod 755 {logger}.tmp
mv -f {logger}.tmp {logger}
SSH_ORIGINAL_COMMAND=true SSH_CLIENT='0 0 0' {logger} || {{ echo "the logger does not run" >&2; exit 1; }}

# 2. sudo, for the read-only Docker commands.
if ! have sudo; then
  if have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q sudo >/dev/null </dev/null || true
  elif have dnf; then dnf install -y -q sudo >/dev/null </dev/null || true
  elif have yum; then yum install -y -q sudo >/dev/null </dev/null || true
  elif have apk; then apk add -q sudo </dev/null || true
  elif have pacman; then pacman -S --needed --noconfirm sudo >/dev/null </dev/null || true
  elif have zypper; then zypper -q -n install sudo </dev/null || true
  fi
  have sudo && echo "bt: installed sudo" || echo "bt: no sudo (Docker commands will not work)"
fi

# 3. The user: no password, groups that read logs, nothing else. An account
# that exists already must be one this script made.
if id "$u" >/dev/null 2>&1; then
  if [ "$(id -u "$u")" = 0 ] || ! grep -qs blackthorn-ssh "$(home_of "$u")/.ssh/authorized_keys"; then
    echo "a user $u exists already and blackthorn did not make it; choose another name (--user)" >&2
    exit 1
  fi
else
  shell=/bin/sh; [ -x /bin/bash ] && shell=/bin/bash
  if have useradd; then useradd -m -s "$shell" "$u"
  else adduser -D -s "$shell" "$u"
  fi
  echo "bt: created user $u"
fi
for g in adm systemd-journal; do
  if grep -q "^$g:" /etc/group; then
    if have usermod; then usermod -a -G "$g" "$u"; else addgroup "$u" "$g" 2>/dev/null || true; fi
  fi
done
if id -nG "$u" | tr ' ' '\n' | grep -qx docker; then
  echo "bt: $u is in the docker group, which is root: remove it with: gpasswd -d $u docker" >&2
  exit 1
fi
h=$(home_of "$u")
[ -n "$h" ] && [ -d "$h" ] || {{ echo "user $u has no home directory" >&2; exit 1; }}
# The home and its key file belong to root, so the user cannot replace its
# own key line (and with it the logger).
chown root:"$u" "$h"
chmod 750 "$h"
rm -rf "$h/.ssh.bt"
mkdir "$h/.ssh.bt"
printf '%s\n' "$ro_line" >"$h/.ssh.bt/authorized_keys"
chmod 644 "$h/.ssh.bt/authorized_keys"
chmod 755 "$h/.ssh.bt"
chown -R root:root "$h/.ssh.bt"
rm -rf "$h/.ssh"
mv "$h/.ssh.bt" "$h/.ssh"

# 4. sudo rules: read-only Docker commands, with their output logged.
if have sudo && [ -d /etc/sudoers.d ]; then
  d=$(command -v docker 2>/dev/null || true)
  if [ -n "$d" ]; then
    f=/etc/sudoers.d/blackthorn
    cat >"$f.tmp" <<EOF
# Installed by blackthorn (thorn host readonly). Read-only Docker commands
# for $u; sudo records their output (sudoreplay -l).
Defaults:$u env_reset, always_set_home, log_output, !requiretty, !lecture
Cmnd_Alias BLACKTHORN_READ = {docker}
$u ALL=(root) NOPASSWD: BLACKTHORN_READ
EOF
    chmod 440 "$f.tmp"
    if visudo -c -f "$f.tmp" >/dev/null; then mv -f "$f.tmp" "$f"; echo "bt: sudo rules for docker"
    else rm -f "$f.tmp"; echo "bt: sudo rules rejected by visudo" >&2; exit 1
    fi
  else
    rm -f /etc/sudoers.d/blackthorn
    echo "bt: no docker here, so no sudo rules"
  fi
fi

# 5. The admin key gets the logger too.
ah=$(home_of "$admin_user")
ak="$ah/.ssh/authorized_keys"
if [ -n "$ah" ] && [ -f "$ak" ] && grep -qF "$admin_key" "$ak"; then
  awk -v k="$admin_key" -v l="$admin_line" 'index($0, k) {{ print l; next }} {{ print }}' "$ak" >"$ak.bt"
  chmod 600 "$ak.bt"
  chown "$admin_user" "$ak.bt" 2>/dev/null || true
  mv -f "$ak.bt" "$ak"
  echo "bt: admin key logged"
else
  echo "bt: admin key not found in $ak; its commands are not logged on this machine"
fi
echo "bt: done"
"#,
        user = s.user,
        ro_line = s.ro_line,
        admin_user = s.admin_user,
        admin_key = s.admin_key,
        admin_line = s.admin_line,
        logger = paths::REMOTE_LOGGER,
        logger_text = LOGGER,
        docker = docker.join(", "),
    )
}

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
    let known = PathBuf::from(format!("/run/blackthorn-check-{name}.known_hosts"));
    let lines: String = h
        .host_keys
        .iter()
        .map(|k| format!("blackthorn-{name} {k}\n"))
        .collect();
    crate::sys::write_file(&known, &lines, 0o600, None)?;
    let child = Command::new("ssh")
        .args([
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
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known.display()))
        .arg("-o")
        .arg(format!("HostKeyAlias=blackthorn-{name}"))
        .arg("-i")
        .arg(key)
        .args(["-p", &h.port.to_string()])
        .arg(format!("{user}@{}", h.address))
        .arg(command)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let out = (|| -> Result<Output> {
        let mut child = child.context("running ssh")?;
        if let Some(text) = input {
            let mut stdin = child.stdin.take().context("ssh stdin")?;
            stdin.write_all(text.as_bytes())?;
        }
        Ok(child.wait_with_output()?)
    })();
    let _ = std::fs::remove_file(&known);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_has_everything() {
        let s = setup_script(&Setup {
            user: "blackthorn",
            ro_line: "from=\"100.64.0.1\",restrict,command=\"/usr/local/libexec/blackthorn-ssh\" ssh-ed25519 AAAA ro",
            admin_user: "root",
            admin_key: "AAAB",
            admin_line: "from=\"100.64.0.1\",restrict,command=\"/usr/local/libexec/blackthorn-ssh\" ssh-ed25519 AAAB admin",
        });
        assert!(s.starts_with("#!/bin/sh\n"));
        assert!(s.contains("u='blackthorn'"));
        assert!(s.contains("ro_line='from=\"100.64.0.1\",restrict,command="));
        assert!(s.contains("exec \"${SHELL:-/bin/sh}\" -c \"$c\"\nBLACKTHORN_LOGGER\n"));
        assert!(s.contains(
            "Cmnd_Alias BLACKTHORN_READ = $d ps, $d ps *, $d logs *, $d stats --no-stream,"
        ));
        assert!(s.contains("visudo -c -f"));
        assert!(s.contains("chown root:\"$u\" \"$h\""));
        assert!(s.contains("echo \"bt: done\""));
        // Nothing that would hand out root or secrets.
        for bad in [
            "exec *",
            "run *",
            "inspect",
            "compose",
            "usermod -a -G docker",
        ] {
            assert!(!s.contains(bad), "{bad}");
        }
    }
}
