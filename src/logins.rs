//! Logins of each space's own on a machine (v0.12): `bt-<key>`, an ordinary
//! user that owns /srv/<space> and runs its own containers (and, given root
//! for a time, may use sudo), and `bt-<key>-ro`, which only looks.
//!
//! Blackthorn makes them through the machine's management login: root, or
//! a user with sudo without a password. The spaces never get that login.
//! Their keys live where they cannot change them, in /etc/ssh/blackthorn
//! (sshd's AuthorizedKeysFile), each with blackthorn's logger as forced
//! command, so the machine's system log names the space of every command.
//!
//! Work that fails because the machine cannot be reached is kept in the
//! machine's `pending` list and retried every minute by the tick.

use crate::ctx::{self, Ctx};
use crate::state::{Account, Host, Pending, Problem, State};
use crate::{keys, paths, remote, sys};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// The helper a read-only login runs (as the space's user login, through
/// sudo) to look at that login's own rootless containers.
pub const RDOCKER: &str = "/usr/local/libexec/blackthorn-rdocker";

const RDOCKER_TEXT: &str = r#"#!/bin/sh
# Installed by blackthorn (thorn host setup). A space's read-only login runs
# this through sudo, as the space's user login, to look at its containers.
u=$(id -u)
export DOCKER_HOST="unix:///run/user/$u/docker.sock" XDG_RUNTIME_DIR="/run/user/$u"
exec docker "$@"
"#;

/// The shell functions every script starts with.
const PRELUDE: &str = r#"set -eu
[ "$(id -u)" = 0 ] || { echo "this needs root" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
home_of() { awk -F: -v u="$1" '$1 == u { print $6 }' /etc/passwd; }
comment_of() { awk -F: -v u="$1" '$1 == u { print $5 }' /etc/passwd; }
sudoers() {
  # sudoers NAME: the text on standard input, checked first.
  cat >"/etc/sudoers.d/$1.tmp"
  chmod 440 "/etc/sudoers.d/$1.tmp"
  mv -f "/etc/sudoers.d/$1.tmp" "/etc/sudoers.d/$1"
  if ! visudo -c >/dev/null 2>&1; then
    rm -f "/etc/sudoers.d/$1"
    echo "sudo rules $1 rejected by visudo" >&2
    exit 1
  fi
}
end_sessions() {
  # Ends the SSH sessions of user $1, with what they run (through sudo too,
  # where logind keeps sessions).
  if have loginctl; then
    for s in $(loginctl list-sessions --no-legend 2>/dev/null | awk -v u="$1" '$3 == u { print $1 }'); do
      loginctl terminate-session "$s" 2>/dev/null || true
    done
  fi
  pkill -KILL -u "$1" -f '^sshd:' 2>/dev/null || true
}
"#;

/// Quotes a value for the scripts: single quotes, none inside.
fn q(s: &str) -> Result<String> {
    if s.contains('\'') || s.contains('\n') {
        bail!("{s:?} cannot go into a script");
    }
    Ok(format!("'{s}'"))
}

pub struct SetupInput<'a> {
    /// The management login and its key line (with the logger), whose
    /// line on the machine gets the logger too.
    pub admin_user: &'a str,
    pub admin_key: &'a str,
    pub admin_line: &'a str,
    /// Printed for a machine blackthorn reaches as an ordinary user: also
    /// let its key log in as root (that is what makes the setup possible).
    pub add_root: bool,
    /// The shared read-only login of before, whose sudo rule stays until
    /// it goes.
    pub legacy: Option<&'a str>,
}

/// Sets a machine up for logins of each space's own. Run as root there.
/// Safe to run again.
pub fn setup_script(s: &SetupInput) -> Result<String> {
    let docker: Vec<String> = remote::DOCKER_READ
        .iter()
        .map(|a| format!("$d {a}"))
        .collect();
    let rdocker: Vec<String> = remote::DOCKER_READ
        .iter()
        .map(|a| format!("{RDOCKER} {a}"))
        .collect();
    let legacy_rule = match s.legacy {
        Some(u) => format!("{u} ALL=(root) NOPASSWD: BLACKTHORN_READ\n"),
        None => String::new(),
    };
    Ok(format!(
        r#"#!/bin/sh
# blackthorn: logins of each space's own on this machine (thorn host setup).
# Run as root. Safe to run again.
{PRELUDE}
admin_user={admin_user}
admin_key={admin_key}
admin_line={admin_line}
add_root={add_root}
[ "$(uname -s)" = Linux ] || {{ echo "only Linux machines get logins of each space's own for now" >&2; exit 1; }}

# 1. The logger every blackthorn key runs first.
mkdir -p /usr/local/libexec
cat >{logger}.tmp <<'BLACKTHORN_LOGGER'
{logger_text}BLACKTHORN_LOGGER
chmod 755 {logger}.tmp
mv -f {logger}.tmp {logger}
SSH_ORIGINAL_COMMAND=true SSH_CLIENT='0 0 0' {logger} || {{ echo "the logger does not run" >&2; exit 1; }}
cat >{rdocker}.tmp <<'BLACKTHORN_RDOCKER'
{rdocker_text}BLACKTHORN_RDOCKER
chmod 755 {rdocker}.tmp
mv -f {rdocker}.tmp {rdocker}

# 2. sudo: for the read-only Docker commands, and root when it is given.
if ! have sudo; then
  if have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q sudo >/dev/null </dev/null || true
  elif have dnf; then dnf install -y -q sudo >/dev/null </dev/null || true
  elif have yum; then yum install -y -q sudo >/dev/null </dev/null || true
  elif have apk; then apk add -q sudo </dev/null || true
  elif have pacman; then pacman -S --needed --noconfirm sudo >/dev/null </dev/null || true
  elif have zypper; then zypper -q -n install sudo </dev/null || true
  fi
fi
have sudo && have visudo || {{ echo "sudo is not installed and could not be" >&2; exit 1; }}
d=$(command -v docker 2>/dev/null || echo /usr/bin/docker)
sudoers blackthorn <<EOF
# Installed by blackthorn (thorn host setup). Read-only Docker commands, for
# the spaces' read-only logins.
Cmnd_Alias BLACKTHORN_READ = {docker}
Cmnd_Alias BLACKTHORN_RREAD = {rdocker_cmds}
{legacy_rule}EOF
echo "bt: sudo rules"

# 3. sshd also reads key lines from {keys}, where only root writes.
mkdir -p {keys}
chown root:root {keys}
chmod 755 {keys}
conf=/etc/ssh/sshd_config
line="AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2 {keys}/%u"
if grep -Eqs '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/' "$conf"; then
  mkdir -p /etc/ssh/sshd_config.d
  printf '# Installed by blackthorn (thorn host setup).\n%s\n' "$line" >/etc/ssh/sshd_config.d/10-blackthorn-keys.conf
elif ! grep -qF "{keys}/%u" "$conf"; then
  {{ printf '# blackthorn (thorn host setup):\n%s\n' "$line"; cat "$conf"; }} >"$conf.bt"
  chmod 644 "$conf.bt"
  mv -f "$conf.bt" "$conf"
fi
sshd=$(command -v sshd 2>/dev/null || echo /usr/sbin/sshd)
"$sshd" -t || {{ echo "sshd does not accept its configuration" >&2; exit 1; }}
if "$sshd" -T 2>/dev/null | grep -i '^authorizedkeysfile' | grep -qF "{keys}/%u"; then :; else
  echo "sshd will not read {keys}: another AuthorizedKeysFile comes first in $conf" >&2; exit 1
fi
if have systemctl && systemctl is-active -q ssh 2>/dev/null; then systemctl reload ssh
elif have systemctl && systemctl is-active -q sshd 2>/dev/null; then systemctl reload sshd
elif [ -s /run/sshd.pid ]; then kill -HUP "$(cat /run/sshd.pid)"
elif [ -s /var/run/sshd.pid ]; then kill -HUP "$(cat /var/run/sshd.pid)"
else echo "bt: reload sshd yourself"
fi
echo "bt: sshd reads the spaces' key lines"

# 4. Rootless Docker, where Docker is (Debian and Ubuntu).
tool=$(command -v dockerd-rootless-setuptool.sh 2>/dev/null || true)
[ -n "$tool" ] || [ ! -x /usr/share/docker.io/contrib/dockerd-rootless-setuptool.sh ] || tool=/usr/share/docker.io/contrib/dockerd-rootless-setuptool.sh
if [ -z "$tool" ] && have docker && have apt-get; then
  if dpkg -s docker-ce >/dev/null 2>&1; then pkgs="docker-ce-rootless-extras uidmap"
  elif dpkg -s docker.io >/dev/null 2>&1; then pkgs="rootlesskit uidmap"
  else pkgs=""
  fi
  if [ -n "$pkgs" ]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q $pkgs >/dev/null </dev/null 2>&1 || true
  fi
  tool=$(command -v dockerd-rootless-setuptool.sh 2>/dev/null || true)
  [ -n "$tool" ] || [ ! -x /usr/share/docker.io/contrib/dockerd-rootless-setuptool.sh ] || tool=/usr/share/docker.io/contrib/dockerd-rootless-setuptool.sh
fi
if [ -n "$tool" ] && have loginctl && have newuidmap; then echo "bt: rootless docker: yes"
elif ! have docker; then echo "bt: rootless docker: no (Docker is not installed)"
else echo "bt: rootless docker: no (only Debian and Ubuntu with Docker's packages for now)"
fi

# 5. The management key gets the logger too.
logged() {{
  ah=$(home_of "$1")
  ak="$ah/.ssh/authorized_keys"
  if [ -n "$ah" ] && [ -f "$ak" ] && grep -qF "$admin_key" "$ak"; then
    awk -v k="$admin_key" -v l="$admin_line" 'index($0, k) {{ print l; next }} {{ print }}' "$ak" >"$ak.bt"
    chmod 600 "$ak.bt"
    chown "$1" "$ak.bt" 2>/dev/null || true
    mv -f "$ak.bt" "$ak"
    return 0
  fi
  return 1
}}
if [ "$add_root" = 1 ]; then
  rh=$(home_of root)
  mkdir -p "$rh/.ssh"
  chmod 700 "$rh/.ssh"
  touch "$rh/.ssh/authorized_keys"
  chmod 600 "$rh/.ssh/authorized_keys"
  logged root || printf '%s\n' "$admin_line" >>"$rh/.ssh/authorized_keys"
  echo "bt: blackthorn's key logs in as root"
fi
if logged "$admin_user"; then echo "bt: management key logged"
else echo "bt: management key not found for $admin_user; its commands are not logged here"
fi
echo "bt: done"
"#,
        admin_user = q(s.admin_user)?,
        admin_key = q(s.admin_key)?,
        admin_line = q(s.admin_line)?,
        add_root = if s.add_root { 1 } else { 0 },
        logger = paths::REMOTE_LOGGER,
        logger_text = remote::LOGGER,
        rdocker = RDOCKER,
        rdocker_text = RDOCKER_TEXT,
        docker = docker.join(", "),
        rdocker_cmds = rdocker.join(", "),
        keys = paths::REMOTE_KEYS_DIR,
    ))
}

pub struct AccountsInput<'a> {
    pub key: &'a str,
    /// The user login too (the space's own machine), else only the
    /// read-only one (a machine it reaches through a bridge).
    pub full: bool,
    /// Its folder: /srv/<srv>.
    pub srv: Option<&'a str>,
    pub user_line: &'a str,
    pub ro_line: &'a str,
}

/// Makes (or brings up to date) a space's logins on a set-up machine.
pub fn accounts_script(a: &AccountsInput) -> Result<String> {
    Ok(format!(
        r#"#!/bin/sh
# blackthorn: the logins of space {key} on this machine.
{PRELUDE}
k={key}
u="bt-$k"
ro="bt-$k-ro"
full={full}
srv={srv}
user_line={user_line}
ro_line={ro_line}
shell=/bin/sh; [ -x /bin/bash ] && shell=/bin/bash
mark="blackthorn space $k"
make_user() {{
  if id "$1" >/dev/null 2>&1; then
    [ "$(comment_of "$1")" = "$mark" ] || {{ echo "a user $1 exists already and blackthorn did not make it" >&2; exit 1; }}
  else
    if have useradd; then useradd -m -c "$mark" -s "$shell" "$1"
    else adduser -D -g "$mark" -s "$shell" "$1"
    fi
    echo "bt: made $1"
  fi
  for g in adm systemd-journal; do
    if grep -q "^$g:" /etc/group; then
      if have usermod; then usermod -a -G "$g" "$1"; else addgroup "$1" "$g" 2>/dev/null || true; fi
    fi
  done
  if id -nG "$1" | tr ' ' '\n' | grep -qx docker; then
    echo "$1 is in the docker group, which is root: remove it with: gpasswd -d $1 docker" >&2
    exit 1
  fi
}}
key_line() {{
  printf '%s\n' "$2" >"{keys}/$1.tmp"
  chmod 644 "{keys}/$1.tmp"
  mv -f "{keys}/$1.tmp" "{keys}/$1"
}}
[ -d {keys} ] || {{ echo "this machine is not set up yet (thorn host setup)" >&2; exit 1; }}

make_user "$ro"
rh=$(home_of "$ro")
chown root:"$ro" "$rh"
chmod 750 "$rh"
key_line "$ro" "$ro_line"
if [ "$full" = 1 ]; then
  make_user "$u"
  uh=$(home_of "$u")
  chown "$u:$u" "$uh"
  chmod 750 "$uh"
  if have usermod; then usermod -a -G "$u" "$ro"; else addgroup "$ro" "$u" 2>/dev/null || true; fi
  key_line "$u" "$user_line"
  if [ -n "$srv" ]; then
    d="/srv/$srv"
    if [ ! -e "$d" ]; then
      mkdir -p "$d"
      chown "$u:$u" "$d"
      chmod 2750 "$d"
      echo "bt: made $d"
    else
      owner=$(stat -c %U "$d" 2>/dev/null || echo "?")
      if [ "$owner" = "$u" ]; then :
      elif [ "$owner" = UNKNOWN ] || ! id "$owner" >/dev/null 2>&1; then
        chown -R "$u:$u" "$d"
        echo "bt: $d was left by a removed space; it is $u's now"
      else
        echo "bt: $d belongs to $owner; not given to $u"
      fi
    fi
  fi
  if have loginctl; then loginctl enable-linger "$u" 2>/dev/null || true; fi
  rule="$ro ALL=($u) NOPASSWD: BLACKTHORN_RREAD"
else
  rule=""
fi
sudoers "bt-$k-ro" <<EOF
# Installed by blackthorn: what the read-only login of space $k may run
# with sudo. Only reading.
Defaults:$ro !requiretty, !lecture
$ro ALL=(root) NOPASSWD: BLACKTHORN_READ
$rule
EOF

# Rootless Docker for the user login, where the machine has it.
if [ "$full" = 1 ]; then
  tool=$(command -v dockerd-rootless-setuptool.sh 2>/dev/null || true)
  [ -n "$tool" ] || [ ! -x /usr/share/docker.io/contrib/dockerd-rootless-setuptool.sh ] || tool=/usr/share/docker.io/contrib/dockerd-rootless-setuptool.sh
  uid=$(id -u "$u")
  if [ -z "$tool" ] || ! have loginctl; then
    echo "bt: rootless docker: not on this machine"
  elif [ -f "$(home_of "$u")/.config/systemd/user/docker.service" ]; then
    echo "bt: rootless docker: ready"
  else
    systemctl start "user@$uid.service" 2>/dev/null || true
    if runuser -u "$u" -- env XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" "$tool" install >"/tmp/bt-rootless-$k.log" 2>&1; then
      echo "bt: rootless docker: ready"
    else
      echo "bt: rootless docker: failed ($(tail -n 1 "/tmp/bt-rootless-$k.log"))"
    fi
  fi
fi
echo "bt: done"
"#,
        key = q(a.key)?,
        full = if a.full { 1 } else { 0 },
        srv = q(a.srv.unwrap_or(""))?,
        user_line = q(a.user_line)?,
        ro_line = q(a.ro_line)?,
        keys = paths::REMOTE_KEYS_DIR,
    ))
}

/// Gives a space root (sudo for anything) on its machine; with `secs`, the
/// machine takes it back by itself then too, even if the hub cannot reach
/// it at that time.
pub fn root_script(key: &str, secs: Option<u64>) -> Result<String> {
    Ok(format!(
        r#"#!/bin/sh
# blackthorn: root for space {key}.
{PRELUDE}
k={key}
u="bt-$k"
id "$u" >/dev/null 2>&1 || {{ echo "space $k has no login here" >&2; exit 1; }}
sudoers "bt-$k-root" <<EOF
# Installed by blackthorn: space $k has root here, until blackthorn takes it
# back (thorn root SPACE --off).
Defaults:$u !requiretty, !lecture
$u ALL=(ALL:ALL) NOPASSWD: ALL
EOF
if have systemctl; then
  systemctl stop "blackthorn-unroot-$k.timer" "blackthorn-unroot-$k.service" 2>/dev/null || true
  systemctl reset-failed "blackthorn-unroot-$k.service" 2>/dev/null || true
fi
secs={secs}
if [ -n "$secs" ]; then
  if have systemd-run; then
    systemd-run --quiet --unit="blackthorn-unroot-$k" --on-active="${{secs}}s" \
      /bin/sh -c "rm -f /etc/sudoers.d/bt-$k-root; loginctl list-sessions --no-legend 2>/dev/null | awk -v u=$u '\$3 == u {{ print \$1 }}' | xargs -r -n1 loginctl terminate-session; pkill -KILL -u $u -f '^sshd:' || true"
    echo "bt: the machine ends it by itself too"
  else
    echo "bt: no systemd-run: only blackthorn ends it"
  fi
fi
echo "bt: done"
"#,
        key = q(key)?,
        secs = secs.map(|s| s.to_string()).unwrap_or_default(),
    ))
}

/// Takes a space's root away and ends its sessions (with what they run).
pub fn revoke_script(key: &str) -> Result<String> {
    Ok(format!(
        r#"#!/bin/sh
# blackthorn: no more root for space {key}.
{PRELUDE}
k={key}
u="bt-$k"
rm -f "/etc/sudoers.d/bt-$k-root"
if have systemctl; then
  systemctl stop "blackthorn-unroot-$k.timer" "blackthorn-unroot-$k.service" 2>/dev/null || true
  systemctl reset-failed "blackthorn-unroot-$k.service" 2>/dev/null || true
fi
if id "$u" >/dev/null 2>&1; then end_sessions "$u"; fi
echo "bt: done"
"#,
        key = q(key)?,
    ))
}

/// Removes a space's logins, what they run, and (`purge`) its folder.
pub fn remove_script(key: &str, srv: Option<&str>, purge: bool) -> Result<String> {
    Ok(format!(
        r#"#!/bin/sh
# blackthorn: space {key} is gone.
{PRELUDE}
k={key}
srv={srv}
purge={purge}
rm -f "/etc/sudoers.d/bt-$k-root" "/etc/sudoers.d/bt-$k-ro"
if have systemctl; then
  systemctl stop "blackthorn-unroot-$k.timer" "blackthorn-unroot-$k.service" 2>/dev/null || true
fi
for u in "bt-$k" "bt-$k-ro"; do
  rm -f "{keys}/$u"
  id "$u" >/dev/null 2>&1 || continue
  [ "$(comment_of "$u")" = "blackthorn space $k" ] || {{ echo "bt: $u is not blackthorn's; left alone"; continue; }}
  if have loginctl; then
    loginctl disable-linger "$u" 2>/dev/null || true
    loginctl terminate-user "$u" 2>/dev/null || true
  fi
  end_sessions "$u"
  pkill -KILL -u "$u" 2>/dev/null || true
  sleep 1
  h=$(home_of "$u")
  if have userdel; then userdel "$u" 2>/dev/null || userdel -f "$u"; else deluser "$u"; fi
  case "$h" in /home/bt-*) rm -rf "$h" ;; esac
  echo "bt: removed $u"
done
if [ -n "$srv" ] && [ -d "/srv/$srv" ]; then
  if [ "$purge" = 1 ]; then rm -rf "/srv/$srv"; echo "bt: removed /srv/$srv"
  else echo "bt: kept /srv/$srv"
  fi
fi
echo "bt: done"
"#,
        key = q(key)?,
        srv = q(srv.unwrap_or(""))?,
        purge = if purge { 1 } else { 0 },
        keys = paths::REMOTE_KEYS_DIR,
    ))
}

/// Removes the shared read-only login of before, once every space there
/// has its own.
pub fn legacy_remove_script(user: &str) -> Result<String> {
    Ok(format!(
        r#"#!/bin/sh
# blackthorn: the shared read-only login {user} is no longer used.
{PRELUDE}
u={user}
if id "$u" >/dev/null 2>&1 && grep -qs blackthorn-ssh "$(home_of "$u")/.ssh/authorized_keys"; then
  end_sessions "$u"
  pkill -KILL -u "$u" 2>/dev/null || true
  sleep 1
  h=$(home_of "$u")
  if have userdel; then userdel "$u" 2>/dev/null || userdel -f "$u"; else deluser "$u"; fi
  case "$h" in /home/*) rm -rf "$h" ;; esac
  echo "bt: removed $u"
fi
if [ -f /etc/sudoers.d/blackthorn ] && grep -q "^$u ALL=" /etc/sudoers.d/blackthorn; then
  grep -v "^$u ALL=" /etc/sudoers.d/blackthorn | sudoers blackthorn
fi
echo "bt: done"
"#,
        user = q(user)?,
    ))
}

// ------------------------------------------------------------ running them

/// Runs a script as root on a machine, through its management login.
/// Returns the script's own report (its "bt: " lines, without "done").
pub fn run(name: &str, h: &Host, script: &str) -> Result<Vec<String>> {
    let cmd = if h.root_login() {
        "sh -s"
    } else {
        "sudo -n sh -s"
    };
    let out = remote::ssh(name, h, &paths::key_file(name), &h.user, cmd, Some(script))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let report: Vec<String> = text
        .lines()
        .filter_map(|l| l.strip_prefix("bt: "))
        .filter(|l| *l != "done")
        .map(String::from)
        .collect();
    if !out.status.success() || !text.lines().any(|l| l == "bt: done") {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        if !h.root_login() && (err.contains("password is required") || err.contains("sudo:")) {
            bail!(
                "{name}: blackthorn logs in as {}, which cannot use sudo without a password; \
                 run the setup yourself as root there (thorn host setup {name} --print)",
                h.user
            );
        }
        bail!(
            "{name}: {}",
            if err.is_empty() {
                "the script did not finish"
            } else {
                err
            }
        );
    }
    Ok(report)
}

/// The key line for one of blackthorn's keys on a machine: limited to the
/// hub's addresses, restricted, with the logger.
fn logged_line(cfg: &crate::config::Config, h: &Host, public: &str) -> String {
    keys::logged_key_line(public, &crate::ops::hub_addresses(cfg, h.address))
}

/// What setting a machine up did.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SetupDone {
    /// The setup script's report, then each space's.
    pub report: Vec<String>,
    /// Spaces whose logins could not be made yet (retried).
    pub waiting: Vec<String>,
}

/// The setup script for a machine, to run as root there by hand: for a
/// machine blackthorn reaches as an ordinary user (who cannot sudo), it
/// also lets blackthorn's key log in as root.
pub fn setup_print(name: &str) -> Result<String> {
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    let h = state.host(name)?;
    script_for(&cfg, &state, name, !h.root_login())
}

fn script_for(
    cfg: &crate::config::Config,
    state: &State,
    name: &str,
    add_root: bool,
) -> Result<String> {
    let h = state.host(name)?;
    if h.os != crate::state::Os::Linux {
        bail!(
            "{name} runs {}; logins of each space's own are for Linux machines for now",
            h.os
        );
    }
    let admin_pub = keys::public_key(name)?;
    let admin_key = admin_pub
        .split_whitespace()
        .nth(1)
        .context("the management public key has no key part")?
        .to_string();
    setup_script(&SetupInput {
        admin_user: &h.user,
        admin_key: &admin_key,
        admin_line: &logged_line(cfg, h, &admin_pub),
        add_root,
        legacy: h.readonly.as_deref(),
    })
}

/// Sets a machine up for logins of each space's own, then makes them for
/// its spaces (and the spaces bridged to it), then removes the shared
/// read-only login of before. `run`: through the management login; else
/// you ran the printed script yourself, and blackthorn checks that its key
/// now logs in as root.
pub fn setup(name: &str, run_it: bool) -> Result<SetupDone> {
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    let mut h = state.host(name)?.clone();
    let mut done = SetupDone::default();
    if run_it {
        let script = script_for(&cfg, &state, name, false)?;
        match run(name, &h, &script) {
            Ok(r) => done.report = r,
            Err(e) => {
                let mut ctx = Ctx::open()?;
                if let Some(x) = ctx.state.hosts.get_mut(name) {
                    x.problem = Some(Problem {
                        at: ctx.now,
                        text: format!("{e:#}"),
                    });
                }
                ctx.commit()?;
                return Err(e);
            }
        }
    } else {
        // The printed script let blackthorn's key in as root: use it.
        let out = remote::ssh(name, &h, &paths::key_file(name), "root", "id -u", None)?;
        let ok = out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "0";
        if !ok && !h.root_login() {
            bail!(
                "blackthorn's key does not log in to {name} as root yet: run the printed script \
                 there as root first (thorn host setup {name} --print)"
            );
        }
        if !ok {
            bail!(
                "could not log in to {name} as root: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        h.user = "root".into();
        // Ask the machine what the script found.
        let out = remote::ssh(
            name,
            &h,
            &paths::key_file(name),
            "root",
            "test -d /etc/ssh/blackthorn && echo set-up; \
             if command -v dockerd-rootless-setuptool.sh >/dev/null 2>&1 || \
             [ -x /usr/share/docker.io/contrib/dockerd-rootless-setuptool.sh ]; then \
             echo rootless docker: yes; fi",
            None,
        )?;
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        if !text.lines().any(|l| l == "set-up") {
            bail!("{name} is not set up: run the printed script there as root first");
        }
        done.report = text
            .lines()
            .filter(|l| l.starts_with("rootless"))
            .map(String::from)
            .collect();
    }
    let docker = done.report.iter().any(|l| l == "rootless docker: yes");
    {
        let mut ctx = Ctx::open()?;
        let x = ctx
            .state
            .hosts
            .get_mut(name)
            .with_context(|| format!("{name} was removed meanwhile"))?;
        x.user = h.user.clone();
        x.setup = Some(ctx.now);
        x.rootless_docker = docker;
        x.problem = None;
        ctx.commit()?;
    }
    let (r, waiting) = make_accounts(name)?;
    done.report.extend(r);
    done.waiting = waiting;
    if done.waiting.is_empty() {
        if let Err(e) = drop_legacy(name) {
            done.report
                .push(format!("the shared read-only login stays for now: {e:#}"));
        }
    }
    Ok(done)
}

/// The logins a machine should have: (space key, its own machine, folder).
fn wanted(state: &State, host: &str, now: u64) -> Vec<(String, bool, String)> {
    let mut v: Vec<(String, bool, String)> = state
        .spaces
        .iter()
        .filter(|(_, s)| s.host == host)
        .map(|(n, s)| (s.key.clone(), true, n.clone()))
        .collect();
    for b in state.bridges.iter().filter(|b| b.active(now)) {
        let (Some(from), Some(to)) = (state.spaces.get(&b.from), state.spaces.get(&b.to)) else {
            continue;
        };
        if to.host == host && from.host != host && !v.iter().any(|(k, _, _)| *k == from.key) {
            v.push((from.key.clone(), false, b.from.clone()));
        }
    }
    v
}

/// Makes the logins a set-up machine is missing. Returns the report and
/// the spaces still waiting for theirs.
pub fn make_accounts(name: &str) -> Result<(Vec<String>, Vec<String>)> {
    let (cfg, state) = ctx::read_only()?;
    let h = state.host(name)?.clone();
    if h.setup.is_none() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut report = Vec::new();
    let mut waiting = Vec::new();
    for (key, full, space) in wanted(&state, name, crate::state::now()) {
        if h.accounts.get(&key).is_some_and(|a| a.full || !full) {
            continue;
        }
        match make_one(&cfg, name, &h, &key, full, &space) {
            Ok(r) => {
                report.extend(r.into_iter().map(|l| format!("{space}: {l}")));
                let mut ctx = Ctx::open()?;
                if let Some(x) = ctx.state.hosts.get_mut(name) {
                    x.accounts.insert(
                        key.clone(),
                        Account {
                            full,
                            srv: full.then(|| space.clone()),
                        },
                    );
                    x.pending
                        .retain(|p| !matches!(p, Pending::Accounts { key: k, .. } if *k == key));
                }
                ctx.commit()?;
            }
            Err(e) => {
                report.push(format!("{space}: {e:#}"));
                waiting.push(space.clone());
                let mut ctx = Ctx::open()?;
                if let Some(x) = ctx.state.hosts.get_mut(name) {
                    let p = Pending::Accounts {
                        key: key.clone(),
                        full,
                    };
                    if !x.pending.contains(&p) {
                        x.pending.push(p);
                    }
                }
                ctx.commit()?;
            }
        }
    }
    Ok((report, waiting))
}

fn make_one(
    cfg: &crate::config::Config,
    name: &str,
    h: &Host,
    key: &str,
    full: bool,
    space: &str,
) -> Result<Vec<String>> {
    keys::generate_space(key)?;
    let user_line = logged_line(cfg, h, &keys::public_of(&paths::space_key_file(key))?);
    let ro_line = logged_line(cfg, h, &keys::public_of(&paths::space_ro_key_file(key))?);
    let script = accounts_script(&AccountsInput {
        key,
        full,
        srv: full.then_some(space),
        user_line: &user_line,
        ro_line: &ro_line,
    })?;
    run(name, h, &script)
}

/// Removes the shared read-only login of before from a machine whose
/// spaces all have their own.
fn drop_legacy(name: &str) -> Result<()> {
    let (_, state) = ctx::read_only()?;
    let h = state.host(name)?.clone();
    let Some(user) = h.readonly.clone() else {
        return Ok(());
    };
    run(name, &h, &legacy_remove_script(&user)?)?;
    let mut ctx = Ctx::open()?;
    if let Some(x) = ctx.state.hosts.get_mut(name) {
        x.readonly = None;
    }
    ctx.commit()?;
    for p in [paths::ro_key_file(name), paths::ro_pubkey_file(name)] {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

// ------------------------------------------------------------ root

/// Gives a space root on its machine (set up for it) until `until`, or
/// until taken back. Through the machine first; the state after.
pub fn grant(space: &str, until: Option<u64>) -> Result<()> {
    let (_, state) = ctx::read_only()?;
    let s = state.space(space)?.clone();
    let h = state.host(&s.host)?.clone();
    if h.setup.is_some() {
        if !h.accounts.get(&s.key).is_some_and(|a| a.full) {
            bail!(
                "{space} has no login of its own on {} yet; it is made when the machine can be \
                 reached (or: thorn host setup {})",
                s.host,
                s.host
            );
        }
        let now = crate::state::now();
        run(
            &s.host,
            &h,
            &root_script(&s.key, until.map(|u| u.saturating_sub(now)))?,
        )?;
    } else if !h.root_login() {
        bail!(
            "blackthorn reaches {} as {}, not root, so it has no root to give",
            s.host,
            h.user
        );
    }
    let mut ctx = Ctx::open()?;
    let now = ctx.now;
    let sp = ctx
        .state
        .spaces
        .get_mut(space)
        .with_context(|| format!("{space} was removed meanwhile"))?;
    sp.root = Some(crate::state::Root { since: now, until });
    let key = sp.key.clone();
    if let Some(x) = ctx.state.hosts.get_mut(&s.host) {
        x.pending
            .retain(|p| !matches!(p, Pending::Revoke { key: k } if *k == key));
    }
    ctx.commit()?;
    drop(ctx);
    close_connections(&s.key);
    Ok(())
}

/// Takes a space's root away: at once on the hub (its agent no longer
/// holds a key that has it), then on the machine (or later, if it cannot
/// be reached: the tick retries).
pub fn revoke(space: &str) -> Result<bool> {
    let mut ctx = Ctx::open()?;
    let s = ctx.state.space(space)?.clone();
    if s.root.is_none() {
        return Ok(false);
    }
    ctx.state.spaces.get_mut(space).expect("checked").root = None;
    let set_up = ctx
        .state
        .hosts
        .get(&s.host)
        .is_some_and(|h| h.setup.is_some());
    if set_up {
        if let Some(x) = ctx.state.hosts.get_mut(&s.host) {
            let p = Pending::Revoke { key: s.key.clone() };
            if !x.pending.contains(&p) {
                x.pending.push(p);
            }
        }
    }
    ctx.commit()?;
    drop(ctx);
    close_connections(&s.key);
    if set_up {
        let _ = do_pending(&s.host);
    }
    Ok(true)
}

/// Ends a space's SSH connections on the hub (its open ones and the shared
/// connections kept for reuse), so a changed login applies at once. What
/// its chats run over SSH right then is cut off.
pub fn close_connections(key: &str) {
    let user = paths::unix_user(key);
    let _ = std::process::Command::new("pkill")
        .args(["-KILL", "-u", &user, "-x", "ssh"])
        .status();
    if let Ok(dir) = std::fs::read_dir(paths::space_runtime(key)) {
        for e in dir.flatten() {
            if e.file_name().to_string_lossy().starts_with("ssh-") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Does what a machine still needs. Returns what was done; stops at the
/// first failure (the machine is probably not reachable).
pub fn do_pending(name: &str) -> Result<Vec<String>> {
    let (_, state) = ctx::read_only()?;
    let h = state.host(name)?.clone();
    let mut done = Vec::new();
    for p in h.pending.clone() {
        let script = match &p {
            Pending::Accounts { .. } => {
                // make_accounts goes through every login the machine lacks.
                let (r, waiting) = make_accounts(name)?;
                done.extend(r);
                if !waiting.is_empty() {
                    break;
                }
                continue;
            }
            Pending::Revoke { key } => revoke_script(key)?,
            Pending::Remove { key, srv, purge } => remove_script(key, srv.as_deref(), *purge)?,
        };
        run(name, &h, &script)?;
        let mut ctx = Ctx::open()?;
        if let Some(x) = ctx.state.hosts.get_mut(name) {
            x.pending.retain(|q| *q != p);
            if let Pending::Remove { key, .. } = &p {
                x.accounts.remove(key);
            }
        }
        ctx.commit()?;
        if let Pending::Remove { key, .. } = &p {
            let (_, st) = ctx::read_only()?;
            if !st.spaces.values().any(|s| s.key == *key) {
                let _ = keys::remove_space(key);
            }
        }
        done.push(match &p {
            Pending::Revoke { key } => format!("root taken back from space {key}"),
            Pending::Remove { key, .. } => format!("logins of space {key} removed"),
            Pending::Accounts { .. } => unreachable!(),
        });
    }
    Ok(done)
}

/// Queues the removal of a space's logins from every machine that has
/// them (after the space is gone, or a bridge ended), and tries at once.
pub fn forget(state: &mut State, key: &str, purge: bool, only: Option<&str>) {
    for (n, h) in state.hosts.iter_mut() {
        if only.is_some_and(|o| o != n) {
            continue;
        }
        h.pending.retain(|p| p.key() != key);
        if let Some(a) = h.accounts.get(key) {
            h.pending.push(Pending::Remove {
                key: key.to_string(),
                srv: a.srv.clone(),
                purge,
            });
        }
    }
}

/// Queues the removal of read-only logins kept for bridges that ended.
/// Returns the machines with something to do.
pub fn unused(state: &mut State, now: u64) -> Vec<String> {
    let mut gone: Vec<(String, String)> = Vec::new();
    for (n, h) in &state.hosts {
        if h.setup.is_none() {
            continue;
        }
        let want = wanted(state, n, now);
        for (key, a) in &h.accounts {
            let queued = h
                .pending
                .iter()
                .any(|p| matches!(p, Pending::Remove { key: k, .. } if k == key));
            if !a.full && !queued && !want.iter().any(|(k, _, _)| k == key) {
                gone.push((n.clone(), key.clone()));
            }
        }
    }
    let mut hosts = Vec::new();
    for (n, key) in gone {
        forget(state, &key, false, Some(&n));
        if !hosts.contains(&n) {
            hosts.push(n);
        }
    }
    hosts
}

/// Every minute: take back root whose time ran out, retry what machines
/// still need, and set up (once an hour at most) the machines reached as
/// root that are not yet. Returns the spaces whose root ended.
pub fn tick() -> Result<Vec<String>> {
    let mut ctx = Ctx::open()?;
    let now = ctx.now;
    let mut ended = Vec::new();
    let mut revoke = Vec::new();
    for (n, s) in ctx.state.spaces.iter_mut() {
        if s.root.as_ref().is_some_and(|r| !r.active(now)) {
            s.root = None;
            ended.push(n.clone());
            revoke.push((s.host.clone(), s.key.clone()));
        }
    }
    let bridged = unused(&mut ctx.state, now);
    for (host, key) in &revoke {
        if let Some(h) = ctx.state.hosts.get_mut(host) {
            if h.setup.is_some() {
                let p = Pending::Revoke { key: key.clone() };
                if !h.pending.contains(&p) {
                    h.pending.push(p);
                }
            }
        }
    }
    if !ended.is_empty() || !bridged.is_empty() {
        ctx.commit()?;
    }
    let state = ctx.state.clone();
    drop(ctx);
    for (_, key) in &revoke {
        close_connections(key);
    }
    for (name, h) in &state.hosts {
        if h.blocked(now) {
            continue;
        }
        if h.setup.is_some() {
            if !h.pending.is_empty() {
                if let Err(e) = do_pending(name) {
                    eprintln!("{name}: {e:#}");
                }
            }
            continue;
        }
        // Not set up: try once an hour, where blackthorn is root (a user
        // with sudo is set up when you ask, from the machine's page).
        let tried = h.problem.as_ref().map_or(0, |p| p.at);
        if h.root_login() && h.os == crate::state::Os::Linux && now.saturating_sub(tried) >= 3600 {
            match setup(name, true) {
                Ok(d) => println!(
                    "{name} set up for logins of each space's own: {}",
                    d.report.join("; ")
                ),
                Err(e) => eprintln!("{name}: setting up failed: {e:#}"),
            }
        }
    }
    Ok(ended)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_script_has_everything() {
        let s = setup_script(&SetupInput {
            admin_user: "alice",
            admin_key: "AAAB",
            admin_line: "from=\"100.64.0.1\",restrict,command=\"/usr/local/libexec/blackthorn-ssh\" ssh-ed25519 AAAB admin",
            add_root: true,
            legacy: Some("blackthorn"),
        })
        .unwrap();
        assert!(s.starts_with("#!/bin/sh\n"));
        assert!(s.contains("add_root=1"));
        assert!(s.contains("exec \"${SHELL:-/bin/sh}\" -c \"$c\"\nBLACKTHORN_LOGGER\n"));
        assert!(s.contains(
            "Cmnd_Alias BLACKTHORN_READ = $d ps, $d ps *, $d logs *, $d stats --no-stream,"
        ));
        assert!(
            s.contains("Cmnd_Alias BLACKTHORN_RREAD = /usr/local/libexec/blackthorn-rdocker ps,")
        );
        assert!(s.contains("blackthorn ALL=(root) NOPASSWD: BLACKTHORN_READ"));
        assert!(s.contains(
            "AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2 /etc/ssh/blackthorn/%u"
        ));
        assert!(s.contains("echo \"bt: done\""));
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

    #[test]
    fn account_and_root_scripts() {
        let a = accounts_script(&AccountsInput {
            key: "a1b2c3d4",
            full: true,
            srv: Some("fig-claude"),
            user_line: "restrict ssh-ed25519 AAAA u",
            ro_line: "restrict ssh-ed25519 AAAB r",
        })
        .unwrap();
        assert!(a.contains("k='a1b2c3d4'"));
        assert!(a.contains("srv='fig-claude'"));
        assert!(a.contains("$ro ALL=(root) NOPASSWD: BLACKTHORN_READ"));
        assert!(a.contains("chmod 2750 \"$d\""));
        assert!(!a.contains("NOPASSWD: ALL"), "no root here");
        let r = root_script("a1b2c3d4", Some(3600)).unwrap();
        assert!(r.contains("$u ALL=(ALL:ALL) NOPASSWD: ALL"));
        assert!(r.contains("secs=3600"));
        assert!(root_script("a1b2c3d4", None).unwrap().contains("secs=\n"));
        assert!(revoke_script("a1b2c3d4")
            .unwrap()
            .contains("rm -f \"/etc/sudoers.d/bt-$k-root\""));
        let rm = remove_script("a1b2c3d4", Some("fig-claude"), false).unwrap();
        assert!(rm.contains("purge=0"));
        assert!(q("it's").is_err(), "no quotes inside");
    }

    #[test]
    fn logins_wanted_on_a_machine() {
        let mut st = State::default();
        let mut s = crate::state::tests_space("fig");
        s.key = "aaaa".into();
        st.spaces.insert("fig-claude".into(), s);
        let mut s = crate::state::tests_space("nas");
        s.key = "bbbb".into();
        st.spaces.insert("nas-claude".into(), s);
        st.bridges.push(crate::state::Bridge {
            from: "nas-claude".into(),
            to: "fig-claude".into(),
            since: 0,
            until: Some(100),
        });
        let w = wanted(&st, "fig", 5);
        assert_eq!(
            w,
            vec![
                ("aaaa".to_string(), true, "fig-claude".to_string()),
                ("bbbb".to_string(), false, "nas-claude".to_string())
            ]
        );
        assert_eq!(wanted(&st, "fig", 100).len(), 1, "the bridge ended");
    }
}
