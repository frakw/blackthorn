//! /var/lib/blackthorn/state.toml: the hosts, spaces and bridges blackthorn manages.
//! Only `thorn` writes it, always while holding the state lock.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct State {
    pub hosts: BTreeMap<String, Host>,
    pub spaces: BTreeMap<String, Space>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bridges: Vec<Bridge>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    #[default]
    Linux,
    Macos,
}

impl Os {
    pub fn describe(self) -> &'static str {
        match self {
            Os::Linux => "Linux",
            Os::Macos => {
                "macOS (zsh, BSD userland: flags of sed, grep, date, stat differ from GNU)"
            }
        }
    }

    /// From the output of `uname -s`.
    pub fn from_uname(s: &str) -> Option<Os> {
        match s.trim() {
            "Linux" => Some(Os::Linux),
            "Darwin" => Some(Os::Macos),
            _ => None,
        }
    }
}

impl std::fmt::Display for Os {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Os::Linux => "linux",
            Os::Macos => "macos",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub address: IpAddr,
    pub port: u16,
    pub user: String,
    /// The host's public keys as "<type> <base64>", recorded when it was
    /// added. Spaces refuse any other key.
    #[serde(default)]
    pub host_keys: Vec<String>,
    /// Learned by `thorn host check` (uname -s).
    #[serde(default)]
    pub os: Os,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<Block>,
    /// The shared read-only login of v0.7 to v0.11 (`thorn host readonly`,
    /// e.g. "blackthorn"), with a key of its own. Removed once the machine
    /// is set up for logins of each space's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readonly: Option<String>,
    /// When it was set up for logins of each space's own (`thorn host
    /// setup`). None: its spaces use the machine's own logins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup: Option<u64>,
    /// Whether the setup found rootless Docker possible there.
    #[serde(default, skip_serializing_if = "is_false")]
    pub rootless_docker: bool,
    /// The spaces with logins of their own there, by space key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub accounts: BTreeMap<String, Account>,
    /// Changes the machine still needs (it could not be reached), retried
    /// every minute.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<Pending>,
    /// Why setting it up failed last, and when (retried hourly).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<Problem>,
}

/// A space's logins on a machine: `bt-<key>` (user, and root with sudo)
/// and `bt-<key>-ro` (read-only); on a machine it only reaches through a
/// bridge, the read-only one alone.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Account {
    /// Has `bt-<key>` too (its own machine).
    #[serde(default, skip_serializing_if = "is_false")]
    pub full: bool,
    /// Its folder there, /srv/<srv> (the space's name when it was made).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub srv: Option<String>,
}

/// Work a machine still needs from the hub.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "do", rename_all = "kebab-case")]
pub enum Pending {
    /// Make a space's logins there (`full`: its own machine).
    Accounts { key: String, full: bool },
    /// Take a space's root away (sudo) and end its sessions.
    Revoke { key: String },
    /// Remove a space's logins (and, with `purge`, its /srv folder).
    Remove {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        srv: Option<String>,
        #[serde(default, skip_serializing_if = "is_false")]
        purge: bool,
    },
}

impl Pending {
    pub fn key(&self) -> &str {
        match self {
            Pending::Accounts { key, .. }
            | Pending::Revoke { key }
            | Pending::Remove { key, .. } => key,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Problem {
    pub at: u64,
    pub text: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// What an account may do with a space. Hub admins may do everything.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Read its chats, terminal and state.
    View,
    /// Also type into its chats, answer Claude, start and stop chats and
    /// the space.
    Use,
    /// Also change its settings, access and bridges, share it, delete it.
    Manage,
    /// Its owner (or a hub admin): also give it to another account.
    Owner,
}

impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Level::View => "view",
            Level::Use => "use",
            Level::Manage => "manage",
            Level::Owner => "owner",
        })
    }
}

impl std::str::FromStr for Level {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "view" => Level::View,
            "use" => Level::Use,
            "manage" => Level::Manage,
            _ => anyhow::bail!("a share is view, use or manage, not {s:?}"),
        })
    }
}

/// A space's usual login on its machine, below any root it is given for
/// a time.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// Before v0.12: the machine's admin login. Read once, then turned
    /// into User with root (see `State::upgrade`).
    #[default]
    Admin,
    /// Look, do not touch.
    Readonly,
    /// An ordinary user: its own files and containers.
    User,
}

impl Access {
    pub fn tier(self) -> Tier {
        match self {
            Access::Readonly => Tier::ReadOnly,
            Access::User => Tier::User,
            Access::Admin => Tier::Root,
        }
    }
}

impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.tier().fmt(f)
    }
}

impl std::str::FromStr for Access {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "read-only" | "readonly" | "ro" => Access::Readonly,
            "user" => Access::User,
            _ => bail!("a usual login is read-only or user, not {s:?} (root is given for a time: thorn root)"),
        })
    }
}

/// How far a space goes on a machine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    ReadOnly,
    User,
    Root,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Tier::ReadOnly => "read-only",
            Tier::User => "user",
            Tier::Root => "root",
        })
    }
}

/// Root given to a space, until a time or (None) until taken back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub since: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

impl Root {
    pub fn active(&self, now: u64) -> bool {
        self.until.map_or(true, |u| now < u)
    }
}

/// How a space logs in to a machine it can reach.
#[derive(Debug, Clone, PartialEq)]
pub struct Login<'a> {
    pub host: &'a str,
    pub h: &'a Host,
    pub user: String,
    /// The key file its agent holds for this login.
    pub key: std::path::PathBuf,
    pub tier: Tier,
    /// Reached through a bridge (not the space's own machine).
    pub bridged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Block {
    /// Unix seconds.
    pub since: u64,
    /// Unix seconds; None blocks until `thorn host unblock`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A space is one machine worked on by one AI agent: its own Unix user,
/// firewall rules, ssh-agent and conversations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Space {
    /// Stable identity: names the Unix user (bt-<key>), the systemd units and
    /// the home directory, so renaming a space touches none of them.
    pub key: String,
    /// The machine this space works on.
    pub host: String,
    /// "claude", or the name of an agent in config.toml.
    pub agent: String,
    /// Claude only: one Remote Control server with many chats (default), or
    /// a single conversation that can also be typed into on the terminal.
    #[serde(default)]
    pub mode: Mode,
    /// Claude only: reachable through Remote Control (the Claude app,
    /// claude.ai/code). Off: only from the hub itself, through its terminal
    /// (the web UI or `thorn attach`).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub remote_control: bool,
    /// Name shown in Remote Control on your phone or laptop. The Claude app
    /// names the environment after the work folder, so it is also that
    /// folder's name (`dir`) for spaces made since v0.6.
    pub rc_name: String,
    /// The work folder in the space's home: the Remote Control name, or
    /// "work" for spaces made before v0.6 (until their Remote Control name
    /// is changed).
    #[serde(default = "work_dir")]
    pub dir: String,
    /// The conversation a single-mode space resumes.
    pub conversation: String,
    /// Extra arguments for the agent, e.g. ["--permission-mode", "acceptEdits"].
    #[serde(default)]
    pub args: Vec<String>,
    pub created: u64,
    /// Its usual login on its machine: read-only or user.
    #[serde(default)]
    pub access: Access,
    /// Root on its machine, for a time or until taken back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<Root>,
    /// Before v0.12: when a limited admin space stopped. Read once, then
    /// turned into `root`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    /// The name a new conversation gets when it starts (single mode and
    /// spaces without Remote Control).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The web account that owns it; None: only hub admins (spaces made
    /// on the hub's command line, or before v0.11).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Other accounts it is shared with, and how far.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub shares: BTreeMap<String, Level>,
}

impl Space {
    /// How far it goes on its machine now.
    pub fn tier(&self, now: u64) -> Tier {
        if self.root.as_ref().is_some_and(|r| r.active(now)) {
            Tier::Root
        } else {
            self.access.tier()
        }
    }

    /// How far `user` may go with this space (`admin`: a hub admin).
    pub fn level(&self, user: &str, admin: bool) -> Option<Level> {
        if admin || self.owner.as_deref() == Some(user) {
            return Some(Level::Owner);
        }
        self.shares.get(user).copied()
    }
}

fn yes() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Server,
    Single,
}

/// Lets the chats of space `from` also reach the machine of space `to`, for
/// a limited time. One-way: `to` gains nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bridge {
    pub from: String,
    pub to: String,
    pub since: u64,
    /// Unix seconds; None lasts until `thorn bridge rm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
}

impl Block {
    pub fn active(&self, now: u64) -> bool {
        self.until.map_or(true, |u| now < u)
    }
}

impl Bridge {
    pub fn active(&self, now: u64) -> bool {
        self.until.map_or(true, |u| now < u)
    }
}

impl Host {
    pub fn blocked(&self, now: u64) -> bool {
        self.block.as_ref().is_some_and(|b| b.active(now))
    }

    /// Blackthorn logs in as root (directly; not through sudo).
    pub fn root_login(&self) -> bool {
        self.user == "root"
    }

    /// The logins its spaces can have.
    pub fn tiers(&self) -> Vec<Tier> {
        if self.setup.is_some() {
            return vec![Tier::ReadOnly, Tier::User, Tier::Root];
        }
        let mut v = Vec::new();
        if self.readonly.is_some() {
            v.push(Tier::ReadOnly);
        }
        v.push(if self.root_login() {
            Tier::Root
        } else {
            Tier::User
        });
        v
    }
}

impl State {
    pub fn load(path: &Path) -> Result<State> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let mut st: State =
                    toml::from_str(&text).with_context(|| format!("reading {}", path.display()))?;
                st.upgrade();
                Ok(st)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Turns the admin spaces of v0.7 to v0.11 into a usual login and
    /// root: a time-limited one (its machine had a read-only login) stays
    /// read-only, with root for the time it had left; any other keeps root
    /// until taken back, over a user login. Where the admin login is not
    /// root, it was a user's all along.
    pub fn upgrade(&mut self) {
        for s in self.spaces.values_mut() {
            if s.access != Access::Admin {
                continue;
            }
            let h = self.hosts.get(&s.host);
            let ro = h.is_some_and(|h| h.readonly.is_some());
            let root_login = h.is_some_and(|h| h.root_login());
            if ro {
                s.access = Access::Readonly;
                if let Some(u) = s.until {
                    s.root = Some(Root {
                        since: s.created,
                        until: Some(u),
                    });
                }
            } else {
                s.access = Access::User;
                if root_login {
                    s.root = Some(Root {
                        since: s.created,
                        until: None,
                    });
                }
            }
            s.until = None;
        }
    }

    /// Atomic replace: write a temporary file next to it, then rename.
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self)?;
        let tmp = path.with_extension("toml.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .with_context(|| format!("writing {}", tmp.display()))?;
            f.write_all(b"# Managed by thorn. Do not edit by hand; use the thorn command.\n")?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    /// The hosts a space may reach right now: its own machine plus the
    /// machines of the spaces it has an active bridge to, minus blocked ones.
    pub fn reachable_hosts<'a>(&'a self, space: &str, now: u64) -> Vec<(&'a str, &'a Host)> {
        let Some(s) = self.spaces.get(space) else {
            return Vec::new();
        };
        let mut names: BTreeSet<&str> = BTreeSet::new();
        names.insert(s.host.as_str());
        for b in self
            .bridges
            .iter()
            .filter(|b| b.from == space && b.active(now))
        {
            if let Some(t) = self.spaces.get(&b.to) {
                names.insert(t.host.as_str());
            }
        }
        names
            .into_iter()
            .filter_map(|n| self.hosts.get_key_value(n))
            .filter(|(_, h)| !h.blocked(now))
            .map(|(n, h)| (n.as_str(), h))
            .collect()
    }

    /// How space `space` logs in to each machine it may reach now.
    ///
    /// A machine set up for it: its own logins there, `bt-<key>` (user, or
    /// root through sudo) or `bt-<key>-ro`, by how far it goes now; through
    /// a bridge always the read-only one. None until they are made.
    ///
    /// Any other machine: the machine's own logins, its shared read-only
    /// one or blackthorn's (root, or a user's). A bridge takes the
    /// read-only one if there is one. Nothing if the login it should have
    /// is not there (a user login on a machine blackthorn reaches only as
    /// root, which has none).
    pub fn logins<'a>(&'a self, space: &str, now: u64) -> Vec<Login<'a>> {
        let Some(s) = self.spaces.get(space) else {
            return Vec::new();
        };
        self.reachable_hosts(space, now)
            .into_iter()
            .filter_map(|(name, h)| {
                let own = name == s.host;
                let want = if own { s.tier(now) } else { Tier::ReadOnly };
                if h.setup.is_some() {
                    let a = h.accounts.get(&s.key)?;
                    let tier = if a.full { want } else { Tier::ReadOnly };
                    let (user, key) = if tier == Tier::ReadOnly {
                        (
                            crate::paths::remote_ro_user(&s.key),
                            crate::paths::space_ro_key_file(&s.key),
                        )
                    } else {
                        (
                            crate::paths::unix_user(&s.key),
                            crate::paths::space_key_file(&s.key),
                        )
                    };
                    return Some(Login {
                        host: name,
                        h,
                        user,
                        key,
                        tier,
                        bridged: !own,
                    });
                }
                let ro = h.readonly.as_ref().filter(|_| want == Tier::ReadOnly);
                if let Some(u) = ro {
                    return Some(Login {
                        host: name,
                        h,
                        user: u.clone(),
                        key: crate::paths::ro_key_file(name),
                        tier: Tier::ReadOnly,
                        bridged: !own,
                    });
                }
                let tier = if h.root_login() {
                    Tier::Root
                } else {
                    Tier::User
                };
                // Only a bridge falls back to more than it asked for, as
                // before v0.12; a space gets no more than its tier.
                if own && tier > want {
                    return None;
                }
                Some(Login {
                    host: name,
                    h,
                    user: h.user.clone(),
                    key: crate::paths::key_file(name),
                    tier,
                    bridged: !own,
                })
            })
            .collect()
    }

    /// Lifts blocks whose time is up. Returns the hosts that were unblocked.
    pub fn expire_blocks(&mut self, now: u64) -> Vec<String> {
        let mut lifted = Vec::new();
        for (name, host) in self.hosts.iter_mut() {
            if host.block.as_ref().is_some_and(|b| !b.active(now)) {
                host.block = None;
                lifted.push(name.clone());
            }
        }
        lifted
    }

    /// Removes bridges whose time is up. Returns them as "from -> to".
    pub fn expire_bridges(&mut self, now: u64) -> Vec<String> {
        let mut gone = Vec::new();
        self.bridges.retain(|b| {
            let keep = b.active(now);
            if !keep {
                gone.push(format!("{} -> {}", b.from, b.to));
            }
            keep
        });
        gone
    }

    pub fn space_by_key(&self, key: &str) -> Option<(&str, &Space)> {
        self.spaces
            .iter()
            .find(|(_, s)| s.key == key)
            .map(|(n, s)| (n.as_str(), s))
    }

    pub fn space(&self, name: &str) -> Result<&Space> {
        match self.spaces.get(name) {
            Some(s) => Ok(s),
            None => bail!("no space named {name:?} (thorn ls lists them)"),
        }
    }

    pub fn host(&self, name: &str) -> Result<&Host> {
        match self.hosts.get(name) {
            Some(h) => Ok(h),
            None => bail!("no host named {name:?} (thorn host ls lists them)"),
        }
    }

    pub fn spaces_on(&self, host: &str) -> Vec<&str> {
        self.spaces
            .iter()
            .filter(|(_, s)| s.host == host)
            .map(|(n, _)| n.as_str())
            .collect()
    }
}

/// Held for the whole of a command that changes state.
pub struct StateLock {
    _file: File,
}

impl StateLock {
    pub fn acquire(path: &Path) -> Result<StateLock> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        // SAFETY: flock on a file descriptor we own.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("locking blackthorn state");
        }
        Ok(StateLock { _file: file })
    }
}

/// Space and host names: they appear in commands, file names, ssh aliases
/// and Remote Control names, so keep them plain.
pub fn validate_name(kind: &str, name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !ok {
        bail!(
            "{kind} name {name:?} is not allowed: use 1-32 characters, lowercase letters, \
             digits and '-', starting with a letter"
        );
    }
    Ok(())
}

/// Remote Control names are shown to you and passed to claude as one argument.
fn work_dir() -> String {
    "work".into()
}

impl Space {
    /// Where the agent runs: its work folder.
    pub fn workdir(&self) -> std::path::PathBuf {
        crate::paths::space_home(&self.key).join(&self.dir)
    }
}

pub fn validate_rc_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.starts_with('.')
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if !ok {
        bail!("Remote Control name {name:?} is not allowed: use letters, digits, '-', '_' and '.' (not first)");
    }
    Ok(())
}

/// Login names on the remote host.
pub fn validate_remote_user(user: &str) -> Result<()> {
    let ok = !user.is_empty()
        && user.len() <= 32
        && !user.starts_with('-')
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if !ok {
        bail!("remote user {user:?} is not a valid login name");
    }
    Ok(())
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A space for tests elsewhere.
#[cfg(test)]
pub fn tests_space(host: &str) -> Space {
    tests::space(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(block: Option<Block>) -> Host {
        Host {
            address: "100.80.0.3".parse().unwrap(),
            port: 22,
            user: "frakw".into(),
            host_keys: vec![],
            os: Os::Linux,
            block,
            readonly: None,
            setup: None,
            rootless_docker: false,
            accounts: BTreeMap::new(),
            pending: Vec::new(),
            problem: None,
        }
    }

    pub fn space(host: &str) -> Space {
        Space {
            key: format!("k{host}"),
            host: host.into(),
            agent: "claude".into(),
            mode: Mode::Server,
            remote_control: true,
            rc_name: format!("{host}-claude"),
            dir: format!("{host}-claude"),
            conversation: "7bb9dc88-2ec5-4933-90b6-b872466876b2".into(),
            args: vec![],
            created: 0,
            access: Access::User,
            root: None,
            until: None,
            title: None,
            owner: None,
            shares: BTreeMap::new(),
        }
    }

    fn forever() -> Option<Block> {
        Some(Block {
            since: 0,
            until: None,
            reason: None,
        })
    }

    #[test]
    fn names() {
        assert!(validate_name("space", "ops").is_ok());
        assert!(validate_name("space", "fig-201").is_ok());
        assert!(validate_name("space", "").is_err());
        assert!(validate_name("space", "1ops").is_err());
        assert!(validate_name("space", "Ops").is_err());
        assert!(validate_name("space", "a/b").is_err());
        assert!(validate_name("space", "-x").is_err());
        assert!(validate_name("space", &"a".repeat(33)).is_err());
        assert!(validate_rc_name("ops-hub").is_ok());
        assert!(validate_rc_name("ops hub").is_err());
        assert!(validate_remote_user("frakw").is_ok());
        assert!(validate_remote_user("-oProxyCommand=x").is_err());
    }

    #[test]
    fn blocks_and_expiry() {
        let timed = Block {
            since: 10,
            until: Some(100),
            reason: None,
        };
        assert!(forever().unwrap().active(1_000_000));
        assert!(timed.active(99));
        assert!(!timed.active(100));

        let mut st = State::default();
        st.hosts.insert("basil".into(), host(Some(timed)));
        st.hosts.insert("pine".into(), host(forever()));
        st.hosts.insert("nas".into(), host(None));
        assert!(st.expire_blocks(50).is_empty());
        assert_eq!(st.expire_blocks(100), vec!["basil".to_string()]);
        assert!(st.hosts["basil"].block.is_none());
        assert!(st.hosts["pine"].block.is_some());
    }

    #[test]
    fn a_space_reaches_its_host_and_bridged_hosts() {
        let mut st = State::default();
        st.hosts.insert("fig".into(), host(None));
        st.hosts.insert("nas".into(), host(None));
        st.hosts.insert("pine".into(), host(forever()));
        st.spaces.insert("fig-claude".into(), space("fig"));
        st.spaces.insert("nas-claude".into(), space("nas"));
        st.spaces.insert("pine-claude".into(), space("pine"));
        let names = |st: &State, s: &str, now| -> Vec<String> {
            st.reachable_hosts(s, now)
                .into_iter()
                .map(|(n, _)| n.to_string())
                .collect()
        };
        assert_eq!(names(&st, "fig-claude", 5), vec!["fig"]);
        assert!(names(&st, "pine-claude", 5).is_empty(), "blocked");
        assert!(names(&st, "gone", 5).is_empty());

        st.bridges.push(Bridge {
            from: "fig-claude".into(),
            to: "nas-claude".into(),
            since: 0,
            until: Some(100),
        });
        st.bridges.push(Bridge {
            from: "fig-claude".into(),
            to: "pine-claude".into(),
            since: 0,
            until: None,
        });
        assert_eq!(names(&st, "fig-claude", 5), vec!["fig", "nas"]);
        assert_eq!(
            names(&st, "nas-claude", 5),
            vec!["nas"],
            "bridges are one-way"
        );
        assert_eq!(names(&st, "fig-claude", 100), vec!["fig"], "expired");
        assert_eq!(st.expire_bridges(100), vec!["fig-claude -> nas-claude"]);
        assert_eq!(st.bridges.len(), 1);
    }

    #[test]
    fn logins_follow_access_and_bridges() {
        // Machines not set up: their own logins.
        let mut st = State::default();
        st.hosts.insert("fig".into(), host(None));
        let mut nas = host(None);
        nas.readonly = Some("blackthorn".into());
        st.hosts.insert("nas".into(), nas);
        st.spaces.insert("fig-claude".into(), space("fig"));
        let mut ro = space("nas");
        ro.access = Access::Readonly;
        st.spaces.insert("nas-ro".into(), ro);
        st.spaces.insert("nas-user".into(), space("nas"));
        st.bridges.push(Bridge {
            from: "fig-claude".into(),
            to: "nas-user".into(),
            since: 0,
            until: None,
        });
        let l = st.logins("fig-claude", 5);
        assert_eq!(l.len(), 2);
        assert_eq!(
            (l[0].host, l[0].user.as_str(), l[0].tier),
            ("fig", "frakw", Tier::User)
        );
        assert_eq!(
            (l[1].host, l[1].user.as_str(), l[1].tier, l[1].bridged),
            ("nas", "blackthorn", Tier::ReadOnly, true),
            "a bridge reaches the read-only login"
        );
        let l = st.logins("nas-ro", 5);
        assert_eq!(
            (l[0].user.as_str(), l[0].tier),
            ("blackthorn", Tier::ReadOnly)
        );
        assert_eq!(st.logins("nas-user", 5)[0].user, "frakw");
        st.hosts.get_mut("nas").unwrap().readonly = None;
        assert!(st.logins("nas-ro", 5).is_empty(), "no read-only login left");

        // Reached as root only: no user login there, root for root.
        st.hosts.get_mut("fig").unwrap().user = "root".into();
        assert!(st.logins("fig-claude", 5).is_empty());
        st.spaces.get_mut("fig-claude").unwrap().root = Some(Root {
            since: 0,
            until: Some(10),
        });
        let l = st.logins("fig-claude", 5);
        assert_eq!((l[0].user.as_str(), l[0].tier), ("root", Tier::Root));
        assert!(st.logins("fig-claude", 10).is_empty(), "root ran out");
    }

    #[test]
    fn logins_of_their_own() {
        let mut st = State::default();
        let mut fig = host(None);
        fig.setup = Some(1);
        st.hosts.insert("fig".into(), fig);
        let mut nas = host(None);
        nas.setup = Some(1);
        st.hosts.insert("nas".into(), nas);
        let mut s = space("fig");
        s.key = "a1b2c3d4".into();
        st.spaces.insert("fig-claude".into(), s);
        st.spaces.insert("nas-claude".into(), space("nas"));
        st.bridges.push(Bridge {
            from: "fig-claude".into(),
            to: "nas-claude".into(),
            since: 0,
            until: None,
        });
        assert!(st.logins("fig-claude", 5).is_empty(), "not made yet");
        st.hosts.get_mut("fig").unwrap().accounts.insert(
            "a1b2c3d4".into(),
            Account {
                full: true,
                srv: Some("fig-claude".into()),
            },
        );
        st.hosts
            .get_mut("nas")
            .unwrap()
            .accounts
            .insert("a1b2c3d4".into(), Account::default());
        let l = st.logins("fig-claude", 5);
        assert_eq!((l[0].user.as_str(), l[0].tier), ("bt-a1b2c3d4", Tier::User));
        assert!(l[0].key.ends_with("spaces/a1b2c3d4"));
        assert_eq!(
            (l[1].user.as_str(), l[1].tier, l[1].bridged),
            ("bt-a1b2c3d4-ro", Tier::ReadOnly, true)
        );
        assert!(l[1].key.ends_with("spaces/a1b2c3d4-ro"));

        let s = st.spaces.get_mut("fig-claude").unwrap();
        s.access = Access::Readonly;
        let l = st.logins("fig-claude", 5);
        assert_eq!(l[0].user, "bt-a1b2c3d4-ro");
        st.spaces.get_mut("fig-claude").unwrap().root = Some(Root {
            since: 0,
            until: None,
        });
        let l = st.logins("fig-claude", 5);
        assert_eq!(
            (l[0].user.as_str(), l[0].tier),
            ("bt-a1b2c3d4", Tier::Root),
            "root is the user login with sudo"
        );
        assert_eq!(l[1].tier, Tier::ReadOnly, "a bridge stays read-only");
    }

    #[test]
    fn admin_spaces_of_before_become_root() {
        let mut st = State::default();
        let mut fig = host(None);
        fig.user = "root".into();
        st.hosts.insert("fig".into(), fig);
        let mut nas = host(None);
        nas.user = "root".into();
        nas.readonly = Some("blackthorn".into());
        st.hosts.insert("nas".into(), nas);
        st.hosts.insert("mac".into(), host(None));
        for (n, h, until) in [
            ("fig-claude", "fig", None),
            ("nas-admin", "nas", Some(500)),
            ("nas-idle", "nas", None),
            ("mac-claude", "mac", None),
        ] {
            let mut s = space(h);
            s.access = Access::Admin;
            s.until = until;
            st.spaces.insert(n.into(), s);
        }
        st.upgrade();
        let get = |n: &str| {
            let s = &st.spaces[n];
            (s.access, s.root.as_ref().map(|r| r.until), s.until)
        };
        assert_eq!(get("fig-claude"), (Access::User, Some(None), None));
        assert_eq!(get("nas-admin"), (Access::Readonly, Some(Some(500)), None));
        assert_eq!(get("nas-idle"), (Access::Readonly, None, None));
        assert_eq!(
            get("mac-claude"),
            (Access::User, None, None),
            "frakw is no root"
        );
    }

    #[test]
    fn pending_work_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        let mut st = State::default();
        let mut h = host(None);
        h.setup = Some(3);
        h.pending = vec![
            Pending::Accounts {
                key: "a".into(),
                full: true,
            },
            Pending::Revoke { key: "b".into() },
            Pending::Remove {
                key: "c".into(),
                srv: Some("x".into()),
                purge: true,
            },
        ];
        st.hosts.insert("fig".into(), h);
        st.save(&path).unwrap();
        assert_eq!(State::load(&path).unwrap(), st);
    }

    #[test]
    fn os_from_uname() {
        assert_eq!(Os::from_uname("Linux\n"), Some(Os::Linux));
        assert_eq!(Os::from_uname("Darwin"), Some(Os::Macos));
        assert_eq!(Os::from_uname("MINGW64_NT"), None);
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        let mut st = State::default();
        st.hosts.insert(
            "basil".into(),
            host(Some(Block {
                since: 1,
                until: Some(2),
                reason: Some("x".into()),
            })),
        );
        st.spaces.insert("basil-claude".into(), space("basil"));
        st.bridges.push(Bridge {
            from: "basil-claude".into(),
            to: "basil-claude".into(),
            since: 1,
            until: None,
        });
        st.save(&path).unwrap();
        assert_eq!(State::load(&path).unwrap(), st);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn missing_state_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            State::load(&dir.path().join("none.toml")).unwrap(),
            State::default()
        );
    }
}
