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
}

impl State {
    pub fn load(path: &Path) -> Result<State> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("reading {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
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
