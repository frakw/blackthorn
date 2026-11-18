//! /var/lib/blackthorn/state.toml: the hosts and sessions blackthorn manages.
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
    pub sessions: BTreeMap<String, Session>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub address: IpAddr,
    pub port: u16,
    pub user: String,
    /// The host's public keys as "<type> <base64>", recorded when it was
    /// added. Sessions refuse any other key.
    #[serde(default)]
    pub host_keys: Vec<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Session {
    /// Stable identity: names the Unix user (bt-<key>), the systemd units and
    /// the home directory, so renaming a session touches none of them.
    pub key: String,
    /// The Claude Code conversation id the session resumes.
    pub conversation: String,
    /// Name shown in Remote Control on your phone or laptop.
    pub rc_name: String,
    #[serde(default)]
    pub hosts: BTreeSet<String>,
    /// Extra arguments for `claude`, e.g. ["--permission-mode", "acceptEdits"].
    #[serde(default)]
    pub args: Vec<String>,
    pub created: u64,
}

impl Block {
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

    /// Hosts a session may reach right now: granted, known, and not blocked.
    pub fn reachable_hosts<'a>(&'a self, session: &Session, now: u64) -> Vec<(&'a str, &'a Host)> {
        session
            .hosts
            .iter()
            .filter_map(|name| self.hosts.get_key_value(name.as_str()))
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

    pub fn session_by_key(&self, key: &str) -> Option<(&str, &Session)> {
        self.sessions
            .iter()
            .find(|(_, s)| s.key == key)
            .map(|(n, s)| (n.as_str(), s))
    }

    pub fn session(&self, name: &str) -> Result<&Session> {
        match self.sessions.get(name) {
            Some(s) => Ok(s),
            None => bail!("no session named {name:?} (thorn ls lists them)"),
        }
    }

    pub fn host(&self, name: &str) -> Result<&Host> {
        match self.hosts.get(name) {
            Some(h) => Ok(h),
            None => bail!("no host named {name:?} (thorn host ls lists them)"),
        }
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

/// Session and host names: they appear in commands, file names, ssh aliases
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
pub fn validate_rc_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if !ok {
        bail!("Remote Control name {name:?} is not allowed: use letters, digits, '-', '_' and '.'");
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
            block,
        }
    }

    fn session(hosts: &[&str]) -> Session {
        Session {
            key: "a1b2c3d4".into(),
            conversation: "7bb9dc88-2ec5-4933-90b6-b872466876b2".into(),
            rc_name: "ops".into(),
            hosts: hosts.iter().map(|s| s.to_string()).collect(),
            args: vec![],
            created: 0,
        }
    }

    #[test]
    fn names() {
        assert!(validate_name("session", "ops").is_ok());
        assert!(validate_name("session", "fig-201").is_ok());
        assert!(validate_name("session", "").is_err());
        assert!(validate_name("session", "1ops").is_err());
        assert!(validate_name("session", "Ops").is_err());
        assert!(validate_name("session", "a/b").is_err());
        assert!(validate_name("session", "-x").is_err());
        assert!(validate_name("session", &"a".repeat(33)).is_err());
        assert!(validate_rc_name("ops-hub").is_ok());
        assert!(validate_rc_name("ops hub").is_err());
        assert!(validate_remote_user("frakw").is_ok());
        assert!(validate_remote_user("-oProxyCommand=x").is_err());
    }

    #[test]
    fn blocks_and_expiry() {
        let forever = Block {
            since: 10,
            until: None,
            reason: None,
        };
        let timed = Block {
            since: 10,
            until: Some(100),
            reason: None,
        };
        assert!(forever.active(1_000_000));
        assert!(timed.active(99));
        assert!(!timed.active(100));

        let mut st = State::default();
        st.hosts.insert("basil".into(), host(Some(timed)));
        st.hosts.insert("pine".into(), host(Some(forever)));
        st.hosts.insert("nas".into(), host(None));
        assert!(st.expire_blocks(50).is_empty());
        assert_eq!(st.expire_blocks(100), vec!["basil".to_string()]);
        assert!(st.hosts["basil"].block.is_none());
        assert!(st.hosts["pine"].block.is_some());
    }

    #[test]
    fn reachable_skips_blocked_and_unknown() {
        let mut st = State::default();
        st.hosts.insert("basil".into(), host(None));
        st.hosts.insert(
            "pine".into(),
            host(Some(Block {
                since: 0,
                until: None,
                reason: None,
            })),
        );
        let s = session(&["basil", "pine", "gone"]);
        let names: Vec<_> = st
            .reachable_hosts(&s, 5)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, vec!["basil"]);
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
        st.sessions.insert("ops".into(), session(&["basil"]));
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
