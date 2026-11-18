//! Brings the system in line with the state: firewall, per-session files,
//! and the keys in each session's agent. Every command that changes state
//! ends by calling `everything`; it is safe to run at any time.

use crate::config::{self, Config};
use crate::firewall::{self, Plan, SessionRules};
use crate::state::{Session, State};
use crate::{keys, paths, render, sys};
use anyhow::{Context, Result};
use std::path::Path;

/// Where the last applied ruleset is kept, to skip identical reloads.
const LAST_RULESET: &str = "/run/blackthorn-firewall.nft";

pub fn everything(cfg: &Config, state: &State, now: u64) -> Result<()> {
    firewall_rules(cfg, state, now, false)?;
    for (name, s) in &state.sessions {
        session_files(cfg, state, name, s, now)
            .with_context(|| format!("updating files of session {name}"))?;
        let hosts: Vec<&str> = state
            .reachable_hosts(s, now)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        keys::sync_agent(&s.key, &hosts)
            .with_context(|| format!("updating the keys of session {name}"))?;
    }
    Ok(())
}

pub fn plan(cfg: &Config, state: &State, now: u64) -> Plan {
    let mut sessions = Vec::new();
    for (name, s) in &state.sessions {
        let Some(ids) = sys::lookup_user(&paths::unix_user(&s.key)) else {
            eprintln!("warning: session {name} has no Unix user; it is not running");
            continue;
        };
        let allow = state
            .reachable_hosts(s, now)
            .into_iter()
            .map(|(n, h)| (n.to_string(), h.address, h.port))
            .collect();
        sessions.push(SessionRules {
            name: name.clone(),
            uid: ids.uid,
            allow,
        });
    }
    let dns = if cfg.egress.dns.is_empty() {
        std::fs::read_to_string("/etc/resolv.conf")
            .map(|t| config::parse_resolv_conf(&t))
            .unwrap_or_default()
    } else {
        cfg.egress.dns.clone()
    };
    Plan {
        sessions,
        dns,
        https_anywhere: cfg.egress.https_anywhere,
    }
}

/// Loads the ruleset if it differs from the last one loaded (or `force`).
/// Returns whether it was loaded.
pub fn firewall_rules(cfg: &Config, state: &State, now: u64, force: bool) -> Result<bool> {
    let ruleset = firewall::render(&plan(cfg, state, now));
    let last = std::fs::read_to_string(LAST_RULESET).unwrap_or_default();
    if !force && last == ruleset && firewall::show().is_ok() {
        return Ok(false);
    }
    firewall::apply(&ruleset)?;
    sys::write_file(Path::new(LAST_RULESET), &ruleset, 0o600, None)?;
    Ok(true)
}

pub fn session_files(cfg: &Config, state: &State, name: &str, s: &Session, now: u64) -> Result<()> {
    let home = paths::session_home(&s.key);
    if !home.exists() {
        return Ok(());
    }
    let reachable = state.reachable_hosts(s, now);

    // ~/.ssh belongs to root so the generated files are not the session's
    // to change (see THREAT_MODEL.md for what that does and does not stop).
    let ssh_dir = home.join(".ssh");
    sys::mkdir(&ssh_dir, 0o755)?;
    sys::chown(&ssh_dir, 0, 0)?;
    sys::write_file(
        &ssh_dir.join("config"),
        &render::ssh_config(&s.key, &reachable),
        0o644,
        None,
    )?;
    sys::write_file(
        &ssh_dir.join("known_hosts"),
        &render::known_hosts(&reachable),
        0o644,
        None,
    )?;

    let workdir = paths::session_workdir(&s.key);
    if workdir.exists() {
        sys::write_file(
            &workdir.join("CLAUDE.md"),
            &render::claude_md(name, state, s, now),
            0o644,
            None,
        )?;
    }

    let launch = render::launch(
        name,
        s,
        cfg.claude_bin.to_str().context("claude_bin is not UTF-8")?,
        &cfg.claude_args,
    );
    sys::write_file(
        &paths::launch_file(&s.key),
        &toml::to_string(&launch)?,
        0o644,
        None,
    )?;
    Ok(())
}
