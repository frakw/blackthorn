//! Brings the system in line with the state: firewall, per-space files, and
//! the keys in each space's agent. Every command that changes state ends by
//! calling `everything`; it is safe to run at any time.

use crate::config::{self, Config};
use crate::firewall::{self, InboundPlan, Plan, SpaceRules};
use crate::state::{Space, State};
use crate::{keys, paths, render, sys};
use anyhow::{Context, Result};
use std::net::IpAddr;
use std::path::Path;

/// Where the last applied ruleset is kept, to skip identical reloads.
const LAST_RULESET: &str = "/run/blackthorn-firewall.nft";

pub fn everything(cfg: &Config, state: &State, now: u64) -> Result<()> {
    firewall_rules(cfg, state, now, false)?;
    for (name, s) in &state.spaces {
        space_files(cfg, state, name, s, now)
            .with_context(|| format!("updating files of space {name}"))?;
        keys::sync_agent(&s.key, &agent_keys(state, name, now))
            .with_context(|| format!("updating the keys of space {name}"))?;
    }
    Ok(())
}

/// The keys a space's agent holds: one per machine it may reach now, for
/// the login it uses there.
pub fn agent_keys(state: &State, space: &str, now: u64) -> Vec<std::path::PathBuf> {
    state
        .logins(space, now)
        .iter()
        .map(keys::login_key)
        .collect()
}

/// Every address that must never open a connection to the hub.
pub fn denied_inbound(cfg: &Config, state: &State) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = state.hosts.values().map(|h| h.address).collect();
    v.extend(cfg.never_manage.iter().copied());
    v.extend(cfg.inbound.deny_from.iter().copied());
    v.sort();
    v.dedup();
    v
}

pub fn admin_ports(cfg: &Config) -> Vec<u16> {
    let mut ports = vec![cfg.inbound.ssh_port];
    ports.extend(cfg.web.listen.iter().map(|a| a.port()));
    ports.sort();
    ports.dedup();
    ports
}

pub fn plan(cfg: &Config, state: &State, now: u64) -> Plan {
    let mut spaces = Vec::new();
    for (name, s) in &state.spaces {
        let Some(ids) = sys::lookup_user(&paths::unix_user(&s.key)) else {
            eprintln!("warning: space {name} has no Unix user; it is not running");
            continue;
        };
        let allow = state
            .reachable_hosts(name, now)
            .into_iter()
            .map(|(n, h)| (n.to_string(), h.address, h.port))
            .collect();
        spaces.push(SpaceRules {
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
        spaces,
        dns,
        https_anywhere: cfg.egress.https_anywhere,
        inbound: InboundPlan {
            deny_from: denied_inbound(cfg, state),
            admin_from: cfg.inbound.admin_from.clone(),
            admin_ports: admin_ports(cfg),
        },
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

pub fn space_files(cfg: &Config, state: &State, name: &str, s: &Space, now: u64) -> Result<()> {
    let home = paths::space_home(&s.key);
    if !home.exists() {
        return Ok(());
    }
    let logins = state.logins(name, now);

    // ~/.ssh belongs to root so the generated files are not the space's to
    // change (see THREAT_MODEL.md for what that does and does not stop).
    let ssh_dir = home.join(".ssh");
    sys::mkdir(&ssh_dir, 0o755)?;
    sys::chown(&ssh_dir, 0, 0)?;
    sys::write_file(
        &ssh_dir.join("config"),
        &render::ssh_config(&s.key, &logins),
        0o644,
        None,
    )?;
    sys::write_file(
        &ssh_dir.join("known_hosts"),
        &render::known_hosts(&logins),
        0o644,
        None,
    )?;

    let workdir = s.workdir();
    if workdir.exists() {
        sys::write_file(
            &workdir.join(cfg.instructions_file(&s.agent)),
            &render::instructions(name, state, now),
            0o644,
            None,
        )?;
    }

    sys::write_file(
        &paths::launch_file(&s.key),
        &toml::to_string(&render::launch(name, s, cfg))?,
        0o644,
        None,
    )?;
    Ok(())
}
