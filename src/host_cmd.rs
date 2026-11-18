//! thorn host add / rm / ls / block / unblock / pubkey / check / rescan

use crate::ctx::Ctx;
use crate::session_cmd::print_table;
use crate::state::{now, validate_name, validate_remote_user, Block, Host};
use crate::{keys, paths, sys};
use anyhow::{bail, Context, Result};
use std::io::{BufRead, IsTerminal, Write};
use std::net::IpAddr;
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

/// "user@100.80.0.3" or "user@[fd7a::1]" or "user@fd7a::1".
pub fn parse_target(target: &str) -> Result<(String, IpAddr)> {
    let Some((user, addr)) = target.rsplit_once('@') else {
        bail!("give the host as user@address, e.g. root@100.80.0.3");
    };
    validate_remote_user(user)?;
    let addr = addr.trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = addr.parse().with_context(|| {
        format!(
            "{addr:?} is not an IP address. blackthorn stores addresses, not names, so a \
             changed DNS record cannot redirect a session; use the host's (tailnet) IP"
        )
    })?;
    Ok((user.to_string(), ip))
}

pub fn add(name: &str, target: &str, port: u16, yes: bool) -> Result<()> {
    let mut ctx = Ctx::open()?;
    validate_name("host", name)?;
    if ctx.state.hosts.contains_key(name) {
        bail!("there is already a host named {name:?}");
    }
    let (user, address) = parse_target(target)?;

    let host_keys = keys::scan(address, port)?;
    confirm_fingerprints(name, &host_keys, yes)?;
    keys::generate(name)?;

    ctx.state.hosts.insert(
        name.to_string(),
        Host {
            address,
            port,
            user: user.clone(),
            host_keys,
            block: None,
        },
    );
    ctx.commit()?;

    println!("\nadded host {name} ({user}@{address}, port {port}).");
    println!("\nOn {name}, add this line to ~{user}/.ssh/authorized_keys:\n");
    println!("{}\n", keys::authorized_keys_line(name)?);
    println!("then check it with: sudo thorn host check {name}");
    println!("and give it to a session with: sudo thorn grant <session> {name}");
    Ok(())
}

fn confirm_fingerprints(name: &str, host_keys: &[String], yes: bool) -> Result<()> {
    println!("{name} presents these host keys:");
    for fp in keys::fingerprints(host_keys)? {
        println!("  {fp}");
    }
    println!("compare them with the output of this, run on {name} itself:");
    println!("  for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$f\"; done");
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "not confirmed; run interactively, or pass --yes if you have checked the fingerprints"
        );
    }
    print!("do they match? [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    if !matches!(line.trim(), "y" | "Y" | "yes") {
        bail!("not added");
    }
    Ok(())
}

pub fn rm(name: &str) -> Result<()> {
    let mut ctx = Ctx::open()?;
    ctx.state.host(name)?;
    let mut revoked = Vec::new();
    for (sname, s) in ctx.state.sessions.iter_mut() {
        if s.hosts.remove(name) {
            revoked.push(sname.clone());
        }
    }
    ctx.state.hosts.remove(name);
    ctx.commit()?;
    keys::remove(name)?;
    println!("removed host {name} and its key");
    if !revoked.is_empty() {
        println!("it was revoked from: {}", revoked.join(", "));
    }
    println!("remember to delete the blackthorn line from its authorized_keys");
    Ok(())
}

pub fn ls() -> Result<()> {
    let (_, state) = crate::ctx::read_only()?;
    if state.hosts.is_empty() {
        println!("no hosts; add one with: sudo thorn host add <name> user@address");
        return Ok(());
    }
    let t = now();
    let mut rows = vec![vec![
        "NAME".to_string(),
        "ADDRESS".into(),
        "USER".into(),
        "SESSIONS".into(),
        "STATUS".into(),
    ]];
    for (name, h) in &state.hosts {
        let sessions: Vec<&str> = state
            .sessions
            .iter()
            .filter(|(_, s)| s.hosts.contains(name))
            .map(|(n, _)| n.as_str())
            .collect();
        let status = match &h.block {
            Some(b) if b.active(t) => describe_block(b, t),
            _ => "open".into(),
        };
        let addr = if h.port == 22 {
            h.address.to_string()
        } else {
            format!("{}:{}", h.address, h.port)
        };
        rows.push(vec![
            name.clone(),
            addr,
            h.user.clone(),
            if sessions.is_empty() {
                "-".into()
            } else {
                sessions.join(",")
            },
            status,
        ]);
    }
    print_table(&rows);
    Ok(())
}

pub fn describe_block(b: &Block, now: u64) -> String {
    let mut s = match b.until {
        None => "BLOCKED".to_string(),
        Some(u) => format!(
            "BLOCKED for {}",
            humantime::format_duration(Duration::from_secs(
                u.saturating_sub(now).div_ceil(60) * 60
            ))
        ),
    };
    if let Some(r) = &b.reason {
        s.push_str(&format!(" ({r})"));
    }
    s
}

pub fn block(name: &str, duration: Option<&str>, reason: Option<String>) -> Result<()> {
    let mut ctx = Ctx::open()?;
    ctx.state.host(name)?;
    let until = match duration {
        None => None,
        Some(d) => {
            let d = humantime::parse_duration(d)
                .with_context(|| format!("{d:?} is not a duration; try 30m, 2h or 1d"))?;
            Some(ctx.now + d.as_secs())
        }
    };
    let now = ctx.now;
    let h = ctx.state.hosts.get_mut(name).expect("checked above");
    h.block = Some(Block {
        since: now,
        until,
        reason,
    });
    ctx.commit()?;
    match until {
        None => {
            println!("{name} is blocked for every session until: sudo thorn host unblock {name}")
        }
        Some(u) => println!(
            "{name} is blocked for every session until {} (lifted automatically)",
            humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(u))
        ),
    }
    println!("open connections to it were cut and its key was taken out of every session's agent");
    Ok(())
}

pub fn unblock(name: &str) -> Result<()> {
    let mut ctx = Ctx::open()?;
    ctx.state.host(name)?;
    ctx.state.hosts.get_mut(name).expect("checked above").block = None;
    ctx.commit()?;
    println!("{name} is open again for the sessions it is granted to");
    Ok(())
}

pub fn pubkey(name: &str) -> Result<()> {
    sys::require_root()?;
    let (_, state) = crate::ctx::read_only()?;
    state.host(name)?;
    println!("{}", keys::authorized_keys_line(name)?);
    Ok(())
}

/// Logs in with the host's key the way a session would, as root (so not
/// subject to the session firewall), and runs `true`.
pub fn check(name: &str) -> Result<()> {
    sys::require_root()?;
    let (_, state) = crate::ctx::read_only()?;
    let h = state.host(name)?;
    let known = std::path::PathBuf::from(format!("/run/blackthorn-check-{name}.known_hosts"));
    let lines: String = h
        .host_keys
        .iter()
        .map(|k| format!("blackthorn-{name} {k}\n"))
        .collect();
    sys::write_file(&known, &lines, 0o600, None)?;
    let out = Command::new("ssh")
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
        .arg(paths::key_file(name))
        .args(["-p", &h.port.to_string()])
        .arg(format!("{}@{}", h.user, h.address))
        .arg("true")
        .output();
    let _ = std::fs::remove_file(&known);
    let out = out.context("running ssh")?;
    if !out.status.success() {
        bail!(
            "could not log in to {name}: {}\nis the line from `sudo thorn host pubkey {name}` in its authorized_keys?",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    println!("ok: blackthorn can log in to {name} as {}", h.user);
    if h.block.as_ref().is_some_and(|b| b.active(now())) {
        println!("(note: {name} is currently blocked for sessions)");
    }
    Ok(())
}

pub fn rescan(name: &str, yes: bool) -> Result<()> {
    let mut ctx = Ctx::open()?;
    let h = ctx.state.host(name)?.clone();
    let fresh = keys::scan(h.address, h.port)?;
    if fresh == h.host_keys {
        println!("{name}'s host keys have not changed");
        return Ok(());
    }
    println!("{name}'s host keys CHANGED. If you did not reinstall it or regenerate its keys, stop here.");
    confirm_fingerprints(name, &fresh, yes)?;
    ctx.state.hosts.get_mut(name).expect("exists").host_keys = fresh;
    ctx.commit()?;
    println!("saved the new host keys for {name}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(
            parse_target("root@100.80.0.3").unwrap(),
            ("root".into(), "100.80.0.3".parse().unwrap())
        );
        assert_eq!(
            parse_target("me@[fd7a::1]").unwrap().1,
            "fd7a::1".parse::<IpAddr>().unwrap()
        );
        assert!(parse_target("100.80.0.3").is_err());
        assert!(parse_target("root@nas.local").is_err());
        assert!(parse_target("-oProxyCommand=x@1.2.3.4").is_err());
    }

    #[test]
    fn block_descriptions() {
        assert_eq!(
            describe_block(
                &Block {
                    since: 0,
                    until: None,
                    reason: None
                },
                5
            ),
            "BLOCKED"
        );
        let b = Block {
            since: 0,
            until: Some(3600),
            reason: Some("upgrade".into()),
        };
        assert_eq!(describe_block(&b, 0), "BLOCKED for 1h (upgrade)");
    }
}
