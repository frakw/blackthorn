//! thorn config show / set: the settings the web UI's Settings page changes.
//! thorn update: install the latest release.
//! thorn tailscale: Tailscale on the hub.

use crate::{ops, sys, units};
use anyhow::Result;

pub fn show() -> Result<()> {
    for s in ops::config_show()? {
        let value = if s.value.is_empty() {
            "(empty)"
        } else {
            &s.value
        };
        println!("{} = {value}\n    {}\n", s.key, s.help);
    }
    let peers = ops::tailnet_peers();
    if !peers.is_empty() {
        println!("Devices on this hub's tailnet:");
        for p in peers {
            let ips: Vec<String> = p.ips.iter().map(|a| a.to_string()).collect();
            println!(
                "  {:<20} {:<36} {}{}",
                p.name,
                ips.join(", "),
                if p.online { "online" } else { "offline" },
                if p.hub { " (this hub)" } else { "" }
            );
        }
    }
    Ok(())
}

pub fn update(check: bool) -> Result<()> {
    let info = ops::update_check();
    if let Some(e) = &info.error {
        anyhow::bail!("{e}");
    }
    let latest = info.latest.clone().unwrap_or_default();
    if !info.newer {
        println!(
            "blackthorn v{} is up to date (latest release: {latest})",
            info.current
        );
        return Ok(());
    }
    println!(
        "blackthorn {latest} is out (this hub runs v{}): {}",
        info.current,
        info.url.as_deref().unwrap_or("")
    );
    if check {
        println!("install it with: sudo thorn update");
        return Ok(());
    }
    let tag = ops::update_start()?;
    println!(
        "updating to {tag} in the background; follow it with: journalctl -u {} -f",
        ops::UPDATE_UNIT
    );
    Ok(())
}

pub fn tailscale_status() -> Result<()> {
    let v = ops::tailscale_view();
    if let Some(b) = &v.busy {
        println!(
            "blackthorn is {b} (journalctl -u {} -f)",
            ops::TAILSCALE_UNIT
        );
    }
    if !v.installed {
        println!("Tailscale is not installed: sudo thorn tailscale install");
        return Ok(());
    }
    println!("Tailscale {}", v.version.as_deref().unwrap_or(""));
    println!(
        "state: {}",
        if v.state.is_empty() {
            "not answering"
        } else {
            &v.state
        }
    );
    if let Some(u) = &v.auth_url {
        println!("sign in at: {u}");
    }
    if let Some(n) = &v.name {
        println!("name: {n}");
    }
    if !v.ips.is_empty() {
        let ips: Vec<String> = v.ips.iter().map(|a| a.to_string()).collect();
        println!("addresses: {}", ips.join(", "));
    }
    if let Some(t) = &v.tailnet {
        println!(
            "tailnet: {t} (coordinated by {})",
            v.control.as_deref().unwrap_or("?")
        );
    }
    if v.state == "Running" {
        println!("devices: {} ({} online)", v.peers, v.online);
    }
    match v.web_url() {
        Some(u) => println!("web interface: {u}"),
        None => println!("web interface: off (sudo thorn tailscale web on)"),
    }
    if let Some(c) = v.console_url() {
        println!("admin console: {c}");
    }
    Ok(())
}

pub fn tailscale_install() -> Result<()> {
    println!(
        "{}; follow it with: journalctl -u {} -f",
        ops::tailscale_install()?,
        ops::TAILSCALE_UNIT
    );
    println!("then: sudo thorn tailscale up");
    Ok(())
}

/// Starts the sign-in and prints the link once Tailscale has one.
pub fn tailscale_up() -> Result<()> {
    ops::tailscale_up()?;
    for _ in 0..60 {
        let v = ops::tailscale_view();
        if v.state == "Running" {
            println!("the hub is on the tailnet");
            return Ok(());
        }
        if let Some(u) = v.auth_url {
            println!("sign in at: {u}");
            println!("(thorn tailscale status shows when it is done)");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    println!("no sign-in link yet: journalctl -u {}", ops::TAILSCALE_UNIT);
    Ok(())
}

pub fn set(key: &str, value: &str) -> Result<()> {
    let r = ops::config_set(
        &[(key.to_string(), value.to_string())],
        ops::ssh_client(),
        false,
    )?;
    println!("changed {} and applied it", r.changed.join(", "));
    if let Some(urls) = r.web_moved {
        sys::systemctl(&["try-restart", units::WEB])?;
        println!("the web UI is now on {}", urls.join(" "));
    }
    Ok(())
}
