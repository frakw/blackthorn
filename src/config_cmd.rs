//! thorn config show / set: the settings the web UI's Settings page changes.
//! thorn update: install the latest release.

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
