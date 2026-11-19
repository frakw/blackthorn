//! thorn init, apply, firewall, and the internal commands systemd runs.

use crate::config::Config;
use crate::ctx::{self, Ctx};
use crate::state::{now, StateLock};
use crate::{apply, firewall, keys, ops, paths, sys, units, web_cmd};
use anyhow::{bail, Context, Result};
use std::io::IsTerminal;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

const NEEDED: &[(&str, &str)] = &[
    ("tmux", "tmux"),
    ("ssh", "openssh-client"),
    ("ssh-agent", "openssh-client"),
    ("ssh-add", "openssh-client"),
    ("ssh-keygen", "openssh-client"),
    ("ssh-keyscan", "openssh-client"),
    ("nft", "nftables"),
    ("useradd", "passwd"),
    ("runuser", "util-linux"),
    ("systemctl", "systemd"),
];

/// What `thorn init` does beyond the basics.
pub struct InitOpts {
    pub claude_from: Option<PathBuf>,
    /// Leave the web UI off on a first install.
    pub no_web: bool,
}

pub fn init(opts: InitOpts) -> Result<()> {
    sys::require_root()?;

    let missing: Vec<&str> = NEEDED
        .iter()
        .filter(|(p, _)| !sys::which(p))
        .map(|(_, pkg)| *pkg)
        .collect();
    if !missing.is_empty() {
        let mut pkgs = missing.clone();
        pkgs.dedup();
        bail!(
            "missing programs; install them first:\n  apt install {}",
            pkgs.join(" ")
        );
    }

    // Put this binary where the units expect it.
    let me = std::env::current_exe()?.canonicalize()?;
    let target = Path::new(paths::THORN_BIN);
    if target.canonicalize().ok().as_deref() != Some(me.as_path()) {
        install_file(&me, target)?;
        println!("installed {}", target.display());
    }

    for (dir, mode) in [
        (paths::CONFIG_DIR, 0o755),
        (paths::KEYS_DIR, 0o700),
        (paths::STATE_DIR, 0o755),
        (paths::SPACES_DIR, 0o755),
        (paths::LAUNCH_DIR, 0o755),
    ] {
        sys::mkdir(Path::new(dir), mode)?;
    }
    // A first install: no config file yet. Later runs (upgrades) leave the
    // config, and whether the web UI is on, as they are.
    let first = !Path::new(paths::CONFIG_FILE).exists();
    let web_on = first && !opts.no_web;
    if first {
        let listen = if web_on { default_listen() } else { vec![] };
        sys::write_file(
            Path::new(paths::CONFIG_FILE),
            &Config::default_text(&listen),
            0o644,
            None,
        )?;
        println!("wrote {}", paths::CONFIG_FILE);
    }
    let cfg = Config::load(Path::new(paths::CONFIG_FILE))?;

    let claude_from = opts.claude_from.or_else(|| {
        if cfg.claude_bin.is_file() {
            None
        } else {
            find_claude()
        }
    });
    if let Some(src) = claude_from {
        let src = src
            .canonicalize()
            .with_context(|| format!("{} not found", src.display()))?;
        install_file(&src, &cfg.claude_bin)?;
        println!(
            "installed Claude Code from {} to {}",
            src.display(),
            cfg.claude_bin.display()
        );
    }
    if !cfg.claude_bin.is_file() {
        println!(
            "warning: {} does not exist. Install Claude Code for your own user, then run:\n  \
             sudo thorn init --claude-from ~/.local/bin/claude",
            cfg.claude_bin.display()
        );
    }

    // The unprivileged user the web UI runs as (created now so the API
    // unit's Group= exists even if the web UI is never turned on).
    if sys::lookup_user(paths::WEB_USER).is_none() {
        sys::create_user(paths::WEB_USER, std::path::Path::new("/nonexistent"))?;
    }

    for (name, text) in units::all() {
        sys::write_file(
            &Path::new(paths::SYSTEMD_DIR).join(name),
            &text,
            0o644,
            None,
        )?;
    }
    sys::systemctl(&["daemon-reload"])?;
    {
        let _lock = StateLock::acquire(Path::new(paths::LOCK_FILE))?;
        let (cfg, state) = ctx::read_only()?;
        apply::everything(&cfg, &state, now())?;
    }
    sys::systemctl(&["enable", "--now", units::FIREWALL, units::TICK_TIMER])?;

    // Who may administer the hub, asked while someone is at the terminal
    // and nobody is listed yet.
    if std::io::stdin().is_terminal() && cfg.inbound.admin_from.is_empty() {
        if let Err(e) = ask_admin_devices() {
            println!("admin devices not set: {e:#}");
        }
    }

    if web_on {
        sys::systemctl(&["enable", "--now", units::API, units::WEB])?;
    } else if sys::unit_state(units::WEB) == "active" {
        sys::systemctl(&["restart", units::API, units::WEB])?;
    }
    let web_active = sys::unit_state(units::WEB) == "active";

    // The first web account, asked for right here when someone is at the
    // terminal (the installer hands init the terminal).
    let mut have_account = web_cmd::has_accounts()?;
    if web_active && !have_account && std::io::stdin().is_terminal() {
        println!("\nCreate your web account (password + authenticator app).");
        have_account = match web_cmd::first_account() {
            Ok(()) => true,
            Err(e) => {
                println!("no account created: {e:#}");
                false
            }
        };
    }

    println!("\nblackthorn is ready.");
    if web_active {
        for url in web_urls(&cfg.web.listen) {
            println!("  web UI: {url}");
        }
        if !have_account {
            println!("  create your login first: sudo thorn web user add <name>");
        }
        if cfg.web.listen.iter().any(|a| a.ip().is_unspecified()) {
            println!(
                "  note: the web UI listens on every address, over plain HTTP. Reach it through\n  \
                 Tailscale or a trusted network, and list your devices in inbound.admin_from\n  \
                 in {} (then: sudo thorn apply).",
                paths::CONFIG_FILE
            );
        }
        println!("  In the web UI: add a machine, create a space on it, sign in to Claude.");
    } else {
        println!("  sudo thorn host add <name> user@<address>   register a machine");
        println!("  sudo thorn new <name>                       create a space on it (Claude)");
        println!("  sudo thorn login <name>-claude              sign it in; it starts right after");
    }
    Ok(())
}

/// Lists the tailnet's devices (and where this SSH session comes from) and
/// lets you pick the ones that may reach the hub's SSH and web UI. Managed
/// machines are shown but cannot be picked: they must never reach the hub.
fn ask_admin_devices() -> Result<()> {
    use std::io::Write;
    let here = ssh_sources();
    let (_, state) = ctx::read_only()?;
    let managed: Vec<IpAddr> = state.hosts.values().map(|h| h.address).collect();
    // (label, address, picked by default)
    let mut choices: Vec<(String, IpAddr, bool)> = Vec::new();
    let mut shown_managed = Vec::new();
    for p in ops::tailnet_peers().into_iter().filter(|p| !p.hub) {
        let Some(ip) = p
            .ips
            .iter()
            .find(|i| i.is_ipv4())
            .or(p.ips.first())
            .copied()
        else {
            continue;
        };
        if p.ips.iter().any(|i| managed.contains(i)) {
            shown_managed.push(format!("{} {ip}", p.name));
            continue;
        }
        let you = p.ips.iter().any(|i| here.contains(i));
        let label = format!(
            "{:<20} {:<16} {}{}",
            p.name,
            ip,
            if p.online { "online" } else { "offline" },
            if you {
                "   <- you are connected from here"
            } else {
                ""
            }
        );
        choices.push((label, ip, you));
    }
    for ip in &here {
        if !choices.iter().any(|c| c.1 == *ip) && !managed.contains(ip) {
            choices.push((
                format!(
                    "{:<20} {ip:<16}    <- you are connected from here",
                    "(this SSH session)"
                ),
                *ip,
                true,
            ));
        }
    }
    if choices.is_empty() {
        return Ok(());
    }
    println!(
        "\nWhich devices may administer this hub (its SSH and web UI)? Everything else is refused."
    );
    for (i, (label, _, _)) in choices.iter().enumerate() {
        println!("  {:>2}) {label}", i + 1);
    }
    for m in &shown_managed {
        println!("   -) {m}   (a managed machine: never allowed)");
    }
    let defaults: Vec<String> = choices
        .iter()
        .enumerate()
        .filter(|(_, c)| c.2)
        .map(|(i, _)| (i + 1).to_string())
        .collect();
    loop {
        print!(
            "Numbers separated by spaces, \"all\", or \"none\" to leave it open [{}]: ",
            if defaults.is_empty() {
                "none".to_string()
            } else {
                defaults.join(" ")
            }
        );
        std::io::stdout().flush()?;
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            return Ok(());
        }
        let line = line.trim();
        let picked: Vec<IpAddr> = match line {
            "" if defaults.is_empty() => Vec::new(),
            "" => choices.iter().filter(|c| c.2).map(|c| c.1).collect(),
            "none" => Vec::new(),
            "all" => choices.iter().map(|c| c.1).collect(),
            _ => {
                let nums: Option<Vec<usize>> = line
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|x| !x.is_empty())
                    .map(|x| {
                        x.parse::<usize>()
                            .ok()
                            .filter(|n| (1..=choices.len()).contains(n))
                    })
                    .collect();
                match nums {
                    Some(n) => n.into_iter().map(|i| choices[i - 1].1).collect(),
                    None => {
                        println!("numbers from 1 to {}, please", choices.len());
                        continue;
                    }
                }
            }
        };
        if picked.is_empty() {
            println!("left open: any device that can reach the hub may try to log in (change it in Settings)");
            return Ok(());
        }
        let value = picked
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        match ops::config_set(
            &[("inbound.admin_from".to_string(), value.clone())],
            here.first().copied(),
            false,
        ) {
            Ok(_) => {
                println!("only these may administer the hub now: {value}");
                return Ok(());
            }
            Err(e) => println!("{e:#}"),
        }
    }
}

/// Addresses of the SSH sessions open to this machine right now.
fn ssh_sources() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = ops::ssh_client().into_iter().collect();
    if let Ok(text) = sys::output("ss", &["-Htn", "state", "established", "( sport = :22 )"]) {
        for ip in parse_ss_peers(&text) {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// The peer addresses in `ss -Htn state established` output.
fn parse_ss_peers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let peer = l.split_whitespace().last()?;
            let (host, _port) = peer.rsplit_once(':')?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let host = host.split('%').next()?;
            let ip: IpAddr = host.parse().ok()?;
            Some(match ip {
                IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                v4 => v4,
            })
        })
        .collect()
}

/// Where a new web UI listens: the hub's tailnet address when Tailscale is
/// up (only your tailnet can reach it), otherwise every address.
fn default_listen() -> Vec<SocketAddr> {
    let tailnet: Vec<SocketAddr> = ops::tailscale_ips()
        .into_iter()
        .filter(|ip| ip.is_ipv4())
        .map(|ip| SocketAddr::new(ip, WEB_PORT))
        .collect();
    if tailnet.is_empty() {
        vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), WEB_PORT)]
    } else {
        tailnet
    }
}

const WEB_PORT: u16 = 7180;

/// Addresses to open in a browser, with "every address" spelled out.
fn web_urls(listen: &[SocketAddr]) -> Vec<String> {
    let mut urls = Vec::new();
    for a in listen {
        if a.ip().is_unspecified() {
            let ips = sys::output("hostname", &["-I"]).unwrap_or_default();
            let ips: Vec<IpAddr> = ips
                .split_whitespace()
                .filter_map(|s| s.parse().ok())
                .filter(|ip: &IpAddr| ip.is_ipv4())
                .collect();
            if ips.is_empty() {
                urls.push(format!("http://<this machine's address>:{}/", a.port()));
            }
            urls.extend(ips.iter().map(|ip| format!("http://{ip}:{}/", a.port())));
        } else {
            urls.push(format!("http://{a}/"));
        }
    }
    urls
}

/// Claude Code installed the usual way, in the home of whoever ran sudo, or
/// root's.
fn find_claude() -> Option<PathBuf> {
    let mut homes = Vec::new();
    if let Ok(u) = std::env::var("SUDO_USER") {
        homes.extend(sys::user_home(&u));
    }
    homes.extend(sys::user_home("root"));
    homes
        .into_iter()
        .map(|h| h.join(".local/bin/claude"))
        .find(|p| p.is_file())
}

fn install_file(src: &Path, dest: &Path) -> Result<()> {
    let tmp = dest.with_extension("thorn-new");
    std::fs::copy(src, &tmp)
        .with_context(|| format!("copying {} to {}", src.display(), tmp.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    sys::chown(&tmp, 0, 0)?;
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

pub fn apply_all() -> Result<()> {
    let ctx = Ctx::open()?;
    apply::firewall_rules(&ctx.cfg, &ctx.state, ctx.now, true)?;
    apply::everything(&ctx.cfg, &ctx.state, ctx.now)?;
    drop(ctx);
    // Picks up a changed listen address.
    sys::systemctl(&["try-restart", units::WEB])?;
    println!("applied");
    Ok(())
}

/// Run by blackthorn-firewall.service at boot, and by hand.
pub fn firewall_apply() -> Result<()> {
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    apply::firewall_rules(&cfg, &state, now(), true)?;
    Ok(())
}

pub fn firewall_show(planned: bool) -> Result<()> {
    sys::require_root()?;
    if planned {
        let (cfg, state) = ctx::read_only()?;
        let ruleset = firewall::render(&apply::plan(&cfg, &state, now()));
        print!("{ruleset}");
        firewall::check(&ruleset)?;
        eprintln!("(nft accepts these rules)");
    } else {
        print!("{}", firewall::show()?);
    }
    Ok(())
}

/// Every minute: lift expired blocks, end expired bridges, and reload the
/// firewall if anything it depends on changed (such as the nameservers in
/// /etc/resolv.conf).
pub fn tick() -> Result<()> {
    let mut ctx = Ctx::open()?;
    let lifted = ctx.state.expire_blocks(ctx.now);
    let ended = ctx.state.expire_bridges(ctx.now);
    if lifted.is_empty() && ended.is_empty() {
        apply::firewall_rules(&ctx.cfg, &ctx.state, ctx.now, false)?;
    } else {
        ctx.commit()?;
        for h in &lifted {
            println!("block lifted: {h}");
        }
        for b in &ended {
            println!("bridge ended: {b}");
        }
    }
    // Notifications go out over the network: not while holding the lock.
    let state = ctx.state.clone();
    drop(ctx);
    crate::notify::tick(&state, &lifted, &ended);
    Ok(())
}

/// ExecStartPost of the agent unit: load the space's keys.
pub fn load_keys(key: &str) -> Result<()> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let Some((name, _)) = state.space_by_key(key) else {
        bail!("no space with key {key}");
    };
    keys::wait_for_socket(key)?;
    let hosts: Vec<&str> = state
        .reachable_hosts(name, now())
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    keys::sync_agent(key, &hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_session_sources() {
        let ss = "0      0      100.80.0.6:22      100.80.0.2:51515\n\
                  0      52     [::ffff:192.168.10.106]:22 [::ffff:192.168.10.5]:40000\n\
                  0      0      [fd7a:115c::6]:22  [fd7a:115c::2]:6000\n";
        assert_eq!(
            parse_ss_peers(ss),
            vec![
                "100.80.0.2".parse::<IpAddr>().unwrap(),
                "192.168.10.5".parse().unwrap(),
                "fd7a:115c::2".parse().unwrap()
            ]
        );
    }
}
