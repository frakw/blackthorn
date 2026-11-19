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
        return Ok(());
    }
    ctx.commit()?;
    for h in lifted {
        println!("block lifted: {h}");
    }
    for b in ended {
        println!("bridge ended: {b}");
    }
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
