//! thorn init, apply, firewall, and the internal commands systemd runs.

use crate::config::Config;
use crate::ctx::{self, Ctx};
use crate::state::{now, StateLock};
use crate::{apply, firewall, keys, paths, sys, units};
use anyhow::{bail, Context, Result};
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

pub fn init(claude_from: Option<PathBuf>) -> Result<()> {
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
    if !Path::new(paths::CONFIG_FILE).exists() {
        sys::write_file(
            Path::new(paths::CONFIG_FILE),
            &Config::default_text(),
            0o644,
            None,
        )?;
        println!("wrote {}", paths::CONFIG_FILE);
    }
    let cfg = Config::load(Path::new(paths::CONFIG_FILE))?;

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

    if sys::unit_state(units::WEB) == "active" {
        sys::systemctl(&["restart", units::API, units::WEB])?;
    }

    println!("\nblackthorn is ready. Next:");
    println!("  sudo thorn host add <name> user@<address>   register a machine");
    println!("  sudo thorn new <name>                       create a space on it (Claude)");
    println!("  sudo thorn login <name>-claude              sign it in; it starts right after");
    println!("  sudo thorn web user add <you>               then: sudo thorn web enable");
    Ok(())
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
