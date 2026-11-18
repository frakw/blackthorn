//! thorn init, thorn status, and the internal commands systemd runs.

use crate::config::Config;
use crate::ctx::{self, Ctx};
use crate::host_cmd::describe_block;
use crate::state::{now, StateLock};
use crate::{apply, firewall, keys, paths, session_cmd, sys, units};
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
        (paths::SESSIONS_DIR, 0o755),
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

    println!("\nblackthorn is ready. Next:");
    println!("  sudo thorn host add <name> user@<address>     register a machine");
    println!("  sudo thorn new <session> --host <name>        create a session");
    println!("  sudo thorn login <session>                    sign it in and start it");
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

pub fn status() -> Result<()> {
    let (cfg, state) = ctx::read_only()?;
    let t = now();
    let fw = if firewall::show().is_ok() {
        "loaded"
    } else {
        "NOT LOADED (sessions are unrestricted!)"
    };
    println!("firewall:    {fw}");
    println!("block timer: {}", sys::unit_state(units::TICK_TIMER));
    let claude = sys::output(
        "timeout",
        &[
            "10",
            cfg.claude_bin.to_str().unwrap_or("claude"),
            "--version",
        ],
    )
    .map(|v| v.trim().to_string())
    .unwrap_or_else(|_| format!("missing ({})", cfg.claude_bin.display()));
    println!("claude:      {claude}");
    println!(
        "egress:      https {}, dns {}",
        if cfg.egress.https_anywhere {
            "anywhere"
        } else {
            "off"
        },
        if cfg.egress.dns.is_empty() {
            "from /etc/resolv.conf".to_string()
        } else {
            format!("{:?}", cfg.egress.dns)
        }
    );
    if let Ok(mem) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(avail) = mem.lines().find(|l| l.starts_with("MemAvailable:")) {
            let kb: u64 = avail
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            println!("memory:      {} MB available", kb / 1024);
        }
    }
    println!();
    session_cmd::ls()?;
    let blocked: Vec<String> = state
        .hosts
        .iter()
        .filter(|(_, h)| h.blocked(t))
        .map(|(n, h)| {
            format!(
                "{n}: {}",
                describe_block(h.block.as_ref().expect("blocked"), t)
            )
        })
        .collect();
    if !blocked.is_empty() {
        println!("\nblocked hosts:");
        for b in blocked {
            println!("  {b}");
        }
    }
    Ok(())
}

pub fn apply_all() -> Result<()> {
    let ctx = Ctx::open()?;
    apply::firewall_rules(&ctx.cfg, &ctx.state, ctx.now, true)?;
    apply::everything(&ctx.cfg, &ctx.state, ctx.now)?;
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

/// Every minute: lift expired blocks, and reload the firewall if anything it
/// depends on changed (such as the nameservers in /etc/resolv.conf).
pub fn tick() -> Result<()> {
    let mut ctx = Ctx::open()?;
    let lifted = ctx.state.expire_blocks(ctx.now);
    if lifted.is_empty() {
        apply::firewall_rules(&ctx.cfg, &ctx.state, ctx.now, false)?;
    } else {
        ctx.commit()?;
        println!("block lifted: {}", lifted.join(", "));
    }
    Ok(())
}

/// ExecStartPost of the agent unit: load the session's keys.
pub fn load_keys(key: &str) -> Result<()> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let Some((_, s)) = state.session_by_key(key) else {
        bail!("no session with key {key}");
    };
    keys::wait_for_socket(key)?;
    let hosts: Vec<&str> = state
        .reachable_hosts(s, now())
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    keys::sync_agent(key, &hosts)
}
