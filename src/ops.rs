//! Every operation blackthorn offers, independent of how it is asked for.
//! The CLI and the web API both call these functions, so they offer the same
//! things. Functions that change state open (and lock) the context
//! themselves and never print; they return what happened.

use crate::config::{Config, CLAUDE};
use crate::ctx::{self, Ctx};
use crate::state::{
    now, validate_name, validate_rc_name, Access, Block, Bridge, Host, Mode, Os, Space, State,
};
use crate::{apply, keys, paths, render, sys, units};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

// ---------------------------------------------------------------- views

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overview {
    pub hub: HubView,
    pub spaces: Vec<SpaceView>,
    pub hosts: Vec<HostView>,
    pub bridges: Vec<BridgeView>,
    pub agents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubView {
    pub hostname: String,
    pub firewall_loaded: bool,
    pub timer: String,
    pub claude_version: Option<String>,
    pub https_anywhere: bool,
    pub admin_from: Vec<IpAddr>,
    pub denied_inbound: Vec<IpAddr>,
    pub web_listen: Vec<String>,
    pub memory_available_mb: Option<u64>,
    /// The networks the hub is on, for the map.
    #[serde(default)]
    pub net: NetView,
}

/// The hub's networks: its tailnet (and who coordinates it) and its LAN
/// (and the router that is its way to the internet).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NetView {
    /// The tailnet's coordination server: "Tailscale", or your headscale's
    /// host name. None: not on a tailnet.
    pub control: Option<String>,
    /// The hub's LAN, e.g. "192.168.10.0/24".
    pub lan: Option<String>,
    /// Its default gateway.
    pub router: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceView {
    pub name: String,
    pub host: String,
    pub agent: String,
    pub mode: Mode,
    /// Claude: reachable through Remote Control.
    #[serde(default = "crate::render::yes")]
    pub remote_control: bool,
    pub rc_name: String,
    /// What the Claude app calls its environment: the work folder's name.
    #[serde(default)]
    pub dir: String,
    /// "running", "stopped", "failed", "needs login", ...
    pub state: String,
    pub memory_mb: Option<u64>,
    /// Conversations written to in the last 24 hours (Claude only).
    pub chats_24h: Option<usize>,
    /// Hosts it can reach right now.
    pub reachable: Vec<String>,
    /// The model it last answered with ("Opus 5.5"), Claude only.
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub access: Access,
    /// The login it uses on its machine ("blackthorn", "root").
    #[serde(default)]
    pub login: String,
    /// An admin space on a machine with a read-only login: runs only for a
    /// time, one at a time, not at boot.
    #[serde(default)]
    pub limited: bool,
    /// When it is stopped, while it runs as a limited admin space.
    #[serde(default)]
    pub until: Option<u64>,
    /// Its extra arguments skip permission prompts (auto mode): risky with
    /// admin access.
    #[serde(default)]
    pub unattended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostView {
    pub name: String,
    pub address: IpAddr,
    pub port: u16,
    pub user: String,
    pub os: Os,
    pub spaces: Vec<String>,
    /// The read-only login's user, if it has one.
    #[serde(default)]
    pub readonly: Option<String>,
    pub blocked: bool,
    /// "BLOCKED for 42m (kernel upgrade)" or "open".
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeView {
    pub from: String,
    pub to: String,
    /// The machine `from` gains.
    pub host: String,
    pub until: Option<u64>,
    /// "for 52m" or "until removed".
    pub remaining: String,
}

pub fn overview(with_version: bool) -> Result<Overview> {
    let (cfg, state) = ctx::read_only()?;
    let t = now();
    let hub = HubView {
        hostname: sys::hostname(),
        firewall_loaded: crate::firewall::show().is_ok(),
        timer: sys::unit_state(units::TICK_TIMER),
        claude_version: if with_version {
            claude_version(&cfg)
        } else {
            None
        },
        https_anywhere: cfg.egress.https_anywhere,
        admin_from: cfg.inbound.admin_from.clone(),
        denied_inbound: crate::apply::denied_inbound(&cfg, &state),
        web_listen: cfg.web.listen.iter().map(|a| a.to_string()).collect(),
        memory_available_mb: memory_available_mb(),
        net: net_view(),
    };
    let spaces = state
        .spaces
        .iter()
        .map(|(name, s)| {
            let unit = paths::space_unit(&s.key);
            let state_str = if !logged_in(s) {
                "needs login".to_string()
            } else {
                match sys::unit_state(&unit).as_str() {
                    "active" => "running".to_string(),
                    "inactive" => "stopped".to_string(),
                    other => other.to_string(),
                }
            };
            SpaceView {
                name: name.clone(),
                host: s.host.clone(),
                agent: s.agent.clone(),
                mode: s.mode,
                remote_control: s.remote_control,
                rc_name: s.rc_name.clone(),
                dir: s.dir.clone(),
                state: state_str,
                memory_mb: sys::unit_memory(&unit).map(|b| b / 1_048_576),
                chats_24h: (s.agent == CLAUDE).then(|| recent_chats(&s.key, t)),
                model: (s.agent == CLAUDE)
                    .then(|| last_model(&s.key))
                    .flatten()
                    .map(|m| model_name(&m)),
                reachable: state
                    .reachable_hosts(name, t)
                    .into_iter()
                    .map(|(n, _)| n.to_string())
                    .collect(),
                access: s.access,
                login: state
                    .hosts
                    .get(&s.host)
                    .map(|h| match s.access {
                        Access::Admin => h.user.clone(),
                        Access::Readonly => h.readonly.clone().unwrap_or_default(),
                    })
                    .unwrap_or_default(),
                limited: state.limited(s),
                until: s.until.filter(|u| *u > t),
                unattended: unattended(&cfg.claude_args) || unattended(&s.args),
            }
        })
        .collect();
    let hosts = state
        .hosts
        .iter()
        .map(|(name, h)| HostView {
            name: name.clone(),
            address: h.address,
            port: h.port,
            user: h.user.clone(),
            os: h.os,
            spaces: state
                .spaces_on(name)
                .into_iter()
                .map(String::from)
                .collect(),
            readonly: h.readonly.clone(),
            blocked: h.blocked(t),
            status: match &h.block {
                Some(b) if b.active(t) => describe_block(b, t),
                _ => "open".into(),
            },
        })
        .collect();
    let bridges = state
        .bridges
        .iter()
        .filter(|b| b.active(t))
        .map(|b| BridgeView {
            from: b.from.clone(),
            to: b.to.clone(),
            host: state
                .spaces
                .get(&b.to)
                .map(|s| s.host.clone())
                .unwrap_or_default(),
            until: b.until,
            remaining: describe_until(b.until, t),
        })
        .collect();
    Ok(Overview {
        hub,
        spaces,
        hosts,
        bridges,
        agents: cfg.agent_names(),
    })
}

/// Agent arguments that let it act without asking first.
pub fn unattended(args: &[String]) -> bool {
    args.iter().enumerate().any(|(i, a)| {
        a == "--dangerously-skip-permissions"
            || a == "--permission-mode=bypassPermissions"
            || a == "--permission-mode=auto"
            || (a == "--permission-mode"
                && args
                    .get(i + 1)
                    .is_some_and(|m| m == "bypassPermissions" || m == "auto"))
    })
}

fn net_view() -> NetView {
    let control = if tailscale_ips().is_empty() {
        None
    } else {
        Some(
            sys::output("tailscale", &["debug", "prefs"])
                .ok()
                .and_then(|p| control_name(&p))
                .unwrap_or_else(|| "Tailscale".into()),
        )
    };
    let route = sys::output("ip", &["-4", "route", "show", "default"]).unwrap_or_default();
    let (router, dev) = default_route(&route);
    let lan = dev.and_then(|d| {
        let a = sys::output("ip", &["-o", "-4", "addr", "show", "dev", &d]).ok()?;
        lan_of(&a)
    });
    NetView {
        control,
        lan,
        router,
    }
}

/// "Tailscale" for Tailscale's own server, else the server's host name,
/// from `tailscale debug prefs`.
fn control_name(prefs: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(prefs).ok()?;
    let url = v["ControlURL"].as_str().unwrap_or("");
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split(['/', ':'])
        .next()
        .unwrap_or("");
    Some(if host.is_empty() || host.ends_with("tailscale.com") {
        "Tailscale".into()
    } else {
        host.to_string()
    })
}

/// The gateway and device of `ip -4 route show default`.
fn default_route(out: &str) -> (Option<IpAddr>, Option<String>) {
    let line = out.lines().next().unwrap_or("");
    let w: Vec<&str> = line.split_whitespace().collect();
    let after = |k: &str| w.windows(2).find(|p| p[0] == k).map(|p| p[1].to_string());
    (after("via").and_then(|v| v.parse().ok()), after("dev"))
}

/// "192.168.10.0/24" from `ip -o -4 addr show dev X`.
fn lan_of(out: &str) -> Option<String> {
    let cidr = out.split_whitespace().skip_while(|w| *w != "inet").nth(1)?;
    let (addr, len) = cidr.split_once('/')?;
    let addr: std::net::Ipv4Addr = addr.parse().ok()?;
    let len: u32 = len.parse().ok().filter(|l| *l <= 32)?;
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    let net = std::net::Ipv4Addr::from(u32::from(addr) & mask);
    Some(format!("{net}/{len}"))
}

pub fn claude_version(cfg: &Config) -> Option<String> {
    sys::output("timeout", &["10", cfg.claude_bin.to_str()?, "--version"])
        .ok()
        .map(|v| v.trim().to_string())
}

fn memory_available_mb() -> Option<u64> {
    let mem = std::fs::read_to_string("/proc/meminfo").ok()?;
    let line = mem.lines().find(|l| l.starts_with("MemAvailable:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024)
}

/// Claude Code keeps each conversation in ~/.claude/projects/<dir>/<id>.jsonl.
fn recent_chats(key: &str, now: u64) -> usize {
    let projects = paths::space_home(key).join(".claude/projects");
    let Ok(dirs) = std::fs::read_dir(projects) else {
        return 0;
    };
    let cutoff = UNIX_EPOCH + Duration::from_secs(now.saturating_sub(86_400));
    dirs.flatten()
        .filter_map(|d| std::fs::read_dir(d.path()).ok())
        .flat_map(|f| f.flatten())
        .filter(|f| f.path().extension().is_some_and(|e| e == "jsonl"))
        .filter(|f| {
            f.metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|m| m >= cutoff)
        })
        .count()
}

/// The model a Claude space last answered with, from the end of its newest
/// transcript.
fn last_model(key: &str) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::OpenOptionsExt;
    const TAIL: u64 = 256 * 1024;
    let newest = chat_files(key)
        .into_iter()
        .filter_map(|(_, p)| Some((std::fs::symlink_metadata(&p).ok()?.modified().ok()?, p)))
        .max_by_key(|(m, _)| *m)?
        .1;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(newest)
        .ok()?;
    let len = f.metadata().ok()?.len();
    if len > TAIL {
        f.seek(SeekFrom::Start(len - TAIL)).ok()?;
    }
    let mut buf = Vec::new();
    f.take(TAIL).read_to_end(&mut buf).ok()?;
    String::from_utf8_lossy(&buf)
        .lines()
        .rev()
        .filter(|l| l.contains("\"assistant\"") && l.contains("\"model\""))
        .find_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            let m = v["message"]["model"].as_str()?;
            m.starts_with("claude").then(|| m.to_string())
        })
}

/// "claude-opus-5-5" -> "Opus 5.5", "claude-3-5-sonnet-20241022" ->
/// "Sonnet 3.5"; anything else as it is.
pub fn model_name(id: &str) -> String {
    let Some(rest) = id.strip_prefix("claude-") else {
        return id.to_string();
    };
    let parts: Vec<&str> = rest.split('-').collect();
    let Some(family) = parts
        .iter()
        .find(|p| p.chars().all(|c| c.is_ascii_alphabetic()))
    else {
        return id.to_string();
    };
    let version: Vec<&str> = parts
        .iter()
        .filter(|p| !p.is_empty() && p.len() <= 2 && p.chars().all(|c| c.is_ascii_digit()))
        .copied()
        .collect();
    let mut name: String = family[..1].to_ascii_uppercase();
    name.push_str(&family[1..]);
    if !version.is_empty() {
        name.push(' ');
        name.push_str(&version.join("."));
    }
    name
}

pub fn describe_until(until: Option<u64>, now: u64) -> String {
    match until {
        None => "until removed".into(),
        Some(u) => format!(
            "for {}",
            humantime::format_duration(Duration::from_secs(
                u.saturating_sub(now).div_ceil(60) * 60
            ))
        ),
    }
}

/// "52m", "1h 5m": time left until `u`, in whole minutes.
pub fn describe_left(u: u64, now: u64) -> String {
    humantime::format_duration(Duration::from_secs(u.saturating_sub(now).div_ceil(60) * 60))
        .to_string()
}

pub fn describe_block(b: &Block, now: u64) -> String {
    let mut s = match b.until {
        None => "BLOCKED".to_string(),
        Some(_) => format!("BLOCKED {}", describe_until(b.until, now)),
    };
    if let Some(r) = &b.reason {
        s.push_str(&format!(" ({r})"));
    }
    s
}

pub fn rfc3339(t: u64) -> String {
    humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(t)).to_string()
}

pub fn parse_duration(d: &str) -> Result<u64> {
    Ok(humantime::parse_duration(d)
        .with_context(|| format!("{d:?} is not a duration; try 30m, 2h or 1d"))?
        .as_secs())
}

// ---------------------------------------------------------------- spaces

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewSpace {
    pub host: String,
    /// Default: claude.
    pub agent: Option<String>,
    /// Default: <host>-<agent>.
    pub name: Option<String>,
    #[serde(default)]
    pub single: bool,
    /// Claude: no Remote Control; use it from the hub's terminal only.
    #[serde(default)]
    pub local: bool,
    pub rc_name: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// Default: read-only if the machine has a read-only login, else admin.
    #[serde(default)]
    pub access: Option<Access>,
}

pub fn logged_in(s: &Space) -> bool {
    s.agent != CLAUDE
        || paths::space_home(&s.key)
            .join(".claude/.credentials.json")
            .exists()
}

/// Creates a space. Returns its name. Claude spaces start after `login`;
/// other agents start now.
pub fn space_new(o: NewSpace) -> Result<String> {
    let mut ctx = Ctx::open()?;
    ctx.state.host(&o.host)?;
    let agent = o.agent.unwrap_or_else(|| CLAUDE.to_string());
    if !ctx.cfg.agent_exists(&agent) {
        bail!(
            "no agent named {agent:?}; available: {} (add others under [agents] in {})",
            ctx.cfg.agent_names().join(", "),
            paths::CONFIG_FILE
        );
    }
    let readonly_login = ctx.state.host(&o.host)?.readonly.is_some();
    let access = o.access.unwrap_or(if readonly_login {
        Access::Readonly
    } else {
        Access::Admin
    });
    if access == Access::Readonly && !readonly_login {
        bail!(
            "{} has no read-only login yet; set one up first (thorn host readonly {})",
            o.host,
            o.host
        );
    }
    let name = o.name.unwrap_or_else(|| {
        if access == Access::Admin && readonly_login {
            format!("{}-admin", o.host)
        } else {
            format!("{}-{agent}", o.host)
        }
    });
    validate_name("space", &name)?;
    if ctx.state.spaces.contains_key(&name) {
        bail!("there is already a space named {name:?}; choose another with --name");
    }
    // The Claude app lists Remote Control environments by this name:
    // machine and space ("fig-claude" already says both).
    let rc_name = o
        .rc_name
        .filter(|r| !r.trim().is_empty())
        .unwrap_or_else(|| {
            if name.starts_with(&o.host) {
                name.clone()
            } else {
                format!("{}-{name}", o.host)
            }
        });
    validate_rc_name(&rc_name)?;
    if ctx.state.spaces.values().any(|s| s.rc_name == rc_name) {
        bail!("another space already uses the Remote Control name {rc_name:?}");
    }

    let key = loop {
        let k = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
        let taken = ctx.state.spaces.values().any(|s| s.key == k)
            || sys::lookup_user(&paths::unix_user(&k)).is_some()
            || paths::space_home(&k).exists();
        if !taken {
            break k;
        }
    };

    let home = paths::space_home(&key);
    let ids = sys::create_user(&paths::unix_user(&key), &home)?;
    sys::mkdir(&home, 0o700)?;
    sys::chown(&home, ids.uid, ids.gid)?;
    let workdir = home.join(&rc_name);
    sys::mkdir(&workdir, 0o755)?;
    sys::chown(&workdir, ids.uid, ids.gid)?;
    if agent == CLAUDE {
        sys::write_file(
            &home.join(".claude.json"),
            &render::initial_claude_json(workdir.to_str().context("workdir path")?),
            0o600,
            Some((ids.uid, ids.gid)),
        )?;
    }

    let space = Space {
        key: key.clone(),
        host: o.host,
        agent,
        mode: if o.single { Mode::Single } else { Mode::Server },
        remote_control: !o.local,
        dir: rc_name.clone(),
        rc_name,
        conversation: uuid::Uuid::new_v4().to_string(),
        args: o.args,
        created: ctx.now,
        access,
        until: None,
        title: None,
    };
    let limited = ctx.state.limited(&space);
    let start_now = logged_in(&space) && !limited;
    ctx.state.spaces.insert(name.clone(), space);
    ctx.commit()?;
    drop(ctx);
    if !limited {
        sys::systemctl(&["enable", &paths::space_unit(&key)])?;
    }
    if start_now {
        sys::systemctl(&["start", &paths::space_unit(&key)])?;
    }
    Ok(name)
}

/// Deletes a space. Returns where its files were archived (None if purged).
pub fn space_rm(name: &str, purge: bool) -> Result<Option<PathBuf>> {
    let mut ctx = Ctx::open()?;
    let s = ctx.state.space(name)?.clone();
    let _ = sys::systemctl(&["disable", "--now", &paths::space_unit(&s.key)]);
    let _ = sys::systemctl(&["stop", &paths::agent_unit(&s.key)]);
    login_cancel(&s.key);
    ctx.state.spaces.remove(name);
    ctx.state.bridges.retain(|b| b.from != name && b.to != name);
    ctx.commit()?;
    drop(ctx);

    let home = paths::space_home(&s.key);
    sys::delete_user(&paths::unix_user(&s.key))?;
    let _ = std::fs::remove_file(paths::launch_file(&s.key));
    if purge {
        if home.exists() {
            std::fs::remove_dir_all(&home)
                .with_context(|| format!("removing {}", home.display()))?;
        }
        return Ok(None);
    }
    if !home.exists() {
        return Ok(None);
    }
    // The uid is free again; keep the files, but owned by root, so a future
    // space that gets the same uid cannot read them.
    sys::mkdir(Path::new(paths::ARCHIVE_DIR), 0o700)?;
    let dest = Path::new(paths::ARCHIVE_DIR).join(format!("{name}-{}", s.key));
    sys::run(
        "chown",
        &[
            "-R",
            "--no-dereference",
            "root:root",
            home.to_str().context("path")?,
        ],
    )?;
    std::fs::rename(&home, &dest)?;
    Ok(Some(dest))
}

/// The default Remote Control name of a space on a machine.
pub fn default_rc_name(host: &str, space: &str) -> String {
    if space.starts_with(host) {
        space.to_string()
    } else {
        format!("{host}-{space}")
    }
}

/// How Claude Code names a project's folder under ~/.claude/projects.
fn project_dir_name(path: &Path) -> String {
    path.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

/// Renames a space (`new` may equal `old`), and/or its Remote Control name
/// (`rc_name`; by default it follows the space's name if it was the
/// default). A new Remote Control name moves the work folder, which the
/// Claude app names the environment after, and Claude Code's records of
/// it, so the chats stay. Returns whether the space was restarted.
pub fn space_rename(old: &str, new: &str, rc_name: Option<String>) -> Result<bool> {
    let mut ctx = Ctx::open()?;
    validate_name("space", new)?;
    if new != old && ctx.state.spaces.contains_key(new) {
        bail!("there is already a space named {new:?}");
    }
    let mut s = ctx.state.space(old)?.clone();
    let old_rc = s.rc_name.clone();
    if let Some(rc) = rc_name.filter(|r| !r.trim().is_empty()) {
        s.rc_name = rc.trim().to_string();
    } else if s.rc_name == old || s.rc_name == default_rc_name(&s.host, old) {
        s.rc_name = default_rc_name(&s.host, new);
    }
    validate_rc_name(&s.rc_name)?;
    if ctx
        .state
        .spaces
        .iter()
        .any(|(n, o)| n != old && o.rc_name == s.rc_name)
    {
        bail!(
            "another space already uses the Remote Control name {:?}",
            s.rc_name
        );
    }
    if new == old && s.rc_name == old_rc {
        return Ok(false);
    }
    let unit = paths::space_unit(&s.key);
    let was_running = sys::unit_state(&unit) == "active";
    let move_dir = s.agent == CLAUDE && s.rc_name != old_rc && s.dir != s.rc_name;
    if move_dir {
        if was_running {
            sys::systemctl(&["stop", &unit])?;
        }
        move_workdir(&s, &s.rc_name)?;
        s.dir = s.rc_name.clone();
    }
    ctx.state.spaces.remove(old);
    ctx.state.spaces.insert(new.to_string(), s.clone());
    for b in ctx.state.bridges.iter_mut() {
        if b.from == old {
            b.from = new.to_string();
        }
        if b.to == old {
            b.to = new.to_string();
        }
    }
    ctx.commit()?;
    drop(ctx);
    if move_dir && was_running {
        sys::systemctl(&["start", &unit])?;
        return Ok(true);
    }
    if s.rc_name != old_rc && was_running {
        sys::systemctl(&["restart", &unit])?;
        return Ok(true);
    }
    Ok(false)
}

/// Renames a space's work folder to `dir`, with Claude Code's project
/// folder for it (its chats) and its trust of the folder. Root acts inside
/// the space's home: it only renames entries there, and refuses links.
fn move_workdir(s: &Space, dir: &str) -> Result<()> {
    let home = paths::space_home(&s.key);
    let from = s.workdir();
    let to = home.join(dir);
    let is_dir = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    if std::fs::symlink_metadata(&to).is_ok() {
        bail!("{} already exists in the space's home", to.display());
    }
    if is_dir(&from) {
        std::fs::rename(&from, &to)?;
    } else {
        let ids =
            sys::lookup_user(&paths::unix_user(&s.key)).context("the space user is missing")?;
        sys::mkdir(&to, 0o755)?;
        sys::chown(&to, ids.uid, ids.gid)?;
    }
    let projects = home.join(".claude/projects");
    let (pf, pt) = (
        projects.join(project_dir_name(&from)),
        projects.join(project_dir_name(&to)),
    );
    if is_dir(&projects) && is_dir(&pf) && std::fs::symlink_metadata(&pt).is_err() {
        std::fs::rename(&pf, &pt)?;
    }
    trust_folder(s, &to)
}

/// Marks a folder as trusted in the space's ~/.claude.json, so Claude Code
/// starts there without asking.
fn trust_folder(s: &Space, dir: &Path) -> Result<()> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = paths::space_home(&s.key).join(".claude.json");
    let uid = space_uid(&s.key)?;
    let mut text = String::new();
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        let m = f.metadata()?;
        if !m.is_file() || m.uid() != uid {
            bail!("{} is not the space's own file", path.display());
        }
        f.read_to_string(&mut text)?;
    }
    let mut v: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|_| serde_json::json!({}));
    if !v.is_object() {
        v = serde_json::json!({});
    }
    let key = dir.to_string_lossy().to_string();
    let projects = v
        .as_object_mut()
        .expect("object")
        .entry("projects")
        .or_insert_with(|| serde_json::json!({}));
    if !projects.is_object() {
        *projects = serde_json::json!({});
    }
    let entry = projects
        .as_object_mut()
        .expect("object")
        .entry(key)
        .or_insert_with(|| serde_json::json!({}));
    if !entry.is_object() {
        *entry = serde_json::json!({});
    }
    entry["hasTrustDialogAccepted"] = serde_json::json!(true);
    let gid = sys::lookup_user(&paths::unix_user(&s.key))
        .map(|u| u.gid)
        .unwrap_or(uid);
    sys::write_file(
        &path,
        &serde_json::to_string_pretty(&v)?,
        0o600,
        Some((uid, gid)),
    )
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Start,
    Stop,
    Restart,
}

impl Action {
    pub fn done(self) -> &'static str {
        match self {
            Action::Start => "started",
            Action::Stop => "stopped",
            Action::Restart => "restarted",
        }
    }
}

/// How long an admin space runs when no time is given (signing in, or
/// `thorn start` without --for), and the longest it may.
pub const ADMIN_DEFAULT: u64 = 3600;
pub const ADMIN_MAX: u64 = 86_400;

/// Starts, stops or restarts spaces (all of them if `names` is empty).
/// Returns one line per space. An admin space on a machine with a
/// read-only login starts only with `admin_for` (seconds): it runs that
/// long. Over the web that takes an authenticator code (SpaceStartFor), so
/// the plain web Start passes None.
pub fn space_control(
    action: Action,
    names: &[String],
    admin_for: Option<u64>,
) -> Result<Vec<String>> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let targets: Vec<(String, Space)> = if names.is_empty() {
        state
            .spaces
            .iter()
            .map(|(n, s)| (n.clone(), s.clone()))
            .collect()
    } else {
        names
            .iter()
            .map(|n| state.space(n).map(|s| (n.clone(), s.clone())))
            .collect::<Result<_>>()?
    };
    let all = names.is_empty();
    let mut out = Vec::new();
    for (name, s) in targets {
        if action != Action::Stop && !logged_in(&s) {
            out.push(format!("{name}: not signed in yet (thorn login {name})"));
            continue;
        }
        if action == Action::Stop {
            sys::systemctl(&["stop", &paths::space_unit(&s.key)])?;
            out.push(format!("{name}: stopped"));
            continue;
        }
        // `--all` leaves limited admin spaces alone rather than failing.
        if all && state.limited(&s) && admin_for.is_none() {
            out.push(format!(
                "{name}: admin space, not started (start it on its own, for a time)"
            ));
            continue;
        }
        match start_unit(&name, action == Action::Restart, admin_for)? {
            Some(until) => out.push(format!(
                "{name}: {} as admin until {} UTC",
                action.done(),
                rfc3339(until)
            )),
            None => out.push(format!("{name}: {}", action.done())),
        }
    }
    Ok(out)
}

/// Starts (or restarts) a space. A limited admin space (its machine has a
/// read-only login) needs `admin_for`, unless it is running and only
/// restarted (then it keeps its time), and may not run next to another
/// admin space on the same machine. Returns until when it runs as admin.
pub fn start_unit(name: &str, restart: bool, admin_for: Option<u64>) -> Result<Option<u64>> {
    let mut ctx = Ctx::open()?;
    let s = ctx.state.space(name)?.clone();
    let unit = paths::space_unit(&s.key);
    let running = sys::unit_state(&unit) == "active";
    if !ctx.state.limited(&s) {
        drop(ctx);
        sys::systemctl(&[if restart { "restart" } else { "start" }, &unit])?;
        return Ok(None);
    }
    if running && (restart || admin_for.is_none()) {
        drop(ctx);
        if restart {
            sys::systemctl(&["restart", &unit])?;
        }
        return Ok(s.until);
    }
    let Some(secs) = admin_for else {
        bail!(
            "{name} has admin access to {}, which has a read-only login: start it for a limited \
             time (thorn start {name} --for 1h; on the web, Start for…)",
            s.host
        );
    };
    if secs == 0 || secs > ADMIN_MAX {
        bail!("an admin space runs for 1 minute to 1 day at a time");
    }
    if let Some((other, _)) = ctx.state.spaces.iter().find(|(n, o)| {
        *n != name
            && o.host == s.host
            && o.access == Access::Admin
            && sys::unit_state(&paths::space_unit(&o.key)) == "active"
    }) {
        bail!(
            "{other} is already working on {} as admin; stop it first (one admin space per machine at a time)",
            s.host
        );
    }
    let until = ctx.now + secs;
    ctx.state.spaces.get_mut(name).expect("checked").until = Some(until);
    ctx.commit()?;
    drop(ctx);
    sys::systemctl(&[if running { "restart" } else { "start" }, &unit])?;
    Ok(Some(until))
}

/// After signing in: start the space, unless it is a limited admin space
/// (those start only when you say for how long). Returns whether it started.
pub fn start_after_login(name: &str) -> Result<bool> {
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?;
    if state.limited(s) {
        return Ok(false);
    }
    sys::systemctl(&["restart", &paths::space_unit(&s.key)])?;
    Ok(true)
}

/// Stops admin spaces whose time is up. Returns their names.
pub fn expire_admin(ctx: &mut Ctx) -> Vec<String> {
    let mut ended = Vec::new();
    for (name, s) in ctx.state.spaces.iter_mut() {
        if s.until.is_some_and(|u| u <= ctx.now) {
            s.until = None;
            if sys::unit_state(&paths::space_unit(&s.key)) == "active" {
                let _ = sys::systemctl(&["stop", &paths::space_unit(&s.key)]);
                ended.push(name.clone());
            }
        }
    }
    ended
}

/// Makes a space admin or read-only on its machine. Read-only needs the
/// machine's read-only login. A running space restarts (its open SSH
/// connections close); one that becomes a limited admin space stops
/// instead, and starts again only for a time. Returns what happened.
pub fn space_access(name: &str, access: Access) -> Result<String> {
    let mut ctx = Ctx::open()?;
    let s = ctx.state.space(name)?.clone();
    let h = ctx.state.host(&s.host)?.clone();
    if access == Access::Readonly && h.readonly.is_none() {
        bail!(
            "{} has no read-only login yet; set one up first (thorn host readonly {})",
            s.host,
            s.host
        );
    }
    if s.access == access {
        return Ok(format!("{name} is already {access}"));
    }
    let sp = ctx.state.spaces.get_mut(name).expect("checked");
    sp.access = access;
    sp.until = None;
    let limited = ctx.state.limited(&ctx.state.spaces[name]);
    ctx.commit()?;
    drop(ctx);
    let unit = paths::space_unit(&s.key);
    let running = sys::unit_state(&unit) == "active";
    if limited {
        sys::systemctl(&["disable", &unit])?;
        if running {
            sys::systemctl(&["stop", &unit])?;
        }
        return Ok(format!(
            "{name} is now admin on {}; it stopped: start it for a limited time when you need it",
            s.host
        ));
    }
    sys::systemctl(&["enable", &unit])?;
    if running {
        sys::systemctl(&["restart", &unit])?;
        return Ok(format!(
            "{name} is now {access} on {}; it restarted",
            s.host
        ));
    }
    Ok(format!("{name} is now {access} on {}", s.host))
}

/// The text on the space's terminal right now.
pub fn space_screen(name: &str) -> Result<String> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?;
    let sock = paths::tmux_socket(&s.key);
    if !sock.exists() {
        bail!("space {name} is not running");
    }
    capture(&sock)
}

fn capture(sock: &Path) -> Result<String> {
    sys::output(
        "tmux",
        &[
            "-S",
            sock.to_str().context("socket path")?,
            "capture-pane",
            "-p",
            "-J",
            "-t",
            "main",
        ],
    )
}

/// Keys the web UI may send to a space's terminal.
pub const SPECIAL_KEYS: &[&str] = &["Enter", "Escape", "C-c", "Up", "Down", "Tab", "BSpace"];

/// Types text (followed by Enter if `enter`), or presses one special key.
pub fn space_send(name: &str, text: Option<&str>, key: Option<&str>, enter: bool) -> Result<()> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?;
    let sock = paths::tmux_socket(&s.key);
    if !sock.exists() {
        bail!("space {name} is not running");
    }
    send_keys(&sock, text, key, enter)
}

fn send_keys(sock: &Path, text: Option<&str>, key: Option<&str>, enter: bool) -> Result<()> {
    let sock = sock.to_str().context("socket path")?;
    if let Some(t) = text {
        if t.len() > 4096 || t.chars().any(|c| c.is_control()) {
            bail!("text must be one line without control characters");
        }
        if !t.is_empty() {
            sys::run("tmux", &["-S", sock, "send-keys", "-t", "main", "-l", t])?;
        }
    }
    if let Some(k) = key {
        if !SPECIAL_KEYS.contains(&k) {
            bail!("key {k:?} is not one of {}", SPECIAL_KEYS.join(", "));
        }
        sys::run("tmux", &["-S", sock, "send-keys", "-t", "main", k])?;
    }
    if enter {
        sys::run("tmux", &["-S", sock, "send-keys", "-t", "main", "Enter"])?;
    }
    Ok(())
}

// ---------------------------------------------------------------- chats

/// One Claude conversation of a space, from its transcript on the hub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chat {
    pub id: String,
    pub title: String,
    /// Unix seconds of the last write.
    pub modified: u64,
    pub kb: u64,
    /// The one conversation a single-mode or local-only space resumes.
    pub main: bool,
    /// Running in a window of its own (started from the hub in a Remote
    /// Control space).
    #[serde(default)]
    pub window: bool,
}

/// Transcripts: ~/.claude/projects/<dir>/<uuid>.jsonl, real files and
/// directories only (the space user owns these; root never follows a link
/// it may have planted).
pub(crate) fn chat_files(key: &str) -> Vec<(String, PathBuf)> {
    let projects = paths::space_home(key).join(".claude/projects");
    let Ok(dirs) = std::fs::read_dir(projects) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for d in dirs.flatten() {
        if !d.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(files) = std::fs::read_dir(d.path()) else {
            continue;
        };
        for f in files.flatten() {
            let p = f.path();
            if !f.file_type().is_ok_and(|t| t.is_file())
                || !p.extension().is_some_and(|e| e == "jsonl")
            {
                continue;
            }
            if let Some(id) = p
                .file_stem()
                .and_then(|s| s.to_str())
                .filter(|s| uuid::Uuid::parse_str(s).is_ok())
            {
                out.push((id.to_string(), p));
            }
        }
    }
    out
}

/// A chat's name, as Claude Code shows it: the name you gave it, else the
/// title Claude made up, else its first message.
pub fn chat_title(transcript: &str) -> Option<String> {
    let mut custom: Option<String> = None;
    let mut ai: Option<String> = None;
    let mut summary: Option<String> = None;
    let mut first: Option<String> = None;
    for line in transcript.lines() {
        let interesting = line.contains("\"custom-title\"")
            || line.contains("\"ai-title\"")
            || line.contains("\"summary\"")
            || (first.is_none() && line.contains("\"user\""));
        if !interesting {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let text = |k: &str| {
            v[k].as_str()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        };
        match v["type"].as_str() {
            // The last one wins; an empty one clears the name.
            Some("custom-title") => custom = text("customTitle"),
            Some("ai-title") => ai = text("aiTitle"),
            Some("summary") => summary = text("summary"),
            Some("user") if first.is_none() && v["isMeta"].as_bool() != Some(true) => {
                first = user_text(&v["message"]["content"]);
            }
            _ => {}
        }
    }
    let t = custom.or(ai).or(summary).or(first)?;
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    Some(if t.chars().count() > 80 {
        let mut s: String = t.chars().take(79).collect();
        s.push('…');
        s
    } else {
        t
    })
}

/// A transcript's text; of a big one only the start (its first message)
/// and the end (its latest name), which is where titles are.
fn head_and_tail(path: &Path, len: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    const PART: u64 = 1 << 20;
    let Ok(mut f) = std::fs::File::open(path) else {
        return String::new();
    };
    let mut buf = Vec::new();
    if len <= 4 * PART {
        let _ = f.read_to_end(&mut buf);
    } else {
        let _ = (&mut f).take(PART).read_to_end(&mut buf);
        buf.push(b'\n');
        if f.seek(SeekFrom::Start(len - PART)).is_ok() {
            let _ = f.take(PART).read_to_end(&mut buf);
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn user_text(c: &serde_json::Value) -> Option<String> {
    let t = match c {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) => a
            .iter()
            .find(|x| x["type"] == "text")
            .and_then(|x| x["text"].as_str())?
            .to_string(),
        _ => return None,
    };
    let t = t.trim();
    // Commands and other tool-made messages start with a tag.
    (!t.is_empty() && !t.starts_with('<')).then(|| t.to_string())
}

fn space_uid(key: &str) -> Result<u32> {
    Ok(sys::lookup_user(&paths::unix_user(key))
        .context("the space user is missing")?
        .uid)
}

fn main_conversation(s: &Space) -> Option<&str> {
    (s.agent == CLAUDE && (s.mode == Mode::Single || !s.remote_control))
        .then_some(s.conversation.as_str())
}

pub fn chat_list(name: &str) -> Result<Vec<Chat>> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?;
    if s.agent != CLAUDE {
        bail!(
            "space {name} runs {}; only Claude chats are listed",
            s.agent
        );
    }
    let main = main_conversation(s);
    let windows = chat_windows(&s.key);
    let mut chats: Vec<Chat> = chat_files(&s.key)
        .into_iter()
        .filter_map(|(id, p)| {
            let meta = std::fs::symlink_metadata(&p).ok()?;
            let modified = meta
                .modified()
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_secs();
            let text = head_and_tail(&p, meta.len());
            Some(Chat {
                title: chat_title(&text).unwrap_or_else(|| "(no messages yet)".into()),
                main: main == Some(id.as_str()),
                window: windows.iter().any(|w| id.starts_with(w.as_str())),
                id,
                modified,
                kb: meta.len().div_ceil(1024),
            })
        })
        .collect();
    chats.sort_by_key(|c| std::cmp::Reverse(c.modified));
    chats.truncate(200);
    Ok(chats)
}

/// A chat by its id, or a unique start of it (at least 4 characters).
fn find_chat(key: &str, id: &str) -> Result<(String, PathBuf)> {
    let id = id.trim().to_ascii_lowercase();
    if id.len() < 4 {
        bail!("give at least the first 4 characters of the chat id");
    }
    let mut found: Vec<(String, PathBuf)> = chat_files(key)
        .into_iter()
        .filter(|(i, _)| i.starts_with(&id))
        .collect();
    match found.len() {
        0 => bail!("no chat {id} in this space (thorn chat ls lists them)"),
        1 => Ok(found.remove(0)),
        _ => bail!("{id} matches several chats; give more of its id"),
    }
}

/// Opens a transcript to append to, refusing links and files the space
/// user does not own.
fn open_transcript(path: &Path, uid: u32) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != uid {
        bail!("{} is not the space's own transcript", path.display());
    }
    Ok(f)
}

/// Names a chat the way Claude Code's /rename does: a custom-title line at
/// the end of its transcript, which Claude Code picks up.
pub fn chat_rename(name: &str, id: &str, title: &str) -> Result<String> {
    use std::io::Write as _;
    sys::require_root()?;
    let title = title.trim();
    if title.is_empty() || title.chars().count() > 100 || title.chars().any(char::is_control) {
        bail!("a chat name is 1 to 100 characters on one line");
    }
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?;
    let (id, path) = find_chat(&s.key, id)?;
    let mut f = open_transcript(&path, space_uid(&s.key)?)?;
    let line = serde_json::json!({ "type": "custom-title", "customTitle": title, "sessionId": id });
    f.write_all(format!("{line}\n").as_bytes())?;
    Ok(id)
}

/// Deletes a chat's transcript (and its subagent files) from the hub.
pub fn chat_rm(name: &str, id: &str) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?;
    let (id, path) = find_chat(&s.key, id)?;
    if main_conversation(s) == Some(id.as_str()) {
        bail!("this is the conversation space {name} runs; delete the space instead");
    }
    let meta = std::fs::symlink_metadata(&path)?;
    if !meta.is_file() || meta.uid() != space_uid(&s.key)? {
        bail!("{} is not the space's own transcript", path.display());
    }
    let recent = meta
        .modified()
        .ok()
        .and_then(|m| m.elapsed().ok())
        .is_some_and(|e| e < Duration::from_secs(600));
    if recent && sys::unit_state(&paths::space_unit(&s.key)) == "active" {
        bail!("this chat was in use in the last 10 minutes; stop the space first, or wait");
    }
    std::fs::remove_file(&path)?;
    let extra = path.with_extension("");
    if std::fs::symlink_metadata(&extra).is_ok_and(|m| m.is_dir()) {
        std::fs::remove_dir_all(&extra)?;
    }
    Ok(id)
}

/// What `chat_open` did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatOpened {
    pub id: String,
    /// The space was running and was restarted into the chat.
    pub restarted: bool,
    /// It runs in a window of its own (a Remote Control space).
    #[serde(default)]
    pub window: bool,
}

/// The first 8 characters of the chats running in windows of their own.
fn chat_windows(key: &str) -> Vec<String> {
    let sock = paths::tmux_socket(key);
    let Some(sock) = sock.to_str().filter(|_| sock.exists()) else {
        return Vec::new();
    };
    sys::output(
        "tmux",
        &["-S", sock, "list-windows", "-F", "#{window_name}"],
    )
    .unwrap_or_default()
    .lines()
    .filter_map(|l| l.strip_prefix("chat-"))
    .map(String::from)
    .collect()
}

/// A Remote Control space: a new chat (or an earlier one) in a window of
/// its own next to the Remote Control server, itself on Remote Control,
/// so it shows in the Claude app. It runs until it is closed or the space
/// stops.
fn open_window(
    name: &str,
    s: &Space,
    cfg: &Config,
    id: Option<&str>,
    title: Option<&str>,
) -> Result<ChatOpened> {
    let sock = paths::tmux_socket(&s.key);
    if !sock.exists() || sys::unit_state(&paths::space_unit(&s.key)) != "active" {
        bail!("space {name} is not running; start it first");
    }
    let (id, resume) = match id {
        None => (uuid::Uuid::new_v4().to_string(), false),
        Some(i) => {
            let (id, path) = find_chat(&s.key, i)?;
            let recent = std::fs::symlink_metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| m.elapsed().ok())
                .is_some_and(|e| e < Duration::from_secs(600));
            if recent {
                bail!("this chat was in use in the last 10 minutes; continue it in the Claude app");
            }
            (id, true)
        }
    };
    if chat_windows(&s.key)
        .iter()
        .any(|w| id.starts_with(w.as_str()))
    {
        bail!("this chat is already running");
    }
    let l = render::launch(name, s, cfg);
    let window = format!("chat-{}", &id[..8]);
    let home = paths::space_home(&s.key);
    let workdir = s.workdir();
    let env_home = format!("HOME={}", home.display());
    let env_agent = format!("SSH_AUTH_SOCK={}", paths::agent_socket(&s.key).display());
    let mut args: Vec<&str> = vec![
        "-S",
        sock.to_str().context("socket path")?,
        "new-window",
        "-d",
        "-n",
        &window,
        "-c",
        workdir.to_str().context("work path")?,
        "-e",
        &env_home,
        "-e",
        &env_agent,
        "-e",
        "DISABLE_AUTOUPDATER=1",
        "--",
        &l.bin,
        if resume { "--resume" } else { "--session-id" },
        &id,
        "--remote-control",
        &l.rc_name,
    ];
    if let (false, Some(t)) = (resume, title) {
        args.extend(["--name", t]);
    }
    args.extend(l.args.iter().map(String::as_str));
    sys::run("tmux", &args)?;
    Ok(ChatOpened {
        id,
        restarted: false,
        window: true,
    })
}

/// Makes a one-conversation space (single mode, or without Remote Control)
/// run a new conversation (`id` None) or an earlier one. The chat it ran
/// before stays in the list. With Remote Control in server mode there is
/// nothing to switch: new chats are started from the Claude app.
pub fn chat_open(name: &str, id: Option<&str>, title: Option<&str>) -> Result<ChatOpened> {
    let title = title.map(str::trim).filter(|t| !t.is_empty());
    if let Some(t) = title {
        if t.chars().count() > 100 || t.chars().any(char::is_control) {
            bail!("a chat name is 1 to 100 characters on one line");
        }
    }
    let title = title.filter(|_| id.is_none());
    let mut ctx = Ctx::open()?;
    let s = ctx.state.space(name)?.clone();
    if s.agent != CLAUDE {
        bail!(
            "space {name} runs {}; only Claude spaces have chats",
            s.agent
        );
    }
    if main_conversation(&s).is_none() {
        let cfg = ctx.cfg.clone();
        drop(ctx);
        return open_window(name, &s, &cfg, id, title);
    }
    let id = match id {
        None => uuid::Uuid::new_v4().to_string(),
        Some(i) => find_chat(&s.key, i)?.0,
    };
    if id == s.conversation {
        return Ok(ChatOpened {
            id,
            restarted: false,
            window: false,
        });
    }
    let sp = ctx.state.spaces.get_mut(name).expect("checked");
    sp.conversation = id.clone();
    sp.title = title.map(String::from);
    ctx.commit()?;
    drop(ctx);
    let unit = paths::space_unit(&s.key);
    let restarted = sys::unit_state(&unit) == "active";
    if restarted {
        sys::systemctl(&["restart", &unit])?;
    }
    Ok(ChatOpened {
        id,
        restarted,
        window: false,
    })
}

/// Turns Remote Control on or off for a Claude space. Returns whether the
/// space was restarted for it.
pub fn space_set_remote(name: &str, on: bool) -> Result<bool> {
    let mut ctx = Ctx::open()?;
    let s = ctx
        .state
        .spaces
        .get_mut(name)
        .with_context(|| format!("no space named {name:?} (thorn ls lists them)"))?;
    if s.agent != CLAUDE {
        bail!("only Claude spaces have Remote Control");
    }
    if s.remote_control == on {
        return Ok(false);
    }
    s.remote_control = on;
    let unit = paths::space_unit(&s.key);
    ctx.commit()?;
    drop(ctx);
    if sys::unit_state(&unit) == "active" {
        sys::systemctl(&["restart", &unit])?;
        return Ok(true);
    }
    Ok(false)
}

// ---------------------------------------------------------------- updates

pub const RELEASES: &str = "https://github.com/frakw/blackthorn/releases";
pub const UPDATE_UNIT: &str = "blackthorn-update.service";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub current: String,
    pub latest: Option<String>,
    pub newer: bool,
    /// The release page of `latest`.
    pub url: Option<String>,
    pub error: Option<String>,
    /// An update is running right now.
    pub running: bool,
}

/// "v0.4.1" -> (0, 4, 1). Pre-releases and anything else: None.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().strip_prefix('v').unwrap_or(v.trim()).split('.');
    let mut n = || -> Option<u64> {
        let p = it.next()?;
        (!p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
            .then(|| p.parse().ok())
            .flatten()
    };
    let v = (n()?, n()?, n()?);
    it.next().is_none().then_some(v)
}

/// The tag GitHub redirects releases/latest to.
fn parse_release_tag(redirect: &str) -> Option<String> {
    let tag = redirect.trim().rsplit_once("/releases/tag/")?.1;
    (tag.starts_with('v') && parse_version(tag).is_some()).then(|| tag.to_string())
}

pub fn latest_release() -> Result<String> {
    let out = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "15",
            "--proto",
            "=https",
            "-o",
            "/dev/null",
            "-w",
            "%{redirect_url}",
            &format!("{RELEASES}/latest"),
        ])
        .output()
        .context("running curl")?;
    if !out.status.success() {
        bail!(
            "could not reach GitHub: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    parse_release_tag(&String::from_utf8_lossy(&out.stdout))
        .context("GitHub did not name a latest release")
}

pub fn update_check() -> UpdateInfo {
    let current = env!("CARGO_PKG_VERSION").to_string();
    let running = matches!(
        sys::unit_state(UPDATE_UNIT).as_str(),
        "active" | "activating"
    );
    match latest_release() {
        Ok(tag) => UpdateInfo {
            newer: parse_version(&tag) > parse_version(&current),
            url: Some(format!("{RELEASES}/tag/{tag}")),
            latest: Some(tag),
            current,
            error: None,
            running,
        },
        Err(e) => UpdateInfo {
            current,
            error: Some(format!("{e:#}")),
            running,
            ..Default::default()
        },
    }
}

/// Starts the installer of the latest release in its own systemd unit (it
/// restarts the API and the web UI as it goes). Returns the tag.
pub fn update_start() -> Result<String> {
    sys::require_root()?;
    let info = update_check();
    if info.running {
        bail!("an update is already running (journalctl -u {UPDATE_UNIT})");
    }
    if let Some(e) = info.error {
        bail!(e);
    }
    let tag = info.latest.context("no release found")?;
    if !info.newer {
        bail!("already at the latest release ({tag})");
    }
    // `tag` passed parse_version: v and digits and dots only.
    let script = format!(
        "set -e; f=$(mktemp); trap 'rm -f \"$f\"' EXIT; \
         curl -fsSL --proto '=https' -o \"$f\" {RELEASES}/download/{tag}/install.sh; \
         sh \"$f\" --version {tag} --no-claude </dev/null"
    );
    sys::run(
        "systemd-run",
        &[
            "--unit",
            UPDATE_UNIT,
            "--collect",
            "--quiet",
            "--description",
            "blackthorn: update",
            "/bin/sh",
            "-c",
            &script,
        ],
    )?;
    Ok(tag)
}

// ---------------------------------------------------------------- tailnet

/// A device on the hub's tailnet, from `tailscale status`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Peer {
    pub name: String,
    pub ips: Vec<IpAddr>,
    pub online: bool,
    pub os: String,
    /// The hub itself.
    pub hub: bool,
}

pub fn tailnet_peers() -> Vec<Peer> {
    let Ok(out) = Command::new("tailscale")
        .args(["status", "--json"])
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    parse_tailscale_status(&String::from_utf8_lossy(&out.stdout))
}

fn parse_tailscale_status(s: &str) -> Vec<Peer> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(s) else {
        return Vec::new();
    };
    let peer = |p: &serde_json::Value, hub: bool| -> Option<Peer> {
        let name = p["HostName"]
            .as_str()
            .filter(|n| !n.is_empty())
            .or_else(|| p["DNSName"].as_str()?.split('.').next())?
            .to_string();
        let ips: Vec<IpAddr> = p["TailscaleIPs"]
            .as_array()?
            .iter()
            .filter_map(|x| x.as_str()?.parse().ok())
            .collect();
        Some(Peer {
            name,
            ips,
            online: hub || p["Online"].as_bool().unwrap_or(false),
            os: p["OS"].as_str().unwrap_or("").to_string(),
            hub,
        })
    };
    let mut out: Vec<Peer> = v["Peer"]
        .as_object()
        .map(|m| m.values().filter_map(|p| peer(p, false)).collect())
        .unwrap_or_default();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    if let Some(me) = peer(&v["Self"], true) {
        out.insert(0, me);
    }
    out
}

// ---------------------------------------------------------------- sign-in

/// Starts `claude auth login` for a space in the background and returns the
/// sign-in link it prints. Finish with `login_finish`.
pub fn login_start(name: &str) -> Result<String> {
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    let s = state.space(name)?.clone();
    if s.agent != CLAUDE {
        bail!(
            "space {name} runs {}, which signs in on its own terminal",
            s.agent
        );
    }
    login_cancel(&s.key);
    let user = paths::unix_user(&s.key);
    let ids = sys::lookup_user(&user).with_context(|| format!("user {user} is missing"))?;
    let sock = paths::login_socket(&s.key);
    let dir = sock.parent().expect("socket has a directory");
    sys::mkdir(Path::new("/run/blackthorn-login"), 0o755)?;
    sys::mkdir(dir, 0o700)?;
    sys::chown(dir, ids.uid, ids.gid)?;
    let home = paths::space_home(&s.key);
    let status = Command::new("runuser")
        .args(["-u", &user, "--", "env"])
        .arg(format!("HOME={}", home.display()))
        .arg("DISABLE_AUTOUPDATER=1")
        .arg("tmux")
        .arg("-S")
        .arg(&sock)
        .args(["new-session", "-d", "-s", "main", "-x", "500", "-y", "50"])
        .arg(&cfg.claude_bin)
        .args(["auth", "login", "--claudeai"])
        .current_dir(s.workdir())
        .status()
        .context("starting claude auth login")?;
    if !status.success() {
        bail!("could not start claude auth login");
    }
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(500));
        let screen = capture(&sock).unwrap_or_default();
        if let Some(url) = find_login_url(&screen) {
            return Ok(url);
        }
    }
    let screen = capture(&sock).unwrap_or_default();
    login_cancel(&s.key);
    bail!("claude did not print a sign-in link:\n{}", screen.trim())
}

pub fn find_login_url(screen: &str) -> Option<String> {
    screen
        .split_whitespace()
        .find(|w| w.starts_with("https://") && w.contains("oauth"))
        .map(|w| w.to_string())
}

/// Gives the code from the sign-in page to the waiting `claude auth login`,
/// then starts the space.
pub fn login_finish(name: &str, code: &str) -> Result<()> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?.clone();
    let sock = paths::login_socket(&s.key);
    if !sock.exists() {
        bail!("no sign-in is in progress for {name}; start one first");
    }
    let code = code.trim();
    if code.is_empty() || code.len() > 512 || !code.chars().all(|c| c.is_ascii_graphic()) {
        bail!("that does not look like a sign-in code");
    }
    send_keys(&sock, Some(code), None, true)?;
    let creds = paths::space_home(&s.key).join(".claude/.credentials.json");
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(500));
        if creds.exists() {
            login_cancel(&s.key);
            start_after_login(name)?;
            return Ok(());
        }
    }
    let screen = capture(&sock).unwrap_or_default();
    bail!("sign-in did not complete; claude says:\n{}", screen.trim())
}

/// Ends a sign-in that is in progress, if any.
pub fn login_cancel(key: &str) {
    let sock = paths::login_socket(key);
    if sock.exists() {
        let _ = Command::new("tmux")
            .arg("-S")
            .arg(&sock)
            .arg("kill-server")
            .output();
    }
    if let Some(dir) = sock.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

// ---------------------------------------------------------------- bridges

/// Lets space `from` reach the machine of space `to`, for `secs` seconds
/// (None: until removed). Replaces an existing bridge between the two.
pub fn bridge_add(from: &str, to: &str, secs: Option<u64>) -> Result<Bridge> {
    let mut ctx = Ctx::open()?;
    let f = ctx.state.space(from)?.clone();
    let t = ctx.state.space(to)?.clone();
    if from == to || f.host == t.host {
        bail!("{from} already works on {}", t.host);
    }
    let b = Bridge {
        from: from.into(),
        to: to.into(),
        since: ctx.now,
        until: secs.map(|s| ctx.now + s),
    };
    ctx.state
        .bridges
        .retain(|x| !(x.from == from && x.to == to));
    ctx.state.bridges.push(b.clone());
    ctx.commit()?;
    Ok(b)
}

pub fn bridge_rm(from: &str, to: &str) -> Result<()> {
    let mut ctx = Ctx::open()?;
    let before = ctx.state.bridges.len();
    ctx.state
        .bridges
        .retain(|x| !(x.from == from && x.to == to));
    if ctx.state.bridges.len() == before {
        bail!("there is no bridge from {from} to {to}");
    }
    ctx.commit()
}

// ---------------------------------------------------------------- hosts

/// "user@100.80.0.3" or "user@[fd7a::1]" or "user@fd7a::1".
pub fn parse_target(target: &str) -> Result<(String, IpAddr)> {
    let Some((user, addr)) = target.rsplit_once('@') else {
        bail!("give the host as user@address, e.g. root@100.80.0.3");
    };
    crate::state::validate_remote_user(user)?;
    let addr = addr.trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = addr.parse().with_context(|| {
        format!(
            "{addr:?} is not an IP address. blackthorn stores addresses, not names, so a \
             changed DNS record cannot redirect a space; use the host's (tailnet) IP"
        )
    })?;
    Ok((user.to_string(), ip))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub user: String,
    pub address: IpAddr,
    pub port: u16,
    pub host_keys: Vec<String>,
    pub fingerprints: Vec<String>,
}

/// Reads a machine's host keys, for you to confirm before `host_add`.
/// `client` is the address of whoever asks (your SSH or browser connection).
pub fn host_scan(target: &str, port: u16, client: Option<IpAddr>) -> Result<Scan> {
    scan_target(target, port, client, None)
}

/// Reads the host keys at a registered machine's new address, for you to
/// confirm before `host_move`.
pub fn host_move_scan(name: &str, target: &str, port: u16, client: Option<IpAddr>) -> Result<Scan> {
    scan_target(target, port, client, Some(name))
}

/// `moving`: the registered machine that will get this address, if any.
fn scan_target(
    target: &str,
    port: u16,
    client: Option<IpAddr>,
    moving: Option<&str>,
) -> Result<Scan> {
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    if let Some(n) = moving {
        state.host(n)?;
    }
    let (user, address) = parse_target(target)?;
    refuse_address(&cfg, address, client)?;
    check_address_free(&state, address, port, moving)?;
    let host_keys = keys::scan(address, port)?;
    let fingerprints = keys::fingerprints(&host_keys)?;
    Ok(Scan {
        user,
        address,
        port,
        host_keys,
        fingerprints,
    })
}

fn check_address_free(
    state: &State,
    address: IpAddr,
    port: u16,
    except: Option<&str>,
) -> Result<()> {
    if let Some((n, _)) = state
        .hosts
        .iter()
        .find(|(n, h)| Some(n.as_str()) != except && h.address == address && h.port == port)
    {
        bail!("{address} port {port} is already registered as {n}");
    }
    Ok(())
}

/// Machines blackthorn will not manage: they would have a path back.
fn refuse_address(cfg: &Config, address: IpAddr, client: Option<IpAddr>) -> Result<()> {
    if cfg.never_manage.contains(&address) {
        bail!(
            "{address} is listed in never_manage in {}: blackthorn must have nothing to do with it",
            paths::CONFIG_FILE
        );
    }
    if cfg.inbound.admin_from.contains(&address) || client == Some(address) {
        bail!(
            "{address} is a device you administer the hub from. A managed machine must never \
             be able to reach the hub, so it cannot be both; manage it from a space only if you \
             stop using it for administration"
        );
    }
    Ok(())
}

/// Registers a machine whose host keys you confirmed (from `host_scan`).
/// The keys are read again and must not have changed. Returns the line to
/// put in its authorized_keys.
pub fn host_add(
    name: &str,
    target: &str,
    port: u16,
    confirmed_keys: &[String],
    client: Option<IpAddr>,
) -> Result<String> {
    let mut ctx = Ctx::open()?;
    validate_name("host", name)?;
    if ctx.state.hosts.contains_key(name) {
        bail!("there is already a host named {name:?}");
    }
    let (user, address) = parse_target(target)?;
    refuse_address(&ctx.cfg, address, client)?;
    let host_keys = keys::scan(address, port)?;
    if host_keys != confirmed_keys {
        bail!("{address}'s host keys changed since you confirmed them; scan again");
    }
    keys::generate(name)?;
    ctx.state.hosts.insert(
        name.to_string(),
        Host {
            address,
            port,
            user,
            host_keys,
            os: Os::Linux,
            block: None,
            readonly: None,
        },
    );
    ctx.commit()?;
    authorized_keys_line(&ctx.cfg, &ctx.state, name)
}

/// Gives a registered machine a new address, login or port (for example its
/// tailnet address instead of its LAN one), with host keys you confirmed
/// (from `host_move_scan`). Its spaces stay; their files and firewall rules
/// follow. Returns the new authorized_keys line, which replaces the old one
/// on the machine.
pub fn host_move(
    name: &str,
    target: &str,
    port: u16,
    confirmed_keys: &[String],
    client: Option<IpAddr>,
) -> Result<String> {
    let mut ctx = Ctx::open()?;
    ctx.state.host(name)?;
    let (user, address) = parse_target(target)?;
    refuse_address(&ctx.cfg, address, client)?;
    check_address_free(&ctx.state, address, port, Some(name))?;
    let host_keys = keys::scan(address, port)?;
    if host_keys != confirmed_keys {
        bail!("{address}'s host keys changed since you confirmed them; scan again");
    }
    let h = ctx.state.hosts.get_mut(name).expect("exists");
    h.address = address;
    h.port = port;
    h.user = user;
    h.host_keys = host_keys;
    ctx.commit()?;
    authorized_keys_line(&ctx.cfg, &ctx.state, name)
}

/// The authorized_keys line for a host, limited to the hub's addresses.
pub fn authorized_keys_line(cfg: &Config, state: &State, name: &str) -> Result<String> {
    let from = hub_addresses(cfg, state.host(name)?.address);
    keys::authorized_keys_line(name, &from)
}

/// The addresses a machine sees the hub's connections come from: ssh_from
/// if set, else the source address the kernel picks on the route to it (on
/// a LAN and on a tailnet alike), else the hub's tailnet addresses.
fn hub_addresses(cfg: &Config, target: IpAddr) -> Vec<IpAddr> {
    if !cfg.ssh_from.is_empty() {
        return cfg.ssh_from.clone();
    }
    let route = sys::output("ip", &["route", "get", &target.to_string()]);
    match route.ok().as_deref().and_then(route_source) {
        Some(src) => vec![src],
        None => tailscale_ips(),
    }
}

/// The `src` address in `ip route get` output.
fn route_source(out: &str) -> Option<IpAddr> {
    let words: Vec<&str> = out.split_whitespace().collect();
    words
        .windows(2)
        .find(|w| w[0] == "src")
        .and_then(|w| w[1].parse().ok())
}

pub fn host_pubkey(name: &str) -> Result<String> {
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    authorized_keys_line(&cfg, &state, name)
}

/// The hub's tailnet addresses, if tailscale is installed and up.
pub fn tailscale_ips() -> Vec<IpAddr> {
    sys::output("tailscale", &["ip"])
        .map(|o| o.lines().filter_map(|l| l.trim().parse().ok()).collect())
        .unwrap_or_default()
}

/// Forgets a machine and deletes its key. Refused while spaces work on it.
pub fn host_rm(name: &str) -> Result<()> {
    let mut ctx = Ctx::open()?;
    ctx.state.host(name)?;
    let users: Vec<String> = ctx
        .state
        .spaces_on(name)
        .into_iter()
        .map(String::from)
        .collect();
    if !users.is_empty() {
        bail!(
            "spaces work on {name}: {}; remove them first (thorn rm <space>)",
            users.join(", ")
        );
    }
    ctx.state.hosts.remove(name);
    ctx.commit()?;
    keys::remove(name)
}

/// Renames a machine. Its spaces keep working on it; what they call it in
/// SSH (`ssh <name>`) and in their instructions changes with it.
pub fn host_rename(old: &str, new: &str) -> Result<()> {
    let mut ctx = Ctx::open()?;
    validate_name("host", new)?;
    if ctx.state.hosts.contains_key(new) {
        bail!("there is already a machine named {new:?}");
    }
    let h = ctx.state.host(old)?.clone();
    let moves = [
        (paths::key_file(old), paths::key_file(new)),
        (paths::pubkey_file(old), paths::pubkey_file(new)),
        (paths::ro_key_file(old), paths::ro_key_file(new)),
        (paths::ro_pubkey_file(old), paths::ro_pubkey_file(new)),
    ];
    for (_, to) in &moves {
        if to.exists() {
            bail!("{} is in the way; move it aside first", to.display());
        }
    }
    let move_keys = |back: bool| -> Result<()> {
        for (a, b) in &moves {
            let (from, to) = if back { (b, a) } else { (a, b) };
            if from.exists() {
                std::fs::rename(from, to)
                    .with_context(|| format!("moving {} to {}", from.display(), to.display()))?;
            }
        }
        Ok(())
    };
    move_keys(false)?;
    ctx.state.hosts.remove(old);
    ctx.state.hosts.insert(new.to_string(), h);
    for s in ctx.state.spaces.values_mut() {
        if s.host == old {
            s.host = new.to_string();
        }
    }
    if let Err(e) = ctx.commit() {
        let _ = move_keys(true);
        return Err(e);
    }
    Ok(())
}

/// Cuts every space off from a machine, now. Returns when the block ends.
pub fn host_block(name: &str, secs: Option<u64>, reason: Option<String>) -> Result<Option<u64>> {
    let mut ctx = Ctx::open()?;
    ctx.state.host(name)?;
    let now = ctx.now;
    let until = secs.map(|s| now + s);
    ctx.state.hosts.get_mut(name).expect("checked").block = Some(Block {
        since: now,
        until,
        reason: reason.filter(|r| !r.trim().is_empty()),
    });
    ctx.commit()?;
    Ok(until)
}

pub fn host_unblock(name: &str) -> Result<()> {
    let mut ctx = Ctx::open()?;
    ctx.state.host(name)?;
    ctx.state.hosts.get_mut(name).expect("checked").block = None;
    ctx.commit()
}

/// Logs in with the host's key as root (not subject to the space firewall)
/// and runs `uname -s`. Records the machine's OS. Returns it.
pub fn host_check(name: &str) -> Result<Os> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let h = state.host(name)?.clone();
    let out = crate::remote::ssh(name, &h, &paths::key_file(name), &h.user, "uname -s", None)?;
    if !out.status.success() {
        bail!(
            "could not log in to {name}: {}\nis the line from `thorn host pubkey {name}` in its authorized_keys?",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let uname = String::from_utf8_lossy(&out.stdout);
    let os = Os::from_uname(&uname).with_context(|| {
        format!(
            "logged in, but {name} runs {:?}; blackthorn supports Linux and macOS machines",
            uname.trim()
        )
    })?;
    if os != h.os {
        let mut ctx = Ctx::open()?;
        if let Some(host) = ctx.state.hosts.get_mut(name) {
            host.os = os;
        }
        ctx.commit()?;
    }
    Ok(os)
}

/// What `host_readonly` did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadonlyDone {
    pub user: String,
    /// The setup script's own report ("installed sudo", ...).
    pub report: Vec<String>,
    /// Admin spaces on the machine, which from now on run for a limited
    /// time and not at boot.
    pub limited: Vec<String>,
}

/// The read-only login's setup for a machine: the script to run as root
/// there, from the keys and addresses blackthorn has.
fn readonly_script(cfg: &Config, state: &State, name: &str, user: &str) -> Result<String> {
    let h = state.host(name)?;
    if h.os != Os::Linux {
        bail!(
            "{name} runs {}; read-only logins are for Linux machines for now",
            h.os
        );
    }
    crate::state::validate_remote_user(user)?;
    if user == "root" || user == h.user {
        bail!("the read-only login needs a user of its own, not {user}");
    }
    keys::generate_ro(name)?;
    let from = hub_addresses(cfg, h.address);
    let admin_pub = keys::public_key(name)?;
    let admin_key = admin_pub
        .split_whitespace()
        .nth(1)
        .context("the admin public key has no key part")?
        .to_string();
    Ok(crate::remote::setup_script(&crate::remote::Setup {
        user,
        ro_line: &keys::logged_key_line(&keys::ro_public_key(name)?, &from),
        admin_user: &h.user,
        admin_key: &admin_key,
        admin_line: &keys::logged_key_line(&admin_pub, &from),
    }))
}

/// The setup script, to run by hand as root on the machine (instead of
/// letting the hub log in as its admin to run it).
pub fn host_readonly_script(name: &str, user: &str) -> Result<String> {
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    readonly_script(&cfg, &state, name, user)
}

/// Gives a machine a read-only login: runs the setup as its admin login
/// (unless `run` is false: you ran the script yourself), checks that the
/// new login works and cannot use sudo for anything else, and records it.
pub fn host_readonly(name: &str, user: &str, run: bool) -> Result<ReadonlyDone> {
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    let h = state.host(name)?.clone();
    let mut report = Vec::new();
    if run {
        let script = readonly_script(&cfg, &state, name, user)?;
        let cmd = if h.user == "root" {
            "sh -s"
        } else {
            "sudo -n sh -s"
        };
        let out = crate::remote::ssh(
            name,
            &h,
            &paths::key_file(name),
            &h.user,
            cmd,
            Some(&script),
        )?;
        let text = String::from_utf8_lossy(&out.stdout);
        report = text
            .lines()
            .filter_map(|l| l.strip_prefix("bt: "))
            .filter(|l| *l != "done")
            .map(String::from)
            .collect();
        if !out.status.success() || !text.lines().any(|l| l == "bt: done") {
            bail!(
                "setting up {name} failed: {}{}",
                String::from_utf8_lossy(&out.stderr).trim(),
                if h.user == "root" {
                    ""
                } else {
                    " (the admin login needs sudo without a password; or run the script yourself: \
                     thorn host readonly NAME --print)"
                }
            );
        }
    } else if !paths::ro_key_file(name).exists() {
        bail!("no read-only key for {name} yet: print the script first (thorn host readonly {name} --print)");
    }
    readonly_verify(name, &h, user)?;

    let mut ctx = Ctx::open()?;
    let host = ctx
        .state
        .hosts
        .get_mut(name)
        .with_context(|| format!("{name} was removed meanwhile"))?;
    host.readonly = Some(user.to_string());
    let limited: Vec<(String, String)> = ctx
        .state
        .spaces
        .iter()
        .filter(|(_, s)| s.host == name && s.access == Access::Admin)
        .map(|(n, s)| (n.clone(), s.key.clone()))
        .collect();
    ctx.commit()?;
    drop(ctx);
    for (_, key) in &limited {
        let _ = sys::systemctl(&["disable", &paths::space_unit(key)]);
    }
    Ok(ReadonlyDone {
        user: user.to_string(),
        report,
        limited: limited.into_iter().map(|(n, _)| n).collect(),
    })
}

/// Logs in with the read-only key: it must work, and sudo must not run
/// just anything.
fn readonly_verify(name: &str, h: &Host, user: &str) -> Result<()> {
    let out = crate::remote::ssh(
        name,
        h,
        &paths::ro_key_file(name),
        user,
        "id -un; if sudo -n true 2>/dev/null; then echo SUDO-ANYTHING; fi",
        None,
    )?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || text.lines().next() != Some(user) {
        bail!(
            "could not log in to {name} as {user}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    if text.contains("SUDO-ANYTHING") {
        bail!(
            "{user} on {name} can run anything with sudo, so it is not read-only; \
             remove its other sudo rules first"
        );
    }
    Ok(())
}

/// Reads a machine's host keys again. Returns the scan and whether they
/// differ from the recorded ones.
pub fn host_rescan(name: &str) -> Result<(Scan, bool)> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let h = state.host(name)?;
    let host_keys = keys::scan(h.address, h.port)?;
    let changed = host_keys != h.host_keys;
    Ok((
        Scan {
            user: h.user.clone(),
            address: h.address,
            port: h.port,
            fingerprints: keys::fingerprints(&host_keys)?,
            host_keys,
        },
        changed,
    ))
}

/// Saves new host keys you confirmed (from `host_rescan`).
pub fn host_rescan_confirm(name: &str, confirmed_keys: &[String]) -> Result<()> {
    let mut ctx = Ctx::open()?;
    let h = ctx.state.host(name)?.clone();
    let fresh = keys::scan(h.address, h.port)?;
    if fresh != confirmed_keys {
        bail!("{name}'s host keys changed again since you confirmed them; scan again");
    }
    ctx.state.hosts.get_mut(name).expect("exists").host_keys = fresh;
    ctx.commit()
}

/// The address of the SSH client this command runs under, if any.
pub fn ssh_client() -> Option<IpAddr> {
    std::env::var("SSH_CONNECTION")
        .ok()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

// ------------------------------------------------------------- settings

/// The settings the web UI and `thorn config` can change, with what they
/// mean. Everything else stays in config.toml.
pub const SETTINGS: &[(&str, &str)] = &[
    (
        "inbound.admin_from",
        "Your devices: only these addresses may connect to the hub's SSH and web UI. \
         Empty: anything that can reach the hub may try.",
    ),
    (
        "never_manage",
        "Machines blackthorn must never manage, such as your tailnet's control server. \
         Their connections to the hub are dropped.",
    ),
    (
        "inbound.deny_from",
        "More addresses whose connections to the hub are always dropped.",
    ),
    (
        "web.listen",
        "Where the web UI listens, as address:port, e.g. the hub's tailnet address :7180.",
    ),
    (
        "ssh_from",
        "The hub's own addresses for from=\"...\" in key lines. Empty: found for each machine.",
    ),
    (
        "egress.https_anywhere",
        "Spaces may open HTTPS to any address (true or false). Claude Code needs it.",
    ),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Setting {
    pub key: String,
    pub value: String,
    pub help: String,
}

pub fn config_show() -> Result<Vec<Setting>> {
    sys::require_root()?;
    let (cfg, _) = ctx::read_only()?;
    Ok(SETTINGS
        .iter()
        .map(|(k, h)| Setting {
            key: k.to_string(),
            value: setting_value(&cfg, k),
            help: h.to_string(),
        })
        .collect())
}

fn setting_value(cfg: &Config, key: &str) -> String {
    fn list<T: ToString>(v: &[T]) -> String {
        v.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
    match key {
        "inbound.admin_from" => list(&cfg.inbound.admin_from),
        "never_manage" => list(&cfg.never_manage),
        "inbound.deny_from" => list(&cfg.inbound.deny_from),
        "web.listen" => list(&cfg.web.listen),
        "ssh_from" => list(&cfg.ssh_from),
        "egress.https_anywhere" => cfg.egress.https_anywhere.to_string(),
        _ => String::new(),
    }
}

/// Addresses separated by commas or spaces; empty is an empty list.
fn parse_list<T: std::str::FromStr>(key: &str, value: &str) -> Result<Vec<T>>
where
    T::Err: std::fmt::Display,
{
    value
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<T>().map_err(|e| anyhow!("{key}: {s:?}: {e}")))
        .collect()
}

fn toml_list<T: ToString>(v: &[T]) -> toml_edit::Item {
    let mut a = toml_edit::Array::new();
    for x in v {
        a.push(x.to_string());
    }
    toml_edit::value(a)
}

/// What a settings change did.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigChange {
    pub changed: Vec<String>,
    /// The web UI's new addresses, when it moved (it restarts on them).
    pub web_moved: Option<Vec<String>>,
}

/// Changes settings (`key`, `value` pairs) in config.toml, keeping its
/// comments, and applies them. Refused if it would lock out `client` (the
/// address of whoever asks) or make a managed machine an admin device.
/// `from_web`: the web UI may not turn itself off.
pub fn config_set(
    changes: &[(String, String)],
    client: Option<IpAddr>,
    from_web: bool,
) -> Result<ConfigChange> {
    let ctx = Ctx::open()?;
    let text = std::fs::read_to_string(paths::CONFIG_FILE).unwrap_or_default();
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .with_context(|| format!("reading {}", paths::CONFIG_FILE))?;
    let mut cfg = ctx.cfg.clone();
    let mut out = ConfigChange::default();
    for (key, value) in changes {
        let value = value.trim();
        match key.as_str() {
            "inbound.admin_from" => {
                cfg.inbound.admin_from = parse_list(key, value)?;
                doc["inbound"]["admin_from"] = toml_list(&cfg.inbound.admin_from);
            }
            "never_manage" => {
                cfg.never_manage = parse_list(key, value)?;
                doc["never_manage"] = toml_list(&cfg.never_manage);
            }
            "inbound.deny_from" => {
                cfg.inbound.deny_from = parse_list(key, value)?;
                doc["inbound"]["deny_from"] = toml_list(&cfg.inbound.deny_from);
            }
            "web.listen" => {
                cfg.web.listen = parse_list::<SocketAddr>(key, value)?;
                doc["web"]["listen"] = toml_list(&cfg.web.listen);
            }
            "ssh_from" => {
                cfg.ssh_from = parse_list(key, value)?;
                doc["ssh_from"] = toml_list(&cfg.ssh_from);
            }
            "egress.https_anywhere" => {
                cfg.egress.https_anywhere = match value {
                    "true" | "yes" | "on" => true,
                    "false" | "no" | "off" => false,
                    _ => bail!("{key} is true or false, not {value:?}"),
                };
                doc["egress"]["https_anywhere"] = toml_edit::value(cfg.egress.https_anywhere);
            }
            _ => bail!("unknown setting {key:?}; `thorn config show` lists them"),
        }
        if !out.changed.contains(key) {
            out.changed.push(key.clone());
        }
    }
    check_settings(&cfg, &ctx.state, client, from_web, &local_addresses())?;
    let new_text = doc.to_string();
    let parsed: Config = toml::from_str(&new_text)
        .with_context(|| format!("the change would break {}", paths::CONFIG_FILE))?;
    if parsed != cfg {
        bail!(
            "the change was not written as expected; edit {} by hand",
            paths::CONFIG_FILE
        );
    }
    sys::write_file(Path::new(paths::CONFIG_FILE), &new_text, 0o644, None)?;
    apply::firewall_rules(&cfg, &ctx.state, ctx.now, true)?;
    apply::everything(&cfg, &ctx.state, ctx.now)?;
    if cfg.web.listen != ctx.cfg.web.listen {
        out.web_moved = Some(
            cfg.web
                .listen
                .iter()
                .map(|a| format!("http://{a}/"))
                .collect(),
        );
    }
    Ok(out)
}

fn check_settings(
    cfg: &Config,
    state: &State,
    client: Option<IpAddr>,
    from_web: bool,
    local: &[IpAddr],
) -> Result<()> {
    for (n, h) in &state.hosts {
        if cfg.inbound.admin_from.contains(&h.address) {
            bail!(
                "{} is machine {n}: a managed machine must never be able to reach the hub, \
                 so it cannot be an admin device",
                h.address
            );
        }
        if cfg.never_manage.contains(&h.address) {
            bail!(
                "{} is machine {n}, which blackthorn manages; remove it first (thorn host rm {n})",
                h.address
            );
        }
    }
    if let Some(c) = client {
        let shut_out = (!cfg.inbound.admin_from.is_empty() && !cfg.inbound.admin_from.contains(&c))
            || cfg.inbound.deny_from.contains(&c)
            || cfg.never_manage.contains(&c);
        if shut_out {
            bail!(
                "this would lock you out: you are connected from {c}, which would no longer be \
                 let in. Add {c} to inbound.admin_from, or make this change from the hub's console"
            );
        }
    }
    if from_web && cfg.web.listen.is_empty() {
        bail!("the web UI cannot turn itself off; use `sudo thorn web disable` on the hub");
    }
    if !local.is_empty() {
        for a in &cfg.web.listen {
            if !a.ip().is_unspecified() && !local.contains(&a.ip()) {
                bail!(
                    "{} is not an address of this machine; the web UI could not listen there",
                    a.ip()
                );
            }
        }
    }
    Ok(())
}

/// This machine's own addresses (empty if `ip` cannot tell).
fn local_addresses() -> Vec<IpAddr> {
    sys::output("ip", &["-o", "addr", "show"])
        .map(|o| parse_ip_addr(&o))
        .unwrap_or_default()
}

fn parse_ip_addr(out: &str) -> Vec<IpAddr> {
    out.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            let i = w.iter().position(|x| *x == "inet" || *x == "inet6")?;
            w.get(i + 1)?.split('/').next()?.parse().ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_of_the_hub() {
        assert_eq!(
            control_name(r#"{"ControlURL":"https://headscale.example.com:443/"}"#).as_deref(),
            Some("headscale.example.com")
        );
        assert_eq!(
            control_name(r#"{"ControlURL":"https://controlplane.tailscale.com"}"#).as_deref(),
            Some("Tailscale")
        );
        assert_eq!(
            default_route("default via 192.168.10.1 dev ens18 proto static onlink \n"),
            (Some("192.168.10.1".parse().unwrap()), Some("ens18".into()))
        );
        assert_eq!(default_route(""), (None, None));
        assert_eq!(
            lan_of("2: ens18    inet 192.168.10.106/24 brd 192.168.10.255 scope global ens18\\       valid_lft forever").as_deref(),
            Some("192.168.10.0/24")
        );
        assert!(unattended(&[
            "--permission-mode".into(),
            "bypassPermissions".into()
        ]));
        assert!(unattended(&["--dangerously-skip-permissions".into()]));
        assert!(!unattended(&[
            "--permission-mode".into(),
            "acceptEdits".into()
        ]));
    }

    #[test]
    fn setting_checks() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        let mut state = State::default();
        state.hosts.insert(
            "fig".into(),
            Host {
                address: ip("100.80.0.3"),
                port: 22,
                user: "root".into(),
                host_keys: vec![],
                os: Os::Linux,
                block: None,
                readonly: None,
            },
        );
        let local = [ip("127.0.0.1"), ip("100.64.0.10")];
        let me = Some(ip("100.64.0.2"));
        let mut cfg = Config {
            web: crate::config::Web {
                listen: vec!["0.0.0.0:7180".parse().unwrap()],
                ..Default::default()
            },
            ..Config::default()
        };
        assert!(check_settings(&cfg, &state, me, true, &local).is_ok());
        cfg.inbound.admin_from = vec![ip("100.64.0.5")];
        let e = check_settings(&cfg, &state, me, true, &local).unwrap_err();
        assert!(e.to_string().contains("lock you out"), "{e}");
        assert!(check_settings(&cfg, &state, None, false, &local).is_ok());
        cfg.inbound.admin_from = vec![ip("100.64.0.2"), ip("100.80.0.3")];
        assert!(check_settings(&cfg, &state, me, true, &local).is_err());
        cfg.inbound.admin_from = vec![ip("100.64.0.2")];
        cfg.never_manage = vec![ip("100.80.0.3")];
        assert!(check_settings(&cfg, &state, me, true, &local).is_err());
        cfg.never_manage = vec![];
        cfg.web.listen = vec!["100.64.0.10:7180".parse().unwrap()];
        assert!(check_settings(&cfg, &state, me, true, &local).is_ok());
        cfg.web.listen = vec!["100.64.0.99:7180".parse().unwrap()];
        assert!(check_settings(&cfg, &state, me, true, &local).is_err());
        cfg.web.listen = vec![];
        assert!(check_settings(&cfg, &state, me, true, &local).is_err());
        assert!(check_settings(&cfg, &state, me, false, &local).is_ok());
    }

    #[test]
    fn lists_and_addresses() {
        let v: Vec<IpAddr> = parse_list("k", "100.64.0.2, 100.64.0.3 ,fd7a::1").unwrap();
        assert_eq!(v.len(), 3);
        assert!(parse_list::<IpAddr>("k", "").unwrap().is_empty());
        assert!(parse_list::<IpAddr>("k", "laptop").is_err());
        let out = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n\
                   2: ens18    inet 192.168.10.106/24 brd 192.168.10.255 scope global ens18\n\
                   3: tailscale0    inet6 fd7a:115c:a1e0::1/128 scope global\n";
        let a = parse_ip_addr(out);
        assert_eq!(a.len(), 3);
        assert!(a.contains(&"192.168.10.106".parse().unwrap()));
    }

    #[test]
    fn settings_keep_comments() {
        let text = "# mine\nnever_manage = []\n\n[inbound]\n# my devices\nadmin_from = []\n";
        let mut doc: toml_edit::DocumentMut = text.parse().unwrap();
        doc["inbound"]["admin_from"] = toml_list(&["100.64.0.2".parse::<IpAddr>().unwrap()]);
        doc["web"]["listen"] = toml_list(&["0.0.0.0:7180".parse::<SocketAddr>().unwrap()]);
        let out = doc.to_string();
        assert!(out.contains("# my devices"), "{out}");
        let c: Config = toml::from_str(&out).unwrap();
        assert_eq!(
            c.inbound.admin_from,
            vec!["100.64.0.2".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(c.web.listen.len(), 1);
    }

    #[test]
    fn route_sources() {
        let lan = "192.168.10.5 dev ens18 src 192.168.10.106 uid 0 \n    cache \n";
        assert_eq!(route_source(lan), Some("192.168.10.106".parse().unwrap()));
        let tailnet = "100.80.0.3 dev tailscale0 table 52 src 100.64.0.10 uid 0 \n    cache \n";
        assert_eq!(route_source(tailnet), Some("100.64.0.10".parse().unwrap()));
        assert_eq!(route_source(""), None);
        assert_eq!(route_source("unreachable 10.9.9.9"), None);
    }

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
        let forever = Block {
            since: 0,
            until: None,
            reason: None,
        };
        assert_eq!(describe_block(&forever, 5), "BLOCKED");
        let b = Block {
            since: 0,
            until: Some(3600),
            reason: Some("upgrade".into()),
        };
        assert_eq!(describe_block(&b, 0), "BLOCKED for 1h (upgrade)");
        assert_eq!(describe_until(Some(3000), 0), "for 50m");
    }

    #[test]
    fn refuses_admin_devices_and_never_manage() {
        let mut cfg = Config {
            never_manage: vec!["100.64.0.4".parse().unwrap()],
            ..Default::default()
        };
        cfg.inbound.admin_from = vec!["100.64.0.2".parse().unwrap()];
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(refuse_address(&cfg, ip("100.64.0.4"), None).is_err());
        assert!(refuse_address(&cfg, ip("100.64.0.2"), None).is_err());
        assert!(refuse_address(&cfg, ip("100.64.0.9"), Some(ip("100.64.0.9"))).is_err());
        assert!(refuse_address(&cfg, ip("100.64.0.9"), Some(ip("100.64.0.2"))).is_ok());
    }

    #[test]
    fn login_url_from_screen() {
        let screen = "Opening browser to sign in…\nIf the browser didn't open, visit: \
                      https://claude.com/cai/oauth/authorize?code=true&state=x\n\
                      Paste code here if prompted >";
        assert_eq!(
            find_login_url(screen).unwrap(),
            "https://claude.com/cai/oauth/authorize?code=true&state=x"
        );
        assert!(find_login_url("nothing").is_none());
    }

    #[test]
    fn chat_titles() {
        let t = |lines: &[&str]| chat_title(&lines.join("\n"));
        let user =
            r#"{"type":"user","message":{"role":"user","content":"fix the   nginx config"}}"#;
        let meta = r#"{"type":"user","isMeta":true,"message":{"content":"<command-name>/clear</command-name>"}}"#;
        let blocks =
            r#"{"type":"user","message":{"content":[{"type":"text","text":"check disk usage"}]}}"#;
        assert_eq!(t(&[meta, user]).as_deref(), Some("fix the nginx config"));
        assert_eq!(t(&[blocks]).as_deref(), Some("check disk usage"));
        let ai = r#"{"type":"ai-title","aiTitle":"Nginx config fix","sessionId":"x"}"#;
        assert_eq!(t(&[user, ai]).as_deref(), Some("Nginx config fix"));
        let named = r#"{"type":"custom-title","customTitle":"web server","sessionId":"x"}"#;
        let renamed = r#"{"type":"custom-title","customTitle":"proxy","sessionId":"x"}"#;
        assert_eq!(t(&[user, named, ai, renamed]).as_deref(), Some("proxy"));
        let cleared = r#"{"type":"custom-title","customTitle":"","sessionId":"x"}"#;
        assert_eq!(
            t(&[user, named, cleared]).as_deref(),
            Some("fix the nginx config")
        );
        assert_eq!(t(&[meta]), None);
        assert_eq!(t(&["not json", ""]), None);
        let long = format!(
            r#"{{"type":"user","message":{{"content":"{}"}}}}"#,
            "x".repeat(200)
        );
        assert_eq!(t(&[&long]).unwrap().chars().count(), 80);
    }

    #[test]
    fn model_names() {
        assert_eq!(model_name("claude-opus-5-5"), "Opus 5.5");
        assert_eq!(model_name("claude-fable-5-2"), "Fable 5.2");
        assert_eq!(model_name("claude-sonnet-4-5-20250929"), "Sonnet 4.5");
        assert_eq!(model_name("claude-3-5-sonnet-20241022"), "Sonnet 3.5");
        assert_eq!(model_name("claude-haiku-5-5"), "Haiku 5.5");
        assert_eq!(model_name("gpt-5"), "gpt-5");
    }

    #[test]
    fn versions_and_release_tags() {
        assert_eq!(parse_version("v0.4.1"), Some((0, 4, 1)));
        assert_eq!(parse_version("0.10.0"), Some((0, 10, 0)));
        assert!(parse_version("v0.10.0") > parse_version("v0.9.9"));
        assert_eq!(parse_version("v0.4.1-rc1"), None);
        assert_eq!(parse_version("v0.4"), None);
        assert_eq!(parse_version("v0.4.1.2"), None);
        assert_eq!(parse_version("v0.4.1; rm -rf /"), None);
        assert_eq!(
            parse_release_tag("https://github.com/frakw/blackthorn/releases/tag/v0.4.0").as_deref(),
            Some("v0.4.0")
        );
        assert_eq!(
            parse_release_tag("https://github.com/frakw/blackthorn/releases/tag/v1;x"),
            None
        );
        assert_eq!(parse_release_tag(""), None);
    }

    #[test]
    fn tailnet_devices() {
        let status = r#"{
          "Self": {"HostName": "frakw-blackthorn", "TailscaleIPs": ["100.80.0.6", "fd7a:115c:a1e0::6"], "OS": "linux", "Online": true},
          "Peer": {
            "k1": {"HostName": "rosemary", "TailscaleIPs": ["100.80.0.2"], "OS": "macOS", "Online": true},
            "k2": {"HostName": "", "DNSName": "basil.tail.example.", "TailscaleIPs": ["100.80.0.4"], "OS": "android", "Online": false}
          }
        }"#;
        let p = parse_tailscale_status(status);
        assert_eq!(p.len(), 3);
        assert!(p[0].hub && p[0].name == "frakw-blackthorn" && p[0].ips.len() == 2);
        assert_eq!(p[1].name, "basil");
        assert!(!p[1].online);
        assert_eq!(p[2].name, "rosemary");
        assert_eq!(p[2].ips, vec!["100.80.0.2".parse::<IpAddr>().unwrap()]);
        assert!(parse_tailscale_status("not json").is_empty());
    }
}
