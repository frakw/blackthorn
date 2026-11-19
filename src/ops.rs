//! Every operation blackthorn offers, independent of how it is asked for.
//! The CLI and the web API both call these functions, so they offer the same
//! things. Functions that change state open (and lock) the context
//! themselves and never print; they return what happened.

use crate::config::{Config, CLAUDE};
use crate::ctx::{self, Ctx};
use crate::state::{now, validate_name, validate_rc_name, Block, Bridge, Host, Mode, Os, Space};
use crate::{keys, paths, render, sys, units};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceView {
    pub name: String,
    pub host: String,
    pub agent: String,
    pub mode: Mode,
    pub rc_name: String,
    /// "running", "stopped", "failed", "needs login", ...
    pub state: String,
    pub memory_mb: Option<u64>,
    /// Conversations written to in the last 24 hours (Claude only).
    pub chats_24h: Option<usize>,
    /// Hosts it can reach right now.
    pub reachable: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostView {
    pub name: String,
    pub address: IpAddr,
    pub port: u16,
    pub user: String,
    pub os: Os,
    pub spaces: Vec<String>,
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
                rc_name: s.rc_name.clone(),
                state: state_str,
                memory_mb: sys::unit_memory(&unit).map(|b| b / 1_048_576),
                chats_24h: (s.agent == CLAUDE).then(|| recent_chats(&s.key, t)),
                reachable: state
                    .reachable_hosts(name, t)
                    .into_iter()
                    .map(|(n, _)| n.to_string())
                    .collect(),
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
    pub rc_name: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
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
    let name = o.name.unwrap_or_else(|| format!("{}-{agent}", o.host));
    validate_name("space", &name)?;
    if ctx.state.spaces.contains_key(&name) {
        bail!("there is already a space named {name:?}; choose another with --name");
    }
    let rc_name = o.rc_name.unwrap_or_else(|| name.clone());
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
    let workdir = paths::space_workdir(&key);
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
        rc_name,
        conversation: uuid::Uuid::new_v4().to_string(),
        args: o.args,
        created: ctx.now,
    };
    let start_now = logged_in(&space);
    ctx.state.spaces.insert(name.clone(), space);
    ctx.commit()?;
    drop(ctx);
    sys::systemctl(&["enable", &paths::space_unit(&key)])?;
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

/// Renames a space. Returns whether it was restarted to show a new Remote
/// Control name.
pub fn space_rename(old: &str, new: &str, rc_name: Option<String>) -> Result<bool> {
    let mut ctx = Ctx::open()?;
    validate_name("space", new)?;
    if ctx.state.spaces.contains_key(new) {
        bail!("there is already a space named {new:?}");
    }
    let mut s = ctx.state.space(old)?.clone();
    let old_rc = s.rc_name.clone();
    if let Some(rc) = rc_name {
        s.rc_name = rc;
    } else if s.rc_name == old {
        s.rc_name = new.to_string();
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
    let unit = paths::space_unit(&s.key);
    if s.rc_name != old_rc && sys::unit_state(&unit) == "active" {
        sys::systemctl(&["restart", &unit])?;
        return Ok(true);
    }
    Ok(false)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Start,
    Stop,
    Restart,
}

impl Action {
    pub fn verb(self) -> &'static str {
        match self {
            Action::Start => "start",
            Action::Stop => "stop",
            Action::Restart => "restart",
        }
    }
    pub fn done(self) -> &'static str {
        match self {
            Action::Start => "started",
            Action::Stop => "stopped",
            Action::Restart => "restarted",
        }
    }
}

/// Starts, stops or restarts spaces (all of them if `names` is empty).
/// Returns one line per space.
pub fn space_control(action: Action, names: &[String]) -> Result<Vec<String>> {
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
    let mut out = Vec::new();
    for (name, s) in targets {
        if action != Action::Stop && !logged_in(&s) {
            out.push(format!("{name}: not signed in yet (thorn login {name})"));
            continue;
        }
        sys::systemctl(&[action.verb(), &paths::space_unit(&s.key)])?;
        out.push(format!("{name}: {}", action.done()));
    }
    Ok(out)
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
        .current_dir(paths::space_workdir(&s.key))
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
            sys::systemctl(&["restart", &paths::space_unit(&s.key)])?;
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
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    let (user, address) = parse_target(target)?;
    refuse_address(&cfg, address, client)?;
    if let Some((n, _)) = state
        .hosts
        .iter()
        .find(|(_, h)| h.address == address && h.port == port)
    {
        bail!("{address} port {port} is already registered as {n}");
    }
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
        },
    );
    ctx.commit()?;
    authorized_keys_line(&ctx.cfg, name)
}

/// The authorized_keys line for a host, limited to the hub's addresses.
pub fn authorized_keys_line(cfg: &Config, name: &str) -> Result<String> {
    let from = if cfg.ssh_from.is_empty() {
        tailscale_ips()
    } else {
        cfg.ssh_from.clone()
    };
    keys::authorized_keys_line(name, &from)
}

pub fn host_pubkey(name: &str) -> Result<String> {
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    state.host(name)?;
    authorized_keys_line(&cfg, name)
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
    let known = PathBuf::from(format!("/run/blackthorn-check-{name}.known_hosts"));
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
        .arg("uname -s")
        .output();
    let _ = std::fs::remove_file(&known);
    let out = out.context("running ssh")?;
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
}
