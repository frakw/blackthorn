//! Every operation blackthorn offers, independent of how it is asked for.
//! The CLI and the web API both call these functions, so they offer the same
//! things. Functions that change state open (and lock) the context
//! themselves and never print; they return what happened.

use crate::config::{Config, CLAUDE};
use crate::ctx::{self, Ctx};
use crate::state::{
    now, validate_name, validate_rc_name, Block, Bridge, Host, Mode, Os, Space, State,
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
            },
        );
        let local = [ip("127.0.0.1"), ip("100.64.0.10")];
        let me = Some(ip("100.64.0.2"));
        let mut cfg = Config::default();
        cfg.web.listen = vec!["0.0.0.0:7180".parse().unwrap()];
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
}
