//! `thorn _api`: the root half of the web UI.
//!
//! It listens only on a Unix socket (/run/blackthorn-api/api.sock) that the
//! web user's group may open. The web process forwards each request with
//! the browser's session token; this process checks passwords and TOTP
//! codes, keeps the sessions, and calls the same `ops` functions as the
//! command line. So the process that parses HTTP from the network has no
//! privileges, and cannot act without a logged-in user.
//!
//! Protocol: one JSON request per connection, one JSON response back.

use crate::ops::{self, Action, NewSpace};
use crate::webauth::{self, Users};
use crate::{ctx, paths, sys};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const IDLE: u64 = 30 * 60;
const ABSOLUTE: u64 = 12 * 3600;
const MAX_FAILURES: u32 = 5;
const LOCKOUT: u64 = 15 * 60;
const MAX_REQUEST: u64 = 256 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub csrf: Option<String>,
    #[serde(default)]
    pub client: Option<IpAddr>,
    pub op: Op,
}

/// `code` fields are a fresh TOTP code, asked again for the operations that
/// can do the most harm.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    WebConfig,
    Login {
        user: String,
        password: String,
        code: String,
    },
    Logout,
    Whoami,
    Overview,
    SpaceNew {
        space: NewSpace,
    },
    SpaceRm {
        name: String,
        purge: bool,
        code: String,
    },
    SpaceRename {
        old: String,
        new: String,
        rc_name: Option<String>,
        code: String,
    },
    SpaceControl {
        action: Action,
        names: Vec<String>,
    },
    SpaceScreen {
        name: String,
    },
    SpaceSend {
        name: String,
        text: Option<String>,
        key: Option<String>,
        enter: bool,
    },
    LoginStart {
        name: String,
    },
    LoginFinish {
        name: String,
        code: String,
    },
    LoginCancel {
        name: String,
    },
    BridgeAdd {
        from: String,
        to: String,
        duration: Option<String>,
        code: String,
    },
    BridgeRm {
        from: String,
        to: String,
    },
    HostScan {
        target: String,
        port: u16,
    },
    HostAdd {
        name: String,
        target: String,
        port: u16,
        keys: Vec<String>,
        code: String,
    },
    HostRm {
        name: String,
        code: String,
    },
    HostBlock {
        name: String,
        duration: Option<String>,
        reason: Option<String>,
    },
    HostUnblock {
        name: String,
    },
    HostPubkey {
        name: String,
    },
    HostCheck {
        name: String,
    },
    HostRescan {
        name: String,
    },
    HostRescanConfirm {
        name: String,
        keys: Vec<String>,
        code: String,
    },
    HostMoveScan {
        name: String,
        target: String,
        port: u16,
    },
    HostMove {
        name: String,
        target: String,
        port: u16,
        keys: Vec<String>,
        code: String,
    },
    ConfigShow,
    ConfigSet {
        changes: Vec<(String, String)>,
        code: String,
    },
    TailnetPeers,
    ChatList {
        name: String,
    },
    ChatRename {
        name: String,
        id: String,
        title: String,
        code: String,
    },
    /// A new conversation (id None), or an earlier one, becomes the one a
    /// one-conversation space runs.
    ChatOpen {
        name: String,
        id: Option<String>,
    },
    HostRename {
        old: String,
        new: String,
        code: String,
    },
    AccountRename {
        new: String,
        code: String,
    },
    NotifyShow,
    NotifySet {
        url: String,
        /// None keeps the current token.
        token: Option<String>,
        code: String,
    },
    NotifyTest,
    ChatRm {
        name: String,
        id: String,
    },
    SpaceRemote {
        name: String,
        on: bool,
    },
    UpdateCheck {
        refresh: bool,
    },
    Update {
        code: String,
    },
    /// The logged-in account.
    Account,
    AccountPassword {
        current: String,
        new: String,
        code: String,
    },
    /// A new authenticator secret to scan; it replaces the old one only
    /// once AccountTotpFinish gets a code made from it.
    AccountTotpBegin {
        code: String,
    },
    AccountTotpFinish {
        code: String,
    },
}

impl Op {
    fn name(&self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.get("op").and_then(|o| o.as_str().map(String::from)))
            .unwrap_or_default()
    }

    /// Reading needs a session; changing anything also needs the CSRF value.
    fn changes_state(&self) -> bool {
        !matches!(
            self,
            Op::WebConfig
                | Op::Login { .. }
                | Op::Whoami
                | Op::Overview
                | Op::SpaceScreen { .. }
                | Op::HostPubkey { .. }
                | Op::ConfigShow
                | Op::TailnetPeers
                | Op::ChatList { .. }
                | Op::UpdateCheck { .. }
                | Op::Account
                | Op::NotifyShow
        )
    }

    fn step_up_code(&self) -> Option<&str> {
        match self {
            Op::SpaceRm { code, .. }
            | Op::BridgeAdd { code, .. }
            | Op::HostAdd { code, .. }
            | Op::HostRm { code, .. }
            | Op::HostRescanConfirm { code, .. }
            | Op::HostMove { code, .. }
            | Op::ConfigSet { code, .. }
            | Op::Update { code, .. }
            | Op::AccountPassword { code, .. }
            | Op::AccountTotpBegin { code }
            | Op::SpaceRename { code, .. }
            | Op::ChatRename { code, .. }
            | Op::HostRename { code, .. }
            | Op::AccountRename { code, .. }
            | Op::NotifySet { code, .. } => Some(code),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

struct Session {
    user: String,
    csrf: String,
    created: u64,
    last_seen: u64,
}

#[derive(Default)]
struct Server {
    sessions: HashMap<String, Session>,
    /// Failed logins per account and per client address.
    failures: HashMap<String, (u32, u64)>,
    /// `claude --version` is slow; cache it.
    claude_version: Option<(u64, Option<String>)>,
    /// Asking GitHub for the latest release, at most every few hours.
    update: Option<(u64, ops::UpdateInfo)>,
    /// Authenticator secrets being set up, per account.
    pending_totp: HashMap<String, (String, u64)>,
}

const UPDATE_EVERY: u64 = 6 * 3600;
const PENDING_TOTP: u64 = 10 * 60;

pub fn serve() -> Result<()> {
    sys::require_root()?;
    let sock = Path::new(paths::API_SOCKET);
    if !Path::new(paths::API_DIR).is_dir() {
        bail!(
            "{} is missing; run me from blackthorn-api.service",
            paths::API_DIR
        );
    }
    let _ = std::fs::remove_file(sock);
    let listener = UnixListener::bind(sock).context("binding the API socket")?;
    let web = sys::lookup_user(paths::WEB_USER)
        .with_context(|| format!("user {} is missing; run thorn init", paths::WEB_USER))?;
    sys::chown(sock, 0, web.gid)?;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o660))?;
    eprintln!("blackthorn api: listening on {}", sock.display());

    let server = Arc::new(Mutex::new(Server::default()));
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let server = server.clone();
        std::thread::spawn(move || {
            let _ = handle(conn, &server);
        });
    }
    Ok(())
}

fn handle(conn: UnixStream, server: &Mutex<Server>) -> Result<()> {
    // Only the web user (and root) may talk to us; the socket mode already
    // says so, and the peer credentials double-check it.
    let peer = peer_uid(&conn)?;
    let web_uid = sys::lookup_user(paths::WEB_USER).map(|u| u.uid);
    if peer != 0 && Some(peer) != web_uid {
        bail!("refusing uid {peer}");
    }
    conn.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut line = String::new();
    BufReader::new((&conn).take_limit(MAX_REQUEST)).read_line(&mut line)?;
    let resp = match serde_json::from_str::<Request>(&line) {
        Ok(req) => {
            let op = req.op.name();
            let client = req.client;
            let r = dispatch(req, server);
            let who = r.1.as_deref().unwrap_or("-");
            match &r.0 {
                Ok(_) => eprintln!("api: {who} from {} {op}: ok", show(client)),
                Err(e) => eprintln!(
                    "api: {who} from {} {op}: {}",
                    show(client),
                    e.to_string().lines().next().unwrap_or("")
                ),
            }
            r.0
        }
        Err(e) => Err(anyhow::anyhow!("bad request: {e}")),
    };
    let resp = match resp {
        Ok(data) => Response {
            ok: true,
            error: None,
            data,
        },
        Err(e) => Response {
            ok: false,
            error: Some(format!("{e:#}")),
            data: serde_json::Value::Null,
        },
    };
    let mut conn = conn;
    serde_json::to_writer(&mut conn, &resp)?;
    conn.write_all(b"\n")?;
    Ok(())
}

fn show(c: Option<IpAddr>) -> String {
    c.map(|c| c.to_string()).unwrap_or_else(|| "?".into())
}

trait TakeLimit: std::io::Read + Sized {
    fn take_limit(self, n: u64) -> std::io::Take<Self> {
        self.take(n)
    }
}
impl<R: std::io::Read> TakeLimit for R {}

fn peer_uid(conn: &UnixStream) -> Result<u32> {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt fills a ucred of the size we pass.
    let rc = unsafe {
        libc::getsockopt(
            conn.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        bail!("SO_PEERCRED failed");
    }
    Ok(cred.uid)
}

type Out = (Result<serde_json::Value>, Option<String>);

fn json<T: Serialize>(v: T) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(v)?)
}

fn dispatch(req: Request, server: &Mutex<Server>) -> Out {
    let now = crate::state::now();
    match &req.op {
        Op::WebConfig => {
            let r = ctx::read_only().map(
                |(cfg, _)| serde_json::json!({ "listen": cfg.web.listen, "hub": sys::hostname() }),
            );
            return (r, None);
        }
        Op::Login {
            user,
            password,
            code,
        } => {
            return (
                login(server, user, password, code, req.client, now),
                Some(user.clone()),
            )
        }
        _ => {}
    }

    // Everything else needs a live session.
    let user = {
        let mut s = server.lock().expect("lock");
        s.sessions
            .retain(|_, x| now - x.last_seen < IDLE && now - x.created < ABSOLUTE);
        let Some(tok) = req.token.as_deref() else {
            return (Err(anyhow::anyhow!("not logged in")), None);
        };
        let Some(sess) = s.sessions.get_mut(tok) else {
            return (Err(anyhow::anyhow!("not logged in")), None);
        };
        if req.op.changes_state()
            && !req
                .csrf
                .as_deref()
                .is_some_and(|c| webauth::same(c, &sess.csrf))
        {
            return (Err(anyhow::anyhow!("stale form; reload the page")), None);
        }
        sess.last_seen = now;
        sess.user.clone()
    };
    if let Some(code) = req.op.step_up_code() {
        if let Err(e) = check_code(&user, code, now) {
            return (Err(e), Some(user));
        }
    }
    let r = run_op(req, server, &user, now);
    (r, Some(user))
}

fn login(
    server: &Mutex<Server>,
    user: &str,
    password: &str,
    code: &str,
    client: Option<IpAddr>,
    now: u64,
) -> Result<serde_json::Value> {
    let keys = [format!("user:{user}"), format!("ip:{}", show(client))];
    {
        let s = server.lock().expect("lock");
        for k in &keys {
            if let Some((n, until)) = s.failures.get(k) {
                if *n >= MAX_FAILURES && now < *until {
                    bail!(
                        "too many failed logins; try again in {} minutes",
                        (until - now).div_ceil(60)
                    );
                }
            }
        }
    }
    let ok = check_login(user, password, code, now);
    let mut s = server.lock().expect("lock");
    if ok.is_err() {
        for k in keys {
            let e = s.failures.entry(k).or_insert((0, 0));
            if now >= e.1 && e.0 >= MAX_FAILURES {
                *e = (0, 0);
            }
            e.0 += 1;
            e.1 = now + LOCKOUT;
        }
        // The same answer whatever was wrong.
        bail!("wrong account, password or code");
    }
    for k in keys {
        s.failures.remove(&k);
    }
    let token = webauth::random_token();
    let csrf = webauth::random_token();
    s.sessions.insert(
        token.clone(),
        Session {
            user: user.to_string(),
            csrf: csrf.clone(),
            created: now,
            last_seen: now,
        },
    );
    Ok(serde_json::json!({ "token": token, "csrf": csrf, "user": user }))
}

/// Password, then a TOTP code or one unused recovery code.
fn check_login(user: &str, password: &str, code: &str, now: u64) -> Result<()> {
    let path = Path::new(paths::WEB_USERS_FILE);
    let mut users = Users::load(path)?;
    let Some(u) = users.users.get_mut(user) else {
        // Spend the same time as a real check, so timing does not tell
        // which accounts exist.
        static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let dummy =
            DUMMY.get_or_init(|| webauth::hash_password("dummy password").unwrap_or_default());
        let _ = webauth::verify_password(password, dummy);
        bail!("no such account");
    };
    if !webauth::verify_password(password, &u.password) {
        bail!("wrong password");
    }
    if let Some(step) = webauth::verify_totp(&u.totp_secret, code, now, u.last_step) {
        u.last_step = step;
        users.save(path)?;
        return Ok(());
    }
    let code = code.trim().to_ascii_lowercase();
    if let Some(i) = u
        .recovery
        .iter()
        .position(|h| webauth::verify_password(&code, h))
    {
        u.recovery.remove(i);
        let left = u.recovery.len();
        users.save(path)?;
        eprintln!("api: {user} used a recovery code ({left} left)");
        return Ok(());
    }
    bail!("wrong code")
}

/// A fresh TOTP code for an operation that can do harm.
fn check_code(user: &str, code: &str, now: u64) -> Result<()> {
    let path = Path::new(paths::WEB_USERS_FILE);
    let mut users = Users::load(path)?;
    let u = users.users.get_mut(user).context("account removed")?;
    match webauth::verify_totp(&u.totp_secret, code, now, u.last_step) {
        Some(step) => {
            u.last_step = step;
            users.save(path)
        }
        None => bail!("this needs a fresh code from your authenticator app"),
    }
}

fn run_op(req: Request, server: &Mutex<Server>, user: &str, now: u64) -> Result<serde_json::Value> {
    let client = req.client;
    match req.op {
        Op::WebConfig | Op::Login { .. } => unreachable!("handled before"),
        Op::Logout => {
            if let Some(t) = req.token {
                server.lock().expect("lock").sessions.remove(&t);
            }
            json(())
        }
        Op::Whoami => {
            let s = server.lock().expect("lock");
            let csrf = req
                .token
                .and_then(|t| s.sessions.get(&t).map(|x| x.csrf.clone()));
            json(serde_json::json!({ "user": user, "csrf": csrf }))
        }
        Op::Overview => {
            let cached = {
                let s = server.lock().expect("lock");
                s.claude_version
                    .clone()
                    .filter(|(t, _)| now - t < 300)
                    .map(|(_, v)| v)
            };
            let mut o = ops::overview(false)?;
            o.hub.claude_version = match cached {
                Some(v) => v,
                None => {
                    let (cfg, _) = ctx::read_only()?;
                    let v = ops::claude_version(&cfg);
                    server.lock().expect("lock").claude_version = Some((now, v.clone()));
                    v
                }
            };
            json(o)
        }
        Op::SpaceNew { space } => json(ops::space_new(space)?),
        Op::SpaceRm { name, purge, .. } => json(ops::space_rm(&name, purge)?),
        Op::SpaceRename {
            old, new, rc_name, ..
        } => json(ops::space_rename(
            &old,
            &new,
            rc_name.filter(|r| !r.is_empty()),
        )?),
        Op::SpaceControl { action, names } => {
            if names.is_empty() {
                bail!("name a space");
            }
            json(ops::space_control(action, &names)?)
        }
        Op::SpaceScreen { name } => json(ops::space_screen(&name)?),
        Op::SpaceSend {
            name,
            text,
            key,
            enter,
        } => json(ops::space_send(
            &name,
            text.as_deref(),
            key.as_deref(),
            enter,
        )?),
        Op::LoginStart { name } => json(ops::login_start(&name)?),
        Op::LoginFinish { name, code } => json(ops::login_finish(&name, &code)?),
        Op::LoginCancel { name } => {
            let (_, state) = ctx::read_only()?;
            ops::login_cancel(&state.space(&name)?.key);
            json(())
        }
        Op::BridgeAdd {
            from, to, duration, ..
        } => {
            let secs = match duration.as_deref().map(str::trim) {
                None | Some("") | Some("forever") => None,
                Some(d) => Some(ops::parse_duration(d)?),
            };
            json(ops::bridge_add(&from, &to, secs)?)
        }
        Op::BridgeRm { from, to } => json(ops::bridge_rm(&from, &to)?),
        Op::HostScan { target, port } => json(ops::host_scan(&target, port, client)?),
        Op::HostAdd {
            name,
            target,
            port,
            keys,
            ..
        } => json(ops::host_add(&name, &target, port, &keys, client)?),
        Op::HostRm { name, .. } => json(ops::host_rm(&name)?),
        Op::HostBlock {
            name,
            duration,
            reason,
        } => {
            let secs = match duration.as_deref().map(str::trim) {
                None | Some("") => None,
                Some(d) => Some(ops::parse_duration(d)?),
            };
            json(ops::host_block(&name, secs, reason)?)
        }
        Op::HostUnblock { name } => json(ops::host_unblock(&name)?),
        Op::HostPubkey { name } => json(ops::host_pubkey(&name)?),
        Op::HostCheck { name } => json(ops::host_check(&name)?),
        Op::HostRescan { name } => json(ops::host_rescan(&name)?),
        Op::HostRescanConfirm { name, keys, .. } => json(ops::host_rescan_confirm(&name, &keys)?),
        Op::HostMoveScan { name, target, port } => {
            json(ops::host_move_scan(&name, &target, port, client)?)
        }
        Op::HostMove {
            name,
            target,
            port,
            keys,
            ..
        } => json(ops::host_move(&name, &target, port, &keys, client)?),
        Op::ConfigShow => json(ops::config_show()?),
        Op::TailnetPeers => json(ops::tailnet_peers()),
        Op::ChatList { name } => json(ops::chat_list(&name)?),
        Op::ChatRename {
            name, id, title, ..
        } => json(ops::chat_rename(&name, &id, &title)?),
        Op::ChatOpen { name, id } => json(ops::chat_open(&name, id.as_deref())?),
        Op::HostRename { old, new, .. } => json(ops::host_rename(&old, &new)?),
        Op::AccountRename { new, .. } => {
            crate::web_cmd::rename_account(user, &new)?;
            let mut s = server.lock().expect("lock");
            for sess in s.sessions.values_mut() {
                if sess.user == user {
                    sess.user = new.clone();
                }
            }
            if let Some(p) = s.pending_totp.remove(user) {
                s.pending_totp.insert(new.clone(), p);
            }
            json(new)
        }
        Op::NotifyShow => json(crate::notify::view()),
        Op::NotifySet { url, token, .. } => {
            crate::notify::set(&url, token.as_deref())?;
            json(crate::notify::view())
        }
        Op::NotifyTest => json(crate::notify::test()?),
        Op::ChatRm { name, id } => json(ops::chat_rm(&name, &id)?),
        Op::SpaceRemote { name, on } => json(ops::space_set_remote(&name, on)?),
        Op::UpdateCheck { refresh } => {
            let cached = {
                let s = server.lock().expect("lock");
                s.update.clone().filter(|(t, u)| {
                    let ttl = if u.error.is_some() { 600 } else { UPDATE_EVERY };
                    !refresh && now.saturating_sub(*t) < ttl
                })
            };
            let mut info = match cached {
                Some((_, u)) => u,
                None => {
                    let u = ops::update_check();
                    server.lock().expect("lock").update = Some((now, u.clone()));
                    u
                }
            };
            info.running = matches!(
                sys::unit_state(ops::UPDATE_UNIT).as_str(),
                "active" | "activating"
            );
            json(info)
        }
        Op::Update { .. } => {
            let tag = ops::update_start()?;
            server.lock().expect("lock").update = None;
            json(tag)
        }
        Op::Account => {
            let users = Users::load(Path::new(paths::WEB_USERS_FILE))?;
            let u = users.users.get(user).context("account removed")?;
            json(serde_json::json!({ "user": user, "recovery_left": u.recovery.len() }))
        }
        Op::AccountPassword { current, new, .. } => {
            let path = Path::new(paths::WEB_USERS_FILE);
            let mut users = Users::load(path)?;
            let u = users.users.get_mut(user).context("account removed")?;
            if !webauth::verify_password(&current, &u.password) {
                bail!("the current password is wrong");
            }
            webauth::check_password_strength(&new)?;
            u.password = webauth::hash_password(&new)?;
            users.save(path)?;
            end_other_sessions(server, user, req.token.as_deref());
            json("password changed; your other logins ended")
        }
        Op::AccountTotpBegin { .. } => {
            let secret = webauth::new_secret();
            let uri = webauth::otpauth_uri(user, &sys::hostname(), &secret);
            let qr = webauth::qr_svg(&uri)?;
            server
                .lock()
                .expect("lock")
                .pending_totp
                .insert(user.to_string(), (secret.clone(), now));
            json(serde_json::json!({ "secret": secret, "qr": qr }))
        }
        Op::AccountTotpFinish { code } => {
            let pending = server
                .lock()
                .expect("lock")
                .pending_totp
                .get(user)
                .filter(|(_, t)| now - t < PENDING_TOTP)
                .cloned();
            let Some((secret, _)) = pending else {
                bail!("start again: the new authenticator was not confirmed within 10 minutes");
            };
            let Some(step) = webauth::verify_totp(&secret, &code, now, 0) else {
                bail!("that code does not match the new authenticator; check the phone's clock and try again");
            };
            let codes = webauth::new_recovery_codes();
            let path = Path::new(paths::WEB_USERS_FILE);
            let mut users = Users::load(path)?;
            let u = users.users.get_mut(user).context("account removed")?;
            u.totp_secret = secret;
            u.last_step = step;
            u.recovery = codes
                .iter()
                .map(|c| webauth::hash_password(c))
                .collect::<Result<_>>()?;
            users.save(path)?;
            server.lock().expect("lock").pending_totp.remove(user);
            end_other_sessions(server, user, req.token.as_deref());
            json(codes)
        }
        Op::ConfigSet { changes, .. } => {
            let r = ops::config_set(&changes, client, true)?;
            if r.web_moved.is_some() {
                // After this answer has gone back through the web process.
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_secs(2));
                    let _ = sys::systemctl(&["try-restart", crate::units::WEB]);
                });
            }
            json(r)
        }
    }
}

/// After a password or authenticator change: every login of `user` but
/// this one ends.
fn end_other_sessions(server: &Mutex<Server>, user: &str, keep: Option<&str>) {
    server
        .lock()
        .expect("lock")
        .sessions
        .retain(|t, s| s.user != user || Some(t.as_str()) == keep);
}

/// One example of every operation, for the test that the CLI offers each.
/// The match below has no wildcard: adding an operation fails to compile
/// until it is listed here too.
#[cfg(test)]
pub fn all_op_names() -> Vec<String> {
    let s = String::new;
    let all = vec![
        Op::WebConfig,
        Op::Login {
            user: s(),
            password: s(),
            code: s(),
        },
        Op::Logout,
        Op::Whoami,
        Op::Overview,
        Op::SpaceNew {
            space: NewSpace::default(),
        },
        Op::SpaceRm {
            name: s(),
            purge: false,
            code: s(),
        },
        Op::SpaceRename {
            old: s(),
            new: s(),
            rc_name: None,
            code: s(),
        },
        Op::SpaceControl {
            action: Action::Start,
            names: vec![],
        },
        Op::SpaceScreen { name: s() },
        Op::SpaceSend {
            name: s(),
            text: None,
            key: None,
            enter: false,
        },
        Op::LoginStart { name: s() },
        Op::LoginFinish {
            name: s(),
            code: s(),
        },
        Op::LoginCancel { name: s() },
        Op::BridgeAdd {
            from: s(),
            to: s(),
            duration: None,
            code: s(),
        },
        Op::BridgeRm { from: s(), to: s() },
        Op::HostScan {
            target: s(),
            port: 22,
        },
        Op::HostAdd {
            name: s(),
            target: s(),
            port: 22,
            keys: vec![],
            code: s(),
        },
        Op::HostRm {
            name: s(),
            code: s(),
        },
        Op::HostBlock {
            name: s(),
            duration: None,
            reason: None,
        },
        Op::HostUnblock { name: s() },
        Op::HostPubkey { name: s() },
        Op::HostCheck { name: s() },
        Op::HostRescan { name: s() },
        Op::HostRescanConfirm {
            name: s(),
            keys: vec![],
            code: s(),
        },
        Op::HostMoveScan {
            name: s(),
            target: s(),
            port: 22,
        },
        Op::HostMove {
            name: s(),
            target: s(),
            port: 22,
            keys: vec![],
            code: s(),
        },
        Op::ConfigShow,
        Op::ConfigSet {
            changes: vec![],
            code: s(),
        },
        Op::TailnetPeers,
        Op::ChatList { name: s() },
        Op::ChatRename {
            name: s(),
            id: s(),
            title: s(),
            code: s(),
        },
        Op::ChatOpen {
            name: s(),
            id: None,
        },
        Op::HostRename {
            old: s(),
            new: s(),
            code: s(),
        },
        Op::AccountRename {
            new: s(),
            code: s(),
        },
        Op::NotifyShow,
        Op::NotifySet {
            url: s(),
            token: None,
            code: s(),
        },
        Op::NotifyTest,
        Op::ChatRm { name: s(), id: s() },
        Op::SpaceRemote {
            name: s(),
            on: true,
        },
        Op::UpdateCheck { refresh: false },
        Op::Update { code: s() },
        Op::Account,
        Op::AccountPassword {
            current: s(),
            new: s(),
            code: s(),
        },
        Op::AccountTotpBegin { code: s() },
        Op::AccountTotpFinish { code: s() },
    ];
    for op in &all {
        match op {
            Op::WebConfig
            | Op::Login { .. }
            | Op::Logout
            | Op::Whoami
            | Op::Overview
            | Op::SpaceNew { .. }
            | Op::SpaceRm { .. }
            | Op::SpaceRename { .. }
            | Op::SpaceControl { .. }
            | Op::SpaceScreen { .. }
            | Op::SpaceSend { .. }
            | Op::LoginStart { .. }
            | Op::LoginFinish { .. }
            | Op::LoginCancel { .. }
            | Op::BridgeAdd { .. }
            | Op::BridgeRm { .. }
            | Op::HostScan { .. }
            | Op::HostAdd { .. }
            | Op::HostRm { .. }
            | Op::HostBlock { .. }
            | Op::HostUnblock { .. }
            | Op::HostPubkey { .. }
            | Op::HostCheck { .. }
            | Op::HostRescan { .. }
            | Op::HostRescanConfirm { .. }
            | Op::HostMoveScan { .. }
            | Op::HostMove { .. }
            | Op::ConfigShow
            | Op::ConfigSet { .. }
            | Op::TailnetPeers
            | Op::ChatList { .. }
            | Op::ChatRename { .. }
            | Op::ChatRm { .. }
            | Op::SpaceRemote { .. }
            | Op::UpdateCheck { .. }
            | Op::Update { .. }
            | Op::Account
            | Op::AccountPassword { .. }
            | Op::AccountTotpBegin { .. }
            | Op::AccountTotpFinish { .. }
            | Op::ChatOpen { .. }
            | Op::HostRename { .. }
            | Op::AccountRename { .. }
            | Op::NotifyShow
            | Op::NotifySet { .. }
            | Op::NotifyTest => {}
        }
    }
    all.iter().map(Op::name).collect()
}

/// Client side, used by the web process.
pub fn call(req: &Request) -> Result<Response> {
    let mut conn = UnixStream::connect(paths::API_SOCKET)
        .context("the blackthorn API is not running (systemctl status blackthorn-api)")?;
    conn.set_read_timeout(Some(Duration::from_secs(120)))?;
    serde_json::to_writer(&mut conn, req)?;
    conn.write_all(b"\n")?;
    let mut line = String::new();
    BufReader::new(conn).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_classified() {
        assert!(!Op::Overview.changes_state());
        assert!(Op::HostUnblock { name: "x".into() }.changes_state());
        assert!(Op::Logout.changes_state());
        let rm = Op::HostRm {
            name: "x".into(),
            code: "123456".into(),
        };
        assert_eq!(rm.step_up_code(), Some("123456"));
        assert_eq!(rm.name(), "host_rm");
        assert!(Op::HostBlock {
            name: "x".into(),
            duration: None,
            reason: None
        }
        .step_up_code()
        .is_none());
    }

    #[test]
    fn request_wire_format() {
        let r: Request = serde_json::from_str(
            r#"{"token":"t","csrf":"c","client":"100.64.0.2","op":{"op":"space_control","action":"restart","names":["fig-claude"]}}"#,
        )
        .unwrap();
        assert!(matches!(
            r.op,
            Op::SpaceControl {
                action: Action::Restart,
                ..
            }
        ));
    }
}
