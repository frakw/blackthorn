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

const MAX_FAILURES: u32 = 5;
const LOCKOUT: u64 = 15 * 60;
/// Files for chats come this way too (in base64).
const MAX_REQUEST: u64 = 16 << 20;

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub csrf: Option<String>,
    #[serde(default)]
    pub client: Option<IpAddr>,
    /// The browser's User-Agent, to tell logins apart.
    #[serde(default)]
    pub agent: Option<String>,
    /// The token that unlocks typing into chats on this browser.
    #[serde(default)]
    pub chat: Option<String>,
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
    /// The account's logins, and the browsers that may type into chats.
    SessionList,
    /// Ends one of them (by its id from SessionList).
    SessionEnd {
        id: String,
    },
    /// Ends every login and chat unlock of the account but this browser's.
    SessionEndOthers,
    /// Root commands asked for by spaces with root on approval: those the
    /// account may decide on (manage), waiting first; `all`: decided too.
    AskList {
        #[serde(default)]
        all: bool,
    },
    /// Approves or refuses one (needs the chat unlock, and manage).
    AskDecide {
        id: String,
        approve: bool,
        #[serde(default)]
        reason: String,
    },
    /// Lets this browser type into chats, for the login lifetime: asks the
    /// password and a code again.
    ChatUnlock {
        password: String,
        code: String,
    },
    /// Shares a space with an account, or (level None) stops.
    SpaceShare {
        name: String,
        account: String,
        level: Option<crate::state::Level>,
        code: String,
    },
    /// Gives a space to another account (None: the hub admins).
    SpaceOwner {
        name: String,
        account: Option<String>,
        code: String,
    },
    /// The web accounts' names, to share with.
    AccountNames,
    /// A chat's transcript from an offset (None: its latest part), and
    /// what its terminal shows.
    ChatFeed {
        name: String,
        id: String,
        from: Option<u64>,
        /// Instead: the messages before this offset (Load earlier).
        #[serde(default)]
        before: Option<u64>,
    },
    /// The slash commands a space's chats know.
    ChatCommands {
        name: String,
    },
    /// Types a message into a chat (needs the chat unlock).
    ChatSend {
        name: String,
        id: String,
        text: String,
    },
    /// Presses Escape, or a choice's number (needs the chat unlock).
    ChatKey {
        name: String,
        id: String,
        key: String,
    },
    /// Saves a file for a chat (base64; needs the chat unlock).
    ChatUpload {
        name: String,
        id: String,
        filename: String,
        data: String,
    },
    /// A Codex space's chats (see codex.rs).
    CodexChats {
        name: String,
    },
    /// A Codex chat's latest turns, unless nothing changed since `since`.
    CodexFeed {
        name: String,
        id: String,
        #[serde(default)]
        since: u64,
        #[serde(default)]
        turns: u32,
    },
    /// Starts a Codex chat with its first message (needs the chat unlock).
    CodexNew {
        name: String,
        text: String,
    },
    /// Sends a message to a Codex chat (needs the chat unlock).
    CodexSend {
        name: String,
        id: String,
        text: String,
    },
    /// Stops what Codex is doing in a chat (needs the chat unlock).
    CodexStop {
        name: String,
        id: String,
    },
    /// Answers what Codex asks (needs the chat unlock).
    CodexAnswer {
        name: String,
        id: String,
        ask: u64,
        decision: String,
        #[serde(default)]
        answers: std::collections::BTreeMap<String, String>,
    },
    CodexRename {
        name: String,
        id: String,
        title: String,
    },
    CodexArchive {
        name: String,
        id: String,
    },
    SpaceNew {
        space: NewSpace,
    },
    SpaceRm {
        name: String,
        purge: bool,
        /// Its folder on its machine (/srv/<name>) too.
        #[serde(default)]
        purge_data: bool,
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
    /// Signs a Codex space in with an OpenAI API key.
    LoginApiKey {
        name: String,
        key: String,
    },
    /// Codex on the hub: its version, an install running.
    CodexShow,
    /// Installs or updates Codex on the hub.
    CodexInstall {
        code: String,
    },
    /// Lets a space work on one more machine (admins: like making a space).
    SpaceConnect {
        name: String,
        host: String,
        access: crate::state::Access,
        code: String,
    },
    /// Takes a machine from a space. Needs no code: it only takes away.
    SpaceDisconnect {
        name: String,
        host: String,
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
    /// Tailscale on the hub.
    TailscaleShow,
    TailscaleInstall {
        code: String,
    },
    /// Signs the hub in to Tailscale.
    TailscaleUp {
        code: String,
    },
    /// Tailscale's web interface on or off.
    TailscaleWeb {
        on: bool,
        code: String,
    },
    ChatList {
        name: String,
    },
    /// A new conversation (id None), or an earlier one, becomes the one a
    /// one-conversation space runs.
    ChatOpen {
        name: String,
        id: Option<String>,
        /// A new chat's name.
        #[serde(default)]
        title: Option<String>,
    },
    /// Gives a space root on one of its machines (`host`: needed when it
    /// has several): for a time ("8h"), "forever" or "ask". `take`: from
    /// the space that has it there.
    SpaceRoot {
        name: String,
        #[serde(default)]
        host: Option<String>,
        duration: String,
        #[serde(default)]
        take: bool,
        code: String,
    },
    /// Takes a space's root back. Needs no code: it only takes away.
    SpaceRootOff {
        name: String,
        #[serde(default)]
        host: Option<String>,
    },
    /// A space's usual login on one of its machines. Up (to user) takes a
    /// code; down does not.
    SpaceAccess {
        name: String,
        #[serde(default)]
        host: Option<String>,
        access: crate::state::Access,
        #[serde(default)]
        code: String,
    },
    HostSetup {
        name: String,
        code: String,
    },
    /// The latest commands a space ran.
    Activity {
        name: String,
        limit: usize,
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
    /// A WebAuthn challenge: purpose "login" (no session needed),
    /// "register" or "step_up".
    PasskeyBegin {
        purpose: String,
    },
    /// Logs in with a passkey (instead of password and code).
    PasskeyLogin {
        answer: crate::webauthn::Answer,
    },
    PasskeyAdd {
        name: String,
        answer: crate::webauthn::Answer,
        code: String,
    },
    PasskeyRm {
        id: String,
        code: String,
    },
    ChatRm {
        name: String,
        id: String,
    },
    /// Stops a chat the hub started in a window of its own.
    ChatStop {
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
                | Op::SessionList
                | Op::AccountNames
                | Op::ChatFeed { .. }
                | Op::ChatCommands { .. }
                | Op::CodexChats { .. }
                | Op::CodexFeed { .. }
                | Op::SpaceScreen { .. }
                | Op::HostPubkey { .. }
                | Op::ConfigShow
                | Op::TailnetPeers
                | Op::TailscaleShow
                | Op::ChatList { .. }
                | Op::Activity { .. }
                | Op::UpdateCheck { .. }
                | Op::CodexShow
                | Op::Account
                | Op::NotifyShow
                | Op::PasskeyLogin { .. }
        )
    }

    /// Typing into a chat needs this browser's chat unlock.
    fn needs_chat_unlock(&self) -> bool {
        matches!(
            self,
            Op::ChatSend { .. }
                | Op::ChatKey { .. }
                | Op::ChatUpload { .. }
                | Op::AskDecide { .. }
                | Op::CodexNew { .. }
                | Op::CodexSend { .. }
                | Op::CodexStop { .. }
                | Op::CodexAnswer { .. }
        )
    }

    fn step_up_code(&self) -> Option<&str> {
        match self {
            Op::SpaceRm { code, .. }
            | Op::SpaceConnect { code, .. }
            | Op::HostAdd { code, .. }
            | Op::HostRm { code, .. }
            | Op::HostRescanConfirm { code, .. }
            | Op::HostMove { code, .. }
            | Op::ConfigSet { code, .. }
            | Op::Update { code, .. }
            | Op::CodexInstall { code }
            | Op::AccountPassword { code, .. }
            | Op::AccountTotpBegin { code }
            | Op::SpaceRename { code, .. }
            | Op::HostRename { code, .. }
            | Op::AccountRename { code, .. }
            | Op::NotifySet { code, .. }
            | Op::PasskeyAdd { code, .. }
            | Op::PasskeyRm { code, .. }
            | Op::SpaceRoot { code, .. }
            | Op::HostSetup { code, .. }
            | Op::TailscaleInstall { code }
            | Op::TailscaleUp { code }
            | Op::TailscaleWeb { code, .. }
            | Op::SpaceShare { code, .. }
            | Op::SpaceOwner { code, .. } => Some(code),
            Op::SpaceAccess { access, code, .. } if *access != crate::state::Access::Readonly => {
                Some(code)
            }
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

/// A login, or a chat unlock. Kept by the hash of its token.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Session {
    /// Shown, and used to end it; not the token.
    id: String,
    user: String,
    #[serde(default)]
    csrf: String,
    created: u64,
    last_seen: u64,
    /// "password", "passkey"; "chat" for a chat unlock.
    #[serde(default)]
    how: String,
    #[serde(default)]
    agent: String,
    #[serde(default)]
    ip: Option<IpAddr>,
    #[serde(default)]
    login_ip: Option<IpAddr>,
}

#[derive(Default, Serialize, Deserialize)]
struct Stored {
    #[serde(default)]
    sessions: HashMap<String, Session>,
    #[serde(default)]
    unlocks: HashMap<String, Session>,
}

/// What the account's logins page shows of one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionView {
    pub id: String,
    /// A login, or a chat unlock.
    pub chat: bool,
    pub how: String,
    pub browser: String,
    pub os: String,
    pub device: String,
    pub agent: String,
    pub ip: Option<IpAddr>,
    pub login_ip: Option<IpAddr>,
    pub created: u64,
    pub last_seen: u64,
    pub expires: u64,
    /// This browser's.
    pub current: bool,
}

#[derive(Default)]
struct Server {
    sessions: HashMap<String, Session>,
    unlocks: HashMap<String, Session>,
    /// When the sessions were last written to disk.
    saved: u64,
    /// When the settings were read: web.session_hours in seconds, and how
    /// long a login may go unused (None: as long as it lasts).
    lifetime: Option<(u64, u64, Option<u64>)>,
    /// Failed logins per account and per client address.
    failures: HashMap<String, (u32, u64)>,
    /// `claude --version` is slow; cache it.
    claude_version: Option<(u64, Option<String>)>,
    /// Asking GitHub for the latest release, at most every few hours.
    update: Option<(u64, ops::UpdateInfo)>,
    /// Authenticator secrets being set up, per account.
    pending_totp: HashMap<String, (String, u64)>,
    /// WebAuthn challenges handed out: challenge -> (purpose, account,
    /// expiry). Each is used once.
    challenges: HashMap<String, (String, Option<String>, u64)>,
}

const CHALLENGE_TTL: u64 = 300;

/// A token as it is kept: its SHA-256, so the file does not hold them.
fn token_key(token: &str) -> String {
    webauth::hex(ring::digest::digest(&ring::digest::SHA256, token.as_bytes()).as_ref())
}

/// The longest a browser's User-Agent is kept.
fn agent_of(a: Option<&str>) -> String {
    a.unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(300)
        .collect()
}

impl Server {
    fn load() -> Server {
        let stored: Stored = std::fs::read_to_string(paths::WEB_SESSIONS_FILE)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        Server {
            sessions: stored.sessions,
            unlocks: stored.unlocks,
            ..Server::default()
        }
    }

    /// Writes the sessions now, or (`force` false) if a minute has passed.
    fn save(&mut self, now: u64, force: bool) {
        if !force && now < self.saved + 60 {
            return;
        }
        self.saved = now;
        let stored = Stored {
            sessions: self.sessions.clone(),
            unlocks: self.unlocks.clone(),
        };
        if let Ok(text) = serde_json::to_string(&stored) {
            if let Err(e) = sys::write_file(Path::new(paths::WEB_SESSIONS_FILE), &text, 0o600, None)
            {
                eprintln!("api: saving the web sessions: {e:#}");
            }
        }
    }

    /// How long a login (and a chat unlock) lasts.
    fn lifetime(&mut self, now: u64) -> u64 {
        self.limits(now).0
    }

    /// How long a login lasts, and may go unused.
    fn limits(&mut self, now: u64) -> (u64, Option<u64>) {
        match self.lifetime {
            Some((at, secs, idle)) if now < at + 60 => (secs, idle),
            _ => {
                let web = crate::config::Config::load(Path::new(paths::CONFIG_FILE))
                    .map(|c| c.web)
                    .unwrap_or_default();
                let secs = u64::from(web.session_hours.clamp(1, 720)) * 3600;
                let idle = web
                    .idle_logout
                    .then(|| u64::from(web.idle_minutes.clamp(1, 1440)) * 60);
                self.lifetime = Some((now, secs, idle));
                (secs, idle)
            }
        }
    }

    /// Drops what has expired; writes the change.
    fn expire(&mut self, now: u64) {
        let (life, idle) = self.limits(now);
        let before = self.sessions.len() + self.unlocks.len();
        self.sessions.retain(|_, x| {
            idle.map_or(true, |i| now.saturating_sub(x.last_seen) < i)
                && now.saturating_sub(x.created) < life
        });
        self.unlocks
            .retain(|_, x| now.saturating_sub(x.created) < life);
        if self.sessions.len() + self.unlocks.len() != before {
            self.save(now, true);
        }
    }
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

    let server = Arc::new(Mutex::new(Server::load()));
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
            // The web process needs the TLS key to serve HTTPS; it gets it
            // here because it cannot read the key file itself.
            let r = ctx::read_only().and_then(|(cfg, _)| {
                Ok(serde_json::json!({
                    "listen": cfg.web.listen,
                    "hub": sys::hostname(),
                    "tls": crate::tls::material(&cfg)?,
                }))
            });
            return (r, None);
        }
        Op::Login {
            user,
            password,
            code,
        } => {
            return (
                login(server, user, password, code, &req, now),
                Some(user.clone()),
            )
        }
        Op::PasskeyBegin { purpose } if purpose == "login" => {
            return (passkey_begin(server, "login", None, now), None);
        }
        Op::PasskeyLogin { answer } => return passkey_login(server, answer, &req, now),
        _ => {}
    }

    // Everything else needs a live session.
    let user = {
        let mut s = server.lock().expect("lock");
        s.expire(now);
        let Some(tok) = req.token.as_deref() else {
            return (Err(anyhow::anyhow!("not logged in")), None);
        };
        let Some(sess) = s.sessions.get_mut(&token_key(tok)) else {
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
        if req.client.is_some() {
            sess.ip = req.client;
        }
        let user = sess.user.clone();
        if req.op.needs_chat_unlock() {
            let unlocked = req
                .chat
                .as_deref()
                .and_then(|t| s.unlocks.get_mut(&token_key(t)))
                .filter(|x| x.user == user);
            match unlocked {
                Some(x) => {
                    x.last_seen = now;
                    if req.client.is_some() {
                        x.ip = req.client;
                    }
                }
                None => {
                    return (
                        Err(anyhow::anyhow!(
                            "this browser may not type into chats yet: unlock it with your password and a code"
                        )),
                        Some(user),
                    )
                }
            }
        }
        s.save(now, false);
        user
    };
    let admin = match Users::load(Path::new(paths::WEB_USERS_FILE))
        .ok()
        .and_then(|u| u.users.get(&user).map(|x| x.admin))
    {
        Some(a) => a,
        None => return (Err(anyhow::anyhow!("this account is gone")), Some(user)),
    };
    if let Err(e) = authorize(&req.op, &user, admin) {
        return (Err(e), Some(user));
    }
    if let Some(code) = req.op.step_up_code() {
        if let Err(e) = check_step_up(server, &user, code, now) {
            return (Err(e), Some(user));
        }
    }
    let r = run_op(req, server, &user, admin, now);
    (r, Some(user))
}

/// What an operation needs of the account asking.
enum Need {
    /// Any logged-in account (its own things, or filtered).
    Login,
    /// A hub admin: machines, settings, the hub.
    Admin,
    /// This far with each of these spaces.
    Spaces(Vec<String>, crate::state::Level),
}

fn need(op: &Op) -> Need {
    use crate::state::Level::{Manage, Owner, Use, View};
    let one = |n: &String, l| Need::Spaces(vec![n.clone()], l);
    match op {
        Op::WebConfig
        | Op::Login { .. }
        | Op::Logout
        | Op::Whoami
        | Op::Overview
        | Op::SessionList
        | Op::SessionEnd { .. }
        | Op::SessionEndOthers
        | Op::ChatUnlock { .. }
        | Op::AskList { .. }
        | Op::AskDecide { .. }
        | Op::AccountNames
        | Op::Account
        | Op::AccountPassword { .. }
        | Op::AccountTotpBegin { .. }
        | Op::AccountTotpFinish { .. }
        | Op::AccountRename { .. }
        | Op::PasskeyBegin { .. }
        | Op::PasskeyLogin { .. }
        | Op::PasskeyAdd { .. }
        | Op::PasskeyRm { .. } => Need::Login,
        Op::SpaceNew { .. }
        | Op::SpaceConnect { .. }
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
        | Op::HostRename { .. }
        | Op::HostSetup { .. }
        | Op::ConfigShow
        | Op::ConfigSet { .. }
        | Op::TailnetPeers
        | Op::TailscaleShow
        | Op::TailscaleInstall { .. }
        | Op::TailscaleUp { .. }
        | Op::TailscaleWeb { .. }
        | Op::NotifyShow
        | Op::NotifySet { .. }
        | Op::NotifyTest
        | Op::UpdateCheck { .. }
        | Op::Update { .. }
        | Op::CodexShow
        | Op::CodexInstall { .. } => Need::Admin,
        Op::ChatFeed { name, .. }
        | Op::ChatCommands { name }
        | Op::SpaceScreen { name }
        | Op::ChatList { name }
        | Op::CodexChats { name }
        | Op::CodexFeed { name, .. }
        | Op::Activity { name, .. } => one(name, View),
        Op::ChatSend { name, .. }
        | Op::ChatKey { name, .. }
        | Op::ChatUpload { name, .. }
        | Op::ChatOpen { name, .. }
        | Op::ChatStop { name, .. }
        | Op::CodexNew { name, .. }
        | Op::CodexSend { name, .. }
        | Op::CodexStop { name, .. }
        | Op::CodexAnswer { name, .. }
        | Op::CodexRename { name, .. }
        | Op::SpaceSend { name, .. }
        | Op::SpaceRootOff { name, .. } => one(name, Use),
        Op::SpaceAccess { name, access, .. } => one(
            name,
            if *access == crate::state::Access::Readonly {
                Use
            } else {
                Manage
            },
        ),
        Op::SpaceControl { names, .. } => Need::Spaces(names.clone(), Use),
        Op::SpaceRm { name, .. }
        | Op::LoginStart { name }
        | Op::LoginFinish { name, .. }
        | Op::LoginCancel { name }
        | Op::LoginApiKey { name, .. }
        | Op::SpaceRoot { name, .. }
        | Op::SpaceRemote { name, .. }
        | Op::ChatRm { name, .. }
        | Op::CodexArchive { name, .. }
        | Op::SpaceShare { name, .. } => one(name, Manage),
        Op::SpaceRename { old, .. } => one(old, Manage),
        Op::SpaceDisconnect { name, .. } => one(name, Manage),
        Op::SpaceOwner { name, .. } => one(name, Owner),
    }
}

/// Refuses what the account may not do. Hub admins may do everything.
fn authorize(op: &Op, user: &str, admin: bool) -> Result<()> {
    if admin {
        return Ok(());
    }
    match need(op) {
        Need::Login => Ok(()),
        Need::Admin => bail!("only a hub admin may do that"),
        Need::Spaces(names, want) => {
            let (_, state) = ctx::read_only()?;
            for n in &names {
                let has = state.spaces.get(n).and_then(|s| s.level(user, false));
                match has {
                    None => bail!("no space named {n}"),
                    Some(l) if l < want => bail!(
                        "you may {} {n}; that needs {want}",
                        match l {
                            crate::state::Level::View => "only view",
                            crate::state::Level::Use => "only use",
                            _ => "only manage",
                        }
                    ),
                    Some(_) => {}
                }
            }
            Ok(())
        }
    }
}

fn login(
    server: &Mutex<Server>,
    user: &str,
    password: &str,
    code: &str,
    req: &Request,
    now: u64,
) -> Result<serde_json::Value> {
    check_password_and_code(server, user, password, code, req.client, now)?;
    let mut s = server.lock().expect("lock");
    Ok(new_session(&mut s, user, now, req, "password"))
}

/// Password and a code, counting failures per account and address.
fn check_password_and_code(
    server: &Mutex<Server>,
    user: &str,
    password: &str,
    code: &str,
    client: Option<IpAddr>,
    now: u64,
) -> Result<()> {
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
    Ok(())
}

fn new_session(
    s: &mut Server,
    user: &str,
    now: u64,
    req: &Request,
    how: &str,
) -> serde_json::Value {
    let token = webauth::random_token();
    let csrf = webauth::random_token();
    s.sessions.insert(
        token_key(&token),
        Session {
            id: webauth::hex(&webauth::random_bytes::<8>()),
            user: user.to_string(),
            csrf: csrf.clone(),
            created: now,
            last_seen: now,
            how: how.into(),
            agent: agent_of(req.agent.as_deref()),
            ip: req.client,
            login_ip: req.client,
        },
    );
    let life = s.lifetime(now);
    s.save(now, true);
    serde_json::json!({ "token": token, "csrf": csrf, "user": user, "max_age": life })
}

/// The account's logins and chat unlocks, newest use first.
fn session_list(
    s: &mut Server,
    user: &str,
    token: Option<&str>,
    chat: Option<&str>,
    now: u64,
) -> Vec<SessionView> {
    let (life, idle) = s.limits(now);
    let mine = token.map(token_key);
    let chat = chat.map(token_key);
    let view = |k: &String, x: &Session, is_chat: bool| {
        let (browser, os, device) = webauth::describe_agent(&x.agent);
        let idle_end = match idle {
            Some(i) if !is_chat => x.last_seen + i,
            _ => u64::MAX,
        };
        SessionView {
            id: x.id.clone(),
            chat: is_chat,
            how: x.how.clone(),
            browser,
            os,
            device,
            agent: x.agent.clone(),
            ip: x.ip,
            login_ip: x.login_ip,
            created: x.created,
            last_seen: x.last_seen,
            expires: (x.created + life).min(idle_end),
            current: Some(k)
                == if is_chat {
                    chat.as_ref()
                } else {
                    mine.as_ref()
                },
        }
    };
    let mut v: Vec<SessionView> = s
        .sessions
        .iter()
        .filter(|(_, x)| x.user == user)
        .map(|(k, x)| view(k, x, false))
        .chain(
            s.unlocks
                .iter()
                .filter(|(_, x)| x.user == user)
                .map(|(k, x)| view(k, x, true)),
        )
        .collect();
    v.sort_by_key(|x| (std::cmp::Reverse(x.current), std::cmp::Reverse(x.last_seen)));
    v
}

/// The hub's WebAuthn identity: its HTTPS name and the origins of its pages.
fn site() -> Result<(String, Vec<String>)> {
    let (cfg, _) = ctx::read_only()?;
    if !cfg.web.https() {
        bail!("passkeys need the web UI on HTTPS (see: thorn web https)");
    }
    Ok((cfg.web.name.clone(), crate::tls::origins(&cfg.web)))
}

fn passkey_begin(
    server: &Mutex<Server>,
    purpose: &str,
    user: Option<&str>,
    now: u64,
) -> Result<serde_json::Value> {
    let (rp_id, _) = site()?;
    let mut credentials = Vec::new();
    if let Some(u) = user {
        let users = Users::load(Path::new(paths::WEB_USERS_FILE))?;
        let acct = users.users.get(u).context("account removed")?;
        credentials = acct.passkeys.iter().map(|p| p.id.clone()).collect();
        if purpose == "step_up" && credentials.is_empty() {
            bail!("this account has no passkey; use a code from your authenticator app");
        }
    }
    let challenge = crate::webauthn::b64(&webauth::random_bytes::<32>());
    {
        let mut s = server.lock().expect("lock");
        s.challenges.retain(|_, c| c.2 > now);
        if s.challenges.len() > 1000 {
            bail!("too many passkey requests at once; try again in a few minutes");
        }
        s.challenges.insert(
            challenge.clone(),
            (
                purpose.to_string(),
                user.map(String::from),
                now + CHALLENGE_TTL,
            ),
        );
    }
    let user_name = user.unwrap_or("").to_string();
    let user_id = if user_name.is_empty() {
        String::new()
    } else {
        use sha2::Digest;
        let h = sha2::Sha256::digest(format!("blackthorn:{user_name}").as_bytes());
        crate::webauthn::b64(&h[..16])
    };
    json(crate::webauthn::Options {
        challenge,
        rp_id,
        rp_name: format!("blackthorn on {}", sys::hostname()),
        user_id,
        user_name,
        credentials,
    })
}

/// Takes back the challenge an answer carries, if it was handed out for
/// this purpose (and account) and has not expired. Each works once.
fn take_challenge(
    server: &Mutex<Server>,
    answer: &crate::webauthn::Answer,
    purpose: &str,
    user: Option<&str>,
    now: u64,
) -> Result<String> {
    let client = crate::webauthn::unb64(&answer.client_data)?;
    let v: serde_json::Value = serde_json::from_slice(&client).context("clientDataJSON")?;
    let ch = v["challenge"]
        .as_str()
        .unwrap_or("")
        .trim_end_matches('=')
        .to_string();
    let mut s = server.lock().expect("lock");
    match s.challenges.remove(&ch) {
        Some((p, u, until)) if p == purpose && u.as_deref() == user && until > now => Ok(ch),
        _ => bail!("the passkey request expired or was already used; try again"),
    }
}

fn passkey_login(
    server: &Mutex<Server>,
    answer: &crate::webauthn::Answer,
    req: &Request,
    now: u64,
) -> Out {
    let ip_key = format!("ip:{}", show(req.client));
    {
        let s = server.lock().expect("lock");
        if let Some((n, until)) = s.failures.get(&ip_key) {
            if *n >= MAX_FAILURES && now < *until {
                let mins = (until - now).div_ceil(60);
                return (
                    Err(anyhow::anyhow!(
                        "too many failed logins; try again in {mins} minutes"
                    )),
                    None,
                );
            }
        }
    }
    let r = (|| -> Result<String> {
        let ch = take_challenge(server, answer, "login", None, now)?;
        let (rp_id, origins) = site()?;
        let site = crate::webauthn::Site {
            rp_id: &rp_id,
            origins: &origins,
        };
        let path = Path::new(paths::WEB_USERS_FILE);
        let mut users = Users::load(path)?;
        let id = answer.id.trim_end_matches('=');
        let (name, u) = users
            .users
            .iter_mut()
            .find(|(_, u)| u.passkeys.iter().any(|p| p.id == id))
            .context("this passkey is not registered here")?;
        let name = name.clone();
        let pk = u.passkeys.iter_mut().find(|p| p.id == id).expect("found");
        pk.counter = crate::webauthn::verify(answer, &ch, &site, pk)?;
        users.save(path)?;
        Ok(name)
    })();
    let mut s = server.lock().expect("lock");
    match r {
        Ok(user) => {
            s.failures.remove(&ip_key);
            eprintln!("api: {user} logged in with a passkey");
            (
                Ok(new_session(&mut s, &user, now, req, "passkey")),
                Some(user),
            )
        }
        Err(e) => {
            let f = s.failures.entry(ip_key).or_insert((0, 0));
            if now >= f.1 && f.0 >= MAX_FAILURES {
                *f = (0, 0);
            }
            f.0 += 1;
            f.1 = now + LOCKOUT;
            (Err(e), None)
        }
    }
}

/// A fresh TOTP code, or a passkey answer (JSON), for an operation that
/// can do harm.
fn check_step_up(server: &Mutex<Server>, user: &str, code: &str, now: u64) -> Result<()> {
    if !code.trim_start().starts_with('{') {
        return check_code(user, code, now);
    }
    let answer: crate::webauthn::Answer = serde_json::from_str(code).context("passkey answer")?;
    let ch = take_challenge(server, &answer, "step_up", Some(user), now)?;
    let (rp_id, origins) = site()?;
    let site = crate::webauthn::Site {
        rp_id: &rp_id,
        origins: &origins,
    };
    let path = Path::new(paths::WEB_USERS_FILE);
    let mut users = Users::load(path)?;
    let u = users.users.get_mut(user).context("account removed")?;
    let id = answer.id.trim_end_matches('=');
    let pk = u
        .passkeys
        .iter_mut()
        .find(|p| p.id == id)
        .context("that passkey is not one of this account's")?;
    pk.counter = crate::webauthn::verify(&answer, &ch, &site, pk)?;
    users.save(path)
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

fn run_op(
    req: Request,
    server: &Mutex<Server>,
    user: &str,
    admin: bool,
    now: u64,
) -> Result<serde_json::Value> {
    let client = req.client;
    match req.op {
        Op::WebConfig | Op::Login { .. } => unreachable!("handled before"),
        Op::Logout => {
            if let Some(t) = &req.token {
                let mut s = server.lock().expect("lock");
                s.sessions.remove(&token_key(t));
                s.save(now, true);
            }
            json(())
        }
        Op::ChatFeed {
            name,
            id,
            from,
            before,
        } => {
            let mut f = crate::chat::feed(&name, &id, from, before)?;
            let (_, st) = ctx::read_only()?;
            let sp = st.space(&name)?;
            f.level = sp.level(user, admin);
            if f.level >= Some(crate::state::Level::Manage) {
                f.asks = crate::asks::list()
                    .into_iter()
                    .filter(|a| a.key == sp.key && a.waiting())
                    .collect();
            }
            json(f)
        }
        Op::AskList { all } => {
            let (_, st) = ctx::read_only()?;
            let may = |a: &crate::asks::Ask| {
                st.space_by_key(&a.key)
                    .is_some_and(|(_, s)| s.level(user, admin) >= Some(crate::state::Level::Manage))
                    || admin
            };
            json(
                crate::asks::list()
                    .into_iter()
                    .filter(|a| (all || a.waiting()) && may(a))
                    .take(if all { 100 } else { usize::MAX })
                    .collect::<Vec<_>>(),
            )
        }
        Op::AskDecide {
            id,
            approve,
            reason,
        } => {
            let a = crate::asks::get(&id).with_context(|| format!("no ask {id}"))?;
            let (_, st) = ctx::read_only()?;
            let ok = admin
                || st.space_by_key(&a.key).is_some_and(|(_, s)| {
                    s.level(user, admin) >= Some(crate::state::Level::Manage)
                });
            if !ok {
                bail!(
                    "only who may manage {} decides on its root commands",
                    a.space
                );
            }
            json(crate::asks::decide(&id, approve, user, &reason)?)
        }
        Op::ChatCommands { name } => json(crate::chat::commands(&name)?),
        Op::CodexChats { name } => json(crate::codex::chats(&name)?),
        Op::CodexFeed {
            name,
            id,
            since,
            turns,
        } => {
            let mut f = crate::codex::feed(&name, &id, since, if turns == 0 { 30 } else { turns })?;
            let (_, st) = ctx::read_only()?;
            f.level = st.space(&name)?.level(user, admin);
            json(f)
        }
        Op::CodexNew { name, text } => json(crate::codex::new(&name, &text, user)?),
        Op::CodexSend { name, id, text } => json(crate::codex::send(&name, &id, &text, user)?),
        Op::CodexStop { name, id } => json(crate::codex::stop(&name, &id, user)?),
        Op::CodexAnswer {
            name,
            id,
            ask,
            decision,
            answers,
        } => json(crate::codex::answer(
            &name, &id, ask, &decision, &answers, user,
        )?),
        Op::CodexRename { name, id, title } => json(crate::codex::rename(&name, &id, &title)?),
        Op::CodexArchive { name, id } => json(crate::codex::archive(&name, &id)?),
        Op::ChatSend { name, id, text } => json(crate::chat::send(&name, &id, &text, user)?),
        Op::ChatKey { name, id, key } => json(crate::chat::key(&name, &id, &key, user)?),
        Op::ChatUpload {
            name,
            id,
            filename,
            data,
        } => {
            use base64::Engine as _;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data.trim())
                .context("the file did not arrive whole")?;
            json(crate::chat::upload(&name, &id, &filename, &bytes, user)?)
        }
        Op::SessionList => {
            let mut s = server.lock().expect("lock");
            json(session_list(
                &mut s,
                user,
                req.token.as_deref(),
                req.chat.as_deref(),
                now,
            ))
        }
        Op::SessionEnd { id } => {
            let mut s = server.lock().expect("lock");
            let before = s.sessions.len() + s.unlocks.len();
            s.sessions.retain(|_, x| !(x.user == user && x.id == id));
            s.unlocks.retain(|_, x| !(x.user == user && x.id == id));
            if s.sessions.len() + s.unlocks.len() == before {
                bail!("no such login (it may have ended already)");
            }
            s.save(now, true);
            json(())
        }
        Op::SessionEndOthers => {
            end_other_sessions(server, user, req.token.as_deref(), req.chat.as_deref());
            json(())
        }
        Op::ChatUnlock { password, code } => {
            check_password_and_code(server, user, &password, &code, req.client, now)?;
            let token = webauth::random_token();
            let mut s = server.lock().expect("lock");
            s.unlocks.insert(
                token_key(&token),
                Session {
                    id: webauth::hex(&webauth::random_bytes::<8>()),
                    user: user.to_string(),
                    csrf: String::new(),
                    created: now,
                    last_seen: now,
                    how: "chat".into(),
                    agent: agent_of(req.agent.as_deref()),
                    ip: req.client,
                    login_ip: req.client,
                },
            );
            let life = s.lifetime(now);
            s.save(now, true);
            json(serde_json::json!({ "token": token, "max_age": life }))
        }
        Op::Whoami => {
            let s = server.lock().expect("lock");
            let mine = req
                .token
                .as_deref()
                .and_then(|t| s.sessions.get(&token_key(t)));
            let csrf = mine.map(|x| x.csrf.clone());
            let session = mine.map(|x| x.id.clone());
            let chat = req
                .chat
                .as_deref()
                .and_then(|t| s.unlocks.get(&token_key(t)))
                .is_some_and(|x| x.user == user);
            drop(s);
            // Whether this account can step up with a passkey.
            let passkey = ctx::read_only().is_ok_and(|(c, _)| c.web.https())
                && Users::load(Path::new(paths::WEB_USERS_FILE))
                    .is_ok_and(|u| u.users.get(user).is_some_and(|x| !x.passkeys.is_empty()));
            json(serde_json::json!({
                "user": user, "csrf": csrf, "passkey": passkey, "session": session, "chat": chat,
                "admin": admin,
            }))
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
            see_only_yours(&mut o, user, admin)?;
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
        Op::SpaceNew { mut space } => {
            space.owner = Some(user.to_string());
            json(ops::space_new(space)?)
        }
        Op::SpaceShare {
            name,
            account,
            level,
            ..
        } => json(ops::space_share(&name, &account, level)?),
        Op::SpaceOwner { name, account, .. } => json(ops::space_owner(&name, account.as_deref())?),
        Op::AccountNames => json(
            Users::load(Path::new(paths::WEB_USERS_FILE))?
                .users
                .into_keys()
                .collect::<Vec<_>>(),
        ),
        Op::SpaceRm {
            name,
            purge,
            purge_data,
            ..
        } => json(ops::space_rm(&name, purge, purge_data)?),
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
        } => {
            ops::space_send(&name, text.as_deref(), key.as_deref(), enter)?;
            // Typed on the space's terminal: recorded like a chat message.
            if let Ok((_, st)) = ctx::read_only() {
                if let Ok(sp) = st.space(&name) {
                    let what = match (&text, &key) {
                        (Some(t), _) if !t.is_empty() => t.clone(),
                        (_, Some(k)) => format!("[{k}]"),
                        _ => "[Enter]".into(),
                    };
                    let _ = crate::activity::record(&sp.key, "terminal", user, &what, "");
                }
            }
            json(())
        }
        Op::LoginStart { name } => json(ops::login_start(&name)?),
        Op::LoginFinish { name, code } => json(ops::login_finish(&name, &code)?),
        Op::LoginApiKey { name, key } => json(ops::login_api_key(&name, &key)?),
        Op::CodexShow => json(ops::codex_view()?),
        Op::CodexInstall { .. } => json(ops::codex_install()?),
        Op::LoginCancel { name } => {
            let (_, state) = ctx::read_only()?;
            ops::login_cancel(&state.space(&name)?.key);
            json(())
        }
        Op::SpaceConnect {
            name, host, access, ..
        } => json(ops::space_connect(&name, &host, Some(access))?),
        Op::SpaceDisconnect { name, host } => json(ops::space_disconnect(&name, &host)?),
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
        Op::TailscaleShow => json(ops::tailscale_view()),
        Op::TailscaleInstall { .. } => json(ops::tailscale_install()?),
        Op::TailscaleUp { .. } => json(ops::tailscale_up()?),
        Op::TailscaleWeb { on, .. } => json(ops::tailscale_web(on)?),
        Op::ChatList { name } => json(ops::chat_list(&name)?),
        Op::ChatOpen { name, id, title } => {
            json(ops::chat_open(&name, id.as_deref(), title.as_deref())?)
        }
        Op::SpaceRoot {
            name,
            host,
            duration,
            take,
            ..
        } => {
            let root = ops::parse_root(&duration)?;
            if root.is_none() {
                bail!("say for how long, or forever");
            }
            json(ops::space_root(&name, host.as_deref(), root, take)?)
        }
        Op::SpaceRootOff { name, host } => {
            json(ops::space_root(&name, host.as_deref(), None, false)?)
        }
        Op::SpaceAccess {
            name, host, access, ..
        } => json(ops::space_login(&name, host.as_deref(), access)?),
        Op::HostSetup { name, .. } => json(crate::logins::setup(&name, true)?),
        Op::Activity { name, limit } => json(crate::activity::list(&name, limit.min(500))?),
        Op::HostRename { old, new, .. } => json(ops::host_rename(&old, &new)?),
        Op::AccountRename { new, .. } => {
            crate::web_cmd::rename_account(user, &new)?;
            let mut s = server.lock().expect("lock");
            let srv = &mut *s;
            for sess in srv.sessions.values_mut().chain(srv.unlocks.values_mut()) {
                if sess.user == user {
                    sess.user = new.clone();
                }
            }
            s.save(now, true);
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
        Op::PasskeyLogin { .. } => unreachable!("handled before"),
        Op::PasskeyBegin { purpose } => match purpose.as_str() {
            "register" | "step_up" => passkey_begin(server, &purpose, Some(user), now),
            _ => bail!("unknown passkey purpose"),
        },
        Op::PasskeyAdd { name, answer, .. } => {
            let name = name.trim();
            if name.is_empty() || name.chars().count() > 60 || name.chars().any(char::is_control) {
                bail!("give the passkey a name of 1 to 60 characters, such as \"iPhone\" or \"YubiKey\"");
            }
            let ch = take_challenge(server, &answer, "register", Some(user), now)?;
            let (rp_id, origins) = site()?;
            let site = crate::webauthn::Site {
                rp_id: &rp_id,
                origins: &origins,
            };
            let pk = crate::webauthn::register(&answer, &ch, &site, name, now)?;
            let path = Path::new(paths::WEB_USERS_FILE);
            let mut users = Users::load(path)?;
            if users
                .users
                .values()
                .any(|u| u.passkeys.iter().any(|p| p.id == pk.id))
            {
                bail!("this passkey is already registered");
            }
            let u = users.users.get_mut(user).context("account removed")?;
            if u.passkeys.len() >= 20 {
                bail!("an account holds at most 20 passkeys");
            }
            u.passkeys.push(pk);
            users.save(path)?;
            json(format!("passkey {name} added"))
        }
        Op::PasskeyRm { id, .. } => {
            let path = Path::new(paths::WEB_USERS_FILE);
            let mut users = Users::load(path)?;
            let u = users.users.get_mut(user).context("account removed")?;
            let before = u.passkeys.len();
            u.passkeys.retain(|p| p.id != id);
            if u.passkeys.len() == before {
                bail!("no such passkey");
            }
            users.save(path)?;
            json("passkey removed")
        }
        Op::ChatRm { name, id } => json(ops::chat_rm(&name, &id)?),
        Op::ChatStop { name, id } => json(ops::chat_stop(&name, &id)?),
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
            let passkeys: Vec<serde_json::Value> = u
                .passkeys
                .iter()
                .map(|p| serde_json::json!({ "id": p.id, "name": p.name, "added": p.added }))
                .collect();
            let https = ctx::read_only()
                .map(|(c, _)| c.web.https())
                .unwrap_or(false);
            json(serde_json::json!({
                "user": user,
                "recovery_left": u.recovery.len(),
                "passkeys": passkeys,
                "https": https,
            }))
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
            end_other_sessions(server, user, req.token.as_deref(), req.chat.as_deref());
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
            end_other_sessions(server, user, req.token.as_deref(), req.chat.as_deref());
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

/// What an account that is not a hub admin sees of the hub: the spaces
/// it may see (and how far), and their machines.
fn see_only_yours(o: &mut ops::Overview, user: &str, admin: bool) -> Result<()> {
    let (_, state) = ctx::read_only()?;
    for s in &mut o.spaces {
        s.level = state.spaces.get(&s.name).and_then(|x| x.level(user, admin));
    }
    if admin {
        return Ok(());
    }
    o.spaces.retain(|s| s.level.is_some());
    for s in &mut o.spaces {
        // Who else it is shared with is for those who manage it.
        if s.level < Some(crate::state::Level::Manage) {
            s.shares.clear();
        }
    }
    let seen: std::collections::BTreeSet<String> =
        o.spaces.iter().map(|s| s.name.clone()).collect();
    let machines: std::collections::BTreeSet<String> = o
        .spaces
        .iter()
        .flat_map(|s| s.machines.iter().map(|m| m.host.clone()))
        .collect();
    o.hosts.retain(|h| machines.contains(&h.name));
    for h in &mut o.hosts {
        h.spaces.retain(|s| seen.contains(s));
    }
    o.hub.admin_from.clear();
    o.hub.denied_inbound.clear();
    Ok(())
}

/// After a password or authenticator change: every login of `user` but
/// this one ends.
fn end_other_sessions(
    server: &Mutex<Server>,
    user: &str,
    keep: Option<&str>,
    keep_chat: Option<&str>,
) {
    let keep = keep.map(token_key);
    let keep_chat = keep_chat.map(token_key);
    let mut s = server.lock().expect("lock");
    s.sessions
        .retain(|t, x| x.user != user || Some(t) == keep.as_ref());
    s.unlocks
        .retain(|t, x| x.user != user || Some(t) == keep_chat.as_ref());
    s.save(crate::state::now(), true);
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
        Op::SessionList,
        Op::SpaceShare {
            name: s(),
            account: s(),
            level: None,
            code: s(),
        },
        Op::SpaceOwner {
            name: s(),
            account: None,
            code: s(),
        },
        Op::AccountNames,
        Op::SessionEnd { id: s() },
        Op::SessionEndOthers,
        Op::ChatUnlock {
            password: s(),
            code: s(),
        },
        Op::ChatFeed {
            name: s(),
            id: s(),
            from: None,
            before: None,
        },
        Op::ChatCommands { name: s() },
        Op::ChatSend {
            name: s(),
            id: s(),
            text: s(),
        },
        Op::ChatKey {
            name: s(),
            id: s(),
            key: s(),
        },
        Op::ChatUpload {
            name: s(),
            id: s(),
            filename: s(),
            data: s(),
        },
        Op::SpaceNew {
            space: NewSpace::default(),
        },
        Op::SpaceRm {
            name: s(),
            purge: false,
            purge_data: false,
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
        Op::SpaceConnect {
            name: s(),
            host: s(),
            access: Default::default(),
            code: s(),
        },
        Op::SpaceDisconnect {
            name: s(),
            host: s(),
        },
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
        Op::TailscaleShow,
        Op::TailscaleInstall { code: s() },
        Op::TailscaleUp { code: s() },
        Op::TailscaleWeb {
            on: true,
            code: s(),
        },
        Op::ChatList { name: s() },
        Op::ChatOpen {
            name: s(),
            id: None,
            title: None,
        },
        Op::SpaceRoot {
            name: s(),
            host: None,
            duration: s(),
            take: false,
            code: s(),
        },
        Op::SpaceRootOff {
            name: s(),
            host: None,
        },
        Op::AskList { all: false },
        Op::AskDecide {
            id: s(),
            approve: false,
            reason: s(),
        },
        Op::SpaceAccess {
            name: s(),
            host: None,
            access: Default::default(),
            code: s(),
        },
        Op::HostSetup {
            name: s(),
            code: s(),
        },
        Op::Activity {
            name: s(),
            limit: 0,
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
        Op::PasskeyBegin { purpose: s() },
        Op::PasskeyLogin {
            answer: Default::default(),
        },
        Op::PasskeyAdd {
            name: s(),
            answer: Default::default(),
            code: s(),
        },
        Op::PasskeyRm { id: s(), code: s() },
        Op::ChatRm { name: s(), id: s() },
        Op::ChatStop { name: s(), id: s() },
        Op::SpaceRemote {
            name: s(),
            on: true,
        },
        Op::UpdateCheck { refresh: false },
        Op::Update { code: s() },
        Op::LoginApiKey {
            name: s(),
            key: s(),
        },
        Op::CodexShow,
        Op::CodexInstall { code: s() },
        Op::CodexChats { name: s() },
        Op::CodexFeed {
            name: s(),
            id: s(),
            since: 0,
            turns: 0,
        },
        Op::CodexNew {
            name: s(),
            text: s(),
        },
        Op::CodexSend {
            name: s(),
            id: s(),
            text: s(),
        },
        Op::CodexStop { name: s(), id: s() },
        Op::CodexAnswer {
            name: s(),
            id: s(),
            ask: 0,
            decision: s(),
            answers: Default::default(),
        },
        Op::CodexRename {
            name: s(),
            id: s(),
            title: s(),
        },
        Op::CodexArchive { name: s(), id: s() },
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
            | Op::SessionList
            | Op::SpaceShare { .. }
            | Op::SpaceOwner { .. }
            | Op::AccountNames
            | Op::SessionEnd { .. }
            | Op::SessionEndOthers
            | Op::ChatUnlock { .. }
            | Op::ChatFeed { .. }
            | Op::ChatCommands { .. }
            | Op::ChatSend { .. }
            | Op::ChatKey { .. }
            | Op::ChatUpload { .. }
            | Op::SpaceNew { .. }
            | Op::SpaceRm { .. }
            | Op::SpaceRename { .. }
            | Op::SpaceControl { .. }
            | Op::SpaceRoot { .. }
            | Op::SpaceRootOff { .. }
            | Op::AskList { .. }
            | Op::AskDecide { .. }
            | Op::SpaceAccess { .. }
            | Op::HostSetup { .. }
            | Op::Activity { .. }
            | Op::SpaceScreen { .. }
            | Op::SpaceSend { .. }
            | Op::LoginStart { .. }
            | Op::LoginFinish { .. }
            | Op::LoginCancel { .. }
            | Op::SpaceConnect { .. }
            | Op::SpaceDisconnect { .. }
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
            | Op::TailscaleShow
            | Op::TailscaleInstall { .. }
            | Op::TailscaleUp { .. }
            | Op::TailscaleWeb { .. }
            | Op::ChatList { .. }
            | Op::ChatRm { .. }
            | Op::ChatStop { .. }
            | Op::SpaceRemote { .. }
            | Op::UpdateCheck { .. }
            | Op::Update { .. }
            | Op::LoginApiKey { .. }
            | Op::CodexShow
            | Op::CodexInstall { .. }
            | Op::CodexChats { .. }
            | Op::CodexFeed { .. }
            | Op::CodexNew { .. }
            | Op::CodexSend { .. }
            | Op::CodexStop { .. }
            | Op::CodexAnswer { .. }
            | Op::CodexRename { .. }
            | Op::CodexArchive { .. }
            | Op::Account
            | Op::AccountPassword { .. }
            | Op::AccountTotpBegin { .. }
            | Op::AccountTotpFinish { .. }
            | Op::ChatOpen { .. }
            | Op::HostRename { .. }
            | Op::AccountRename { .. }
            | Op::NotifyShow
            | Op::NotifySet { .. }
            | Op::NotifyTest
            | Op::PasskeyBegin { .. }
            | Op::PasskeyLogin { .. }
            | Op::PasskeyAdd { .. }
            | Op::PasskeyRm { .. } => {}
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
