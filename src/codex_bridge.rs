//! `thorn _codex <key>`: runs inside a Codex space's tmux pane, as the
//! space user, in place of a terminal Codex.
//!
//! It starts `codex app-server` (JSON-RPC, a message a line, on its stdin
//! and stdout) and keeps the one connection to it: what Codex says comes
//! in on one thread and updates what the bridge knows (each chat's turn in
//! progress, what Codex waits on an answer for); the hub's requests come in
//! on a Unix socket, one a connection (see codex.rs). When Codex ends, the
//! bridge ends too, and `thorn _run` starts both again.
//!
//! Codex runs without its own sandbox and asks before what it is unsure of
//! (as the space's terminal Codex did): the space is the sandbox.

use crate::codex::{self, Ask, Chat, Feed, Item, Question};
use crate::paths;
use crate::render::Launch;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

const APPROVAL: &str = "on-request";
const SANDBOX: &str = "danger-full-access";
/// The longest request the hub sends.
const MAX_REQUEST: u64 = 1 << 20;
/// What Codex prints of a running command, kept while it runs.
const MAX_LIVE_OUTPUT: usize = 64 << 10;

/// A chat the bridge has seen something of since it started.
#[derive(Default)]
struct Live {
    version: u64,
    /// "idle", "active", "systemError", "notLoaded".
    status: String,
    /// The turn in progress, and its items so far.
    turn: Option<String>,
    items: Vec<Value>,
    notice: String,
    name: Option<String>,
}

/// A request from Codex waiting on a person.
struct Pending {
    key: u64,
    /// Its JSON-RPC id, to answer with.
    rpc: Value,
    method: String,
    thread: String,
    params: Value,
}

#[derive(Default)]
struct State {
    version: u64,
    threads: HashMap<String, Live>,
    pending: Vec<Pending>,
    next_ask: u64,
    /// Threads Codex has loaded (it can take a message without a resume).
    loaded: HashSet<String>,
}

impl State {
    fn live(&mut self, id: &str) -> &mut Live {
        self.version += 1;
        let v = self.version;
        let l = self.threads.entry(id.to_string()).or_default();
        l.version = v;
        l
    }
}

type Waiter = mpsc::Sender<std::result::Result<Value, String>>;

struct Bridge {
    out: Mutex<ChildStdin>,
    next: AtomicU64,
    waiting: Mutex<HashMap<u64, Waiter>>,
    state: Mutex<State>,
    workdir: String,
    model: Option<String>,
}

impl Bridge {
    fn write(&self, v: &Value) -> Result<()> {
        let mut line = v.to_string();
        line.push('\n');
        let mut out = self.out.lock().expect("stdin lock");
        out.write_all(line.as_bytes())?;
        out.flush()?;
        Ok(())
    }

    /// A request to Codex, and its result.
    fn call(&self, method: &str, params: Value, wait: Duration) -> Result<Value> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel();
        self.waiting.lock().expect("lock").insert(id, tx);
        self.write(&json!({"id": id, "method": method, "params": params}))?;
        match rx.recv_timeout(wait) {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => bail!("Codex: {e}"),
            Err(_) => {
                self.waiting.lock().expect("lock").remove(&id);
                bail!("Codex did not answer {method} in time")
            }
        }
    }
}

/// The app-server options among the space's arguments (`-c key=value`,
/// `--enable`, `--disable`), and the model (`-m`/`--model`). The rest are
/// for a terminal Codex.
fn split_args(args: &[String]) -> (Vec<String>, Option<String>, Vec<String>) {
    let mut keep = Vec::new();
    let mut model = None;
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-c" | "--config" | "--enable" | "--disable" => {
                if let Some(v) = it.next() {
                    keep.push(a.clone());
                    keep.push(v.clone());
                }
            }
            "-m" | "--model" => model = it.next().cloned(),
            _ => {
                if let Some(v) = a.strip_prefix("--model=") {
                    model = Some(v.to_string());
                } else if a.starts_with("--config=") {
                    keep.push(a.clone());
                } else {
                    rest.push(a.clone());
                }
            }
        }
    }
    (keep, model, rest)
}

fn log(msg: &str) {
    let now = humantime::format_rfc3339_seconds(std::time::SystemTime::now());
    println!("{now} {msg}");
}

pub fn run(key: &str) -> Result<()> {
    let text = std::fs::read_to_string(paths::launch_file(key))?;
    let launch: Launch = toml::from_str(&text)?;
    let home = paths::space_home(key);
    let workdir = if launch.workdir.is_empty() {
        home.join("work").display().to_string()
    } else {
        launch.workdir.clone()
    };
    let (keep, model, rest) = split_args(&launch.args);
    if !rest.is_empty() {
        log(&format!(
            "left out (for a terminal Codex): {}",
            rest.join(" ")
        ));
    }
    let mut cmd = Command::new(&launch.bin);
    cmd.arg("app-server")
        .args(&keep)
        .current_dir(&workdir)
        .env("HOME", &home)
        .env("SSH_AUTH_SOCK", paths::agent_socket(key))
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: prctl is async-signal-safe. Codex ends with the bridge.
        unsafe {
            cmd.pre_exec(|| {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM);
                Ok(())
            });
        }
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("starting {} app-server", launch.bin))?;
    let bridge = Arc::new(Bridge {
        out: Mutex::new(child.stdin.take().context("codex stdin")?),
        next: AtomicU64::new(1),
        waiting: Mutex::new(HashMap::new()),
        state: Mutex::new(State::default()),
        workdir,
        model,
    });
    let stdout = child.stdout.take().context("codex stdout")?;
    {
        let b = bridge.clone();
        std::thread::spawn(move || {
            read_codex(&b, stdout);
            log("Codex ended");
            std::process::exit(1);
        });
    }
    let version = env!("CARGO_PKG_VERSION");
    bridge.call(
        "initialize",
        json!({"clientInfo": {"name": "blackthorn", "title": "blackthorn", "version": version}}),
        Duration::from_secs(60),
    )?;
    bridge.write(&json!({"method": "initialized"}))?;

    let sock = paths::codex_socket(key);
    let _ = std::fs::remove_file(&sock);
    let listener =
        UnixListener::bind(&sock).with_context(|| format!("listening on {}", sock.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    }
    log(&format!(
        "Codex is ready: start and continue its chats on the hub's web page, or with thorn codex (in {})",
        bridge.workdir
    ));
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
        let b = bridge.clone();
        std::thread::spawn(move || {
            if let Err(e) = serve(&b, conn) {
                log(&format!("a request failed: {e:#}"));
            }
        });
    }
    Ok(())
}

/// What Codex says: answers, its own requests, and news.
fn read_codex(b: &Bridge, stdout: std::process::ChildStdout) {
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let method = v["method"].as_str().map(str::to_string);
        match (method, v.get("id")) {
            (Some(m), Some(id)) => request(b, &m, id.clone(), v["params"].clone()),
            (Some(m), None) => notice(b, &m, &v["params"]),
            (None, Some(id)) => {
                let Some(id) = id.as_u64() else { continue };
                if let Some(tx) = b.waiting.lock().expect("lock").remove(&id) {
                    let r = if v.get("error").is_some() {
                        Err(v["error"]["message"]
                            .as_str()
                            .unwrap_or("error")
                            .to_string())
                    } else {
                        Ok(v["result"].clone())
                    };
                    let _ = tx.send(r);
                }
            }
            _ => {}
        }
    }
}

/// A request from Codex: what needs a person waits for one; the rest is
/// turned down.
fn request(b: &Bridge, method: &str, rpc: Value, params: Value) {
    let person = matches!(
        method,
        "item/commandExecution/requestApproval"
            | "item/fileChange/requestApproval"
            | "item/permissions/requestApproval"
            | "item/tool/requestUserInput"
            | "execCommandApproval"
            | "applyPatchApproval"
    );
    if person {
        let thread = params["threadId"]
            .as_str()
            .or_else(|| params["conversationId"].as_str())
            .unwrap_or("")
            .to_string();
        let mut st = b.state.lock().expect("lock");
        st.next_ask += 1;
        let key = st.next_ask;
        st.live(&thread);
        st.pending.push(Pending {
            key,
            rpc,
            method: method.to_string(),
            thread: thread.clone(),
            params,
        });
        drop(st);
        log(&format!(
            "chat {}: Codex asks ({method}); answer on the hub",
            short(&thread)
        ));
        return;
    }
    let reply = if method == "mcpServer/elicitation/request" {
        json!({"id": rpc, "result": {"action": "decline"}})
    } else {
        json!({"id": rpc, "error": {"code": -32601, "message": "blackthorn does not handle this"}})
    };
    let _ = b.write(&reply);
}

fn short(id: &str) -> &str {
    &id[..8.min(id.len())]
}

fn upsert(items: &mut Vec<Value>, item: &Value) {
    let id = &item["id"];
    match items.iter_mut().find(|i| &i["id"] == id) {
        Some(i) => *i = item.clone(),
        None => items.push(item.clone()),
    }
}

/// Appends to a string field of a live item.
fn append(items: &mut [Value], id: &str, field: &str, delta: &str, max: usize) {
    if let Some(i) = items.iter_mut().find(|i| i["id"] == id) {
        let mut s = i[field].as_str().unwrap_or("").to_string();
        if s.len() < max {
            s.push_str(delta);
        }
        i[field] = Value::String(s);
    }
}

/// News from Codex.
fn notice(b: &Bridge, method: &str, p: &Value) {
    let thread = p["threadId"]
        .as_str()
        .or_else(|| p["thread"]["id"].as_str())
        .unwrap_or("")
        .to_string();
    if thread.is_empty() {
        return;
    }
    let mut st = b.state.lock().expect("lock");
    match method {
        "thread/started" => {
            st.loaded.insert(thread.clone());
            let l = st.live(&thread);
            l.status = p["thread"]["status"]["type"]
                .as_str()
                .unwrap_or("idle")
                .into();
        }
        "thread/status/changed" => {
            let status = p["status"]["type"].as_str().unwrap_or("").to_string();
            if status == "notLoaded" {
                st.loaded.remove(&thread);
            }
            st.live(&thread).status = status;
        }
        "thread/closed" => {
            st.loaded.remove(&thread);
            st.live(&thread).status = "notLoaded".into();
        }
        "thread/name/updated" => {
            st.live(&thread).name = p["threadName"].as_str().map(str::to_string);
        }
        "turn/started" => {
            let l = st.live(&thread);
            l.turn = p["turn"]["id"].as_str().map(str::to_string);
            l.items.clear();
            l.notice.clear();
        }
        "turn/completed" => {
            let l = st.live(&thread);
            l.turn = None;
            l.items.clear();
            let how = p["turn"]["status"].as_str().unwrap_or("").to_string();
            st.pending.retain(|x| x.thread != thread);
            drop(st);
            log(&format!("chat {}: turn {how}", short(&thread)));
            return;
        }
        "item/started" | "item/completed" => {
            let l = st.live(&thread);
            upsert(&mut l.items, &p["item"]);
        }
        "item/agentMessage/delta" => {
            let id = p["itemId"].as_str().unwrap_or("");
            let l = st.live(&thread);
            append(
                &mut l.items,
                id,
                "text",
                p["delta"].as_str().unwrap_or(""),
                usize::MAX,
            );
        }
        "item/commandExecution/outputDelta" => {
            let id = p["itemId"].as_str().unwrap_or("");
            let l = st.live(&thread);
            append(
                &mut l.items,
                id,
                "aggregatedOutput",
                p["delta"].as_str().unwrap_or(""),
                MAX_LIVE_OUTPUT,
            );
        }
        "error" => {
            let msg = p["error"]["message"]
                .as_str()
                .unwrap_or("error")
                .to_string();
            st.live(&thread).notice = msg;
        }
        "serverRequest/resolved" => {
            let id = p["requestId"].clone();
            st.pending.retain(|x| x.rpc != id);
            st.live(&thread);
        }
        _ => {}
    }
}

/// One request from the hub.
fn serve(b: &Bridge, conn: UnixStream) -> Result<()> {
    conn.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut line = String::new();
    BufReader::new((&conn).take(MAX_REQUEST)).read_line(&mut line)?;
    let req: Value = serde_json::from_str(&line).context("not JSON")?;
    let reply = match handle(b, &req) {
        Ok(v) => json!({"ok": v}),
        Err(e) => json!({"error": format!("{e:#}")}),
    };
    let mut out = reply.to_string();
    out.push('\n');
    (&conn).write_all(out.as_bytes())?;
    Ok(())
}

fn thread_id(req: &Value) -> Result<String> {
    let id = req["id"].as_str().unwrap_or("");
    if !codex::id_ok(id) {
        bail!("no such chat: {id}");
    }
    Ok(id.to_string())
}

fn text_input(req: &Value) -> Result<Value> {
    let text = req["text"].as_str().unwrap_or("");
    if text.trim().is_empty() || text.len() > codex::MAX_MESSAGE {
        bail!("nothing to send, or too much");
    }
    Ok(json!([{"type": "text", "text": text, "text_elements": []}]))
}

const QUICK: Duration = Duration::from_secs(15);
const SLOW: Duration = Duration::from_secs(80);

fn handle(b: &Bridge, req: &Value) -> Result<Value> {
    match req["op"].as_str().unwrap_or("") {
        "list" => Ok(serde_json::to_value(list(b)?)?),
        "feed" => Ok(serde_json::to_value(feed(b, req)?)?),
        "new" => {
            let input = text_input(req)?;
            let mut params =
                json!({"cwd": b.workdir, "approvalPolicy": APPROVAL, "sandbox": SANDBOX});
            if let Some(m) = &b.model {
                params["model"] = json!(m);
            }
            let r = b.call("thread/start", params, SLOW)?;
            let id = r["thread"]["id"].as_str().unwrap_or("").to_string();
            if !codex::id_ok(&id) {
                bail!("Codex did not start a chat");
            }
            b.state.lock().expect("lock").loaded.insert(id.clone());
            b.call("turn/start", json!({"threadId": id, "input": input}), SLOW)?;
            log(&format!("chat {}: started from the hub", short(&id)));
            Ok(json!({"id": id}))
        }
        "send" => {
            let id = thread_id(req)?;
            let input = text_input(req)?;
            load(b, &id)?;
            let turn = b
                .state
                .lock()
                .expect("lock")
                .threads
                .get(&id)
                .and_then(|l| l.turn.clone());
            match turn {
                Some(t) => b.call(
                    "turn/steer",
                    json!({"threadId": id, "expectedTurnId": t, "input": input}),
                    SLOW,
                )?,
                None => b.call("turn/start", json!({"threadId": id, "input": input}), SLOW)?,
            };
            Ok(json!({}))
        }
        "stop" => {
            let id = thread_id(req)?;
            let turn = b
                .state
                .lock()
                .expect("lock")
                .threads
                .get(&id)
                .and_then(|l| l.turn.clone());
            let Some(t) = turn else {
                bail!("Codex is not working in this chat")
            };
            b.call(
                "turn/interrupt",
                json!({"threadId": id, "turnId": t}),
                QUICK,
            )?;
            Ok(json!({}))
        }
        "answer" => {
            let id = thread_id(req)?;
            answer(b, &id, req)?;
            Ok(json!({}))
        }
        "name" => {
            let id = thread_id(req)?;
            let name = req["name"].as_str().unwrap_or("").trim().to_string();
            if name.is_empty() {
                bail!("no name");
            }
            b.call(
                "thread/name/set",
                json!({"threadId": id, "name": name}),
                QUICK,
            )?;
            b.state.lock().expect("lock").live(&id).name = Some(name);
            Ok(json!({}))
        }
        "archive" => {
            let id = thread_id(req)?;
            b.call("thread/archive", json!({"threadId": id}), QUICK)?;
            let mut st = b.state.lock().expect("lock");
            st.loaded.remove(&id);
            st.threads.remove(&id);
            Ok(json!({}))
        }
        op => bail!("unknown request {op:?}"),
    }
}

/// Loads a chat into Codex (after Codex restarted, or one made in a
/// terminal), so it can take a message.
fn load(b: &Bridge, id: &str) -> Result<()> {
    if b.state.lock().expect("lock").loaded.contains(id) {
        return Ok(());
    }
    let mut params = json!({"threadId": id, "excludeTurns": true,
        "approvalPolicy": APPROVAL, "sandbox": SANDBOX});
    if let Some(m) = &b.model {
        params["model"] = json!(m);
    }
    b.call("thread/resume", params, SLOW)?;
    b.state.lock().expect("lock").loaded.insert(id.to_string());
    Ok(())
}

/// What a chat is doing, for the list.
fn state_of(st: &State, id: &str) -> String {
    if st.pending.iter().any(|p| p.thread == id) {
        return "waiting".into();
    }
    match st.threads.get(id) {
        Some(l) if l.turn.is_some() => "working".into(),
        Some(l) if l.status == "systemError" => "error".into(),
        _ => String::new(),
    }
}

fn title(name: Option<&str>, preview: &str) -> String {
    match name.map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => n.to_string(),
        None => {
            let first = preview
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("")
                .trim();
            let mut t: String = first.chars().take(80).collect();
            if first.chars().count() > 80 {
                t.push('…');
            }
            t
        }
    }
}

fn list(b: &Bridge) -> Result<Vec<Chat>> {
    let r = b.call(
        "thread/list",
        json!({"sortKey": "updated_at", "limit": 100}),
        QUICK,
    )?;
    let st = b.state.lock().expect("lock");
    let mut out = Vec::new();
    for t in r["data"].as_array().into_iter().flatten() {
        let id = t["id"].as_str().unwrap_or("").to_string();
        if !codex::id_ok(&id) {
            continue;
        }
        let name = st
            .threads
            .get(&id)
            .and_then(|l| l.name.clone())
            .or_else(|| t["name"].as_str().map(str::to_string));
        out.push(Chat {
            title: title(name.as_deref(), t["preview"].as_str().unwrap_or("")),
            created: t["createdAt"].as_u64().unwrap_or(0),
            updated: t["updatedAt"].as_u64().unwrap_or(0),
            state: state_of(&st, &id),
            id,
        });
    }
    Ok(out)
}

fn ask_of(p: &Pending, live: Option<&Live>) -> Ask {
    let q = &p.params;
    let mut a = Ask {
        key: p.key,
        ..Default::default()
    };
    match p.method.as_str() {
        "item/commandExecution/requestApproval" | "execCommandApproval" => {
            a.kind = "command".into();
            a.text = match &q["command"] {
                Value::String(s) => s.clone(),
                v => crate::activity::argv_text(v).unwrap_or_default(),
            };
            let mut d = format!("in {}", q["cwd"].as_str().unwrap_or("?"));
            if let Some(r) = q["reason"].as_str() {
                d.push_str(&format!("\n{r}"));
            }
            a.detail = d;
        }
        "item/fileChange/requestApproval" | "applyPatchApproval" => {
            a.kind = "files".into();
            a.text = q["reason"].as_str().unwrap_or("").to_string();
            // The changes are in the item it is about.
            let item = q["itemId"]
                .as_str()
                .and_then(|i| live.and_then(|l| l.items.iter().find(|x| x["id"] == i)));
            if let Some(it) = item.and_then(codex::item) {
                a.detail = format!("{}\n\n{}", it.text, it.detail);
            }
        }
        "item/permissions/requestApproval" => {
            a.kind = "permissions".into();
            a.text = q["reason"].as_str().unwrap_or("").to_string();
            a.detail = serde_json::to_string_pretty(&q["permissions"]).unwrap_or_default();
        }
        _ => {
            a.kind = "question".into();
            for x in q["questions"].as_array().into_iter().flatten() {
                a.questions.push(Question {
                    id: x["id"].as_str().unwrap_or("").to_string(),
                    header: x["header"].as_str().unwrap_or("").to_string(),
                    question: x["question"].as_str().unwrap_or("").to_string(),
                    options: x["options"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .map(|o| {
                            (
                                o["label"].as_str().unwrap_or("").to_string(),
                                o["description"].as_str().unwrap_or("").to_string(),
                            )
                        })
                        .collect(),
                    other: x["isOther"].as_bool().unwrap_or(false),
                    secret: x["isSecret"].as_bool().unwrap_or(false),
                });
            }
        }
    }
    a
}

fn feed(b: &Bridge, req: &Value) -> Result<Feed> {
    let id = thread_id(req)?;
    let since = req["since"].as_u64().unwrap_or(0);
    let turns = req["turns"].as_u64().unwrap_or(30).clamp(1, 500);
    {
        let st = b.state.lock().expect("lock");
        let v = st.threads.get(&id).map_or(0, |l| l.version);
        if v > 0 && v == since {
            return Ok(Feed {
                version: v,
                same: true,
                ..Default::default()
            });
        }
    }
    let r = b.call(
        "thread/turns/list",
        json!({"threadId": id, "itemsView": "full", "limit": turns}),
        QUICK,
    )?;
    let info = b
        .call("thread/read", json!({"threadId": id}), QUICK)
        .unwrap_or(Value::Null);
    let st = b.state.lock().expect("lock");
    let live = st.threads.get(&id);
    let running = live.and_then(|l| l.turn.clone());
    let mut list: Vec<&Value> = r["data"].as_array().into_iter().flatten().collect();
    // Newest first from Codex.
    list.reverse();
    let mut items: Vec<Item> = Vec::new();
    for t in list {
        if running.is_some() && t["id"].as_str() == running.as_deref() {
            continue;
        }
        codex::turn_items(t, &mut items);
    }
    if let Some(l) = live.filter(|l| l.turn.is_some()) {
        items.extend(l.items.iter().filter_map(codex::item));
    }
    let name = live
        .and_then(|l| l.name.clone())
        .or_else(|| info["thread"]["name"].as_str().map(str::to_string));
    Ok(Feed {
        version: live.map_or(0, |l| l.version),
        same: false,
        title: title(
            name.as_deref(),
            info["thread"]["preview"].as_str().unwrap_or(""),
        ),
        state: state_of(&st, &id),
        items,
        more: r["nextCursor"].is_string(),
        asks: st
            .pending
            .iter()
            .filter(|p| p.thread == id)
            .map(|p| ask_of(p, live))
            .collect(),
        notice: live.map(|l| l.notice.clone()).unwrap_or_default(),
        model: info["thread"]["model"].as_str().unwrap_or("").to_string(),
        level: None,
    })
}

/// Answers a request of Codex's, in the form its method takes.
fn answer(b: &Bridge, id: &str, req: &Value) -> Result<()> {
    let key = req["ask"].as_u64().unwrap_or(0);
    let decision = req["decision"].as_str().unwrap_or("");
    let p = {
        let mut st = b.state.lock().expect("lock");
        let Some(at) = st
            .pending
            .iter()
            .position(|p| p.key == key && p.thread == id)
        else {
            bail!("Codex is not waiting on that any more");
        };
        let p = st.pending.remove(at);
        st.live(id);
        p
    };
    let result = match p.method.as_str() {
        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
            let d = match decision {
                "accept" => "accept",
                "session" => "acceptForSession",
                "cancel" => "cancel",
                _ => "decline",
            };
            json!({"decision": d})
        }
        "execCommandApproval" | "applyPatchApproval" => {
            let d = match decision {
                "accept" => "approved",
                "session" => "approved_for_session",
                "cancel" => "abort",
                _ => "denied",
            };
            json!({"decision": d})
        }
        "item/permissions/requestApproval" => {
            if matches!(decision, "accept" | "session") {
                json!({"permissions": p.params["permissions"],
                    "scope": if decision == "session" { "session" } else { "turn" }})
            } else {
                json!({"permissions": {}})
            }
        }
        _ => {
            // Questions: the answers given; declining answers nothing.
            let mut answers = serde_json::Map::new();
            if matches!(decision, "accept" | "session") {
                for (k, v) in req["answers"].as_object().into_iter().flatten() {
                    if let Some(s) = v.as_str() {
                        answers.insert(k.clone(), json!({"answers": [s]}));
                    }
                }
            }
            json!({"answers": answers})
        }
    };
    b.write(&json!({"id": p.rpc, "result": result}))?;
    if decision == "cancel" && p.method.starts_with("item/tool") {
        let turn = b
            .state
            .lock()
            .expect("lock")
            .threads
            .get(id)
            .and_then(|l| l.turn.clone());
        if let Some(t) = turn {
            let _ = b.call(
                "turn/interrupt",
                json!({"threadId": id, "turnId": t}),
                QUICK,
            );
        }
    }
    log(&format!("chat {}: answered ({decision})", short(id)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_split() {
        let a: Vec<String> = [
            "--sandbox",
            "danger-full-access",
            "-m",
            "gpt-6.1",
            "-c",
            "x=1",
            "--enable",
            "web",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let (keep, model, rest) = split_args(&a);
        assert_eq!(keep, ["-c", "x=1", "--enable", "web"]);
        assert_eq!(model.as_deref(), Some("gpt-6.1"));
        assert_eq!(rest, ["--sandbox", "danger-full-access"]);
    }

    #[test]
    fn titles() {
        assert_eq!(title(Some(" Fix nginx "), "x"), "Fix nginx");
        assert_eq!(title(None, "\n  hello there\nmore"), "hello there");
        assert_eq!(title(Some(""), &"a".repeat(90)).chars().count(), 81);
    }

    #[test]
    fn states() {
        let mut st = State::default();
        st.live("t").turn = Some("u".into());
        assert_eq!(state_of(&st, "t"), "working");
        st.pending.push(Pending {
            key: 1,
            rpc: json!(5),
            method: "item/commandExecution/requestApproval".into(),
            thread: "t".into(),
            params: json!({"command": "rm -rf /tmp/x", "cwd": "/w"}),
        });
        assert_eq!(state_of(&st, "t"), "waiting");
        let a = ask_of(&st.pending[0], None);
        assert_eq!(
            (a.kind.as_str(), a.text.as_str()),
            ("command", "rm -rf /tmp/x")
        );
        assert_eq!(state_of(&st, "other"), "");
    }

    #[test]
    fn live_items_grow() {
        let mut items = vec![json!({"type": "agentMessage", "id": "a", "text": "He"})];
        append(&mut items, "a", "text", "llo", usize::MAX);
        upsert(
            &mut items,
            &json!({"type": "commandExecution", "id": "c", "command": "ls"}),
        );
        append(&mut items, "c", "aggregatedOutput", "x\n", 10);
        assert_eq!(items[0]["text"], "Hello");
        assert_eq!(items[1]["aggregatedOutput"], "x\n");
    }
}
