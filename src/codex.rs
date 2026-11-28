//! Codex chats, on the hub's side.
//!
//! A Codex space runs `codex app-server` behind a small bridge
//! (`thorn _codex`, see codex_bridge.rs) in its tmux pane, as the space
//! user. The bridge keeps the one connection to Codex: it starts chats
//! (Codex calls them threads), sends messages, holds what Codex asks to be
//! approved until someone answers, and reads a chat's history. The hub
//! reaches it over a Unix socket in the space's runtime directory, one
//! request per connection: a line of JSON there and back.
//!
//! The bridge runs as the space user, so what it says is the space's word:
//! the hub reads it into the types below (bounded in size), shows it
//! escaped, and records what people send in the space's activity log, which
//! the space cannot write.

use crate::{ctx, paths, sys};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// The longest message kept, and of a command's output or a diff.
const MAX_TEXT: usize = 40_000;
const MAX_OUTPUT: usize = 8_000;
const MAX_DIFF: usize = 30_000;
/// The longest answer read from the bridge.
const MAX_REPLY: u64 = 16 << 20;
/// The longest message sent to Codex.
pub const MAX_MESSAGE: usize = 100_000;

/// One thing said or done in a chat.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Item {
    /// "user", "agent" (Markdown), "reasoning", "plan", "command",
    /// "files", "tool", "search", "error", "note".
    pub kind: String,
    #[serde(default)]
    pub id: String,
    /// The message; a command line; the files changed ("update path").
    #[serde(default)]
    pub text: String,
    /// A command's output; the diffs; a tool's input and result.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// "inProgress", "completed", "failed", "declined" (commands, files,
    /// tools).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<i64>,
    /// Who sent a message from the hub (set by the hub, from its log).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

/// Something Codex waits on an answer for.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Ask {
    /// The bridge's number for it.
    pub key: u64,
    /// "command" (run this?), "files" (change these files?), "permissions"
    /// (more access?), "question" (questions to answer).
    pub kind: String,
    /// The command; the reason given.
    #[serde(default)]
    pub text: String,
    /// Where the command runs; the files and their diffs; the access asked
    /// for.
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub questions: Vec<Question>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Question {
    pub id: String,
    #[serde(default)]
    pub header: String,
    #[serde(default)]
    pub question: String,
    /// (label, what it means).
    #[serde(default)]
    pub options: Vec<(String, String)>,
    /// A free answer is welcome too.
    #[serde(default)]
    pub other: bool,
    #[serde(default)]
    pub secret: bool,
}

/// A chat in the list.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Chat {
    pub id: String,
    /// Its name, else the start of its first message.
    pub title: String,
    /// Unix seconds.
    #[serde(default)]
    pub created: u64,
    #[serde(default)]
    pub updated: u64,
    /// "working", "waiting" (on an answer), "error", or "" (idle).
    #[serde(default)]
    pub state: String,
}

/// A chat's latest part.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Feed {
    /// Changes whenever something in the chat does (0: not known to the
    /// bridge since it started).
    pub version: u64,
    /// Nothing changed since the version asked about: the rest is empty.
    #[serde(default)]
    pub same: bool,
    #[serde(default)]
    pub title: String,
    /// As in `Chat::state`.
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub items: Vec<Item>,
    /// Earlier turns were left out.
    #[serde(default)]
    pub more: bool,
    #[serde(default)]
    pub asks: Vec<Ask>,
    /// Codex retrying, or the last error.
    #[serde(default)]
    pub notice: String,
    #[serde(default)]
    pub model: String,
    /// How far the account asking may go with the space (set by the API).
    #[serde(default)]
    pub level: Option<crate::state::Level>,
}

/// A thread id: Codex makes UUIDs.
pub fn id_ok(id: &str) -> bool {
    id.len() == 36 && uuid::Uuid::parse_str(id).is_ok()
}

pub fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n… ({} more characters)", &s[..end], s.len() - end)
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// The text of a user message's parts.
fn user_text(content: &Value) -> String {
    let mut parts = Vec::new();
    for c in content.as_array().into_iter().flatten() {
        match c["type"].as_str().unwrap_or("") {
            "text" => parts.push(s(&c["text"])),
            "image" | "localImage" => parts.push("[image]".into()),
            "mention" | "skill" => parts.push(format!("@{}", s(&c["name"]))),
            _ => {}
        }
    }
    parts.join("\n")
}

/// The files of a file change: ("update path", the diffs).
fn changes(v: &Value) -> (String, String) {
    let mut list = Vec::new();
    let mut diffs = String::new();
    for c in v.as_array().into_iter().flatten() {
        let kind = c["kind"]["type"]
            .as_str()
            .or_else(|| c["kind"].as_str())
            .unwrap_or("update");
        let path = s(&c["path"]);
        let to = c["kind"]["move_path"].as_str().unwrap_or("");
        if to.is_empty() {
            list.push(format!("{kind} {path}"));
        } else {
            list.push(format!("{kind} {path} → {to}"));
        }
        diffs.push_str(&format!("--- {path}\n{}\n", s(&c["diff"])));
    }
    (list.join("\n"), clip(&diffs, MAX_DIFF))
}

/// One of Codex's thread items, as an item here (None: nothing to show).
pub fn item(v: &Value) -> Option<Item> {
    let id = s(&v["id"]);
    let mut it = Item {
        id,
        status: s(&v["status"]),
        ..Default::default()
    };
    match v["type"].as_str().unwrap_or("") {
        "userMessage" => {
            it.kind = "user".into();
            it.text = clip(&user_text(&v["content"]), MAX_TEXT);
        }
        "agentMessage" => {
            it.kind = "agent".into();
            it.text = clip(&s(&v["text"]), MAX_TEXT);
        }
        "reasoning" => {
            let parts: Vec<String> = v["summary"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
            if parts.is_empty() {
                return None;
            }
            it.kind = "reasoning".into();
            it.text = clip(&parts.join("\n\n"), MAX_TEXT);
        }
        "plan" => {
            it.kind = "plan".into();
            it.text = clip(&s(&v["text"]), MAX_TEXT);
        }
        "commandExecution" => {
            it.kind = "command".into();
            it.text = clip(&unwrap_shell(&s(&v["command"])), MAX_OUTPUT);
            it.detail = tail(&s(&v["aggregatedOutput"]), MAX_OUTPUT);
            it.exit = v["exitCode"].as_i64();
        }
        "fileChange" => {
            it.kind = "files".into();
            (it.text, it.detail) = changes(&v["changes"]);
        }
        "mcpToolCall" => {
            it.kind = "tool".into();
            it.text = format!("{}.{}", s(&v["server"]), s(&v["tool"]));
            let mut d = format!("{}\n", v["arguments"]);
            if let Some(e) = v["error"]["message"].as_str() {
                d.push_str(&format!("\nerror: {e}"));
            } else if !v["result"].is_null() {
                d.push_str(&format!("\n{}", v["result"]["content"]));
            }
            it.detail = clip(&d, MAX_OUTPUT);
        }
        "dynamicToolCall" => {
            it.kind = "tool".into();
            it.text = s(&v["tool"]);
            it.detail = clip(&v["arguments"].to_string(), MAX_OUTPUT);
        }
        "webSearch" => {
            it.kind = "search".into();
            it.text = s(&v["query"]);
            if it.text.is_empty() {
                it.text = s(&v["action"]["url"]);
            }
        }
        "imageView" => {
            it.kind = "note".into();
            it.text = format!("looked at the image {}", s(&v["path"]));
        }
        "imageGeneration" => {
            it.kind = "note".into();
            it.text = format!("made an image {}", s(&v["savedPath"]));
        }
        "contextCompaction" => {
            it.kind = "note".into();
            it.text = "Codex summed up the chat so far to make room".into();
        }
        "enteredReviewMode" => {
            it.kind = "note".into();
            it.text = "review started".into();
        }
        "exitedReviewMode" => {
            it.kind = "agent".into();
            it.text = clip(&s(&v["review"]), MAX_TEXT);
        }
        "collabAgentToolCall" | "subAgentActivity" => {
            it.kind = "note".into();
            it.text = "a helper agent was at work".into();
        }
        _ => return None,
    }
    Some(it)
}

/// `/bin/bash -lc 'SCRIPT'` (how Codex shows the commands it runs) as
/// SCRIPT; anything else as it is.
pub fn unwrap_shell(cmd: &str) -> String {
    let shells = [
        "/bin/bash -lc ",
        "bash -lc ",
        "/usr/bin/bash -lc ",
        "/bin/sh -c ",
        "sh -c ",
        "/bin/zsh -lc ",
    ];
    let Some(rest) = shells.iter().find_map(|p| cmd.strip_prefix(p)) else {
        return cmd.to_string();
    };
    // Single-quoted parts and \' between them: 'it'\''s' is it's.
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => loop {
                match chars.next() {
                    Some('\'') => break,
                    Some(c) => out.push(c),
                    None => return cmd.to_string(),
                }
            },
            '\\' => match chars.next() {
                Some(c) => out.push(c),
                None => return cmd.to_string(),
            },
            '"' | '$' | '`' => return cmd.to_string(),
            c if c.is_whitespace() => return cmd.to_string(),
            c => out.push(c),
        }
    }
    out
}

/// The end of a long output, where the outcome is.
fn tail(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    format!("… ({start} characters before)\n{}", &s[start..])
}

/// A turn's items, and how it ended if not well.
pub fn turn_items(turn: &Value, out: &mut Vec<Item>) {
    for v in turn["items"].as_array().into_iter().flatten() {
        if let Some(it) = item(v) {
            out.push(it);
        }
    }
    match turn["status"].as_str().unwrap_or("") {
        "failed" => out.push(Item {
            kind: "error".into(),
            id: format!("{}-end", s(&turn["id"])),
            text: clip(
                turn["error"]["message"]
                    .as_str()
                    .unwrap_or("this turn failed"),
                MAX_OUTPUT,
            ),
            ..Default::default()
        }),
        "interrupted" => out.push(Item {
            kind: "note".into(),
            id: format!("{}-end", s(&turn["id"])),
            text: "stopped".into(),
            ..Default::default()
        }),
        _ => {}
    }
}

// ------------------------------------------------------------ the hub side

/// Connects to the space's bridge: the socket must be a socket of the
/// space user's, reached without following a link it may have put there.
fn connect(key: &str) -> Result<UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let path = paths::codex_socket(key);
    let user = paths::unix_user(key);
    let uid = sys::lookup_user(&user)
        .with_context(|| format!("user {user} is missing"))?
        .uid;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: a valid C string; the fd is owned by the File below.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        bail!("Codex is not running in this space: start the space");
    }
    // SAFETY: fd was just opened and is not owned elsewhere.
    let f = unsafe { std::fs::File::from_raw_fd(fd) };
    let m = f.metadata()?;
    if !m.file_type().is_socket() || m.uid() != uid {
        bail!("{} is not the space's own socket", path.display());
    }
    let stream = UnixStream::connect(format!("/proc/self/fd/{}", f.as_raw_fd()))
        .map_err(|_| anyhow::anyhow!("Codex is not running in this space: start the space"))?;
    Ok(stream)
}

/// One request to the space's bridge.
pub fn call(key: &str, req: Value, wait: Duration) -> Result<Value> {
    let mut stream = connect(key)?;
    stream.set_read_timeout(Some(wait))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut line = req.to_string();
    line.push('\n');
    stream.write_all(line.as_bytes())?;
    let mut reply = String::new();
    BufReader::new(stream.take(MAX_REPLY))
        .read_line(&mut reply)
        .context("no answer from the space's Codex bridge")?;
    let v: Value =
        serde_json::from_str(&reply).context("an answer from the bridge that is not JSON")?;
    if let Some(e) = v["error"].as_str() {
        bail!("{e}");
    }
    Ok(v["ok"].clone())
}

/// The space, which must run Codex.
fn space(name: &str) -> Result<crate::state::Space> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?.clone();
    if s.agent != crate::config::CODEX {
        bail!("space {name} runs {}, not Codex", s.agent);
    }
    Ok(s)
}

const QUICK: Duration = Duration::from_secs(20);
const SLOW: Duration = Duration::from_secs(90);

fn check_message(text: &str) -> Result<&str> {
    let text = text.trim_end();
    if text.trim().is_empty() {
        bail!("nothing to send");
    }
    if text.len() > MAX_MESSAGE {
        bail!("that message is too long");
    }
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        bail!("the message holds control characters");
    }
    Ok(text)
}

fn check_id(id: &str) -> Result<()> {
    if !id_ok(id) {
        bail!("no such chat: {id}");
    }
    Ok(())
}

pub fn chats(name: &str) -> Result<Vec<Chat>> {
    let s = space(name)?;
    Ok(serde_json::from_value(call(
        &s.key,
        json!({"op": "list"}),
        QUICK,
    )?)?)
}

/// A chat's latest `turns` turns (with who sent each message from the
/// hub), unless nothing changed since `since`.
pub fn feed(name: &str, id: &str, since: u64, turns: u32) -> Result<Feed> {
    check_id(id)?;
    let s = space(name)?;
    let v = call(
        &s.key,
        json!({"op": "feed", "id": id, "since": since, "turns": turns.clamp(1, 500)}),
        QUICK,
    )?;
    let mut f: Feed = serde_json::from_value(v)?;
    if f.items.iter().any(|i| i.kind == "user") {
        let mut sent = crate::activity::sent_to(&s.key, id);
        for it in f.items.iter_mut().filter(|i| i.kind == "user") {
            if let Some(at) = sent.iter().position(|(_, m)| m.trim() == it.text.trim()) {
                it.by = Some(sent.remove(at).0);
            }
        }
    }
    Ok(f)
}

/// Starts a chat with its first message; its id.
pub fn new(name: &str, text: &str, by: &str) -> Result<String> {
    let text = check_message(text)?;
    let s = space(name)?;
    let v = call(&s.key, json!({"op": "new", "text": text}), SLOW)?;
    let id = v["id"].as_str().unwrap_or("").to_string();
    check_id(&id)?;
    crate::activity::record(&s.key, &id, by, text, "")?;
    Ok(id)
}

/// Sends a message: a new turn, or (while Codex works) more for the turn
/// it is on.
pub fn send(name: &str, id: &str, text: &str, by: &str) -> Result<()> {
    check_id(id)?;
    let text = check_message(text)?;
    let s = space(name)?;
    call(&s.key, json!({"op": "send", "id": id, "text": text}), SLOW)?;
    crate::activity::record(&s.key, id, by, text, "")?;
    Ok(())
}

pub fn stop(name: &str, id: &str, by: &str) -> Result<()> {
    check_id(id)?;
    let s = space(name)?;
    call(&s.key, json!({"op": "stop", "id": id}), QUICK)?;
    crate::activity::record(&s.key, id, by, "", "stopped Codex")?;
    Ok(())
}

/// Answers what Codex asked: "accept", "session" (and the same again in
/// this chat), "decline" (Codex goes on without it), "cancel" (and stop);
/// for questions, `answers` by question id.
pub fn answer(
    name: &str,
    id: &str,
    ask: u64,
    decision: &str,
    answers: &std::collections::BTreeMap<String, String>,
    by: &str,
) -> Result<()> {
    check_id(id)?;
    if !matches!(decision, "accept" | "session" | "decline" | "cancel") {
        bail!("answer accept, session, decline or cancel");
    }
    let s = space(name)?;
    call(
        &s.key,
        json!({"op": "answer", "id": id, "ask": ask, "decision": decision, "answers": answers}),
        QUICK,
    )?;
    let what = match decision {
        "accept" => "allowed once",
        "session" => "allowed for this chat",
        "decline" => "declined",
        _ => "declined and stopped",
    };
    crate::activity::record(&s.key, id, by, "", &format!("Codex asked: {what}"))?;
    Ok(())
}

pub fn rename(name: &str, id: &str, title: &str) -> Result<()> {
    check_id(id)?;
    let title = title.trim();
    if title.is_empty() || title.chars().count() > 100 || title.chars().any(char::is_control) {
        bail!("a chat name is 1 to 100 characters, on one line");
    }
    let s = space(name)?;
    call(
        &s.key,
        json!({"op": "name", "id": id, "name": title}),
        QUICK,
    )?;
    Ok(())
}

/// Archives a chat: Codex keeps it, out of the list.
pub fn archive(name: &str, id: &str) -> Result<()> {
    check_id(id)?;
    let s = space(name)?;
    call(&s.key, json!({"op": "archive", "id": id}), QUICK)?;
    Ok(())
}

/// What a chat's list shows for its state.
pub fn state_label(state: &str) -> &'static str {
    match state {
        "working" => "working",
        "waiting" => "waiting for you",
        "error" => "error",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_read() {
        let v = json!({"type": "userMessage", "id": "u1", "content": [
            {"type": "text", "text": "hi"}, {"type": "localImage", "path": "/x.png"}]});
        let it = item(&v).unwrap();
        assert_eq!(
            (it.kind.as_str(), it.text.as_str()),
            ("user", "hi\n[image]")
        );

        let v = json!({"type": "commandExecution", "id": "c1", "command": "ls -la",
            "cwd": "/w", "commandActions": [], "status": "completed",
            "aggregatedOutput": "a\nb\n", "exitCode": 0});
        let it = item(&v).unwrap();
        assert_eq!(it.kind, "command");
        assert_eq!(it.text, "ls -la");
        assert_eq!(it.detail, "a\nb\n");
        assert_eq!(it.exit, Some(0));

        let v = json!({"type": "fileChange", "id": "f1", "status": "completed", "changes": [
            {"path": "/w/a.txt", "kind": {"type": "add"}, "diff": "+x"},
            {"path": "/w/b.txt", "kind": {"type": "update", "move_path": "/w/c.txt"}, "diff": "-y\n+z"}]});
        let it = item(&v).unwrap();
        assert_eq!(it.text, "add /w/a.txt\nupdate /w/b.txt → /w/c.txt");
        assert!(it.detail.contains("--- /w/b.txt\n-y\n+z"));

        assert!(item(&json!({"type": "reasoning", "id": "r", "summary": []})).is_none());
        assert!(item(&json!({"type": "somethingNew", "id": "n"})).is_none());
    }

    #[test]
    fn turn_endings() {
        let mut out = Vec::new();
        turn_items(
            &json!({"id": "t1", "status": "failed", "error": {"message": "401"}, "items": [
                {"type": "agentMessage", "id": "a", "text": "**hi**"}]}),
            &mut out,
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].kind, "agent");
        assert_eq!(
            (out[1].kind.as_str(), out[1].text.as_str()),
            ("error", "401")
        );
        out.clear();
        turn_items(
            &json!({"id": "t2", "status": "interrupted", "items": []}),
            &mut out,
        );
        assert_eq!(out[0].text, "stopped");
    }

    #[test]
    fn long_output_keeps_its_end() {
        let s = "x".repeat(MAX_OUTPUT) + "THE END";
        let t = tail(&s, MAX_OUTPUT);
        assert!(t.ends_with("THE END"));
        assert!(t.starts_with("… (7 characters before)"));
    }

    #[test]
    fn shell_unwrapped() {
        assert_eq!(
            unwrap_shell("/bin/bash -lc 'touch approved.txt'"),
            "touch approved.txt"
        );
        assert_eq!(
            unwrap_shell(r"/bin/bash -lc 'echo '\''hi'\'''"),
            "echo 'hi'"
        );
        assert_eq!(unwrap_shell("/bin/bash -lc ls"), "ls");
        assert_eq!(
            unwrap_shell(r#"/bin/bash -lc "ls $HOME""#),
            r#"/bin/bash -lc "ls $HOME""#
        );
        assert_eq!(
            unwrap_shell("/bin/bash -lc 'a' 'b'"),
            "/bin/bash -lc 'a' 'b'"
        );
        assert_eq!(unwrap_shell("git status"), "git status");
    }

    #[test]
    fn ids() {
        assert!(id_ok("01a22171-1046-78d0-9f82-dfd478164a10"));
        assert!(!id_ok("01a22171"));
        assert!(!id_ok("../../etc/passwd-0000000000000000000"));
    }
}
