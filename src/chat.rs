//! A chat in the web UI: what it says (read from its transcript), what its
//! terminal is doing, and typing into it.
//!
//! Typing goes to the Claude Code the hub runs for the chat, in its tmux
//! window, as a paste followed by Enter: the same as a person at that
//! terminal. Nothing is typed while Claude Code is asking a question;
//! those answers are buttons the person presses, seeing the question.

use crate::ops::{chat_running, chat_windows, find_chat, main_conversation};
use crate::state::Space;
use crate::{ctx, paths, sys};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// The most of a transcript read at once.
const WINDOW: u64 = 4 << 20;
/// The longest text kept of one message, and of a tool's input or result.
const MAX_TEXT: usize = 40_000;
const MAX_TOOL: usize = 6_000;
/// The largest file uploaded to a chat.
pub const MAX_UPLOAD: usize = 10 << 20;

/// One thing said or done in a chat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Item {
    /// "user", "assistant" (Markdown), "tool" (a tool used), "result" (what
    /// it gave back), "note" (a command, or something else small).
    pub kind: String,
    pub text: String,
    /// A tool's name; a tool use's id (a result names it too).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// One line about a tool use: the command, the file...
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub error: bool,
    /// The language of a tool's text, to colour it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lang: String,
    /// The account that sent a message from the hub (the chat page, or
    /// "hub:<user>" for thorn chat send).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
}

/// What the chat's terminal shows.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Screen {
    /// "idle", "busy" (working: Escape stops it), "asking" (a question with
    /// choices), "stopped" (not running), "elsewhere" (running, but not in
    /// a terminal of the hub: in the Claude app).
    pub state: String,
    /// The question, and its choices (the key to press, what it says).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub question: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Feed {
    pub items: Vec<Item>,
    /// Where to read from next time.
    pub offset: u64,
    /// The transcript was read from its start (or a window before its
    /// end): the page should start over with these items.
    pub reset: bool,
    /// Older messages were left out: they end at `start`.
    pub cut: bool,
    #[serde(default)]
    pub start: u64,
    pub title: String,
    pub screen: Screen,
    /// The hub can type into it (it runs in a terminal of the hub).
    pub typing: bool,
    /// The model of Claude's latest answer read now (empty: none read).
    #[serde(default)]
    pub model: String,
    /// The space's settings: its model and effort level, if set.
    #[serde(default)]
    pub model_setting: String,
    #[serde(default)]
    pub effort: String,
    /// How far the account asking may go with the space (set by the API).
    #[serde(default)]
    pub level: Option<crate::state::Level>,
    /// Root commands of the space waiting for approval (set by the API,
    /// for an account that may decide on them).
    #[serde(default)]
    pub asks: Vec<crate::asks::Ask>,
}

/// The models and effort levels the chat page offers (Claude Code's
/// /model and /effort take these).
pub const MODELS: &[&str] = &["opus", "sonnet", "haiku", "fable"];
pub const EFFORTS: &[&str] = &["low", "medium", "high", "xhigh", "max", "auto"];

/// The model of the latest answer in transcript lines.
fn last_model(text: &str) -> String {
    text.lines()
        .rev()
        .filter(|l| l.contains("\"assistant\""))
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v["message"]["model"].as_str().map(String::from))
        .find(|m| m.starts_with("claude"))
        .unwrap_or_default()
}

/// The model and effort level in the space's Claude Code settings.
fn settings(s: &Space) -> (String, String) {
    let path = paths::space_home(&s.key).join(".claude/settings.json");
    let Ok(uid) = crate::ops::space_uid(&s.key) else {
        return Default::default();
    };
    let Ok(f) = open_own(&path, uid) else {
        return Default::default();
    };
    let mut text = String::new();
    let _ = f.take(256 * 1024).read_to_string(&mut text);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    let get = |k: &str| v[k].as_str().unwrap_or("").chars().take(60).collect();
    (get("model"), get("effortLevel"))
}

/// A chat by (the start of) its id, and its transcript; a new chat the
/// hub runs has none until its first message, so by its whole id.
fn locate(s: &Space, id: &str) -> Result<(String, Option<std::path::PathBuf>)> {
    match find_chat(&s.key, id) {
        Ok((id, path)) => Ok((id, Some(path))),
        Err(e) => {
            let id = id.trim().to_ascii_lowercase();
            if uuid::Uuid::parse_str(&id).is_ok() && target(s, &id).is_some() {
                Ok((id, None))
            } else {
                Err(e)
            }
        }
    }
}

/// The chat's transcript from `from` on (None: its latest part), and its
/// terminal.
pub fn feed(name: &str, id: &str, from: Option<u64>, before: Option<u64>) -> Result<Feed> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?;
    let (id, path) = locate(s, id)?;
    let (model_setting, effort) = settings(s);
    let Some(path) = path else {
        return Ok(Feed {
            reset: from.is_none(),
            screen: screen(s, &id, Path::new("")),
            typing: true,
            model_setting,
            effort,
            ..Feed::default()
        });
    };
    let mut f = open_own(&path, crate::ops::space_uid(&s.key)?)?;
    let len = f.metadata()?.len();
    if let Some(before) = before {
        return earlier(&mut f, before.min(len), &s.key, &id);
    }
    let (start, reset) = match from {
        Some(o) if o <= len && len - o <= WINDOW => (o, false),
        _ => (len.saturating_sub(WINDOW), true),
    };
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    (&mut f).take(len - start).read_to_end(&mut buf)?;
    let mut text = &buf[..];
    let cut = reset && start > 0;
    let mut start = start;
    if cut {
        // From the first whole line.
        let skip = text
            .iter()
            .position(|&b| b == b'\n')
            .map_or(text.len(), |i| i + 1);
        text = &text[skip..];
        start += skip as u64;
    }
    // Only whole lines; a line being written is read next time.
    let whole = text.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    let offset = len - (text.len() - whole) as u64;
    let lines = String::from_utf8_lossy(&text[..whole]);
    let mut items = parse(&lines);
    senders(&mut items, &s.key, &id);
    let model = last_model(&lines);
    let typing = target(s, &id).is_some();
    let screen = screen(s, &id, &path);
    // The name is near the end; read again with each start over.
    let title = if reset {
        crate::ops::chat_title(&String::from_utf8_lossy(text)).unwrap_or_default()
    } else {
        String::new()
    };
    Ok(Feed {
        items,
        offset,
        reset,
        cut,
        start,
        title,
        screen,
        typing,
        model,
        model_setting,
        effort,
        level: None,
        asks: Vec::new(),
    })
}

/// Marks the messages sent from the hub with who sent them, matching
/// them in order with what the space's log recorded.
fn senders(items: &mut [Item], key: &str, id: &str) {
    if !items.iter().any(|i| i.kind == "user") {
        return;
    }
    let mut sent = crate::activity::sent_to(key, id);
    for it in items.iter_mut().filter(|i| i.kind == "user") {
        if let Some(at) = sent.iter().position(|(_, m)| m.trim() == it.text.trim()) {
            it.by = Some(sent.remove(at).0);
        }
    }
}

/// The messages before `before` (where an earlier read started, so at a
/// line's start): a window's worth, from a whole line.
fn earlier(f: &mut std::fs::File, before: u64, key: &str, id: &str) -> Result<Feed> {
    let mut start = before.saturating_sub(WINDOW);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.take(before - start).read_to_end(&mut buf)?;
    let mut text = &buf[..];
    if start > 0 {
        let skip = text
            .iter()
            .position(|&b| b == b'\n')
            .map_or(text.len(), |i| i + 1);
        text = &text[skip..];
        start += skip as u64;
    }
    let mut items = parse(&String::from_utf8_lossy(text));
    senders(&mut items, key, id);
    Ok(Feed {
        items,
        cut: start > 0,
        start,
        ..Feed::default()
    })
}

/// Opens a file of the space's for reading: a real file it owns, not a
/// link it planted.
fn open_own(path: &Path, uid: u32) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let m = f.metadata()?;
    if !m.is_file() || m.uid() != uid {
        bail!("{} is not the space's own file", path.display());
    }
    Ok(f)
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n… ({} more characters)", &s[..end], s.len() - end)
}

/// The text of a tool result's content: a string, or text parts.
fn content_text(c: &serde_json::Value) -> String {
    match c {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|x| match x["type"].as_str() {
                Some("text") => x["text"].as_str().map(String::from),
                Some("image") => Some("[image]".into()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// A line about a tool use: its command, file, pattern or address.
fn tool_summary(input: &serde_json::Value) -> String {
    for k in [
        "command",
        "file_path",
        "notebook_path",
        "pattern",
        "url",
        "query",
        "description",
        "prompt",
    ] {
        if let Some(v) = input[k].as_str() {
            let line = v.lines().next().unwrap_or("");
            return line.chars().take(160).collect();
        }
    }
    String::new()
}

/// A tool use's input, for reading: an edit as its lines out and in,
/// else the input as JSON.
fn tool_text(name: &str, input: &serde_json::Value) -> String {
    let diff = |old: &str, new: &str| {
        let mut t = String::new();
        for l in old.lines() {
            t.push_str(&format!("- {l}\n"));
        }
        for l in new.lines() {
            t.push_str(&format!("+ {l}\n"));
        }
        t
    };
    let text = match name {
        "Edit" => diff(
            input["old_string"].as_str().unwrap_or(""),
            input["new_string"].as_str().unwrap_or(""),
        ),
        "MultiEdit" => input["edits"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| {
                diff(
                    e["old_string"].as_str().unwrap_or(""),
                    e["new_string"].as_str().unwrap_or(""),
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
        "Write" => input["content"].as_str().unwrap_or("").to_string(),
        "Bash" => input["command"].as_str().unwrap_or("").to_string(),
        _ => serde_json::to_string_pretty(input).unwrap_or_default(),
    };
    clip(&text, MAX_TOOL)
}

/// A user message's text, unless it is one a tool or command made.
fn user_note(t: &str) -> Option<Item> {
    let t = t.trim();
    let tag = |name: &str| -> Option<String> {
        let open = format!("<{name}>");
        let close = format!("</{name}>");
        let a = t.find(&open)? + open.len();
        let b = t[a..].find(&close)? + a;
        Some(t[a..b].trim().to_string())
    };
    if let Some(cmd) = tag("command-name") {
        let args = tag("command-args").unwrap_or_default();
        return Some(note(format!("{cmd} {args}").trim().to_string()));
    }
    if let Some(out) = tag("local-command-stdout") {
        return (!out.is_empty()).then(|| note(clip(&out, MAX_TOOL)));
    }
    if t.starts_with('<') || t.is_empty() {
        return None;
    }
    Some(Item {
        kind: "user".into(),
        text: clip(t, MAX_TEXT),
        name: None,
        id: None,
        summary: String::new(),
        error: false,
        lang: String::new(),
        by: None,
    })
}

fn note(text: String) -> Item {
    Item {
        kind: "note".into(),
        text,
        name: None,
        id: None,
        summary: String::new(),
        error: false,
        lang: String::new(),
        by: None,
    }
}

/// The items of transcript lines.
pub fn parse(text: &str) -> Vec<Item> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v["isMeta"].as_bool() == Some(true) || v["isSidechain"].as_bool() == Some(true) {
            continue;
        }
        let content = &v["message"]["content"];
        match v["type"].as_str() {
            Some("user") => match content {
                serde_json::Value::String(s) => out.extend(user_note(s)),
                serde_json::Value::Array(parts) => {
                    for p in parts {
                        match p["type"].as_str() {
                            Some("text") => out.extend(user_note(p["text"].as_str().unwrap_or(""))),
                            Some("image") => out.push(Item {
                                kind: "user".into(),
                                text: "[image]".into(),
                                name: None,
                                id: None,
                                summary: String::new(),
                                error: false,
                                lang: String::new(),
                                by: None,
                            }),
                            Some("tool_result") => out.push(Item {
                                kind: "result".into(),
                                text: clip(&content_text(&p["content"]), MAX_TOOL),
                                name: None,
                                id: p["tool_use_id"].as_str().map(String::from),
                                summary: String::new(),
                                error: p["is_error"].as_bool() == Some(true),
                                lang: String::new(),
                                by: None,
                            }),
                            _ => {}
                        }
                    }
                }
                _ => {}
            },
            Some("assistant") => {
                for p in content.as_array().into_iter().flatten() {
                    match p["type"].as_str() {
                        Some("text") => {
                            let t = p["text"].as_str().unwrap_or("").trim();
                            if !t.is_empty() {
                                out.push(Item {
                                    kind: "assistant".into(),
                                    text: clip(t, MAX_TEXT),
                                    name: None,
                                    id: None,
                                    summary: String::new(),
                                    error: false,
                                    lang: String::new(),
                                    by: None,
                                });
                            }
                        }
                        Some("tool_use") => {
                            let name = p["name"].as_str().unwrap_or("tool").to_string();
                            let lang = match name.as_str() {
                                "Bash" => "sh".to_string(),
                                "Write" => crate::highlight::lang_of_path(
                                    p["input"]["file_path"].as_str().unwrap_or(""),
                                )
                                .to_string(),
                                "Edit" | "MultiEdit" => String::new(),
                                _ => "json".to_string(),
                            };
                            out.push(Item {
                                kind: "tool".into(),
                                text: tool_text(&name, &p["input"]),
                                summary: tool_summary(&p["input"]),
                                name: Some(name),
                                id: p["id"].as_str().map(String::from),
                                error: false,
                                lang,
                                by: None,
                            });
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// The tmux window the hub runs the chat in, if it does.
fn target(s: &Space, id: &str) -> Option<String> {
    if sys::unit_state(&paths::space_unit(&s.key)) != "active" {
        return None;
    }
    if main_conversation(s) == Some(id) {
        return Some("main".into());
    }
    chat_windows(&s.key)
        .into_iter()
        .find(|w| id.starts_with(w.as_str()))
        .map(|w| format!("chat-{w}"))
}

fn tmux(s: &Space, args: &[&str]) -> Result<String> {
    let sock = paths::tmux_socket(&s.key);
    let sock = sock.to_str().context("socket path")?;
    let mut all = vec!["-S", sock];
    all.extend_from_slice(args);
    sys::output("tmux", &all)
}

fn screen(s: &Space, id: &str, path: &Path) -> Screen {
    let Some(t) = target(s, id) else {
        return Screen {
            state: if chat_running(s, id, path) {
                "elsewhere"
            } else {
                "stopped"
            }
            .into(),
            ..Screen::default()
        };
    };
    match tmux(s, &["capture-pane", "-p", "-J", "-t", &t]) {
        Ok(text) => read_screen(&text),
        Err(_) => Screen {
            state: "stopped".into(),
            ..Screen::default()
        },
    }
}

/// What Claude Code's terminal shows: a question with numbered choices
/// near its end, working ("esc to interrupt"), or waiting.
pub fn read_screen(text: &str) -> Screen {
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    let end = lines
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .map_or(0, |i| i + 1);
    let tail = &lines[end.saturating_sub(30)..end];
    // Choices: "❯ 1. Yes", "  2. Yes, and don't ask again", ...
    let mut choices: Vec<(String, String)> = Vec::new();
    let mut first = None;
    let mut last = 0;
    for (i, l) in tail.iter().enumerate() {
        let inner = l.trim_start().trim_start_matches(['│', '|']).trim_start();
        let t = inner.trim_start_matches(['❯', '>', '›']).trim_start();
        let digits: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
        let rest = (digits.len() == 1)
            .then(|| t[1..].strip_prefix(". "))
            .flatten();
        let Some(rest) = rest else {
            continue;
        };
        if digits == "1" {
            // A new list starts.
            choices.clear();
            first = Some(i);
        }
        if digits == (choices.len() + 1).to_string() {
            let label = rest.trim().trim_end_matches(['│', '|']).trim();
            choices.push((digits, label.to_string()));
            last = i;
        }
    }
    // Claude Code shows its input line again once it stops asking: a
    // numbered list above that is something it wrote.
    let input_after = tail.iter().skip(last + 1).any(|l| {
        let t = l.trim_start().trim_start_matches(['│', '|']).trim_start();
        (t.starts_with('>') || t.starts_with('❯'))
            && !t[t.char_indices().nth(1).map_or(t.len(), |(i, _)| i)..]
                .trim_start()
                .starts_with(|c: char| c.is_ascii_digit())
    });
    if choices.len() >= 2 && !input_after {
        let at = first.unwrap_or(0);
        let question = tail[..at]
            .iter()
            .rev()
            .map(|l| {
                l.trim()
                    .trim_matches(['│', '|', '╭', '╰', '─', '╮', '╯'])
                    .trim()
            })
            .take_while(|l| {
                let numbered =
                    l.len() > 2 && l.as_bytes()[0].is_ascii_digit() && l[1..].starts_with(". ");
                !l.is_empty() && !numbered
            })
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        return Screen {
            state: "asking".into(),
            question,
            choices,
        };
    }
    let busy = tail
        .iter()
        .any(|l| l.to_ascii_lowercase().contains("esc to interrupt"));
    Screen {
        state: if busy { "busy" } else { "idle" }.into(),
        ..Screen::default()
    }
}

/// The running chat's tmux window, or why there is none.
fn typing_target(name: &str, id: &str) -> Result<(Space, String, std::path::PathBuf)> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?.clone();
    let (id, path) = locate(&s, id)?;
    let path = path.unwrap_or_else(|| std::path::PathBuf::from(format!("{id}.jsonl")));
    let Some(t) = target(&s, &id) else {
        if chat_running(&s, &id, &path) {
            bail!("this chat runs in the Claude app, not in a terminal of the hub: type there");
        }
        bail!("this chat is not running: continue it first");
    };
    Ok((s, t, path))
}

/// Types a message into the chat and sends it; `by` is recorded with it.
pub fn send(name: &str, id: &str, text: &str, by: &str) -> Result<()> {
    let text = text.trim_end();
    if text.trim().is_empty() {
        bail!("nothing to send");
    }
    if text.len() > 100_000 {
        bail!("that message is too long");
    }
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        bail!("the message holds control characters");
    }
    let (s, t, path) = typing_target(name, id)?;
    let now = screen(&s, id_of(&path), &path);
    if now.state == "asking" {
        bail!("Claude is asking a question; answer it first");
    }
    let sock = paths::tmux_socket(&s.key);
    let sock = sock.to_str().context("socket path")?;
    let buffer = format!("bt-chat-{t}");
    let mut child = Command::new("tmux")
        .args(["-S", sock, "load-buffer", "-b", &buffer, "-"])
        .stdin(Stdio::piped())
        .spawn()
        .context("tmux load-buffer")?;
    child
        .stdin
        .take()
        .context("tmux stdin")?
        .write_all(text.as_bytes())?;
    if !child.wait()?.success() {
        bail!("tmux could not take the message");
    }
    // As a paste, so lines are not sent one by one.
    tmux(&s, &["paste-buffer", "-p", "-d", "-b", &buffer, "-t", &t])?;
    std::thread::sleep(std::time::Duration::from_millis(300));
    tmux(&s, &["send-keys", "-t", &t, "Enter"])?;
    crate::activity::record(&s.key, id_of(&path), by, text, "")?;
    Ok(())
}

fn id_of(path: &Path) -> &str {
    path.file_stem().and_then(|s| s.to_str()).unwrap_or("")
}

/// Keys the chat page may press: Escape (stop), and a choice's number
/// while Claude Code asks.
pub fn key(name: &str, id: &str, key: &str, by: &str) -> Result<()> {
    let (s, t, path) = typing_target(name, id)?;
    let what = match key {
        "Escape" => "stopped Claude".to_string(),
        k if k.len() == 1 && k.chars().all(|c| c.is_ascii_digit()) => {
            let now = screen(&s, id_of(&path), &path);
            let Some((_, label)) = now.choices.iter().find(|(n, _)| n == k) else {
                bail!("Claude is not asking that any more; look again");
            };
            format!(
                "answered {:?} with {k}. {label}",
                now.question.lines().last().unwrap_or("")
            )
        }
        _ => bail!("the chat page does not press {key:?}"),
    };
    tmux(&s, &["send-keys", "-t", &t, key])?;
    crate::activity::record(&s.key, id_of(&path), by, "", &what)?;
    Ok(())
}

/// A file for the chat: saved, as the space's user, in .uploads in the
/// chat's folder. Its path there, to mention as @path.
pub fn upload(name: &str, id: &str, filename: &str, data: &[u8], by: &str) -> Result<String> {
    sys::require_root()?;
    if data.len() > MAX_UPLOAD {
        bail!("files up to {} MB", MAX_UPLOAD >> 20);
    }
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?;
    let (chat, _) = locate(s, id)?;
    let clean: String = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .take(80)
        .collect();
    let clean = clean.trim_start_matches(['.', '-']);
    let clean = if clean.is_empty() { "file" } else { clean };
    let stamp = humantime::format_rfc3339_seconds(std::time::SystemTime::now())
        .to_string()
        .replace([':', '-'], "")
        .replace('T', "-")
        .trim_end_matches('Z')
        .to_string();
    let rel = format!(".uploads/{stamp}-{clean}");
    let dir = s.workdir();
    // As the space's user: a link it planted leads nowhere it may not write.
    let mut child = Command::new("runuser")
        .args(["-u", &paths::unix_user(&s.key), "--", "sh", "-c"])
        .arg("umask 077 && set -C && mkdir -p .uploads && cat > \"$1\"")
        .args(["sh", &rel])
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("runuser")?;
    child.stdin.take().context("stdin")?.write_all(data)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "could not save the file: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    crate::activity::record(&s.key, &chat, by, "", &format!("added the file {rel}"))?;
    Ok(rel)
}

/// A slash command the chat page offers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SlashCommand {
    pub name: String,
    pub about: String,
}

const BUILT_IN: &[(&str, &str)] = &[
    ("compact", "Summarise the chat so far, to free room"),
    ("context", "How full the context is"),
    ("cost", "What this chat has used"),
    ("model", "Choose the model"),
    ("rename", "Name this chat (shows in the Claude app)"),
    ("review", "Review a pull request"),
    ("init", "Write a CLAUDE.md for this folder"),
    ("memory", "Edit Claude's memory files"),
    ("status", "Version, model, account"),
    ("help", "Every command"),
    (
        "clear",
        "Start over (a new chat: this page stops following it)",
    ),
];

/// Built-in commands, then the space's own (commands and skills, of the
/// space's user and of its folder).
pub fn commands(name: &str) -> Result<Vec<SlashCommand>> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?;
    let uid = crate::ops::space_uid(&s.key)?;
    let mut out: Vec<SlashCommand> = BUILT_IN
        .iter()
        .map(|(n, a)| SlashCommand {
            name: n.to_string(),
            about: a.to_string(),
        })
        .collect();
    let home = paths::space_home(&s.key).join(".claude");
    let work = s.workdir().join(".claude");
    for base in [&home, &work] {
        own_commands(&base.join("commands"), "", uid, 0, &mut out);
        own_skills(&base.join("skills"), uid, &mut out);
    }
    out.truncate(300);
    Ok(out)
}

/// The `description:` of a Markdown file's front matter.
fn description(path: &Path, uid: u32) -> String {
    let Ok(f) = open_own(path, uid) else {
        return String::new();
    };
    let mut head = String::new();
    let _ = f.take(4096).read_to_string(&mut head);
    head.lines()
        .find_map(|l| l.strip_prefix("description:"))
        .map(|d| {
            d.trim()
                .trim_matches(['"', '\''])
                .chars()
                .take(160)
                .collect()
        })
        .unwrap_or_default()
}

fn real_dir(e: &std::fs::DirEntry) -> bool {
    e.file_type().is_ok_and(|t| t.is_dir())
}

fn own_commands(dir: &Path, prefix: &str, uid: u32, depth: u32, out: &mut Vec<SlashCommand>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if n.starts_with('.') {
            continue;
        }
        if real_dir(&e) && depth < 3 {
            own_commands(&e.path(), &format!("{prefix}{n}:"), uid, depth + 1, out);
        } else if let Some(stem) = n.strip_suffix(".md") {
            if e.file_type().is_ok_and(|t| t.is_file()) {
                out.push(SlashCommand {
                    name: format!("{prefix}{stem}"),
                    about: description(&e.path(), uid),
                });
            }
        }
    }
}

fn own_skills(dir: &Path, uid: u32, out: &mut Vec<SlashCommand>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let n = e.file_name().to_string_lossy().to_string();
        if n.starts_with('.') || !real_dir(&e) {
            continue;
        }
        out.push(SlashCommand {
            about: description(&e.path().join("SKILL.md"), uid),
            name: n,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_items() {
        let lines = [
            r#"{"type":"user","message":{"role":"user","content":"check the disks"}}"#,
            r#"{"type":"user","isMeta":true,"message":{"role":"user","content":"meta"}}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"hm"},{"type":"text","text":"Looking."},{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"df -h\nmore","description":"disks"}}]}}"#,
            r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"/dev/sda1 50%","is_error":false}]}}"#,
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t2","name":"Edit","input":{"file_path":"/a","old_string":"x","new_string":"y"}}]}}"#,
            r#"{"type":"user","message":{"content":"<command-name>/compact</command-name><command-args></command-args>"}}"#,
            r#"{"type":"user","message":{"content":"<local-command-stdout></local-command-stdout>"}}"#,
            r#"not json"#,
        ];
        let items = parse(&lines.join("\n"));
        let kinds: Vec<&str> = items.iter().map(|i| i.kind.as_str()).collect();
        assert_eq!(
            kinds,
            ["user", "assistant", "tool", "result", "tool", "note"]
        );
        assert_eq!(items[2].summary, "df -h");
        assert_eq!(items[2].text, "df -h\nmore");
        assert_eq!(items[3].id.as_deref(), Some("t1"));
        assert_eq!(items[4].text, "- x\n+ y\n");
        assert_eq!(items[5].text, "/compact");
    }

    #[test]
    fn screens_read() {
        let asking = "\
╭──────────────────────────────╮
│ Bash command                 │
│   rm -rf /tmp/x              │
│ Do you want to proceed?      │
│ ❯ 1. Yes                     │
│   2. Yes, and don't ask again │
│   3. No, and tell Claude what to do differently (esc) │
╰──────────────────────────────╯
";
        let s = read_screen(asking);
        assert_eq!(s.state, "asking");
        assert_eq!(s.choices.len(), 3);
        assert_eq!(s.choices[0], ("1".to_string(), "Yes".to_string()));
        assert!(
            s.question.contains("Do you want to proceed?"),
            "{}",
            s.question
        );
        assert_eq!(
            read_screen("✻ Thinking… (esc to interrupt)\n> ").state,
            "busy"
        );
        assert_eq!(read_screen("> \n  ? for shortcuts").state, "idle");
        // A numbered list in Claude's answer is not a question... unless
        // it is the last thing shown; then it is offered, and the page
        // shows it with the screen's text to judge by.
        assert_eq!(read_screen("1. one\nsome text\n> ").state, "idle");
        assert_eq!(
            read_screen("Options:\n1. one\n2. two\n\n> \n? for shortcuts").state,
            "idle"
        );
        let again = "1. old\n2. list\nDo you want to make this edit?\n❯ 1. Yes\n  2. No";
        let s = read_screen(again);
        assert_eq!(s.state, "asking");
        assert_eq!(s.choices[1].1, "No");
        assert_eq!(s.question, "Do you want to make this edit?");
    }

    #[test]
    fn latest_model() {
        let t = [
            r#"{"type":"assistant","message":{"model":"claude-sonnet-5-5","content":[]}}"#,
            r#"{"type":"assistant","message":{"model":"claude-opus-5-5","content":[]}}"#,
            r#"{"type":"assistant","message":{"model":"<synthetic>","content":[]}}"#,
        ]
        .join("\n");
        assert_eq!(last_model(&t), "claude-opus-5-5");
        assert_eq!(last_model("{}"), "");
    }

    #[test]
    fn clipped_on_a_character() {
        let t = clip("ééé", 3);
        assert!(t.starts_with('é') && t.contains("more characters"));
    }
}
