//! What each space did: every shell command its agent ran, copied by root
//! from the agent's transcripts into /var/log/blackthorn/<key>.log once a
//! minute (from `thorn _tick`).
//!
//! The transcripts belong to the space, so an agent talked into it could
//! edit or delete them; the copy belongs to root and only grows. What a
//! space writes and erases within the same minute can still be missed, and
//! a transcript that shrinks is noted as such. The machines themselves keep
//! their own record (see `remote`).

use crate::config::{CLAUDE, CODEX};
use crate::paths;
use crate::state::{now, State};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

/// One command a space ran.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    /// Unix seconds, from the transcript.
    pub t: u64,
    /// The chat it was in (the first 8 characters of its id).
    pub chat: String,
    /// The command line. Empty for a note.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cmd: String,
    /// Something about the record itself, such as a transcript that shrank.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// Who did it from the hub: a web account, or "hub:<user>" for the
    /// hub's command line. With `msg`: a message they typed into the chat;
    /// with `note`: a key they pressed, a file they added.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub by: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub msg: String,
}

impl Entry {
    /// The machine it ran on, when it is `ssh <host> ...`; else the hub.
    pub fn host(&self) -> Option<&str> {
        let mut w = self.cmd.split_whitespace();
        if w.next() != Some("ssh") {
            return None;
        }
        // Options that take a value (`-o BatchMode=yes`, `-p 22`).
        while let Some(a) = w.next() {
            match a.strip_prefix('-') {
                Some(o) if o.len() == 1 && "bcDEeFIiJLlmOopQRSWw".contains(o) => {
                    w.next();
                }
                Some(_) => {}
                None => return Some(a),
            }
        }
        None
    }
}

/// The longest command kept, in characters.
const CMD_MAX: usize = 4000;
/// Read at most this much of one transcript per tick.
const READ_MAX: u64 = 8 << 20;
/// A log this big is moved to <key>.log.1 (one older file is kept).
const LOG_MAX: u64 = 10 << 20;

#[derive(Debug, Default, Serialize, Deserialize)]
struct Seen {
    /// Transcript path -> how many bytes were read.
    #[serde(default)]
    offsets: BTreeMap<String, u64>,
}

/// From `thorn _tick`: copies new commands from every Claude space's
/// transcripts. Errors are printed, not fatal.
pub fn tick(state: &State) {
    if let Err(e) = copy_all(state) {
        eprintln!("activity: {e:#}");
    }
}

fn copy_all(state: &State) -> Result<()> {
    crate::sys::mkdir(Path::new(paths::ACTIVITY_DIR), 0o700)?;
    let seen_path = Path::new(paths::ACTIVITY_SEEN_FILE);
    let mut seen: Seen = std::fs::read_to_string(seen_path)
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default();
    let mut live = BTreeMap::new();
    for s in state
        .spaces
        .values()
        .filter(|s| s.agent == CLAUDE || s.agent == CODEX)
    {
        let codex = s.agent == CODEX;
        let files = if codex {
            codex_files(&s.key)
        } else {
            crate::ops::chat_files(&s.key)
        };
        let mut new = Vec::new();
        for (id, path) in files {
            let key = path.display().to_string();
            let from = seen.offsets.get(&key).copied().unwrap_or(0);
            match read_from(&path, from) {
                Ok((text, to, shrank)) => {
                    let chat = id[..8.min(id.len())].to_string();
                    if shrank {
                        new.push(Entry {
                            t: now(),
                            chat: chat.clone(),
                            cmd: String::new(),
                            note: "transcript got shorter: something edited or replaced it; \
                                   commands it held before are in this log"
                                .into(),
                            ..Default::default()
                        });
                    }
                    new.extend(if codex {
                        codex_commands(&text, &chat)
                    } else {
                        commands(&text, &chat)
                    });
                    live.insert(key, to);
                }
                Err(_) => {
                    live.insert(key, from);
                }
            }
        }
        if !new.is_empty() {
            append(&s.key, &new)?;
        }
    }
    // Forget transcripts that are gone.
    seen.offsets = live;
    crate::sys::write_file(seen_path, &toml::to_string(&seen)?, 0o600, None)
}

/// The complete lines after `from`, the offset after them, and whether the
/// file got shorter than `from` (then it is read from the start).
fn read_from(path: &Path, from: u64) -> Result<(String, u64, bool)> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        anyhow::bail!("not a file");
    }
    let len = meta.len();
    let (start, shrank) = if len < from { (0, true) } else { (from, false) };
    if len == start {
        return Ok((String::new(), start, shrank));
    }
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.take(READ_MAX).read_to_end(&mut buf)?;
    // Only whole lines: the last one may still be being written.
    let end = buf.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    buf.truncate(end);
    Ok((
        String::from_utf8_lossy(&buf).into_owned(),
        start + end as u64,
        shrank,
    ))
}

/// The shell commands in transcript lines.
pub fn commands(text: &str, chat: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.contains("\"tool_use\"") {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v["type"] != "assistant" {
            continue;
        }
        let t = v["timestamp"]
            .as_str()
            .and_then(|s| humantime::parse_rfc3339_weak(s.trim_end_matches('Z')).ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or_else(now, |d| d.as_secs());
        let Some(items) = v["message"]["content"].as_array() else {
            continue;
        };
        for it in items {
            if it["type"] != "tool_use" || it["name"] != "Bash" {
                continue;
            }
            let Some(cmd) = it["input"]["command"].as_str() else {
                continue;
            };
            let mut cmd = cmd.trim().to_string();
            if cmd.chars().count() > CMD_MAX {
                cmd = cmd.chars().take(CMD_MAX).collect::<String>() + "…";
            }
            out.push(Entry {
                t,
                chat: chat.to_string(),
                cmd,
                ..Default::default()
            });
        }
    }
    out
}

/// A Codex space's session transcripts ("rollouts"):
/// ~/.codex/sessions/YYYY/MM/DD/rollout-<time>-<thread id>.jsonl, with the
/// thread id. Compressed ones (.jsonl.zst, made of old sessions) are not
/// read: they were read while they were written. Symbolic links are not
/// followed.
pub fn codex_files(key: &str) -> Vec<(String, std::path::PathBuf)> {
    fn walk(dir: &Path, depth: u32, out: &mut Vec<(String, std::path::PathBuf)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let Ok(t) = e.file_type() else { continue };
            let p = e.path();
            if t.is_dir() && depth < 3 {
                walk(&p, depth + 1, out);
            } else if t.is_file() {
                if let Some(id) = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(codex_thread_id)
                {
                    out.push((id, p));
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(&paths::space_home(key).join(".codex/sessions"), 0, &mut out);
    out
}

/// The thread id in a rollout file's name, "rollout-2026-11-25T08-00-05-
/// <uuid>.jsonl" (or "..._<rollout id>.jsonl" after a revert).
pub fn codex_thread_id(name: &str) -> Option<String> {
    let core = name.strip_prefix("rollout-")?.strip_suffix(".jsonl")?;
    let ids = core.get(20..)?;
    let thread = ids.split('_').next()?;
    uuid::Uuid::parse_str(thread).ok()?;
    Some(thread.to_string())
}

/// The shell commands in Codex rollout lines: {"timestamp", "type":
/// "response_item", "payload": a function call (exec_command {cmd},
/// shell_command {command}, shell {command: [argv]}) or a local shell call
/// (action.command: [argv])}.
pub fn codex_commands(text: &str, chat: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.contains("\"response_item\"") {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v["type"] != "response_item" {
            continue;
        }
        let p = &v["payload"];
        let cmd = match p["type"].as_str() {
            Some("function_call") => {
                let args: serde_json::Value = p["arguments"]
                    .as_str()
                    .and_then(|a| serde_json::from_str(a).ok())
                    .unwrap_or_else(|| p["arguments"].clone());
                match p["name"].as_str() {
                    Some("exec_command") => args["cmd"].as_str().map(str::to_string),
                    Some("shell_command") => args["command"].as_str().map(str::to_string),
                    Some("shell") => argv_text(&args["command"]),
                    _ => None,
                }
            }
            Some("local_shell_call") => argv_text(&p["action"]["command"]),
            _ => None,
        };
        let Some(cmd) = cmd else { continue };
        let t = v["timestamp"]
            .as_str()
            .and_then(|s| humantime::parse_rfc3339_weak(s.trim_end_matches('Z')).ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or_else(now, |d| d.as_secs());
        let mut cmd = cmd.trim().to_string();
        if cmd.chars().count() > CMD_MAX {
            cmd = cmd.chars().take(CMD_MAX).collect::<String>() + "…";
        }
        out.push(Entry {
            t,
            chat: chat.to_string(),
            cmd,
            ..Default::default()
        });
    }
    out
}

/// An argv as one command line: the script of `bash -lc SCRIPT` (how Codex
/// runs commands), else the words joined.
fn argv_text(v: &serde_json::Value) -> Option<String> {
    let a: Vec<&str> = v.as_array()?.iter().filter_map(|x| x.as_str()).collect();
    match a.as_slice() {
        [] => None,
        [sh, flag, script]
            if sh.ends_with("sh") && flag.starts_with('-') && flag.ends_with('c') =>
        {
            Some(script.to_string())
        }
        _ => Some(a.join(" ")),
    }
}

fn append(key: &str, entries: &[Entry]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = paths::activity_file(key);
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_MAX) {
        let _ = std::fs::rename(&path, path.with_extension("log.1"));
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mut text = String::new();
    for e in entries {
        text.push_str(&serde_json::to_string(e)?);
        text.push('\n');
    }
    f.write_all(text.as_bytes())?;
    Ok(())
}

/// Records what someone did in a chat from the hub: a message they sent
/// (`msg`), or something else (`note`). The chat is the first 8
/// characters of its id.
pub fn record(key: &str, chat: &str, by: &str, msg: &str, note: &str) -> Result<()> {
    append(
        key,
        &[Entry {
            t: now(),
            chat: chat[..8.min(chat.len())].to_string(),
            by: by.to_string(),
            msg: msg.chars().take(20_000).collect(),
            note: note.to_string(),
            ..Default::default()
        }],
    )
}

/// The messages sent to a chat from the hub, oldest first: (who, text).
pub fn sent_to(key: &str, chat: &str) -> Vec<(String, String)> {
    let chat = &chat[..8.min(chat.len())];
    let Ok(mut f) = std::fs::File::open(paths::activity_file(key)) else {
        return Vec::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = f.seek(SeekFrom::Start(len.saturating_sub(4 << 20)));
    let mut buf = String::new();
    let _ = f.read_to_string(&mut buf);
    buf.lines()
        .filter(|l| l.contains("\"msg\""))
        .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
        .filter(|e| e.chat == chat && !e.msg.is_empty())
        .map(|e| (e.by, e.msg))
        .collect()
}

/// The latest `limit` commands of a space, newest first.
pub fn list(name: &str, limit: usize) -> Result<Vec<Entry>> {
    crate::sys::require_root()?;
    let (_, state) = crate::ctx::read_only()?;
    let s = state.space(name)?;
    let path = paths::activity_file(&s.key);
    let mut f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    // The end of the file holds the newest.
    let len = f.metadata()?.len();
    let tail = (limit as u64 * 600).clamp(64 << 10, 4 << 20);
    f.seek(SeekFrom::Start(len.saturating_sub(tail)))?;
    let mut buf = String::new();
    f.read_to_string(&mut buf)?;
    let mut v: Vec<Entry> = buf
        .lines()
        .rev()
        .filter_map(|l| serde_json::from_str(l).ok())
        .take(limit)
        .collect();
    v.truncate(limit);
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_shell_commands() {
        let text = concat!(
            r#"{"type":"user","message":{"content":"how full is the disk?"},"timestamp":"2026-11-20T08:00:00.000Z"}"#,
            "\n",
            r#"{"type":"assistant","timestamp":"2026-11-20T08:00:05.120Z","message":{"content":[{"type":"text","text":"Let me look."},{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ssh fig 'df -h /'","description":"disk"}},{"type":"tool_use","id":"t2","name":"Read","input":{"file_path":"/etc/hosts"}}]}}"#,
            "\n",
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"  uptime  "}}]}}"#,
            "\n",
            "not json \"tool_use\"\n",
        );
        let v = commands(text, "c7d81a95");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].cmd, "ssh fig 'df -h /'");
        assert_eq!(v[0].t, 1_795_161_605);
        assert_eq!(v[0].chat, "c7d81a95");
        assert_eq!(v[0].host(), Some("fig"));
        assert_eq!(v[1].cmd, "uptime");
        assert_eq!(v[1].host(), None);
        let e = Entry {
            t: 0,
            chat: "x".into(),
            cmd: "ssh -o BatchMode=yes nas uptime".into(),
            ..Default::default()
        };
        assert_eq!(e.host(), Some("nas"));
    }

    #[test]
    fn reads_whole_lines_and_notices_shrinking() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.jsonl");
        std::fs::write(&p, "one\ntwo\npart").unwrap();
        let (text, to, shrank) = read_from(&p, 0).unwrap();
        assert_eq!((text.as_str(), to, shrank), ("one\ntwo\n", 8, false));
        std::fs::write(&p, "one\ntwo\npartial\n").unwrap();
        let (text, to, _) = read_from(&p, 8).unwrap();
        assert_eq!((text.as_str(), to), ("partial\n", 16));
        std::fs::write(&p, "new\n").unwrap();
        let (text, to, shrank) = read_from(&p, 16).unwrap();
        assert_eq!((text.as_str(), to, shrank), ("new\n", 4, true));
        let link = dir.path().join("link.jsonl");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(read_from(&link, 0).is_err(), "links are not followed");
    }

    #[test]
    fn finds_codex_commands() {
        let text = concat!(
            r#"{"timestamp":"2026-11-25T08:00:00.000Z","type":"session_meta","payload":{"id":"x"}}"#,
            "\n",
            r#"{"timestamp":"2026-11-25T08:00:05.120Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"ssh fig 'df -h /'\",\"yield_time_ms\":1000}","call_id":"c1"}}"#,
            "\n",
            r#"{"timestamp":"2026-11-25T08:00:06Z","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"uptime\"]}","call_id":"c2"}}"#,
            "\n",
            r#"{"timestamp":"2026-11-25T08:00:07Z","type":"response_item","payload":{"type":"local_shell_call","call_id":"c3","status":"completed","action":{"type":"exec","command":["ls","-la"]}}}"#,
            "\n",
            r#"{"timestamp":"2026-11-25T08:00:08Z","type":"response_item","payload":{"type":"function_call","name":"shell_command","arguments":"{\"command\":\"free -m\"}","call_id":"c4"}}"#,
            "\n",
            r#"{"timestamp":"2026-11-25T08:00:09Z","type":"response_item","payload":{"type":"function_call","name":"apply_patch","arguments":"{}","call_id":"c5"}}"#,
            "\n",
            r#"{"timestamp":"2026-11-25T08:00:10Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"exec_command"}]}}"#,
            "\n",
        );
        let v = codex_commands(text, "0199a213");
        let cmds: Vec<&str> = v.iter().map(|e| e.cmd.as_str()).collect();
        assert_eq!(
            cmds,
            vec!["ssh fig 'df -h /'", "uptime", "ls -la", "free -m"]
        );
        assert_eq!(v[0].host(), Some("fig"));
        assert_eq!(v[0].t, 1795593605);
        assert_eq!(v[0].chat, "0199a213");
    }

    #[test]
    fn codex_rollout_names() {
        assert_eq!(
            codex_thread_id(
                "rollout-2026-11-25T08-00-05-0199a213-81c0-7800-8aa1-bbab2a035a53.jsonl"
            )
            .as_deref(),
            Some("0199a213-81c0-7800-8aa1-bbab2a035a53")
        );
        assert_eq!(
            codex_thread_id("rollout-2026-11-25T08-00-05-0199a213-81c0-7800-8aa1-bbab2a035a53_0199a214-81c0-7800-8aa1-bbab2a035a53.jsonl").as_deref(),
            Some("0199a213-81c0-7800-8aa1-bbab2a035a53")
        );
        assert_eq!(
            codex_thread_id(
                "rollout-2026-11-25T08-00-05-0199a213-81c0-7800-8aa1-bbab2a035a53.jsonl.zst"
            ),
            None
        );
        assert_eq!(codex_thread_id("history.jsonl"), None);
    }
}
