//! thorn new / rm / rename / start / stop / restart / attach / login / ls /
//! connect / disconnect: the CLI side of the space operations in `ops`.

use crate::ops::{self, Action, NewSpace};
use crate::{ctx, paths, sys};
use anyhow::{bail, Context, Result};
use std::os::unix::process::CommandExt;
use std::process::Command;

pub fn new(o: NewSpace) -> Result<()> {
    let done = ops::space_new(o)?;
    let name = done.name;
    let (_, state) = ctx::read_only()?;
    let s = state.space(&name)?;
    let t = crate::state::now();
    let m = s.machines.first().context("the space has no machine")?;
    println!(
        "created space {name}: {} on {}, logs in as {} (Remote Control name {}, user {})",
        s.agent,
        m.host,
        m.tier(t),
        s.rc_name,
        paths::unix_user(&s.key)
    );
    match &m.root {
        Some(r) if r.active(t) => match r.until {
            Some(u) => println!(
                "it has root there until {} UTC, then logs in as {}",
                ops::rfc3339(u),
                m.access
            ),
            None => println!("it has root there until taken back: sudo thorn root {name} --off"),
        },
        _ => {}
    }
    println!("to let it work on more machines: sudo thorn connect {name} HOST");
    for n in &done.notes {
        println!("note: {n}");
    }
    if ops::logged_in(s) {
        println!("it is running; open it with: sudo thorn attach {name}");
    } else {
        if s.agent == crate::config::CODEX {
            println!(
                "\nnext: sign it in to Codex (once; it starts right after), with a device code:"
            );
            println!("  sudo thorn login {name}");
            println!("or an OpenAI API key, read from standard input:");
            println!("  sudo thorn login {name} --api-key");
        } else {
            println!("\nnext: sign it in to Claude (once; it starts right after):");
            println!("  sudo thorn login {name}");
        }
    }
    Ok(())
}

pub fn login(name: &str, api_key: bool) -> Result<()> {
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    let s = state.space(name)?.clone();
    if s.agent == crate::config::CODEX {
        return codex_login(name, &s, &cfg, api_key);
    }
    if api_key {
        bail!("only Codex spaces sign in with an API key");
    }
    if s.agent != crate::config::CLAUDE {
        bail!(
            "space {name} runs {}; sign it in on its own terminal: sudo thorn attach {name}",
            s.agent
        );
    }
    let user = paths::unix_user(&s.key);
    let home = paths::space_home(&s.key);
    println!("Signing in space {name}. Open the link it prints on any device, then paste the code here.\n");
    let status = Command::new("runuser")
        .args(["-u", &user, "--", "env"])
        .arg(format!("HOME={}", home.display()))
        .arg("DISABLE_AUTOUPDATER=1")
        .arg(&cfg.claude_bin)
        .args(["auth", "login", "--claudeai"])
        .current_dir(s.workdir())
        .status()
        .context("running claude auth login")?;
    if !status.success() {
        bail!("sign-in did not complete");
    }
    if ops::start_after_login(name)? {
        println!(
            "\nspace {name} is running; it appears in Remote Control as {}",
            s.rc_name
        );
    } else {
        println!(
            "\nsigned in. {name} is an admin space: start it when you need it, for a time:\n  \
             sudo thorn start {name} --for 1h"
        );
    }
    Ok(())
}

/// Codex: `codex login --device-auth` at this terminal (it prints a page
/// and a code), or an API key read from standard input.
fn codex_login(
    name: &str,
    s: &crate::state::Space,
    cfg: &crate::config::Config,
    api_key: bool,
) -> Result<()> {
    if api_key {
        let key = crate::seal::read_password("OpenAI API key (not shown): ")?;
        ops::login_api_key(name, &key)?;
        println!("signed in; space {name} is starting");
        return Ok(());
    }
    let user = paths::unix_user(&s.key);
    let home = paths::space_home(&s.key);
    println!(
        "Signing in space {name}: open the page it prints on any device and enter the code.\n"
    );
    let status = Command::new("runuser")
        .args(["-u", &user, "--", "env"])
        .arg(format!("HOME={}", home.display()))
        .arg(&cfg.codex_bin)
        .args(["login", "--device-auth"])
        .current_dir(s.workdir())
        .status()
        .context("running codex login")?;
    if !status.success() {
        bail!("sign-in did not complete");
    }
    ops::start_after_login(name)?;
    println!("\nspace {name} is running");
    Ok(())
}

pub fn rm(name: &str, purge: bool, purge_data: bool) -> Result<()> {
    match ops::space_rm(name, purge, purge_data)? {
        Some(dest) => println!(
            "removed space {name}; its files (including conversations) are in {}",
            dest.display()
        ),
        None => println!("removed space {name} and its files"),
    }
    Ok(())
}

pub fn rename(old: &str, new: &str, rc_name: Option<String>) -> Result<()> {
    let restarted = ops::space_rename(old, new, rc_name)?;
    println!("renamed space {old} to {new}");
    if restarted {
        println!("restarted it so Remote Control shows the new name");
        println!(
            "the old name stays in the Claude app's list of environments, offline, \
             until Anthropic clears it"
        );
    }
    Ok(())
}

pub fn control(action: Action, names: &[String], all: bool) -> Result<()> {
    if names.is_empty() && !all {
        bail!("name a space, or use --all");
    }
    for line in ops::space_control(action, names)? {
        println!("{line}");
    }
    Ok(())
}

pub fn attach(name: &str) -> Result<()> {
    sys::require_root()?;
    let (_, state) = ctx::read_only()?;
    let s = state.space(name)?;
    let sock = paths::tmux_socket(&s.key);
    if !sock.exists() {
        bail!("space {name} is not running; start it with: sudo thorn start {name}");
    }
    println!("attaching to {name}; leave with Ctrl-b then d (the space keeps running)");
    let err = Command::new("tmux")
        .arg("-S")
        .arg(&sock)
        .args(["attach", "-t", "main"])
        .exec();
    Err(err).context("running tmux")
}

pub fn screen(name: &str) -> Result<()> {
    print!("{}", ops::space_screen(name)?);
    Ok(())
}

pub fn send(name: &str, text: Option<&str>, key: Option<&str>, no_enter: bool) -> Result<()> {
    if text.is_none() && key.is_none() {
        bail!("give text to type, or --key");
    }
    ops::space_send(name, text, key, text.is_some() && !no_enter)
}

pub fn ls() -> Result<()> {
    let o = ops::overview(false)?;
    if o.spaces.is_empty() {
        println!("no spaces; create one with: sudo thorn new <host>");
        return Ok(());
    }
    let mut rows = vec![vec![
        "NAME".to_string(),
        "MACHINES".into(),
        "AGENT".into(),
        "LOGINS".into(),
        "STATE".into(),
        "REMOTE CONTROL".into(),
        "CAN REACH".into(),
        "MEMORY".into(),
    ]];
    for s in &o.spaces {
        let logins: Vec<String> = s
            .machines
            .iter()
            .map(|m| {
                let how = match &m.root {
                    Some(r) if r.ask => format!("{}, root on approval", m.access),
                    Some(r) => match r.until {
                        Some(u) => format!(
                            "root ({} left), then {}",
                            ops::describe_left(u, crate::state::now()),
                            m.access
                        ),
                        None => "root".into(),
                    },
                    None => m.access.to_string(),
                };
                if s.machines.len() == 1 {
                    how
                } else {
                    format!("{}: {how}", m.host)
                }
            })
            .collect();
        rows.push(vec![
            s.name.clone(),
            s.machines
                .iter()
                .map(|m| m.host.as_str())
                .collect::<Vec<_>>()
                .join(","),
            agent_label(&s.agent, s.mode),
            logins.join("; "),
            s.state.clone(),
            s.rc_name.clone(),
            if s.reachable.is_empty() {
                "nothing".into()
            } else {
                s.reachable.join(",")
            },
            s.memory_mb
                .map(|m| format!("{m} MB"))
                .unwrap_or_else(|| "-".into()),
        ]);
    }
    print_table(&rows);
    Ok(())
}

pub fn agent_label(agent: &str, mode: crate::state::Mode) -> String {
    if agent == crate::config::CLAUDE && mode == crate::state::Mode::Single {
        "claude (single)".into()
    } else {
        agent.to_string()
    }
}

pub fn print_table(rows: &[Vec<String>]) {
    let cols = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    let widths: Vec<usize> = (0..cols)
        .map(|c| {
            rows.iter()
                .map(|r| r.get(c).map_or(0, |s| s.chars().count()))
                .max()
                .unwrap_or(0)
        })
        .collect();
    for r in rows {
        let line: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(i, cell)| format!("{cell:<w$}", w = widths[i]))
            .collect();
        println!("{}", line.join("  ").trim_end());
    }
}

pub fn chat_ls(space: &str) -> Result<()> {
    let chats = ops::chat_list(space)?;
    if chats.is_empty() {
        println!("no chats in {space} yet");
    }
    let now = crate::state::now();
    for c in chats {
        println!(
            "{}  {:>8} ago  {}{}",
            &c.id[..8],
            ago(now.saturating_sub(c.modified)),
            c.title,
            if c.main {
                "  (the space's conversation)"
            } else if c.window {
                "  (running, started from the hub)"
            } else if c.running {
                "  (running)"
            } else {
                ""
            }
        );
    }
    Ok(())
}

fn ago(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m", secs / 60),
        3600..=86_399 => format!("{}h", secs / 3600),
        _ => format!("{}d", secs / 86_400),
    }
}

pub fn log(space: &str, n: usize) -> Result<()> {
    let v = crate::activity::list(space, n)?;
    if v.is_empty() {
        println!("no commands recorded for {space} yet");
        return Ok(());
    }
    for e in v.iter().rev() {
        let when = ops::rfc3339(e.t);
        if !e.msg.is_empty() {
            println!(
                "{when}  {}  {} sent: {}",
                e.chat,
                e.by,
                e.msg.replace('\n', "\n    ")
            );
        } else if !e.by.is_empty() {
            println!("{when}  {}  {}: {}", e.chat, e.by, e.note);
        } else if e.note.is_empty() {
            println!("{when}  {}  {}", e.chat, e.cmd.replace('\n', "\n    "));
        } else {
            println!("{when}  {}  NOTE: {}", e.chat, e.note);
        }
    }
    Ok(())
}

pub fn chat_rm(space: &str, id: &str) -> Result<()> {
    let id = ops::chat_rm(space, id)?;
    println!("deleted chat {} from the hub", &id[..8]);
    Ok(())
}

pub fn share(space: &str, account: &str, level: &str) -> Result<()> {
    let level = match level {
        "none" => None,
        l => Some(l.parse()?),
    };
    println!("{}", ops::space_share(space, account, level)?);
    Ok(())
}

pub fn owner(space: &str, account: Option<&str>) -> Result<()> {
    println!("{}", ops::space_owner(space, account)?);
    Ok(())
}

pub fn chat_send(space: &str, id: &str, text: &str) -> Result<()> {
    let by = format!(
        "hub:{}",
        std::env::var("SUDO_USER").unwrap_or_else(|_| "root".into())
    );
    crate::chat::send(space, id, text, &by)?;
    println!("sent");
    Ok(())
}

pub fn chat_stop(space: &str, id: &str) -> Result<()> {
    let id = ops::chat_stop(space, id)?;
    println!("stopped chat {}", &id[..8]);
    Ok(())
}

pub fn chat_open(space: &str, id: Option<&str>, title: Option<&str>) -> Result<()> {
    let o = ops::chat_open(space, id, title)?;
    let what = if id.is_some() {
        "back to chat"
    } else {
        "new chat"
    };
    if o.window {
        println!(
            "{space}: {what} {} in a window of its own; it shows in the Claude app \
             (or: sudo thorn attach {space}, then Ctrl-b n)",
            &o.id[..8]
        );
    } else if o.restarted {
        println!("{space}: {what} {} (restarted into it)", &o.id[..8]);
    } else {
        println!("{space}: {what} {}; it starts with the space", &o.id[..8]);
    }
    Ok(())
}

pub fn login_as(name: &str, host: Option<&str>, access: crate::state::Access) -> Result<()> {
    println!("{}", ops::space_login(name, host, access)?);
    Ok(())
}

pub fn connect(name: &str, host: &str, access: Option<crate::state::Access>) -> Result<()> {
    println!("{}", ops::space_connect(name, host, access)?);
    Ok(())
}

pub fn disconnect(name: &str, host: &str) -> Result<()> {
    println!("{}", ops::space_disconnect(name, host)?);
    Ok(())
}

/// thorn root SPACE [--host H] [--take] --for 8h | --forever | --ask | --off
pub fn root(
    name: &str,
    host: Option<&str>,
    take: bool,
    duration: Option<&str>,
    forever: bool,
    ask: bool,
    off: bool,
) -> Result<()> {
    let root = if off {
        None
    } else if ask {
        ops::parse_root("ask")?
    } else if forever {
        ops::parse_root("forever")?
    } else {
        match duration {
            Some(d) => ops::parse_root(d)?,
            None => ops::parse_root("8h")?,
        }
    };
    println!("{}", ops::space_root(name, host, root, take)?);
    Ok(())
}

pub fn remote(name: &str, on: bool) -> Result<()> {
    let restarted = ops::space_set_remote(name, on)?;
    let again = if restarted { " (restarted)" } else { "" };
    if on {
        println!("{name}: Remote Control on{again}");
    } else {
        println!("{name}: Remote Control off{again}; use it with: sudo thorn attach {name}");
    }
    Ok(())
}

/// thorn approvals [--all]
pub fn approvals(all: bool) -> Result<()> {
    sys::require_root()?;
    let asks: Vec<crate::asks::Ask> = crate::asks::list()
        .into_iter()
        .filter(|a| all || a.waiting())
        .take(if all { 30 } else { usize::MAX })
        .collect();
    if asks.is_empty() {
        println!(
            "{}",
            if all {
                "no asks yet"
            } else {
                "nothing waiting for approval"
            }
        );
        return Ok(());
    }
    for a in &asks {
        println!(
            "{}  {} on {}  {}  {}",
            a.id,
            a.space,
            a.host,
            ops::rfc3339(a.time),
            match (a.state.as_str(), a.rc) {
                ("done", Some(rc)) => format!("ran (exit {rc}), approved by {}", a.by),
                ("approved", _) => format!("approved by {}", a.by),
                ("denied", _) => format!("refused by {}", a.by),
                (s, _) => s.to_string(),
            }
        );
        println!("    as root, in {}: {}", a.cwd, a.cmd);
        if a.input_len > 0 {
            println!("    with {} bytes on its standard input:", a.input_len);
            for l in a.input.lines().take(40) {
                println!("    | {l}");
            }
        }
        for f in &a.flags {
            println!("    ! {f}");
        }
    }
    if !all {
        println!(
            "\napprove with: sudo thorn approve ID   refuse with: sudo thorn deny ID [--reason R]"
        );
    }
    Ok(())
}

/// thorn approve ID / thorn deny ID
pub fn decide(id: &str, approve: bool, reason: Option<&str>) -> Result<()> {
    sys::require_root()?;
    let by = format!(
        "hub:{}",
        std::env::var("SUDO_USER").unwrap_or_else(|_| "root".into())
    );
    let a = crate::asks::decide(id, approve, &by, reason.unwrap_or(""))?;
    println!(
        "{} {}: {} on {}",
        if approve { "approved" } else { "refused" },
        a.id,
        a.space,
        a.host
    );
    Ok(())
}

// ---------------------------------------------------------- Codex chats

fn by_cli() -> String {
    format!(
        "hub:{}",
        std::env::var("SUDO_USER").unwrap_or_else(|_| "root".into())
    )
}

/// A chat's whole id from its start.
fn codex_chat(space: &str, chat: &str) -> Result<String> {
    if crate::codex::id_ok(chat) {
        return Ok(chat.to_string());
    }
    let chat = chat.trim().to_ascii_lowercase();
    let found: Vec<String> = crate::codex::chats(space)?
        .into_iter()
        .map(|c| c.id)
        .filter(|id| !chat.is_empty() && id.starts_with(&chat))
        .collect();
    match found.as_slice() {
        [one] => Ok(one.clone()),
        [] => anyhow::bail!("no chat in {space} starts with {chat}"),
        _ => anyhow::bail!("more than one chat starts with {chat}: give more of its id"),
    }
}

pub fn codex_chats(space: &str) -> Result<()> {
    let chats = crate::codex::chats(space)?;
    if chats.is_empty() {
        println!("no chats in {space} yet: thorn codex new {space} MESSAGE");
    }
    let now = crate::state::now();
    for c in chats {
        let state = crate::codex::state_label(&c.state);
        println!(
            "{}  {:>8} ago  {}{}",
            c.id,
            ago(now.saturating_sub(c.updated)),
            c.title,
            if state.is_empty() {
                String::new()
            } else {
                format!("  ({state})")
            }
        );
    }
    Ok(())
}

pub fn codex_show(space: &str, chat: &str, turns: u32) -> Result<()> {
    let id = codex_chat(space, chat)?;
    let f = crate::codex::feed(space, &id, 0, turns)?;
    println!("# {}", f.title);
    if f.more {
        println!("(earlier turns left out: --turns N for more)");
    }
    for it in &f.items {
        match it.kind.as_str() {
            "user" => println!(
                "\n> {}{}",
                it.text.replace('\n', "\n> "),
                it.by
                    .as_ref()
                    .map(|b| format!("\n  (sent by {b})"))
                    .unwrap_or_default()
            ),
            "agent" | "plan" => println!("\n{}", it.text),
            "command" => {
                let exit = it.exit.map(|e| format!(" (exit {e})")).unwrap_or_default();
                println!("\n$ {}{exit}", it.text);
            }
            "files" => println!("\nchanged files:\n{}", it.text),
            "reasoning" => {}
            _ => println!("\n[{}] {}", it.kind, it.text),
        }
    }
    for a in &f.asks {
        println!(
            "\nCodex asks ({}), number {}:\n{}\n{}",
            a.kind, a.key, a.text, a.detail
        );
        for q in &a.questions {
            let opts: Vec<&str> = q.options.iter().map(|(l, _)| l.as_str()).collect();
            println!("  {}: {} [{}]", q.id, q.question, opts.join(" / "));
        }
        println!(
            "answer: sudo thorn codex answer {space} {} {} accept|session|decline|cancel",
            &id[..8],
            a.key
        );
    }
    let state = crate::codex::state_label(&f.state);
    if !state.is_empty() {
        println!("\n({state})");
    }
    if !f.notice.is_empty() {
        println!("\n{}", f.notice);
    }
    Ok(())
}

pub fn codex_new(space: &str, text: &str) -> Result<()> {
    let id = crate::codex::new(space, text, &by_cli())?;
    println!("started chat {id}");
    Ok(())
}

pub fn codex_send(space: &str, chat: &str, text: &str) -> Result<()> {
    let id = codex_chat(space, chat)?;
    crate::codex::send(space, &id, text, &by_cli())?;
    println!("sent");
    Ok(())
}

pub fn codex_stop(space: &str, chat: &str) -> Result<()> {
    let id = codex_chat(space, chat)?;
    crate::codex::stop(space, &id, &by_cli())?;
    println!("stopped");
    Ok(())
}

pub fn codex_answer(
    space: &str,
    chat: &str,
    ask: u64,
    decision: &str,
    answers: &[String],
) -> Result<()> {
    let id = codex_chat(space, chat)?;
    let mut map = std::collections::BTreeMap::new();
    for a in answers {
        let Some((k, v)) = a.split_once('=') else {
            anyhow::bail!("--answer takes ID=ANSWER");
        };
        map.insert(k.to_string(), v.to_string());
    }
    crate::codex::answer(space, &id, ask, decision, &map, &by_cli())?;
    println!("answered");
    Ok(())
}

pub fn codex_rename(space: &str, chat: &str, name: &str) -> Result<()> {
    let id = codex_chat(space, chat)?;
    crate::codex::rename(space, &id, name)?;
    println!("renamed");
    Ok(())
}

pub fn codex_archive(space: &str, chat: &str) -> Result<()> {
    let id = codex_chat(space, chat)?;
    crate::codex::archive(space, &id)?;
    println!("archived chat {}", &id[..8]);
    Ok(())
}
