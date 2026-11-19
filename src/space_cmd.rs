//! thorn new / rm / rename / start / stop / restart / attach / login / ls /
//! bridge: the CLI side of the space operations in `ops`.

use crate::ops::{self, Action, NewSpace};
use crate::{ctx, paths, sys};
use anyhow::{bail, Context, Result};
use std::os::unix::process::CommandExt;
use std::process::Command;

pub fn new(o: NewSpace) -> Result<()> {
    let name = ops::space_new(o)?;
    let (_, state) = ctx::read_only()?;
    let s = state.space(&name)?;
    println!(
        "created space {name}: {} on {} (Remote Control name {}, user {})",
        s.agent,
        s.host,
        s.rc_name,
        paths::unix_user(&s.key)
    );
    if ops::logged_in(s) {
        println!("it is running; open it with: sudo thorn attach {name}");
    } else {
        println!("\nnext: sign it in to Claude (once; it starts right after):");
        println!("  sudo thorn login {name}");
    }
    Ok(())
}

pub fn login(name: &str) -> Result<()> {
    sys::require_root()?;
    let (cfg, state) = ctx::read_only()?;
    let s = state.space(name)?.clone();
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
        .current_dir(paths::space_workdir(&s.key))
        .status()
        .context("running claude auth login")?;
    if !status.success() {
        bail!("sign-in did not complete");
    }
    sys::systemctl(&["restart", &paths::space_unit(&s.key)])?;
    println!(
        "\nspace {name} is running; it appears in Remote Control as {}",
        s.rc_name
    );
    Ok(())
}

pub fn rm(name: &str, purge: bool) -> Result<()> {
    match ops::space_rm(name, purge)? {
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
        "HOST".into(),
        "AGENT".into(),
        "STATE".into(),
        "REMOTE CONTROL".into(),
        "CAN REACH".into(),
        "MEMORY".into(),
    ]];
    for s in &o.spaces {
        rows.push(vec![
            s.name.clone(),
            s.host.clone(),
            agent_label(&s.agent, s.mode),
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

pub fn bridge_add(from: &str, to: &str, duration: Option<&str>, permanent: bool) -> Result<()> {
    let secs = if permanent {
        None
    } else {
        Some(ops::parse_duration(duration.unwrap_or("1h"))?)
    };
    let b = ops::bridge_add(from, to, secs)?;
    let (_, state) = ctx::read_only()?;
    let host = state.space(to)?.host.clone();
    match b.until {
        Some(u) => println!(
            "bridge up: {from} can reach {host} until {} (removed automatically)",
            ops::rfc3339(u)
        ),
        None => {
            println!("bridge up: {from} can reach {host} until: sudo thorn bridge rm {from} {to}")
        }
    }
    println!(
        "while it lasts, {} and {host} are one trust zone for {from}'s chats",
        state.space(from)?.host
    );
    Ok(())
}

pub fn bridge_rm(from: &str, to: &str) -> Result<()> {
    ops::bridge_rm(from, to)?;
    println!("bridge removed; open connections from {from} to {to}'s machine were cut");
    Ok(())
}

pub fn bridge_ls() -> Result<()> {
    let o = ops::overview(false)?;
    if o.bridges.is_empty() {
        println!("no bridges");
        return Ok(());
    }
    let mut rows = vec![vec![
        "FROM".to_string(),
        "TO".into(),
        "REACHES".into(),
        "LASTS".into(),
    ]];
    for b in &o.bridges {
        rows.push(vec![
            b.from.clone(),
            b.to.clone(),
            b.host.clone(),
            b.remaining.clone(),
        ]);
    }
    print_table(&rows);
    Ok(())
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

pub fn chat_rename(space: &str, id: &str, title: &str) -> Result<()> {
    let id = ops::chat_rename(space, id, title)?;
    println!("chat {} is now called {title:?}", &id[..8]);
    Ok(())
}

pub fn chat_rm(space: &str, id: &str) -> Result<()> {
    let id = ops::chat_rm(space, id)?;
    println!("deleted chat {} from the hub", &id[..8]);
    Ok(())
}

pub fn chat_open(space: &str, id: Option<&str>) -> Result<()> {
    let o = ops::chat_open(space, id)?;
    let what = if id.is_some() {
        "back to chat"
    } else {
        "new chat"
    };
    if o.restarted {
        println!("{space}: {what} {} (restarted into it)", &o.id[..8]);
    } else {
        println!("{space}: {what} {}; it starts with the space", &o.id[..8]);
    }
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
