//! thorn new / rm / rename / start / stop / restart / attach / login /
//! grant / revoke / ls

use crate::ctx::Ctx;
use crate::state::{validate_name, validate_rc_name, Session};
use crate::{paths, render, sys};
use anyhow::{bail, Context, Result};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

pub struct NewOpts {
    pub name: String,
    pub hosts: Vec<String>,
    pub rc_name: Option<String>,
    pub args: Vec<String>,
}

pub fn new(o: NewOpts) -> Result<()> {
    let mut ctx = Ctx::open()?;
    validate_name("session", &o.name)?;
    if ctx.state.sessions.contains_key(&o.name) {
        bail!("there is already a session named {:?}", o.name);
    }
    let rc_name = o.rc_name.unwrap_or_else(|| o.name.clone());
    validate_rc_name(&rc_name)?;
    if ctx.state.sessions.values().any(|s| s.rc_name == rc_name) {
        bail!("another session already uses the Remote Control name {rc_name:?}");
    }
    for h in &o.hosts {
        ctx.state.host(h)?;
    }

    let key = loop {
        let k = uuid::Uuid::new_v4().simple().to_string()[..8].to_string();
        let taken = ctx.state.sessions.values().any(|s| s.key == k)
            || sys::lookup_user(&paths::unix_user(&k)).is_some()
            || paths::session_home(&k).exists();
        if !taken {
            break k;
        }
    };

    let home = paths::session_home(&key);
    let ids = sys::create_user(&paths::unix_user(&key), &home)?;
    sys::mkdir(&home, 0o700)?;
    sys::chown(&home, ids.uid, ids.gid)?;
    let workdir = paths::session_workdir(&key);
    sys::mkdir(&workdir, 0o755)?;
    sys::chown(&workdir, ids.uid, ids.gid)?;
    let claude_json = home.join(".claude.json");
    if !claude_json.exists() {
        sys::write_file(
            &claude_json,
            &render::initial_claude_json(workdir.to_str().context("workdir path")?),
            0o600,
            Some((ids.uid, ids.gid)),
        )?;
    }

    ctx.state.sessions.insert(
        o.name.clone(),
        Session {
            key: key.clone(),
            conversation: uuid::Uuid::new_v4().to_string(),
            rc_name: rc_name.clone(),
            hosts: o.hosts.iter().cloned().collect(),
            args: o.args,
            created: ctx.now,
        },
    );
    ctx.commit()?;
    sys::systemctl(&["enable", &paths::session_unit(&key)])?;

    println!(
        "created session {} (Remote Control name {rc_name}, user {})",
        o.name,
        paths::unix_user(&key)
    );
    if o.hosts.is_empty() {
        println!(
            "it can reach no hosts yet; add some with: sudo thorn grant {} <host>",
            o.name
        );
    } else {
        println!("it can reach: {}", o.hosts.join(", "));
    }
    println!("\nnext: sign it in to Claude (once; it starts right after):");
    println!("  sudo thorn login {}", o.name);
    Ok(())
}

pub fn login(name: &str) -> Result<()> {
    let ctx = Ctx::open()?;
    let s = ctx.state.session(name)?.clone();
    let user = paths::unix_user(&s.key);
    let home = paths::session_home(&s.key);
    let claude = ctx.cfg.claude_bin.clone();
    drop(ctx); // do not hold the lock while waiting for you

    println!("Signing in session {name}. Open the link it prints on any device, then paste the code here.\n");
    let status = Command::new("runuser")
        .args(["-u", &user, "--", "env"])
        .arg(format!("HOME={}", home.display()))
        .arg("DISABLE_AUTOUPDATER=1")
        .arg(&claude)
        .args(["auth", "login", "--claudeai"])
        .current_dir(paths::session_workdir(&s.key))
        .status()
        .context("running claude auth login")?;
    if !status.success() {
        bail!("sign-in did not complete");
    }
    sys::systemctl(&["restart", &paths::session_unit(&s.key)])?;
    println!(
        "\nsession {name} is running; it appears in Remote Control as {}",
        s.rc_name
    );
    Ok(())
}

pub fn logged_in(key: &str) -> bool {
    paths::session_home(key)
        .join(".claude/.credentials.json")
        .exists()
}

pub fn rm(name: &str, purge: bool) -> Result<()> {
    let mut ctx = Ctx::open()?;
    let s = ctx.state.session(name)?.clone();
    let unit = paths::session_unit(&s.key);
    let _ = sys::systemctl(&["disable", "--now", &unit]);
    let _ = sys::systemctl(&["stop", &paths::agent_unit(&s.key)]);
    ctx.state.sessions.remove(name);
    ctx.commit()?;

    let home = paths::session_home(&s.key);
    sys::delete_user(&paths::unix_user(&s.key))?;
    let _ = std::fs::remove_file(paths::launch_file(&s.key));
    if purge {
        if home.exists() {
            std::fs::remove_dir_all(&home)
                .with_context(|| format!("removing {}", home.display()))?;
        }
        println!("removed session {name} and its files");
    } else if home.exists() {
        // The uid is free again; keep the files, but owned by root, so a
        // future session that gets the same uid cannot read them.
        let archive = Path::new(paths::STATE_DIR).join("archive");
        sys::mkdir(&archive, 0o700)?;
        let dest = archive.join(format!("{name}-{}", s.key));
        chown_tree(&home)?;
        std::fs::rename(&home, &dest)?;
        println!(
            "removed session {name}; its files (including the conversation) are in {}",
            dest.display()
        );
    }
    Ok(())
}

fn chown_tree(p: &Path) -> Result<()> {
    sys::run(
        "chown",
        &[
            "-R",
            "--no-dereference",
            "root:root",
            p.to_str().context("path")?,
        ],
    )
}

pub fn rename(old: &str, new: &str, rc_name: Option<String>) -> Result<()> {
    let mut ctx = Ctx::open()?;
    validate_name("session", new)?;
    if ctx.state.sessions.contains_key(new) {
        bail!("there is already a session named {new:?}");
    }
    let mut s = ctx.state.session(old)?.clone();
    let old_rc = s.rc_name.clone();
    if let Some(rc) = rc_name {
        s.rc_name = rc;
    } else if s.rc_name == old {
        s.rc_name = new.to_string();
    }
    validate_rc_name(&s.rc_name)?;
    if ctx
        .state
        .sessions
        .iter()
        .any(|(n, o)| n != old && o.rc_name == s.rc_name)
    {
        bail!(
            "another session already uses the Remote Control name {:?}",
            s.rc_name
        );
    }
    ctx.state.sessions.remove(old);
    ctx.state.sessions.insert(new.to_string(), s.clone());
    ctx.commit()?;
    println!("renamed session {old} to {new}");
    if s.rc_name != old_rc {
        let unit = paths::session_unit(&s.key);
        if sys::unit_state(&unit) == "active" {
            sys::systemctl(&["restart", &unit])?;
            println!(
                "restarted it so Remote Control shows the new name {}",
                s.rc_name
            );
        }
    }
    Ok(())
}

pub fn control(action: &str, names: &[String], all: bool) -> Result<()> {
    let ctx = Ctx::open()?;
    let targets: Vec<(String, Session)> = if all {
        ctx.state
            .sessions
            .iter()
            .map(|(n, s)| (n.clone(), s.clone()))
            .collect()
    } else {
        if names.is_empty() {
            bail!("name a session, or use --all");
        }
        names
            .iter()
            .map(|n| ctx.state.session(n).map(|s| (n.clone(), s.clone())))
            .collect::<Result<_>>()?
    };
    drop(ctx);
    for (name, s) in targets {
        if action != "stop" && !logged_in(&s.key) {
            println!("{name}: not signed in yet; run: sudo thorn login {name}");
            continue;
        }
        sys::systemctl(&[action, &paths::session_unit(&s.key)])?;
        let done = match action {
            "start" => "started",
            "stop" => "stopped",
            _ => "restarted",
        };
        println!("{name}: {done}");
    }
    Ok(())
}

pub fn attach(name: &str) -> Result<()> {
    sys::require_root()?;
    let (_, state) = crate::ctx::read_only()?;
    let s = state.session(name)?;
    let sock = paths::tmux_socket(&s.key);
    if !sock.exists() {
        bail!("session {name} is not running; start it with: sudo thorn start {name}");
    }
    println!("attaching to {name}; leave with Ctrl-b then d (the session keeps running)");
    let err = Command::new("tmux")
        .arg("-S")
        .arg(&sock)
        .args(["attach", "-t", "main"])
        .exec();
    Err(err).context("running tmux")
}

pub fn grant(session: &str, hosts: &[String], revoke: bool) -> Result<()> {
    let mut ctx = Ctx::open()?;
    for h in hosts {
        if !revoke {
            ctx.state.host(h)?;
        }
    }
    let s = ctx
        .state
        .sessions
        .get_mut(session)
        .with_context(|| format!("no session named {session:?}"))?;
    for h in hosts {
        if revoke {
            s.hosts.remove(h);
        } else {
            s.hosts.insert(h.clone());
        }
    }
    let now_hosts: Vec<String> = s.hosts.iter().cloned().collect();
    ctx.commit()?;
    let verb = if revoke { "revoked" } else { "granted" };
    println!(
        "{verb}: {} (session {session} can reach: {})",
        hosts.join(", "),
        list_or_none(&now_hosts)
    );
    println!("the firewall and keys changed now; Claude sees the new host list in CLAUDE.md after: sudo thorn restart {session}");
    Ok(())
}

fn list_or_none(v: &[String]) -> String {
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}

pub fn ls() -> Result<()> {
    let (_, state) = crate::ctx::read_only()?;
    if state.sessions.is_empty() {
        println!("no sessions; create one with: sudo thorn new <name> --host <host>");
        return Ok(());
    }
    let mut rows = vec![vec![
        "NAME".to_string(),
        "STATE".into(),
        "REMOTE CONTROL".into(),
        "HOSTS".into(),
        "MEMORY".into(),
    ]];
    for (name, s) in &state.sessions {
        let unit = paths::session_unit(&s.key);
        let mut st = sys::unit_state(&unit);
        if !logged_in(&s.key) {
            st = "needs login".into();
        }
        let mem = sys::unit_memory(&unit)
            .map(|b| format!("{} MB", b / 1_048_576))
            .unwrap_or_else(|| "-".into());
        let hosts: Vec<String> = s
            .hosts
            .iter()
            .map(|h| match state.hosts.get(h) {
                Some(host) if host.blocked(crate::state::now()) => format!("{h}(blocked)"),
                Some(_) => h.clone(),
                None => format!("{h}(removed)"),
            })
            .collect();
        rows.push(vec![
            name.clone(),
            st,
            s.rc_name.clone(),
            list_or_none(&hosts),
            mem,
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
