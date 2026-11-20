//! thorn host add / rm / ls / block / unblock / pubkey / check / rescan /
//! set-address: the CLI side of the host operations in `ops`.

use crate::ops::{self, Scan};
use crate::space_cmd::print_table;
use anyhow::{bail, Result};
use std::io::{BufRead, IsTerminal, Write};

pub fn add(name: &str, target: &str, port: u16, yes: bool) -> Result<()> {
    crate::state::validate_name("host", name)?;
    let scan = ops::host_scan(target, port, ops::ssh_client())?;
    confirm_fingerprints(name, &scan, yes)?;
    let line = ops::host_add(name, target, port, &scan.host_keys, ops::ssh_client())?;
    println!(
        "\nadded host {name} ({}@{}, port {port}).",
        scan.user, scan.address
    );
    println!(
        "\nOn {name}, add this line to ~{}/.ssh/authorized_keys:\n",
        scan.user
    );
    print_line(&line);
    println!("then check it with: sudo thorn host check {name}");
    println!("and create a space on it with: sudo thorn new {name}");
    Ok(())
}

pub fn set_address(name: &str, target: &str, port: u16, yes: bool) -> Result<()> {
    let scan = ops::host_move_scan(name, target, port, ops::ssh_client())?;
    confirm_fingerprints(name, &scan, yes)?;
    let line = ops::host_move(name, target, port, &scan.host_keys, ops::ssh_client())?;
    println!(
        "\n{name} is now {}@{}, port {port}; its spaces follow.",
        scan.user, scan.address
    );
    println!(
        "\nOn {name}, replace its blackthorn line in ~{}/.ssh/authorized_keys with:\n",
        scan.user
    );
    print_line(&line);
    println!("then check it with: sudo thorn host check {name}");
    Ok(())
}

fn print_line(line: &str) {
    println!("{line}\n");
    if !line.starts_with("from=") {
        println!(
            "(no from=\"...\" limit: the hub found no address of its own to limit the key to; \
             set ssh_from in /etc/blackthorn/config.toml)\n"
        );
    }
}

fn confirm_fingerprints(name: &str, scan: &Scan, yes: bool) -> Result<()> {
    println!("{name} presents these host keys:");
    for fp in &scan.fingerprints {
        println!("  {fp}");
    }
    println!("compare them with the output of this, run on {name} itself:");
    println!("  for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$f\"; done");
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "not confirmed; run interactively, or pass --yes if you have checked the fingerprints"
        );
    }
    print!("do they match? [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    if !matches!(line.trim(), "y" | "Y" | "yes") {
        bail!("not confirmed");
    }
    Ok(())
}

pub fn rename(old: &str, new: &str) -> Result<()> {
    ops::host_rename(old, new)?;
    println!("machine {old} is now {new}; its spaces now reach it as `ssh {new}`");
    Ok(())
}

pub fn rm(name: &str) -> Result<()> {
    ops::host_rm(name)?;
    println!("removed host {name} and its key");
    println!("remember to delete the blackthorn line from its authorized_keys");
    Ok(())
}

pub fn ls() -> Result<()> {
    let o = ops::overview(false)?;
    if o.hosts.is_empty() {
        println!("no hosts; add one with: sudo thorn host add <name> user@address");
        return Ok(());
    }
    let mut rows = vec![vec![
        "NAME".to_string(),
        "ADDRESS".into(),
        "ADMIN".into(),
        "READ-ONLY".into(),
        "OS".into(),
        "SPACES".into(),
        "STATUS".into(),
    ]];
    for h in &o.hosts {
        let addr = if h.port == 22 {
            h.address.to_string()
        } else {
            format!("{}:{}", h.address, h.port)
        };
        rows.push(vec![
            h.name.clone(),
            addr,
            h.user.clone(),
            h.readonly.clone().unwrap_or_else(|| "-".into()),
            h.os.to_string(),
            if h.spaces.is_empty() {
                "-".into()
            } else {
                h.spaces.join(",")
            },
            h.status.clone(),
        ]);
    }
    print_table(&rows);
    Ok(())
}

pub fn block(name: &str, duration: Option<&str>, reason: Option<String>) -> Result<()> {
    let secs = duration.map(ops::parse_duration).transpose()?;
    match ops::host_block(name, secs, reason)? {
        None => println!("{name} is blocked for every space until: sudo thorn host unblock {name}"),
        Some(u) => println!(
            "{name} is blocked for every space until {} (lifted automatically)",
            ops::rfc3339(u)
        ),
    }
    println!("open connections to it were cut and its key was taken out of every agent");
    Ok(())
}

pub fn unblock(name: &str) -> Result<()> {
    ops::host_unblock(name)?;
    println!("{name} is open again");
    Ok(())
}

pub fn pubkey(name: &str) -> Result<()> {
    println!("{}", ops::host_pubkey(name)?);
    Ok(())
}

pub fn check(name: &str) -> Result<()> {
    let os = ops::host_check(name)?;
    println!("ok: blackthorn can log in to {name} ({os})");
    Ok(())
}

pub fn readonly(name: &str, user: &str, print: bool, verify: bool) -> Result<()> {
    if print {
        print!("{}", ops::host_readonly_script(name, user)?);
        eprintln!(
            "\n# Run that as root on {name} (e.g. save it as setup.sh, then: sudo sh setup.sh),\n\
             # then: sudo thorn host readonly {name} --user {user} --verify"
        );
        return Ok(());
    }
    if !verify {
        println!("setting up a read-only login on {name}, as its admin login...");
    }
    let done = ops::host_readonly(name, user, !verify)?;
    for line in &done.report {
        println!("  {line}");
    }
    println!(
        "{name} has a read-only login: {}. New spaces on it are read-only by default.",
        done.user
    );
    println!(
        "commands blackthorn's keys run there are in its system log: journalctl -t blackthorn"
    );
    if !done.limited.is_empty() {
        println!(
            "admin spaces on {name} ({}) now run only when started, for a time, one at a time; \
             those running now keep running until stopped. Make one read-only with: \
             sudo thorn access SPACE readonly",
            done.limited.join(", ")
        );
    }
    Ok(())
}

pub fn rescan(name: &str, yes: bool) -> Result<()> {
    let (scan, changed) = ops::host_rescan(name)?;
    if !changed {
        println!("{name}'s host keys have not changed");
        return Ok(());
    }
    println!("{name}'s host keys CHANGED. If you did not reinstall it or regenerate its keys, stop here.");
    confirm_fingerprints(name, &scan, yes)?;
    ops::host_rescan_confirm(name, &scan.host_keys)?;
    println!("saved the new host keys for {name}");
    Ok(())
}
