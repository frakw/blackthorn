//! thorn status (and --json): the hub at a glance, machines with the spaces
//! that work on them, bridges between them.

use crate::ops::{self, Overview};
use crate::space_cmd::agent_label;
use anyhow::Result;
use std::fmt::Write as _;

pub fn status(json: bool) -> Result<()> {
    let o = ops::overview(true)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&o)?);
    } else {
        print!("{}", map(&o));
    }
    Ok(())
}

/// A text map: the hub, then each machine with its spaces.
pub fn map(o: &Overview) -> String {
    let mut out = String::new();
    let h = &o.hub;
    let _ = writeln!(
        out,
        "{}  firewall {} · block timer {} · claude {}",
        h.hostname,
        if h.firewall_loaded {
            "loaded"
        } else {
            "NOT LOADED (spaces are unrestricted!)"
        },
        h.timer,
        h.claude_version.as_deref().unwrap_or("missing")
    );
    let _ = writeln!(
        out,
        "inbound: {} managed/denied address(es) refused · admin from: {} · web: {}",
        h.denied_inbound.len(),
        if h.admin_from.is_empty() {
            "anywhere (set inbound.admin_from)".to_string()
        } else {
            list(&h.admin_from)
        },
        if h.web_listen.is_empty() {
            "off".to_string()
        } else {
            h.web_listen.join(", ")
        }
    );
    let _ = writeln!(
        out,
        "egress: https {}{}",
        if h.https_anywhere { "anywhere" } else { "off" },
        h.memory_available_mb
            .map(|m| format!(" · memory {m} MB available"))
            .unwrap_or_default()
    );
    out.push('\n');
    if o.hosts.is_empty() {
        out.push_str("no machines yet: sudo thorn host add <name> user@address\n");
    }
    for host in &o.hosts {
        let _ = writeln!(
            out,
            "{}  {}@{} · {} · {}",
            host.name, host.user, host.address, host.os, host.status
        );
        let spaces: Vec<_> = o.spaces.iter().filter(|s| s.host == host.name).collect();
        if spaces.is_empty() {
            let _ = writeln!(out, " └─ (no spaces: sudo thorn new {})", host.name);
        }
        for (i, s) in spaces.iter().enumerate() {
            let last = i + 1 == spaces.len();
            let mut line = format!(
                " {} {}  {}  {}",
                if last { "└─" } else { "├─" },
                s.name,
                agent_label(&s.agent, s.mode),
                s.state
            );
            if s.state == "needs login" {
                let _ = write!(line, " → sudo thorn login {}", s.name);
            }
            if let Some(n) = s.chats_24h {
                let _ = write!(line, "  {n} chat(s)/24h");
            }
            if let Some(m) = s.memory_mb {
                let _ = write!(line, "  {m} MB");
            }
            let _ = writeln!(out, "{line}");
            for b in o.bridges.iter().filter(|b| b.from == s.name) {
                let _ = writeln!(
                    out,
                    " {}    └─ bridge → {} (via {}) {}",
                    if last { " " } else { "│" },
                    b.host,
                    b.to,
                    b.remaining
                );
            }
        }
    }
    out
}

fn list<T: std::fmt::Display>(v: &[T]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
