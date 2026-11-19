//! The architecture map as SVG: your devices on top, the hub with its
//! spaces in the middle, the machines below, with a line from each space to
//! the machine it works on and dashed lines for bridges.

use crate::ops::{HostView, Overview, SpaceView};
use std::fmt::Write as _;

const SW: i32 = 190; // space box
const SH: i32 = 60;
const GAP: i32 = 14;
const PAD: i32 = 12;
const COL_GAP: i32 = 28;
const MARGIN: i32 = 24;
const SPACE_Y: i32 = 112;
const HOST_Y: i32 = 252;
const HOST_H: i32 = 60;

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n - 1).collect();
        t.push('…');
        t
    }
}

pub fn state_class(state: &str) -> &'static str {
    match state {
        "running" => "ok",
        "needs login" => "warn",
        "stopped" => "idle",
        "activating" | "deactivating" | "reloading" => "warn",
        _ => "bad",
    }
}

struct Col<'a> {
    host: &'a HostView,
    spaces: Vec<&'a SpaceView>,
    x: i32,
    w: i32,
}

pub fn svg(o: &Overview) -> String {
    let mut cols: Vec<Col> = Vec::new();
    let mut x = MARGIN;
    for h in &o.hosts {
        let spaces: Vec<&SpaceView> = o.spaces.iter().filter(|s| s.host == h.name).collect();
        let n = spaces.len().max(1) as i32;
        let w = (n * SW + (n - 1) * GAP + 2 * PAD).max(SW + 2 * PAD);
        cols.push(Col {
            host: h,
            spaces,
            x,
            w,
        });
        x += w + COL_GAP;
    }
    let width = (x - COL_GAP + MARGIN).max(560);
    let height = HOST_Y + HOST_H + 52;

    let mut out = String::new();
    let _ = write!(
        out,
        "<svg class=\"map\" viewBox=\"0 0 {width} {height}\" width=\"{width}\" height=\"{height}\" \
         role=\"img\" aria-label=\"blackthorn map\" xmlns=\"http://www.w3.org/2000/svg\">"
    );
    out.push_str(
        "<defs><marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"7\" \
         markerHeight=\"7\" orient=\"auto-start-reverse\"><path d=\"M0,0 L10,5 L0,10 z\" \
         class=\"arrowhead\"/></marker><marker id=\"arrow-b\" viewBox=\"0 0 10 10\" refX=\"9\" \
         refY=\"5\" markerWidth=\"7\" markerHeight=\"7\" orient=\"auto\"><path d=\"M0,0 L10,5 L0,10 z\" \
         class=\"arrowhead-bridge\"/></marker></defs>",
    );

    // Your devices.
    let _ = write!(
        out,
        "<rect class=\"devices\" x=\"{MARGIN}\" y=\"12\" width=\"{}\" height=\"34\" rx=\"8\"/>\
         <text class=\"t-dim\" x=\"{}\" y=\"34\">your phone / laptop · Remote Control via claude.ai · \
         this page over the tailnet</text>",
        width - 2 * MARGIN,
        MARGIN + 14
    );
    let _ = write!(
        out,
        "<line class=\"link\" x1=\"{c}\" y1=\"46\" x2=\"{c}\" y2=\"70\" marker-end=\"url(#arrow)\"/>",
        c = width / 2
    );

    // The hub.
    let hub_h = SPACE_Y + SH + 22 - 74;
    let _ = write!(
        out,
        "<rect class=\"hub\" x=\"{MARGIN}\" y=\"74\" width=\"{}\" height=\"{hub_h}\" rx=\"10\"/>",
        width - 2 * MARGIN
    );
    let fw = if o.hub.firewall_loaded {
        "<tspan class=\"t-ok\">firewall on</tspan>"
    } else {
        "<tspan class=\"t-bad\">FIREWALL NOT LOADED</tspan>"
    };
    let _ = write!(
        out,
        "<text class=\"t-strong\" x=\"{}\" y=\"98\">{} <tspan class=\"t-dim\">hub ·</tspan> {fw}</text>",
        MARGIN + 14,
        esc(&o.hub.hostname)
    );

    if cols.is_empty() {
        let _ = write!(
            out,
            "<text class=\"t-dim\" x=\"{}\" y=\"{}\">No machines yet. Add one under Machines, \
             then create a space on it.</text>",
            MARGIN + 14,
            SPACE_Y + 30
        );
    }

    // Space positions, for the bridge lines.
    let mut space_x: Vec<(&str, i32)> = Vec::new();
    for c in &cols {
        for (i, s) in c.spaces.iter().enumerate() {
            space_x.push((s.name.as_str(), c.x + PAD + i as i32 * (SW + GAP) + SW / 2));
        }
    }
    let host_x = |name: &str| -> Option<i32> {
        cols.iter()
            .find(|c| c.host.name == name)
            .map(|c| c.x + c.w / 2)
    };

    // Lines first, so boxes sit on top of them.
    for c in &cols {
        let hx = c.x + c.w / 2;
        for s in &c.spaces {
            let sx = space_x
                .iter()
                .find(|(n, _)| *n == s.name)
                .map(|(_, x)| *x)
                .unwrap_or(hx);
            let cls = if c.host.blocked { "link cut" } else { "link" };
            let _ = write!(
                out,
                "<path class=\"{cls}\" d=\"M{sx},{} C{sx},{} {hx},{} {hx},{}\" marker-end=\"url(#arrow)\"/>",
                SPACE_Y + SH,
                SPACE_Y + SH + 40,
                HOST_Y - 40,
                HOST_Y - 2
            );
        }
    }
    for b in &o.bridges {
        let (Some(sx), Some(hx)) = (
            space_x.iter().find(|(n, _)| *n == b.from).map(|(_, x)| *x),
            host_x(&b.host),
        ) else {
            continue;
        };
        let _ = write!(
            out,
            "<path class=\"bridge\" d=\"M{sx},{} C{sx},{} {hx},{} {hx},{}\" marker-end=\"url(#arrow-b)\"/>",
            SPACE_Y + SH,
            SPACE_Y + SH + 60,
            HOST_Y - 60,
            HOST_Y - 2
        );
        let _ = write!(
            out,
            "<text class=\"t-bridge\" x=\"{}\" y=\"{}\" text-anchor=\"middle\">bridge {}</text>",
            (sx + hx) / 2,
            (SPACE_Y + SH + HOST_Y) / 2 + 4,
            esc(&b.remaining)
        );
    }

    // Spaces.
    for c in &cols {
        if c.spaces.is_empty() {
            let _ = write!(
                out,
                "<text class=\"t-dim\" x=\"{}\" y=\"{}\" text-anchor=\"middle\">no space</text>",
                c.x + c.w / 2,
                SPACE_Y + SH / 2 + 4
            );
        }
        for (i, s) in c.spaces.iter().enumerate() {
            let x = c.x + PAD + i as i32 * (SW + GAP);
            let detail = match (s.chats_24h, s.memory_mb) {
                (Some(n), Some(m)) => format!("{n} chat(s) today · {m} MB"),
                (Some(n), None) => format!("{n} chat(s) today"),
                (None, Some(m)) => format!("{m} MB"),
                (None, None) => String::new(),
            };
            let _ = write!(
                out,
                "<a href=\"/space/{n}\"><g class=\"space\"><rect x=\"{x}\" y=\"{SPACE_Y}\" width=\"{SW}\" \
                 height=\"{SH}\" rx=\"8\"/><circle class=\"dot {cls}\" cx=\"{}\" cy=\"{}\" r=\"5\"/>\
                 <text class=\"t-strong\" x=\"{}\" y=\"{}\">{name}</text>\
                 <text class=\"t-dim\" x=\"{}\" y=\"{}\">{agent} · {state}</text>\
                 <text class=\"t-dim\" x=\"{}\" y=\"{}\">{detail}</text></g></a>",
                x + 14,
                SPACE_Y + 19,
                x + 26,
                SPACE_Y + 23,
                x + 12,
                SPACE_Y + 40,
                x + 12,
                SPACE_Y + 54,
                n = crate::webauth::url_encode(&s.name),
                cls = state_class(&s.state),
                name = esc(&clip(&s.name, 22)),
                agent = esc(&s.agent),
                state = esc(&s.state),
                detail = esc(&detail),
            );
        }
    }

    let _ = write!(
        out,
        "<text class=\"t-dim\" x=\"{}\" y=\"{}\">outbound SSH only ↓</text>",
        MARGIN + 4,
        HOST_Y - 16
    );

    // Machines.
    for c in &cols {
        let h = c.host;
        let cls = if h.blocked { "host blocked" } else { "host" };
        let x = c.x + PAD / 2;
        let w = c.w - PAD;
        let _ = write!(
            out,
            "<a href=\"/host/{n}\"><g class=\"{cls}\"><rect x=\"{x}\" y=\"{HOST_Y}\" width=\"{w}\" \
             height=\"{HOST_H}\" rx=\"8\"/>\
             <text class=\"t-strong\" x=\"{}\" y=\"{}\">{name}</text>\
             <text class=\"t-dim\" x=\"{}\" y=\"{}\">{user}@{addr} · {os}</text>\
             <text class=\"{scls}\" x=\"{}\" y=\"{}\">{status}</text></g></a>",
            x + 12,
            HOST_Y + 21,
            x + 12,
            HOST_Y + 38,
            x + 12,
            HOST_Y + 53,
            n = crate::webauth::url_encode(&h.name),
            name = esc(&h.name),
            user = esc(&h.user),
            addr = h.address,
            os = h.os,
            scls = if h.blocked { "t-bad" } else { "t-dim" },
            status = esc(&clip(&h.status, (w / 7).max(10) as usize)),
        );
    }
    let _ = write!(
        out,
        "<text class=\"t-dim\" x=\"{}\" y=\"{}\">machines cannot connect to the hub</text>",
        MARGIN + 4,
        HOST_Y + HOST_H + 26
    );
    out.push_str("</svg>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{BridgeView, HubView};
    use crate::state::{Mode, Os};

    fn overview() -> Overview {
        let host = |n: &str, blocked| HostView {
            name: n.into(),
            address: "100.80.0.3".parse().unwrap(),
            port: 22,
            user: "root".into(),
            os: Os::Linux,
            spaces: vec![],
            blocked,
            status: if blocked {
                "BLOCKED".into()
            } else {
                "open".into()
            },
        };
        let space = |n: &str, h: &str, st: &str| SpaceView {
            name: n.into(),
            host: h.into(),
            agent: "claude".into(),
            mode: Mode::Server,
            rc_name: n.into(),
            state: st.into(),
            memory_mb: Some(300),
            chats_24h: Some(2),
            reachable: vec![],
        };
        Overview {
            hub: HubView {
                hostname: "blackthorn".into(),
                firewall_loaded: true,
                timer: "active".into(),
                claude_version: None,
                https_anywhere: true,
                admin_from: vec![],
                denied_inbound: vec![],
                web_listen: vec![],
                memory_available_mb: None,
            },
            spaces: vec![
                space("fig-claude", "fig", "running"),
                space("fig-aider", "fig", "stopped"),
                space("nas-<x>", "nas", "needs login"),
            ],
            hosts: vec![host("fig", false), host("nas", true), host("pine", false)],
            bridges: vec![BridgeView {
                from: "fig-claude".into(),
                to: "nas-<x>".into(),
                host: "nas".into(),
                until: Some(10),
                remaining: "for 52m".into(),
            }],
            agents: vec!["claude".into()],
        }
    }

    #[test]
    fn draws_every_space_host_and_bridge() {
        let s = svg(&overview());
        assert!(s.starts_with("<svg"));
        assert!(s.ends_with("</svg>"));
        assert_eq!(s.matches("class=\"space\"").count(), 3);
        assert_eq!(s.matches("<g class=\"host").count(), 3);
        assert!(s.contains("class=\"host blocked\""));
        assert!(s.contains("class=\"link cut\""));
        assert!(s.contains("class=\"bridge\""));
        assert!(s.contains("bridge for 52m"));
        assert!(s.contains("no space"), "pine has none");
        assert!(s.contains("href=\"/space/fig-claude\""));
    }

    #[test]
    fn escapes_text() {
        let s = svg(&overview());
        assert!(s.contains("nas-&lt;x&gt;"));
        assert!(!s.contains("nas-<x>"));
        assert!(s.contains("href=\"/space/nas-%3Cx%3E\""));
    }

    #[test]
    fn empty_hub() {
        let mut o = overview();
        o.hosts.clear();
        o.spaces.clear();
        o.bridges.clear();
        assert!(svg(&o).contains("No machines yet"));
    }
}
