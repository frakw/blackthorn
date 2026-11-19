//! The architecture map as SVG, drawn like a node editor: your devices, the
//! hub, its spaces and the machines they work on, left to right, with a
//! wire from each space to its machine and dashed wires for bridges.

use crate::ops::{Overview, SpaceView};
use std::fmt::Write as _;

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

/// How you reach this page, from where the web UI listens.
fn web_path(listen: &[String]) -> &'static str {
    let ips: Vec<std::net::IpAddr> = listen
        .iter()
        .filter_map(|a| a.parse::<std::net::SocketAddr>().ok())
        .map(|a| a.ip())
        .collect();
    let tailnet = |ip: &std::net::IpAddr| match ip {
        std::net::IpAddr::V4(v) => v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64,
        std::net::IpAddr::V6(v) => v.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    };
    if !ips.is_empty() && ips.iter().all(tailnet) {
        "over the tailnet"
    } else {
        "over your network"
    }
}

// A node editor: boxes with a title bar, an input port on the left, an
// output port on the right, and curved wires between them. The layout here
// is the starting point; the page's script lets you drag nodes, pan and
// zoom, and remembers where you put them.

const NW: i32 = 230; // node width
const TITLE: i32 = 28;
const SLOT_Y: i32 = TITLE + 14; // the ports' row
const ROW: i32 = 18;
const GAP_Y: i32 = 26;
const COLS: [i32; 4] = [40, 330, 620, 910];
const TOP: i32 = 40;

#[derive(Clone, Copy, PartialEq)]
enum Tone {
    Dim,
    Ok,
    Bad,
}

struct Node {
    id: String,
    kind: &'static str,
    title: String,
    dot: Option<&'static str>,
    href: Option<String>,
    slot_in: Option<&'static str>,
    slot_out: Option<&'static str>,
    rows: Vec<(Tone, String)>,
    x: i32,
    y: i32,
}

impl Node {
    fn h(&self) -> i32 {
        SLOT_Y + 10 + self.rows.len() as i32 * ROW + 6
    }
}

struct Wire {
    from: String,
    to: String,
    class: &'static str,
    label: Option<String>,
}

/// The cubic curve from an output port to an input port.
pub fn wire_path(x1: i32, y1: i32, x2: i32, y2: i32) -> String {
    let dx = ((x2 - x1).abs() / 2).max(50);
    format!("M{x1},{y1} C{},{y1} {},{y2} {x2},{y2}", x1 + dx, x2 - dx)
}

pub fn svg(o: &Overview) -> String {
    let mut nodes: Vec<Node> = Vec::new();
    let mut wires: Vec<Wire> = Vec::new();
    let hub = &o.hub;

    let admin = if hub.admin_from.is_empty() {
        (Tone::Bad, "admin from: anywhere".to_string())
    } else {
        (
            Tone::Dim,
            clip(
                &format!(
                    "admin from: {}",
                    hub.admin_from
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                34,
            ),
        )
    };
    nodes.push(Node {
        id: "devices".into(),
        kind: "devices",
        title: "Your devices".into(),
        dot: None,
        href: None,
        slot_in: None,
        slot_out: Some("connect"),
        rows: vec![
            admin,
            (Tone::Dim, "chats: Remote Control, claude.ai".into()),
            (
                Tone::Dim,
                format!("this page {}", web_path(&hub.web_listen)),
            ),
        ],
        x: COLS[0],
        y: 0,
    });
    nodes.push(Node {
        id: "hub".into(),
        kind: "hub",
        title: format!("{} · hub", clip(&hub.hostname, 22)),
        dot: None,
        href: None,
        slot_in: Some("admin"),
        slot_out: Some("spaces"),
        rows: vec![
            if hub.firewall_loaded {
                (Tone::Ok, "firewall on".into())
            } else {
                (Tone::Bad, "FIREWALL NOT LOADED".into())
            },
            match &hub.claude_version {
                Some(v) => (Tone::Dim, clip(&format!("claude {v}"), 34)),
                None => (Tone::Dim, "claude: not installed".into()),
            },
            match hub.memory_available_mb {
                Some(m) => (
                    if m > 300 { Tone::Dim } else { Tone::Bad },
                    format!("{m} MB memory free"),
                ),
                None => (Tone::Dim, String::new()),
            },
        ],
        x: COLS[1],
        y: 0,
    });
    wires.push(Wire {
        from: "devices".into(),
        to: "hub".into(),
        class: "wire",
        label: None,
    });

    // Spaces in the third column, grouped by machine; each machine in the
    // fourth, level with its spaces.
    let mut sy = TOP;
    let mut hy = TOP;
    for h in &o.hosts {
        let spaces: Vec<&SpaceView> = o.spaces.iter().filter(|s| s.host == h.name).collect();
        let first = sy;
        for s in &spaces {
            let detail = match (s.chats_24h, s.memory_mb) {
                (Some(n), Some(m)) => format!("{n} chat(s) today · {m} MB"),
                (Some(n), None) => format!("{n} chat(s) today"),
                (None, Some(m)) => format!("{m} MB"),
                (None, None) => String::new(),
            };
            let reach = if s.agent != crate::config::CLAUDE {
                "terminal only"
            } else if s.remote_control {
                "Remote Control"
            } else {
                "local only (no Remote Control)"
            };
            let n = Node {
                id: format!("space:{}", s.name),
                kind: "space",
                title: clip(&s.name, 24),
                dot: Some(state_class(&s.state)),
                href: Some(format!("/space/{}", crate::webauth::url_encode(&s.name))),
                slot_in: Some("hub"),
                slot_out: Some("ssh"),
                rows: vec![
                    (Tone::Dim, format!("{} · {}", s.agent, s.state)),
                    (Tone::Dim, detail),
                    (Tone::Dim, reach.into()),
                ],
                x: COLS[2],
                y: sy,
            };
            sy += n.h() + GAP_Y;
            nodes.push(n);
            wires.push(Wire {
                from: "hub".into(),
                to: format!("space:{}", s.name),
                class: "wire",
                label: None,
            });
            wires.push(Wire {
                from: format!("space:{}", s.name),
                to: format!("host:{}", h.name),
                class: if h.blocked { "wire cut" } else { "wire" },
                label: None,
            });
        }
        let node = Node {
            id: format!("host:{}", h.name),
            kind: "host",
            title: clip(&h.name, 24),
            dot: None,
            href: Some(format!("/host/{}", crate::webauth::url_encode(&h.name))),
            slot_in: Some("ssh"),
            slot_out: None,
            rows: vec![
                (Tone::Dim, clip(&format!("{}@{}", h.user, h.address), 34)),
                (Tone::Dim, h.os.to_string()),
                if h.blocked {
                    (Tone::Bad, clip(&h.status, 34))
                } else if spaces.is_empty() {
                    (Tone::Dim, "no space yet".into())
                } else {
                    (Tone::Ok, clip(&h.status, 34))
                },
            ],
            x: COLS[3],
            y: 0,
        };
        let height = node.h();
        let centre = if spaces.is_empty() {
            hy
        } else {
            (first + sy - GAP_Y) / 2 - height / 2
        };
        let y = centre.max(hy);
        hy = y + height + GAP_Y;
        // The next machine's spaces start below this machine.
        sy = sy.max(hy);
        nodes.push(Node { y, ..node });
    }
    for b in &o.bridges {
        wires.push(Wire {
            from: format!("space:{}", b.from),
            to: format!("host:{}", b.host),
            class: "wire bridge",
            label: Some(format!("bridge {}", b.remaining)),
        });
    }

    let bottom = nodes
        .iter()
        .map(|n| n.y + n.h())
        .max()
        .unwrap_or(0)
        .max(220);
    // The devices and the hub halfway down.
    for n in nodes.iter_mut().take(2) {
        n.y = ((bottom + TOP) / 2 - n.h() / 2).max(TOP);
    }
    let width = COLS[3] + NW + 40;
    let height = bottom + 40;

    let mut out = String::new();
    let _ = write!(
        out,
        "<svg class=\"map graph\" viewBox=\"0 0 {width} {height}\" width=\"{width}\" height=\"{height}\" \
         role=\"img\" aria-label=\"blackthorn map\" xmlns=\"http://www.w3.org/2000/svg\">\
         <defs><pattern id=\"grid\" width=\"24\" height=\"24\" patternUnits=\"userSpaceOnUse\">\
         <circle class=\"grid-dot\" cx=\"1\" cy=\"1\" r=\"1.1\"/></pattern></defs>\
         <rect class=\"grid-bg\" x=\"-20000\" y=\"-20000\" width=\"40000\" height=\"40000\" fill=\"url(#grid)\"/>"
    );

    // Wires under the nodes.
    let find = |id: &str| nodes.iter().find(|n| n.id == id);
    out.push_str("<g class=\"wires\">");
    for w in &wires {
        let (Some(a), Some(b)) = (find(&w.from), find(&w.to)) else {
            continue;
        };
        let (x1, y1, x2, y2) = (a.x + NW, a.y + SLOT_Y, b.x, b.y + SLOT_Y);
        let _ = write!(
            out,
            "<path class=\"{}\" data-from=\"{}\" data-to=\"{}\" d=\"{}\"/>",
            w.class,
            esc(&w.from),
            esc(&w.to),
            wire_path(x1, y1, x2, y2)
        );
        if let Some(l) = &w.label {
            let _ = write!(
                out,
                "<text class=\"wire-label\" data-from=\"{}\" data-to=\"{}\" x=\"{}\" y=\"{}\" \
                 text-anchor=\"middle\">{}</text>",
                esc(&w.from),
                esc(&w.to),
                (x1 + x2) / 2,
                (y1 + y2) / 2 - 6,
                esc(l)
            );
        }
    }
    out.push_str("</g>");

    for n in &nodes {
        let h = n.h();
        let _ = write!(
            out,
            "<g class=\"node kind-{}\" data-node=\"{}\" data-w=\"{NW}\" transform=\"translate({},{})\">\
             <rect class=\"node-body\" width=\"{NW}\" height=\"{h}\" rx=\"8\"/>\
             <path class=\"node-title\" d=\"M0,8 a8,8 0 0 1 8,-8 h{} a8,8 0 0 1 8,8 v{} h-{NW} z\"/>",
            n.kind,
            esc(&n.id),
            n.x,
            n.y,
            NW - 16,
            TITLE - 8,
        );
        let mut tx = 12;
        if let Some(cls) = n.dot {
            let _ = write!(
                out,
                "<circle class=\"dot {cls}\" cx=\"17\" cy=\"{}\" r=\"5\"/>",
                TITLE / 2
            );
            tx = 28;
        }
        let name = format!(
            "<text class=\"node-name\" x=\"{tx}\" y=\"{}\">{}</text>",
            TITLE / 2 + 5,
            esc(&n.title)
        );
        match &n.href {
            Some(href) => {
                let _ = write!(out, "<a href=\"{}\">{name}</a>", esc(href));
            }
            None => out.push_str(&name),
        }
        if let Some(l) = n.slot_in {
            let _ = write!(
                out,
                "<circle class=\"port\" cx=\"0\" cy=\"{SLOT_Y}\" r=\"5\"/>\
                 <text class=\"slot\" x=\"12\" y=\"{}\">{l}</text>",
                SLOT_Y + 4
            );
        }
        if let Some(l) = n.slot_out {
            let _ = write!(
                out,
                "<circle class=\"port\" cx=\"{NW}\" cy=\"{SLOT_Y}\" r=\"5\"/>\
                 <text class=\"slot\" x=\"{}\" y=\"{}\" text-anchor=\"end\">{l}</text>",
                NW - 12,
                SLOT_Y + 4
            );
        }
        for (i, (tone, text)) in n.rows.iter().enumerate() {
            let cls = match tone {
                Tone::Dim => "t-dim",
                Tone::Ok => "t-ok",
                Tone::Bad => "t-bad",
            };
            let _ = write!(
                out,
                "<text class=\"{cls}\" x=\"12\" y=\"{}\">{}</text>",
                SLOT_Y + 14 + (i as i32 + 1) * ROW - 4,
                esc(text)
            );
        }
        out.push_str("</g>");
    }

    if o.hosts.is_empty() {
        let _ = write!(
            out,
            "<text class=\"t-dim\" x=\"{}\" y=\"{}\">No machines yet: add one under Machines, \
             then create a space on it.</text>",
            COLS[2],
            TOP + 20
        );
    }
    out.push_str("</svg>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn says_how_the_page_is_reached() {
        let l = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(web_path(&l(&["100.64.0.10:7180"])), "over the tailnet");
        assert_eq!(
            web_path(&l(&["[fd7a:115c:a1e0::1]:7180"])),
            "over the tailnet"
        );
        assert_eq!(web_path(&l(&["0.0.0.0:7180"])), "over your network");
        assert_eq!(web_path(&l(&["192.168.10.106:7180"])), "over your network");
        assert_eq!(web_path(&l(&["100.128.0.1:7180"])), "over your network");
    }
    use crate::ops::{BridgeView, HostView, HubView};
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
            remote_control: n != "fig-aider",
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
    fn draws_every_node_and_wire() {
        let s = svg(&overview());
        assert!(s.starts_with("<svg class=\"map graph\""));
        assert!(s.ends_with("</svg>"));
        assert_eq!(s.matches("class=\"node kind-space\"").count(), 3);
        assert_eq!(s.matches("class=\"node kind-host\"").count(), 3);
        assert_eq!(s.matches("class=\"node kind-hub\"").count(), 1);
        assert_eq!(s.matches("class=\"node kind-devices\"").count(), 1);
        // devices->hub, hub->3 spaces, 3 spaces->their machines, 1 bridge.
        assert_eq!(s.matches("<path class=\"wire").count(), 8);
        assert!(
            s.contains("class=\"wire cut\" data-from=\"space:nas-&lt;x&gt;\" data-to=\"host:nas\"")
        );
        assert!(
            s.contains("class=\"wire bridge\" data-from=\"space:fig-claude\" data-to=\"host:nas\"")
        );
        assert!(s.contains("bridge for 52m"));
        assert!(s.contains("no space yet"), "pine has none");
        assert!(s.contains("href=\"/space/fig-claude\""));
        assert!(s.contains("local only"), "fig-aider has Remote Control off");
        assert!(s.contains("admin from: anywhere"));
    }

    #[test]
    fn nodes_do_not_overlap_in_a_column() {
        let s = svg(&overview());
        let mut boxes: Vec<(i32, i32, i32)> = Vec::new(); // x, y, height
        for part in s.split("<g class=\"node ").skip(1) {
            let t = &part[part.find("translate(").unwrap() + 10..];
            let (x, rest) = t.split_once(',').unwrap();
            let y = rest.split(')').next().unwrap();
            let h = part
                .split("height=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            boxes.push((x.parse().unwrap(), y.parse().unwrap(), h.parse().unwrap()));
        }
        assert_eq!(boxes.len(), 8);
        for (i, a) in boxes.iter().enumerate() {
            for b in &boxes[i + 1..] {
                if a.0 == b.0 {
                    assert!(a.1 + a.2 <= b.1 || b.1 + b.2 <= a.1, "{a:?} overlaps {b:?}");
                }
            }
        }
    }

    #[test]
    fn wires_curve_from_port_to_port() {
        assert_eq!(wire_path(0, 10, 300, 50), "M0,10 C150,10 150,50 300,50");
        assert_eq!(wire_path(0, 0, 40, 0), "M0,0 C50,0 -10,0 40,0");
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
