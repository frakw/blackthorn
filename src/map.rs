//! The architecture map as SVG, drawn like a node editor: your devices on
//! the left; this hub (blackthorn and its spaces) in one frame; the Claude
//! app and the models a space uses in the cloud's frame; the machines the
//! spaces work on to the right. Dashed wires are bridges (amber) and blocks
//! (red).

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

// A node editor: boxes with a title bar, input ports on the left, output
// ports on the right, and curved wires between them. Frames group the nodes
// that run on one machine (this hub) or in one company's cloud. Arrows show
// who opens the connection. The layout here is the starting point; the
// page's script lets you drag nodes, pan and zoom, and remembers where you
// put them.

const NW: i32 = 230; // node width
const TITLE: i32 = 28;
const SLOT_Y: i32 = TITLE + 14; // the first port's row
const SLOT_ROW: i32 = 18; // between ports
const ROW: i32 = 18;
const GAP_Y: i32 = 26;
const COLS: [i32; 4] = [40, 330, 620, 910];
const TOP: i32 = 40;
const PAD: i32 = 16; // frame padding
const FRAME_TITLE: i32 = 26;
const ICONS: i32 = 26; // the devices' icon row

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
    ins: Vec<&'static str>,
    outs: Vec<&'static str>,
    icons: bool,
    rows: Vec<(Tone, String)>,
    x: i32,
    y: i32,
}

impl Node {
    fn slots(&self) -> i32 {
        self.ins.len().max(self.outs.len()).max(1) as i32
    }

    /// Where the text rows start.
    fn body_y(&self) -> i32 {
        SLOT_Y + (self.slots() - 1) * SLOT_ROW + 10 + if self.icons { ICONS } else { 0 }
    }

    fn h(&self) -> i32 {
        self.body_y() + self.rows.len() as i32 * ROW + 6
    }
}

/// Who opens the connection a wire stands for.
#[derive(Clone, Copy, PartialEq)]
enum Dir {
    /// The left end (an output port) connects to the right end.
    Forward,
    /// The right end connects to the left end (a space dialing out to the
    /// Claude app's servers).
    Back,
}

struct Wire {
    from: String,
    fp: usize,
    to: String,
    tp: usize,
    class: &'static str,
    dir: Dir,
    label: Option<String>,
}

fn wire(from: &str, fp: usize, to: &str, tp: usize, class: &'static str, dir: Dir) -> Wire {
    Wire {
        from: from.into(),
        fp,
        to: to.into(),
        tp,
        class,
        dir,
        label: None,
    }
}

struct Frame {
    kind: &'static str,
    title: String,
    members: Vec<String>,
}

/// The cubic curve from an output port to an input port.
pub fn wire_path(x1: i32, y1: i32, x2: i32, y2: i32) -> String {
    let dx = ((x2 - x1).abs() / 2).max(50);
    format!("M{x1},{y1} C{},{y1} {},{y2} {x2},{y2}", x1 + dx, x2 - dx)
}

/// The cloud an agent talks to, for agents blackthorn knows.
struct Provider {
    id: &'static str,
    company: &'static str,
    /// Where you chat with the agent's spaces from, if anywhere.
    app: Option<&'static str>,
    models: &'static str,
}

fn provider(agent: &str) -> Option<Provider> {
    match agent {
        crate::config::CLAUDE => Some(Provider {
            id: "anthropic",
            company: "Anthropic",
            app: Some("Claude app · claude.ai"),
            models: "Claude models",
        }),
        "codex" => Some(Provider {
            id: "openai",
            company: "OpenAI",
            app: None,
            models: "OpenAI models",
        }),
        _ => None,
    }
}

fn slots_of(agent: &str) -> (Vec<&'static str>, Vec<&'static str>) {
    match provider(agent) {
        Some(p) if p.app.is_some() => (vec!["blackthorn", "chats"], vec!["model", "ssh"]),
        Some(_) => (vec!["blackthorn"], vec!["model", "ssh"]),
        None => (vec!["blackthorn"], vec!["ssh"]),
    }
}

pub fn svg(o: &Overview) -> String {
    let mut nodes: Vec<Node> = Vec::new();
    let mut wires: Vec<Wire> = Vec::new();
    let mut frames: Vec<Frame> = Vec::new();
    let hub = &o.hub;

    // ---- the clouds: one frame per company, app on the left, models right.
    let mut y_cloud = TOP + FRAME_TITLE;
    let mut providers: Vec<Provider> = Vec::new();
    for s in &o.spaces {
        if let Some(p) = provider(&s.agent) {
            if !providers.iter().any(|q| q.id == p.id) {
                providers.push(p);
            }
        }
    }
    let mut app_of: Vec<(&'static str, String)> = Vec::new(); // provider -> app node
    let mut models_of: Vec<(&'static str, String)> = Vec::new();
    for p in &providers {
        let spaces: Vec<&SpaceView> = o
            .spaces
            .iter()
            .filter(|s| provider(&s.agent).is_some_and(|q| q.id == p.id))
            .collect();
        let mut members = Vec::new();
        let mut bottom = y_cloud;
        let remote: Vec<&&SpaceView> = spaces.iter().filter(|s| s.remote_control).collect();
        if let (Some(app), false) = (p.app, remote.is_empty()) {
            let id = format!("app:{}", p.id);
            let n = Node {
                id: id.clone(),
                kind: "app",
                title: app.into(),
                dot: None,
                href: None,
                ins: vec!["you"],
                outs: vec!["Remote Control"],
                icons: false,
                rows: vec![
                    (Tone::Dim, "chats from phone, desktop, web".into()),
                    (
                        Tone::Dim,
                        format!("{} space(s) with Remote Control", remote.len()),
                    ),
                ],
                x: COLS[1],
                y: y_cloud,
            };
            bottom = bottom.max(n.y + n.h());
            nodes.push(n);
            members.push(id.clone());
            app_of.push((p.id, id));
        }
        // The models in use, each with the spaces using it.
        let mut used: Vec<(String, Vec<&str>)> = Vec::new();
        for s in &spaces {
            let m = s.model.clone().unwrap_or_else(|| "(not known yet)".into());
            match used.iter_mut().find(|(n, _)| *n == m) {
                Some((_, v)) => v.push(&s.name),
                None => used.push((m, vec![&s.name])),
            }
        }
        let id = format!("models:{}", p.id);
        let n = Node {
            id: id.clone(),
            kind: "model",
            title: p.models.into(),
            dot: None,
            href: None,
            ins: vec!["spaces"],
            outs: vec![],
            icons: false,
            rows: used
                .iter()
                .map(|(m, v)| (Tone::Dim, clip(&format!("{m}: {}", v.join(", ")), 34)))
                .collect(),
            x: COLS[3],
            y: y_cloud,
        };
        bottom = bottom.max(n.y + n.h());
        nodes.push(n);
        members.push(id.clone());
        models_of.push((p.id, id));
        frames.push(Frame {
            kind: "cloud",
            title: format!("{} · cloud", p.company),
            members,
        });
        y_cloud = bottom + PAD + 30 + FRAME_TITLE;
    }

    // ---- this hub: blackthorn and its spaces in one frame; the machines
    // they work on to the right, level with their spaces.
    let top = if providers.is_empty() {
        TOP + FRAME_TITLE
    } else {
        y_cloud
    };
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
    let has_app = !app_of.is_empty();
    nodes.push(Node {
        id: "devices".into(),
        kind: "devices",
        title: "Your devices".into(),
        dot: None,
        href: None,
        ins: vec![],
        outs: if has_app {
            vec!["web UI · SSH", "chats"]
        } else {
            vec!["web UI · SSH"]
        },
        icons: true,
        rows: vec![
            admin,
            (Tone::Dim, format!("web UI {}", web_path(&hub.web_listen))),
        ],
        x: COLS[0],
        y: 0,
    });
    nodes.push(Node {
        id: "hub".into(),
        kind: "hub",
        title: "blackthorn".into(),
        dot: None,
        href: None,
        ins: vec!["admin"],
        outs: vec!["runs"],
        icons: false,
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
        y: top,
    });
    wires.push(wire("devices", 0, "hub", 0, "wire", Dir::Forward));
    for (_, app) in &app_of {
        wires.push(wire("devices", 1, app, 0, "wire", Dir::Forward));
    }
    let mut hub_members = vec!["hub".to_string()];

    let mut sy = top;
    let mut hy = top;
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
            let p = provider(&s.agent);
            let reach = match &p {
                None => "terminal only".to_string(),
                Some(p) if p.app.is_some() && s.remote_control => "Remote Control".into(),
                Some(p) if p.app.is_some() => "local only (no Remote Control)".into(),
                Some(_) => "terminal only".into(),
            };
            let (ins, outs) = slots_of(&s.agent);
            let id = format!("space:{}", s.name);
            let mut rows = vec![
                (Tone::Dim, format!("{} · {}", s.agent, s.state)),
                (Tone::Dim, detail),
            ];
            if let Some(m) = &s.model {
                rows.push((Tone::Dim, clip(&format!("model: {m}"), 34)));
            }
            rows.push((Tone::Dim, reach));
            let n = Node {
                id: id.clone(),
                kind: "space",
                title: clip(&s.name, 24),
                dot: Some(state_class(&s.state)),
                href: Some(format!("/space/{}", crate::webauth::url_encode(&s.name))),
                ins,
                outs: outs.clone(),
                icons: false,
                rows,
                x: COLS[2],
                y: sy,
            };
            sy += n.h() + GAP_Y;
            nodes.push(n);
            hub_members.push(id.clone());
            wires.push(wire("hub", 0, &id, 0, "wire", Dir::Forward));
            if let Some(p) = &p {
                if s.remote_control {
                    if let Some((_, app)) = app_of.iter().find(|(q, _)| *q == p.id) {
                        wires.push(wire(app, 0, &id, 1, "wire", Dir::Back));
                    }
                }
                if let Some((_, m)) = models_of.iter().find(|(q, _)| *q == p.id) {
                    wires.push(wire(&id, 0, m, 0, "wire", Dir::Forward));
                }
            }
            let ssh = outs.len() - 1;
            wires.push(wire(
                &id,
                ssh,
                &format!("host:{}", h.name),
                0,
                if h.blocked { "wire cut" } else { "wire" },
                Dir::Forward,
            ));
        }
        let node = Node {
            id: format!("host:{}", h.name),
            kind: "host",
            title: clip(&h.name, 24),
            dot: None,
            href: Some(format!("/host/{}", crate::webauth::url_encode(&h.name))),
            ins: vec!["ssh"],
            outs: vec![],
            icons: false,
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
        sy = sy.max(hy);
        nodes.push(Node { y, ..node });
    }
    for b in &o.bridges {
        let ssh = slots_of(
            &o.spaces
                .iter()
                .find(|s| s.name == b.from)
                .map(|s| s.agent.clone())
                .unwrap_or_default(),
        )
        .1
        .len()
            - 1;
        wires.push(Wire {
            label: Some(format!("bridge {}", b.remaining)),
            ..wire(
                &format!("space:{}", b.from),
                ssh,
                &format!("host:{}", b.host),
                0,
                "wire bridge",
                Dir::Forward,
            )
        });
    }
    frames.push(Frame {
        kind: "machine",
        title: format!("{} · this hub", clip(&hub.hostname, 30)),
        members: hub_members,
    });

    // The devices halfway down everything.
    let bottom = nodes
        .iter()
        .map(|n| n.y + n.h())
        .max()
        .unwrap_or(0)
        .max(220);
    if let Some(d) = nodes.iter_mut().find(|n| n.id == "devices") {
        d.y = ((bottom + TOP) / 2 - d.h() / 2).max(TOP);
    }
    let width = COLS[3] + NW + 40;
    let height = bottom + PAD + 40;

    let mut out = String::new();
    let _ = write!(
        out,
        "<svg class=\"map graph\" viewBox=\"0 0 {width} {height}\" width=\"{width}\" height=\"{height}\" \
         role=\"img\" aria-label=\"blackthorn map\" xmlns=\"http://www.w3.org/2000/svg\">\
         <defs><pattern id=\"grid\" width=\"24\" height=\"24\" patternUnits=\"userSpaceOnUse\">\
         <circle class=\"grid-dot\" cx=\"1\" cy=\"1\" r=\"1.1\"/></pattern>\
         <marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"7\" markerHeight=\"7\" \
         orient=\"auto-start-reverse\"><path class=\"arrow\" d=\"M0,0 L10,5 L0,10 z\"/></marker></defs>\
         <rect class=\"grid-bg\" x=\"-20000\" y=\"-20000\" width=\"40000\" height=\"40000\" fill=\"url(#grid)\"/>"
    );
    let find = |id: &str| nodes.iter().find(|n| n.id == id);

    // Frames under everything.
    out.push_str("<g class=\"frames\">");
    for f in &frames {
        let ms: Vec<&Node> = f.members.iter().filter_map(|m| find(m)).collect();
        if ms.is_empty() {
            continue;
        }
        let x1 = ms.iter().map(|n| n.x).min().unwrap_or(0) - PAD;
        let y1 = ms.iter().map(|n| n.y).min().unwrap_or(0) - PAD - FRAME_TITLE;
        let x2 = ms.iter().map(|n| n.x + NW).max().unwrap_or(0) + PAD;
        let y2 = ms.iter().map(|n| n.y + n.h()).max().unwrap_or(0) + PAD;
        let _ = write!(
            out,
            "<g class=\"frame kind-{}\" data-members=\"{}\"><rect class=\"frame-body\" x=\"{x1}\" y=\"{y1}\" \
             width=\"{}\" height=\"{}\" rx=\"12\"/><text class=\"frame-title\" x=\"{}\" y=\"{}\">{}</text></g>",
            f.kind,
            esc(&f.members.join(" ")),
            x2 - x1,
            y2 - y1,
            x1 + 12,
            y1 + 18,
            esc(&f.title)
        );
    }
    out.push_str("</g>");

    // Wires under the nodes.
    out.push_str("<g class=\"wires\">");
    for w in &wires {
        let (Some(a), Some(b)) = (find(&w.from), find(&w.to)) else {
            continue;
        };
        let (x1, y1) = (a.x + NW, a.y + SLOT_Y + w.fp as i32 * SLOT_ROW);
        let (x2, y2) = (b.x, b.y + SLOT_Y + w.tp as i32 * SLOT_ROW);
        let marker = match w.dir {
            Dir::Forward => "marker-end=\"url(#arrow)\"",
            Dir::Back => "marker-start=\"url(#arrow)\"",
        };
        let ends = format!(
            "data-from=\"{}\" data-fp=\"{}\" data-to=\"{}\" data-tp=\"{}\"",
            esc(&w.from),
            w.fp,
            esc(&w.to),
            w.tp
        );
        let _ = write!(
            out,
            "<path class=\"{}\" {ends} {marker} d=\"{}\"/>",
            w.class,
            wire_path(x1, y1, x2, y2)
        );
        if let Some(l) = &w.label {
            let _ = write!(
                out,
                "<text class=\"wire-label\" {ends} x=\"{}\" y=\"{}\" text-anchor=\"middle\">{}</text>",
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
        for (i, l) in n.ins.iter().enumerate() {
            let y = SLOT_Y + i as i32 * SLOT_ROW;
            let _ = write!(
                out,
                "<circle class=\"port\" cx=\"0\" cy=\"{y}\" r=\"5\"/>\
                 <text class=\"slot\" x=\"12\" y=\"{}\">{l}</text>",
                y + 4
            );
        }
        for (i, l) in n.outs.iter().enumerate() {
            let y = SLOT_Y + i as i32 * SLOT_ROW;
            let _ = write!(
                out,
                "<circle class=\"port\" cx=\"{NW}\" cy=\"{y}\" r=\"5\"/>\
                 <text class=\"slot\" x=\"{}\" y=\"{}\" text-anchor=\"end\">{l}</text>",
                NW - 12,
                y + 4
            );
        }
        if n.icons {
            let _ = write!(
                out,
                "<g class=\"icons\" transform=\"translate(12,{})\">{DEVICE_ICONS}</g>",
                n.body_y() - ICONS + 2
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
                n.body_y() + (i as i32 + 1) * ROW - 4,
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
            top + 20
        );
    }
    out.push_str("</svg>");
    out
}

/// Phone, laptop, desktop and terminal, drawn in lines (20 px high).
const DEVICE_ICONS: &str = "<rect x=\"2\" y=\"1\" width=\"11\" height=\"18\" rx=\"2\"/><path d=\"M6 16h3\"/>\
    <g transform=\"translate(24,0)\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"11\" rx=\"1.5\"/><path d=\"M0 17h24\"/></g>\
    <g transform=\"translate(56,0)\"><rect x=\"0\" y=\"1\" width=\"22\" height=\"14\" rx=\"1.5\"/><path d=\"M11 15v4M6 19h10\"/></g>\
    <g transform=\"translate(88,0)\"><rect x=\"0\" y=\"1\" width=\"22\" height=\"17\" rx=\"2\"/><path d=\"M4 7l4 3-4 3M10 14h7\"/></g>";

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
            dir: n.into(),
            state: st.into(),
            memory_mb: Some(300),
            chats_24h: Some(2),
            reachable: vec![],
            model: (n == "fig-claude").then(|| "Opus 5.5".to_string()),
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
        assert_eq!(s.matches("class=\"node kind-app\"").count(), 1);
        assert_eq!(s.matches("class=\"node kind-model\"").count(), 1);
        // devices->hub and ->app, hub->3 spaces, app->2 spaces with Remote
        // Control, 3 spaces->models, 3 spaces->their machines, 1 bridge.
        assert_eq!(s.matches("<path class=\"wire").count(), 14);
        assert!(s.contains(
            "class=\"wire cut\" data-from=\"space:nas-&lt;x&gt;\" data-fp=\"1\" data-to=\"host:nas\""
        ));
        assert!(s.contains(
            "class=\"wire bridge\" data-from=\"space:fig-claude\" data-fp=\"1\" data-to=\"host:nas\""
        ));
        // Spaces dial out to the Claude app: the arrow points back to it.
        assert!(s.contains(
            "data-from=\"app:anthropic\" data-fp=\"0\" data-to=\"space:fig-claude\" data-tp=\"1\" marker-start"
        ));
        assert!(
            !s.contains("data-to=\"space:fig-aider\" data-tp=\"1\""),
            "Remote Control off"
        );
        assert!(s.contains("bridge for 52m"));
        assert!(s.contains("no space yet"), "pine has none");
        assert!(s.contains("href=\"/space/fig-claude\""));
        assert!(s.contains("local only"), "fig-aider has Remote Control off");
        assert!(s.contains("admin from: anywhere"));
        assert!(s.contains("Opus 5.5: fig-claude"));
        assert!(s.contains("model: Opus 5.5"));
        // Frames: this hub (blackthorn and its spaces), and the cloud.
        assert!(s.contains(
            "class=\"frame kind-machine\" data-members=\"hub space:fig-claude space:fig-aider space:nas-&lt;x&gt;\""
        ));
        assert!(s.contains(
            "class=\"frame kind-cloud\" data-members=\"app:anthropic models:anthropic\""
        ));
        assert!(s.contains("Anthropic · cloud"));
    }

    #[test]
    fn without_claude_spaces_no_cloud() {
        let mut o = overview();
        for s in o.spaces.iter_mut() {
            s.agent = "aider".into();
        }
        let s = svg(&o);
        assert!(!s.contains("kind-cloud"));
        assert!(!s.contains("kind-app"));
        assert!(s.contains("terminal only"));
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
        assert_eq!(boxes.len(), 10);
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
