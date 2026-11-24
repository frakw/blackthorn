//! The architecture map as SVG, drawn like a node editor. Bands from top
//! to bottom: the AI company's cloud (the Claude app, the API the agents
//! call), with your devices beside it, since they reach the spaces only
//! through the app; your tailnet (the device you manage blackthorn from,
//! this hub with blackthorn and its spaces, the machines on the tailnet);
//! your LAN (its router, the machines on it). Arrows point the way commands
//! go. Dashed wires are bridges (amber) and blocks (red); dotted ones are
//! services a space uses, and the hub's way to the internet.

use crate::ops::{HostView, Overview, SpaceView};
use crate::state::Tier;
use std::fmt::Write as _;
use std::net::IpAddr;

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

/// A tailnet address (Tailscale's CGNAT range, or its IPv6 prefix).
pub fn is_tailnet(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64,
        IpAddr::V6(v) => v.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

/// A private (LAN) address.
pub fn is_lan(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_link_local(),
        IpAddr::V6(v) => !is_tailnet(ip) && (v.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// How you reach this page, from where the web UI listens.
fn web_path(listen: &[String]) -> &'static str {
    let ips: Vec<std::net::IpAddr> = listen
        .iter()
        .filter_map(|a| a.parse::<std::net::SocketAddr>().ok())
        .map(|a| a.ip())
        .collect();
    if !ips.is_empty() && ips.iter().all(is_tailnet) {
        "over the tailnet"
    } else {
        "over your network"
    }
}

// A node editor: boxes with a title bar, input ports on the left, output
// ports on the right, and curved wires between them. Frames group what runs
// in one place (a company's cloud, this hub) or on one network (the
// tailnet, the LAN); a frame inside another is drawn with more padding. The
// layout here is the starting point; the page's script lets you drag nodes,
// pan and zoom, and remembers where you put them.

const NW: i32 = 230; // node width
const TITLE: i32 = 28;
const SLOT_Y: i32 = TITLE + 14; // the first port's row
const SLOT_ROW: i32 = 18; // between ports
const ROW: i32 = 18;
const GAP_Y: i32 = 26;
const COLS: [i32; 4] = [40, 330, 620, 910];
const TOP: i32 = 40;
const PAD: i32 = 16; // frame padding
const OUTER: i32 = 34; // padding of a frame around a frame
const FRAME_TITLE: i32 = 26;
const BAND_GAP: i32 = 40; // between the cloud, tailnet and LAN bands
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
    /// Line drawings above the text rows.
    icons: Option<&'static str>,
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
        SLOT_Y + (self.slots() - 1) * SLOT_ROW + 10 + if self.icons.is_some() { ICONS } else { 0 }
    }

    fn h(&self) -> i32 {
        self.body_y() + self.rows.len() as i32 * ROW + 6
    }

    fn port_in(&self, name: &str) -> usize {
        self.ins.iter().position(|p| *p == name).unwrap_or(0)
    }

    fn port_out(&self, name: &str) -> usize {
        self.outs.iter().position(|p| *p == name).unwrap_or(0)
    }
}

/// A wire from an output port to an input port. The arrow points the way
/// commands go (always from left end to right end).
struct Wire {
    from: String,
    fp: usize,
    to: String,
    tp: usize,
    class: &'static str,
    arrow: bool,
    /// Leaves from a port on the left side of `from` (the hub's internet).
    from_left: bool,
    label: Option<String>,
}

fn wire(from: &str, fp: usize, to: &str, tp: usize, class: &'static str) -> Wire {
    Wire {
        from: from.into(),
        fp,
        to: to.into(),
        tp,
        class,
        arrow: true,
        from_left: false,
        label: None,
    }
}

struct Frame {
    kind: &'static str,
    title: String,
    members: Vec<String>,
    pad: i32,
}

/// The cubic curve from an output port to an input port.
pub fn wire_path(x1: i32, y1: i32, x2: i32, y2: i32) -> String {
    let dx = ((x2 - x1).abs() / 2).max(50);
    format!("M{x1},{y1} C{},{y1} {},{y2} {x2},{y2}", x1 + dx, x2 - dx)
}

/// The curve between two ports on the left sides of their nodes.
pub fn wire_path_left(x1: i32, y1: i32, x2: i32, y2: i32) -> String {
    let dx = ((x2 - x1).abs() / 2).max(60);
    format!(
        "M{x1},{y1} C{},{y1} {},{y2} {x2},{y2}",
        x1.min(x2) - dx,
        x2 - dx
    )
}

/// The cloud an agent talks to, for agents blackthorn knows.
struct Provider {
    id: &'static str,
    company: &'static str,
    /// Where you chat with the agent's spaces from, if anywhere.
    app: Option<&'static str>,
    api: &'static str,
}

fn provider(agent: &str) -> Option<Provider> {
    match agent {
        crate::config::CLAUDE => Some(Provider {
            id: "anthropic",
            company: "Anthropic",
            app: Some("Claude app · claude.ai"),
            api: "Claude API",
        }),
        "codex" => Some(Provider {
            id: "openai",
            company: "OpenAI",
            app: None,
            api: "OpenAI API",
        }),
        _ => None,
    }
}

/// A space's ports. In: Remote Control (from the app, above) on top, then
/// blackthorn (from the hub, to the left). Out: the API (above) on top,
/// then SSH to its machine.
fn space_ports(s: &SpaceView) -> (Vec<&'static str>, Vec<&'static str>) {
    match provider(&s.agent) {
        Some(p) if p.app.is_some() && s.remote_control => {
            (vec!["Remote Control", "blackthorn"], vec!["API", "ssh"])
        }
        Some(_) => (vec!["blackthorn"], vec!["API", "ssh"]),
        None => (vec!["blackthorn"], vec!["ssh"]),
    }
}

/// Where a machine is drawn: on the tailnet, on the LAN, or elsewhere.
#[derive(Clone, Copy, PartialEq)]
enum Net {
    Tailnet,
    Lan,
    Other,
}

fn net_of(h: &HostView) -> Net {
    if is_tailnet(&h.address) {
        Net::Tailnet
    } else if is_lan(&h.address) {
        Net::Lan
    } else {
        Net::Other
    }
}

fn host_node(h: &HostView, spaces: usize) -> Node {
    let mut rows = vec![(Tone::Dim, clip(&format!("{} · {}", h.address, h.os), 34))];
    rows.push((Tone::Dim, clip(&format!("blackthorn: {}", h.user), 34)));
    if h.setup.is_some() {
        rows.push((Tone::Ok, "spaces: logins of their own".into()));
    } else if let Some(u) = &h.readonly {
        rows.push((Tone::Ok, clip(&format!("read-only: {u}"), 34)));
    }
    rows.push(if h.blocked {
        (Tone::Bad, clip(&h.status, 34))
    } else if spaces == 0 {
        (Tone::Dim, "no space yet".into())
    } else {
        (Tone::Ok, clip(&h.status, 34))
    });
    Node {
        id: format!("host:{}", h.name),
        kind: "host",
        title: clip(&h.name, 24),
        dot: None,
        href: Some(format!("/host/{}", crate::webauth::url_encode(&h.name))),
        ins: vec!["ssh"],
        outs: vec![],
        icons: None,
        rows,
        x: COLS[3],
        y: 0,
    }
}

pub fn svg(o: &Overview) -> String {
    let mut nodes: Vec<Node> = Vec::new();
    let mut wires: Vec<Wire> = Vec::new();
    let mut frames: Vec<Frame> = Vec::new();
    let hub = &o.hub;
    let net = &hub.net;
    let tailnet = net.control.is_some();

    // ---- the clouds: one frame per company, app on the left, API right.
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
    let mut api_of: Vec<(&'static str, String)> = Vec::new();
    for p in &providers {
        let spaces: Vec<&SpaceView> = o
            .spaces
            .iter()
            .filter(|s| provider(&s.agent).is_some_and(|q| q.id == p.id))
            .collect();
        let mut members = Vec::new();
        let mut bottom = y_cloud;
        let remote = spaces.iter().filter(|s| s.remote_control).count();
        if let (Some(app), true) = (p.app, remote > 0) {
            let id = format!("app:{}", p.id);
            let n = Node {
                id: id.clone(),
                kind: "app",
                title: app.into(),
                dot: None,
                href: None,
                ins: vec!["you"],
                outs: vec!["Remote Control"],
                icons: None,
                rows: vec![
                    (Tone::Dim, "your chats, from phone, desktop, web".into()),
                    (Tone::Dim, format!("{remote} space(s) with Remote Control")),
                    (Tone::Dim, "spaces connect out to it".into()),
                ],
                x: COLS[1],
                y: y_cloud,
            };
            bottom = bottom.max(n.y + n.h());
            nodes.push(n);
            members.push(id.clone());
            app_of.push((p.id, id));
        }
        // The API the spaces call, with the models they use.
        let mut used: Vec<(String, Vec<&str>)> = Vec::new();
        for s in &spaces {
            let m = s
                .model
                .clone()
                .unwrap_or_else(|| "model not known yet".into());
            match used.iter_mut().find(|(n, _)| *n == m) {
                Some((_, v)) => v.push(&s.name),
                None => used.push((m, vec![&s.name])),
            }
        }
        let id = format!("api:{}", p.id);
        let n = Node {
            id: id.clone(),
            kind: "api",
            title: p.api.into(),
            dot: None,
            href: None,
            ins: vec!["API"],
            outs: vec![],
            icons: None,
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
        api_of.push((p.id, id));
        frames.push(Frame {
            kind: "cloud",
            title: format!("{} · cloud", p.company),
            members,
            pad: PAD,
        });
        y_cloud = bottom + PAD + BAND_GAP + FRAME_TITLE;
    }
    // Your phone, laptop and desktop reach the spaces only through the
    // company's app, so they sit beside its cloud, on no network of yours.
    if let Some((_, app)) = app_of.first() {
        let y = nodes.iter().find(|n| &n.id == app).map_or(TOP, |n| n.y);
        nodes.push(Node {
            id: "devices".into(),
            kind: "devices",
            title: "Your devices".into(),
            dot: None,
            href: None,
            ins: vec![],
            outs: vec!["chats"],
            icons: Some(DEVICE_ICONS),
            rows: vec![(Tone::Dim, "phone, laptop, desktop".into())],
            x: COLS[0],
            y,
        });
        for (_, app) in &app_of {
            wires.push(wire("devices", 0, app, 0, "wire"));
        }
    }

    // ---- the tailnet band: coordination server and your devices on the
    // left, this hub's frame (blackthorn and its spaces), the machines on
    // the tailnet (or elsewhere) level with their spaces.
    let mut top = if providers.is_empty() {
        TOP + FRAME_TITLE
    } else {
        y_cloud
    };
    if tailnet {
        top += OUTER;
    }
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
    let mut tail_members: Vec<String> = Vec::new();
    // The computer you run blackthorn from: its web UI and SSH.
    // On the tailnet when the hub is on one, else on the LAN.
    let manage_on_lan = !tailnet && net.lan.is_some();
    nodes.push(Node {
        id: "manage".into(),
        kind: "devices",
        title: "Management device".into(),
        dot: None,
        href: None,
        ins: vec![],
        outs: vec!["web UI · SSH"],
        icons: Some(MANAGE_ICONS),
        rows: vec![
            admin,
            (Tone::Dim, format!("web UI {}", web_path(&hub.web_listen))),
        ],
        x: COLS[0],
        y: top,
    });
    if tailnet {
        tail_members.push("manage".into());
    }
    // Its way to the internet on the left, out of the way of the spaces.
    let hub_ins = if net.router.is_some() {
        vec!["admin", "internet"]
    } else {
        vec!["admin"]
    };
    nodes.push(Node {
        id: "hub".into(),
        kind: "hub",
        title: "blackthorn".into(),
        dot: None,
        href: None,
        ins: hub_ins,
        outs: vec!["runs"],
        icons: None,
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
    wires.push(wire("manage", 0, "hub", 0, "wire"));
    let mut hub_members = vec!["hub".to_string()];

    // Spaces of machines on the tailnet (or elsewhere) first, then those
    // of LAN machines, so the wires down to the LAN band are short.
    let lan_band = |h: &HostView| net_of(h) != Net::Tailnet && (tailnet || net_of(h) == Net::Lan);
    let mut order: Vec<&HostView> = o.hosts.iter().filter(|h| !lan_band(h)).collect();
    order.extend(o.hosts.iter().filter(|h| lan_band(h)));

    let mut sy = top;
    let mut hy = top;
    let mut lan_hosts: Vec<Node> = Vec::new();
    for h in order {
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
                Some(p) if p.app.is_some() && s.remote_control => "Remote Control",
                Some(p) if p.app.is_some() => "local only (no Remote Control)",
                _ => "terminal only",
            };
            let (ins, outs) = space_ports(s);
            let id = format!("space:{}", s.name);
            let login = if s.login.is_empty() {
                "no login yet".to_string()
            } else {
                s.login.clone()
            };
            let access = match (s.tier, s.root.as_ref().and_then(|r| r.until)) {
                (Tier::ReadOnly, _) => (Tone::Ok, format!("read-only as {login}")),
                (Tier::User, _) => (Tone::Dim, format!("user as {login}")),
                (Tier::Root, Some(u)) => (
                    Tone::Bad,
                    format!(
                        "root as {login} ({})",
                        crate::ops::describe_left(u, crate::state::now())
                    ),
                ),
                (Tier::Root, None) => (Tone::Bad, format!("root as {login}")),
            };
            let mut rows = vec![
                (Tone::Dim, format!("{} · {}", s.agent, s.state)),
                (access.0, clip(&access.1, 34)),
                (Tone::Dim, detail),
            ];
            if let Some(m) = &s.model {
                rows.push((Tone::Dim, clip(&format!("model: {m}"), 34)));
            }
            rows.push((Tone::Dim, reach.into()));
            let n = Node {
                id: id.clone(),
                kind: "space",
                title: clip(&s.name, 24),
                dot: Some(state_class(&s.state)),
                href: Some(format!("/space/{}", crate::webauth::url_encode(&s.name))),
                ins,
                outs,
                icons: None,
                rows,
                x: COLS[2],
                y: sy,
            };
            sy += n.h() + GAP_Y;
            wires.push(wire("hub", 0, &id, n.port_in("blackthorn"), "wire"));
            if let Some(p) = &p {
                if s.remote_control {
                    if let Some((_, app)) = app_of.iter().find(|(q, _)| *q == p.id) {
                        wires.push(wire(app, 0, &id, n.port_in("Remote Control"), "wire"));
                    }
                }
                if let Some((_, api)) = api_of.iter().find(|(q, _)| *q == p.id) {
                    // Uses the API: dotted, no arrow.
                    wires.push(Wire {
                        arrow: false,
                        ..wire(&id, n.port_out("API"), api, 0, "wire uses")
                    });
                }
            }
            let class = if h.blocked {
                "wire cut"
            } else if s.tier == Tier::ReadOnly {
                "wire ro"
            } else if s.tier == Tier::User {
                "wire user"
            } else {
                "wire admin"
            };
            wires.push(wire(
                &id,
                n.port_out("ssh"),
                &format!("host:{}", h.name),
                0,
                class,
            ));
            nodes.push(n);
            hub_members.push(id);
        }
        let node = host_node(h, spaces.len());
        if lan_band(h) {
            lan_hosts.push(node);
            continue;
        }
        let height = node.h();
        let centre = if spaces.is_empty() {
            hy
        } else {
            (first + sy - GAP_Y) / 2 - height / 2
        };
        let y = centre.max(hy);
        hy = y + height + GAP_Y;
        if tailnet && net_of(h) == Net::Tailnet {
            tail_members.push(node.id.clone());
        }
        nodes.push(Node { y, ..node });
    }
    for b in &o.bridges {
        let Some(from) = nodes.iter().find(|n| n.id == format!("space:{}", b.from)) else {
            continue;
        };
        let ssh = from.port_out("ssh");
        wires.push(Wire {
            label: Some(format!("bridge {}", b.remaining)),
            ..wire(
                &format!("space:{}", b.from),
                ssh,
                &format!("host:{}", b.host),
                0,
                "wire bridge",
            )
        });
    }

    // The management device halfway down the tailnet band.
    let band_bottom = nodes
        .iter()
        .filter(|n| n.y >= top - OUTER)
        .map(|n| n.y + n.h())
        .max()
        .unwrap_or(top)
        .max(top + 200);
    if let Some(d) = nodes
        .iter_mut()
        .find(|n| n.id == "manage" && !manage_on_lan)
    {
        d.y = ((top + band_bottom) / 2 - d.h() / 2).max(top);
    }
    tail_members.extend(hub_members.iter().cloned());
    frames.push(Frame {
        kind: "net",
        title: format!("tailnet · {}", net.control.clone().unwrap_or_default()),
        members: if tailnet { tail_members } else { Vec::new() },
        pad: OUTER,
    });
    frames.push(Frame {
        kind: "machine",
        title: format!("{} · this hub", clip(&hub.hostname, 30)),
        members: hub_members,
        pad: PAD,
    });

    // ---- the LAN band: the router (the hub's way to the internet) and the
    // machines on the LAN.
    let band_bottom = nodes
        .iter()
        .map(|n| n.y + n.h())
        .max()
        .unwrap_or(top)
        .max(top + 200);
    let mut ly = band_bottom + if tailnet { OUTER } else { PAD } + BAND_GAP + FRAME_TITLE + PAD;
    if net.router.is_some() || !lan_hosts.is_empty() || manage_on_lan {
        let mut lan_members = Vec::new();
        // On the LAN, the management device goes first; the router (in the
        // same column, its internet side toward the hub) below it.
        let mut router_y = ly;
        if manage_on_lan {
            if let Some(m) = nodes.iter_mut().find(|n| n.id == "manage") {
                m.y = ly;
                router_y = ly + m.h() + GAP_Y;
            }
            lan_members.push("manage".to_string());
        }
        if let Some(r) = net.router {
            nodes.push(Node {
                id: "router".into(),
                kind: "net",
                title: "Router".into(),
                dot: None,
                href: None,
                ins: vec![],
                outs: vec!["internet"],
                icons: None,
                rows: vec![
                    (Tone::Dim, format!("{r} · the hub's gateway")),
                    (Tone::Dim, "its way to the internet".into()),
                ],
                x: COLS[0],
                y: router_y,
            });
            lan_members.push("router".to_string());
            // Its internet side to the hub's: dotted, no arrow.
            wires.push(Wire {
                arrow: false,
                ..wire("router", 0, "hub", 1, "wire uses")
            });
        }
        for n in lan_hosts {
            let h = n.h();
            if is_lan_node(&n, o) {
                lan_members.push(n.id.clone());
            }
            nodes.push(Node { y: ly, ..n });
            ly += h + GAP_Y;
        }
        frames.push(Frame {
            kind: "lan",
            title: match &net.lan {
                Some(l) => format!("LAN · {l}"),
                None => "LAN".into(),
            },
            members: lan_members,
            pad: PAD,
        });
    }

    let bottom = nodes
        .iter()
        .map(|n| n.y + n.h())
        .max()
        .unwrap_or(0)
        .max(220);
    let width = COLS[3] + NW + 40;
    let height = bottom + OUTER + 40;

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
        let pad = f.pad;
        let x1 = ms.iter().map(|n| n.x).min().unwrap_or(0) - pad;
        let y1 = ms.iter().map(|n| n.y).min().unwrap_or(0) - pad - FRAME_TITLE;
        let x2 = ms.iter().map(|n| n.x + NW).max().unwrap_or(0) + pad;
        let y2 = ms.iter().map(|n| n.y + n.h()).max().unwrap_or(0) + pad;
        let _ = write!(
            out,
            "<g class=\"frame kind-{}\" data-pad=\"{pad}\" data-members=\"{}\"><rect class=\"frame-body\" x=\"{x1}\" y=\"{y1}\" \
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
        let x1 = if w.from_left { a.x } else { a.x + NW };
        let y1 = a.y + SLOT_Y + w.fp as i32 * SLOT_ROW;
        let (x2, y2) = (b.x, b.y + SLOT_Y + w.tp as i32 * SLOT_ROW);
        let marker = if w.arrow {
            "marker-end=\"url(#arrow)\""
        } else {
            ""
        };
        let ends = format!(
            "data-from=\"{}\" data-fp=\"{}\" data-to=\"{}\" data-tp=\"{}\"{}",
            esc(&w.from),
            w.fp,
            esc(&w.to),
            w.tp,
            if w.from_left { " data-fs=\"left\"" } else { "" }
        );
        let d = if w.from_left {
            wire_path_left(x1, y1, x2, y2)
        } else {
            wire_path(x1, y1, x2, y2)
        };
        let _ = write!(
            out,
            "<path class=\"{}\" {ends} {marker} d=\"{d}\"/>",
            w.class
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
        if let Some(icons) = n.icons {
            let _ = write!(
                out,
                "<g class=\"icons\" transform=\"translate(12,{})\">{icons}</g>",
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

/// LAN machines go in the LAN frame; other ones only sit in its band.
fn is_lan_node(n: &Node, o: &Overview) -> bool {
    o.hosts
        .iter()
        .find(|h| format!("host:{}", h.name) == n.id)
        .is_some_and(|h| net_of(h) == Net::Lan)
}

/// Phone, laptop and desktop, drawn in lines (20 px high).
const DEVICE_ICONS: &str = "<rect x=\"2\" y=\"1\" width=\"11\" height=\"18\" rx=\"2\"/><path d=\"M6 16h3\"/>\
    <g transform=\"translate(24,0)\"><rect x=\"3\" y=\"3\" width=\"18\" height=\"11\" rx=\"1.5\"/><path d=\"M0 17h24\"/></g>\
    <g transform=\"translate(56,0)\"><rect x=\"0\" y=\"1\" width=\"22\" height=\"14\" rx=\"1.5\"/><path d=\"M11 15v4M6 19h10\"/></g>";

/// A browser window and a terminal (20 px high).
const MANAGE_ICONS: &str = "<rect x=\"0\" y=\"1\" width=\"24\" height=\"17\" rx=\"2\"/><path d=\"M0 6h24\"/>\
    <circle cx=\"3.5\" cy=\"3.5\" r=\"0.6\"/><circle cx=\"6.5\" cy=\"3.5\" r=\"0.6\"/>\
    <g transform=\"translate(34,0)\"><rect x=\"0\" y=\"1\" width=\"24\" height=\"17\" rx=\"2\"/><path d=\"M5 7l4 3-4 3M11 14h7\"/></g>";

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
    use crate::ops::{BridgeView, HubView, NetView};
    use crate::state::{Mode, Os};

    fn overview() -> Overview {
        let host = |n: &str, ip: &str, blocked| HostView {
            name: n.into(),
            address: ip.parse().unwrap(),
            port: 22,
            user: "root".into(),
            os: Os::Linux,
            spaces: vec![],
            readonly: (n == "fig").then(|| "blackthorn".to_string()),
            blocked,
            status: if blocked {
                "BLOCKED".into()
            } else {
                "open".into()
            },
            setup: None,
            tiers: vec![],
            rootless_docker: false,
            logins: vec![],
            pending: vec![],
            problem: None,
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
            access: if n == "fig-claude" {
                crate::state::Access::Readonly
            } else {
                crate::state::Access::User
            },
            tier: if n == "fig-claude" {
                Tier::ReadOnly
            } else {
                Tier::Root
            },
            root: (n != "fig-claude").then_some(crate::state::Root {
                since: 0,
                until: None,
            }),
            login: if n == "fig-claude" {
                "blackthorn"
            } else {
                "root"
            }
            .into(),
            root_beside: vec![],
            srv: None,
            unattended: false,
            owner: None,
            shares: Vec::new(),
            level: None,
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
                web_listen: vec!["100.64.0.10:7180".into()],
                memory_available_mb: None,
                net: NetView {
                    control: Some("headscale.example.com".into()),
                    lan: Some("192.168.10.0/24".into()),
                    router: Some("192.168.10.1".parse().unwrap()),
                },
            },
            spaces: vec![
                space("fig-claude", "fig", "running"),
                space("fig-aider", "fig", "stopped"),
                space("nas-<x>", "nas", "needs login"),
            ],
            hosts: vec![
                host("fig", "100.80.0.3", false),
                host("nas", "192.168.10.5", true),
                host("pine", "100.80.0.9", false),
            ],
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
        assert_eq!(
            s.matches("class=\"node kind-devices\"").count(),
            2,
            "your devices and the management device"
        );
        assert_eq!(s.matches("class=\"node kind-app\"").count(), 1);
        assert_eq!(s.matches("class=\"node kind-api\"").count(), 1);
        assert_eq!(
            s.matches("class=\"node kind-net\"").count(),
            1,
            "the router"
        );
        assert!(!s.contains("Tailnet coordination"));
        // management device->hub, devices->app, hub->3 spaces, app->2 spaces
        // with Remote Control, 3 spaces->API, 3 spaces->their machines,
        // 1 bridge, router->hub.
        assert_eq!(s.matches("<path class=\"wire").count(), 15);
        // The router's internet side to the hub's, dotted, no arrow.
        assert!(s.contains(
            "class=\"wire uses\" data-from=\"router\" data-fp=\"0\" data-to=\"hub\" data-tp=\"1\"  d="
        ));
        // Arrows go the way commands go: the Claude app to a space.
        assert!(s.contains(
            "data-from=\"app:anthropic\" data-fp=\"0\" data-to=\"space:fig-claude\" data-tp=\"0\" marker-end"
        ));
        assert!(!s.contains("marker-start"));
        // Read-only and admin logins, a blocked machine, a bridge.
        assert!(s.contains(
            "class=\"wire ro\" data-from=\"space:fig-claude\" data-fp=\"1\" data-to=\"host:fig\""
        ));
        assert!(s.contains("class=\"wire admin\" data-from=\"space:fig-aider\""));
        assert!(s.contains(
            "class=\"wire cut\" data-from=\"space:nas-&lt;x&gt;\" data-fp=\"1\" data-to=\"host:nas\""
        ));
        assert!(s.contains(
            "class=\"wire bridge\" data-from=\"space:fig-claude\" data-fp=\"1\" data-to=\"host:nas\""
        ));
        assert!(s.contains("class=\"wire uses\" data-from=\"space:fig-claude\" data-fp=\"0\" data-to=\"api:anthropic\""));
        // No arrow into the API.
        assert!(s.contains("data-to=\"api:anthropic\" data-tp=\"0\"  d="));
        assert!(
            !s.contains("data-from=\"app:anthropic\" data-fp=\"0\" data-to=\"space:fig-aider\""),
            "Remote Control off: no wire from the app"
        );
        assert!(s.contains("read-only as blackthorn"));
        assert!(s.contains("root as root"));
        assert!(s.contains("read-only: blackthorn"));
        assert!(s.contains("bridge for 52m"));
        assert!(s.contains("no space yet"), "pine has none");
        assert!(s.contains("href=\"/space/fig-claude\""));
        assert!(s.contains("local only"), "fig-aider has Remote Control off");
        assert!(s.contains("admin from: anywhere"));
        assert!(s.contains("Opus 5.5: fig-claude"));
        assert!(s.contains("model: Opus 5.5"));
        // Frames: the cloud, the tailnet around this hub, the LAN.
        assert!(s.contains("class=\"frame kind-cloud\" data-pad=\"16\" data-members=\"app:anthropic api:anthropic\""));
        assert!(s.contains(
            "class=\"frame kind-machine\" data-pad=\"16\" data-members=\"hub space:fig-claude space:fig-aider space:nas-&lt;x&gt;\""
        ));
        assert!(s.contains(
            "class=\"frame kind-net\" data-pad=\"34\" data-members=\"manage host:fig host:pine hub space:fig-claude"
        ));
        assert!(
            s.contains("class=\"frame kind-lan\" data-pad=\"16\" data-members=\"router host:nas\"")
        );
        assert!(s.contains("tailnet · headscale.example.com"));
        assert!(s.contains("LAN · 192.168.10.0/24"));
        assert!(s.contains("Anthropic · cloud"));
        // Your devices reach the spaces only through the app, beside the
        // cloud and in no frame; the management device reaches the hub.
        assert!(s.contains("data-from=\"devices\" data-fp=\"0\" data-to=\"app:anthropic\""));
        assert!(!s.contains("data-from=\"devices\" data-fp=\"0\" data-to=\"hub\""));
        assert!(s.contains("data-from=\"manage\" data-fp=\"0\" data-to=\"hub\" data-tp=\"0\""));
        assert!(!s.contains("data-members=\"devices"));
        assert!(!s.contains(" devices "));
    }

    #[test]
    fn management_device_on_the_tailnet_else_the_lan() {
        // Reached over the LAN address, the hub is still on the tailnet.
        let mut o = overview();
        o.hub.web_listen = vec!["0.0.0.0:7180".into()];
        let s = svg(&o);
        assert!(s.contains("data-members=\"manage host:fig"));
        assert!(s.contains("data-members=\"router host:nas\""));
        // No tailnet: on the LAN.
        o.hub.net.control = None;
        let s = svg(&o);
        assert!(s.contains(
            "class=\"frame kind-lan\" data-pad=\"16\" data-members=\"manage router host:nas\""
        ));
    }

    #[test]
    fn networks_of_machines() {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        assert!(is_tailnet(&ip("100.80.0.3")));
        assert!(!is_tailnet(&ip("100.128.0.1")));
        assert!(is_tailnet(&ip("fd7a:115c:a1e0::5")));
        assert!(is_lan(&ip("192.168.10.5")));
        assert!(is_lan(&ip("10.0.0.2")));
        assert!(!is_lan(&ip("100.80.0.3")));
        assert!(!is_lan(&ip("fd7a:115c:a1e0::5")));
        assert!(is_lan(&ip("fd00::1")));
        assert!(!is_lan(&ip("8.8.8.8")));
    }

    #[test]
    fn without_networks_or_claude() {
        let mut o = overview();
        o.hub.net = NetView::default();
        for s in o.spaces.iter_mut() {
            s.agent = "aider".into();
        }
        let s = svg(&o);
        assert!(!s.contains("kind-cloud"));
        assert!(!s.contains("kind-app"));
        assert!(!s.contains("frame kind-net"));
        assert!(s.contains("terminal only"));
        // Without a tailnet the LAN machine still sits in the LAN frame.
        assert!(s.contains("class=\"frame kind-lan\" data-pad=\"16\" data-members=\"host:nas\""));
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
        assert_eq!(boxes.len(), 12);
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
