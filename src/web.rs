//! `thorn _web`: the web UI. Runs as the unprivileged blackthorn-web user,
//! renders pages, and forwards every request to the root API with the
//! browser's session token. It holds no secrets and can do nothing the API
//! does not allow a logged-in user to do.
//!
//! Pages are plain HTML forms (they work without JavaScript); a small script
//! refreshes the map and the terminal view. Strict CSP, no inline script or
//! style, no third-party anything.

use crate::api::{self, Op, Request, Response};
use crate::http;
use crate::map::{self, esc};
use crate::ops::{Action, BridgeView, HostView, NewSpace, Overview, Scan, SpaceView, SPECIAL_KEYS};
use crate::webauth::url_encode;
use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

const CSS: &str = include_str!("assets/app.css");
const JS: &str = include_str!("assets/app.js");
const COOKIE: &str = "bt_session";

pub fn serve() -> Result<()> {
    let cfg = api::call(&Request {
        token: None,
        csrf: None,
        client: None,
        op: Op::WebConfig,
    })?;
    let listen: Vec<SocketAddr> =
        serde_json::from_value(cfg.data.get("listen").cloned().unwrap_or_default())
            .context("reading the web config from the API")?;
    if listen.is_empty() {
        anyhow::bail!("web.listen is empty in /etc/blackthorn/config.toml");
    }
    let mut handles = Vec::new();
    for addr in listen {
        eprintln!("blackthorn web: listening on http://{addr}/");
        handles.push(std::thread::spawn(move || http::serve(addr, handle)));
    }
    for h in handles {
        match h.join() {
            Ok(Err(e)) => return Err(e),
            Err(_) => anyhow::bail!("listener thread panicked"),
            Ok(Ok(())) => {}
        }
    }
    Ok(())
}

// ------------------------------------------------------------- plumbing

struct Ctx {
    token: Option<String>,
    client: Option<IpAddr>,
    csrf: String,
    user: String,
}

enum Reply {
    Html(u16, String),
    Text(String),
    Svg(String),
    Asset(&'static str, &'static str),
    Redirect(String, Option<String>),
}

fn handle(req: http::Request) -> http::Response {
    let client = Some(req.remote);
    let method = if req.method == "HEAD" {
        "GET"
    } else {
        req.method.as_str()
    };
    let (path, query) = req.target.split_once('?').unwrap_or((&req.target, ""));
    let query = parse_form(query);
    let token = cookie(&req, COOKIE);
    let form = if method == "POST" {
        parse_form(&req.body)
    } else {
        HashMap::new()
    };

    let reply = route(method, path, &query, &form, token, client);
    let mut headers: Vec<(String, String)> = [
        ("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("X-Frame-Options", "DENY"),
        ("Cache-Control", "no-store"),
    ]
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    let mut add = |k: &str, v: &str| headers.push((k.to_string(), v.to_string()));
    let (status, body) = match reply {
        Reply::Html(code, html) => {
            add("Content-Type", "text/html; charset=utf-8");
            (code, html.into_bytes())
        }
        Reply::Text(t) => {
            add("Content-Type", "text/plain; charset=utf-8");
            (200, t.into_bytes())
        }
        Reply::Svg(s) => {
            add("Content-Type", "image/svg+xml");
            (200, s.into_bytes())
        }
        Reply::Asset(kind, body) => {
            add("Content-Type", kind);
            (200, body.as_bytes().to_vec())
        }
        Reply::Redirect(to, set_cookie) => {
            add("Location", &to);
            if let Some(c) = set_cookie {
                add("Set-Cookie", &c);
            }
            (303, Vec::new())
        }
    };
    http::Response {
        status,
        headers,
        body,
    }
}

fn cookie(req: &http::Request, name: &str) -> Option<String> {
    req.header("Cookie")
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
        .filter(|v| v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit()))
}

pub fn parse_form(s: &str) -> HashMap<String, String> {
    s.split('&')
        .filter(|kv| !kv.is_empty())
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            Some((url_decode(k)?, url_decode(v)?))
        })
        .collect()
}

fn url_decode(s: &str) -> Option<String> {
    let s = s.replace('+', " ");
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn call(c: &Ctx, op: Op) -> Result<Response> {
    api::call(&Request {
        token: c.token.clone(),
        csrf: Some(c.csrf.clone()),
        client: c.client,
        op,
    })
}

/// Calls the API and decodes the data, or returns its error message.
fn get<T: DeserializeOwned>(c: &Ctx, op: Op) -> std::result::Result<T, String> {
    match call(c, op) {
        Ok(r) if r.ok => serde_json::from_value(r.data).map_err(|e| e.to_string()),
        Ok(r) => Err(r.error.unwrap_or_else(|| "failed".into())),
        Err(e) => Err(format!("{e:#}")),
    }
}

fn back(to: &str, r: std::result::Result<String, String>) -> Reply {
    let sep = if to.contains('?') { '&' } else { '?' };
    match r {
        Ok(m) => Reply::Redirect(format!("{to}{sep}ok={}", url_encode(&m)), None),
        Err(e) => Reply::Redirect(format!("{to}{sep}err={}", url_encode(&e)), None),
    }
}

fn f<'a>(form: &'a HashMap<String, String>, k: &str) -> &'a str {
    form.get(k).map(|s| s.as_str()).unwrap_or("")
}

fn opt(form: &HashMap<String, String>, k: &str) -> Option<String> {
    let v = f(form, k).trim();
    (!v.is_empty()).then(|| v.to_string())
}

// ---------------------------------------------------------------- routes

fn route(
    method: &str,
    path: &str,
    query: &HashMap<String, String>,
    form: &HashMap<String, String>,
    token: Option<String>,
    client: Option<IpAddr>,
) -> Reply {
    match (method, path) {
        ("GET", "/static/app.css") => return Reply::Asset("text/css; charset=utf-8", CSS),
        ("GET", "/static/app.js") => return Reply::Asset("text/javascript; charset=utf-8", JS),
        ("GET", "/login") => return login_page(query.get("err").map(|s| s.as_str())),
        ("POST", "/login") => return login_post(form, client),
        _ => {}
    }

    // Everything else needs a session.
    let mut c = Ctx {
        token,
        client,
        csrf: String::new(),
        user: String::new(),
    };
    if c.token.is_none() {
        return Reply::Redirect("/login".into(), None);
    }
    match get::<serde_json::Value>(&c, Op::Whoami) {
        Ok(v) => {
            c.user = v["user"].as_str().unwrap_or("").to_string();
            c.csrf = v["csrf"].as_str().unwrap_or("").to_string();
        }
        Err(_) => return Reply::Redirect("/login".into(), Some(clear_cookie())),
    }
    if method == "POST" && !crate::webauth::same(f(form, "csrf"), &c.csrf) {
        return back("/", Err("stale form; reload the page and try again".into()));
    }
    let flash = Flash {
        ok: query.get("ok").cloned(),
        err: query.get("err").cloned(),
    };
    let seg: Vec<&str> = path.trim_matches('/').split('/').collect();
    let name = seg.get(1).and_then(|s| url_decode(s)).unwrap_or_default();

    match (method, seg.as_slice()) {
        ("GET", [""]) => map_page(&c, &flash),
        ("GET", ["map.svg"]) => match get::<Overview>(&c, Op::Overview) {
            Ok(o) => Reply::Svg(map::svg(&o)),
            Err(e) => Reply::Text(e),
        },
        ("POST", ["logout"]) => {
            let _ = call(&c, Op::Logout);
            Reply::Redirect("/login".into(), Some(clear_cookie()))
        }

        ("GET", ["spaces"]) => spaces_page(&c, &flash),
        ("POST", ["spaces"]) => {
            let space = NewSpace {
                host: f(form, "host").into(),
                agent: opt(form, "agent"),
                name: opt(form, "name"),
                single: f(form, "single") == "on",
                rc_name: opt(form, "rc_name"),
                args: f(form, "args")
                    .split_whitespace()
                    .map(String::from)
                    .collect(),
            };
            match get::<String>(&c, Op::SpaceNew { space }) {
                Ok(n) => back(
                    &format!("/space/{}", url_encode(&n)),
                    Ok(format!("created {n}")),
                ),
                Err(e) => back("/spaces", Err(e)),
            }
        }
        ("GET", ["space", _]) => space_page(&c, &name, &flash),
        ("GET", ["space", _, "screen"]) => {
            match get::<String>(&c, Op::SpaceScreen { name: name.clone() }) {
                Ok(s) => Reply::Text(s),
                Err(e) => Reply::Text(format!("({e})")),
            }
        }
        ("POST", ["space", _, action]) => space_post(&c, &name, action, form),

        ("GET", ["hosts"]) => hosts_page(&c, &flash),
        ("POST", ["hosts", "scan"]) => host_scan(&c, form),
        ("POST", ["hosts"]) => {
            let keys: Vec<String> = serde_json::from_str(f(form, "keys")).unwrap_or_default();
            let n = f(form, "name").to_string();
            match get::<String>(
                &c,
                Op::HostAdd {
                    name: n.clone(),
                    target: f(form, "target").into(),
                    port: f(form, "port").parse().unwrap_or(22),
                    keys,
                    code: f(form, "code").into(),
                },
            ) {
                Ok(_) => back(
                    &format!("/host/{}", url_encode(&n)),
                    Ok(format!(
                        "added {n}; install the key line below on it, then press Check"
                    )),
                ),
                Err(e) => back("/hosts", Err(e)),
            }
        }
        ("GET", ["host", _]) => host_page(&c, &name, &flash),
        ("POST", ["host", _, action]) => host_post(&c, &name, action, form),

        ("GET", ["bridges"]) => bridges_page(&c, &flash),
        ("POST", ["bridges"]) => {
            let from = f(form, "from").to_string();
            let r = get::<serde_json::Value>(
                &c,
                Op::BridgeAdd {
                    from: from.clone(),
                    to: f(form, "to").into(),
                    duration: opt(form, "duration"),
                    code: f(form, "code").into(),
                },
            );
            back(
                f(form, "back")
                    .strip_prefix('/')
                    .map_or("/bridges", |_| f(form, "back")),
                r.map(|_| format!("bridge up from {from}")),
            )
        }
        ("POST", ["bridges", "rm"]) => {
            let r = get::<serde_json::Value>(
                &c,
                Op::BridgeRm {
                    from: f(form, "from").into(),
                    to: f(form, "to").into(),
                },
            );
            back("/bridges", r.map(|_| "bridge removed".into()))
        }
        _ => Reply::Html(
            404,
            page(&c, "Not found", "<h1>Not found</h1>", &Flash::default()),
        ),
    }
}

fn clear_cookie() -> String {
    format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

#[derive(Default)]
struct Flash {
    ok: Option<String>,
    err: Option<String>,
}

// ---------------------------------------------------------------- pages

fn page(c: &Ctx, title: &str, body: &str, flash: &Flash) -> String {
    let mut fl = String::new();
    if let Some(m) = &flash.ok {
        fl.push_str(&format!("<p class=\"flash ok\">{}</p>", esc(m)));
    }
    if let Some(m) = &flash.err {
        fl.push_str(&format!("<pre class=\"flash err\">{}</pre>", esc(m)));
    }
    let nav = if c.user.is_empty() {
        String::new()
    } else {
        format!(
            "<nav><a href=\"/\">Map</a><a href=\"/spaces\">Spaces</a><a href=\"/hosts\">Machines</a>\
             <a href=\"/bridges\">Bridges</a></nav><form method=\"post\" action=\"/logout\" class=\"logout\">\
             {}<button class=\"link\">Log out {}</button></form>",
            csrf(c),
            esc(&c.user)
        )
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{} · blackthorn</title><link rel=\"stylesheet\" href=\"/static/app.css\">\
         <script src=\"/static/app.js\" defer></script></head><body>\
         <header class=\"top\"><a class=\"brand\" href=\"/\">blackthorn</a>{nav}</header>\
         <main>{fl}{body}</main></body></html>",
        esc(title)
    )
}

fn csrf(c: &Ctx) -> String {
    format!(
        "<input type=\"hidden\" name=\"csrf\" value=\"{}\">",
        esc(&c.csrf)
    )
}

fn code_field() -> &'static str {
    "<label>Authenticator code <input name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" \
     pattern=\"[0-9]{6}\" maxlength=\"6\" required class=\"code\"></label>"
}

fn button(c: &Ctx, action: &str, label: &str, class: &str, extra: &str) -> String {
    format!(
        "<form method=\"post\" action=\"{}\" class=\"inline\">{}{extra}<button class=\"{class}\">{}</button></form>",
        esc(action),
        csrf(c),
        esc(label)
    )
}

fn login_page(err: Option<&str>) -> Reply {
    let c = Ctx {
        token: None,
        client: None,
        csrf: String::new(),
        user: String::new(),
    };
    let body = "<section class=\"card narrow\"><h1>Log in</h1>\
        <form method=\"post\" action=\"/login\" class=\"stack\">\
        <label>Account <input name=\"user\" autocomplete=\"username\" required autofocus></label>\
        <label>Password <input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label>\
        <label>Authenticator code <input name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" required class=\"code\"></label>\
        <button class=\"primary\">Log in</button>\
        <p class=\"hint\">Lost your phone? A recovery code works in place of the authenticator code.</p>\
        <p class=\"hint\">No account yet? On the hub, run <code>sudo thorn web user add &lt;name&gt;</code>.</p>\
        </form></section>";
    let flash = Flash {
        ok: None,
        err: err.map(String::from),
    };
    Reply::Html(200, page(&c, "Log in", body, &flash))
}

fn login_post(form: &HashMap<String, String>, client: Option<IpAddr>) -> Reply {
    let r = api::call(&Request {
        token: None,
        csrf: None,
        client,
        op: Op::Login {
            user: f(form, "user").into(),
            password: f(form, "password").into(),
            code: f(form, "code").into(),
        },
    });
    match r {
        Ok(r) if r.ok => {
            let token = r.data["token"].as_str().unwrap_or("").to_string();
            Reply::Redirect(
                "/".into(),
                Some(format!(
                    "{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/"
                )),
            )
        }
        Ok(r) => Reply::Redirect(
            format!(
                "/login?err={}",
                url_encode(&r.error.unwrap_or_else(|| "failed".into()))
            ),
            None,
        ),
        Err(e) => Reply::Redirect(
            format!("/login?err={}", url_encode(&format!("{e:#}"))),
            None,
        ),
    }
}

fn overview_or_error(c: &Ctx, title: &str, flash: &Flash) -> std::result::Result<Overview, Reply> {
    get::<Overview>(c, Op::Overview).map_err(|e| {
        Reply::Html(
            500,
            page(
                c,
                title,
                &format!("<pre class=\"flash err\">{}</pre>", esc(&e)),
                flash,
            ),
        )
    })
}

fn map_page(c: &Ctx, flash: &Flash) -> Reply {
    let o = match overview_or_error(c, "Map", flash) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let hub = &o.hub;
    let mut b = String::new();
    b.push_str("<section class=\"strip\">");
    b.push_str(&chip(
        hub.firewall_loaded,
        "firewall",
        if hub.firewall_loaded {
            "on"
        } else {
            "NOT LOADED"
        },
    ));
    b.push_str(&chip(hub.timer == "active", "block timer", &hub.timer));
    b.push_str(&chip(
        hub.claude_version.is_some(),
        "claude",
        hub.claude_version.as_deref().unwrap_or("missing"),
    ));
    b.push_str(&chip(
        !hub.admin_from.is_empty(),
        "admin from",
        &if hub.admin_from.is_empty() {
            "anywhere".to_string()
        } else {
            hub.admin_from
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        },
    ));
    b.push_str(&chip(
        true,
        "refused inbound",
        &format!("{} address(es)", hub.denied_inbound.len()),
    ));
    if let Some(m) = hub.memory_available_mb {
        b.push_str(&chip(m > 300, "memory free", &format!("{m} MB")));
    }
    b.push_str("</section>");

    let attention: Vec<String> = o
        .spaces
        .iter()
        .filter(|s| s.state != "running" && s.state != "stopped")
        .map(|s| {
            format!(
                "<li><a href=\"/space/{}\">{}</a>: {}</li>",
                url_encode(&s.name),
                esc(&s.name),
                esc(&s.state)
            )
        })
        .chain(o.hosts.iter().filter(|h| h.blocked).map(|h| {
            format!(
                "<li><a href=\"/host/{}\">{}</a>: {}</li>",
                url_encode(&h.name),
                esc(&h.name),
                esc(&h.status)
            )
        }))
        .collect();
    if !attention.is_empty() {
        b.push_str(&format!(
            "<section class=\"card attention\"><h2>Needs attention</h2><ul>{}</ul></section>",
            attention.join("")
        ));
    }
    b.push_str(&format!(
        "<section class=\"card\"><div class=\"map-wrap\" id=\"map\" data-refresh=\"/map.svg\">{}</div>\
         <p class=\"legend\"><span class=\"dot ok\"></span>running <span class=\"dot warn\"></span>needs \
         login <span class=\"dot idle\"></span>stopped <span class=\"dot bad\"></span>failed \
         <span class=\"swatch bridge\"></span>bridge <span class=\"swatch cut\"></span>blocked</p></section>",
        map::svg(&o)
    ));
    Reply::Html(200, page(c, "Map", &b, flash))
}

fn chip(good: bool, label: &str, value: &str) -> String {
    format!(
        "<span class=\"chip {}\"><span class=\"k\">{}</span> {}</span>",
        if good { "good" } else { "bad" },
        esc(label),
        esc(value)
    )
}

fn space_row(c: &Ctx, s: &SpaceView) -> String {
    let n = url_encode(&s.name);
    let actions = if s.state == "needs login" {
        format!("<a class=\"btn\" href=\"/space/{n}#login\">Sign in</a>")
    } else {
        let mut a = String::new();
        if s.state != "running" {
            a.push_str(&button(c, &format!("/space/{n}/start"), "Start", "", ""));
        } else {
            a.push_str(&button(
                c,
                &format!("/space/{n}/restart"),
                "Restart",
                "",
                "",
            ));
            a.push_str(&button(c, &format!("/space/{n}/stop"), "Stop", "", ""));
        }
        a
    };
    format!(
        "<tr><td><span class=\"dot {}\"></span><a href=\"/space/{n}\">{}</a></td><td>{}</td><td>{}</td>\
         <td>{}</td><td>{}</td><td>{}</td><td class=\"actions\">{actions}</td></tr>",
        map::state_class(&s.state),
        esc(&s.name),
        esc(&s.host),
        esc(&crate::space_cmd::agent_label(&s.agent, s.mode)),
        esc(&s.state),
        esc(&s.rc_name),
        s.chats_24h.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
    )
}

fn spaces_page(c: &Ctx, flash: &Flash) -> Reply {
    let o = match overview_or_error(c, "Spaces", flash) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let mut b = String::from("<h1>Spaces</h1><p class=\"hint\">A space is one machine worked on by one AI agent: its own user, keys, firewall rules and chats.</p>");
    if o.spaces.is_empty() {
        b.push_str("<p>No spaces yet.</p>");
    } else {
        b.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Space</th><th>Machine</th><th>Agent</th><th>State</th><th>Remote Control</th><th>Chats today</th><th></th></tr></thead><tbody>");
        for s in &o.spaces {
            b.push_str(&space_row(c, s));
        }
        b.push_str("</tbody></table></div>");
    }
    if o.hosts.is_empty() {
        b.push_str("<p>Add a machine first, under <a href=\"/hosts\">Machines</a>.</p>");
    } else {
        let hosts: String = o
            .hosts
            .iter()
            .map(|h| format!("<option>{}</option>", esc(&h.name)))
            .collect();
        let agents: String = o
            .agents
            .iter()
            .map(|a| format!("<option>{}</option>", esc(a)))
            .collect();
        b.push_str(&format!(
            "<section class=\"card\"><h2>New space</h2><form method=\"post\" action=\"/spaces\" class=\"grid\">{}\
             <label>Machine <select name=\"host\">{hosts}</select></label>\
             <label>Agent <select name=\"agent\">{agents}</select></label>\
             <label>Name <input name=\"name\" placeholder=\"machine-agent\"></label>\
             <label>Remote Control name <input name=\"rc_name\" placeholder=\"same as name\"></label>\
             <label>Extra arguments <input name=\"args\" placeholder=\"--permission-mode acceptEdits\"></label>\
             <label class=\"check\"><input type=\"checkbox\" name=\"single\"> One conversation (also typed into on the terminal)</label>\
             <button class=\"primary\">Create</button></form></section>",
            csrf(c)
        ));
    }
    Reply::Html(200, page(c, "Spaces", &b, flash))
}

fn space_page(c: &Ctx, name: &str, flash: &Flash) -> Reply {
    let o = match overview_or_error(c, name, flash) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let Some(s) = o.spaces.iter().find(|s| s.name == name) else {
        return Reply::Html(404, page(c, name, "<h1>No such space</h1>", flash));
    };
    let n = url_encode(&s.name);
    let mut b = format!(
        "<h1><span class=\"dot {}\"></span>{}</h1><dl class=\"facts\"><dt>Machine</dt><dd><a href=\"/host/{}\">{}</a></dd>\
         <dt>Agent</dt><dd>{}</dd><dt>State</dt><dd>{}</dd><dt>Remote Control name</dt><dd>{}</dd>\
         <dt>Can reach now</dt><dd>{}</dd><dt>Memory</dt><dd>{}</dd></dl>",
        map::state_class(&s.state),
        esc(&s.name),
        url_encode(&s.host),
        esc(&s.host),
        esc(&crate::space_cmd::agent_label(&s.agent, s.mode)),
        esc(&s.state),
        esc(&s.rc_name),
        if s.reachable.is_empty() {
            "nothing (machine blocked?)".into()
        } else {
            esc(&s.reachable.join(", "))
        },
        s.memory_mb.map(|m| format!("{m} MB")).unwrap_or_else(|| "-".into()),
    );

    b.push_str("<section class=\"row\">");
    if s.state == "needs login" {
        b.push_str(&format!(
            "<section class=\"card\" id=\"login\"><h2>Sign in to Claude</h2><p>Each space signs in once. \
             Start, open the link on any device, then paste the code it shows.</p>{}</section>",
            button(c, &format!("/space/{n}/login"), "Start sign-in", "primary", "")
        ));
    } else {
        b.push_str("<section class=\"card\"><h2>Control</h2><div class=\"buttons\">");
        b.push_str(&button(c, &format!("/space/{n}/start"), "Start", "", ""));
        b.push_str(&button(
            c,
            &format!("/space/{n}/restart"),
            "Restart",
            "",
            "",
        ));
        b.push_str(&button(c, &format!("/space/{n}/stop"), "Stop", "", ""));
        if s.agent == "claude" {
            b.push_str(&button(
                c,
                &format!("/space/{n}/login"),
                "Sign in again",
                "",
                "",
            ));
        }
        b.push_str("</div></section>");
    }
    b.push_str("</section>");

    // Terminal.
    let keys: String = SPECIAL_KEYS
        .iter()
        .map(|k| {
            format!(
                "<form method=\"post\" action=\"/space/{n}/send\" class=\"inline send\">{}<input type=\"hidden\" name=\"key\" value=\"{k}\"><button>{k}</button></form>",
                csrf(c)
            )
        })
        .collect();
    b.push_str(&format!(
        "<section class=\"card\"><h2>Terminal</h2><p class=\"hint\">What the space's terminal shows, refreshed every \
         few seconds. Chats themselves are in the Claude app or claude.ai/code under <b>{}</b>.</p>\
         <pre class=\"screen\" id=\"screen\" data-src=\"/space/{n}/screen\">…</pre>\
         <form method=\"post\" action=\"/space/{n}/send\" class=\"send typing\">{}<input name=\"text\" \
         placeholder=\"type a line, Enter sends it\" autocomplete=\"off\"><button>Send</button></form>\
         <div class=\"buttons keys\">{keys}</div></section>",
        esc(&s.rc_name),
        csrf(c)
    ));

    // Bridges.
    let outgoing: Vec<&BridgeView> = o.bridges.iter().filter(|x| x.from == s.name).collect();
    let mut br = String::new();
    for x in &outgoing {
        br.push_str(&format!(
            "<li>→ {} (via {}) {} {}</li>",
            esc(&x.host),
            esc(&x.to),
            esc(&x.remaining),
            button(
                c,
                "/bridges/rm",
                "Remove",
                "link",
                &format!(
                    "<input type=\"hidden\" name=\"from\" value=\"{}\"><input type=\"hidden\" name=\"to\" value=\"{}\">",
                    esc(&x.from),
                    esc(&x.to)
                )
            )
        ));
    }
    let others: String = o
        .spaces
        .iter()
        .filter(|x| x.host != s.host)
        .map(|x| {
            format!(
                "<option value=\"{}\">{} ({})</option>",
                esc(&x.name),
                esc(&x.host),
                esc(&x.name)
            )
        })
        .collect();
    b.push_str(&format!(
        "<section class=\"card\"><h2>Bridges</h2><p class=\"hint\">A bridge lets this space's chats also reach \
         another space's machine for a while. While it lasts, both machines are one trust zone for this space.</p>\
         <ul>{}</ul>",
        if br.is_empty() { "<li>none</li>".into() } else { br }
    ));
    if !others.is_empty() {
        b.push_str(&format!(
            "<form method=\"post\" action=\"/bridges\" class=\"grid\">{}<input type=\"hidden\" name=\"from\" value=\"{}\">\
             <input type=\"hidden\" name=\"back\" value=\"/space/{n}\">\
             <label>Reach <select name=\"to\">{others}</select></label>{}{}<button>Open bridge</button></form>",
            csrf(c),
            esc(&s.name),
            duration_select(&["30m", "1h", "4h", "1d"], "1h", true),
            code_field()
        ));
    }
    b.push_str("</section>");

    // Rename, delete.
    b.push_str(&format!(
        "<section class=\"row\"><section class=\"card\"><h2>Rename</h2><form method=\"post\" action=\"/space/{n}/rename\" class=\"stack\">{}\
         <label>New name <input name=\"new\" required></label><label>Remote Control name \
         <input name=\"rc_name\" placeholder=\"follows the name\"></label><button>Rename</button></form></section>\
         <section class=\"card danger\"><h2>Delete</h2><p>Stops the space and removes its user. Its files and \
         conversations are archived on the hub unless you purge them.</p><form method=\"post\" action=\"/space/{n}/rm\" \
         class=\"stack\" data-confirm=\"Delete space {}?\">{}<label class=\"check\"><input type=\"checkbox\" name=\"purge\"> \
         Also delete its files</label>{}<button class=\"danger\">Delete space</button></form></section></section>",
        csrf(c),
        esc(&s.name),
        csrf(c),
        code_field()
    ));
    Reply::Html(200, page(c, &s.name, &b, flash))
}

fn duration_select(options: &[&str], default: &str, forever: bool) -> String {
    let mut o: String = options
        .iter()
        .map(|d| {
            format!(
                "<option{}>{d}</option>",
                if *d == default { " selected" } else { "" }
            )
        })
        .collect();
    if forever {
        o.push_str("<option value=\"forever\">until removed</option>");
    }
    format!("<label>For <select name=\"duration\">{o}</select></label>")
}

fn space_post(c: &Ctx, name: &str, action: &str, form: &HashMap<String, String>) -> Reply {
    let here = format!("/space/{}", url_encode(name));
    let control = |a: Action| {
        let r = get::<Vec<String>>(
            c,
            Op::SpaceControl {
                action: a,
                names: vec![name.to_string()],
            },
        );
        back(&here, r.map(|v| v.join("; ")))
    };
    match action {
        "start" => control(Action::Start),
        "stop" => control(Action::Stop),
        "restart" => control(Action::Restart),
        "send" => {
            let text = opt(form, "text").or_else(|| form.get("text").cloned().filter(|t| !t.is_empty()));
            let key = opt(form, "key");
            let r = get::<serde_json::Value>(
                c,
                Op::SpaceSend {
                    name: name.into(),
                    enter: text.is_some(),
                    text,
                    key,
                },
            );
            back(&here, r.map(|_| "sent".into()))
        }
        "login" => match get::<String>(c, Op::LoginStart { name: name.into() }) {
            Ok(url) => Reply::Html(
                200,
                page(
                    c,
                    "Sign in",
                    &format!(
                        "<section class=\"card narrow\"><h1>Sign in {}</h1><ol class=\"steps\">\
                         <li><a class=\"btn primary\" href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">Open the Claude sign-in page</a></li>\
                         <li>Sign in, then copy the code it shows.</li><li><form method=\"post\" \
                         action=\"/space/{}/login-finish\" class=\"stack\">{}<label>Code <input name=\"code\" required \
                         autocomplete=\"off\"></label><button class=\"primary\">Finish</button></form></li></ol>{}</section>",
                        esc(name),
                        esc(&url),
                        url_encode(name),
                        csrf(c),
                        button(c, &format!("/space/{}/login-cancel", url_encode(name)), "Cancel", "link", "")
                    ),
                    &Flash::default(),
                ),
            ),
            Err(e) => back(&here, Err(e)),
        },
        "login-finish" => {
            let r = get::<serde_json::Value>(
                c,
                Op::LoginFinish {
                    name: name.into(),
                    code: f(form, "code").into(),
                },
            );
            back(&here, r.map(|_| "signed in; the space is starting".into()))
        }
        "login-cancel" => {
            let r = get::<serde_json::Value>(c, Op::LoginCancel { name: name.into() });
            back(&here, r.map(|_| "sign-in cancelled".into()))
        }
        "rename" => {
            let new = f(form, "new").trim().to_string();
            match get::<bool>(
                c,
                Op::SpaceRename {
                    old: name.into(),
                    new: new.clone(),
                    rc_name: opt(form, "rc_name"),
                },
            ) {
                Ok(restarted) => back(
                    &format!("/space/{}", url_encode(&new)),
                    Ok(if restarted {
                        "renamed and restarted with the new Remote Control name".into()
                    } else {
                        "renamed".into()
                    }),
                ),
                Err(e) => back(&here, Err(e)),
            }
        }
        "rm" => {
            let r = get::<Option<String>>(
                c,
                Op::SpaceRm {
                    name: name.into(),
                    purge: f(form, "purge") == "on",
                    code: f(form, "code").into(),
                },
            );
            match r {
                Ok(Some(p)) => back("/spaces", Ok(format!("deleted {name}; files archived in {p}"))),
                Ok(None) => back("/spaces", Ok(format!("deleted {name}"))),
                Err(e) => back(&here, Err(e)),
            }
        }
        _ => back(&here, Err("unknown action".into())),
    }
}

fn hosts_page(c: &Ctx, flash: &Flash) -> Reply {
    let o = match overview_or_error(c, "Machines", flash) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let mut b = String::from("<h1>Machines</h1>");
    if o.hosts.is_empty() {
        b.push_str("<p>No machines yet.</p>");
    } else {
        b.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Machine</th><th>Address</th><th>User</th><th>OS</th><th>Spaces</th><th>Status</th></tr></thead><tbody>");
        for h in &o.hosts {
            b.push_str(&host_row(h));
        }
        b.push_str("</tbody></table></div>");
    }
    b.push_str(&format!(
        "<section class=\"card\"><h2>Add a machine</h2><p class=\"hint\">By IP address (its tailnet address works \
         well), Linux or macOS with an SSH server. You confirm its host key fingerprints next.</p>\
         <form method=\"post\" action=\"/hosts/scan\" class=\"grid\">{}<label>Name <input name=\"name\" required \
         placeholder=\"fig\"></label><label>Login <input name=\"target\" required placeholder=\"user@100.80.0.3\"></label>\
         <label>Port <input name=\"port\" value=\"22\" inputmode=\"numeric\"></label><button class=\"primary\">Read host keys</button></form></section>",
        csrf(c)
    ));
    Reply::Html(200, page(c, "Machines", &b, flash))
}

fn host_row(h: &HostView) -> String {
    format!(
        "<tr><td><a href=\"/host/{}\">{}</a></td><td>{}{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"{}\">{}</td></tr>",
        url_encode(&h.name),
        esc(&h.name),
        h.address,
        if h.port == 22 { String::new() } else { format!(":{}", h.port) },
        esc(&h.user),
        h.os,
        if h.spaces.is_empty() { "-".into() } else { esc(&h.spaces.join(", ")) },
        if h.blocked { "t-bad" } else { "" },
        esc(&h.status)
    )
}

fn host_scan(c: &Ctx, form: &HashMap<String, String>) -> Reply {
    let name = f(form, "name").trim().to_string();
    let target = f(form, "target").trim().to_string();
    let port: u16 = f(form, "port").trim().parse().unwrap_or(22);
    match get::<Scan>(
        c,
        Op::HostScan {
            target: target.clone(),
            port,
        },
    ) {
        Ok(scan) => {
            let fps: String = scan
                .fingerprints
                .iter()
                .map(|f| format!("<li><code>{}</code></li>", esc(f)))
                .collect();
            let b = format!(
                "<section class=\"card narrow\"><h1>Confirm {}</h1><p>{} presents these host keys:</p><ul>{fps}</ul>\
                 <p>Compare them with the output of this, run on the machine itself:</p>\
                 <pre>for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$f\"; done</pre>\
                 <form method=\"post\" action=\"/hosts\" class=\"stack\">{}\
                 <input type=\"hidden\" name=\"name\" value=\"{}\"><input type=\"hidden\" name=\"target\" value=\"{}\">\
                 <input type=\"hidden\" name=\"port\" value=\"{port}\"><input type=\"hidden\" name=\"keys\" value=\"{}\">\
                 {}<button class=\"primary\">They match: add {}</button></form><p><a href=\"/hosts\">They do not match</a></p></section>",
                esc(&name),
                esc(&format!("{}:{}", scan.address, scan.port)),
                csrf(c),
                esc(&name),
                esc(&target),
                esc(&serde_json::to_string(&scan.host_keys).unwrap_or_default()),
                code_field(),
                esc(&name)
            );
            Reply::Html(200, page(c, "Confirm host keys", &b, &Flash::default()))
        }
        Err(e) => back("/hosts", Err(e)),
    }
}

fn host_page(c: &Ctx, name: &str, flash: &Flash) -> Reply {
    let o = match overview_or_error(c, name, flash) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let Some(h) = o.hosts.iter().find(|h| h.name == name) else {
        return Reply::Html(404, page(c, name, "<h1>No such machine</h1>", flash));
    };
    let n = url_encode(&h.name);
    let line = get::<String>(c, Op::HostPubkey { name: name.into() }).unwrap_or_else(|e| e);
    let spaces: String = if h.spaces.is_empty() {
        "none. <a href=\"/spaces\">Create one</a>".to_string()
    } else {
        h.spaces
            .iter()
            .map(|s| format!("<a href=\"/space/{}\">{}</a>", url_encode(s), esc(s)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut b = format!(
        "<h1>{}</h1><dl class=\"facts\"><dt>Login</dt><dd>{}@{} port {}</dd><dt>OS</dt><dd>{}</dd>\
         <dt>Spaces</dt><dd>{spaces}</dd><dt>Status</dt><dd class=\"{}\">{}</dd></dl>",
        esc(&h.name),
        esc(&h.user),
        h.address,
        h.port,
        h.os,
        if h.blocked { "t-bad" } else { "" },
        esc(&h.status)
    );
    b.push_str(&format!(
        "<section class=\"card\"><h2>Key</h2><p>Put this line in <code>~{}/.ssh/authorized_keys</code> on {}:</p>\
         <pre class=\"wrap\">{}</pre><div class=\"buttons\">{}{}</div></section>",
        esc(&h.user),
        esc(&h.name),
        esc(&line),
        button(c, &format!("/host/{n}/check"), "Check login", "primary", ""),
        button(c, &format!("/host/{n}/rescan"), "Re-read host keys", "", "")
    ));
    b.push_str(&format!(
        "<section class=\"card\"><h2>Address</h2><p>Moved {} to another network, such as its tailnet \
         address? Its spaces stay.</p><form method=\"post\" action=\"/host/{n}/move-scan\" class=\"grid\">{}\
         <label>Login <input name=\"target\" value=\"{}\" required></label>\
         <label>Port <input name=\"port\" value=\"{}\" inputmode=\"numeric\"></label>\
         <button>Read its host keys</button></form></section>",
        esc(&h.name),
        csrf(c),
        esc(&format!("{}@{}", h.user, h.address)),
        h.port
    ));
    if h.blocked {
        b.push_str(&format!(
            "<section class=\"card\"><h2>Blocked</h2><p>No space can reach {} until you unblock it{}.</p>{}</section>",
            esc(&h.name),
            if h.status.contains(" for ") { " or the time runs out" } else { "" },
            button(c, &format!("/host/{n}/unblock"), "Unblock now", "primary", "")
        ));
    } else {
        b.push_str(&format!(
            "<section class=\"card\"><h2>Block</h2><p>Cut every space off from {} now, including open \
             connections.</p><form method=\"post\" action=\"/host/{n}/block\" class=\"grid\">{}{}<label>Reason \
             <input name=\"reason\" placeholder=\"optional\"></label><button class=\"danger\">Block</button></form></section>",
            esc(&h.name),
            csrf(c),
            duration_select(&["15m", "1h", "4h", "1d"], "1h", true).replace("value=\"forever\"", "value=\"\"")
        ));
    }
    b.push_str(&format!(
        "<section class=\"card danger\"><h2>Remove</h2><p>Forget {} and delete its key. Delete its spaces first.</p>\
         <form method=\"post\" action=\"/host/{n}/rm\" class=\"stack\" data-confirm=\"Remove machine {}?\">{}{}\
         <button class=\"danger\">Remove machine</button></form></section>",
        esc(&h.name),
        esc(&h.name),
        csrf(c),
        code_field()
    ));
    Reply::Html(200, page(c, &h.name, &b, flash))
}

fn host_post(c: &Ctx, name: &str, action: &str, form: &HashMap<String, String>) -> Reply {
    let here = format!("/host/{}", url_encode(name));
    match action {
        "check" => back(
            &here,
            get::<String>(c, Op::HostCheck { name: name.into() })
                .map(|os| format!("blackthorn can log in to {name} ({os})")),
        ),
        "block" => back(
            &here,
            get::<Option<u64>>(
                c,
                Op::HostBlock {
                    name: name.into(),
                    duration: opt(form, "duration"),
                    reason: opt(form, "reason"),
                },
            )
            .map(|u| match u {
                Some(u) => format!("blocked until {} UTC", crate::ops::rfc3339(u)),
                None => "blocked until you unblock it".into(),
            }),
        ),
        "unblock" => back(
            &here,
            get::<serde_json::Value>(c, Op::HostUnblock { name: name.into() })
                .map(|_| "unblocked".into()),
        ),
        "rescan" => match get::<(Scan, bool)>(c, Op::HostRescan { name: name.into() }) {
            Ok((_, false)) => back(&here, Ok("host keys unchanged".into())),
            Ok((scan, true)) => {
                let fps: String = scan
                    .fingerprints
                    .iter()
                    .map(|f| format!("<li><code>{}</code></li>", esc(f)))
                    .collect();
                let b = format!(
                    "<section class=\"card narrow danger\"><h1>{}'s host keys changed</h1><p>If you did not reinstall it \
                     or regenerate its keys, stop here.</p><ul>{fps}</ul><form method=\"post\" action=\"{here}/rescan-confirm\" \
                     class=\"stack\">{}<input type=\"hidden\" name=\"keys\" value=\"{}\">{}<button class=\"danger\">Save new keys</button>\
                     </form><p><a href=\"{here}\">Cancel</a></p></section>",
                    esc(name),
                    csrf(c),
                    esc(&serde_json::to_string(&scan.host_keys).unwrap_or_default()),
                    code_field()
                );
                Reply::Html(200, page(c, "Host keys changed", &b, &Flash::default()))
            }
            Err(e) => back(&here, Err(e)),
        },
        "rescan-confirm" => back(
            &here,
            get::<serde_json::Value>(
                c,
                Op::HostRescanConfirm {
                    name: name.into(),
                    keys: serde_json::from_str(f(form, "keys")).unwrap_or_default(),
                    code: f(form, "code").into(),
                },
            )
            .map(|_| "new host keys saved".into()),
        ),
        "move-scan" => {
            let target = f(form, "target").trim().to_string();
            let port: u16 = f(form, "port").trim().parse().unwrap_or(22);
            match get::<Scan>(
                c,
                Op::HostMoveScan {
                    name: name.into(),
                    target: target.clone(),
                    port,
                },
            ) {
                Ok(scan) => {
                    let fps: String = scan
                        .fingerprints
                        .iter()
                        .map(|f| format!("<li><code>{}</code></li>", esc(f)))
                        .collect();
                    let b = format!(
                        "<section class=\"card narrow\"><h1>Move {}</h1><p>{} presents these host keys:</p><ul>{fps}</ul>\
                         <p>Compare them with the output of this, run on the machine itself:</p>\
                         <pre>for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$f\"; done</pre>\
                         <form method=\"post\" action=\"{here}/move\" class=\"stack\">{}\
                         <input type=\"hidden\" name=\"target\" value=\"{}\">\
                         <input type=\"hidden\" name=\"port\" value=\"{port}\"><input type=\"hidden\" name=\"keys\" value=\"{}\">\
                         {}<button class=\"primary\">They match: move {}</button></form><p><a href=\"{here}\">Cancel</a></p></section>",
                        esc(name),
                        esc(&format!("{}:{}", scan.address, scan.port)),
                        csrf(c),
                        esc(&target),
                        esc(&serde_json::to_string(&scan.host_keys).unwrap_or_default()),
                        code_field(),
                        esc(name)
                    );
                    Reply::Html(200, page(c, "Confirm host keys", &b, &Flash::default()))
                }
                Err(e) => back(&here, Err(e)),
            }
        }
        "move" => back(
            &here,
            get::<String>(
                c,
                Op::HostMove {
                    name: name.into(),
                    target: f(form, "target").into(),
                    port: f(form, "port").parse().unwrap_or(22),
                    keys: serde_json::from_str(f(form, "keys")).unwrap_or_default(),
                    code: f(form, "code").into(),
                },
            )
            .map(|_| {
                "moved; replace its key line on the machine with the one below, then press Check"
                    .into()
            }),
        ),
        "rm" => match get::<serde_json::Value>(
            c,
            Op::HostRm {
                name: name.into(),
                code: f(form, "code").into(),
            },
        ) {
            Ok(_) => back(
                "/hosts",
                Ok(format!(
                    "removed {name}; delete its key line from its authorized_keys"
                )),
            ),
            Err(e) => back(&here, Err(e)),
        },
        _ => back(&here, Err("unknown action".into())),
    }
}

fn bridges_page(c: &Ctx, flash: &Flash) -> Reply {
    let o = match overview_or_error(c, "Bridges", flash) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let mut b = String::from(
        "<h1>Bridges</h1><p class=\"hint\">A bridge lets one space reach another space's machine for a while. It is \
         one-way: the other space gains nothing. While it lasts, the two machines are one trust zone for the \
         bridged space.</p>",
    );
    if o.bridges.is_empty() {
        b.push_str("<p>No bridges.</p>");
    } else {
        b.push_str("<div class=\"table-wrap\"><table><thead><tr><th>From</th><th>Reaches</th><th>Via</th><th>Lasts</th><th></th></tr></thead><tbody>");
        for x in &o.bridges {
            b.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&x.from),
                esc(&x.host),
                esc(&x.to),
                esc(&x.remaining),
                button(
                    c,
                    "/bridges/rm",
                    "Remove",
                    "",
                    &format!(
                        "<input type=\"hidden\" name=\"from\" value=\"{}\"><input type=\"hidden\" name=\"to\" value=\"{}\">",
                        esc(&x.from),
                        esc(&x.to)
                    )
                )
            ));
        }
        b.push_str("</tbody></table></div>");
    }
    if o.spaces.len() >= 2 {
        let opts: String = o
            .spaces
            .iter()
            .map(|s| {
                format!(
                    "<option value=\"{}\">{} ({})</option>",
                    esc(&s.name),
                    esc(&s.name),
                    esc(&s.host)
                )
            })
            .collect();
        b.push_str(&format!(
            "<section class=\"card\"><h2>Open a bridge</h2><form method=\"post\" action=\"/bridges\" class=\"grid\">{}\
             <label>Space <select name=\"from\">{opts}</select></label><label>May also reach the machine of \
             <select name=\"to\">{opts}</select></label>{}{}<button class=\"primary\">Open bridge</button></form></section>",
            csrf(c),
            duration_select(&["30m", "1h", "4h", "1d"], "1h", true),
            code_field()
        ));
    }
    Reply::Html(200, page(c, "Bridges", &b, flash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms() {
        let f = parse_form("a=1&b=hello+world&c=%E2%9C%93&d=&e");
        assert_eq!(f["a"], "1");
        assert_eq!(f["b"], "hello world");
        assert_eq!(f["c"], "✓");
        assert_eq!(f["d"], "");
        assert_eq!(f["e"], "");
        assert!(parse_form("x=%ZZ").is_empty());
        assert!(parse_form("x=%4").is_empty());
    }
}
