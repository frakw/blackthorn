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
use crate::notify::NotifyView;
use crate::ops::{
    self, Action, BridgeView, Chat, ConfigChange, HostView, NewSpace, Overview, Peer, Scan,
    Setting, SpaceView, SPECIAL_KEYS,
};
use crate::webauth::url_encode;
use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

const CSS: &str = include_str!("assets/app.css");
const JS: &str = include_str!("assets/app.js");
const COOKIE: &str = "bt_session";
/// Lets this browser type into chats (see Op::ChatUnlock).
const CHAT_COOKIE: &str = "bt_chat";

thread_local! {
    /// This request's User-Agent and chat-unlock token, sent along to the
    /// API with every call made for it.
    static META: std::cell::RefCell<(Option<String>, Option<String>)> =
        const { std::cell::RefCell::new((None, None)) };
}

/// A request to the API, with this browser's User-Agent and chat token.
fn request(token: Option<String>, csrf: Option<String>, client: Option<IpAddr>, op: Op) -> Request {
    let (agent, chat) = META.with(|m| m.borrow().clone());
    Request {
        token,
        csrf,
        client,
        agent,
        chat,
        op,
    }
}

/// What the API tells the web process at start: where to listen, and the
/// certificate for HTTPS.
fn web_config() -> Result<(Vec<SocketAddr>, Option<crate::tls::Material>)> {
    let cfg = api::call(&request(None, None, None, Op::WebConfig))?;
    if !cfg.ok {
        anyhow::bail!("{}", cfg.error.unwrap_or_default());
    }
    let listen: Vec<SocketAddr> =
        serde_json::from_value(cfg.data.get("listen").cloned().unwrap_or_default())
            .context("reading the web config from the API")?;
    let tls = serde_json::from_value(cfg.data.get("tls").cloned().unwrap_or_default())
        .context("reading the TLS settings from the API")?;
    Ok((listen, tls))
}

/// Served over HTTPS (so passkeys can be offered).
static HTTPS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn https() -> bool {
    HTTPS.get().copied().unwrap_or(false)
}

pub fn serve() -> Result<()> {
    let (listen, material) = web_config()?;
    let _ = HTTPS.set(material.is_some());
    if listen.is_empty() {
        anyhow::bail!("web.listen is empty in /etc/blackthorn/config.toml");
    }
    let tls: Option<http::Tls> = match &material {
        Some(m) => Some(std::sync::Arc::new(std::sync::RwLock::new(
            http::tls_config(&m.cert, &m.key)?,
        ))),
        None => None,
    };
    // A renewed certificate is picked up within ten minutes.
    if let (Some(tls), Some(mut current)) = (tls.clone(), material.clone()) {
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(600));
            let Ok((_, Some(m))) = web_config() else {
                continue;
            };
            if m == current {
                continue;
            }
            match http::tls_config(&m.cert, &m.key) {
                Ok(c) => {
                    *tls.write().expect("tls lock") = c;
                    eprintln!("blackthorn web: certificate renewed");
                    current = m;
                }
                Err(e) => eprintln!("blackthorn web: the new certificate is not usable: {e:#}"),
            }
        });
    }
    let mut handles = Vec::new();
    for addr in listen {
        match &material {
            Some(m) => eprintln!(
                "blackthorn web: listening on {addr} for https://{}:{}/",
                m.name,
                addr.port()
            ),
            None => eprintln!("blackthorn web: listening on http://{addr}/"),
        }
        let tls = tls.clone();
        handles.push(std::thread::spawn(move || http::serve(addr, tls, handle)));
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
    /// The page's path, to mark where you are in the menu.
    path: String,
    /// The account can step up with a passkey (on HTTPS).
    passkey: bool,
    /// This login's id (see Op::SessionList).
    session: String,
    /// This browser may type into chats.
    chat: bool,
}

enum Reply {
    Html(u16, String),
    Json(u16, String),
    Text(String),
    Svg(String),
    Asset(&'static str, &'static str),
    Redirect(String, Option<String>),
}

fn handle(req: http::Request) -> http::Response {
    let client = Some(req.remote);
    let secure = req.secure;
    let method = if req.method == "HEAD" {
        "GET"
    } else {
        req.method.as_str()
    };
    let (path, query) = req.target.split_once('?').unwrap_or((&req.target, ""));
    let query = parse_form(query);
    let token = cookie(&req, COOKIE);
    let agent = req.header("User-Agent").next().map(String::from);
    META.with(|m| *m.borrow_mut() = (agent, cookie(&req, CHAT_COOKIE)));
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
        Reply::Json(code, j) => {
            add("Content-Type", "application/json");
            (code, j.into_bytes())
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
            // Several cookies are separated by a newline.
            for c in set_cookie.iter().flat_map(|c| c.lines()) {
                // Over HTTPS the browser must never send it over plain HTTP.
                add(
                    "Set-Cookie",
                    &if secure {
                        format!("{c}; Secure")
                    } else {
                        c.to_string()
                    },
                );
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
    api::call(&request(
        c.token.clone(),
        Some(c.csrf.clone()),
        c.client,
        op,
    ))
}

/// Calls the API and decodes the data, or returns its error message.
fn get<T: DeserializeOwned>(c: &Ctx, op: Op) -> std::result::Result<T, String> {
    match call(c, op) {
        Ok(r) if r.ok => serde_json::from_value(r.data).map_err(|e| e.to_string()),
        Ok(r) => Err(r.error.unwrap_or_else(|| "failed".into())),
        Err(e) => Err(format!("{e:#}")),
    }
}

/// Back to a page with a message. The message goes in the query, before
/// any #anchor, or the server would never see it.
fn back(to: &str, r: std::result::Result<String, String>) -> Reply {
    let (path, anchor) = match to.split_once('#') {
        Some((p, a)) => (p, format!("#{a}")),
        None => (to, String::new()),
    };
    let sep = if path.contains('?') { '&' } else { '?' };
    let (k, m) = match r {
        Ok(m) => ("ok", m),
        Err(e) => ("err", e),
    };
    Reply::Redirect(format!("{path}{sep}{k}={}{anchor}", url_encode(&m)), None)
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
        ("GET", "/static/logo.svg") => return Reply::Asset("image/svg+xml", LOGO_FILE),
        ("GET", "/login") => return login_page(query.get("err").map(|s| s.as_str())),
        ("POST", "/login") => return login_post(form, client),
        ("POST", "/login/passkey") => return passkey_login_post(form, client),
        ("POST", "/passkey/begin") if f(form, "purpose") == "login" => {
            return passkey_begin(None, client, "login")
        }
        _ => {}
    }

    // Everything else needs a session.
    let mut c = Ctx {
        token,
        client,
        csrf: String::new(),
        user: String::new(),
        path: path.to_string(),
        passkey: false,
        session: String::new(),
        chat: false,
    };
    if c.token.is_none() {
        return Reply::Redirect("/login".into(), None);
    }
    match get::<serde_json::Value>(&c, Op::Whoami) {
        Ok(v) => {
            c.user = v["user"].as_str().unwrap_or("").to_string();
            c.csrf = v["csrf"].as_str().unwrap_or("").to_string();
            c.passkey = v["passkey"].as_bool().unwrap_or(false);
            c.session = v["session"].as_str().unwrap_or("").to_string();
            c.chat = v["chat"].as_bool().unwrap_or(false);
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
                local: f(form, "local") == "on",
                rc_name: opt(form, "rc_name"),
                args: f(form, "args")
                    .split_whitespace()
                    .map(String::from)
                    .collect(),
                access: match f(form, "access") {
                    "readonly" => Some(crate::state::Access::Readonly),
                    "admin" => Some(crate::state::Access::Admin),
                    _ => None,
                },
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

        ("GET", ["settings"]) => settings_page(&c, &flash),
        ("POST", ["settings"]) => settings_post(&c, form),
        ("POST", ["update"]) => match get::<String>(
            &c,
            Op::Update {
                code: f(form, "code").into(),
            },
        ) {
            Ok(tag) => updating_page(&c, &tag),
            Err(e) => back("/settings#update", Err(e)),
        },
        ("POST", ["tailscale", action]) => {
            let code = f(form, "code").to_string();
            let op = match *action {
                "install" => Op::TailscaleInstall { code },
                "up" => Op::TailscaleUp { code },
                "web-on" => Op::TailscaleWeb { on: true, code },
                "web-off" => Op::TailscaleWeb { on: false, code },
                _ => return back("/settings#tailscale", Err("unknown action".into())),
            };
            back("/settings#tailscale", get::<String>(&c, op))
        }
        ("POST", ["update", "check"]) => {
            let r = get::<ops::UpdateInfo>(&c, Op::UpdateCheck { refresh: true });
            back(
                "/settings#update",
                r.map(|u| match (u.error, u.newer, u.latest) {
                    (Some(e), _, _) => format!("could not check: {e}"),
                    (None, true, Some(t)) => format!("{t} is available"),
                    _ => "this is the latest release".into(),
                }),
            )
        }

        ("POST", ["notify"]) => {
            let token = form
                .get("token")
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty());
            let token = if f(form, "clear_token") == "on" {
                Some(String::new())
            } else {
                token
            };
            back(
                "/settings#notify",
                get::<NotifyView>(
                    &c,
                    Op::NotifySet {
                        url: f(form, "url").into(),
                        token,
                        code: f(form, "code").into(),
                    },
                )
                .map(|v| {
                    if v.url.is_empty() {
                        "notifications off".into()
                    } else {
                        "saved; press Send a test to check".into()
                    }
                }),
            )
        }
        ("POST", ["notify", "test"]) => back(
            "/settings#notify",
            get::<serde_json::Value>(&c, Op::NotifyTest)
                .map(|_| "test sent; it should be on your phone".into()),
        ),

        ("POST", ["passkey", "begin"]) => passkey_begin(Some(&c), client, f(form, "purpose")),

        ("GET", ["account"]) => account_page(&c, &flash),
        ("POST", ["account", action]) => account_post(&c, action, form),

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
            let to = f(form, "back");
            let local = to.starts_with('/') && !to.starts_with("//") && !to.contains('\\');
            back(
                if local { to } else { "/bridges" },
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

const MENU: &[(&str, &str)] = &[
    ("/", "Map"),
    ("/spaces", "Spaces"),
    ("/hosts", "Machines"),
    ("/bridges", "Bridges"),
    ("/settings", "Settings"),
];

/// Which menu entry a page belongs to.
fn section(path: &str) -> &'static str {
    match path.trim_start_matches('/').split('/').next().unwrap_or("") {
        "spaces" | "space" => "/spaces",
        "hosts" | "host" => "/hosts",
        "bridges" => "/bridges",
        "settings" | "update" => "/settings",
        "account" => "/account",
        _ => "/",
    }
}

fn page(c: &Ctx, title: &str, body: &str, flash: &Flash) -> String {
    page_with(c, title, body, flash, "")
}

/// `head`: extra tags for <head>, e.g. a refresh while an update runs.
fn page_with(c: &Ctx, title: &str, body: &str, flash: &Flash, head: &str) -> String {
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
        let here = section(&c.path);
        let links: String = MENU
            .iter()
            .map(|(href, label)| {
                format!(
                    "<a href=\"{href}\"{}>{label}</a>",
                    if *href == here {
                        " class=\"on\" aria-current=\"page\""
                    } else {
                        ""
                    }
                )
            })
            .collect();
        format!(
            "<nav class=\"menu\">{links}</nav><div class=\"me\"><a href=\"/account\"{}>{}</a>\
             <form method=\"post\" action=\"/logout\" class=\"inline\">{}<button class=\"link\">Log out</button></form></div>",
            if here == "/account" { " class=\"on\"" } else { "" },
            esc(&c.user),
            csrf(c)
        )
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{} · blackthorn</title><link rel=\"stylesheet\" href=\"/static/app.css\">\
         <link rel=\"icon\" href=\"/static/logo.svg\" type=\"image/svg+xml\">{head}\
         <script src=\"/static/app.js\" defer></script></head><body{}>\
         <header class=\"top\"><div class=\"bar\"><a class=\"brand\" href=\"/\">{LOGO}blackthorn</a>\
         <span class=\"version\" title=\"blackthorn version\">v{VERSION}</span></div>{nav}</header>\
         <main>{fl}{body}</main></body></html>",
        if c.passkey { " data-passkey=\"1\"" } else { "" },
        esc(title)
    )
}

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The logo inline (colored by the stylesheet), and as a file (favicon).
const LOGO: &str =
    "<svg class=\"logo\" viewBox=\"0 0 32 32\" width=\"22\" height=\"22\" aria-hidden=\"true\">\
    <path class=\"logo-branch\" d=\"M3.1 26.5 L5.5 28.9 L21.7 12.7 L28.8 3.2 L19.3 10.3 Z\"/>\
    <path class=\"logo-branch\" d=\"M13.4 21 L16.4 18 L23.4 21.4 Z\"/>\
    <path class=\"logo-branch\" d=\"M5 24.6 L7.4 22.2 L1.6 17.2 Z\"/>\
    <circle class=\"logo-berry\" cx=\"10.6\" cy=\"12.4\" r=\"6\"/></svg>";
const LOGO_FILE: &str = include_str!("../assets/logo.svg");

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

/// A Rename button that pops up a small form asking for the new name and
/// a code. Plain HTML (an open <details> drawn as a dialog; clicking the
/// dimmed backdrop closes it), so it works without the script too.
/// `field` is the form field the new name goes in; `hidden` adds fields;
/// `note` (HTML) goes under the name.
fn rename_dialog(
    c: &Ctx,
    action: &str,
    what: &str,
    field: &str,
    current: &str,
    hidden: &str,
    note: &str,
) -> String {
    format!(
        "<details class=\"pop\"><summary class=\"btn\">Rename</summary>\
         <form method=\"post\" action=\"{}\" class=\"stack pop-body\" role=\"dialog\" aria-label=\"Rename {}\">{}{hidden}\
         <h2>Rename {}</h2><label>New name <input name=\"{field}\" value=\"{}\" required maxlength=\"100\" \
         autocomplete=\"off\" spellcheck=\"false\"></label>{note}{}\
         <div class=\"buttons\"><button class=\"primary\">Save</button>\
         <button type=\"button\" class=\"link\" data-close hidden>Cancel</button></div></form></details>",
        esc(action),
        esc(what),
        csrf(c),
        esc(what),
        esc(current),
        code_field()
    )
}

/// A button that pops up a small form (like `rename_dialog`): `fields` go
/// inside, with the CSRF value; `summary_class` styles the button.
fn pop_dialog(
    c: &Ctx,
    action: &str,
    label: &str,
    summary_class: &str,
    title: &str,
    fields: &str,
    submit: &str,
) -> String {
    format!(
        "<details class=\"pop\"><summary class=\"btn {summary_class}\">{}</summary>\
         <form method=\"post\" action=\"{}\" class=\"stack pop-body\" role=\"dialog\" aria-label=\"{}\">{}\
         <h2>{}</h2>{fields}<div class=\"buttons\"><button class=\"primary\">{}</button>\
         <button type=\"button\" class=\"link\" data-close hidden>Cancel</button></div></form></details>",
        esc(label),
        esc(action),
        esc(title),
        csrf(c),
        esc(title),
        esc(submit)
    )
}

/// Text with a Copy button (the button appears only with the script).
fn copyable(id: &str, text: &str) -> String {
    format!(
        "<div class=\"copyable\"><pre class=\"wrap\" id=\"{id}\">{}</pre>\
         <button type=\"button\" class=\"copy\" data-copy=\"{id}\" hidden>Copy</button></div>",
        esc(text)
    )
}

fn ago(secs: u64) -> String {
    match secs {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86_399 => format!("{} h ago", secs / 3600),
        _ => format!("{} days ago", secs / 86_400),
    }
}

fn login_page(err: Option<&str>) -> Reply {
    let c = Ctx {
        token: None,
        client: None,
        csrf: String::new(),
        user: String::new(),
        path: "/login".into(),
        passkey: false,
        session: String::new(),
        chat: false,
    };
    let passkey = if https() {
        "<div class=\"passkey-login\" hidden><button type=\"button\" class=\"primary\" data-passkey-login>Log in with a passkey</button>\
         <p class=\"hint\">or with your password and authenticator code:</p></div>\
         <form method=\"post\" action=\"/login/passkey\" id=\"passkey-login\" hidden><input type=\"hidden\" name=\"answer\"></form>"
    } else {
        ""
    };
    let body = format!("<section class=\"card narrow\"><h1>Log in</h1>{passkey}\
        <form method=\"post\" action=\"/login\" class=\"stack\">\
        <label>Account <input name=\"user\" autocomplete=\"username\" required autofocus></label>\
        <label>Password <input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label>\
        <label>Authenticator code <input name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" required class=\"code\"></label>\
        <button class=\"primary\">Log in</button>\
        <p class=\"hint\">Lost your phone? A recovery code works in place of the authenticator code.</p>\
        <p class=\"hint\">No account yet? On the hub, run <code>sudo thorn web user add &lt;name&gt;</code>.</p>\
        </form></section>");
    let flash = Flash {
        ok: None,
        err: err.map(String::from),
    };
    Reply::Html(200, page(&c, "Log in", &body, &flash))
}

/// A WebAuthn challenge for the page's script, as JSON.
fn passkey_begin(c: Option<&Ctx>, client: Option<IpAddr>, purpose: &str) -> Reply {
    let r = api::call(&request(
        c.and_then(|c| c.token.clone()),
        c.map(|c| c.csrf.clone()),
        client,
        Op::PasskeyBegin {
            purpose: purpose.into(),
        },
    ));
    match r {
        Ok(r) if r.ok => Reply::Json(200, r.data.to_string()),
        Ok(r) => Reply::Json(
            400,
            serde_json::json!({ "error": r.error.unwrap_or_default() }).to_string(),
        ),
        Err(e) => Reply::Json(
            500,
            serde_json::json!({ "error": format!("{e:#}") }).to_string(),
        ),
    }
}

fn passkey_login_post(form: &HashMap<String, String>, client: Option<IpAddr>) -> Reply {
    let answer = match serde_json::from_str(f(form, "answer")) {
        Ok(a) => a,
        Err(_) => return Reply::Redirect("/login?err=no%20passkey%20answer".into(), None),
    };
    login_reply(api::call(&request(
        None,
        None,
        client,
        Op::PasskeyLogin { answer },
    )))
}

fn login_post(form: &HashMap<String, String>, client: Option<IpAddr>) -> Reply {
    login_reply(api::call(&request(
        None,
        None,
        client,
        Op::Login {
            user: f(form, "user").into(),
            password: f(form, "password").into(),
            code: f(form, "code").into(),
        },
    )))
}

fn login_reply(r: Result<Response>) -> Reply {
    match r {
        Ok(r) if r.ok => {
            let token = r.data["token"].as_str().unwrap_or("").to_string();
            let age = r.data["max_age"].as_u64().unwrap_or(24 * 3600);
            Reply::Redirect(
                "/".into(),
                Some(format!(
                    "{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={age}"
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

/// The hub's health: the checks that failed, or one line saying all passed.
fn health(o: &Overview) -> String {
    let hub = &o.hub;
    let mut bad: Vec<String> = Vec::new();
    if !hub.firewall_loaded {
        bad.push("the firewall is NOT loaded: run <code>sudo thorn apply</code>".into());
    }
    if hub.timer != "active" {
        bad.push(format!(
            "the block timer is {}: blocks and bridges will not expire",
            esc(&hub.timer)
        ));
    }
    if hub.claude_version.is_none() {
        bad.push(
            "Claude Code is not installed: <code>sudo thorn init --claude-from …</code>".into(),
        );
    }
    if hub.admin_from.is_empty() {
        bad.push(
            "admin from anywhere: anything that reaches the hub may try to log in. \
             <a href=\"/settings#inbound.admin_from\">List your devices</a>"
                .into(),
        );
    }
    if hub.memory_available_mb.is_some_and(|m| m <= 300) {
        bad.push(format!(
            "low memory: {} MB free",
            hub.memory_available_mb.unwrap_or(0)
        ));
    }
    let facts = format!(
        "<dl class=\"facts\"><dt>Firewall</dt><dd>{}</dd><dt>Block timer</dt><dd>{}</dd><dt>Claude Code</dt><dd>{}</dd>\
         <dt>Admin from</dt><dd>{}</dd><dt>Refused inbound</dt><dd>{} address(es)</dd><dt>Memory free</dt><dd>{}</dd></dl>",
        if hub.firewall_loaded { "on" } else { "NOT LOADED" },
        esc(&hub.timer),
        esc(hub.claude_version.as_deref().unwrap_or("missing")),
        if hub.admin_from.is_empty() {
            "anywhere".to_string()
        } else {
            esc(&hub.admin_from.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "))
        },
        hub.denied_inbound.len(),
        hub.memory_available_mb.map(|m| format!("{m} MB")).unwrap_or_else(|| "-".into()),
    );
    if bad.is_empty() {
        format!(
            "<details class=\"health ok\"><summary><span class=\"dot ok\"></span>All hub checks pass</summary>{facts}</details>"
        )
    } else {
        format!(
            "<details class=\"health bad\" open><summary><span class=\"dot bad\"></span>{} hub check(s) need you</summary>\
             <ul>{}</ul>{facts}</details>",
            bad.len(),
            bad.iter().map(|b| format!("<li>{b}</li>")).collect::<String>()
        )
    }
}

fn map_page(c: &Ctx, flash: &Flash) -> Reply {
    let o = match overview_or_error(c, "Map", flash) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let mut b = health(&o);

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
        "<section class=\"card graph-card\"><div class=\"graph-tools\" hidden>\
         <button type=\"button\" data-map=\"in\" title=\"Zoom in\">+</button>\
         <button type=\"button\" data-map=\"out\" title=\"Zoom out\">−</button>\
         <button type=\"button\" data-map=\"fit\">Fit</button>\
         <button type=\"button\" data-map=\"reset\" title=\"Put every box back where it started\">Reset layout</button>\
         <span class=\"hint\">Drag boxes to arrange them; drag the background to pan.</span></div>\
         <div class=\"graph-wrap\" id=\"map\" data-refresh=\"/map.svg\">{}</div>\
         <p class=\"legend\"><span class=\"dot ok\"></span>running <span class=\"dot warn\"></span>needs \
         login <span class=\"dot idle\"></span>stopped <span class=\"dot bad\"></span>failed \
         <span class=\"swatch ro\"></span>read-only login <span class=\"swatch admin\"></span>admin login \
         <span class=\"swatch bridge\"></span>bridge <span class=\"swatch cut\"></span>blocked (a machine you cut off) \
         <span class=\"swatch uses\"></span>a service it uses \
         <span>Arrows point the way commands go: from you, through the Claude app or the hub, to a space, to its \
         machine. Every connection is opened from the left end except Remote Control, which the space keeps open \
         out to the Claude app; machines never connect back to the hub. Frames are a company's cloud, this hub, \
         and your networks.</span></p></section>",
        map::svg(&o)
    ));
    Reply::Html(200, page(c, "Map", &b, flash))
}

fn reach_badge(s: &SpaceView) -> &'static str {
    if s.agent != crate::config::CLAUDE {
        "<span class=\"badge\">terminal</span>"
    } else if s.remote_control {
        "<span class=\"badge\">Remote Control</span>"
    } else {
        "<span class=\"badge local\">local only</span>"
    }
}

fn space_controls(c: &Ctx, s: &SpaceView) -> String {
    let n = url_encode(&s.name);
    if s.state == "needs login" {
        return format!("<a class=\"btn primary\" href=\"/space/{n}#login\">Sign in</a>");
    }
    if s.state == "running" {
        format!(
            "{}{}",
            button(c, &format!("/space/{n}/restart"), "Restart", "", ""),
            button(c, &format!("/space/{n}/stop"), "Stop", "", "")
        )
    } else if s.limited {
        start_for_dialog(c, s)
    } else {
        button(c, &format!("/space/{n}/start"), "Start", "primary", "")
    }
}

/// Starting an admin space on a machine with a read-only login: for how
/// long, with a code.
fn start_for_dialog(c: &Ctx, s: &SpaceView) -> String {
    pop_dialog(
        c,
        &format!("/space/{}/start-for", url_encode(&s.name)),
        "Start as admin…",
        "primary",
        &format!("Start {} as admin", s.name),
        &format!(
            "<p class=\"hint\">It logs in to {} as <b>{}</b>, which can change anything there. It stops by \
             itself when the time is up; only one admin space per machine runs at a time.</p>{}{}",
            esc(&s.host),
            esc(&s.login),
            duration_select(&["15m", "30m", "1h", "2h", "4h", "8h"], "1h", false),
            code_field()
        ),
        "Start",
    )
}

/// The space's access as a badge: read-only, admin, admin with time left.
fn access_badge(s: &SpaceView) -> String {
    match (s.access, s.until) {
        (crate::state::Access::Readonly, _) => "<span class=\"badge ro\">read-only</span>".into(),
        (_, Some(u)) if s.state == "running" => format!(
            "<span class=\"badge admin\">admin · {} left</span>",
            esc(&crate::ops::describe_left(u, crate::state::now()))
        ),
        _ => "<span class=\"badge admin\">admin</span>".into(),
    }
}

fn space_card(c: &Ctx, s: &SpaceView) -> String {
    let chats = s
        .chats_24h
        .map(|n| format!(" · {n} chat(s) today"))
        .unwrap_or_default();
    format!(
        "<article class=\"item\"><div class=\"item-head\"><span class=\"dot {}\"></span>\
         <a class=\"item-name\" href=\"/space/{}\">{}</a>{}{}</div>\
         <p class=\"item-meta\">on {} · {} · {}{chats}</p><div class=\"buttons\">{}</div></article>",
        map::state_class(&s.state),
        url_encode(&s.name),
        esc(&s.name),
        access_badge(s),
        reach_badge(s),
        esc(&s.host),
        esc(&crate::space_cmd::agent_label(&s.agent, s.mode)),
        esc(&s.state),
        space_controls(c, s)
    )
}

fn spaces_page(c: &Ctx, flash: &Flash) -> Reply {
    let o = match overview_or_error(c, "Spaces", flash) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let mut b = String::from(
        "<h1>Spaces</h1><p class=\"hint\">A space is one machine worked on by one AI agent: its own user, keys, \
         firewall rules and chats.</p>",
    );
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
            "<details class=\"card add\"{}><summary>+ New space</summary><form method=\"post\" action=\"/spaces\" class=\"stack\">{}\
             <div class=\"fields\"><label>Machine <select name=\"host\">{hosts}</select></label>\
             <label>Agent <select name=\"agent\">{agents}</select></label>\
             <label>Access <select name=\"access\"><option value=\"\">default: read-only if the machine has a read-only login</option>\
             <option value=\"readonly\">read-only</option><option value=\"admin\">admin (runs for a limited time where there is a read-only login)</option></select></label></div>\
             <details class=\"more\"><summary>More options</summary><div class=\"stack\">\
             <label>Name <input name=\"name\" placeholder=\"machine-agent\"></label>\
             <label>Claude: Remote Control name, as the Claude app lists it <input name=\"rc_name\" \
             placeholder=\"machine-space\" pattern=\"[A-Za-z0-9_\\-][A-Za-z0-9_.\\-]*\" maxlength=\"64\"></label>\
             <label>Extra arguments for the agent <input name=\"args\" placeholder=\"--permission-mode acceptEdits\"></label>\
             <label class=\"check\"><input type=\"checkbox\" name=\"single\"> Claude: one conversation, also typed into on the terminal</label>\
             <label class=\"check\"><input type=\"checkbox\" name=\"local\"> Claude: no Remote Control (only from this hub)</label>\
             </div></details><div><button class=\"primary\">Create space</button></div></form></details>",
            if o.spaces.is_empty() { " open" } else { "" },
            csrf(c)
        ));
    }
    if o.spaces.is_empty() {
        b.push_str("<p>No spaces yet.</p>");
    } else {
        b.push_str("<div class=\"items\">");
        for s in &o.spaces {
            b.push_str(&space_card(c, s));
        }
        b.push_str("</div>");
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
    let claude = s.agent == crate::config::CLAUDE;
    let mut b = format!(
        "<div class=\"page-head\"><h1><span class=\"dot {}\"></span>{}</h1><div class=\"buttons\">{}{}</div></div>\
         <p class=\"item-meta\">on <a href=\"/host/{}\">{}</a> as {} · {} · {}{} {}{}</p>",
        map::state_class(&s.state),
        esc(&s.name),
        space_controls(c, s),
        rename_dialog(c, &format!("/space/{n}/rename"), "space", "new", &s.name, "", ""),
        url_encode(&s.host),
        esc(&s.host),
        esc(&s.login),
        esc(&crate::space_cmd::agent_label(&s.agent, s.mode)),
        esc(&s.state),
        s.memory_mb.map(|m| format!(" · {m} MB")).unwrap_or_default(),
        access_badge(s),
        reach_badge(s),
    );
    if s.access == crate::state::Access::Admin && s.unattended {
        b.push_str(
            "<p class=\"flash err\">This admin space skips permission prompts (its arguments include auto or \
             bypass permission mode): its agent changes the machine without asking. Prefer a read-only space, \
             or drop those arguments.</p>",
        );
    }
    if s.reachable.is_empty() {
        b.push_str("<p class=\"t-bad\">It can reach no machine right now (blocked?).</p>");
    } else if s.reachable.len() > 1 {
        b.push_str(&format!(
            "<p class=\"hint\">Can reach now: {}</p>",
            esc(&s.reachable.join(", "))
        ));
    }

    if s.state == "needs login" {
        b.push_str(&format!(
            "<section class=\"card attention\" id=\"login\"><h2>Sign in to Claude</h2><p>Each space signs in once. \
             Start, open the link on any device, then paste the code it shows.</p>{}</section>",
            button(c, &format!("/space/{n}/login"), "Start sign-in", "primary", "")
        ));
    }

    if claude {
        b.push_str(&chats_card(c, s));
        b.push_str(&activity_card(c, s));
    }

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
    let where_chats = if !claude {
        "The agent runs here.".to_string()
    } else if s.remote_control {
        format!(
            "Chats themselves are in the Claude app or claude.ai/code under <b>{}</b>.",
            esc(&s.rc_name)
        )
    } else {
        "Remote Control is off: this is the only way in, besides <code>sudo thorn attach</code> on the hub.".to_string()
    };
    b.push_str(&format!(
        "<section class=\"card\"><h2>Terminal</h2><p class=\"hint\">What the space's terminal shows, refreshed every \
         few seconds. {where_chats}</p>\
         <pre class=\"screen\" id=\"screen\" data-src=\"/space/{n}/screen\">…</pre>\
         <form method=\"post\" action=\"/space/{n}/send\" class=\"send typing\">{}<input name=\"text\" \
         placeholder=\"type a line, Enter sends it\" autocomplete=\"off\"><button>Send</button></form>\
         <div class=\"buttons keys\">{keys}</div></section>",
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

    // Settings of the space.
    b.push_str("<section class=\"row\">");
    b.push_str(&access_card(
        c,
        s,
        o.hosts.iter().find(|h| h.name == s.host),
    ));
    if claude {
        let (text, label, on, class) = if s.remote_control {
            (
                format!(
                    "On: its chats are in the Claude app and on claude.ai/code under <b>{}</b>. Turned off, \
                     it becomes one conversation reached only from this hub.",
                    esc(&s.rc_name)
                ),
                "Turn Remote Control off",
                "off",
                "",
            )
        } else {
            (
                "Off: one conversation, reached only from this hub (the terminal above, or \
                 <code>sudo thorn attach</code>). It does not show in the Claude app."
                    .to_string(),
                "Turn Remote Control on",
                "on",
                "primary",
            )
        };
        let shown = if s.dir == s.rc_name {
            format!(
                "The Claude app lists it as <b>{}</b>, an environment named after its folder; \
                 each chat in it shows under the chat's own name. A new name makes a new \
                 environment: the old one stays in the app's list, offline, until Anthropic \
                 clears it (Claude Code has no way to remove it).",
                esc(&s.dir)
            )
        } else {
            format!(
                "The Claude app lists it as <b>{}</b> (its folder's name, from before v0.6). \
                 Give it a Remote Control name to change that.",
                esc(&s.dir)
            )
        };
        b.push_str(&format!(
            "<section class=\"card\"><h2>Remote Control</h2><p>{text}</p><p class=\"hint\">{shown}</p>\
             <div class=\"buttons\"><form method=\"post\" action=\"/space/{n}/remote\" class=\"inline\" data-confirm=\"{}? The space restarts.\">{}\
             <input type=\"hidden\" name=\"on\" value=\"{on}\"><button class=\"{class}\">{label}</button></form>{}</div></section>",
            esc(label),
            csrf(c),
            rename_dialog(c, &format!("/space/{n}/rc-name"), "in the Claude app", "rc_name", &s.rc_name, "", "")
        ));
    }
    b.push_str(&format!(
        "<section class=\"card danger\"><h2>Delete</h2><p>Stops the space and removes its user. Its files and \
         conversations are archived on the hub unless you purge them.</p><form method=\"post\" action=\"/space/{n}/rm\" \
         class=\"stack\" data-confirm=\"Delete space {}?\">{}<label class=\"check\"><input type=\"checkbox\" name=\"purge\"> \
         Also delete its files</label>{}<button class=\"danger\">Delete space</button></form></section></section>",
        esc(&s.name),
        csrf(c),
        code_field()
    ));
    Reply::Html(200, page(c, &s.name, &b, flash))
}

fn chats_card(c: &Ctx, s: &SpaceView) -> String {
    let n = url_encode(&s.name);
    let chats = match get::<Vec<Chat>>(
        c,
        Op::ChatList {
            name: s.name.clone(),
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            return format!(
                "<section class=\"card\"><h2>Chats</h2><p class=\"t-bad\">{}</p></section>",
                esc(&e)
            )
        }
    };
    // One conversation at a time (single mode, or Remote Control off): a
    // new chat, or an earlier one, replaces it. Otherwise chats are started
    // in the Claude app.
    let one = s.mode == crate::state::Mode::Single || !s.remote_control;
    let now = crate::state::now();
    let mut rows = String::new();
    for ch in &chats {
        let id = esc(&ch.id);
        let hidden = format!("<input type=\"hidden\" name=\"id\" value=\"{id}\">");
        let running = ch.running || ch.main || ch.window;
        let delete = format!(
            "<form method=\"post\" action=\"/space/{n}/chat-rm\" class=\"inline\" data-confirm=\"{}\">{}\
             {hidden}<button class=\"link danger-text\">Delete</button></form>",
            if ch.window {
                format!("Stop and delete the chat {}?", esc(&ch.title))
            } else {
                format!("Delete the chat {}?", esc(&ch.title))
            },
            csrf(c)
        );
        let side = if ch.window {
            // Started from the hub: stopped from here too.
            format!(
                "<span class=\"badge\">running now</span><form method=\"post\" action=\"/space/{n}/chat-stop\" \
                 class=\"inline\" data-confirm=\"Stop this chat? It leaves the Claude app; Continue brings it back.\">\
                 {}{hidden}<button class=\"link\">Stop</button></form>{delete}",
                csrf(c)
            )
        } else if running {
            let how = if ch.main {
                "the space runs this chat: start or continue another one to switch"
            } else {
                "running in the Claude app: end it there to delete it here"
            };
            format!("<span class=\"badge\" title=\"{how}\">running now</span>")
        } else {
            let confirm = if one {
                "Continue this chat? The space restarts into it."
            } else {
                "Continue this chat? It runs next to the others and shows in the Claude app."
            };
            format!(
                "<form method=\"post\" action=\"/space/{n}/chat-open\" class=\"inline\" \
                 data-confirm=\"{confirm}\">{}{hidden}<button class=\"link\">Continue</button></form>{delete}",
                csrf(c)
            )
        };
        rows.push_str(&format!(
            "<li class=\"chat\"><div class=\"chat-main\"><span class=\"chat-title\">{}</span>\
             <span class=\"item-meta\">{} · {} KB · <code>{}</code></span></div>\
             <div class=\"chat-actions\">{side}</div></li>",
            esc(&ch.title),
            ago(now.saturating_sub(ch.modified)),
            ch.kb,
            esc(&ch.id[..8.min(ch.id.len())]),
        ));
    }
    let (confirm, how) = if one {
        (
            "The space restarts into it; the current chat stays in the list.".to_string(),
            "This space runs one chat at a time: start a new one, or continue an earlier one, and the space restarts into it."
                .to_string(),
        )
    } else {
        (
            "It runs next to the others and shows in the Claude app.".to_string(),
            format!(
                "Chats started here run next to the ones from the Claude app, and show there too (under <b>{}</b>). \
                 They run until closed or the space stops.",
                esc(&s.rc_name)
            ),
        )
    };
    let new_chat = pop_dialog(
        c,
        &format!("/space/{n}/chat-new"),
        "+ New chat",
        "primary",
        "New chat",
        &format!(
            "<p class=\"hint\">{}</p><label>Name <input name=\"title\" maxlength=\"100\" autocomplete=\"off\" \
             placeholder=\"optional: Claude names it otherwise\" autofocus></label>\
             <p class=\"hint\">It is called by the start of its id and this name (<code>9cf982e0 name</code>), \
             here and in the Claude app. To rename it later, type <code>/rename NAME</code> in the chat.</p>",
            esc(&confirm)
        ),
        "Start chat",
    );
    format!(
        "<section class=\"card\" id=\"chats\"><div class=\"page-head\"><h2>Chats</h2>{new_chat}</div>\
         <p class=\"hint\">{how} Newest first, under Claude's name for each (rename one by typing \
         <code>/rename NAME</code> in it). Deleting removes the hub's copy; the Claude app may still list it.</p>{}</section>",
        if rows.is_empty() {
            "<p>No chats yet.</p>".to_string()
        } else {
            format!("<ul class=\"chats\">{rows}</ul>")
        }
    )
}

fn access_card(c: &Ctx, s: &SpaceView, h: Option<&HostView>) -> String {
    let n = url_encode(&s.name);
    let ro_login = h.and_then(|h| h.readonly.clone());
    let (text, change) = match s.access {
        crate::state::Access::Readonly => (
            format!(
                "<b>Read-only</b>: it logs in to {} as <b>{}</b>, which can read logs and run read-only Docker \
                 commands, and change nothing.",
                esc(&s.host),
                esc(&s.login)
            ),
            Some(("admin", "Make it admin…", "It will log in as the machine's admin login and can change anything. \
                   It stops now and then runs only when you start it, for a time.")),
        ),
        crate::state::Access::Admin => (
            format!(
                "<b>Admin</b>: it logs in to {} as <b>{}</b> and can change anything there.{}",
                esc(&s.host),
                esc(&s.login),
                if s.limited {
                    " Because the machine has a read-only login, it runs only when you start it, for a time, \
                     and never next to another admin space on the same machine."
                } else {
                    ""
                }
            ),
            ro_login.as_ref().map(|_| {
                ("readonly", "Make it read-only…", "It will log in as the machine's read-only login. A running \
                  space restarts; its chats stay.")
            }),
        ),
    };
    let action = match change {
        Some((to, label, why)) => pop_dialog(
            c,
            &format!("/space/{n}/access"),
            label,
            "",
            label.trim_end_matches('…'),
            &format!(
                "<p class=\"hint\">{why}</p><input type=\"hidden\" name=\"access\" value=\"{to}\">{}",
                code_field()
            ),
            "Change",
        ),
        None => format!(
            "<p class=\"hint\">For a read-only space, give {} a read-only login first, on <a href=\"/host/{}\">its page</a>.</p>",
            esc(&s.host),
            url_encode(&s.host)
        ),
    };
    format!("<section class=\"card\" id=\"access\"><h2>Access</h2><p>{text}</p>{action}</section>")
}

fn activity_card(c: &Ctx, s: &SpaceView) -> String {
    let entries = match get::<Vec<crate::activity::Entry>>(
        c,
        Op::Activity {
            name: s.name.clone(),
            limit: 30,
        },
    ) {
        Ok(v) => v,
        Err(e) => {
            return format!(
                "<section class=\"card\" id=\"activity\"><h2>Activity</h2><p class=\"t-bad\">{}</p></section>",
                esc(&e)
            )
        }
    };
    let now = crate::state::now();
    let rows: String = entries
        .iter()
        .map(|e| {
            if !e.note.is_empty() {
                return format!(
                    "<li class=\"act note\"><span class=\"item-meta\">{} · chat {}</span><span class=\"t-bad\">{}</span></li>",
                    ago(now.saturating_sub(e.t)),
                    esc(&e.chat),
                    esc(&e.note)
                );
            }
            format!(
                "<li class=\"act\"><span class=\"item-meta\">{} · chat <code>{}</code>{}</span><pre class=\"cmd\">{}</pre></li>",
                ago(now.saturating_sub(e.t)),
                esc(&e.chat),
                e.host()
                    .map(|h| format!(" · on <b>{}</b>", esc(h)))
                    .unwrap_or_default(),
                esc(&e.cmd)
            )
        })
        .collect();
    format!(
        "<section class=\"card\" id=\"activity\"><h2>Activity</h2><p class=\"hint\">The commands its chats ran, \
         newest first, copied every minute into a log on the hub that the space cannot change (all of it: \
         <code>sudo thorn log {}</code>). Machines with a read-only login also keep their own record: \
         <code>journalctl -t blackthorn</code> there.</p>{}</section>",
        esc(&s.name),
        if rows.is_empty() {
            "<p>Nothing yet.</p>".to_string()
        } else {
            format!("<ul class=\"acts\">{rows}</ul>")
        }
    )
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
                    rc_name: None,
                    code: f(form, "code").into(),
                },
            ) {
                Ok(restarted) => back(
                    &format!("/space/{}", url_encode(&new)),
                    Ok(if restarted {
                        "renamed and restarted with the new Remote Control name; the old one \
                         stays in the Claude app, offline"
                            .into()
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
        "remote" => {
            let on = f(form, "on") == "on";
            back(
                &here,
                get::<bool>(
                    c,
                    Op::SpaceRemote {
                        name: name.into(),
                        on,
                    },
                )
                .map(|restarted| {
                    format!(
                        "Remote Control {}{}",
                        if on { "on" } else { "off" },
                        if restarted { "; the space restarted" } else { "" }
                    )
                }),
            )
        }
        "rc-name" => back(
            &here,
            get::<bool>(
                c,
                Op::SpaceRename {
                    old: name.into(),
                    new: name.into(),
                    rc_name: Some(f(form, "rc_name").trim().to_string()),
                    code: f(form, "code").into(),
                },
            )
            .map(|restarted| {
                if restarted {
                    "Remote Control name changed; the space restarted under it. The old \
                     name stays in the Claude app, offline"
                        .into()
                } else {
                    "Remote Control name changed".into()
                }
            }),
        ),
        "chat-new" | "chat-open" => back(
            &format!("{here}#chats"),
            get::<ops::ChatOpened>(
                c,
                Op::ChatOpen {
                    name: name.into(),
                    id: (action == "chat-open").then(|| f(form, "id").to_string()),
                    title: (action == "chat-new").then(|| f(form, "title").to_string()),
                },
            )
            .map(|o| {
                let what = if action == "chat-new" { "new chat started" } else { "back in that chat" };
                if o.window {
                    format!("{what}; open it in the Claude app")
                } else if o.restarted {
                    format!("{what}; the space restarted into it")
                } else {
                    format!("{what}; it runs when the space starts")
                }
            }),
        ),
        "start-for" => back(
            &here,
            get::<Option<u64>>(
                c,
                Op::SpaceStartFor {
                    name: name.into(),
                    duration: f(form, "duration").into(),
                    code: f(form, "code").into(),
                },
            )
            .map(|u| match u {
                Some(u) => format!("started as admin until {} UTC", crate::ops::rfc3339(u)),
                None => "started".into(),
            }),
        ),
        "access" => back(
            &here,
            get::<String>(
                c,
                Op::SpaceAccess {
                    name: name.into(),
                    access: if f(form, "access") == "readonly" {
                        crate::state::Access::Readonly
                    } else {
                        crate::state::Access::Admin
                    },
                    code: f(form, "code").into(),
                },
            ),
        ),
        "chat-rm" => back(
            &format!("{here}#chats"),
            get::<String>(
                c,
                Op::ChatRm {
                    name: name.into(),
                    id: f(form, "id").into(),
                },
            )
            .map(|_| "chat deleted".into()),
        ),
        "chat-stop" => back(
            &format!("{here}#chats"),
            get::<String>(
                c,
                Op::ChatStop {
                    name: name.into(),
                    id: f(form, "id").into(),
                },
            )
            .map(|_| "chat stopped".into()),
        ),
        _ => back(&here, Err("unknown action".into())),
    }
}

fn hosts_page(c: &Ctx, flash: &Flash) -> Reply {
    let o = match overview_or_error(c, "Machines", flash) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let mut b = String::from("<h1>Machines</h1>");
    b.push_str(&format!(
        "<details class=\"card add\"{}><summary>+ Add a machine</summary><p class=\"hint\">Linux or macOS with an SSH server, by IP \
         address (its tailnet address works well). Next you check that blackthorn reached the right machine.</p>\
         <form method=\"post\" action=\"/hosts/scan\" class=\"stack\">{}<div class=\"fields\"><label>Name <input name=\"name\" required \
         placeholder=\"fig\"></label><label>Login <input name=\"target\" required placeholder=\"user@100.80.0.3\"></label>\
         <label class=\"narrow\">Port <input name=\"port\" value=\"22\" inputmode=\"numeric\"></label></div>\
         <div><button class=\"primary\">Next: check it is the right machine</button></div></form></details>",
        if o.hosts.is_empty() { " open" } else { "" },
        csrf(c)
    ));
    if o.hosts.is_empty() {
        b.push_str("<p>No machines yet.</p>");
    } else {
        b.push_str("<div class=\"items\">");
        for h in &o.hosts {
            b.push_str(&host_card(h));
        }
        b.push_str("</div>");
    }
    Reply::Html(200, page(c, "Machines", &b, flash))
}

fn host_card(h: &HostView) -> String {
    format!(
        "<article class=\"item\"><div class=\"item-head\"><span class=\"dot {}\"></span>\
         <a class=\"item-name\" href=\"/host/{}\">{}</a>{}</div>\
         <p class=\"item-meta\">{}@{}{} · {}</p><p class=\"item-meta\">spaces: {}</p><p class=\"{}\">{}</p></article>",
        if h.blocked { "bad" } else { "ok" },
        url_encode(&h.name),
        esc(&h.name),
        match &h.readonly {
            Some(u) => format!("<span class=\"badge ro\">read-only login: {}</span>", esc(u)),
            None => String::new(),
        },
        esc(&h.user),
        h.address,
        if h.port == 22 { String::new() } else { format!(":{}", h.port) },
        h.os,
        if h.spaces.is_empty() { "none".into() } else { esc(&h.spaces.join(", ")) },
        if h.blocked { "t-bad" } else { "item-meta" },
        esc(&h.status)
    )
}

const FINGERPRINT_CMD: &str =
    "for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$f\"; done";

/// "Is this really <name>?": the host key fingerprints, how to compare them,
/// and the form that accepts them.
fn keys_confirm(
    c: &Ctx,
    name: &str,
    scan: &Scan,
    action: &str,
    hidden: &str,
    accept: &str,
    cancel: &str,
) -> String {
    let fps: String = scan
        .fingerprints
        .iter()
        .map(|f| format!("<li><code>{}</code></li>", esc(f)))
        .collect();
    format!(
        "<section class=\"card narrow\"><h1>Is this really {name}?</h1>\
         <p>blackthorn reached <code>{addr}</code>. Every SSH server has its own <b>host keys</b>, like an ID card, \
         and these are the fingerprints of the ones it showed:</p><ul class=\"fingerprints\">{fps}</ul>\
         <p>If something else answered at that address (a typo, another machine, someone in between), they would \
         differ. Once you accept them, blackthorn refuses to talk to {name} if they ever change.</p>\
         <ol class=\"steps\"><li>On {name} itself, run this and compare its lines with the ones above:{cmd}</li>\
         <li><form method=\"post\" action=\"{action}\" class=\"stack\">{csrf}{hidden}\
         <input type=\"hidden\" name=\"keys\" value=\"{keys}\">{code}<button class=\"primary\">They match: {accept}</button></form></li></ol>\
         <p><a href=\"{cancel}\">They do not match: stop here</a></p></section>",
        name = esc(name),
        addr = esc(&format!("{}:{}", scan.address, scan.port)),
        cmd = copyable("fpcmd", FINGERPRINT_CMD),
        action = esc(action),
        csrf = csrf(c),
        keys = esc(&serde_json::to_string(&scan.host_keys).unwrap_or_default()),
        code = code_field(),
        accept = esc(accept),
        cancel = esc(cancel),
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
            let hidden = format!(
                "<input type=\"hidden\" name=\"name\" value=\"{}\"><input type=\"hidden\" name=\"target\" value=\"{}\">\
                 <input type=\"hidden\" name=\"port\" value=\"{port}\">",
                esc(&name),
                esc(&target)
            );
            let b = keys_confirm(
                c,
                &name,
                &scan,
                "/hosts",
                &hidden,
                &format!("add {name}"),
                "/hosts",
            );
            Reply::Html(200, page(c, "Check the machine", &b, &Flash::default()))
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
        "<div class=\"page-head\"><h1><span class=\"dot {}\"></span>{}</h1><div class=\"buttons\">{}</div></div>\
         <p class=\"item-meta\">{}@{} port {} · {} · spaces: {spaces}</p><p class=\"{}\">{}</p>",
        if h.blocked { "bad" } else { "ok" },
        esc(&h.name),
        rename_dialog(c, &format!("/host/{n}/rename"), "machine", "new", &h.name, "", ""),
        esc(&h.user),
        h.address,
        h.port,
        h.os,
        if h.blocked { "t-bad" } else { "hint" },
        esc(&h.status)
    );
    let install = format!(
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '{}' >> ~/.ssh/authorized_keys",
        line.replace('\'', "")
    );
    b.push_str(&format!(
        "<section class=\"card\"><h2>Key</h2><p>blackthorn logs in to {} with its own key. Put this line in \
         <code>~{}/.ssh/authorized_keys</code> there:</p>{}\
         <p class=\"hint\">Or run this on {} as {}:</p>{}<div class=\"buttons\">{}{}</div></section>",
        esc(&h.name),
        esc(&h.user),
        copyable("keyline", &line),
        esc(&h.name),
        esc(&h.user),
        copyable("keycmd", &install),
        button(c, &format!("/host/{n}/check"), "Check login", "primary", ""),
        button(c, &format!("/host/{n}/rescan"), "Check its host keys again", "", "")
    ));
    b.push_str(&readonly_card(c, h));
    b.push_str("<section class=\"row\">");
    b.push_str(&format!(
        "<section class=\"card\"><h2>Address</h2><p>Moved {} to another network, such as its tailnet \
         address? Its spaces stay.</p><form method=\"post\" action=\"/host/{n}/move-scan\" class=\"stack\">{}\
         <div class=\"fields\"><label>Login <input name=\"target\" value=\"{}\" required></label>\
         <label class=\"narrow\">Port <input name=\"port\" value=\"{}\" inputmode=\"numeric\"></label></div>\
         <div><button>Next: check it is the right machine</button></div></form></section>",
        esc(&h.name),
        csrf(c),
        esc(&format!("{}@{}", h.user, h.address)),
        h.port
    ));
    if h.blocked {
        b.push_str(&format!(
            "<section class=\"card attention\"><h2>Blocked</h2><p>No space can reach {} until you unblock it{}.</p>{}</section>",
            esc(&h.name),
            if h.status.contains(" for ") { " or the time runs out" } else { "" },
            button(c, &format!("/host/{n}/unblock"), "Unblock now", "primary", "")
        ));
    } else {
        b.push_str(&format!(
            "<section class=\"card\"><h2>Block</h2><p>Cut every space off from {} now, including open \
             connections.</p><form method=\"post\" action=\"/host/{n}/block\" class=\"stack\">{}<div class=\"fields\">{}<label>Reason \
             <input name=\"reason\" placeholder=\"optional\"></label></div><div><button class=\"danger\">Block</button></div></form></section>",
            esc(&h.name),
            csrf(c),
            duration_select(&["15m", "1h", "4h", "1d"], "1h", true).replace("value=\"forever\"", "value=\"\"")
        ));
    }
    b.push_str(&format!(
        "<section class=\"card danger\"><h2>Remove</h2><p>Forget {} and delete its key. Delete its spaces first.</p>\
         <form method=\"post\" action=\"/host/{n}/rm\" class=\"stack\" data-confirm=\"Remove machine {}?\">{}{}\
         <button class=\"danger\">Remove machine</button></form></section></section>",
        esc(&h.name),
        esc(&h.name),
        csrf(c),
        code_field()
    ));
    Reply::Html(200, page(c, &h.name, &b, flash))
}

fn readonly_card(c: &Ctx, h: &HostView) -> String {
    let n = url_encode(&h.name);
    let user = h.readonly.clone().unwrap_or_else(|| "blackthorn".into());
    let setup = pop_dialog(
        c,
        &format!("/host/{n}/readonly"),
        if h.readonly.is_some() { "Set it up again…" } else { "Set up a read-only login…" },
        if h.readonly.is_some() { "" } else { "primary" },
        "Read-only login",
        &format!(
            "<p class=\"hint\">blackthorn logs in to {} as <b>{}</b> and: creates the user below (groups \
             <code>adm</code> and <code>systemd-journal</code>, home owned by root), gives it a key of its own and \
             sudo for read-only Docker commands only (installing sudo if missing), and makes both its keys log every \
             command to the system log. Linux only. Or run it yourself: <code>sudo thorn host readonly {} --print</code>.</p>\
             <label>User <input name=\"user\" value=\"{}\" required maxlength=\"32\" autocomplete=\"off\"></label>{}",
            esc(&h.name),
            esc(&h.user),
            esc(&h.name),
            esc(&user),
            code_field()
        ),
        "Set up",
    );
    let text = match &h.readonly {
        Some(u) => format!(
            "<p>Spaces can log in as <b>{}</b>: they read logs and run <code>docker ps</code>, <code>logs</code>, \
             <code>stats</code>, <code>images</code>, <code>top</code> and <code>system df</code>, and change nothing. \
             New spaces here are read-only; admin spaces run only when started, for a time, one at a time.</p>\
             <p class=\"hint\">Every command blackthorn's keys run here is in its system log: \
             <code>journalctl -t blackthorn</code>. Set it up again after giving the machine a new address.</p>",
            esc(u)
        ),
        None => format!(
            "<p>Every space here logs in as <b>{}</b>, so its agent can change anything. A read-only login lets \
             most spaces only look, and keeps admin access for when you need it, for a limited time.</p>",
            esc(&h.user)
        ),
    };
    format!(
        "<section class=\"card\" id=\"readonly\"><h2>Read-only login</h2>{text}{setup}</section>"
    )
}

fn host_post(c: &Ctx, name: &str, action: &str, form: &HashMap<String, String>) -> Reply {
    let here = format!("/host/{}", url_encode(name));
    match action {
        "readonly" => back(
            &here,
            get::<ops::ReadonlyDone>(
                c,
                Op::HostReadonly {
                    name: name.into(),
                    user: f(form, "user").into(),
                    code: f(form, "code").into(),
                },
            )
            .map(|d| {
                let mut m = format!("{name} has a read-only login: {}", d.user);
                if !d.report.is_empty() {
                    m.push_str(&format!(" ({})", d.report.join("; ")));
                }
                if !d.limited.is_empty() {
                    m.push_str(&format!(
                        ". Admin spaces here ({}) now run only when started, for a time",
                        d.limited.join(", ")
                    ));
                }
                m
            }),
        ),
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
                let b = format!(
                    "<p class=\"flash err\">{}'s host keys changed. If you did not reinstall it or regenerate \
                     its keys, stop here.</p>{}",
                    esc(name),
                    keys_confirm(
                        c,
                        name,
                        &scan,
                        &format!("{here}/rescan-confirm"),
                        "",
                        "save the new keys",
                        &here
                    )
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
                    let hidden = format!(
                        "<input type=\"hidden\" name=\"target\" value=\"{}\">\
                         <input type=\"hidden\" name=\"port\" value=\"{port}\">",
                        esc(&target)
                    );
                    let b = keys_confirm(
                        c,
                        name,
                        &scan,
                        &format!("{here}/move"),
                        &hidden,
                        &format!("move {name}"),
                        &here,
                    );
                    Reply::Html(200, page(c, "Check the machine", &b, &Flash::default()))
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
        "rename" => {
            let new = f(form, "new").trim().to_string();
            match get::<serde_json::Value>(
                c,
                Op::HostRename {
                    old: name.into(),
                    new: new.clone(),
                    code: f(form, "code").into(),
                },
            ) {
                Ok(_) => back(
                    &format!("/host/{}", url_encode(&new)),
                    Ok(format!("renamed; its spaces now reach it as ssh {new}")),
                ),
                Err(e) => back(&here, Err(e)),
            }
        }
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

/// Which settings are lists of addresses, and of what kind.
fn list_kind(key: &str) -> Option<&'static str> {
    match key {
        "inbound.admin_from" | "never_manage" | "inbound.deny_from" | "ssh_from" => Some("ip"),
        "web.listen" => Some("socket"),
        _ => None,
    }
}

fn update_card(c: &Ctx) -> String {
    let u = match get::<ops::UpdateInfo>(c, Op::UpdateCheck { refresh: false }) {
        Ok(u) => u,
        Err(e) => ops::UpdateInfo {
            current: VERSION.into(),
            error: Some(e),
            ..Default::default()
        },
    };
    let check_again = button(c, "/update/check", "Check again", "link", "");
    let body = if u.running {
        "<p>An update is running right now; this page comes back in a minute.</p>".to_string()
    } else if let Some(e) = &u.error {
        format!(
            "<p>This hub runs <b>v{}</b>. Could not check for a newer release: {} {check_again}</p>",
            esc(&u.current),
            esc(e)
        )
    } else if u.newer {
        format!(
            "<p>This hub runs <b>v{}</b>; <b>{}</b> is out. <a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">What is new</a></p>\
             <p class=\"hint\">Updating downloads the release's installer from GitHub, checks the new <code>thorn</code> \
             against the release's checksums, and restarts the web UI. Settings, accounts and spaces stay; running \
             chats are not interrupted.</p>\
             <form method=\"post\" action=\"/update\" class=\"stack\">{}{}<div><button class=\"primary\">Update to {}</button></div></form>",
            esc(&u.current),
            esc(u.latest.as_deref().unwrap_or("")),
            esc(u.url.as_deref().unwrap_or(ops::RELEASES)),
            csrf(c),
            code_field(),
            esc(u.latest.as_deref().unwrap_or("")),
        )
    } else {
        format!(
            "<p>This hub runs <b>v{}</b>, the latest release. {check_again}</p>",
            esc(&u.current)
        )
    };
    format!("<section class=\"card\" id=\"update\"><h2>blackthorn version</h2>{body}</section>")
}

fn settings_page(c: &Ctx, flash: &Flash) -> Reply {
    let settings = match get::<Vec<Setting>>(c, Op::ConfigShow) {
        Ok(s) => s,
        Err(e) => {
            return Reply::Html(
                500,
                page(c, "Settings", &format!("<pre>{}</pre>", esc(&e)), flash),
            )
        }
    };
    let peers = get::<Vec<Peer>>(c, Op::TailnetPeers).unwrap_or_default();
    let mut fields = String::new();
    for s in &settings {
        let key = esc(&s.key);
        let input = match list_kind(&s.key) {
            _ if s.key == "egress.https_anywhere" => {
                let on = s.value == "true";
                format!(
                    "<select name=\"{key}\" id=\"{key}\"><option value=\"true\"{}>true</option><option value=\"false\"{}>false</option></select>",
                    if on { " selected" } else { "" },
                    if on { "" } else { " selected" },
                )
            }
            Some(kind) => format!(
                "<div class=\"list-edit\" data-kind=\"{kind}\"><input name=\"{key}\" id=\"{key}\" value=\"{}\" \
                 placeholder=\"(empty)\" class=\"list-raw\" autocomplete=\"off\"></div>",
                esc(&s.value)
            ),
            None => format!(
                "<input name=\"{key}\" id=\"{key}\" value=\"{}\" placeholder=\"(empty)\">",
                esc(&s.value)
            ),
        };
        fields.push_str(&format!(
            "<div class=\"setting\"><label for=\"{key}\"><code>{key}</code></label><p class=\"hint\">{}</p>{input}</div>",
            esc(&s.help)
        ));
    }
    let you = c
        .client
        .map(|a| format!(" You are connected from <code>{a}</code>."))
        .unwrap_or_default();
    // What the address picker offers: this device, then the tailnet's.
    let picker = serde_json::json!({
        "you": c.client.map(|a| a.to_string()),
        "peers": peers,
    });
    let peers_note = if peers.is_empty() {
        "<p class=\"hint\">This hub is not on a tailnet (or <code>tailscale</code> is not installed), so the \
         address picker offers only the device you are on.</p>"
            .to_string()
    } else {
        format!(
            "<p class=\"hint\">The address picker lists the {} devices on this hub's tailnet, and whether they are online.</p>",
            peers.len()
        )
    };
    let ts = get::<ops::TailscaleView>(c, Op::TailscaleShow).unwrap_or_default();
    let b = format!(
        "<h1>Settings</h1>{}{}{}<section class=\"card\"><h2>Network and access</h2><p class=\"hint\">Saved to \
         <code>/etc/blackthorn/config.toml</code> and applied at once.{you} A change that would shut you out is \
         refused.</p>{peers_note}<form method=\"post\" action=\"/settings\" class=\"stack settings\">{}{fields}{}\
         <div><button class=\"primary\">Save</button></div></form></section>\
         <dialog id=\"add-address\" data-picker=\"{}\"><form method=\"dialog\" class=\"stack\">\
         <h2>Add an address</h2><label>Address <input name=\"address\" autocomplete=\"off\" spellcheck=\"false\"></label>\
         <p class=\"dialog-error t-bad\" hidden></p><div class=\"suggest\"></div>\
         <div class=\"buttons\"><button value=\"add\" class=\"primary\">Add</button><button value=\"cancel\" formnovalidate>Cancel</button></div>\
         </form></dialog>\
         <section class=\"card\" id=\"backup\"><h2>Backup</h2><p>On the hub: <code>sudo thorn export FILE</code> \
         saves everything blackthorn keeps (settings, machine keys, accounts, spaces with their Claude logins and \
         chats, what they ran) to one file; <code>sudo thorn import FILE</code> brings it back, on this hub or a new \
         one, with the same version of blackthorn ({}).</p><p class=\"hint\">Only from the hub's own terminal: the \
         file holds every secret here.</p></section>",
        update_card(c),
        tailscale_card(c, &ts),
        notify_card(c),
        csrf(c),
        code_field(),
        esc(&picker.to_string()),
        crate::backup::version(),
    );
    // Watched while an install or sign-in runs.
    let head = if ts.busy.is_some() {
        "<meta http-equiv=\"refresh\" content=\"5;url=/settings#tailscale\">"
    } else {
        ""
    };
    Reply::Html(200, page_with(c, "Settings", &b, flash, head))
}

fn tailscale_card(c: &Ctx, v: &ops::TailscaleView) -> String {
    let link = |url: &str, text: &str| {
        format!(
            "<a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">{}</a>",
            esc(url),
            esc(text)
        )
    };
    let action = |path: &str, label: &str, title: &str, hint: &str| {
        pop_dialog(
            c,
            &format!("/tailscale/{path}"),
            label,
            "primary",
            title,
            &format!("<p class=\"hint\">{hint}</p>{}", code_field()),
            label,
        )
    };
    let mut body = String::new();
    if let Some(b) = &v.busy {
        body.push_str(&format!(
            "<p><span class=\"badge\">{}</span> This page refreshes by itself.</p>",
            esc(b)
        ));
    }
    if !v.installed {
        body.push_str("<p>Tailscale is not installed on this hub.</p>");
        if v.busy.is_none() {
            body.push_str(&action(
                "install",
                "Install Tailscale",
                "Install Tailscale",
                "Runs Tailscale's own installer (https://tailscale.com/install.sh), which adds its package \
                 repository for this system and installs it. Then sign in.",
            ));
        }
    } else {
        let state = match v.state.as_str() {
            "Running" => "<span class=\"t-ok\">on the tailnet</span>".to_string(),
            "NeedsLogin" => "<span class=\"t-bad\">needs to sign in</span>".to_string(),
            "NeedsMachineAuth" => {
                "<span class=\"t-bad\">waiting for an admin to approve it</span>".to_string()
            }
            "Stopped" => "<span class=\"t-bad\">stopped</span>".to_string(),
            "" => "<span class=\"t-bad\">not answering (is tailscaled running?)</span>".to_string(),
            s => esc(s),
        };
        let mut rows = vec![
            ("Version", esc(v.version.as_deref().unwrap_or("?"))),
            ("State", state),
        ];
        if let Some(n) = &v.name {
            rows.push(("Name", format!("<code>{}</code>", esc(n))));
        }
        if !v.ips.is_empty() {
            let ips: Vec<String> = v.ips.iter().map(|a| format!("<code>{a}</code>")).collect();
            rows.push(("Addresses", ips.join(" ")));
        }
        if let Some(t) = &v.tailnet {
            rows.push((
                "Tailnet",
                format!(
                    "{} · coordinated by {}",
                    esc(t),
                    esc(v.control.as_deref().unwrap_or("?"))
                ),
            ));
        }
        if v.state == "Running" {
            rows.push(("Devices", format!("{} ({} online)", v.peers, v.online)));
        }
        body.push_str("<dl class=\"facts\">");
        for (k, val) in rows {
            body.push_str(&format!("<dt>{k}</dt><dd>{val}</dd>"));
        }
        body.push_str("</dl>");
        if let Some(u) = &v.auth_url {
            body.push_str(&format!(
                "<p>Sign the hub in: {} (log in with your Tailscale account; this page shows it once it is done).</p>",
                link(u, "open the sign-in page")
            ));
        } else if v.state != "Running" && v.busy.is_none() {
            body.push_str(&action(
                "up",
                "Sign in to Tailscale",
                "Sign the hub in to Tailscale",
                "Joins the hub to your tailnet on Tailscale's own coordination server: a sign-in link shows \
                 here. The hub keeps its own DNS settings.",
            ));
        }
        if v.state == "Running" {
            let mut links = Vec::new();
            match v.web_url() {
                Some(u) => {
                    links.push(link(&u, "Tailscale's web interface"));
                    body.push_str(
                        "<p>Tailscale's web interface is on, for the devices allowed to manage the hub \
                         (<code>inbound.admin_from</code>).</p>",
                    );
                    body.push_str(&action(
                        "web-off",
                        "Turn it off",
                        "Turn off Tailscale's web interface",
                        "Port 5252 on the hub's tailnet address stops answering.",
                    ));
                }
                None => {
                    body.push_str(
                        "<p>Tailscale's own web interface (this device's Tailscale settings: exit node, subnet \
                         routes, sign out) is off.</p>",
                    );
                    body.push_str(&action(
                        "web-on",
                        "Turn on its web interface",
                        "Turn on Tailscale's web interface",
                        "It answers on port 5252 of the hub's tailnet address, to the devices allowed to manage \
                         the hub; changing settings there asks you to sign in to Tailscale again.",
                    ));
                }
            }
            if let Some(u) = v.console_url() {
                links.push(link(u, "Tailscale admin console"));
            }
            if !links.is_empty() {
                body.push_str(&format!("<p>{}</p>", links.join(" · ")));
            }
        }
    }
    if !v.log.is_empty() && (v.busy.is_some() || v.state != "Running") {
        body.push_str(&format!(
            "<details{}><summary>Last output</summary><pre class=\"wrap\">{}</pre></details>",
            if v.busy.is_some() { " open" } else { "" },
            esc(&v.log.join("\n"))
        ));
    }
    format!("<section class=\"card\" id=\"tailscale\"><h2>Tailscale</h2>{body}</section>")
}

fn notify_card(c: &Ctx) -> String {
    let v = get::<NotifyView>(c, Op::NotifyShow).unwrap_or_default();
    let on = !v.url.is_empty();
    let status = if on {
        format!(
            "<p>On: messages go to <code>{}</code>{}. Subscribe to that topic in the ntfy app.</p>{}",
            esc(&v.url),
            if v.token { " with an access token" } else { "" },
            button(c, "/notify/test", "Send a test", "", "")
        )
    } else {
        "<p>Off.</p>".to_string()
    };
    let suggested = format!("https://ntfy.sh/{}", crate::notify::random_topic());
    format!(
        "<section class=\"card\" id=\"notify\"><h2>Notifications</h2><p class=\"hint\">Pushed to your phone with \
         <a href=\"https://ntfy.sh\" target=\"_blank\" rel=\"noopener noreferrer\">ntfy</a> when a managed machine tries to \
         connect to the hub, a space fails or needs to sign in again, a block or bridge ends, or a new release is out. \
         Use ntfy.sh with a topic nobody can guess, or your own ntfy server. Messages carry names, never secrets.</p>\
         {status}<form method=\"post\" action=\"/notify\" class=\"stack\">{}\
         <label>Topic URL <input name=\"url\" value=\"{}\" placeholder=\"{}\" autocomplete=\"off\" spellcheck=\"false\"></label>\
         <p class=\"hint\">Empty turns notifications off. A fresh random topic: <code>{}</code></p>\
         <label>Access token, for a protected topic <input name=\"token\" type=\"password\" autocomplete=\"off\" \
         placeholder=\"{}\"></label>{}{}<div><button class=\"primary\">Save</button></div></form></section>",
        csrf(c),
        esc(&v.url),
        esc(&suggested),
        esc(&suggested),
        if v.token { "(kept unless you type a new one)" } else { "(optional)" },
        if v.token {
            "<label class=\"check\"><input type=\"checkbox\" name=\"clear_token\"> Remove the access token</label>"
        } else {
            ""
        },
        code_field()
    )
}

fn updating_page(c: &Ctx, tag: &str) -> Reply {
    let b = format!(
        "<section class=\"card narrow\"><h1>Updating to {}</h1><p>The installer is running on the hub. The web UI \
         restarts on the way, so this page reloads by itself in about a minute.</p>\
         <p class=\"hint\">On the hub you can follow it with <code>journalctl -u {} -f</code>.</p></section>",
        esc(tag),
        ops::UPDATE_UNIT
    );
    Reply::Html(
        200,
        page_with(
            c,
            "Updating",
            &b,
            &Flash::default(),
            "<meta http-equiv=\"refresh\" content=\"45;url=/settings#update\">",
        ),
    )
}

fn passkeys_card(c: &Ctx, acct: &serde_json::Value) -> String {
    if acct["https"].as_bool() != Some(true) {
        return "<section class=\"card\" id=\"passkeys\"><h2>Passkeys and security keys</h2><p>They need the web UI on \
                HTTPS, under a name such as <code>blackthorn.example.com</code>. On the hub: \
                <code>sudo thorn web https --help</code>.</p></section>"
            .to_string();
    }
    let now = crate::state::now();
    let mut rows = String::new();
    for p in acct["passkeys"].as_array().into_iter().flatten() {
        let id = p["id"].as_str().unwrap_or("");
        let added = p["added"].as_u64().unwrap_or(0);
        rows.push_str(&format!(
            "<li class=\"chat\"><div class=\"chat-main\"><span class=\"chat-title\">{}</span>\
             <span class=\"item-meta\">added {}</span></div><div class=\"chat-actions\">\
             <details class=\"pop\"><summary class=\"btn\">Remove</summary><form method=\"post\" action=\"/account/passkey-rm\" \
             class=\"stack pop-body\">{}<input type=\"hidden\" name=\"id\" value=\"{}\"><h2>Remove passkey {}</h2>{}\
             <div class=\"buttons\"><button class=\"danger\">Remove</button><button type=\"button\" class=\"link\" data-close hidden>Cancel</button></div>\
             </form></details></div></li>",
            esc(p["name"].as_str().unwrap_or("")),
            ago(now.saturating_sub(added)),
            csrf(c),
            esc(id),
            esc(p["name"].as_str().unwrap_or("")),
            code_field()
        ));
    }
    format!(
        "<section class=\"card\" id=\"passkeys\"><h2>Passkeys and security keys</h2><p class=\"hint\">Log in with \
         your phone's or computer's fingerprint, face or PIN, or a hardware key (with a PIN set), instead of the password \
         and code; and confirm risky actions with it instead of a code.</p>{}\
         <form method=\"post\" action=\"/account/passkey-add\" class=\"stack passkey-add\">{}\
         <input type=\"hidden\" name=\"answer\"><label>Name <input name=\"name\" required maxlength=\"60\" \
         placeholder=\"iPhone, YubiKey, ...\"></label>{}<p class=\"dialog-error t-bad\" hidden></p>\
         <div><button class=\"primary\">Add a passkey</button></div><noscript>Adding a passkey needs JavaScript.</noscript>\
         </form></section>",
        if rows.is_empty() {
            "<p>None yet.</p>".to_string()
        } else {
            format!("<ul class=\"chats\">{rows}</ul>")
        },
        csrf(c),
        code_field()
    )
}

fn account_page(c: &Ctx, flash: &Flash) -> Reply {
    let acct = get::<serde_json::Value>(c, Op::Account).unwrap_or_default();
    let left = acct["recovery_left"].as_u64().unwrap_or(0);
    let b = format!(
        "<div class=\"page-head\"><h1>Account {}</h1><div class=\"buttons\">{}</div></div><section class=\"row\">\
         <section class=\"card\"><h2>Password</h2><form method=\"post\" action=\"/account/password\" class=\"stack\">{}\
         <label>Current password <input name=\"current\" type=\"password\" autocomplete=\"current-password\" required></label>\
         <label>New password (12+ characters) <input name=\"new\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\" required></label>\
         <label>New password again <input name=\"again\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\" required></label>\
         {}<div><button class=\"primary\">Change password</button></div></form></section>\
         <section class=\"card\"><h2>Authenticator app</h2><p>Moving to a new phone, or worried the old one leaked? \
         Set up a new authenticator: the old one stops working once the new one is confirmed, and you get new \
         recovery codes.</p><p class=\"hint\">{left} recovery code(s) left.</p>\
         <form method=\"post\" action=\"/account/totp-begin\" class=\"stack\">{}\
         <label>Code from your current authenticator <input name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" \
         pattern=\"[0-9]{{6}}\" maxlength=\"6\" required class=\"code\"></label>\
         <div><button>Set up a new authenticator</button></div></form></section></section>{}{}\
         <p class=\"hint\">Accounts are added and removed on the hub itself: <code>sudo thorn web user add &lt;name&gt;</code>, \
         <code>sudo thorn web user rm &lt;name&gt;</code>.</p>",
        esc(&c.user),
        rename_dialog(c, "/account/rename", "account", "new", &c.user, "", ""),
        csrf(c),
        code_field(),
        csrf(c),
        passkeys_card(c, &acct),
        sessions_card(c),
    );
    Reply::Html(200, page(c, "Account", &b, flash))
}

/// A time, in UTC; the page's script shows it in the browser's own time.
fn when(t: u64) -> String {
    let utc = ops::rfc3339(t);
    format!(
        "<time datetime=\"{utc}\" data-local>{}</time>",
        utc.replace('T', " ")
    )
}

/// The account's logins and chat unlocks, each ended on its own.
fn sessions_card(c: &Ctx) -> String {
    let list = match get::<Vec<api::SessionView>>(c, Op::SessionList) {
        Ok(v) => v,
        Err(e) => {
            return format!(
                "<section class=\"card\" id=\"sessions\"><h2>Logins</h2><p class=\"t-bad\">{}</p></section>",
                esc(&e)
            )
        }
    };
    let now = crate::state::now();
    let mut rows = String::new();
    for x in &list {
        let what = if x.chat {
            "may type into chats".to_string()
        } else {
            format!(
                "logged in with a {}",
                if x.how == "passkey" {
                    "passkey"
                } else {
                    "password and code"
                }
            )
        };
        let ip = |a: &Option<IpAddr>| a.map(|a| a.to_string()).unwrap_or_else(|| "?".into());
        let from = if x.ip != x.login_ip {
            format!("{} (logged in from {})", ip(&x.ip), ip(&x.login_ip))
        } else {
            ip(&x.ip)
        };
        let end = format!(
            "<form method=\"post\" action=\"/account/session-end\" class=\"inline\" data-confirm=\"{}\">{}\
             <input type=\"hidden\" name=\"id\" value=\"{}\"><button class=\"link danger-text\">{}</button></form>",
            if x.current && !x.chat {
                "Log out this browser?"
            } else if x.chat {
                "This browser will need the password and a code again to type into chats. End it?"
            } else {
                "End this login? That browser goes back to the login page."
            },
            csrf(c),
            esc(&x.id),
            if x.current && !x.chat { "Log out" } else { "End" }
        );
        rows.push_str(&format!(
            "<li class=\"chat\"><div class=\"chat-main\"><span class=\"chat-title\">{} on {} <span class=\"hint\">({})</span>{}</span>\
             <span class=\"item-meta\">{what} · from {} · since {} · last used {} · ends {}</span>\
             <span class=\"item-meta\" title=\"{}\"><code>{}</code></span></div>\
             <div class=\"chat-actions\">{end}</div></li>",
            esc(&x.browser),
            esc(&x.os),
            esc(&x.device),
            if x.current { " <span class=\"badge\">this browser</span>" } else { "" },
            esc(&from),
            when(x.created),
            if now.saturating_sub(x.last_seen) < 60 { "just now".to_string() } else { ago(now.saturating_sub(x.last_seen)) },
            when(x.expires),
            esc(&x.agent),
            esc(&x.id),
        ));
    }
    let others = list.iter().any(|x| !x.current);
    format!(
        "<section class=\"card\" id=\"sessions\"><div class=\"page-head\"><h2>Logins</h2>{}</div>\
         <p class=\"hint\">Where this account is logged in, and the browsers that may type into chats. A login ends \
         after 30 idle minutes, or <code>web.session_hours</code> after it began (Settings).</p>{}</section>",
        if others {
            format!(
                "<form method=\"post\" action=\"/account/session-end-others\" class=\"inline\" \
                 data-confirm=\"End every login and chat unlock but this browser's?\">{}<button>End all others</button></form>",
                csrf(c)
            )
        } else {
            String::new()
        },
        if rows.is_empty() {
            "<p>None.</p>".to_string()
        } else {
            format!("<ul class=\"chats\">{rows}</ul>")
        }
    )
}

fn account_post(c: &Ctx, action: &str, form: &HashMap<String, String>) -> Reply {
    match action {
        "session-end" => {
            let id = f(form, "id");
            let r = get::<serde_json::Value>(c, Op::SessionEnd { id: id.into() });
            if r.is_ok() && id == c.session {
                return Reply::Redirect("/login".into(), Some(clear_cookie()));
            }
            back("/account#sessions", r.map(|_| "ended".into()))
        }
        "session-end-others" => back(
            "/account#sessions",
            get::<serde_json::Value>(c, Op::SessionEndOthers)
                .map(|_| "every other login ended".into()),
        ),
        "passkey-add" => back(
            "/account#passkeys",
            match serde_json::from_str(f(form, "answer")) {
                Ok(answer) => get::<String>(
                    c,
                    Op::PasskeyAdd {
                        name: f(form, "name").into(),
                        answer,
                        code: f(form, "code").into(),
                    },
                ),
                Err(_) => Err("the browser gave no passkey (it needs JavaScript and HTTPS)".into()),
            },
        ),
        "passkey-rm" => back(
            "/account#passkeys",
            get::<String>(
                c,
                Op::PasskeyRm {
                    id: f(form, "id").into(),
                    code: f(form, "code").into(),
                },
            ),
        ),
        "rename" => back(
            "/account",
            get::<String>(
                c,
                Op::AccountRename {
                    new: f(form, "new").trim().into(),
                    code: f(form, "code").into(),
                },
            )
            .map(|n| format!("you are now {n}; log in with that name from now on")),
        ),
        "password" => {
            if f(form, "new") != f(form, "again") {
                return back("/account", Err("the two new passwords differ".into()));
            }
            back(
                "/account",
                get::<String>(
                    c,
                    Op::AccountPassword {
                        current: f(form, "current").into(),
                        new: f(form, "new").into(),
                        code: f(form, "code").into(),
                    },
                ),
            )
        }
        "totp-begin" => match get::<serde_json::Value>(
            c,
            Op::AccountTotpBegin {
                code: f(form, "code").into(),
            },
        ) {
            Ok(v) => {
                let secret = v["secret"].as_str().unwrap_or("");
                // The QR code is our own SVG (qrcode crate output), not user input.
                let qr = v["qr"].as_str().unwrap_or("");
                let b = format!(
                    "<section class=\"card narrow\"><h1>New authenticator</h1><ol class=\"steps\">\
                     <li>Scan this with your authenticator app:<div class=\"qr\">{qr}</div>\
                     <p class=\"hint\">or enter this key by hand:</p>{}</li>\
                     <li><form method=\"post\" action=\"/account/totp-finish\" class=\"stack\">{}\
                     <label>The code the app now shows for blackthorn <input name=\"code\" inputmode=\"numeric\" \
                     autocomplete=\"one-time-code\" pattern=\"[0-9]{{6}}\" maxlength=\"6\" required class=\"code\"></label>\
                     <button class=\"primary\">Confirm</button></form></li></ol>\
                     <p class=\"hint\">Until you confirm, your current authenticator keeps working. This expires in 10 minutes.</p>\
                     <p><a href=\"/account\">Cancel</a></p></section>",
                    copyable("totpkey", secret),
                    csrf(c),
                );
                Reply::Html(200, page(c, "New authenticator", &b, &Flash::default()))
            }
            Err(e) => back("/account", Err(e)),
        },
        "totp-finish" => match get::<Vec<String>>(
            c,
            Op::AccountTotpFinish {
                code: f(form, "code").into(),
            },
        ) {
            Ok(codes) => {
                let b = format!(
                    "<section class=\"card narrow\"><h1>New authenticator confirmed</h1><p>From now on log in with \
                     the new one. Your other logins ended.</p><p>Your new recovery codes: each works once instead \
                     of a code, if you lose the phone. Write them down now; they are not shown again.</p>{}\
                     <p><a class=\"btn primary\" href=\"/account\">Done</a></p></section>",
                    copyable("codes", &codes.join("\n"))
                );
                Reply::Html(200, page(c, "Recovery codes", &b, &Flash::default()))
            }
            Err(e) if e.starts_with("start again") => back("/account", Err(e)),
            Err(e) => {
                let b = format!(
                    "<section class=\"card narrow\"><h1>New authenticator</h1>\
                     <form method=\"post\" action=\"/account/totp-finish\" class=\"stack\">{}\
                     <label>The code the app now shows for blackthorn <input name=\"code\" inputmode=\"numeric\" \
                     autocomplete=\"one-time-code\" pattern=\"[0-9]{{6}}\" maxlength=\"6\" required class=\"code\" autofocus></label>\
                     <button class=\"primary\">Confirm</button></form><p><a href=\"/account\">Cancel</a></p></section>",
                    csrf(c)
                );
                let flash = Flash {
                    ok: None,
                    err: Some(e),
                };
                Reply::Html(200, page(c, "New authenticator", &b, &flash))
            }
        },
        _ => back("/account", Err("unknown action".into())),
    }
}

fn settings_post(c: &Ctx, form: &HashMap<String, String>) -> Reply {
    let current = match get::<Vec<Setting>>(c, Op::ConfigShow) {
        Ok(s) => s,
        Err(e) => return back("/settings", Err(e)),
    };
    // Only what was changed, so the rest of the file stays as it is.
    let norm = |v: &str| {
        v.split(|ch: char| ch == ',' || ch.is_whitespace())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let changes: Vec<(String, String)> = current
        .iter()
        .filter_map(|s| {
            let v = form.get(&s.key)?;
            (norm(v) != norm(&s.value)).then(|| (s.key.clone(), v.clone()))
        })
        .collect();
    if changes.is_empty() {
        return back("/settings", Ok("nothing changed".into()));
    }
    let r = get::<ConfigChange>(
        c,
        Op::ConfigSet {
            changes,
            code: f(form, "code").into(),
        },
    );
    back(
        "/settings",
        r.map(|r| match r.web_moved {
            Some(urls) => format!(
                "saved {}; the web UI moves to {} in a few seconds",
                r.changed.join(", "),
                urls.join(" ")
            ),
            None => format!("saved {}", r.changed.join(", ")),
        }),
    )
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
        b.push_str("<div class=\"items\">");
        for x in &o.bridges {
            b.push_str(&format!(
                "<article class=\"item\"><div class=\"item-head\"><span class=\"swatch bridge\"></span>\
                 <span class=\"item-name\">{} → {}</span></div><p class=\"item-meta\">via space {} · {}</p>\
                 <div class=\"buttons\">{}</div></article>",
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
        b.push_str("</div>");
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
            "<section class=\"card\"><h2>Open a bridge</h2><form method=\"post\" action=\"/bridges\" class=\"stack\">{}\
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
    fn messages_go_before_the_anchor() {
        let at = |r: Reply| match r {
            Reply::Redirect(to, _) => to,
            _ => panic!("not a redirect"),
        };
        assert_eq!(
            at(back("/space/a#chats", Ok("chat stopped".into()))),
            "/space/a?ok=chat%20stopped#chats"
        );
        assert_eq!(at(back("/settings", Err("no".into()))), "/settings?err=no");
        assert_eq!(at(back("/x?y=1#z", Ok("k".into()))), "/x?y=1&ok=k#z");
    }

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
