//! Notifications: a few things only the hub knows, pushed to an ntfy topic
//! (ntfy.sh or your own ntfy server).
//!
//! The topic URL and token live in a root-only file: on ntfy.sh the topic
//! name is all it takes to read or send, so spaces must not see it. Messages
//! carry names and states only, never secrets.

use crate::state::{now, State};
use crate::{ops, paths, sys};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Notify {
    /// The topic URL, e.g. https://ntfy.sh/blackthorn-k3x9... Empty: off.
    #[serde(default)]
    pub url: String,
    /// Access token for a protected topic (sent as a Bearer token).
    #[serde(default)]
    pub token: String,
}

impl Notify {
    pub fn load() -> Notify {
        std::fs::read_to_string(paths::NOTIFY_FILE)
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn on(&self) -> bool {
        !self.url.is_empty()
    }
}

/// What the settings page shows: never the token, and only as much of the
/// topic as tells you which one it is.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NotifyView {
    pub url: String,
    pub token: bool,
}

pub fn view() -> NotifyView {
    let n = Notify::load();
    NotifyView {
        url: n.url,
        token: !n.token.is_empty(),
    }
}

pub fn check_url(url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .context("the topic URL starts with https:// (or http:// for your own server)")?;
    let (host, topic) = rest
        .split_once('/')
        .context("the URL needs a topic: https://ntfy.sh/<topic>")?;
    if host.is_empty() || topic.is_empty() || topic.contains('/') {
        bail!("the URL looks like https://<server>/<topic>");
    }
    let ok = |c: char| c.is_ascii_alphanumeric() || "-_.:[]".contains(c);
    if !host.chars().all(ok)
        || !topic
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
    {
        bail!("the server and topic may hold letters, digits, - and _ only");
    }
    if topic.len() < 12 && host == "ntfy.sh" {
        bail!("on ntfy.sh anyone who knows the topic can read it; use a long random one (Suggest picks one)");
    }
    Ok(())
}

/// A topic name nobody will guess.
pub fn random_topic() -> String {
    let b = crate::webauth::random_bytes::<12>();
    let s: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("blackthorn-{s}")
}

/// Saves the settings (empty url: off). `token: None` keeps the current one.
pub fn set(url: &str, token: Option<&str>) -> Result<()> {
    let url = url.trim();
    let mut n = Notify::load();
    if url.is_empty() {
        n = Notify::default();
    } else {
        check_url(url)?;
        if n.url != url {
            n.token.clear();
        }
        n.url = url.to_string();
    }
    if let Some(t) = token {
        let t = t.trim();
        if t.chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"')
        {
            bail!("that does not look like an access token");
        }
        n.token = t.to_string();
    }
    sys::write_file(
        Path::new(paths::NOTIFY_FILE),
        &toml::to_string(&n)?,
        0o600,
        None,
    )
}

/// Sends one message now.
pub fn send(n: &Notify, title: &str, body: &str, tags: &str) -> Result<()> {
    if !n.on() {
        bail!("notifications are off");
    }
    // Given on standard input so the topic and token never show in `ps`.
    let mut cfg = format!(
        "url = {}\nheader = {}\ndata-binary = {}\n",
        quote(&n.url),
        quote(&format!("Title: {}", one_line(title))),
        quote(body),
    );
    if !tags.is_empty() {
        cfg.push_str(&format!("header = {}\n", quote(&format!("Tags: {tags}"))));
    }
    if !n.token.is_empty() {
        cfg.push_str(&format!(
            "header = {}\n",
            quote(&format!("Authorization: Bearer {}", n.token))
        ));
    }
    let mut child = Command::new("curl")
        .args([
            "-sS",
            "-f",
            "-m",
            "15",
            "--proto",
            "=https,http",
            "-o",
            "/dev/null",
            "-K",
            "-",
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running curl")?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(cfg.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "could not send the notification: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// A string in curl's config syntax.
fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn test() -> Result<()> {
    send(
        &Notify::load(),
        &format!("blackthorn on {}", sys::hostname()),
        "Notifications work.",
        "white_check_mark",
    )
}

/// What was last reported, so each thing is said once.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Seen {
    /// Space name -> the bad state reported ("failed", "needs login").
    #[serde(default)]
    spaces: BTreeMap<String, String>,
    #[serde(default)]
    release: String,
    #[serde(default)]
    release_checked: u64,
}

const RELEASE_EVERY: u64 = 6 * 3600;

/// Run every minute by `thorn _tick`: report what changed. `lifted` and
/// `ended` are the blocks and bridges that tick just let go.
pub fn tick(state: &State, lifted: &[String], ended: &[String], root_ended: &[String]) {
    let n = Notify::load();
    let attempts = take_connect_back_attempts();
    if !n.on() {
        return;
    }
    let host = sys::hostname();
    let mut seen: Seen = std::fs::read_to_string(paths::NOTIFY_SEEN_FILE)
        .ok()
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default();
    let mut msgs: Vec<(String, String, &str)> = Vec::new();

    for ip in attempts {
        let who = state
            .hosts
            .iter()
            .find(|(_, h)| h.address == ip)
            .map(|(n, _)| format!("machine {n} ({ip})"))
            .unwrap_or_else(|| ip.to_string());
        msgs.push((
            format!("{who} tried to connect to the hub"),
            "The firewall dropped it. A managed machine should never connect back; \
             check what on it is doing so."
                .into(),
            "warning",
        ));
    }
    for (name, s) in &state.spaces {
        let bad = if !ops::logged_in(s) {
            Some("needs login")
        } else if sys::unit_state(&paths::space_unit(&s.key)) == "failed" {
            Some("failed")
        } else {
            None
        };
        match bad {
            Some(b) if seen.spaces.get(name).map(String::as_str) != Some(b) => {
                seen.spaces.insert(name.clone(), b.into());
                let body = if b == "failed" {
                    "It stopped with an error; see its page in the web UI or `thorn logs`."
                } else {
                    "Sign it in from its page in the web UI, or with `thorn login`."
                };
                msgs.push((format!("space {name} {b}"), body.into(), "rotating_light"));
            }
            Some(_) => {}
            None => {
                seen.spaces.remove(name);
            }
        }
    }
    seen.spaces.retain(|n, _| state.spaces.contains_key(n));
    for h in lifted {
        msgs.push((
            format!("block on {h} lifted"),
            "Spaces can reach it again.".into(),
            "unlock",
        ));
    }
    for b in ended {
        msgs.push((
            format!("bridge {b} ended"),
            "The time it was given ran out.".into(),
            "link",
        ));
    }
    for s in root_ended {
        let back = state
            .spaces
            .get(s)
            .map(|x| x.access.to_string())
            .unwrap_or_else(|| "its usual login".into());
        msgs.push((
            format!("root of space {s} ended"),
            format!("Its time ran out. It goes on as {back}; its chats are still running."),
            "lock",
        ));
    }
    let t = now();
    if t.saturating_sub(seen.release_checked) >= RELEASE_EVERY {
        seen.release_checked = t;
        let u = ops::update_check();
        let latest = u.latest.clone().unwrap_or_default();
        if u.newer && latest != seen.release {
            seen.release = latest.clone();
            msgs.push((
                format!("blackthorn {latest} is out"),
                format!(
                    "This hub runs {}. Update from Settings in the web UI, or: sudo thorn update",
                    u.current
                ),
                "package",
            ));
        }
    }
    for (title, body, tags) in msgs {
        if let Err(e) = send(&n, &format!("{host}: {title}"), &body, tags) {
            eprintln!("{e:#}");
        }
    }
    if let Ok(text) = toml::to_string(&seen) {
        let _ = sys::write_file(Path::new(paths::NOTIFY_SEEN_FILE), &text, 0o600, None);
    }
}

/// Addresses the firewall saw trying to open connections to the hub since
/// the last call (the firewall's `tried` sets, emptied here).
fn take_connect_back_attempts() -> Vec<IpAddr> {
    let mut out = Vec::new();
    for set in [crate::firewall::TRIED4, crate::firewall::TRIED6] {
        let Ok(o) = Command::new("nft")
            .args(["-j", "list", "set", "inet", crate::firewall::TABLE, set])
            .output()
        else {
            continue;
        };
        if !o.status.success() {
            continue;
        }
        out.extend(parse_set_elements(&String::from_utf8_lossy(&o.stdout)));
        let _ = Command::new("nft")
            .args(["flush", "set", "inet", crate::firewall::TABLE, set])
            .status();
    }
    out.sort();
    out.dedup();
    out
}

/// The addresses in `nft -j list set` output.
fn parse_set_elements(json: &str) -> Vec<IpAddr> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in v["nftables"].as_array().into_iter().flatten() {
        for e in item["set"]["elem"].as_array().into_iter().flatten() {
            // A plain address, or {"elem": {"val": address, ...}}.
            let a = e.as_str().or_else(|| e["elem"]["val"].as_str());
            if let Some(ip) = a.and_then(|s| s.parse().ok()) {
                out.push(ip);
            }
        }
    }
    out
}

// ------------------------------------------------------------ commands

pub fn cmd_show() -> Result<()> {
    sys::require_root()?;
    let v = view();
    if v.url.is_empty() {
        println!("notifications are off; turn them on with: sudo thorn notify set [URL]");
    } else {
        println!(
            "notifications go to {}{}",
            v.url,
            if v.token {
                " (with an access token)"
            } else {
                ""
            }
        );
        println!("subscribe to that topic in the ntfy app; try it with: sudo thorn notify test");
    }
    Ok(())
}

/// `url` None: a new random topic on ntfy.sh. `ask_token`: read an access
/// token from the terminal (or standard input).
pub fn cmd_set(url: Option<String>, ask_token: bool) -> Result<()> {
    sys::require_root()?;
    let url = url.unwrap_or_else(|| format!("https://ntfy.sh/{}", random_topic()));
    let token = if ask_token {
        use std::io::{BufRead, IsTerminal};
        if std::io::stdin().is_terminal() {
            print!("access token: ");
            std::io::stdout().flush()?;
        }
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        Some(line.trim().to_string())
    } else {
        None
    };
    set(&url, token.as_deref())?;
    println!("notifications go to {url}");
    println!(
        "subscribe to it in the ntfy app (or open it in a browser), then: sudo thorn notify test"
    );
    Ok(())
}

pub fn cmd_off() -> Result<()> {
    sys::require_root()?;
    set("", None)?;
    println!("notifications are off");
    Ok(())
}

pub fn cmd_test() -> Result<()> {
    sys::require_root()?;
    test()?;
    println!("sent");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert!(check_url("https://ntfy.sh/blackthorn-0123456789ab").is_ok());
        assert!(check_url("https://ntfy.example.com/hub").is_ok());
        assert!(check_url("http://100.64.0.9:8080/hub_alerts").is_ok());
        assert!(check_url("https://ntfy.sh/short").is_err());
        assert!(check_url("ftp://ntfy.sh/blackthorn-0123456789ab").is_err());
        assert!(check_url("https://ntfy.sh/").is_err());
        assert!(check_url("https://ntfy.sh/a/b").is_err());
        assert!(check_url("https://ntfy.sh/x\" -o /etc/passwd").is_err());
        assert!(check_url(&format!("https://ntfy.sh/{}", random_topic())).is_ok());
    }

    #[test]
    fn curl_config_quoting() {
        assert_eq!(quote("a \"b\" \\ c\nd"), "\"a \\\"b\\\" \\\\ c\\nd\"");
        assert_eq!(quote("x\u{7}y"), "\"xy\"");
    }

    #[test]
    fn nft_set_elements() {
        let j = r#"{"nftables":[{"metainfo":{}},{"set":{"family":"inet","name":"tried4",
            "elem":["100.80.0.3",{"elem":{"val":"100.80.0.4","expires":10}}]}}]}"#;
        assert_eq!(
            parse_set_elements(j),
            vec![
                "100.80.0.3".parse::<IpAddr>().unwrap(),
                "100.80.0.4".parse().unwrap()
            ]
        );
        assert!(parse_set_elements(r#"{"nftables":[{"set":{"name":"tried4"}}]}"#).is_empty());
    }
}
