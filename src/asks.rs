//! Root on approval: each command a space wants run as root on its machine
//! waits there (blackthorn-ask, see `logins::ASK_TEXT`) until someone
//! approves it on the hub.
//!
//! The hub watches: `thorn _asks` (a unit of its own) keeps one SSH
//! connection open, as blackthorn's own login, to each machine with such a
//! space, running `blackthorn-ask --watch`, which prints each new ask. The
//! machine never connects to the hub. Approving or refusing writes one file
//! there, through the same login. The command that runs is the one stored
//! when it was asked, with its standard input: what you approve is what
//! runs.

use crate::ctx;
use crate::state::{now, Host, State, StateLock};
use crate::{logins, paths};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::io::BufRead;
use std::path::Path;
use std::sync::{Arc, Mutex};

const FILE: &str = "/var/lib/blackthorn/asks.json";
const LOCK: &str = "/var/lib/blackthorn/asks.lock";
/// How many asks are kept (the newest).
const KEEP: usize = 300;
/// The most of a script on standard input that the hub keeps and shows.
const MAX_INPUT: usize = 1 << 20;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Ask {
    /// 16 hex digits, made by the machine.
    pub id: String,
    pub host: String,
    /// The space's name then, and its key.
    pub space: String,
    pub key: String,
    /// When it was asked (the machine's clock).
    pub time: u64,
    /// Where it runs, what, and what comes on its standard input.
    pub cwd: String,
    pub cmd: String,
    #[serde(default)]
    pub input: String,
    #[serde(default)]
    pub input_len: u64,
    /// What to look at twice, in words.
    #[serde(default)]
    pub flags: Vec<String>,
    /// waiting, approved, denied, expired, done.
    pub state: String,
    /// Who approved or refused it, when, and why not.
    #[serde(default)]
    pub by: String,
    #[serde(default)]
    pub decided: u64,
    #[serde(default)]
    pub reason: String,
    /// Its exit status, once it ran.
    #[serde(default)]
    pub rc: Option<i32>,
}

impl Ask {
    pub fn waiting(&self) -> bool {
        self.state == "waiting"
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Store {
    asks: Vec<Ask>,
}

fn load() -> Store {
    std::fs::read_to_string(FILE)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save(s: &Store) -> Result<()> {
    let text = serde_json::to_string(s)?;
    let tmp = format!("{FILE}.tmp");
    crate::sys::write_file(Path::new(&tmp), &text, 0o600, None)?;
    std::fs::rename(&tmp, FILE).context("saving the asks")
}

/// Changes the asks, holding their lock.
fn change<T>(f: impl FnOnce(&mut Store) -> T) -> Result<T> {
    let _lock = StateLock::acquire(Path::new(LOCK))?;
    let mut s = load();
    let r = f(&mut s);
    if s.asks.len() > KEEP {
        let cut = s.asks.len() - KEEP;
        s.asks.drain(..cut);
    }
    save(&s)?;
    Ok(r)
}

/// The asks, newest first.
pub fn list() -> Vec<Ask> {
    let mut v = load().asks;
    v.reverse();
    v
}

pub fn get(id: &str) -> Option<Ask> {
    load().asks.into_iter().find(|a| a.id == id)
}

/// What deserves a second look in an ask, in words. Nothing is refused for
/// it: the text is all there to read.
pub fn flags(cmd: &str, input: &[u8]) -> Vec<String> {
    let mut f = Vec::new();
    let c = cmd.to_lowercase();
    if !input.is_empty() {
        f.push("runs a script that comes on its standard input (shown below)".into());
        if std::str::from_utf8(input).is_err() {
            f.push("its standard input is not text".into());
        }
    }
    if (c.contains("curl") || c.contains("wget"))
        && (c.contains("| sh") || c.contains("|sh") || c.contains("| bash") || c.contains("|bash"))
    {
        f.push("runs something it downloads".into());
    }
    if c.contains("base64 -d")
        || c.contains("base64 --decode")
        || c.contains("xxd -r")
        || c.contains("eval ")
    {
        f.push("decodes or evaluates text, so what runs is not what you read".into());
    }
    let inline = ["python", "perl", "ruby", "node", "php"]
        .iter()
        .any(|p| c.contains(p))
        && (c.contains(" -c ") || c.contains(" -e "))
        && cmd.len() > 300;
    if inline {
        f.push("a long program inline".into());
    }
    for (word, why) in [
        ("rm -rf", "removes files"),
        ("mkfs", "formats a disk"),
        (" dd ", "writes raw data"),
        ("authorized_keys", "touches SSH keys"),
        ("sudoers", "touches sudo's rules"),
        ("/etc/shadow", "touches passwords"),
        ("crontab", "schedules commands"),
        ("useradd", "adds users"),
        ("passwd", "changes passwords"),
    ] {
        if c.contains(word) {
            f.push(why.into());
        }
    }
    f
}

// ---------------------------------------------------------------- deciding

/// Approves (or refuses) an ask: tells the machine, then records it.
/// `by`: a web account, or "hub:<user>" from the command line.
pub fn decide(id: &str, approve: bool, by: &str, reason: &str) -> Result<Ask> {
    if id.len() != 16 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("no ask {id:?}");
    }
    let a = get(id).with_context(|| format!("no ask {id}"))?;
    if !a.waiting() {
        bail!("ask {id} is {} already", a.state);
    }
    let (_, state) = ctx::read_only()?;
    let h = state.host(&a.host)?.clone();
    if approve {
        // Only while the space still has root on approval there.
        let ok = state
            .space_by_key(&a.key)
            .is_some_and(|(_, s)| s.machine(&a.host).is_some_and(|m| m.asks(now())));
        if !ok {
            bail!("{} no longer has root on approval on {}", a.space, a.host);
        }
    }
    let reason = reason.replace(['\n', '\''], " ");
    let what = if approve {
        format!(": >/var/lib/blackthorn-ask/{id}.ok")
    } else {
        format!(
            "printf '%s\\n' '{}' >/var/lib/blackthorn-ask/{id}.no",
            if reason.trim().is_empty() {
                format!("refused by {by}")
            } else {
                format!("refused by {by}: {}", reason.trim())
            }
        )
    };
    let script = format!(
        "set -eu\n[ -e /var/lib/blackthorn-ask/{id}.req ] || {{ echo 'it is over on the machine' >&2; exit 1; }}\n{what}\necho 'bt: done'\n"
    );
    logins::run(&a.host, &h, &script)?;
    let t = now();
    let done = change(|s| {
        s.asks.iter_mut().find(|x| x.id == id).map(|x| {
            x.state = if approve { "approved" } else { "denied" }.into();
            x.by = by.to_string();
            x.decided = t;
            x.reason = reason.trim().to_string();
            x.clone()
        })
    })?
    .context("the ask went away")?;
    let _ = crate::activity::record(
        &a.key,
        "",
        by,
        "",
        &format!(
            "{} root for: {}",
            if approve { "approved" } else { "refused" },
            clip(&a.cmd, 300)
        ),
    );
    Ok(done)
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

// ---------------------------------------------------------------- watching

/// The machines to watch now: set up for blackthorn-ask, not blocked, with
/// a space that has root on approval.
fn wanted(state: &State, t: u64) -> BTreeMap<String, Host> {
    state
        .hosts
        .iter()
        .filter(|(_, h)| h.setup_version >= logins::SETUP_VERSION && !h.blocked(t))
        .filter(|(n, _)| {
            state
                .spaces
                .values()
                .any(|s| s.machine(n).is_some_and(|m| m.asks(t)))
        })
        .map(|(n, h)| (n.clone(), h.clone()))
        .collect()
}

/// `thorn _asks`: watch the machines, for as long as it runs.
pub fn run() -> Result<()> {
    crate::sys::require_root()?;
    let watching: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    loop {
        let want = match ctx::read_only() {
            Ok((_, state)) => wanted(&state, now()),
            Err(e) => {
                eprintln!("reading the state: {e:#}");
                BTreeMap::new()
            }
        };
        {
            let mut w = watching.lock().expect("lock");
            w.retain(|n| want.contains_key(n));
            for (name, h) in want {
                if w.insert(name.clone()) {
                    let watching = watching.clone();
                    std::thread::spawn(move || watch(&name, &h, &watching));
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

/// One machine: connect, read what it prints, and connect again after a
/// pause if the connection ends, until it is no longer wanted.
fn watch(name: &str, h: &Host, watching: &Arc<Mutex<HashSet<String>>>) {
    let wanted = || watching.lock().expect("lock").contains(name);
    while wanted() {
        if let Err(e) = watch_once(name, h, &wanted) {
            eprintln!("{name}: {e:#}");
        }
        for _ in 0..10 {
            if !wanted() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

fn watch_once(name: &str, h: &Host, wanted: &dyn Fn() -> bool) -> Result<()> {
    let known = crate::remote::known_hosts(name, h)?;
    let cmd = if h.root_login() {
        format!("{} --watch", logins::ASK)
    } else {
        format!("sudo -n {} --watch", logins::ASK)
    };
    let child = crate::remote::ssh_command(name, h, &paths::key_file(name), &h.user, &known)
        .arg(cmd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&known);
            return Err(e).context("running ssh");
        }
    };
    let out = child.stdout.take().context("ssh output")?;
    let mut r = std::io::BufReader::new(out);
    let mut line = String::new();
    let result = loop {
        line.clear();
        match r.read_line(&mut line) {
            Ok(0) => break Ok(()),
            Ok(_) => {}
            Err(e) => break Err(e.into()),
        }
        if !wanted() {
            break Ok(());
        }
        if let Err(e) = handle(name, line.trim_end()) {
            eprintln!("{name}: {e:#}");
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&known);
    result
}

fn b64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .unwrap_or_default()
}

/// One line from blackthorn-ask --watch.
fn handle(host: &str, line: &str) -> Result<()> {
    let mut f = line.split(' ');
    match f.next() {
        Some("REQ") => {
            let (id, user, time, cwd, cmd, len) = (
                f.next().unwrap_or(""),
                f.next().unwrap_or(""),
                f.next().unwrap_or("0"),
                f.next().unwrap_or(""),
                f.next().unwrap_or(""),
                f.next().unwrap_or("0"),
            );
            let input = b64(f.next().unwrap_or(""));
            asked(
                host,
                id,
                user,
                time.parse().unwrap_or(0),
                &b64(cwd),
                &b64(cmd),
                len.parse().unwrap_or(0),
                &input,
            )
        }
        Some("DONE") => {
            let id = f.next().unwrap_or("");
            let rc: Option<i32> = f.next().and_then(|x| x.parse().ok());
            let a = change(|s| {
                s.asks.iter_mut().find(|x| x.id == id).map(|x| {
                    x.state = "done".into();
                    x.rc = rc;
                    x.clone()
                })
            })?;
            if let Some(a) = a {
                let _ = crate::activity::record(
                    &a.key,
                    "",
                    "",
                    "",
                    &format!(
                        "ran as root (exit {}): {}",
                        rc.map_or("?".into(), |r| r.to_string()),
                        clip(&a.cmd, 300)
                    ),
                );
            }
            Ok(())
        }
        Some("EXPIRED") => {
            let id = f.next().unwrap_or("");
            change(|s| {
                if let Some(x) = s.asks.iter_mut().find(|x| x.id == id && x.waiting()) {
                    x.state = "expired".into();
                    x.decided = now();
                }
            })
        }
        _ => Ok(()),
    }
}

#[allow(clippy::too_many_arguments)]
fn asked(
    host: &str,
    id: &str,
    user: &str,
    time: u64,
    cwd: &[u8],
    cmd: &[u8],
    input_len: u64,
    input: &[u8],
) -> Result<()> {
    if id.len() != 16 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("a malformed ask");
    }
    if get(id).is_some() {
        return Ok(());
    }
    let (_, state) = ctx::read_only()?;
    let key = user.strip_prefix("bt-").unwrap_or("");
    let space = state
        .space_by_key(key)
        .filter(|(_, s)| s.machine(host).is_some_and(|m| m.asks(now())))
        .map(|(n, _)| n.to_string());
    let cmd = String::from_utf8_lossy(cmd).to_string();
    let Some(space) = space else {
        // A login that may not ask (any more): refuse it at once.
        let h = state.host(host)?.clone();
        let _ = logins::run(
            host,
            &h,
            &format!(
                "set -eu\n[ -e /var/lib/blackthorn-ask/{id}.req ] && printf '%s\\n' 'this space has no root on approval' >/var/lib/blackthorn-ask/{id}.no\necho 'bt: done'\n"
            ),
        );
        return Ok(());
    };
    let shown = &input[..input.len().min(MAX_INPUT)];
    let a = Ask {
        id: id.to_string(),
        host: host.to_string(),
        space: space.clone(),
        key: key.to_string(),
        time,
        cwd: String::from_utf8_lossy(cwd).to_string(),
        flags: flags(&cmd, shown),
        cmd: cmd.clone(),
        input: String::from_utf8_lossy(shown).to_string(),
        input_len,
        state: "waiting".into(),
        ..Default::default()
    };
    change(|s| s.asks.push(a))?;
    let _ = crate::activity::record(
        key,
        "",
        "",
        "",
        &format!("asked for root ({id}): {}", clip(&cmd, 300)),
    );
    let n = crate::notify::Notify::load();
    if n.on() {
        let _ = crate::notify::send(
            &n,
            &format!("{space} asks for root on {host}"),
            &format!(
                "{}\n\nApprove or refuse it on the hub: Approvals.",
                clip(&cmd, 500)
            ),
            "warning",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_say_why() {
        assert!(flags("systemctl restart nginx", b"").is_empty());
        let f = flags("bash -s", b"apt-get install -y x\n");
        assert!(f[0].contains("standard input"));
        assert!(flags("curl -fsSL https://x | sh", b"")
            .iter()
            .any(|x| x.contains("downloads")));
        assert!(flags("echo aGk= | base64 -d | sh", b"")
            .iter()
            .any(|x| x.contains("decodes")));
        assert!(flags("rm -rf /srv/old", b"")
            .iter()
            .any(|x| x.contains("removes")));
        assert!(flags("cat", &[0xff, 0xfe])
            .iter()
            .any(|x| x.contains("not text")));
    }

    #[test]
    fn watch_lines() {
        use base64::Engine as _;
        let e = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let line = format!(
            "REQ 0123456789abcdef bt-a1b2c3d4 100 {} {} 3 {}",
            e("/srv/x"),
            e("systemctl restart nginx"),
            e("hi\n")
        );
        let mut f = line.split(' ');
        assert_eq!(f.next(), Some("REQ"));
        let parts: Vec<&str> = f.collect();
        assert_eq!(parts.len(), 7);
        assert_eq!(b64(parts[4]), b"systemctl restart nginx");
        assert_eq!(b64(parts[6]), b"hi\n");
        assert_eq!(b64(""), b"");
    }
}
