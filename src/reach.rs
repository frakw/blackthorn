//! Whether the hub reaches each machine: once a minute (from `thorn _tick`)
//! root opens a connection to its SSH port and waits for the server's
//! greeting, then says its own and hangs up, so the machine logs a plain
//! "connection closed [preauth]" (not a failed login, nor a missing
//! greeting, which some fail2ban filters count). No login is made.
//!
//! Results go to /var/lib/blackthorn/reach.json, for the overview.

use crate::paths;
use crate::state::{now, State};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// How long a machine may take to connect and to greet.
const TIMEOUT: Duration = Duration::from_secs(5);

/// A result older than this is not trusted (the tick stopped).
pub const STALE: u64 = 5 * 60;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Reach {
    /// When it was checked, Unix seconds.
    pub at: u64,
    pub ok: bool,
    /// Why not, in words; empty when it is reached.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub why: String,
}

/// Connects to an SSH server and reads its greeting.
pub fn probe(addr: SocketAddr) -> Result<(), String> {
    let mut s = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| match e.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            "no answer (timed out)".to_string()
        }
        std::io::ErrorKind::ConnectionRefused => "connection refused".to_string(),
        _ => e.to_string(),
    })?;
    let _ = s.set_read_timeout(Some(TIMEOUT));
    let _ = s.set_write_timeout(Some(TIMEOUT));
    let mut buf = [0u8; 256];
    let mut got = Vec::new();
    while !got.windows(4).any(|w| w == b"SSH-") || !got.contains(&b'\n') {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
        if got.len() > 4096 {
            break;
        }
    }
    if !got.windows(4).any(|w| w == b"SSH-") {
        return Err(if got.is_empty() {
            "connected, but no SSH greeting".into()
        } else {
            "something other than SSH answers there".into()
        });
    }
    let _ = s.write_all(b"SSH-2.0-blackthorn-check\r\n");
    Ok(())
}

/// Checks every machine, at the same time, and records the results.
pub fn tick(state: &State) {
    let t = now();
    let checks: Vec<_> = state
        .hosts
        .iter()
        .map(|(name, h)| {
            let addr = SocketAddr::new(h.address, h.port);
            (name.clone(), std::thread::spawn(move || probe(addr)))
        })
        .collect();
    let results: BTreeMap<String, Reach> = checks
        .into_iter()
        .map(|(name, j)| {
            let r = j.join().unwrap_or_else(|_| Err("the check failed".into()));
            let reach = Reach {
                at: t,
                ok: r.is_ok(),
                why: r.err().unwrap_or_default(),
            };
            (name, reach)
        })
        .collect();
    if let Err(e) = save(&results) {
        eprintln!("reach: {e:#}");
    }
}

fn save(r: &BTreeMap<String, Reach>) -> anyhow::Result<()> {
    let tmp = format!("{}.tmp", paths::REACH_FILE);
    std::fs::write(&tmp, serde_json::to_vec(r)?)?;
    std::fs::rename(&tmp, paths::REACH_FILE)?;
    Ok(())
}

/// The last results, by machine.
pub fn load() -> BTreeMap<String, Reach> {
    std::fs::read(paths::REACH_FILE)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Whether a space reaches its machine now, and why (not): from the last
/// check, the firewall and its login there.
pub fn link(reach: Option<&Reach>, blocked: Option<&str>, login: &str, now: u64) -> (bool, String) {
    if let Some(b) = blocked {
        return (false, format!("cut off from its machine: {b}"));
    }
    if login.is_empty() {
        return (false, "no login on its machine".into());
    }
    match reach {
        None => (false, "not checked yet".into()),
        Some(r) if now.saturating_sub(r.at) > STALE => (
            false,
            "not checked for a while (is the hub's tick running?)".into(),
        ),
        Some(r) if !r.ok => (false, format!("its machine does not answer: {}", r.why)),
        Some(_) => (true, format!("reaches its machine as {login}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn reads_an_ssh_greeting() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            c.write_all(b"SSH-2.0-OpenSSH_9.2\r\n").unwrap();
            let mut b = [0u8; 64];
            let n = c.read(&mut b).unwrap();
            String::from_utf8_lossy(&b[..n]).to_string()
        });
        assert_eq!(probe(addr), Ok(()));
        assert!(srv.join().unwrap().starts_with("SSH-2.0-blackthorn-check"));
    }

    #[test]
    fn refuses_what_is_not_ssh() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            c.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").unwrap();
        });
        assert!(probe(addr).is_err());
    }

    #[test]
    fn says_why_a_space_is_not_linked() {
        let ok = Reach {
            at: 100,
            ok: true,
            why: String::new(),
        };
        assert!(link(Some(&ok), None, "bt-1", 110).0);
        assert!(!link(Some(&ok), Some("BLOCKED for 5m"), "bt-1", 110).0);
        assert!(!link(Some(&ok), None, "", 110).0);
        assert!(!link(Some(&ok), None, "bt-1", 100 + STALE + 1).0);
        assert!(!link(None, None, "bt-1", 110).0);
        let down = Reach {
            at: 100,
            ok: false,
            why: "connection refused".into(),
        };
        assert!(link(Some(&down), None, "bt-1", 110).1.contains("refused"));
    }
}
