//! SSH keys: one key pair per host, kept by root, handed to spaces only
//! through their ssh-agent.

use crate::paths;
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::process::{Command, Stdio};

pub fn generate(host: &str) -> Result<()> {
    keygen(
        &paths::key_file(host),
        &format!("blackthorn@{}:{host}", crate::sys::hostname()),
    )
}

/// A space's own two keys: its user (and root) login and its read-only
/// one, for the machines set up for logins of each space's own.
pub fn generate_space(key: &str) -> Result<()> {
    crate::sys::mkdir(Path::new(paths::SPACE_KEYS_DIR), 0o700)?;
    let hub = crate::sys::hostname();
    keygen(
        &paths::space_key_file(key),
        &format!("blackthorn@{hub}:space-{key}"),
    )?;
    keygen(
        &paths::space_ro_key_file(key),
        &format!("blackthorn@{hub}:space-{key}:readonly"),
    )
}

pub fn remove_space(key: &str) -> Result<()> {
    for p in [paths::space_key_file(key), paths::space_ro_key_file(key)] {
        for f in [p.clone(), p.with_extension("pub")] {
            match std::fs::remove_file(&f) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e).with_context(|| format!("removing {}", f.display())),
            }
        }
    }
    Ok(())
}

/// The public half of a key file.
pub fn public_of(file: &Path) -> Result<String> {
    let mut p = file.as_os_str().to_owned();
    p.push(".pub");
    read_public(Path::new(&p))
}

fn keygen(key: &Path, comment: &str) -> Result<()> {
    if key.exists() {
        return Ok(());
    }
    crate::sys::run(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            comment,
            "-f",
            key.to_str().context("key path")?,
        ],
    )
}

pub fn remove(host: &str) -> Result<()> {
    for p in [
        paths::key_file(host),
        paths::pubkey_file(host),
        paths::ro_key_file(host),
        paths::ro_pubkey_file(host),
    ] {
        match std::fs::remove_file(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", p.display())),
        }
    }
    Ok(())
}

pub fn public_key(host: &str) -> Result<String> {
    read_public(&paths::pubkey_file(host))
}

fn read_public(p: &Path) -> Result<String> {
    Ok(std::fs::read_to_string(p)
        .with_context(|| format!("reading {}", p.display()))?
        .trim()
        .to_string())
}

/// The line to put in the remote user's ~/.ssh/authorized_keys. `restrict`
/// turns off port, agent and X11 forwarding and pty allocation for this key;
/// `from` limits it to the hub's addresses, so a copy is useless elsewhere.
pub fn authorized_keys_line(host: &str, from: &[IpAddr]) -> Result<String> {
    Ok(key_line(&public_key(host)?, from))
}

pub fn key_line(public_key: &str, from: &[IpAddr]) -> String {
    if from.is_empty() {
        format!("restrict {public_key}")
    } else {
        let list: Vec<String> = from.iter().map(|a| a.to_string()).collect();
        format!("from=\"{}\",restrict {public_key}", list.join(","))
    }
}

/// The same, with blackthorn's logger as forced command: the machine
/// records every command run with this key (see `remote::LOGGER`).
pub fn logged_key_line(public_key: &str, from: &[IpAddr]) -> String {
    let line = key_line(public_key, from);
    let (opts, key) = line.split_once(' ').expect("options, then the key");
    format!("{opts},command=\"{}\" {key}", paths::REMOTE_LOGGER)
}

/// The host's public keys as "<type> <base64>", fetched with ssh-keyscan.
pub fn scan(addr: IpAddr, port: u16) -> Result<Vec<String>> {
    let out = Command::new("ssh-keyscan")
        .args([
            "-T",
            "5",
            "-p",
            &port.to_string(),
            "-t",
            "ed25519,ecdsa,rsa",
        ])
        .arg(addr.to_string())
        .stdin(Stdio::null())
        .output()
        .context("running ssh-keyscan")?;
    let keys = parse_keyscan(&String::from_utf8_lossy(&out.stdout));
    if keys.is_empty() {
        bail!(
            "could not read the SSH host keys of {addr} port {port}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(keys)
}

pub fn parse_keyscan(text: &str) -> Vec<String> {
    let mut keys: Vec<String> = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let _host = f.next()?;
            let kind = f.next()?;
            let b64 = f.next()?;
            Some(format!("{kind} {b64}"))
        })
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// "SHA256:... (ED25519)" for each host key, for you to compare with the
/// fingerprints the remote host prints (ssh-keygen -lf /etc/ssh/ssh_host_*.pub).
pub fn fingerprints(host_keys: &[String]) -> Result<Vec<String>> {
    let mut child = Command::new("ssh-keygen")
        .args(["-l", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running ssh-keygen")?;
    {
        let mut stdin = child.stdin.take().expect("piped");
        for k in host_keys {
            writeln!(stdin, "{k}")?;
        }
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "ssh-keygen -l failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            // "256 SHA256:abc no comment (ED25519)"
            let mut f = l.split_whitespace();
            let _bits = f.next()?;
            let fp = f.next()?;
            let kind = l.rsplit(' ').next()?;
            Some(format!("{fp} {kind}"))
        })
        .collect())
}

/// Replaces everything in a space's agent with these keys. Does nothing
/// if the agent is not running.
pub fn sync_agent(key: &str, files: &[std::path::PathBuf]) -> Result<()> {
    let sock = paths::agent_socket(key);
    if !sock.exists() {
        return Ok(());
    }
    ssh_add(&sock, &["-D"]).or_else(|e| {
        // "The agent has no identities" is not an error worth stopping for.
        if e.to_string().contains("no identities") {
            Ok(())
        } else {
            Err(e)
        }
    })?;
    for file in files {
        if file.exists() {
            ssh_add(&sock, &[file.to_str().context("key path")?])?;
        }
    }
    Ok(())
}

fn ssh_add(sock: &Path, args: &[&str]) -> Result<()> {
    let out = Command::new("ssh-add")
        .args(args)
        .env("SSH_AUTH_SOCK", sock)
        .stdin(Stdio::null())
        .output()
        .context("running ssh-add")?;
    if !out.status.success() {
        bail!(
            "ssh-add {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Waits for an agent socket to appear (the agent unit's ExecStartPost runs
/// right after ssh-agent is started).
pub fn wait_for_socket(key: &str) -> Result<()> {
    let sock = paths::agent_socket(key);
    for _ in 0..50 {
        if sock.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    bail!("ssh-agent socket {} did not appear", sock.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_lines() {
        assert_eq!(
            key_line("ssh-ed25519 AAAA c", &[]),
            "restrict ssh-ed25519 AAAA c"
        );
        let from = ["100.64.0.10".parse().unwrap(), "fd7a::a".parse().unwrap()];
        assert_eq!(
            key_line("ssh-ed25519 AAAA c", &from),
            "from=\"100.64.0.10,fd7a::a\",restrict ssh-ed25519 AAAA c"
        );
        assert_eq!(
            logged_key_line("ssh-ed25519 AAAA c", &from[..1]),
            "from=\"100.64.0.10\",restrict,command=\"/usr/local/libexec/blackthorn-ssh\" ssh-ed25519 AAAA c"
        );
    }

    #[test]
    fn keyscan_output() {
        let text = "# 100.80.0.3:22 SSH-2.0-OpenSSH_9.2\n\
                    100.80.0.3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n\
                    [100.80.0.3]:2222 ecdsa-sha2-nistp256 AAAAE2Vj\n\
                    100.80.0.3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA\n";
        assert_eq!(
            parse_keyscan(text),
            vec![
                "ecdsa-sha2-nistp256 AAAAE2Vj".to_string(),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA".to_string()
            ]
        );
    }
}
