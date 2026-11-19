//! HTTPS for the web UI: where its certificate comes from, read by root and
//! handed to the unprivileged web process through the API socket.
//!
//! Two sources, set in config.toml's [web] (or `thorn web https`):
//! - files you keep up to date, e.g. certbot with a DNS challenge, which
//!   works for a hub that is reachable only inside your tailnet;
//! - `tailscale cert`, with Tailscale's own coordination server.

use crate::config::{Config, Web};
use crate::{paths, sys};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Material {
    pub name: String,
    pub cert: String,
    pub key: String,
}

fn tailscale_paths() -> (PathBuf, PathBuf) {
    let d = Path::new(paths::TLS_DIR);
    (d.join("cert.pem"), d.join("key.pem"))
}

/// The files in use (for Tailscale, the ones blackthorn keeps).
pub fn files(web: &Web) -> Option<(PathBuf, PathBuf)> {
    if !web.https() {
        return None;
    }
    if web.tls_tailscale {
        return Some(tailscale_paths());
    }
    Some((web.tls_cert.clone()?, web.tls_key.clone()?))
}

/// The certificate and key, or None for plain HTTP.
pub fn material(cfg: &Config) -> Result<Option<Material>> {
    let Some((cert, key)) = files(&cfg.web) else {
        return Ok(None);
    };
    if cfg.web.tls_tailscale && !cert.exists() {
        tailscale_cert(&cfg.web.name)?;
    }
    Ok(Some(Material {
        name: cfg.web.name.clone(),
        cert: std::fs::read_to_string(&cert)
            .with_context(|| format!("reading {}", cert.display()))?,
        key: std::fs::read_to_string(&key).with_context(|| format!("reading {}", key.display()))?,
    }))
}

/// Asks Tailscale for a certificate for `name` (it renews only when due).
pub fn tailscale_cert(name: &str) -> Result<()> {
    sys::mkdir(Path::new(paths::TLS_DIR), 0o700)?;
    let (cert, key) = tailscale_paths();
    sys::run(
        "tailscale",
        &[
            "cert",
            "--cert-file",
            cert.to_str().context("path")?,
            "--key-file",
            key.to_str().context("path")?,
            name,
        ],
    )
    .context(
        "tailscale cert failed: it needs Tailscale's own coordination server with MagicDNS \
         and HTTPS turned on in its admin console (Headscale cannot issue certificates)",
    )
}

/// From `thorn _tick`: keep a Tailscale certificate fresh (checked daily).
pub fn tick(cfg: &Config) {
    if !cfg.web.https() || !cfg.web.tls_tailscale {
        return;
    }
    let (cert, _) = tailscale_paths();
    let fresh = std::fs::metadata(&cert)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|m| SystemTime::now().duration_since(m).ok())
        .is_some_and(|age| age < Duration::from_secs(86_400));
    if !fresh {
        if let Err(e) = tailscale_cert(&cfg.web.name) {
            eprintln!("{e:#}");
        } else {
            // Touch it so the check waits another day even when nothing
            // was renewed.
            let _ = std::fs::File::options()
                .append(true)
                .open(&cert)
                .and_then(|f| f.set_modified(SystemTime::now()));
        }
    }
}

/// The origins pages come from (for passkeys): https://name:port for each
/// port the web UI listens on.
pub fn origins(web: &Web) -> Vec<String> {
    let mut out = Vec::new();
    for a in &web.listen {
        let o = if a.port() == 443 {
            format!("https://{}", web.name)
        } else {
            format!("https://{}:{}", web.name, a.port())
        };
        if !out.contains(&o) {
            out.push(o);
        }
    }
    out
}

/// The web UI's address(es) to open.
pub fn urls(web: &Web) -> Vec<String> {
    if web.https() {
        origins(web).into_iter().map(|o| format!("{o}/")).collect()
    } else {
        web.listen.iter().map(|a| format!("http://{a}/")).collect()
    }
}

/// The hub's own tailnet name (MagicDNS), for `thorn web https --tailscale`.
pub fn tailscale_name() -> Result<String> {
    let out = sys::output("tailscale", &["status", "--json"])?;
    let v: serde_json::Value = serde_json::from_str(&out)?;
    let name = v["Self"]["DNSName"]
        .as_str()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_string();
    if name.is_empty() {
        bail!("Tailscale reports no DNS name for this machine (is MagicDNS on?)");
    }
    Ok(name)
}

/// A host name a certificate can be for.
pub fn check_name(name: &str) -> Result<()> {
    let ok = name.len() <= 253
        && name.contains('.')
        && name.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && name.parse::<std::net::IpAddr>().is_err();
    if !ok {
        bail!("{name:?} is not a host name (passkeys need a name such as blackthorn.example.com, not an IP address)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_origins() {
        assert!(check_name("blackthorn.example.com").is_ok());
        assert!(check_name("hub.tail1234.ts.net").is_ok());
        assert!(check_name("100.64.0.10").is_err());
        assert!(check_name("localhost").is_err());
        assert!(check_name("bad_name.example.com").is_err());
        let web = Web {
            listen: vec![
                "100.64.0.10:7180".parse().unwrap(),
                "[fd7a::1]:7180".parse().unwrap(),
            ],
            name: "hub.example.com".into(),
            tls_tailscale: true,
            ..Web::default()
        };
        assert!(web.https());
        assert_eq!(origins(&web), vec!["https://hub.example.com:7180"]);
        assert_eq!(urls(&web), vec!["https://hub.example.com:7180/"]);
        let plain = Web {
            listen: vec!["100.64.0.10:7180".parse().unwrap()],
            ..Web::default()
        };
        assert!(!plain.https());
        assert_eq!(urls(&plain), vec!["http://100.64.0.10:7180/"]);
    }
}
