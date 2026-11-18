//! /etc/blackthorn/config.toml: settings an administrator edits by hand.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The Claude Code binary every session runs. Sessions do not update it
    /// themselves; replace it with `thorn init --claude-from <path>`.
    pub claude_bin: PathBuf,
    /// Arguments added to every `claude` invocation, before per-session ones.
    pub claude_args: Vec<String>,
    pub egress: Egress,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Egress {
    /// Allow sessions to open HTTPS (TCP 443) connections to any address.
    /// Claude Code needs to reach Anthropic; their addresses are not fixed,
    /// so the default is true. See THREAT_MODEL.md.
    pub https_anywhere: bool,
    /// DNS servers sessions may query. Empty means: the nameservers listed
    /// in /etc/resolv.conf when the firewall is applied.
    pub dns: Vec<IpAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            claude_bin: PathBuf::from("/usr/local/bin/claude"),
            claude_args: Vec::new(),
            egress: Egress::default(),
        }
    }
}

impl Default for Egress {
    fn default() -> Self {
        Egress {
            https_anywhere: true,
            dns: Vec::new(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("reading {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn default_text() -> String {
        let body = toml::to_string_pretty(&Config::default()).expect("default config serializes");
        format!(
            "# blackthorn configuration. See README.md for every option.\n\
             # Run `thorn apply` after editing.\n\n{body}"
        )
    }
}

/// Nameservers from resolv.conf text.
pub fn parse_resolv_conf(text: &str) -> Vec<IpAddr> {
    text.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            match (it.next(), it.next()) {
                (Some("nameserver"), Some(addr)) => {
                    // Drop a zone suffix such as fe80::1%eth0.
                    addr.split('%').next().and_then(|a| a.parse().ok())
                }
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_round_trips() {
        let text = Config::default_text();
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed, Config::default());
    }

    #[test]
    fn partial_config_uses_defaults() {
        let c: Config = toml::from_str("[egress]\nhttps_anywhere = false\n").unwrap();
        assert!(!c.egress.https_anywhere);
        assert_eq!(c.claude_bin, PathBuf::from("/usr/local/bin/claude"));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(toml::from_str::<Config>("claude_bni = \"/x\"\n").is_err());
    }

    #[test]
    fn resolv_conf() {
        let text = "# comment\nnameserver 100.100.100.100\nsearch x\nnameserver fe80::1%eth0\nnameserver bogus\n";
        let got = parse_resolv_conf(text);
        assert_eq!(
            got,
            vec![
                "100.100.100.100".parse::<IpAddr>().unwrap(),
                "fe80::1".parse::<IpAddr>().unwrap()
            ]
        );
    }
}
