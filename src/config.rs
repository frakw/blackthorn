//! /etc/blackthorn/config.toml: settings an administrator edits by hand.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// The Claude Code binary every space runs. Spaces do not update it
    /// themselves; replace it with `thorn init --claude-from <path>`.
    pub claude_bin: PathBuf,
    /// Arguments added to every Claude Code start, before per-space ones.
    pub claude_args: Vec<String>,
    /// Most chats one server-mode space runs at once.
    pub capacity: u32,
    /// This hub's addresses as managed machines see them. Used for the
    /// `from="..."` option of the authorized_keys line, so a stolen key is
    /// useless from anywhere else. Empty: ask tailscale, if installed.
    pub ssh_from: Vec<IpAddr>,
    /// Machines blackthorn must never manage, such as the server that runs
    /// your tailnet's control plane or your password manager. `thorn host
    /// add` refuses them and the hub drops connections from them.
    pub never_manage: Vec<IpAddr>,
    pub egress: Egress,
    pub inbound: Inbound,
    pub web: Web,
    /// Agents other than Claude Code, run in a terminal only:
    /// [agents.aider] bin = "/usr/local/bin/aider".
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub agents: BTreeMap<String, Agent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Egress {
    /// Allow spaces to open HTTPS (TCP 443) connections to any address.
    /// Claude Code needs to reach Anthropic; their addresses are not fixed,
    /// so the default is true. See THREAT_MODEL.md.
    pub https_anywhere: bool,
    /// DNS servers spaces may query. Empty means: the nameservers listed
    /// in /etc/resolv.conf when the firewall is applied.
    pub dns: Vec<IpAddr>,
}

/// Connections into the hub. Managed machines are always refused.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Inbound {
    /// The hub's SSH port, an admin port like the web UI's.
    pub ssh_port: u16,
    /// If not empty, only these addresses (your own devices) may connect to
    /// the admin ports: SSH and the web UI.
    pub admin_from: Vec<IpAddr>,
    /// Extra addresses whose connections are always dropped.
    pub deny_from: Vec<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Web {
    /// Where the web UI listens, e.g. ["100.64.0.10:7180"] (the hub's
    /// tailnet address). Empty: the web UI is off.
    pub listen: Vec<SocketAddr>,
    /// HTTPS (needed for passkeys): the name the web UI is reached by, such
    /// as "blackthorn.example.com", which its certificate is for.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The certificate chain and key (PEM), e.g. from certbot. Read again
    /// when they change, so renewing them is enough.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<PathBuf>,
    /// Or: get the certificate from Tailscale (`tailscale cert`; needs
    /// Tailscale's own coordination server with HTTPS on, not Headscale).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub tls_tailscale: bool,
    /// How long a web login lasts, in hours, however busy. A chat unlocked
    /// for typing stays so as long.
    pub session_hours: u32,
    /// A web login also ends after `idle_minutes` without use.
    pub idle_logout: bool,
    pub idle_minutes: u32,
}

impl Default for Web {
    fn default() -> Self {
        Web {
            listen: Vec::new(),
            name: String::new(),
            tls_cert: None,
            tls_key: None,
            tls_tailscale: false,
            session_hours: 24,
            idle_logout: true,
            idle_minutes: 30,
        }
    }
}

impl Web {
    /// Served over HTTPS.
    pub fn https(&self) -> bool {
        !self.name.is_empty()
            && (self.tls_tailscale || (self.tls_cert.is_some() && self.tls_key.is_some()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    pub bin: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    /// The file the agent reads its instructions from, in its work directory.
    #[serde(default = "default_instructions")]
    pub instructions: String,
}

fn default_instructions() -> String {
    "AGENTS.md".into()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            claude_bin: PathBuf::from("/usr/local/bin/claude"),
            claude_args: Vec::new(),
            capacity: 8,
            ssh_from: Vec::new(),
            never_manage: Vec::new(),
            egress: Egress::default(),
            inbound: Inbound::default(),
            web: Web::default(),
            agents: BTreeMap::new(),
        }
    }
}

impl Default for Inbound {
    fn default() -> Self {
        Inbound {
            ssh_port: 22,
            admin_from: Vec::new(),
            deny_from: Vec::new(),
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

/// Built-in and configured agents.
pub const CLAUDE: &str = "claude";

impl Config {
    pub fn agent_exists(&self, name: &str) -> bool {
        name == CLAUDE || self.agents.contains_key(name)
    }

    /// The file an agent reads its instructions from.
    pub fn instructions_file(&self, agent: &str) -> String {
        match self.agents.get(agent) {
            Some(a) if agent != CLAUDE => a.instructions.clone(),
            _ => "CLAUDE.md".into(),
        }
    }

    pub fn agent_names(&self) -> Vec<String> {
        let mut v = vec![CLAUDE.to_string()];
        v.extend(self.agents.keys().filter(|k| *k != CLAUDE).cloned());
        v
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

    /// The first config file, with the web UI listening on `listen`.
    pub fn default_text(listen: &[SocketAddr]) -> String {
        let cfg = Config {
            web: Web {
                listen: listen.to_vec(),
                ..Web::default()
            },
            ..Config::default()
        };
        let body = toml::to_string_pretty(&cfg).expect("default config serializes");
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
        let text = Config::default_text(&[]);
        let parsed: Config = toml::from_str(&text).unwrap();
        assert_eq!(parsed, Config::default());
        let listen: SocketAddr = "0.0.0.0:7180".parse().unwrap();
        let parsed: Config = toml::from_str(&Config::default_text(&[listen])).unwrap();
        assert_eq!(parsed.web.listen, vec![listen]);
    }

    #[test]
    fn partial_config_uses_defaults() {
        let c: Config = toml::from_str("[egress]\nhttps_anywhere = false\n").unwrap();
        assert!(!c.egress.https_anywhere);
        assert_eq!(c.claude_bin, PathBuf::from("/usr/local/bin/claude"));
    }

    #[test]
    fn agents_and_inbound() {
        let c: Config = toml::from_str(
            "never_manage = [\"100.64.0.4\"]\n[inbound]\nadmin_from = [\"100.64.0.2\"]\n\
             [web]\nlisten = [\"100.64.0.10:7180\"]\n\
             [agents.aider]\nbin = \"/usr/local/bin/aider\"\n",
        )
        .unwrap();
        assert!(c.agent_exists("claude"));
        assert!(c.agent_exists("aider"));
        assert!(!c.agent_exists("codex"));
        assert_eq!(c.instructions_file("aider"), "AGENTS.md");
        assert_eq!(c.instructions_file("claude"), "CLAUDE.md");
        assert_eq!(c.agent_names(), vec!["claude", "aider"]);
        assert_eq!(c.web.listen[0].port(), 7180);
        assert_eq!(c.inbound.admin_from.len(), 1);
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
