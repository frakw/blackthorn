//! thorn: the command-line interface of blackthorn.

mod apply;
mod config;
mod ctx;
mod firewall;
mod host_cmd;
mod init_cmd;
mod keys;
mod paths;
mod render;
mod runner;
mod session_cmd;
mod state;
mod sys;
mod units;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "thorn",
    version,
    about = "blackthorn: keep Claude Code sessions running on an isolated hub, each able to reach only the hosts you grant it.",
    after_help = "Most commands change system state and must run as root (sudo thorn ...)."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up this machine: directories, systemd units, firewall.
    Init {
        /// Copy this Claude Code binary to where sessions run it from
        /// (e.g. ~/.local/bin/claude). Run again to update Claude Code.
        #[arg(long, value_name = "PATH")]
        claude_from: Option<PathBuf>,
    },
    /// Overview: firewall, sessions, blocked hosts.
    Status,
    /// List sessions.
    Ls,
    /// Create a session.
    New {
        name: String,
        /// Hosts it may reach (comma-separated or repeated).
        #[arg(long = "host", value_delimiter = ',')]
        hosts: Vec<String>,
        /// Name shown in Remote Control (default: the session name).
        #[arg(long)]
        rc_name: Option<String>,
        /// Extra argument for claude, e.g. --arg=--permission-mode --arg=acceptEdits.
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Sign a session in to Claude, then start it.
    Login { name: String },
    /// Delete a session (its conversation is archived unless --purge).
    Rm {
        name: String,
        #[arg(long)]
        purge: bool,
    },
    /// Rename a session (and its Remote Control name, if it was the default).
    Rename {
        old: String,
        new: String,
        #[arg(long)]
        rc_name: Option<String>,
    },
    /// Start sessions.
    Start {
        names: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Stop sessions.
    Stop {
        names: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Restart sessions (to pick up a new CLAUDE.md or Claude Code version).
    Restart {
        names: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Open a session's terminal. Leave with Ctrl-b then d.
    Attach { name: String },
    /// Let a session reach hosts.
    Grant {
        session: String,
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    /// Stop a session from reaching hosts.
    Revoke {
        session: String,
        #[arg(required = true)]
        hosts: Vec<String>,
    },
    /// Manage the machines sessions can reach.
    #[command(subcommand)]
    Host(HostCmd),
    /// Show or reload the session firewall.
    #[command(subcommand)]
    Firewall(FirewallCmd),
    /// Rewrite every generated file and reload the firewall.
    Apply,

    #[command(name = "_run", hide = true)]
    Run { key: String },
    #[command(name = "_load-keys", hide = true)]
    LoadKeys { key: String },
    #[command(name = "_tick", hide = true)]
    Tick,
}

#[derive(Subcommand)]
enum HostCmd {
    /// Register a machine, e.g. `thorn host add fig root@100.80.0.3`.
    Add {
        name: String,
        /// user@address (an IP address, e.g. its tailnet address).
        target: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Accept the host keys without asking (only if you have compared the fingerprints).
        #[arg(long)]
        yes: bool,
    },
    /// Forget a machine and revoke it from every session.
    Rm { name: String },
    /// List machines.
    Ls,
    /// Cut every session off from a machine, now.
    Block {
        name: String,
        /// Lift the block automatically after this long (30m, 2h, 1d).
        #[arg(long = "for", value_name = "DURATION")]
        duration: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Lift a block.
    Unblock { name: String },
    /// Print the authorized_keys line to install on the machine.
    Pubkey { name: String },
    /// Check that blackthorn can log in to the machine.
    Check { name: String },
    /// Re-read the machine's host keys (after reinstalling it).
    Rescan {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum FirewallCmd {
    /// Reload the rules from the current state.
    Apply,
    /// Print the rules loaded in the kernel (or --planned: what apply would load).
    Show {
        #[arg(long)]
        planned: bool,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("thorn: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    use session_cmd as s;
    match cli.cmd {
        Cmd::Init { claude_from } => init_cmd::init(claude_from),
        Cmd::Status => init_cmd::status(),
        Cmd::Ls => s::ls(),
        Cmd::New {
            name,
            hosts,
            rc_name,
            args,
        } => s::new(s::NewOpts {
            name,
            hosts,
            rc_name,
            args,
        }),
        Cmd::Login { name } => s::login(&name),
        Cmd::Rm { name, purge } => s::rm(&name, purge),
        Cmd::Rename { old, new, rc_name } => s::rename(&old, &new, rc_name),
        Cmd::Start { names, all } => s::control("start", &names, all),
        Cmd::Stop { names, all } => s::control("stop", &names, all),
        Cmd::Restart { names, all } => s::control("restart", &names, all),
        Cmd::Attach { name } => s::attach(&name),
        Cmd::Grant { session, hosts } => s::grant(&session, &hosts, false),
        Cmd::Revoke { session, hosts } => s::grant(&session, &hosts, true),
        Cmd::Host(h) => match h {
            HostCmd::Add {
                name,
                target,
                port,
                yes,
            } => host_cmd::add(&name, &target, port, yes),
            HostCmd::Rm { name } => host_cmd::rm(&name),
            HostCmd::Ls => host_cmd::ls(),
            HostCmd::Block {
                name,
                duration,
                reason,
            } => host_cmd::block(&name, duration.as_deref(), reason),
            HostCmd::Unblock { name } => host_cmd::unblock(&name),
            HostCmd::Pubkey { name } => host_cmd::pubkey(&name),
            HostCmd::Check { name } => host_cmd::check(&name),
            HostCmd::Rescan { name, yes } => host_cmd::rescan(&name, yes),
        },
        Cmd::Firewall(f) => match f {
            FirewallCmd::Apply => init_cmd::firewall_apply(),
            FirewallCmd::Show { planned } => init_cmd::firewall_show(planned),
        },
        Cmd::Apply => init_cmd::apply_all(),
        Cmd::Run { key } => runner::run(&key),
        Cmd::LoadKeys { key } => init_cmd::load_keys(&key),
        Cmd::Tick => init_cmd::tick(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn new_accepts_hosts_and_claude_args() {
        let cli = Cli::try_parse_from([
            "thorn",
            "new",
            "ops",
            "--host",
            "fig,nas",
            "--host",
            "cypress",
            "--arg=--permission-mode",
            "--arg",
            "acceptEdits",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::New { hosts, args, .. } => {
                assert_eq!(hosts, vec!["fig", "nas", "cypress"]);
                assert_eq!(args, vec!["--permission-mode", "acceptEdits"]);
            }
            _ => panic!("wrong command"),
        }
    }
}
