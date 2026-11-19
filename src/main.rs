//! thorn: the command-line interface of blackthorn.

mod api;
mod apply;
mod config;
mod ctx;
mod firewall;
mod harden;
mod host_cmd;
mod http;
mod init_cmd;
mod keys;
mod map;
mod ops;
mod paths;
mod render;
mod runner;
mod space_cmd;
mod state;
mod sys;
mod units;
mod view_cmd;
mod web;
mod web_cmd;
mod webauth;

use anyhow::Result;
use clap::{Parser, Subcommand};
use ops::Action;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "thorn",
    version,
    about = "blackthorn: an isolated hub where AI agents work on your machines over SSH, one way only.",
    after_help = "Most commands change system state and must run as root (sudo thorn ...).\n\
                  Everything here is also in the web UI (thorn web), and the other way round."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set up this machine: directories, systemd units, firewall.
    Init {
        /// Copy this Claude Code binary to where spaces run it from
        /// (e.g. ~/.local/bin/claude). Run again to update Claude Code.
        #[arg(long, value_name = "PATH")]
        claude_from: Option<PathBuf>,
        /// On a first install, leave the web UI off (turn it on later with
        /// `thorn web enable`).
        #[arg(long)]
        no_web: bool,
    },
    /// The hub at a glance: machines, their spaces, bridges.
    Status {
        /// Machine-readable.
        #[arg(long)]
        json: bool,
    },
    /// List spaces.
    Ls,
    /// Create a space: one machine worked on by one agent.
    New {
        /// The machine it works on.
        host: String,
        /// claude (default) or an agent from config.toml.
        #[arg(long)]
        agent: Option<String>,
        /// Default: <host>-<agent>.
        #[arg(long)]
        name: Option<String>,
        /// Claude: one conversation you can also type into on the terminal,
        /// instead of a Remote Control server with many chats.
        #[arg(long)]
        single: bool,
        /// Name shown in Remote Control (default: the space name).
        #[arg(long)]
        rc_name: Option<String>,
        /// Extra argument for the agent, e.g. --arg=--permission-mode --arg=acceptEdits.
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Sign a Claude space in, then start it.
    Login { name: String },
    /// Delete a space (its files are archived unless --purge).
    Rm {
        name: String,
        #[arg(long)]
        purge: bool,
    },
    /// Rename a space (and its Remote Control name, if it was the default).
    Rename {
        old: String,
        new: String,
        #[arg(long)]
        rc_name: Option<String>,
    },
    /// Start spaces.
    Start {
        names: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Stop spaces.
    Stop {
        names: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Restart spaces (to pick up new instructions or a new Claude Code).
    Restart {
        names: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Open a space's terminal. Leave with Ctrl-b then d.
    Attach { name: String },
    /// Print what a space's terminal shows.
    Screen { name: String },
    /// Type into a space's terminal (a line, followed by Enter), or press a key.
    Send {
        name: String,
        text: Option<String>,
        /// Enter, Escape, C-c, Up, Down, Tab or BSpace.
        #[arg(long)]
        key: Option<String>,
        /// Type the text without pressing Enter.
        #[arg(long)]
        no_enter: bool,
    },
    /// Let one space reach another space's machine for a while.
    #[command(subcommand)]
    Bridge(BridgeCmd),
    /// Manage the machines spaces work on.
    #[command(subcommand)]
    Host(HostCmd),
    /// The web UI and its accounts.
    #[command(subcommand)]
    Web(WebCmd),
    /// Two-factor SSH logins to this hub.
    #[command(subcommand)]
    Harden(HardenCmd),
    /// Show or reload the firewall.
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
    #[command(name = "_api", hide = true)]
    Api,
    #[command(name = "_web", hide = true)]
    WebServe,
    #[command(name = "_totp", hide = true)]
    Totp { secret: String },
}

#[derive(Subcommand)]
enum BridgeCmd {
    /// `thorn bridge add fig-claude nas-claude`: fig-claude may also reach nas.
    Add {
        from: String,
        to: String,
        /// How long (30m, 2h, 1d). Default 1h.
        #[arg(long = "for", value_name = "DURATION")]
        duration: Option<String>,
        /// Until removed.
        #[arg(long, conflicts_with = "duration")]
        permanent: bool,
    },
    /// End a bridge now.
    Rm { from: String, to: String },
    /// List bridges.
    Ls,
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
    /// Forget a machine (delete its spaces first).
    Rm { name: String },
    /// List machines.
    Ls,
    /// Cut every space off from a machine, now.
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
    /// Check that blackthorn can log in, and learn the machine's OS.
    Check { name: String },
    /// Re-read the machine's host keys (after reinstalling it).
    Rescan {
        name: String,
        #[arg(long)]
        yes: bool,
    },
    /// Give a machine a new address, login or port, e.g. its tailnet IP
    /// instead of its LAN one. Its spaces stay.
    SetAddress {
        name: String,
        /// user@address
        target: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// Accept the host keys without asking (only if you have compared the fingerprints).
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum WebCmd {
    /// Start the web UI (and at every boot).
    Enable,
    /// Stop the web UI.
    Disable,
    /// Web UI accounts.
    #[command(subcommand)]
    User(WebUserCmd),
}

#[derive(Subcommand)]
enum WebUserCmd {
    /// Add an account: password plus authenticator app.
    Add {
        name: String,
        #[arg(long, hide = true)]
        totp_secret: Option<String>,
    },
    /// Remove an account.
    Rm { name: String },
    /// List accounts.
    Ls,
    /// Change an account's password.
    Passwd { name: String },
    /// Set up a new authenticator app (and new recovery codes).
    TotpReset { name: String },
}

#[derive(Subcommand)]
enum HardenCmd {
    /// Require a second factor for SSH logins; undone automatically unless confirmed.
    Ssh {
        /// Key plus a code from an authenticator app.
        #[arg(long)]
        totp: bool,
        /// A FIDO2 hardware key (ed25519-sk).
        #[arg(long)]
        fido: bool,
        /// The admin account (default: the one running sudo).
        #[arg(long)]
        user: Option<String>,
        /// Undo unless confirmed within this long.
        #[arg(long, default_value = "5m")]
        rollback_after: String,
        #[arg(long, hide = true)]
        totp_secret: Option<String>,
    },
    /// Keep the new SSH settings.
    Confirm,
    /// Restore the SSH settings from before.
    Undo,
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
    use space_cmd as s;
    match cli.cmd {
        Cmd::Init {
            claude_from,
            no_web,
        } => init_cmd::init(init_cmd::InitOpts {
            claude_from,
            no_web,
        }),
        Cmd::Status { json } => view_cmd::status(json),
        Cmd::Ls => s::ls(),
        Cmd::New {
            host,
            agent,
            name,
            single,
            rc_name,
            args,
        } => s::new(ops::NewSpace {
            host,
            agent,
            name,
            single,
            rc_name,
            args,
        }),
        Cmd::Login { name } => s::login(&name),
        Cmd::Rm { name, purge } => s::rm(&name, purge),
        Cmd::Rename { old, new, rc_name } => s::rename(&old, &new, rc_name),
        Cmd::Start { names, all } => s::control(Action::Start, &names, all),
        Cmd::Stop { names, all } => s::control(Action::Stop, &names, all),
        Cmd::Restart { names, all } => s::control(Action::Restart, &names, all),
        Cmd::Attach { name } => s::attach(&name),
        Cmd::Screen { name } => s::screen(&name),
        Cmd::Send {
            name,
            text,
            key,
            no_enter,
        } => s::send(&name, text.as_deref(), key.as_deref(), no_enter),
        Cmd::Bridge(b) => match b {
            BridgeCmd::Add {
                from,
                to,
                duration,
                permanent,
            } => s::bridge_add(&from, &to, duration.as_deref(), permanent),
            BridgeCmd::Rm { from, to } => s::bridge_rm(&from, &to),
            BridgeCmd::Ls => s::bridge_ls(),
        },
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
            HostCmd::SetAddress {
                name,
                target,
                port,
                yes,
            } => host_cmd::set_address(&name, &target, port, yes),
        },
        Cmd::Web(w) => match w {
            WebCmd::Enable => web_cmd::enable(),
            WebCmd::Disable => web_cmd::disable(),
            WebCmd::User(u) => match u {
                WebUserCmd::Add { name, totp_secret } => web_cmd::user_add(&name, totp_secret),
                WebUserCmd::Rm { name } => web_cmd::user_rm(&name),
                WebUserCmd::Ls => web_cmd::user_ls(),
                WebUserCmd::Passwd { name } => web_cmd::user_passwd(&name),
                WebUserCmd::TotpReset { name } => web_cmd::user_totp_reset(&name),
            },
        },
        Cmd::Harden(h) => match h {
            HardenCmd::Ssh {
                totp,
                fido,
                user,
                rollback_after,
                totp_secret,
            } => harden::ssh(harden::Opts {
                totp,
                fido,
                user,
                rollback_after,
                totp_secret,
            }),
            HardenCmd::Confirm => harden::confirm(),
            HardenCmd::Undo => harden::undo(),
        },
        Cmd::Firewall(f) => match f {
            FirewallCmd::Apply => init_cmd::firewall_apply(),
            FirewallCmd::Show { planned } => init_cmd::firewall_show(planned),
        },
        Cmd::Apply => init_cmd::apply_all(),
        Cmd::Run { key } => runner::run(&key),
        Cmd::LoadKeys { key } => init_cmd::load_keys(&key),
        Cmd::Tick => init_cmd::tick(),
        Cmd::Api => api::serve(),
        Cmd::WebServe => web::serve(),
        Cmd::Totp { secret } => web_cmd::totp(&secret),
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
    fn new_takes_a_host_and_agent_args() {
        let cli = Cli::try_parse_from([
            "thorn",
            "new",
            "fig",
            "--agent",
            "aider",
            "--arg=--permission-mode",
            "--arg",
            "acceptEdits",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::New {
                host, agent, args, ..
            } => {
                assert_eq!(host, "fig");
                assert_eq!(agent.as_deref(), Some("aider"));
                assert_eq!(args, vec!["--permission-mode", "acceptEdits"]);
            }
            _ => panic!("wrong command"),
        }
    }

    /// Every operation the web API offers has a command here (the CLI is the
    /// fallback when the web UI is down, so it must not lack anything).
    #[test]
    fn every_api_operation_has_a_command() {
        let cmd = Cli::command();
        let has = |path: &[&str]| {
            let mut c = &cmd;
            for p in path {
                match c.find_subcommand(p) {
                    Some(s) => c = s,
                    None => return false,
                }
            }
            true
        };
        let table: &[(&str, &[&str])] = &[
            ("overview", &["status"]),
            ("space_new", &["new"]),
            ("space_rm", &["rm"]),
            ("space_rename", &["rename"]),
            ("space_control", &["restart"]),
            ("space_screen", &["screen"]),
            ("space_send", &["send"]),
            ("login_start", &["login"]),
            ("login_finish", &["login"]),
            ("login_cancel", &["login"]),
            ("bridge_add", &["bridge", "add"]),
            ("bridge_rm", &["bridge", "rm"]),
            ("host_scan", &["host", "add"]),
            ("host_add", &["host", "add"]),
            ("host_rm", &["host", "rm"]),
            ("host_block", &["host", "block"]),
            ("host_unblock", &["host", "unblock"]),
            ("host_pubkey", &["host", "pubkey"]),
            ("host_check", &["host", "check"]),
            ("host_rescan", &["host", "rescan"]),
            ("host_rescan_confirm", &["host", "rescan"]),
            ("host_move_scan", &["host", "set-address"]),
            ("host_move", &["host", "set-address"]),
        ];
        // Operations that exist only because of the web: sessions.
        let web_only = ["web_config", "login", "logout", "whoami"];
        for (op, path) in table {
            assert!(has(path), "{op}: missing thorn {}", path.join(" "));
        }
        for op in api::all_op_names() {
            assert!(
                web_only.contains(&op.as_str()) || table.iter().any(|(o, _)| *o == op),
                "API operation {op} has no CLI command in this table"
            );
        }
    }
}
