//! thorn: the command-line interface of blackthorn.

mod activity;
mod api;
mod apply;
mod asks;
mod backup;
mod chat;
mod codex;
mod codex_bridge;
mod config;
mod config_cmd;
mod ctx;
mod firewall;
mod harden;
mod highlight;
mod host_cmd;
mod http;
mod init_cmd;
mod keys;
mod logins;
mod map;
mod markdown;
mod notify;
mod ops;
mod paths;
mod reach;
mod remote;
mod render;
mod runner;
mod seal;
mod space_cmd;
mod state;
mod sys;
mod tls;
mod units;
mod view_cmd;
mod web;
mod web_cmd;
mod webauth;
mod webauthn;

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
        /// claude (default), codex, or an agent from config.toml.
        #[arg(long)]
        agent: Option<String>,
        /// Default: <host>-<agent>.
        #[arg(long)]
        name: Option<String>,
        /// Claude: one conversation you can also type into on the terminal,
        /// instead of a Remote Control server with many chats.
        #[arg(long)]
        single: bool,
        /// Claude: without Remote Control; use it only from the hub's
        /// terminal (thorn attach, or the web UI).
        #[arg(long)]
        local: bool,
        /// The name the Claude app lists its Remote Control environment by
        /// (default: <machine>-<space>, or the space name if it starts
        /// with the machine's). It is also the work folder's name.
        #[arg(long)]
        rc_name: Option<String>,
        /// Extra argument for the agent, e.g. --arg=--permission-mode --arg=acceptEdits.
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,
        /// Its usual login on its machine: read-only or user. Default:
        /// user where the machine has one, else read-only.
        #[arg(long, value_parser = ["read-only", "readonly", "user"])]
        access: Option<String>,
        /// Root from the start, for a time (8h; at most 72h) or "forever";
        /// "no" for none. Default: 8h on a machine set up for logins of
        /// each space's own (thorn host setup).
        #[arg(long)]
        root: Option<String>,
    },
    /// Sign a Claude or Codex space in, then start it. Codex: a device code
    /// (a page and a code to enter there), or --api-key.
    Login {
        name: String,
        /// Codex: read an OpenAI API key from standard input instead.
        #[arg(long)]
        api_key: bool,
    },
    /// Delete a space (its files are archived unless --purge). Its logins
    /// on its machine go too; its folder there (/srv/<name>) stays unless
    /// --purge-data.
    Rm {
        name: String,
        #[arg(long)]
        purge: bool,
        #[arg(long)]
        purge_data: bool,
    },
    /// Rename a space (and its Remote Control name, if it was the default).
    /// `thorn rename SPACE SPACE --rc-name NAME` changes only the name the
    /// Claude app lists it by; the space restarts, its chats stay.
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
    /// What spaces with root on approval asked to run as root (waiting
    /// ones; --all: the latest decided too).
    Approvals {
        #[arg(long)]
        all: bool,
    },
    /// Approve an ask: the command runs as root on the machine, as asked.
    Approve { id: String },
    /// Refuse an ask.
    Deny {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Watch the machines for asks (run by blackthorn-asks.service).
    #[command(name = "_asks", hide = true)]
    AsksWatch,
    /// Set a space's usual login on its machine: read-only or user. It
    /// applies at once; the space and its chats go on.
    Access {
        name: String,
        #[arg(value_parser = ["read-only", "readonly", "user"])]
        access: String,
    },
    /// Give a space root on its machine, for a time (default 8h, at most
    /// 72h) or until taken back; or take it back. When it ends, the space
    /// goes back to its usual login; its chats go on.
    Root {
        name: String,
        #[arg(long = "for", value_name = "DURATION", conflicts_with_all = ["forever", "ask", "off"])]
        duration: Option<String>,
        #[arg(long, conflicts_with_all = ["ask", "off"])]
        forever: bool,
        /// Root on approval: it logs in as its user, and each command it
        /// wants as root waits until you approve it (thorn approvals).
        #[arg(long, conflicts_with = "off")]
        ask: bool,
        #[arg(long)]
        off: bool,
    },
    /// The commands a space ran, oldest first (copied from its chats every
    /// minute into /var/log/blackthorn).
    Log {
        name: String,
        /// How many of the latest.
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },
    /// Turn a Claude space's Remote Control on or off. Off, it is one local
    /// conversation, reached only from the hub (thorn attach, the web UI).
    Remote {
        name: String,
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Share a space with another web account: view (read its chats and
    /// terminal), use (also type into chats, start and stop), manage (also
    /// change and delete it), or none (stop sharing). Hub admins see every
    /// space anyway.
    Share {
        name: String,
        account: String,
        #[arg(value_parser = ["view", "use", "manage", "none"])]
        level: String,
    },
    /// Give a space to another web account (the old owner may still manage
    /// it). "--hub" gives it to the hub admins only.
    Owner {
        name: String,
        #[arg(required_unless_present = "hub")]
        account: Option<String>,
        #[arg(long)]
        hub: bool,
    },
    /// A space's Claude chats: list, name, delete.
    #[command(subcommand)]
    Chat(ChatCmd),
    /// Let one space reach another space's machine for a while.
    #[command(subcommand)]
    Bridge(BridgeCmd),
    /// Save everything blackthorn keeps (settings, machine keys, accounts,
    /// spaces with their Claude logins and chats, logs) to one file. It
    /// holds every secret on the hub: give it a password, or keep it like
    /// one. On a terminal it asks whether to.
    Export {
        /// Where to write it.
        file: std::path::PathBuf,
        /// Protect it with a password (asked for; without a terminal, read
        /// from the first line of standard input).
        #[arg(long, conflicts_with = "no_password")]
        password: bool,
        /// No password, without asking.
        #[arg(long)]
        no_password: bool,
    },
    /// Bring back an export from this same version of blackthorn, on this
    /// hub or a new one (after `thorn init`). What is here is set aside.
    Import {
        file: std::path::PathBuf,
        /// Replace the spaces and machines this hub has now.
        #[arg(long)]
        replace: bool,
    },
    /// Install the latest blackthorn release (settings, accounts and spaces
    /// stay).
    Update {
        /// Only say whether there is a newer release.
        #[arg(long)]
        check: bool,
    },
    /// Push notifications (ntfy): a machine trying to connect back, a space
    /// failing or needing login, blocks and bridges ending, new releases.
    #[command(subcommand)]
    Notify(NotifyCmd),
    /// Tailscale on the hub: install it, sign in, its web interface.
    #[command(subcommand)]
    Tailscale(TailscaleCmd),
    /// OpenAI's Codex on the hub, for Codex spaces.
    #[command(subcommand)]
    Codex(CodexCmd),
    /// Show or change the settings the web UI can change too.
    #[command(subcommand)]
    Config(ConfigCmd),
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
    #[command(name = "_codex", hide = true)]
    CodexBridge { key: String },
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
enum ChatCmd {
    /// List a space's chats, newest first.
    Ls { space: String },
    /// Delete a chat's transcript from the hub (one started from the hub is
    /// stopped first).
    Rm { space: String, id: String },
    /// Stop a chat started from the hub in a Remote Control space.
    Stop { space: String, id: String },
    /// Type a message into a chat the hub runs, and send it (as the chat
    /// page does). Not while Claude asks a question.
    Send {
        space: String,
        id: String,
        text: String,
    },
    /// Start a new chat. A one-conversation space (single mode, Remote
    /// Control off) restarts into it; a Remote Control space runs it in a
    /// window of its own, shown in the Claude app.
    New {
        space: String,
        /// Its name (default: Claude names it). Claude Code gets the id's
        /// start and the name: `9cf982e0 NAME`.
        #[arg(long)]
        name: Option<String>,
    },
    /// Go back to an earlier chat, the same way.
    Open { space: String, id: String },
}

#[derive(Subcommand)]
enum CodexCmd {
    /// Its version, and whether an install is running.
    Status,
    /// Install or update it with OpenAI's installer (into /opt/codex).
    /// Codex spaces use the new version once restarted.
    Install,
    /// List a Codex space's chats, latest first. CHAT below may be the
    /// start of a chat's id.
    Chats { space: String },
    /// Print a chat: its messages, commands and what Codex waits on.
    Show {
        space: String,
        chat: String,
        /// How many of its latest turns.
        #[arg(long, default_value_t = 20)]
        turns: u32,
    },
    /// Start a chat with its first message.
    New { space: String, text: String },
    /// Send a message to a chat (while Codex works: more for what it is
    /// doing).
    Send {
        space: String,
        chat: String,
        text: String,
    },
    /// Stop what Codex is doing in a chat.
    Stop { space: String, chat: String },
    /// Answer what Codex asks (see `show` for its number): accept, session
    /// (and the same again in this chat), decline, or cancel (and stop).
    Answer {
        space: String,
        chat: String,
        ask: u64,
        decision: String,
        /// For questions: ID=ANSWER, repeated.
        #[arg(long = "answer")]
        answers: Vec<String>,
    },
    /// Name a chat.
    Rename {
        space: String,
        chat: String,
        name: String,
    },
    /// Archive a chat: Codex keeps it, out of the list.
    Archive { space: String, chat: String },
}

#[derive(Subcommand)]
enum TailscaleCmd {
    /// Whether it is installed, signed in, and on which tailnet.
    Status,
    /// Install it with Tailscale's own installer.
    Install,
    /// Sign the hub in to Tailscale (prints the sign-in link).
    Up,
    /// Turn Tailscale's web interface (port 5252 on the tailnet) on or off.
    Web {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
}

#[derive(Subcommand)]
enum NotifyCmd {
    /// Where notifications go.
    Show,
    /// Send them to an ntfy topic: https://ntfy.sh/<topic> or your own
    /// server. Without a URL: a new random topic on ntfy.sh.
    Set {
        url: Option<String>,
        /// Ask for an access token (for a protected topic).
        #[arg(long)]
        token: bool,
    },
    /// Stop sending them.
    Off,
    /// Send a test message.
    Test,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// The settings and their values.
    Show,
    /// Change one, e.g. `thorn config set inbound.admin_from "100.64.0.2, 100.64.0.3"`.
    /// An empty value empties a list.
    Set { key: String, value: String },
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
    /// Rename a machine; its spaces stay (and reach it by the new name).
    Rename { old: String, new: String },
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
    /// Set a Linux machine up for logins of each space's own: bt-<id>, an
    /// ordinary user with /srv/<space> and its own containers (root, when
    /// given, through sudo), and bt-<id>-ro, which reads logs and runs
    /// read-only Docker commands; every command they run goes to the
    /// machine's system log. Done through blackthorn's login there (root,
    /// or sudo without a password); or --print the script to run there as
    /// root (it also lets blackthorn's key log in as root), then run this
    /// again with --verify. Machines reached as root are set up by
    /// themselves.
    Setup {
        name: String,
        /// Print the setup script instead of running it.
        #[arg(long, conflicts_with = "verify")]
        print: bool,
        /// You ran the printed script yourself: check, then make the logins.
        #[arg(long)]
        verify: bool,
    },
    /// The name of `setup` before v0.12.
    #[command(hide = true)]
    Readonly {
        name: String,
        #[arg(long, default_value = "blackthorn")]
        user: String,
        #[arg(long, conflicts_with = "verify")]
        print: bool,
        #[arg(long)]
        verify: bool,
    },
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
    /// HTTPS for the web UI (needed for passkeys). Without options: show it.
    /// With your own certificate (e.g. certbot with a DNS challenge; renew
    /// it as usual, blackthorn picks it up):
    ///   thorn web https --cert /etc/letsencrypt/live/hub.example.com/fullchain.pem \
    ///                   --key /etc/letsencrypt/live/hub.example.com/privkey.pem --name hub.example.com
    /// Or from Tailscale (its own server, not Headscale): thorn web https --tailscale
    Https {
        #[arg(long, requires_all = ["key", "name"], conflicts_with_all = ["tailscale", "off"])]
        cert: Option<PathBuf>,
        #[arg(long, requires = "cert")]
        key: Option<PathBuf>,
        /// The name the certificate is for, which leads to the hub.
        #[arg(long)]
        name: Option<String>,
        #[arg(long, conflicts_with = "off")]
        tailscale: bool,
        /// Back to plain HTTP.
        #[arg(long)]
        off: bool,
    },
    /// Web UI accounts.
    #[command(subcommand)]
    User(WebUserCmd),
}

#[derive(Subcommand)]
enum WebUserCmd {
    /// Add an account: password plus authenticator app.
    Add {
        name: String,
        /// A hub admin (machines, settings, every space); otherwise it sees
        /// only the spaces shared with it (thorn share).
        #[arg(long)]
        admin: bool,
        #[arg(long, hide = true)]
        totp_secret: Option<String>,
    },
    /// Make an account a hub admin, or not.
    Admin {
        name: String,
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Remove an account.
    Rm { name: String },
    /// Rename an account.
    Rename { old: String, new: String },
    /// Remove a passkey (by its name or id, from `web user ls`).
    PasskeyRm { name: String, passkey: String },
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

fn parse_access(a: &str) -> state::Access {
    if a == "user" {
        state::Access::User
    } else {
        state::Access::Readonly
    }
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
            local,
            rc_name,
            args,
            access,
            root,
        } => s::new(ops::NewSpace {
            host,
            agent,
            name,
            single,
            local,
            rc_name,
            args,
            access: access.as_deref().map(parse_access),
            root,
            owner: None,
        }),
        Cmd::Login { name, api_key } => s::login(&name, api_key),
        Cmd::Rm {
            name,
            purge,
            purge_data,
        } => s::rm(&name, purge, purge_data),
        Cmd::Rename { old, new, rc_name } => s::rename(&old, &new, rc_name),
        Cmd::Start { names, all } => s::control(Action::Start, &names, all),
        Cmd::Stop { names, all } => s::control(Action::Stop, &names, all),
        Cmd::Restart { names, all } => s::control(Action::Restart, &names, all),
        Cmd::Access { name, access } => s::login_as(&name, parse_access(&access)),
        Cmd::Root {
            name,
            duration,
            forever,
            ask,
            off,
        } => s::root(&name, duration.as_deref(), forever, ask, off),
        Cmd::Approvals { all } => s::approvals(all),
        Cmd::Approve { id } => s::decide(&id, true, None),
        Cmd::Deny { id, reason } => s::decide(&id, false, reason.as_deref()),
        Cmd::AsksWatch => asks::run(),
        Cmd::Log { name, lines } => s::log(&name, lines),
        Cmd::Attach { name } => s::attach(&name),
        Cmd::Screen { name } => s::screen(&name),
        Cmd::Send {
            name,
            text,
            key,
            no_enter,
        } => s::send(&name, text.as_deref(), key.as_deref(), no_enter),
        Cmd::Remote { name, state } => s::remote(&name, state == "on"),
        Cmd::Share {
            name,
            account,
            level,
        } => s::share(&name, &account, &level),
        Cmd::Owner { name, account, hub } => {
            s::owner(&name, if hub { None } else { account.as_deref() })
        }
        Cmd::Chat(c) => match c {
            ChatCmd::Ls { space } => s::chat_ls(&space),
            ChatCmd::Rm { space, id } => s::chat_rm(&space, &id),
            ChatCmd::Stop { space, id } => s::chat_stop(&space, &id),
            ChatCmd::Send { space, id, text } => s::chat_send(&space, &id, &text),
            ChatCmd::New { space, name } => s::chat_open(&space, None, name.as_deref()),
            ChatCmd::Open { space, id } => s::chat_open(&space, Some(&id), None),
        },
        Cmd::Export {
            file,
            password,
            no_password,
        } => {
            use std::io::IsTerminal;
            let ask = !password && !no_password && std::io::stdin().is_terminal();
            let password = if password
                || (ask && seal::ask_yes("Protect the export with a password? [Y/n] ", true)?)
            {
                let p = seal::read_password("Password: ")?;
                if std::io::stdin().is_terminal() && seal::read_password("Again: ")? != p {
                    anyhow::bail!("the passwords differ");
                }
                Some(p)
            } else {
                None
            };
            let m = backup::export(&file, password.as_deref())?;
            println!(
                "exported blackthorn {} ({} space(s)) to {}{}",
                m.version,
                m.owners.len(),
                file.display(),
                if password.is_some() {
                    ", with a password"
                } else {
                    ""
                }
            );
            if password.is_some() {
                println!("it cannot be imported without the password: there is no way back if it is lost");
            } else {
                println!("it holds every key and Claude login on this hub; keep it like one");
            }
            println!("import it with the same version: sudo thorn import FILE");
            Ok(())
        }
        Cmd::Import { file, replace } => {
            let password = if backup::sealed(&file)? {
                Some(seal::read_password("The export's password: ")?)
            } else {
                None
            };
            let r = backup::import(&file, replace, password.as_deref())?;
            println!(
                "imported blackthorn {} from {}: {} space(s), {} machine(s)",
                r.manifest.version, r.manifest.hostname, r.spaces, r.hosts
            );
            if !r.started.is_empty() {
                println!("started: {}", r.started.join(", "));
            }
            for p in &r.before {
                println!("what was here before: {}", p.display());
            }
            Ok(())
        }
        Cmd::Update { check } => config_cmd::update(check),
        Cmd::Codex(c) => match c {
            CodexCmd::Status => config_cmd::codex_status(),
            CodexCmd::Install => config_cmd::codex_install(),
            CodexCmd::Chats { space } => s::codex_chats(&space),
            CodexCmd::Show { space, chat, turns } => s::codex_show(&space, &chat, turns),
            CodexCmd::New { space, text } => s::codex_new(&space, &text),
            CodexCmd::Send { space, chat, text } => s::codex_send(&space, &chat, &text),
            CodexCmd::Stop { space, chat } => s::codex_stop(&space, &chat),
            CodexCmd::Answer {
                space,
                chat,
                ask,
                decision,
                answers,
            } => s::codex_answer(&space, &chat, ask, &decision, &answers),
            CodexCmd::Rename { space, chat, name } => s::codex_rename(&space, &chat, &name),
            CodexCmd::Archive { space, chat } => s::codex_archive(&space, &chat),
        },
        Cmd::Tailscale(t) => match t {
            TailscaleCmd::Status => config_cmd::tailscale_status(),
            TailscaleCmd::Install => config_cmd::tailscale_install(),
            TailscaleCmd::Up => config_cmd::tailscale_up(),
            TailscaleCmd::Web { state } => {
                println!("{}", ops::tailscale_web(state == "on")?);
                Ok(())
            }
        },
        Cmd::Notify(n) => match n {
            NotifyCmd::Show => notify::cmd_show(),
            NotifyCmd::Set { url, token } => notify::cmd_set(url, token),
            NotifyCmd::Off => notify::cmd_off(),
            NotifyCmd::Test => notify::cmd_test(),
        },
        Cmd::Config(c) => match c {
            ConfigCmd::Show => config_cmd::show(),
            ConfigCmd::Set { key, value } => config_cmd::set(&key, &value),
        },
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
            HostCmd::Rename { old, new } => host_cmd::rename(&old, &new),
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
            HostCmd::Setup {
                name,
                print,
                verify,
            } => host_cmd::setup(&name, print, verify),
            HostCmd::Readonly {
                name,
                user: _,
                print,
                verify,
            } => host_cmd::readonly(&name, print, verify),
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
            WebCmd::Https {
                cert,
                key,
                name,
                tailscale,
                off,
            } => web_cmd::https(if off {
                web_cmd::Https::Off
            } else if tailscale {
                web_cmd::Https::Tailscale { name }
            } else {
                match (cert, key, name) {
                    (Some(cert), Some(key), Some(name)) => {
                        web_cmd::Https::Files { cert, key, name }
                    }
                    _ => web_cmd::Https::Show,
                }
            }),
            WebCmd::User(u) => match u {
                WebUserCmd::Add {
                    name,
                    admin,
                    totp_secret,
                } => web_cmd::user_add(&name, totp_secret, admin),
                WebUserCmd::Admin { name, state } => web_cmd::user_admin(&name, state == "on"),
                WebUserCmd::Rm { name } => web_cmd::user_rm(&name),
                WebUserCmd::Rename { old, new } => web_cmd::user_rename(&old, &new),
                WebUserCmd::PasskeyRm { name, passkey } => {
                    web_cmd::user_passkey_rm(&name, &passkey)
                }
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
        Cmd::CodexBridge { key } => codex_bridge::run(&key),
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
            ("config_show", &["config", "show"]),
            ("config_set", &["config", "set"]),
            ("tailnet_peers", &["config", "show"]),
            ("tailscale_show", &["tailscale", "status"]),
            ("tailscale_install", &["tailscale", "install"]),
            ("tailscale_up", &["tailscale", "up"]),
            ("tailscale_web", &["tailscale", "web"]),
            ("chat_list", &["chat", "ls"]),
            ("chat_rm", &["chat", "rm"]),
            ("chat_stop", &["chat", "stop"]),
            ("chat_send", &["chat", "send"]),
            ("space_share", &["share"]),
            ("space_owner", &["owner"]),
            ("space_remote", &["remote"]),
            ("update_check", &["update"]),
            ("update", &["update"]),
            ("account", &["web", "user", "ls"]),
            ("account_password", &["web", "user", "passwd"]),
            ("account_totp_begin", &["web", "user", "totp-reset"]),
            ("account_totp_finish", &["web", "user", "totp-reset"]),
            ("chat_open", &["chat", "new"]),
            ("host_rename", &["host", "rename"]),
            ("account_rename", &["web", "user", "rename"]),
            ("notify_show", &["notify", "show"]),
            ("notify_set", &["notify", "set"]),
            ("notify_test", &["notify", "test"]),
            ("passkey_rm", &["web", "user", "passkey-rm"]),
            ("space_access", &["access"]),
            ("space_root", &["root"]),
            ("space_root_off", &["root"]),
            ("ask_list", &["approvals"]),
            ("ask_decide", &["approve"]),
            ("host_setup", &["host", "setup"]),
            ("activity", &["log"]),
            ("login_api_key", &["login"]),
            ("codex_show", &["codex", "status"]),
            ("codex_install", &["codex", "install"]),
            ("codex_chats", &["codex", "chats"]),
            ("codex_feed", &["codex", "show"]),
            ("codex_new", &["codex", "new"]),
            ("codex_send", &["codex", "send"]),
            ("codex_stop", &["codex", "stop"]),
            ("codex_answer", &["codex", "answer"]),
            ("codex_rename", &["codex", "rename"]),
            ("codex_archive", &["codex", "archive"]),
        ];
        // Operations that exist only because of the web: sessions.
        // Passkeys are made and used in a browser.
        let web_only = [
            "web_config",
            "login",
            "logout",
            "whoami",
            "passkey_begin",
            "passkey_login",
            "passkey_add",
            "account_names",
            "session_list",
            "session_end",
            "session_end_others",
            "chat_unlock",
            "chat_feed",
            "chat_commands",
            "chat_upload",
            "chat_key",
        ];
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
