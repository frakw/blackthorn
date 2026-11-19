# blackthorn

blackthorn turns one small, isolated machine into the place where your AI
coding agents live. They keep running there, you reach them from your phone
or laptop, and each one can work on exactly one of your machines, over SSH,
one way only.

Status: **early (v0.2)**. It works and is tested end to end, but expect
changes. Read [THREAT_MODEL.md](THREAT_MODEL.md) before trusting it with
anything important.

## What it does

1. **Agents that keep running.** Each space runs Claude Code as a Remote
   Control server: open as many chats as you like from the Claude app or
   claude.ai/code. Spaces survive disconnects, restart after crashes and
   come back after a reboot.
2. **Many machines from one place.** Sign in to Claude on the hub only. The
   machines it works on need an SSH server and one line in
   `authorized_keys`. Linux and macOS.
3. **One-way isolation, simple permissions.** A space is *one machine + one
   agent*. It can reach that machine and nothing else; the machines cannot
   reach the hub at all. To let a space work on a second machine for a
   while, open a **bridge**. Cut a machine off from everything with one
   **block**. All of it is enforced by the kernel, not by asking the model.
4. **Keys stay on the hub.** Private keys never leave root-only files; each
   space gets only its own key, through an agent it cannot read. Keys only
   work from the hub's address.
5. **See everything.** A web UI with a live map of machines, spaces and
   bridges, or the same from the command line.

## How it works

```
 your phone / laptop ── Remote Control (via claude.ai) ──┐
 you ── web UI / SSH over your tailnet, 2FA ──┐          │
                                              ▼          ▼
 ┌──────────────────────── blackthorn hub ───────────────────────────┐
 │ thorn (root): state, keys, firewall, systemd units                │
 │ web UI: unprivileged process ── root API on a Unix socket         │
 │                                                                   │
 │ space "fig-claude"  = Unix user bt-1a2b3c4d                       │
 │   tmux ─ claude remote-control      ssh-agent: fig's key          │
 │                                     nftables: may reach fig:22    │
 │ space "nas-claude"  = Unix user bt-5e6f7a8b                       │
 │   tmux ─ claude remote-control      ssh-agent: nas's key          │
 │      └─ bridge for 1h ─────────────────────────────┐              │
 └───────────────┬───────────────────────────────────────────────────┘
                 │ outbound SSH only                 │
        ┌────────┴─────────┐                         │
        ▼                  ▼                         ▼
       fig                nas  ◄─────────────────────┘
       (machines cannot connect to the hub: the hub's firewall drops them)
```

Each space is:

- **its own Unix user** (`bt-<key>`), so spaces cannot read each other's
  files, credentials or agents;
- **a systemd unit** (`blackthorn-space@<key>`) running a tmux server whose
  only pane runs the agent, sandboxed with `ProtectSystem=strict`,
  `ProtectHome`, `NoNewPrivileges` and friends;
- **an ssh-agent** (`blackthorn-agent@<key>`) holding the key of its
  machine (and of bridged machines). Root loads the keys; ssh-agent refuses
  to let the space user read its memory;
- **nftables rules** matching the space's uid: it may send packets only to
  loopback, your DNS servers, HTTPS (for Anthropic), and the SSH port of
  the machines it may reach. Everything else is rejected, including packets
  on connections that were already open, so blocks and the end of a bridge
  take effect at once.

The hub's own inbound firewall drops every connection from a managed
machine, and, if you list your devices, allows the admin ports (SSH, web UI)
from those only.

## Requirements

- A dedicated machine or VM running Debian 13 with systemd. Nothing else
  should run on it. (Other systemd distributions with nftables may work but
  are untested.)
- `tmux`, `openssh-client`, `nftables` (`thorn init` tells you what is
  missing). For SSH two-factor: `openssh-server`,
  `libpam-google-authenticator`.
- A Claude plan with Remote Control (Pro, Max, Team or Enterprise). Each
  space signs in once; tokens from `claude setup-token` cannot be used,
  because they cannot start Remote Control.
- Machines to manage (Linux or macOS), reachable from the hub at a fixed IP
  address. A Tailscale or Headscale tailnet works well.

## Install

On the hub (Debian, Ubuntu, Fedora or Arch, with systemd):

```sh
curl -fsSL https://github.com/frakw/blackthorn/releases/latest/download/install.sh | sh
```

That one line:

1. installs `tmux`, `openssh-client` and `nftables` if they are missing;
2. downloads `thorn` (a static binary) and checks it against the release's
   `SHA256SUMS`;
3. installs Claude Code with Anthropic's installer, unless it is already
   there, and puts it at `/usr/local/bin/claude`, root-owned, so spaces run
   it but cannot change it;
4. runs `thorn init`: systemd units, the firewall, and the web UI, turned on;
5. asks for your web account: a password, then a QR code for your
   authenticator app.

It ends by printing the web UI's address. Open it, log in, and do the rest
there: add a machine, create a space on it, sign it in to Claude.

Run the same line again to upgrade; your configuration stays as it is. To
update Claude Code: `... | sh -s -- --update-claude`. Other options:
`--version v0.3.0`, `--no-claude`, `--no-web`, and `--binary ./thorn` to
install a binary you built yourself (`cargo build --release`; the hub needs
no compiler).

## Quick start

From the web UI, or the same from the command line:

```sh
# 1. Register a machine by IP. Confirm its host-key fingerprints when asked.
sudo thorn host add fig root@100.80.0.3

# 2. Put the printed line in fig's authorized_keys, then check:
sudo thorn host check fig

# 3. Create a space on it (Claude Code), sign it in once, and it starts.
sudo thorn new fig                 # creates "fig-claude"
sudo thorn login fig-claude

# 4. Open "fig-claude" in the Claude app or claude.ai/code and start chats.
sudo thorn status                  # the map, in text
```

Cut a machine off for an hour, or let `fig-claude` reach `nas` for 30
minutes:

```sh
sudo thorn host block fig --for 1h --reason "kernel upgrade"
sudo thorn bridge add fig-claude nas-claude --for 30m
```

## Web UI

The web UI is the everyday way to run blackthorn: the map, spaces (with a
live view of each space's terminal, and Claude sign-in), machines, blocks
and bridges. The command line can do everything it can, for when it is down.

Logins need the password and a TOTP code; deleting a space, removing a
machine, opening a bridge and accepting new host keys ask for a fresh code
again. The HTTP-facing process runs as an unprivileged, sandboxed user and
cannot act on its own: a root process behind a Unix socket checks every
login and code.

It is plain HTTP. On install it listens on the hub's tailnet address when
Tailscale is up, where WireGuard already encrypts the traffic and no domain
or certificate is needed. Without Tailscale it listens on every address;
then narrow it down, and limit who may connect at all:

```sh
# /etc/blackthorn/config.toml
[web]
listen = ["100.64.0.10:7180"]      # the hub's tailnet address

[inbound]
admin_from = ["100.64.0.2", "100.64.0.3"]   # your laptop and phone

sudo thorn apply
```

More accounts: `sudo thorn web user add NAME`. Turn the web UI off with
`sudo thorn web disable`; the command line keeps working.

## SSH two-factor

```sh
sudo apt install openssh-server libpam-google-authenticator
sudo thorn harden ssh --totp       # key + authenticator code
sudo thorn harden ssh --fido       # or: a FIDO2 hardware key (ed25519-sk)
```

It shows a QR code, checks a code from your app, changes sshd, and **undoes
the change by itself after five minutes** unless you log in again from a
new terminal and run `sudo thorn harden confirm`. `sudo thorn harden undo`
restores the old settings at any time.

## Commands

| Command | What it does |
|---|---|
| `thorn init [--claude-from PATH] [--no-web]` | Set up the hub (the installer runs it), or update Claude Code |
| `thorn status [--json]` | The map: machines, spaces, bridges, hub health |
| `thorn ls` | Spaces: machine, agent, state, what they can reach |
| `thorn new HOST [--agent A] [--name N] [--single] [--rc-name N] [--arg A]...` | Create a space on a machine |
| `thorn login SPACE` | Sign a Claude space in, then start it |
| `thorn start\|stop\|restart SPACE... \| --all` | Control spaces |
| `thorn attach SPACE` | Open the space's terminal |
| `thorn screen SPACE` / `thorn send SPACE TEXT` | Read or type into the terminal without attaching |
| `thorn rename OLD NEW [--rc-name N]` | Rename; same chats |
| `thorn rm SPACE [--purge]` | Delete; files are archived unless `--purge` |
| `thorn bridge add FROM TO [--for 1h]` / `bridge rm` / `bridge ls` | Let one space reach another space's machine for a while |
| `thorn host add NAME USER@IP [--port P]` | Register a machine and create its key |
| `thorn host ls` / `host check` / `host pubkey` / `host rescan` / `host rm` | Manage machines |
| `thorn host block NAME [--for 30m] [--reason R]` / `host unblock` | Cut a machine off from every space |
| `thorn web enable\|disable` / `web user add\|rm\|ls\|passwd\|totp-reset` | The web UI and its accounts |
| `thorn harden ssh --totp\|--fido` / `harden confirm\|undo` | Two-factor SSH to the hub |
| `thorn firewall show [--planned]` / `firewall apply` | Inspect or reload the rules |
| `thorn apply` | Rewrite all generated files and reload everything |

Commands that change anything must run as root.

### Spaces and agents

A space runs **Claude Code** by default, as a Remote Control server with
many chats. `--single` gives one conversation that you can also type into
on the terminal. Options for Claude Code go after `--arg`:

```sh
sudo thorn new fig --arg=--permission-mode --arg=acceptEdits
```

Other terminal agents can run in a space too; you use them through
`thorn attach`, the web UI's terminal view, or `thorn screen`/`send`.
Declare them in the configuration:

```toml
[agents.aider]
bin = "/usr/local/bin/aider"
args = ["--no-auto-commits"]
instructions = "CONVENTIONS.md"   # where it reads its instructions
```

Every space gets an instructions file (`CLAUDE.md`, or the agent's own)
listing what it can reach and the rules of the hub.

## Configuration

`/etc/blackthorn/config.toml` (run `sudo thorn apply` after editing):

| Key | Default | Meaning |
|---|---|---|
| `claude_bin` | `/usr/local/bin/claude` | Claude Code binary spaces run |
| `claude_args` | `[]` | Arguments added to every Claude space |
| `capacity` | `8` | Most chats one space runs at once |
| `ssh_from` | `[]` | The hub's addresses as machines see them, for `from="..."` in key lines. Empty: `tailscale ip` |
| `never_manage` | `[]` | Addresses blackthorn refuses to manage and always drops (your tailnet control server, password manager...) |
| `egress.https_anywhere` | `true` | Allow HTTPS to any address (Claude Code needs Anthropic, whose addresses change). See the threat model |
| `egress.dns` | `[]` | DNS servers spaces may use; empty means those in `/etc/resolv.conf` |
| `inbound.admin_from` | `[]` | If set, only these addresses may reach SSH and the web UI |
| `inbound.ssh_port` | `22` | The hub's SSH port |
| `inbound.deny_from` | `[]` | More addresses to drop (managed machines are always dropped) |
| `web.listen` | `[]` | Where the web UI listens; empty: off |
| `agents.<name>` | | Other agents: `bin`, `args`, `instructions` |

## With Tailscale or Headscale

- Join the hub to the tailnet with its own tag, Tailscale SSH off, and
  without accepting routes others advertise:
  `tailscale up --advertise-tags=tag:blackthorn --ssh=false --accept-routes=false`.
  Do this before installing blackthorn: the web UI then listens on the
  tailnet address only.
- In the tailnet policy, let your own devices reach `tag:blackthorn` on the
  admin ports, let `tag:blackthorn` reach your servers on port 22, and
  nothing else. The hub's own firewall enforces the same, in case the
  policy is wrong.
- Register machines by their tailnet IP. The key line then carries
  `from="<hub's tailnet IP>"` automatically.
- Do not manage the machine that runs your control server, and list it in
  `never_manage`: whoever controls it controls who can reach the hub.

## Files

| Path | Contents |
|---|---|
| `/etc/blackthorn/config.toml` | Configuration |
| `/etc/blackthorn/keys/` | One private key per machine (root only) |
| `/etc/blackthorn/web-users.toml` | Web accounts: password hashes, TOTP secrets (root only) |
| `/var/lib/blackthorn/state.toml` | Machines, spaces, bridges, blocks (root only; use `thorn`) |
| `/var/lib/blackthorn/spaces/<key>/` | Space home: agent config, credentials, conversations |
| `/var/lib/blackthorn/archive/` | Removed spaces |
| `/etc/systemd/system/blackthorn-*` | Units installed by `thorn init` |

The web API logs every action (who, from where, what, result) to the
journal: `journalctl -u blackthorn-api`.

## Hardening the hub

blackthorn limits what spaces can do. Protecting the hub itself is up to
you:

- Run it as a dedicated VM. Put a firewall *outside* it too (for example
  the Proxmox VM firewall): no inbound connections except your admin
  network. Remote Control needs no inbound port.
- Reach it for administration only over a private network (such as a
  tailnet), from devices listed in `inbound.admin_from`.
- Turn on `thorn harden ssh`.
- On managed machines, prefer a non-root user for the hub's key.
- Protect your Claude account with strong authentication: anyone signed in
  to it can drive your spaces through Remote Control.

## Development

```sh
cargo test                       # unit tests
sudo cargo test -- --ignored     # also checks the generated rules with `nft -c`
tests/e2e/run.sh                 # full test in throwaway Docker containers
```

The end-to-end test starts a systemd container as the hub, two SSH targets
and an "admin laptop", and checks isolation between spaces, the inbound
firewall, the web UI (login, CSRF, step-up codes, Claude sign-in), bridges,
blocks, renames, SSH two-factor with its automatic undo, reboots and
removal, using a fake `claude`.

## License

[MIT](LICENSE). blackthorn is an independent project, not affiliated with
Anthropic.
