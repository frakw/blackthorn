<p align="center"><img src="assets/logo.svg" width="96" height="96" alt=""></p>

# blackthorn

blackthorn turns one small, isolated machine into the place where your AI
coding agents live. They keep running there, you reach them from your phone
or laptop, and each one can work on exactly one of your machines, over SSH,
one way only.

Status: **early (v0.4)**. It works and is tested end to end, but expect
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
4. offers to install Tailscale when it is missing (with Tailscale's own
   installer; for Headscale it asks for your server's URL), so only your
   own devices can reach the hub;
5. runs `thorn init`: systemd units, the firewall, and the web UI, turned on;
6. lists your tailnet's devices and asks which may administer the hub (its
   SSH and web UI); managed machines are shown but can never be picked;
7. asks for your web account: a password, then a QR code for your
   authenticator app.

It ends by printing the web UI's address. Open it, log in, and do the rest
there: add a machine, create a space on it, sign it in to Claude.

Run the same line again to upgrade, or press **Update** on the web UI's
Settings page when it says a new release is out (`sudo thorn update` does the
same); your configuration stays as it is. To update Claude Code: `... | sh -s -- --update-claude`. Other options:
`--version v0.3.0`, `--no-claude`, `--no-web`, `--tailscale` /
`--no-tailscale`, `--login-server URL` (your Headscale), and `--binary ./thorn` to
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

The web UI is the everyday way to run blackthorn, on a laptop or a phone:

- **Map**: your devices, the hub (blackthorn and its spaces, framed as one
  machine), the Claude app and the models your spaces use (framed as
  Anthropic's cloud), and the machines the spaces work on, as boxes and
  wires like a node editor. Arrows point from whoever opens the connection.
  Drag boxes around, pan and zoom; the layout is remembered in your browser.
- **Spaces**: each one's chats (new, continue, rename, delete; with Remote
  Control a new chat runs next to the others and shows in the Claude app),
  a live view of its terminal, Claude sign-in, bridges, Remote Control on
  or off, and the name the Claude app lists it by.
- **Machines**: the key line to install (with a Copy button), checking the
  machine's host keys, blocks, renaming.
- **Settings**: who may connect, never_manage and the web address, edited
  as lists of addresses with a picker that knows your tailnet's devices and
  whether they are online; and the blackthorn version, with one-click
  updates.
- **Notifications** (on the Settings page): pushed to your phone through
  [ntfy](https://ntfy.sh) (ntfy.sh or your own server) when a managed
  machine tries to connect to the hub, a space fails or must sign in again,
  a block or bridge ends, or a new release is out.
- **Account**: rename it, change your password, or move to a new
  authenticator app.

The command line can do everything it can, for when it is down.

Logins need the password and a TOTP code; deleting or renaming anything,
removing a machine, opening a bridge, accepting new host keys and changing
settings ask for a fresh code again. The HTTP-facing process runs as an unprivileged, sandboxed user and
cannot act on its own: a root process behind a Unix socket checks every
login and code.

### HTTPS and passkeys

Passkeys (Face ID, Touch ID, Windows Hello, Android) and hardware keys with a
PIN log you in on their own, and stand in for the authenticator code where
one is asked again ("or use a passkey"). Add them on the **Account** page.
Browsers allow them only over HTTPS, under a name, so give the web UI one:

```sh
# Your own domain, e.g. a DNS record hub.example.com -> the hub's tailnet IP,
# and a certificate from certbot with a DNS challenge (the hub need not be
# reachable from the internet). Renew it as usual; blackthorn picks it up.
sudo thorn web https --cert /etc/letsencrypt/live/hub.example.com/fullchain.pem \
                     --key  /etc/letsencrypt/live/hub.example.com/privkey.pem --name hub.example.com

# Or Tailscale's own coordination server (not Headscale), with MagicDNS and
# HTTPS turned on in its admin console: a certificate for hub.<tailnet>.ts.net.
sudo thorn web https --tailscale

sudo thorn web https          # what is set
sudo thorn web https --off    # back to plain HTTP
```

Then it speaks only HTTPS. Without it, the password and code are enough.

It is plain HTTP until then. On install it listens on the hub's tailnet address when
Tailscale is up, where WireGuard already encrypts the traffic and no domain
or certificate is needed. Without Tailscale it listens on every address;
then narrow it down, and limit who may connect at all, on the
**Settings** page or from the command line:

```sh
sudo thorn config set web.listen 100.64.0.10:7180                 # the hub's tailnet address
sudo thorn config set inbound.admin_from "100.64.0.2, 100.64.0.3"  # your laptop and phone
sudo thorn config show
```

Settings changes are written to `/etc/blackthorn/config.toml` (its comments
stay) and applied at once. On the web they need a fresh code, and a change
that would shut out the device you are using is refused. Everything else in
the file is edited by hand, followed by `sudo thorn apply`.

Accounts are added and removed only on the hub itself, with
`sudo thorn web user add NAME` and `sudo thorn web user rm NAME`; once you
have written down the recovery codes, the terminal is cleared, so neither
they nor the QR code stay in its scrollback. Turn the web UI off with
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
| `thorn new HOST [--agent A] [--name N] [--single] [--local] [--arg A]...` | Create a space on a machine |
| `thorn login SPACE` | Sign a Claude space in, then start it |
| `thorn start\|stop\|restart SPACE... \| --all` | Control spaces |
| `thorn attach SPACE` | Open the space's terminal |
| `thorn screen SPACE` / `thorn send SPACE TEXT` | Read or type into the terminal without attaching |
| `thorn rename OLD NEW [--rc-name N]` | Rename; same chats |
| `thorn chat ls SPACE` / `chat rename SPACE ID NAME` / `chat rm SPACE ID` | A space's Claude chats |
| `thorn chat new SPACE` / `chat open SPACE ID` | Start a new chat, or go back to one |
| `thorn remote SPACE on\|off` | Remote Control on, or off: one local conversation, only from the hub |
| `thorn rm SPACE [--purge]` | Delete; files are archived unless `--purge` |
| `thorn bridge add FROM TO [--for 1h]` / `bridge rm` / `bridge ls` | Let one space reach another space's machine for a while |
| `thorn host add NAME USER@IP [--port P]` | Register a machine and create its key |
| `thorn host ls` / `host check` / `host pubkey` / `host rescan` / `host rename` / `host rm` | Manage machines |
| `thorn host set-address NAME USER@IP [--port P]` | Move a machine to a new address (e.g. LAN to tailnet); its spaces stay |
| `thorn host block NAME [--for 30m] [--reason R]` / `host unblock` | Cut a machine off from every space |
| `thorn web enable\|disable` / `web user add\|rm\|ls\|rename\|passwd\|totp-reset` | The web UI and its accounts |
| `thorn web https [--cert C --key K --name N \| --tailscale \| --off]` | HTTPS for the web UI (needed for passkeys) |
| `thorn web user passkey-rm NAME PASSKEY` | Remove a lost passkey |
| `thorn notify set [URL] [--token]` / `notify show\|test\|off` | Notifications to an ntfy topic (no URL: a new random topic on ntfy.sh) |
| `thorn config show` / `config set KEY VALUE` | The settings the web UI can change: admin devices, never_manage, web address, ... |
| `thorn harden ssh --totp\|--fido` / `harden confirm\|undo` | Two-factor SSH to the hub |
| `thorn firewall show [--planned]` / `firewall apply` | Inspect or reload the rules |
| `thorn apply` | Rewrite all generated files and reload everything |
| `thorn update [--check]` | Install the latest release (settings, accounts and spaces stay) |

Commands that change anything must run as root.

### Spaces and agents

A space runs **Claude Code** by default, as a Remote Control server with
many chats. `--single` gives one conversation that you can also type into
on the terminal. `--local` (or Remote Control off on its page) leaves
Remote Control out altogether: one conversation, reached only from the hub,
through the web UI's terminal or `thorn attach`, and not shown in your
Claude account's session list. Options for Claude Code go after `--arg`:

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
| `ssh_from` | `[]` | The hub's addresses as machines see them, for `from="..."` in key lines. Empty: the hub's source address on the route to each machine |
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

### Starting on a LAN, moving to a tailnet later

Everything works on a plain LAN: the web UI listens on every address, and
each key line is limited to the hub's LAN address (the address it uses to
reach that machine). Give the hub a fixed LAN address (a DHCP reservation),
since the key lines depend on it. To move to a tailnet later:

1. Join the hub (and the machines) to the tailnet, as above.
2. On the Settings page (or with `sudo thorn config set`), set `web.listen`
   to the hub's tailnet address and `inbound.admin_from` to your devices'
   tailnet addresses.
3. For each machine: `sudo thorn host set-address fig root@100.80.0.3`
   (or *Address* on its page in the web UI), and replace its line in
   `authorized_keys` with the new one it prints.
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
