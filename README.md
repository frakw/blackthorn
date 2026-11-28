# <img src="assets/logo.svg" width="40" height="40" alt="" align="top"> blackthorn

blackthorn turns one small, isolated machine into the place where your AI
coding agents live. They keep running there, you reach them from your phone
or laptop, and each one can work on exactly one of your machines, over SSH,
one way only.

Status: **early (v0.18)**. It works and is tested end to end, but expect
changes. Read [THREAT_MODEL.md](THREAT_MODEL.md) before trusting it with
anything important.

## What it does

1. **Agents that keep running.** Each space runs Claude Code as a Remote
   Control server: open as many chats as you like from the Claude app or
   claude.ai/code. Spaces survive disconnects, restart after crashes and
   come back after a reboot.
2. **Many machines from one place.** Sign in to Claude on the hub only. The
   machines it works on need an SSH server and one line in
   `authorized_keys`. Linux, macOS and Windows.
3. **One-way isolation, simple permissions.** A space is *one agent + the
   machines you give it*. It can reach those machines and nothing else; the
   machines cannot reach the hub at all. Cut a machine off from everything
   with one **block**. All of it is enforced by the kernel, not by asking
   the model. On the machines themselves, each space has **logins of its
   own**, set machine by machine: an ordinary user for its project, a
   read-only one, and root only for a time you choose, and only one space
   at a time on a machine.
4. **Keys stay on the hub.** Private keys never leave root-only files; each
   space gets only its own key, through an agent it cannot read. Keys only
   work from the hub's address.
5. **See everything.** A web UI with a live map of machines and spaces,
   or the same from the command line. Every command a space runs
   is recorded on the hub, and on machines set up for logins of each
   space's own, in their own system log too.

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
 │ space "ops"         = Unix user bt-5e6f7a8b                       │
 │   tmux ─ codex (chats on the web)   ssh-agent: fig's read-only    │
 │                                       key, nas's user key         │
 │                                     nftables: fig:22, nas:22      │
 └───────────────┬───────────────────────────────────────────────────┘
                 │ outbound SSH only
        ┌────────┴─────────┐
        ▼                  ▼
       fig                nas
       (machines cannot connect to the hub: the hub's firewall drops them)
```

Each space is:

- **its own Unix user** (`bt-<key>`), so spaces cannot read each other's
  files, credentials or agents;
- **a systemd unit** (`blackthorn-space@<key>`) running a tmux server whose
  only pane runs the agent, sandboxed with `ProtectSystem=strict`,
  `ProtectHome`, `NoNewPrivileges` and friends;
- **an ssh-agent** (`blackthorn-agent@<key>`) holding the keys of its
  machines, each for the login it has there now: a machine where it is
  read-only gets no key that logs in as more. Root loads the keys;
  ssh-agent refuses to let the space user read its memory;
- **nftables rules** matching the space's uid: it may send packets only to
  loopback, your DNS servers, HTTPS (for Anthropic), and the SSH port of
  the machines it may reach. Everything else is rejected, including packets
  on connections that were already open, so blocks and taking a machine
  from a space take effect at once.

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
- For Codex spaces: a ChatGPT plan with Codex (device code sign-in allowed
  for your account or workspace), or an OpenAI API key.
- Machines to manage (Linux, macOS or Windows with OpenSSH Server),
  reachable from the hub at a fixed IP address. A Tailscale or Headscale
  tailnet works well. Logins of each space's own are for Linux machines;
  see [macOS and Windows machines](#macos-and-windows-machines).

## Install

On the hub (Debian, Ubuntu, Fedora or Arch, with systemd):

```sh
curl -fsSL https://blackthorn.frakw.work/install.sh | sh
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

A machine blackthorn reaches as root is then set up for logins of each
space's own by itself (see [Logins](#logins)). What a space may do there:

```sh
sudo thorn access fig-claude user        # its usual login: user or read-only
sudo thorn root fig-claude --for 8h      # root for a time (or --forever), then back
sudo thorn root fig-claude --off         # take it back now
```

Let `fig-claude` work on `nas` too (read-only there unless you say
otherwise; each machine has its own login and root), take it away again,
or cut a machine off for an hour:

```sh
sudo thorn connect fig-claude nas                 # --access user for more
sudo thorn root fig-claude --host nas --for 1h    # root on nas only
sudo thorn disconnect fig-claude nas
sudo thorn host block fig --for 1h --reason "kernel upgrade"
```

One space at a time has root on a machine: giving it to another takes it
from the first only when you say so (`--take`, or the checkbox on the
web). Spaces with a user login there cannot touch each other's files, so
root is the one way two spaces could change the same thing. Other chats of
the same space can still be at work on a machine at once: each space's
instructions tell its agent to look at what ran there lately
(`journalctl -t blackthorn`) before changing the machine itself.

## Web UI

The web UI is the everyday way to run blackthorn, on a laptop or a phone:

- **Map**: the Claude app and the models your spaces use (framed as
  Anthropic's cloud, with your devices beside it), your tailnet and LAN
  (with the router, the hub's way to the internet), the device you manage
  the hub from, the hub (blackthorn and its spaces, framed as one machine), and
  the machines the spaces work on, as boxes and wires like a node editor.
  Arrows point the way commands go.
  Drag boxes around, pan and zoom; the layout is remembered in your browser.
- **Spaces**: each one's chats (new, continue, stop, delete; with
  Remote Control a new chat runs next to the others and shows in the Claude
  app), each with its own page to read and type into it (see
  [Chats on the web](#chats-on-the-web)),
  a live view of its terminal, Claude sign-in, its machines (the login and
  root on each, adding and removing them), Remote Control on or off, and
  the name the Claude app lists it by.
- **Machines**: the key line to install (with a Copy button), checking the
  machine's host keys, blocks, renaming.
- **Settings**: who may connect, never_manage and the web address, edited
  as lists of addresses with a picker that knows your tailnet's devices and
  whether they are online; Tailscale on the hub (install, sign in, its
  state, its own web interface); and the blackthorn version, with one-click
  updates.
- **Notifications** (on the Settings page): pushed to your phone through
  [ntfy](https://ntfy.sh) (ntfy.sh or your own server) when a managed
  machine tries to connect to the hub, a space fails or must sign in again,
  a block or root time ends, or a new release is out.
- **Account**: rename it, change your password, or move to a new
  authenticator app; see where it is logged in (browser, system, address,
  last used) and end any of those logins.

The command line can do everything it can, for when it is down.

Logins need the password and a TOTP code; deleting or renaming anything,
removing a machine, adding one to a space, accepting new host keys and changing
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
| `thorn status [--json]` | The map: machines, the spaces on them, hub health |
| `thorn ls` | Spaces: machines, agent, logins, state, what they can reach |
| `thorn new HOST [--agent A] [--name N] [--access user\|read-only] [--root 8h\|forever\|no] [--single] [--local] [--arg A]...` | Create a space on a machine |
| `thorn login SPACE [--api-key]` | Sign a Claude or Codex space in, then start it (Codex: a device code, or an API key on standard input) |
| `thorn codex status` / `install` | OpenAI's Codex on the hub: its version; install or update it |
| `thorn codex chats\|show\|new\|send\|stop\|answer\|rename\|archive\|models SPACE ...` | A Codex space's chats: list, read, start, write (with `--file`, `--model`, `--effort`), stop, answer what Codex asks; the models it offers |
| `thorn start\|stop\|restart SPACE... \| --all` | Control spaces |
| `thorn connect SPACE HOST [--access read-only\|user]` / `thorn disconnect SPACE HOST` | Let a space work on one more machine (read-only by default); take one from it |
| `thorn access SPACE user\|read-only [--host H]` | A space's usual login on one of its machines; applies at once |
| `thorn root SPACE [--host H] [--take] [--for 8h \| --forever \| --ask \| --off]` | Give a space root on one of its machines for a time (at most 72h), until taken back, or on approval; take it back. One space at a time per machine (`--take` takes it over) |
| `thorn approvals [--all]` / `thorn approve ID` / `thorn deny ID [--reason R]` | Root commands spaces with root on approval asked for |
| `thorn log SPACE [-n 50]` | The commands a space ran (recorded by root) |
| `thorn attach SPACE` | Open the space's terminal |
| `thorn screen SPACE` / `thorn send SPACE TEXT` | Read or type into the terminal without attaching |
| `thorn rename OLD NEW [--rc-name N]` | Rename; same chats |
| `thorn share SPACE ACCOUNT view\|use\|manage\|none` / `thorn owner SPACE ACCOUNT` | Share a space; give it away |
| `thorn chat ls SPACE` / `chat new SPACE [--name N]` / `chat send SPACE ID TEXT` / `chat stop SPACE ID` / `chat rm SPACE ID` | A space's Claude chats |
| `thorn chat new SPACE [--name N]` / `chat open SPACE ID` | Start a new chat, or go back to one |
| `thorn remote SPACE on\|off` | Remote Control on, or off: one local conversation, only from the hub |
| `thorn rm SPACE [--purge] [--purge-data]` | Delete; files are archived unless `--purge`; its folder on the machine stays unless `--purge-data` |
| `thorn host add NAME USER@IP [--port P]` | Register a machine and create its key |
| `thorn host ls` / `host check` / `host pubkey` / `host rescan` / `host rename` / `host rm` | Manage machines |
| `thorn host setup NAME [--print \| --verify]` | Set a Linux machine up for logins of each space's own, and log their commands there |
| `thorn host set-address NAME USER@IP [--port P]` | Move a machine to a new address (e.g. LAN to tailnet); its spaces stay |
| `thorn host block NAME [--for 30m] [--reason R]` / `host unblock` | Cut a machine off from every space |
| `thorn web enable\|disable` / `web user add [--admin]\|admin\|rm\|ls\|rename\|passwd\|totp-reset` | The web UI and its accounts |
| `thorn web https [--cert C --key K --name N \| --tailscale \| --off]` | HTTPS for the web UI (needed for passkeys) |
| `thorn web user passkey-rm NAME PASSKEY` | Remove a lost passkey |
| `thorn notify set [URL] [--token]` / `notify show\|test\|off` | Notifications to an ntfy topic (no URL: a new random topic on ntfy.sh) |
| `thorn config show` / `config set KEY VALUE` | The settings the web UI can change: admin devices, never_manage, web address, ... |
| `thorn harden ssh --totp\|--fido` / `harden confirm\|undo` | Two-factor SSH to the hub |
| `thorn firewall show [--planned]` / `firewall apply` | Inspect or reload the rules |
| `thorn apply` | Rewrite all generated files and reload everything |
| `thorn update [--check]` | Install the latest release (settings, accounts and spaces stay) |
| `thorn export FILE [--password]` / `thorn import FILE [--replace]` | Save everything to one file (with a password if you like); bring it back with the same version |
| `thorn tailscale status` / `install` / `up` / `web on\|off` | Tailscale on the hub |

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

**Codex** (OpenAI's coding agent) runs in a space too: install it once
(`sudo thorn codex install`, or Settings → Codex; OpenAI's installer, into
`/opt/codex`, where spaces can run it but not change it), then

```sh
sudo thorn new fig --agent codex        # creates "fig-codex"
sudo thorn login fig-codex              # a page and a code to enter there
echo "$OPENAI_API_KEY" | sudo thorn login fig-codex --api-key   # or a key
```

A Codex space reads its instructions from `AGENTS.md`, runs Codex without
Codex's own sandbox (the space already is one: its own user, firewall and
logins) and with Codex asking before commands it is unsure of. Its chats
are on its page in the web UI: start as many as you like, each a
conversation of its own, and continue any of them later. The page shows
what Codex says, the commands it runs with their output, and the files it
changes; when Codex asks to run something, the chat shows what and offers
**Allow once**, **Allow for this chat**, **Decline** or **Decline and
stop**.

Add files to a message with **+**, by dropping them on the box, or by
pasting a picture. Files are saved in the space's work folder, under
`.uploads/`, with the same 10 MB limit as Claude chats. Codex shows
pictures to the model. For any other file, Codex gets its path and opens
it itself.

Each chat has its own model and reasoning effort, picked under the
message box from the models your Codex account offers. A change applies
from your next message. The same from the command line:

```sh
sudo thorn codex chats fig-codex
sudo thorn codex new fig-codex "Why is nginx restarting?"
sudo thorn codex show fig-codex 0199a2         # the start of a chat's id
sudo thorn codex send fig-codex 0199a2 "Check the logs from last night too"
sudo thorn codex send fig-codex 0199a2 "What is this?" --file shot.png
sudo thorn codex models fig-codex              # its models and efforts
sudo thorn codex send fig-codex 0199a2 "Think harder" --model gpt-5.5 --effort high
sudo thorn codex answer fig-codex 0199a2 1 accept
```

Behind the page, the space runs `codex app-server` (Codex's own interface
for programs, the one its editor extensions use) through a small bridge
the hub reaches over a socket; the space's terminal shows the bridge's log.
OpenAI's phone remote control needs their desktop app, so it is not
offered. The commands it runs are recorded like Claude's.

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
listing what it can reach, as whom, and the rules of the hub.

### Logins

The hub decides *which* machine a space reaches; what the space may do
there is up to the login it uses. If that login is root, an agent misled by
text it read (or simply wrong) runs as root, and from that machine it can
also reach the internet past the hub's firewall. So the real limit has to
be on the machine.

`thorn host setup NAME` sets a Linux machine up so that each space has
logins of its own there. blackthorn logs in as the machine's own login
(root, or a user with sudo without a password) and:

- has sshd also read key lines from `/etc/ssh/blackthorn/<user>`, and
  take blackthorn's certificates (see *SSH certificates* below), both
  where only root writes, so no space can change its own lines;
- puts a logger in front of every blackthorn key (`command=` in the key
  line), so every command is in the machine's system log, under the
  space's own user: `journalctl -t blackthorn`;
- installs sudo if missing, and checks for rootless Docker (Debian and
  Ubuntu with Docker's packages for now).

Then each space gets, with keys of its own (`from="<hub>",restrict`):

- **`bt-<id>`**, an ordinary user: its home and `/srv/<space>` are its
  own, and it runs its own containers (rootless Docker, apart from the
  machine's) and services (`systemctl --user`, lingering). No sudo. Ports
  below 1024 are not its to open.
- **`bt-<id>-ro`**, which only looks: in the `adm` and `systemd-journal`
  groups, so it reads `/var/log` and `journalctl`; with sudo for the Docker
  commands that only read (`docker ps`, `logs`, `stats --no-stream`,
  `images`, `top`, `system df`), of the machine's Docker and of its own
  user login's; and it reads `/srv/<space>`. Not in the list, on purpose,
  because each amounts to root or hands out secrets: the `docker` group,
  `docker exec`, `run`, `cp`, `compose`, `docker inspect` (environment
  variables hold passwords), `apt`, `systemctl restart`.
- **root**, only when you give it: `bt-<id>` may then use sudo for
  anything, for a time (15 minutes to 72 hours) or until you take it back.
  When it ends, the space goes back to its usual login at once (its open
  connections are cut, with what they ran as root); its chats go on. With
  a time, the machine also takes root back by itself, even if the hub
  cannot reach it then. What root did meanwhile (packages, configuration,
  timers) stays: the system log has every command.

**Root on approval** is the careful way to give root: the space logs in
as its user, and may use sudo for one program alone, `blackthorn-ask`. It
asks with the whole command (and any script on its standard input, up to
1 MB); the ask waits on the machine; the hub, which keeps an SSH
connection open to it (the machine never connects back), shows it under
*Approvals*, on the chat's page, and in a notification. What you approve
runs as root exactly as it was shown; what you refuse, or leave for 10
minutes, does not. Signs worth a second look (a downloaded script, decoded
text, `rm -rf`, keys) are pointed out, not refused. Deciding needs a browser
unlocked as for typing into chats, and *manage* on the space; every ask
and decision goes to the space's log.

On each of its machines, a space has a usual login, user or read-only, and
root on top for a time. Change either at once, on the space's page or with
`thorn access` and `thorn root` (`--host` when it has several machines);
going up needs an authenticator code on the web, going down does not. New
spaces get root on their machine for 8 hours, then user; a machine added
later (`thorn connect`) starts read-only. One space at a time has root on a
machine. Each machine has a user key of its own, and the space's agent
holds it only while the space may log in there as more than read-only.

blackthorn sets up machines it reaches as root by itself (once an hour
until it works). One it reaches as an ordinary user cannot be set up that
way: its spaces log in as that user, with all that user can do, and no
root. To set it up anyway, `thorn host setup NAME --print` prints the
script; run it there as root (it also lets blackthorn's key log in as
root), then `thorn host setup NAME --verify`. Run the setup again after
the machine moves address.

### SSH certificates

On a set-up machine, the spaces and blackthorn itself log in with
**certificates** instead of keys the machine lists. The setup makes the
machine's sshd trust blackthorn's certificate authority
(`/etc/ssh/blackthorn/ca.pub`) for the names in
`/etc/ssh/blackthorn/principals/<login>`, each line with the hub's
addresses and the logger, as the key lines were. A machine whose sshd
already trusts another authority keeps the key lines.

- A space's key exists only in memory (`/run`), made again at every
  boot. Its agent holds one certificate naming the logins it has now
  (its user login on one machine, its read-only login on another), good
  for ten minutes and renewed every minute while it may work there.
  Taking a machine away, or lowering a login, changes the next
  certificate, and the old one is useless within minutes.
- blackthorn's own management login gets a certificate the same way.
  Its key line stays in the machine's `authorized_keys` until you remove
  it: **Remove the key line** on the machine's page (or
  `thorn host drop-key NAME`) checks that a certificate alone logs in,
  then removes it. After that, nothing stored on the hub opens the
  machine by itself.
- Every certificate has a serial, written to
  `/var/log/blackthorn/certs.log` on the hub and to the machine's sshd log
  when it is used. A serial on a machine that the hub did not log is a
  certificate someone else signed.

The hub CA's private key is in `/etc/blackthorn/ca`, root's alone, so
whoever has root on the hub can sign certificates while they have it.
The **recovery key** is for after: make it once (Settings → SSH
certificates, or `thorn ca recovery`), keep it away from the hub (a
password manager, or paper), and the machines trust it too. After a
break-in, on a new hub restored from an export:

```sh
sudo thorn ca rotate --recovery-key recovery.key   # a new hub CA, sent to every machine
sudo thorn ca recovery --replace                   # the old recovery key has been used
```

The old hub CA stops working on every machine reached; `thorn ca push
--recovery-key FILE` reaches the rest later. `thorn ca status` shows the
CAs, the machines that trust them and the latest certificates.

### macOS and Windows machines

blackthorn manages macOS and Windows machines too, more simply: their
spaces log in as the account blackthorn was given there, with everything
it may do (its files, its keys, `sudo` if it needs no password). Logins of
each space's own, root for a time and root on approval are for Linux
machines. Give blackthorn an account made for it, with only what its
spaces need.

- **macOS**: turn on Remote Login (System Settings → General → Sharing),
  then add blackthorn's key line to that account's
  `~/.ssh/authorized_keys`. Spaces are told it is macOS (zsh, BSD tools).
- **Windows**: install OpenSSH Server and start it, in PowerShell as
  administrator (the install can take several minutes; where it cannot use
  Windows Update, install the MSI from
  [Win32-OpenSSH's releases](https://github.com/PowerShell/Win32-OpenSSH/releases)
  instead):

  ```powershell
  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
  Start-Service sshd; Set-Service sshd -StartupType Automatic
  # only your tailnet may reach port 22
  New-NetFirewallRule -Name sshd-tailnet -DisplayName 'OpenSSH (tailnet)' -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress 100.64.0.0/10 -Action Allow
  ```

  Then, for an administrator account, the key line goes in
  `C:\ProgramData\ssh\administrators_authorized_keys`, which only
  Administrators and SYSTEM may change; for another account, in its
  `%USERPROFILE%\.ssh\authorized_keys` (both exist only once sshd has
  started). The machine's page in the web UI has the PowerShell commands.
  Tested on Windows 10 IoT LTSC with Win32-OpenSSH 10.4, and on macOS 26.4.

`thorn host check NAME` (or Check login on its page) finds out which it is,
and on Windows whether its SSH server runs commands in cmd.exe or
PowerShell; the spaces' instructions say so, with how to quote for it. The
commands a space runs there are recorded on the hub as on any machine, but
not in the machine's own log.

### What a space did

Every shell command a Claude space runs is copied from its chats into
`/var/log/blackthorn/<space>.log` once a minute, by root: `thorn log SPACE`,
or the space's *Activity* card. The chats belong to the space and it could
rewrite them; the copy is root's, and a chat that shrinks is noted.

### Names in the Claude app

The Claude app lists each Remote Control space as an *environment* named
after its folder, which is its Remote Control name. A chat started with a
name (*New chat*, or `thorn chat new SPACE --name NAME`) is called
`<first 8 characters of its id> NAME` there, e.g. `9cf982e0 web check`, so
it is easy to match with the hub's list. Otherwise it shows under Claude's
title for it, else `<Remote Control name>-<random>` until it has one.

The hub lists chats under Claude's own names and does not rename them: a
running Claude Code keeps its name in memory and writes it back when it
stops. Rename a chat by typing `/rename NAME` in it.

Changing a Remote Control name moves the folder, so the app gets a new
environment. The old one stays in its list, offline, until Anthropic clears
it: Claude Code keeps it on purpose so a restarted space can take its chats
back, and offers no way to delete it.

### Chats on the web

Each chat has a page (click its name on the space's page): Claude's
answers as they come, with code (coloured), lists and tables; the tools it used and
what they gave back, folded; edits as lines out and in. A long chat shows
its latest part first; *Load earlier messages* brings the rest. A new chat
opens on its page.

To type into chats from a browser, unlock it once with your password and
a code; it stays so for `web.session_hours` (24 by default), and the
Account page lists and ends it like a login. Then:

- **Send** a message (Enter on a computer, Shift+Enter for a new line).
- **+**: add files or photos (up to 10 MB each, or paste a picture into
  the box). Pictures show as previews; remove any, or drag them into
  order. They are saved in the chat's folder under `.uploads/` and
  mentioned at the end of the message as `@.uploads/...`, in that order,
  so Claude reads them.
- **Model and effort** (under the box): sent to the chat as `/model` and
  `/effort`; the button shows the model of the latest answer.
- **/**: Claude Code's commands, and the space's own commands and skills.
- **Stop** while Claude works (Escape), and buttons for the choices when it
  asks a question (allow a command, say). Nothing is typed while it asks.

Typing works for chats the hub runs: those started or continued from the
hub, and a one-chat space's chat. A chat started in the Claude app can be
read along; end it there and continue it from the hub to type. `thorn chat
send SPACE ID TEXT` does the same from the hub.

### Sharing spaces

Each space has an owner: the web account that made it (spaces made on the
hub's command line belong to the hub admins). Its owner, or anyone who may
manage it, shares it with other accounts, from its page or `thorn share
SPACE ACCOUNT view|use|manage|none`:

- **view**: read its chats, terminal and state;
- **use**: also type into its chats, answer Claude, start and stop chats
  and the space;
- **manage**: also change its settings and its logins on its machines,
  share it and delete it.

Its owner may also give it to another account (`thorn owner SPACE
ACCOUNT`); the old owner may still manage it. Hub admins (the first
account, and those made with `thorn web user add NAME --admin` or `thorn
web user admin NAME on`) may do everything, and alone see machines, add
machines to spaces and change settings. Other accounts see only the spaces they own or that
are shared with them.

Every message typed into a chat from the hub (the chat page, the
terminal, `thorn chat send`), every answer pressed and every file added is
recorded in the space's log with the account that did it (`thorn log`, the
Activity card), and the chat page shows who sent each.

## Backup and moving to a new hub

```sh
sudo thorn export /root/blackthorn.bt      # on the old hub; asks whether to set a password
sudo thorn import /root/blackthorn.bt      # on the new one, after install and thorn init; asks for it
```

The file holds `/etc/blackthorn`, `/var/lib/blackthorn` and
`/var/log/blackthorn`: settings, machine keys, web accounts, every space
with its Claude login and chats, and what the spaces ran. It is written
readable by root only; it holds every secret on the hub, so give it a
password (`--password`; without a terminal, the first line of standard
input) or keep it like one. With a password the whole file is sealed
(Argon2id and ChaCha20-Poly1305, in checked pieces): a wrong password or a
damaged file is refused before anything on the hub changes, and a lost
password cannot be recovered. Only the version of blackthorn that made it imports it (`thorn
update` first, or install that version), so nothing is read by code that
expects something else.

Importing sets aside what the hub has (`/etc/blackthorn.before-import-*`
and so on), stops and removes the spaces' users, unpacks the file, gives
each space a user again, reloads the firewall and starts the spaces. A hub
that already has spaces or machines needs `--replace`. The settings come
along as they were, including the web UI's address: on a hub with another
address, set it again with `thorn config set`.

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

The **Settings** page (or `sudo thorn tailscale`) installs Tailscale with
its own installer, signs the hub in to Tailscale's coordination server (a
sign-in link shows there), shows its state, and turns on Tailscale's own
web interface (port 5252 on the hub's tailnet address, limited like the
web UI by `inbound.admin_from`), with a link to it and to the admin
console. It keeps the hub's DNS settings (`--accept-dns=false`). For
Headscale, a tag or other options, run `tailscale up` yourself:

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
| `/var/lib/blackthorn/state.toml` | Machines, spaces and their machines, blocks (root only; use `thorn`) |
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
firewall, the web UI (login, CSRF, step-up codes, Claude sign-in), spaces on several machines,
blocks, renames, SSH two-factor with its automatic undo, reboots and
removal, using a fake `claude`.

## License

[MIT](LICENSE). blackthorn is an independent project, not affiliated with
Anthropic.
