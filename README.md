# blackthorn

blackthorn turns one small, isolated machine into a hub for
[Claude Code](https://code.claude.com). Sessions keep running there in tmux,
reachable from your phone or laptop through Remote Control. Each session can
reach only the machines you grant it, over SSH, and you can cut a machine off
from every session with one command.

Status: **early (v0.1)**. It works and is tested end to end, but expect
changes. Read [THREAT_MODEL.md](THREAT_MODEL.md) before trusting it with
anything important.

## Why

- **One place to sign in.** Claude Code runs only on the hub. The machines it
  works on need nothing but an SSH server and one line in `authorized_keys`.
- **One way only.** The hub connects out to your machines; they have no way
  back in. A compromised machine holds no Claude credentials and no keys to
  anything else.
- **Real boundaries, not instructions.** What a session can reach is
  enforced by the kernel and by which keys it holds, not by asking the model
  nicely. The generated `CLAUDE.md` explains the rules to Claude, but nothing
  depends on Claude following them.
- **Always on.** Sessions survive disconnects, restart after crashes, and
  come back with the same conversation and Remote Control name after a
  reboot.

## How it works

```
 your phone / laptop ── Remote Control (via claude.ai) ──┐
 you ── SSH (admin only) ──┐                             │
                           ▼                             ▼
 ┌──────────────────────── blackthorn hub ───────────────────────────┐
 │ thorn (root): state, keys, firewall, systemd units                │
 │                                                                   │
 │ session "ops"  = Unix user bt-1a2b3c4d                            │
 │   tmux ─ claude --remote-control ops                              │
 │   ssh-agent: keys for fig, nas      nftables: may reach fig, nas  │
 │                                                                   │
 │ session "site" = Unix user bt-5e6f7a8b                            │
 │   tmux ─ claude --remote-control site                             │
 │   ssh-agent: key for web1           nftables: may reach web1      │
 └───────────────┬───────────────────────────────────────────────────┘
                 │ outbound SSH only
        ┌────────┼─────────┐
        ▼        ▼         ▼
       fig      nas       web1      (cannot connect to the hub)
```

Each session is:

- **its own Unix user** (`bt-<key>`), so sessions cannot read each other's
  files, credentials or agents;
- **a systemd unit** (`blackthorn-session@<key>`) running a tmux server whose
  only pane runs Claude Code with `--remote-control`, sandboxed with
  `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges` and friends;
- **an ssh-agent** (`blackthorn-agent@<key>`) holding the keys of the hosts
  the session may use. Private keys stay in root-only files; root loads them
  into the agent, and ssh-agent refuses to let the session user read its
  memory;
- **nftables rules** matching the session's uid: it may send packets only to
  loopback, your DNS servers, HTTPS (for Anthropic), and the SSH port of each
  granted host. Everything else is rejected, including packets on
  connections that were already open, so a block takes effect at once.

## Requirements

- A dedicated machine or VM running Debian 13 with systemd. Nothing else
  should run on it. (Other systemd distributions with nftables may work but
  are untested.)
- `tmux`, `openssh-client`, `nftables` (`thorn init` tells you what is missing).
- A Claude plan with Remote Control (Pro, Max, Team or Enterprise). Each
  session signs in once with `thorn login`; tokens from `claude setup-token`
  cannot be used, because they cannot start Remote Control.
- Machines to manage, reachable from the hub at a fixed IP address (a
  Tailscale or Headscale tailnet address works well).

## Install

blackthorn is not meant to have a compiler on the hub. Build it elsewhere:

```sh
cargo build --release          # produces target/release/thorn
```

Copy `thorn` to the hub. There, install Claude Code for your own admin user
the usual way, then:

```sh
sudo apt install tmux openssh-client nftables
sudo ./thorn init --claude-from ~/.local/bin/claude
```

`init` installs `thorn` to `/usr/local/bin`, copies the Claude Code binary to
`/usr/local/bin/claude` (sessions run that copy and never update it
themselves; run `init --claude-from` again to update), installs the systemd
units, and loads the firewall.

## Quick start

```sh
# 1. Register a machine (by IP). You are shown its host-key fingerprints to confirm.
sudo thorn host add fig root@100.80.0.3

# 2. Put the printed line in fig's ~root/.ssh/authorized_keys, then check:
sudo thorn host check fig

# 3. Create a session that may use fig, sign it in, and it starts.
sudo thorn new ops --host fig
sudo thorn login ops

# 4. Open "ops" in Remote Control on your phone, or attach on the hub:
sudo thorn attach ops          # leave with Ctrl-b then d
```

Cut a machine off while you investigate something, for an hour:

```sh
sudo thorn host block fig --for 1h --reason "kernel upgrade"
```

## Commands

| Command | What it does |
|---|---|
| `thorn init [--claude-from PATH]` | Set up the hub, or update Claude Code |
| `thorn status` | Firewall, timer, Claude version, sessions, blocked hosts |
| `thorn ls` | Sessions: state, Remote Control name, hosts, memory |
| `thorn new NAME [--host H,...] [--rc-name N] [--arg A]...` | Create a session |
| `thorn login NAME` | Sign the session in to Claude, then start it |
| `thorn start\|stop\|restart NAME... \| --all` | Control sessions |
| `thorn attach NAME` | Open the session's terminal |
| `thorn rename OLD NEW [--rc-name N]` | Rename; same conversation |
| `thorn rm NAME [--purge]` | Delete; files are archived unless `--purge` |
| `thorn grant SESSION HOST...` / `thorn revoke SESSION HOST...` | Change what a session may reach (takes effect now) |
| `thorn host add NAME USER@IP [--port P]` | Register a machine and create its key |
| `thorn host ls` | Machines, which sessions use them, block status |
| `thorn host block NAME [--for 30m] [--reason R]` / `host unblock NAME` | Cut a machine off from every session |
| `thorn host pubkey NAME` | The `authorized_keys` line for the machine |
| `thorn host check NAME` | Test that the hub can log in |
| `thorn host rescan NAME` | Re-read host keys after reinstalling the machine |
| `thorn host rm NAME` | Forget a machine and revoke it everywhere |
| `thorn firewall show [--planned]` / `firewall apply` | Inspect or reload the rules |
| `thorn apply` | Rewrite all generated files and reload everything |

Commands that change anything must run as root.

Passing options to Claude Code, for example a permission mode:

```sh
sudo thorn new ops --host fig --arg=--permission-mode --arg=acceptEdits
```

## Configuration

`/etc/blackthorn/config.toml` (run `sudo thorn apply` after editing):

| Key | Default | Meaning |
|---|---|---|
| `claude_bin` | `/usr/local/bin/claude` | Claude Code binary sessions run |
| `claude_args` | `[]` | Arguments added to every session |
| `egress.https_anywhere` | `true` | Allow HTTPS to any address (Claude Code needs Anthropic, whose addresses change). See the threat model |
| `egress.dns` | `[]` | DNS servers sessions may use; empty means those in `/etc/resolv.conf` |

## Files

| Path | Contents |
|---|---|
| `/etc/blackthorn/config.toml` | Configuration |
| `/etc/blackthorn/keys/` | One private key per host (root only) |
| `/var/lib/blackthorn/state.toml` | Hosts, sessions, blocks (root only; edit with `thorn`) |
| `/var/lib/blackthorn/sessions/<key>/` | Session home: Claude config, credentials, conversations |
| `/var/lib/blackthorn/sessions/<key>/work/CLAUDE.md` | Generated rules and host list for Claude |
| `/var/lib/blackthorn/archive/` | Removed sessions |
| `/etc/systemd/system/blackthorn-*` | Units installed by `thorn init` |

## Hardening the hub

blackthorn limits what sessions can do. Protecting the hub itself is up to
you:

- Run it as a dedicated VM. Put a firewall *outside* it (for example the
  Proxmox VM firewall): no inbound connections except your admin SSH.
  Remote Control needs no inbound port.
- Reach it for administration over a private network (such as a tailnet)
  whose access rules let your own devices in and keep managed machines out.
- Allow SSH key logins only.
- On managed machines, prefer a non-root user for the hub's key.

## Development

```sh
cargo test                       # unit tests
sudo cargo test -- --ignored     # also checks the generated rules with `nft -c`
tests/e2e/run.sh                 # full test in throwaway Docker containers
```

The end-to-end test starts a systemd container as the hub and two SSH
targets, and checks isolation between sessions, blocks, grants, renames,
reboots and removal, using a fake `claude`.

## License

[MIT](LICENSE). blackthorn is an independent project, not affiliated with
Anthropic.
