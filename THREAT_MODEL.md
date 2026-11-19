# Threat model

This document says what blackthorn protects against, how, and what it does
not protect against. If something here is wrong or missing, please open an
issue.

## What is being protected

- **The managed machines**, from actions you did not intend.
- **The hub's secrets**: the Claude sign-in of each space, the SSH private
  keys for the managed machines, and the web UI's accounts.
- **Isolation between spaces**: work on one machine should not spill onto
  another.
- **The hub itself**, from the machines it manages: they must have no way
  back.

## Who is trusted

- **Root on the hub** (you). Root can do everything blackthorn prevents.
- **The hypervisor** hosting the hub, and anyone who controls it.
- **Anthropic's service**, which runs the model and relays Remote Control.
- **Your Claude account.** Anyone who can sign in to it can drive your
  spaces through Remote Control. Protect it with strong authentication.
- **Your admin devices** (the laptop and phone listed in
  `inbound.admin_from`) and your web UI password and authenticator.
- **Whatever controls the network path to the hub's admin SSH**, for example
  a Tailscale or Headscale control server: it decides who can reach port 22.
  Key-only SSH remains the last barrier.

## Threats considered

1. **A managed machine is compromised.** The attacker controls that
   machine, including what it returns to the hub.
2. **Prompt injection.** Text the model reads (a file, a log line, command
   output, a web page) tries to make it do something else, such as reaching
   another machine or leaking data.
3. **A misbehaving space.** For whatever reason, the agent of one space runs
   arbitrary commands as its own Unix user.
4. **Attacks on the web UI** from the network it listens on: password
   guessing, cross-site request forgery, malformed HTTP.

## What blackthorn enforces

These hold even if the model does exactly what an attacker wants, because
they are enforced by the kernel or by what the space has, not by the model.

| Control | Mechanism |
|---|---|
| Spaces are separated | Each space is its own Unix user with its own home (mode 0700). |
| A space reaches only its machine | nftables rules match the space's uid and allow only the IP and SSH port of its machine (and of machines it has an active bridge to) while not blocked, plus DNS and HTTPS. Everything else is rejected. |
| Blocks and bridge ends are immediate | There is no "established connections are allowed" rule for spaces, so packets on open connections are rejected too. Keys are removed from agents at the same time. Timed blocks and bridges end within a minute of their time. |
| Bridges are one-way | A bridge from A to B gives A's user B's machine; B's user gains nothing. |
| Managed machines cannot reach the hub | The hub's input rules drop every connection from a managed machine (and from `never_manage`/`deny_from` addresses). Replies to the hub's own SSH connections still arrive. blackthorn refuses to manage an address listed in `inbound.admin_from` or the address you are connected from. |
| Admin ports only from your devices | If `inbound.admin_from` is set, only those addresses may reach SSH and the web UI. |
| Spaces never see private keys | Keys are root-only files. Root loads them into the space's ssh-agent, which marks itself non-dumpable so the space user cannot read its memory. |
| Stolen keys are useless elsewhere | The suggested `authorized_keys` line has `from="<hub address>"` and `restrict`: usable only from the hub, with no port, agent or X11 forwarding and no pty. |
| Host identities are pinned | Machines are stored by IP address, not name, and their host keys are recorded when added, after you confirm the fingerprints. |
| Spaces cannot change the system | systemd sandbox: `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, `PrivateTmp`, `RestrictSUIDSGID`, and more. |
| Without the firewall, nothing runs | Space units require the firewall unit, and stopping the firewall unit leaves its rules loaded. |
| The web UI's network side has no power | The HTTP listener runs as the unprivileged `blackthorn-web` user in a tight systemd sandbox, with no access to blackthorn's files. It forwards requests to a root API on a Unix socket, which accepts only that user, checks the password (Argon2id) and TOTP code itself, keeps the sessions, and enforces the CSRF value. A compromised web process can act only through a session a user has logged in to. |
| Logins resist guessing | Password and TOTP are both needed; each code works once; five failures lock the account and the address for 15 minutes. Deleting spaces, removing machines, opening bridges and accepting new host keys need a fresh code. |
| Web pages are hard to abuse | SameSite=Strict, HttpOnly session cookie; a CSRF value on every form; a CSP that allows no inline script or third-party resource; a small HTTP parser with size, time and connection limits. |
| SSH changes cannot lock you out | `thorn harden ssh` checks your authenticator first, validates sshd's configuration, and undoes itself unless you confirm from a new login. |

## What blackthorn does not protect against

Know these before you rely on it.

1. **Spaces share your Claude account.** Every space signs in to the same
   claude.ai account, and a space can read its own sign-in (Claude Code
   needs it). A misbehaving space could use that sign-in to reach your
   other spaces through Remote Control, around the firewall. Isolation
   between spaces therefore holds for machines and keys, not for the Claude
   account. Not addressed yet; separate Claude accounts per trust level
   avoid it.

2. **A bridge makes one trust zone.** While space A has a bridge to B's
   machine, injected text from either machine can drive A's actions on the
   other. Keep bridges short, and between machines you trust alike.

3. **A space can do anything its remote user can.** blackthorn decides
   *whether* a space reaches a machine, not *what* it does there. Use a
   non-root remote user, and sudo rules, for limits on the machine itself.

4. **Data can leave over HTTPS.** By default spaces may open HTTPS
   connections to any address, because Claude Code must reach Anthropic and
   Anthropic's addresses change. A misbehaving space can therefore send
   anything it can read (including data from its hosts) to any HTTPS server.
   DNS queries to the allowed resolvers are a second, slower channel. A
   domain-allowlisting egress proxy is planned. Set
   `egress.https_anywhere = false` if you can supply the addresses another
   way.

5. **ssh_config is a convenience, not a control.** The generated
   `~/.ssh/config` sets `ForwardAgent no`, `ClearAllForwardings yes` and
   strict host-key checking, but the space can run `ssh` with its own
   options. In particular it could forward its agent to its machine: the
   `restrict` option in the key line refuses that, if you used the line
   blackthorn suggests.

6. **Each space can change its own agent setup.** It owns its home, so it
   can edit its own settings, hooks and instructions file. This affects
   only that space.

7. **Root on the hub is everything.** Whoever gets root on the hub, through a
   kernel exploit, a bug in blackthorn (including its root API), or your own
   credentials, has every key and every space. Keep the hub minimal and
   updated, and run nothing else on it.

8. **The network overlay is trusted.** If the hub's admin ports are
   reachable through a tailnet, whoever controls the tailnet's control
   server can change who reaches them, and could give another node the
   address of one of your admin devices, getting past `inbound.admin_from`.
   The password, TOTP code and SSH keys still stand in the way. Run the
   control server on a machine blackthorn does not manage, and list it in
   `never_manage`.

9. **The web UI is plain HTTP.** It relies on the tailnet's encryption. Do
   not make it listen on an address reachable outside the tailnet.

10. **Remote Control is as safe as your Claude account.** Spaces accept
    instructions from Remote Control. See "Who is trusted".

11. **Availability is not protected.** A space can exhaust memory or CPU,
    or kill its own agent. Spaces are separate units, so this affects
    others only through shared resources.

## Reporting a vulnerability

Please report security problems privately through GitHub's "Report a
vulnerability" (Security tab) rather than in a public issue.
