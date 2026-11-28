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
- **Where you install from**: the GitHub release (or the mirror you point
  the installer at) and Anthropic's Claude Code installer, over HTTPS. The
  release's `SHA256SUMS` catches a damaged download, not a compromised
  release; build from source and use `install.sh --binary` if that matters
  to you.

## Threats considered

1. **A managed machine is compromised.** The attacker controls that
   machine, including what it returns to the hub.
2. **Prompt injection.** Text the model reads (a file, a log line, command
   output, a web page) tries to make it do something else, such as reaching
   another machine or leaking data.
3. **A misbehaving space.** For whatever reason, the agent of one space runs
   arbitrary commands as its own Unix user.
4. **Attacks on the web UI** from the network it listens on: password
   guessing, cross-site request forgery, malformed HTTP. Whoever has your
   password and authenticator can also change who may reach the hub
   (Settings), just as root on the console can; such changes need a fresh
   code, are logged, and may not shut out the device making them.

## What blackthorn enforces

These hold even if the model does exactly what an attacker wants, because
they are enforced by the kernel or by what the space has, not by the model.

| Control | Mechanism |
|---|---|
| Spaces are separated | Each space is its own Unix user with its own home (mode 0700). |
| A space reaches only its machine | nftables rules match the space's uid and allow only the IP and SSH port of its machine (and of machines it has an active bridge to) while not blocked, plus DNS and HTTPS. Everything else is rejected. |
| Blocks and bridge ends are immediate | There is no "established connections are allowed" rule for spaces, so packets on open connections are rejected too. Keys are removed from agents at the same time. Timed blocks and bridges end within a minute of their time. |
| Bridges are one-way | A bridge from A to B gives A's user B's machine; B's user gains nothing. |
| Managed machines cannot reach the hub | The hub's input rules drop every connection from a managed machine (and from `never_manage`/`deny_from` addresses), and note who tried, for notifications. Replies to the hub's own SSH connections still arrive. blackthorn refuses to manage an address listed in `inbound.admin_from` or the address you are connected from. |
| Admin ports only from your devices | If `inbound.admin_from` is set, only those addresses may reach SSH and the web UI. |
| Spaces never see private keys | Keys are root-only files. Root loads them into the space's ssh-agent, which marks itself non-dumpable so the space user cannot read its memory. |
| Each space has logins of its own | On a machine set up with `thorn host setup`, a space's agent holds only its own key for the login it has now: `bt-<id>` (an ordinary user, its home and `/srv/<space>`) or `bt-<id>-ro` (reads logs through groups, sudo only for listed Docker commands that read). Their key lines are in `/etc/ssh/blackthorn`, which only root writes. Root is sudo for `bt-<id>`, given with a code from the web for at most 72 hours or until taken back, and taken back on the machine too (by the hub, and by a timer on the machine itself); its sessions are ended then. blackthorn's own login there is never handed to a space. Root on approval gives sudo for `blackthorn-ask` alone: the command and its standard input are stored by root on the machine when asked, the hub shows exactly those, and only those run once approved (the approval is a file the hub writes through its own login; one waiting run claims it, so it runs once). Asks from a space without root on approval are refused. |
| Commands leave a record | Root copies every shell command from each space's chats into a log the space cannot write, once a minute. On set-up machines, every blackthorn key runs a logger first (`command=`), so the machine's own system log has every command, under the space's own login, out of reach of the spaces' users. |
| Stolen keys are useless elsewhere | The suggested `authorized_keys` line has `from="<hub address>"` and `restrict`: usable only from the hub, with no port, agent or X11 forwarding and no pty. |
| Host identities are pinned | Machines are stored by IP address, not name, and their host keys are recorded when added, after you confirm the fingerprints. |
| Spaces cannot change the system | systemd sandbox: `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, `PrivateTmp`, `RestrictSUIDSGID`, and more. |
| Without the firewall, nothing runs | Space units require the firewall unit, and stopping the firewall unit leaves its rules loaded. |
| The web UI's network side has no power | The HTTP listener runs as the unprivileged `blackthorn-web` user in a tight systemd sandbox, with no access to blackthorn's files. It forwards requests to a root API on a Unix socket, which accepts only that user, checks the password (Argon2id) and TOTP code itself, keeps the sessions, and enforces the CSRF value. A compromised web process can act only through a session a user has logged in to. |
| Logins resist guessing | Password and TOTP are both needed; each code works once; five failures lock the account and the address for 15 minutes. Deleting spaces, removing machines, moving them, renaming anything, opening bridges, accepting new host keys, changing settings or notifications, updating blackthorn, giving a space root, raising a space's usual login, setting a machine up and changing your password or authenticator need a fresh code. A new authenticator replaces the old one only after a code made from it is accepted; password and authenticator changes end your other logins. Accounts are created and removed only on the hub's command line. Passkeys must verify the user (PIN or biometrics) and are checked for the hub's name and origin, a one-time challenge, the signature and a growing counter. |
| Account secrets do not linger | The terminal that showed a new account's QR code and recovery codes is cleared, scrollback included, once you have written them down. |
| Root does not follow a space's links | Listing, naming and deleting chats reads and writes files in the space's home as root; it skips symbolic links, opens transcripts with `O_NOFOLLOW`, and acts only on files the space user owns. Generated files (such as CLAUDE.md in the space's own work folder) are written through a temporary file created anew (`O_EXCL`), owned and set by its descriptor, so a link planted at that name is never followed (before v0.6 it was). |
| Web pages are hard to abuse | SameSite=Strict, HttpOnly session cookie; a CSRF value on every form; a CSP that allows no inline script or third-party resource; a small HTTP parser with size, time and connection limits. |
| Exports are root's | `thorn export` runs only as root on the hub (not from the web), writes a new file readable by root alone, and refuses to overwrite one. The file holds every private key, Claude login and account secret on the hub. `thorn import` takes only an export from the same version, unpacks only blackthorn's own folders, and sets aside what was there instead of deleting it. With a password (`--password`, offered on a terminal) the file is sealed with ChaCha20-Poly1305 under a key Argon2id makes from it (64 MiB, 3 passes, a random salt), in numbered 64 KiB pieces with the last one marked, so a wrong password, a changed byte, or pieces reordered, dropped or cut off are refused before import changes anything. |
| Tailscale from the web | Installing Tailscale, signing in and its web interface need a fresh authenticator code. The installer is Tailscale's own, over HTTPS. Its web interface (port 5252) counts as an admin port: with `inbound.admin_from` set, only those addresses reach it, and managed machines never do. While it is off, the hub's firewall drops connections to that port too, since `tailscale set --webclient=false` does not always stop it. |
| Typing into chats from the web | A chat's page shows its transcript to anyone logged in; typing into it, pressing Stop or answering Claude's questions, and adding files need this browser to be unlocked with the password and a code again (a separate HttpOnly cookie, listed with the logins and ended the same way). Messages go to the chat's tmux window as a paste and Enter, as at its terminal; nothing is typed while the screen shows Claude asking a question, and an answer is only a number the question offers, pressed by you. Files are written by the space's own user into `.uploads` in its folder. |
| Logins can be seen and ended | The account page lists each login and chat unlock with its browser, system and address, and ends any of them. They are kept by the SHA-256 of their tokens in a root-only file, so a restart keeps them and the file gives none away; they last `web.session_hours` (24) at most, and logins end after `web.idle_minutes` (30) unused unless `web.idle_logout` is turned off. |
| Shared spaces stay within their share | Accounts that are not hub admins see and act on only the spaces they own or that are shared with them, at the level shared (view, use, manage); the root API checks this for every request, and filters what the map and lists show. Machines, bridges to spaces they may not manage, settings, Tailscale, updates and accounts are for hub admins. Sharing or giving away a space needs a fresh code. Messages typed into chats from the hub, answers and files are logged with the account. A hub admin, like root, can see everything: sharing does not protect accounts from them. |
| SSH changes cannot lock you out | `thorn harden ssh` checks your authenticator first, validates sshd's configuration, and undoes itself unless you confirm from a new login. |

## What blackthorn does not protect against

Know these before you rely on it.

1. **Spaces share your Claude account.** Every space signs in to the same
   claude.ai account, and a space can read its own sign-in (Claude Code
   needs it). A misbehaving space could use that sign-in to reach your
   other spaces through Remote Control, around the firewall. Isolation
   between spaces therefore holds for machines and keys, not for the Claude
   account. Not addressed yet; separate Claude accounts per trust level
   avoid it. Codex spaces are the same with your ChatGPT account, or with
   the API key they were given (`~/.codex/auth.json`, readable by the
   space): give each its own key with only the permissions it needs, so it
   can be revoked alone.

2. **A bridge makes one trust zone.** While space A has a bridge to B's
   machine, injected text from either machine can drive A's actions on the
   other. Keep bridges short, and between machines you trust alike.

3. **A space can do anything its remote user can.** blackthorn decides
   *whether* a space reaches a machine; the login decides *what* it does
   there. A space with root is unlimited on its machine, and from there it
   can also reach the internet, past the hub's firewall; root taken back
   leaves behind whatever root changed meanwhile. A user login can do all
   its user can: change its own files and containers, and send out
   anything it reads. Even read-only, a space can send out anything that
   login can read (logs included), from the machine itself: read-only
   stops changes, not reading. On a machine blackthorn reaches as an
   ordinary user (not set up), the spaces are that user. A rule you add to
   the sudoers file yourself can undo all of it; the docker group or
   `docker exec` is
   root. The command record misses what a space writes and erases within
   the same minute on the hub, and a script fed over standard input
   (`ssh host sh < script`) is logged on the machine only as its command
   line.

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

9. **The web UI is plain HTTP unless you give it a certificate.** Then
   it relies on the tailnet's encryption. A fresh install without Tailscale
   listens on every address; anyone on that network path can then read the
   session cookie. Set `web.listen` to the tailnet address and
   `inbound.admin_from` to your devices, and do not make it reachable
   outside the tailnet. With `thorn web https` it speaks only HTTPS, the
   session cookie is `Secure`, and passkeys work. The unprivileged web
   process holds the TLS key (it gets it from the root API, since it cannot
   read the key file), so whoever takes over that process can impersonate
   the web UI until the certificate is replaced.

10. **Remote Control is as safe as your Claude account.** Spaces accept
    instructions from Remote Control. See "Who is trusted". A space with
    Remote Control off is reached only from the hub, but it still signs in
    to the same account (point 1).

11. **Updates trust GitHub.** The web UI's Update button (and
    `thorn update`) runs the release's `install.sh`, downloaded over HTTPS
    from GitHub, as root; it checks the new `thorn` against the release's
    `SHA256SUMS`, which come from the same place. Whoever can publish a
    release in the repository can therefore run code on your hub, exactly
    as with the first install. Checking for a release sends one HTTPS
    request to github.com from the hub, at most every six hours, while the
    Settings page is open.

12. **Notifications leave the hub.** With notifications on, the hub
    (as root, not a space) sends short messages to the ntfy server you
    chose: names of spaces and machines, their states, addresses that tried
    to connect. Never secrets. On ntfy.sh anyone who knows the topic can
    read them, so blackthorn suggests a long random one and keeps it, and
    any access token, in a root-only file spaces cannot read. A missing
    notification proves nothing: the hub may be down, or its network.

13. **Codex comes from OpenAI's installer.** `thorn codex install` (and
    Settings → Codex) runs `https://chatgpt.com/codex/install.sh` as root,
    which downloads Codex and checks it against OpenAI's own checksums.
    Whoever can change that script or those releases can run code on your
    hub, as with Tailscale's installer. Codex runs in its spaces without
    its own sandbox: the space's user, firewall and logins are the limits,
    as for Claude Code. Its chats go through a bridge (`thorn _codex`)
    that runs as the space user, so the space can say anything there: the
    hub reaches its socket only if it is the space user's own socket (not
    a link), reads bounded answers, shows them escaped, and keeps who sent
    what in the space's log, which the space cannot write. Codex asking
    before a command is Codex's own care, not a limit: the space could run
    the command anyway.

14. **Availability is not protected.** A space can exhaust memory or CPU,
    or kill its own agent. Spaces are separate units, so this affects
    others only through shared resources.

## Reporting a vulnerability

Please report security problems privately through GitHub's "Report a
vulnerability" (Security tab) rather than in a public issue.
