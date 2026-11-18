# Threat model

This document says what blackthorn protects against, how, and what it does
not protect against. If something here is wrong or missing, please open an
issue.

## What is being protected

- **The managed machines**, from actions you did not intend.
- **The hub's secrets**: the Claude sign-in of each session, and the SSH
  private keys for the managed machines.
- **Isolation between sessions**: work on one set of machines should not
  spill onto another.

## Who is trusted

- **Root on the hub** (you). Root can do everything blackthorn prevents.
- **The hypervisor** hosting the hub, and anyone who controls it.
- **Anthropic's service**, which runs the model and relays Remote Control.
- **Your Claude account.** Anyone who can sign in to it can drive your
  sessions through Remote Control. Protect it with strong authentication.
- **Whatever controls the network path to the hub's admin SSH**, for example
  a Tailscale or Headscale control server: it decides who can reach port 22.
  Key-only SSH remains the last barrier.

## Threats considered

1. **A managed machine is compromised.** The attacker controls that
   machine, including what it returns to the hub.
2. **Prompt injection.** Text the model reads (a file, a log line, command
   output, a web page) tries to make it do something else, such as reaching
   another machine or leaking data.
3. **A misbehaving session.** For whatever reason, the Claude Code process of
   one session runs arbitrary commands as its own Unix user.

## What blackthorn enforces

These hold even if the model does exactly what an attacker wants, because
they are enforced by the kernel or by what the session has, not by the model.

| Control | Mechanism |
|---|---|
| Sessions are separated | Each session is its own Unix user with its own home (mode 0700). |
| A session reaches only its granted hosts | nftables rules match the session's uid and allow only the IP and SSH port of each granted, unblocked host, plus DNS and HTTPS. Everything else is rejected. |
| Blocks and revocations are immediate | There is no "established connections are allowed" rule, so packets on open connections are rejected too. Keys are removed from agents at the same time. |
| Sessions never see private keys | Keys are root-only files. Root loads them into the session's ssh-agent, which marks itself non-dumpable so the session user cannot read its memory. |
| A session holds only its own keys | One agent per session, holding only the keys of its granted, unblocked hosts. |
| Host identities are pinned | Hosts are stored by IP address, not name, and their host keys are recorded when added (after you confirm the fingerprints). |
| Sessions cannot change the system | systemd sandbox: `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`, `PrivateTmp`, `RestrictSUIDSGID`, and more. |
| The hub cannot be reached from managed machines | blackthorn opens no listening ports. Managed machines have no credentials for the hub. (Enforcing "no inbound" is the job of the firewall outside the hub; see README.) |
| Keys are limited on the remote side | The suggested `authorized_keys` line starts with `restrict`: no port, agent or X11 forwarding, no pty. |
| Without the firewall, nothing runs | Session units require the firewall unit, and stopping the firewall unit leaves its rules loaded. |

## What blackthorn does not protect against

Know these before you rely on it.

1. **Hosts in one session form one trust zone.** If a session may reach
   hosts A and B, injected text from A can drive actions on B. Put machines
   you trust differently in different sessions.

2. **A session can do anything its remote user can.** blackthorn decides
   *whether* a session reaches a machine, not *what* it does there. Use a
   non-root remote user, and sudo rules, for limits on the machine itself.

3. **Data can leave over HTTPS.** By default sessions may open HTTPS
   connections to any address, because Claude Code must reach Anthropic and
   Anthropic's addresses change. A misbehaving session can therefore send
   anything it can read (including data from its hosts) to any HTTPS server.
   DNS queries to the allowed resolvers are a second, slower channel. A
   domain-allowlisting egress proxy is planned. Set
   `egress.https_anywhere = false` if you can supply the addresses another
   way.

4. **ssh_config is a convenience, not a control.** The generated
   `~/.ssh/config` sets `ForwardAgent no`, `ClearAllForwardings yes` and
   strict host-key checking, but the session can run `ssh` with its own
   options. In particular it could forward its agent to one of its hosts,
   letting a compromised host use the session's other keys: that reaches no
   more hosts than the session already can (see 1), and the firewall still
   applies.

5. **Each session can change its own Claude Code setup.** It owns its home,
   so it can edit its own settings, hooks and `CLAUDE.md`. This affects only
   that session.

6. **Root on the hub is everything.** Whoever gets root on the hub, through a
   kernel exploit, a bug in blackthorn, or your own credentials, has every
   key and every session. Keep the hub minimal and updated, and run nothing
   else on it.

7. **The network overlay is trusted.** If the hub's admin SSH is reachable
   through a tailnet, whoever controls the tailnet's control server can
   change who reaches it, and could impersonate a node's address. If that
   server runs on a machine the hub manages, that machine has a path back to
   the hub, contradicting "one way only". Host the control server elsewhere,
   or accept and note the risk.

8. **Remote Control is as safe as your Claude account.** Sessions accept
   instructions from Remote Control. See "Who is trusted".

9. **Availability is not protected.** A session can exhaust memory or CPU,
   or kill its own agent. Sessions are separate units, so this affects others
   only through shared resources.

## Reporting a vulnerability

Please report security problems privately through GitHub's "Report a
vulnerability" (Security tab) rather than in a public issue.
