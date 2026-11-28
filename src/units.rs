//! systemd units installed by `thorn init`.
//!
//! Each space is two template instances keyed by the space key:
//!   blackthorn-agent@<key>  ssh-agent holding the keys of the hosts the
//!                           space may reach (loaded by root)
//!   blackthorn-space@<key>  tmux server whose only pane runs the agent
//! Both run as the space's own user. They require the firewall unit, so a
//! space never runs without its egress rules in place.
//!
//! The web UI is two units: blackthorn-api (root, a Unix socket only) and
//! blackthorn-web (an unprivileged user, the HTTP listener).

pub const FIREWALL: &str = "blackthorn-firewall.service";
pub const TICK_SERVICE: &str = "blackthorn-tick.service";
pub const TICK_TIMER: &str = "blackthorn-tick.timer";
pub const AGENT_TEMPLATE: &str = "blackthorn-agent@.service";
pub const SPACE_TEMPLATE: &str = "blackthorn-space@.service";
pub const API: &str = "blackthorn-api.service";
pub const WEB: &str = "blackthorn-web.service";
pub const ASKS: &str = "blackthorn-asks.service";

pub fn all() -> Vec<(&'static str, String)> {
    vec![
        (FIREWALL, firewall()),
        (TICK_SERVICE, tick_service()),
        (TICK_TIMER, tick_timer()),
        (AGENT_TEMPLATE, agent()),
        (SPACE_TEMPLATE, space()),
        (API, api()),
        (WEB, web()),
        (ASKS, asks()),
    ]
}

fn firewall() -> String {
    // No ExecStop: stopping this unit leaves the rules loaded (fail closed).
    "# Installed by thorn init.
[Unit]
Description=blackthorn: firewall (space egress, hub inbound)
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/thorn firewall apply

[Install]
WantedBy=multi-user.target
"
    .to_string()
}

fn asks() -> String {
    // Root on the hub, outbound SSH only: it watches the machines with a
    // space that has root on approval (and does nothing without one).
    "# Installed by thorn init.
[Unit]
Description=blackthorn: watch for root commands waiting for approval
After=network-online.target blackthorn-firewall.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/thorn _asks
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"
    .to_string()
}

fn tick_service() -> String {
    "# Installed by thorn init.
[Unit]
Description=blackthorn: lift expired blocks and root, refresh the firewall

[Service]
Type=oneshot
ExecStart=/usr/local/bin/thorn _tick
"
    .to_string()
}

fn tick_timer() -> String {
    "# Installed by thorn init.
[Unit]
Description=blackthorn: run thorn _tick every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=5s

[Install]
WantedBy=timers.target
"
    .to_string()
}

fn agent() -> String {
    "# Installed by thorn init.
[Unit]
Description=blackthorn: ssh-agent for space %i
Requires=blackthorn-firewall.service
After=blackthorn-firewall.service
PartOf=blackthorn-space@%i.service

[Service]
Type=simple
User=bt-%i
Group=bt-%i
RuntimeDirectory=blackthorn-agent/%i
RuntimeDirectoryMode=0700
# ssh-agent marks itself non-dumpable, so the space user cannot read keys
# out of its memory. Keys are added by root below and never touch the
# space user's files.
ExecStart=/usr/bin/ssh-agent -D -a /run/blackthorn-agent/%i/agent.sock
ExecStartPost=+/usr/local/bin/thorn _load-keys %i
Restart=on-failure
RestartSec=5
"
    .to_string()
}

fn space() -> String {
    "# Installed by thorn init.
[Unit]
Description=blackthorn: space %i
Requires=blackthorn-firewall.service blackthorn-agent@%i.service
After=blackthorn-firewall.service blackthorn-agent@%i.service network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=forking
User=bt-%i
Group=bt-%i
Environment=HOME=/var/lib/blackthorn/spaces/%i
WorkingDirectory=/var/lib/blackthorn/spaces/%i
RuntimeDirectory=blackthorn/%i
RuntimeDirectoryMode=0700
ExecStart=/usr/bin/tmux -S /run/blackthorn/%i/tmux.sock new-session -d -s main -x 200 -y 50 /usr/local/bin/thorn _run %i
ExecStop=/usr/bin/tmux -S /run/blackthorn/%i/tmux.sock kill-server
# The agent exiting is handled inside the pane by thorn _run; this restarts
# the whole space only if tmux itself fails.
Restart=on-failure
RestartSec=10

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/blackthorn/spaces/%i /run/blackthorn-agent/%i
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes

[Install]
WantedBy=multi-user.target
"
    .to_string()
}

fn api() -> String {
    // Root, because it creates users and manages units. It listens only on
    // a Unix socket that the web user's group may open, and checks the
    // password and TOTP code itself, so the web process cannot act alone.
    "# Installed by thorn init.
[Unit]
Description=blackthorn: API for the web UI (root, Unix socket only)
After=blackthorn-firewall.service

[Service]
Type=simple
Group=blackthorn-web
RuntimeDirectory=blackthorn-api
RuntimeDirectoryMode=0750
ExecStart=/usr/local/bin/thorn _api
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"
    .to_string()
}

fn web() -> String {
    // The part that parses HTTP from the network: unprivileged and boxed in.
    // If its listen address does not exist yet (the tailnet is still coming
    // up), it fails and is retried.
    "# Installed by thorn init.
[Unit]
Description=blackthorn: web UI
Requires=blackthorn-api.service
After=blackthorn-api.service network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
User=blackthorn-web
Group=blackthorn-web
ExecStart=/usr/local/bin/thorn _web
Restart=always
RestartSec=5

NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallArchitectures=native
InaccessiblePaths=/etc/blackthorn /var/lib/blackthorn

[Install]
WantedBy=multi-user.target
"
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaces_require_firewall_and_agent() {
        let s = space();
        assert!(s.contains("Requires=blackthorn-firewall.service blackthorn-agent@%i.service"));
        assert!(s.contains("User=bt-%i"));
        let a = agent();
        assert!(a.contains("Requires=blackthorn-firewall.service"));
        assert!(a.contains("ExecStartPost=+/usr/local/bin/thorn _load-keys %i"));
    }

    #[test]
    fn firewall_fails_closed() {
        assert!(!firewall().contains("ExecStop"));
    }

    #[test]
    fn paths_agree_with_paths_module() {
        use crate::paths;
        let s = space();
        assert!(s.contains(&paths::tmux_socket("%i").display().to_string()));
        assert!(s.contains(&format!(
            "WorkingDirectory={}\n",
            paths::space_home("%i").display()
        )));
        assert!(api().contains("RuntimeDirectory=blackthorn-api"));
        assert!(paths::API_SOCKET.starts_with(paths::API_DIR));
        assert!(web().contains(&format!("User={}", paths::WEB_USER)));
        assert!(agent().contains(&paths::agent_socket("%i").display().to_string()));
    }
}
