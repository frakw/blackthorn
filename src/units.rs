//! systemd units installed by `thorn init`.
//!
//! Each session is two template instances keyed by the session key:
//!   blackthorn-agent@<key>    ssh-agent holding the keys of the hosts the
//!                             session may reach (loaded by root)
//!   blackthorn-session@<key>  tmux server whose only pane runs Claude Code
//! Both run as the session's own user. They require the firewall unit, so a
//! session never runs without its egress rules in place.

pub const FIREWALL: &str = "blackthorn-firewall.service";
pub const TICK_SERVICE: &str = "blackthorn-tick.service";
pub const TICK_TIMER: &str = "blackthorn-tick.timer";
pub const AGENT_TEMPLATE: &str = "blackthorn-agent@.service";
pub const SESSION_TEMPLATE: &str = "blackthorn-session@.service";

pub fn all() -> Vec<(&'static str, String)> {
    vec![
        (FIREWALL, firewall()),
        (TICK_SERVICE, tick_service()),
        (TICK_TIMER, tick_timer()),
        (AGENT_TEMPLATE, agent()),
        (SESSION_TEMPLATE, session()),
    ]
}

fn firewall() -> String {
    // No ExecStop: stopping this unit leaves the rules loaded (fail closed).
    "# Installed by thorn init.
[Unit]
Description=blackthorn: egress rules for session users
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

fn tick_service() -> String {
    "# Installed by thorn init.
[Unit]
Description=blackthorn: lift expired host blocks and refresh the firewall

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
Description=blackthorn: ssh-agent for session %i
Requires=blackthorn-firewall.service
After=blackthorn-firewall.service
PartOf=blackthorn-session@%i.service

[Service]
Type=simple
User=bt-%i
Group=bt-%i
RuntimeDirectory=blackthorn-agent/%i
RuntimeDirectoryMode=0700
# ssh-agent marks itself non-dumpable, so the session user cannot read keys
# out of its memory. Keys are added by root below and never touch the
# session user's files.
ExecStart=/usr/bin/ssh-agent -D -a /run/blackthorn-agent/%i/agent.sock
ExecStartPost=+/usr/local/bin/thorn _load-keys %i
Restart=on-failure
RestartSec=5
"
    .to_string()
}

fn session() -> String {
    "# Installed by thorn init.
[Unit]
Description=blackthorn: Claude Code session %i
Requires=blackthorn-firewall.service blackthorn-agent@%i.service
After=blackthorn-firewall.service blackthorn-agent@%i.service network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=forking
User=bt-%i
Group=bt-%i
Environment=HOME=/var/lib/blackthorn/sessions/%i
WorkingDirectory=/var/lib/blackthorn/sessions/%i/work
RuntimeDirectory=blackthorn/%i
RuntimeDirectoryMode=0700
ExecStart=/usr/bin/tmux -S /run/blackthorn/%i/tmux.sock new-session -d -s main -x 200 -y 50 /usr/local/bin/thorn _run %i
ExecStop=/usr/bin/tmux -S /run/blackthorn/%i/tmux.sock kill-server
# claude exiting with an error is retried inside the pane by thorn _run;
# this restarts the whole session only if tmux itself fails.
Restart=on-failure
RestartSec=10

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/blackthorn/sessions/%i /run/blackthorn-agent/%i
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_require_firewall_and_agent() {
        let s = session();
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
        let s = session();
        assert!(s.contains(&paths::tmux_socket("%i").display().to_string()));
        assert!(s.contains(&paths::session_workdir("%i").display().to_string()));
        assert!(agent().contains(&paths::agent_socket("%i").display().to_string()));
    }
}
