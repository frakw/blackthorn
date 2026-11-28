//! Every path blackthorn reads or writes, in one place.

use std::path::PathBuf;

pub const CONFIG_DIR: &str = "/etc/blackthorn";
pub const CONFIG_FILE: &str = "/etc/blackthorn/config.toml";
/// Private keys, one per host. Root only.
pub const KEYS_DIR: &str = "/etc/blackthorn/keys";
/// Web UI accounts: password hashes and TOTP secrets. Root only.
pub const WEB_USERS_FILE: &str = "/etc/blackthorn/web-users.toml";
/// Where notifications go (the ntfy topic and token). Root only.
pub const NOTIFY_FILE: &str = "/etc/blackthorn/notify.toml";

pub const STATE_DIR: &str = "/var/lib/blackthorn";
pub const STATE_FILE: &str = "/var/lib/blackthorn/state.toml";
/// Web logins (their tokens hashed), so an update does not end them.
pub const WEB_SESSIONS_FILE: &str = "/var/lib/blackthorn/web-sessions.json";
pub const LOCK_FILE: &str = "/var/lib/blackthorn/state.lock";
/// Whether each machine answered the last check (see `reach`).
pub const REACH_FILE: &str = "/var/lib/blackthorn/reach.json";
/// Space homes: /var/lib/blackthorn/spaces/<key>.
pub const SPACES_DIR: &str = "/var/lib/blackthorn/spaces";
/// What `thorn _run` needs to start a space, readable by the space user
/// but writable only by root.
pub const LAUNCH_DIR: &str = "/var/lib/blackthorn/launch";
/// What notifications already said, so each thing is said once.
pub const NOTIFY_SEEN_FILE: &str = "/var/lib/blackthorn/notified.toml";
/// The web UI's certificate when Tailscale issues it. Root only.
pub const TLS_DIR: &str = "/var/lib/blackthorn/tls";
pub const ARCHIVE_DIR: &str = "/var/lib/blackthorn/archive";

/// The root-only API the web UI talks to.
pub const API_DIR: &str = "/run/blackthorn-api";
pub const API_SOCKET: &str = "/run/blackthorn-api/api.sock";
/// The unprivileged user the web UI runs as.
pub const WEB_USER: &str = "blackthorn-web";

pub const SYSTEMD_DIR: &str = "/etc/systemd/system";
pub const THORN_BIN: &str = "/usr/local/bin/thorn";

pub fn key_file(host: &str) -> PathBuf {
    PathBuf::from(KEYS_DIR).join(host)
}

pub fn pubkey_file(host: &str) -> PathBuf {
    PathBuf::from(KEYS_DIR).join(format!("{host}.pub"))
}

/// The key of a machine's read-only login (`thorn host readonly`). Host
/// names have no '.', so these never clash with another host's key.
pub fn ro_key_file(host: &str) -> PathBuf {
    PathBuf::from(KEYS_DIR).join(format!("{host}.ro"))
}

pub fn ro_pubkey_file(host: &str) -> PathBuf {
    PathBuf::from(KEYS_DIR).join(format!("{host}.ro.pub"))
}

/// The commands each space ran, copied from its transcripts by root:
/// /var/log/blackthorn/<key>.log.
pub const ACTIVITY_DIR: &str = "/var/log/blackthorn";
/// How far each transcript has been copied.
pub const ACTIVITY_SEEN_FILE: &str = "/var/lib/blackthorn/activity.toml";

pub fn activity_file(key: &str) -> PathBuf {
    PathBuf::from(ACTIVITY_DIR).join(format!("{key}.log"))
}

/// On a managed machine: the forced command of blackthorn's keys, which logs
/// each command to the system log before running it.
pub const REMOTE_LOGGER: &str = "/usr/local/libexec/blackthorn-ssh";

pub fn space_home(key: &str) -> PathBuf {
    PathBuf::from(SPACES_DIR).join(key)
}

pub fn launch_file(key: &str) -> PathBuf {
    PathBuf::from(LAUNCH_DIR).join(format!("{key}.toml"))
}

/// Runtime directory of the space unit (RuntimeDirectory=blackthorn/%i).
pub fn space_runtime(key: &str) -> PathBuf {
    PathBuf::from("/run/blackthorn").join(key)
}

pub fn tmux_socket(key: &str) -> PathBuf {
    space_runtime(key).join("tmux.sock")
}

/// Where a Codex space's bridge listens (see codex.rs).
pub fn codex_socket(key: &str) -> PathBuf {
    space_runtime(key).join("codex.sock")
}

/// tmux server used while a space signs in from the web UI.
pub fn login_socket(key: &str) -> PathBuf {
    PathBuf::from("/run/blackthorn-login")
        .join(key)
        .join("tmux.sock")
}

/// Runtime directory of the agent unit (RuntimeDirectory=blackthorn-agent/%i).
pub fn agent_socket(key: &str) -> PathBuf {
    PathBuf::from("/run/blackthorn-agent")
        .join(key)
        .join("agent.sock")
}

pub fn unix_user(key: &str) -> String {
    format!("bt-{key}")
}

/// A space's read-only login on the machines set up for logins of each
/// space's own (its user login there has the same name as its Unix user
/// here, `unix_user`).
pub fn remote_ro_user(key: &str) -> String {
    format!("bt-{key}-ro")
}

/// The keys of each space's own logins: its user (and root) login on each
/// of its machines, and its read-only one. Their own folder, so no
/// machine's name can clash.
pub const SPACE_KEYS_DIR: &str = "/etc/blackthorn/keys/spaces";

/// The key of a space's user (and root) login on one of its machines
/// (`id`: the machine's key id; empty: the space's key of before v0.16).
pub fn space_key_file(key: &str, id: &str) -> PathBuf {
    if id.is_empty() {
        PathBuf::from(SPACE_KEYS_DIR).join(key)
    } else {
        PathBuf::from(SPACE_KEYS_DIR).join(format!("{key}.{id}"))
    }
}

pub fn space_ro_key_file(key: &str) -> PathBuf {
    PathBuf::from(SPACE_KEYS_DIR).join(format!("{key}-ro"))
}

/// Where a machine set up by blackthorn keeps the key lines of the
/// spaces' logins, out of their reach (sshd's AuthorizedKeysFile).
pub const REMOTE_KEYS_DIR: &str = "/etc/ssh/blackthorn";

pub fn space_unit(key: &str) -> String {
    format!("blackthorn-space@{key}.service")
}

pub fn agent_unit(key: &str) -> String {
    format!("blackthorn-agent@{key}.service")
}
