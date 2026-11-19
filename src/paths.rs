//! Every path blackthorn reads or writes, in one place.

use std::path::PathBuf;

pub const CONFIG_DIR: &str = "/etc/blackthorn";
pub const CONFIG_FILE: &str = "/etc/blackthorn/config.toml";
/// Private keys, one per host. Root only.
pub const KEYS_DIR: &str = "/etc/blackthorn/keys";
/// Web UI accounts: password hashes and TOTP secrets. Root only.
pub const WEB_USERS_FILE: &str = "/etc/blackthorn/web-users.toml";

pub const STATE_DIR: &str = "/var/lib/blackthorn";
pub const STATE_FILE: &str = "/var/lib/blackthorn/state.toml";
pub const LOCK_FILE: &str = "/var/lib/blackthorn/state.lock";
/// Space homes: /var/lib/blackthorn/spaces/<key>.
pub const SPACES_DIR: &str = "/var/lib/blackthorn/spaces";
/// What `thorn _run` needs to start a space, readable by the space user
/// but writable only by root.
pub const LAUNCH_DIR: &str = "/var/lib/blackthorn/launch";
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

pub fn space_home(key: &str) -> PathBuf {
    PathBuf::from(SPACES_DIR).join(key)
}

pub fn space_workdir(key: &str) -> PathBuf {
    space_home(key).join("work")
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

pub fn space_unit(key: &str) -> String {
    format!("blackthorn-space@{key}.service")
}

pub fn agent_unit(key: &str) -> String {
    format!("blackthorn-agent@{key}.service")
}
