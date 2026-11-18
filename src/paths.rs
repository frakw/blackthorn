//! Every path blackthorn reads or writes, in one place.

use std::path::PathBuf;

pub const CONFIG_DIR: &str = "/etc/blackthorn";
pub const CONFIG_FILE: &str = "/etc/blackthorn/config.toml";
/// Private keys, one per host. Root only.
pub const KEYS_DIR: &str = "/etc/blackthorn/keys";

pub const STATE_DIR: &str = "/var/lib/blackthorn";
pub const STATE_FILE: &str = "/var/lib/blackthorn/state.toml";
pub const LOCK_FILE: &str = "/var/lib/blackthorn/state.lock";
/// Session homes: /var/lib/blackthorn/sessions/<key>.
pub const SESSIONS_DIR: &str = "/var/lib/blackthorn/sessions";
/// What `thorn _run` needs to start a session, readable by the session user
/// but writable only by root.
pub const LAUNCH_DIR: &str = "/var/lib/blackthorn/launch";

pub const SYSTEMD_DIR: &str = "/etc/systemd/system";
pub const THORN_BIN: &str = "/usr/local/bin/thorn";

pub fn key_file(host: &str) -> PathBuf {
    PathBuf::from(KEYS_DIR).join(host)
}

pub fn pubkey_file(host: &str) -> PathBuf {
    PathBuf::from(KEYS_DIR).join(format!("{host}.pub"))
}

pub fn session_home(key: &str) -> PathBuf {
    PathBuf::from(SESSIONS_DIR).join(key)
}

pub fn session_workdir(key: &str) -> PathBuf {
    session_home(key).join("work")
}

pub fn launch_file(key: &str) -> PathBuf {
    PathBuf::from(LAUNCH_DIR).join(format!("{key}.toml"))
}

/// Runtime directory of the session unit (RuntimeDirectory=blackthorn/%i).
pub fn session_runtime(key: &str) -> PathBuf {
    PathBuf::from("/run/blackthorn").join(key)
}

pub fn tmux_socket(key: &str) -> PathBuf {
    session_runtime(key).join("tmux.sock")
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

pub fn session_unit(key: &str) -> String {
    format!("blackthorn-session@{key}.service")
}

pub fn agent_unit(key: &str) -> String {
    format!("blackthorn-agent@{key}.service")
}
