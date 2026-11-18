//! Shared setup for commands that change state.

use crate::config::Config;
use crate::state::{now, State, StateLock};
use crate::{apply, paths, sys};
use anyhow::{bail, Result};
use std::path::Path;

pub struct Ctx {
    pub cfg: Config,
    pub state: State,
    pub now: u64,
    _lock: StateLock,
}

impl Ctx {
    /// Root, initialized, and holding the state lock.
    pub fn open() -> Result<Ctx> {
        sys::require_root()?;
        if !Path::new(paths::STATE_DIR).is_dir() {
            bail!("blackthorn is not set up on this machine yet; run: sudo thorn init");
        }
        let lock = StateLock::acquire(Path::new(paths::LOCK_FILE))?;
        Ok(Ctx {
            cfg: Config::load(Path::new(paths::CONFIG_FILE))?,
            state: State::load(Path::new(paths::STATE_FILE))?,
            now: now(),
            _lock: lock,
        })
    }

    /// Saves the state and brings the system in line with it.
    pub fn commit(&self) -> Result<()> {
        self.state.save(Path::new(paths::STATE_FILE))?;
        apply::everything(&self.cfg, &self.state, self.now)
    }
}

/// Read-only view without the lock, for code that runs inside systemd units
/// started while a command holds the lock (the state file is replaced
/// atomically, so a lock-free read is always consistent).
pub fn read_only() -> Result<(Config, State)> {
    Ok((
        Config::load(Path::new(paths::CONFIG_FILE))?,
        State::load(Path::new(paths::STATE_FILE))?,
    ))
}
