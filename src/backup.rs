//! `thorn export` and `thorn import`: everything blackthorn keeps, in one
//! file, to move a hub to a new machine or bring one back.
//!
//! The file is a .tar.gz of /etc/blackthorn (settings, machine keys, web
//! accounts), /var/lib/blackthorn (state, each space's home with its Claude
//! login and chats, archived spaces) and /var/log/blackthorn (what each space
//! ran), with a manifest saying which blackthorn made it. Only the same
//! version imports it: the files are taken as they are, so a version that
//! reads them differently is refused rather than guessed at.
//!
//! It holds every private key and Claude login on the hub: keep it like one.

use crate::config::CLAUDE;
use crate::ctx::Ctx;
use crate::state::{now, State};
use crate::{apply, paths, sys, units};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

const MANIFEST: &str = "blackthorn-export.toml";
const FORMAT: u32 = 1;
/// What an export holds, relative to /.
const DIRS: [&str; 3] = ["etc/blackthorn", "var/lib/blackthorn", "var/log/blackthorn"];
/// Remade on the machine that imports.
const SKIP: [&str; 2] = ["var/lib/blackthorn/state.lock", "var/lib/blackthorn/launch"];

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub format: u32,
    /// The blackthorn that made it, e.g. "0.8.0".
    pub version: String,
    pub created: u64,
    pub hostname: String,
    /// Which of DIRS it holds.
    pub dirs: Vec<String>,
    /// Space key -> the uid and gid its files had, to give them to the
    /// space's new user.
    pub owners: BTreeMap<String, (u32, u32)>,
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Writes the export to `out`. Returns what it holds.
pub fn export(out: &Path) -> Result<Manifest> {
    // The lock keeps the state as it is while it is copied; spaces may
    // still add to their chats.
    let ctx = Ctx::open()?;
    if std::fs::symlink_metadata(out).is_ok() {
        bail!("{} already exists", out.display());
    }
    let mut owners = BTreeMap::new();
    for s in ctx.state.spaces.values() {
        if let Some(ids) = sys::lookup_user(&paths::unix_user(&s.key)) {
            owners.insert(s.key.clone(), (ids.uid, ids.gid));
        }
    }
    let m = Manifest {
        format: FORMAT,
        version: version().into(),
        created: now(),
        hostname: sys::hostname(),
        dirs: DIRS
            .iter()
            .filter(|d| Path::new("/").join(d).is_dir())
            .map(|d| d.to_string())
            .collect(),
        owners,
    };
    let tmp = tempdir("export")?;
    sys::write_file(&tmp.join(MANIFEST), &toml::to_string(&m)?, 0o600, None)?;

    // Made first, so the file is root's alone from the start.
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(out)
            .with_context(|| format!("creating {}", out.display()))?;
    }
    let mut cmd = Command::new("tar");
    cmd.args(["--create", "--gzip", "--numeric-owner", "--file"])
        .arg(out)
        .arg("--warning=no-file-changed");
    for s in SKIP {
        cmd.arg(format!("--exclude={s}"));
    }
    cmd.arg("-C").arg(&tmp).arg(MANIFEST).arg("-C").arg("/");
    cmd.args(&m.dirs);
    let status = cmd.status().context("running tar")?;
    let _ = std::fs::remove_dir_all(&tmp);
    // 1: a file changed while it was read (a chat being written).
    if !matches!(status.code(), Some(0 | 1)) {
        let _ = std::fs::remove_file(out);
        bail!("tar failed ({status})");
    }
    drop(ctx);
    Ok(m)
}

/// The manifest of an export file.
pub fn read_manifest(file: &Path) -> Result<Manifest> {
    let out = Command::new("tar")
        .args(["--extract", "--gzip", "--to-stdout", "--file"])
        .arg(file)
        .arg(MANIFEST)
        .output()
        .context("running tar")?;
    if !out.status.success() {
        bail!(
            "{} is not a blackthorn export (no {MANIFEST} in it)",
            file.display()
        );
    }
    let m: Manifest = toml::from_str(&String::from_utf8_lossy(&out.stdout))
        .with_context(|| format!("reading {MANIFEST}"))?;
    check(&m)?;
    Ok(m)
}

/// Only an export from this very version is taken.
pub fn check(m: &Manifest) -> Result<()> {
    if m.format != FORMAT {
        bail!("this export has format {}, not {FORMAT}", m.format);
    }
    if m.version != version() {
        bail!(
            "this export is from blackthorn {}, this is {}: import it with {} \
             (or export again from a hub running {})",
            m.version,
            version(),
            m.version,
            version()
        );
    }
    for d in &m.dirs {
        if !DIRS.contains(&d.as_str()) {
            bail!("this export holds {d:?}, which blackthorn does not keep");
        }
    }
    Ok(())
}

pub struct Imported {
    pub manifest: Manifest,
    pub spaces: usize,
    pub hosts: usize,
    pub started: Vec<String>,
    /// Where what was here before went.
    pub before: Vec<PathBuf>,
}

/// Replaces this hub's data with an export's. With spaces or machines
/// here already, `replace` must be set: they are stopped and their users
/// removed, and their files are kept aside (`Imported::before`).
pub fn import(file: &Path, replace: bool) -> Result<Imported> {
    sys::require_root()?;
    let m = read_manifest(file)?;

    // What is here now.
    let ctx = Ctx::open()?;
    let here = ctx.state.clone();
    if !(here.spaces.is_empty() && here.hosts.is_empty()) && !replace {
        bail!(
            "this hub has {} space(s) and {} machine(s); importing replaces them \
             (they are stopped and set aside, not deleted): add --replace",
            here.spaces.len(),
            here.hosts.len()
        );
    }
    drop(ctx);

    // Nothing may change the files while they are swapped.
    let quiet = [units::TICK_TIMER, units::WEB, units::API];
    for u in quiet {
        let _ = sys::systemctl(&["stop", u]);
    }
    let result = swap(file, &m, &here);
    for u in quiet {
        let _ = sys::systemctl(&["start", u]);
    }
    let before = result?;

    // The new state: a user for each space, its files given to it, the
    // system brought in line, the spaces started.
    let ctx = Ctx::open()?;
    for s in ctx.state.spaces.values() {
        let home = paths::space_home(&s.key);
        let ids = sys::create_user(&paths::unix_user(&s.key), &home)?;
        if let Some(&(uid, gid)) = m.owners.get(&s.key) {
            give(&home, uid, gid, ids.uid, ids.gid)?;
        }
    }
    apply::firewall_rules(&ctx.cfg, &ctx.state, ctx.now, true)?;
    apply::everything(&ctx.cfg, &ctx.state, ctx.now)?;
    let mut started = Vec::new();
    for (name, s) in &ctx.state.spaces {
        let unit = paths::space_unit(&s.key);
        if ctx.state.limited(s) {
            let _ = sys::systemctl(&["disable", &unit]);
            continue;
        }
        sys::systemctl(&["enable", &unit])?;
        if s.agent != CLAUDE || crate::ops::logged_in(s) {
            sys::systemctl(&["restart", &unit])?;
            started.push(name.clone());
        }
    }
    let (spaces, hosts) = (ctx.state.spaces.len(), ctx.state.hosts.len());
    drop(ctx);
    Ok(Imported {
        manifest: m,
        spaces,
        hosts,
        started,
        before,
    })
}

/// Stops what is here, moves it aside, and unpacks the export in its
/// place. Returns where the old files went.
fn swap(file: &Path, m: &Manifest, here: &State) -> Result<Vec<PathBuf>> {
    for s in here.spaces.values() {
        let _ = sys::systemctl(&["disable", "--now", &paths::space_unit(&s.key)]);
        let _ = sys::systemctl(&["stop", &paths::agent_unit(&s.key)]);
        crate::ops::login_cancel(&s.key);
    }
    for s in here.spaces.values() {
        sys::delete_user(&paths::unix_user(&s.key))?;
    }
    let stamp = now();
    let mut before = Vec::new();
    for d in DIRS {
        let p = Path::new("/").join(d);
        if std::fs::symlink_metadata(&p).is_err() {
            continue;
        }
        let aside = PathBuf::from(format!("/{d}.before-import-{stamp}"));
        std::fs::rename(&p, &aside)
            .with_context(|| format!("moving {} to {}", p.display(), aside.display()))?;
        // Owned by root alone: the old spaces' uids are free again.
        sys::run("chmod", &["700", aside.to_str().context("path")?])?;
        before.push(aside);
    }
    let status = Command::new("tar")
        .args([
            "--extract",
            "--gzip",
            "--numeric-owner",
            "--same-permissions",
            "--file",
        ])
        .arg(file)
        .arg("-C")
        .arg("/")
        .args(&m.dirs)
        .status()
        .context("running tar")?;
    if !status.success() {
        bail!(
            "unpacking failed ({status}); what was here before is in {}",
            before
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    // The tick remakes the lock file; launch files come from `apply`.
    sys::mkdir(Path::new(paths::LAUNCH_DIR), 0o755)?;
    Ok(before)
}

/// Gives a space's files from its old uid and gid to its new ones. Files
/// root owns (its ~/.ssh) stay root's.
fn give(home: &Path, uid: u32, gid: u32, new_uid: u32, new_gid: u32) -> Result<()> {
    let home = home.to_str().context("path")?;
    if uid != new_uid {
        sys::run(
            "chown",
            &[
                "-R",
                "--no-dereference",
                &format!("--from={uid}"),
                &new_uid.to_string(),
                home,
            ],
        )?;
    }
    if gid != new_gid {
        sys::run(
            "chown",
            &[
                "-R",
                "--no-dereference",
                &format!("--from=:{gid}"),
                &format!(":{new_gid}"),
                home,
            ],
        )?;
    }
    Ok(())
}

fn tempdir(what: &str) -> Result<PathBuf> {
    let p = std::env::temp_dir().join(format!(
        "blackthorn-{what}-{}",
        uuid::Uuid::new_v4().simple()
    ));
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&p)
        .with_context(|| format!("creating {}", p.display()))?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            format: FORMAT,
            version: version().into(),
            created: 1,
            hostname: "blackthorn".into(),
            dirs: vec!["etc/blackthorn".into(), "var/lib/blackthorn".into()],
            owners: BTreeMap::from([("52df44ed".to_string(), (998, 997))]),
        }
    }

    #[test]
    fn takes_only_its_own_version() {
        assert!(check(&manifest()).is_ok());
        let older = Manifest {
            version: "0.0.1".into(),
            ..manifest()
        };
        let e = check(&older).unwrap_err().to_string();
        assert!(e.contains("from blackthorn 0.0.1"), "{e}");
        let odd = Manifest {
            dirs: vec!["etc".into()],
            ..manifest()
        };
        assert!(check(&odd).is_err(), "only blackthorn's own folders");
        let future = Manifest {
            format: 2,
            ..manifest()
        };
        assert!(check(&future).is_err());
    }

    #[test]
    fn manifest_round_trips() {
        let m = manifest();
        let back: Manifest = toml::from_str(&toml::to_string(&m).unwrap()).unwrap();
        assert_eq!(back, m);
    }
}
