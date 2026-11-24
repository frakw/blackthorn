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
//! It holds every private key and Claude login on the hub: keep it like one,
//! or give it a password (see `seal`), which import then asks for.

use crate::config::CLAUDE;
use crate::ctx::Ctx;
use crate::state::{now, State};
use crate::{apply, paths, sys, units};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

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

/// Writes the export to `out`, sealed with `password` if one is given.
/// Returns what it holds.
pub fn export(out: &Path, password: Option<&str>) -> Result<Manifest> {
    if password.is_some_and(|p| p.chars().count() < crate::seal::MIN_PASSWORD) {
        bail!(
            "a password is at least {} characters",
            crate::seal::MIN_PASSWORD
        );
    }
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
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(out)
            .with_context(|| format!("creating {}", out.display()))?
    };
    let mut cmd = Command::new("tar");
    cmd.args(["--create", "--gzip", "--numeric-owner", "--file", "-"])
        .arg("--warning=no-file-changed");
    for s in SKIP {
        cmd.arg(format!("--exclude={s}"));
    }
    cmd.arg("-C").arg(&tmp).arg(MANIFEST).arg("-C").arg("/");
    cmd.args(&m.dirs);
    let result = write_tar(cmd, file, password);
    let _ = std::fs::remove_dir_all(&tmp);
    let failed = match result {
        // 1: a file changed while it was read (a chat being written).
        Ok(status) if matches!(status.code(), Some(0 | 1)) => None,
        Ok(status) => Some(anyhow::anyhow!("tar failed ({status})")),
        Err(e) => Some(e),
    };
    if let Some(e) = failed {
        let _ = std::fs::remove_file(out);
        return Err(e);
    }
    drop(ctx);
    Ok(m)
}

/// Runs tar writing to its standard output, into `file`, sealed or not.
fn write_tar(mut cmd: Command, file: std::fs::File, password: Option<&str>) -> Result<ExitStatus> {
    let mut child = cmd.stdout(Stdio::piped()).spawn().context("running tar")?;
    let mut from = child.stdout.take().context("tar output")?;
    let out = std::io::BufWriter::new(file);
    let copied = (|| -> Result<()> {
        let mut out = match password {
            Some(p) => {
                let mut s = crate::seal::Sealer::new(out, p)?;
                std::io::copy(&mut from, &mut s)?;
                s.finish()?
            }
            None => {
                let mut out = out;
                std::io::copy(&mut from, &mut out)?;
                out
            }
        };
        out.flush()?;
        out.get_ref().sync_all()?;
        Ok(())
    })();
    drop(from);
    let status = child.wait().context("running tar")?;
    copied.map(|_| status)
}

/// The export's contents as tar reads them: opened with the password if it
/// is sealed.
fn open_export(file: &Path, password: Option<&str>) -> Result<Box<dyn Read + Send>> {
    let f = std::fs::File::open(file).with_context(|| format!("opening {}", file.display()))?;
    if !crate::seal::is_sealed(file)? {
        return Ok(Box::new(f));
    }
    let p = password.context("this export has a password")?;
    Ok(Box::new(crate::seal::Opener::new(f, p)?))
}

/// Runs tar reading the export from its standard input, with `args`.
/// Returns its status and, with `capture`, what it wrote.
fn read_tar(
    file: &Path,
    password: Option<&str>,
    args: &[&OsStr],
    capture: bool,
) -> Result<(ExitStatus, Vec<u8>)> {
    let mut from = open_export(file, password)?;
    let mut child = Command::new("tar")
        .args(["--gzip", "--file", "-"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(if capture {
            Stdio::piped()
        } else {
            Stdio::inherit()
        })
        .spawn()
        .context("running tar")?;
    let mut to = child.stdin.take().context("tar input")?;
    let feeder = std::thread::spawn(move || -> std::io::Result<()> {
        match std::io::copy(&mut from, &mut to) {
            // tar stops reading once it has what it wants.
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            r => r.map(|_| ()),
        }
    });
    let out = child.wait_with_output().context("running tar")?;
    let fed = feeder
        .join()
        .map_err(|_| anyhow::anyhow!("reading the export failed"))?;
    fed.with_context(|| format!("reading {}", file.display()))?;
    Ok((out.status, out.stdout))
}

/// Whether an export has a password.
pub fn sealed(file: &Path) -> Result<bool> {
    crate::seal::is_sealed(file)
}

/// The manifest of an export file. With a password, a wrong one fails here.
pub fn read_manifest(file: &Path, password: Option<&str>) -> Result<Manifest> {
    let (status, out) = read_tar(
        file,
        password,
        &[
            OsStr::new("--extract"),
            OsStr::new("--to-stdout"),
            OsStr::new(MANIFEST),
        ],
        true,
    )?;
    if !status.success() {
        bail!(
            "{} is not a blackthorn export (no {MANIFEST} in it)",
            file.display()
        );
    }
    let m: Manifest = toml::from_str(&String::from_utf8_lossy(&out))
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
pub fn import(file: &Path, replace: bool, password: Option<&str>) -> Result<Imported> {
    sys::require_root()?;
    let m = read_manifest(file, password)?;

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
    let result = swap(file, password, &m, &here);
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
fn swap(file: &Path, password: Option<&str>, m: &Manifest, here: &State) -> Result<Vec<PathBuf>> {
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
    let mut args: Vec<&OsStr> = vec![
        OsStr::new("--extract"),
        OsStr::new("--numeric-owner"),
        OsStr::new("--same-permissions"),
        OsStr::new("-C"),
        OsStr::new("/"),
    ];
    args.extend(m.dirs.iter().map(|d| OsStr::new(d.as_str())));
    let unpacked = read_tar(file, password, &args, false);
    if !unpacked.as_ref().is_ok_and(|(s, _)| s.success()) {
        bail!(
            "unpacking failed ({}); what was here before is in {}",
            match &unpacked {
                Ok((s, _)) => s.to_string(),
                Err(e) => format!("{e:#}"),
            },
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
