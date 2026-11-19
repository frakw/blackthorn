//! Thin wrappers around the system: commands, users, files.

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn require_root() -> Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        bail!("this command changes system state; run it as root (sudo thorn ...)");
    }
    Ok(())
}

/// Runs a command, failing with its stderr if it exits non-zero.
pub fn run(prog: &str, args: &[&str]) -> Result<()> {
    let out = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {prog}"))?;
    if !out.status.success() {
        bail!(
            "{prog} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Runs a command and returns its stdout.
pub fn output(prog: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("running {prog}"))?;
    if !out.status.success() {
        bail!(
            "{prog} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn systemctl(args: &[&str]) -> Result<()> {
    run("systemctl", args)
}

/// "active", "inactive", "failed", ... (never errors).
pub fn unit_state(unit: &str) -> String {
    Command::new("systemctl")
        .args(["is-active", unit])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

pub fn unit_memory(unit: &str) -> Option<u64> {
    let out = output(
        "systemctl",
        &["show", "-p", "MemoryCurrent", "--value", unit],
    )
    .ok()?;
    out.trim().parse().ok()
}

pub struct UserIds {
    pub uid: u32,
    pub gid: u32,
}

pub fn lookup_user(name: &str) -> Option<UserIds> {
    let c = CString::new(name).ok()?;
    // SAFETY: getpwnam returns a pointer to static storage or null; we copy
    // the two integers out immediately.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    let pw = unsafe { &*pw };
    Some(UserIds {
        uid: pw.pw_uid,
        gid: pw.pw_gid,
    })
}

/// A user's home directory from the password database.
pub fn user_home(name: &str) -> Option<PathBuf> {
    let c = CString::new(name).ok()?;
    // SAFETY: as in lookup_user; the directory string is copied out at once.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
    Some(PathBuf::from(dir.to_str().ok()?))
}

/// A system user with its own group, no password and no login shell.
pub fn create_user(name: &str, home: &Path) -> Result<UserIds> {
    if lookup_user(name).is_none() {
        let home = home.to_str().context("home path is not UTF-8")?;
        run(
            "useradd",
            &[
                "--system",
                "--user-group",
                "--home-dir",
                home,
                "--no-create-home",
                "--shell",
                "/usr/sbin/nologin",
                "--comment",
                "blackthorn session",
                name,
            ],
        )?;
    }
    lookup_user(name).with_context(|| format!("user {name} was not created"))
}

pub fn delete_user(name: &str) -> Result<()> {
    if lookup_user(name).is_some() {
        run("userdel", &[name])?;
    }
    Ok(())
}

pub fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    std::os::unix::fs::chown(path, Some(uid), Some(gid))
        .with_context(|| format!("chown {}", path.display()))
}

pub fn mkdir(path: &Path, mode: u32) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {}", path.display()))
}

/// Writes a file atomically with the given mode, owned by root unless
/// `owner` says otherwise.
pub fn write_file(path: &Path, content: &str, mode: u32, owner: Option<(u32, u32)>) -> Result<()> {
    // Some of these files are written into folders a space user owns, so
    // that user may have put anything at the temporary name: a link to
    // /etc/shadow, say. The temporary file is created anew (O_EXCL, which
    // does not follow links), and its mode and owner are set on the open
    // file, never by path.
    let tmp = path.with_file_name(format!(
        ".{}.thorn-tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
    ));
    let _ = std::fs::remove_file(&tmp);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(content.as_bytes())?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid))
                .with_context(|| format!("chown {}", tmp.display()))?;
        }
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

pub fn which(prog: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(prog).is_file()))
        .unwrap_or(false)
}

pub fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "blackthorn".into())
}

#[cfg(test)]
mod write_tests {
    use super::*;

    #[test]
    fn write_file_does_not_follow_a_planted_link() {
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim");
        std::fs::write(&victim, "keep me").unwrap();
        let target = d.path().join("CLAUDE.md");
        std::os::unix::fs::symlink(&victim, d.path().join(".CLAUDE.md.thorn-tmp")).unwrap();
        write_file(&target, "new", 0o644, None).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        assert!(!std::fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
