//! thorn harden ssh: two-factor SSH logins to the hub (key plus TOTP, or a
//! FIDO2 hardware key), with an automatic undo if you do not confirm that
//! you can still log in.

use crate::{paths, sys, webauth};
use anyhow::{bail, Context, Result};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

const DROP_IN: &str = "/etc/ssh/sshd_config.d/10-blackthorn.conf";
const PAM_SSHD: &str = "/etc/pam.d/sshd";
const PAM_LINE: &str = "auth required pam_google_authenticator.so";
const ROLLBACK_UNIT: &str = "blackthorn-harden-rollback";

fn backup_dir() -> PathBuf {
    Path::new(paths::STATE_DIR).join("harden-backup")
}

pub struct Opts {
    pub totp: bool,
    pub fido: bool,
    pub user: Option<String>,
    pub rollback_after: String,
    pub totp_secret: Option<String>,
}

pub fn ssh(o: Opts) -> Result<()> {
    sys::require_root()?;
    if !o.totp && !o.fido {
        bail!("choose --totp (key + authenticator code), --fido (hardware key), or both");
    }
    let user = o
        .user
        .or_else(|| std::env::var("SUDO_USER").ok())
        .filter(|u| u != "root")
        .context("say which admin account to protect with --user (not root)")?;
    let home = home_of(&user)?;
    let keys = std::fs::read_to_string(home.join(".ssh/authorized_keys")).unwrap_or_default();
    let key_lines: Vec<&str> = keys
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .collect();
    if key_lines.is_empty() {
        bail!("{user} has no SSH keys in ~/.ssh/authorized_keys; add one first, or you would be locked out");
    }
    if o.fido
        && !key_lines
            .iter()
            .any(|l| l.contains("sk-ssh-ed25519") || l.contains("sk-ecdsa"))
    {
        bail!(
            "{user} has no hardware-key (sk-) SSH key. On your computer: ssh-keygen -t ed25519-sk, \
             then add the .pub line to ~{user}/.ssh/authorized_keys here and run this again"
        );
    }
    let secs = crate::ops::parse_duration(&o.rollback_after)?;
    if !(15..=3600).contains(&secs) {
        bail!("--rollback-after must be between 15s and 1h");
    }
    if sys::unit_state(&format!("{ROLLBACK_UNIT}.timer")) == "active" {
        bail!("a change is already waiting for confirmation: sudo thorn harden confirm (or undo)");
    }
    if !sys::which("sshd") && !Path::new("/usr/sbin/sshd").exists() {
        bail!("openssh-server is not installed");
    }

    if o.totp {
        if !pam_module_installed() {
            bail!("install the PAM module first: apt install libpam-google-authenticator");
        }
        enroll(&user, &home, o.totp_secret)?;
    }

    backup()?;
    sys::write_file(Path::new(DROP_IN), &drop_in(o.totp, o.fido), 0o644, None)?;
    if o.totp {
        let pam = std::fs::read_to_string(PAM_SSHD).context("reading /etc/pam.d/sshd")?;
        sys::write_file(Path::new(PAM_SSHD), &pam_with_totp(&pam), 0o644, None)?;
    }
    if let Err(e) = sys::run("/usr/sbin/sshd", &["-t"]) {
        restore()?;
        bail!("sshd rejected the new settings, nothing changed: {e}");
    }
    reload_sshd()?;
    sys::run(
        "systemd-run",
        &[
            &format!("--unit={ROLLBACK_UNIT}"),
            &format!("--on-active={secs}"),
            "--timer-property=AccuracySec=1s",
            paths::THORN_BIN,
            "harden",
            "undo",
        ],
    )?;
    println!(
        "\nSSH now requires {} for {user}.",
        match (o.totp, o.fido) {
            (true, true) => "a hardware key and an authenticator code",
            (true, false) => "your key and an authenticator code",
            _ => "a hardware key",
        }
    );
    println!(
        "Keep this session open. In a NEW terminal, log in again to check it works, then run:"
    );
    println!("  sudo thorn harden confirm");
    println!(
        "If you do not confirm within {}, the change is undone automatically.",
        humantime::format_duration(std::time::Duration::from_secs(secs))
    );
    Ok(())
}

pub fn confirm() -> Result<()> {
    sys::require_root()?;
    if sys::unit_state(&format!("{ROLLBACK_UNIT}.timer")) != "active" {
        bail!("nothing is waiting for confirmation");
    }
    sys::systemctl(&["stop", &format!("{ROLLBACK_UNIT}.timer")])?;
    println!("confirmed; the SSH settings stay");
    Ok(())
}

pub fn undo() -> Result<()> {
    sys::require_root()?;
    let _ = sys::systemctl(&["stop", &format!("{ROLLBACK_UNIT}.timer")]);
    restore()?;
    reload_sshd()?;
    println!("SSH settings restored to what they were before thorn harden");
    Ok(())
}

fn home_of(user: &str) -> Result<PathBuf> {
    let c = std::ffi::CString::new(user)?;
    // SAFETY: getpwnam returns static storage or null; we copy out at once.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        bail!("no user {user}");
    }
    let dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
    Ok(PathBuf::from(dir.to_string_lossy().into_owned()))
}

fn pam_module_installed() -> bool {
    [
        "/usr/lib/x86_64-linux-gnu/security/pam_google_authenticator.so",
        "/usr/lib/aarch64-linux-gnu/security/pam_google_authenticator.so",
        "/lib/security/pam_google_authenticator.so",
        "/usr/lib/security/pam_google_authenticator.so",
    ]
    .iter()
    .any(|p| Path::new(p).exists())
}

/// Writes ~/.google_authenticator after you prove the app has the secret.
fn enroll(user: &str, home: &Path, fixed: Option<String>) -> Result<()> {
    let secret = fixed.unwrap_or_else(webauth::new_secret);
    let uri = webauth::otpauth_uri(user, &format!("{}-ssh", sys::hostname()), &secret);
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        println!("Scan this with your authenticator app (SSH logins to this hub):\n");
        println!("{}", webauth::qr_terminal(&uri)?);
    }
    println!("key: {secret}");
    let mut ok = false;
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    for _ in 0..3 {
        if interactive {
            print!("code shown by the app: ");
            std::io::stdout().flush()?;
        }
        let code = lines.next().context("no more input")??;
        if webauth::verify_totp(&secret, &code, crate::state::now(), 0).is_some() {
            ok = true;
            break;
        }
        println!("that code does not match; try again");
    }
    if !ok {
        bail!("the authenticator was not confirmed; nothing was changed");
    }
    let scratch: Vec<String> = (0..5)
        .map(|_| {
            let b = webauth::random_bytes::<4>();
            format!("{:08}", u32::from_le_bytes(b) % 100_000_000)
        })
        .collect();
    let file = home.join(".google_authenticator");
    let ids = sys::lookup_user(user).context("user vanished")?;
    sys::write_file(
        &file,
        &google_authenticator_file(&secret, &scratch),
        0o400,
        Some((ids.uid, ids.gid)),
    )?;
    println!("\nSSH emergency codes (each works once instead of a code; keep them offline):");
    for s in &scratch {
        println!("  {s}");
    }
    Ok(())
}

pub fn google_authenticator_file(secret: &str, scratch: &[String]) -> String {
    let mut s = format!(
        "{secret}\n\" RATE_LIMIT 3 30\n\" WINDOW_SIZE 3\n\" DISALLOW_REUSE\n\" TOTP_AUTH\n"
    );
    for c in scratch {
        s.push_str(c);
        s.push('\n');
    }
    s
}

pub fn drop_in(totp: bool, fido: bool) -> String {
    let mut s = String::from(
        "# Installed by thorn harden ssh. Undo with: sudo thorn harden undo\n\
         PasswordAuthentication no\n\
         PermitRootLogin no\n\
         PubkeyAuthentication yes\n\
         UsePAM yes\n",
    );
    if totp {
        s.push_str("KbdInteractiveAuthentication yes\nAuthenticationMethods publickey,keyboard-interactive\n");
    } else {
        s.push_str("KbdInteractiveAuthentication no\nAuthenticationMethods publickey\n");
    }
    if fido {
        s.push_str(
            "PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com\n",
        );
    }
    s
}

/// Asks for the TOTP code instead of the password: the key has already
/// proven who you are, the code is the second factor.
pub fn pam_with_totp(pam: &str) -> String {
    if pam.contains(PAM_LINE) {
        return pam.to_string();
    }
    let mut out = String::new();
    let mut placed = false;
    for line in pam.lines() {
        if line.trim() == "@include common-auth" {
            out.push_str(PAM_LINE);
            out.push('\n');
            out.push_str("# @include common-auth  (disabled by thorn harden ssh)\n");
            placed = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !placed {
        out = format!("{PAM_LINE}\n{out}");
    }
    out
}

/// Saves the original files (or notes that they did not exist).
fn backup() -> Result<()> {
    let dir = backup_dir();
    sys::mkdir(&dir, 0o700)?;
    for (src, name) in [(DROP_IN, "drop-in"), (PAM_SSHD, "pam-sshd")] {
        let dest = dir.join(name);
        let absent = dir.join(format!("{name}.absent"));
        let _ = std::fs::remove_file(&dest);
        let _ = std::fs::remove_file(&absent);
        match std::fs::read_to_string(src) {
            Ok(t) => sys::write_file(&dest, &t, 0o600, None)?,
            Err(_) => sys::write_file(&absent, "", 0o600, None)?,
        }
    }
    Ok(())
}

fn restore() -> Result<()> {
    let dir = backup_dir();
    for (src, name) in [(DROP_IN, "drop-in"), (PAM_SSHD, "pam-sshd")] {
        let saved = dir.join(name);
        if dir.join(format!("{name}.absent")).exists() {
            let _ = std::fs::remove_file(src);
        } else if let Ok(t) = std::fs::read_to_string(&saved) {
            sys::write_file(Path::new(src), &t, 0o644, None)?;
        }
    }
    Ok(())
}

fn reload_sshd() -> Result<()> {
    sys::systemctl(&["reload", "ssh.service"])
        .or_else(|_| sys::systemctl(&["reload", "sshd.service"]))
        .context("reloading sshd")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pam_replaces_password_with_code() {
        let debian = "#%PAM-1.0\n# Standard Un*x authentication.\n@include common-auth\naccount required pam_nologin.so\n";
        let out = pam_with_totp(debian);
        assert!(out.contains("auth required pam_google_authenticator.so\n# @include common-auth"));
        assert!(!out.lines().any(|l| l.trim() == "@include common-auth"));
        assert_eq!(pam_with_totp(&out), out, "idempotent");
    }

    #[test]
    fn sshd_settings() {
        let t = drop_in(true, false);
        assert!(t.contains("AuthenticationMethods publickey,keyboard-interactive"));
        assert!(t.contains("PasswordAuthentication no"));
        let f = drop_in(false, true);
        assert!(f.contains("AuthenticationMethods publickey\n"));
        assert!(f.contains("PubkeyAcceptedAlgorithms sk-ssh-ed25519@openssh.com"));
    }

    #[test]
    fn authenticator_file() {
        let f = google_authenticator_file("ABC", &["12345678".into()]);
        assert!(f.starts_with("ABC\n\" RATE_LIMIT 3 30\n"));
        assert!(f.contains("\" TOTP_AUTH\n12345678\n"));
    }
}
