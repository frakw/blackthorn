//! thorn web enable / disable / user ...: accounts for the web UI and
//! turning it on.

use crate::webauth::{self, User, Users};
use crate::{ctx, paths, sys, units};
use anyhow::{bail, Context, Result};
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

fn users_path() -> &'static Path {
    Path::new(paths::WEB_USERS_FILE)
}

pub fn enable() -> Result<()> {
    sys::require_root()?;
    let (cfg, _) = ctx::read_only()?;
    if cfg.web.listen.is_empty() {
        bail!(
            "set where the web UI listens first, in {}:\n  [web]\n  listen = [\"<this hub's tailnet IP>:7180\"]\n\
             (then run: sudo thorn apply)",
            paths::CONFIG_FILE
        );
    }
    if cfg.inbound.admin_from.is_empty() {
        println!(
            "note: inbound.admin_from is empty, so any device that can reach {} may try to log in; \
             consider listing your own devices there",
            cfg.web.listen
                .iter()
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    sys::systemctl(&["enable", "--now", units::API, units::WEB])?;
    for a in &cfg.web.listen {
        println!("web UI on http://{a}/");
    }
    if !has_accounts()? {
        println!("no web accounts yet; add one with: sudo thorn web user add <name>");
    }
    Ok(())
}

pub fn disable() -> Result<()> {
    sys::require_root()?;
    sys::systemctl(&["disable", "--now", units::WEB, units::API])?;
    println!("web UI stopped; the command line keeps working");
    Ok(())
}

pub fn user_ls() -> Result<()> {
    sys::require_root()?;
    let users = Users::load(users_path())?;
    if users.users.is_empty() {
        println!("no web accounts; add one with: sudo thorn web user add <name>");
    }
    for (name, u) in &users.users {
        println!("{name}  ({} recovery codes left)", u.recovery.len());
    }
    Ok(())
}

pub fn has_accounts() -> Result<bool> {
    Ok(!Users::load(users_path())?.users.is_empty())
}

/// Asks for a name (suggesting whoever ran sudo) and adds that account.
pub fn first_account() -> Result<()> {
    let suggested = std::env::var("SUDO_USER")
        .ok()
        .filter(|u| u != "root" && crate::state::validate_name("account", u).is_ok())
        .unwrap_or_else(|| "admin".into());
    let mut input = Input::new();
    let name = input.line(&format!("account name [{suggested}]: "))?;
    let name = if name.is_empty() { suggested } else { name };
    add_account(&name, None, &mut input)
}

pub fn user_add(name: &str, totp_secret: Option<String>) -> Result<()> {
    add_account(name, totp_secret, &mut Input::new())
}

/// Takes the one `Input` (and so the one stdin lock) the caller already
/// holds: a second lock on stdin would wait forever.
fn add_account(name: &str, totp_secret: Option<String>, input: &mut Input) -> Result<()> {
    sys::require_root()?;
    crate::state::validate_name("account", name)?;
    let mut users = Users::load(users_path())?;
    if users.users.contains_key(name) {
        bail!("there is already an account named {name}");
    }
    let password = input.new_password()?;
    let (secret, recovery, step) = enroll_totp(name, totp_secret, input)?;
    users.users.insert(
        name.to_string(),
        User {
            password: webauth::hash_password(&password)?,
            totp_secret: secret,
            recovery: hash_codes(&recovery)?,
            last_step: step,
        },
    );
    users.save(users_path())?;
    print_recovery(&recovery, input)?;
    if sys::unit_state(units::WEB) == "active" {
        println!("account {name} added; log in to the web UI with it");
    } else {
        println!("account {name} added; turn the web UI on with: sudo thorn web enable");
    }
    Ok(())
}

pub fn user_rm(name: &str) -> Result<()> {
    sys::require_root()?;
    let mut users = Users::load(users_path())?;
    if users.users.remove(name).is_none() {
        bail!("no account named {name}");
    }
    users.save(users_path())?;
    let _ = sys::systemctl(&["try-restart", units::API]);
    println!("account {name} removed (and logged out)");
    Ok(())
}

pub fn user_passwd(name: &str) -> Result<()> {
    sys::require_root()?;
    let mut users = Users::load(users_path())?;
    let u = users
        .users
        .get_mut(name)
        .with_context(|| format!("no account named {name}"))?;
    u.password = webauth::hash_password(&Input::new().new_password()?)?;
    users.save(users_path())?;
    let _ = sys::systemctl(&["try-restart", units::API]);
    println!("password changed for {name}; existing logins ended");
    Ok(())
}

pub fn user_totp_reset(name: &str) -> Result<()> {
    sys::require_root()?;
    let mut users = Users::load(users_path())?;
    if !users.users.contains_key(name) {
        bail!("no account named {name}");
    }
    let mut input = Input::new();
    let (secret, recovery, step) = enroll_totp(name, None, &mut input)?;
    let u = users.users.get_mut(name).expect("checked");
    u.totp_secret = secret;
    u.recovery = hash_codes(&recovery)?;
    u.last_step = step;
    users.save(users_path())?;
    let _ = sys::systemctl(&["try-restart", units::API]);
    print_recovery(&recovery, &mut input)?;
    println!("new authenticator set for {name}; existing logins ended");
    Ok(())
}

/// Shows the secret as a QR code and asks for a code from the app, so a
/// mistyped or unscanned secret never locks you out.
fn enroll_totp(
    name: &str,
    fixed: Option<String>,
    input: &mut Input,
) -> Result<(String, Vec<String>, u64)> {
    let secret = match fixed {
        Some(s) => {
            webauth::base32_decode(&s).context("--totp-secret is not base32")?;
            s
        }
        None => webauth::new_secret(),
    };
    let uri = webauth::otpauth_uri(name, &sys::hostname(), &secret);
    if input.interactive {
        println!("\nScan this with your authenticator app (or enter the key by hand):\n");
        println!("{}", webauth::qr_terminal(&uri)?);
    }
    println!("key: {secret}");
    for attempt in 0..3 {
        let code = input.line("code shown by the app: ")?;
        if let Some(step) = webauth::verify_totp(&secret, &code, crate::state::now(), 0) {
            return Ok((secret, webauth::new_recovery_codes(), step));
        }
        if attempt < 2 {
            println!("that code does not match; check the phone's clock and try again");
        }
    }
    bail!("the authenticator was not confirmed; nothing was saved")
}

fn hash_codes(codes: &[String]) -> Result<Vec<String>> {
    codes.iter().map(|c| webauth::hash_password(c)).collect()
}

/// Prints the recovery codes. At a terminal, waits until they are written
/// down, then clears the screen and its scrollback, so neither they nor the
/// QR code above stay in the terminal's history.
fn print_recovery(codes: &[String], input: &mut Input) -> Result<()> {
    println!("\nRecovery codes (each works once instead of a TOTP code; keep them offline):");
    for c in codes {
        println!("  {c}");
    }
    println!();
    if input.interactive {
        input.line("Press Enter once you have written them down (the screen is then cleared): ")?;
        print!("\x1b[H\x1b[2J\x1b[3J");
        println!("Cleared the QR code and the recovery codes from this terminal.");
    }
    Ok(())
}

/// Reads answers from the terminal (without echo for passwords), or line by
/// line from standard input when it is not a terminal (for scripts).
struct Input {
    interactive: bool,
    lines: std::io::Lines<std::io::StdinLock<'static>>,
}

impl Input {
    fn new() -> Input {
        Input {
            interactive: std::io::stdin().is_terminal(),
            lines: std::io::stdin().lock().lines(),
        }
    }

    fn line(&mut self, prompt: &str) -> Result<String> {
        if self.interactive {
            print!("{prompt}");
            std::io::stdout().flush()?;
        }
        Ok(self
            .lines
            .next()
            .context("no more input")??
            .trim()
            .to_string())
    }

    fn secret(&mut self, prompt: &str) -> Result<String> {
        if !self.interactive {
            return self.line(prompt);
        }
        let _echo = EchoOff::new();
        let r = self.line(prompt);
        println!();
        r
    }

    fn new_password(&mut self) -> Result<String> {
        loop {
            let p = self.secret("password (12+ characters): ")?;
            if let Err(e) = webauth::check_password_strength(&p) {
                if !self.interactive {
                    return Err(e);
                }
                println!("{e}");
                continue;
            }
            if self.interactive && self.secret("again: ")? != p {
                println!("they differ; once more");
                continue;
            }
            return Ok(p);
        }
    }
}

/// Turns terminal echo off until dropped.
struct EchoOff(Option<libc::termios>);

impl EchoOff {
    fn new() -> EchoOff {
        // SAFETY: termios calls on stdin with a zeroed struct they fill in.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut t) != 0 {
                return EchoOff(None);
            }
            let saved = t;
            t.c_lflag &= !libc::ECHO;
            libc::tcsetattr(0, libc::TCSANOW, &t);
            EchoOff(Some(saved))
        }
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        if let Some(t) = self.0 {
            // SAFETY: restores the settings read in new().
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, &t);
            }
        }
    }
}

/// Hidden helper for scripts and tests: the current code for a secret.
pub fn totp(secret: &str) -> Result<()> {
    println!("{}", webauth::totp_now(secret, crate::state::now())?);
    Ok(())
}
