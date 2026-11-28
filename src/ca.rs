//! SSH certificates (v0.18): machines trust blackthorn's certificate
//! authority instead of each of its keys, and every login it makes carries
//! a certificate that is good for minutes.
//!
//! - The hub CA (/etc/blackthorn/ca/hub) signs. Only root reads it.
//! - The recovery CA is made on request; its private half is shown once,
//!   for you to keep away from the hub. Machines trust it too, so a hub
//!   that was broken into can be replaced: a new hub CA, pushed to the
//!   machines with a certificate the recovery key signs.
//! - A space's key lives only in memory (/run, a tmpfs): made again at
//!   boot, in its agent with one certificate naming every login it has now
//!   (`space-<key>-<machine id>` for its user login on a machine,
//!   `space-<key>-ro` for its read-only ones), for ten minutes, renewed by
//!   the minute tick.
//! - The management login gets a certificate the same way
//!   (`blackthorn-manage`), signed when a command needs one.
//! - On a machine, sshd trusts the CAs in /etc/ssh/blackthorn/ca.pub and
//!   takes, for each account, the names in
//!   /etc/ssh/blackthorn/principals/<account>, each with the logger as
//!   forced command and the hub's addresses as the only source.
//! - Every certificate is a line in /var/log/blackthorn/certs.log: its
//!   serial, which the machine's sshd logs too.

use crate::state::{Host, State, Tier};
use crate::{paths, sys};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub const CA_DIR: &str = "/etc/blackthorn/ca";
pub const HUB_CA: &str = "/etc/blackthorn/ca/hub";
pub const RECOVERY_PUB: &str = "/etc/blackthorn/ca/recovery.pub";
const SERIAL_FILE: &str = "/var/lib/blackthorn/ca-serial";
pub const CERT_LOG: &str = "/var/log/blackthorn/certs.log";
/// In memory (a tmpfs): the spaces' keys and every certificate.
pub const CERT_DIR: &str = "/run/blackthorn-certs";

/// On a machine.
pub const REMOTE_CA: &str = "/etc/ssh/blackthorn/ca.pub";
pub const REMOTE_PRINCIPALS: &str = "/etc/ssh/blackthorn/principals";

/// What the management login's certificate names.
pub const MANAGE: &str = "blackthorn-manage";

/// How long a certificate is good for, and when it is renewed.
const VALID_SECS: u64 = 600;
const RENEW_LEFT: u64 = 240;

/// The name a space's user login on a machine takes in certificates.
pub fn user_principal(key: &str, key_id: &str) -> String {
    format!(
        "space-{key}-{}",
        if key_id.is_empty() { "main" } else { key_id }
    )
}

/// The name its read-only logins take (the same on every machine: they
/// only read).
pub fn ro_principal(key: &str) -> String {
    format!("space-{key}-ro")
}

/// A space's key, in memory.
pub fn space_key(key: &str) -> PathBuf {
    Path::new(CERT_DIR).join(format!("space-{key}"))
}

fn cert_of(key_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}-cert.pub", key_file.display()))
}

/// Makes the hub CA if there is none yet.
pub fn ensure_hub_ca() -> Result<()> {
    if Path::new(HUB_CA).exists() {
        return Ok(());
    }
    sys::mkdir(Path::new(CA_DIR), 0o700)?;
    sys::run(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            &format!("blackthorn hub CA on {}", sys::hostname()),
            "-f",
            HUB_CA,
        ],
    )
}

/// The CA public keys machines trust: the hub's, and the recovery one.
pub fn trusted() -> Result<Vec<String>> {
    ensure_hub_ca()?;
    let mut v = vec![read_line(Path::new(&format!("{HUB_CA}.pub")))?];
    if let Ok(r) = read_line(Path::new(RECOVERY_PUB)) {
        v.push(r);
    }
    Ok(v)
}

fn read_line(p: &Path) -> Result<String> {
    Ok(std::fs::read_to_string(p)
        .with_context(|| format!("reading {}", p.display()))?
        .trim()
        .to_string())
}

/// Holds the certificate lock while alive (several processes sign: the
/// tick, the API, the asks daemon).
struct Lock(std::fs::File);

fn lock() -> Result<Lock> {
    sys::mkdir(Path::new(CERT_DIR), 0o700)?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(Path::new(CERT_DIR).join(".lock"))?;
    use std::os::unix::io::AsRawFd;
    // SAFETY: flock on a file descriptor we own.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        bail!("locking {CERT_DIR}");
    }
    Ok(Lock(f))
}

impl Drop for Lock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: as above.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn next_serial() -> Result<u64> {
    let n = std::fs::read_to_string(SERIAL_FILE)
        .ok()
        .and_then(|t| t.trim().parse::<u64>().ok())
        .unwrap_or(0)
        + 1;
    sys::write_file(Path::new(SERIAL_FILE), &format!("{n}\n"), 0o600, None)?;
    Ok(n)
}

/// What to sign.
pub struct Sign<'a> {
    /// The CA's private key file.
    pub ca: &'a Path,
    /// The public key to certify.
    pub public: &'a str,
    /// Where the certificate goes.
    pub to: &'a Path,
    pub id: &'a str,
    pub principals: &'a [String],
    pub secs: u64,
    /// The only addresses it may be used from (empty: anywhere the
    /// machine's own lines allow).
    pub from: &'a [IpAddr],
}

/// Signs a certificate (the caller holds the lock). Its serial.
fn sign(s: &Sign) -> Result<u64> {
    if s.principals.is_empty() {
        bail!("a certificate names someone");
    }
    let serial = next_serial()?;
    // ssh-keygen writes <name>-cert.pub beside the public key it signs.
    let tmp = Path::new(CERT_DIR).join(format!(".sign-{}-{serial}", std::process::id()));
    let public = PathBuf::from(format!("{}.pub", tmp.display()));
    sys::write_file(&public, &format!("{}\n", s.public.trim()), 0o600, None)?;
    let validity = format!("-5m:+{}m", s.secs.div_ceil(60));
    let principals = s.principals.join(",");
    let id = format!("{}#{serial}", s.id);
    let mut args: Vec<String> = vec![
        "-q".into(),
        "-s".into(),
        s.ca.display().to_string(),
        "-I".into(),
        id.clone(),
        "-n".into(),
        principals.clone(),
        "-V".into(),
        validity,
        "-z".into(),
        serial.to_string(),
        "-O".into(),
        "clear".into(),
    ];
    if !s.from.is_empty() {
        let list: Vec<String> = s.from.iter().map(|a| a.to_string()).collect();
        args.push("-O".into());
        args.push(format!("source-address={}", list.join(",")));
    }
    args.push(public.display().to_string());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let r = sys::run("ssh-keygen", &refs);
    let made = PathBuf::from(format!("{}-cert.pub", tmp.display()));
    let _ = std::fs::remove_file(&public);
    r?;
    std::fs::rename(&made, s.to).with_context(|| format!("placing {}", s.to.display()))?;
    log(serial, &id, &principals, s.secs);
    Ok(serial)
}

fn log(serial: u64, id: &str, principals: &str, secs: u64) {
    let now = crate::state::now();
    let line = format!(
        "{} serial={serial} id={id} principals={principals} valid={}m\n",
        humantime::format_rfc3339_seconds(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(now)
        ),
        secs / 60
    );
    let _ = sys::mkdir(Path::new(paths::ACTIVITY_DIR), 0o750);
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(CERT_LOG)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// What a certificate in the agent was made for, kept beside it.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
struct Meta {
    principals: Vec<String>,
    from: Vec<IpAddr>,
    until: u64,
}

fn meta_file(key_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.meta", key_file.display()))
}

/// The names a space's certificate carries now, and the addresses it may
/// be used from: for each of its logins on a machine that trusts the CA.
pub fn space_principals(
    cfg: &crate::config::Config,
    state: &State,
    space: &str,
    now: u64,
) -> (Vec<String>, Vec<IpAddr>) {
    let Some(s) = state.spaces.get(space) else {
        return (Vec::new(), Vec::new());
    };
    let mut names = Vec::new();
    let mut from = Vec::new();
    for l in state.logins(space, now) {
        if !uses_cert(l.h, &s.key) {
            continue;
        }
        let Some(m) = s.machine(l.host) else { continue };
        names.push(if l.tier == Tier::ReadOnly {
            ro_principal(&s.key)
        } else {
            user_principal(&s.key, &m.key_id)
        });
        from.extend(crate::ops::hub_addresses(cfg, l.h.address));
    }
    names.sort();
    names.dedup();
    from.sort();
    from.dedup();
    (names, from)
}

/// Whether a space logs in to a machine with its certificate: the machine
/// trusts the CA and has the space's names.
pub fn uses_cert(h: &Host, key: &str) -> bool {
    h.ca && h.accounts.get(key).is_some_and(|a| a.ca)
}

/// Brings a space's key and certificate up to date: made if missing,
/// signed again when its logins changed or it runs out soon, removed when
/// it has none. Whether anything changed (its agent needs them again).
pub fn refresh_space(
    cfg: &crate::config::Config,
    state: &State,
    space: &str,
    now: u64,
) -> Result<bool> {
    let Some(s) = state.spaces.get(space) else {
        return Ok(false);
    };
    let (principals, from) = space_principals(cfg, state, space, now);
    let key = space_key(&s.key);
    let cert = cert_of(&key);
    let _l = lock()?;
    if principals.is_empty() {
        let had = cert.exists();
        let _ = std::fs::remove_file(&cert);
        let _ = std::fs::remove_file(meta_file(&key));
        return Ok(had);
    }
    let old: Meta = std::fs::read_to_string(meta_file(&key))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let fresh = key.exists()
        && cert.exists()
        && old.principals == principals
        && old.from == from
        && old.until > now + RENEW_LEFT;
    if fresh {
        return Ok(false);
    }
    if !key.exists() {
        let _ = std::fs::remove_file(PathBuf::from(format!("{}.pub", key.display())));
        sys::run(
            "ssh-keygen",
            &[
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                &format!("blackthorn space {} (in memory)", s.key),
                "-f",
                key.to_str().context("key path")?,
            ],
        )?;
    }
    ensure_hub_ca()?;
    let public = read_line(Path::new(&format!("{}.pub", key.display())))?;
    sign(&Sign {
        ca: Path::new(HUB_CA),
        public: &public,
        to: &cert,
        id: &format!("{space}@{}", sys::hostname()),
        principals: &principals,
        secs: VALID_SECS,
        from: &from,
    })?;
    let meta = Meta {
        principals,
        from,
        until: now + VALID_SECS,
    };
    sys::write_file(
        &meta_file(&key),
        &serde_json::to_string(&meta)?,
        0o600,
        None,
    )?;
    Ok(true)
}

/// The management login's certificate for a machine that trusts the CA,
/// signed when it has less than a few minutes left. None: the machine
/// does not, or signing failed (the key alone is tried then).
pub fn manage_cert(cfg: &crate::config::Config, name: &str, h: &Host) -> Option<PathBuf> {
    if !h.ca {
        return None;
    }
    match manage_cert_with(cfg, name, h, Path::new(HUB_CA), VALID_SECS) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("{name}: no certificate for the management login: {e:#}");
            None
        }
    }
}

fn manage_cert_with(
    cfg: &crate::config::Config,
    name: &str,
    h: &Host,
    ca: &Path,
    secs: u64,
) -> Result<PathBuf> {
    let to = Path::new(CERT_DIR).join(format!("manage-{name}-cert.pub"));
    let meta = PathBuf::from(format!("{}.meta", to.display()));
    let now = crate::state::now();
    let _l = lock()?;
    let from = crate::ops::hub_addresses(cfg, h.address);
    let fresh_for_hub = ca == Path::new(HUB_CA);
    if fresh_for_hub && to.exists() {
        let old: Meta = std::fs::read_to_string(&meta)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        if old.until > now + RENEW_LEFT / 2 && old.from == from {
            return Ok(to);
        }
    }
    let public = read_line(&paths::pubkey_file(name))?;
    sign(&Sign {
        ca,
        public: &public,
        to: &to,
        id: &format!("manage@{}:{name}", sys::hostname()),
        principals: &[MANAGE.to_string()],
        secs,
        from: &from,
    })?;
    let m = Meta {
        principals: vec![MANAGE.to_string()],
        from,
        until: if fresh_for_hub { now + secs } else { 0 },
    };
    sys::write_file(&meta, &serde_json::to_string(&m)?, 0o600, None)?;
    Ok(to)
}

/// Every minute: renew the spaces' certificates that run out soon, and
/// give their agents the new ones.
pub fn tick(cfg: &crate::config::Config, state: &State, now: u64) {
    for (name, s) in &state.spaces {
        match refresh_space(cfg, state, name, now) {
            Ok(true) => {
                if let Err(e) =
                    crate::keys::sync_agent(&s.key, &crate::apply::agent_keys(state, name, now))
                {
                    eprintln!("{name}: certificate: {e:#}");
                }
            }
            Ok(false) => {}
            Err(e) => eprintln!("{name}: certificate: {e:#}"),
        }
    }
}

/// The script that puts the CAs a machine trusts in place.
pub fn trust_script(pubs: &[String]) -> Result<String> {
    for p in pubs {
        if p.contains('\'') || p.contains('\n') || p.contains("BLACKTHORN_CA") {
            bail!("an odd CA key");
        }
    }
    Ok(format!(
        r#"#!/bin/sh
# blackthorn: the certificate authorities this machine trusts for its logins.
set -eu
[ -d /etc/ssh/blackthorn ] || {{ echo "this machine is not set up (thorn host setup)" >&2; exit 1; }}
cat >{ca}.tmp <<'BLACKTHORN_CA'
{list}
BLACKTHORN_CA
chmod 644 {ca}.tmp
mv -f {ca}.tmp {ca}
echo "bt: done"
"#,
        ca = REMOTE_CA,
        list = pubs.join("\n"),
    ))
}

/// Status, for `thorn ca status` and the Settings page.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    /// SHA256 fingerprints.
    pub hub: String,
    pub recovery: Option<String>,
    /// Machines that trust the CA, and those set up that do not (why).
    pub trusting: Vec<String>,
    pub not: Vec<(String, String)>,
    /// The latest certificates, newest first.
    pub latest: Vec<String>,
}

fn fingerprint(public_file: &str) -> String {
    sys::output("ssh-keygen", &["-l", "-f", public_file])
        .ok()
        .and_then(|o| o.split_whitespace().nth(1).map(String::from))
        .unwrap_or_default()
}

pub fn status() -> Result<Status> {
    sys::require_root()?;
    ensure_hub_ca()?;
    let (_, state) = crate::ctx::read_only()?;
    let mut st = Status {
        hub: fingerprint(&format!("{HUB_CA}.pub")),
        recovery: Path::new(RECOVERY_PUB)
            .exists()
            .then(|| fingerprint(RECOVERY_PUB)),
        ..Default::default()
    };
    for (n, h) in &state.hosts {
        if h.setup.is_none() {
            continue;
        }
        if h.ca {
            st.trusting.push(n.clone());
        } else {
            st.not.push((
                n.clone(),
                h.ca_problem
                    .clone()
                    .unwrap_or_else(|| "not set up for certificates yet".into()),
            ));
        }
    }
    let text = std::fs::read_to_string(CERT_LOG).unwrap_or_default();
    st.latest = text.lines().rev().take(20).map(String::from).collect();
    Ok(st)
}

/// Makes the recovery CA (again, with `replace`): its private key, to show
/// once. Machines learn the new public half as they are reached.
pub fn make_recovery(replace: bool) -> Result<String> {
    sys::require_root()?;
    if Path::new(RECOVERY_PUB).exists() && !replace {
        bail!("there is a recovery key already; making a new one retires it (--replace)");
    }
    sys::mkdir(Path::new(CA_DIR), 0o700)?;
    let _l = lock()?;
    let tmp = Path::new(CERT_DIR).join(format!(".recovery-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(format!("{}.pub", tmp.display()));
    let date = humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string();
    sys::run(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            &format!(
                "blackthorn recovery CA for {} ({})",
                sys::hostname(),
                &date[..10]
            ),
            "-f",
            tmp.to_str().context("path")?,
        ],
    )?;
    let private = std::fs::read_to_string(&tmp);
    let public = std::fs::read_to_string(format!("{}.pub", tmp.display()));
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(format!("{}.pub", tmp.display()));
    let (private, public) = (private?, public?);
    sys::write_file(Path::new(RECOVERY_PUB), &public, 0o644, None)?;
    drop(_l);
    queue_trust()?;
    Ok(private)
}

/// Queues the CA list for every machine that trusts the CA (the tick
/// sends it).
pub fn queue_trust() -> Result<()> {
    let mut ctx = crate::ctx::Ctx::open()?;
    for h in ctx.state.hosts.values_mut() {
        if h.ca && !h.pending.contains(&crate::state::Pending::Trust) {
            h.pending.push(crate::state::Pending::Trust);
        }
    }
    ctx.commit()
}

/// Sends a machine the CAs to trust now, through its management login
/// with a certificate `ca` signs (the hub's, or a recovery key's).
pub fn push_trust(name: &str, ca: Option<&Path>) -> Result<()> {
    let (cfg, state) = crate::ctx::read_only()?;
    let h = state.host(name)?.clone();
    let script = trust_script(&trusted()?)?;
    let cert = match ca {
        Some(ca) => Some(manage_cert_with(&cfg, name, &h, ca, 300)?),
        None => manage_cert(&cfg, name, &h),
    };
    let cmd = if h.root_login() {
        "sh -s"
    } else {
        "sudo -n sh -s"
    };
    let out = crate::remote::ssh_with(
        name,
        &h,
        &paths::key_file(name),
        cert.as_deref(),
        &h.user,
        cmd,
        Some(&script),
    )?;
    if !out.status.success()
        || !String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|l| l == "bt: done")
    {
        bail!("{name}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    if ca.is_some() {
        // A recovery-signed certificate is not kept for later.
        let _ = std::fs::remove_file(Path::new(CERT_DIR).join(format!("manage-{name}-cert.pub")));
        let _ =
            std::fs::remove_file(Path::new(CERT_DIR).join(format!("manage-{name}-cert.pub.meta")));
    }
    Ok(())
}

/// A copy of a private key file only root reads (ssh-keygen refuses one
/// others may read). Removed by the caller.
fn private_copy(from: &Path) -> Result<PathBuf> {
    let text =
        std::fs::read_to_string(from).with_context(|| format!("reading {}", from.display()))?;
    if !text.contains("PRIVATE KEY") {
        bail!("{} is not a private key", from.display());
    }
    sys::mkdir(Path::new(CERT_DIR), 0o700)?;
    let to = Path::new(CERT_DIR).join(format!(".given-{}", std::process::id()));
    sys::write_file(&to, &text, 0o600, None)?;
    Ok(to)
}

/// A new hub CA, sent to every machine that trusts the old one (signed by
/// `recovery`, the recovery key's file, when the old hub CA must not be
/// used: after a break-in). The old hub CA is gone afterwards. Returns
/// the machines reached and those not (with why).
pub fn rotate(recovery: Option<&Path>) -> Result<(Vec<String>, Vec<(String, String)>)> {
    sys::require_root()?;
    ensure_hub_ca()?;
    let given = recovery.map(private_copy).transpose()?;
    let old = PathBuf::from(format!("{HUB_CA}.old"));
    {
        let _l = lock()?;
        std::fs::rename(HUB_CA, &old)?;
        std::fs::rename(format!("{HUB_CA}.pub"), format!("{}.pub", old.display()))?;
        if let Err(e) = ensure_hub_ca() {
            let _ = std::fs::rename(&old, HUB_CA);
            let _ = std::fs::rename(format!("{}.pub", old.display()), format!("{HUB_CA}.pub"));
            return Err(e);
        }
    }
    // Every certificate out there is the old CA's: none is reused, and
    // the spaces' are signed anew when the machines are told (below).
    if let Ok(dir) = std::fs::read_dir(CERT_DIR) {
        for e in dir.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.ends_with(".meta") || n.starts_with("manage-") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let signer = given.clone().unwrap_or_else(|| old.clone());
    let r = push_all(&signer);
    if let Some(g) = given {
        let _ = std::fs::remove_file(g);
    }
    let _ = std::fs::remove_file(&old);
    let _ = std::fs::remove_file(format!("{}.pub", old.display()));
    r
}

/// Sends every machine that trusts the CA the CAs to trust, with a
/// certificate from `signer` (a private key file).
pub fn push(recovery: &Path) -> Result<(Vec<String>, Vec<(String, String)>)> {
    sys::require_root()?;
    let given = private_copy(recovery)?;
    let r = push_all(&given);
    let _ = std::fs::remove_file(given);
    r
}

fn push_all(signer: &Path) -> Result<(Vec<String>, Vec<(String, String)>)> {
    let (_, state) = crate::ctx::read_only()?;
    let mut ok = Vec::new();
    let mut failed = Vec::new();
    for (n, h) in &state.hosts {
        if !h.ca {
            continue;
        }
        match push_trust(n, Some(signer)) {
            Ok(()) => ok.push(n.clone()),
            Err(e) => failed.push((n.clone(), format!("{e:#}"))),
        }
    }
    let mut ctx = crate::ctx::Ctx::open()?;
    for n in &ok {
        if let Some(h) = ctx.state.hosts.get_mut(n) {
            h.pending.retain(|p| *p != crate::state::Pending::Trust);
        }
    }
    for (n, _) in &failed {
        if let Some(h) = ctx.state.hosts.get_mut(n) {
            if !h.pending.contains(&crate::state::Pending::Trust) {
                h.pending.push(crate::state::Pending::Trust);
            }
        }
    }
    ctx.commit()?;
    Ok((ok, failed))
}

/// Lets a machine take only certificates from the management login:
/// checks that a certificate alone logs in (with a key made for the test
/// and nowhere listed), then removes blackthorn's key line from the
/// login's authorized_keys (and root's, if it was added there).
pub fn drop_key(name: &str) -> Result<()> {
    sys::require_root()?;
    let (cfg, state) = crate::ctx::read_only()?;
    let h = state.host(name)?.clone();
    if !h.ca {
        bail!("{name} does not take blackthorn's certificates yet (thorn host setup {name})");
    }
    // The test: a throwaway key, certified, no line anywhere.
    let _l = lock()?;
    let tmp = Path::new(CERT_DIR).join(format!(".test-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(format!("{}.pub", tmp.display()));
    sys::run(
        "ssh-keygen",
        &[
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "blackthorn test",
            "-f",
            tmp.to_str().context("path")?,
        ],
    )?;
    let public = read_line(Path::new(&format!("{}.pub", tmp.display())))?;
    let cert = cert_of(&tmp);
    let signed = sign(&Sign {
        ca: Path::new(HUB_CA),
        public: &public,
        to: &cert,
        id: &format!("test@{}:{name}", sys::hostname()),
        principals: &[MANAGE.to_string()],
        secs: 120,
        from: &crate::ops::hub_addresses(&cfg, h.address),
    });
    drop(_l);
    let cleanup = || {
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(format!("{}.pub", tmp.display()));
        let _ = std::fs::remove_file(&cert);
    };
    if let Err(e) = signed {
        cleanup();
        return Err(e);
    }
    let out = crate::remote::ssh_with(name, &h, &tmp, Some(&cert), &h.user, "id -un", None);
    let worked = out
        .as_ref()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == h.user);
    if !worked {
        cleanup();
        bail!(
            "a certificate alone does not log in to {name} as {} yet{}: its key line stays",
            h.user,
            out.map(|o| format!(" ({})", String::from_utf8_lossy(&o.stderr).trim()))
                .unwrap_or_default()
        );
    }
    let admin_key = read_line(&paths::pubkey_file(name))?
        .split_whitespace()
        .nth(1)
        .context("the management key")?
        .to_string();
    let script = format!(
        r#"#!/bin/sh
set -eu
k='{admin_key}'
home_of() {{ awk -F: -v u="$1" '$1 == u {{ print $6 }}' /etc/passwd; }}
for u in '{user}' root; do
  h=$(home_of "$u")
  f="$h/.ssh/authorized_keys"
  [ -n "$h" ] && [ -f "$f" ] && grep -qF "$k" "$f" || continue
  grep -vF "$k" "$f" >"$f.bt" || true
  chmod 600 "$f.bt"
  chown "$u" "$f.bt" 2>/dev/null || true
  mv -f "$f.bt" "$f"
  echo "bt: removed from $u"
done
echo "bt: done"
"#,
        user = h.user,
    );
    if h.user.contains('\'') {
        cleanup();
        bail!("an odd user name");
    }
    let cmd = if h.root_login() {
        "sh -s"
    } else {
        "sudo -n sh -s"
    };
    let out = crate::remote::ssh_with(name, &h, &tmp, Some(&cert), &h.user, cmd, Some(&script));
    cleanup();
    let out = out?;
    if !out.status.success() {
        bail!("{name}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let mut ctx = crate::ctx::Ctx::open()?;
    if let Some(x) = ctx.state.hosts.get_mut(name) {
        x.key_dropped = true;
    }
    ctx.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(user_principal("a1b2c3d4", ""), "space-a1b2c3d4-main");
        assert_eq!(
            user_principal("a1b2c3d4", "0f0f0f0f"),
            "space-a1b2c3d4-0f0f0f0f"
        );
        assert_eq!(ro_principal("a1b2c3d4"), "space-a1b2c3d4-ro");
        assert!(
            trust_script(&["ssh-ed25519 AAAA hub".into(), "ssh-ed25519 BBBB rec".into()])
                .unwrap()
                .contains("ssh-ed25519 AAAA hub\nssh-ed25519 BBBB rec\nBLACKTHORN_CA\n")
        );
        assert!(trust_script(&["x'y".into()]).is_err());
    }
}
