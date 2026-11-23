//! Web UI accounts: password (Argon2id) plus TOTP (RFC 6238), and recovery
//! codes. Stored in /etc/blackthorn/web-users.toml, readable by root only;
//! only the root API process checks them.

use anyhow::{bail, Context, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use std::collections::BTreeMap;
use std::path::Path;

pub const STEP: u64 = 30;
pub const ISSUER: &str = "blackthorn";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Users {
    pub users: BTreeMap<String, User>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct User {
    /// Argon2id PHC string.
    pub password: String,
    /// Base32, no padding.
    pub totp_secret: String,
    /// Argon2id hashes of unused recovery codes.
    #[serde(default)]
    pub recovery: Vec<String>,
    /// The last TOTP time step accepted, so a code works only once.
    #[serde(default)]
    pub last_step: u64,
    /// Passkeys and security keys: each logs in on its own, and stands in
    /// for a TOTP code where one is asked again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub passkeys: Vec<crate::webauthn::Passkey>,
    /// A hub admin: machines, settings, every space. Others see only the
    /// spaces they own or that are shared with them. Accounts from before
    /// v0.11 are admins.
    #[serde(default = "yes")]
    pub admin: bool,
}

fn yes() -> bool {
    true
}

impl Users {
    pub fn load(path: &Path) -> Result<Users> {
        match std::fs::read_to_string(path) {
            Ok(t) => toml::from_str(&t).with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Users::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::sys::write_file(
            path,
            &format!(
                "# Managed by thorn web user. Root only.\n{}",
                toml::to_string_pretty(self)?
            ),
            0o600,
            None,
        )
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the kernel provides random numbers");
    b
}

pub fn random_token() -> String {
    hex(&random_bytes::<32>())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt =
        SaltString::encode_b64(&random_bytes::<16>()).map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing: {e}"))?
        .to_string())
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc)
        .map(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
}

/// A password you can live with: long enough, not trivially repetitive.
pub fn check_password_strength(p: &str) -> Result<()> {
    if p.chars().count() < 12 {
        bail!("use at least 12 characters");
    }
    let distinct: std::collections::BTreeSet<char> = p.chars().collect();
    if distinct.len() < 5 {
        bail!("use more different characters");
    }
    Ok(())
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let v = B32
            .iter()
            .position(|&x| x as char == c.to_ascii_uppercase())
            .with_context(|| format!("{c:?} is not base32"))? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

/// The 6-digit code for one time step (RFC 4226 HOTP with HMAC-SHA1).
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let off = (h[19] & 0x0f) as usize;
    let bin = ((h[off] as u32 & 0x7f) << 24)
        | ((h[off + 1] as u32) << 16)
        | ((h[off + 2] as u32) << 8)
        | (h[off + 3] as u32);
    bin % 1_000_000
}

pub fn totp_now(secret_b32: &str, now: u64) -> Result<String> {
    Ok(format!(
        "{:06}",
        hotp(&base32_decode(secret_b32)?, now / STEP)
    ))
}

/// Checks a code against the current time step and one either side. Returns
/// the step it matched, which must be newer than `last_step` (a code works
/// once).
pub fn verify_totp(secret_b32: &str, code: &str, now: u64, last_step: u64) -> Option<u64> {
    let code = code.trim().replace(' ', "");
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let secret = base32_decode(secret_b32).ok()?;
    let cur = now / STEP;
    [cur.saturating_sub(1), cur, cur + 1]
        .into_iter()
        .find(|&step| step > last_step && hotp(&secret, step) == want)
}

pub fn new_secret() -> String {
    base32_encode(&random_bytes::<20>())
}

pub fn otpauth_uri(user: &str, hub: &str, secret: &str) -> String {
    let label = format!("{ISSUER}:{user}@{hub}");
    format!(
        "otpauth://totp/{}?secret={secret}&issuer={ISSUER}&algorithm=SHA1&digits=6&period={STEP}",
        url_encode(&label)
    )
}

pub fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Ten one-time recovery codes like "k7m2-9qxr-4tdw".
pub fn new_recovery_codes() -> Vec<String> {
    const ALPHA: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    (0..10)
        .map(|_| {
            let r = random_bytes::<12>();
            let chars: String = r
                .iter()
                .map(|b| ALPHA[*b as usize % ALPHA.len()] as char)
                .collect();
            format!("{}-{}-{}", &chars[0..4], &chars[4..8], &chars[8..12])
        })
        .collect()
}

/// A QR code drawn with Unicode half blocks, for a terminal.
pub fn qr_terminal(data: &str) -> Result<String> {
    let code = qrcode::QrCode::new(data.as_bytes()).context("making a QR code")?;
    Ok(code
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Light)
        .light_color(qrcode::render::unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

/// The same as an SVG image, black on white so any camera reads it.
pub fn qr_svg(data: &str) -> Result<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(data.as_bytes()).context("making a QR code")?;
    let s = code
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .quiet_zone(true)
        .build();
    // Inline in a page: without the XML declaration.
    Ok(match s.find("<svg") {
        Some(i) => s[i..].to_string(),
        None => s,
    })
}

/// Constant-time comparison of two strings (tokens, CSRF values).
pub fn same(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// A browser's User-Agent, told plainly: browser, system, kind of device.
/// A guess (a browser may say anything), good enough to tell logins apart.
pub fn describe_agent(ua: &str) -> (String, String, String) {
    let version = |key: &str| -> Option<String> {
        let at = ua.find(key)? + key.len();
        let v: String = ua[at..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        (!v.is_empty()).then_some(v)
    };
    let named = |name: &str, key: &str| match version(key) {
        Some(v) => format!("{name} {v}"),
        None => name.to_string(),
    };
    let browser = if ua.contains("Edg/") || ua.contains("EdgA/") || ua.contains("EdgiOS/") {
        named(
            "Edge",
            if ua.contains("EdgiOS/") {
                "EdgiOS/"
            } else if ua.contains("EdgA/") {
                "EdgA/"
            } else {
                "Edg/"
            },
        )
    } else if ua.contains("OPR/") {
        named("Opera", "OPR/")
    } else if ua.contains("SamsungBrowser/") {
        named("Samsung Internet", "SamsungBrowser/")
    } else if ua.contains("Firefox/") || ua.contains("FxiOS/") {
        named(
            "Firefox",
            if ua.contains("FxiOS/") {
                "FxiOS/"
            } else {
                "Firefox/"
            },
        )
    } else if ua.contains("CriOS/") {
        named("Chrome", "CriOS/")
    } else if ua.contains("Chrome/") {
        named("Chrome", "Chrome/")
    } else if ua.contains("Safari/") {
        named("Safari", "Version/")
    } else if ua.starts_with("curl/") {
        named("curl", "curl/")
    } else if ua.is_empty() {
        "unknown".into()
    } else {
        ua.split(['/', ' '])
            .next()
            .unwrap_or("unknown")
            .chars()
            .take(30)
            .collect()
    };
    let os = if ua.contains("iPhone") {
        "iOS"
    } else if ua.contains("iPad") {
        "iPadOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("CrOS") {
        "ChromeOS"
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        "macOS"
    } else if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "unknown"
    };
    let device = if ua.contains("iPad") || (ua.contains("Android") && !ua.contains("Mobile")) {
        "tablet"
    } else if ua.contains("Mobi") || ua.contains("iPhone") {
        "phone"
    } else if os == "unknown" {
        "unknown"
    } else {
        "computer"
    };
    (browser, os.into(), device.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_round_trip_and_rfc_vector() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(base32_decode("mzxw 6ytb oi==").unwrap(), b"foobar");
        let r = random_bytes::<20>();
        assert_eq!(base32_decode(&base32_encode(&r)).unwrap(), r);
        assert!(base32_decode("1").is_err());
    }

    #[test]
    fn hotp_rfc4226_vectors() {
        let secret = b"12345678901234567890";
        let want = [755224, 287082, 359152, 969429, 338314];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(hotp(secret, i as u64), *w);
        }
    }

    #[test]
    fn totp_rfc6238_vector_and_replay() {
        // RFC 6238 SHA1 vector: T=59 -> 94287082 (8 digits); 6 digits: 287082.
        let secret = base32_encode(b"12345678901234567890");
        assert_eq!(totp_now(&secret, 59).unwrap(), "287082");
        let step = verify_totp(&secret, "287082", 59, 0).unwrap();
        assert_eq!(step, 1);
        assert!(
            verify_totp(&secret, "287082", 59, step).is_none(),
            "no replay"
        );
        assert!(
            verify_totp(&secret, "287082", 59 + 30 * 5, 0).is_none(),
            "too old"
        );
        assert!(verify_totp(&secret, "28708", 59, 0).is_none());
        assert!(verify_totp(&secret, "abcdef", 59, 0).is_none());
    }

    #[test]
    fn passwords() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong", &h));
        assert!(!verify_password("x", "not a hash"));
        assert!(check_password_strength("short").is_err());
        assert!(check_password_strength("aaaaaaaaaaaaaaaa").is_err());
        assert!(check_password_strength("correct horse battery").is_ok());
    }

    #[test]
    fn uri_and_codes() {
        let u = otpauth_uri("frakw", "blackthorn", "ABC");
        assert!(u.starts_with("otpauth://totp/blackthorn%3Afrakw%40blackthorn?secret=ABC"));
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), 10);
        assert!(codes.iter().all(|c| c.len() == 14));
        assert!(qr_terminal(&u).unwrap().contains('█'));
        assert!(qr_svg(&u).unwrap().starts_with("<svg"));
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "abcd"));
    }

    #[test]
    fn agents_told_plainly() {
        let d = |ua: &str| {
            let (b, o, k) = describe_agent(ua);
            format!("{b} / {o} / {k}")
        };
        assert_eq!(
            d("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
            "Chrome 131 / macOS / computer"
        );
        assert_eq!(
            d("Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"),
            "Safari 18 / iOS / phone"
        );
        assert_eq!(
            d("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"),
            "Edge 131 / Windows / computer"
        );
        assert_eq!(
            d("Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"),
            "Firefox 133 / Linux / computer"
        );
        assert_eq!(
            d("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"),
            "Chrome 131 / Android / phone"
        );
        assert_eq!(d("curl/8.5.0"), "curl 8 / unknown / unknown");
        assert_eq!(d(""), "unknown / unknown / unknown");
    }
}
