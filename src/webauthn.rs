//! Passkeys and hardware security keys (WebAuthn), verified here without a
//! WebAuthn library: the few checks the standard requires of a relying
//! party, for ES256 (P-256) and Ed25519 keys.
//!
//! - Registration: the browser's clientDataJSON must carry our challenge,
//!   the type webauthn.create and our origin; the authenticator data must be
//!   for our RP ID, with user presence and user verification (a PIN,
//!   fingerprint or face: a passkey is then two factors on its own). The
//!   attestation statement is not checked (we ask for none).
//! - Login and step-up: the same for webauthn.get, plus the signature over
//!   authenticatorData || SHA-256(clientDataJSON) with the stored key, and a
//!   signature counter that must grow when the authenticator keeps one.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn unb64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .context("not base64url")
}

/// A registered credential, as kept in web-users.toml.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Passkey {
    /// Credential id, base64url.
    pub id: String,
    /// The COSE public key, base64url.
    pub key: String,
    #[serde(default)]
    pub counter: u32,
    pub name: String,
    pub added: u64,
}

/// What the page needs to call navigator.credentials (all base64url).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Options {
    pub challenge: String,
    pub rp_id: String,
    pub rp_name: String,
    /// Registration only.
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub user_name: String,
    /// Credentials the account already has (excluded when registering,
    /// allowed when stepping up; empty at login: any passkey of this site).
    #[serde(default)]
    pub credentials: Vec<String>,
}

/// The browser's answer, as the page posts it (all base64url).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Answer {
    pub id: String,
    pub client_data: String,
    /// Registration.
    #[serde(default)]
    pub attestation: String,
    /// Login.
    #[serde(default)]
    pub authenticator_data: String,
    #[serde(default)]
    pub signature: String,
}

/// Where we are: the RP ID (a domain name) and the origins pages come from.
pub struct Site<'a> {
    pub rp_id: &'a str,
    pub origins: &'a [String],
}

fn check_client_data(raw: &[u8], kind: &str, challenge: &str, site: &Site) -> Result<()> {
    let v: serde_json::Value = serde_json::from_slice(raw).context("clientDataJSON")?;
    if v["type"] != kind {
        bail!("not a {kind} answer");
    }
    let got = v["challenge"].as_str().unwrap_or("");
    if got.trim_end_matches('=') != challenge || challenge.is_empty() {
        bail!("the passkey answered another request; try again");
    }
    let origin = v["origin"].as_str().unwrap_or("");
    if !site.origins.iter().any(|o| o == origin) {
        bail!("the passkey was used on {origin}, not on this hub's address");
    }
    if v["crossOrigin"].as_bool() == Some(true) {
        bail!("cross-origin passkey use");
    }
    Ok(())
}

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const AT: u8 = 0x40;

/// rpIdHash, flags, counter, and the rest.
fn parse_auth_data<'a>(d: &'a [u8], site: &Site) -> Result<(u8, u32, &'a [u8])> {
    if d.len() < 37 {
        bail!("authenticator data too short");
    }
    if d[..32] != Sha256::digest(site.rp_id.as_bytes())[..] {
        bail!("the passkey belongs to another site");
    }
    let flags = d[32];
    if flags & UP == 0 {
        bail!("the authenticator did not see you (no touch)");
    }
    if flags & UV == 0 {
        bail!("the authenticator did not verify you (set a PIN or use a passkey with a fingerprint, face or PIN)");
    }
    let counter = u32::from_be_bytes([d[33], d[34], d[35], d[36]]);
    Ok((flags, counter, &d[37..]))
}

/// Checks a registration answer; returns the new credential.
pub fn register(
    answer: &Answer,
    challenge: &str,
    site: &Site,
    name: &str,
    now: u64,
) -> Result<Passkey> {
    let client = unb64(&answer.client_data)?;
    check_client_data(&client, "webauthn.create", challenge, site)?;
    let att = Cbor::parse(&unb64(&answer.attestation)?)?;
    let auth = att
        .get_text("authData")
        .and_then(Cbor::bytes)
        .context("no authData")?;
    let (flags, counter, rest) = parse_auth_data(auth, site)?;
    if flags & AT == 0 || rest.len() < 18 {
        bail!("no credential in the answer");
    }
    let len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
    let id = rest.get(18..18 + len).context("credential id cut short")?;
    let key_bytes = &rest[18 + len..];
    let (key, used) = Cbor::parse_prefix(key_bytes)?;
    let _check = verifier(&key)?; // a key type we can check
    if b64(id) != answer.id.trim_end_matches('=') {
        bail!("credential id mismatch");
    }
    Ok(Passkey {
        id: b64(id),
        key: b64(&key_bytes[..used]),
        counter,
        name: name.to_string(),
        added: now,
    })
}

/// Checks a login or step-up answer against `pk`; returns the new counter.
pub fn verify(answer: &Answer, challenge: &str, site: &Site, pk: &Passkey) -> Result<u32> {
    let client = unb64(&answer.client_data)?;
    check_client_data(&client, "webauthn.get", challenge, site)?;
    let auth = unb64(&answer.authenticator_data)?;
    let (_, counter, _) = parse_auth_data(&auth, site)?;
    let key = Cbor::parse(&unb64(&pk.key)?)?;
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&client));
    verifier(&key)?(&signed, &unb64(&answer.signature)?)?;
    if (counter != 0 || pk.counter != 0) && counter <= pk.counter {
        bail!("this authenticator's counter went back: it may have been cloned");
    }
    Ok(counter)
}

type Check = Box<dyn Fn(&[u8], &[u8]) -> Result<()>>;

/// The signature check for a COSE key.
fn verifier(k: &Cbor) -> Result<Check> {
    let kty = k.get_int(1).and_then(Cbor::int);
    let alg = k.get_int(3).and_then(Cbor::int);
    match (kty, alg) {
        (Some(2), Some(-7)) => {
            let x = k.get_int(-2).and_then(Cbor::bytes).context("no x")?;
            let y = k.get_int(-3).and_then(Cbor::bytes).context("no y")?;
            if x.len() != 32 || y.len() != 32 {
                bail!("bad P-256 key");
            }
            let mut sec1 = vec![4u8];
            sec1.extend_from_slice(x);
            sec1.extend_from_slice(y);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).context("bad P-256 key")?;
            Ok(Box::new(move |msg, sig| {
                use p256::ecdsa::signature::Verifier;
                let sig = p256::ecdsa::Signature::from_der(sig).context("bad signature")?;
                vk.verify(msg, &sig).context("wrong signature")
            }))
        }
        (Some(1), Some(-8)) => {
            let x = k.get_int(-2).and_then(Cbor::bytes).context("no x")?;
            let x: [u8; 32] = x.try_into().ok().context("bad Ed25519 key")?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&x).context("bad Ed25519 key")?;
            Ok(Box::new(move |msg, sig| {
                let sig: [u8; 64] = sig.try_into().ok().context("bad signature")?;
                vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig))
                    .ok()
                    .context("wrong signature")
            }))
        }
        _ => bail!("this kind of key is not supported (only ES256 and Ed25519)"),
    }
}

// ---------------------------------------------------------------- CBOR

/// The part of CBOR that WebAuthn uses.
#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Simple(u8),
}

impl Cbor {
    pub fn parse(b: &[u8]) -> Result<Cbor> {
        let (v, n) = Cbor::parse_prefix(b)?;
        if n != b.len() {
            bail!("trailing bytes after CBOR");
        }
        Ok(v)
    }

    /// One item from the start of `b`, and how many bytes it took.
    pub fn parse_prefix(b: &[u8]) -> Result<(Cbor, usize)> {
        let mut pos = 0;
        let v = item(b, &mut pos, 0)?;
        Ok((v, pos))
    }

    fn get(&self, key: &Cbor) -> Option<&Cbor> {
        match self {
            Cbor::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_int(&self, k: i64) -> Option<&Cbor> {
        self.get(&Cbor::Int(k))
    }

    pub fn get_text(&self, k: &str) -> Option<&Cbor> {
        self.get(&Cbor::Text(k.into()))
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn int(&self) -> Option<i64> {
        match self {
            Cbor::Int(i) => Some(*i),
            _ => None,
        }
    }
}

fn take<'a>(b: &'a [u8], pos: &mut usize, n: usize) -> Result<&'a [u8]> {
    let s = b.get(*pos..*pos + n).context("CBOR cut short")?;
    *pos += n;
    Ok(s)
}

fn item(b: &[u8], pos: &mut usize, depth: u32) -> Result<Cbor> {
    if depth > 16 {
        bail!("CBOR nested too deep");
    }
    let first = take(b, pos, 1)?[0];
    let (major, info) = (first >> 5, first & 0x1f);
    let arg: u64 = match info {
        0..=23 => info as u64,
        24 => take(b, pos, 1)?[0] as u64,
        25 => u16::from_be_bytes(take(b, pos, 2)?.try_into()?) as u64,
        26 => u32::from_be_bytes(take(b, pos, 4)?.try_into()?) as u64,
        27 => u64::from_be_bytes(take(b, pos, 8)?.try_into()?),
        _ => bail!("indefinite or reserved CBOR lengths are not used by WebAuthn"),
    };
    let len = |a: u64| -> Result<usize> {
        let n = usize::try_from(a)?;
        if n > b.len() {
            bail!("CBOR length too large");
        }
        Ok(n)
    };
    Ok(match major {
        0 => Cbor::Int(i64::try_from(arg)?),
        1 => Cbor::Int(-1 - i64::try_from(arg)?),
        2 => Cbor::Bytes(take(b, pos, len(arg)?)?.to_vec()),
        3 => Cbor::Text(String::from_utf8(take(b, pos, len(arg)?)?.to_vec())?),
        4 => {
            let n = len(arg)?;
            let mut v = Vec::new();
            for _ in 0..n {
                v.push(item(b, pos, depth + 1)?);
            }
            Cbor::Array(v)
        }
        5 => {
            let n = len(arg)?;
            let mut v = Vec::new();
            for _ in 0..n {
                let k = item(b, pos, depth + 1)?;
                let x = item(b, pos, depth + 1)?;
                v.push((k, x));
            }
            Cbor::Map(v)
        }
        6 => item(b, pos, depth + 1)?, // a tag: keep the value
        7 if info < 24 => Cbor::Simple(info),
        _ => bail!("CBOR floats are not used by WebAuthn"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};

    // A tiny CBOR writer for building test answers.
    fn head(major: u8, n: u64, out: &mut Vec<u8>) {
        if n < 24 {
            out.push(major << 5 | n as u8);
        } else if n < 256 {
            out.extend([major << 5 | 24, n as u8]);
        } else {
            out.push(major << 5 | 25);
            out.extend((n as u16).to_be_bytes());
        }
    }
    fn enc(v: &Cbor, out: &mut Vec<u8>) {
        match v {
            Cbor::Int(i) if *i >= 0 => head(0, *i as u64, out),
            Cbor::Int(i) => head(1, (-1 - i) as u64, out),
            Cbor::Bytes(b) => {
                head(2, b.len() as u64, out);
                out.extend(b);
            }
            Cbor::Text(t) => {
                head(3, t.len() as u64, out);
                out.extend(t.as_bytes());
            }
            Cbor::Array(a) => {
                head(4, a.len() as u64, out);
                a.iter().for_each(|x| enc(x, out));
            }
            Cbor::Map(m) => {
                head(5, m.len() as u64, out);
                for (k, x) in m {
                    enc(k, out);
                    enc(x, out);
                }
            }
            Cbor::Simple(s) => out.push(7 << 5 | s),
        }
    }

    const RP: &str = "blackthorn.example.com";
    fn site() -> (String, Vec<String>) {
        (RP.into(), vec![format!("https://{RP}:7180")])
    }
    fn client(kind: &str, challenge: &str, origin: &str) -> String {
        b64(
            serde_json::json!({"type": kind, "challenge": challenge, "origin": origin})
                .to_string()
                .as_bytes(),
        )
    }
    fn auth_data(flags: u8, counter: u32, rp: &str) -> Vec<u8> {
        let mut d = Sha256::digest(rp.as_bytes()).to_vec();
        d.push(flags);
        d.extend(counter.to_be_bytes());
        d
    }

    fn registration(sk: &SigningKey, challenge: &str, flags: u8) -> Answer {
        let pt = sk.verifying_key().to_encoded_point(false);
        let cose = Cbor::Map(vec![
            (Cbor::Int(1), Cbor::Int(2)),
            (Cbor::Int(3), Cbor::Int(-7)),
            (Cbor::Int(-1), Cbor::Int(1)),
            (Cbor::Int(-2), Cbor::Bytes(pt.x().unwrap().to_vec())),
            (Cbor::Int(-3), Cbor::Bytes(pt.y().unwrap().to_vec())),
        ]);
        let cred = [7u8; 16];
        let mut ad = auth_data(flags, 0, RP);
        ad.extend([0u8; 16]);
        ad.extend((cred.len() as u16).to_be_bytes());
        ad.extend(cred);
        enc(&cose, &mut ad);
        let mut att = Vec::new();
        enc(
            &Cbor::Map(vec![
                (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
                (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
                (Cbor::Text("authData".into()), Cbor::Bytes(ad)),
            ]),
            &mut att,
        );
        Answer {
            id: b64(&cred),
            client_data: client("webauthn.create", challenge, &format!("https://{RP}:7180")),
            attestation: b64(&att),
            ..Answer::default()
        }
    }

    fn login(sk: &SigningKey, challenge: &str, counter: u32, origin: &str) -> Answer {
        let ad = auth_data(UP | UV, counter, RP);
        let cd = client("webauthn.get", challenge, origin);
        let mut signed = ad.clone();
        signed.extend(Sha256::digest(unb64(&cd).unwrap()));
        let sig: p256::ecdsa::Signature = sk.sign(&signed);
        Answer {
            id: b64(&[7u8; 16]),
            client_data: cd,
            authenticator_data: b64(&ad),
            signature: b64(sig.to_der().as_bytes()),
            ..Answer::default()
        }
    }

    #[test]
    fn registers_then_logs_in_with_p256() {
        let (rp, origins) = site();
        let s = Site {
            rp_id: &rp,
            origins: &origins,
        };
        let sk = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let pk = register(
            &registration(&sk, "abc", UP | UV | AT),
            "abc",
            &s,
            "phone",
            1,
        )
        .unwrap();
        assert_eq!(pk.id, b64(&[7u8; 16]));
        assert!(
            register(&registration(&sk, "abc", UP | UV | AT), "xyz", &s, "x", 1).is_err(),
            "challenge"
        );
        assert!(
            register(&registration(&sk, "abc", UP | AT), "abc", &s, "x", 1).is_err(),
            "no UV"
        );

        let origin = &origins[0];
        assert_eq!(
            verify(&login(&sk, "c1", 5, origin), "c1", &s, &pk).unwrap(),
            5
        );
        assert!(
            verify(&login(&sk, "c1", 5, origin), "c2", &s, &pk).is_err(),
            "other challenge"
        );
        assert!(
            verify(&login(&sk, "c1", 5, "https://evil.example"), "c1", &s, &pk).is_err(),
            "origin"
        );
        let other = SigningKey::from_slice(&[0x43; 32]).unwrap();
        assert!(
            verify(&login(&other, "c1", 5, origin), "c1", &s, &pk).is_err(),
            "wrong key"
        );
        let mut used = pk.clone();
        used.counter = 9;
        assert!(
            verify(&login(&sk, "c1", 5, origin), "c1", &s, &used).is_err(),
            "counter back"
        );
        let other_site = Site {
            rp_id: "other.example.com",
            origins: &origins,
        };
        assert!(
            verify(&login(&sk, "c1", 5, origin), "c1", &other_site, &pk).is_err(),
            "rp id"
        );
    }

    #[test]
    fn cbor_limits() {
        assert!(Cbor::parse(&[0x5f]).is_err(), "indefinite");
        assert!(
            Cbor::parse(&[0x5a, 0xff, 0xff, 0xff, 0xff]).is_err(),
            "huge length"
        );
        assert!(Cbor::parse(&[0x81; 40]).is_err(), "too deep");
        assert_eq!(Cbor::parse(&[0x20]).unwrap(), Cbor::Int(-1));
        assert!(Cbor::parse(&[0x01, 0x02]).is_err(), "trailing");
    }
}
