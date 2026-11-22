//! Password protection for exports. Argon2id makes a key from the password
//! and a random salt; ChaCha20-Poly1305 seals the file in 64 KiB pieces,
//! each numbered and the last one marked, so a wrong password, or a piece
//! changed, moved, dropped or cut off, is found before anything is used.
//!
//! The file: MAGIC, the Argon2 memory (KiB), passes and lanes (u32, little
//! endian), the salt, then the sealed pieces.

use anyhow::{anyhow, bail, Context, Result};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;

pub const MAGIC: &[u8] = b"blackthorn-sealed-1\n";
const PIECE: usize = 64 * 1024;
const TAG: usize = 16;
const SALT: usize = 16;
// Tests run unoptimised: a light key there.
const MEMORY_KIB: u32 = if cfg!(test) { 256 } else { 64 * 1024 };
const PASSES: u32 = 3;
const LANES: u32 = 1;
/// The shortest password taken for a new file.
pub const MIN_PASSWORD: usize = 8;

fn key(password: &str, memory: u32, passes: u32, lanes: u32, salt: &[u8]) -> Result<LessSafeKey> {
    // A file asking for far more work than blackthorn makes is not ours.
    if memory > 1024 * 1024 || passes > 16 || lanes > 16 {
        bail!("this file asks for more work than blackthorn ever does: not a blackthorn export");
    }
    let params =
        argon2::Params::new(memory, passes, lanes, Some(32)).map_err(|e| anyhow!("{e}"))?;
    let mut k = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut k)
        .map_err(|e| anyhow!("{e}"))?;
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &k).map_err(|_| anyhow!("bad key"))?;
    Ok(LessSafeKey::new(unbound))
}

/// Each piece's number, and whether it is the last. A key is used for one
/// file only (its salt is new), so numbers never repeat under a key.
fn nonce(n: u64, last: bool) -> Nonce {
    let mut b = [0u8; 12];
    b[3..11].copy_from_slice(&n.to_be_bytes());
    b[11] = u8::from(last);
    Nonce::assume_unique_for_key(b)
}

/// Whether a file starts like a sealed one.
pub fn is_sealed(path: &Path) -> Result<bool> {
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut head = vec![0u8; MAGIC.len()];
    let mut got = 0;
    while got < head.len() {
        match f.read(&mut head[got..])? {
            0 => break,
            n => got += n,
        }
    }
    Ok(got == head.len() && head == MAGIC)
}

/// Seals what is written to it. `finish` writes the last piece.
pub struct Sealer<W: Write> {
    out: W,
    key: LessSafeKey,
    header: Vec<u8>,
    buf: Vec<u8>,
    n: u64,
}

impl<W: Write> Sealer<W> {
    pub fn new(mut out: W, password: &str) -> Result<Self> {
        let salt: [u8; SALT] = crate::webauth::random_bytes();
        let mut header = MAGIC.to_vec();
        for v in [MEMORY_KIB, PASSES, LANES] {
            header.extend(v.to_le_bytes());
        }
        header.extend(salt);
        out.write_all(&header)?;
        Ok(Sealer {
            out,
            key: key(password, MEMORY_KIB, PASSES, LANES, &salt)?,
            header,
            buf: Vec::with_capacity(PIECE + TAG),
            n: 0,
        })
    }

    fn seal(&mut self, last: bool) -> io::Result<()> {
        let mut piece = std::mem::replace(&mut self.buf, Vec::with_capacity(PIECE + TAG));
        self.key
            .seal_in_place_append_tag(nonce(self.n, last), Aad::from(&self.header), &mut piece)
            .map_err(|_| io::Error::other("sealing failed"))?;
        self.out.write_all(&piece)?;
        self.n += 1;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.seal(true)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for Sealer<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut rest = data;
        while !rest.is_empty() {
            // A full piece is sealed only once more follows, so the last
            // piece is always the one `finish` seals.
            if self.buf.len() == PIECE {
                self.seal(false)?;
            }
            let take = (PIECE - self.buf.len()).min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads what a Sealer wrote, checking every piece.
pub struct Opener<R: Read> {
    inp: BufReader<R>,
    key: LessSafeKey,
    header: Vec<u8>,
    plain: Vec<u8>,
    pos: usize,
    n: u64,
    done: bool,
}

const WRONG: &str = "wrong password, or the file is damaged";

impl<R: Read> Opener<R> {
    /// Fails at once on a wrong password.
    pub fn new(inp: R, password: &str) -> Result<Self> {
        let mut inp = BufReader::with_capacity(PIECE + TAG + 1, inp);
        let mut header = vec![0u8; MAGIC.len() + 12 + SALT];
        inp.read_exact(&mut header)
            .context("not a password-protected blackthorn export")?;
        if &header[..MAGIC.len()] != MAGIC {
            bail!("not a password-protected blackthorn export");
        }
        let u = |i: usize| {
            let at = MAGIC.len() + 4 * i;
            u32::from_le_bytes(header[at..at + 4].try_into().expect("4 bytes"))
        };
        let key = key(password, u(0), u(1), u(2), &header[MAGIC.len() + 12..])?;
        let mut o = Opener {
            inp,
            key,
            header,
            plain: Vec::new(),
            pos: 0,
            n: 0,
            done: false,
        };
        o.next_piece().map_err(|e| anyhow!("{e}"))?;
        Ok(o)
    }

    fn next_piece(&mut self) -> io::Result<()> {
        let mut piece = vec![0u8; PIECE + TAG];
        let mut got = 0;
        while got < piece.len() {
            match self.inp.read(&mut piece[got..])? {
                0 => break,
                n => got += n,
            }
        }
        piece.truncate(got);
        let last = got < PIECE + TAG || self.inp.fill_buf()?.is_empty();
        if got < TAG {
            return Err(io::Error::new(io::ErrorKind::InvalidData, WRONG));
        }
        let len = self
            .key
            .open_in_place(nonce(self.n, last), Aad::from(&self.header), &mut piece)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, WRONG))?
            .len();
        piece.truncate(len);
        self.plain = piece;
        self.pos = 0;
        self.n += 1;
        self.done = last;
        Ok(())
    }
}

impl<R: Read> Read for Opener<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.plain.len() {
            if self.done {
                return Ok(0);
            }
            self.next_piece()?;
        }
        let n = (self.plain.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// A password from the terminal, not shown as it is typed; without a
/// terminal, one line of standard input (for scripts).
pub fn read_password(prompt: &str) -> Result<String> {
    use std::io::IsTerminal;
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        let mut line = String::new();
        stdin.lock().read_line(&mut line)?;
        return Ok(line.trim_end_matches(['\n', '\r']).to_string());
    }
    eprint!("{prompt}");
    io::stderr().flush()?;
    // SAFETY: termios is plain data, filled in by tcgetattr on stdin.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut t) } != 0 {
        bail!("cannot read the terminal's settings");
    }
    let old = t;
    t.c_lflag &= !libc::ECHO;
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };
    let mut line = String::new();
    let r = stdin.lock().read_line(&mut line);
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &old) };
    eprintln!();
    r?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Asks a yes/no question on the terminal; `default` on an empty answer.
pub fn ask_yes(prompt: &str, default: bool) -> Result<bool> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(match line.trim().to_ascii_lowercase().as_str() {
        "" => default,
        a => a.starts_with('y'),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seal(data: &[u8], pw: &str) -> Vec<u8> {
        let mut s = Sealer::new(Vec::new(), pw).unwrap();
        // In odd-sized writes, across piece boundaries.
        for c in data.chunks(7000) {
            s.write_all(c).unwrap();
        }
        s.finish().unwrap()
    }

    fn open(file: &[u8], pw: &str) -> Result<Vec<u8>> {
        let mut o = Opener::new(file, pw)?;
        let mut out = Vec::new();
        o.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn round_trips_any_length() {
        for len in [0, 1, PIECE - 1, PIECE, PIECE + 1, 2 * PIECE, 3 * PIECE + 17] {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            let f = seal(&data, "correct horse");
            assert!(f.starts_with(MAGIC));
            assert_eq!(open(&f, "correct horse").unwrap(), data, "length {len}");
        }
    }

    #[test]
    fn finds_a_wrong_password_and_damage() {
        let data = vec![7u8; 2 * PIECE + 5];
        let f = seal(&data, "correct horse");
        let e = open(&f, "wrong horse").unwrap_err().to_string();
        assert!(e.contains("wrong password"), "{e}");
        // A byte changed late in the file.
        let mut bad = f.clone();
        let at = bad.len() - 3;
        bad[at] ^= 1;
        assert!(open(&bad, "correct horse").is_err());
        // Cut off after a whole piece: that piece was not the last.
        let header = MAGIC.len() + 12 + SALT;
        let cut = &f[..header + PIECE + TAG];
        assert!(open(cut, "correct horse").is_err());
        // The last piece dropped... and the header changed.
        let mut hdr = f.clone();
        hdr[MAGIC.len() + 12] ^= 1;
        assert!(open(&hdr, "correct horse").is_err());
        assert!(open(&f[..header], "correct horse").is_err());
    }
}
