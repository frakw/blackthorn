//! A deliberately small HTTP/1.1 server for the web UI: one request per
//! connection (`Connection: close`), no chunked bodies, hard limits on
//! sizes, time and concurrency. Nothing a client sends can take the
//! listener down: every connection is handled on its own thread and every
//! error just closes that connection. With a certificate it speaks only
//! HTTPS (rustls), and the certificate can be swapped while it runs.

use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

const MAX_HEAD: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_BODY: usize = 64 * 1024;
/// A file for a chat (base64, in a form) may be this big.
const MAX_UPLOAD_BODY: usize = 16 << 20;
const MAX_CONNECTIONS: usize = 64;
const TIMEOUT: Duration = Duration::from_secs(15);

pub struct Request {
    pub method: String,
    /// Path and query, as sent.
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub remote: IpAddr,
    /// Came over HTTPS.
    pub secure: bool,
}

/// The TLS settings in use, replaced when the certificate is renewed.
pub type Tls = Arc<RwLock<Arc<rustls::ServerConfig>>>;

/// A rustls server configuration from PEM text.
pub fn tls_config(cert_pem: &str, key_pem: &str) -> Result<Arc<rustls::ServerConfig>> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<std::result::Result<_, _>>()
        .context("reading the certificate")?;
    if certs.is_empty() {
        bail!("no certificate in the certificate file");
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .context("reading the key")?
        .context("no private key in the key file")?;
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("the certificate and key do not go together")?;
    Ok(Arc::new(cfg))
}

impl Request {
    pub fn header<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Serves forever on `addr`, calling `handler` for each request.
pub fn serve<F>(addr: SocketAddr, tls: Option<Tls>, handler: F) -> Result<()>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    let listener = TcpListener::bind(addr).with_context(|| format!("cannot listen on {addr}"))?;
    let handler = Arc::new(handler);
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            // Out of file descriptors or similar: do not spin.
            std::thread::sleep(Duration::from_millis(50));
            continue;
        };
        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            continue; // dropped: closes the connection
        }
        active.fetch_add(1, Ordering::SeqCst);
        let handler = handler.clone();
        let active = active.clone();
        let tls = tls.as_ref().map(|t| t.read().expect("tls lock").clone());
        std::thread::spawn(move || {
            if let Err(e) = connection(stream, tls, &*handler) {
                eprintln!("web: connection: {e:#}");
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

fn connection<F: Fn(Request) -> Response>(
    stream: TcpStream,
    tls: Option<Arc<rustls::ServerConfig>>,
    handler: &F,
) -> Result<()> {
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let remote = stream.peer_addr()?.ip();
    match tls {
        None => exchange(stream, remote, false, handler),
        Some(cfg) => {
            let conn = rustls::ServerConnection::new(cfg)?;
            let mut s = rustls::StreamOwned::new(conn, stream);
            exchange(&mut s, remote, true, handler)?;
            s.conn.send_close_notify();
            let _ = s.flush();
            Ok(())
        }
    }
}

/// One request and its response over `stream`.
fn exchange<S: Read + Write, F: Fn(Request) -> Response>(
    mut stream: S,
    remote: IpAddr,
    secure: bool,
    handler: &F,
) -> Result<()> {
    let req = read_request(BufReader::new(&mut stream), remote).map(|mut r| {
        r.secure = secure;
        r
    });
    let mut out = stream;
    let resp = match req {
        Ok(req) => {
            let head = req.method == "HEAD";
            let mut r = handler(req);
            if head {
                r.body.clear();
            }
            r
        }
        Err(e) => Response {
            status: 400,
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: format!("bad request: {e}\n").into_bytes(),
        },
    };
    write_response(&mut out, &resp)?;
    out.flush()?;
    Ok(())
}

pub fn read_request<R: Read>(r: BufReader<R>, remote: IpAddr) -> Result<Request> {
    let mut r = r.take((MAX_HEAD + MAX_UPLOAD_BODY) as u64);
    let mut head_len = 0;
    let mut line = String::new();
    let mut next_line = |r: &mut std::io::Take<BufReader<R>>, line: &mut String| -> Result<()> {
        line.clear();
        let n = r.read_line(line)?;
        head_len += n;
        if n == 0 {
            bail!("connection closed");
        }
        if head_len > MAX_HEAD {
            bail!("request head too large");
        }
        Ok(())
    };
    next_line(&mut r, &mut line)?;
    let mut parts = line.trim_end().split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("malformed request line");
    };
    if !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        bail!("unsupported request");
    }
    let (method, target) = (method.to_string(), target.to_string());
    let mut headers = Vec::new();
    loop {
        next_line(&mut r, &mut line)?;
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        let Some((k, v)) = l.split_once(':') else {
            bail!("malformed header");
        };
        headers.push((k.trim().to_string(), v.trim().to_string()));
        if headers.len() > MAX_HEADERS {
            bail!("too many headers");
        }
    }
    let te = headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"));
    if te {
        bail!("chunked bodies are not supported");
    }
    let len: usize = match headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
    {
        Some((_, v)) => v.parse().context("bad content-length")?,
        None => 0,
    };
    let max = if target
        .split('?')
        .next()
        .unwrap_or("")
        .ends_with("/chat-upload")
    {
        MAX_UPLOAD_BODY
    } else {
        MAX_BODY
    };
    if len > max {
        bail!("body too large");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Request {
        method,
        target,
        headers,
        body: String::from_utf8(body).context("body is not UTF-8")?,
        remote,
        secure: false,
    })
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "",
    }
}

pub fn write_response<W: Write>(w: &mut W, r: &Response) -> Result<()> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", r.status, reason(r.status));
    for (k, v) in &r.headers {
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            bail!("header with a line break");
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        r.body.len()
    ));
    w.write_all(head.as_bytes())?;
    w.write_all(&r.body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Result<Request> {
        read_request(BufReader::new(raw.as_bytes()), "127.0.0.1".parse().unwrap())
    }

    #[test]
    fn parses_a_form_post() {
        let r = parse(
            "POST /login?x=1 HTTP/1.1\r\nHost: hub\r\nCookie: a=b\r\nContent-Length: 7\r\n\r\nuser=me",
        )
        .unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.target, "/login?x=1");
        assert_eq!(r.body, "user=me");
        assert_eq!(r.header("cookie").next(), Some("a=b"));
    }

    #[test]
    fn refuses_what_it_does_not_handle() {
        assert!(parse("GET http://x/ HTTP/1.1\r\n\r\n").is_err());
        assert!(parse("GET / HTTP/2\r\n\r\n").is_err());
        assert!(parse("GET /\r\n\r\n").is_err());
        assert!(parse("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
        assert!(parse("POST / HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n").is_err());
        assert!(parse("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort").is_err());
        let huge = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEAD));
        assert!(parse(&huge).is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn writes_a_response() {
        let mut out = Vec::new();
        write_response(
            &mut out,
            &Response {
                status: 303,
                headers: vec![("Location".into(), "/".into())],
                body: vec![],
            },
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 303 See Other\r\nLocation: /\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let bad = Response {
            status: 200,
            headers: vec![("X".into(), "a\r\nSet-Cookie: x".into())],
            body: vec![],
        };
        assert!(write_response(&mut Vec::new(), &bad).is_err());
    }
}
