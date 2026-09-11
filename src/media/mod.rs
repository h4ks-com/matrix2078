//! Tiny local HTTP server for cached media files.
//!
//! Serves `GET /<file>?s=<hmac>` from the media cache dir.
//!
//! Hardening (the server may be reachable from beyond loopback, e.g. for
//! voidbar on another host):
//! - URLs are signed with an install-wide secret (imagor-style, no expiry);
//! - the `Host` header must match the configured listen address (kills DNS
//!   rebinding);
//! - responses force `CSP: sandbox` + `nosniff` and `Content-Disposition`
//!   so cached HTML/SVG can't execute in this origin.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

type HmacSha256 = Hmac<Sha256>;

pub struct MediaServer {
    listen: SocketAddr,
    /// Base URL used in generated links (`http://<listen>` unless a public
    /// URL is configured — containers sit behind port mappings).
    url_base: String,
    /// `host[:port]` the Host header must match (authority of `url_base`).
    expected_host: String,
    dir: PathBuf,
    key: Vec<u8>,
}

impl MediaServer {
    pub fn new(listen: SocketAddr, dir: PathBuf, public_url: Option<String>) -> Self {
        let key = load_or_create_secret(&dir);
        let url_base = public_url
            .map(|u| u.trim_end_matches('/').to_owned())
            .unwrap_or_else(|| format!("http://{listen}"));
        let expected_host = url_base
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        Self { listen, url_base, expected_host, dir, key }
    }

    /// A signed URL for a cached file (no expiry: links live in IRC backlogs).
    pub fn url_for(&self, file_name: &str) -> String {
        format!("{}/{}?s={}", self.url_base, file_name, self.sign(file_name))
    }

    fn sign(&self, file_name: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("hmac key");
        mac.update(file_name.as_bytes());
        let tag = mac.finalize().into_bytes();
        hex(&tag[..16])
    }

    fn verify(&self, file_name: &str, sig: &str) -> bool {
        constant_time_eq(self.sign(file_name).as_bytes(), sig.as_bytes())
    }

    pub async fn run(self: Arc<Self>) -> Result<()> {
        let listener = TcpListener::bind(self.listen)
            .await
            .with_context(|| format!("binding media server on {}", self.listen))?;
        tracing::info!(listen = %self.listen, dir = %self.dir.display(), "media server listening");
        self.run_on(listener).await;
        Ok(())
    }

    pub async fn run_on(self: Arc<Self>, listener: TcpListener) {
        loop {
            let Ok((stream, _)) = listener.accept().await else { return };
            let srv = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = srv.serve(stream).await {
                    tracing::debug!(error = %e, "media connection error");
                }
            });
        }
    }

    async fn serve(&self, mut stream: TcpStream) -> Result<()> {
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 512];
        // read request head only
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");

        // Host must match the public URL authority (or the listen address):
        // blocks DNS rebinding and foreign-origin access when listening
        // beyond loopback.
        let host = lines
            .find_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned())))
            .filter(|(k, _)| k == "host")
            .map(|(_, v)| v);
        let host_ok = match host.as_deref() {
            Some(h) => h.eq_ignore_ascii_case(&self.expected_host),
            None => false,
        };
        if !host_ok {
            self.respond(&mut stream, 403, "Forbidden", b"text/plain", b"bad host\r\n", None)
                .await?;
            return Ok(());
        }

        if method != "GET" {
            self.respond(&mut stream, 405, "Method Not Allowed", b"text/plain", b"GET only\r\n", None)
                .await?;
            return Ok(());
        }

        let (path_part, query) = target.split_once('?').unwrap_or((target, ""));
        let name = path_part.trim_start_matches('/');
        if name.is_empty()
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            || name.contains("..")
        {
            self.respond(&mut stream, 404, "Not Found", b"text/plain", b"nope\r\n", None).await?;
            return Ok(());
        }

        // signature: ?s=<hex>
        let mut sig: Option<String> = None;
        for kv in query.split('&').filter(|s| !s.is_empty()) {
            if let Some((k, v)) = kv.split_once('=') {
                if k == "s" {
                    sig = Some(v.to_owned());
                }
            }
        }
        match sig {
            Some(s) if self.verify(name, &s) => {}
            _ => {
                self.respond(&mut stream, 403, "Forbidden", b"text/plain", b"bad signature\r\n", None)
                    .await?;
                return Ok(());
            }
        }

        let path = self.dir.join(name);
        match tokio::fs::read(&path).await {
            Ok(body) => {
                let ctype = content_type(&path).to_owned();
                self.respond(&mut stream, 200, "OK", ctype.as_bytes(), &body, Some(name)).await?;
            }
            Err(_) => {
                self.respond(&mut stream, 404, "Not Found", b"text/plain", b"nope\r\n", None).await?;
            }
        }
        Ok(())
    }

    async fn respond(
        &self,
        stream: &mut TcpStream,
        code: u16,
        reason: &str,
        ctype: &[u8],
        body: &[u8],
        filename: Option<&str>,
    ) -> Result<()> {
        let disposition = match filename {
            Some(f) => {
                let safe: String = f.chars().filter(|c| !c.is_control() && *c != '"' && *c != '\\').collect();
                if is_inline(&ctype) {
                    format!("inline; filename=\"{safe}\"")
                } else {
                    format!("attachment; filename=\"{safe}\"")
                }
            }
            None => String::new(),
        };
        let mut head = format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; sandbox\r\nReferrer-Policy: no-referrer\r\nCache-Control: private, max-age=86400\r\n",
            String::from_utf8_lossy(ctype),
            body.len()
        );
        if !disposition.is_empty() {
            head.push_str(&format!("Content-Disposition: {disposition}\r\n"));
        }
        head.push_str("Connection: close\r\n\r\n");
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await?;
        Ok(())
    }
}

/// Load the install-wide HMAC secret, creating it on first start.
fn load_or_create_secret(dir: &Path) -> Vec<u8> {
    let path = dir.join(".media-secret");
    if let Ok(hexkey) = std::fs::read_to_string(&path) {
        if let Ok(key) = unhex(hexkey.trim()) {
            if key.len() == 32 {
                return key;
            }
        }
        tracing::warn!("regenerating invalid media secret");
    }
    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    let _ = std::fs::create_dir_all(dir);
    if let Err(e) = std::fs::write(&path, hex(&key)) {
        tracing::warn!(error = %e, "could not persist media secret; URLs die on restart");
    }
    key
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ()))
        .collect()
}

fn is_inline(ctype: &[u8]) -> bool {
    matches!(ctype, b"image/png" | b"image/jpeg" | b"image/gif" | b"image/webp" | b"image/avif" | b"video/mp4" | b"video/webm" | b"audio/ogg" | b"audio/mpeg" | b"text/plain; charset=utf-8")
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase().as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ogg" => "audio/ogg",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn http_get(addr: SocketAddr, target: &str, host: Option<&str>) -> String {
        use std::time::Duration;
        let mut s = TcpStream::connect(addr).await.unwrap();
        let host = host.map(|h| h.to_owned()).unwrap_or_else(|| addr.to_string());
        s.write_all(
            format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn signed_urls_serve_and_everything_else_fails() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x.png"), b"fakepng").unwrap();
        std::fs::write(dir.path().join("evil.html"), b"<script>bad()</script>").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = Arc::new(MediaServer::new(addr, dir.path().to_path_buf(), None));
        tokio::spawn(Arc::clone(&srv).run_on(listener));

        // valid signed url
        let url = srv.url_for("x.png");
        let target = url.split_once(&addr.to_string()).unwrap().1.to_owned();
        let resp = http_get(addr, &target, None).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(resp.contains("Content-Type: image/png"));
        assert!(resp.contains("Content-Disposition: inline"));
        assert!(resp.contains("X-Content-Type-Options: nosniff"));
        assert!(resp.contains("sandbox"));
        assert!(resp.ends_with("fakepng"));

        // no signature
        let resp = http_get(addr, "/x.png", None).await;
        assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");

        // tampered signature
        let resp = http_get(addr, &format!("{target}X"), None).await;
        assert!(resp.starts_with("HTTP/1.1 403"));

        // signature for another file (rewrapped onto a different name)
        let sig = srv.sign("x.png");
        let resp = http_get(addr, &format!("/evil.html?s={sig}"), None).await;
        assert!(resp.starts_with("HTTP/1.1 403"));

        // wrong host (dns rebinding)
        let resp = http_get(addr, &target, Some("evil.example")).await;
        assert!(resp.starts_with("HTTP/1.1 403"));

        // html is never rendered inline
        let target = srv.url_for("evil.html").split_once(&addr.to_string()).unwrap().1.to_owned();
        let resp = http_get(addr, &target, None).await;
        assert!(resp.starts_with("HTTP/1.1 200"));
        assert!(resp.contains("Content-Disposition: attachment"));

        // traversal
        let resp = http_get(addr, "/../secret", None).await;
        assert!(resp.starts_with("HTTP/1.1 404"));

        // unknown file
        let resp = http_get(addr, "/nope.png", None).await;
        assert!(resp.starts_with("HTTP/1.1 403"));
    }

    #[tokio::test]
    async fn public_url_overrides_links_and_host_check() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("y.png"), b"png").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = Arc::new(MediaServer::new(
            addr,
            dir.path().to_path_buf(),
            Some("http://media.example.com:8443/".to_owned()),
        ));
        tokio::spawn(Arc::clone(&srv).run_on(listener));

        let url = srv.url_for("y.png");
        assert!(url.starts_with("http://media.example.com:8443/y.png?s="), "{url}");
        let target = format!("/y.png?s={}", srv.sign("y.png"));
        // Host matching the public authority passes …
        let resp = http_get(addr, &target, Some("media.example.com:8443")).await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        // … while the raw bind address no longer does.
        let resp = http_get(addr, &target, None).await;
        assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0u8, 1, 2, 255, 128];
        assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
    }
}
