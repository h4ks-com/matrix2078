//! Tiny local HTTP server for cached media files.
//!
//! Serves `GET /<file>` from the media cache dir. Deliberately
//! dependency-free: loopback-only, no ranges, no keep-alive.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub struct MediaServer {
    listen: SocketAddr,
    dir: PathBuf,
}

impl MediaServer {
    pub fn new(listen: SocketAddr, dir: PathBuf) -> Self {
        Self { listen, dir }
    }

    pub fn url_for(&self, file_name: &str) -> String {
        format!("http://{}/{}", self.listen, file_name)
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
        let mut parts = head.split_whitespace();
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");

        if method != "GET" {
            self.respond(&mut stream, 405, "Method Not Allowed", b"text/plain", b"GET only\r\n")
                .await?;
            return Ok(());
        }
        // strip query string, reject traversal
        let name = target.split('?').next().unwrap_or("").trim_start_matches('/');
        if name.is_empty()
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            || name.contains("..")
        {
            self.respond(&mut stream, 404, "Not Found", b"text/plain", b"nope\r\n").await?;
            return Ok(());
        }
        let path = self.dir.join(name);
        match tokio::fs::read(&path).await {
            Ok(body) => {
                let ctype = content_type(&path).to_owned();
                self.respond(&mut stream, 200, "OK", ctype.as_bytes(), &body).await?;
            }
            Err(_) => {
                self.respond(&mut stream, 404, "Not Found", b"text/plain", b"nope\r\n").await?;
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
    ) -> Result<()> {
        let head = format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            String::from_utf8_lossy(ctype),
            body.len()
        );
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;
        stream.flush().await?;
        Ok(())
    }
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase().as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "svg" => "image/svg+xml",
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

    #[tokio::test]
    async fn serves_and_404s() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x.png"), b"fakepng").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = Arc::new(MediaServer::new(addr, dir.path().to_path_buf()));
        tokio::spawn(srv.run_on(listener));

        let resp = http_get(addr, "/x.png").await;
        assert!(resp.starts_with("HTTP/1.1 200"));
        assert!(resp.contains("Content-Type: image/png"));
        assert!(resp.ends_with("fakepng"));

        let resp = http_get(addr, "/../etc").await;
        assert!(resp.starts_with("HTTP/1.1 404"));

        let resp = http_get(addr, "/nope.png").await;
        assert!(resp.starts_with("HTTP/1.1 404"));
    }

    async fn http_get(addr: SocketAddr, target: &str) -> String {
        use std::time::Duration;
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf).await;
        String::from_utf8_lossy(&buf).into_owned()
    }
}
