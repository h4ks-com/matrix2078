//! Authenticated media download + on-disk cache.
//!
//! Never hands raw `mxc://` or `/_matrix/media` URLs to IRC clients: files
//! are fetched with the user's access token (decrypted automatically in
//! encrypted rooms by matrix-sdk) and served from the local cache over the
//! built-in HTTP server.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use matrix_sdk::{
    Client,
    media::{MediaFormat, MediaRequestParameters},
    ruma::{OwnedMxcUri, events::room::MediaSource},
};

/// Global media cache dir (shared by all users): `state_dir/media`.
pub fn cache_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("media")
}

/// Fetch `source` into the cache and return the cached file path.
/// Returns the existing file immediately if already cached.
pub async fn fetch_to_cache(
    client: &Client,
    dir: &Path,
    source: &MediaSource,
    mime_hint: Option<&str>,
) -> Result<PathBuf> {
    let uri: OwnedMxcUri = match source {
        MediaSource::Plain(uri) => uri.clone(),
        MediaSource::Encrypted(file) => (&file.url).clone(),
    };
    let file_name = cache_file_name(&uri, mime_hint);
    let path = dir.join(&file_name);
    if path.exists() {
        return Ok(path);
    }
    let content = client
        .media()
        .get_media_content(
            &MediaRequestParameters { source: source.clone(), format: MediaFormat::File },
            false,
        )
        .await
        .context("downloading media")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(".{file_name}.part"));
    fs::write(&tmp, &content).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("storing {}", path.display()))?;
    tracing::debug!(mxc = %uri, bytes = content.len(), "media cached");
    Ok(path)
}

/// Stable cache file name for an mxc URI: `<server>_<media-id>.<ext>`.
fn cache_file_name(uri: &matrix_sdk::ruma::MxcUri, mime_hint: Option<&str>) -> String {
    let (server, id) = match uri.parts() {
        Ok(parts) => parts,
        Err(e) => {
            return format!("broken_{e}.bin");
        }
    };
    let server = sanitize(server.as_str());
    let id = sanitize(id);
    let ext = mime_hint
        .and_then(|m| mime_extension(m))
        .unwrap_or_else(|| "bin".to_owned());
    format!("{server}_{id}.{ext}")
}

/// Extensions a cached avatar may live under (the type is sniffed from the
/// bytes on first download, so it is not known before fetching).
const AVATAR_EXTS: &[&str] = &["png", "jpg", "gif", "webp", "avif", "bin"];

/// Fetch a user avatar into the cache and return the cached file name.
///
/// Avatars are plain (unencrypted) media whose content type is not known up
/// front: the image type is sniffed from magic bytes. Existing cache entries
/// are returned immediately.
pub async fn fetch_avatar_to_cache(
    client: &Client,
    dir: &Path,
    uri: &matrix_sdk::ruma::MxcUri,
) -> Result<String> {
    let (server, id) = uri.parts().context("parsing avatar mxc")?;
    let base = format!("{}_{}", sanitize(server.as_str()), sanitize(id));
    for ext in AVATAR_EXTS {
        let name = format!("{base}.{ext}");
        if dir.join(&name).exists() {
            return Ok(name);
        }
    }
    let content = client
        .media()
        .get_media_content(
            &MediaRequestParameters {
                source: MediaSource::Plain(uri.to_owned()),
                format: MediaFormat::File,
            },
            false,
        )
        .await
        .context("downloading avatar")?;
    let file_name = format!("{base}.{}", sniff_image_ext(&content).unwrap_or("bin"));
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = dir.join(format!(".{file_name}.part"));
    fs::write(&tmp, &content).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, dir.join(&file_name))
        .with_context(|| format!("storing {}", file_name))?;
    tracing::debug!(mxc = %uri, bytes = content.len(), "avatar cached");
    Ok(file_name)
}

/// Image type from magic bytes.
fn sniff_image_ext(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0x89, b'P', b'N', b'G']) {
        return Some("png");
    }
    if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("jpg");
    }
    if b.starts_with(b"GIF8") {
        return Some("gif");
    }
    if b.len() >= 12 && b.starts_with(b"RIFF") && &b[8..12] == b"WEBP" {
        return Some("webp");
    }
    if b.len() >= 12 && &b[4..8] == b"ftyp" && matches!(&b[8..12], b"avif" | b"avis") {
        return Some("avif");
    }
    None
}

fn sanitize(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect()
}

fn mime_extension(mime: &str) -> Option<String> {
    let base = mime.split(';').next()?.trim().to_ascii_lowercase();
    let ext = match base.as_str() {
        "image/png" => "png",
        "image/jpeg" => "jpg",
        "image/gif" => "gif",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        "image/avif" => "avif",
        "audio/ogg" => "ogg",
        "audio/mpeg" => "mp3",
        "video/mp4" => "mp4",
        "video/webm" => "webm",
        "text/plain" => "txt",
        "text/markdown" => "md",
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        _ => return None,
    };
    Some(ext.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names() {
        let uri = matrix_sdk::ruma::mxc_uri!("mxc://m.doesnmlab.xyz/AbCdEf123");
        let name = cache_file_name(&uri, Some("image/png"));
        assert_eq!(name, "m.doesnmlab.xyz_AbCdEf123.png");
        let name = cache_file_name(&uri, Some("application/octet-stream"));
        assert_eq!(name, "m.doesnmlab.xyz_AbCdEf123.bin");
        let name = cache_file_name(&uri, None);
        assert_eq!(name, "m.doesnmlab.xyz_AbCdEf123.bin");
    }

    #[test]
    fn image_sniffing() {
        assert_eq!(sniff_image_ext(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A]), Some("png"));
        assert_eq!(sniff_image_ext(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("jpg"));
        assert_eq!(sniff_image_ext(b"GIF89a"), Some("gif"));
        let webp = [b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'E', b'B', b'P'];
        assert_eq!(sniff_image_ext(&webp), Some("webp"));
        let avif = [0, 0, 0, 0x18, b'f', b't', b'y', b'p', b'a', b'v', b'i', b'f'];
        assert_eq!(sniff_image_ext(&avif), Some("avif"));
        assert_eq!(sniff_image_ext(b"not an image"), None);
    }
}
