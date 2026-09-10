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
}
