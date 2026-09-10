//! Persistent Matrix session storage: JSON blob encrypted with the IRC
//! password (see [`crate::state`]) under `state_dir/<nick>/session.bin`.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use matrix_sdk::authentication::matrix::MatrixSession;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PersistedSession {
    /// Homeserver base URL to rebuild the client on restore.
    pub homeserver: String,
    #[serde(flatten)]
    pub session: MatrixSession,
}

pub fn session_path(dir: &Path) -> std::path::PathBuf {
    dir.join("session.bin")
}

pub fn save(dir: &Path, irc_pass: &str, ps: &PersistedSession) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let json = serde_json::to_vec(ps).context("serializing session")?;
    let blob = crate::state::seal(irc_pass, &json)?;
    let path = session_path(dir);
    fs::write(&path, blob).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub fn load(dir: &Path, irc_pass: &str) -> Result<PersistedSession> {
    let path = session_path(dir);
    let blob = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
    let json = crate::state::unseal(irc_pass, &blob)?;
    serde_json::from_slice(&json).context("deserializing session")
}

#[cfg(test)]
mod tests {
    use super::*;
    use matrix_sdk::SessionMeta;
    use matrix_sdk::authentication::SessionTokens;
    use matrix_sdk::ruma::{owned_device_id, owned_user_id};

    fn test_session() -> PersistedSession {
        PersistedSession {
            homeserver: "https://example.org".to_owned(),
            session: MatrixSession {
                meta: SessionMeta {
                    user_id: owned_user_id!("@m2078:example.org"),
                    device_id: owned_device_id!("ABCD1234"),
                },
                tokens: SessionTokens {
                    access_token: "s3cr3t".to_owned(),
                    refresh_token: None,
                },
            },
        }
    }

    #[test]
    fn roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ps = test_session();
        save(dir.path(), "ircpass", &ps).unwrap();

        assert!(session_path(dir.path()).is_file());
        let back = load(dir.path(), "ircpass").unwrap();
        assert_eq!(back.homeserver, "https://example.org");
        assert_eq!(back.session.meta.user_id, ps.session.meta.user_id);
        assert_eq!(back.session.tokens.access_token, "s3cr3t");
    }

    #[test]
    fn wrong_password_rejected() {
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), "right", &test_session()).unwrap();
        assert!(load(dir.path(), "wrong").is_err());
    }
}
