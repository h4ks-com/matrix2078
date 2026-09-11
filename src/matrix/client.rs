//! matrix-sdk client construction, login and session restore.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use matrix_sdk::Client;
use regex::Regex;

use crate::config::Config;

use super::session::{PersistedSession, load, save};

/// Filesystem-safe directory name for an IRC nick.
pub fn user_dir(state_dir: &Path, nick: &str) -> PathBuf {
    let re = Regex::new(r"[^A-Za-z0-9_\-\[\]\\^`{}]").unwrap();
    let mut name = re.replace_all(nick, "_").to_string();
    // no leading dots: avoid hidden dirs and `..`
    while name.starts_with('.') {
        name.remove(0);
    }
    if name.is_empty() {
        name = "_".to_string();
    }
    state_dir.join(name)
}

async fn build_client(homeserver: &str, sqlite_dir: &Path) -> Result<Client> {
    fs::create_dir_all(sqlite_dir)
        .with_context(|| format!("creating state dir {}", sqlite_dir.display()))?;
    let mut builder = Client::builder().sqlite_store(sqlite_dir, None);
    if homeserver.contains("://") {
        builder = builder.homeserver_url(homeserver);
    } else {
        // bare domain: full spec discovery (well-known, then _matrix._tcp
        // SRV, then https://domain) — the pto/matrirc style, done by the SDK
        let server_name = matrix_sdk::ruma::ServerName::parse(homeserver)
            .with_context(|| format!("invalid server name {homeserver:?}"))?;
        builder = builder.server_name(&server_name);
    }
    builder
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("building matrix client for {homeserver}: {e}"))
}

/// Restore a stored session for `nick`, or log in with the IRC password and
/// persist the new session (only when registration is allowed).
///
/// `login_user` is the Matrix user id (or localpart) used for a fresh login:
/// taken from the USER field when it looks like an mxid, else the nick.
/// `hs_override` (GECOS/config/env) wins over the stored homeserver.
/// State key for a login: mxid localpart when `login_user` is a full mxid
/// (keeps SASL `@user:domain` and nick-based logins on the same session),
/// else the nick.
pub fn state_key(nick: &str, login_user: &str) -> String {
    login_user
        .trim_start_matches('@')
        .split_once(':')
        .map(|(local, _)| local.to_owned())
        .unwrap_or_else(|| nick.to_owned())
}

/// Restore a stored session for `nick`, or log in with the IRC password and
/// persist the new session (only when registration is allowed).
///
/// `login_user` is the Matrix user id (or localpart) used for a fresh login:
/// taken from the USER field when it looks like an mxid, else the nick.
/// `hs_override` (GECOS/config/env) wins over the stored homeserver.
pub async fn login_or_restore(
    cfg: &Config,
    nick: &str,
    irc_pass: &str,
    login_user: &str,
    hs_override: Option<&str>,
) -> Result<Client> {
    let dir = user_dir(&cfg.state_dir, &state_key(nick, login_user));
    let sqlite_dir = dir.join("sqlite");

    if super::session::session_path(&dir).exists() {
        let ps: PersistedSession = load(&dir, irc_pass)?;
        let homeserver = hs_override
            .map(str::to_owned)
            .unwrap_or_else(|| cfg.homeserver.clone().unwrap_or(ps.homeserver.clone()));
        let client = build_client(&homeserver, &sqlite_dir).await?;
        let user_id = ps.session.meta.user_id.clone();
        client
            .matrix_auth()
            .restore_session(ps.session, matrix_sdk::store::RoomLoadSettings::default())
            .await
            .context("restoring matrix session")?;
        tracing::info!(nick, homeserver, %user_id, "restored matrix session");
        Ok(client)
    } else {
        if !cfg.allow_register {
            bail!(
                "no stored session for nick {nick:?}; start matrix2078 with --allow-register \
                 (or MATRIX2078_ALLOW_REGISTER=1) to create one"
            );
        }
        let homeserver = hs_override
            .map(str::to_owned)
            .or_else(|| cfg.homeserver.clone())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "homeserver not configured; set it in matrix2078.toml, \
                     MATRIX2078_HOMESERVER, or the IRC realname (GECOS) field"
                )
            })?;
        let client = build_client(&homeserver, &sqlite_dir).await?;
        client
            .matrix_auth()
            .login_username(login_user, irc_pass)
            .initial_device_display_name("matrix2078")
            .send()
            .await
            .context("matrix login failed (bad user/password?)")?;
        let session = client
            .matrix_auth()
            .session()
            .ok_or_else(|| anyhow::anyhow!("no session after login"))?;
        // persist the *resolved* homeserver so restores skip discovery
        let resolved = client.homeserver().to_string();
        let ps = PersistedSession { homeserver: resolved.clone(), session };
        save(&dir, irc_pass, &ps)?;
        tracing::info!(nick, homeserver = %resolved, user = %ps.session.meta.user_id, "logged in and stored new matrix session");
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_dir_sanitizes() {
        let d = user_dir(Path::new("./state"), "m2078");
        assert_eq!(d, PathBuf::from("./state").join("m2078"));
        // dots are outside the allowed charset, so `..` becomes `__`, never traversal
        assert_eq!(user_dir(Path::new("./state"), ".."), PathBuf::from("./state").join("__"));
        assert_eq!(
            user_dir(Path::new("./state"), "a b/c"),
            PathBuf::from("./state").join("a_b_c")
        );
        assert_eq!(user_dir(Path::new("./state"), "@m2078:hs"), PathBuf::from("./state").join("_m2078_hs"));
    }
}
