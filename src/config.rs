//! matrix2078 configuration: TOML file + `MATRIX2078_*` env overrides.

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address the IRCd listens on.
    pub listen: SocketAddr,
    /// Address the local media HTTP server listens on.
    pub media_listen: SocketAddr,
    /// Public base URL for media links, when the server is reachable at a
    /// different address than it listens on (containers behind port maps).
    pub media_public_url: Option<String>,
    /// IRC server name shown in numerics and prefixes.
    pub server_name: String,
    /// Directory for persistent (encrypted) sessions and matrix-sdk state.
    pub state_dir: PathBuf,
    /// Homeserver base URL; used when not given via GECOS in USER.
    /// Required for the first login of a user, afterwards taken from the
    /// stored session unless overridden.
    pub homeserver: Option<String>,
    /// Allow creating new Matrix sessions from IRC PASS/NICK/USER registration.
    pub allow_register: bool,
    /// Room↔channel relay tuning.
    pub bridge: BridgeConfig,
    /// Optional TLS for the IRC listener (PEM cert + key), for
    /// non-loopback hosting.
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to the PEM certificate chain.
    pub cert: PathBuf,
    /// Path to the PEM private key.
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BridgeConfig {
    /// Maximum number of nicks sent in NAMES/353 and WHO/352 replies.
    /// Huge Matrix rooms (thousands of members) freeze IRC clients if the
    /// full list is sent, so it is capped.
    pub names_limit: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 2078)),
            media_listen: SocketAddr::from(([127, 0, 0, 1], 2079)),
            media_public_url: None,
            server_name: "matrix2078".to_owned(),
            state_dir: PathBuf::from("./state"),
            homeserver: None,
            allow_register: false,
            bridge: BridgeConfig::default(),
            tls: None,
        }
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self { names_limit: 200 }
    }
}

impl Config {
    /// Load config from `path` (must exist) and apply env overrides.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        cfg.apply_env();
        Ok(cfg)
    }

    pub fn load_or_default(path: &Path) -> Result<Self> {
        if path.exists() {
            Config::load(path)
        } else if path == &PathBuf::from("matrix2078.toml") {
            let mut cfg = Config::default();
            cfg.apply_env();
            Ok(cfg)
        } else {
            bail!("config file not found: {}", path.display())
        }
    }

    fn apply_env(&mut self) {
        if let Some(v) = env_parse::<SocketAddr>("MATRIX2078_LISTEN") {
            self.listen = v;
        }
        if let Some(v) = env_parse::<SocketAddr>("MATRIX2078_MEDIA_LISTEN") {
            self.media_listen = v;
        }
        if let Some(v) = env_str("MATRIX2078_MEDIA_PUBLIC_URL") {
            self.media_public_url = Some(v);
        }
        if let Some(v) = env_str("MATRIX2078_SERVER_NAME") {
            self.server_name = v;
        }
        if let Some(v) = env_str("MATRIX2078_STATE_DIR") {
            self.state_dir = PathBuf::from(v);
        }
        if let Some(v) = env_str("MATRIX2078_HOMESERVER") {
            self.homeserver = Some(v);
        }
        if let Some(v) = env_parse::<bool>("MATRIX2078_ALLOW_REGISTER") {
            self.allow_register = v;
        }
        if let Some(v) = env_parse::<usize>("MATRIX2078_NAMES_LIMIT") {
            self.bridge.names_limit = v;
        }
        // both cert and key must be present for TLS
        match (env_str("MATRIX2078_TLS_CERT"), env_str("MATRIX2078_TLS_KEY")) {
            (Some(cert), Some(key)) => {
                self.tls = Some(TlsConfig { cert: PathBuf::from(cert), key: PathBuf::from(key) });
            }
            (None, None) => {}
            _ => eprintln!("warning: MATRIX2078_TLS_CERT and MATRIX2078_TLS_KEY must be set together; ignoring"),
        }
    }
}

fn env_str(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    let raw = env_str(key)?;
    match raw.trim().parse::<T>() {
        Ok(v) => Some(v),
        Err(_) => {
            eprintln!("warning: ignoring unparseable {key}={raw:?}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.listen.to_string(), "127.0.0.1:2078");
        assert_eq!(cfg.media_listen.to_string(), "127.0.0.1:2079");
        assert_eq!(cfg.state_dir, PathBuf::from("./state"));
        assert!(!cfg.allow_register);
        assert_eq!(cfg.bridge.names_limit, 200);
    }

    #[test]
    fn parse_toml() {
        let cfg: Config = toml::from_str(
            r##"
            listen = "127.0.0.1:6667"
            state_dir = "./st"
            homeserver = "https://example.org"
            [bridge]
            names_limit = 50
            "##,
        )
        .unwrap();
        assert_eq!(cfg.listen.to_string(), "127.0.0.1:6667");
        assert_eq!(cfg.homeserver.as_deref(), Some("https://example.org"));
        assert_eq!(cfg.bridge.names_limit, 50);
    }

    #[test]
    fn parse_tls() {
        let cfg: Config = toml::from_str(
            r##"
            [tls]
            cert = "certs/fullchain.pem"
            key = "certs/privkey.pem"
            "##,
        )
        .unwrap();
        let tls = cfg.tls.expect("tls present");
        assert_eq!(tls.cert, PathBuf::from("certs/fullchain.pem"));
        assert_eq!(tls.key, PathBuf::from("certs/privkey.pem"));
    }

    #[test]
    fn env_overrides() {
        std::env::set_var("MATRIX2078_TEST_LISTEN", "127.0.0.1:6697");
        let listen: SocketAddr =
            env_parse("MATRIX2078_TEST_LISTEN").expect("should parse socket addr");
        assert_eq!(listen.to_string(), "127.0.0.1:6697");

        std::env::set_var("MATRIX2078_TEST_BOOL", "true");
        assert_eq!(env_parse::<bool>("MATRIX2078_TEST_BOOL"), Some(true));

        std::env::set_var("MATRIX2078_TEST_NUM", "42");
        assert_eq!(env_parse::<usize>("MATRIX2078_TEST_NUM"), Some(42));

        std::env::set_var("MATRIX2078_TEST_JUNK", "not-a-port");
        assert_eq!(env_parse::<SocketAddr>("MATRIX2078_TEST_JUNK"), None);
    }
}
