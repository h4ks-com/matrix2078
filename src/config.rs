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
    /// IRC server name shown in numerics and prefixes.
    pub server_name: String,
    /// Directory for persistent (encrypted) sessions and matrix-sdk state.
    pub state_dir: PathBuf,
    /// Homeserver base URL; required for the first login of a user,
    /// afterwards taken from the stored session unless overridden.
    pub homeserver: Option<String>,
    /// Allow creating new Matrix sessions from IRC PASS/NICK/USER registration.
    pub allow_register: bool,
    /// M0 single-room relay settings.
    pub bridge: BridgeConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BridgeConfig {
    /// Matrix room to relay: room id (`!…`) or alias (`#…:…`).
    /// Defaults to the first joined room.
    pub room: Option<String>,
    /// IRC channel name for the relayed room. Defaults to `#matrix`.
    pub channel: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 2078)),
            server_name: "matrix2078".to_owned(),
            state_dir: PathBuf::from("./state"),
            homeserver: None,
            allow_register: false,
            bridge: BridgeConfig::default(),
        }
    }
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self { room: None, channel: "#matrix".to_owned() }
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
        if let Some(v) = env_str("MATRIX2078_BRIDGE_ROOM") {
            self.bridge.room = Some(v);
        }
        if let Some(v) = env_str("MATRIX2078_BRIDGE_CHANNEL") {
            self.bridge.channel = v;
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
        assert_eq!(cfg.state_dir, PathBuf::from("./state"));
        assert!(!cfg.allow_register);
        assert_eq!(cfg.bridge.channel, "#matrix");
    }

    #[test]
    fn parse_toml() {
        let cfg: Config = toml::from_str(
            r##"
            listen = "127.0.0.1:6667"
            state_dir = "./st"
            homeserver = "https://example.org"
            [bridge]
            room = "!abc:example.org"
            channel = "#test"
            "##,
        )
        .unwrap();
        assert_eq!(cfg.listen.to_string(), "127.0.0.1:6667");
        assert_eq!(cfg.homeserver.as_deref(), Some("https://example.org"));
        assert_eq!(cfg.bridge.room.as_deref(), Some("!abc:example.org"));
        assert_eq!(cfg.bridge.channel, "#test");
    }

    #[test]
    fn env_overrides() {
        // unique key values to avoid clashing with parallel tests
        std::env::set_var("MATRIX2078_TEST_LISTEN", "127.0.0.1:6697");
        let listen: SocketAddr =
            env_parse("MATRIX2078_TEST_LISTEN").expect("should parse socket addr");
        assert_eq!(listen.to_string(), "127.0.0.1:6697");

        std::env::set_var("MATRIX2078_TEST_BOOL", "true");
        assert_eq!(env_parse::<bool>("MATRIX2078_TEST_BOOL"), Some(true));

        std::env::set_var("MATRIX2078_TEST_JUNK", "not-a-port");
        assert_eq!(env_parse::<SocketAddr>("MATRIX2078_TEST_JUNK"), None);
    }
}
