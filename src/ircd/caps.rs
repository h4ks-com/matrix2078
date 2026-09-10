//! IRCv3 capability negotiation (CAP LS/REQ/ACK/NAK/LIST).
//!
//! Capabilities offered (M2 set):
//! - `server-time`, `echo-message`, `message-tags`
//! - `away-notify`, `account-notify`, `account-tag`
//! - `batch`, `multi-prefix`, `extended-join`, `userhost-in-names`
//! - `sasl=PLAIN`
//! - `draft/chathistory`
//! - `draft/multiline`

use std::collections::HashSet;

/// All capabilities this server supports, with optional values.
pub const SUPPORTED: &[(&str, Option<&str>)] = &[
    ("server-time", None),
    ("echo-message", None),
    ("message-tags", None),
    ("away-notify", None),
    ("account-notify", None),
    ("account-tag", None),
    ("batch", None),
    ("multi-prefix", None),
    ("extended-join", None),
    ("userhost-in-names", None),
    ("sasl", Some("PLAIN")),
    ("draft/chathistory", None),
    ("draft/multiline", None),
];

/// Capabilities negotiated for a single connection.
#[derive(Clone, Debug, Default)]
pub struct Caps {
    enabled: HashSet<String>,
}

impl Caps {
    /// The LS line: all supported caps with values.
    pub fn ls() -> String {
        SUPPORTED
            .iter()
            .map(|(name, val)| match val {
                Some(v) => format!("{name}={v}"),
                None => (*name).to_owned(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn has(&self, name: &str) -> bool {
        self.enabled.contains(name)
    }

    /// Space-separated list of negotiated caps (for CAP LIST).
    pub fn list(&self) -> String {
        let mut names: Vec<&str> = self.enabled.iter().map(String::as_str).collect();
        names.sort_unstable();
        names.join(" ")
    }

    /// Apply a `CAP REQ` identifier list (`cap1 cap2 -cap3`).
    ///
    /// Returns `Ok(ack_line)` with the names to ACK, or `Err(nak_line)` if an
    /// unknown capability was requested (the whole REQ is NAKed and nothing
    /// is applied).
    pub fn apply_req(&mut self, identifier_params: &str) -> Result<String, String> {
        let tokens: Vec<&str> = identifier_params.split_whitespace().collect();
        for token in &tokens {
            let name = token.strip_prefix('-').unwrap_or(token);
            if !SUPPORTED.iter().any(|(supported, _)| supported.eq_ignore_ascii_case(name)) {
                return Err(identifier_params.to_owned());
            }
        }
        for token in &tokens {
            let (disable, name) = match token.strip_prefix('-') {
                Some(n) => (true, n),
                None => (false, &token[..]),
            };
            if disable {
                self.enabled.remove(name.to_owned().as_str());
            } else {
                self.enabled.insert(name.to_owned());
            }
        }
        Ok(tokens.into_iter().map(str::to_owned).collect::<Vec<_>>().join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ls_contains_core_caps() {
        let ls = Caps::ls();
        for c in ["server-time", "echo-message", "message-tags", "sasl=PLAIN", "draft/chathistory", "draft/multiline"] {
            assert!(ls.contains(c), "missing {c} in {ls}");
        }
    }

    #[test]
    fn req_ack_and_disable() {
        let mut caps = Caps::default();
        let ack = caps.apply_req("server-time echo-message -batch").unwrap();
        assert_eq!(ack, "server-time echo-message -batch");
        assert!(caps.has("server-time"));
        assert!(!caps.has("batch"));
        assert_eq!(caps.list(), "echo-message server-time");
    }

    #[test]
    fn req_unknown_naks_everything() {
        let mut caps = Caps::default();
        caps.apply_req("server-time").unwrap();
        let err = caps.apply_req("echo-message bogus-cap").unwrap_err();
        assert_eq!(err, "echo-message bogus-cap");
        assert!(!caps.has("echo-message"), "unknown cap must not partially apply");
        assert!(caps.has("server-time"));
    }
}
