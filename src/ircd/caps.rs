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
    ("msgid", None),
    ("away-notify", None),
    ("account-notify", None),
    ("account-tag", None),
    ("batch", None),
    ("multi-prefix", None),
    ("extended-join", None),
    ("userhost-in-names", None),
    ("sasl", Some("PLAIN")),
    ("draft/chathistory", None),
    // spec REQUIRED value: max-bytes[,max-lines]
    ("draft/multiline", Some("max-bytes=4096,max-lines=32")),
    ("draft/message-redaction", None),
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
    /// Returns `(ack_list, nak_list)`: supported tokens are applied and
    /// ACKed, unknown ones are NAKed. Acking known caps while naking the
    /// unknown rest (instead of rejecting the whole REQ) is what clients
    /// like girc expect when they request several caps in one line.
    pub fn apply_req(&mut self, identifier_params: &str) -> (String, String) {
        let mut ack: Vec<&str> = Vec::new();
        let mut nak: Vec<&str> = Vec::new();
        for token in identifier_params.split_whitespace() {
            let name = token.strip_prefix('-').unwrap_or(token);
            if SUPPORTED.iter().any(|(supported, _)| supported.eq_ignore_ascii_case(name)) {
                let (disable, bare) = match token.strip_prefix('-') {
                    Some(n) => (true, n),
                    None => (false, token),
                };
                if disable {
                    self.enabled.remove(bare.to_ascii_lowercase().as_str());
                } else {
                    self.enabled.insert(bare.to_owned());
                }
                ack.push(token);
            } else {
                nak.push(token);
            }
        }
        (ack.join(" "), nak.join(" "))
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
        let (ack, _) = caps.apply_req("server-time echo-message -batch");
        assert_eq!(ack, "server-time echo-message -batch");
        assert!(caps.has("server-time"));
        assert!(!caps.has("batch"));
        assert_eq!(caps.list(), "echo-message server-time");
    }

    #[test]
    fn req_unknown_is_naked_but_known_still_acks() {
        let mut caps = Caps::default();
        caps.apply_req("server-time");
        let (ack, nak) = caps.apply_req("echo-message bogus-cap");
        assert_eq!(ack, "echo-message");
        assert_eq!(nak, "bogus-cap");
        assert!(caps.has("echo-message"));
        assert!(!caps.has("bogus-cap"));
    }
}
