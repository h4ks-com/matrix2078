//! IRC connection registration state.

use super::caps::Caps;

/// State accumulated during PASS/NICK/USER/CAP/SASL registration.
#[derive(Debug, Default)]
pub struct Registration {
    pub pass: Option<String>,
    pub nick: Option<String>,
    pub user: Option<String>,
    pub realname: Option<String>,
    /// Capabilities negotiated during registration.
    pub caps: Caps,
    /// True once the client sent any CAP subcommand (negotiation started).
    pub cap_started: bool,
    /// True after CAP END (or when negotiation never started).
    pub cap_ended: bool,
    /// SASL PLAIN credentials decoded from AUTHENTICATE.
    pub sasl_user: Option<String>,
    pub sasl_pass: Option<String>,
    /// True between AUTHENTICATE PLAIN and the final payload (or abort).
    pub sasl_pending: bool,
}

impl Registration {
    /// Registration is complete once we have a nick and a username,
    /// capability negotiation is not in progress, and SASL (if started)
    /// has finished.
    pub fn is_complete(&self) -> bool {
        self.nick.is_some()
            && self.user.is_some()
            && (!self.cap_started || self.cap_ended)
            && !self.sasl_pending
    }
}

/// Validate an IRC nick (M0 rules: 1–16 chars, IRC charset, no leading digit).
pub fn valid_nick(nick: &str) -> bool {
    if nick.is_empty() || nick.len() > 16 {
        return false;
    }
    let mut chars = nick.chars();
    let first = chars.next().unwrap();
    if first.is_ascii_digit() || "#&$:.!@*?,".contains(first) {
        return false;
    }
    chars.all(|c| {
        c.is_ascii_alphanumeric() || "_-[]\\^`{}|".contains(c)
    })
}

/// Decode SASL PLAIN base64 payload into (authzid, authcid, password).
pub fn decode_sasl_plain(payload: &str) -> Option<(String, String, String)> {
    use base64::Engine;
    let raw = if payload == "+" {
        Vec::new()
    } else {
        base64::engine::general_purpose::STANDARD.decode(payload).ok()?
    };
    let text = String::from_utf8(raw).ok()?;
    let mut fields = text.split('\0');
    let authzid = fields.next()?.to_owned();
    let authcid = fields.next()?.to_owned();
    let passwd = fields.next()?.to_owned();
    if fields.next().is_some() {
        return None;
    }
    if authcid.is_empty() || passwd.is_empty() {
        return None;
    }
    Some((authzid, authcid, passwd))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_rules() {
        let mut r = Registration::default();
        assert!(!r.is_complete());
        r.nick = Some("m2078".into());
        r.user = Some("m2078".into());
        assert!(r.is_complete());

        let mut r = Registration::default();
        r.cap_started = true;
        r.nick = Some("m2078".into());
        r.user = Some("m2078".into());
        assert!(!r.is_complete());
        r.cap_ended = true;
        assert!(r.is_complete());

        let mut r = Registration::default();
        r.nick = Some("m2078".into());
        r.user = Some("m2078".into());
        r.sasl_pending = true;
        assert!(!r.is_complete());
        r.sasl_pending = false;
        assert!(r.is_complete());
    }

    #[test]
    fn nick_validation() {
        assert!(valid_nick("m2078"));
        assert!(valid_nick("weechat`"));
        assert!(!valid_nick(""));
        assert!(!valid_nick("2fast"));
        assert!(!valid_nick("#chan"));
        assert!(!valid_nick("has space"));
        assert!(!valid_nick("toolongnicknameee"));
    }

    #[test]
    fn sasl_plain_decoding() {
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD
            .encode("\u{0}m2078:doesnmlab.xyz\u{0}hunter2");
        let (z, cid, pass) = decode_sasl_plain(&payload).unwrap();
        assert_eq!((z.as_str(), cid.as_str(), pass.as_str()), ("", "m2078:doesnmlab.xyz", "hunter2"));

        assert!(decode_sasl_plain("not base64!!").is_none());
        assert!(decode_sasl_plain("aGk=").is_none()); // no \0 separators
    }
}
