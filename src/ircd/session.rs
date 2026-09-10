//! IRC connection registration state.

/// State accumulated during PASS/NICK/USER/CAP registration.
#[derive(Debug, Default)]
pub struct Registration {
    pub pass: Option<String>,
    pub nick: Option<String>,
    pub user: Option<String>,
    pub realname: Option<String>,
    /// True once the client sent any CAP subcommand (negotiation started).
    pub cap_started: bool,
    /// True after CAP END (or when negotiation never started).
    pub cap_ended: bool,
}

impl Registration {
    /// Registration is complete once we have a nick and a username, and
    /// capability negotiation is not in progress.
    pub fn is_complete(&self) -> bool {
        self.nick.is_some() && self.user.is_some() && (!self.cap_started || self.cap_ended)
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
}
