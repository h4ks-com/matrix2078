//! IRC message construction helpers.

use irc::proto::{Command, Message, Prefix, Response};

/// A message from the server (numeric or command), e.g. `:matrix2078 001 nick :Welcome`.
pub fn srv(server: &str, command: Command) -> Message {
    Message {
        tags: None,
        prefix: Some(Prefix::ServerName(server.to_owned())),
        command,
    }
}

/// A numeric addressed to `target`; `args` exclude the leading target param.
pub fn num(server: &str, code: Response, target: &str, args: Vec<String>) -> Message {
    let mut full = vec![target.to_owned()];
    full.extend(args);
    srv(server, Command::Response(code, full))
}

/// A message on behalf of a user (matrix participant or the IRC client itself).
pub fn user(nick: &str, command: Command) -> Message {
    Message {
        tags: None,
        prefix: Some(Prefix::Nickname(nick.to_owned(), "matrix".to_owned(), "matrix".to_owned())),
        command,
    }
}

/// The IRC client's own prefix: `nick!user@host`.
pub fn client_prefix(nick: &str, username: &str) -> Prefix {
    Prefix::Nickname(nick.to_owned(), username.to_owned(), "matrix2078".to_owned())
}

/// A message on behalf of the connected IRC client.
pub fn from_client(prefix: &Prefix, command: Command) -> Message {
    Message { tags: None, prefix: Some(prefix.clone()), command }
}

/// Extract the localpart of a Matrix user id as a (M0-quality) IRC nick.
pub fn mxid_to_nick(mxid: &str) -> String {
    let local = mxid.trim_start_matches('@').split(':').next().unwrap_or(mxid);
    if local.is_empty() {
        "matrix".to_owned()
    } else {
        local.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_numeric() {
        let m = num("matrix2078", Response::RPL_WELCOME, "nick", vec!["Welcome".into()]);
        assert_eq!(m.to_string(), ":matrix2078 001 nick Welcome\r\n");
    }

    #[test]
    fn renders_trailing_param() {
        let m = user("alice", Command::PRIVMSG("#chan".into(), "hi there".into()));
        assert_eq!(m.to_string(), ":alice!matrix@matrix PRIVMSG #chan :hi there\r\n");
    }

    #[test]
    fn mxid_localpart() {
        assert_eq!(mxid_to_nick("@m2078-peer:doesnmlab.xyz"), "m2078-peer");
        assert_eq!(mxid_to_nick("@x:y"), "x");
    }
}
