//! IRC message construction helpers.

use irc::proto::{Command, Message, Prefix, Response};
use irc::proto::message::Tag;

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
        prefix: Some(user_prefix(nick)),
        command,
    }
}

/// Prefix for a Matrix participant: `nick!matrix@matrix`.
pub fn user_prefix(nick: &str) -> Prefix {
    Prefix::Nickname(nick.to_owned(), "matrix".to_owned(), "matrix".to_owned())
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

/// `msgid` (message id) tag: Matrix event id without the leading `$`.
pub fn msgid_tag(event_id: &str) -> Tag {
    Tag("msgid".to_owned(), Some(event_id.trim_start_matches('$').to_owned()))
}

/// `time` (server-time) tag: ISO 8601 with millisecond precision, `Z` suffix.
pub fn time_tag(ms: u64) -> Tag {
    Tag("time".to_owned(), Some(iso_time(ms)))
}

/// Render milliseconds-since-epoch as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn iso_time(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let millis = ms % 1000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Days since 1970-01-01 to (year, month, day) — Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
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

    #[test]
    fn iso_time_formatting() {
        assert_eq!(iso_time(0), "1970-01-01T00:00:00.000Z");
        // 2026-08-26T04:34:56.789Z
        assert_eq!(iso_time(1787718896789), "2026-08-26T04:34:56.789Z");
        // leap-year boundary: 2024-02-29
        assert_eq!(iso_time(1709164800000), "2024-02-29T00:00:00.000Z");
    }

    #[test]
    fn msgid_strips_dollar() {
        let Tag(k, v) = msgid_tag("$abc123");
        assert_eq!(k, "msgid");
        assert_eq!(v.as_deref(), Some("abc123"));
    }

    #[test]
    fn parses_multiline_batch_and_tags() {
        let open: Message = "BATCH +t1 draft/multiline #m2078-plain".parse().unwrap();
        match open.command {
            Command::BATCH(ref_name, sub, args) => {
                assert_eq!(ref_name, "+t1");
                let sub = sub.unwrap();
                match sub {
                    irc::proto::BatchSubCommand::CUSTOM(t) => {
                        assert!(t.eq_ignore_ascii_case("draft/multiline"));
                    }
                    other => panic!("unexpected sub {other:?}"),
                }
                assert_eq!(args.unwrap(), vec!["#m2078-plain".to_owned()]);
            }
            other => panic!("unexpected command {other:?}"),
        }
        let close: Message = "BATCH -t1".parse().unwrap();
        match close.command {
            Command::BATCH(ref_name, sub, args) => {
                assert_eq!(ref_name, "-t1");
                assert!(sub.is_none());
                assert!(args.is_none());
            }
            other => panic!("unexpected command {other:?}"),
        }
        let line: Message = "@draft/multiline=t1 PRIVMSG #m2078-plain :second line".parse().unwrap();
        let tags = line.tags.unwrap();
        let ml = tags.iter().find(|t| t.0 == "draft/multiline").unwrap();
        assert_eq!(ml.1.as_deref(), Some("t1"));
    }

    #[test]
    fn tags_render_in_message() {
        let mut m = user("alice", Command::PRIVMSG("#c".into(), "hi".into()));
        m.tags = Some(vec![time_tag(1709164800123), msgid_tag("$x")]);
        // "hi" has no spaces, so the codec needs no trailing colon
        assert_eq!(
            m.to_string(),
            "@time=2024-02-29T00:00:00.123Z;msgid=x :alice!matrix@matrix PRIVMSG #c hi\r\n"
        );
        let mut m2 = user("alice", Command::PRIVMSG("#c".into(), "hi there".into()));
        m2.tags = Some(vec![time_tag(1709164800123), msgid_tag("$x")]);
        assert_eq!(
            m2.to_string(),
            "@time=2024-02-29T00:00:00.123Z;msgid=x :alice!matrix@matrix PRIVMSG #c :hi there\r\n"
        );
    }
}
