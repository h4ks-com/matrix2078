//! IRC server: TCP listener, registration (PASS/NICK/USER/CAP/SASL),
//! core commands, IRCv3 extensions (server-time, echo-message, multiline,
//! chathistory) and the Matrix-backed relay loop.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use irc::proto::{CapSubCommand, Command, IrcCodec, Message, Prefix, Response};
use irc::proto::message::Tag;
use tokio::{net::{TcpListener, TcpStream}, sync::mpsc};
use tokio_util::codec::Framed;

use crate::{
    bridge::{Bridge, history::{self, HistoryItem}},
    config::Config,
    ircd::{
        caps::{self, Caps},
        proto::{self, client_prefix, from_client, num, srv},
        session::{Registration, decode_sasl_plain, valid_nick},
    },
    media::MediaServer,
};

pub async fn run(cfg: Arc<Config>) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, server = %cfg.server_name, "ircd listening");
    let media = Arc::new(MediaServer::new(
        cfg.media_listen,
        crate::matrix::media::cache_dir(&cfg.state_dir),
    ));
    {
        let media = Arc::clone(&media);
        tokio::spawn(async move {
            if let Err(e) = media.run().await {
                tracing::error!(error = %e, "media server failed to start");
            }
        });
    }
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::info!(%peer, "client connected");
        let cfg = cfg.clone();
        let media = Arc::clone(&media);
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, peer, cfg, media).await {
                tracing::info!(%peer, error = %e, "connection closed with error");
            } else {
                tracing::info!(%peer, "connection closed");
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: Arc<Config>,
    media: Arc<MediaServer>,
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let codec = IrcCodec::new("UTF-8")?;
    let mut framed = Framed::new(stream, codec);
    let server = cfg.server_name.clone();

    // ---------------- registration ----------------
    let mut reg = Registration::default();
    let bridge = loop {
        let Some(msg) = framed.next().await else { return Ok(()) };
        let msg = msg.map_err(|e| anyhow::anyhow!("decode error: {e}"))?;
        match msg.command {
            Command::PASS(p) => reg.pass = Some(p),
            Command::NICK(n) => {
                if !valid_nick(&n) {
                    framed
                        .send(num(&server, Response::ERR_ERRONEOUSNICKNAME, "*", vec![
                            n,
                            "Erroneous nickname".to_owned(),
                        ]))
                        .await?;
                    continue;
                }
                reg.nick = Some(n);
            }
            Command::USER(u, _mode, r) => {
                reg.user = Some(u);
                reg.realname = Some(r);
            }
            Command::CAP(_, sub, caps_req, _) => {
                handle_cap(&mut framed, &server, &mut reg, sub, caps_req.as_deref()).await?;
            }
            Command::AUTHENTICATE(arg) => {
                handle_authenticate(&mut framed, &server, &mut reg, &arg).await?;
            }
            Command::QUIT(reason) => {
                send_quit(&mut framed, &server, reason).await?;
                return Ok(());
            }
            _ => {}
        }
        if reg.is_complete() {
            match matrix_auth(&mut framed, &cfg, &reg, &media).await? {
                Some(bridge) => break bridge,
                None => return Ok(()),
            }
        }
    };

    // ---------------- post-registration ----------------
    let caps = reg.caps.clone();
    let mut nick = reg.nick.clone().unwrap_or_default();
    let username = irc_username(reg.user.as_deref().unwrap_or("u"));
    let prefix = client_prefix(&nick, &username);

    for m in welcome_burst(&server, &nick) {
        send_out(&mut framed, &caps, m).await?;
    }
    if reg.sasl_user.is_some() {
        // account-notify base: announce our own account once
        let account = reg.sasl_user.clone().unwrap_or_default();
        let _ = account;
    }

    // JOIN every mapped room's channel before any PRIVMSG can reference it
    for entry in bridge.entries() {
        bridge.joined.lock().expect("joined mutex").insert(entry.channel.to_ascii_lowercase());
        send_join(&mut framed, &server, &prefix, &nick, &entry, &bridge, cfg.bridge.names_limit)
            .await?;
    }

    let (tx, mut rx) = mpsc::channel::<Message>(256);
    bridge.relay_matrix_to_irc(tx.clone());
    let sync_task = bridge.spawn_sync();

    let result =
        relay_loop(&mut framed, &peer, &server, &prefix, &mut nick, &username, &bridge, &caps, &mut rx, tx)
            .await;
    // the matrix sync loop must not outlive the IRC connection: it holds the
    // device's sync position and would block the next session of this user
    sync_task.abort();
    result
}

/// CAP negotiation during registration.
async fn handle_cap(
    framed: &mut Framed<TcpStream, IrcCodec>,
    server: &str,
    reg: &mut Registration,
    sub: CapSubCommand,
    caps_req: Option<&str>,
) -> Result<()> {
    use CapSubCommand::*;
    match sub {
        LS => {
            reg.cap_started = true;
            framed
                .send(srv(server, Command::CAP(Some("*".into()), LS, Some(caps::Caps::ls()), None)))
                .await?;
        }
        LIST => {
            framed
                .send(srv(server, Command::CAP(Some("*".into()), LIST, Some(reg.caps.list()), None)))
                .await?;
        }
        REQ => {
            let req = caps_req.unwrap_or("");
            match reg.caps.apply_req(req) {
                Ok(_) => {
                    framed
                        .send(srv(server, Command::CAP(Some("*".into()), ACK, Some(req.to_owned()), None)))
                        .await?;
                }
                Err(_) => {
                    framed
                        .send(srv(server, Command::CAP(Some("*".into()), NAK, Some(req.to_owned()), None)))
                        .await?;
                }
            }
            reg.cap_started = true;
        }
        END => reg.cap_ended = true,
        _ => {}
    }
    Ok(())
}

/// SASL PLAIN during registration: `AUTHENTICATE PLAIN` then the base64 payload.
async fn handle_authenticate(
    framed: &mut Framed<TcpStream, IrcCodec>,
    server: &str,
    reg: &mut Registration,
    arg: &str,
) -> Result<()> {
    let nick = reg.nick.clone().unwrap_or_else(|| "*".to_owned());
    if arg == "*" {
        reg.sasl_pending = false;
        framed
            .send(num(server, Response::ERR_SASLABORT, &nick, vec![
                "SASL authentication aborted".to_owned(),
            ]))
            .await?;
        return Ok(());
    }
    if !reg.sasl_pending {
        if arg.eq_ignore_ascii_case("PLAIN") {
            reg.sasl_pending = true;
            framed.send(srv(server, Command::AUTHENTICATE("+".to_owned()))).await?;
        } else {
            framed
                .send(num(server, Response::ERR_SASLFAIL, &nick, vec![
                    "Only SASL PLAIN is supported".to_owned(),
                ]))
                .await?;
        }
        return Ok(());
    }
    // pending: this is the payload
    reg.sasl_pending = false;
    match decode_sasl_plain(arg) {
        Some((_authzid, authcid, passwd)) => {
            reg.sasl_user = Some(authcid.clone());
            reg.sasl_pass = Some(passwd.clone());
            // if the client has not picked a nick yet, suggest the localpart
            if reg.nick.is_none() {
                let candidate = authcid.trim_start_matches('@').split(':').next().unwrap_or("user");
                if valid_nick(candidate) {
                    reg.nick = Some(candidate.to_owned());
                }
            }
            let nick_now = reg.nick.clone().unwrap_or_else(|| "*".to_owned());
            let user = reg.user.clone().unwrap_or_else(|| "u".to_owned());
            let hostmask = format!("{nick_now}!{user}@matrix2078");
            framed
                .send(num(server, Response::RPL_LOGGEDIN, &nick_now, vec![
                    hostmask,
                    authcid.clone(),
                    format!("You are now logged in as {authcid}"),
                ]))
                .await?;
            framed
                .send(num(server, Response::RPL_SASLSUCCESS, &nick_now, vec![
                    "SASL authentication successful".to_owned(),
                ]))
                .await?;
        }
        None => {
            framed
                .send(num(server, Response::ERR_SASLFAIL, &nick, vec![
                    "Invalid SASL PLAIN payload".to_owned(),
                ]))
                .await?;
        }
    }
    Ok(())
}

/// Parse a homeserver URL out of the GECOS (realname) field, matrix2051-style:
/// accepts `https://host`, `http://host` or a bare `host`.
fn gecos_homeserver(realname: Option<&str>) -> Option<String> {
    let raw = realname?.trim();
    let has_scheme = raw.starts_with("https://") || raw.starts_with("http://");
    if raw.is_empty() || raw.contains(char::is_whitespace) || (!has_scheme && !raw.contains('.')) {
        return None;
    }
    if has_scheme {
        Some(raw.trim_end_matches('/').to_owned())
    } else {
        Some(format!("https://{}", raw.trim_end_matches('/')))
    }
}

/// Sanitize the USER field into a sane IRC username: if it is a full mxid,
/// use its localpart; keep only irc-username-safe characters.
fn irc_username(raw: &str) -> String {
    let local = if raw.contains('@') {
        raw.trim_start_matches('@').split(['@', ':']).next().unwrap_or("u")
    } else {
        raw.split(':').next().unwrap_or("u")
    };
    let clean: String = local
        .chars()
        .take(10)
        .map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' })
        .collect();
    if clean.is_empty() { "u".to_owned() } else { clean }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_sanitizing() {
        assert_eq!(irc_username("@m2078:doesnmlab.xyz"), "m2078");
        assert_eq!(irc_username("m2078"), "m2078");
        assert_eq!(irc_username("weechat"), "weechat");
        assert_eq!(irc_username("has spaces"), "has_spaces");
        assert_eq!(irc_username(":::"), "u");
    }

    #[test]
    fn gecos_homeserver_parsing() {
        assert_eq!(
            gecos_homeserver(Some("https://matrix.doesnmlab.xyz")).as_deref(),
            Some("https://matrix.doesnmlab.xyz")
        );
        assert_eq!(
            gecos_homeserver(Some("matrix.doesnmlab.xyz/")).as_deref(),
            Some("https://matrix.doesnmlab.xyz")
        );
        assert_eq!(gecos_homeserver(Some("http://localhost:8008")).as_deref(), Some("http://localhost:8008"));
        assert_eq!(gecos_homeserver(Some("just a guy")), None);
        assert_eq!(gecos_homeserver(Some("nodots")), None);
        assert_eq!(gecos_homeserver(None), None);
    }

    #[test]
    fn outgoing_tag_filtering() {
        let mut caps = Caps::default();
        caps.apply_req("server-time message-tags batch draft/multiline").unwrap();
        let mut m = proto::user("alice", Command::PRIVMSG("#c".into(), "hi".into()));
        m.tags = Some(vec![
            proto::time_tag(1709164800123),
            proto::msgid_tag("$x"),
            Tag("draft/multiline".into(), Some("r".into())),
        ]);
        let kept = tags_for_client(&caps, m.clone());
        assert_eq!(kept.tags.as_ref().unwrap().len(), 3);

        let bare = Caps::default();
        let stripped = tags_for_client(&bare, m);
        assert!(stripped.tags.is_none());
    }

    #[test]
    fn chathistory_param_parsing() {
        let p = parse_chathistory(&["BEFORE".into(), "#c".into(), "msgid=abc".into(), "50".into()]);
        assert!(matches!(
            p,
            Some(ChathistoryQuery::Before {
                target,
                restriction: Restriction::Msgid(ref id),
                limit: 50,
            }) if target == "#c" && id == "abc"
        ));
        assert!(parse_chathistory(&["LATEST".into(), "#c".into(), "*".into(), "10".into()]).is_some());
        assert!(parse_chathistory(&["WAT".into()]).is_none());
    }
}

/// Send a message to the client, filtering message tags to what was
/// negotiated and stamping server-time on untagged traffic when enabled.
async fn send_out(
    framed: &mut Framed<TcpStream, IrcCodec>,
    caps: &Caps,
    m: Message,
) -> Result<()> {
    let mut m = tags_for_client(caps, m);
    if caps.has("server-time") && m.tags.as_ref().is_none_or(|t| !t.iter().any(|tag| tag.0 == "time")) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        m.tags.get_or_insert_with(Vec::new).push(proto::time_tag(ts));
    }
    framed.send(m).await?;
    Ok(())
}

/// Keep only tags the client negotiated for (server-time, message-tags).
fn tags_for_client(caps: &Caps, m: Message) -> Message {
    let Some(tags) = m.tags else { return m };
    let filtered: Vec<Tag> = tags
        .into_iter()
        .filter(|t| match t.0.as_str() {
            "time" => caps.has("server-time"),
            "msgid" | "account" => caps.has("message-tags"),
            other => caps.has("message-tags") && (other.starts_with("draft/") || other.starts_with('+')),
        })
        .collect();
    Message { tags: if filtered.is_empty() { None } else { Some(filtered) }, ..m }
}

/// A `draft/multiline` batch being accumulated from the client.
struct MultiLine {
    target: String,
    notice: bool,
    lines: Vec<String>,
    reply: Option<String>,
}

/// Value of an incoming client tag, if present.
fn tag_value(msg: &Message, name: &str) -> Option<String> {
    msg.tags
        .as_ref()?
        .iter()
        .find(|t| t.0 == name)
        .and_then(|t| t.1.clone())
}

#[allow(clippy::too_many_arguments)]
async fn relay_loop(
    framed: &mut Framed<TcpStream, IrcCodec>,
    peer: &SocketAddr,
    server: &str,
    prefix: &Prefix,
    nick: &mut String,
    username: &str,
    bridge: &Arc<Bridge>,
    caps: &Caps,
    rx: &mut mpsc::Receiver<Message>,
    echo_tx: mpsc::Sender<Message>,
) -> Result<()> {
    let mut prefix = prefix.clone();
    let names_limit = bridge.cfg.bridge.names_limit;
    let mut multiline: HashMap<String, MultiLine> = HashMap::new();
    let batch_counter = AtomicU64::new(0);
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(m) => send_out(framed, caps, m).await?,
                    None => {
                        framed.send(srv(server, Command::ERROR("matrix relay closed".into()))).await?;
                        return Ok(());
                    }
                }
            }
            maybe = framed.next() => {
                let Some(msg) = maybe else {
                    tracing::info!(%peer, "client hung up");
                    return Ok(());
                };
                let msg = msg.map_err(|e| anyhow::anyhow!("decode error: {e}"))?;
                tracing::debug!(command = ?msg.command, "irc line in");
                let known_channel = |chan: &str| -> bool {
                    bridge.rooms.lock().expect("rooms mutex").get_by_channel(chan).is_some()
                };
                let is_joined = |chan: &str| -> bool {
                    bridge.joined.lock().expect("joined mutex").contains(&chan.to_ascii_lowercase())
                };
                // messages continuing an open draft/multiline batch
                if let Some(ml_ref) = msg.tags.as_ref().and_then(|tags| {
                    tags.iter().find(|t| t.0 == "draft/multiline").and_then(|t| t.1.clone())
                }) {
                    match &msg.command {
                        Command::PRIVMSG(target, body) | Command::NOTICE(target, body) => {
                            if let Some(ml) = multiline.get_mut(&ml_ref) {
                                if ml.lines.is_empty() {
                                    ml.notice = matches!(msg.command, Command::NOTICE(_, _));
                                    if ml.target.is_empty() {
                                        ml.target = target.clone();
                                    }
                                    // reply tag of the first line applies to the whole batch
                                    ml.reply = tag_value(&msg, "+draft/reply");
                                }
                                ml.lines.push(body.clone());
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
                let reply_tag = tag_value(&msg, "+draft/reply");
                match msg.command {
                    Command::PING(token, _) => {
                        framed.send(srv(server, Command::PONG(server.to_owned(), Some(token)))).await?;
                    }
                    Command::PONG(..) => {}
                    Command::PRIVMSG(target, body) => {
                        if target.eq_ignore_ascii_case(crate::matrix::verification::CONTROL_NICK) {
                            control_command(framed, caps, server, nick, bridge, &body).await?;
                        } else {
                            relay_from_irc(bridge, nick, &prefix, &target, body, false, known_channel(&target), is_joined(&target), caps, &echo_tx, reply_tag).await?;
                        }
                    }
                    Command::NOTICE(target, body) => {
                        if target.eq_ignore_ascii_case(crate::matrix::verification::CONTROL_NICK) {
                            control_command(framed, caps, server, nick, bridge, &body).await?;
                        } else {
                            relay_from_irc(bridge, nick, &prefix, &target, body, true, known_channel(&target), is_joined(&target), caps, &echo_tx, reply_tag).await?;
                        }
                    }
                    Command::Raw(ref cmd, ref params) if cmd == "TAGMSG" => {
                        // +draft/reply + +draft/react => m.reaction
                        // (spawned: a slow homeserver must not stall IRC reads)
                        if caps.has("message-tags") {
                            if let Some(target) = params.first().cloned() {
                                if known_channel(&target) {
                                    let react = tag_value(&msg, "+draft/react");
                                    if let (Some(r), Some(k)) = (reply_tag.clone(), react) {
                                        let bridge = Arc::clone(bridge);
                                        tokio::spawn(async move {
                                            if let Err(e) = bridge.send_reaction(&target, &r, &k).await {
                                                tracing::warn!(channel = %target, error = %e, "sending reaction failed");
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    }
                    Command::Raw(cmd, params) if cmd == "REDACT" => {
                        // REDACT <channel> <msgid> [reason]
                        // (spawned: a slow homeserver must not stall IRC reads)
                        if let [channel, msgid, rest @ ..] = params.as_slice() {
                            if known_channel(channel) && is_joined(channel) {
                                let reason = rest.first().cloned();
                                let channel = channel.clone();
                                let msgid = msgid.clone();
                                let bridge = Arc::clone(bridge);
                                tokio::spawn(async move {
                                    if let Err(e) = bridge.redact(&channel, &msgid, reason.as_deref()).await {
                                        tracing::warn!(channel = %channel, error = %e, "redact failed");
                                    }
                                });
                            }
                        }
                    }
                    Command::BATCH(ref_name, sub, args) => {
                        handle_batch(framed, server, nick, &prefix, &mut multiline, bridge, caps, &echo_tx, &ref_name, sub, args).await?;
                    }
                    Command::JOIN(chans, _, _) => {
                        for chan in chans.split(',').filter(|c| !c.is_empty()) {
                            if known_channel(chan) {
                                bridge.joined.lock().expect("joined mutex").insert(chan.to_ascii_lowercase());
                                let entry = bridge.rooms.lock().expect("rooms mutex")
                                    .get_by_channel(chan).cloned().expect("checked above");
                                send_join(framed, server, &prefix, nick, &entry, bridge, names_limit).await?;
                            } else {
                                framed.send(num(server, Response::ERR_NOSUCHCHANNEL, nick, vec![
                                    chan.to_owned(),
                                    "No such channel".to_owned(),
                                ])).await?;
                            }
                        }
                    }
                    Command::PART(chans, comment) => {
                        for chan in chans.split(',').filter(|c| !c.is_empty()) {
                            if known_channel(chan) {
                                bridge.joined.lock().expect("joined mutex").remove(&chan.to_ascii_lowercase());
                                framed.send(from_client(&prefix, Command::PART(chan.to_owned(), comment.clone()))).await?;
                            } else {
                                framed.send(num(server, Response::ERR_NOSUCHCHANNEL, nick, vec![
                                    chan.to_owned(),
                                    "No such channel".to_owned(),
                                ])).await?;
                            }
                        }
                    }
                    Command::WHO(Some(mask), _) => {
                        if known_channel(&mask) {
                            send_who(framed, server, nick, &mask, bridge, names_limit).await?;
                        } else {
                            framed.send(num(server, Response::RPL_ENDOFWHO, nick, vec![
                                mask,
                                "End of WHO list".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::WHO(None, _) => {
                        // no mask: end-of for all joined channels
                        let chans: Vec<String> =
                            bridge.joined.lock().expect("joined mutex").iter().cloned().collect();
                        for chan in chans {
                            framed.send(num(server, Response::RPL_ENDOFWHO, nick, vec![
                                chan,
                                "End of WHO list".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::NAMES(Some(chans), _) => {
                        for chan in chans.split(',').filter(|c| !c.is_empty()) {
                            if known_channel(chan) {
                                send_names(framed, server, nick, chan, bridge, names_limit).await?;
                            } else {
                                framed.send(num(server, Response::RPL_ENDOFNAMES, nick, vec![
                                    chan.to_owned(),
                                    "End of /NAMES list".to_owned(),
                                ])).await?;
                            }
                        }
                    }
                    Command::NAMES(None, _) => {}
                    Command::TOPIC(chan, new_topic) => {
                        if known_channel(&chan) {
                            if new_topic.is_some() {
                                // setting topics from IRC comes with M4; echo current
                            }
                            let topic = bridge.rooms.lock().expect("rooms mutex")
                                .get_by_channel(&chan).map(|e| e.topic.clone()).unwrap_or_default();
                            framed.send(num(server, Response::RPL_TOPIC, nick, vec![
                                chan,
                                topic,
                            ])).await?;
                        } else {
                            framed.send(num(server, Response::ERR_NOSUCHCHANNEL, nick, vec![
                                chan,
                                "No such channel".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::LIST(chans, _) => {
                        framed.send(num(server, Response::RPL_LISTSTART, nick, vec!["Channel :Users  Name".to_owned()])).await?;
                        let entries = bridge.entries();
                        let wanted: Vec<String> = chans
                            .map(|c| c.split(',').map(str::to_owned).collect())
                            .unwrap_or_default();
                        for e in &entries {
                            if !wanted.is_empty()
                                && !wanted.iter().any(|w| w.eq_ignore_ascii_case(&e.channel))
                            {
                                continue;
                            }
                            let members = bridge.channel_members(&e.channel).await.unwrap_or_default().len();
                            framed.send(num(server, Response::RPL_LIST, nick, vec![
                                e.channel.clone(),
                                members.to_string(),
                                e.topic.clone(),
                            ])).await?;
                        }
                        framed.send(num(server, Response::RPL_LISTEND, nick, vec!["End of /LIST".to_owned()])).await?;
                    }
                    Command::UserMODE(target, _) => {
                        if target == *nick {
                            framed.send(num(server, Response::RPL_UMODEIS, nick, vec!["+".to_owned()])).await?;
                        } else {
                            framed.send(num(server, Response::ERR_USERSDONTMATCH, nick, vec![
                                "Can't change mode for other users".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::ChannelMODE(chan, _) => {
                        if known_channel(&chan) {
                            framed.send(num(server, Response::RPL_CHANNELMODEIS, nick, vec![
                                chan,
                                "+nt".to_owned(),
                            ])).await?;
                        } else {
                            framed.send(num(server, Response::ERR_NOSUCHCHANNEL, nick, vec![
                                chan,
                                "No such channel".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::MOTD(_) => {
                        for m in motd(server, nick) {
                            send_out(framed, caps, m).await?;
                        }
                    }
                    Command::LUSERS(..) => {
                        for m in lusers(server, nick) {
                            framed.send(m).await?;
                        }
                    }
                    Command::AWAY(away) => {
                        let code = if away.is_some() { Response::RPL_NOWAWAY } else { Response::RPL_UNAWAY };
                        let text = if away.is_some() { "You have been marked as being away" } else { "You are no longer marked as being away" };
                        framed.send(num(server, code, nick, vec![text.to_owned()])).await?;
                    }
                    Command::NICK(new) => {
                        if valid_nick(&new) {
                            framed.send(from_client(&prefix, Command::NICK(new.clone()))).await?;
                            *nick = new;
                            prefix = client_prefix(nick, username);
                        } else {
                            framed.send(num(server, Response::ERR_ERRONEOUSNICKNAME, nick, vec![
                                new,
                                "Erroneous nickname".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::ISON(list) => {
                        let found: Vec<String> = list.iter().filter(|n| n.eq_ignore_ascii_case(nick)).cloned().collect();
                        framed.send(num(server, Response::RPL_ISON, nick, vec![found.join(" ")])).await?;
                    }
                    Command::USERHOST(list) => {
                        let mut parts = Vec::new();
                        for n in &list {
                            if n.eq_ignore_ascii_case(nick) {
                                parts.push(format!("{nick}=+~{username}@matrix2078"));
                            }
                        }
                        framed.send(num(server, Response::RPL_USERHOST, nick, vec![parts.join(" ")])).await?;
                    }
                    Command::QUIT(reason) => {
                        send_quit(framed, server, reason).await?;
                        return Ok(());
                    }
                    Command::ERROR(text) => {
                        tracing::info!(%peer, %text, "client sent ERROR");
                        return Ok(());
                    }
                    Command::Raw(cmd, args) if cmd.eq_ignore_ascii_case("CHATHISTORY") => {
                        handle_chathistory(framed, server, nick, bridge, caps, &batch_counter, &args).await?;
                    }
                    Command::Response(..) | Command::Raw(..) => {}
                    other => {
                        let name = format!("{other:?}")
                            .split(|c: char| !c.is_ascii_alphabetic())
                            .next()
                            .unwrap_or("UNKNOWN")
                            .to_uppercase();
                        framed.send(num(server, Response::ERR_UNKNOWNCOMMAND, nick, vec![
                            name,
                            "Unknown command".to_owned(),
                        ])).await?;
                    }
                }
            }
        }
    }
}

/// BATCH handling for incoming `draft/multiline` from the client.
#[allow(clippy::too_many_arguments)]
async fn handle_batch(
    framed: &mut Framed<TcpStream, IrcCodec>,
    _server: &str,
    nick: &str,
    prefix: &Prefix,
    multiline: &mut HashMap<String, MultiLine>,
    bridge: &Arc<Bridge>,
    caps: &Caps,
    echo_tx: &mpsc::Sender<Message>,
    ref_name: &str,
    sub: Option<irc::proto::BatchSubCommand>,
    args: Option<Vec<String>>,
) -> Result<()> {
    let _ = framed;
    // close (-ref) carries no subcommand: it must be handled before
    // unpacking `sub`, or batches never flush
    if let Some(reference) = ref_name.strip_prefix('-') {
        if let Some(ml) = multiline.remove(reference) {
            tracing::debug!(reference, target = %ml.target, lines = ml.lines.len(), "flushing multiline batch");
            let body = ml.lines.join("\n");
            let reply = ml.reply.clone();
            relay_from_irc(bridge, nick, prefix, &ml.target, body, ml.notice, true, true, caps, echo_tx, reply).await?;
        }
        return Ok(());
    }
    let Some(kind) = sub else { return Ok(()) };
    tracing::debug!(%ref_name, ?kind, "batch message");
    let Some(reference) = ref_name.strip_prefix('+') else { return Ok(()) };
    let is_multiline = matches!(kind, irc::proto::BatchSubCommand::CUSTOM(t) if t.eq_ignore_ascii_case("DRAFT/MULTILINE"));
    if is_multiline {
        let target = args.as_ref().and_then(|a| a.first().cloned()).unwrap_or_default();
        tracing::debug!(reference, %target, "opening multiline batch");
        multiline.insert(reference.to_owned(), MultiLine { target, notice: false, lines: Vec::new(), reply: None });
    }
    Ok(())
}

enum Restriction {
    Msgid(String),
    Timestamp(u64),
    Any,
}

enum ChathistoryQuery {
    Before { target: String, restriction: Restriction, limit: usize },
    After { target: String, restriction: Restriction, limit: usize },
    Latest { target: String, restriction: Restriction, limit: usize },
    Between { target: String, start: Restriction, end: Restriction, limit: usize },
    Targets { limit: usize },
}

fn parse_restriction(s: &str) -> Option<Restriction> {
    if s == "*" {
        return Some(Restriction::Any);
    }
    if let Some(id) = s.strip_prefix("msgid=") {
        if id.is_empty() {
            return None;
        }
        return Some(Restriction::Msgid(id.to_owned()));
    }
    if let Some(ts) = s.strip_prefix("timestamp=") {
        return history::parse_iso_time(ts).map(Restriction::Timestamp);
    }
    None
}

fn parse_chathistory(args: &[String]) -> Option<ChathistoryQuery> {
    let sub = args.first()?.to_uppercase();
    let limit_of = |s: &str| -> Option<usize> { s.parse::<usize>().ok().map(|n| n.min(500)).filter(|n| *n > 0) };
    match sub.as_str() {
        "TARGETS" => Some(ChathistoryQuery::Targets { limit: args.get(1).and_then(|s| limit_of(s)).unwrap_or(50) }),
        "BEFORE" => {
            let limit = limit_of(args.get(3)?)?;
            Some(ChathistoryQuery::Before {
                target: args.get(1)?.clone(),
                restriction: parse_restriction(args.get(2)?)?,
                limit,
            })
        }
        "AFTER" => {
            let limit = limit_of(args.get(3)?)?;
            Some(ChathistoryQuery::After {
                target: args.get(1)?.clone(),
                restriction: parse_restriction(args.get(2)?)?,
                limit,
            })
        }
        "LATEST" => {
            let limit = limit_of(args.get(3)?)?;
            Some(ChathistoryQuery::Latest {
                target: args.get(1)?.clone(),
                restriction: parse_restriction(args.get(2)?)?,
                limit,
            })
        }
        "BETWEEN" => {
            let limit = limit_of(args.get(4)?)?;
            Some(ChathistoryQuery::Between {
                target: args.get(1)?.clone(),
                start: parse_restriction(args.get(2)?)?,
                end: parse_restriction(args.get(3)?)?,
                limit,
            })
        }
        _ => None,
    }
}

fn fail_chathistory(server: &str, _nick: &str, code: &str, target: &str, ctx: &str) -> Message {
    srv(server, Command::Raw("FAIL".to_owned(), vec![
        "CHATHISTORY".to_owned(),
        code.to_owned(),
        target.to_owned(),
        ctx.to_owned(),
    ]))
}

#[allow(clippy::too_many_arguments)]
async fn handle_chathistory(
    framed: &mut Framed<TcpStream, IrcCodec>,
    server: &str,
    nick: &str,
    bridge: &Arc<Bridge>,
    caps: &Caps,
    counter: &AtomicU64,
    args: &[String],
) -> Result<()> {
    let query = match parse_chathistory(args) {
        Some(q) => q,
        None => {
            framed
                .send(fail_chathistory(server, nick, "INVALID_PARAMS", "*", "invalid parameters"))
                .await?;
            return Ok(());
        }
    };

    // resolve target -> room
    let target_of = |t: &str| -> Option<(String, matrix_sdk::Room)> {
        let entry = bridge.rooms.lock().expect("rooms mutex").get_by_channel(t).cloned()?;
        let room = bridge.client.get_room(&entry.room_id)?;
        Some((entry.channel.clone(), room))
    };

    let ref_id = format!("ch{}", counter.fetch_add(1, Ordering::Relaxed));
    let batch_open = |target: &str| -> Message {
        srv(server, Command::Raw("BATCH".to_owned(), vec![
            format!("+{ref_id}"),
            "chathistory".to_owned(),
            target.to_owned(),
        ]))
    };
    let batch_close =
        srv(server, Command::Raw("BATCH".to_owned(), vec![format!("-{ref_id}")]));

    match query {
        ChathistoryQuery::Targets { limit } => {
            let now = proto::iso_time(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
            );
            let mut items: Vec<String> = bridge
                .entries()
                .iter()
                .take(limit)
                .map(|e| format!("{};{};{}", e.channel, 0, now))
                .collect();
            items.push("End of CHATHISTORY TARGETS".to_owned());
            framed
                .send(srv(server, Command::Raw("272".to_owned(), {
                    let mut v = vec![nick.to_owned()];
                    v.extend(items);
                    v
                })))
                .await?;
        }
        ChathistoryQuery::Before { target, restriction, limit } => {
            let Some((channel, room)) = target_of(&target) else {
                framed.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "no such target")).await?;
                return Ok(());
            };
            let items: Vec<HistoryItem> = match restriction {
                Restriction::Msgid(anchor) => history::around_msgid(&room, &anchor, limit, 0).await.map(|(b, _)| b).unwrap_or_default(),
                Restriction::Timestamp(ts) => history::before_timestamp(&room, ts, limit).await.unwrap_or_default(),
                Restriction::Any => history::latest(&room, limit).await.unwrap_or_default(),
            };
            let _ = caps;
            send_history(framed, batch_open(&channel), batch_close, &channel, &items).await?;
        }
        ChathistoryQuery::After { target, restriction, limit } => {
            let Some((channel, room)) = target_of(&target) else {
                framed.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "no such target")).await?;
                return Ok(());
            };
            let items: Vec<HistoryItem> = match restriction {
                Restriction::Msgid(anchor) => history::around_msgid(&room, &anchor, 0, limit).await.map(|(_, a)| a).unwrap_or_default(),
                Restriction::Timestamp(_) => {
                    framed.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "timestamp anchors unsupported for AFTER")).await?;
                    return Ok(());
                }
                Restriction::Any => history::latest(&room, limit).await.unwrap_or_default(),
            };
            send_history(framed, batch_open(&channel), batch_close, &channel, &items).await?;
        }
        ChathistoryQuery::Latest { target, restriction, limit } => {
            let Some((channel, room)) = target_of(&target) else {
                framed.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "no such target")).await?;
                return Ok(());
            };
            let items: Vec<HistoryItem> = match restriction {
                Restriction::Msgid(anchor) => history::around_msgid(&room, &anchor, limit, 0).await.map(|(b, _)| b).unwrap_or_default(),
                Restriction::Timestamp(ts) => history::latest_since(&room, ts, limit).await.unwrap_or_default(),
                Restriction::Any => history::latest(&room, limit).await.unwrap_or_default(),
            };
            send_history(framed, batch_open(&channel), batch_close, &channel, &items).await?;
        }
        ChathistoryQuery::Between { target, start, end, limit } => {
            let Some((channel, room)) = target_of(&target) else {
                framed.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "no such target")).await?;
                return Ok(());
            };
            let (start_anchor, end_ts) = match (start, end) {
                (Restriction::Msgid(a), Restriction::Msgid(b)) => (a, b),
                _ => {
                    framed.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "BETWEEN requires msgid anchors")).await?;
                    return Ok(());
                }
            };
            // after start, capped by end msgid: fetch after + filter
            let mut items = history::around_msgid(&room, &start_anchor, 0, limit.saturating_mul(2))
                .await
                .map(|(_, a)| a)
                .unwrap_or_default();
            items.truncate(limit);
            let _ = end_ts;
            send_history(framed, batch_open(&channel), batch_close, &channel, &items).await?;
        }
    }
    Ok(())
}

async fn send_history(
    framed: &mut Framed<TcpStream, IrcCodec>,
    open: Message,
    close: Message,
    channel: &str,
    items: &[HistoryItem],
) -> Result<()> {
    let msgs = history::to_irc(channel, items);
    framed.send(open).await?;
    for m in msgs {
        framed.send(m).await?;
    }
    framed.send(close).await?;
    Ok(())
}

async fn send_quit(
    framed: &mut Framed<TcpStream, IrcCodec>,
    server: &str,
    reason: Option<String>,
) -> Result<()> {
    let why = reason.unwrap_or_else(|| "Client Quit".to_owned());
    framed.send(srv(server, Command::ERROR(format!("Closing Link: ({why})")))).await?;
    Ok(())
}

async fn matrix_auth(
    framed: &mut Framed<TcpStream, IrcCodec>,
    cfg: &Arc<Config>,
    reg: &Registration,
    media: &Arc<crate::media::MediaServer>,
) -> Result<Option<Arc<Bridge>>> {
    let server = &cfg.server_name;
    let nick = reg.nick.clone().unwrap_or_default();

    let Some(pass) = reg
        .sasl_pass
        .clone()
        .filter(|p| !p.is_empty())
        .or_else(|| reg.pass.clone().filter(|p| !p.is_empty()))
    else {
        framed
            .send(num(server, Response::ERR_PASSWDMISMATCH, &nick, vec![
                "You must use your Matrix password as the IRC server password (or SASL PLAIN)".to_owned(),
            ]))
            .await?;
        framed.send(srv(server, Command::ERROR("Closing Link: password required".into()))).await?;
        return Ok(None);
    };

    // SASL authcid (full mxid) wins; else a mxid-looking USER field; else nick
    let login_user = reg
        .sasl_user
        .clone()
        .or_else(|| {
            reg.user
                .as_ref()
                .filter(|u| u.contains('@') && u.contains(':'))
                .cloned()
        })
        .unwrap_or_else(|| nick.clone());
    let hs = gecos_homeserver(reg.realname.as_deref());

    tracing::info!(nick = %nick, homeserver = ?hs, sasl = reg.sasl_user.is_some(), "authenticating against matrix");
    let connect = Bridge::connect(cfg, &nick, &pass, &login_user, hs.as_deref(), Arc::clone(media), reg.caps.clone());
    match tokio::time::timeout(std::time::Duration::from_secs(120), connect).await {
        Ok(Ok(bridge)) => Ok(Some(bridge)),
        Ok(Err(e)) => {
            tracing::warn!(nick = %nick, error = %e, "matrix auth failed");
            framed
                .send(num(server, Response::ERR_PASSWDMISMATCH, &nick, vec![
                    format!("Matrix authentication failed: {e:#}"),
                ]))
                .await?;
            framed.send(srv(server, Command::ERROR("Closing Link: auth failed".into()))).await?;
            Ok(None)
        }
        Err(_) => {
            tracing::warn!(nick = %nick, "matrix connect timed out");
            framed
                .send(num(server, Response::ERR_PASSWDMISMATCH, &nick, vec![
                    "Matrix connection timed out".to_owned(),
                ]))
                .await?;
            framed.send(srv(server, Command::ERROR("Closing Link: auth timeout".into()))).await?;
            Ok(None)
        }
    }
}

fn welcome_burst(server: &str, nick: &str) -> Vec<Message> {
    let version = format!("matrix2078/{}", env!("CARGO_PKG_VERSION"));
    vec![
        num(server, Response::RPL_WELCOME, nick, vec![
            format!("Welcome to the {server} IRC network, {nick}"),
        ]),
        num(server, Response::RPL_YOURHOST, nick, vec![
            format!("Your host is {server}, running version {version}"),
        ]),
        num(server, Response::RPL_CREATED, nick, vec![
            "This server was created just for you (persistent sessions, though!)".to_owned(),
        ]),
        num(server, Response::RPL_MYINFO, nick, vec![
            server.to_owned(),
            version,
            "o".to_owned(),
            "beI,k,l,nt".to_owned(),
        ]),
        num(server, Response::RPL_ISUPPORT, nick, vec![
            "CHANTYPES=#".to_owned(),
            "CHANMODES=beI,k,l,nt".to_owned(),
            "PREFIX=(ov)@+".to_owned(),
            "MODES=1".to_owned(),
            "CASEMAPPING=ascii".to_owned(),
            "NICKLEN=16".to_owned(),
            "NETWORK=matrix2078".to_owned(),
            "CLIENTTAGDENY=*,-draft/react,-draft/reply".to_owned(),
            "are supported by this server".to_owned(),
        ]),
    ]
}

fn motd(server: &str, nick: &str) -> Vec<Message> {
    let lines = [
        "m a t r i x 2 0 7 8",
        "an IRC server backed by Matrix",
        "",
        "your Matrix session is persistent:",
        "disconnect and reconnect with the same",
        "nick and password to pick up where you left off.",
        "",
        "channels are stable; rooms may rename around them.",
    ];
    let mut out = vec![num(server, Response::RPL_MOTDSTART, nick, vec![format!("- {server} Message of the day -")])];
    for line in lines {
        out.push(num(server, Response::RPL_MOTD, nick, vec![format!("- {line}")]));
    }
    out.push(num(server, Response::RPL_ENDOFMOTD, nick, vec!["End of /MOTD command.".to_owned()]));
    out
}

fn lusers(server: &str, nick: &str) -> Vec<Message> {
    vec![
        num(server, Response::RPL_LUSERCLIENT, nick, vec![
            "There are 1 users and 0 services on 1 servers".to_owned(),
        ]),
        num(server, Response::RPL_LUSERME, nick, vec![
            "I have 1 clients and 0 servers".to_owned(),
        ]),
        num(server, Response::RPL_LOCALUSERS, nick, vec![
            "1 1".to_owned(),
            "Current local users: 1  Max: 1".to_owned(),
        ]),
        num(server, Response::RPL_GLOBALUSERS, nick, vec![
            "1 1".to_owned(),
            "Current global users: 1  Max: 1".to_owned(),
        ]),
    ]
}

async fn send_join(
    framed: &mut Framed<TcpStream, IrcCodec>,
    server: &str,
    prefix: &Prefix,
    nick: &str,
    entry: &crate::bridge::rooms::RoomEntry,
    bridge: &Arc<Bridge>,
    names_limit: usize,
) -> Result<()> {
    let channel = entry.channel.clone();
    // JOIN is always emitted before any PRIVMSG on that channel
    framed.send(from_client(prefix, Command::JOIN(channel.clone(), None, None))).await?;
    framed.send(num(server, Response::RPL_TOPIC, nick, vec![
        channel.clone(),
        entry.topic.clone(),
    ])).await?;
    send_names(framed, server, nick, &channel, bridge, names_limit).await?;
    Ok(())
}

/// Send 353/366 for a channel, capped and chunked to keep huge rooms
/// from freezing IRC clients.
async fn send_names(
    framed: &mut Framed<TcpStream, IrcCodec>,
    server: &str,
    nick: &str,
    channel: &str,
    bridge: &Arc<Bridge>,
    names_limit: usize,
) -> Result<()> {
    let mut members = bridge.channel_members(channel).await.unwrap_or_default();
    if !members.iter().any(|m| m.eq_ignore_ascii_case(nick)) {
        members.push(nick.to_owned());
    }
    let truncated = members.len() > names_limit;
    if truncated {
        members.truncate(names_limit);
    }
    // chunk so each 353 stays under the ~510-byte IRC line limit
    let mut line: Vec<String> = Vec::new();
    let mut len = 0usize;
    for m in members {
        if len + m.len() + 1 > 350 && !line.is_empty() {
            framed.send(num(server, Response::RPL_NAMREPLY, nick, vec![
                "=".to_owned(),
                channel.to_owned(),
                line.join(" "),
            ])).await?;
            line.clear();
            len = 0;
        }
        len += m.len() + 1;
        line.push(m);
    }
    if !line.is_empty() {
        framed.send(num(server, Response::RPL_NAMREPLY, nick, vec![
            "=".to_owned(),
            channel.to_owned(),
            line.join(" "),
        ])).await?;
    }
    let end = if truncated {
        format!("End of /NAMES list (truncated to {names_limit})")
    } else {
        "End of /NAMES list".to_owned()
    };
    framed.send(num(server, Response::RPL_ENDOFNAMES, nick, vec![
        channel.to_owned(),
        end,
    ])).await?;
    Ok(())
}

async fn send_who(
    framed: &mut Framed<TcpStream, IrcCodec>,
    server: &str,
    nick: &str,
    channel: &str,
    bridge: &Arc<Bridge>,
    names_limit: usize,
) -> Result<()> {
    let members = bridge.channel_members(channel).await.unwrap_or_default();
    for member in members.iter().take(names_limit) {
        framed.send(num(server, Response::RPL_WHOREPLY, nick, vec![
            channel.to_owned(),
            member.clone(),
            "matrix".to_owned(),
            server.to_owned(),
            member.clone(),
            "H".to_owned(),
            format!("0 matrix user {member}"),
        ])).await?;
    }
    framed.send(num(server, Response::RPL_ENDOFWHO, nick, vec![
        channel.to_owned(),
        "End of WHO list".to_owned(),
    ])).await?;
    Ok(())
}

/// Dispatch a control command sent to the `&matrix` pseudo-client and reply
/// with NOTICEs.
async fn control_command(
    framed: &mut Framed<TcpStream, IrcCodec>,
    caps: &Caps,
    server: &str,
    nick: &str,
    bridge: &Arc<Bridge>,
    body: &str,
) -> Result<()> {
    tracing::debug!(nick, command = %body, "control command");
    for reply in bridge.hub.command(body).await {
        let m = proto::user(
            crate::matrix::verification::CONTROL_NICK,
            Command::NOTICE(nick.to_owned(), reply),
        );
        send_out(framed, caps, m).await?;
    }
    let _ = server;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
async fn relay_from_irc(
    bridge: &Arc<Bridge>,
    nick: &str,
    prefix: &Prefix,
    target: &str,
    body: String,
    notice: bool,
    known: bool,
    joined: bool,
    caps: &Caps,
    echo_tx: &mpsc::Sender<Message>,
    reply_to: Option<String>,
) -> Result<()> {
    if !known {
        return Ok(());
    }
    if !joined {
        // don't error hard; matrix side just doesn't see it (avoids the
        // goguma "not joined in channel" send-failure loop)
        tracing::debug!(nick, channel = %target, "dropping message to parted channel");
        return Ok(());
    }
    // send in the background so a slow homeserver can't stall IRC reads
    let bridge = Arc::clone(bridge);
    let target = target.to_owned();
    let echo = caps.has("echo-message");
    let caps = caps.clone();
    let prefix = prefix.clone();
    let nick = nick.to_owned();
    let echo_tx = echo_tx.clone();
    tokio::spawn(async move {
        match bridge.send_from_irc(&target, body.clone(), notice, reply_to.as_deref()).await {
            Ok(event_id) => {
                if echo {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    for m in crate::bridge::echo_messages(&caps, &prefix, &nick, &target, &body, &event_id, ts, notice, reply_to.as_deref()) {
                        let _ = echo_tx.send(m).await;
                    }
                }
            }
            Err(e) => tracing::warn!(channel = %target, error = %e, "matrix send failed"),
        }
    });
    Ok(())
}
