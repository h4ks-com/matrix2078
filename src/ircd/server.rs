//! Minimal IRC server: TCP listener, registration, core commands,
//! and the Matrix-backed relay loop.

use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use irc::proto::{CapSubCommand, Command, IrcCodec, Message, Prefix, Response};
use tokio::{net::{TcpListener, TcpStream}, sync::mpsc};
use tokio_util::codec::Framed;

use crate::{
    bridge::Bridge,
    config::Config,
    ircd::{
        proto::{client_prefix, from_client, num, srv},
        session::{Registration, valid_nick},
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
            Command::CAP(_, sub, caps, _) => match sub {
                CapSubCommand::LS => {
                    reg.cap_started = true;
                    framed
                        .send(srv(&server, Command::CAP(Some("*".into()), CapSubCommand::LS, Some(String::new()), None)))
                        .await?;
                }
                CapSubCommand::LIST => {
                    framed
                        .send(srv(&server, Command::CAP(Some("*".into()), CapSubCommand::LIST, Some(String::new()), None)))
                        .await?;
                }
                CapSubCommand::REQ => {
                    framed
                        .send(srv(&server, Command::CAP(Some("*".into()), CapSubCommand::NAK, caps, None)))
                        .await?;
                }
                CapSubCommand::END => reg.cap_ended = true,
                _ => {}
            },
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
    let mut nick = reg.nick.clone().unwrap_or_default();
    let username = irc_username(reg.user.as_deref().unwrap_or("u"));
    let prefix = client_prefix(&nick, &username);

    for m in welcome_burst(&server, &nick) {
        framed.send(m).await?;
    }

    // JOIN every mapped room's channel before any PRIVMSG can reference it
    for entry in bridge.entries() {
        bridge.joined.lock().expect("joined mutex").insert(entry.channel.to_ascii_lowercase());
        send_join(&mut framed, &server, &prefix, &nick, &entry, &bridge, cfg.bridge.names_limit)
            .await?;
    }

    let (tx, mut rx) = mpsc::channel::<Message>(256);
    bridge.relay_matrix_to_irc(tx);
    let sync_task = bridge.spawn_sync();

    let result =
        relay_loop(&mut framed, &peer, &server, &prefix, &mut nick, &username, &bridge, &mut rx)
            .await;
    // the matrix sync loop must not outlive the IRC connection: it holds the
    // device's sync position and would block the next session of this user
    sync_task.abort();
    result
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
    rx: &mut mpsc::Receiver<Message>,
) -> Result<()> {
    let mut prefix = prefix.clone();
    let names_limit = bridge.cfg.bridge.names_limit;
    loop {
        tokio::select! {
            maybe = rx.recv() => {
                match maybe {
                    Some(m) => framed.send(m).await?,
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
                let known_channel = |chan: &str| -> bool {
                    bridge.rooms.lock().expect("rooms mutex").get_by_channel(chan).is_some()
                };
                let is_joined = |chan: &str| -> bool {
                    bridge.joined.lock().expect("joined mutex").contains(&chan.to_ascii_lowercase())
                };
                match msg.command {
                    Command::PING(token, _) => {
                        framed.send(srv(server, Command::PONG(server.to_owned(), Some(token)))).await?;
                    }
                    Command::PONG(..) => {}
                    Command::PRIVMSG(target, body) => {
                        relay_from_irc(bridge, nick, &target, body, false, known_channel(&target), is_joined(&target)).await?;
                    }
                    Command::NOTICE(target, body) => {
                        relay_from_irc(bridge, nick, &target, body, true, known_channel(&target), is_joined(&target)).await?;
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
                            if let Some(_) = new_topic {
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
                            framed.send(m).await?;
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

    let Some(pass) = reg.pass.clone().filter(|p| !p.is_empty()) else {
        framed
            .send(num(server, Response::ERR_PASSWDMISMATCH, &nick, vec![
                "You must use your Matrix password as the IRC server password".to_owned(),
            ]))
            .await?;
        framed.send(srv(server, Command::ERROR("Closing Link: password required".into()))).await?;
        return Ok(None);
    };

    let login_user = match &reg.user {
        Some(u) if u.contains('@') && u.contains(':') => u.clone(),
        _ => nick.clone(),
    };
    let hs = gecos_homeserver(reg.realname.as_deref());

    tracing::info!(nick = %nick, homeserver = ?hs, "authenticating against matrix");
    let connect = Bridge::connect(cfg, &nick, &pass, &login_user, hs.as_deref(), Arc::clone(media));
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

async fn relay_from_irc(
    bridge: &Arc<Bridge>,
    nick: &str,
    target: &str,
    body: String,
    notice: bool,
    known: bool,
    joined: bool,
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
    tokio::spawn(async move {
        if let Err(e) = bridge.send_from_irc(&target, body, notice).await {
            tracing::warn!(channel = %target, error = %e, "matrix send failed");
        }
    });
    Ok(())
}
