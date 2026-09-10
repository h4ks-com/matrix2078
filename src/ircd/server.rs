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
};

pub async fn run(cfg: Arc<Config>) -> Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    tracing::info!(listen = %cfg.listen, server = %cfg.server_name, "ircd listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::info!(%peer, "client connected");
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, peer, cfg).await {
                tracing::info!(%peer, error = %e, "connection closed with error");
            } else {
                tracing::info!(%peer, "connection closed");
            }
        });
    }
}

async fn handle_conn(stream: TcpStream, peer: SocketAddr, cfg: Arc<Config>) -> Result<()> {
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
            match matrix_auth(&mut framed, &cfg, &reg).await? {
                Some(bridge) => break bridge,
                None => return Ok(()),
            }
        }
    };

    // ---------------- post-registration ----------------
    let mut nick = reg.nick.clone().unwrap_or_default();
    let username = irc_username(reg.user.as_deref().unwrap_or("u"));
    let prefix = client_prefix(&nick, &username);
    let channel = bridge.channel.clone();

    for m in welcome_burst(&server, &nick) {
        framed.send(m).await?;
    }

    // force-join the relayed channel before any PRIVMSG can reference it
    send_join(&mut framed, &server, &prefix, &nick, &bridge).await?;

    let (tx, mut rx) = mpsc::channel::<Message>(64);
    bridge.relay_matrix_to_irc(tx);
    let sync_task = bridge.spawn_sync();

    let result = relay_loop(&mut framed, &peer, &server, &prefix, &mut nick, &username, &channel, &bridge, &mut rx).await;
    // the matrix sync loop must not outlive the IRC connection: it holds the
    // device's sync position and would block the next session of this user
    sync_task.abort();
    result
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
}

#[allow(clippy::too_many_arguments)]
async fn relay_loop(
    framed: &mut Framed<TcpStream, IrcCodec>,
    peer: &SocketAddr,
    server: &str,
    prefix: &Prefix,
    nick: &mut String,
    username: &str,
    channel: &str,
    bridge: &Bridge,
    rx: &mut mpsc::Receiver<Message>,
) -> Result<()> {
    let mut prefix = prefix.clone();
    let mut joined = true;
    let server_owned = server.to_owned();
    let server = server_owned.as_str();
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
                match msg.command {
                    Command::PING(token, _) => {
                        framed.send(srv(server, Command::PONG(server.to_owned(), Some(token)))).await?;
                    }
                    Command::PONG(..) => {}
                    Command::PRIVMSG(target, body) => {
                        relay_from_irc(framed, bridge, server, nick, &target, body, false, joined).await?;
                    }
                    Command::NOTICE(target, body) => {
                        relay_from_irc(framed, bridge, server, nick, &target, body, true, joined).await?;
                    }
                    Command::JOIN(chans, _, _) => {
                        for chan in chans.split(',').filter(|c| !c.is_empty()) {
                            if chan.eq_ignore_ascii_case(channel) {
                                joined = true;
                                send_join(framed, server, &prefix, nick, bridge).await?;
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
                            if chan.eq_ignore_ascii_case(channel) {
                                joined = false;
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
                        if mask.eq_ignore_ascii_case(channel) {
                            send_who(framed, server, nick, channel, &bridge.members).await?;
                        } else {
                            framed.send(num(server, Response::RPL_ENDOFWHO, nick, vec![
                                mask,
                                "End of WHO list".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::WHO(None, _) => {
                        send_who(framed, server, nick, channel, &bridge.members).await?;
                    }
                    Command::TOPIC(chan, _) => {
                        if chan.eq_ignore_ascii_case(channel) {
                            framed.send(num(server, Response::RPL_TOPIC, nick, vec![
                                channel.to_owned(),
                                bridge.topic.clone(),
                            ])).await?;
                        } else {
                            framed.send(num(server, Response::ERR_NOSUCHCHANNEL, nick, vec![
                                chan,
                                "No such channel".to_owned(),
                            ])).await?;
                        }
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
                        if chan.eq_ignore_ascii_case(channel) {
                            framed.send(num(server, Response::RPL_CHANNELMODEIS, nick, vec![
                                channel.to_owned(),
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
) -> Result<Option<Bridge>> {
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

    tracing::info!(nick = %nick, "authenticating against matrix");
    let connect = Bridge::connect(cfg, &nick, &pass, &login_user);
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
    bridge: &Bridge,
) -> Result<()> {
    let channel = &bridge.channel;
    // JOIN is always emitted before any PRIVMSG on that channel
    framed.send(from_client(prefix, Command::JOIN(channel.clone(), None, None))).await?;
    framed.send(num(server, Response::RPL_TOPIC, nick, vec![
        channel.clone(),
        bridge.topic.clone(),
    ])).await?;
    let mut members = bridge.members.clone();
    if !members.iter().any(|m| m.eq_ignore_ascii_case(nick)) {
        members.push(nick.to_owned());
    }
    framed.send(num(server, Response::RPL_NAMREPLY, nick, vec![
        "=".to_owned(),
        channel.clone(),
        members.join(" "),
    ])).await?;
    framed.send(num(server, Response::RPL_ENDOFNAMES, nick, vec![
        channel.clone(),
        "End of /NAMES list".to_owned(),
    ])).await?;
    Ok(())
}

async fn send_who(
    framed: &mut Framed<TcpStream, IrcCodec>,
    server: &str,
    nick: &str,
    channel: &str,
    members: &[String],
) -> Result<()> {
    for member in members {
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
    framed: &mut Framed<TcpStream, IrcCodec>,
    bridge: &Bridge,
    server: &str,
    nick: &str,
    target: &str,
    body: String,
    notice: bool,
    joined: bool,
) -> Result<()> {
    if !target.eq_ignore_ascii_case(&bridge.channel) {
        framed.send(num(server, Response::ERR_NOSUCHNICK, nick, vec![
            target.to_owned(),
            "No such nick/channel".to_owned(),
        ])).await?;
        return Ok(());
    }
    if !joined {
        framed.send(num(server, Response::ERR_NOTONCHANNEL, nick, vec![
            target.to_owned(),
            "You're not on that channel".to_owned(),
        ])).await?;
        return Ok(());
    }
    // send in the background so a slow homeserver can't stall IRC reads
    let bridge = bridge.clone();
    tokio::spawn(async move {
        if let Err(e) = bridge.send_from_irc(body, notice).await {
            tracing::warn!(error = %e, "matrix send failed");
        }
    });
    Ok(())
}
