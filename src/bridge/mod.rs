//! Bridge: all joined Matrix rooms ⇄ stable IRC channels, both directions.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use irc::proto::{Command, Message};
use matrix_sdk::{
    Client, Room, RoomState,
    config::SyncSettings,
    ruma::{
        OwnedRoomId,
        events::{
            presence::PresenceEvent,
            room::{
                MediaSource,
                message::{MessageType, RoomMessageEventContent, SyncRoomMessageEvent},
                name::SyncRoomNameEvent,
                topic::SyncRoomTopicEvent,
            },
        },
    },
};
use tokio::sync::mpsc;

use crate::{
    bridge::rooms::{RoomEntry, RoomMaps},
    config::Config,
    ircd::{caps::Caps, proto},
    matrix::client::login_or_restore,
    matrix::verification::VerificationHub,
    media::MediaServer,
};

pub mod history;
pub mod rooms;

/// Shared per-user bridge state visible to event handlers.
pub struct Bridge {
    pub client: Client,
    pub own_mxid: matrix_sdk::ruma::OwnedUserId,
    pub rooms: Arc<Mutex<RoomMaps>>,
    /// IRC channels the client currently occupies (lowercase).
    pub joined: Arc<Mutex<HashSet<String>>>,
    pub cfg: Arc<Config>,
    pub media: Arc<MediaServer>,
    /// Capabilities negotiated by the owning IRC connection.
    pub caps: Caps,
    /// SAS verification flows driven through the `&matrix` pseudo-client.
    pub hub: Arc<VerificationHub>,
}

impl Bridge {
    /// Log in / restore the Matrix session, do the initial sync and build
    /// the room→channel mapping for every joined (non-space) room.
    pub async fn connect(
        cfg: &Arc<Config>,
        nick: &str,
        irc_pass: &str,
        login_user: &str,
        hs_override: Option<&str>,
        media: Arc<MediaServer>,
        caps: Caps,
    ) -> Result<Arc<Self>> {
        let client = login_or_restore(cfg, nick, irc_pass, login_user, hs_override).await?;

        client
            .sync_once(SyncSettings::default().ignore_timeout_on_first_sync(true))
            .await
            .context("initial matrix sync failed")?;
        let own_mxid = client
            .user_id()
            .map(|u| u.to_owned())
            .ok_or_else(|| anyhow::anyhow!("client has no user id after sync"))?;
        let hub = VerificationHub::new(client.clone(), own_mxid.clone(), nick);

        let maps_path = channels_path(&cfg.state_dir, &crate::matrix::client::state_key(nick, login_user));
        let mut maps = RoomMaps::load(maps_path);
        let live: HashSet<OwnedRoomId> =
            client.joined_rooms().iter().map(|r| r.room_id().to_owned()).collect();
        maps.prune_to(&live);
        for room in client.joined_rooms() {
            if room.is_space() {
                continue;
            }
            let (base, topic) = Self::room_label(&room).await;
            maps.ensure(room.room_id().to_owned(), &base, topic);
        }

        Ok(Arc::new(Self {
            client: client.clone(),
            own_mxid,
            rooms: Arc::new(Mutex::new(maps)),
            joined: Arc::new(Mutex::new(HashSet::new())),
            cfg: cfg.clone(),
            media,
            caps,
            hub,
        }))
    }

    /// Preferred channel base (without `#`) and topic for a room.
    async fn room_label(room: &Room) -> (String, String) {
        let alias = room.canonical_alias().map(|a| {
            a.alias()
                .trim_start_matches('#')
                .split(':')
                .next()
                .unwrap_or("")
                .to_owned()
        }).filter(|l| !l.is_empty());
        let base = match alias {
            Some(a) => a,
            None => match room.name().filter(|n| !n.is_empty()) {
                Some(n) => n,
                None => room
                    .display_name()
                    .await
                    .ok()
                    .and_then(display_string)
                    .filter(|d| !d.is_empty())
                    .unwrap_or_else(|| room.room_id().to_string()),
            },
        };
        let topic = room
            .topic()
            .filter(|t| !t.is_empty())
            .or_else(|| room.name().filter(|n| !n.is_empty()))
            .unwrap_or_else(|| format!("Matrix room {}", room.room_id()));
        (base, topic.replace('\n', " | ").replace('\r', ""))
    }

    /// Members of the room mapped to `channel`, as IRC nicks.
    pub async fn channel_members(&self, channel: &str) -> Option<Vec<String>> {
        let room_id = {
            let maps = self.rooms.lock().expect("rooms mutex");
            maps.get_by_channel(channel).map(|e| e.room_id.clone())
        }?;
        let room = self.client.get_room(&room_id)?;
        let members = room
            .members(matrix_sdk::RoomMemberships::JOIN)
            .await
            .unwrap_or_default();
        Some(
            members
                .iter()
                .map(|m| proto::mxid_to_nick(m.user_id().as_str()))
                .collect(),
        )
    }

    /// Register event handlers pushing relayed IRC lines into `tx`.
    pub fn relay_matrix_to_irc(&self, tx: mpsc::Sender<Message>) {
        self.hub.attach(tx.clone());
        self.message_handler(tx.clone());
        self.topic_handler(tx.clone());
        self.encrypted_handler(tx.clone());
        self.presence_handler(tx);
    }

    fn message_handler(&self, tx: mpsc::Sender<Message>) {
        let rooms = Arc::clone(&self.rooms);
        let joined = Arc::clone(&self.joined);
        let own = self.own_mxid.clone();
        let cfg = Arc::clone(&self.cfg);
        let media = Arc::clone(&self.media);
        let caps = self.caps.clone();
        let hub = Arc::clone(&self.hub);
        self.client.add_event_handler(
            move |ev: SyncRoomMessageEvent, room: Room, client: Client| {
                let tx = tx.clone();
                let rooms = Arc::clone(&rooms);
                let joined = Arc::clone(&joined);
                let own = own.clone();
                let cfg = Arc::clone(&cfg);
                let media = Arc::clone(&media);
                let caps = caps.clone();
                let hub = Arc::clone(&hub);
                async move {
                    let matrix_sdk::ruma::events::SyncMessageLikeEvent::Original(ev) = ev else {
                        return;
                    };
                    // edits arrive as separate m.replace events; skip them for now
                    if let Some(rel) = &ev.content.relates_to {
                        if rel.rel_type()
                            == Some(matrix_sdk::ruma::events::relation::RelationType::Replacement)
                        {
                            return;
                        }
                    }
                    if room.state() != RoomState::Joined {
                        return;
                    }
                    let sender = ev.sender.clone();
                    if sender == own {
                        return;
                    }

                    // in-room verification requests: route to the &matrix flow
                    if let MessageType::VerificationRequest(c) = &ev.content.msgtype {
                        hub.register_by_flow(&sender, ev.event_id.as_str()).await;
                        let _ = tx
                            .send(proto::user(
                                crate::matrix::verification::CONTROL_NICK,
                                Command::NOTICE(
                                    "*".to_owned(),
                                    format!(
                                        "verification request from {} in this room — \
                                         /msg {} verify accept",
                                        sender,
                                        crate::matrix::verification::CONTROL_NICK
                                    ),
                                ),
                            ))
                            .await;
                        return;
                    }

                    // find or create the room mapping
                    let entry = {
                        let maps = rooms.lock().expect("rooms mutex");
                        maps.get_by_room(room.room_id()).cloned()
                    };
                    let entry = match entry {
                        Some(e) => e,
                        None => {
                            let (base, topic) = Bridge::room_label(&room).await;
                            let mut maps = rooms.lock().expect("rooms mutex");
                            maps.ensure(room.room_id().to_owned(), &base, topic).clone()
                        }
                    };
                    let channel = entry.channel.clone();

                    let body = match render_body(&ev.content.msgtype, &client, &media, &cfg).await
                    {
                        Some(b) => b,
                        None => return,
                    };

                    // JOIN must always be emitted before any PRIVMSG on a channel
                    let need_join = {
                        let mut j = joined.lock().expect("joined mutex");
                        let lower = channel.to_ascii_lowercase();
                        if j.contains(&lower) {
                            false
                        } else {
                            j.insert(lower);
                            true
                        }
                    };
                    let nick = proto::mxid_to_nick(sender.as_str());
                    if need_join {
                        let _ = tx
                            .send(proto::user(&nick, Command::JOIN(channel.clone(), None, None)))
                            .await;
                        let _ = tx
                            .send(proto::srv(
                                &cfg.server_name,
                                Command::Response(
                                    irc::proto::Response::RPL_TOPIC,
                                    vec!["*".into(), channel.clone(), entry.topic.clone()],
                                ),
                            ))
                            .await;
                    }

                    let ts = u64::from(ev.origin_server_ts.get());
                    let msgid = ev.event_id.to_string();
                    let is_notice = matches!(&ev.content.msgtype, MessageType::Notice(_));
                    let is_emote = matches!(&ev.content.msgtype, MessageType::Emote(_));
                    let sender_prefix = proto::user_prefix(&nick);
                    let msgs = body_to_irc(&caps, &sender_prefix, &channel, &body, &msgid, ts, is_notice, is_emote);
                    for m in msgs {
                        let _ = tx.send(m).await;
                    }
                }
            },
        );
    }

    /// away-notify: mirror Matrix presence changes of other users.
    fn presence_handler(&self, tx: mpsc::Sender<Message>) {
        let seen_away: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        self.client.add_event_handler(
            move |ev: PresenceEvent| {
                let tx = tx.clone();
                let seen = Arc::clone(&seen_away);
                async move {
                    let nick = proto::mxid_to_nick(ev.sender.as_str());
                    let away = ev.content.presence
                        == matrix_sdk::ruma::presence::PresenceState::Unavailable;
                    let fire = {
                        let mut s = seen.lock().expect("away mutex");
                        let known = s.contains(&nick);
                        if away && !known {
                            s.insert(nick.clone());
                            true
                        } else if !away && known {
                            s.remove(&nick);
                            true
                        } else {
                            false
                        }
                    };
                    if fire {
                        let reason = ev
                            .content
                            .status_msg
                            .clone()
                            .unwrap_or_else(|| "away".to_owned());
                        let cmd = if away {
                            Command::AWAY(Some(reason))
                        } else {
                            Command::AWAY(None)
                        };
                        let _ = tx.send(proto::user(&nick, cmd)).await;
                    }
                }
            },
        );
    }

    /// Messages we could not decrypt (room keys missing): surface them as
    /// placeholder lines instead of silently dropping.
    fn encrypted_handler(&self, tx: mpsc::Sender<Message>) {
        let rooms = Arc::clone(&self.rooms);
        let joined = Arc::clone(&self.joined);
        let own = self.own_mxid.clone();
        self.client.add_event_handler(
            move |ev: matrix_sdk::ruma::events::room::encrypted::SyncRoomEncryptedEvent,
                  room: Room| {
                let tx = tx.clone();
                let rooms = Arc::clone(&rooms);
                let joined = Arc::clone(&joined);
                let own = own.clone();
                async move {
                    let matrix_sdk::ruma::events::SyncMessageLikeEvent::Original(ev) = ev else {
                        return;
                    };
                    if room.state() != RoomState::Joined || ev.sender == own {
                        return;
                    }
                    let Some(entry) = ({
                        let maps = rooms.lock().expect("rooms mutex");
                        maps.get_by_room(room.room_id()).cloned()
                    }) else {
                        return;
                    };
                    let channel = entry.channel.clone();
                    let need_join = {
                        let mut j = joined.lock().expect("joined mutex");
                        let lower = channel.to_ascii_lowercase();
                        if j.contains(&lower) {
                            false
                        } else {
                            j.insert(lower);
                            true
                        }
                    };
                    if need_join {
                        let _ = tx
                            .send(proto::user(
                                &proto::mxid_to_nick(ev.sender.as_str()),
                                Command::JOIN(channel.clone(), None, None),
                            ))
                            .await;
                    }
                    let nick = proto::mxid_to_nick(ev.sender.as_str());
                    let ts = u64::from(ev.origin_server_ts.get());
                    let mut m = proto::user(
                        &nick,
                        Command::NOTICE(
                            channel.clone(),
                            "\u{1f512} [unable to decrypt — keys not available yet]".to_owned(),
                        ),
                    );
                    m.tags = Some(vec![proto::time_tag(ts), proto::msgid_tag(&ev.event_id.to_string())]);
                    let _ = tx.send(m).await;
                }
            },
        );
    }

    fn topic_handler(&self, tx: mpsc::Sender<Message>) {
        let tx_topic = tx.clone();
        let rooms_topic = Arc::clone(&self.rooms);

        self.client.add_event_handler(
            move |ev: SyncRoomTopicEvent, room: Room| {
                let mut tx = tx_topic.clone();
                let rooms = Arc::clone(&rooms_topic);
                async move {
                    let matrix_sdk::ruma::events::SyncStateEvent::Original(ev) = ev else {
                        return;
                    };
                    push_topic(&mut tx, &rooms, &room, ev.content.topic).await;
                }
            },
        );
        let rooms2 = Arc::clone(&self.rooms);
        self.client.add_event_handler(
            move |ev: SyncRoomNameEvent, room: Room| {
                let mut tx = tx.clone();
                let rooms = Arc::clone(&rooms2);
                async move {
                    let matrix_sdk::ruma::events::SyncStateEvent::Original(ev) = ev else {
                        return;
                    };
                    push_topic(&mut tx, &rooms, &room, ev.content.name).await;
                }
            },
        );
    }

    /// Keep the sync loop running in the background. The returned handle
    /// must be aborted when the owning IRC connection goes away.
    pub fn spawn_sync(&self) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        tokio::spawn(sync_forever(client))
    }

    /// Deliver an IRC line to the mapped Matrix room. Returns the new event id.
    pub async fn send_from_irc(
        &self,
        channel: &str,
        body: String,
        notice: bool,
    ) -> Result<String> {
        let room_id = {
            let maps = self.rooms.lock().expect("rooms mutex");
            maps.get_by_channel(channel).map(|e| e.room_id.clone())
        };
        let Some(room_id) = room_id else {
            anyhow::bail!("no room mapped for channel {channel}");
        };
        let Some(room) = self.client.get_room(&room_id) else {
            anyhow::bail!("lost room {}", room_id.as_str());
        };
        let content = if notice {
            RoomMessageEventContent::notice_plain(body)
        } else {
            RoomMessageEventContent::text_plain(body)
        };
        let resp = room
            .send(content)
            .await
            .context("sending message to matrix room")?;
        Ok(resp.response.event_id.to_string())
    }

    /// Snapshot of mapped rooms for the initial JOIN burst.
    pub fn entries(&self) -> Vec<RoomEntry> {
        self.rooms.lock().expect("rooms mutex").entries().to_vec()
    }
}

/// Build outgoing IRC message(s) for a Matrix body:
/// - multiline-capable clients get a `draft/multiline` batch;
/// - everyone else gets one PRIVMSG per line, word-wrapped.
fn body_to_irc(
    caps: &Caps,
    sender: &irc::proto::Prefix,
    channel: &str,
    body: &str,
    msgid: &str,
    ts: u64,
    notice: bool,
    emote: bool,
) -> Vec<Message> {
    let lines = wrap_body(body);
    let mk_cmd = |line: String| -> Command {
        if notice {
            Command::NOTICE(channel.to_owned(), line)
        } else if emote {
            Command::PRIVMSG(channel.to_owned(), format!("\u{1}ACTION {line}\u{1}"))
        } else {
            Command::PRIVMSG(channel.to_owned(), line)
        }
    };
    let tags_for = |multiline_ref: Option<&str>| -> Vec<irc::proto::message::Tag> {
        let mut tags = vec![proto::time_tag(ts), proto::msgid_tag(msgid)];
        if let Some(r) = multiline_ref {
            tags.push(irc::proto::message::Tag(
                "draft/multiline".to_owned(),
                Some(r.to_owned()),
            ));
        }
        tags
    };

    if caps.has("draft/multiline") && caps.has("batch") && caps.has("message-tags") {
        // one batch per message, ref derived from the event id
        let reference = format!("m.{}", msgid.trim_start_matches('$'));
        let mut out = vec![Message {
            tags: None,
            prefix: Some(sender.clone()),
            command: Command::Raw(
                "BATCH".to_owned(),
                vec![
                    format!("+{reference}"),
                    "draft/multiline".to_owned(),
                    channel.to_owned(),
                ],
            ),
        }];
        for line in lines {
            let m = Message {
                tags: Some(tags_for(Some(&reference))),
                prefix: Some(sender.clone()),
                command: mk_cmd(line),
            };
            out.push(m);
        }
        out.push(Message {
            tags: None,
            prefix: Some(sender.clone()),
            command: Command::Raw("BATCH".to_owned(), vec![format!("-{reference}")]),
        });
        out
    } else {
        lines
            .into_iter()
            .map(|line| Message {
                tags: Some(tags_for(None)),
                prefix: Some(sender.clone()),
                command: mk_cmd(line),
            })
            .collect()
    }
}

/// Build echo-message line(s) for the client's own Matrix delivery.
pub fn echo_messages(
    caps: &Caps,
    prefix: &irc::proto::Prefix,
    _nick: &str,
    target: &str,
    body: &str,
    event_id: &str,
    ts: u64,
    notice: bool,
) -> Vec<Message> {
    body_to_irc(caps, prefix, target, body, event_id, ts, notice, false)
}

/// Split a body into IRC-safe lines: split on newlines, then word-wrap any
/// over-long line (port of matrix2051's word_wrap idea).
pub fn wrap_body(body: &str) -> Vec<String> {
    const WIDTH: usize = 400; // leaves headroom for tags+prefix within 512
    let mut out = Vec::new();
    for line in body.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.chars().count() <= WIDTH {
            out.push(line.to_owned());
            continue;
        }
        let mut current = String::new();
        for word in line.split(' ') {
            let wlen = word.chars().count();
            if current.is_empty() {
                if wlen > WIDTH {
                    // unbreakable monster word: hard-chop
                    for chunk in chunks(word, WIDTH) {
                        out.push(chunk.to_owned());
                    }
                } else {
                    current.push_str(word);
                }
            } else if current.chars().count() + 1 + wlen <= WIDTH {
                current.push(' ');
                current.push_str(word);
            } else {
                out.push(std::mem::take(&mut current));
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            out.push(current);
        }
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

fn chunks(s: &str, width: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    while start < s.len() {
        let mut end = (start + width).min(s.len());
        while end < s.len() && !s.is_char_boundary(end) {
            end += 1;
        }
        out.push(&s[start..end]);
        start = end;
    }
    out
}

async fn push_topic(
    tx: &mut mpsc::Sender<Message>,
    rooms: &Arc<Mutex<RoomMaps>>,
    room: &Room,
    new: String,
) {
    // Room name/topic changes surface as TOPIC, never as a channel rename.
    let entry = {
        let maps = rooms.lock().expect("rooms mutex");
        maps.get_by_room(room.room_id()).cloned()
    };
    let Some(entry) = entry else { return };
    let topic = new.replace('\n', " | ").replace('\r', "");
    {
        let mut maps = rooms.lock().expect("rooms mutex");
        if let Some(e) = maps.get_by_room_mut(room.room_id()) {
            e.topic = topic.clone();
        }
    }
    let _ = tx
        .send(proto::user("matrix", Command::TOPIC(entry.channel, Some(topic))))
        .await;
}

async fn sync_forever(client: Client) {
    loop {
        tracing::debug!("starting continuous sync");
        if let Err(e) = client.sync(SyncSettings::default()).await {
            tracing::error!(error = %e, "matrix sync loop died, restarting in 5s");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}

fn channels_path(state_dir: &Path, nick: &str) -> PathBuf {
    crate::matrix::client::user_dir(state_dir, nick).join("channels.json")
}

/// Extract the string from a computed room display name.
fn display_string(d: matrix_sdk::RoomDisplayName) -> Option<String> {
    use matrix_sdk::RoomDisplayName::*;
    match d {
        Named(s) | Aliased(s) | Calculated(s) | EmptyWas(s) => Some(s),
        Empty => None,
    }
}

/// Render a Matrix msgtype into an IRC message body.
/// Text/emote/notice pass through (with mxc links localized); attachments
/// become a one-liner pointing at the local authenticated-media cache.
async fn render_body(
    msgtype: &MessageType,
    client: &Client,
    media: &Arc<MediaServer>,
    cfg: &Arc<Config>,
) -> Option<String> {
    match msgtype {
        MessageType::Text(c) => Some(localize_mxc(&c.body, client, media, cfg).await),
        MessageType::Notice(c) => Some(localize_mxc(&c.body, client, media, cfg).await),
        MessageType::Emote(c) => Some(localize_mxc(&c.body, client, media, cfg).await),
        MessageType::Image(c) => Some(
            attachment_line(
                "image",
                &c.body,
                c.filename.as_deref(),
                &c.source,
                c.info.as_deref().and_then(|i| i.mimetype.as_deref()),
                c.info.as_deref().and_then(|i| i.size).and_then(|s| u64::try_from(s).ok()),
                client,
                media,
                cfg,
            )
            .await,
        ),
        MessageType::File(c) => Some(
            attachment_line(
                "file",
                &c.body,
                Some(c.filename()),
                &c.source,
                c.info.as_deref().and_then(|i| i.mimetype.as_deref()),
                c.info.as_deref().and_then(|i| i.size).and_then(|s| u64::try_from(s).ok()),
                client,
                media,
                cfg,
            )
            .await,
        ),
        MessageType::Audio(c) => Some(
            attachment_line(
                "audio",
                &c.body,
                c.filename.as_deref(),
                &c.source,
                c.info.as_deref().and_then(|i| i.mimetype.as_deref()),
                c.info.as_deref().and_then(|i| i.size).and_then(|s| u64::try_from(s).ok()),
                client,
                media,
                cfg,
            )
            .await,
        ),
        MessageType::Video(c) => Some(
            attachment_line(
                "video",
                &c.body,
                c.filename.as_deref(),
                &c.source,
                c.info.as_deref().and_then(|i| i.mimetype.as_deref()),
                c.info.as_deref().and_then(|i| i.size).and_then(|s| u64::try_from(s).ok()),
                client,
                media,
                cfg,
            )
            .await,
        ),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn attachment_line(
    kind: &str,
    body: &str,
    filename: Option<&str>,
    source: &MediaSource,
    mime: Option<&str>,
    size: Option<u64>,
    client: &Client,
    media: &Arc<MediaServer>,
    cfg: &Arc<Config>,
) -> String {
    let name = filename.filter(|n| !n.is_empty()).unwrap_or(body);
    let size_str = size.map(|s| format!(" ({})", human_size(s))).unwrap_or_default();
    let dir = crate::matrix::media::cache_dir(&cfg.state_dir);
    tracing::debug!(kind, %name, "rendering attachment");
    let url = match crate::matrix::media::fetch_to_cache(client, &dir, source, mime).await {
        Ok(path) => {
            let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
            tracing::debug!(kind, file, "attachment cached");
            media.url_for(file)
        }
        Err(e) => format!("<media unavailable: {e:#}>"),
    };
    format!("[{kind}] {name}{size_str} — {url}")
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

/// Replace `mxc://` URIs in a text body with local media-cache URLs.
async fn localize_mxc(
    body: &str,
    client: &Client,
    media: &Arc<MediaServer>,
    cfg: &Arc<Config>,
) -> String {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"mxc://([A-Za-z0-9.\-]+)/([A-Za-z0-9_\-=]+)").expect("mxc regex")
    });

    let mut out = String::with_capacity(body.len());
    let mut last = 0;
    let dir = crate::matrix::media::cache_dir(&cfg.state_dir);
    for m in re.captures_iter(body) {
        let whole = m.get(0).expect("group 0");
        let server = m.get(1).expect("server").as_str();
        let id = m.get(2).expect("id").as_str();
        out.push_str(&body[last..whole.start()]);
        let source = matrix_sdk::ruma::OwnedMxcUri::try_from(format!("mxc://{server}/{id}"))
            .ok()
            .map(matrix_sdk::ruma::events::room::MediaSource::Plain);
        let source = match source {
            Some(s) => s,
            None => {
                out.push_str(whole.as_str());
                last = whole.end();
                continue;
            }
        };
        match crate::matrix::media::fetch_to_cache(client, &dir, &source, None).await {
            Ok(path) => {
                let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
                out.push_str(&media.url_for(file));
            }
            Err(_) => out.push_str(whole.as_str()),
        }
        last = whole.end();
    }
    out.push_str(&body[last..]);
    out
}
