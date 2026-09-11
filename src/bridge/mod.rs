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

/// A pending room invitation surfaced over IRC.
#[derive(Debug, Clone)]
pub struct PendingInvite {
    pub idx: u64,
    pub room_id: OwnedRoomId,
    /// Best-effort room name (name, alias localpart or inviter's name).
    pub name: String,
    /// Inviter mxid.
    pub sender: String,
}

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
    /// IRC nick of the owning connection (query messages are addressed to it).
    pub irc_nick: String,
    /// Pending invitations awaiting `/msg &matrix accept|decline`.
    pub invites: Arc<Mutex<Vec<PendingInvite>>>,
    next_invite_idx: Arc<std::sync::atomic::AtomicU64>,
    /// Event ids we sent from *this* connection: their sync echo must not be
    /// relayed back (messages from the same account via other clients still
    /// must be, like matrix2051 did).
    sent: Arc<Mutex<HashSet<String>>>,
}

impl Bridge {
    /// Log in / restore the Matrix session and load the stored room→channel
    /// mapping. This is deliberately fast: the initial sync and the mapping of
    /// newly seen rooms happen in [`Bridge::spawn_bootstrap`] so the IRC
    /// registration burst is not delayed by a long initial sync.
    pub async fn connect(
        cfg: &Arc<Config>,
        nick: &str,
        irc_pass: &str,
        login_user: &str,
        media: Arc<MediaServer>,
        caps: Caps,
    ) -> Result<Arc<Self>> {
        let client = login_or_restore(cfg, nick, irc_pass, login_user).await?;

        let own_mxid = client
            .user_id()
            .map(|u| u.to_owned())
            .ok_or_else(|| anyhow::anyhow!("client has no user id"))?;
        let hub = VerificationHub::new(client.clone(), own_mxid.clone(), nick);

        let maps_path = channels_path(&cfg.state_dir, &crate::matrix::client::state_key(login_user));
        let rooms = Arc::new(Mutex::new(RoomMaps::load(maps_path)));

        Ok(Arc::new(Self {
            client: client.clone(),
            own_mxid,
            rooms,
            joined: Arc::new(Mutex::new(HashSet::new())),
            cfg: cfg.clone(),
            media,
            caps,
            hub,
            irc_nick: nick.to_owned(),
            invites: Arc::new(Mutex::new(Vec::new())),
            next_invite_idx: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            sent: Arc::new(Mutex::new(HashSet::new())),
        }))
    }

    /// Remember an event we sent from this connection, so its sync echo is
    /// not relayed back to the client.
    fn note_sent(&self, event_id: &str) {
        let mut s = self.sent.lock().expect("sent mutex");
        if s.len() > 4096 {
            s.clear();
        }
        s.insert(event_id.to_owned());
    }

    /// Compute (or refresh) the mapping for a joined room: 2-party DMs map
    /// to IRC queries, everything else to stable channels.
    pub async fn ensure_room_mapping(maps: &Arc<Mutex<RoomMaps>>, room: &Room) -> RoomEntry {
        if room.compute_is_dm().await.unwrap_or_else(|_| room.is_dm()) {
            let other = room
                .members(matrix_sdk::RoomMemberships::JOIN)
                .await
                .unwrap_or_default()
                .into_iter()
                .find(|m| m.user_id() != room.client().user_id().expect("own id"))
                .map(|m| proto::mxid_to_nick(m.user_id().as_str()))
                .unwrap_or_else(|| "query".to_owned());
            let mut maps = maps.lock().expect("rooms mutex");
            maps.ensure_query(room.room_id().to_owned(), &other, String::new()).clone()
        } else {
            let (base, topic) = Self::room_label(room).await;
            let mut maps = maps.lock().expect("rooms mutex");
            maps.ensure(room.room_id().to_owned(), &base, topic).clone()
        }
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
        self.reaction_handler(tx.clone());
        self.redaction_handler(tx.clone());
        self.presence_handler(tx.clone());
        self.invite_handler(tx.clone());
        // prompt for invitations collected during the initial sync
        let invites = Arc::clone(&self.invites);
        let irc_nick = self.irc_nick.clone();
        let txp = tx.clone();
        tokio::spawn(async move {
            let pending = invites.lock().expect("invites mutex").clone();
            for inv in pending {
                let _ = txp.send(invite_prompt(&irc_nick, &inv)).await;
            }
        });
    }

    fn message_handler(&self, tx: mpsc::Sender<Message>) {
        let rooms = Arc::clone(&self.rooms);
        let joined = Arc::clone(&self.joined);
        let own = self.own_mxid.clone();
        let cfg = Arc::clone(&self.cfg);
        let media = Arc::clone(&self.media);
        let caps = self.caps.clone();
        let hub = Arc::clone(&self.hub);
        let irc_nick = self.irc_nick.clone();
        let sent = Arc::clone(&self.sent);
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
                let irc_nick = irc_nick.clone();
                let sent = Arc::clone(&sent);
                async move {
                    let matrix_sdk::ruma::events::SyncMessageLikeEvent::Original(ev) = ev else {
                        return;
                    };
                    use matrix_sdk::ruma::events::room::message::Relation;
                    // m.replace edits render the new content as "* new body",
                    // replies carry +draft/reply and drop the "> " fallback
                    let mut is_edit = false;
                    let (reply_to, msgtype): (Option<String>, &MessageType) =
                        match &ev.content.relates_to {
                            Some(Relation::Replacement(rep)) => {
                                is_edit = true;
                                (Some(rep.event_id.to_string()), &rep.new_content.msgtype)
                            }
                            Some(Relation::Reply(r)) => {
                                (Some(r.in_reply_to.event_id.to_string()), &ev.content.msgtype)
                            }
                            _ => (None, &ev.content.msgtype),
                        };
                    if room.state() != RoomState::Joined {
                        return;
                    }
                    let sender = ev.sender.clone();
                    // our own echo from this connection was already delivered
                    // via echo-message; the same account on another client
                    // must still come through
                    if sender == own
                        && sent.lock().expect("sent mutex").contains(&ev.event_id.to_string())
                    {
                        tracing::debug!(event = %ev.event_id, "dropping own echo already shown via echo-message");
                        return;
                    }
                    tracing::info!(
                        sender = %sender,
                        room = room.room_id().as_str(),
                        event = %ev.event_id,
                        "relaying matrix message"
                    );

                    // in-room verification requests: route to the &matrix flow
                    if let MessageType::VerificationRequest(_) = &ev.content.msgtype {
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
                        None => Bridge::ensure_room_mapping(&rooms, &room).await,
                    };
                    // DMs surface as queries: PRIVMSG from the other party
                    // addressed to our own nick; no channel JOIN/TOPIC
                    let target = if entry.query.is_some() {
                        irc_nick.clone()
                    } else {
                        entry.channel.clone()
                    };

                    let body = match render_body(msgtype, &client, &media, &cfg).await {
                        Some(b) => b,
                        None => return,
                    };
                    // rich formatting: prefer the HTML form when present
                    let body = if let Some(html) = formatted_of(msgtype) {
                        let converted = crate::format::matrix_to_irc(&html);
                        if converted.is_empty() { body } else { converted }
                    } else {
                        body
                    };
                    // strip the rich-reply fallback from plain bodies; clients
                    // without message-tags cannot see +draft/reply and keep
                    // the quoted fallback for context instead
                    let body = if reply_to.is_some() && !is_edit && caps.has("message-tags") {
                        crate::format::strip_reply_fallback(&body)
                    } else {
                        body
                    };
                    // edits render as "* new body"
                    let body = if is_edit {
                        format!("* {body}")
                    } else {
                        body
                    };
                    // replace full mxids of room members with their IRC nicks
                    let body = localize_mentions(&body, &room).await;

                    // JOIN must always be emitted before any PRIVMSG on a channel
                    let need_join = entry.query.is_none() && {
                        let mut j = joined.lock().expect("joined mutex");
                        let lower = target.to_ascii_lowercase();
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
                            .send(proto::user(&nick, Command::JOIN(target.clone(), None, None)))
                            .await;
                        let _ = tx
                            .send(proto::srv(
                                &cfg.server_name,
                                Command::Response(
                                    irc::proto::Response::RPL_TOPIC,
                                    vec!["*".into(), target.clone(), entry.topic.clone()],
                                ),
                            ))
                            .await;
                    }

                    let ts = u64::from(ev.origin_server_ts.get());
                    let msgid = ev.event_id.to_string();
                    let is_notice = matches!(msgtype, MessageType::Notice(_));
                    let is_emote = matches!(msgtype, MessageType::Emote(_));
                    let sender_prefix = proto::user_prefix(&nick);
                    let msgs = body_to_irc(
                        &caps, &sender_prefix, &target, &body, &msgid, ts, is_notice, is_emote,
                        reply_to.as_deref(),
                    );
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
        let irc_nick = self.irc_nick.clone();
        let sent = Arc::clone(&self.sent);
        self.client.add_event_handler(
            move |ev: matrix_sdk::ruma::events::room::encrypted::SyncRoomEncryptedEvent,
                  room: Room| {
                let tx = tx.clone();
                let rooms = Arc::clone(&rooms);
                let joined = Arc::clone(&joined);
                let own = own.clone();
                let irc_nick = irc_nick.clone();
                let sent = Arc::clone(&sent);
                async move {
                    let matrix_sdk::ruma::events::SyncMessageLikeEvent::Original(ev) = ev else {
                        return;
                    };
                    if room.state() != RoomState::Joined
                        || (ev.sender == own
                            && sent.lock().expect("sent mutex").contains(&ev.event_id.to_string()))
                    {
                        return;
                    }
                    let Some(entry) = ({
                        let maps = rooms.lock().expect("rooms mutex");
                        maps.get_by_room(room.room_id()).cloned()
                    }) else {
                        return;
                    };
                    let is_query = entry.query.is_some();
                    let channel = if is_query {
                        irc_nick.clone()
                    } else {
                        entry.channel.clone()
                    };
                    let need_join = !is_query && {
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

    /// m.reaction → IRC TAGMSG carrying `+draft/reply` + `+draft/react`
    /// (only meaningful for clients that negotiated message-tags).
    fn reaction_handler(&self, tx: mpsc::Sender<Message>) {
        let rooms = Arc::clone(&self.rooms);
        let joined = Arc::clone(&self.joined);
        let own = self.own_mxid.clone();
        let caps = self.caps.clone();
        let sent = Arc::clone(&self.sent);
        self.client.add_event_handler(
            move |ev: matrix_sdk::ruma::events::reaction::SyncReactionEvent, room: Room| {
                let tx = tx.clone();
                let rooms = Arc::clone(&rooms);
                let joined = Arc::clone(&joined);
                let own = own.clone();
                let caps = caps.clone();
                let sent = Arc::clone(&sent);
                async move {
                    if !caps.has("message-tags") {
                        return;
                    }
                    let matrix_sdk::ruma::events::reaction::SyncReactionEvent::Original(ev) = ev else {
                        return;
                    };
                    if room.state() != RoomState::Joined
                        || (ev.sender == own
                            && sent.lock().expect("sent mutex").contains(&ev.event_id.to_string()))
                    {
                        return;
                    }
                    let ann = &ev.content.relates_to;
                    let Some(entry) = ({
                        let maps = rooms.lock().expect("rooms mutex");
                        maps.get_by_room(room.room_id()).cloned()
                    }) else {
                        return;
                    };
                    // only relay reactions on channels the client occupies
                    if !joined
                        .lock()
                        .expect("joined mutex")
                        .contains(&entry.channel.to_ascii_lowercase())
                    {
                        return;
                    }
                    let nick = proto::mxid_to_nick(ev.sender.as_str());
                    let ts = u64::from(ev.origin_server_ts.get());
                    let mut m = proto::user(&nick, Command::Raw("TAGMSG".to_owned(), vec![entry.channel]));
                    m.tags = Some(vec![
                        proto::time_tag(ts),
                        proto::msgid_tag(&ev.event_id.to_string()),
                        irc::proto::message::Tag(
                            "+draft/reply".to_owned(),
                            Some(ann.event_id.to_string()),
                        ),
                        irc::proto::message::Tag(
                            "+draft/react".to_owned(),
                            Some(ann.key.clone()),
                        ),
                    ]);
                    let _ = tx.send(m).await;
                }
            },
        );
    }

    /// m.room.redaction → IRC `REDACT` (draft/message-redaction) or a
    /// downgraded NOTICE for legacy clients.
    fn redaction_handler(&self, tx: mpsc::Sender<Message>) {
        let rooms = Arc::clone(&self.rooms);
        let joined = Arc::clone(&self.joined);
        let own = self.own_mxid.clone();
        let caps = self.caps.clone();
        let server = self.cfg.server_name.clone();
        let sent = Arc::clone(&self.sent);
        self.client.add_event_handler(
            move |ev: matrix_sdk::ruma::events::room::redaction::SyncRoomRedactionEvent,
                  room: Room| {
                let tx = tx.clone();
                let rooms = Arc::clone(&rooms);
                let joined = Arc::clone(&joined);
                let own = own.clone();
                let caps = caps.clone();
                let server = server.clone();
                let sent = Arc::clone(&sent);
                async move {
                    let matrix_sdk::ruma::events::room::redaction::SyncRoomRedactionEvent::Original(ev) = ev else {
                        return;
                    };
                    // room v11+ keeps `redacts` in the content
                    let Some(redacted_id) = ev.content.redacts.clone() else {
                        return;
                    };
                    if room.state() != RoomState::Joined
                        || (ev.sender == own
                            && sent.lock().expect("sent mutex").contains(&ev.event_id.to_string()))
                    {
                        return;
                    }
                    let Some(entry) = ({
                        let maps = rooms.lock().expect("rooms mutex");
                        maps.get_by_room(room.room_id()).cloned()
                    }) else {
                        return;
                    };
                    if !joined
                        .lock()
                        .expect("joined mutex")
                        .contains(&entry.channel.to_ascii_lowercase())
                    {
                        return;
                    }
                    let nick = proto::mxid_to_nick(ev.sender.as_str());
                    let ts = u64::from(ev.origin_server_ts.get());
                    let msgid = ev.event_id.to_string();
                    let target = redacted_id.to_string();
                    if caps.has("draft/message-redaction") && caps.has("message-tags") {
                        let mut params = vec![entry.channel.clone(), target.clone()];
                        if let Some(reason) = &ev.content.reason {
                            params.push(reason.clone());
                        }
                        let mut m =
                            proto::user(&nick, Command::Raw("REDACT".to_owned(), params));
                        m.tags = Some(vec![
                            proto::time_tag(ts),
                            proto::msgid_tag(&msgid),
                            irc::proto::message::Tag(
                                "+draft/reply".to_owned(),
                                Some(target),
                            ),
                        ]);
                        let _ = tx.send(m).await;
                    } else {
                        let reason = ev
                            .content
                            .reason
                            .as_deref()
                            .map(|r| format!(": {r}"))
                            .unwrap_or_default();
                        let mut m = proto::user(
                            &nick,
                            Command::NOTICE(
                                entry.channel.clone(),
                                format!("deleted an event{reason}"),
                            ),
                        );
                        m.tags = Some(vec![
                            proto::time_tag(ts),
                            proto::msgid_tag(&msgid),
                        ]);
                        let _ = m.tags; // NOTICE downgrade keeps tags minimal
                        let _ = server;
                        let _ = tx.send(m).await;
                    }
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

    /// Initial sync + rebuild of the room→channel mapping. Returns every
    /// channel-mapped entry (the caller deduplicates against channels it has
    /// already joined). Runs once per IRC connection after registration, off
    /// the registration critical path.
    pub async fn bootstrap_sync(&self) -> anyhow::Result<Vec<RoomEntry>> {
        self.client
            .sync_once(SyncSettings::default().ignore_timeout_on_first_sync(true))
            .await
            .context("initial matrix sync failed")?;
        let live: HashSet<OwnedRoomId> = self
            .client
            .joined_rooms()
            .iter()
            .map(|r| r.room_id().to_owned())
            .collect();
        self.rooms.lock().expect("rooms mutex").prune_to(&live);
        let mut out = Vec::new();
        for room in self.client.joined_rooms() {
            if room.is_space() {
                continue;
            }
            let entry = Self::ensure_room_mapping(&self.rooms, &room).await;
            if entry.query.is_none() {
                out.push(entry);
            }
        }
        Ok(out)
    }

    /// Collect invitations that arrived while no connection was active, so
    /// the caller can prompt for them.
    pub async fn collect_offline_invites(&self) {
        let mut idx = self
            .next_invite_idx
            .load(std::sync::atomic::Ordering::SeqCst);
        let mut invites = Vec::new();
        for room in self.client.invited_rooms() {
            idx += 1;
            let mut inv = describe_invite(&room).await;
            inv.idx = idx;
            invites.push(inv);
        }
        self.next_invite_idx
            .store(idx + 1, std::sync::atomic::Ordering::SeqCst);
        *self.invites.lock().expect("invites mutex") = invites;
    }

    /// NOTICE prompts for every currently pending invitation.
    pub fn invite_prompts(&self) -> Vec<Message> {
        let invites = self.invites.lock().expect("invites mutex").clone();
        invites.iter().map(|inv| invite_prompt(&self.irc_nick, inv)).collect()
    }

    /// Deliver an IRC line to the mapped Matrix room. Returns the new event id.
    pub async fn send_from_irc(
        &self,
        channel: &str,
        body: String,
        notice: bool,
        reply_to: Option<&str>,
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
        let event_id = Self::send_room_message(&room, body, notice, reply_to).await?;
        self.note_sent(&event_id);
        Ok(event_id)
    }

    /// Deliver an IRC query PRIVMSG/NOTICE to the DM room with `nick`,
    /// creating the DM if this is the first contact.
    pub async fn send_query(
        &self,
        nick: &str,
        body: String,
        notice: bool,
        reply_to: Option<&str>,
    ) -> Result<String> {
        // an already-mapped DM room wins
        let mapped = {
            let maps = self.rooms.lock().expect("rooms mutex");
            maps.get_by_query(nick).map(|e| e.room_id.clone())
        };
        let room = match mapped.and_then(|rid| self.client.get_room(&rid)) {
            Some(r) if r.state() == RoomState::Joined => r,
            _ => {
                let uid = self
                    .resolve_nick(nick)
                    .await
                    .ok_or_else(|| anyhow::anyhow!("no Matrix user known as nick {nick}"))?;
                match self.client.get_dm_room(&uid) {
                    Some(r) if r.state() == RoomState::Joined => r,
                    _ => self.client.create_dm(&uid).await.context("creating DM room")?,
                }
            }
        };
        // keep the mapping fresh (covers newly created DMs)
        Self::ensure_room_mapping(&self.rooms, &room).await;
        let event_id = Self::send_room_message(&room, body, notice, reply_to).await?;
        self.note_sent(&event_id);
        Ok(event_id)
    }

    /// Resolve an IRC nick to a Matrix user id by scanning the members of
    /// every joined room.
    async fn resolve_nick(&self, nick: &str) -> Option<matrix_sdk::ruma::OwnedUserId> {
        for room in self.client.joined_rooms() {
            let members = room
                .members(matrix_sdk::RoomMemberships::JOIN)
                .await
                .unwrap_or_default();
            for m in members {
                if proto::mxid_to_nick(m.user_id().as_str()).eq_ignore_ascii_case(nick) {
                    return Some(m.user_id().to_owned());
                }
            }
        }
        None
    }

    /// Shared send path: IRC→Matrix conversion, reply relation, mentions.
    async fn send_room_message(
        room: &Room,
        body: String,
        notice: bool,
        reply_to: Option<&str>,
    ) -> Result<String> {
        // a bare http(s) link becomes a native m.image/m.file/… upload so
        // Matrix clients render it as media instead of a bare URL
        if reply_to.is_none() && !notice {
            if let Some(res) = try_url_attachment(room, body.trim()).await {
                return res;
            }
        }
        // IRC → Matrix formatting (mIRC codes, links, mxid links)
        let member_mxids: Vec<String> = room
            .members(matrix_sdk::RoomMemberships::JOIN)
            .await
            .unwrap_or_default()
            .iter()
            .map(|m| m.user_id().to_string())
            .collect();
        let conv = crate::format::irc_to_matrix(&body, &member_mxids);
        let mut content = match (&conv.html, notice) {
            (Some(html), false) => RoomMessageEventContent::text_html(&conv.plain, html),
            (Some(html), true) => RoomMessageEventContent::notice_html(&conv.plain, html),
            (None, false) => RoomMessageEventContent::text_plain(&conv.plain),
            (None, true) => RoomMessageEventContent::notice_plain(&conv.plain),
        };
        if let Some(reply) = reply_to {
            if let Ok(event_id) = matrix_sdk::ruma::EventId::parse(reply) {
                use matrix_sdk::ruma::events::{
                    relation::{InReplyTo, Reply},
                    room::message::Relation,
                };
                content.relates_to = Some(Relation::Reply(Reply::new(InReplyTo::new(event_id))));
            }
        }
        // mentions: IRC nicks present as words map back to Matrix user ids
        let mentioned = mentioned_mxids(&body, room, &member_mxids).await;
        if !mentioned.is_empty() {
            let mut m = matrix_sdk::ruma::events::Mentions::new();
            m.user_ids = mentioned
                .iter()
                .filter_map(|s| matrix_sdk::ruma::UserId::parse(s.as_str()).ok())
                .collect();
            content.mentions = Some(m);
        }
        let resp = room
            .send(content)
            .await
            .context("sending message to matrix room")?;
        Ok(resp.response.event_id.to_string())
    }

    /// Live invitations while connected: prompt over IRC from `&matrix`.
    /// Invited rooms surface as *stripped* member events.
    fn invite_handler(&self, tx: mpsc::Sender<Message>) {
        use matrix_sdk::ruma::events::room::member::{MembershipState, StrippedRoomMemberEvent};
        let invites = Arc::clone(&self.invites);
        let counter = Arc::clone(&self.next_invite_idx);
        let own = self.own_mxid.clone();
        let irc_nick = self.irc_nick.clone();
        self.client.add_event_handler(
            move |ev: StrippedRoomMemberEvent, room: Room| {
                let tx = tx.clone();
                let invites = Arc::clone(&invites);
                let counter = Arc::clone(&counter);
                let own = own.clone();
                let irc_nick = irc_nick.clone();
                async move {
                    // our own invite membership, in a room we are not in yet
                    if ev.state_key != *own
                        || ev.content.membership != MembershipState::Invite
                        || room.state() != RoomState::Invited
                    {
                        return;
                    }
                    let room_id = room.room_id().to_owned();
                    // several stripped events fire per invite; dedupe
                    if invites
                        .lock()
                        .expect("invites mutex")
                        .iter()
                        .any(|i| i.room_id == room_id)
                    {
                        return;
                    }
                    let mut inv = describe_invite(&room).await;
                    inv.sender = ev.sender.to_string();
                    inv.idx = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let _ = tx.send(invite_prompt(&irc_nick, &inv)).await;
                    invites.lock().expect("invites mutex").push(inv);
                }
            },
        );
    }

    /// Handle `/msg &matrix accept|decline|invites …`. On a successful accept
    /// of a channel room the new mapping is returned so the caller can emit
    /// the JOIN burst.
    pub async fn invite_command(
        &self,
        rest: &str,
    ) -> Result<(Vec<String>, Option<RoomEntry>)> {
        let mut words = rest.split_whitespace();
        let cmd = words.next().unwrap_or_default().to_ascii_lowercase();
        let arg = words.next().map(str::to_owned);
        let find = |arg: &str| -> Option<PendingInvite> {
            let invites = self.invites.lock().expect("invites mutex");
            invites
                .iter()
                .find(|i| {
                    i.idx.to_string() == arg
                        || i.room_id.as_str().eq_ignore_ascii_case(arg)
                })
                .cloned()
        };
        match (cmd.as_str(), arg) {
            ("invites", _) => {
                let invites = self.invites.lock().expect("invites mutex").clone();
                let mut out = Vec::new();
                if invites.is_empty() {
                    out.push("no pending invitations".to_owned());
                }
                for i in invites {
                    out.push(format!(
                        "#{}: {} from {} — accept {} | decline {}",
                        i.idx, i.name, proto::mxid_to_nick(&i.sender), i.idx, i.idx
                    ));
                }
                Ok((out, None))
            }
            ("accept", Some(arg)) => {
                let Some(inv) = find(&arg) else {
                    return Ok((vec![format!("no pending invite matching {arg}")], None));
                };
                self.invites
                    .lock()
                    .expect("invites mutex")
                    .retain(|i| i.room_id != inv.room_id);
                let Some(room) = self.client.get_room(&inv.room_id) else {
                    return Ok((vec!["lost the invited room".to_owned()], None));
                };
                room.join().await.context("joining invited room")?;
                // direct invitations become DM queries: mirror the flag into
                // our m.direct account data so compute_is_dm() agrees
                if invite_was_direct(&room).await {
                    let _ = room.set_is_direct(true).await;
                }
                let entry = Self::ensure_room_mapping(&self.rooms, &room).await;
                if entry.query.is_none() {
                    self.joined
                        .lock()
                        .expect("joined mutex")
                        .insert(entry.channel.to_ascii_lowercase());
                    Ok((
                        vec![format!("joined {}", entry.channel)],
                        Some(entry),
                    ))
                } else {
                    Ok((
                        vec![format!("joined DM with {}", entry.query.clone().unwrap_or_default())],
                        None,
                    ))
                }
            }
            ("decline", Some(arg)) => {
                let Some(inv) = find(&arg) else {
                    return Ok((vec![format!("no pending invite matching {arg}")], None));
                };
                self.invites
                    .lock()
                    .expect("invites mutex")
                    .retain(|i| i.room_id != inv.room_id);
                if let Some(room) = self.client.get_room(&inv.room_id) {
                    room.leave().await.context("declining invitation")?;
                }
                Ok((vec![format!("declined {}", inv.name)], None))
            }
            _ => Ok((
                vec!["usage: accept <n|room-id> | decline <n|room-id> | invites".to_owned()],
                None,
            )),
        }
    }


    /// Send a reaction (`+draft/react` TAGMSG) as an m.reaction annotation.
    pub async fn send_reaction(&self, channel: &str, target: &str, key: &str) -> Result<()> {
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
        let event_id =
            matrix_sdk::ruma::EventId::parse(target).context("bad reply event id")?;
        let ann = matrix_sdk::ruma::events::relation::Annotation::new(
            event_id,
            key.to_owned(),
        );
        match room
            .send(matrix_sdk::ruma::events::reaction::ReactionEventContent::new(ann))
            .await
        {
            Ok(resp) => {
                self.note_sent(resp.response.event_id.as_str());
                Ok(())
            }
            // re-reacting with the same key is a no-op on the Matrix side
            Err(e) if e.to_string().contains("M_DUPLICATE_ANNOTATION") => Ok(()),
            Err(e) => Err(e).context("sending m.reaction"),
        }
    }

    /// Redact an event (IRC `REDACT` command).
    pub async fn redact(&self, channel: &str, target: &str, reason: Option<&str>) -> Result<()> {
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
        let event_id =
            matrix_sdk::ruma::EventId::parse(target).context("bad redact target")?;
        match room.redact(&event_id, reason, None).await {
            Ok(resp) => {
                self.note_sent(resp.event_id.as_str());
                Ok(())
            }
            Err(e) => Err(e).context("redacting event"),
        }
    }

    /// Snapshot of mapped rooms for the initial JOIN burst.
    pub fn entries(&self) -> Vec<RoomEntry> {
        self.rooms.lock().expect("rooms mutex").entries().to_vec()
    }
}

/// Build outgoing IRC message(s) for a Matrix body:
/// - multiline-capable clients get a `draft/multiline` batch;
/// - everyone else gets one PRIVMSG per line, word-wrapped.
#[allow(clippy::too_many_arguments)]
fn body_to_irc(
    caps: &Caps,
    sender: &irc::proto::Prefix,
    channel: &str,
    body: &str,
    msgid: &str,
    ts: u64,
    notice: bool,
    emote: bool,
    reply_to: Option<&str>,
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
        if let Some(reply) = reply_to {
            tags.push(irc::proto::message::Tag(
                "+draft/reply".to_owned(),
                Some(reply.to_owned()),
            ));
        }
        tags
    };
    if lines.len() > 1 && caps.has("draft/multiline") && caps.has("batch") && caps.has("message-tags") {
        // one batch per message, ref derived from the event id; per spec the
        // msgid/time/reply tags ride the opening BATCH and each line is
        // marked with the server-side batch=<ref> tag
        let reference = format!("m.{}", msgid.trim_start_matches('$'));
        let mut open_tags = vec![proto::time_tag(ts), proto::msgid_tag(msgid)];
        if let Some(reply) = reply_to {
            open_tags.push(irc::proto::message::Tag(
                "+draft/reply".to_owned(),
                Some(reply.to_owned()),
            ));
        }
        let mut out = vec![Message {
            tags: Some(open_tags),
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
                tags: Some(vec![irc::proto::message::Tag(
                    "batch".to_owned(),
                    Some(reference.clone()),
                )]),
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
        // fallback: one PRIVMSG per line; blank lines are not allowed here
        lines
            .into_iter()
            .filter(|l| !l.trim().is_empty())
            .map(|line| Message {
                tags: Some(tags_for(None)),
                prefix: Some(sender.clone()),
                command: mk_cmd(line),
            })
            .collect()
    }
}

/// Build echo-message line(s) for the client's own Matrix delivery.
#[allow(clippy::too_many_arguments)]
pub fn echo_messages(
    caps: &Caps,
    prefix: &irc::proto::Prefix,
    _nick: &str,
    target: &str,
    body: &str,
    event_id: &str,
    ts: u64,
    notice: bool,
    reply_to: Option<&str>,
) -> Vec<Message> {
    body_to_irc(caps, prefix, target, body, event_id, ts, notice, false, reply_to)
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

/// Best-effort description of an invited room for the IRC prompt.
async fn describe_invite(room: &Room) -> PendingInvite {
    let name = room
        .name()
        .filter(|n| !n.is_empty())
        .or_else(|| {
            room.canonical_alias()
                .map(|a| a.alias().trim_start_matches('#').to_owned())
        })
        .or_else(|| {
            room.alt_aliases()
                .last()
                .map(|a| a.alias().trim_start_matches('#').to_owned())
        })
        .unwrap_or_else(|| "unnamed room".to_owned());
    let sender = room
        .invite_details()
        .await
        .map(|d| d.inviter_id.to_string())
        .unwrap_or_default();
    PendingInvite { idx: 0, room_id: room.room_id().to_owned(), name, sender }
}

/// Was this invited room created as a direct chat? Reads the `is_direct`
/// flag off our own (stripped) member event.
async fn invite_was_direct(room: &Room) -> bool {
    let Some(own) = room.client().user_id().map(|u| u.to_owned()) else {
        return false;
    };
    let Some(member) = room.get_member(&own).await.ok().flatten() else {
        return false;
    };
    use matrix_sdk::deserialized_responses::SyncOrStrippedState;
    match member.event().as_ref() {
        SyncOrStrippedState::Sync(e) => e
            .as_original()
            .map(|o| o.content.is_direct)
            .unwrap_or_default()
            .unwrap_or(false),
        SyncOrStrippedState::Stripped(e) => e.content.is_direct.unwrap_or(false),
    }
}

/// The IRC prompt line for a pending invitation.
fn invite_prompt(irc_nick: &str, inv: &PendingInvite) -> Message {
    proto::user(
        crate::matrix::verification::CONTROL_NICK,
        Command::NOTICE(
            irc_nick.to_owned(),
            format!(
                "invite #{}: {} from {} — /msg {} accept {} | decline {} [{}]",
                inv.idx,
                inv.name,
                proto::mxid_to_nick(&inv.sender),
                crate::matrix::verification::CONTROL_NICK,
                inv.idx,
                inv.idx,
                inv.room_id
            ),
        ),
    )
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
        .send(proto::user("matrix", Command::TOPIC(entry.channel, Some(topic.replace(['\r', '\n'], " ")))))
        .await;
}

pub(crate) async fn sync_forever(client: Client) {
    loop {
        tracing::debug!("starting continuous sync");
        if let Err(e) = client.sync(SyncSettings::default()).await {
            tracing::error!(error = %e, "matrix sync loop died, restarting in 5s");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }
}

/// Max bytes fetched for a bare-URL upload.
const URL_ATTACHMENT_LIMIT: usize = 25 * 1024 * 1024;

/// Extension → MIME for bare-URL uploads. `None` means "not recognizable,
/// keep the message a plain text link".
fn ext_mime(url: &str) -> Option<&'static str> {
    let path = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url);
    let path = path.split(['?', '#']).next().unwrap_or("");
    let name = path.rsplit('/').next().unwrap_or("");
    let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
    Some(match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "bmp" => "image/bmp",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "mp3" => "audio/mpeg",
        "ogg" | "oga" | "opus" => "audio/ogg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "json" => "application/json",
        "xml" => "application/xml",
        "doc" | "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" | "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" | "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "apk" => "application/vnd.android.package-archive",
        "iso" => "application/x-iso9660-image",
        "deb" => "application/vnd.debian.binary-package",
        "rpm" => "application/x-rpm",
        _ => return None,
    })
}

/// Filename of a URL path ("download" when the path has none).
fn url_filename(url: &str) -> String {
    let path = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let path = path.split(['?', '#']).next().unwrap_or("");
    let name = path.rsplit('/').next().unwrap_or("");
    let name = percent_decode(name);
    if name.is_empty() {
        "download".to_owned()
    } else {
        name
    }
}

/// Minimal percent-decoding for filename display.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() + 1 && i + 2 < bytes.len() {
            let hex = &s[i + 1..i + 3];
            if let Ok(v) = u8::from_str_radix(hex, 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// If `body` is a bare http(s) URL pointing at recognizable media, download
/// it (size-capped) and send it as a native Matrix attachment. Returns
/// `None` when the body should stay a plain text message; `Some(result)` is
/// the final send outcome.
async fn try_url_attachment(room: &Room, body: &str) -> Option<Result<String>> {
    if !(body.starts_with("http://") || body.starts_with("https://")) || body.contains(char::is_whitespace) {
        return None;
    }
    // decide the MIME: Content-Type wins, the extension is the fallback
    let http = match reqwest::Client::builder()
        .user_agent(concat!(
            "matrix2078/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/h4ks-com/matrix2078)"
        ))
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };
    let resp = match http.get(body).send().await {
        Ok(r) if r.status().is_success() => r,
        Ok(r) => {
            tracing::debug!(url = body, status = %r.status(), "url attachment: fetch failed");
            return None;
        }
        Err(e) => {
            tracing::debug!(url = body, error = %e, "url attachment: network error");
            return None;
        }
    };
    let header_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or("").trim().to_owned());
    let mime_str = match header_type {
        Some(t) if !t.is_empty() && t != "application/octet-stream" => t,
        _ => ext_mime(body)?.to_owned(),
    };
    // only media/document types become uploads; web pages stay links
    let is_media = mime_str.starts_with("image/")
        || mime_str.starts_with("video/")
        || mime_str.starts_with("audio/")
        || mime_str.starts_with("application/")
        || mime_str.starts_with("text/plain");
    if !is_media || mime_str == "text/html" {
        tracing::debug!(url = body, mime = %mime_str, "url attachment: not a media type");
        return None;
    }
    // size guard before pulling the body
    if let Some(len) = resp.content_length() {
        if len as usize > URL_ATTACHMENT_LIMIT {
            return None;
        }
    }
    let data = match resp.bytes().await {
        Ok(b) => b,
        Err(_) => return None,
    };
    if data.is_empty() || data.len() > URL_ATTACHMENT_LIMIT {
        return None;
    }
    let mime: mime::Mime = match mime_str.parse() {
        Ok(m) => m,
        Err(_) => return None,
    };
    let filename = url_filename(body);
    tracing::info!(%filename, %mime_str, bytes = data.len(), "uploading bare URL as attachment");
    let send = room
        .send_attachment(
            filename,
            &mime,
            data.to_vec(),
            matrix_sdk::attachment::AttachmentConfig::new(),
        )
        .await;
    Some(send.map(|r| r.event_id.to_string()).map_err(|e| anyhow::anyhow!("uploading URL: {e:#}")))
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

/// HTML `formatted_body` of a message msgtype, if the client sent
/// `org.matrix.custom.html`.
fn formatted_of(msgtype: &MessageType) -> Option<String> {
    use matrix_sdk::ruma::events::room::message::MessageFormat;
    let formatted = match msgtype {
        MessageType::Text(c) => c.formatted.as_ref()?,
        MessageType::Notice(c) => c.formatted.as_ref()?,
        MessageType::Emote(c) => c.formatted.as_ref()?,
        _ => return None,
    };
    if !matches!(formatted.format, MessageFormat::Html) {
        return None;
    }
    Some(formatted.body.clone())
}

/// Replace full mxids (`@user:server`) of room members with IRC nicks.
async fn localize_mentions(body: &str, room: &Room) -> String {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"@[\w./=#+-]+:[\w.\-]+(?::\d+)?").expect("mxid regex"));
    if !re.is_match(body) {
        return body.to_owned();
    }
    let members = room
        .members(matrix_sdk::RoomMemberships::JOIN)
        .await
        .unwrap_or_default();
    let mut out = String::with_capacity(body.len());
    let mut last = 0;
    for m in re.captures_iter(body) {
        let whole = m.get(0).expect("group 0");
        out.push_str(&body[last..whole.start()]);
        let found = members
            .iter()
            .find(|mem| mem.user_id().as_str() == whole.as_str());
        match found {
            Some(mem) => out.push_str(&proto::mxid_to_nick(mem.user_id().as_str())),
            None => out.push_str(whole.as_str()),
        }
        last = whole.end();
    }
    out.push_str(&body[last..]);
    out
}

/// Matrix user ids mentioned by IRC nicks appearing as words in `body`.
async fn mentioned_mxids(
    body: &str,
    _room: &Room,
    member_mxids: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    for word in body.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-' && c != '[' && c != ']' && c != '^' && c != '{' && c != '}') {
        for mxid in member_mxids {
            let nick = proto::mxid_to_nick(mxid);
            if nick.eq_ignore_ascii_case(word) && !out.iter().any(|m| m == mxid) {
                out.push(mxid.clone());
            }
        }
    }
    out.sort();
    out
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
