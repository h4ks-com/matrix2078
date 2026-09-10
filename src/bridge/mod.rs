//! M0 bridge: one Matrix room ⇄ one IRC channel, both directions.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use irc::proto::{Command, Message};
use matrix_sdk::{
    Client, Room, RoomState,
    config::SyncSettings,
    ruma::{
        OwnedRoomId,
        events::room::message::{MessageType, RoomMessageEventContent, SyncRoomMessageEvent},
    },
};
use tokio::sync::mpsc;

use crate::{
    config::Config,
    ircd::proto,
    matrix::client::login_or_restore,
};

#[derive(Clone)]
pub struct Bridge {
    pub client: Client,
    pub room: Room,
    pub room_id: OwnedRoomId,
    /// IRC channel name (stable, `#…`).
    pub channel: String,
    /// Topic shown to the IRC client (room topic or name).
    pub topic: String,
    /// Nicks present in the room (M0: mxid localparts).
    pub members: Vec<String>,
    /// Our own Matrix user id, to skip echoes of our own sends.
    pub own_mxid: matrix_sdk::ruma::OwnedUserId,
}

impl Bridge {
    /// Log in / restore the Matrix session and do the initial sync.
    pub async fn connect(
        cfg: &Arc<Config>,
        nick: &str,
        irc_pass: &str,
        login_user: &str,
    ) -> Result<Self> {
        let client = login_or_restore(cfg, nick, irc_pass, login_user).await?;

        client
            .sync_once(
                SyncSettings::default().ignore_timeout_on_first_sync(true),
            )
            .await
            .context("initial matrix sync failed")?;
        let own_mxid = client
            .user_id()
            .map(|u| u.to_owned())
            .ok_or_else(|| anyhow::anyhow!("client has no user id after sync"))?;

        let (room, channel) = Self::pick_room(&client, cfg).await?;
        let room_id = room.room_id().to_owned();
        let topic = Self::room_topic(&room, &channel);
        let members = Self::member_nicks(&room).await;

        Ok(Self { client, room, room_id, channel, topic, members, own_mxid })
    }

    async fn pick_room(client: &Client, cfg: &Config) -> Result<(Room, String)> {
        match cfg.bridge.room.as_deref() {
            Some(spec) => {
                let room_id = if let Some(id) = spec.strip_prefix('!') {
                    matrix_sdk::ruma::OwnedRoomId::try_from(format!("!{id}"))
                        .map_err(|e| anyhow::anyhow!("bad room id {spec:?}: {e}"))?
                } else if let Some(alias) = spec.strip_prefix('#') {
                    let alias = matrix_sdk::ruma::OwnedRoomAliasId::try_from(format!("#{alias}"))
                        .map_err(|e| anyhow::anyhow!("bad room alias {spec:?}: {e}"))?;
                    let resolved = client
                        .resolve_room_alias(&alias)
                        .await
                        .with_context(|| format!("resolving alias {spec}"))?;
                    resolved.room_id
                } else {
                    bail!("bridge.room must be a room id (!…) or alias (#…), got {spec:?}")
                };
                let room = client
                    .get_room(&room_id)
                    .ok_or_else(|| anyhow::anyhow!("we are not in room {room_id}"))?;
                let channel = default_channel_for(cfg, spec);
                Ok((room, channel))
            }
            None => {
                let room = client
                    .joined_rooms()
                    .into_iter()
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("no joined rooms to relay"))?;
                Ok((room, cfg.bridge.channel.clone()))
            }
        }
    }

    fn room_topic(room: &Room, channel: &str) -> String {
        let base = if let Some(t) = room.topic().filter(|t| !t.is_empty()) {
            t
        } else if let Some(name) = room.name().filter(|n| !n.is_empty()) {
            name
        } else {
            format!("Matrix room {}", room.room_id())
        };
        format!("{} [{}]", base.replace('\n', " | ").replace('\r', ""), channel)
    }

    async fn member_nicks(room: &Room) -> Vec<String> {
        match room.members(matrix_sdk::RoomMemberships::JOIN).await {
            Ok(members) => members
                .iter()
                .map(|m| proto::mxid_to_nick(m.user_id().as_str()))
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "listing room members failed");
                Vec::new()
            }
        }
    }

    /// Subscribe to room messages; relayed lines are pushed into `tx`.
    pub fn relay_matrix_to_irc(&self, tx: mpsc::Sender<Message>) {
        let room_id = self.room_id.clone();
        let channel = self.channel.clone();
        let own = self.own_mxid.clone();
        self.client.add_event_handler(move |ev: SyncRoomMessageEvent, room: Room| {
            let tx = tx.clone();
            async move {
                let matrix_sdk::ruma::events::SyncMessageLikeEvent::Original(ev) = ev else {
                    return;
                };
                if room.room_id() != &room_id || room.state() != RoomState::Joined {
                    return;
                }
                if ev.sender == own {
                    return;
                }
                let (body, notice) = match ev.content.msgtype {
                    MessageType::Text(t) => (t.body, false),
                    MessageType::Notice(t) => (t.body, true),
                    _ => return,
                };
                let nick = proto::mxid_to_nick(ev.sender.as_str());
                let cmd = if notice {
                    Command::NOTICE(channel.clone(), body)
                } else {
                    Command::PRIVMSG(channel.clone(), body)
                };
                if let Err(e) = tx.send(proto::user(&nick, cmd)).await {
                    tracing::warn!(error = %e, "irc side went away");
                }
            }
        });
    }

    /// Keep the sync loop running in the background. The returned handle
    /// must be aborted when the owning IRC connection goes away.
    pub fn spawn_sync(&self) -> tokio::task::JoinHandle<()> {
        let client = self.client.clone();
        tokio::spawn(sync_forever(client))
    }

    /// Deliver an IRC line to Matrix (text or notice).
    pub async fn send_from_irc(&self, body: String, notice: bool) -> Result<()> {
        let content = if notice {
            RoomMessageEventContent::notice_plain(body)
        } else {
            RoomMessageEventContent::text_plain(body)
        };
        self.room
            .send(content)
            .await
            .map(|_| ())
            .context("sending message to matrix room")?;
        Ok(())
    }
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

fn default_channel_for(cfg: &Config, spec: &str) -> String {
    if cfg.bridge.channel != "#matrix" {
        return cfg.bridge.channel.clone();
    }
    // default: derive from alias localpart
    if let Some(rest) = spec.strip_prefix('#') {
        let local = rest.split(':').next().unwrap_or("matrix");
        let clean: String = local
            .chars()
            .map(|c| if c.is_alphanumeric() || "._-".contains(c) { c } else { '_' })
            .collect();
        format!("#{}", clean)
    } else {
        "#matrix".to_owned()
    }
}
