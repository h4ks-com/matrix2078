//! Persistent Matrix room → IRC channel mapping.
//!
//! Channel names must be stable per room (AGENTS.md): a Matrix room name
//! change surfaces as TOPIC, never as a channel rename. The mapping is
//! persisted as JSON under `state_dir/<nick>/channels.json`.
//!
//! Naming (matrix2051 rules): canonical alias localpart, else sanitized
//! display name; collisions deduped with `_2`, `_3`, … suffixes.

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use matrix_sdk::ruma::OwnedRoomId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomEntry {
    pub room_id: OwnedRoomId,
    /// IRC channel name, always `#…`, lowercase. Empty for query (DM)
    /// mappings, which live in `query` instead.
    pub channel: String,
    /// Query nick of the other party — set for 2-member DM rooms mapped to
    /// IRC queries instead of channels.
    #[serde(default)]
    pub query: Option<String>,
    /// Current topic shown to IRC (room topic or name).
    pub topic: String,
}

#[derive(Debug)]
pub struct RoomMaps {
    rooms: Vec<RoomEntry>,
    path: PathBuf,
}

impl RoomMaps {
    pub fn load(path: PathBuf) -> Self {
        let rooms = fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<RoomEntry>>(&b).ok())
            .unwrap_or_default();
        Self { rooms, path }
    }

    fn save(&self) {
        if let Err(e) = fs::create_dir_all(self.path.parent().unwrap_or(Path::new(".")))
            .and_then(|_| {
                fs::write(&self.path, serde_json::to_vec_pretty(&self.rooms).expect("serde rooms"))
            })
        {
            tracing::warn!(error = %e, path = %self.path.display(), "failed to persist channel map");
        }
    }

    /// Drop mappings for rooms we are no longer in.
    pub fn prune_to(&mut self, live: &HashSet<OwnedRoomId>) {
        let before = self.rooms.len();
        self.rooms.retain(|r| live.contains(&r.room_id));
        if self.rooms.len() != before {
            self.save();
        }
    }

    pub fn entries(&self) -> &[RoomEntry] {
        &self.rooms
    }

    pub fn get_by_room(&self, room_id: &matrix_sdk::ruma::RoomId) -> Option<&RoomEntry> {
        self.rooms.iter().find(|r| r.room_id == room_id)
    }

    pub fn get_by_room_mut(&mut self, room_id: &matrix_sdk::ruma::RoomId) -> Option<&mut RoomEntry> {
        self.rooms.iter_mut().find(|r| r.room_id == room_id)
    }

    pub fn get_by_channel(&self, channel: &str) -> Option<&RoomEntry> {
        let lower = channel.to_ascii_lowercase();
        self.rooms.iter().find(|r| r.channel == lower && !r.channel.is_empty())
    }

    /// Find a DM/query mapping by the other party's nick (case-insensitive).
    pub fn get_by_query(&self, nick: &str) -> Option<&RoomEntry> {
        self.rooms
            .iter()
            .find(|r| r.query.as_deref().is_some_and(|q| q.eq_ignore_ascii_case(nick)))
    }

    /// Insert or refresh the mapping for a room, computing a unique stable
    /// channel name on first sight. `base` is the preferred channel base
    /// (alias localpart or display name, without `#`).
    pub fn ensure(&mut self, room_id: OwnedRoomId, base: &str, topic: String) -> &RoomEntry {
        if let Some(idx) = self.rooms.iter().position(|r| r.room_id == room_id) {
            let e = &mut self.rooms[idx];
            if e.topic != topic {
                e.topic = topic;
                self.save();
            }
            return &self.rooms[idx];
        }
        let channel = self.unique_channel(base);
        self.rooms.push(RoomEntry { room_id, channel, query: None, topic });
        self.save();
        self.rooms.last().expect("just pushed")
    }

    /// Insert or refresh a DM mapping: the room surfaces as IRC queries with
    /// `nick` (the other party) instead of a channel.
    pub fn ensure_query(&mut self, room_id: OwnedRoomId, nick: &str, topic: String) -> &RoomEntry {
        if let Some(idx) = self.rooms.iter().position(|r| r.room_id == room_id) {
            let e = &mut self.rooms[idx];
            e.query = Some(nick.to_owned());
            e.channel = String::new();
            if e.topic != topic {
                e.topic = topic;
                self.save();
            }
            return &self.rooms[idx];
        }
        let unique = self.unique_query_nick(nick);
        self.rooms.push(RoomEntry {
            room_id,
            channel: String::new(),
            query: Some(unique),
            topic,
        });
        self.save();
        self.rooms.last().expect("just pushed")
    }

    /// Two users with the same localpart map to the same nick; dedupe with
    /// `_2` suffixes so queries stay routable.
    fn unique_query_nick(&self, nick: &str) -> String {
        let taken = |n: &str| {
            self.rooms
                .iter()
                .any(|r| r.query.as_deref().is_some_and(|q| q.eq_ignore_ascii_case(n)))
        };
        if !taken(nick) {
            return nick.to_owned();
        }
        for i in 2.. {
            let candidate = format!("{nick}_{i}");
            if !taken(&candidate) {
                return candidate;
            }
        }
        unreachable!()
    }

    fn unique_channel(&self, base: &str) -> String {
        let sanitized = sanitize_base(base);
        let taken: HashSet<String> =
            self.rooms.iter().map(|r| r.channel.clone()).collect();
        let candidate = format!("#{sanitized}");
        if !taken.contains(&candidate) {
            return candidate;
        }
        for i in 2.. {
            let candidate = format!("#{sanitized}_{i}");
            if !taken.contains(&candidate) {
                return candidate;
            }
        }
        unreachable!()
    }
}

/// Sanitize a room alias localpart / display name into a channel base:
/// lowercase, keep `[a-z0-9._-]`, collapse everything else to `_`.
pub fn sanitize_base(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_underscore = false;
    for c in raw.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_' || c == '-' {
            out.push(c);
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    let trimmed = out.trim_matches(|c| c == '_' || c == '.').to_string();
    let mut base: String = trimmed.chars().take(32).collect();
    if base.is_empty() {
        base = "room".to_owned();
    }
    base
}

#[cfg(test)]
mod tests {
    use super::*;
    use matrix_sdk::ruma::{owned_room_id, room_id};

    fn rid(s: &str) -> OwnedRoomId {
        OwnedRoomId::try_from(s.to_owned()).expect("valid room id")
    }

    fn maps() -> RoomMaps {
        let dir = tempfile::tempdir().unwrap();
        RoomMaps::load(dir.path().join("channels.json"))
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_base("m2078-plain"), "m2078-plain");
        // non-ascii runs collapse to a single underscore, then get trimmed
        assert_eq!(sanitize_base("Мама Weeby!!!"), "weeby");
        assert_eq!(sanitize_base("___...___"), "room");
        assert_eq!(sanitize_base(""), "room");
        let long = "x".repeat(100);
        assert_eq!(sanitize_base(&long).len(), 32);
    }

    #[test]
    fn unique_names_and_stability() {
        let mut m = maps();
        let a = m.ensure(rid("!a:x.org"), "dev", "t".into());
        assert_eq!(a.channel, "#dev");
        let b = m.ensure(rid("!b:x.org"), "dev", "t".into());
        assert_eq!(b.channel, "#dev_2");
        let c = m.ensure(rid("!c:x.org"), "DeV", "t".into());
        assert_eq!(c.channel, "#dev_3");

        // same room asked again: name is stable, no new suffix
        let a2 = m.ensure(rid("!a:x.org"), "dev", "t2".into());
        assert_eq!(a2.channel, "#dev");
        assert_eq!(a2.topic, "t2");
        assert_eq!(m.rooms.len(), 3);
    }

    #[test]
    fn query_mapping() {
        let mut m = maps();
        let a = m.ensure_query(rid("!dm:x.org"), "alice", "t".into());
        assert_eq!(a.query.as_deref(), Some("alice"));
        assert_eq!(a.channel, "");
        assert!(m.get_by_channel("#alice").is_none());
        assert_eq!(m.get_by_query("ALICE").unwrap().room_id, room_id!("!dm:x.org"));
        // two different users named bob: second gets a deduped nick
        m.ensure_query(rid("!dm2:x.org"), "bob", "t".into());
        let b2 = m.ensure_query(rid("!dm3:x.org"), "bob", "t".into());
        assert_eq!(b2.query.as_deref(), Some("bob_2"));
        // a channel and a query never collide
        let c = m.ensure(rid("!ch:x.org"), "alice", "t".into());
        assert_eq!(c.channel, "#alice");
        assert_eq!(m.get_by_query("alice").unwrap().room_id, room_id!("!dm:x.org"));
        // a room migrated from channel to query loses its channel name
        let e = m.ensure_query(rid("!ch:x.org"), "carol", "t".into());
        assert_eq!(e.channel, "");
        assert!(m.get_by_channel("#alice").is_none());
    }

    #[test]
    fn deserialize_legacy_entry_without_query() {
        let json = r##"[{"room_id":"!a:x.org","channel":"#dev","topic":"t"}]"##;
        let rooms: Vec<RoomEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(rooms[0].channel, "#dev");
        assert!(rooms[0].query.is_none());
    }

    #[test]
    fn lookup_and_prune() {
        let mut m = maps();
        m.ensure(rid("!a:x.org"), "alpha", "t".into());
        m.ensure(rid("!b:x.org"), "beta", "t".into());
        assert_eq!(m.get_by_channel("#ALPHA").unwrap().room_id, room_id!("!a:x.org"));
        assert!(m.get_by_channel("#nope").is_none());

        let live: HashSet<OwnedRoomId> = [rid("!a:x.org")].into_iter().collect();
        m.prune_to(&live);
        assert_eq!(m.rooms.len(), 1);
        assert!(m.get_by_room(room_id!("!b:x.org")).is_none());
    }
}
