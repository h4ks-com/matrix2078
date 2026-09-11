//! CHATHISTORY backend: fetch room history from Matrix (`/messages`,
//! `/context`) and map it to IRC messages with `time`/`msgid` tags.

use anyhow::{Context, Result};
use matrix_sdk::{
    Room,
    deserialized_responses::TimelineEvent,
    room::MessagesOptions,
    ruma::{
        events::{
            AnySyncMessageLikeEvent, AnySyncTimelineEvent,
            room::message::MessageType,
        },
        EventId, UInt, uint,
    },
};

use crate::ircd::proto;

/// Max pages of `/messages` we will walk for a timestamp-restricted query.
const MAX_TS_PAGES: usize = 10;

/// A relayable history message.
#[derive(Debug, Clone)]
pub struct HistoryItem {
    pub ts_ms: u64,
    pub event_id: String,
    pub sender: String,
    pub notice: bool,
    pub body: String,
    pub reply_to: Option<String>,
}

/// Parse the `time=` tag format (`ISO 8601`) back into unix milliseconds.
pub fn parse_iso_time(s: &str) -> Option<u64> {
    // Minimal parser: YYYY-MM-DDTHH:MM:SS(.mmm)?Z
    let s = s.trim_end_matches('Z');
    let (date, rest) = s.split_once('T')?;
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let d: i64 = d.next()?.parse().ok()?;
    let (hms, frac) = match rest.split_once('.') {
        Some((h, f)) => (h, f),
        None => (rest, ""),
    };
    let mut t = hms.split(':');
    let h: i64 = t.next()?.parse().ok()?;
    let mi: i64 = t.next()?.parse().ok()?;
    let se: i64 = t.next()?.parse().ok()?;
    let millis: u64 = if frac.is_empty() {
        0
    } else {
        let padded = format!("{frac:0<3}");
        padded[..3.min(padded.len())].parse().unwrap_or(0)
    };
    // days from civil (inverse of proto::civil_from_days)
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + se;
    Some(secs.unsigned_abs() * 1000 + millis)
}

/// Extract a relayable message from a raw timeline event, if it is one.
fn item_from_event(ev: &TimelineEvent) -> Option<HistoryItem> {
    let raw = ev.raw().deserialize().ok()?;
    let AnySyncTimelineEvent::MessageLike(msg) = raw else {
        return None;
    };
    // events we could not decrypt stay m.room.encrypted — show a placeholder
    if let AnySyncMessageLikeEvent::RoomEncrypted(matrix_sdk::ruma::events::SyncMessageLikeEvent::Original(enc)) = &msg
    {
        return Some(HistoryItem {
            ts_ms: u64::from(enc.origin_server_ts.get()),
            event_id: enc.event_id.to_string(),
            sender: enc.sender.to_string(),
            notice: true,
            body: "\u{1f512} [unable to decrypt]".to_owned(),
            reply_to: None,
        });
    }
    let AnySyncMessageLikeEvent::RoomMessage(msg) = msg else {
        return None;
    };
    let matrix_sdk::ruma::events::SyncMessageLikeEvent::Original(orig) = msg else {
        return None;
    };
    use matrix_sdk::ruma::events::room::message::Relation;
    let mut reply_to = None;
    if let Some(rel) = &orig.content.relates_to {
        match rel {
            Relation::Replacement(_) => return None, // edits are folded into the original in M4
            Relation::Reply(r) => {
                reply_to = Some(r.in_reply_to.event_id.to_string());
            }
            _ => {}
        }
    }
    let ts = u64::from(orig.origin_server_ts.get());
    let mut body = history_body(&orig.content.msgtype);
    if reply_to.is_some() {
        body = crate::format::strip_reply_fallback(&body);
    }
    Some(HistoryItem {
        ts_ms: ts,
        event_id: orig.event_id.to_string(),
        sender: orig.sender.to_string(),
        notice: matches!(orig.content.msgtype, MessageType::Notice(_)),
        body,
        reply_to,
    })
}

/// Render a msgtype for history output (no media fetches — they'd be slow).
fn history_body(msgtype: &MessageType) -> String {
    match msgtype {
        MessageType::Text(c) => c.body.clone(),
        MessageType::Notice(c) => c.body.clone(),
        MessageType::Emote(c) => format!("\u{1}ACTION {}\u{1}", c.body),
        MessageType::Image(c) => format!("[image] {}", c.body),
        MessageType::Audio(c) => format!("[audio] {}", c.body),
        MessageType::Video(c) => format!("[video] {}", c.body),
        MessageType::File(c) => format!("[file] {}", c.body),
        _ => String::new(),
    }
}

/// CHATHISTORY BEFORE/AFTER with a msgid anchor: use `/context`, then
/// paginate with `/messages` if more events are needed.
pub async fn around_msgid(
    room: &Room,
    anchor: &str,
    before: usize,
    after: usize,
) -> Result<(Vec<HistoryItem>, Vec<HistoryItem>)> {
    let eid = EventId::parse(anchor.trim_start_matches('$'))
        .with_context(|| format!("bad event id {anchor}"))?;
    let ctx_limit = UInt::try_from(before.max(after).min(100)).unwrap_or_else(|_| uint!(100));
    let resp = room
        .event_with_context(&eid, false, ctx_limit, None)
        .await
        .context("matrix /context failed")?;

    // events_before is reverse-chronological
    let mut before_items: Vec<HistoryItem> =
        resp.events_before.iter().filter_map(item_from_event).collect();
    // events_after is chronological
    let mut after_items: Vec<HistoryItem> =
        resp.events_after.iter().filter_map(item_from_event).collect();

    // top up via /messages if the context window was too small
    if before_items.len() < before && before > 0 {
        let mut from = resp.prev_batch_token.clone();
        let mut have = before_items.len();
        while have < before {
            let Some(token) = from.clone() else { break };
            let mut opts = MessagesOptions::backward().from(token.as_str());
            opts.limit = uint!(100);
            let Ok(page) = room.messages(opts).await else { break };
            let items: Vec<HistoryItem> = page.chunk.iter().filter_map(item_from_event).collect();
            have += items.len();
            // backward chunk is newest-first; prepend in order
            let mut merged = items;
            merged.extend(before_items.drain(..));
            before_items = merged;
            match page.end {
                Some(t) if !before_items.is_empty() => from = Some(t),
                _ => break,
            }
        }
    }
    if after_items.len() < after && after > 0 {
        let mut from = resp.next_batch_token.clone();
        let mut have = after_items.len();
        while have < after {
            let Some(token) = from.clone() else { break };
            let mut opts = MessagesOptions::forward().from(token.as_str());
            opts.limit = uint!(100);
            let Ok(page) = room.messages(opts).await else { break };
            let items: Vec<HistoryItem> = page.chunk.iter().filter_map(item_from_event).collect();
            have += items.len();
            after_items.extend(items);
            match page.end {
                Some(t) if !after_items.is_empty() => from = Some(t),
                _ => break,
            }
        }
    }

    before_items.truncate(before);
    after_items.truncate(after);
    // both lists returned chronological
    Ok((before_items, after_items))
}

/// Walk backwards from the room's live edge collecting message events,
/// optionally bounded by a timestamp filter (`keep(ts)`).
async fn walk_backward<F>(room: &Room, limit: usize, keep: F) -> Result<Vec<HistoryItem>>
where
    F: Fn(u64) -> bool,
{
    let mut from: Option<String> = None;
    let mut out: Vec<HistoryItem> = Vec::new(); // newest-first
    let mut pages = 0usize;
    loop {
        let mut opts = MessagesOptions::backward();
        opts.limit = uint!(100);
        if let Some(token) = from.clone() {
            opts.from = Some(token);
        }
        let page = room.messages(opts).await.context("matrix /messages failed")?;
        pages += 1;
        for ev in &page.chunk {
            if let Some(item) = item_from_event(ev) {
                if keep(item.ts_ms) {
                    out.push(item);
                }
            }
        }
        let hit_limit = out.len() >= limit;
        match page.end {
            Some(t) if !hit_limit && pages < MAX_TS_PAGES => from = Some(t),
            _ => break,
        }
    }
    out.truncate(limit);
    Ok(out) // newest-first
}

/// CHATHISTORY LATEST (no anchor): newest `limit` message events, chronological.
pub async fn latest(room: &Room, limit: usize) -> Result<Vec<HistoryItem>> {
    let mut items = walk_backward(room, limit, |_| true).await?;
    items.reverse(); // chronological
    Ok(items)
}

/// CHATHISTORY LATEST timestamp=ts: events with ts >= anchor, chronological.
pub async fn latest_since(room: &Room, ts_ms: u64, limit: usize) -> Result<Vec<HistoryItem>> {
    let mut items = walk_backward(room, limit, |ts| ts >= ts_ms).await?;
    items.reverse();
    Ok(items)
}

/// CHATHISTORY BEFORE timestamp=ts: up to `limit` events strictly older than
/// the anchor, chronological.
pub async fn before_timestamp(room: &Room, ts_ms: u64, limit: usize) -> Result<Vec<HistoryItem>> {
    let mut items = walk_backward(room, limit, |ts| ts < ts_ms).await?;
    items.reverse();
    Ok(items)
}

/// Map history items to IRC PRIVMSG/NOTICE lines with `time`/`msgid` (and
/// `+draft/reply` for replies) tags.
pub fn to_irc(target: &str, items: &[HistoryItem]) -> Vec<irc::proto::Message> {
    items
        .iter()
        .filter(|i| !i.body.is_empty())
        .map(|i| {
            let nick = proto::mxid_to_nick(&i.sender);
            let cmd = if i.notice {
                irc::proto::Command::NOTICE(target.to_owned(), i.body.clone())
            } else {
                irc::proto::Command::PRIVMSG(target.to_owned(), i.body.clone())
            };
            let mut m = proto::user(&nick, cmd);
            let mut tags = vec![proto::time_tag(i.ts_ms), proto::msgid_tag(&i.event_id)];
            if let Some(r) = &i.reply_to {
                tags.push(irc::proto::message::Tag(
                    "+draft/reply".to_owned(),
                    Some(r.clone()),
                ));
            }
            m.tags = Some(tags);
            m
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_parse_roundtrip() {
        for ms in [0u64, 1709164800123, 1787718896789, 951782400000] {
            let iso = proto::iso_time(ms);
            assert_eq!(parse_iso_time(&iso), Some(ms), "roundtrip failed for {iso}");
        }
        assert_eq!(parse_iso_time("2024-02-29T00:00:00Z"), Some(1709164800000));
        assert!(parse_iso_time("garbage").is_none());
        assert!(parse_iso_time("2024-02-29").is_none());
    }
}
