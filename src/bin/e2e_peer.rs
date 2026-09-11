#![recursion_limit = "4096"]

//! E2EE test peer (shipped in the same crate to share one target dir):
//! logs in as the peer test user, and either sends (auto-encrypted)
//! messages/files or runs an automated SAS verification against matrix2078's
//! device.
//!
//! Usage:
//!   matrix2078 --bin e2e_peer -- send <room-id> <text...>
//!   matrix2078 --bin e2e_peer -- send-image <room-id> <file> [body]
//!   matrix2078 --bin e2e_peer -- verify        (waits for a request; auto-accepts/confirms)
//!   matrix2078 --bin e2e_peer -- request <mxid>
//!
//! Env: E2E_PEER_HOMESERVER, E2E_PEER_USER, E2E_PEER_PASS, E2E_PEER_STATE.
//! Progress lines are printed to stdout (flushed) for the test scripts.

use std::{io::Write as _, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use matrix_sdk::{
    Client,
    config::SyncSettings,
    encryption::verification::{SasVerification, Verification, VerificationRequest},
    room::MessagesOptions,
    ruma::{
        events::{
            key::verification::request::ToDeviceKeyVerificationRequestEvent,
            room::message::{
                ImageMessageEventContent, MessageType, RoomMessageEventContent,
                ReplacementMetadata,
            },
            Mentions,
        },
        EventId, OwnedUserId, RoomId, UserId,
    },
};
use matrix_sdk::ruma::events::room::message::Relation as MessageRelation;

fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}
use tokio::sync::mpsc;

fn out(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredSession {
    homeserver: String,
    session: matrix_sdk::authentication::matrix::MatrixSession,
}

async fn build_client(homeserver: &str, state: &PathBuf) -> Result<Client> {
    std::fs::create_dir_all(state)?;
    Client::builder()
        .homeserver_url(homeserver)
        .sqlite_store(state, None)
        .build()
        .await
        .context("building client")
}

async fn login(homeserver: &str, user: &str, pass: &str, state: &PathBuf) -> Result<Client> {
    let sess_path = state.join("session.json");
    let client = build_client(homeserver, state).await?;
    if sess_path.exists() {
        let stored: StoredSession = serde_json::from_str(&std::fs::read_to_string(&sess_path)?)?;
        client
            .matrix_auth()
            .restore_session(stored.session, matrix_sdk::store::RoomLoadSettings::default())
            .await
            .context("restore session")?;
        out(&format!("RESTORED {}", client.user_id().unwrap()));
    } else {
        client
            .matrix_auth()
            .login_username(user, pass)
            .initial_device_display_name("m2078-e2e-peer")
            .send()
            .await
            .context("login")?;
        let session = client.matrix_auth().session().context("no session")?;
        std::fs::write(
            &sess_path,
            serde_json::to_string(&StoredSession { homeserver: homeserver.to_owned(), session })?,
        )?;
        out(&format!("LOGGEDIN {}", client.user_id().unwrap()));
    }
    let c = client.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = c.sync(SyncSettings::default()).await {
                eprintln!("sync error: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    });
    // let the first sync settle
    tokio::time::sleep(Duration::from_secs(2)).await;
    Ok(client)
}

/// Drive a verification flow we take part in: auto-accept if it's incoming,
/// start SAS when ready, print emojis, auto-confirm, print VERIFIED.
async fn auto_flow(
    client: Client,
    request: VerificationRequest,
    we_started: bool,
    done_tx: mpsc::Sender<()>,
) {
    if !we_started {
        if let Err(e) = request.accept().await {
            out(&format!("ACCEPTFAIL {e}"));
            return;
        }
        out("ACCEPTED");
    }
    let other: OwnedUserId = request.other_user_id().to_owned();
    let flow_id = request.flow_id().to_owned();
    let mut sas: Option<SasVerification> = None;
    let mut shown = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        if tokio::time::Instant::now() > deadline {
            out("TIMEOUT");
            let _ = request.cancel().await;
            return;
        }
        if request.is_done() {
            out("VERIFIED");
            let _ = done_tx.send(()).await;
            return;
        }
        if request.is_cancelled() {
            out("CANCELLED");
            return;
        }
        if sas.is_none() {
            let found = if we_started && request.is_ready() {
                request.start_sas().await.ok().flatten()
            } else {
                match client.encryption().get_verification(&other, &flow_id).await {
                    Some(Verification::SasV1(s)) => Some(s),
                    _ => None,
                }
            };
            if let Some(s) = found {
                sas = Some(s);
            }
        }
        if let Some(s) = &sas {
            if !shown && s.can_be_presented() {
                if let Some(emojis) = s.emoji() {
                    let syms: Vec<&str> = emojis.iter().map(|e| e.symbol).collect();
                    out(&format!("SAS {}", syms.join(" ")));
                }
                shown = true;
            }
            if shown {
                if let Err(e) = s.confirm().await {
                    out(&format!("CONFIRMFAIL {e}"));
                } else {
                    out("CONFIRMED");
                }
                // is_done lands on the next iteration(s); brief cooldown so we
                // don't spam m.key.verification.confirm
                tokio::time::sleep(Duration::from_millis(900)).await;
                continue;
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
}

async fn run_verify(client: Client, start_to: Option<&str>) -> Result<()> {
    let (done_tx, mut done_rx) = mpsc::channel::<()>(1);
    let (req_tx, mut req_rx) = mpsc::channel::<VerificationRequest>(4);
    let ct = client.clone();
    client.add_event_handler(
        move |ev: ToDeviceKeyVerificationRequestEvent, client: Client| {
            let tx = req_tx.clone();
            async move {
                let flow = ev.content.transaction_id.to_string();
                if let Some(req) = client
                    .encryption()
                    .get_verification_request(&ev.sender, &flow)
                    .await
                {
                    let _ = tx.send(req).await;
                }
            }
        },
    );
    let _ = ct;

    if let Some(mxid) = start_to {
        let uid = UserId::parse(mxid).context("bad mxid")?;
        let request = match client.encryption().get_user_identity(&uid).await {
            Ok(Some(id)) => id.request_verification().await.context("requesting verification")?,
            _ => {
                // fall back to the user's first device
                let devs = client.encryption().get_user_devices(&uid).await?;
                let d = devs.devices().next().context("no devices")?;
                d.request_verification().await.context("requesting verification")?
            }
        };
        out(&format!("REQUESTED {uid}"));
        tokio::spawn(auto_flow(client.clone(), request, true, done_tx.clone()));
    } else {
        out("WAITING");
    }

    // serve incoming requests + wait for any flow to finish
    let client2 = client.clone();
    let done_tx2 = done_tx.clone();
    let server = tokio::spawn(async move {
        while let Some(req) = req_rx.recv().await {
            out(&format!("REQUEST from {}", req.other_user_id()));
            tokio::spawn(auto_flow(client2.clone(), req, false, done_tx2.clone()));
        }
    });
    let _ = server;

    let _ = done_rx.recv().await.context("no verification completed");
    // small settle delay for the DONE event exchange
    tokio::time::sleep(Duration::from_millis(1500)).await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let homeserver = std::env::var("E2E_PEER_HOMESERVER").unwrap_or_else(|_| "https://matrix.doesnmlab.xyz".into());
    let user = std::env::var("E2E_PEER_USER").context("E2E_PEER_USER not set")?;
    let pass = std::env::var("E2E_PEER_PASS").context("E2E_PEER_PASS not set")?;
    let state = PathBuf::from(
        std::env::var("E2E_PEER_STATE").unwrap_or_else(|_| "state".into()),
    );

    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let client = login(&homeserver, &user, &pass, &state).await?;

    match cmd {
        "verify" => run_verify(client, None).await?,
        "request" => {
            let mxid = args.get(2).context("request <mxid>")?.clone();
            run_verify(client, Some(&mxid)).await?
        }
        "send" => {
            let room_id = RoomId::parse(args.get(2).context("send <room> <text>")?)
                .context("bad room id")?;
            let text = args.get(3..).context("send <room> <text>")?.join(" ");
            let room = client.get_room(&room_id).with_context(|| format!("not in room {room_id}"))?;
            let resp = room.send(RoomMessageEventContent::text_plain(text)).await?;
            out(&format!("SENT {}", resp.response.event_id));
        }
        "format" => {
            // format <room> <html...>: plain body is derived by tag-stripping
            let room_id = RoomId::parse(args.get(2).context("format <room> <html>")?)
                .context("bad room id")?;
            let html = args.get(3..).context("format <room> <html>")?.join(" ");
            let plain = strip_tags(&html);
            let room = client.get_room(&room_id).with_context(|| format!("not in room {room_id}"))?;
            let resp = room.send(RoomMessageEventContent::text_html(plain, html)).await?;
            out(&format!("SENT {}", resp.response.event_id));
        }
        "reply" => {
            let room_id = RoomId::parse(args.get(2).context("reply <room> <event> <text>")?)
                .context("bad room id")?;
            let event = EventId::parse(args.get(3).context("reply <room> <event> <text>")?)
                .context("bad event id")?;
            let text = args.get(4..).context("reply <room> <event> <text>")?.join(" ");
            let room = client.get_room(&room_id).with_context(|| format!("not in room {room_id}"))?;
            let mut content = RoomMessageEventContent::text_plain(text);
            content.relates_to = Some(MessageRelation::Reply(
                matrix_sdk::ruma::events::relation::Reply::with_event_id(event),
            ));
            let resp = room.send(content).await?;
            out(&format!("SENT {}", resp.response.event_id));
        }
        "react" => {
            let room_id = RoomId::parse(args.get(2).context("react <room> <event> <key>")?)
                .context("bad room id")?;
            let event = EventId::parse(args.get(3).context("react <room> <event> <key>")?)
                .context("bad event id")?;
            let key = args.get(4).context("react <room> <event> <key>")?.clone();
            let room = client.get_room(&room_id).with_context(|| format!("not in room {room_id}"))?;
            let ann = matrix_sdk::ruma::events::relation::Annotation::new(event, key);
            room.send(matrix_sdk::ruma::events::reaction::ReactionEventContent::new(ann))
                .await
                .context("sending m.reaction")?;
            out("REACTED");
        }
        "edit" => {
            let room_id = RoomId::parse(args.get(2).context("edit <room> <event> <text>")?)
                .context("bad room id")?;
            let event = EventId::parse(args.get(3).context("edit <room> <event> <text>")?)
                .context("bad event id")?;
            let text = args.get(4..).context("edit <room> <event> <text>")?.join(" ");
            let room = client.get_room(&room_id).with_context(|| format!("not in room {room_id}"))?;
            let content = RoomMessageEventContent::text_plain(text)
                .make_replacement(ReplacementMetadata::new(event, None));
            let resp = room.send(content).await?;
            out(&format!("SENT {}", resp.response.event_id));
        }
        "redact" => {
            let room_id = RoomId::parse(args.get(2).context("redact <room> <event> [reason]")?)
                .context("bad room id")?;
            let event = EventId::parse(args.get(3).context("redact <room> <event> [reason]")?)
                .context("bad event id")?;
            let reason = args.get(4..).map(|r| r.join(" "));
            let room = client.get_room(&room_id).with_context(|| format!("not in room {room_id}"))?;
            room.redact(&event, reason.as_deref(), None).await?;
            out("REDACTED");
        }
        "mention" => {
            let room_id = RoomId::parse(args.get(2).context("mention <room> <mxid> <text>")?)
                .context("bad room id")?;
            let mxid = args.get(3).context("mention <room> <mxid> <text>")?.clone();
            let text = args.get(4..).context("mention <room> <mxid> <text>")?.join(" ");
            let room = client.get_room(&room_id).with_context(|| format!("not in room {room_id}"))?;
            let uid = UserId::parse(&mxid).context("bad mxid")?;
            let mut mentions = Mentions::new();
            mentions.user_ids.insert(uid);
            let content = RoomMessageEventContent::text_plain(text).add_mentions(mentions);
            let resp = room.send(content).await?;
            out(&format!("SENT {}", resp.response.event_id));
        }
        "read" => {
            // read <room> <n>: print the latest n message-like events (JSON)
            let room_id = RoomId::parse(args.get(2).context("read <room> <n>")?)
                .context("bad room id")?;
            let n: u32 = args.get(3).context("read <room> <n>")?.parse().context("bad n")?;
            let room = client.get_room(&room_id).with_context(|| format!("not in room {room_id}"))?;
            let mut opts = MessagesOptions::backward();
            opts.limit = matrix_sdk::ruma::UInt::from(n);
            let msgs = room.messages(opts).await.context("fetching messages")?;
            for item in msgs.chunk.iter().rev() {
                let payload = serde_json::to_string(item.raw().json()).unwrap_or_default();
                println!("EVT {payload}");
            }
            let _ = std::io::stdout().flush();
        }
        "send-image" => {
            let room_id = RoomId::parse(args.get(2).context("send-image <room> <file>")?)
                .context("bad room id")?;
            let path = args.get(3).context("send-image <room> <file>")?;
            let body = args.get(4).cloned().unwrap_or_else(|| "e2e image".into());
            let room = client.get_room(&room_id).with_context(|| format!("not in room {room_id}"))?;
            let mut file = std::fs::File::open(path)?;
            let enc_file = client.upload_encrypted_file(&mut file).await?;
            let content = RoomMessageEventContent::new(MessageType::Image(
                ImageMessageEventContent::encrypted(body, enc_file),
            ));
            let resp = room.send(content).await?;
            out(&format!("SENT {}", resp.response.event_id));
        }
        "dm" => {
            // dm <mxid> <text...>: reuse the existing DM room or create one
            let mxid = args.get(2).context("dm <mxid> <text>")?.clone();
            let text = args.get(3..).context("dm <mxid> <text>")?.join(" ");
            let uid = UserId::parse(&mxid).context("bad mxid")?;
            let room = match client.get_dm_room(&uid) {
                Some(r) => r,
                None => client.create_dm(&uid).await.context("creating DM")?,
            };
            let resp = room.send(RoomMessageEventContent::text_plain(text)).await?;
            out(&format!("SENT {} {}", resp.response.event_id, room.room_id()));
        }
        "mkinvite" => {
            // mkinvite <name> <mxid>: create a room named <name> and invite mxid
            let name = args.get(2).context("mkinvite <name> <mxid>")?.clone();
            let target = UserId::parse(args.get(3).context("mkinvite <name> <mxid>")?)
                .context("bad mxid")?;
            let mut req = matrix_sdk::ruma::api::client::room::create_room::v3::Request::new();
            req.name = Some(name.clone());
            req.invite = vec![target];
            let room = client.create_room(req).await.context("creating room")?;
            out(&format!("CREATED {} {}", room.room_id(), name));
        }
        "whoami" => out(&format!("{}", client.user_id().context("no uid")?)),
        other => bail!("unknown command {other:?}: send|send-image|verify|request|dm|mkinvite|whoami"),
    }
    Ok(())
}
