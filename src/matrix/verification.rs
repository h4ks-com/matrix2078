//! SAS device verification driven through IRC prompts.
//!
//! Incoming Matrix verification requests surface as NOTICEs from the
//! `&matrix` pseudo-client; the user drives the flow by messaging it
//! (`verify accept`, `verify match`, …). Port of matrirc's
//! `src/matrix/verification.rs` idea onto matrix-sdk 0.18 APIs.

use std::sync::{Arc, Mutex};

use irc::proto::{Command, Message};
use matrix_sdk::{
    Client,
    encryption::verification::{SasVerification, Verification, VerificationRequest},
    ruma::{
        OwnedUserId, UserId,
        events::key::verification::request::ToDeviceKeyVerificationRequestEvent,
    },
};
use tokio::sync::mpsc;

use crate::ircd::proto;

/// Pseudo-client nick that accepts bridge control commands.
pub const CONTROL_NICK: &str = "&matrix";

struct Entry {
    flow_id: String,
    other: OwnedUserId,
    we_started: bool,
    request: VerificationRequest,
    sas: Option<SasVerification>,
    emojis_shown: bool,
    announced: bool,
}

impl Entry {
    fn stage(&self) -> &'static str {
        if self.request.is_done() || (self.sas.as_ref().is_some_and(|s| s.is_done())) {
            "done"
        } else if self.request.is_cancelled() {
            "cancelled"
        } else if self.request.is_passive() {
            "passive"
        } else if self.request.is_ready() {
            if self.emojis_shown {
                "waiting for confirm"
            } else if self.sas.is_some() {
                "sas"
            } else {
                "ready"
            }
        } else if self.we_started {
            "sent, waiting"
        } else {
            "waiting for accept"
        }
    }
}

pub struct VerificationHub {
    client: Client,
    own: OwnedUserId,
    nick: String,
    entries: Mutex<Vec<Entry>>,
    tx: Mutex<Option<mpsc::Sender<Message>>>,
    driver_started: std::sync::atomic::AtomicBool,
}

impl VerificationHub {
    pub fn new(client: Client, own: OwnedUserId, nick: &str) -> Arc<Self> {
        Arc::new(Self {
            client,
            own,
            nick: nick.to_owned(),
            entries: Mutex::new(Vec::new()),
            tx: Mutex::new(None),
            driver_started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Give the hub the outbound IRC channel and start the state driver.
    /// Called when the owning IRC connection enters relay mode.
    pub fn attach(self: &Arc<Self>, tx: mpsc::Sender<Message>) {
        *self.tx.lock().expect("hub tx") = Some(tx);
        if !self
            .driver_started
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            let hub = Arc::clone(self);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_millis(400));
                loop {
                    tick.tick().await;
                    hub.drive().await;
                }
            });
            let hub = Arc::clone(self);
            self.client.add_event_handler(
                move |ev: ToDeviceKeyVerificationRequestEvent, client: Client| {
                    let hub = Arc::clone(&hub);
                    async move {
                        let flow_id = ev.content.transaction_id.to_string();
                        if let Some(req) = client
                            .encryption()
                            .get_verification_request(&ev.sender, &flow_id)
                            .await
                        {
                            hub.register(req, ev.sender.clone(), false);
                        }
                    }
                },
            );
        }
    }

    fn notice(&self, text: &str) {
        let tx = self.tx.lock().expect("hub tx");
        if let Some(tx) = tx.as_ref() {
            let m = proto::user(CONTROL_NICK, Command::NOTICE(self.nick.clone(), text.to_owned()));
            let _ = tx.try_send(m);
        } else {
            tracing::debug!(text, "verification notice (no client attached)");
        }
    }

    /// Register a verification request and tell the IRC user about it.
    pub fn register(&self, request: VerificationRequest, other: OwnedUserId, we_started: bool) {
        let flow_id = request.flow_id().to_owned();
        {
            let mut entries = self.entries.lock().expect("hub entries");
            if entries.iter().any(|e| e.flow_id == flow_id) {
                return;
            }
            entries.push(Entry {
                flow_id: flow_id.clone(),
                other: other.clone(),
                we_started,
                request,
                sas: None,
                emojis_shown: false,
                announced: false,
            });
        }
        if !we_started {
            self.notice(&format!(
                "verification request from {other}. \
                 Reply with: /msg {CONTROL_NICK} verify accept"
            ));
        } else {
            self.notice(&format!("verification request sent to {other}"));
        }
    }

    /// Look up a request by flow id (in-room requests use the event id).
    pub async fn register_by_flow(&self, sender: &UserId, flow_id: &str) {
        if let Some(req) = self.client.encryption().get_verification_request(sender, flow_id).await
        {
            self.register(req, sender.to_owned(), false);
        }
    }

    /// Advance every active flow: start SAS where possible, show emojis,
    /// report completion or cancellation.
    async fn drive(&self) {
        // work on clones so we never hold the lock across an await
        let snapshot: Vec<(String, VerificationRequest, Option<SasVerification>, bool, bool)> = {
            let entries = self.entries.lock().expect("hub entries");
            entries
                .iter()
                .map(|e| {
                    (
                        e.flow_id.clone(),
                        e.request.clone(),
                        e.sas.clone(),
                        e.we_started,
                        e.emojis_shown,
                    )
                })
                .collect()
        };

        for (flow_id, request, sas, we_started, emojis_shown) in snapshot {
            tracing::debug!(%flow_id, ready = request.is_ready(), "drive tick");
            if sas.is_none() {
                if request.is_done() || request.is_cancelled() || request.is_passive() {
                    continue; // handled by the terminal branch below
                }
                // NB: `is_ready()` is only true in the Ready state; once the
                // other side sends `m.key.verification.start` the request
                // transitions away from it, so poll `get_verification`
                // unconditionally to pick the SAS object up.
                let maybe_sas = if we_started && request.is_ready() {
                    match request.start_sas().await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(%flow_id, error = %e, "starting sas failed");
                            None
                        }
                    }
                } else {
                    match self
                        .client
                        .encryption()
                        .get_verification(&request.other_user_id(), &flow_id)
                        .await
                    {
                        Some(Verification::SasV1(s)) => Some(s),
                        _ => None,
                    }
                };
                if let Some(s) = maybe_sas {
                    tracing::debug!(%flow_id, "sas object found");
                    // for an incoming Start we must send m.key.verification.accept
                    if !we_started {
                        if let Err(e) = s.accept().await {
                            tracing::debug!(%flow_id, error = %e, "sas accept (already accepted?)");
                        }
                    }
                    self.set_sas(&flow_id, s);
                }
            } else if let Some(s) = &sas {
                if !emojis_shown && s.can_be_presented() {
                    if let Some(emojis) = s.emoji() {
                        let symbols: Vec<&str> = emojis.iter().map(|e| e.symbol).collect();
                        let words: Vec<&str> = emojis.iter().map(|e| e.description).collect();
                        self.notice(&format!(
                            "SAS for {}: {}  ({})",
                            request.other_user_id(),
                            symbols.join(" "),
                            words.join(", ")
                        ));
                        self.notice(&format!(
                            "Do they match? /msg {CONTROL_NICK} verify match | verify mismatch"
                        ));
                    }
                    self.set_emojis_shown(&flow_id);
                }
            }
        }

        // terminal states → notice + forget
        let finished: Vec<(String, String)> = {
            let entries = self.entries.lock().expect("hub entries");
            entries
                .iter()
                .filter(|e| !e.announced)
                .filter(|e| e.request.is_done() || e.request.is_cancelled())
                .map(|e| {
                    let msg = if e.request.is_done() {
                        format!("verification with {} done: device is now trusted", e.other)
                    } else {
                        let reason = e
                            .request
                            .cancel_info()
                            .map(|c| c.reason().to_owned())
                            .unwrap_or_else(|| "unknown reason".to_owned());
                        format!("verification with {} cancelled: {reason}", e.other)
                    };
                    (e.flow_id.clone(), msg)
                })
                .collect()
        };
        if finished.is_empty() {
            return;
        }
        for (flow_id, msg) in finished {
            self.notice(&msg);
            let mut entries = self.entries.lock().expect("hub entries");
            entries.retain(|e| !(e.flow_id == flow_id && (e.request.is_done() || e.request.is_cancelled())));
        }
    }

    fn set_sas(&self, flow_id: &str, sas: SasVerification) {
        let mut entries = self.entries.lock().expect("hub entries");
        if let Some(e) = entries.iter_mut().find(|e| e.flow_id == flow_id) {
            e.sas = Some(sas);
        }
    }

    fn set_emojis_shown(&self, flow_id: &str) {
        let mut entries = self.entries.lock().expect("hub entries");
        if let Some(e) = entries.iter_mut().find(|e| e.flow_id == flow_id) {
            e.emojis_shown = true;
        }
    }

    fn pick(&self, idx: Option<usize>) -> Option<(usize, String, VerificationRequest)> {
        let entries = self.entries.lock().expect("hub entries");
        let i = idx.unwrap_or(entries.len().saturating_sub(1));
        entries.get(i).map(|e| (i, e.flow_id.clone(), e.request.clone()))
    }

    fn with_sas(&self, i: usize) -> Option<SasVerification> {
        self.entries.lock().expect("hub entries").get(i).and_then(|e| e.sas.clone())
    }

    /// Handle one control command line; returns NOTICE reply lines.
    pub async fn command(&self, line: &str) -> Vec<String> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(first) = parts.first() else {
            return vec!["empty command".to_owned()];
        };
        let cmd = first.to_ascii_lowercase();
        let mut out = Vec::new();
        match (cmd.as_str(), parts.len()) {
            ("help", _) => out.extend([
                format!("commands (PRIVMSG {CONTROL_NICK} <cmd>):"),
                "  help                        this help".to_owned(),
                "  verify                      list verification flows".to_owned(),
                "  verify accept [n]           accept request and run SAS".to_owned(),
                "  verify match [n]            confirm the SAS emojis match".to_owned(),
                "  verify mismatch [n]         reject the SAS emojis".to_owned(),
                "  verify cancel [n]           cancel a flow".to_owned(),
                "  verify start <@user:dom>    start verifying a user (or own devices)".to_owned(),
                "  devices [@user:dom]         list devices and their trust".to_owned(),
            ]),
            ("verify", 1) => {
                let entries = self.entries.lock().expect("hub entries");
                if entries.is_empty() {
                    out.push("no verification flows".to_owned());
                }
                for (i, e) in entries.iter().enumerate() {
                    out.push(format!("[{i}] {} ({})", e.other, e.stage()));
                }
            }
            ("verify", _) => {
                let sub = parts[1].to_ascii_lowercase();
                match (sub.as_str(), parts.get(2)) {
                    ("start", Some(arg)) => out.extend(self.verify_start(arg).await),
                    (_, n) => {
                        let idx = n.and_then(|s| s.parse::<usize>().ok());
                        out.extend(self.verify_sub(&sub, idx).await);
                    }
                }
            }
            ("devices", _) => {
                let uid = match parts.get(1) {
                    Some(a) => match UserId::parse(a.to_owned()) {
                        Ok(u) => u,
                        Err(_) => {
                            out.push("bad user id".to_owned());
                            return out;
                        }
                    },
                    None => self.own.clone(),
                };
                match self.client.encryption().get_user_devices(&uid).await {
                    Ok(devices) => {
                        out.push(format!("devices of {uid}:"));
                        for d in devices.devices() {
                            let trust = if d.is_verified() { "trusted" } else { "NOT trusted" };
                            out.push(format!(
                                "  {} {} [{trust}]",
                                d.device_id(),
                                d.display_name().unwrap_or("-")
                            ));
                        }
                    }
                    Err(e) => out.push(format!("listing devices failed: {e}")),
                }
            }
            _ => out.push(format!("unknown command {cmd:?}, try help")),
        }
        out
    }

    async fn verify_sub(&self, sub: &str, idx: Option<usize>) -> Vec<String> {
        let Some((i, _flow, request)) = self.pick(idx) else {
            return vec!["no such verification flow".to_owned()];
        };
        match sub {
            "accept" => match request.accept().await {
                Ok(()) => {
                    // the requester starts SAS; ours arrives via the driver
                    vec!["accepted; waiting for the SAS emojis".to_owned()]
                }
                Err(e) => vec![format!("accept failed: {e}")],
            },
            "match" | "yes" | "confirm" => match self.with_sas(i) {
                Some(sas) => match sas.confirm().await {
                    Ok(()) => vec!["confirmed; verification completing".to_owned()],
                    Err(e) => vec![format!("confirm failed: {e}")],
                },
                None => vec!["no SAS to confirm yet".to_owned()],
            },
            "mismatch" | "no" => match self.with_sas(i) {
                Some(sas) => match sas.mismatch().await {
                    Ok(()) => vec!["mismatch reported; cancelling verification".to_owned()],
                    Err(e) => vec![format!("mismatch failed: {e}")],
                },
                None => vec!["no SAS to reject yet".to_owned()],
            },
            "cancel" => {
                let res = match self.with_sas(i) {
                    Some(sas) => sas.cancel().await,
                    None => request.cancel().await,
                };
                match res {
                    Ok(()) => vec!["cancelled".to_owned()],
                    Err(e) => vec![format!("cancel failed: {e}")],
                }
            }
            other => vec![format!("unknown verify subcommand {other:?}")],
        }
    }

    async fn verify_start(&self, arg: &str) -> Vec<String> {
        let arg = arg.trim_start_matches('@');
        let target: OwnedUserId = match UserId::parse(format!("@{arg}")) {
            Ok(u) => u,
            Err(_) => return vec!["usage: verify start <@user:domain>".to_owned()],
        };
        if target == self.own {
            // verify our own other devices: pick the first unverified one
            let devices = match self.client.encryption().get_user_devices(&self.own).await {
                Ok(d) => d,
                Err(e) => return vec![format!("listing own devices failed: {e}")],
            };
            let own_id = self.client.device_id();
            let device = devices
                .devices()
                .find(|d| Some(d.device_id()) != own_id && !d.is_verified());
            let Some(device) = device else {
                return vec!["no unverified devices of yours found".to_owned()];
            };
            match device.request_verification().await {
                Ok(req) => {
                    let other = req.other_user_id().to_owned();
                    self.register(req, other, true);
                    vec!["verification request sent (own device)".to_owned()]
                }
                Err(e) => vec![format!("requesting verification failed: {e}")],
            }
        } else {
            let identity = match self.client.encryption().get_user_identity(&target).await {
                Ok(Some(i)) => i,
                Ok(None) => {
                    return vec![format!("no identity known for {target}; they must be in a shared room")]
                }
                Err(e) => return vec![format!("looking up identity failed: {e}")],
            };
            match identity.request_verification().await {
                Ok(req) => {
                    let other = req.other_user_id().to_owned();
                    self.register(req, other, true);
                    vec!["verification request sent".to_owned()]
                }
                Err(e) => vec![format!("requesting verification failed: {e}")],
            }
        }
    }
}
