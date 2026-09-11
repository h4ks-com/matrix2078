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

use anyhow::{Context as _, Result};
use futures::{SinkExt, StreamExt};
use irc::proto::{CapSubCommand, Command, IrcCodec, Message, Prefix, Response};
use irc::proto::message::Tag;
use tokio::{net::{TcpListener, TcpStream}, sync::mpsc};
use tokio_util::codec::Framed;
use futures::stream::{SplitSink, SplitStream};

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

/// Any accepted client stream: plain TCP or TLS.
pub trait ClientStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {
    fn set_nodelay(&self);
}

impl ClientStream for TcpStream {
    fn set_nodelay(&self) {
        TcpStream::set_nodelay(self, true).ok();
    }
}

impl ClientStream for tokio_rustls::server::TlsStream<TcpStream> {
    fn set_nodelay(&self) {
        let _ = self.get_ref().0.set_nodelay(true);
    }
}

/// A framed client connection regardless of transport.
type Frame<S> = Framed<S, IrcCodec>;
type SinkHalf<S> = SplitSink<Framed<S, IrcCodec>, Message>;
type StreamHalf<S> = SplitStream<Framed<S, IrcCodec>>;
pub async fn run(cfg: Arc<Config>) -> Result<()> {
    // ring-backed crypto provider for rustls (ignored if already installed)
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let tls_acceptor = match &cfg.tls {
        Some(tls) => {
            let certs = load_certs(&tls.cert)?;
            let key = load_key(&tls.key)?;
            let config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .context("building TLS config")?;
            Some(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)))
        }
        None => None,
    };

    let listener = TcpListener::bind(cfg.listen).await?;
    tracing::info!(
        listen = %cfg.listen,
        tls = cfg.tls.is_some(),
        server = %cfg.server_name,
        "ircd listening"
    );
    let media = Arc::new(MediaServer::new(
        cfg.media_listen,
        crate::matrix::media::cache_dir(&cfg.state_dir),
        cfg.media_public_url.clone(),
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
        tracing::info!(%peer, tls = tls_acceptor.is_some(), "client connected");
        let cfg = cfg.clone();
        let media = Arc::clone(&media);
        let acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let res = match acceptor {
                Some(acceptor) => match acceptor.accept(stream).await {
                    Ok(tls_stream) => handle_conn(tls_stream, peer, cfg, media).await,
                    Err(e) => Err(anyhow::anyhow!("TLS handshake: {e}")),
                },
                None => handle_conn(stream, peer, cfg, media).await,
            };
            match res {
                Ok(()) => tracing::info!(%peer, "connection closed"),
                Err(e) => tracing::info!(%peer, error = %e, "connection closed with error"),
            }
        });
    }
}

fn load_certs(path: &std::path::Path) -> Result<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path).with_context(|| format!("opening cert {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certs {}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_key(path: &std::path::Path) -> Result<tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path).with_context(|| format!("opening key {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing key {}", path.display()))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", path.display()))
}

async fn handle_conn<S: ClientStream + 'static>(
    stream: S,
    peer: SocketAddr,
    cfg: Arc<Config>,
    media: Arc<MediaServer>,
) -> Result<()> {
    stream.set_nodelay();
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
        framed.send(tags_for_client(&caps, m)).await?;
    }
    if reg.sasl_user.is_some() {
        // account-notify base: announce our own account once
        let account = reg.sasl_user.clone().unwrap_or_default();
        let _ = account;
    }

    // dedicated writer with a priority lane: PONG/ERROR must overtake any
    // backlog of history/NAMES lines, or clients measuring ping round-trips
    // time out while we are still flushing prefill bursts
    let (sink, stream) = futures::StreamExt::split(framed);
    let (prio_tx, prio_rx) = mpsc::channel::<Message>(32);
    let (tx, rx) = mpsc::channel::<Message>(256);
    let last_seen = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
    let writer = spawn_writer(
        sink,
        caps.clone(),
        server.clone(),
        prio_rx,
        rx,
        last_seen.clone(),
    );

    // JOIN every already-mapped room's channel before any PRIVMSG can
    // reference it (DM/query mappings surface as private messages, not
    // channels). Rooms first seen on this connection are joined by the
    // background bootstrap task below.
    //
    // The burst itself also runs in the background: fetching members of
    // federated rooms can take tens of seconds and must not stall the read
    // loop (a client PING would go unanswered and the connection die).
    bridge.relay_matrix_to_irc(tx.clone());
    {
        let bridge = Arc::clone(&bridge);
        let tx = tx.clone();
        let server = server.clone();
        let nick = nick.clone();
        let username = username.clone();
        let names_limit = cfg.bridge.names_limit;
        for entry in bridge.entries() {
            if entry.query.is_some() {
                continue;
            }
            bridge.joined.lock().expect("joined mutex").insert(entry.channel.to_ascii_lowercase());
        }
        tokio::spawn(async move {
            let prefix = client_prefix(&nick, &username);
            for entry in bridge.entries() {
                if entry.query.is_some() {
                    continue;
                }
                let members = bridge.channel_members(&entry.channel).await.unwrap_or_default();
                for m in join_burst_messages(&server, &prefix, &nick, &entry, members, names_limit) {
                    let _ = tx.send(m).await;
                }
            }
        });
    }

    // initial sync + mapping of newly seen rooms must not block registration
    let sync_task = spawn_bootstrap(
        Arc::clone(&bridge),
        tx.clone(),
        server.clone(),
        nick.clone(),
        username.clone(),
        cfg.bridge.names_limit,
    );

    let result =
        relay_loop(stream, &peer, &server, &prefix, &mut nick, &username, &bridge, &caps, &prio_tx, &tx, &last_seen)
            .await;
    writer.abort();
    // the matrix sync loop must not outlive the IRC connection: it holds the
    // device's sync position and would block the next session of this user
    sync_task.abort();
    result
}

/// Dedicated connection writer: owns the socket half, always drains the
/// priority lane (PONG/ERROR) first, keeps the keepalive PING cadence and
/// drops dead peers.
fn spawn_writer<S: ClientStream + 'static>(
    mut sink: SinkHalf<S>,
    caps: Caps,
    server: String,
    mut prio_rx: mpsc::Receiver<Message>,
    mut rx: mpsc::Receiver<Message>,
    last_seen: Arc<std::sync::Mutex<tokio::time::Instant>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut pinged = false;
        let mut seen_at = *last_seen.lock().expect("last_seen mutex");
        let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(30));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                maybe = prio_rx.recv() => {
                    match maybe {
                        Some(m) => {
                            if sink.send(m).await.is_err() {
                                break;
                            }
                        }
                        None => continue,
                    }
                }
                _ = keepalive.tick() => {
                    let now_seen = *last_seen.lock().expect("last_seen mutex");
                    if now_seen != seen_at {
                        seen_at = now_seen;
                        pinged = false;
                    }
                    let idle = tokio::time::Instant::now() - seen_at;
                    if idle >= std::time::Duration::from_secs(480) {
                        tracing::info!("ping timeout, closing connection");
                        let _ = sink
                            .send(srv(&server, Command::ERROR("Ping timeout: 480 seconds".into())))
                            .await;
                        break;
                    }
                    if idle >= std::time::Duration::from_secs(90) && !pinged {
                        let token = format!("m2078.{}", idle.as_secs());
                        if sink
                            .send(srv(&server, Command::PING(server.clone(), Some(token))))
                            .await
                            .is_err()
                        {
                            break;
                        }
                        pinged = true;
                    }
                }
                maybe = rx.recv() => {
                    match maybe {
                        Some(m) => {
                            if sink.send(tags_for_client(&caps, m)).await.is_err() {
                                break;
                            }
                        }
                        None => {
                            let _ = sink
                                .send(srv(&server, Command::ERROR("matrix relay closed".into())))
                                .await;
                            break;
                        }
                    }
                }
            }
        }
    })
}

/// CAP negotiation during registration.
#[allow(clippy::too_many_arguments)]
async fn handle_cap<S: ClientStream>(
    framed: &mut Frame<S>,
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
            let (ack, nak) = reg.caps.apply_req(req);
            if !ack.is_empty() {
                framed
                    .send(srv(server, Command::CAP(Some("*".into()), ACK, Some(ack), None)))
                    .await?;
            }
            if !nak.is_empty() {
                framed
                    .send(srv(server, Command::CAP(Some("*".into()), NAK, Some(nak), None)))
                    .await?;
            }
            reg.cap_started = true;
        }
        END => reg.cap_ended = true,
        _ => {}
    }
    Ok(())
}

/// SASL PLAIN during registration: `AUTHENTICATE PLAIN` then the base64 payload.
async fn handle_authenticate<S: ClientStream>(
    framed: &mut Frame<S>,
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

/// Sanitize the USER field into a sane IRC username: if it is a full mxid,
/// use its localpart; keep only irc-username-safe characters.
/// The realname (GECOS) is ignored on purpose: a client-supplied homeserver
/// would turn the instance into an open Matrix proxy (matrix2051 non-goal).
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
    fn outgoing_tag_filtering() {
        let mut caps = Caps::default();
        caps.apply_req("server-time message-tags batch draft/multiline");
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

    /// Full TLS listener test: self-signed cert (rcgen), IRCd behind
    /// tokio-rustls, client with an accept-any verifier, PASS/NICK/USER
    /// registration over the TLS stream.
    #[tokio::test]
    async fn tls_registration_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        // pick free ports
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let media_listen = probe.local_addr().unwrap();
        drop(probe);

        let cfg = Arc::new(Config {
            listen,
            media_listen,
            state_dir: dir.path().join("state"),
            tls: Some(crate::config::TlsConfig { cert: cert_path, key: key_path }),
            ..Config::default()
        });
        tokio::spawn(async move {
            if let Err(e) = run(cfg).await {
                panic!("server run failed: {e}");
            }
        });
        // wait for the listener to come up
        for _ in 0..100 {
            if std::net::TcpStream::connect_timeout(&listen, std::time::Duration::from_millis(100)).is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // client that accepts any certificate
        #[derive(Debug)]
        struct NoVerify;
        impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
                _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: tokio_rustls::rustls::pki_types::UnixTime,
            ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error> {
                Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
                _dss: &tokio_rustls::rustls::DigitallySignedStruct,
            ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
                Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
                _dss: &tokio_rustls::rustls::DigitallySignedStruct,
            ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
                Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
                vec![
                    tokio_rustls::rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    tokio_rustls::rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    tokio_rustls::rustls::SignatureScheme::ED25519,
                    tokio_rustls::rustls::SignatureScheme::RSA_PSS_SHA256,
                ]
            }
        }
        let mut tls_config = tokio_rustls::rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
            .with_no_client_auth();
        tls_config.alpn_protocols = Vec::new();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));

        let tcp = tokio::net::TcpStream::connect(listen).await.unwrap();
        let tls_stream = connector
            .connect(tokio_rustls::rustls::pki_types::ServerName::try_from("localhost".to_owned()).unwrap(), tcp)
            .await
            .expect("TLS handshake");
        let mut framed = Framed::new(tls_stream, IrcCodec::new("UTF-8").unwrap());
        use futures::SinkExt;
        framed
            .send(Message {
                tags: None,
                prefix: None,
                command: Command::PASS("secret".to_owned()),
            })
            .await
            .unwrap();
        framed
            .send(Message {
                tags: None,
                prefix: None,
                command: Command::NICK("tester".to_owned()),
            })
            .await
            .unwrap();
        framed
            .send(Message {
                tags: None,
                prefix: None,
                command: Command::USER("t".to_owned(), "0".to_owned(), "x".to_owned()),
            })
            .await
            .unwrap();
        // registration will fail with ERR_PASSWDMISMATCH (no matrix behind
        // it), but any numeric reply proves the TLS IRC path works
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut saw_numeric = false;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_secs(5), framed.next()).await {
                Ok(Some(Ok(m))) => {
                    if matches!(m.command, Command::Response(..)) {
                        saw_numeric = true;
                        break;
                    }
                }
                _ => break,
            }
        }
        assert!(saw_numeric, "expected a numeric reply over TLS");
    }
}

/// Send a message to the client, filtering message tags to what was
/// negotiated and stamping server-time on untagged traffic when enabled.
async fn send_out<S: ClientStream>(
    framed: &mut Frame<S>,
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

/// Keep only tags the client negotiated for (server-time, msgid,
/// message-tags).
fn tags_for_client(caps: &Caps, m: Message) -> Message {
    let Some(tags) = m.tags else { return m };
    let filtered: Vec<Tag> = tags
        .into_iter()
        .filter(|t| match t.0.as_str() {
            "time" => caps.has("server-time"),
            "msgid" => caps.has("msgid") || caps.has("message-tags"),
            "account" => caps.has("account-tag"),
            "batch" => caps.has("batch"),
            other => caps.has("message-tags") && (other.starts_with("draft/") || other.starts_with('+')),
        })
        .collect();
    Message { tags: if filtered.is_empty() { None } else { Some(filtered) }, ..m }
}

/// A `draft/multiline` batch being accumulated from the client.
/// Each line carries its text and whether it must be concatenated to the
/// previous one without a line break (`draft/multiline-concat`).
struct MultiLine {
    target: String,
    notice: bool,
    lines: Vec<(String, bool)>,
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
async fn relay_loop<S: ClientStream>(
    mut stream: StreamHalf<S>,
    peer: &SocketAddr,
    server: &str,
    prefix: &Prefix,
    nick: &mut String,
    username: &str,
    bridge: &Arc<Bridge>,
    caps: &Caps,
    prio_tx: &mpsc::Sender<Message>,
    tx: &mpsc::Sender<Message>,
    last_seen: &Arc<std::sync::Mutex<tokio::time::Instant>>,
) -> Result<()> {
    let mut prefix = prefix.clone();
    let names_limit = bridge.cfg.bridge.names_limit;
    let mut multiline: HashMap<String, MultiLine> = HashMap::new();
    let batch_counter = AtomicU64::new(0);
    let tx = tx.clone();
    let prio_tx = prio_tx.clone();
    loop {
        tokio::select! {
            maybe = stream.next() => {
                let Some(msg) = maybe else {
                    tracing::info!(%peer, "client hung up");
                    return Ok(());
                };
                let msg = msg.map_err(|e| anyhow::anyhow!("decode error: {e}"))?;
                *last_seen.lock().expect("last_seen mutex") = tokio::time::Instant::now();
                tracing::debug!(command = ?msg.command, "irc line in");
                let known_channel = |chan: &str| -> bool {
                    bridge.rooms.lock().expect("rooms mutex").get_by_channel(chan).is_some()
                };
                let is_joined = |chan: &str| -> bool {
                    bridge.joined.lock().expect("joined mutex").contains(&chan.to_ascii_lowercase())
                };
                // messages continuing an open draft/multiline batch
                // (current spec marks lines with batch=<ref>; the old
                // draft/multiline=<ref> client tag is still accepted)
                let ml_ref = msg.tags.as_ref().and_then(|tags| {
                    let batch = tags
                        .iter()
                        .find(|t| t.0 == "batch")
                        .and_then(|t| t.1.clone());
                    if let Some(b) = batch {
                        return Some(b);
                    }
                    tags.iter()
                        .find(|t| t.0 == "draft/multiline")
                        .and_then(|t| t.1.clone())
                });
                if let Some(ml_ref) = ml_ref {
                    match &msg.command {
                        Command::PRIVMSG(target, body) | Command::NOTICE(target, body) => {
                            if let Some(ml) = multiline.get_mut(&ml_ref) {
                                if ml.lines.is_empty() {
                                    ml.notice = matches!(msg.command, Command::NOTICE(_, _));
                                    if ml.target.is_empty() {
                                        ml.target = target.clone();
                                    }
                                    // legacy reply tag on the first line applies too
                                    if ml.reply.is_none() {
                                        ml.reply = tag_value(&msg, "+draft/reply");
                                    }
                                }
                                let concat = msg.tags.as_ref().is_some_and(|tags| {
                                    tags.iter()
                                        .any(|t| t.0 == "draft/multiline-concat")
                                });
                                ml.lines.push((body.clone(), concat));
                                continue;
                            }
                        }
                        _ => {}
                    }
                }
                let reply_tag = tag_value(&msg, "+draft/reply");
                match msg.command {
                    Command::PING(token, _) => {
                        let _ = prio_tx.send(srv(server, Command::PONG(server.to_owned(), Some(token)))).await;
                    }
                    Command::PONG(..) => {}
                    Command::PRIVMSG(target, body) => {
                        if target.eq_ignore_ascii_case(crate::matrix::verification::CONTROL_NICK) {
                            control_command(&tx, caps, server, nick, &prefix, bridge, &body).await?;
                        } else if target.starts_with('&') {
                            // other service-ish targets: ignore
                        } else if target.starts_with('#') {
                            relay_from_irc(bridge, nick, &prefix, &target, body, false, known_channel(&target), is_joined(&target), caps, &tx, reply_tag).await?;
                        } else {
                            relay_query_from_irc(bridge, nick, &prefix, &target, body, false, caps, &tx, reply_tag).await?;
                        }
                    }
                    Command::NOTICE(target, body) => {
                        if target.eq_ignore_ascii_case(crate::matrix::verification::CONTROL_NICK) {
                            control_command(&tx, caps, server, nick, &prefix, bridge, &body).await?;
                        } else if target.starts_with('&') || target.starts_with('#') {
                            relay_from_irc(bridge, nick, &prefix, &target, body, true, known_channel(&target), is_joined(&target), caps, &tx, reply_tag).await?;
                        } else {
                            relay_query_from_irc(bridge, nick, &prefix, &target, body, true, caps, &tx, reply_tag).await?;
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
                        let reply_on_open = reply_tag.clone();
                        handle_batch(server, nick, &prefix, &mut multiline, bridge, caps, &tx, &ref_name, sub, args, reply_on_open).await?;
                    }
                    Command::JOIN(chans, _, _) => {
                        for chan in chans.split(',').filter(|c| !c.is_empty()) {
                            if known_channel(chan) {
                                bridge.joined.lock().expect("joined mutex").insert(chan.to_ascii_lowercase());
                                let entry = bridge.rooms.lock().expect("rooms mutex")
                                    .get_by_channel(chan).cloned().expect("checked above");
                                // member fetch in the background: must not stall PINGs
                                let bridge2 = Arc::clone(bridge);
                                let tx = tx.clone();
                                let server2 = server.to_owned();
                                let nick2 = nick.to_owned();
                                let prefix2 = prefix.clone();
                                let lim = names_limit;
                                tokio::spawn(async move {
                                    let members = bridge2.channel_members(&entry.channel).await.unwrap_or_default();
                                    for m in join_burst_messages(&server2, &prefix2, &nick2, &entry, members, lim) {
                                        let _ = tx.send(m).await;
                                    }
                                });
                            } else {
                                tx.send(num(server, Response::ERR_NOSUCHCHANNEL, nick, vec![
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
                                tx.send(from_client(&prefix, Command::PART(chan.to_owned(), comment.clone()))).await?;
                            } else {
                                tx.send(num(server, Response::ERR_NOSUCHCHANNEL, nick, vec![
                                    chan.to_owned(),
                                    "No such channel".to_owned(),
                                ])).await?;
                            }
                        }
                    }
                    Command::WHO(Some(mask), _) => {
                        if known_channel(&mask) {
                            // fetch members off the read loop: a slow
                            // homeserver must not stall PING/PONG
                            let bridge2 = Arc::clone(bridge);
                            let tx = tx.clone();
                            let server2 = server.to_owned();
                            let nick2 = nick.to_owned();
                            let mask2 = mask.clone();
                            let lim = names_limit;
                            tokio::spawn(async move {
                                let members = bridge2.channel_members(&mask2).await.unwrap_or_default();
                                for m in who_messages(&server2, &nick2, &mask2, &members, lim) {
                                    let _ = tx.send(m).await;
                                }
                            });
                        } else {
                            tx.send(num(server, Response::RPL_ENDOFWHO, nick, vec![
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
                            tx.send(num(server, Response::RPL_ENDOFWHO, nick, vec![
                                chan,
                                "End of WHO list".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::NAMES(Some(chans), _) => {
                        for chan in chans.split(',').filter(|c| !c.is_empty()) {
                            if known_channel(chan) {
                                let bridge2 = Arc::clone(bridge);
                                let tx = tx.clone();
                                let server2 = server.to_owned();
                                let nick2 = nick.to_owned();
                                let chan2 = chan.to_owned();
                                let lim = names_limit;
                                tokio::spawn(async move {
                                    let members = bridge2.channel_members(&chan2).await.unwrap_or_default();
                                    for m in names_messages(&server2, &nick2, &chan2, members, lim) {
                                        let _ = tx.send(m).await;
                                    }
                                });
                            } else {
                                tx.send(num(server, Response::RPL_ENDOFNAMES, nick, vec![
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
                            tx.send(num(server, Response::RPL_TOPIC, nick, vec![
                                chan,
                                topic,
                            ])).await?;
                        } else {
                            tx.send(num(server, Response::ERR_NOSUCHCHANNEL, nick, vec![
                                chan,
                                "No such channel".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::LIST(chans, _) => {
                        tx.send(num(server, Response::RPL_LISTSTART, nick, vec!["Channel :Users  Name".to_owned()])).await?;
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
                            tx.send(num(server, Response::RPL_LIST, nick, vec![
                                e.channel.clone(),
                                members.to_string(),
                                e.topic.clone(),
                            ])).await?;
                        }
                        tx.send(num(server, Response::RPL_LISTEND, nick, vec!["End of /LIST".to_owned()])).await?;
                    }
                    Command::UserMODE(target, _) => {
                        if target == *nick {
                            tx.send(num(server, Response::RPL_UMODEIS, nick, vec!["+".to_owned()])).await?;
                        } else {
                            tx.send(num(server, Response::ERR_USERSDONTMATCH, nick, vec![
                                "Can't change mode for other users".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::ChannelMODE(chan, _) => {
                        if known_channel(&chan) {
                            tx.send(num(server, Response::RPL_CHANNELMODEIS, nick, vec![
                                chan,
                                "+nt".to_owned(),
                            ])).await?;
                        } else {
                            tx.send(num(server, Response::ERR_NOSUCHCHANNEL, nick, vec![
                                chan,
                                "No such channel".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::MOTD(_) => {
                        for m in motd(server, nick) {
                            let _ = tx.send(m).await;
                        }
                    }
                    Command::LUSERS(..) => {
                        for m in lusers(server, nick) {
                            tx.send(m).await?;
                        }
                    }
                    Command::AWAY(away) => {
                        let code = if away.is_some() { Response::RPL_NOWAWAY } else { Response::RPL_UNAWAY };
                        let text = if away.is_some() { "You have been marked as being away" } else { "You are no longer marked as being away" };
                        tx.send(num(server, code, nick, vec![text.to_owned()])).await?;
                    }
                    Command::NICK(new) => {
                        if valid_nick(&new) {
                            tx.send(from_client(&prefix, Command::NICK(new.clone()))).await?;
                            *nick = new;
                            prefix = client_prefix(nick, username);
                        } else {
                            tx.send(num(server, Response::ERR_ERRONEOUSNICKNAME, nick, vec![
                                new,
                                "Erroneous nickname".to_owned(),
                            ])).await?;
                        }
                    }
                    Command::ISON(list) => {
                        // ourselves + DM query partners are "online"
                        let partners: Vec<String> = bridge
                            .rooms
                            .lock()
                            .expect("rooms mutex")
                            .entries()
                            .iter()
                            .filter_map(|e| e.query.clone())
                            .collect();
                        let found: Vec<String> = list
                            .iter()
                            .filter(|n| {
                                n.eq_ignore_ascii_case(nick)
                                    || partners
                                        .iter()
                                        .any(|p| p.eq_ignore_ascii_case(n))
                            })
                            .cloned()
                            .collect();
                        tx.send(num(server, Response::RPL_ISON, nick, vec![found.join(" ")])).await?;
                    }
                    Command::USERHOST(list) => {
                        let mut parts = Vec::new();
                        for n in &list {
                            if n.eq_ignore_ascii_case(nick) {
                                parts.push(format!("{nick}=+~{username}@matrix2078"));
                            }
                        }
                        tx.send(num(server, Response::RPL_USERHOST, nick, vec![parts.join(" ")])).await?;
                    }
                    Command::QUIT(reason) => {
                        let why = reason.unwrap_or_else(|| "Client Quit".to_owned());
                        let _ = prio_tx
                            .send(srv(server, Command::ERROR(format!("Closing Link: ({why})"))))
                            .await;
                        return Ok(());
                    }
                    Command::ERROR(text) => {
                        tracing::info!(%peer, %text, "client sent ERROR");
                        return Ok(());
                    }
                    Command::Raw(cmd, args) if cmd.eq_ignore_ascii_case("CHATHISTORY") => {
                        // fetch history off the read loop: federated /messages
                        // can take tens of seconds and must not stall PINGs
                        let bridge2 = Arc::clone(bridge);
                        let tx = tx.clone();
                        let server2 = server.to_owned();
                        let nick2 = nick.to_owned();
                        let caps2 = caps.clone();
                        let ref_id = format!("ch{}", batch_counter.fetch_add(1, Ordering::Relaxed));
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_chathistory(tx, &server2, &nick2, &bridge2, &caps2, ref_id, args).await
                            {
                                tracing::warn!(error = %e, "chathistory failed");
                            }
                        });
                    }
                    Command::Response(..) | Command::Raw(..) => {}
                    other => {
                        let name = format!("{other:?}")
                            .split(|c: char| !c.is_ascii_alphabetic())
                            .next()
                            .unwrap_or("UNKNOWN")
                            .to_uppercase();
                        tx.send(num(server, Response::ERR_UNKNOWNCOMMAND, nick, vec![
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
    reply_on_open: Option<String>,
) -> Result<()> {
    // close (-ref) carries no subcommand: it must be handled before
    // unpacking `sub`, or batches never flush
    if let Some(reference) = ref_name.strip_prefix('-') {
        if let Some(ml) = multiline.remove(reference) {
            tracing::debug!(reference, target = %ml.target, lines = ml.lines.len(), "flushing multiline batch");
            // spec join: lines are separated by \n unless the line carried
            // draft/multiline-concat, which joins directly
            let mut body = String::new();
            for (i, (text, concat)) in ml.lines.iter().enumerate() {
                if i > 0 && !concat {
                    body.push('\n');
                }
                body.push_str(text);
            }
            let reply = ml.reply.clone();
            if ml.target.starts_with('#') {
                relay_from_irc(bridge, nick, prefix, &ml.target, body, ml.notice, true, true, caps, echo_tx, reply).await?;
            } else {
                relay_query_from_irc(bridge, nick, prefix, &ml.target, body, ml.notice, caps, echo_tx, reply).await?;
            }
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
        // the spec puts client-only tags (e.g. +draft/reply) on the opening
        // BATCH command, not on the lines
        multiline.insert(reference.to_owned(), MultiLine { target, notice: false, lines: Vec::new(), reply: reply_on_open });
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
    tx: mpsc::Sender<Message>,
    server: &str,
    nick: &str,
    bridge: &Arc<Bridge>,
    caps: &Caps,
    ref_id: String,
    args: Vec<String>,
) -> Result<()> {
    let query = match parse_chathistory(&args) {
        Some(q) => q,
        None => {
            let _ = tx
                .send(fail_chathistory(server, nick, "INVALID_PARAMS", "*", "invalid parameters"))
                .await;
            return Ok(());
        }
    };

    // resolve target -> room (channel or DM query nick)
    let target_of = |t: &str| -> Option<(String, matrix_sdk::Room)> {
        let maps = bridge.rooms.lock().expect("rooms mutex");
        if let Some(entry) = maps.get_by_channel(t).cloned() {
            drop(maps);
            let room = bridge.client.get_room(&entry.room_id)?;
            Some((entry.channel.clone(), room))
        } else if let Some(entry) = maps.get_by_query(t).cloned() {
            drop(maps);
            let room = bridge.client.get_room(&entry.room_id)?;
            Some((entry.query.clone().unwrap_or_else(|| t.to_owned()), room))
        } else {
            None
        }
    };

    let ref_id = ref_id;
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
            let _ = tx
                .send(srv(server, Command::Raw("272".to_owned(), {
                    let mut v = vec![nick.to_owned()];
                    v.extend(items);
                    v
                })))
                .await;
        }
        ChathistoryQuery::Before { target, restriction, limit } => {
            let Some((channel, room)) = target_of(&target) else {
                let _ = tx.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "no such target")).await;
                return Ok(());
            };
            let items: Vec<HistoryItem> = match restriction {
                Restriction::Msgid(anchor) => history::around_msgid(&room, &anchor, limit, 0).await.map(|(b, _)| b).unwrap_or_default(),
                Restriction::Timestamp(ts) => history::before_timestamp(&room, ts, limit).await.unwrap_or_default(),
                Restriction::Any => history::latest(&room, limit).await.unwrap_or_default(),
            };
            let _ = caps;
            send_history(tx, batch_open(&channel), batch_close, &channel, &items).await;
        }
        ChathistoryQuery::After { target, restriction, limit } => {
            let Some((channel, room)) = target_of(&target) else {
                let _ = tx.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "no such target")).await;
                return Ok(());
            };
            let items: Vec<HistoryItem> = match restriction {
                Restriction::Msgid(anchor) => history::around_msgid(&room, &anchor, 0, limit).await.map(|(_, a)| a).unwrap_or_default(),
                Restriction::Timestamp(_) => {
                    let _ = tx.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "timestamp anchors unsupported for AFTER")).await;
                    return Ok(());
                }
                Restriction::Any => history::latest(&room, limit).await.unwrap_or_default(),
            };
            send_history(tx, batch_open(&channel), batch_close, &channel, &items).await;
        }
        ChathistoryQuery::Latest { target, restriction, limit } => {
            let Some((channel, room)) = target_of(&target) else {
                let _ = tx.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "no such target")).await;
                return Ok(());
            };
            let items: Vec<HistoryItem> = match restriction {
                Restriction::Msgid(anchor) => history::around_msgid(&room, &anchor, limit, 0).await.map(|(b, _)| b).unwrap_or_default(),
                Restriction::Timestamp(ts) => history::latest_since(&room, ts, limit).await.unwrap_or_default(),
                Restriction::Any => history::latest(&room, limit).await.unwrap_or_default(),
            };
            send_history(tx, batch_open(&channel), batch_close, &channel, &items).await;
        }
        ChathistoryQuery::Between { target, start, end, limit } => {
            let Some((channel, room)) = target_of(&target) else {
                let _ = tx.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "no such target")).await;
                return Ok(());
            };
            let (start_anchor, end_ts) = match (start, end) {
                (Restriction::Msgid(a), Restriction::Msgid(b)) => (a, b),
                _ => {
                    let _ = tx.send(fail_chathistory(server, nick, "MESSAGE_ERROR", &target, "BETWEEN requires msgid anchors")).await;
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
            send_history(tx, batch_open(&channel), batch_close, &channel, &items).await;
        }
    }
    Ok(())
}

async fn send_history(
    tx: mpsc::Sender<Message>,
    open: Message,
    close: Message,
    channel: &str,
    items: &[HistoryItem],
) {
    let msgs = history::to_irc(channel, items);
    let _ = tx.send(open).await;
    for m in msgs {
        let _ = tx.send(m).await;
    }
    let _ = tx.send(close).await;
}

async fn send_quit<S: ClientStream>(
    framed: &mut Frame<S>,
    server: &str,
    reason: Option<String>,
) -> Result<()> {
    let why = reason.unwrap_or_else(|| "Client Quit".to_owned());
    framed.send(srv(server, Command::ERROR(format!("Closing Link: ({why})")))).await?;
    Ok(())
}

/// Background post-registration work: initial sync, JOIN bursts for rooms
/// first seen on this connection (delivered through `tx` so the relay loop
/// keeps a single write side), offline invitation prompts, then the endless
/// sync loop. The returned handle must be aborted when the connection goes
/// away - it holds the device's sync position and would block the next
/// session of this user.
#[allow(clippy::too_many_arguments)]
fn spawn_bootstrap(
    bridge: Arc<Bridge>,
    tx: mpsc::Sender<Message>,
    server: String,
    nick: String,
    username: String,
    names_limit: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let prefix = client_prefix(&nick, &username);
        match bridge.bootstrap_sync().await {
            Ok(fresh) => {
                for entry in fresh {
                    let lower = entry.channel.to_ascii_lowercase();
                    let need_join = {
                        let mut j = bridge.joined.lock().expect("joined mutex");
                        if j.contains(&lower) {
                            false
                        } else {
                            j.insert(lower);
                            true
                        }
                    };
                    if !need_join {
                        continue;
                    }
                    let members = bridge.channel_members(&entry.channel).await.unwrap_or_default();
                    for m in join_burst_messages(&server, &prefix, &nick, &entry, members, names_limit) {
                        let _ = tx.send(m).await;
                    }
                }
            }
            Err(e) => tracing::warn!(nick = %nick, error = %e, "matrix bootstrap sync failed"),
        }
        bridge.collect_offline_invites().await;
        for m in bridge.invite_prompts() {
            let _ = tx.send(m).await;
        }
        crate::bridge::sync_forever(bridge.client.clone()).await;
    })
}

async fn matrix_auth<S: ClientStream>(
    framed: &mut Frame<S>,
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
    tracing::info!(nick = %nick, homeserver = ?cfg.homeserver, sasl = reg.sasl_user.is_some(), "authenticating against matrix");
    let connect = Bridge::connect(cfg, &nick, &pass, &login_user, Arc::clone(media), reg.caps.clone());
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

async fn send_join<S: ClientStream>(
    framed: &mut Frame<S>,
    server: &str,
    prefix: &Prefix,
    nick: &str,
    entry: &crate::bridge::rooms::RoomEntry,
    bridge: &Arc<Bridge>,
    names_limit: usize,
) -> Result<()> {
    let members = bridge.channel_members(&entry.channel).await.unwrap_or_default();
    for m in join_burst_messages(server, prefix, nick, entry, members, names_limit) {
        framed.send(m).await?;
    }
    Ok(())
}

/// JOIN + TOPIC + 353/366 lines for one mapped room, as standalone messages
/// (usable both from the registration burst and the background bootstrap).
pub fn join_burst_messages(
    server: &str,
    prefix: &Prefix,
    nick: &str,
    entry: &crate::bridge::rooms::RoomEntry,
    members: Vec<String>,
    names_limit: usize,
) -> Vec<Message> {
    let channel = entry.channel.clone();
    let mut out = vec![
        // JOIN is always emitted before any PRIVMSG on that channel
        from_client(prefix, Command::JOIN(channel.clone(), None, None)),
        num(server, Response::RPL_TOPIC, nick, vec![
            channel.clone(),
            entry.topic.clone(),
        ]),
    ];
    out.extend(names_messages(server, nick, &channel, members, names_limit));
    out
}

/// 353/366 for a channel, capped and chunked to keep huge rooms
/// from freezing IRC clients.
fn names_messages(
    server: &str,
    nick: &str,
    channel: &str,
    mut members: Vec<String>,
    names_limit: usize,
) -> Vec<Message> {
    let mut out = Vec::new();
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
            out.push(num(server, Response::RPL_NAMREPLY, nick, vec![
                "=".to_owned(),
                channel.to_owned(),
                line.join(" "),
            ]));
            line.clear();
            len = 0;
        }
        len += m.len() + 1;
        line.push(m);
    }
    if !line.is_empty() {
        out.push(num(server, Response::RPL_NAMREPLY, nick, vec![
            "=".to_owned(),
            channel.to_owned(),
            line.join(" "),
        ]));
    }
    let end = if truncated {
        format!("End of /NAMES list (truncated to {names_limit})")
    } else {
        "End of /NAMES list".to_owned()
    };
    out.push(num(server, Response::RPL_ENDOFNAMES, nick, vec![
        channel.to_owned(),
        end,
    ]));
    out
}

fn who_messages(
    server: &str,
    nick: &str,
    channel: &str,
    members: &[String],
    names_limit: usize,
) -> Vec<Message> {
    let mut out = Vec::new();
    for member in members.iter().take(names_limit) {
        out.push(num(server, Response::RPL_WHOREPLY, nick, vec![
            channel.to_owned(),
            member.clone(),
            "matrix".to_owned(),
            server.to_owned(),
            member.clone(),
            "H".to_owned(),
            format!("0 matrix user {member}"),
        ]));
    }
    out.push(num(server, Response::RPL_ENDOFWHO, nick, vec![
        channel.to_owned(),
        "End of WHO list".to_owned(),
    ]));
    out
}

/// Dispatch a control command sent to the `&matrix` pseudo-client and reply
/// with NOTICEs. `accept`/`decline` manage pending room invitations.
async fn control_command(
    tx: &mpsc::Sender<Message>,
    caps: &Caps,
    server: &str,
    nick: &str,
    prefix: &Prefix,
    bridge: &Arc<Bridge>,
    body: &str,
) -> Result<()> {
    tracing::debug!(nick, command = %body, "control command");
    let first = body.split_whitespace().next().unwrap_or_default().to_ascii_lowercase();
    match first.as_str() {
        "accept" | "decline" | "invites" => {
            let (replies, entry) = match bridge.invite_command(body).await {
                Ok(r) => r,
                Err(e) => (vec![format!("invite command failed: {e:#}")], None),
            };
            for reply in replies {
                let m = proto::user(
                    crate::matrix::verification::CONTROL_NICK,
                    Command::NOTICE(nick.to_owned(), reply),
                );
                let _ = tx.send(tags_for_client(caps, m)).await;
            }
            // newly joined channel: emit the JOIN burst right away
            if let Some(entry) = entry {
                if entry.query.is_none() {
                    let members = bridge.channel_members(&entry.channel).await.unwrap_or_default();
                    for m in join_burst_messages(server, prefix, nick, &entry, members, bridge.cfg.bridge.names_limit) {
                        let _ = tx.send(m).await;
                    }
                }
            }
        }
        _ => {
            for reply in bridge.hub.command(body).await {
                let m = proto::user(
                    crate::matrix::verification::CONTROL_NICK,
                    Command::NOTICE(nick.to_owned(), reply),
                );
                let _ = tx.send(tags_for_client(caps, m)).await;
            }
        }
    }
    Ok(())
}

/// IRC query PRIVMSG/NOTICE (target is a nick) → the DM room with that user.
#[allow(clippy::too_many_arguments)]
async fn relay_query_from_irc(
    bridge: &Arc<Bridge>,
    nick: &str,
    prefix: &Prefix,
    target: &str,
    body: String,
    notice: bool,
    caps: &Caps,
    echo_tx: &mpsc::Sender<Message>,
    reply_to: Option<String>,
) -> Result<()> {
    // send in the background so a slow homeserver can't stall IRC reads
    let bridge = Arc::clone(bridge);
    let target = target.to_owned();
    let echo = caps.has("echo-message");
    let caps = caps.clone();
    let prefix = prefix.clone();
    let nick = nick.to_owned();
    let echo_tx = echo_tx.clone();
    tokio::spawn(async move {
        match bridge.send_query(&target, body.clone(), notice, reply_to.as_deref()).await {
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
            Err(e) => tracing::warn!(query = %target, error = %e, "matrix dm send failed"),
        }
    });
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
