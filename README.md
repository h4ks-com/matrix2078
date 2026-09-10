# matrix2078

An IRC server (IRCd) backed by [Matrix](https://matrix.org/): point a regular
IRC client at it and chat on Matrix. The successor to
[matrix2051](https://github.com/progval/matrix2051).

> 2078: He announces that he's finally making the jump from screen+irssi to
> tmux+weechat.

*(xkcd 1782 alt text)*

## Why

matrix2051 had five fatal flaws, all fixed here by design:

1. **No E2EE.** matrix2078 decrypts Megolm natively via matrix-sdk/vodozemac
   and supports interactive SAS device verification driven through IRC prompts.
2. **Images broken by authenticated media.** Media is fetched with the access
   token, stored locally and served over a stable local HTTP URL — no raw
   `mxc`/`/_matrix/media` URLs ever reach the IRC client.
3. **Cannot join room version 12.** It works here (matrix-sdk 0.18).
4. **"Fake renames" that break clients like goguma** (`not joined in channel`
   and lost rooms). IRC channel names are stable per room — a Matrix room name
   change surfaces as TOPIC, never as RENAME.
5. **One session/device per IRC connection.** Matrix sessions are persistent
   per user: reconnect and you're on the same device, with the same trust.

## Status

M0–M3 done: minimal IRCd, persistent Matrix sessions, **all joined rooms
bridged automatically** (matrix2051-style), stable per-room channel names
(room renames surface as TOPIC, never as channel renames), room version 12
works, authenticated media pipeline (images/files are downloaded with the
access token, cached locally and served at stable signed
`http://127.0.0.1:2079/...` URLs), and capped NAMES/WHO replies so
thousand-member rooms don't freeze IRC clients.

M2 adds IRCv3: capability negotiation, **SASL PLAIN** (user = full
`@user:domain`, password = Matrix password), **server-time** + `msgid` tags
(event ids, used as chathistory anchors), **echo-message**, **draft/multiline**
batches both ways (with word-wrap downgrade for legacy clients),
**draft/chathistory** (LATEST/BEFORE/AFTER/BETWEEN/TARGETS via Matrix
`/messages` + `/context`), away-notify via Matrix presence.

M3 adds end-to-end encryption: **Megolm rooms decrypt natively** (matrix-sdk /
vodozemac) for both live relay and chathistory, **SAS device verification
driven from IRC** via the `&matrix` pseudo-client (`/msg &matrix help`), and
**encrypted media** (attachments in encrypted rooms are fetched with the
token, AES-CTR-decrypted and served like any other file).

M4 adds rich semantics on top: **formatting both ways** (ported from
matrix2051: `org.matrix.custom.html` ⇄ mIRC codes incl. the 16–98 extended
color palette and `\x04RRGGBB` hex colors, URL/mxid linkification), rich
**replies** (`+draft/reply` tag both ways, reply-fallback stripping),
**reactions** (`+draft/react` TAGMSG ⇄ `m.reaction`), **edits** (m.replace
rendered as `* new body`) and **redactions** (`draft/message-redaction`
`REDACT` command, downgraded to a NOTICE for legacy clients), and
**mentions** (IRC nicks ⇄ `m.mentions`, `@user:server` mxids shortened to
nicks). See `AGENTS.md` for the milestone plan up to M6 (goguma/voidbar
compat passes).

## Usage

```
cargo run --release -- --allow-register
```

Then connect an IRC client to `127.0.0.1:2078`:

- **server password** (or SASL PLAIN): your Matrix account password
- **nick**: your Matrix localpart (e.g. `m2078` for `@m2078:example.org`)
- **SASL username**: full `@user:domain` mxid (recommended; also used for
  the first login)
- **username** (optional): full `@user:domain` for the first login
- **realname** (GECOS): your homeserver URL, matrix2051-style (optional if
  configured in `matrix2078.toml`)

Every joined room appears as an IRC channel automatically. The Matrix
session (tokens + state) is stored encrypted under `state/` (keyed by argon2
+ XChaCha20-Poly1305 under your IRC password) and reused on every reconnect
— no device spam. After the first registration, `--allow-register` is no
longer needed.

### Verifying devices from IRC

Interactive SAS verification is surfaced through the `&matrix` pseudo-client:

```
/msg &matrix help
/msg &matrix devices                # list your (or someone's) devices
/msg &matrix verify start @user:homeserver
# when a verification request arrives you get a NOTICE, then:
/msg &matrix verify accept          # shows the SAS emoji row
/msg &matrix verify match           # or: verify mismatch
```

Configuration: `matrix2078.toml` and `MATRIX2078_*` environment variables
(`MATRIX2078_LISTEN`, `MATRIX2078_MEDIA_LISTEN`, `MATRIX2078_STATE_DIR`,
`MATRIX2078_HOMESERVER`, `MATRIX2078_NAMES_LIMIT`,
`MATRIX2078_ALLOW_REGISTER`), plus `RUST_LOG` for log filtering.

## License

AGPL-3.0-only. matrix2078 ports substantial code and ideas from five
Matrix↔IRC gateway ancestors:

- [matrix2051](https://github.com/progval/matrix2051) (Elixir, AGPL) —
  IRCv3 semantics and formatting
- [matrirc](https://github.com/canatin/matrirc) (Rust, WTFPL) — session
  crypto/restore, room mappings, SAS-over-IRC, media
- [matrix-ircd](https://github.com/matrix-ircd/matrix-ircd) (Rust, Apache-2.0)
  — module layout
- [pto](https://github.com/1tldr/pto) (Rust, Apache-2.0) — SRV discovery,
  TLS listeners
- [AgentSmith](https://gitlab.com/robertfoss/agentsmith) (Crystal, MIT) —
  command dispatch and pluggable formatters
