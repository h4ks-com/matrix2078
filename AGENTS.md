# matrix2078 — agent instructions

You are building **matrix2078**: an IRC server (IRCd) backed by Matrix — connect a
regular IRC client to it and chat on Matrix. It is the "sixth project" that takes
the best of five abandoned Matrix↔IRC gateways and replaces
[matrix2051](https://github.com/progval/matrix2051) for the user.

Name origin: alt text of xkcd 1782 —
*"2078: He announces that he's finally making the jump from screen+irssi to tmux+weechat"*.
Use this exact quote in the README.

Talk to the user in **Russian**. Keep answers concise.

## Non-negotiable decisions (already made — do not relitigate)

- **Language/stack:** Rust + `matrix-sdk` **0.18** (default features already include
  `e2e-encryption` + `sqlite`; add `anyhow`), tokio, `clap` (derive), `serde`+`toml`,
  `tracing`/`tracing-subscriber` (env-filter), `irc` crate **1.1** for the wire
  codec only (`irc::proto::IrcCodec` + `tokio_util::codec::Framed`), `argon2`,
  `chacha20poly1305`, `base64`, `regex`, `rand_core` (os_rng), `futures`.
  Toolchain on this machine: cargo/rustc 1.97.1, git 2.55, Windows + PowerShell 5.1.
- **License:** AGPL-3.0 (we port substantial code from matrix2051, which is AGPL).
  Fetch the text from https://www.gnu.org/licenses/agpl-3.0.txt during scaffold.
  Attribution notes for ported code: matrirc is WTFPL, pto Apache-2.0,
  AgentSmith MIT.
- **Hosting:** GitHub org `h4ks-com` → `github.com/h4ks-com/matrix2078`
  (user creates the repo; `gh` CLI is NOT installed — do local `git init -b main`,
  user pushes). Local checkout: `D:\matrix2078` (this directory).
- **Session model:** persistent per-user Matrix sessions (NOT one per IRC
  connection, which is matrix2051's flaw). Encrypt the session blob with
  argon2 + XChaCha20Poly1305 keyed by the IRC password; keep matrix-sdk state in
  `sqlite_store` under `state_dir/<nick>/`.
- **Primary clients to support:** goguma (mobile IRC client by emersion) and
  voidbar (`github.com/h4ks-com/voidbar`, a Go Discord-bouncer whose upstream is
  IRC; it uses girc and lots of IRCv3).

## The user's pain points with matrix2051 (acceptance criteria)

1. **No E2EE** — matrix2078 must decrypt Megolm natively (matrix-sdk/vodozemac)
   and support interactive SAS device verification driven through IRC prompts.
2. **Images broken by authenticated media** — never hand raw `mxc`/`/_matrix/media`
   URLs to the IRC client. Fetch via authenticated
   `/_matrix/client/v1/media/download/...` with the access token (decrypt in
   encrypted rooms), store locally, serve a stable local HTTP URL.
3. **Cannot join room version 12** — must work (matrix-sdk 0.18 handles it).
4. **"Fake renames" break goguma** (matrix2051 emitted channel renames so goguma
   then failed sends with `not joined in channel`; user lost two rooms to this) —
   IRC channel names must be **stable per room** (persisted mapping). A Matrix room
   name change surfaces as TOPIC, never as RENAME. `draft/channel-rename` only for
   clients that negotiate the cap, never for identity. JOIN is always emitted
   before any PRIVMSG on that channel.
5. **Session/device spam per connection** — solved by the persistent session
   model above.

## What to port from the five ancestors

| Source | Take |
|---|---|
| matrix2051 (Elixir, AGPL) | IRCv3 semantics: capability negotiation, message-tags, server-time, echo-message, multiline batches, chathistory (`msgid=` anchors, via `/context`+`/messages`), `downgrade()` for legacy clients, word-wrap, both format converters IRC⇄Matrix HTML incl. the 99-color table and hex colors (`lib/format/*.ex`, `lib/irc/command.ex`, `lib/irc/word_wrap.ex`, `lib/matrix_client/chat_history.ex`) |
| matrirc (Rust, WTFPL) | session crypto + restore (`src/state.rs`, `src/matrix/login.rs`), room→chan/query/LeftChan mapping with deduped nicks and pending-message queue (`src/matrix/room_mappings.rs`), SAS verification over IRC (`src/matrix/verification.rs`), invite prompts, media download (`src/matrix/`, `src/ircd/proto.rs`) |
| matrix-ircd (Rust, Apache-2.0) | module separation `irc/` vs `matrix/` vs `bridge/` |
| pto (Rust, Apache-2.0) | homeserver discovery via `_matrix._tcp` SRV (`src/dns.rs`), TLS option for non-loopback listeners |
| AgentSmith (Crystal, MIT) | small per-command dispatch, pluggable text formatters |

## Milestones

- **M0 (start here):** scaffold + config (TOML `matrix2078.toml` + `MATRIX2078_*` env
  overrides) + logging + minimal IRCd (TCP listener, PASS/NICK/USER registration,
  CAP LS/END passthrough with empty cap list, 001–005, MOTD, PING/PONG,
  JOIN/PART/PRIVMSG/NOTICE, WHO→315) + matrix login/restore + initial sync +
  relay one room both ways. Default listen `127.0.0.1:2078`, state dir `./state`.
  First registration gated by `--allow-register` (matrirc-style) or config.
- **M1:** room→channel mapping (alias localpart, else sanitized display name,
  dedup `_2` suffixes), NAMES/353 from members, TOPIC, room v12, authenticated
  media pipeline.
- **M2:** IRCv3: CAP REQ/ACK for server-time, echo-message, message-tags,
  away-notify, account-notify, SASL PLAIN (SASL user = full `@user:domain`),
  multiline batches, chathistory, downgrade+linewrap.
- **M3:** E2EE decryption end-to-end + SAS verification over IRC + encrypted media.
- **M4:** formatting both ways, replies (`+draft/reply`), reactions
  (`+draft/react`), edits/redactions, mentions.
- **M5:** DM/query mapping (2-member rooms → query target), invitations,
  SRV discovery, optional TLS.
- **M6:** compat passes against goguma (the user's current client — reproduce
  their broken-room scenarios) and voidbar-as-IRC-client.

Testing: unit tests next to code (`cargo test`); integration against the dev
homeserver described in `dev/TESTINFRA.md` using creds from `dev/test-creds.env`
(**gitignored — never commit, never paste into commits/logs**).

## Conventions

- Binary crate layout: `src/main.rs`, `src/config.rs`, `src/state.rs`,
  `src/ircd/…`, `src/matrix/…`, `src/bridge/…`, `src/format/…`.
- Commit messages: short imperative, English.
- No secrets in the repo. `dev/test-creds.env` and `state/` are gitignored.
- Windows/PowerShell notes: PS 5.1 — set
  `[Net.ServicePointManager]::SecurityProtocol=Tls12` for HTTPS REST calls;
  `gh` is unavailable.
- voidbar (separate repo at `D:\voidbar`) gets a README link to matrix2078 later —
  that is a separate changeset in that repo, not here.

## Current status

Only hand-off files exist (`AGENTS.md`, `.gitignore`, `dev/`).
Nothing is scaffolded yet. First steps: `git init -b main`, fetch AGPL LICENSE,
`cargo init`, write README (with the alt-text quote), then M0.
