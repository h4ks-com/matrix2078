# Dev test infrastructure

## Homeserver

- server_name: `doesnmlab.xyz`
- client API base URL: `https://matrix.doesnmlab.xyz`
  (discovered via `https://doesnmlab.xyz/.well-known/matrix/client` → `m.homeserver.base_url`)
- Room versions available: 10, 11 (default), 12 — all stable. **v12 repro room exists.**

## Accounts

Passwords live in `test-creds.env` (gitignored).

| account | role |
|---|---|
| `@m2078:doesnmlab.xyz` | the bridge account (matrix2078 logs in as this) |
| `@m2078-peer:doesnmlab.xyz` | the "other side" (send/receive, second device for E2EE SAS) |
| `@doesnm:doesnmlab.xyz` | the user (owner); has pending invites to everything below |

## Space + rooms

Space `#m2078-space:doesnmlab.xyz` = `!065fIhozr70kVOHgio:doesnmlab.xyz`, contains:

| alias | room_id | purpose |
|---|---|---|
| `#m2078-plain:doesnmlab.xyz` | `!rUL1FW6b5oVOa4GnkX:doesnmlab.xyz` | plain room, default version (11) |
| `#m2078-enc:doesnmlab.xyz` | `!XoWIBq2MspPOE2ltnk:doesnmlab.xyz` | `m.megolm.v1.aes-sha2` encrypted |
| `#m2078-v11:doesnmlab.xyz` | `!3PMxttTfbgUWyytxSw:doesnmlab.xyz` | room version 11 |
| `#m2078-v12:doesnmlab.xyz` | `!IeUTN64RwMY6i6xgrKhnvP_HredonSE6QjLgvryq2_c` | room version 12 — reproduce the matrix2051 v12 bug |
| `#m2078-rename:doesnmlab.xyz` | `!uLCQVJOVBGCvO0byI5:doesnmlab.xyz` | rename churn — reproduce the goguma `not joined in channel` bug |

All rooms: preset `private_chat`, both test accounts joined, `@doesnm` invited.

## Notes for REST calls (PowerShell 5.1)

```powershell
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
# login: POST $hs/_matrix/client/v3/login  (m.login.password, m.id.user)
# createRoom / send / state — standard v3 endpoints
```
