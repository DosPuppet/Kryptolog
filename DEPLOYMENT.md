# Deploying Kryptolog

`start_all.sh` runs a **local** stack: everything it starts listens on
`127.0.0.1`. This page is for a deployment other people reach. It lists what the
application relies on the reverse proxy to do, so that choosing a proxy other than
the shipped nginx example does not silently drop any of it (audit 2026-10-12 K-16,
K-17).

## Topology

```
browser ──TLS──► reverse proxy ──► uvicorn 127.0.0.1:8000   (backend/serve.sh)
                      │
                      └──► frontend/dist, served as static files
Postgres 127.0.0.1:5432 · Redis 127.0.0.1:6379  (docker-compose.yml, password-protected)
```

- **Only the proxy faces the network.** uvicorn, Postgres and Redis bind loopback.
  Docker-published ports bypass host firewalls such as UFW, which is why
  `docker-compose.yml` publishes on `127.0.0.1` rather than relying on one.
- **Serve `frontend/dist` from the proxy, never `vite preview`.** The preview server
  sends no security headers, and a `<meta>` CSP cannot express `frame-ancestors`.
- **Give Kryptolog its own origin** (`https://kryptolog.example.com`), not a path
  under a domain that hosts other applications. Everything on one origin shares
  `localStorage` — where the encrypted vault and the trusted-key store live — and
  the same script context.

## What the proxy must do

| Requirement | Why | nginx example |
|---|---|---|
| Terminate TLS 1.2+ and send HSTS | The SPA holds keys; a downgrade is a key compromise | `ssl_protocols`, `Strict-Transport-Security` |
| Send the SPA's CSP **as a header**, with `frame-ancestors 'none'` | Clickjacking; the `<meta>` CSP cannot carry it | `add_header Content-Security-Policy` |
| `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` | Defence in depth | `add_header …` |
| Cap request bodies at **8 MB** | Matches the backend's own ceiling; the largest legitimate body is a 4 MB device-transfer blob | `client_max_body_size 8M` |
| Append the client to `X-Forwarded-For` | The rate limiter keys on it (see below) | `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` |
| Forward WebSocket upgrades on the API path | The messenger's real-time channel | `Upgrade` / `Connection` headers on `location /api/` |
| Long read timeout on upgraded connections | Sockets live for hours | `proxy_read_timeout 86400` |
| Hide the server version | Nothing but a scanner needs it | `server_tokens off` |

The backend sets its own headers on API responses (`main.py`
`SecurityHeadersMiddleware`) and refuses bodies over 8 MB on its own
(`security/body_limit.py`), so a misconfigured proxy degrades to "API protected,
SPA not", never to nothing.

## Client addresses and rate limiting

`serve.sh` runs uvicorn with `--proxy-headers --forwarded-allow-ips
"$TRUSTED_PROXY_IPS"`. uvicorn walks `X-Forwarded-For` from the right and stops at
the first hop not in that list; that address is the rate-limit key. `X-Real-IP`
is **ignored**: a proxy that relays a client-sent `X-Real-IP` untouched (Caddy
does) let every client choose its own bucket.

- Set `TRUSTED_PROXY_IPS` to the address the proxy connects **from**. If the proxy
  is not listed, every user shares the proxy's single bucket — five logins a
  minute for the whole organisation.
- Never list a range that clients can connect from directly.

### Caddy

Caddy's `reverse_proxy` already appends to `X-Forwarded-For`, and only trusts an
incoming one from `trusted_proxies`. A minimal site:

```caddyfile
kryptolog.example.com {
    request_body {
        max_size 8MB
    }
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains"
        X-Content-Type-Options nosniff
        Referrer-Policy strict-origin-when-cross-origin
        Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss://kryptolog.example.com; worker-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
        -Server
    }
    handle_path /api/* {
        reverse_proxy 127.0.0.1:8000
    }
    handle {
        root * /var/www/kryptolog/frontend/dist
        try_files {path} /index.html
        file_server
    }
}
```

Build the SPA with `VITE_API_BASE_URL=https://kryptolog.example.com/api`.

## Backend configuration

`scripts/init_env.sh` writes `backend/.env` from `backend/.env.example` with
random secrets. In production the server refuses to start unless these are set
explicitly:

- `KRYPTOLOG_JWT_SECRET`
- `KRYPTOLOG_REQUIRE_INVITE` — `true` (recommended) or `false`, never by omission.
  Mint codes with `cd backend && python generate_invites.py`, which refuses to run
  until migrations are applied.
- `ALLOWED_ORIGINS` — the SPA origin. The WebSocket Origin check accepts every
  origin when this list is empty, and a login may only be signed for an origin
  on it.
- `KRYPTOLOG_DEPLOYMENT_ID` — this server's name inside every login and deletion
  signature (`init_env.sh` generates one). A signature made for another server
  is refused.

A malformed `KRYPTOLOG_MESSAGE_RETENTION_DAYS` refuses to start in every mode.
`/docs`, `/redoc` and `/openapi.json` are not served in production.

## Deploying an update

- **Ship the SPA, the extension and the server together.** Signed bodies,
  envelopes and several request shapes change between versions, and an old
  client against a new server fails — sometimes silently (an old SPA shows
  secrets it cannot decrypt).
- **Migrations run before serving**: both `serve.sh` and `start_all.sh` apply
  `alembic upgrade head` and refuse to start if it fails. Back up first
  (`scripts/backup.sh`).
- **crypto-core 4.0.0 is a clean break** (October 2026), as 3.0.0 was before
  it: every key, address, signature and envelope became hybrid (composite
  ML-DSA-65 + Ed25519, X-Wing, SHA-384 addresses). Nothing written by an
  earlier version opens or verifies — messages, wrapped keys, local and
  extension vaults, `.kvault` backups, proofs — and the clients say so by name
  rather than failing as a wrong password. There is no migration path, because
  the new keys exist only on users' devices: **a deployment holding 3.x data
  starts from an empty database**, and users recreate their identities. The
  backend's migration `b4c5d6e7f8a9` refuses to run on a database that still
  holds identities and says so; back up, then recreate the database. 3.2.0 and
  3.3.0 led up to it (3.3.0 adds `users.identity_public_key`).
- **TrustKeys production build** injects into no site by default: each user adds
  the SPA's HTTPS origin under Settings → Manage Trusted Sites. The `build:dev`
  variant (localhost trusted, silent chat signing) is for development only.

### Storage

Every account has a quota — `KRYPTOLOG_QUOTA_SECRETS` (default 1 000 secrets)
and `KRYPTOLOG_QUOTA_BYTES` (default 1 GiB, inline content and file chunks
together) — and file chunks live in PostgreSQL. Size the database disk for
*users × quota*, not for current usage, and monitor it: the quota bounds what one
account can do, not what all of them can.

### Native dependencies

None to build. Python packages come from the hashed lock:
`pip install --require-hashes -r backend/requirements.txt`. ML-DSA-65 and Ed25519
come from the `cryptography` wheel and the OpenSSL it bundles; the backend refuses
to import on a `cryptography` without them (older than 48, or a source build
against OpenSSL < 3.5), rather than failing every login later. Wheels exist for Linux
x86_64/aarch64; on another platform the lock falls back to a source build.

### Rotating the Postgres password

`POSTGRES_PASSWORD` only takes effect when the data volume is first created. On an
existing volume, change the role as well, then update `backend/.env`
(`POSTGRES_PASSWORD`, `DATABASE_URL`, `TEST_DATABASE_URL`):

```bash
docker exec kryptolog-postgres-1 psql -U kryptolog -d kryptolog \
  -c "ALTER ROLE kryptolog PASSWORD '<new password>';"
```

## What is deliberately not done

- **No per-IP connection cap on the WebSocket.** Behind a corporate NAT a whole
  office shares one address, so any cap low enough to matter would lock real
  users out. An unauthenticated socket is closed after 10 s, which bounds what
  one client can hold open.

## Operations

### Security audit log

Every security-relevant event is one JSON line on the `kryptolog.audit`
logger: logins and refused logins (with the reason), key changes, logouts,
shares and revocations, workflow decisions, group membership changes, account
deletions, conversation erases and hides, refused WebSockets, retention purges,
and every 401/403/429. Each line carries the client IP (as uvicorn resolved it,
see above), a shortened address, and the `request_id` that response carried in
`X-Request-ID`. Never content, keys, signatures, tokens or usernames.

It goes to stderr by default, apart from the application log (it does not
propagate). Set `KRYPTOLOG_AUDIT_LOG=/var/log/kryptolog/audit.jsonl` to write a
file instead, and ship that file to your SIEM. Rotate it with logrotate's
`copytruncate`, or restart the backend after rotating.

### Health

`GET /healthz` answers 200 when the database answers and, with Redis
configured, when Redis answers and this worker is actually listening on the
fan-out channel; 503 naming the failed check otherwise. Unauthenticated, and
says nothing else. Point the load balancer or supervisor at it — not at `/`,
which answers 200 from a worker whose realtime delivery is dead.

### Backup and restore

```bash
scripts/backup.sh /srv/backups/kryptolog          # pg_dump, mode 600, checked readable
scripts/restore.sh --verify /srv/backups/kryptolog/kryptolog-<ts>.dump   # rehearsal
scripts/restore.sh <dump> kryptolog_restored      # into a NEW database, never over one
```

Both run the PostgreSQL 16 client from the `postgres:16` image (nothing to
install) against `DATABASE_URL` from `backend/.env`; the password reaches the
container through its environment, never the command line. **Schedule
`backup.sh`, and schedule `restore.sh --verify` too**: a backup that has never
been restored is a hope. The rehearsal restores into a scratch database, checks
that the schema revision is one this checkout knows and that every table exists,
prints row counts, and drops it.

What a backup does **not** contain, by design: users' private keys. They never
reach the server — a lost device without its own vault backup is a lost
identity, and no server backup changes that. Also not in it: `backend/.env`
(JWT secret, deployment id, VAPID keys, service passwords). Back that up with
the deployment's other secrets; losing the JWT secret logs everyone out, losing
the VAPID keys breaks push until browsers resubscribe.

To switch to a restored database: stop the backend, point `DATABASE_URL` at it,
start the backend (it migrates before serving), keep the old database until the
new one is proven.

### Message retention

Unset by default: messages are kept until a user erases them. Set
`KRYPTOLOG_MESSAGE_RETENTION_DAYS=N` to purge DMs and group messages older than
N days, hourly, by every worker under a PostgreSQL advisory lock (one does the
work). Sessions are purged whole — a message is only readable with the key in
its session's first message — so the effective retention is N days to N days
plus 48 hours. A malformed value refuses to start. `cd backend && python
retention.py` runs a single pass, for an external scheduler. Each pass is an
audit event.

Users can also delete a conversation themselves: it is hidden from them on all
their devices, and they may first erase their own messages in it for everyone
(signed, like an account erase; the other side's messages stay).
