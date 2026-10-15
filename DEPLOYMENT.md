# Deploying Kryptolog

`start_all.sh` runs a **local** stack: everything it starts listens on
`127.0.0.1`. This page is for a deployment other people reach. It lists what the
application relies on the reverse proxy to do, so that choosing a proxy other than
the shipped nginx example does not silently drop any of it (audit 2026-10-12 K-16,
K-17). For a first install, follow [Single-host install](#single-host-install)
from step 1. The rest of the page is reference.

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

## Single-host install

One Linux host running everything in the topology above. The examples use
`/opt/kryptolog` for the checkout, `https://kryptolog.example.com` for the
origin, and `/var/www/kryptolog/frontend/dist` as the web root, which is the
path both shipped proxy configurations already serve. The sections after this
one explain each requirement. This section is the order to do them in.

**Do not use `start_all.sh` here.** It is the local development stack: it starts
a `vite preview` server that production must not run, and installs Python
packages with whatever `python3` is on `PATH`.

**Prerequisites:** Linux x86_64 or aarch64 (other platforms build
`cryptography` from source), Python 3.12, Node.js `^22.12 || >=24` (`.nvmrc`
says 22; every `package.json` declares the range and `.npmrc` enforces it, so a
wrong Node fails at `npm ci`), Docker with the compose plugin and the daemon
enabled at boot (`systemctl enable docker`), PM2 (`npm install -g pm2`), rsync,
and nginx or Caddy. **PostgreSQL is a hard dependency:** the migrations, the
quota and rotation locks, the retention lock and the share upserts are
PostgreSQL-only, and the backend refuses any other `DATABASE_URL`.

1. **Clone, and install the backend from the hashed lock.** The venv comes
   first because `init_env.sh` uses its `cryptography` to generate the VAPID
   pair. `serve.sh` finds this venv on its own, including at boot when nothing
   has activated it.

   ```bash
   git clone https://github.com/DosPuppet/Kryptolog.git /opt/kryptolog
   cd /opt/kryptolog
   python3.12 -m venv .venv
   .venv/bin/pip install --require-hashes -r backend/requirements.txt
   ```

2. **Generate the configuration.**

   ```bash
   scripts/init_env.sh
   ```

   This writes `backend/.env` (random secrets, production mode, invite-only,
   mode 600) with a VAPID pair, and `frontend/.env` with the same public key.
   **If it stops on an existing Postgres volume**, a volume from an earlier
   install survives, and it keeps the password it was created with. Choose
   between the ways out it prints. `scripts/init_env.sh --adopt-volume` keeps
   the data and sets the role to the new password. `docker compose
   --env-file backend/.env down -v` discards the data.

   Then edit `backend/.env`:
   - `ALLOWED_ORIGINS=https://kryptolog.example.com`. Production refuses to
     start without it, and the SPA's API URL is derived from it at build time.
   - `TRUSTED_PROXY_IPS`: the address the proxy connects from. The default,
     `127.0.0.1`, is right for a proxy on this host.
   - `KRYPTOLOG_REQUIRE_INVITE`: keep `true` unless signup is meant to be open.
   - `VAPID_SUBJECT`: a real contact (`mailto:` or URL), required by push services.

3. **Start Postgres and Redis.** Both have `restart: unless-stopped`, so they
   come back after a reboot as long as the Docker daemon does.

   ```bash
   docker compose --env-file backend/.env up -d postgres redis
   docker compose --env-file backend/.env ps          # both "healthy"
   ```

4. **Apply the migrations and mint the first invite codes.** `serve.sh` also
   migrates before every start, but running it once here gives you any error
   in your terminal rather than in the PM2 logs. `generate_invites.py` refuses
   to run until the schema is at head.

   ```bash
   cd backend
   ../.venv/bin/python migration_preflight.py --wait 30
   ../.venv/bin/python -m alembic upgrade head
   ../.venv/bin/python generate_invites.py 5
   cd ..
   ```

5. **Build and publish the SPA.**

   ```bash
   scripts/deploy_frontend.sh
   ```

   It derives the build values from `backend/.env`: the API URL from the first
   `ALLOWED_ORIGINS` entry plus `/api` (override with
   `KRYPTOLOG_PUBLIC_API_URL`), and the VAPID public key. No secret from that
   file reaches npm. The build runs in strict mode
   (`frontend/deploymentGuard.js`), so a localhost, plain-http or malformed
   configuration fails here instead of shipping. The result is copied to
   `KRYPTOLOG_WEB_ROOT` (default `/var/www/kryptolog/frontend/dist`); `sudo`
   is used only for that copy, and only if the directory needs it. Copying,
   rather than pointing the proxy into the checkout, avoids two problems:
   `vite build` empties `dist/` first, so a proxy serving the checkout answers
   404 for the whole rebuild, and the proxy would need read access to the
   repository. **Rerun this after every SPA update.**

6. **Configure the proxy.** Start from `nginx.conf.example` or the
   [Caddy site](#caddy) below. Both serve `/var/www/kryptolog/frontend/dist`
   and forward `/api/` to `127.0.0.1:8000` with the `/api` prefix stripped.
   Replace the hostname, then check [What the proxy must do](#what-the-proxy-must-do).

7. **Run the backend under PM2, and persist it.** `ecosystem.prod.cjs` is the
   backend alone. `ecosystem.config.cjs` also starts `vite preview`, which
   production must not run.

   ```bash
   pm2 start ecosystem.prod.cjs
   pm2 save                    # what `pm2 resurrect` restores at boot
   pm2 startup                 # prints a command to run once with sudo
   ```

   `serve.sh` reads `backend/.env` itself on every start, so PM2 needs no
   environment of its own. Before migrating it waits up to 120 s for the
   database (`KRYPTOLOG_DB_WAIT_SECONDS`), which carries the boot race where
   PM2 comes up before Postgres.

8. **Verify.** Each line proves a different part:

   ```bash
   curl -fsS https://kryptolog.example.com/api/healthz       # 200: database, Redis, fan-out listener
   curl -fsSI https://kryptolog.example.com/ | grep -i content-security-policy   # SPA + proxy headers
   curl -fsSI https://kryptolog.example.com/secrets           # 200: the SPA fallback to index.html
   curl -fsSI "https://kryptolog.example.com/assets/$(ls /var/www/kryptolog/frontend/dist/assets | grep '\.js$' | head -1)"
   pm2 status                                                 # kryptolog-backend online, no restarts
   ```

   Then reboot once and check `/api/healthz` again. An install is not finished
   until it has survived one.

9. **TrustKeys, for users who want it.** Build it with `npm run build` (not
   `build:dev`) in `trustkeys/`. Each user then adds
   `https://kryptolog.example.com` under Settings → Manage Trusted Sites.

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

The SPA must be built with `VITE_API_BASE_URL=https://kryptolog.example.com/api`.
`scripts/deploy_frontend.sh` derives that from `ALLOWED_ORIGINS`
([install step 5](#single-host-install)), and its strict build refuses a
localhost or plain-http value.

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

On the single-host layout above:

```bash
cd /opt/kryptolog
scripts/backup.sh /srv/backups/kryptolog              # before anything else
git pull

# Before restarting anything: is the database ready, and can this update
# apply to it? Exit 2 names a revision that needs an empty database.
(cd backend && ../.venv/bin/python migration_preflight.py)

.venv/bin/pip install --require-hashes -r backend/requirements.txt
scripts/deploy_frontend.sh                             # build, check, publish the SPA
pm2 restart kryptolog-backend                          # serve.sh checks, migrates, serves
```

Then repeat the checks from step 8 of the install.

**Run the pre-migration check before restarting.** Two revisions refuse to run
on a database that holds identities: `b4c5d6e7f8a9` (crypto-core 4.0.0) and
`c5d6e7f8a9b0` (5.0.0). Each declares `REQUIRES_EMPTY_DATABASE`, and
`migration_preflight.py` names any that are still pending before anything has
run, together with how many identities the database holds. `serve.sh` and
`start_all.sh` run the same check, so a restart refuses in the same words,
rather than with a traceback halfway through `alembic upgrade`, but by then the
backend is down. If the check names a revision, this update needs an empty
database. Make sure the backup above exists, then follow the cutover notes
below. From 5.0.0 onwards no further empty-database revision is planned.

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
- **crypto-core 5.0.0 is a clean break too** (October 2026, lot 12), and the
  last one meant to need an empty database. Identities become composite
  ML-DSA-65 + **ECDSA-P384**, encryption keys **ETSI TS 103 744 CatKDF over
  P-384 + ML-KEM-768** — every component in the ECCG Agreed Cryptographic
  Mechanisms v2 that ANSSI accepts for certification, which Ed25519 and X-Wing
  were not. Nothing 4.x wrote opens or verifies, and the clients say so by
  name; a deployment holding 4.x data starts from an empty database, and the
  backend's migration `c5d6e7f8a9b0` refuses to run on one that holds
  identities (back up first: `scripts/backup.sh`). From here on an encryption
  key carries its suite and its id (`users.encryption_key_alg`,
  `users.encryption_key_id`), which is what lets the next change of KEM be a
  rotation of keys instead of another wipe. Deploy the SPA, the extension and
  the server together.
- **crypto-core 5.1.0 is additive**: encryption-key rotation. It runs one
  migration (`d6e7f8a9b0c1`, the `encryption_key_rotations` table) and changes
  no stored format, so it deploys over 5.0.0 data. Users replace their key from
  the profile modal (their name, upper right) or, with TrustKeys, approve it in
  the extension; retired keys are listed there too, and destroying one is final
  for whatever was sealed to it and not re-wrapped — chiefly older messages.
  The endpoint is limited to 5 rotations per hour per client; every rotation
  and re-wrap is in the audit trail (`key.rotate`, `key.rewrap`).
- **What a future change of KEM looks like now**: ship a release whose registry
  has the new suite as the active one, then have users rotate. Content sealed to
  the old suite is re-wrapped where it can be and readable with the retired key
  where it cannot; the old suite stays in the registry, decapsulation only,
  until no account can hold a key under it. That is a deliberate, scheduled
  removal — never a fallback for writing. A change of **signature** suite is
  still a cutover: an address is the hash of the identity key.
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
`pip install --require-hashes -r backend/requirements.txt`. ML-DSA-65 and ECDSA
P-384 come from the `cryptography` wheel and the OpenSSL it bundles; the backend refuses
to import on a `cryptography` without them (older than 48, or a source build
against OpenSSL < 3.5), rather than failing every login later. Wheels exist for Linux
x86_64/aarch64; on another platform the lock falls back to a source build.

### Rotating the Postgres password

`POSTGRES_PASSWORD` only takes effect when the data volume is first created. On an
existing volume, change the role as well, then update `backend/.env`
(`POSTGRES_PASSWORD`, `DATABASE_URL`, `TEST_DATABASE_URL`):

Put the new password in `backend/.env` first, then let the script apply it.
It connects over the container's local socket, so it needs neither the old
password nor the new one on a command line:

```bash
scripts/init_env.sh --adopt-volume
```

The same command keeps an old volume when `init_env.sh` has just generated a
fresh `backend/.env` next to it.

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

`GET /healthz` (`/api/healthz` through the proxy) answers 200 when the database answers and, with Redis
configured, when Redis answers and this worker is actually listening on the
fan-out channel; 503 naming the failed check otherwise. Unauthenticated, and
says nothing else. Point the load balancer or supervisor at it — not at `/`,
which answers 200 from a worker whose realtime delivery is dead.

### After a reboot

Three things have to come back, and each now does on its own:

- **Postgres and Redis**: `restart: unless-stopped` in `docker-compose.yml`,
  provided the Docker daemon starts at boot (`systemctl enable docker`).
- **The backend**: `pm2 resurrect`, after `pm2 save` and `pm2 startup`.
- **The order between them**: PM2 often starts the backend before Postgres is
  healthy. `serve.sh` therefore waits for the database (up to
  `KRYPTOLOG_DB_WAIT_SECONDS`, default 120) before it migrates. It used to fail
  at once, and PM2 gave up after five quick restarts (`max_restarts: 5`,
  about thirty seconds), leaving the backend `errored` with nothing reporting it.

If the backend still shows `errored` in `pm2 status`, `pm2 logs
kryptolog-backend` has the pre-migration check's reason. Fix that, then:

```bash
docker compose --env-file backend/.env up -d postgres redis
pm2 restart kryptolog-backend
```

After any reboot, check `pm2 status` and `/api/healthz`.

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
