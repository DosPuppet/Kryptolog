# Kryptolog

A secure secret management and document signing platform built on **NIST FIPS post-quantum cryptography** — ML-KEM-768 (FIPS 203) and ML-DSA-44 (FIPS 204).

For how the pieces fit together read [ARCHITECTURE.md](ARCHITECTURE.md); for what is and is not protected, [THREAT_MODEL.md](THREAT_MODEL.md); before exposing it to anyone, [DEPLOYMENT.md](DEPLOYMENT.md).

Crypto runs on standards-based open-source libraries: [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) in the browser and extension (pure TS, no WASM), and [`pyca/cryptography`](https://cryptography.io/) — ML-DSA from OpenSSL — in the backend (in-process, no sidecar). `@noble/post-quantum` has had no independent third-party audit: it is self-audited and makes no side-channel claims. It stays because no production-grade replacement runs in every browser yet. The server only *verifies* signatures, which handles no secret. Byte-for-byte agreement between the two is proven in CI, down to the same ML-DSA public key from the same seed; the libraries themselves are trusted, not verified, by this project.

---

## Architecture

```
kryptolog/
├── backend/            Python FastAPI API (in-process ML-DSA via pyca/cryptography)
├── frontend/           React 19 SPA (Vite + TailwindCSS 4)
├── trustkeys/          Chrome/Brave extension (MV3, React 18) — PQC key custodian
├── packages/
│   └── crypto-core/    Shared crypto package — single source of truth for every
│                       wire/storage primitive (consumed by SPA + extension)
├── e2e/                Playwright end-to-end suite: real Chromium + the extension
├── scripts/            init_env.sh, backup.sh / restore.sh
└── docker-compose.yml  Local PostgreSQL 16 + Redis 7 (loopback only) for dev + tests
```

```
┌─────────────────────────────┐      ┌─────────────────────────────┐
│         Frontend            │      │     TrustKeys (MV3 ext)     │
│   React 19 + Vite + Router  │◄────►│   holds the private keys    │
│   localhost:5173            │ win. │   window.trustkeys API      │
└──────────┬──────────────────┘ tk   └─────────────────────────────┘
           │        both consume @kryptolog/crypto-core
           │ REST + WebSocket
┌──────────▼──────────────────┐
│       Backend API           │
│   FastAPI + SQLAlchemy      │
│   PyJWT HS256 tokens        │
│   ML-DSA-44 verify (OpenSSL)│
│   localhost:8000            │
└─────┬──────────────────┬────┘
      │                  │ (optional, enables multi-worker)
┌─────▼─────────┐   ┌────▼──────────────────────────┐
│ PostgreSQL 16 │   │ Redis 7                       │
│ kryptolog +   │   │ shared rate limits +          │
│ kryptolog_test│   │ WebSocket fan-out & presence  │
└───────────────┘   └───────────────────────────────┘
```

Two app processes run locally — the FastAPI API and the Vite dev server — on top of a **PostgreSQL 16** database. **Redis is optional but recommended**: without it the backend must stay a **single process** (rate limits, the WebSocket registry, and presence live in process memory); with `REDIS_URL` set, those move to Redis (pub/sub fan-out for WebSocket delivery) and multiple workers/instances are safe. ML-DSA login-challenge verification happens in-process inside the backend (session JWTs are HS256) — there is no separate crypto service.

---

## Features

| Feature | Description |
|---------|-------------|
| **Post-Quantum Authentication** | TrustKeys / local-vault ML-DSA-44 login-challenge signatures, bound to this server's origin and deployment id; the server then issues a 30-minute HS256 session JWT, revocable (sign-out ends every session and hangs up their sockets) |
| **Post-Quantum Cryptography** | ML-KEM-768 (FIPS 203) + ML-DSA-44 (FIPS 204), via `@noble/post-quantum` (clients) and `pyca/cryptography` on OpenSSL (server) |
| **Secret Vault** | E2EE secrets with hybrid encryption (ML-KEM-768 KEM + AES-GCM) — **including entry titles** (the server stores only ciphertext names) |
| **File Vault** | Chunked encrypted file upload/download (up to 50 MB) |
| **Secure Sharing** | Re-wrap session keys for any recipient (ML-KEM-768) |
| **Timebomb Access** | Share secrets with self-destruct timers (ephemeral grants); one grant per person, re-sharing replaces it |
| **Signed Documents** | Create, share, and verify digitally signed documents (sign-then-encrypt) |
| **Multisig Workflows** | Configurable **N-of-M approval quorum** — an approval workflow, not a cryptographic threshold: every listed signer holds the secret (each needs a wrapped key, so nobody approves blind), and the **server** withholds it from the recipients until any N of the M signers have signed the hash of the stored ciphertext (N = M gives classic N-of-N). Recipients' keys are stored withheld at creation or supplied by the completing signer; any signer can **reject** to block the workflow, after which the owner can **delete** it. |
| **E2EE Messenger** | Post-quantum end-to-end encryption: each sender's AES-256-GCM session key, encapsulated with ML-KEM-768 for every recipient and **rotated after 100 messages or 24 h** (and on group membership changes); **per-message ML-DSA-44 signatures over the content, its position and its time, verified client-side** — authorship, replays, gaps and reordering are detected, and an unverifiable message is hidden until the reader chooses to see it. Content-blind relay. |
| **Group Channels** | Multi-user encrypted group chat with owner/admin/member roles; **session key rotates on membership change** (removed members can't read future messages). |
| **Peer Key Verification** | Every encryption key carries a **mandatory self-signed attestation** (signed by the identity key), verified client-side before anything is encrypted to it — a substituted key fails. Each conversation shows a **safety number**, and a contact's key that changed since you last confirmed it **stops sending** until you verify and accept it. The trusted keys travel with your backups. |
| **Push Notifications** | Web Push API (VAPID) for real-time alerts; sent off the request path, at most ten subscriptions per account |
| **Hardened Local Vault** | AES-256-GCM under an **Argon2id** key (46 MiB per guess), 12-character password minimum, for browser-stored keys |
| **Device Key Transfer** | Move keys to another device via a one-time QR / transfer code (encrypted relay, single-use, ~10 min TTL) or a passphrase-encrypted `.kvault` backup file. The decryption secret never reaches the server. |
| **User Profiles** | Manage usernames and PQC identities. The directory is search-only (no listing of all users) |
| **Deletion** | Delete your account — **leave** (reversible: log back in with the same keys) or **erase** (final). Delete a conversation — hide it from your view on all devices, and optionally **erase your own messages in it** for everyone. Erasing is signed, and never takes the other side's messages |
| **Operations** | Structured security audit log (`kryptolog.audit`, JSON), `GET /healthz`, tested backup/restore scripts, optional message retention — see [DEPLOYMENT.md](DEPLOYMENT.md) |

### A note on the messenger's security properties

The messenger uses **hybrid encryption** (an ML-KEM-768 encapsulation per session, used to
wrap a fresh AES-256-GCM session key), a **content-blind server** that only ever sees
ciphertext, and **per-message ML-DSA-44 signatures**: every DM and group message is signed by
the sender and **verified client-side** against the sender's public key, so authorship is
*proven*, not merely asserted by the server. The signature also covers the message's sequence
number and timestamp, so a replayed, dropped or reordered message is flagged; a message whose
signature fails is hidden until the reader explicitly reveals it.

**Key-directory trust**: the server is the directory for contacts' encryption keys, so it is
the natural place for a key-substitution attack. Three client-side defenses stack against it:
(1) every identity **self-signs its own ML-KEM key** (attestation) — mandatory: the server
refuses a key without one, and clients refuse to encrypt to one that does not verify;
(2) **safety numbers** in every conversation let two users compare fingerprints out of band;
(3) a local **TOFU store** remembers the key you last confirmed, and a change **blocks
sending** until you check the new safety number and accept it.

**Session rotation**: every sender's session key is replaced after 100 messages or 24 hours,
and a group's whenever a member is added or removed — a removed member cannot read later
messages, an added one cannot read earlier history.

It is still **not** a ratcheting protocol: a session key is wrapped to each participant's
long-term ML-KEM key, so a compromised long-term key opens every wrap ever sent to it. There is
**no forward secrecy or post-compromise security** against that; rotation only bounds what one
leaked *session* key exposes. Deployments can also purge old messages (retention, off by
default).

**Metadata**: "zero-knowledge" means content-blind, not metadata-blind. **Entry titles are
E2EE** — secret names travel encrypted under the item's own key (so exactly the people with
access to an item can read its name) and group channel names under a per-member-wrapped key
(rebuilt with a fresh key on rename, so ex-members can't read names chosen after they left);
push notification bodies are generic so the server never needs a readable title. What the
server still sees: the social graph (who talks to whom, when), group membership, and unread
state.

---

## Installation

### Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| **Python** | 3.12 | Backend API. The hashed lock is compiled for 3.12, which CI uses. `cryptography` ships wheels for Linux and Apple-silicon macOS; on an **Intel Mac** it builds from source (Rust + an OpenSSL ≥ 3.5, which ML-DSA needs), so running the backend in a Linux container is simpler there |
| **Docker** | Any recent | Easiest way to run PostgreSQL + Redis locally (`docker compose`). Not needed if you point the backend at external instances. |
| **Node.js** | 22.x | Frontend, extension and e2e builds |
| **npm** | 10.x | Comes with Node.js |
| **Chrome / Brave** | Latest | Required for TrustKeys extension |

### 1. Clone the repository

```bash
git clone https://github.com/DosPuppet/Kryptolog.git
cd Kryptolog
```

### 2. Infrastructure (PostgreSQL + Redis)

```bash
# Generates backend/.env with random passwords and JWT secret (first run only),
# then starts Postgres 16 and Redis 7 on 127.0.0.1 with those passwords.
scripts/init_env.sh
docker compose --env-file backend/.env up -d postgres redis
```

Using external instances instead? Set `DATABASE_URL` (and `REDIS_URL`) in
`backend/.env` — see [Configuration](#configuration). Schema migrations are an
explicit step (`alembic upgrade head`, see [Database Migrations](#database-migrations-alembic))
— `start_all.sh` runs it for you; Redis is optional (single-process mode
without it).

### 3. Backend

```bash
cd backend
# backend/.env was generated by scripts/init_env.sh above — production mode,
# invite-only. For local development, set KRYPTOLOG_ENV=development there.

# Python dependencies — use the project venv (recommended)
python3 -m venv ../.venv
source ../.venv/bin/activate
pip install --require-hashes -r requirements.txt   # hashed lock, compiled from requirements.in
```

> ML-DSA comes from the `cryptography` wheel, which bundles its own OpenSSL, so
> nothing is compiled. The backend refuses to import on a `cryptography` without
> ML-DSA-44 (older than 48, or built against OpenSSL < 3.5).

`init_env.sh` already generated the JWT signing secret (`KRYPTOLOG_JWT_SECRET`,
HS256) and the deployment id. To rotate the secret later, `python
generate_server_keys.py` prints a new one; doing so signs everyone out.

**Invite-gated signups** are on in the generated file
(`KRYPTOLOG_REQUIRE_INVITE=true`). Seed codes before creating the first account,
or set it to `false` for local development:

```bash
python generate_invites.py              # 1 single-use code
python generate_invites.py 10           # 10 single-use codes
python generate_invites.py 5 --max-uses 3 --expires-days 7
```

New users paste a code on the **Create / Import vault** screen. The gate only
applies to account *creation* — existing users keep logging in normally, and an
invalid/expired code returns a generic error (no enumeration).

### 4. Frontend

```bash
cd ../frontend
cp .env.example .env   # defaults work for local dev (VITE_API_BASE_URL=http://localhost:8000)
npm install
```

### 5. TrustKeys extension (optional — recommended for secure key custody)

> See [trustkeys/README.md](trustkeys/README.md) for full extension documentation (architecture, Web API reference, key management).

```bash
cd ../trustkeys
npm install
npm run build:dev   # local development: trusts http://localhost, signs chat messages silently
npm run build       # production: injects into no site until you add it (HTTPS only)
```

Then load in Chrome/Brave:
1. Navigate to `chrome://extensions`
2. Enable **Developer Mode** (toggle in top right)
3. Click **Load Unpacked** → select the `trustkeys/dist` folder

---

## Running the Application

### Unified startup (recommended)

```bash
./start_all.sh
```

The script generates `backend/.env` on first run, starts the compose Postgres +
Redis (skipped for external `DATABASE_URL` / missing Docker), installs PM2 and frontend dependencies, builds the frontend if
`dist/` is absent, applies migrations, and launches both services under PM2 —
all bound to `127.0.0.1`. **Activate the venv first**: it installs with whatever
`python3` is on `PATH`.

Manage with: `pm2 status` · `pm2 logs` · `pm2 monit` · `pm2 stop all`.
The app is served at `http://localhost:5173/` (a local `vite preview`; production
serves `frontend/dist` from the reverse proxy — see DEPLOYMENT.md).

### Manual startup (development)

```bash
# Terminal 0 — infrastructure (once)
scripts/init_env.sh && docker compose --env-file backend/.env up -d postgres redis

# Terminal 1 — backend (uvicorn with hot-reload)
cd backend && ./run_dev.sh

# Terminal 2 — frontend (Vite dev server)
cd frontend && npm run dev
```

### URL routes

| Route | Description |
|-------|-------------|
| `/` | Login page (redirects to `/secrets` when authenticated) |
| `/secrets` | Secret vault (default authenticated view) |
| `/multisig` | Multisig workflows |
| `/messenger` | E2EE messenger |
| `/receive` | Receive keys from another device (QR / code / backup file) |
| `/proof-audit` | Offline proof verifier — upload a `.kryptolog-proof.json` to cryptographically verify its ML-DSA-44 signature(s), then check the original text/file(s) against the signed SHA-256 hash. All verification runs client-side |

---

## Configuration

Two `.env` files, one per service. `backend/.env` is generated by
`scripts/init_env.sh` from `backend/.env.example` with random secrets and safe
defaults (production mode, invite-only signup, loopback-only services); copy
`frontend/.env.example` to `frontend/.env` by hand. For anything reachable by
other people, read [DEPLOYMENT.md](DEPLOYMENT.md) first.

- **`backend/.env`** — server config: database + Redis URLs, deployment mode,
  the HS256 JWT signing secret (mandatory in production), CORS origins,
  trusted-proxy IPs, and the VAPID *private* key for Web Push. Holds the app's
  secrets — never commit it.
- **`frontend/.env`** — build-time config baked into the SPA by Vite: the
  backend API URL and the VAPID *public* key. Only `VITE_`-prefixed values are
  exposed to the browser; put nothing secret here.

### Backend (`backend/.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | – | SQLAlchemy database URL. `init_env.sh` points it at the compose Postgres with the generated `POSTGRES_PASSWORD`. Point at any Postgres instance; `sqlite:///./sql_app.db` still works if you must. |
| `POSTGRES_PASSWORD` / `REDIS_PASSWORD` | Compose: **yes** | – | Read by `docker-compose.yml` (run it with `--env-file backend/.env`). No default exists; `init_env.sh` generates both. |
| `KRYPTOLOG_BIND` | No | `127.0.0.1` | Address `serve.sh` binds uvicorn to. Keep loopback behind a local proxy. |
| `TEST_DATABASE_URL` | No | local compose test DB | Database the pytest suite targets (default `...localhost:5432/kryptolog_test`, auto-created by the compose init script). The suite creates/drops all tables around every test — never point it at real data. |
| `REDIS_URL` | No | – | Redis connection URL (`redis://localhost:6379/0` with the compose service). When set, **two** state stores move to Redis: rate limits (durable, shared) and the WebSocket fan-out + presence (pub/sub) — which is what makes multiple workers/instances safe. Unset ⇒ in-memory, single process only. |
| `RATELIMIT_STORAGE_URI` | No | `memory://` | Explicit rate-limit storage URI (overrides `REDIS_URL` for the limiter only). |
| `KRYPTOLOG_ENV` | No | `development` (`production` in the example) | `production` fails closed: the backend refuses to start unless the JWT secret, `KRYPTOLOG_REQUIRE_INVITE`, `ALLOWED_ORIGINS` and `KRYPTOLOG_DEPLOYMENT_ID` are all set, and serves no `/docs`. |
| `KRYPTOLOG_DEPLOYMENT_ID` | Prod: **yes** | `dev` | This server's identity inside every login and deletion signature, so a signature made for one server is refused by another. Generated by `init_env.sh`; 1–64 of `A-Za-z0-9_-`. Changing it invalidates nothing stored. |
| `KRYPTOLOG_JWT_SECRET` | Prod: **yes** | – | HS256 JWT signing secret (hex). From `generate_server_keys.py`. Forges JWTs if leaked — treat as a production secret. Unset in dev ⇒ ephemeral secret, JWTs reset on restart. |
| `KRYPTOLOG_REQUIRE_INVITE` | Prod: **yes** | `false` (`true` in the example) | Access filter. When `true`, registering a **new** identity at first login requires a valid invite code (existing users unaffected). Seed codes with `python generate_invites.py`. |
| `KRYPTOLOG_QUOTA_SECRETS` | No | `1000` | Secrets one account may own. Over it, creation answers 413. |
| `KRYPTOLOG_QUOTA_BYTES` | No | `1073741824` (1 GiB) | Characters one account may store, inline content and file chunks together. Over it, uploads answer 413. |
| `KRYPTOLOG_MESSAGE_RETENTION_DAYS` | No | unset (keep) | Purge DMs and group messages older than this many days, hourly, a whole session at a time. A malformed value refuses to start. |
| `KRYPTOLOG_AUDIT_LOG` | No | unset (stderr) | File to write the JSON security audit trail to. |
| `ALLOWED_ORIGINS` | Prod: **yes** | none (`http://localhost:5173` in the example) | Comma-separated SPA origins: CORS, the WebSocket Origin check, and the origins a login may be signed for. Unset, CORS refuses every browser request. |
| `TRUSTED_PROXY_IPS` | No | `127.0.0.1` | Comma-separated trusted reverse-proxy IPs, passed by `serve.sh` to uvicorn's `--forwarded-allow-ips`. The rate limiter keys on the right-most `X-Forwarded-For` hop not vouched for by one of these; `X-Real-IP` is ignored. |
| `VAPID_PUBLIC_KEY` | No | – | Web Push VAPID public key (required for push notifications) |
| `VAPID_PRIVATE_KEY` | No | – | Web Push VAPID private key |
| `VAPID_SUBJECT` | No | `mailto:admin@kryptolog.io` | Web Push VAPID subject (contact email/URL) |

> **Deployment note — multi-process needs `REDIS_URL`.** Without it, the rate
> limiter, WebSocket connection registry, and presence state live in process
> memory: running multiple workers/instances would multiply effective rate
> limits and drop real-time messages held by another instance — keep pm2
> `instances: 1` and run uvicorn **without** `--workers`. **With `REDIS_URL`
> set**, rate limits move to Redis and WebSocket delivery/presence are shared
> through Redis pub/sub, so multiple workers/instances are safe (the database
> is Postgres, concurrent-writer safe). Setting `REDIS_URL` is worthwhile even
> on a single node so login throttles survive restarts.

### Frontend (`frontend/.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_API_BASE_URL` | No | `http://localhost:8000` | Backend API URL. Also drives the CSP `connect-src` (its https + wss origins are injected into `index.html` at build time). |
| `VITE_VAPID_PUBLIC_KEY` | No | – | Web Push VAPID **public** key. Must match the backend's `VAPID_PRIVATE_KEY`. Leave empty to disable push. |
| `ALLOWED_HOSTS` | No | – | Comma-separated Vite dev server allowed hosts (e.g. a tunnel/proxy hostname). |

---

## Running Tests

### Backend (pytest)

The suite runs against a real PostgreSQL database — the `kryptolog_test` DB
created by the compose init script (override with `TEST_DATABASE_URL`). It
creates and drops all tables around every test, so never point it at a
database you care about. Redis is **not** required (WebSocket fan-out tests use
fakeredis locally; CI also runs them against a real Redis via `TEST_REDIS_URL`).

```bash
cd backend
source ../.venv/bin/activate
pip install -r requirements-dev.txt   # test-only deps, on top of the hashed runtime lock
python3 -m pytest tests/ -v
```

Coverage spans auth, secrets, file chunks, messenger, multisig (including
N-of-M quorum, reject, and delete), groups, users, notifications, key
attestations, account and conversation deletion, retention, the audit trail,
rate-limit storage, WebSocket fan-out/presence, input bounds on every request
body, and the PQC gate — with real ML-DSA signatures on every signature-gated
path (`@pytest.mark.real_signatures`). `alembic check`, `ruff check` and
`ruff format --check` are blocking gates too.

The PQC gate (`backend/tests/test_pqc.py`) proves ML-DSA-44 interop between OpenSSL
(server, through `pyca/cryptography`) and `@noble/post-quantum` (clients) using the
shared fixture `tests/fixtures/pqc_interop.json` — both directions of signature,
and the same public key from the same seed — plus FIPS size conformance and the
(classical HS256) JWT issue/verify/tamper/expiry paths.

### Frontend (vitest), crypto-core and the extension

```bash
cd frontend && npx vitest run          # SPA unit tests (incl. the PQC interop gate)
cd packages/crypto-core && npm test    # byte-compat golden vectors + version guard
cd trustkeys && npm test               # extension (vitest, chrome.* mocked)
```

`src/test/pqc.test.js` covers ML-KEM-768 wrap/unwrap round-trips, ML-DSA-44
sign/verify + tamper rejection, the OpenSSL→noble interop fixture, and a
deterministic seeded-keygen byte-pin. `crypto-core`'s suite pins the wire/storage
formats both apps share.

### End to end (Playwright, real browser + extension)

```bash
cd e2e && npm ci && npx playwright install chromium   # once
npm test   # builds the extension, starts backend + SPA on their own DB, runs
```

Two people — one with TrustKeys, one with a local vault — sign in, message each
other and share a secret, in real Chromium with the extension loaded. Needs the
compose Postgres and Redis; uses its own `kryptolog_e2e` database. See
[e2e/README.md](e2e/README.md). CI runs every suite on each push
(`.github/workflows/ci.yml`).

---

## Database Migrations (Alembic)

Schema changes are managed with Alembic. Migrations are an **explicit deployment
step** — the backend does *not* run them on startup, and will serve whatever
schema it finds. `start_all.sh` applies them before starting the app; if you run
uvicorn yourself, or start PM2 directly with `pm2 start ecosystem.config.cjs`,
run `alembic upgrade head` first.

> The backend used to migrate at import time with a `create_all` + `stamp head`
> fallback. A migration that failed halfway therefore left a partial schema
> stamped as current, which no later upgrade would repair. Failing the deploy is
> the safer outcome, so the fallback is gone.

```bash
cd backend
source ../.venv/bin/activate

# Apply migrations (required before first start, and after pulling model changes)
alembic upgrade head

# After modifying models.py: auto-generate a migration from the model diff
alembic revision --autogenerate -m "describe your change"
# Review the generated file in alembic/versions/, then apply it
alembic upgrade head

# Useful commands
alembic current      # current migration state
alembic history      # migration history
alembic downgrade -1 # step back one revision
```

---

## Tech Stack

### Backend

| Component | Technology |
|-----------|------------|
| Web framework | FastAPI 0.143 |
| ORM | SQLAlchemy 2.1 |
| Database | PostgreSQL 16 (psycopg 3); `DATABASE_URL` to override |
| Shared state (optional) | Redis 7 — rate limits + WebSocket fan-out/presence (`REDIS_URL`) |
| Migrations | Alembic 1.20 |
| HTTP client | httpx 0.28 |
| Validation | Pydantic 2.14 |
| ASGI server | uvicorn (standard) |
| Rate limiting | slowapi 0.1.10 — in-memory by default; Redis-backed when `REDIS_URL` is set |
| Post-quantum crypto | pyca/cryptography 50 on its bundled OpenSSL (ML-DSA-44, FIPS 204) — verifies every signature the server relies on |
| JWT | PyJWT 2.15 — HS256 (server-issued, server-verified) |

Exact versions, with hashes, are in `backend/requirements.txt`, compiled from `backend/requirements.in`.

### Frontend

| Component | Technology |
|-----------|------------|
| UI framework | React 19 |
| Bundler | Vite 7 |
| Routing | react-router-dom 7 |
| Styling | TailwindCSS 4 |
| Icons | lucide-react |
| PQC crypto | @kryptolog/crypto-core (@noble/post-quantum: ML-KEM-768 + ML-DSA-44) |
| QR (key transfer) | qrcode |

### TrustKeys Extension

| Component | Technology |
|-----------|------------|
| UI | React 18, Manifest V3 |
| Build | Vite + @crxjs/vite-plugin |
| PQC | @kryptolog/crypto-core (@noble/post-quantum: ML-KEM-768 + ML-DSA-44) |
| Vault | AES-256-GCM under Argon2id |

---

## Production Deployment Notes

**Read [DEPLOYMENT.md](DEPLOYMENT.md)** — it is the authoritative guide (proxy,
client addresses, required settings, backups, health, retention). The notes
below are only the parts specific to this README's setup.

### Nginx configuration

JWTs are compact HS256 tokens, so the Authorization header is small. But login/approval requests carry PQC material (ML-DSA-44 public keys ~2.6 KB hex, ~3.2 KB base64 signatures) in the request **body**, and file uploads are chunked. The largest legitimate body is under 8 MB, which is also the backend's own limit — match it at the proxy (`nginx.conf.example` does):

```nginx
http {
    client_header_buffer_size 4k;
    large_client_header_buffers 4 16k;
    client_max_body_size 8M;
}
```

### SPA routing

For production serving with Nginx, add a fallback to `index.html` for client-side routing:

```nginx
location / {
    try_files $uri $uri/ /index.html;
}
```

### Building for production

```bash
cd frontend
npm run build
# Output in dist/ — serve with Nginx or any static file server
```

See also the **deployment note** under [Configuration](#configuration): one
backend process without Redis; any number with `REDIS_URL` set.

---

## Push notifications & PWA install

Push notifications are **optional** — the app runs fine without them (the backend
just logs a warning and skips sending). To enable them:

### 1. Generate a VAPID keypair (once)

The env vars take the **base64url key values** (one line each) — *not* file paths,
*not* PEM. Generate both directly (the browser's `applicationServerKey` must be
base64url, and pywebpush accepts the base64url private key as-is):

```bash
pip install pywebpush
python3 - <<'PY'
from py_vapid import Vapid01
from cryptography.hazmat.primitives import serialization
import base64
v = Vapid01(); v.generate_keys()
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
priv = v.private_key.private_numbers().private_value.to_bytes(32, 'big')
pub  = v.public_key.public_bytes(serialization.Encoding.X962,
                                 serialization.PublicFormat.UncompressedPoint)
print("VAPID_PRIVATE_KEY=" + b64u(priv))
print("VAPID_PUBLIC_KEY="  + b64u(pub))
PY
```

### 2. Configure both sides with the matching pair

Paste the **values** above (not file paths):

| Where | Variable | Value |
|-------|----------|-------|
| Backend (`backend/.env`) | `VAPID_PRIVATE_KEY` | the base64url private key |
| Backend | `VAPID_PUBLIC_KEY` | the base64url public key |
| Backend | `VAPID_SUBJECT` | `mailto:you@example.com` |
| Frontend (build-time) | `VITE_VAPID_PUBLIC_KEY` | the **same** base64url public key |

> The frontend public key **must** equal the backend's. A mismatch means
> subscriptions are created against one key but signed with another, and the
> push service silently rejects them.

### 3. Icons & install

The repo ships **placeholder** icons (`frontend/public/icon-192.png`,
`icon-512.png`, `apple-touch-icon.png`) and a `manifest.webmanifest` so the app
is installable. Replace the placeholders with your real branding (same sizes).

### iOS specifics (important)

On iOS, Web Push **only works for a PWA installed to the Home Screen** (iOS
16.4+), never in a Safari tab. To test:
1. Open the site in Safari → Share → **Add to Home Screen**.
2. Launch it from the Home Screen icon (it runs standalone).
3. Inside the app, enable notifications (must be a user tap).

When the app is closed, real-time WebSocket delivery stops (true for any web
app) — push is the only way to be notified, which is why the above must be set
up for background message alerts to work.

---

## Security Notices

> **⚠️ Local Vault (Extension-less Mode)**
>
> When using the Local Vault without the TrustKeys extension:
> - Your PQC keys are encrypted and stored in browser `localStorage`
> - **Clearing browser data will permanently delete your keys**
> - Keys are protected with AES-256-GCM under an Argon2id key (46 MiB per guess); the password must be at least 12 characters
> - **Always back up your keys regularly** (Manage Vault → Transfer / Back up → encrypted `.kvault` file)
> - To move to a new device, use Manage Vault → Transfer / Back up → Send to another device (QR / one-time code)
> - For maximum security, use the TrustKeys Extension
> - Vaults and backups made before crypto-core 3.0.0 (October 2026) no longer open: recreate them
