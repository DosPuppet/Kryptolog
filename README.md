# Kryptolog

A secure secret management and document signing platform built on **NIST FIPS post-quantum cryptography** — ML-KEM-768 (FIPS 203) and ML-DSA-44 (FIPS 204).

Crypto runs on audited, standards-based libraries: [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) in the browser and extension (pure TS, no WASM), and [`liboqs`](https://github.com/open-quantum-safe/liboqs-python) in the backend (in-process, no sidecar).

---

## Architecture

```
kryptolog/
├── backend/            Python FastAPI API (in-process ML-DSA via liboqs)
├── frontend/           React 19 SPA (Vite + TailwindCSS 4)
├── trustkeys/          Chrome/Brave extension (MV3, React 18) — PQC key custodian
├── packages/
│   └── crypto-core/    Shared crypto package — single source of truth for every
│                       wire/storage primitive (consumed by SPA + extension)
└── docker-compose.yml  Local PostgreSQL 16 + Redis 7 for dev + tests
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
│   liboqs ML-DSA-44 verify   │
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
| **Post-Quantum Authentication** | TrustKeys / local-vault ML-DSA-44 login-challenge signatures; the server then issues an HS256 session JWT |
| **Post-Quantum Cryptography** | ML-KEM-768 (FIPS 203) + ML-DSA-44 (FIPS 204), via `@noble/post-quantum` (clients) and `liboqs` (server) |
| **Secret Vault** | E2EE secrets with hybrid encryption (ML-KEM-768 KEM + AES-GCM) — **including entry titles** (the server stores only ciphertext names) |
| **File Vault** | Chunked encrypted file upload/download (up to 50 MB) |
| **Secure Sharing** | Re-wrap session keys for any recipient (ML-KEM-768) |
| **Timebomb Access** | Share secrets with self-destruct timers (ephemeral grants) |
| **Signed Documents** | Create, share, and verify digitally signed documents (sign-then-encrypt) |
| **Multisig Workflows** | Configurable **N-of-M approval quorum** — an approval workflow, not a cryptographic threshold: every listed signer already holds the secret, but it is withheld from the **destination recipient** until any N of the M signers approve (N = M gives classic N-of-N). The completing approval re-wraps the key for the recipient; signing closes once the quorum is met; any signer can **reject** to block the workflow, after which the owner can **delete** it. |
| **E2EE Messenger** | Post-quantum end-to-end encryption: per-message ML-KEM-768 → AES-256-GCM, **per-message ML-DSA-44 signatures verified client-side** (authorship is proven, not asserted by the server), zero-knowledge relay (server stores/forwards only ciphertext). PQC auth only. |
| **Group Channels** | Multi-user encrypted group chat with owner/admin/member roles; **session key rotates on membership change** (removed members can't read future messages). |
| **Peer Key Verification** | Contacts' encryption keys carry a **self-signed attestation** (signed by their identity key) verified client-side before anything is encrypted to them — a lying key directory fails verification. Safety-number fingerprints cover the out-of-band identity check, and a TOFU store flags key changes. |
| **Push Notifications** | Web Push API (VAPID) for real-time alerts |
| **Hardened Local Vault** | AES-256-GCM + PBKDF2-SHA-512 (600k iterations) for browser-stored keys |
| **Device Key Transfer** | Move keys to another device via a one-time QR / transfer code (encrypted relay, single-use, ~10 min TTL) or a passphrase-encrypted `.kvault` backup file. The decryption secret never reaches the server. |
| **User Profiles** | Manage usernames and PQC identities |

### A note on the messenger's security properties

The messenger uses **hybrid encryption** (an ML-KEM-768 encapsulation per session, used to
wrap a fresh AES-256-GCM session key), a **content-blind server** that only ever sees
ciphertext, and **per-message ML-DSA-44 signatures**: every DM and group message is signed by
the sender and **verified client-side** against the sender's public key, so authorship is
*proven*, not merely asserted by the server. The UI flags any message whose signature fails.

**Key-directory trust**: the server is the directory for contacts' encryption keys, so it is
the natural place for a key-substitution attack. Three client-side defenses stack against it:
(1) every identity **self-signs its own ML-KEM key** (attestation) and clients verify that
binding before wrapping anything to the key — a substituted key fails cryptographically;
(2) **safety numbers** let two users compare fingerprints out of band to confirm the identity
itself; (3) a local **TOFU store** flags any key change since last contact. First contact with
an unattested legacy account still trusts the directory.

**Group forward secrecy on membership change**: the group session key is rotated when a member
is added or removed, so a removed member cannot read future messages and an added member cannot
read prior history.

It is still **not** a full ratcheting protocol: within a session, messages are encrypted under a
long-term-key-derived session key, so it does **not** yet provide per-message **forward secrecy**
or **post-compromise security** against compromise of a long-term private key.

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
| **Python** | 3.10+ | Backend API |
| **Docker** | Any recent | Easiest way to run PostgreSQL + Redis locally (`docker compose`). Not needed if you point the backend at external instances. |
| **CMake + C compiler** | Latest | Required to build `liboqs` (the backend's PQC library). `pip install cmake` works; any system `gcc`/`clang` is fine. |
| **Node.js** | 22.x | Frontend + extension build |
| **npm** | 10.x | Comes with Node.js |
| **Chrome / Brave** | Latest | Required for TrustKeys extension |

### 1. Clone the repository

```bash
git clone https://github.com/DosPuppet/Kryptolog.git
cd Kryptolog
```

### 2. Infrastructure (PostgreSQL + Redis)

```bash
# Starts Postgres 16 on :5432 (creates the kryptolog + kryptolog_test databases)
# and Redis 7 on :6379 — matching the defaults in backend/.env.example.
docker compose up -d postgres redis
```

Using external instances instead? Set `DATABASE_URL` (and `REDIS_URL`) in
`backend/.env` — see [Configuration](#configuration). Schema migrations are an
explicit step (`alembic upgrade head`, see [Database Migrations](#database-migrations-alembic))
— `start_all.sh` runs it for you; Redis is optional (single-process mode
without it).

### 3. Backend

```bash
cd backend
cp .env.example .env       # defaults match the compose services

# Python dependencies — use the project venv (recommended)
python3 -m venv ../.venv
source ../.venv/bin/activate
pip install -r requirements.txt   # builds liboqs (C) — needs cmake + a compiler
```

> `liboqs-python` compiles the `liboqs` C library on first install/import. If it
> fails, ensure `cmake` is on your PATH (`pip install cmake`) and a C compiler is
> available.

Generate the JWT signing secret (HS256 — server-issued, server-verified, no
keypair needed) and paste the printed line into `backend/.env`:

```bash
python generate_server_keys.py
# -> KRYPTOLOG_JWT_SECRET=...   (treat like any production secret)
```

If unset, the backend falls back to an **ephemeral** secret — fine for a quick
local run, but every JWT becomes invalid on restart. Required in production.

**Optional — invite-gated signups:** set `KRYPTOLOG_REQUIRE_INVITE=true` in
`backend/.env` and seed codes:

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
npm run build
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

The script starts the compose Postgres + Redis (skipped for external
`DATABASE_URL` / missing Docker), installs PM2 and frontend dependencies if
needed, builds the frontend for preview, and launches both services under PM2.

Manage with: `pm2 status` · `pm2 logs` · `pm2 monit` · `pm2 stop all`.
The app is served at `http://localhost:5173/`.

### Manual startup (development)

```bash
# Terminal 0 — infrastructure (once)
docker compose up -d postgres redis

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
| `/proof-audit` | Offline proof verifier — upload a `.kryptolog-proof.json` to cryptographically verify its ML-DSA-44 signature(s), then check the original text/file(s) against the signed SHA-256 hash. All verification runs client-side |

---

## Configuration

Two `.env` files, one per service. Copy each `.env.example` to `.env` before
starting; the defaults are tuned for local development with the compose
services.

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
| `DATABASE_URL` | No | local compose Postgres | SQLAlchemy database URL. Default `postgresql+psycopg://kryptolog:kryptolog@localhost:5432/kryptolog` matches `docker compose up -d postgres`. Point at any Postgres instance; `sqlite:///./sql_app.db` still works if you must. |
| `TEST_DATABASE_URL` | No | local compose test DB | Database the pytest suite targets (default `...localhost:5432/kryptolog_test`, auto-created by the compose init script). The suite creates/drops all tables around every test — never point it at real data. |
| `REDIS_URL` | No | – | Redis connection URL (`redis://localhost:6379/0` with the compose service). When set, **two** state stores move to Redis: rate limits (durable, shared) and the WebSocket fan-out + presence (pub/sub) — which is what makes multiple workers/instances safe. Unset ⇒ in-memory, single process only. |
| `RATELIMIT_STORAGE_URI` | No | `memory://` | Explicit rate-limit storage URI (overrides `REDIS_URL` for the limiter only). |
| `KRYPTOLOG_ENV` | No | `development` | Set to `production` to fail closed: the backend refuses to start unless the JWT secret below is configured. |
| `KRYPTOLOG_JWT_SECRET` | Prod: **yes** | – | HS256 JWT signing secret (hex). From `generate_server_keys.py`. Forges JWTs if leaked — treat as a production secret. Unset in dev ⇒ ephemeral secret, JWTs reset on restart. |
| `KRYPTOLOG_REQUIRE_INVITE` | No | `false` | Access filter. When `true`, registering a **new** identity at first login requires a valid invite code (existing users unaffected). Seed codes with `python generate_invites.py`. |
| `ALLOWED_ORIGINS` | No | `http://localhost:5173` | Comma-separated CORS origins |
| `TRUSTED_PROXY_IPS` | No | `127.0.0.1` | Comma-separated trusted reverse-proxy IPs. Rate limiting resolves the real client IP from `X-Real-IP`/`X-Forwarded-For` only when the direct peer is listed here (prevents header spoofing). |
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
pip install -r requirements-dev.txt   # test-only deps; runtime deps stay in requirements.txt
python3 -m pytest tests/ -v
```

Coverage spans auth, secrets, file chunks, messenger, multisig (including
N-of-M quorum, reject, and delete), groups, users, notifications, key
attestations, rate-limit storage, WebSocket fan-out/presence, and the PQC gate.

The PQC gate (`backend/tests/test_pqc.py`) proves ML-DSA-44 interop between `liboqs`
(server) and `@noble/post-quantum` (clients) using the shared fixture
`tests/fixtures/pqc_interop.json`, plus FIPS size conformance and the (classical
HS256) JWT issue/verify/tamper/expiry paths.

### Frontend (vitest) & crypto-core

```bash
cd frontend && npx vitest run          # SPA unit tests (incl. the PQC interop gate)
cd packages/crypto-core && npm test    # byte-compat golden vectors + version guard
```

`src/test/pqc.test.js` covers ML-KEM-768 wrap/unwrap round-trips, ML-DSA-44
sign/verify + tamper rejection, the liboqs→noble interop fixture, and a
deterministic seeded-keygen byte-pin. `crypto-core`'s suite pins the wire/storage
formats both apps share.

---

## Database Migrations (Alembic)

Schema changes are managed with Alembic. Migrations are an **explicit deployment
step** — the backend does *not* run them on startup, and will serve whatever
schema it finds. `start_all.sh` applies them before starting the app; if you run
uvicorn yourself, run `alembic upgrade head` first.

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
| Web framework | FastAPI ≥0.128 |
| ORM | SQLAlchemy ≥2.0.46 |
| Database | PostgreSQL 16 (psycopg 3); `DATABASE_URL` to override |
| Shared state (optional) | Redis 7 — rate limits + WebSocket fan-out/presence (`REDIS_URL`) |
| Migrations | Alembic ≥1.13 |
| HTTP client | httpx ≥0.27 |
| Validation | Pydantic ≥2.12 |
| ASGI server | uvicorn ≥0.40 |
| Rate limiting | slowapi 0.1.9 — in-memory by default; Redis-backed when `REDIS_URL` is set |
| Post-quantum crypto | liboqs-python (ML-DSA-44, FIPS 204) — in-process, verifies client login challenges |
| JWT | PyJWT 2.10 — HS256 (server-issued, server-verified) |

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
| Vault | AES-256-GCM encrypted storage |

---

## Production Deployment Notes

### Nginx configuration

JWTs are compact HS256 tokens, so the Authorization header is small. But login/approval requests still carry PQC material (ML-DSA-44 public keys ~2.6 KB hex and ~4.8 KB signatures) in the request **body**, and file uploads are chunked — so keep generous body limits (and somewhat larger header buffers as a safety margin):

```nginx
http {
    client_header_buffer_size 4k;
    large_client_header_buffers 4 16k;
    client_max_body_size 64M;
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
> - Keys are protected with AES-256-GCM via PBKDF2-SHA-512 (600,000 iterations)
> - **Always back up your keys regularly** (Manage Vault → Transfer / Back up → encrypted `.kvault` file)
> - To move to a new device, use Manage Vault → Transfer / Back up → Send to another device (QR / one-time code)
> - For maximum security, use the TrustKeys Extension
