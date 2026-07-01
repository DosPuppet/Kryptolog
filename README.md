# Kryptolog

A secure secret management and document signing platform built on **NIST FIPS post-quantum cryptography** — ML-KEM-768 (FIPS 203) and ML-DSA-44 (FIPS 204).

Crypto runs on audited, standards-based libraries: [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) in the browser and extension (pure TS, no WASM), and [`liboqs`](https://github.com/open-quantum-safe/liboqs-python) in the backend (in-process, no sidecar).

---

## Architecture

```
kryptolog/
├── backend/          Python FastAPI API (in-process ML-DSA via liboqs)
├── frontend/         React 19 SPA (Vite + TailwindCSS 4)
└── trustkeys/        Chrome/Brave extension (MV3, React 18)
```

The application runs **2 processes locally**: a FastAPI REST API and a Vite dev server for the frontend. ML-DSA login-challenge verification happens in-process inside the backend (session JWTs are HS256) — there is no separate crypto service.

```
┌─────────────────────────────┐
│         Frontend            │
│   React 19 + Vite + Router  │
│   ML-KEM-768 + ML-DSA-44    │
│   localhost:5173             │
└──────────┬──────────────────┘
           │ REST + WebSocket
┌──────────▼──────────────────┐
│       Backend API           │
│   FastAPI + SQLAlchemy      │
│   PyJWT HS256 tokens        │
│   liboqs ML-DSA-44 verify   │
│   localhost:8000            │
└──────────┬──────────────────┘
           │
    ┌──────▼──────┐
    │   SQLite    │
    │ sql_app.db  │
    └─────────────┘
```

---

## Features

| Feature | Description |
|---------|-------------|
| **Post-Quantum Authentication** | TrustKeys / local-vault ML-DSA-44 login-challenge signatures; the server then issues an HS256 session JWT |
| **Post-Quantum Cryptography** | ML-KEM-768 (FIPS 203) + ML-DSA-44 (FIPS 204), via `@noble/post-quantum` (clients) and `liboqs` (server) |
| **Secret Vault** | E2EE secrets with hybrid encryption (ML-KEM-768 KEM + AES-GCM) |
| **File Vault** | Chunked encrypted file upload/download (up to 50 MB) |
| **Secure Sharing** | Re-wrap session keys for any recipient (ML-KEM-768) |
| **Timebomb Access** | Share secrets with self-destruct timers (ephemeral grants) |
| **Signed Documents** | Create, share, and verify digitally signed documents (sign-then-encrypt) |
| **Multisig Workflows** | Configurable **N-of-M approval quorum** — an approval workflow, not a cryptographic threshold: every listed signer already holds the secret, but it is withheld from the **destination recipient** until any N of the M signers approve (N = M gives classic N-of-N). The completing approval re-wraps the key for the recipient; signing closes once the quorum is met; any signer can **reject** to block the workflow, after which the owner can **delete** it. |
| **E2EE Messenger** | Post-quantum end-to-end encryption: per-message ML-KEM-768 → AES-256-GCM, **per-message ML-DSA-44 signatures verified client-side** (authorship is proven, not asserted by the server), zero-knowledge relay (server stores/forwards only ciphertext). PQC auth only. |
| **Group Channels** | Multi-user encrypted group chat with owner/admin/member roles; **session key rotates on membership change** (removed members can't read future messages). |
| **Push Notifications** | Web Push API (VAPID) for real-time alerts |
| **Hardened Local Vault** | AES-256-GCM + PBKDF2-SHA-512 (600k iterations) for browser-stored keys |
| **Device Key Transfer** | Move keys to another device via a one-time QR / transfer code (encrypted relay, single-use, ~10 min TTL) or a passphrase-encrypted `.kvault` backup file. The decryption secret never reaches the server. |
| **User Profiles** | Manage usernames and PQC identities |

### A note on the messenger's security properties

The messenger uses **hybrid encryption** (an ML-KEM-768 encapsulation per session, used to
wrap a fresh AES-256-GCM session key), a **zero-knowledge server** that only ever sees
ciphertext, and — as of the 2026-06 audit follow-ups — **per-message ML-DSA-44 signatures**:
every DM and group message is signed by the sender and **verified client-side** against the
sender's public key, so authorship is *proven*, not merely asserted by the server (a malicious
server can't forge or re-attribute a message). The UI flags any message whose signature fails.

**Group forward secrecy on membership change**: the group session key is rotated when a member
is added or removed, so a removed member cannot read future messages and an added member cannot
read prior history.

It is still **not** a full ratcheting protocol: within a session, messages are encrypted under a
long-term-key-derived session key, so it does **not** yet provide per-message **forward secrecy**
or **post-compromise security** against compromise of a long-term private key. 
## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| **Python** | 3.10+ | Backend API |
| **CMake + C compiler** | Latest | Required to build `liboqs` (the backend's PQC library). `pip install cmake` works; any system `gcc`/`clang` is fine. |
| **Node.js** | 22.x | Frontend + extension build |
| **npm** | 10.x | Comes with Node.js |
| **Chrome / Brave** | Latest | Required for TrustKeys extension |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/kryptolog.git
cd kryptolog
```

### 2. Backend setup

```bash
cd backend
cp .env.example .env
```

#### Python dependencies

```bash
# Option A: Using the project's virtualenv (recommended)
python3 -m venv ../.venv
source ../.venv/bin/activate
pip install -r requirements.txt   # builds liboqs C library — needs cmake + a compiler

# Option B: Global install
pip3 install -r requirements.txt
```

> `liboqs-python` compiles the `liboqs` C library on first install/import. If it
> fails, ensure `cmake` is on your PATH (`pip install cmake`) and a C compiler is
> available.

#### Generate the JWT signing secret

The backend signs access tokens with HS256 (PyJWT) using a symmetric secret —
the JWT is server-issued and server-verified only, so no keypair is needed.
Generate one and paste the line into `backend/.env`:

```bash
python generate_server_keys.py
# -> KRYPTOLOG_JWT_SECRET=...   (treat like any production secret)
```

If unset the backend falls back to an **ephemeral** secret — fine for a quick
local run, but every JWT becomes invalid on restart. (liboqs/ML-DSA-44 is still
required server-side to verify client login challenges, regardless.)

#### (Optional) Restrict signups with invite codes

By default anyone can register a new identity. To gate it, set
`KRYPTOLOG_REQUIRE_INVITE=true` in `backend/.env` and seed some codes:

```bash
python generate_invites.py              # 1 single-use code
python generate_invites.py 10           # 10 single-use codes
python generate_invites.py 5 --max-uses 3 --expires-days 7
```

New users paste a code on the **Create / Import vault** screen. The gate only
applies to account *creation* — existing users keep logging in normally, and an
invalid/expired code returns a generic error (no enumeration).

#### Database initialization

The database is created automatically on first startup via Alembic migrations. No manual steps needed.

If you prefer to initialize it explicitly:

```bash
# Apply all migrations (creates tables if DB doesn't exist)
source ../.venv/bin/activate
alembic upgrade head
```

### 3. Frontend setup

```bash
cd ../frontend

# Configure environment
cp .env.example .env
# Default values work for local development:
#   VITE_API_BASE_URL=http://localhost:8000

# Install dependencies
npm install
```

### 4. TrustKeys extension (optional — recommended for secure key custody)

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

The recommended way to run the entire Kryptolog ecosystem (FastAPI Backend and Vite Frontend) is using the unified PM2 script.

### Unified Startup (Recommended)

1. Ensure you have your `.env` configured in the `backend/` directory.
2. Run the unified startup script from the project root:

```bash
./start_all.sh
```

This script will automatically:
- Install PM2 globally if missing.
- Install any missing `npm` dependencies for the frontend.
- Build the frontend for production preview (`npm run build`).
- Launch both services in the background using PM2.

**Managing the Ecosystem:**
- **View status:** `pm2 status`
- **View all logs:** `pm2 logs`
- **Monitor resources:** `pm2 monit`
- **Stop everything:** `pm2 stop all`

The frontend will be available at: `http://localhost:5173/`

### Manual Startup (Development)

If you prefer to run the services in isolated terminals for active development:

**Terminal 1 — Backend**
```bash
cd backend
./run_dev.sh
```
*(Runs `uvicorn` with hot-reload. ML-DSA login-challenge verification is in-process — no sidecar to start.)*

**Terminal 2 — Frontend**
```bash
cd frontend
npm run dev
```

### URL Routes

| Route | Description |
|-------|-------------|
| `/` | Login page (redirects to `/secrets` when authenticated) |
| `/secrets` | Secret vault (default authenticated view) |
| `/multisig` | Multisig workflows |
| `/messenger` | E2EE messenger |
| `/proof-audit` | Offline proof verifier — upload a `.kryptolog-proof.json` to cryptographically verify its ML-DSA-44 signature(s), then check the original text/file(s) against the signed SHA-256 hash. All verification runs client-side |

---

## Running Tests

### Backend (pytest)

```bash
cd backend
source ../.venv/bin/activate
pip install -r requirements-dev.txt   # test-only deps (pytest); runtime deps stay in requirements.txt
python3 -m pytest tests/ -v
```

Currently: **162 tests** covering auth, secrets, file chunks, messenger, multisig (including N-of-M quorum, reject, and delete), groups, users, notifications, rate-limit storage, and the PQC gate (`tests/test_pqc.py`).

The PQC gate (`backend/tests/test_pqc.py`) proves ML-DSA-44 interop between `liboqs`
(server) and `@noble/post-quantum` (clients) using the shared fixture
`tests/fixtures/pqc_interop.json`, plus FIPS size conformance and the (classical
HS256) JWT issue/verify/tamper/expiry paths.

### Frontend (vitest)

```bash
cd frontend
npx vitest run src/test/pqc.test.js   # the PQC interop gate (9 tests)
```

`src/test/pqc.test.js` covers ML-KEM-768 wrap/unwrap round-trips, ML-DSA-44
sign/verify + tamper rejection, the liboqs→noble interop fixture, and a
deterministic seeded-keygen byte-pin.

---

## Database Migrations (Alembic)

Schema changes are managed with Alembic. The backend automatically runs `alembic upgrade head` on startup.

### Creating a new migration

After modifying `models.py`:

```bash
cd backend
source ../.venv/bin/activate

# Auto-generate migration from model diff
alembic revision --autogenerate -m "describe your change"

# Review the generated file in alembic/versions/
# Then apply it
alembic upgrade head
```

### Other useful commands

```bash
# Check current migration state
alembic current

# Show migration history
alembic history

# Downgrade one step
alembic downgrade -1
```

---

## Environment Variables

The app reads two `.env` files, one per service. Copy each `.env.example` to
`.env` and fill it in **before** starting the app:

- **`backend/.env`** — server config: deployment mode, the HS256 JWT signing
  secret (mandatory in production), CORS origins, trusted-proxy IPs, and the VAPID
  *private* key for sending Web Push. Holds the app's secrets — never commit it.
- **`frontend/.env`** — build-time config baked into the SPA by Vite: the backend
  API URL and the VAPID *public* key. Only `VITE_`-prefixed values are exposed to
  the browser; put nothing secret here.

Defaults are tuned for local development, so for a localhost run you can copy both
examples unchanged (push notifications stay off until VAPID keys are set).

### Backend (`backend/.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KRYPTOLOG_ENV` | No | `development` | Set to `production` to fail closed: the backend refuses to start unless the JWT secret below is configured. |
| `KRYPTOLOG_JWT_SECRET` | Prod: **yes** | – | HS256 JWT signing secret (hex). From `generate_server_keys.py`. Forges JWTs if leaked — treat as a production secret. Required when `KRYPTOLOG_ENV=production`; unset in dev ⇒ ephemeral secret, JWTs reset on restart. |
| `KRYPTOLOG_REQUIRE_INVITE` | No | `false` | Access filter. When `true`, registering a **new** identity at first login requires a valid invite code (existing users unaffected). Seed codes with `python generate_invites.py`. |
| `ALLOWED_ORIGINS` | No | `http://localhost:5173` | Comma-separated CORS origins |
| `TRUSTED_PROXY_IPS` | No | `127.0.0.1` | Comma-separated trusted reverse-proxy IPs. Rate limiting resolves the real client IP from `X-Real-IP`/`X-Forwarded-For` only when the direct peer is listed here (prevents header spoofing). |
| `REDIS_URL` | No | – | Redis connection URL. When set, rate limits are stored in Redis (durable across restarts, shared across processes) instead of in-memory. Reused as the limiter store unless `RATELIMIT_STORAGE_URI` is also set. |
| `RATELIMIT_STORAGE_URI` | No | `memory://` | Explicit rate-limit storage URI (overrides `REDIS_URL`). Unset ⇒ in-memory: per-process and reset on restart. See the single-process note below. |
| `VAPID_PUBLIC_KEY` | No | – | Web Push VAPID public key (required for push notifications) |
| `VAPID_PRIVATE_KEY` | No | – | Web Push VAPID private key |
| `VAPID_SUBJECT` | No | `mailto:admin@kryptolog.io` | Web Push VAPID subject (contact email/URL) |

> **Deployment note — the backend runs as a single process.** The rate limiter
> (when no `REDIS_URL` is set), the WebSocket connection registry, and presence
> state are held in process memory. Running multiple workers/instances would
> multiply effective rate limits and drop real-time messages delivered by another
> instance. Keep pm2 `instances: 1` and run uvicorn **without** `--workers`. To
> scale out you need, in order: (1) Redis-backed rate limits (`REDIS_URL`, already
> supported), (2) Postgres, and (3) a shared WebSocket fan-out (e.g. Redis pub/sub).
> Setting `REDIS_URL` is worthwhile even on a single node so login throttles
> survive restarts.

### Frontend (`frontend/.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_API_BASE_URL` | No | `http://localhost:8000` | Backend API URL. Also drives the CSP `connect-src` (its https + wss origins are injected into `index.html` at build time). |
| `VITE_VAPID_PUBLIC_KEY` | No | – | Web Push VAPID **public** key. Must match the backend's `VAPID_PRIVATE_KEY`. Leave empty to disable push. |
| `ALLOWED_HOSTS` | No | – | Comma-separated Vite dev server allowed hosts (e.g. a tunnel/proxy hostname). |

---

## Tech Stack

### Backend

| Component | Technology |
|-----------|------------|
| Web framework | FastAPI ≥0.128 |
| ORM | SQLAlchemy ≥2.0.46 |
| Database | SQLite (via `sql_app.db`) |
| Migrations | Alembic ≥1.13 |
| HTTP client | httpx ≥0.27 |
| Validation | Pydantic ≥2.12 |
| ASGI server | uvicorn ≥0.40 |
| Rate limiting | slowapi 0.1.9 — in-memory by default; set `REDIS_URL` for durable, shared limits (see [Environment Variables](#environment-variables)) |
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
| PQC crypto | @noble/post-quantum (ML-KEM-768 + ML-DSA-44) |
| QR (key transfer) | qrcode |

### TrustKeys Extension

| Component | Technology |
|-----------|------------|
| UI | React 18, Manifest V3 |
| Build | Vite + @crxjs/vite-plugin |
| PQC | @noble/post-quantum (ML-KEM-768 + ML-DSA-44) |
| Vault | AES-256-GCM encrypted storage |

---

## Production Deployment Notes

### Nginx configuration

JWTs are now compact HS256 tokens, so the Authorization header is small. But login/approval requests still carry PQC material (ML-DSA-44 public keys ~2.6 KB hex and ~4.8 KB signatures) in the request **body**, and file uploads are chunked — so keep generous body limits (and somewhat larger header buffers as a safety margin):

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

---





