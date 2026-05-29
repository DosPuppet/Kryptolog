# SafeLog

A secure secret management and document signing platform featuring **Post-Quantum Cryptography** via the TrustKeys browser extension.

---

## Architecture

```
safelog/
├── backend/          Python FastAPI API + Node.js PQC sidecar
├── frontend/         React 19 SPA (Vite + TailwindCSS 4)
└── trustkeys/        Chrome/Brave extension (MV3, React 18)
```

The application runs **3 processes locally**: a FastAPI REST API, a Node.js PQC cryptography microservice, and a Vite dev server for the frontend.

```
┌─────────────────────────────┐
│         Frontend            │
│   React 19 + Vite + Router  │
│   localhost:5173             │
└──────────┬──────────────────┘
           │ REST + WebSocket
┌──────────▼──────────────────┐     ┌──────────────────────┐
│       Backend API           │     │   PQC Microservice   │
│   FastAPI + SQLAlchemy      ├────►│   Node.js            │
│   localhost:8000            │HTTP │   localhost:3002      │
└──────────┬──────────────────┘     └──────────────────────┘
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
| **Dual Authentication** | MetaMask (Ethereum ECDSA) or TrustKeys (Dilithium-signed JWTs) |
| **Post-Quantum Cryptography** | Crystals-Kyber (ML-KEM 768/1024) + Crystals-Dilithium (ML-DSA) |
| **Secret Vault** | E2EE secrets with hybrid encryption (Kyber KEM + AES-GCM) |
| **File Vault** | Chunked encrypted file upload/download (up to 50 MB) |
| **Secure Sharing** | Re-wrap session keys for any recipient (Eth ↔ PQC cross-compatible) |
| **Timebomb Access** | Share secrets with self-destruct timers (ephemeral grants) |
| **Signed Documents** | Create, share, and verify digitally signed documents (sign-then-encrypt) |
| **Multisig Workflows** | N-of-N signature collection with key release on completion |
| **E2EE Messenger** | Signal-lite protocol: AES-256-GCM session keys, Kyber-1024 KEM, Dilithium-512 signatures (PQC auth only) |
| **Group Channels** | Multi-user encrypted group chat with owner/admin/member roles |
| **Push Notifications** | Web Push API (VAPID) for real-time alerts |
| **Hardened Local Vault** | AES-256-GCM + PBKDF2-SHA-512 (600k iterations) for browser-stored keys |
| **MPC Recovery** | Backup PQC identity via Google ID (multi-party computation) |
| **User Profiles** | Manage usernames and PQC identities |

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| **Python** | 3.10+ | Backend API |
| **Node.js** | 22.x | PQC microservice + frontend build |
| **npm** | 10.x | Comes with Node.js |
| **Chrome / Brave** | Latest | Required for TrustKeys extension |
| **MetaMask** | Optional | For standard Ethereum authentication |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/safelog.git
cd safelog
```

### 2. Backend setup

```bash
cd backend

# Create and configure environment variables
cp .env.example .env
# IMPORTANT: Edit .env and set these values:
#   SAFELOG_SECRET_KEY=<random-string>     ← Used to derive server PQC keys
#   PQC_SHARED_SECRET=<random-string>     ← API key for PQC microservice auth
```

#### Python dependencies

```bash
# Option A: Using the project's virtualenv (recommended)
python3 -m venv ../.venv
source ../.venv/bin/activate
pip install -r requirements.txt

# Option B: Global install
pip3 install -r requirements.txt
```

#### Node.js dependencies (for PQC microservice)

```bash
npm install
```

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

### 4. TrustKeys extension (optional — required for PQC features)

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

The recommended way to run the entire Safelog ecosystem (FastAPI Backend, Node.js PQC Sidecar, and Vite Frontend) is using the unified PM2 script.

### Unified Startup (Recommended)

1. Ensure you have your `.env` configured in the `backend/` directory.
2. Run the unified startup script from the project root:

```bash
./start_all.sh
```

This script will automatically:
- Install PM2 globally if missing.
- Install any missing `npm` dependencies for both the frontend and backend sidecar.
- Build the frontend for production preview (`npm run build`).
- Launch all three services in the background using PM2.

**Managing the Ecosystem:**
- **View status:** `pm2 status`
- **View all logs:** `pm2 logs`
- **Monitor resources:** `pm2 monit`
- **Stop everything:** `pm2 stop all`

The frontend will be available at: `http://localhost:5173/`

### Manual Startup (Development)

If you prefer to run the services in isolated terminals for active development:

**Terminal 1 — Backend & PQC Microservice**
```bash
cd backend
./run_dev.sh
```
*(This script automatically launches both `uvicorn` and `pqc_service.js`, checking for PM2 port conflicts first).*

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
| `/messenger` | E2EE messenger (PQC auth only — not available with MetaMask) |
| `/proof-audit` | Proof audit log — view and download signed document history |
| `/auth-bridge` | TrustKeys extension auth bridge |

---

## Running Tests

### Backend (pytest)

```bash
cd backend
source ../.venv/bin/activate
python3 -m pytest tests/ -v
```

Currently: **87 tests** covering auth, secrets, file chunks, messenger, multisig, groups, users, and notifications.

### Frontend (vitest)

```bash
cd frontend
npx vitest run
```

Currently: **7 tests** covering App wiring and AuthContext behavior.

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

### Backend (`backend/.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SAFELOG_SECRET_KEY` | **Yes** | – | Seed for deterministic server PQC key generation |
| `PQC_SHARED_SECRET` | **Yes** | – | API key for authenticating PQC microservice requests |
| `PQC_SERVICE_URL` | No | `http://127.0.0.1:3002` | URL of the PQC sidecar |
| `ALLOWED_ORIGINS` | No | `http://localhost:5173` | Comma-separated CORS origins |
| `VAPID_PUBLIC_KEY` | No | – | Web Push VAPID public key (required for push notifications) |
| `VAPID_PRIVATE_KEY` | No | – | Web Push VAPID private key |
| `VAPID_SUBJECT` | No | `mailto:admin@safelog.io` | Web Push VAPID subject (contact email/URL) |
| `GOOGLE_CLIENT_ID` | No | – | Google OAuth client ID (for MPC recovery, currently disabled) |

### Frontend (`frontend/.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_API_BASE_URL` | No | `http://localhost:8000` | Backend API URL |
| `ALLOWED_HOSTS` | No | – | Comma-separated Vite dev server allowed hosts |
| `VITE_GOOGLE_CLIENT_ID` | No | – | Google OAuth client ID |

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
| Rate limiting | slowapi 0.1.9 |
| JWT | PyJWT 2.10.1 |
| PQC sidecar | Node.js + dilithium-crystals-js |

### Frontend

| Component | Technology |
|-----------|------------|
| UI framework | React 19 |
| Bundler | Vite 7 |
| Routing | react-router-dom 7 |
| Styling | TailwindCSS 4 |
| Icons | lucide-react |
| PQC crypto | crystals-kyber, dilithium-crystals-js |
| Ethereum | ethers 6, @metamask/eth-sig-util |

### TrustKeys Extension

| Component | Technology |
|-----------|------------|
| UI | React 18, Manifest V3 |
| Build | Vite + @crxjs/vite-plugin |
| PQC | crystals-kyber, dilithium-crystals-js |
| Vault | AES-256-GCM encrypted storage |

---

## Production Deployment Notes

### Nginx configuration

PQC signatures (Dilithium) are significantly larger than standard signatures (~2-3 KB). You **must** increase Nginx buffer sizes:

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

## Security Notices

> **⚠️ Local Vault (Extension-less Mode)**
>
> When using the Local Vault without the TrustKeys extension:
> - Your PQC keys are encrypted and stored in browser `localStorage`
> - **Clearing browser data will permanently delete your keys**
> - Keys are protected with AES-256-GCM via PBKDF2-SHA-512 (600,000 iterations)
> - **Always export your vault regularly** (Manage Vault → Export)
> - For maximum security, use the TrustKeys Extension

---

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.




