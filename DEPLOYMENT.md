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
  origin when this list is empty.

`/docs`, `/redoc` and `/openapi.json` are not served in production.

### Storage

Every account has a quota — `KRYPTOLOG_QUOTA_SECRETS` (default 1 000 secrets)
and `KRYPTOLOG_QUOTA_BYTES` (default 1 GiB, inline content and file chunks
together) — and file chunks live in PostgreSQL. Size the database disk for
*users × quota*, not for current usage, and monitor it: the quota bounds what one
account can do, not what all of them can.

### Native dependencies

`scripts/build_liboqs.sh` builds liboqs from a pinned, checksummed release;
`serve.sh` refuses to start without it, so liboqs-python never compiles an
unpinned copy itself. Python packages come from the hashed lock:
`pip install --require-hashes -r backend/requirements.txt`.

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
