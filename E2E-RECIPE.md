# End-to-end verification recipe

The manual pass that automated tests cannot replace. It has been open since the
first audit (`audit/AUDIT-2026-09-03.md` §8 item 5) and is the gate before any
real deployment.

**Why it exists.** Every package is green, and that is not the same as the
system working. The suites are split at exactly the seams that matter: the SPA's
crypto tests use real ML-DSA and real AES-GCM over a *fake transport*, while the
backend's messenger tests use a real transport with *hand-written envelope
literals*. Nobody has ever run client-encrypt → real HTTP → client-decrypt. Same
for the WebSocket: `test_ws.py` drives the handshake in-process through ASGI, so
no test has ever opened a socket, and nothing exercises nginx at all.

Order is by untested risk, not by feature. Stop and record rather than pushing
past a failure — a step here failing is the point of the exercise.

---

## 0. Bring up a clean stack

```bash
# Infra. `down -v` drops the kryptolog-pgdata volume: it is the only complete
# reset the repo offers. `alembic downgrade base` is NOT equivalent — two
# migrations recreate tables they dropped, and f6a7b8c9d0e5's downgrade is a
# no-op by design.
docker compose down -v && docker compose up -d postgres redis

# `start_all.sh` calls `python3 -m pip` with whatever python3 is on PATH, so the
# venv has to be active first or it fails at the dependency step.
source backend/.venv/bin/activate
./start_all.sh
```

`backend/.env` should exist and set `KRYPTOLOG_JWT_SECRET` (otherwise every
restart invalidates all tokens and the browser starts 401ing mid-pass) and
`REDIS_URL` (otherwise presence and WS fan-out run in-process and the L-7 Redis
path is never exercised outside `fakeredis`).

Confirm before starting:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8000/   # 200
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:5173/   # 200
pm2 logs kryptolog-backend --lines 40 --nostream | grep -i 'shared mode'
#   -> "WebSocket fan-out: shared mode enabled (Redis pub/sub)"
```

**Load the extension** from `trustkeys/dist`, built with `npm run build:dev`.
Not `npm run build`: the production build strips
`__TRUSTKEYS_ALLOW_DEV_AUTOSIGN__`, so it prompts for approval on *every*
message signature and makes step 2 unbearable. `chrome://extensions` →
Developer Mode → Load Unpacked → `trustkeys/dist`.

---

## 1. Create an account and log in — do this first

Two fresh accounts, in two browser profiles (or one normal + one incognito with
the extension allowed). Authorize the extension for `http://localhost:5173` via
the extension popup.

**Proves:** the login challenge. The server builds it in `backend/auth.py`, the
SPA gets it from `crypto-core`'s `loginChallengeBody`, and until recently those
were two unrelated copies of one string. They are now pinned against a shared
fixture from both languages (`tests/fixtures/signed_bodies.json`) and a real
ML-DSA login runs through `POST /auth/login` in
`backend/tests/test_signed_bodies.py` — but this is the first time the *browser*
builds it, signs with the *extension*, and the server verifies with liboqs.
Everything below depends on it.

Watch for: a 401 on login means the two sides disagree about the challenge
bytes. A 422 means a bound is wrong; the browser now renders FastAPI's `detail`
list properly, so read it rather than guessing.

---

## 2. Two accounts exchanging DMs

Send in both directions. Leave both windows open — the second account should see
the message arrive without a refresh.

**Proves:** the first join of real crypto to real transport. The session-minting
first message carries two wrapped keys and a signature before any text, which is
the case that used to be capped at ~160 characters.

Check specifically:
- The sender-signature badge reads as valid, not as tampered.
- Messages render decrypted rather than as a "Click to Decrypt" button. That
  button is what a failed unwrap looks like, and it never resolves or explains
  itself — if it appears, the cause is in the log, not on screen.
- Send a message of **accented or CJK text near the length limit**. The budget
  used to assume one byte per character, so this was refused with a bare 422
  well below the advertised 10 000. Now covered by tests, worth seeing once.

---

## 3. A multi-chunk, multi-file upload and download

Upload **two files of at least 512 KB each** (`CHUNK_SIZE`) to one secret, so
each spans two or more chunks, then download both and diff against the
originals.

**Proves:** the AEAD associated-data binding across the *global* chunk index.
`uploadMultipleChunkedFiles` binds `(secret, globalIndex)`; `downloadFileByRange`
must rebuild the same index from `chunk_offset + i`. Getting it wrong downloads
another file's bytes and fails the GCM tag.
`frontend/src/test/fileChunks.test.js` now covers this against a store that
behaves like the server, so this step is confirmation rather than discovery.

Watch for: `Decryption failed: <OperationError>` on download. That is the AAD
refusing a chunk served under the wrong index — correct behaviour if the server
really did serve the wrong chunk, a bug if it did not.

---

## 4. WebSocket delivery through a real socket

With both accounts connected, send a DM and confirm it arrives live.

**Proves:** the join nothing covers. `test_ws.py` exercises the handshake
in-process via ASGI — no TCP, no HTTP `Upgrade` exchange — and no test connects
`POST /messages` to `manager.send_personal_message`, so nothing has ever
asserted that a `NEW_MESSAGE` frame reaches a connected socket.

With `REDIS_URL` set this also runs the L-7 presence path (one sorted set per
address) for the first time outside `fakeredis`.

Check in the browser devtools Network tab: the `/ws` request should show status
101, not 200.

---

## 5. Extension lock / unlock

Lock the vault from the popup, confirm signing is refused, unlock and confirm it
resumes. Then leave it idle past `IDLE_TIMEOUT_MS` (1 hour) — or shorten it
temporarily — and confirm it auto-locks.

**Proves:** only the browser-runtime parts. `trustkeys/test/autolock.test.js`
already fires the alarm and asserts the lock, so this is confirmatory. What a
real browser adds is what the mock cannot model: that Chrome wakes a *suspended*
MV3 service worker to deliver the alarm, and the 1-minute clamp on
`periodInMinutes` in a packed build.

---

## 6. nginx `/api/` configuration check

`nginx.conf.example` is an example: nothing in the repo installs or runs it, so
a live proxy test would mean standing one up. This is the config-only check —
it validates syntax and asserts the M-10 fix is present, and does **not** prove
proxy behaviour.

```bash
SCRATCH=$(mktemp -d)
mkdir -p "$SCRATCH/conf.d" "$SCRATCH/certs" "$SCRATCH/www"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -keyout "$SCRATCH/certs/privkey.pem" -out "$SCRATCH/certs/fullchain.pem" 2>/dev/null
sed -e 's|your-domain\.com|localhost|g' \
    -e 's|/etc/letsencrypt/live/localhost/fullchain.pem|/certs/fullchain.pem|' \
    -e 's|/etc/letsencrypt/live/localhost/privkey.pem|/certs/privkey.pem|' \
    -e 's|/var/www/kryptolog/frontend/dist|/www|' \
    nginx.conf.example > "$SCRATCH/conf.d/kryptolog.conf"
docker run --rm -v "$SCRATCH/conf.d/kryptolog.conf:/etc/nginx/conf.d/kryptolog.conf:ro" \
  -v "$SCRATCH/certs:/certs:ro" -v "$SCRATCH/www:/www:ro" \
  nginx:alpine sh -c 'rm -f /etc/nginx/conf.d/default.conf && nginx -t'

# ...and that the WebSocket upgrade headers are on the block the SPA actually hits.
awk '/location \/api\/ \{/,/^    \}/' nginx.conf.example \
  | grep -E 'proxy_http_version|Upgrade|Connection'
```

The container is the point: nothing is installed on the host, and no sudo.

**Still unverified after this step:** that a `wss://host/api/ws` handshake
actually upgrades through a running nginx. The SPA derives its socket URL as
`VITE_API_BASE_URL.replace('http','ws') + '/ws'`, so a documented production
build opens `/api/ws` and never reaches the carefully-configured `/ws` block
below it — which is the whole of audit M-10. Closing it means running nginx with
a frontend built against `VITE_API_BASE_URL=.../api`.

---

## Recording the result

Note the outcome of each step in `CLAUDE.md` under the remediation status, with
the date and the commit tested. A step that fails is a finding: record what the
browser showed, not just "step 3 failed".
