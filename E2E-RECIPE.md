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

**Rebuild the SPA if any frontend code has changed since the last run.**
`start_all.sh` builds only when `dist/` is *absent*, so an existing stale build
is served silently and the pass verifies the wrong code:

```bash
(cd frontend && npx vite build) && pm2 restart kryptolog-frontend
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
- **The partner is named on arrival, on both sides, without a reload.** This is
  what the first walk of this step found: the `NEW_MESSAGE` frame is hand-built
  and carries addresses only, so a first message from an unknown partner showed
  the literal "New Message" — the same string for everyone — until the next
  `GET /messages/conversations`. The sender saw it too, because the server
  echoes the frame back for device sync and that echo can beat the POST it came
  from. A username is public directory data, not part of the ciphertext, so it
  must appear **even while the body is still undecryptable**. A short address
  (`bbbbbbbb...`) is the acceptable failure; a placeholder name is not.

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

## 5b. SPA biometric unlock (only on a device with platform biometrics)

Manage Vault → enable biometric unlock, lock, then unlock with the
fingerprint/face prompt.

**Proves:** the hardware half. `frontend/src/test/biometrics.test.js` covers the
wiring and the encodings against a mocked PRF authenticator — which is the part
that actually broke once, when the crypto-core module split left `webauthn.js`
calling `toHex`/`fromHex` without importing them and every biometric path threw
`ReferenceError` before reaching the authenticator. What a mock cannot prove is
that a real authenticator returns a stable PRF output for the same salt across
separate ceremonies, which is the assumption the whole design rests on.

**Then keep using the app — the unlock is not the test.** The second walk of
this step found that biometrics worked and the app asked for the password
immediately after, which made the feature pointless. The key-cache TTL defaults
to 0 ("always ask"), so *every* key operation has to be answered from the
authenticator, and three things stopped that. Expect now:

- **One** ceremony to log in (it used to be two for the same password), then one
  more when the dashboard first needs keys, and **no password box**.
- Opening the messenger, a secret and the group list should each cost at most
  one ceremony, never a password prompt.
- If a password box does appear, the console now names the cause — read it
  rather than guessing. A bare `catch {}` swallowing that reason is what made
  the original report undiagnosable from the browser.

Skip if the device has no platform authenticator: there is deliberately no
software fallback, so the feature is simply not offered and
`registerBiometricCredential` throws a message saying so.

**Expect any biometric setup from before 2026-09-11 to be dead.**
`kryptolog_biometrics` and `kryptolog_vault` live in `localStorage`, which a
database wipe does not touch, and both hold pre-cutover hex. The failure is an
opaque `OperationError`, not anything that says "old format" — disable and
re-enable biometrics on a freshly created vault rather than debugging it.

## 6. nginx `/api/` WebSocket upgrade

`nginx.conf.example` is an example — nothing in the repo installs or runs it —
so this stands one up in a container. It closes audit M-10: the SPA derives its
socket URL as `VITE_API_BASE_URL.replace('http','ws') + '/ws'`, so a documented
production build opens `/api/ws` and **never reaches the carefully-configured
`/ws` block further down the file**. Without the upgrade headers on `/api/`, the
handshake is answered as a plain HTTP request and the messenger's real-time
channel simply never connects.

Run from the repo root, with the backend already up on :8000:

```bash
SCRATCH=$(mktemp -d); mkdir -p "$SCRATCH/conf.d"

# Build the SPA the way a real deployment does — against /api. The CSP
# connect-src is baked in at build time, so this must match the URL nginx serves.
# From frontend/, because vite is installed there, not at the repo root.
(cd frontend && VITE_API_BASE_URL=http://localhost:8080/api \
  npx vite build --outDir dist-nginx-test)

# Terminate plain HTTP on 8080 instead of TLS on 443. Everything below that --
# the /api/ block, the buffer sizes, the SPA fallback -- is left as shipped,
# because that is what is under test.
python3 - "$SCRATCH" <<'EOF'
import pathlib, re, sys
scratch = pathlib.Path(sys.argv[1])
src = pathlib.Path('nginx.conf.example').read_text()
src = re.sub(r'# Redirect HTTP → HTTPS\nserver \{\n.*?\n\}\n\n', '', src, flags=re.S)
src = src.replace('    listen 443 ssl;\n    http2 on;\n    server_name your-domain.com;\n',
                  '    listen 8080;\n    server_name localhost;\n')
src = re.sub(r'\n    ssl_certificate .*?ssl_ciphers [^\n]*\n', '\n', src, flags=re.S)
src = src.replace('/var/www/kryptolog/frontend/dist', '/www')
(scratch / 'conf.d' / 'kryptolog.conf').write_text(src)
EOF

docker run -d --name kryptolog-nginx-test --network host \
  -v "$SCRATCH/conf.d/kryptolog.conf:/etc/nginx/conf.d/kryptolog.conf:ro" \
  -v "$PWD/frontend/dist-nginx-test:/www:ro" \
  nginx:alpine sh -c 'rm -f /etc/nginx/conf.d/default.conf && nginx -g "daemon off;"'

curl -s -o /dev/null -w 'SPA  %{http_code}\n' http://localhost:8080/
curl -s -o /dev/null -w 'REST %{http_code}\n' http://localhost:8080/api/docs

# The M-10 assertion: 101, not 200 and not 404.
curl -s -i --http1.1 --max-time 6 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H "Sec-WebSocket-Key: $(head -c 16 /dev/urandom | base64)" \
  -H 'Origin: http://localhost:5173' \
  http://localhost:8080/api/ws | head -1

docker rm -f kryptolog-nginx-test; rm -rf frontend/dist-nginx-test
```

The `Origin` header is a value the backend's allowlist accepts; nginx passes it
through untouched. The origin policy itself is covered by `test_ws.py` — what is
under test here is the proxy.

**Result on 2026-09-11: `HTTP/1.1 101 Switching Protocols`.** Verified by
removing the two `proxy_set_header` lines from the `/api/` block and re-running,
which gives **404** — the request forwarded as plain HTTP to a path that has no
plain-HTTP route. That is the M-10 failure exactly, so the headers are load-
bearing and this check discriminates.

Still not covered by this: TLS. The block is exercised over plain HTTP, so the
certificate paths and `ssl_*` directives are syntax-checked (`nginx -t` runs as
part of the container start) but never handshaken.

## Recording the result

Note the outcome of each step in `CLAUDE.md` under the remediation status, with
the date and the commit tested. A step that fails is a finding: record what the
browser showed, not just "step 3 failed".
