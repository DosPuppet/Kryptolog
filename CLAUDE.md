# CLAUDE.md

Project instructions for Claude Code. **This file is tracked in git on purpose** — work
on this repo is split across dev environments, and the remediation status table below is
the handoff record between them. Keep it current.

## Layout

Monorepo, four parts:

| Path | What |
|---|---|
| `backend/` | FastAPI + SQLAlchemy + Alembic, PostgreSQL. Routers in `routers/`, shared security rules in `security/` (`authorization.py`, `crypto_validation.py`, `url_guard.py`, `usernames.py`). |
| `frontend/` | React 19 SPA (Vite). Messenger state is split under `src/context/messenger/`. |
| `trustkeys/` | MV3 browser extension — the key custodian. Service worker under `src/background/`. |
| `packages/crypto-core/` | `@kryptolog/crypto-core`: one copy of every crypto primitive, consumed by **both** clients via a `file:` dependency. Split into `encoding`/`signing`/`pqc`/`aead`/`vault`/`webauthn`, all re-exported from `src/index.js` — import the package root, never a submodule. |

`crypto-core` exists so the SPA and the extension can never drift apart on wire format.
Byte-for-byte compatibility is enforced by golden vectors in CI, not by a "keep in sync"
comment. Change a primitive there and you change both clients at once.

## Commands

These mirror `.github/workflows/ci.yml` — if you change one, change it there too.

```bash
# backend — needs the docker-compose Postgres running
cd backend && pytest
cd backend && alembic check      # blocking drift gate: models vs migrations
cd backend && ruff check .       # blocking gate — lint is clean, keep it clean
cd backend && ruff format .      # blocking gate (CI runs --check)

# crypto-core
cd packages/crypto-core && npm test
cd packages/crypto-core && npm run lint   # blocking gate — added 2026-09-11

# frontend
cd frontend && npx vitest run
cd frontend && npx vite build
cd frontend && npx eslint .        # blocking gate — lint is clean, keep it clean

# extension
cd trustkeys && npm test           # vitest, node env — chrome.* is mocked (test/chrome-mock.js)
cd trustkeys && npm run build
cd trustkeys && npm run lint       # blocking gate — lint is clean, keep it clean

# full stack (PM2 + docker-compose Postgres/Redis)
./start_all.sh
```

**Gotcha:** `crypto-core` is a symlinked `file:` dep. Vitest resolves the symlink to its
real path and then needs `@noble/post-quantum` next to it, so run `npm ci` inside
`packages/crypto-core` before frontend tests, or the test imports fail on a fresh clone.
(`vite build` is fine — it uses `preserveSymlinks`.)

## Conventions

- **Comments explain *why*, not *what*.** This is the project's strongest asset per the
  last audit; match the existing density and tone. Where a line exists because of a
  specific finding, reference its id (`audit S1`, `KRY-005`, `audit M-1`) so the reason
  survives the next refactor. See `backend/routers/auth.py`, `backend/security/url_guard.py`,
  and `packages/crypto-core/src/{encoding,signing}.js` for the standard.
- **Wire-format changes are a clean cutover.** No compatibility fallbacks — a fallback is
  a downgrade path. Bump `CRYPTO_CORE_VERSION` and regenerate the golden vectors
  *deliberately*; never let a vector auto-update, that defeats their purpose. A
  round-trip is not a golden vector: encode and decode change together, so a
  round-trip passes through any encoding change. Pin the bytes a *peer* receives.
- **Opaque payloads are base64; identifiers are hex.** Ciphertext, IVs, wrapped
  keys, signatures and the vault blob are base64 (`toB64`/`fromB64`). Addresses,
  ML-KEM public keys, SHA-256 digests and safety numbers stay hex
  (`toHex`/`fromHex`) — see the L-12 note below for why the line is drawn there.
- **Security rules belong in `backend/security/`,** not inline in routers. Inline
  re-implementation is what produced KRY-001.
- **Addresses are lowercase everywhere** in the database and in signed bodies. Normalize
  at the boundary.
- Rate-limited endpoints need `request: Request` as the first parameter (slowapi).

## Untracked files

Two things are deliberately **not** in git, so a fresh clone will be missing them:

- `AUDIT.md` — the full security audit (2026-09-01, French).
- `audit/AUDIT-2026-09-03.md` — the follow-up audit (French). `roadmap/` is gone;
  every item in it landed.

Both enumerate not-yet-fixed findings, which is why they stay local. Copy them across
machines out of band. The status table below is the tracked substitute.

## Remediation status — 2026-09-01 audit

Scope: the audit's Immediate + Short Term tiers. Structural debt (O-2…O-6) is deferred.
Detail for each package is in `roadmap/AUDIT-REMEDIATION.md`.

| WP | Scope | Area | Status |
|---|---|---|---|
| 0 | Cross-environment tracking setup | repo | done |
| 1 | Messenger session-adoption hardening | frontend | done — `887f779` |
| 2 | Remove unused bulk chunk-listing endpoint | backend | done — `93f2aa9` |
| 3 | Uniqueness constraints on group members + file chunks | backend | done — `93f2aa9` |
| 4 | Bind chunk index into AEAD associated data | crypto-core | done — `706c7a5` |
| 5 | Move Alembic migrations off the import path | backend | done — `93f2aa9` |
| 6 | Extend signed message body to cover the key envelope | crypto-core | done — `706c7a5` |
| 7 | Rate limits on 16 unprotected endpoints | backend | done — `93f2aa9` |
| 8 | Extension: auto-lock, sender gating, request bounds | trustkeys | done — `e77cf89` |
| 9 | Username normalization, nginx WebSocket, point fixes | mixed | done — `a263995` |
| 10 | Extension test suite (new vitest harness) | trustkeys | done — `e77cf89` |

Suggested order: WP2/3/5/7 (backend, independent) → WP1 → WP4+WP6 (one commit, single
wire-format boundary) → WP8+WP10 → WP9.

Record the commit SHA in the status column as each lands.

**All eleven work packages are done.** The audit's Immediate + Short Term tiers are
closed; structural debt (O-2…O-6, L-4, L-12) is untouched and still deferred.

Two low-severity items have been picked off since:

- **L-14 is done** — `start_all.sh` and `backend/run_dev.sh` no longer `source` the
  env file; they parse it through `scripts/load_env.sh`, covered by
  `backend/tests/test_env_loader.py`.
- **L-7 is done** — shared-mode presence is one sorted set per address
  (`kryptolog:ws:presence:{addr}`, member `{conn_id}:{state}` scored by expiry)
  instead of one key per connection found with `SCAN`. The push path reads it by
  key, so a presence lookup no longer walks the keyspace. Covered by
  `backend/tests/test_ws_fanout.py`. **Rolling restarts:** old and new key layouts
  do not overlap, so a mixed fleet mutually reads empty presence for 90s (worst
  case: a push to a user who has the app in front of them).

Two structural items have been closed as well:

- **O-2 is done** — `security/authorization.py` now answers the group and
  multisig questions too, instead of `groups.py` deriving membership three
  different ways and `multisig.py` rebuilding owner/signer/recipient inline
  next to a `can_read_secret` that already encoded the same rules. Two rules
  genuinely need both a predicate and a query form (one row vs. a paged
  listing); `backend/tests/test_authorization_drift.py` pins each pair against
  the other over every configuration, which is the KRY-001 failure mode, and a
  role/capability table there covers every group endpoint at once.
- **O-3 is done** — `GET /secrets`, `/secrets/shared-with-me`,
  `/secrets/{id}/access`, `/multisig/workflows`, `GET /groups` and
  `GET /messages/conversations` take `limit`/`offset`, bounded at both ends by
  FastAPI like `GET /users`. **The SPA must page:** the lists are capped now,
  so a caller that reads only the first response hides the user's own rows with
  nothing on screen to say so — `frontend/src/utils/paging.js` walks to the end
  and every list caller goes through it. Covered by
  `backend/tests/test_pagination.py` and `frontend/src/test/paging.test.js`.
- **The O-3 byte follow-up is done too** — paging bounded rows, not bytes, so
  the lists now return metadata and **`GET /secrets/{id}` returns content**.
  Four list endpoints stopped embedding `encrypted_data`; `/secrets/{id}/access`
  dropped its nested secret entirely (it was one full copy per grantee). Measured
  at the schema's 500 KB ceiling: a page of 50 went 26.00 MB → **0.40 MB**.

  Three things to know before touching this:
  - **`GET /secrets/{secret_id}` must stay declared below every literal
    `/secrets/...` route.** Above `/secrets/shared-with-me` it swallows that path
    and returns a 422 on an int that was never an int. `test_secret_detail.py`
    has a test for it because nothing about the failure points at route order.
  - **Lists use `SecretSummaryResponse`, not an optional field**, and defer
    `encrypted_data` in SQL as well — dropping it in the schema alone still ships
    every ciphertext to the worker for Pydantic to discard.
  - **The multisig modal hydrates on open** from `GET /multisig/workflow/{id}`;
    it used to sign from the list copy. Signing needs the stored ciphertext's
    hash, so a summary workflow is refused before any signature is produced
    (`frontend/src/test/workflowContent.test.js`).

  **Deploy the SPA and server together** — this is an API shape break. An old SPA
  against a new server shows secrets it cannot decrypt. No `CRYPTO_CORE_VERSION`
  bump: no crypto format changed, only the HTTP envelope.

`roadmap/AUDIT-REMEDIATION.md` has been deleted now that every item in it
landed — `AUDIT.md` section 0 carries the finding-by-finding status, and this table
carries the commits.

**Merged to `main` on 2026-09-10** (fast-forward from `audit-2026-09-03-followups`,
`0125365`..`1be4b36`).

## Code-quality pass — 2026-09-10

Branch `cleanup-2026-09` (`b8f444a`..`a5f7e62`, 43 commits). Not a remediation:
this was a review for simplification, shorter modules and comment quality. Every
commit leaves all four packages green, so the history can be bisected or stopped
at any point.

**Merged to `main` on 2026-09-10** (fast-forward, `b8f444a`..`a5f7e62`), with all
four suites, both builds and all four lint/format/drift gates green at `a5f7e62`.
Both merges have since been pushed — `origin/main` reached `079d008` on
2026-09-11 — and both branches are still around at the merged commit.

**A backend lint gate now exists.** `ruff check .` and `ruff format --check .`
are blocking CI steps, matching the two eslint gates. Config in
`backend/ruff.toml`. Three mechanical commits (import sort, typing
modernization, whole-tree format) are separated from every real change so they
can be skimmed and skipped. **E712 is disabled on purpose:** `Column == False`
renders as `col = false` in SQL, while ruff's suggested `not Column` asks Python
for the column object's truthiness and builds a different query.

### What moved

| Area | Change |
|---|---|
| `backend/utils/clock.py` | New. The one naive-UTC clock; models, routers and `security/` all use it. |
| `backend/security/authorization.py` | Gained `purge_expired_grants` and `is_workflow_managed`, both moved out of `secrets.py`. |
| `backend/routers/secrets.py` | `_check_secret_access` → `_load_secret(requires=...)`, used by all six paths. 513 → 469 lines. |
| `backend/routers/auth.py` | `login` split into claim / verify / upsert / mint. 144 → 26 lines. |
| `backend/routers/{groups,multisig,messenger}.py` | One row loader each; `remove_member`, `sign_multisig_workflow` and `websocket_endpoint` split. |
| `packages/crypto-core/src/` | One 766-line file → six modules (`encoding`, `signing`, `pqc`, `aead`, `vault`, `webauthn`) re-exported from a 34-line `index.js`. Public surface unchanged. |
| `frontend/src/services/api.js` | New. Replaced 35 hand-written `Bearer` headers across 18 files and three error conventions. |
| `frontend/src/utils/` | New `format.js`, `secretPayload.js`, `secretContent.js`, each with tests. |
| `frontend/src/context/PQCContext.jsx` | Nine custody dispatchers → one `withCustody` factory, and its first tests. |
| `trustkeys/src/background/index.js` | 34-arm switch → a `HANDLERS` table. The sender-gating posture is now readable as a table. |

### Behaviour changes (each its own `[BEHAVIOUR]` commit)

- **Naive UTC everywhere.** Aware writes into naive columns worked by accident;
  the two expiry comparisons in `secrets.py` were resolved by the session
  TimeZone and were correct only while the server ran in UTC. Pinned by
  `backend/tests/test_clock.py`, which walks every mapped column.
- **`CRYPTO_CORE_VERSION` 1.6.0 → 1.7.0.** `unwrapSessionKey` no longer accepts
  the legacy `ct` field name. Wrapped keys stored by a client older than the
  `encKey` rename no longer unwrap. **This is the fourth cumulative cutover**
  (1.3.0 → 1.7.0); see the list below before deploying against real data.
  *(Corrected 2026-09-11: "fourth" undercounts. The audit S5 HKDF change was a
  wire break too and predates `CHANGELOG.md`, so it has no version — the honest
  count through 2.0.0 is six.)*
  `packages/crypto-core/package.json` is now synced to the constant.
- **Two dead endpoints removed.** `POST /groups/{id}/mark-read` marked nothing,
  and the reject-workflow `reason` was validated and discarded. Both still
  tolerate a body, so no client breaks.
- **PWA-safe confirm** on reject and delete workflow. `window.confirm` silently
  drops the action in installed PWAs, which is why `utils/confirm.js` exists.
- **Unreachable router guards deleted.** Three sat behind an equal-or-tighter
  Pydantic bound. The transfer 413 sat *above* the schema cap, so it could never
  fire, and the config constant it read had no other reader.
- **Multisig create errors** now surface the server's reason instead of a flat
  "Failed to create workflow".

### Deliberately not done

- **`MessengerContext.jsx` stays at 657 lines.** Its DM and group halves share
  about fifteen closure values, so splitting them into hooks means threading all
  of that through a parameter list — plausibly worse to read than the banner
  comments it has now. Worth doing only alongside a state-shape change.
- **`MultisigCreateModal.jsx` is 522 lines**, down from 593. The wizard step
  panels and a shared user-picker are still worth extracting.
- **`ProofAudit.jsx` (514)** still renders a 120-line IIFE inside its JSX.
- **The `<Modal>` shell** for ten overlays was dropped: visual-only, untested,
  ten files, lowest value per review minute in the plan.
- **The external `CHECK_CONNECTION` arm** answers `connected: true`
  unconditionally with a hardcoded version, and has no in-repo caller. Left
  alone because `externally_connectable` is by definition callable from outside
  this repo. Worth a decision.
- **37 of 44 route handlers still have no docstring**, which is also the whole
  `/docs` surface, since FastAPI publishes them as the OpenAPI description.

### Found by the manual pass — PQC envelope size bounds

The end-to-end test caught three fields whose `max_length` had been set as if
they held user text, when each holds a post-quantum envelope. Not introduced by
the cleanup: the group-name cap has been wrong since `d916b91`.

An address IS an ML-DSA-44 public key (2 624 hex chars), a detached signature is
4 840, and a wrapped ML-KEM session key is ~2 330 — so a "name" or a "message"
costs thousands of characters before any content:

| Field | Was | Effect |
|---|---|---|
| `GroupChannelCreate.name` / `GroupUpdate.name` | 2 000 | **No group could be created at all.** One member's wrap alone is 4 954. Also broke rename and the re-wrap after every add-member. |
| `GroupMessageCreate.content` | 50 000 | A group past **nine** members could not send, in a feature capped at fifty. |
| `MessageBase.content` | 10 000 | The **first** message of a conversation (which mints a session, so it carries two wraps) was capped at ~160 characters. |

`schemas.py` now spells the costs out and derives each bound from them, so the
group bounds move with `MAX_GROUP_MEMBERS` instead of being guessed. Three
places pin it: `tests/test_envelope_sizes.py` posts what the clients really
send, `packages/crypto-core/test/envelope-size.test.js` measures the envelopes
at the producing side, and a test compares the two files' constants — drift
between the two languages is what caused this.

**`apiFetch` now renders a 422 body.** FastAPI returns `detail` as a *list* of
objects; passing it to `Error()` produced the `[object Object]` that made both
of this branch's 422s undiagnosable from the browser. The rejected `input` is
dropped from the message on purpose — it echoes the whole blob.

Still open: the message composer has no `maxLength`, so text past
`MAX_MESSAGE_TEXT_CHARS` (10 000) is refused by the server rather than by the
textarea. Readable now, but better caught client-side.

### Found by the manual pass — datetimes lost their UTC marker on the wire

Reported as "the time-bombed secret feature doesn't work: an expired secret is
still accessible to the grantee". The expiry logic was never the problem — the
server was still, correctly, honouring a grant that had **not** expired yet.
The owner's browser only thought it had.

Every `DateTime` column is naive UTC, and both renderers dropped that fact:
Pydantic emits a naive value as `2026-09-10T15:06:06.550478`, with no offset.
**ECMA-262 parses that form as LOCAL time**, so a UTC+2 browser reads back an
instant two hours early. A grant with 11 minutes left rendered "Expired", while
the grantee — correctly — still had access. It looked exactly like a broken
security control.

The same shift hit every timestamp the SPA shows (chat message times were 2h
early until a refetch), but only on expiry did it read as a bug.

`utils/clock.to_wire_utc()` is now the one renderer, because the readers are
split and a fix to either half alone leaves the other broken:

| Path | Was | Now |
|---|---|---|
| Response models (14 fields) | `created_at: datetime` | `created_at: UtcDateTime` — an `Annotated` alias carrying a `PlainSerializer` |
| Four hand-built WebSocket payloads | `.isoformat()` on the column | `to_wire_utc(...)` |

`tests/test_wire_datetimes.py` pins both: it serializes **every** model in
`schemas.py` and fails on any datetime field that goes out without an offset,
and it greps `routers/` for a bare `.isoformat()`. Both gates were
mutation-tested. No migration and no `CRYPTO_CORE_VERSION` bump — the stored
values were always right, only their rendering was lossy.

**This is the naive-UTC convention's blind spot.** `test_clock.py` proved the
columns and the comparisons agree; nothing checked what the convention looked
like once it left the process. If a future field is aware, `to_wire_utc` passes
its real offset through rather than stamping UTC over it.

## Pre-deployment pass — 2026-09-11

Branch `cutover-base64-2026-09`. The gate before a first deployment: settle the
encoding question while data is still disposable, close the deploy-time holes,
and put the manual recipe somewhere it can actually be followed.

| Scope | Area | Status |
|---|---|---|
| base64 cutover (L-12), crypto-core 2.0.0 | all four | done — `784b558` |
| PM2 migrates before serving (audit §8 item 4) | repo | done — `a29f3bc` |
| Login challenge single-sourced + real signature tests | mixed | done — `7afe9da` |
| Chunked-file round-trip coverage | frontend | done — `47085e1` |
| `E2E-RECIPE.md`, stack wiped and re-seeded | repo | done |
| crypto-core lint gate + live nginx M-10 test + biometric coverage | mixed | done — `ad7046e` |
| DM partner named on arrival, not after a reload | frontend | done — `6a32bb3` |
| Biometric unlock holds for the session, not just the login | frontend | done |

**Merged to `main` on 2026-09-11** (fast-forward, `b7241f7`..`6a32bb3`), with all
four suites (463 / 163 / 50 / 96), both builds and all five lint/format/drift
gates green at `6a32bb3`. Not pushed — `origin/main` is 8 commits behind.

**L-12 is done, and the scope line matters.** Everything opaque moved to base64;
everything that identifies something stayed hex. Base64 is case-sensitive, and
"addresses are lowercase everywhere" is a project-wide convention that would not
have survived the move — an address is also a primary key, a URL path segment,
and part of the signed login body. `b64_chars()` in `schemas.py` derives every
envelope bound from that, and the two languages' constants are still pinned
against each other.

**`fromB64` refuses non-canonical spellings**, and `is_b64` in
`security/crypto_validation.py` mirrors it. Not tidiness: a message signature
commits to its ciphertext *as a string*, so a second valid spelling of one
ciphertext would be a second valid signature for it.

**Three things this pass found rather than changed:**

- **Biometric unlock was dead.** The crypto-core module split (`26a9319`) left
  `toHex`/`fromHex` behind in `encoding.js` while `webauthn.js` kept calling
  them, so every biometric path threw `ReferenceError` before reaching the
  authenticator. Fixed in `b7241f7`. It survived because the module needs
  `window` so it has no tests, **and crypto-core is the only package with no
  lint gate** — `no-undef` never ran over it. That gap is still open.
- **The login challenge had two copies and no test that could fail.** The server
  built it in `auth.py`; the SPA rebuilt it inline. `conftest` stubs the
  verifier, so a typo in either would have passed all of CI and broken every
  login. Now `crypto-core`'s `loginChallengeBody`, pinned from both languages
  against `tests/fixtures/signed_bodies.json`.
- **Long non-ASCII messages were refused.** `CIPHERTEXT_CHARS` budgeted one byte
  per character, so a full-length CJK or accented message blew
  `MAX_DM_CONTENT_LEN` well under the advertised 10 000 and came back as a bare
  422. The bound now derives from 3 bytes per UTF-16 unit, which is the real
  worst case (an astral character is 4 bytes but *two* units, so cheaper per
  unit, not dearer).

**`conftest` has a real opt-out now** — `@pytest.mark.real_signatures` — and
three tests drive a genuine ML-DSA login through `POST /auth/login`, including
the refusals. The previous escape was re-patching over the fixture with a
hand-rolled copy of the verifier, and `test_key_attestation` shows why that is
not enough: its private copy went on decoding hex after production moved to
base64, passing the whole time, because both halves of the test agreed with each
other. Note the old claim that "no backend test exercises a real login
signature" was overstated — `test_pqc.py` always called `verify_pqc_signature`
directly; what was missing was the endpoint path.

**The dev stack has been wiped and re-seeded** (`docker compose down -v`), and
`backend/.env` now sets a persistent `KRYPTOLOG_JWT_SECRET` and `REDIS_URL`.
Both matter for the recipe: without the secret every restart 401s the browser
mid-pass, and without Redis the WS fan-out and L-7 presence path run in-process
and never get exercised. Verified against the live server: a real ML-DSA login
with a base64 signature returns 200, a forged one 401.

**nginx is checked, not proven.** `nginx -t` runs against an adapted
`nginx.conf.example` inside the `nginx:alpine` container (no host install, no
sudo) and the `/api/` block carries the M-10 upgrade headers. That a
`wss://host/api/ws` handshake really upgrades through a running nginx is still
unverified; `E2E-RECIPE.md` §6 says so explicitly.

**All four packages have a blocking lint gate now.** `packages/crypto-core`
was the only one without one — and without an eslint config at all — which is
precisely how a module calling `toHex`/`fromHex` without importing them shipped.
`no-undef` is the rule that earns its place: removing the import again reports
four errors. Four real findings came out of turning it on (three unused `catch`
bindings and a dead test helper), all fixed.

**M-10 is closed for real, not just syntax-checked.** `nginx.conf.example` is
run in an `nginx:alpine` container against an SPA built with
`VITE_API_BASE_URL=.../api`, and `ws://localhost:8080/api/ws` answers **101
Switching Protocols**. Mutation-tested: deleting the two `proxy_set_header`
lines from the `/api/` block turns that into a **404** — the handshake forwarded
as plain HTTP to a path with no plain-HTTP route, which is the audit's failure
description exactly. `E2E-RECIPE.md` §6 carries the procedure, verified verbatim.
TLS is still only syntax-checked: the test terminates plain HTTP on 8080.

**Biometric unlock has coverage now** —
`frontend/src/test/biometrics.test.js`, eight tests against a mocked PRF
authenticator (jsdom supplies `window`/`navigator`, which is what kept this
module outside both suites). It covers the registration options, the
re-derivation of the key from the stored salt, the password round-trip, the
refusal of a device without hardware PRF, and the hex/base64 split where they
meet. Mutation-tested against both the shipped bug and a plausible L-12 slip
(encoding `prfKey` as base64). The hardware assumption — that a real
authenticator returns a stable PRF output across ceremonies — is still a manual
step, now `E2E-RECIPE.md` §5b.

**And the recipe's §5b immediately found the reason biometrics was no use.**
Reported as "biometric unlock works, but the app asks for the password just
after". The key-cache TTL defaults to **0 — "always ask"** — so nothing is
cached and *every* custody call reaches `PQCContext.requestPassword`, whose job
is to answer it from the authenticator instead of the password box. Three things
stopped that working, and all three had to go:

- **A browser allows ONE outstanding `navigator.credentials.get()`**; an
  overlapping call is rejected with `NotAllowedError`. The app starts custody
  calls in parallel on purpose — `hooks/useSecrets.js` fetches own and shared
  secrets at once and each batch-decrypts its titles — so the loser's biometric
  attempt failed and fell through to the password box. `recoverPasswordWithBiometrics`
  now shares the ceremony **in flight** (the `usePartnerDirectory` pattern):
  concurrent callers await the one ceremony, and the reference is dropped the
  moment it settles, so **the password is still never cached** and the next
  operation re-authenticates. Modelled in the test with the browser's own rule —
  a mock that answers two ceremonies at once passes with or without the fix.
- **Logging in ran two ceremonies for one password.**
  `vaultService.unlockWithBiometrics()` recovered it, unlocked, and threw it
  away; `PQCContext` then recovered it again to sign the login challenge. One
  recovery now does both, and that dead service method is gone.
- **`requestPassword` swallowed the reason.** A bare `catch {}` turned every
  biometric failure into an unexplained password box — which is exactly why the
  report could not be diagnosed from the browser. It logs the cause now.

One more of the same family fell out: the modal holds a **single**
resolve/reject pair, so a second concurrent request overwrote the first's and
left that operation's promise pending forever behind a spinner that never
resolved. `requestPassword` shares its in-flight request too — one prompt
answers every waiting operation, which is correct anyway since there is one
vault password. The test for it fails by **timing out**, which is the hang.

Ten tests in `frontend/src/test/biometricCeremony.test.js` (the ceremony
guard) and `frontend/src/test/biometricUnlock.test.jsx` (the provider). Each of
the four fixes was mutation-tested separately and each kills only its own gate;
turning the in-flight share into a permanent cache fails the two tests that
exist to say the password is not retained.

**The recipe found its first bug before it was finished.** Walking step 2, a DM
from an unknown partner showed the literal **"New Message"** as their name until
a reload — the same string for every unknown partner, so the one thing an
undecryptable message needs to convey, who sent it, was the one thing missing.
Two independent causes: `routers/messenger.py` hand-builds the `NEW_MESSAGE`
frame and carries addresses only, and the server echoes that frame back to the
*sender* for device sync, where it can land while the POST it came from is still
in flight — so `sendMessage` found the placeholder row and spread it over the
full directory object the composer was already holding. **A username is public
directory data, not part of the ciphertext**, so it resolves the moment the frame
lands; `context/messenger/usePartnerDirectory.js` fetches it, cached per address
and shared in flight, and does not cache a failure. The placeholder now carries
no username at all, which restores `displayName`'s short-address fallback — not a
name, but a label that differs between people. Six tests in
`frontend/src/test/partnerNames.test.jsx` drive real frames through the
provider's socket, since the bug was in the ordering between socket and request
rather than in either alone; mutation-tested both ways. **DMs only** — group
names go through the M-3 encrypted-name path, which is a different mechanism.

**Two gotchas worth keeping:**
- `start_all.sh` calls `python3 -m pip` with whatever `python3` is on PATH, so
  **the venv must be active before running it** or it fails at the dependency
  step. `backend/serve.sh` does not have this problem — it resolves the
  interpreter itself, checking `backend/.venv` and the repo-root `../.venv` the
  README documents.
- Build the extension with `npm run build:dev` for the recipe. The production
  build strips `__TRUSTKEYS_ALLOW_DEV_AUTOSIGN__` and prompts on every single
  message signature.

### Still open from the remediation

- **End-to-end recipe not run.** The steps now live in a tracked checklist,
  `E2E-RECIPE.md`, ordered by untested risk and saying what each step proves.
  It needs a running stack and a browser. Do this before any real deployment.
  The stack on the dev box is re-seeded and ready for it (empty database,
  persistent JWT secret, `REDIS_URL` set).
- **The cutovers are cumulative, and there are six of them.** `CRYPTO_CORE_VERSION`
  went 1.3.0 → 2.0.0, and the count is one higher than the version list suggests:
  the HKDF derivation of the AES key from the ML-KEM shared secret (audit S5,
  `KEM_KDF_INFO` in `pqc.js`) was a wire break that landed before `CHANGELOG.md`
  existed, so it carries no version at all. Existing chunk uploads no longer
  decrypt, message signatures no longer verify, unsigned legacy messages no
  longer decrypt, wrapped session keys under the old `ct` name no longer unwrap
  (1.7.0), and everything is base64 rather than hex (2.0.0) — **including the
  vault blob, so existing local vaults and `.kvault` backups no longer open.**
  That last one is key custody, not just wire format. Fine for a pre-production
  system; a decision to re-take explicitly if there is ever real data.
- **Nothing can detect old data.** No version marker is persisted anywhere, and
  neither client reads `CRYPTO_CORE_VERSION` — its only consumer is a test
  assertion. Old rows therefore fail as an opaque `OperationError`, or worse: a
  pre-1.4.0 message renders with an **invalid-signature badge** indistinguishable
  from a forgery, and a failed unwrap leaves a "Click to Decrypt" button that
  never resolves and never says why. If real data ever exists, a wipe is safer
  than a migration, because there is no version to migrate *from*.
- **Mixed-script usernames are grandfathered.** The new rule applies on write;
  existing rows are only NFKC-normalized. Migration `f6a7b8c9d0e5` does **not**
  report mixed-script names — it neither rewrites nor reports them, by design.
  What it does do is **raise and abort the whole migration** on an NFKC
  *collision*, and both start paths refuse to start on a failed migration, so on
  a directory holding colliding names this is a hard deploy stop needing a manual
  `UPDATE` pass, not a warning.

### Known issues, not yet scoped

- **Port 5432 may be held by a native PostgreSQL** that lacks the `kryptolog` role, in
  which case `docker compose up -d postgres` fails to bind. Workaround: run the test
  database on another port and point `TEST_DATABASE_URL` at it.
- **`test_ws_fanout` needs `fakeredis`** (`requirements-dev.txt`). Without it five tests
  error out in a way unrelated to whatever you are changing.
- **Extension tests are slow by design** (~15s): the vault KDF is 600k PBKDF2
  iterations and each `bootWithVault()` pays it. Use `boot()` where a test only needs
  the sender guard, which runs before any vault access.
