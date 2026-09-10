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
  *deliberately*; never let a vector auto-update, that defeats their purpose.
- **Security rules belong in `backend/security/`,** not inline in routers. Inline
  re-implementation is what produced KRY-001.
- **Addresses are lowercase everywhere** in the database and in signed bodies. Normalize
  at the boundary.
- Rate-limited endpoints need `request: Request` as the first parameter (slowapi).

## Untracked files

Two things are deliberately **not** in git, so a fresh clone will be missing them:

- `AUDIT.md` — the full security audit (2026-09-01, French).
- `roadmap/` — remediation plans with file/line detail.

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
`0125365`..`1be4b36`). Not pushed — `origin/main` is 8 commits behind.

## Code-quality pass — 2026-09-10

Branch `cleanup-2026-09` (`b8f444a`..`d9c3270`, 37 commits). Not a remediation:
this was a review for simplification, shorter modules and comment quality. Every
commit leaves all four packages green, so the history can be bisected or stopped
at any point.

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

### Still open from before, unchanged

Everything under "Still open from the remediation" below still applies. The
end-to-end manual recipe has **not** been run, and it now matters more: `login`,
`sign_multisig_workflow` and the WebSocket handshake were all split, and
`conftest.py` patches both signature verifiers to `True` as `autouse`, so no
backend test exercises a real login or approval signature.

### Still open from the remediation

- **End-to-end recipe not run.** Everything is covered by automated tests except the
  manual pass, which needs a running stack and a browser: two accounts exchanging DMs;
  the WebSocket connecting through the corrected nginx `/api/` block; a multi-chunk
  file round-tripping to confirm the AAD binding; locking/unlocking the extension to
  confirm the idle alarm fires. Do this before any real deployment.
- **Four cutover breaks are cumulative.** `CRYPTO_CORE_VERSION` went 1.3.0 → 1.7.0.
  Existing chunk uploads no longer decrypt, existing message signatures no longer
  verify, unsigned legacy messages no longer decrypt at all, and (1.7.0) wrapped
  session keys stored under the old `ct` field name no longer unwrap. Fine for a
  pre-production system; a decision if there is real data.
- **Mixed-script usernames are grandfathered.** The new rule applies on write; existing
  rows are only NFKC-normalized. Migration `f6a7b8c9d0e5` reports collisions but
  deliberately does not rename anyone. If the directory already holds such names, that
  needs an operator pass.
- **`conftest.py` patches `auth.verify_message_signature` to `True` as `autouse`,** so
  no backend test exercises a real login signature. Flipping it to opt-out was scoped
  as a follow-up with its own blast radius, and was not done.

### Known issues, not yet scoped

- **Port 5432 may be held by a native PostgreSQL** that lacks the `kryptolog` role, in
  which case `docker compose up -d postgres` fails to bind. Workaround: run the test
  database on another port and point `TEST_DATABASE_URL` at it.
- **`test_ws_fanout` needs `fakeredis`** (`requirements-dev.txt`). Without it five tests
  error out in a way unrelated to whatever you are changing.
- **Extension tests are slow by design** (~15s): the vault KDF is 600k PBKDF2
  iterations and each `bootWithVault()` pays it. Use `boot()` where a test only needs
  the sender guard, which runs before any vault access.
