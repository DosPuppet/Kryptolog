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
| `packages/crypto-core/` | `@kryptolog/crypto-core`: one copy of every crypto primitive, consumed by **both** clients via a `file:` dependency. |

`crypto-core` exists so the SPA and the extension can never drift apart on wire format.
Byte-for-byte compatibility is enforced by golden vectors in CI, not by a "keep in sync"
comment. Change a primitive there and you change both clients at once.

## Commands

These mirror `.github/workflows/ci.yml` — if you change one, change it there too.

```bash
# backend — needs the docker-compose Postgres running
cd backend && pytest

# crypto-core
cd packages/crypto-core && npm test

# frontend
cd frontend && npx vitest run
cd frontend && npx vite build
cd frontend && npx eslint .        # blocking gate — lint is clean, keep it clean

# extension
cd trustkeys && npm run build
cd trustkeys && npm run lint       # advisory: 26 known errors, not yet a gate

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
  and `packages/crypto-core/src/index.js` for the standard.
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
| 4 | Bind chunk index into AEAD associated data | crypto-core | todo |
| 5 | Move Alembic migrations off the import path | backend | done — `93f2aa9` |
| 6 | Extend signed message body to cover the key envelope | crypto-core | todo |
| 7 | Rate limits on 16 unprotected endpoints | backend | done — `93f2aa9` |
| 8 | Extension: auto-lock, sender gating, request bounds | trustkeys | todo |
| 9 | Username normalization, nginx WebSocket, point fixes | mixed | todo |
| 10 | Extension test suite (new vitest harness) | trustkeys | todo |

Suggested order: WP2/3/5/7 (backend, independent) → WP1 → WP4+WP6 (one commit, single
wire-format boundary) → WP8+WP10 → WP9.

Record the commit SHA in the status column as each lands.

### Known issues, not yet scoped

- **Schema drift on `users.username`.** `alembic check` reports a pending
  `remove_index` / `add_constraint` pair: the model keeps `unique=True` on the column
  while migration `d4e5f6a7b8c3` replaced that plain index with a functional `lower()`
  one, so autogenerate keeps wanting to re-add it. Harmless today, but it means
  `alembic check` cannot be used as a drift gate until it is resolved. Fold into WP9,
  which touches username normalization anyway.
- **Port 5432 may be held by a native PostgreSQL** that lacks the `kryptolog` role, in
  which case `docker compose up -d postgres` fails to bind. Workaround: run the test
  database on another port and point `TEST_DATABASE_URL` at it.
- **`test_ws_fanout` needs `fakeredis`** (`requirements-dev.txt`). Without it five tests
  error out in a way unrelated to whatever you are changing.
