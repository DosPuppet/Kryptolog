# Roadmap: Migrate backend from SQLite to PostgreSQL

> Status: **planned** (not started). Design of record for the SQLite → Postgres
> cutover. See also the shared crypto/PQC context in `CLAUDE.md`.

## Context

The backend runs on a single-file SQLite DB (`backend/sql_app.db`), hardcoded in
[database.py:4](../backend/database.py#L4). SQLite is fine for a single-process
dev box but blocks real deployment: no concurrent writers, no network access,
weak concurrency for the messenger/multisig write paths. This migrates the app
to **PostgreSQL** while keeping the SQLAlchemy/Alembic layer intact.

The schema is already portable. All columns use generic types
(`Integer, String, Text, Boolean, DateTime` — no JSON/BLOB/SQLite funcs),
datetimes are stored as **naive UTC** (see `invites._utcnow()`,
[invites.py:17](../backend/invites.py#L17)) which maps cleanly to Postgres
`TIMESTAMP WITHOUT TIME ZONE`, and the one ordering assumption
([groups.py:116](../backend/routers/groups.py#L116), `max(id)` per channel) holds
under Postgres identity columns. So this is a **configuration + infrastructure**
change, not a schema rewrite. Existing Alembic migrations already use
`op.batch_alter_table`, which executes plain `ALTER`s on Postgres — no rewrite
of migration files needed.

Decisions locked:
- **Fresh schema, no data migration** — create the schema on an empty Postgres
  via `alembic upgrade head` (matches the project's clean-cutover stance).
- **Postgres everywhere for tests** — the test harness runs against a real
  Postgres, not in-memory SQLite.
- **Local Postgres via both** — provide a `docker-compose.yml` service *and*
  support pointing `DATABASE_URL` at an external instance.

## Driver + dependencies

- [backend/requirements.txt](../backend/requirements.txt): add
  `psycopg[binary]>=3.2` (psycopg 3; SQLAlchemy 2.0 URL scheme
  `postgresql+psycopg://`). Binary wheel avoids a local libpq/compiler.

## Single source of truth for the DB URL

- [backend/database.py](../backend/database.py): read the URL from env with a
  local-Postgres default, and only pass the SQLite-only `check_same_thread`
  arg when the URL is SQLite:
  ```python
  SQLALCHEMY_DATABASE_URL = os.getenv(
      "DATABASE_URL",
      "postgresql+psycopg://kryptolog:kryptolog@localhost:5432/kryptolog",
  )
  connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}
  engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
  ```
  (`pool_pre_ping` handles dropped Postgres connections gracefully.) Keeping the
  SQLite branch means a `DATABASE_URL=sqlite:///...` still works for anyone who
  wants it, but the default is Postgres.

- [backend/alembic/env.py](../backend/alembic/env.py): stop relying on the
  hardcoded `sqlalchemy.url` in `alembic.ini`. Import the app's URL and inject
  it, and make batch mode SQLite-only so Postgres gets plain DDL:
  ```python
  from database import SQLALCHEMY_DATABASE_URL
  config.set_main_option("sqlalchemy.url", SQLALCHEMY_DATABASE_URL)
  is_sqlite = SQLALCHEMY_DATABASE_URL.startswith("sqlite")
  # pass render_as_batch=is_sqlite in BOTH context.configure() calls (L36, L60)
  ```
  This guarantees the app engine and Alembic (including the **startup**
  `command.upgrade(alembic_cfg, "head")` in [main.py:57-68](../backend/main.py#L57-L68))
  always target the same database.
- [backend/alembic.ini](../backend/alembic.ini): the `sqlalchemy.url` line
  (L89) becomes a harmless placeholder (env.py overrides it); leave a comment
  noting `DATABASE_URL` wins.

## Test harness → Postgres

- [backend/tests/conftest.py](../backend/tests/conftest.py): replace the
  in-memory SQLite engine (the `create_engine("sqlite://", …, StaticPool)` block,
  L36-40) with a Postgres engine from `TEST_DATABASE_URL` (default
  `postgresql+psycopg://kryptolog:kryptolog@localhost:5432/kryptolog_test`);
  drop the `StaticPool`/`check_same_thread` imports. The existing autouse
  `_setup_db` fixture ([conftest.py:94-99](../backend/tests/conftest.py#L94-L99))
  already does `create_all`/`drop_all` per test — that pattern works unchanged on
  Postgres (slower than SQLite but correct and fully isolated). Keep it as-is for
  minimal change; if per-test create/drop proves too slow, switch to a
  session-scoped `create_all` + per-test transaction rollback later.

## Local dev + deployment

- **New `docker-compose.yml`** (repo root): a `postgres:16` service exposing
  5432, with `POSTGRES_USER/PASSWORD/DB=kryptolog` and a named volume, matching
  the default `DATABASE_URL`. Document a one-liner to also create the
  `kryptolog_test` database (init script or `createdb`).
- [backend/.env.example](../backend/.env.example): document `DATABASE_URL` (and
  `TEST_DATABASE_URL`) with the compose defaults and an external-instance
  example.
- [backend/run_dev.sh](../backend/run_dev.sh): the SQLite-journal reload-exclude
  is now dead; trim it (cosmetic, low priority).

## CI

- [.github/workflows/ci.yml](../.github/workflows/ci.yml) **backend job**
  (L21-41): add a `services: postgres:16` container with a health check, set
  `DATABASE_URL`/`TEST_DATABASE_URL` env for the step, create the test DB, and
  run `alembic upgrade head` before `pytest` so the migration chain is validated
  against real Postgres on every push.

## Portability risk to verify (important)

`users.address` is the ML-DSA-44 public-key hex and is the **primary key**
(auto-indexed) plus an indexed FK on hot tables
([models.py:121-122](../backend/models.py#L121-L122), messages sender/recipient).
An ML-DSA-44 public key is 1312 bytes → **~2624 hex chars**, close to Postgres's
**2704-byte btree index-tuple limit**. It should fit, but it's fragile. The
verification step below explicitly checks this. If a future/edge key pushes an
index over the limit, the mitigation is to index a fixed-length digest instead
of the raw value (e.g. a `md5(address)`/`sha256` functional or generated-column
index) rather than widening the schema — call it out but don't pre-build it.

## Verification

1. **Provision:** `docker compose up -d postgres`, then create the test DB
   (`createdb kryptolog_test` or compose init).
2. **Migrations on real Postgres:** `cd backend && DATABASE_URL=postgresql+psycopg://kryptolog:kryptolog@localhost:5432/kryptolog alembic upgrade head`
   → confirm all tables create with **no** btree-index-size error (this is the
   `users.address` check), then `alembic downgrade base` and back up to prove the
   chain is reversible on Postgres.
3. **Full suite against Postgres:** `cd backend && python -m pytest -q` with
   `TEST_DATABASE_URL` set → expect the current **162 passed** with zero
   dialect/isolation regressions.
4. **App boot:** run the backend against the compose Postgres; confirm the
   startup `alembic upgrade head` path in [main.py](../backend/main.py#L57) runs
   clean (no `create_all` fallback warning), then exercise login + create a
   multisig workflow end-to-end.
5. **CI:** push and confirm the backend job goes green with the Postgres service.
