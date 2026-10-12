#!/usr/bin/env bash
# The backend for the end-to-end run: the real server, on its own database.
#
# Never the dev database: `kryptolog_e2e` is dropped and recreated on every
# run, so the tests start from an empty directory and leave nothing behind
# that the next run could depend on. Same Postgres and Redis as the dev stack
# (Redis database 7, so presence and rate-limit keys never meet the dev ones),
# a fresh JWT secret, and port 8002.
set -euo pipefail
cd "$(dirname "$0")/../backend"
source ../scripts/load_env.sh
# Optional: CI has no .env, and passes DATABASE_URL and REDIS_URL itself.
[ -f .env ] && kryptolog_load_env .env

E2E_DB=kryptolog_e2e
BASE="${DATABASE_URL/postgresql+psycopg:/postgresql:}"
export ADMIN_URL="${BASE%/*}/postgres"
PG_IMAGE="${KRYPTOLOG_PG_IMAGE:-postgres:16}"
docker run --rm --network host -e ADMIN_URL "$PG_IMAGE" sh -c "
    psql -q -c 'DROP DATABASE IF EXISTS $E2E_DB WITH (FORCE)' \"\$ADMIN_URL\" &&
    psql -q -c 'CREATE DATABASE $E2E_DB' \"\$ADMIN_URL\""

export DATABASE_URL="${DATABASE_URL%/*}/$E2E_DB"
export REDIS_URL="${REDIS_URL%/*}/7"
export KRYPTOLOG_JWT_SECRET="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export ALLOWED_ORIGINS="http://localhost:5174"
export KRYPTOLOG_ENV=development
export KRYPTOLOG_REQUIRE_INVITE=false
unset KRYPTOLOG_MESSAGE_RETENTION_DAYS

PY=python3
for candidate in .venv/bin/python3 ../.venv/bin/python3; do
    if [ -x "$candidate" ]; then PY="$candidate"; break; fi
done
# Database 7 holds this run's rate-limit counters and presence. A run started
# within a minute of the last one would otherwise inherit its login count and
# hit the 5/minute limit — found as a flake on back-to-back runs.
"$PY" -c 'import os, redis; redis.Redis.from_url(os.environ["REDIS_URL"]).flushdb()'
../scripts/build_liboqs.sh --check
"$PY" -m alembic upgrade head
exec "$PY" -m uvicorn main:app --host 127.0.0.1 --port 8002 --no-server-header
