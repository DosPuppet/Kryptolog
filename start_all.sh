#!/bin/bash
# Unified startup script for Kryptolog using PM2

# Ensure we are in the project root
cd "$(dirname "$0")"

echo "=== Kryptolog Ecosystem Startup ==="

# 1. Check for PM2
if ! command -v pm2 &> /dev/null; then
    echo "PM2 is not installed. Installing globally via npm..."
    npm install -g pm2
fi

# 2. Setup Environment Variables
# Load from .env if it exists
if [ -f backend/.env ]; then
  echo "Loading variables from backend/.env"
  set -a
  source backend/.env
  set +a
fi

# Apply Development Defaults if not set
export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:5173,http://127.0.0.1:5173}"

# JWTs are HS256-signed (PyJWT). For a persistent secret, run
# `python backend/generate_server_keys.py` and set KRYPTOLOG_JWT_SECRET (in
# backend/.env or the environment); otherwise an ephemeral secret is used.
# (liboqs/ML-DSA-44 is still used in-process to verify client login challenges.)
if [ -z "$KRYPTOLOG_JWT_SECRET" ]; then
    echo "WARNING: KRYPTOLOG_JWT_SECRET not set — backend will use an ephemeral JWT secret."
fi

echo "Environment initialized."

# 3. Ensure PostgreSQL is up (migrations run as an explicit step below)
# Default DATABASE_URL targets the docker-compose Postgres on localhost:5432.
# Redis (shared rate limits + WS fan-out, optional) is started alongside it.
DB_URL="${DATABASE_URL:-postgresql+psycopg://kryptolog:kryptolog@localhost:5432/kryptolog}"
if [[ "$DB_URL" != *"localhost"* && "$DB_URL" != *"127.0.0.1"* ]]; then
    echo "DATABASE_URL points at an external database — skipping local Postgres startup."
elif command -v docker &> /dev/null; then
    echo "Starting PostgreSQL + Redis (docker compose)..."
    docker compose up -d postgres redis
    echo -n "Waiting for Postgres to be healthy"
    PG_STATUS=""
    for _ in $(seq 1 30); do
        PG_STATUS=$(docker inspect --format '{{.State.Health.Status}}' "$(docker compose ps -q postgres)" 2>/dev/null)
        [ "$PG_STATUS" = "healthy" ] && break
        echo -n "."
        sleep 1
    done
    echo
    if [ "$PG_STATUS" != "healthy" ]; then
        echo "WARNING: Postgres is not healthy yet — the migration step below may fail. Check: docker compose logs postgres"
    fi
else
    echo "WARNING: docker not found — assuming Postgres is already running at $DB_URL"
fi

# 4. Ensure backend Python dependencies (idempotent: pip skips what's already
# satisfied, so liboqs is only compiled on first run or version bumps).
# --user is invalid inside a virtualenv, where installs go to the venv itself.
echo "Checking backend dependencies..."
PIP_USER_FLAG="--user"
if python3 -c 'import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)'; then
    PIP_USER_FLAG=""
fi
if ! python3 -m pip install $PIP_USER_FLAG -q -r backend/requirements.txt; then
    echo "ERROR: failed to install backend Python dependencies (backend/requirements.txt)."
    exit 1
fi

# 5. Apply database migrations — explicitly, and fail hard.
# This used to run at backend import time behind a bare except that fell back to
# create_all + stamp head, which silently stamped a partially-migrated schema as
# current (audit M-3). Refusing to start is the correct outcome: a drifted schema
# stamped "up to date" cannot be repaired by a later upgrade.
echo "Applying database migrations..."
if ! (cd backend && python3 -m alembic upgrade head); then
    echo "ERROR: database migration failed — refusing to start."
    echo "  Check the schema state with: cd backend && python3 -m alembic current"
    exit 1
fi

# 6. Ensure frontend dependencies and build exist (required for preview)
echo "Checking frontend..."
cd frontend
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi
if [ ! -d "dist" ]; then
    echo "Building frontend for preview..."
    npm run build
fi
cd ..

# 7. Start / Restart PM2 Ecosystem
echo "Starting ecosystem..."
# By passing `--update-env`, PM2 absorbs the newly exported bash variables into the processes
pm2 start ecosystem.config.cjs --update-env

echo "=== Startup Complete ==="
echo "View logs with: pm2 logs"
echo "Monitor with: pm2 monit"
