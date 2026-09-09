#!/bin/bash
# Run FastAPI backend with hot-reload

# Ensure we are in the script's directory (backend). This has to happen BEFORE
# the .env load below, which looks for a relative ./.env — run from the repo
# root, the old ordering silently found no file and loaded nothing.
cd "$(dirname "$0")"

# Set allow origins for development (Vite default + Self)
export ALLOWED_ORIGINS="http://localhost:5173,http://127.0.0.1:5173"

# Parsed as data, never executed (audit L-14) — same defect and same fix as
# start_all.sh; see scripts/load_env.sh for what `source .env` allowed through.
if ! source ../scripts/load_env.sh; then
    echo "ERROR: scripts/load_env.sh is missing — refusing to start rather than"
    echo "  running with a silently unloaded environment."
    exit 1
fi
if [ -f .env ]; then
  kryptolog_load_env .env
fi

# JWTs are HS256-signed (PyJWT). For a persistent dev secret, run
# `python generate_server_keys.py` and set KRYPTOLOG_JWT_SECRET in .env.
# (liboqs/ML-DSA-44 is still used in-process to verify client login challenges.)
if [ -z "$KRYPTOLOG_JWT_SECRET" ]; then
    echo "WARNING: KRYPTOLOG_JWT_SECRET not set — using an ephemeral JWT secret (tokens reset on restart)."
fi

# Apply migrations before serving. The app no longer migrates at import time
# (audit M-3), so this has to be explicit — and fail hard rather than starting
# against a schema that doesn't match the models.
echo "Applying database migrations..."
if ! python3 -m alembic upgrade head; then
    echo "ERROR: database migration failed — refusing to start."
    exit 1
fi

# Start FastAPI Backend
echo "Starting FastAPI Backend..."
uvicorn main:app --reload --port 8000 --h11-max-incomplete-event-size 65536
