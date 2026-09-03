#!/bin/bash
# Run FastAPI backend with hot-reload

# Set allow origins for development (Vite default + Self)
export ALLOWED_ORIGINS="http://localhost:5173,http://127.0.0.1:5173"

# Load environment variables from .env
if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

# Ensure we are in the script's directory (backend)
cd "$(dirname "$0")"

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
