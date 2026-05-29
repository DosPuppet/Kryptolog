#!/bin/bash
# Run FastAPI backend with hot-reload, excluding SQLite journal files to prevent crashes

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

# ML-DSA-44 signing runs in-process via liboqs (no sidecar). For a persistent
# dev key, run `python generate_server_keys.py` and set SAFELOG_ML_DSA_* in .env.
if [ -z "$SAFELOG_ML_DSA_SECRET_KEY" ]; then
    echo "WARNING: SAFELOG_ML_DSA_SECRET_KEY not set — using an ephemeral server key (JWTs reset on restart)."
fi

# Start FastAPI Backend (Increase HTTP Header Size for large ML-DSA JWTs)
echo "Starting FastAPI Backend..."
uvicorn main:app --reload --reload-exclude "*.db" --reload-exclude "*.db-journal" --port 8000 --h11-max-incomplete-event-size 65536
