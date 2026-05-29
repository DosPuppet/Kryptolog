#!/bin/bash
# Run FastAPI backend with hot-reload, excluding SQLite journal files to prevent crashes

# Default secret key for development if not set
if [ -z "$SAFELOG_SECRET_KEY" ]; then
    echo "WARNING: SAFELOG_SECRET_KEY not set. Using dev default."
    export SAFELOG_SECRET_KEY="dev_secret_key_change_me"
fi

if [ -z "$PQC_SHARED_SECRET" ]; then
    echo "WARNING: PQC_SHARED_SECRET not set. Using dev default."
    export PQC_SHARED_SECRET="dev_pqc_secret_change_me"
fi

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

# Check for Node.js dependencies
if [ ! -d "node_modules" ]; then
    echo "Installing Node.js dependencies for PQC service..."
    npm install
fi

# Check if PQC service is already running (e.g. via PM2) on port 3000
if lsof -Pi :3000 -sTCP:LISTEN -t >/dev/null ; then
    echo "PQC Sidecar Service is already running on port 3000 (likely via PM2)."
else
    # Start PQC Sidecar Service
    echo "Starting PQC Sidecar Service..."
    node pqc_service.js &
    PQC_PID=$!

    # Function to kill PQC service on exit
    cleanup() {
        echo "Stopping PQC Service (PID: $PQC_PID)..."
        kill $PQC_PID
    }
    trap cleanup EXIT

    # Wait a moment for PQC service to start
    sleep 2
fi

# Start FastAPI Backend (Increase HTTP Header Size for large Dilithium JWTs)
echo "Starting FastAPI Backend..."
uvicorn main:app --reload --reload-exclude "*.db" --reload-exclude "*.db-journal" --port 8000 --h11-max-incomplete-event-size 65536
