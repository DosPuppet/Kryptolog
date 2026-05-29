#!/bin/bash
# Unified startup script for Safelog using PM2

# Ensure we are in the project root
cd "$(dirname "$0")"

echo "=== Safelog Ecosystem Startup ==="

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
export SAFELOG_SECRET_KEY="${SAFELOG_SECRET_KEY:-dev_secret_key_change_me}"
export PQC_SHARED_SECRET="${PQC_SHARED_SECRET:-dev_pqc_secret_change_me}"
export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-http://localhost:5173,http://127.0.0.1:5173}"

echo "Environment initialized."

# 3. Ensure frontend dependencies and build exist (required for preview)
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

# 4. Ensure backend/PQC dependencies exist
echo "Checking PQC service..."
cd backend
if [ ! -d "node_modules" ]; then
    echo "Installing backend Node.js dependencies..."
    npm install
fi
cd ..

# 5. Start / Restart PM2 Ecosystem
echo "Starting ecosystem..."
# By passing `--update-env`, PM2 absorbs the newly exported bash variables into the processes
pm2 start ecosystem.config.cjs --update-env

echo "=== Startup Complete ==="
echo "View logs with: pm2 logs"
echo "Monitor with: pm2 monit"
