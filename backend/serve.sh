#!/bin/bash
# Production entry point: migrate, then serve. This is what PM2 runs.
#
# Closes the gap commit 98c5f87 documented rather than fixed (audit §8 item 4).
# start_all.sh applies `alembic upgrade head` before `pm2 start`, so the normal
# path was covered — but a bare `pm2 restart kryptolog-backend` after a
# `git pull` skipped it and served new code against an old schema. PM2 restarts
# on its own too (crash, max_memory_restart, `pm2 resurrect` at boot), none of
# which go anywhere near start_all.sh.
#
# The env is loaded HERE rather than inherited, for the same reason: `pm2
# restart` replays the environment it captured when the process was first
# started, so a value added to .env afterwards would never arrive.

set -euo pipefail

cd "$(dirname "$0")"

# Parsed as data, never executed (audit L-14).
if ! source ../scripts/load_env.sh; then
    echo "ERROR: scripts/load_env.sh is missing — refusing to start rather than"
    echo "  running with a silently unloaded environment."
    exit 1
fi
if [ -f .env ]; then
    kryptolog_load_env .env
fi

# Prefer the project venv over whatever `python3` the environment happens to
# offer. PM2 does not restart from a shell with the venv activated — a boot-time
# `pm2 resurrect` has no activation at all — so resolving this from PATH would
# migrate with one interpreter and serve with another, or simply not find
# alembic. start_all.sh activates a venv before it runs, which is why it gets
# away with plain `python3`.
PY=python3
if [ -x .venv/bin/python3 ]; then
    PY=.venv/bin/python3
fi

# Migrations are a deliberate deployment step, not an import-time side effect
# (audit M-3) — and a hard gate: serving new code against an old schema is the
# failure this script exists to prevent, so a failure here must not degrade
# into "start anyway".
echo "Applying database migrations..."
if ! "$PY" -m alembic upgrade head; then
    echo "ERROR: database migration failed — refusing to start."
    exit 1
fi

# exec, so uvicorn REPLACES this shell: PM2 then supervises and signals the
# server directly instead of a wrapper that would swallow SIGTERM and turn
# every restart into a kill after the graceful-stop timeout.
echo "Starting FastAPI backend..."
exec "$PY" -m uvicorn main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --h11-max-incomplete-event-size 65536
