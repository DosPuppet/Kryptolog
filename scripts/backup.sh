#!/usr/bin/env bash
# Back up the Kryptolog database (audit 2026-09-11 M-6: no backup procedure
# existed, documented or otherwise).
#
#   scripts/backup.sh [OUT_DIR]          default OUT_DIR: ./backups
#
# Writes OUT_DIR/kryptolog-<UTC timestamp>.dump (pg_dump custom format, mode
# 600) and checks that pg_restore can read its table of contents back — a dump
# that cannot be listed is not a backup. Restore with scripts/restore.sh, and
# rehearse it: `scripts/restore.sh --verify <dump>` restores into a scratch
# database and checks the result without touching the live one.
#
# What is in it, and what is not — see DEPLOYMENT.md, "Backup and restore":
# every row the server holds, all of it ciphertext or public metadata. NOT the
# users' private keys, which never reach the server, and NOT backend/.env
# (JWT secret, deployment id, VAPID keys, service passwords): back that up
# separately, through whatever holds the deployment's other secrets.
#
# pg_dump runs from the postgres:16 image — the server's major version, so no
# client/server mismatch and nothing to install — with host networking, so
# DATABASE_URL means what it means to the backend. The URL (and its password)
# reaches the container through the environment, never the command line, where
# any local user could read it in the process list.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/load_env.sh
source scripts/load_env.sh
[ -f backend/.env ] && kryptolog_load_env backend/.env

: "${DATABASE_URL:?DATABASE_URL is not set (backend/.env or the environment)}"
# SQLAlchemy's driver suffix means nothing to libpq.
export PG_URL="${DATABASE_URL/postgresql+psycopg:/postgresql:}"
PG_IMAGE="${KRYPTOLOG_PG_IMAGE:-postgres:16}"

OUT_DIR="${1:-backups}"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"
OUT="$OUT_DIR/kryptolog-$(date -u +%Y%m%dT%H%M%SZ).dump"

umask 077
docker run --rm --network host -e PG_URL "$PG_IMAGE" \
    sh -c 'pg_dump --format=custom --no-owner --no-privileges "$PG_URL"' > "$OUT"

# A dump that pg_restore cannot list is not a backup; find out now, not on
# the day it is needed.
if ! docker run --rm -i "$PG_IMAGE" pg_restore --list < "$OUT" > /dev/null; then
    echo "ERROR: $OUT was written but pg_restore cannot read it" >&2
    exit 1
fi

echo "Backup written: $OUT ($(du -h "$OUT" | cut -f1))"
