#!/usr/bin/env bash
# Restore a scripts/backup.sh dump (audit 2026-09-11 M-6).
#
#   scripts/restore.sh --verify DUMP     rehearsal: restore into a scratch
#                                        database, check it, drop it. Touches
#                                        nothing else. Run this regularly.
#   scripts/restore.sh DUMP DBNAME       restore into DBNAME, which must not
#                                        exist yet. Point DATABASE_URL at it
#                                        afterwards, then start the backend:
#                                        both start paths migrate before
#                                        serving, so an older dump is brought
#                                        up to the code's schema.
#
# Never restores over a live database. Replacing one is a decision for an
# operator with the service stopped: restore beside it, switch DATABASE_URL,
# keep the old one until the new one is proven.
#
# The check: every table the current models define exists, alembic_version
# names a revision this repository knows, and the row counts are printed so
# they can be compared with the source.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/load_env.sh
source scripts/load_env.sh
[ -f backend/.env ] && kryptolog_load_env backend/.env

: "${DATABASE_URL:?DATABASE_URL is not set (backend/.env or the environment)}"
BASE_URL="${DATABASE_URL/postgresql+psycopg:/postgresql:}"
PG_IMAGE="${KRYPTOLOG_PG_IMAGE:-postgres:16}"

verify=0
if [ "${1:-}" = "--verify" ]; then
    verify=1
    shift
fi
DUMP="${1:?usage: restore.sh [--verify] DUMP [DBNAME]}"
[ -f "$DUMP" ] || { echo "ERROR: no such dump: $DUMP" >&2; exit 1; }
if [ $verify = 1 ]; then
    DB="kryptolog_restore_check_$(date -u +%s)"
else
    DB="${2:?usage: restore.sh DUMP DBNAME (the database must not exist yet)}"
fi
[[ "$DB" =~ ^[a-z_][a-z0-9_]{0,62}$ ]] || { echo "ERROR: invalid database name: $DB" >&2; exit 1; }

# The same server, another database: replace the path of the URL.
export ADMIN_URL="${BASE_URL%/*}/postgres"
export TARGET_URL="${BASE_URL%/*}/$DB"
export DB

pg() { docker run --rm -i --network host -e ADMIN_URL -e TARGET_URL -e DB "$PG_IMAGE" sh -c "$1"; }

if [ "$(pg 'psql -tAc "SELECT 1 FROM pg_database WHERE datname = '"'"'$DB'"'"'" "$ADMIN_URL"')" = "1" ]; then
    echo "ERROR: database $DB already exists; restore.sh never restores over one" >&2
    exit 1
fi

cleanup() { [ $verify = 1 ] && pg 'psql -qc "DROP DATABASE IF EXISTS \"$DB\"" "$ADMIN_URL"' || true; }
trap cleanup EXIT

pg 'psql -qc "CREATE DATABASE \"$DB\"" "$ADMIN_URL"'
pg 'pg_restore --no-owner --no-privileges --exit-on-error --dbname "$TARGET_URL"' < "$DUMP"

revision="$(pg 'psql -tAc "SELECT version_num FROM alembic_version" "$TARGET_URL"')"
if ! grep -rqs "^revision: str = \"$revision\"" backend/alembic/versions/; then
    echo "ERROR: restored schema is at revision '$revision', unknown to this checkout" >&2
    exit 1
fi

# The tables the CODE expects, read from the models rather than listed here,
# so this check moves with the schema.
PY="${KRYPTOLOG_PYTHON:-$PWD/backend/.venv/bin/python}"
[ -x "$PY" ] || PY=python3
tables="$(cd backend && "$PY" -c 'import models; print(" ".join(sorted(models.Base.metadata.tables)))')"
echo "Restored $DUMP into $DB (schema revision $revision). Rows per table:"
for table in $tables; do
    count="$(pg "psql -tAc 'SELECT count(*) FROM $table' \"\$TARGET_URL\"")" || {
        echo "ERROR: table $table is missing from the restore" >&2
        exit 1
    }
    printf '  %-32s %s\n' "$table" "$count"
done

if [ $verify = 1 ]; then
    echo "Verified. The scratch database $DB is dropped on exit."
else
    trap - EXIT
    echo "Done. Point DATABASE_URL at $DB and start the backend; it migrates before serving."
fi
