#!/usr/bin/env bash
# Create backend/.env from backend/.env.example with freshly generated secrets.
#
# The example ships no usable credential (audit 2026-10-12 K-01): every
# __GENERATE__ becomes a random value, and __POSTGRES_PASSWORD__ /
# __REDIS_PASSWORD__ inside the URLs are filled with the same values the compose
# services get, so the file is consistent by construction.
#
# Never overwrites an existing backend/.env. For one that predates this script
# and lacks the compose passwords, it says what to add and fails, rather than
# generating a password the existing Postgres volume would not know.
#
# Usage: scripts/init_env.sh            (from anywhere)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/backend/.env"
EXAMPLE="$ROOT/backend/.env.example"

if [ -f "$ENV_FILE" ]; then
    missing=()
    for key in POSTGRES_PASSWORD REDIS_PASSWORD; do
        grep -qE "^(export )?$key=.+" "$ENV_FILE" || missing+=("$key")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "ERROR: backend/.env lacks ${missing[*]}." >&2
        echo "  docker-compose.yml no longer has default passwords (audit 2026-10-12 K-01)." >&2
        echo "  Add them, with DATABASE_URL / TEST_DATABASE_URL / REDIS_URL carrying the same" >&2
        echo "  values, and rotate the existing Postgres role — see DEPLOYMENT.md." >&2
        exit 1
    fi
    exit 0
fi

python3 - "$EXAMPLE" "$ENV_FILE" <<'PY'
import os, secrets, sys

src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
pg = secrets.token_urlsafe(24)
rd = secrets.token_urlsafe(24)
lines = []
for line in text.splitlines():
    if line.startswith("POSTGRES_PASSWORD="):
        line = f"POSTGRES_PASSWORD={pg}"
    elif line.startswith("REDIS_PASSWORD="):
        line = f"REDIS_PASSWORD={rd}"
    elif line.startswith("KRYPTOLOG_JWT_SECRET="):
        line = f"KRYPTOLOG_JWT_SECRET={secrets.token_hex(32)}"
    elif line.startswith("KRYPTOLOG_DEPLOYMENT_ID="):
        line = f"KRYPTOLOG_DEPLOYMENT_ID={secrets.token_urlsafe(12)}"
    line = line.replace("__POSTGRES_PASSWORD__", pg).replace("__REDIS_PASSWORD__", rd)
    if "__GENERATE__" in line and not line.lstrip().startswith("#"):
        raise SystemExit(f"unfilled placeholder in {src}: {line}")
    lines.append(line)

fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
PY

echo "Created backend/.env with generated secrets (mode 600)."
echo "  Signup is invite-only: mint a code with  cd backend && python generate_invites.py"
