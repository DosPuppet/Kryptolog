#!/usr/bin/env bash
# Create backend/.env from backend/.env.example with freshly generated secrets,
# and frontend/.env with the values the SPA must share with it.
#
# The example ships no usable credential (audit 2026-10-12 K-01): every
# __GENERATE__ becomes a random value, and __POSTGRES_PASSWORD__ /
# __REDIS_PASSWORD__ inside the URLs are filled with the same values the compose
# services get, so the file is consistent by construction.
#
# The VAPID pair is generated here too, and its public half written into
# frontend/.env as VITE_VAPID_PUBLIC_KEY. It is one value under two names in two
# files, and copying it by hand is where a real install went wrong
# (2026-10-15): a mismatch is not an error anywhere, push just never arrives.
#
# Never overwrites a value that is set. For a backend/.env that predates this
# script and lacks the compose passwords, it says what to add and fails, rather
# than generating a password the existing Postgres volume would not know. And
# when it does generate one next to an EXISTING volume, it says so and stops:
# Postgres applies POSTGRES_PASSWORD only when a volume is first created, so
# that combination otherwise fails much later, as an authentication error in
# the middle of `alembic upgrade`.
#
# Usage (from anywhere):
#   scripts/init_env.sh                 create what is missing (first run)
#   scripts/init_env.sh --vapid         generate the VAPID pair for an existing
#                                       backend/.env whose pair is empty
#   scripts/init_env.sh --adopt-volume  keep an existing Postgres volume: set its
#                                       role's password to backend/.env's

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="$ROOT/backend/.env"
EXAMPLE="$ROOT/backend/.env.example"
FRONT_ENV="$ROOT/frontend/.env"
FRONT_EXAMPLE="$ROOT/frontend/.env.example"

# A Python that has `cryptography`, for the VAPID pair: the project venvs
# first, since a fresh host's system python3 often lacks it.
crypto_python() {
    local py
    for py in "$ROOT/.venv/bin/python3" "$ROOT/backend/.venv/bin/python3" python3; do
        if command -v "$py" >/dev/null 2>&1 &&
            "$py" -c 'import cryptography.hazmat.primitives.asymmetric.ec' 2>/dev/null; then
            echo "$py"
            return 0
        fi
    done
    return 1
}

# env_value FILE KEY — the value, unquoted; empty when unset or absent.
env_value() {
    python3 - "$1" "$2" <<'PY'
import re, sys
path, key = sys.argv[1], sys.argv[2]
for line in open(path, encoding="utf-8"):
    m = re.match(rf"\s*(?:export\s+)?{re.escape(key)}=(.*)$", line)
    if m:
        print(m.group(1).strip().strip("'\""))
        break
PY
}

# fill_value FILE KEY VALUE — set KEY where it is empty or absent, never
# replace a value that is there. Edits in place, so the file keeps its mode.
fill_value() {
    python3 - "$1" "$2" "$3" <<'PY'
import re, sys
path, key, value = sys.argv[1:]
lines = open(path, encoding="utf-8").read().splitlines()
pattern = re.compile(rf"\s*(?:export\s+)?{re.escape(key)}=(.*)$")
for i, line in enumerate(lines):
    m = pattern.match(line)
    if m:
        if m.group(1).strip().strip("'\""):
            sys.exit(0)
        lines[i] = f"{key}={value}"
        break
else:
    lines.append(f"{key}={value}")
with open(path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
PY
}

# Generate the VAPID pair into backend/.env when both halves are empty.
# Returns 1 (with the reason on stderr) when it cannot.
generate_vapid() {
    local priv pub py pair
    priv="$(env_value "$ENV_FILE" VAPID_PRIVATE_KEY)"
    pub="$(env_value "$ENV_FILE" VAPID_PUBLIC_KEY)"
    if [ -n "$priv" ] && [ -n "$pub" ]; then
        return 0
    fi
    if [ -n "$priv" ] || [ -n "$pub" ]; then
        echo "ERROR: backend/.env holds half a VAPID pair; set both or neither." >&2
        return 1
    fi
    if ! py="$(crypto_python)"; then
        echo "  note: no Python with \`cryptography\` yet, so no VAPID pair (push stays off)." >&2
        echo "  Install the backend dependencies, then run: scripts/init_env.sh --vapid" >&2
        return 1
    fi
    # The env values are base64url key bytes, not PEM: the raw P-256 scalar,
    # and the uncompressed point the browser's applicationServerKey takes.
    pair="$("$py" - <<'PY'
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

key = ec.generate_private_key(ec.SECP256R1())
b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
priv = key.private_numbers().private_value.to_bytes(32, "big")
pub = key.public_key().public_bytes(
    serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
)
print(b64u(priv), b64u(pub))
PY
)"
    fill_value "$ENV_FILE" VAPID_PRIVATE_KEY "${pair% *}"
    fill_value "$ENV_FILE" VAPID_PUBLIC_KEY "${pair#* }"
    echo "Generated a VAPID pair in backend/.env (set VAPID_SUBJECT to a real contact)."
}

# Create frontend/.env if missing, and give it the backend's public VAPID key.
sync_frontend_env() {
    local pub front
    if [ ! -f "$FRONT_ENV" ]; then
        cp "$FRONT_EXAMPLE" "$FRONT_ENV"
        echo "Created frontend/.env (development values; scripts/deploy_frontend.sh builds production)."
    fi
    pub="$(env_value "$ENV_FILE" VAPID_PUBLIC_KEY)"
    [ -n "$pub" ] || return 0
    front="$(env_value "$FRONT_ENV" VITE_VAPID_PUBLIC_KEY)"
    if [ -z "$front" ]; then
        fill_value "$FRONT_ENV" VITE_VAPID_PUBLIC_KEY "$pub"
    elif [ "$front" != "$pub" ]; then
        echo "WARNING: frontend/.env's VITE_VAPID_PUBLIC_KEY differs from backend/.env's" >&2
        echo "  VAPID_PUBLIC_KEY. Push will be refused until they match; left untouched." >&2
    fi
}

# The compose Postgres volume, if one exists already (any compose project name).
existing_volume() {
    command -v docker >/dev/null 2>&1 || return 0
    docker volume ls -q --filter name=kryptolog-pgdata 2>/dev/null | head -1
}

compose() {
    (cd "$ROOT" && docker compose --env-file backend/.env "$@")
}

adopt_volume() {
    local pw status
    [ -f "$ENV_FILE" ] || { echo "ERROR: no backend/.env to adopt the volume with." >&2; exit 1; }
    pw="$(env_value "$ENV_FILE" POSTGRES_PASSWORD)"
    [ -n "$pw" ] || { echo "ERROR: backend/.env has no POSTGRES_PASSWORD." >&2; exit 1; }
    compose up -d postgres
    echo -n "Waiting for Postgres"
    for _ in $(seq 1 30); do
        status="$(docker inspect --format '{{.State.Health.Status}}' "$(compose ps -q postgres)" 2>/dev/null || true)"
        [ "$status" = healthy ] && break
        echo -n "."
        sleep 1
    done
    echo
    # Inside the container psql connects over the local socket, which the
    # image trusts, so the old password is not needed. The new one goes in on
    # stdin as a quoted SQL literal, never on a command line.
    python3 -c 'import sys; print("ALTER ROLE kryptolog PASSWORD \x27" + sys.argv[1].replace("\x27", "\x27\x27") + "\x27;")' "$pw" |
        compose exec -T postgres psql -q -v ON_ERROR_STOP=1 -U kryptolog -d kryptolog
    echo "The existing volume's role now uses backend/.env's POSTGRES_PASSWORD."
}

case "${1:-}" in
    --adopt-volume)
        adopt_volume
        exit 0
        ;;
    --vapid)
        [ -f "$ENV_FILE" ] || { echo "ERROR: run scripts/init_env.sh first." >&2; exit 1; }
        generate_vapid
        sync_frontend_env
        exit 0
        ;;
    "") ;;
    *)
        echo "usage: scripts/init_env.sh [--vapid | --adopt-volume]" >&2
        exit 2
        ;;
esac

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
    sync_frontend_env
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
generate_vapid || true
sync_frontend_env
echo "  Signup is invite-only: mint a code with  cd backend && python generate_invites.py"

volume="$(existing_volume)"
if [ -n "$volume" ]; then
    cat >&2 <<EOF

STOP: a Postgres volume already exists ($volume). It keeps the password it
  was created with, which this new backend/.env does not hold, so the backend
  would fail to connect. Choose one before starting anything:
    keep its data, use the new password:  scripts/init_env.sh --adopt-volume
    its data does not matter:             docker compose --env-file backend/.env down -v
    you still have the old backend/.env:  rm backend/.env, then put the old one back
EOF
    exit 1
fi
