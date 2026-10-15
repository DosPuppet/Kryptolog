#!/usr/bin/env bash
# Build the SPA for production and publish it where the reverse proxy serves it.
#
# A real install (2026-10-15) had to invent this step: DEPLOYMENT.md said
# "serve frontend/dist from the proxy" and stopped there. It also had to copy
# the API URL and the VAPID public key into frontend/.env by hand, and a build
# with either missing succeeds and ships a broken bundle. So nothing here is
# typed twice — both values are derived from backend/.env on every run:
#
#   VITE_API_BASE_URL      KRYPTOLOG_PUBLIC_API_URL if set, else the first
#                          ALLOWED_ORIGINS entry + /api (the layout both
#                          shipped proxy configs use)
#   VITE_VAPID_PUBLIC_KEY  VAPID_PUBLIC_KEY
#
# and the build runs with KRYPTOLOG_STRICT_BUILD=1, so frontend/deploymentGuard.js
# refuses a localhost, plain-http or malformed configuration instead of
# shipping it.
#
# Published by COPY to KRYPTOLOG_WEB_ROOT (default /var/www/kryptolog/frontend/dist,
# the path nginx.conf.example and the DEPLOYMENT.md Caddy site serve), never by
# pointing the proxy into the checkout: `vite build` empties dist/ first, so a
# proxy reading the checkout answers 404 for the length of every rebuild, and
# would need read access to the repository besides. Run this after every
# change to the SPA or to those backend/.env values — the proxy serves what
# was copied last.
#
# Usage: scripts/deploy_frontend.sh           (as the deploying user; it asks
#                                              sudo only for the copy, if the
#                                              web root needs it)

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -f backend/.env ]; then
    echo "ERROR: no backend/.env — run scripts/init_env.sh first." >&2
    exit 1
fi
command -v rsync >/dev/null 2>&1 || { echo "ERROR: rsync is required." >&2; exit 1; }

# Read only the values this needs, in a subshell, so backend/.env's secrets
# (JWT secret, database and VAPID private keys) are never exported into npm and
# the install scripts of every package it runs. The caller's environment wins
# over the file, as it does for the backend.
caller_api="${KRYPTOLOG_PUBLIC_API_URL:-}"
caller_root="${KRYPTOLOG_WEB_ROOT:-}"
mapfile -t cfg < <(
    # shellcheck source=load_env.sh
    source scripts/load_env.sh
    kryptolog_load_env backend/.env
    printf '%s\n' "${ALLOWED_ORIGINS:-}" "${KRYPTOLOG_PUBLIC_API_URL:-}" \
        "${KRYPTOLOG_WEB_ROOT:-}" "${VAPID_PUBLIC_KEY:-}" "${VAPID_PRIVATE_KEY:+set}"
)
origins="${cfg[0]}"
api="${caller_api:-${cfg[1]}}"
web_root="${caller_root:-${cfg[2]:-/var/www/kryptolog/frontend/dist}}"
vapid_public="${cfg[3]}"
vapid_private_set="${cfg[4]}"

if [ -z "$api" ]; then
    first="${origins%%,*}"
    first="${first// /}"
    if [ -z "$first" ]; then
        echo "ERROR: set ALLOWED_ORIGINS (or KRYPTOLOG_PUBLIC_API_URL) in backend/.env." >&2
        exit 1
    fi
    api="${first%/}/api"
fi
if [ -n "$vapid_private_set" ] && [ -z "$vapid_public" ]; then
    echo "ERROR: backend/.env has VAPID_PRIVATE_KEY but no VAPID_PUBLIC_KEY." >&2
    exit 1
fi

echo "Building the SPA for $api"
(cd packages/crypto-core && npm ci --no-audit --no-fund)   # the SPA links it
(cd frontend && npm ci --no-audit --no-fund)
(cd frontend && VITE_API_BASE_URL="$api" VITE_VAPID_PUBLIC_KEY="$vapid_public" \
    KRYPTOLOG_STRICT_BUILD=1 npm run build)

dist="$ROOT/frontend/dist"
[ -f "$dist/index.html" ] || { echo "ERROR: the build left no $dist/index.html." >&2; exit 1; }

sudo_cmd=()
probe="$web_root"
while [ ! -e "$probe" ]; do probe="$(dirname "$probe")"; done
[ -w "$probe" ] || sudo_cmd=(sudo)

echo "Publishing to $web_root"
"${sudo_cmd[@]}" mkdir -p "$web_root"
# --delay-updates swaps the new files in together at the end, and
# --delete-after removes the old hashed assets only once they are.
"${sudo_cmd[@]}" rsync -a --delay-updates --delete-after "$dist/" "$web_root/"

# What was published, not what was meant to be.
if grep -rqs 'localhost:8000' "$web_root"; then
    echo "ERROR: the published bundle still calls localhost:8000." >&2
    exit 1
fi
echo "Published. Check it: curl -fsS ${api%/}/healthz"
