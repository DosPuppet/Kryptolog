#!/usr/bin/env bash
# Build the liboqs C library the backend's liboqs-python binding loads, from a
# PINNED, CHECKSUMMED source tarball (audit 2026-10-12 K-14).
#
# Why this exists: when liboqs-python cannot find the shared library, it does
# not fail. It runs `git clone` of the liboqs repository and compiles whatever
# that tag points at, at the first `import oqs` — inside the server process, on
# whatever machine is starting, with no checksum anywhere. The hashed Python lock
# (requirements.txt) pins the BINDING; nothing pinned the C library under it,
# which is the half that does the signature verification.
#
# So the library is built here, deliberately, before anything imports `oqs`, and
# the start paths refuse to start without it (`--check`). The version matches
# the binding's (liboqs-python 0.16.x ↔ liboqs 0.16.0): a binding ahead of its
# library was the ABI risk audit 2026-09-11 F-10 reported.
#
# Usage:
#   scripts/build_liboqs.sh           build + install if missing or wrong version
#   scripts/build_liboqs.sh --check   exit 1 unless the pinned version is installed
#
# Install prefix: $OQS_INSTALL_PATH, else ~/_oqs — the two places liboqs-python
# looks, so no extra configuration is needed on either side.

set -euo pipefail

LIBOQS_VERSION="0.16.0"
# sha256 of https://github.com/open-quantum-safe/liboqs/archive/refs/tags/0.16.0.tar.gz
# Recorded 2026-10-12. Changing the version means changing this line too — a
# mismatch is a refusal, never a warning.
LIBOQS_SHA256="162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae"

PREFIX="${OQS_INSTALL_PATH:-$HOME/_oqs}"
CONFIG_H="$PREFIX/include/oqs/oqsconfig.h"

installed_version() {
    [ -f "$CONFIG_H" ] || return 0
    sed -n 's/^#define OQS_VERSION_TEXT "\(.*\)"$/\1/p' "$CONFIG_H"
}

have_pinned() {
    [ "$(installed_version)" = "$LIBOQS_VERSION" ] &&
        compgen -G "$PREFIX/lib*/liboqs.so*" >/dev/null
}

if [ "${1:-}" = "--check" ]; then
    if have_pinned; then
        exit 0
    fi
    echo "ERROR: liboqs $LIBOQS_VERSION is not installed under $PREFIX" >&2
    echo "  (found: '$(installed_version)'). Run scripts/build_liboqs.sh first —" >&2
    echo "  refusing to let liboqs-python clone and compile an unpinned copy." >&2
    exit 1
fi

if have_pinned; then
    echo "liboqs $LIBOQS_VERSION already installed under $PREFIX"
    exit 0
fi

for tool in curl cmake cc sha256sum tar; do
    command -v "$tool" >/dev/null || { echo "ERROR: $tool is required" >&2; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

TARBALL="$WORK/liboqs-$LIBOQS_VERSION.tar.gz"
curl -fsSL -o "$TARBALL" \
    "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$LIBOQS_VERSION.tar.gz"
echo "$LIBOQS_SHA256  $TARBALL" | sha256sum --check --quiet || {
    echo "ERROR: liboqs $LIBOQS_VERSION tarball does not match its pinned sha256" >&2
    exit 1
}

tar -xzf "$TARBALL" -C "$WORK"
SRC="$WORK/liboqs-$LIBOQS_VERSION"

# Only the two algorithms Kryptolog uses: ML-DSA-44 for every signature the
# server verifies, ML-KEM-768 for the interop tests and audit probes. A minimal
# build is less C code loaded into the server process than the default, which
# also compiles every stateful and experimental scheme.
cmake -S "$SRC" -B "$WORK/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;KEM_ml_kem_768" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" >/dev/null
cmake --build "$WORK/build" --parallel "$(nproc 2>/dev/null || echo 4)" >/dev/null

# A previous version's headers and library would otherwise sit next to the new
# ones, and the loader can pick the wrong .so.
rm -rf "$PREFIX/include/oqs" "$PREFIX"/lib*/liboqs.* "$PREFIX"/lib*/cmake/liboqs
cmake --install "$WORK/build" >/dev/null

have_pinned || { echo "ERROR: install finished but liboqs $LIBOQS_VERSION is not found" >&2; exit 1; }
echo "liboqs $LIBOQS_VERSION installed under $PREFIX"
