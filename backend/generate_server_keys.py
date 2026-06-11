#!/usr/bin/env python3
"""Generate a persistent JWT signing secret for Kryptolog.

Access tokens are HS256-signed with a symmetric secret (PyJWT). Run this once
and put the printed line into backend/.env (or your secret manager). Treat the
secret like any other production credential — anyone holding it can forge
Kryptolog JWTs. It is REQUIRED when KRYPTOLOG_ENV=production; if unset in
development the backend uses an ephemeral secret (all JWTs reset on restart).

    python generate_server_keys.py
"""
import secrets


def main():
    print("# Kryptolog JWT signing secret (HS256)")
    print(f"KRYPTOLOG_JWT_SECRET={secrets.token_hex(32)}")


if __name__ == "__main__":
    main()
