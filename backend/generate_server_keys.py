#!/usr/bin/env python3
"""Generate a persistent ML-DSA-44 server signing keypair for SafeLog.

liboqs has no seeded keygen and cannot re-derive a public key from a secret
key, so the server stores BOTH halves. Run this once and put the printed lines
into backend/.env (or your secret manager). Treat the secret key like any other
production secret — anyone holding it can forge SafeLog JWTs.

    python generate_server_keys.py
"""
import oqs

SIG_ALG = "ML-DSA-44"


def main():
    with oqs.Signature(SIG_ALG) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()

    print(f"# SafeLog server signing keypair ({SIG_ALG})")
    print(f"SAFELOG_ML_DSA_PUBLIC_KEY={public_key.hex()}")
    print(f"SAFELOG_ML_DSA_SECRET_KEY={secret_key.hex()}")


if __name__ == "__main__":
    main()
