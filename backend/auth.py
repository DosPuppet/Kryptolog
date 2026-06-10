from eth_account.messages import encode_defunct
from eth_account import Account
import secrets
import base64
import json
import os
from datetime import datetime, timedelta, timezone

import oqs

# --- Post-quantum signature config (NIST FIPS 204) ---
# All ML-DSA work runs in-process via liboqs; the old Node `pqc_service.js`
# sidecar (audit A1/M1) is gone. ML-DSA-44 byte encodings are interop-verified
# against the browser/extension's @noble/post-quantum (see tests/test_pqc.py).
SIG_ALG = "ML-DSA-44"

# liboqs has no public seeded keygen, and a public key cannot be re-derived from
# a secret key — so the server keypair is generated once (generate_server_keys.py)
# and BOTH halves are stored as hex in the environment.
_SERVER_SECRET_KEY = None  # bytes
_SERVER_PUBLIC_KEY = None  # bytes


def _is_production() -> bool:
    return (os.getenv("KRYPTOLOG_ENV") or "development").strip().lower() in ("production", "prod")


def _load_server_keys():
    """Load the server ML-DSA keypair from env. In production a persistent key is
    mandatory (fail closed); in dev an ephemeral one is generated with a warning.
    Returns (secret_key, public_key)."""
    global _SERVER_SECRET_KEY, _SERVER_PUBLIC_KEY
    if _SERVER_SECRET_KEY is not None and _SERVER_PUBLIC_KEY is not None:
        return _SERVER_SECRET_KEY, _SERVER_PUBLIC_KEY

    sk_hex = os.getenv("KRYPTOLOG_ML_DSA_SECRET_KEY")
    pk_hex = os.getenv("KRYPTOLOG_ML_DSA_PUBLIC_KEY")

    if sk_hex and pk_hex:
        _SERVER_SECRET_KEY = bytes.fromhex(sk_hex)
        _SERVER_PUBLIC_KEY = bytes.fromhex(pk_hex)
    elif _is_production():
        # Fail closed: an ephemeral key would invalidate every JWT on restart and
        # differ per worker — silent, hard-to-debug auth breakage in production.
        raise RuntimeError(
            "KRYPTOLOG_ML_DSA_SECRET_KEY / KRYPTOLOG_ML_DSA_PUBLIC_KEY must be set when "
            "KRYPTOLOG_ENV=production. Generate them with `python generate_server_keys.py` "
            "and provide them via the environment / a secret manager. Refusing to start "
            "with an ephemeral signing key."
        )
    else:
        print(
            "WARNING: KRYPTOLOG_ML_DSA_SECRET_KEY / KRYPTOLOG_ML_DSA_PUBLIC_KEY not set. "
            "Generating an EPHEMERAL server signing key — all JWTs become invalid on "
            "restart. Run `python generate_server_keys.py` and set the env vars for "
            "any persistent deployment."
        )
        with oqs.Signature(SIG_ALG) as signer:
            _SERVER_PUBLIC_KEY = signer.generate_keypair()
            _SERVER_SECRET_KEY = signer.export_secret_key()

    return _SERVER_SECRET_KEY, _SERVER_PUBLIC_KEY


def get_server_public_key() -> str:
    """Server's ML-DSA public key as hex (used to verify the JWTs it issues)."""
    _, pk = _load_server_keys()
    return pk.hex()


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def b64url_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def generate_nonce():
    return secrets.token_hex(16)


# Domain separation (audit H1): every signed payload is wrapped with a context
# tag so a signature minted for one purpose (e.g. approving multisig/document
# content) can never be replayed as another (e.g. this login challenge). The
# context is fixed here in code, never drawn from user-supplied content, and the
# header line cannot be reproduced by a content body, so the namespaces are
# disjoint. Clients apply the identical wrapper (frontend `domainSeparate`).
_DS_HEADER = "Kryptolog Signed Message v1"
_CTX_LOGIN = "login"


def _domain_separate(context: str, body: str) -> str:
    return f"{_DS_HEADER}\ncontext={context}\n{body}"


def _login_message(nonce: str, encryption_public_key: str | None = None) -> str:
    """Canonical login challenge. When an encryption (ML-KEM) key is supplied it
    is folded in, so the identity's signature cryptographically authorizes that
    key — a network attacker can't substitute their own KEM key at login (M-2).
    The whole thing is domain-separated under the `login` context (H1) so a
    content-signing operation can never produce these exact bytes.
    Must be byte-identical to what the clients build."""
    body = f"Sign in to Kryptolog with nonce: {nonce}"
    if encryption_public_key:
        body += f"\nEncryption key: {encryption_public_key}"
    return _domain_separate(_CTX_LOGIN, body)


def verify_pqc_signature(public_key: str, nonce: str, signature: str,
                         encryption_public_key: str | None = None) -> bool:
    """Verify a client login challenge: ML-DSA-44 over the (key-bound) login message.
    `public_key` and `signature` are hex; the client signs with @noble/post-quantum."""
    try:
        message = _login_message(nonce, encryption_public_key).encode("utf-8")
        sig_bytes = bytes.fromhex(signature)
        pk_bytes = bytes.fromhex(public_key)
        with oqs.Signature(SIG_ALG) as verifier:
            return verifier.verify(message, sig_bytes, pk_bytes)
    except Exception as e:
        print(f"PQC verification error: {e}")
        return False


def verify_signature(address: str, nonce: str, signature: str,
                     encryption_public_key: str | None = None) -> bool:
    # A PQC identity is the ML-DSA public key (1312 bytes => 2624 hex chars);
    # an Ethereum address is 42 chars. Dispatch on length, as before.
    if len(address) > 42:
        return verify_pqc_signature(address, nonce, signature, encryption_public_key)

    try:
        message_text = _login_message(nonce, encryption_public_key)
        encoded_message = encode_defunct(text=message_text)
        recovered_address = Account.recover_message(encoded_message, signature=signature)
        return recovered_address.lower() == address.lower()
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire.timestamp()})

    header = {"alg": SIG_ALG, "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header).encode('utf-8'))
    payload_b64 = b64url_encode(json.dumps(to_encode).encode('utf-8'))
    message = f"{header_b64}.{payload_b64}"

    try:
        sk, _ = _load_server_keys()
        with oqs.Signature(SIG_ALG, secret_key=sk) as signer:
            signature_bytes = signer.sign(message.encode('utf-8'))
        signature_b64 = b64url_encode(signature_bytes)
        return f"{message}.{signature_b64}"
    except Exception as e:
        print(f"Token creation failed: {e}")
        return None


def decode_access_token(token: str):
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature_b64 = parts
        message = f"{header_b64}.{payload_b64}".encode('utf-8')
        signature_bytes = b64url_decode(signature_b64)

        _, server_pk = _load_server_keys()
        with oqs.Signature(SIG_ALG) as verifier:
            valid = verifier.verify(message, signature_bytes, server_pk)

        if not valid:
            return None

        payload_json = b64url_decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)

        exp = payload.get("exp")
        if exp:
            if datetime.now(timezone.utc).timestamp() > exp:
                return None

        return payload

    except Exception as e:
        print(f"Token decode error: {e}")
        return None
