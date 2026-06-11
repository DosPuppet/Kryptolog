from eth_account.messages import encode_defunct
from eth_account import Account
import secrets
import logging
import os
from datetime import datetime, timedelta, timezone

import jwt
import oqs

logger = logging.getLogger("kryptolog.auth")

# --- Post-quantum signature config (NIST FIPS 204) ---
# liboqs (ML-DSA-44) is used in-process to verify CLIENT login challenges and
# multisig/document approvals — the only place server-side PQC is genuinely
# needed (the old Node `pqc_service.js` sidecar, audit A1/M1, is gone). Byte
# encodings are interop-verified against the browser/extension's
# @noble/post-quantum (see tests/test_pqc.py).
SIG_ALG = "ML-DSA-44"

# --- JWT signing (classical) ---
# Access tokens are server-issued and server-verified only (no JWKS, clients
# never verify them), so a symmetric HS256 secret is the right primitive — no
# keypair to manage and the token stays small. PyJWT replaces the former
# hand-rolled JOSE + ML-DSA-signed JWTs (audit §2/§3).
JWT_ALG = "HS256"
_JWT_SECRET = None  # str


def _is_production() -> bool:
    return (os.getenv("KRYPTOLOG_ENV") or "development").strip().lower() in ("production", "prod")


def _load_jwt_secret() -> str:
    """Load the HS256 JWT secret from env. In production a persistent secret is
    mandatory (fail closed); in dev an ephemeral one is generated with a warning
    (every JWT then resets on restart and differs per worker)."""
    global _JWT_SECRET
    if _JWT_SECRET is not None:
        return _JWT_SECRET

    secret = os.getenv("KRYPTOLOG_JWT_SECRET")
    if secret:
        _JWT_SECRET = secret
    elif _is_production():
        # Fail closed: an ephemeral secret would invalidate every JWT on restart
        # and differ per worker — silent, hard-to-debug auth breakage in prod.
        raise RuntimeError(
            "KRYPTOLOG_JWT_SECRET must be set when KRYPTOLOG_ENV=production. "
            "Generate one with `python generate_server_keys.py` and provide it via the "
            "environment / a secret manager. Refusing to start with an ephemeral JWT secret."
        )
    else:
        logger.warning(
            "KRYPTOLOG_JWT_SECRET not set. Generating an EPHEMERAL JWT secret — all JWTs "
            "become invalid on restart. Run `python generate_server_keys.py` and set "
            "KRYPTOLOG_JWT_SECRET for any persistent deployment."
        )
        _JWT_SECRET = secrets.token_hex(32)
    return _JWT_SECRET


def get_jwt_secret() -> str:
    """Resolve the JWT secret (triggers the production fail-closed check). Called
    at boot so the process refuses to start without a persistent secret in prod."""
    return _load_jwt_secret()


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


_CTX_MULTISIG = "multisig-approval"


def multisig_approval_message(workflow_id, secret_id, ciphertext_sha256_hex: str) -> str:
    """Server-verifiable multisig approval (audit M1). The server is
    zero-knowledge — it can't see the plaintext a signer approved — but it *can*
    hash the ciphertext it stores. A signer therefore signs the SHA-256 of the
    workflow's stored ciphertext, bound to the workflow + secret id. Domain-
    separated under `multisig-approval` (H1) so it can't be replayed as a login
    or a content/document signature. Clients build the byte-identical string
    (frontend `multisigApprovalMessage`)."""
    body = f"workflow={workflow_id}\nsecret={secret_id}\nct={ciphertext_sha256_hex}"
    return _domain_separate(_CTX_MULTISIG, body)


def verify_message_signature(address: str, message: str, signature: str) -> bool:
    """Verify an exact-message signature from either a PQC identity (ML-DSA-44,
    `address` is the public-key hex) or an Ethereum account (`address` is the
    0x… address). Dispatches on identity length, like `verify_signature`. Used
    for non-login signatures the server must check (e.g. multisig approvals).
    `message` is the exact UTF-8 string that was signed; `signature` is hex
    (PQC) or an 0x ECDSA signature (Ethereum)."""
    try:
        if len(address) > 42:
            with oqs.Signature(SIG_ALG) as verifier:
                return verifier.verify(message.encode("utf-8"),
                                       bytes.fromhex(signature),
                                       bytes.fromhex(address))
        encoded_message = encode_defunct(text=message)
        recovered = Account.recover_message(encoded_message, signature=signature)
        return recovered.lower() == address.lower()
    except Exception as e:
        # Verification failures are expected/attacker-triggerable — keep at debug.
        logger.debug("Message signature verification failed: %s", e)
        return False


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
        logger.debug("PQC verification error: %s", e)
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
        logger.debug("Signature verification failed: %s", e)
        return False


ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire  # PyJWT serializes datetime -> numeric exp claim
    try:
        return jwt.encode(to_encode, _load_jwt_secret(), algorithm=JWT_ALG)
    except Exception as e:
        # A genuine server-side fault (e.g. missing secret) — surface it.
        logger.error("Token creation failed: %s", e)
        return None


def decode_access_token(token: str):
    try:
        # PyJWT validates the signature, the `exp` claim, and that the header
        # `alg` is in the allowed list — so alg-confusion / `none` (audit L2)
        # cannot apply. Malformed/expired/forged tokens raise InvalidTokenError.
        return jwt.decode(token, _load_jwt_secret(), algorithms=[JWT_ALG])
    except jwt.InvalidTokenError as e:
        # Attacker-triggerable; keep at debug to avoid log spam.
        logger.debug("Token decode error: %s", e)
        return None
