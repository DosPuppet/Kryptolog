import base64
import hashlib
import json
import logging
import os
import secrets
from datetime import UTC, datetime, timedelta

import jwt
import oqs

logger = logging.getLogger("kryptolog.auth")

# --- Post-quantum signature config (NIST FIPS 204) ---
# liboqs (ML-DSA-44) is used in-process to verify CLIENT login challenges and
# multisig approvals — the only place server-side PQC is genuinely
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
# tag so a signature minted for one purpose (e.g. approving multisig content)
# can never be replayed as another (e.g. this login challenge). The
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


_CTX_KEY_ATTESTATION = "key-attestation"


def encryption_key_attestation_message(mlkem_public_key_hex: str) -> str:
    """The self-attestation a user signs over their own ML-KEM key (audit M-1).
    Peers verify it against the user's address (= ML-DSA public key) before
    encrypting to that key, so the directory can't substitute a key it controls.
    The server verifies it at login too (hygiene: never store a bad attestation).
    Must be byte-identical to crypto-core's encryptionKeyAttestationBody()."""
    return _domain_separate(_CTX_KEY_ATTESTATION, f"mlkem={mlkem_public_key_hex}")


_CTX_MULTISIG = "multisig-approval"


def multisig_approval_message(workflow_id, secret_id, ciphertext_sha256_hex: str) -> str:
    """Server-verifiable multisig approval (audit M1). The server is
    zero-knowledge — it can't see the plaintext a signer approved — but it *can*
    hash the ciphertext it stores. A signer therefore signs the SHA-256 of the
    workflow's stored ciphertext, bound to the workflow + secret id. Domain-
    separated under `multisig-approval` (H1) so it can't be replayed as a login
    challenge. Clients build the byte-identical string
    (frontend `multisigApprovalMessage`)."""
    body = f"workflow={workflow_id}\nsecret={secret_id}\nct={ciphertext_sha256_hex}"
    return _domain_separate(_CTX_MULTISIG, body)


_CTX_MESSAGE = "message"
_CTX_ACCOUNT_DELETION = "account-deletion"


class NonCanonicalSignedBody(ValueError):
    """A value the two languages would not spell identically inside a signed body.

    Raised rather than guessed at. A signed body only means anything if the
    signer and the verifier build the same bytes, so a value whose rendering
    differs between Python and JS must stop the operation, not produce bytes
    one side would never have written.
    """


class NonCanonicalKeyEnvelope(NonCanonicalSignedBody):
    """A key envelope whose shape the two languages would not agree on."""


def _canonical_json(value) -> str:
    """Mirror of crypto-core's `canonicalJson` (encoding.js).

    Sorted keys, no whitespace, `JSON.stringify` semantics for scalars. Only
    reached through `message_signing_body`, and only over values
    `_check_envelope_shape` has already accepted — see there for why that
    restriction is what makes this mirror safe rather than merely close.
    """
    if value is None:
        return "null"
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json(v) for v in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ",".join(
                f"{json.dumps(k, ensure_ascii=False)}:{_canonical_json(value[k])}"
                for k in sorted(value)
            )
            + "}"
        )
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        # Bools, floats and everything exotic are refused rather than guessed
        # at: Python renders True as "True" and 1.0 as "1.0" where JS gives
        # "true" and "1", so agreeing here would be a coincidence.
        raise NonCanonicalKeyEnvelope(f"unsupported value type: {type(value).__name__}")
    return json.dumps(value, ensure_ascii=False)


def check_envelope_shape(keys) -> None:
    """Refuse a key envelope this mirror cannot promise to spell like JS.

    `_canonical_json` agrees with `canonicalJson` on ASCII strings and integers
    and nothing else: Python escapes non-ASCII by default where JS does not,
    the two sort by code point vs UTF-16 code unit, and lone surrogates cannot
    round-trip at all. In production a `keys` map is address → {kem, iv,
    encKey}, i.e. lowercase hex mapping to base64 — all ASCII, where the two
    provably agree.

    So this validates that assumption instead of assuming it. A payload that
    fails is refused, NOT hashed: a digest computed over a value the client
    spelled differently would fail verification for a reason nothing reports.
    """

    def ascii_str(v) -> bool:
        return isinstance(v, str) and v.isascii()

    if not isinstance(keys, dict) or not keys:
        raise NonCanonicalKeyEnvelope("key envelope must be a non-empty object")
    for name, entry in keys.items():
        if not ascii_str(name):
            raise NonCanonicalKeyEnvelope("key envelope names must be ASCII strings")
        if not isinstance(entry, dict) or not entry:
            raise NonCanonicalKeyEnvelope("each wrapped key must be a non-empty object")
        for field, value in entry.items():
            if not ascii_str(field) or not ascii_str(value):
                raise NonCanonicalKeyEnvelope("wrapped key fields must be ASCII strings")


def _canonical_ciphertext(ct) -> str:
    """Mirror of crypto-core's `canonicalCiphertext`: the AES-GCM envelope
    object serializes as `iv.content`, a pre-serialized string passes through.
    '.' is not in the base64 alphabet, so the separator stays unambiguous."""
    if isinstance(ct, dict):
        return f"{ct.get('iv')}.{ct.get('content')}"
    return ct


def message_signing_body(*, from_: str, conv: str, sid: str, ct, gid: str = "", keys=None) -> str:
    """The bytes a sender signs for one chat message (audit S1).

    Must stay byte-identical to crypto-core's `messageSigningBody` — and unlike
    the other bodies here, this one had no Python half until account deletion
    needed it, because the server never verified a message signature. It does
    now, for redactions only.

    Both branches are implemented even though only `ct=None` is reached in
    production: without the live branch nothing proves this `keysh` agrees with
    the JS one over a real key envelope, and that agreement is the whole point
    of the shared fixture.
    """
    if keys is not None:
        check_envelope_shape(keys)
    # A missing sid renders as `sid=None` here and `sid=null` in JS — the same
    # class of silent divergence `check_envelope_shape` guards the digest
    # against, in the one field that comes straight out of a client-written
    # payload. No legitimate message has one: the session cache is addressed by
    # (conversation, sid), so a payload without it is not a session at all.
    # Refused rather than spelled, because the two spellings would verify on
    # neither side (audit 2026-09-12 M-2c).
    if not isinstance(sid, str) or not sid:
        raise NonCanonicalSignedBody("a signed message body needs a session id")
    tail = "\nredacted=1" if ct is None else f"\nct={_canonical_ciphertext(ct)}"
    keysh = hashlib.sha256(_canonical_json(keys).encode("utf-8")).hexdigest()
    body = f"from={from_}\nconv={conv}\ngid={gid or ''}\nsid={sid}\nkeysh={keysh}" + tail
    return _domain_separate(_CTX_MESSAGE, body)


def account_deletion_message(nonce: str, mode: str, redaction_keys=()) -> str:
    """The bytes a client signs to authorize destroying its own account.

    Its own context (H1), so a login signature cannot be replayed as one — and
    so the extension will not auto-sign it: TrustKeys silently signs only
    `message`-context bodies, and this deliberately falls outside that.

    `mode` is signed because the two modes are not interchangeable: without it a
    relay could downgrade an "erase" into a "leave" or escalate a "leave" into
    an "erase" under a signature that verifies either way. The redaction set is
    signed for the same class of reason — dropping one entry turns a redaction
    into a deletion, which takes the partner's own history with it.

    Entries are `"dm:<id>"` / `"group:<id>"`, never bare ids: the two message
    tables have independent id sequences, so 412 names two different rows and a
    relay could drop one while the set still matched.

    Sorted with the default string order, which is where JS and Python agree:
    both compare ASCII code points. Numeric ids would NOT have been safe —
    JS's default sort is lexicographic, so [2, 10] spells [10, 2] there.

    Must be byte-identical to crypto-core's accountDeletionBody().
    """
    digest = hashlib.sha256(_canonical_json(sorted(redaction_keys)).encode("utf-8")).hexdigest()
    return _domain_separate(
        _CTX_ACCOUNT_DELETION, f"nonce={nonce}\nmode={mode}\nredactions={digest}"
    )


def _sig_bytes(signature: str) -> bytes:
    """Decode a base64 ML-DSA signature, refusing a non-canonical spelling.

    Strict for the same reason crypto-core's fromB64 is: a signature commits to
    a ciphertext in its string form, so accepting two spellings of one value
    would accept two valid signatures for it. `validate=True` alone still lets
    unused trailing bits through, hence the re-encode.
    """
    decoded = base64.b64decode(signature, validate=True)
    if base64.b64encode(decoded).decode() != signature:
        raise ValueError("non-canonical base64 signature")
    return decoded


def verify_message_signature(address: str, message: str, signature: str) -> bool:
    """Verify an exact-message ML-DSA-44 signature. `address` is the signer's
    public key in HEX (an address is an identifier); `signature` is BASE64 (an
    opaque payload — audit L-12). Used for non-login signatures the server must
    check (e.g. multisig approvals). `message` is the exact UTF-8 string signed.
    """
    try:
        with oqs.Signature(SIG_ALG) as verifier:
            return verifier.verify(
                message.encode("utf-8"), _sig_bytes(signature), bytes.fromhex(address)
            )
    except Exception as e:
        # Verification failures are expected/attacker-triggerable — keep at debug.
        logger.debug("Message signature verification failed: %s", e)
        return False


def verify_pqc_signature(
    public_key: str, nonce: str, signature: str, encryption_public_key: str | None = None
) -> bool:
    """Verify a client login challenge: ML-DSA-44 over the (key-bound) login message.
    `public_key` is hex, `signature` is base64; the client signs with
    @noble/post-quantum."""
    try:
        message = _login_message(nonce, encryption_public_key).encode("utf-8")
        sig_bytes = _sig_bytes(signature)
        pk_bytes = bytes.fromhex(public_key)
        with oqs.Signature(SIG_ALG) as verifier:
            return verifier.verify(message, sig_bytes, pk_bytes)
    except Exception as e:
        logger.debug("PQC verification error: %s", e)
        return False


def verify_signature(
    address: str, nonce: str, signature: str, encryption_public_key: str | None = None
) -> bool:
    """Verify a login challenge. Identities are ML-DSA-44 public keys, so this is
    a thin wrapper over verify_pqc_signature (kept for call-site stability)."""
    return verify_pqc_signature(address, nonce, signature, encryption_public_key)


ACCESS_TOKEN_EXPIRE_MINUTES = 30


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    # Aware on purpose, unlike every DB write: `exp` is a JWT claim, not a
    # naive DateTime column, and PyJWT converts this to a UNIX timestamp.
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
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
