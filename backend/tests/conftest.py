"""
Shared test fixtures for Kryptolog backend tests.

Runs against a real PostgreSQL database (TEST_DATABASE_URL, defaulting to the
`kryptolog_test` DB on the docker-compose Postgres). PQC verification runs
in-process via pyca/cryptography (ML-DSA-44) — there is no sidecar to mock, and
tests that need a genuine signature get one from `CompositeSigner`. Two client
signature checks are stubbed (see `_mock_pqc`) because the tests post
placeholder signatures; JWT issuance and verification run for real against an
ephemeral server key.
"""

import hashlib
import os
import sys
from unittest.mock import patch

import pytest

# Ensure backend root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# The compose Postgres password lives in backend/.env now (audit 2026-10-12
# K-01), and pytest does not load that file itself.
from utils.dotenv import read_dotenv_value  # noqa: E402

# Environment first (CI sets it), then backend/.env, then the CI service's own
# credentials — which only exist inside the CI job's throwaway container.
TEST_DATABASE_URL = (
    os.getenv("TEST_DATABASE_URL")
    or read_dotenv_value("TEST_DATABASE_URL")
    or "postgresql+psycopg://kryptolog:kryptolog@localhost:5432/kryptolog_test"
)

# Must be set before importing `database`/`main`: `database` builds its engine
# from DATABASE_URL at import time, and it must hit the test DB, never the dev
# one. (main.py no longer migrates on import — audit M-3 — so this is now only
# about which engine gets constructed.)
os.environ["DATABASE_URL"] = TEST_DATABASE_URL

# Fake VAPID keys for testing
os.environ["VAPID_PUBLIC_KEY"] = "fake_pub"
os.environ["VAPID_PRIVATE_KEY"] = "fake_priv"
os.environ["VAPID_SUBJECT"] = "mailto:test@test.com"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import get_db
from main import app
from models import Base

# ---------- Database (real Postgres, fresh schema per test) ----------

engine = create_engine(TEST_DATABASE_URL, pool_pre_ping=True)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


# ---------- Constants ----------


# address -> identity public key, for every identity the suite makes up. Since
# crypto-core 4.0.0 an address is the SHA-384 of its key, so a test that logs
# an identity in needs the key back from the address; the registry is how.
_IDENTITY_KEYS: dict[str, str] = {}


def identity_key_of(address: str) -> str:
    """The identity public key behind an address the suite made up."""
    return _IDENTITY_KEYS[address]


def register_identity(identity_public_key: str) -> str:
    from security.crypto_validation import address_of

    address = address_of(identity_public_key)
    _IDENTITY_KEYS[address] = identity_public_key
    return address


def synthetic_identity_key(tag: str) -> str:
    """A structurally valid composite identity key, deterministic per tag.

    Not a key anyone holds: signature verification is patched out in these
    tests. But it must be the right SHAPE, all the way down, because the login
    route checks it: 1952 bytes of ML-DSA-65 key (any bytes are one) and a real
    Ed25519 public key, whose order the server verifies (crypto-core 4.0.0,
    security/ed25519_subgroup.py) — random bytes would not be a point at all.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    digest = hashlib.sha256(tag.encode()).digest()
    ml = (digest * (1952 // len(digest) + 1))[:1952]
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"ed25519:" + tag.encode()).digest()
    )
    return (ml + ed.public_key().public_bytes_raw()).hex()


def synthetic_address(tag: str) -> str:
    """The address of `synthetic_identity_key(tag)`, registered so a login can
    send the key with it. These used to be readable strings like
    "pqc_test_user_aaa...", which /auth/nonce refuses (audit L-5)."""
    return register_identity(synthetic_identity_key(tag))


class CompositeSigner:
    """A REAL composite ML-DSA-65 + Ed25519 client identity, for the tests that
    must not trust the stubbed verifier: `identity_public_key` is its key in
    hex, `address` the address that key names, `sign` returns raw signature
    bytes (callers base64 them, as the clients do).

    The one place the suite names the signature library, so swapping it is one
    class rather than a dozen call sites — the liboqs -> pyca/cryptography move
    touched all of them. Signs exactly as crypto-core's composite.js does, with
    auth's own M' builder, which test_hybrid_primitives.py pins to the draft.
    """

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

        self._ml = mldsa.MLDSA65PrivateKey.generate()
        self._ed = ed25519.Ed25519PrivateKey.generate()
        self.identity_public_key = (
            self._ml.public_key().public_bytes_raw() + self._ed.public_key().public_bytes_raw()
        ).hex()
        self.address = register_identity(self.identity_public_key)

    def sign(self, message: bytes) -> bytes:
        import auth

        m = auth._composite_message(message)
        return self._ml.sign(m, auth._COMPOSITE_LABEL) + self._ed.sign(m)


TEST_USER_ADDRESS = synthetic_address("user-1")
TEST_USER_ADDRESS_2 = synthetic_address("user-2")
TEST_USER_ADDRESS_3 = synthetic_address("user-3")
# A structurally valid X-Wing public key: 1216 bytes, hex-encoded (2432
# chars). Not a real key — a KEM key has no cheap validity predicate, so the
# server can only check the format — but it must *be* the right format, since
# login rejects malformed keys (KRY-011).
TEST_ENCRYPTION_KEY = "ab" * 1216


# ---------- Auth helpers ----------


def get_nonce(client, address):
    resp = client.get(f"/auth/nonce/{address}")
    assert resp.status_code == 200, resp.text
    return resp.json()["nonce"]


# What a 3.0.0 client signs a login FOR (audit 2026-10-12 K-02). The suite runs
# without ALLOWED_ORIGINS, so any canonical origin is accepted; the deployment is
# the server's own, "dev" unless KRYPTOLOG_DEPLOYMENT_ID is set.
TEST_ORIGIN = "http://localhost:5173"


def server_deployment() -> str:
    import config

    return config.deployment_id()


def login_body(address, nonce, encryption_key=None, username=None, **extra):
    """A complete login request: the fields every 3.0.0 login carries.

    An encryption key always comes with an attestation now (K-04); the
    placeholder passes because `_mock_pqc` stubs the verifier.
    """
    body = {
        "address": address,
        "identity_public_key": identity_key_of(address),
        "signature": "fake_signature_for_testing",
        "nonce": nonce,
        "origin": TEST_ORIGIN,
        "deployment": server_deployment(),
    }
    if encryption_key:
        body["encryption_public_key"] = encryption_key
        body["encryption_key_attestation"] = "fake_attestation_for_testing"
    if username:
        body["username"] = username
    body.update(extra)
    return body


def do_login(client, address, encryption_key=None, username=None):
    nonce = get_nonce(client, address)
    body = login_body(address, nonce, encryption_key, username)
    resp = client.post("/auth/login", json=body)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return data["access_token"], data["user"]


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}


# ---------- Fixtures ----------


@pytest.fixture(autouse=True)
def _setup_db():
    """Create fresh tables before each test and drop them after."""
    Base.metadata.create_all(bind=engine)
    yield
    # Pushes run off the request path now (utils/push.py): a job still in
    # flight would query a schema that is about to be dropped.
    from utils.push import drain_pushes

    assert drain_pushes(timeout=30), "a push job outlived its test"
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset the slowapi rate limiter so limits don't accumulate across tests."""
    from dependencies import limiter

    try:
        limiter.reset()
    except Exception:
        pass
    yield


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "real_signatures: run with the genuine ML-DSA verifiers instead of the "
        "autouse stubs (see the _mock_pqc fixture).",
    )


@pytest.fixture(autouse=True)
def _mock_pqc(request):
    """Accept the placeholder client signatures used across the endpoint tests:
    the login challenge (`verify_signature`) and the multisig approval
    (`verify_identity_signature`). Server-side token issue/verify is left
    untouched (HS256, audit §2/§3).

    Opt out with `@pytest.mark.real_signatures` when a test needs the real
    thing. Before that marker existed the only escape was re-patching over the
    top of this fixture, which meant hand-rolling a copy of the verifier — and a
    copy is exactly what stops detecting a change to the original, as happened
    when production signatures moved to base64 (audit L-12) and
    test_key_attestation's private copy kept decoding hex, passing all the
    while."""
    if request.node.get_closest_marker("real_signatures"):
        yield
        return
    with (
        patch("auth.verify_signature", return_value=True),
        patch("auth.verify_identity_signature", return_value=True),
    ):
        yield


@pytest.fixture()
def client():
    return TestClient(app)


@pytest.fixture()
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def user1(client):
    token, user = do_login(client, TEST_USER_ADDRESS, TEST_ENCRYPTION_KEY, "TestUser")
    return token, user


@pytest.fixture()
def user2(client):
    token, user = do_login(client, TEST_USER_ADDRESS_2, TEST_ENCRYPTION_KEY, "TestUser2")
    return token, user


@pytest.fixture()
def user3(client):
    token, user = do_login(client, TEST_USER_ADDRESS_3, TEST_ENCRYPTION_KEY, "TestUser3")
    return token, user
