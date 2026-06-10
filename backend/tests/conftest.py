"""
Shared test fixtures for Kryptolog backend tests.

Uses an in-memory SQLite database. PQC signing now runs in-process via liboqs
(ML-DSA-44) — there is no sidecar to mock. We only stub the login-challenge
check `auth.verify_signature` (tests post a placeholder client signature);
JWT issuance and verification run for real against an ephemeral server key.
"""

import sys, os
import pytest
from unittest.mock import patch

# Ensure backend root is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Fake VAPID keys for testing
os.environ["VAPID_PUBLIC_KEY"] = "fake_pub"
os.environ["VAPID_PRIVATE_KEY"] = "fake_priv"
os.environ["VAPID_SUBJECT"] = "mailto:test@test.com"

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from models import Base
from database import get_db
from main import app


# ---------- Database (in-memory, shared across a single test) ----------

# Use a single in-memory DB with StaticPool to share across threads
from sqlalchemy.pool import StaticPool

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


# ---------- Constants ----------

TEST_USER_ADDRESS = "pqc_test_user_" + "a" * 100
TEST_USER_ADDRESS_2 = "pqc_test_user_" + "b" * 100
TEST_ENCRYPTION_KEY = "enc_pub_key_" + "c" * 600  # Must be > 500 chars to pass PQC key validation


# ---------- Auth helpers ----------

def get_nonce(client, address):
    resp = client.get(f"/auth/nonce/{address}")
    assert resp.status_code == 200, resp.text
    return resp.json()["nonce"]


def do_login(client, address, encryption_key=None, username=None):
    nonce = get_nonce(client, address)
    body = {
        "address": address,
        "signature": "fake_signature_for_testing",
        "nonce": nonce,
    }
    if encryption_key:
        body["encryption_public_key"] = encryption_key
    if username:
        body["username"] = username
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


@pytest.fixture(autouse=True)
def _mock_pqc():
    """Accept the placeholder client signatures used across the endpoint tests:
    the login challenge (`verify_signature`) and the multisig approval
    (`verify_message_signature`). Tests that need the *real* verifier override
    these (see test_multisig signature-gate test / the unit tests in test_pqc).
    Real ML-DSA-44 JWT issue/verify (in-process liboqs) is left untouched."""
    with patch("auth.verify_signature", return_value=True), \
         patch("auth.verify_message_signature", return_value=True):
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
