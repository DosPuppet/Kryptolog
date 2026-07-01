"""Tests for the JWT signing-secret policy (auth._load_jwt_secret).

Production must fail closed when no persistent JWT secret is configured, so the
backend never serves with an ephemeral secret (which would invalidate every JWT
on restart and differ per worker). Development still generates an ephemeral one.
"""

import pytest

import auth


def _reset_secret(monkeypatch):
    monkeypatch.setattr(auth, "_JWT_SECRET", None)


def test_is_production_detection(monkeypatch):
    for val, expected in [("production", True), ("prod", True), ("PRODUCTION", True),
                          ("development", False), ("dev", False), ("", False)]:
        monkeypatch.setenv("KRYPTOLOG_ENV", val)
        assert auth._is_production() is expected
    monkeypatch.delenv("KRYPTOLOG_ENV", raising=False)
    assert auth._is_production() is False  # default = development


def test_production_without_secret_fails_closed(monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_ENV", "production")
    monkeypatch.delenv("KRYPTOLOG_JWT_SECRET", raising=False)
    _reset_secret(monkeypatch)
    with pytest.raises(RuntimeError, match="must be set when KRYPTOLOG_ENV=production"):
        auth.get_jwt_secret()


def test_production_with_secret_loads(monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_ENV", "production")
    monkeypatch.setenv("KRYPTOLOG_JWT_SECRET", "deadbeef" * 8)
    _reset_secret(monkeypatch)
    assert auth.get_jwt_secret() == "deadbeef" * 8


def test_development_without_secret_generates_ephemeral(monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_ENV", "development")
    monkeypatch.delenv("KRYPTOLOG_JWT_SECRET", raising=False)
    _reset_secret(monkeypatch)
    secret = auth.get_jwt_secret()
    assert isinstance(secret, str) and len(secret) >= 32  # token_hex(32) -> 64 chars
