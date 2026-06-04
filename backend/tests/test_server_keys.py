"""Tests for the server signing-key policy (auth._load_server_keys).

Production must fail closed when no persistent ML-DSA key is configured, so the
backend never serves with an ephemeral key (which would invalidate every JWT on
restart and differ per worker). Development still generates an ephemeral key.
"""

import oqs
import pytest

import auth

SIG_ALG = "ML-DSA-44"


def _reset_keys(monkeypatch):
    monkeypatch.setattr(auth, "_SERVER_SECRET_KEY", None)
    monkeypatch.setattr(auth, "_SERVER_PUBLIC_KEY", None)


def test_is_production_detection(monkeypatch):
    for val, expected in [("production", True), ("prod", True), ("PRODUCTION", True),
                          ("development", False), ("dev", False), ("", False)]:
        monkeypatch.setenv("KRYPTOLOG_ENV", val)
        assert auth._is_production() is expected
    monkeypatch.delenv("KRYPTOLOG_ENV", raising=False)
    assert auth._is_production() is False  # default = development


def test_production_without_keys_fails_closed(monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_ENV", "production")
    monkeypatch.delenv("KRYPTOLOG_ML_DSA_SECRET_KEY", raising=False)
    monkeypatch.delenv("KRYPTOLOG_ML_DSA_PUBLIC_KEY", raising=False)
    _reset_keys(monkeypatch)
    with pytest.raises(RuntimeError, match="must be set when KRYPTOLOG_ENV=production"):
        auth.get_server_public_key()


def test_production_with_keys_loads(monkeypatch):
    with oqs.Signature(SIG_ALG) as s:
        pk = s.generate_keypair()
        sk = s.export_secret_key()
    monkeypatch.setenv("KRYPTOLOG_ENV", "production")
    monkeypatch.setenv("KRYPTOLOG_ML_DSA_PUBLIC_KEY", pk.hex())
    monkeypatch.setenv("KRYPTOLOG_ML_DSA_SECRET_KEY", sk.hex())
    _reset_keys(monkeypatch)
    assert auth.get_server_public_key() == pk.hex()


def test_development_without_keys_generates_ephemeral(monkeypatch):
    monkeypatch.setenv("KRYPTOLOG_ENV", "development")
    monkeypatch.delenv("KRYPTOLOG_ML_DSA_SECRET_KEY", raising=False)
    monkeypatch.delenv("KRYPTOLOG_ML_DSA_PUBLIC_KEY", raising=False)
    _reset_keys(monkeypatch)
    pk_hex = auth.get_server_public_key()
    assert isinstance(pk_hex, str) and len(bytes.fromhex(pk_hex)) == 1312  # ML-DSA-44 pk
