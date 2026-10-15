"""scripts/init_env.sh, run for real in a scratch copy of the repo layout.

Two things a real install (2026-10-15) got wrong by hand, which the script now
does: the VAPID public key is one value under two names in two files, and a
backend/.env generated next to an existing Postgres volume holds a password
that volume never accepted. `docker` is a stub on PATH, so no test touches the
host's containers.
"""

import base64
import os
import shutil
import stat
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


@pytest.fixture()
def tree(tmp_path):
    for rel in ("scripts/init_env.sh", "backend/.env.example", "frontend/.env.example"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(os.path.join(REPO, rel), tmp_path / rel)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # The interpreter running the suite has `cryptography`; the host's may not.
    (bin_dir / "python3").symlink_to(sys.executable)
    _stub_docker(tmp_path, volumes="")
    return tmp_path


def _stub_docker(root, volumes):
    docker = root / "bin" / "docker"
    docker.write_text(f'#!/bin/sh\n[ "$1 $2" = "volume ls" ] && printf "{volumes}"\nexit 0\n')
    docker.chmod(0o755)


def run(root, *args):
    env = {**os.environ, "PATH": f"{root / 'bin'}:{os.environ['PATH']}"}
    return subprocess.run(
        ["bash", str(root / "scripts" / "init_env.sh"), *args],
        capture_output=True,
        text=True,
        env=env,
    )


def value(path, key):
    for line in path.read_text().splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1]
    return None


def _b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def test_first_run_writes_both_files_with_one_matching_vapid_pair(tree):
    out = run(tree)
    assert out.returncode == 0, out.stderr

    backend, frontend = tree / "backend" / ".env", tree / "frontend" / ".env"
    assert stat.S_IMODE(backend.stat().st_mode) == 0o600
    priv, pub = value(backend, "VAPID_PRIVATE_KEY"), value(backend, "VAPID_PUBLIC_KEY")
    assert value(frontend, "VITE_VAPID_PUBLIC_KEY") == pub

    # A real pair: the public key is the private scalar's point, uncompressed.
    key = ec.derive_private_key(int.from_bytes(_b64u(priv), "big"), ec.SECP256R1())
    point = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    assert _b64u(pub) == point


def test_a_second_run_changes_nothing(tree):
    assert run(tree).returncode == 0
    before = {p: (tree / p).read_bytes() for p in ("backend/.env", "frontend/.env")}
    assert run(tree).returncode == 0
    assert {p: (tree / p).read_bytes() for p in before} == before


def test_an_existing_volume_stops_the_first_run_and_names_the_ways_out(tree):
    _stub_docker(tree, volumes="kryptolog_kryptolog-pgdata\\n")
    out = run(tree)
    assert out.returncode == 1
    assert "kryptolog_kryptolog-pgdata" in out.stderr
    assert "--adopt-volume" in out.stderr and "down -v" in out.stderr
    # Written anyway: --adopt-volume needs the new password to adopt.
    assert value(tree / "backend" / ".env", "POSTGRES_PASSWORD")


def test_vapid_fills_an_older_env_and_never_replaces_a_pair(tree):
    assert run(tree).returncode == 0
    backend, frontend = tree / "backend" / ".env", tree / "frontend" / ".env"
    for path, keys in (
        (backend, ("VAPID_PRIVATE_KEY", "VAPID_PUBLIC_KEY")),
        (frontend, ("VITE_VAPID_PUBLIC_KEY",)),
    ):
        text = path.read_text()
        for key in keys:
            text = text.replace(f"{key}={value(path, key)}", f"{key}=")
        path.write_text(text)

    assert run(tree, "--vapid").returncode == 0
    pub = value(backend, "VAPID_PUBLIC_KEY")
    assert pub and value(frontend, "VITE_VAPID_PUBLIC_KEY") == pub

    assert run(tree, "--vapid").returncode == 0
    assert value(backend, "VAPID_PUBLIC_KEY") == pub


def test_half_a_pair_is_refused_rather_than_completed(tree):
    assert run(tree).returncode == 0
    backend = tree / "backend" / ".env"
    priv = value(backend, "VAPID_PRIVATE_KEY")
    backend.write_text(
        backend.read_text().replace(f"VAPID_PRIVATE_KEY={priv}", "VAPID_PRIVATE_KEY=")
    )
    out = run(tree, "--vapid")
    assert out.returncode == 1
    assert "half a VAPID pair" in out.stderr


def test_a_mismatched_frontend_key_is_reported_not_overwritten(tree):
    assert run(tree).returncode == 0
    frontend = tree / "frontend" / ".env"
    text = frontend.read_text()
    frontend.write_text(
        text.replace(
            f"VITE_VAPID_PUBLIC_KEY={value(frontend, 'VITE_VAPID_PUBLIC_KEY')}",
            "VITE_VAPID_PUBLIC_KEY=someone-elses-key",
        )
    )
    out = run(tree)
    assert out.returncode == 0
    assert "differs" in out.stderr
    assert value(frontend, "VITE_VAPID_PUBLIC_KEY") == "someone-elses-key"
