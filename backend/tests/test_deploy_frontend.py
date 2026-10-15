"""scripts/deploy_frontend.sh, run for real against a stub `npm`.

The stub records the environment the build ran with and writes a dist/ the
way vite would, so these pin what the script derives from backend/.env, that
the build is strict, and that backend secrets never reach npm — whose package
install scripts run with whatever environment it is given.
"""

import os
import shutil
import subprocess

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

NPM = """#!/bin/sh
[ "$1" = "run" ] || exit 0
env > "$STUB_LOG"
mkdir -p dist/assets
echo "<html>${STUB_BUNDLE_API:-$VITE_API_BASE_URL}</html>" > dist/index.html
echo "x" > dist/assets/new.js
"""

ENV = """\
KRYPTOLOG_JWT_SECRET=jwt-secret-must-not-leak
DATABASE_URL=postgresql+psycopg://kryptolog:db-password-must-not-leak@localhost/k
ALLOWED_ORIGINS=https://kryptolog.example.com, https://other.example.com
VAPID_PRIVATE_KEY=vapid-private-must-not-leak
VAPID_PUBLIC_KEY=BPUBLIC
"""


@pytest.fixture()
def tree(tmp_path):
    for rel in ("scripts/deploy_frontend.sh", "scripts/load_env.sh"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(os.path.join(REPO, rel), tmp_path / rel)
    for rel in ("packages/crypto-core", "frontend", "bin"):
        (tmp_path / rel).mkdir(parents=True)
    npm = tmp_path / "bin" / "npm"
    npm.write_text(NPM)
    npm.chmod(0o755)
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / ".env").write_text(ENV)
    web = tmp_path / "www"
    web.mkdir()
    (web / "stale.js").write_text("old")
    return tmp_path


def run(root, **env):
    full = {
        **{k: v for k, v in os.environ.items() if not k.startswith(("KRYPTOLOG_", "VITE_"))},
        "PATH": f"{root / 'bin'}:{os.environ['PATH']}",
        "STUB_LOG": str(root / "npm-env"),
        "KRYPTOLOG_WEB_ROOT": str(root / "www"),
        **env,
    }
    return subprocess.run(
        ["bash", str(root / "scripts" / "deploy_frontend.sh")],
        capture_output=True,
        text=True,
        env=full,
    )


def build_env(root):
    return dict(
        line.split("=", 1) for line in (root / "npm-env").read_text().splitlines() if "=" in line
    )


def test_builds_strict_from_backend_env_and_publishes(tree):
    out = run(tree)
    assert out.returncode == 0, out.stderr

    env = build_env(tree)
    assert env["VITE_API_BASE_URL"] == "https://kryptolog.example.com/api"
    assert env["VITE_VAPID_PUBLIC_KEY"] == "BPUBLIC"
    assert env["KRYPTOLOG_STRICT_BUILD"] == "1"

    web = tree / "www"
    assert "kryptolog.example.com/api" in (web / "index.html").read_text()
    assert (web / "assets" / "new.js").exists()
    assert not (web / "stale.js").exists()


def test_no_backend_secret_reaches_npm(tree):
    assert run(tree).returncode == 0
    dump = (tree / "npm-env").read_text()
    assert "must-not-leak" not in dump


def test_an_explicit_api_url_wins(tree):
    out = run(tree, KRYPTOLOG_PUBLIC_API_URL="https://api.example.com")
    assert out.returncode == 0, out.stderr
    assert build_env(tree)["VITE_API_BASE_URL"] == "https://api.example.com"


def test_half_a_vapid_pair_is_refused_before_building(tree):
    env_file = tree / "backend" / ".env"
    env_file.write_text(
        env_file.read_text().replace("VAPID_PUBLIC_KEY=BPUBLIC", "VAPID_PUBLIC_KEY=")
    )
    out = run(tree)
    assert out.returncode == 1
    assert "no VAPID_PUBLIC_KEY" in out.stderr
    assert not (tree / "npm-env").exists()


def test_a_published_localhost_bundle_fails_the_deploy(tree):
    out = run(tree, STUB_BUNDLE_API="http://localhost:8000")
    assert out.returncode == 1
    assert "localhost:8000" in out.stderr
