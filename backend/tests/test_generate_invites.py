"""generate_invites.py must not build a schema Alembic does not know about.

It called Base.metadata.create_all() on a fresh database, which left every table
present and NO revision stamped — so the `alembic upgrade head` that every start
path runs next failed trying to create them again (audit 2026-09-11 F-7). The
test database is exactly that shape (conftest builds it with create_all), which
makes it the right place to prove the script now refuses.
"""

import os
import subprocess
import sys

import pytest

import generate_invites

BACKEND = os.path.join(os.path.dirname(__file__), "..")


def test_an_unstamped_schema_is_not_current():
    assert generate_invites._schema_is_current() is False


def test_the_script_refuses_instead_of_creating_tables(monkeypatch):
    called = []
    monkeypatch.setattr(
        generate_invites.invites, "create_invites", lambda *a, **k: called.append(1)
    )
    monkeypatch.setattr(sys, "argv", ["generate_invites.py", "1"])
    with pytest.raises(SystemExit, match="alembic upgrade head"):
        generate_invites.main()
    assert called == []


def test_the_script_runs_standalone():
    """Importable without the test harness: no stray import of `models.Base`."""
    out = subprocess.run(
        [sys.executable, "-c", "import generate_invites"],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        env={**os.environ},
    )
    assert out.returncode == 0, out.stderr
