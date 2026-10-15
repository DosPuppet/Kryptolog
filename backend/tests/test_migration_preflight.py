"""The check serve.sh and start_all.sh run before `alembic upgrade head`.

Found by a real install (2026-10-15): after a reboot PM2 started the backend
before Docker had Postgres up, the migration failed five times in thirty
seconds and PM2 gave up; and an update needing an empty database was refused
only halfway through `alembic upgrade head`. The test database is built with
create_all and never stamped, so every revision is pending on it — which is
exactly the shape that lets the second case be shown both ways.
"""

import glob
import os
import subprocess
import sys

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

import migration_preflight
from tests.conftest import engine

BACKEND = os.path.join(os.path.dirname(__file__), "..")
CUTOVERS = {"b4c5d6e7f8a9", "c5d6e7f8a9b0"}


def _blocking():
    with engine.connect() as conn:
        blockers, identities = migration_preflight.blocking_revisions(conn)
    return {s.revision for s in blockers}, identities


def test_an_empty_database_is_never_blocked():
    assert _blocking() == (set(), 0)


def test_identities_block_the_pending_cutovers(user1):
    assert _blocking() == (CUTOVERS, 1)


def test_cutovers_already_applied_block_nothing(user1):
    head = migration_preflight._scripts().get_current_head()
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE alembic_version (version_num varchar(32) PRIMARY KEY)"))
        conn.execute(text("INSERT INTO alembic_version VALUES (:v)"), {"v": head})
    try:
        assert _blocking() == (set(), 0)
    finally:
        with engine.begin() as conn:
            conn.execute(text("DROP TABLE alembic_version"))


def test_main_refuses_with_the_revisions_named_and_changes_nothing(user1, capsys):
    assert migration_preflight.main([]) == 2
    err = capsys.readouterr().err
    assert "holds 1 identities" in err
    for rev in CUTOVERS:
        assert rev in err
    assert "scripts/backup.sh" in err


def test_every_revision_that_wants_an_empty_database_says_so():
    """A future cutover that refuses identities but forgets the flag would go
    back to interrupting `alembic upgrade` instead of being named up front."""
    declared, mentions = set(), set()
    for path in glob.glob(os.path.join(BACKEND, "alembic", "versions", "*.py")):
        source = open(path, encoding="utf-8").read()
        rev = os.path.basename(path).split("_", 1)[0]
        if "REQUIRES_EMPTY_DATABASE = True" in source:
            declared.add(rev)
        if "empty database" in source.lower():
            mentions.add(rev)
    assert declared == CUTOVERS
    assert mentions <= declared


class _Engine:
    """Fails `failures` times with `error`, then connects."""

    def __init__(self, failures, error):
        self.failures, self.error = failures, error

    def connect(self):
        if self.failures:
            self.failures -= 1
            raise self.error
        return engine.connect()


def _down(message="connection refused"):
    return OperationalError("SELECT 1", {}, Exception(message))


def test_waits_for_a_database_that_comes_up():
    slept = []
    error = migration_preflight.wait_for_database(_Engine(2, _down()), 60, sleep=slept.append)
    assert error is None
    assert len(slept) == 2


def test_gives_up_on_a_database_that_never_comes_up():
    clock = iter(range(0, 1000, 10))
    error = migration_preflight.wait_for_database(
        _Engine(10**6, _down()), 30, sleep=lambda _: None, clock=lambda: next(clock)
    )
    assert isinstance(error, OperationalError)


def test_a_wrong_password_is_not_waited_on(capsys, monkeypatch):
    """No amount of waiting fixes it, and it has a known cause worth naming."""
    slept = []
    wrong = _Engine(1, _down('password authentication failed for user "kryptolog"'))
    assert migration_preflight.wait_for_database(wrong, 60, sleep=slept.append) is not None
    assert slept == []

    import database

    monkeypatch.setattr(database, "engine", _Engine(1, wrong.error))
    assert migration_preflight.main(["--wait", "60"]) == 1
    assert "--adopt-volume" in capsys.readouterr().err


def test_a_sqlite_url_is_refused_at_import():
    out = subprocess.run(
        [sys.executable, "-c", "import database"],
        cwd=BACKEND,
        capture_output=True,
        text=True,
        env={**os.environ, "DATABASE_URL": "sqlite:///./sql_app.db"},
    )
    assert out.returncode != 0
    assert "SQLite is not supported" in out.stderr
