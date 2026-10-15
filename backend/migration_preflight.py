"""What serve.sh and start_all.sh check before `alembic upgrade head`.

Two failures used to surface only from inside the migration step, where they
read as something else:

* **The database is not up yet.** At boot, `pm2 resurrect` starts the backend
  as soon as it can, often before Docker has Postgres healthy. The migration
  then failed, PM2 retried five times in about thirty seconds
  (`max_restarts`), and gave up — with nothing saying why, on an install that
  had looked fine until its first reboot. `wait_for_database` waits instead.
  A wrong password is answered at once rather than waited on: it is the usual
  sign of a backend/.env generated next to an older Postgres volume, which no
  amount of waiting fixes.
* **An update needs an empty database.** The crypto-core 4.0.0 and 5.0.0
  cutovers refuse to run over identities. The refusal rolled back cleanly,
  but it arrived as a traceback halfway through `alembic upgrade head`, after
  the backup the operator may not have made. `blocking_revisions` names them
  before anything runs.

A revision declares the second by setting `REQUIRES_EMPTY_DATABASE = True` at
module level. Its own refusal stays, as the last line of defence.

    python migration_preflight.py [--wait SECONDS]

Exit status: 0 ready to migrate, 1 database unreachable, 2 this update needs an
empty database.
"""

import argparse
import os
import sys
import time

from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.util import CommandError
from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError

BACKEND = os.path.dirname(os.path.abspath(__file__))


def _scripts() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(os.path.join(BACKEND, "alembic.ini")))


def _is_auth_failure(exc: OperationalError) -> bool:
    return "password authentication failed" in str(exc.orig or exc)


def wait_for_database(engine, timeout: float, sleep=time.sleep, clock=time.monotonic):
    """None once the database answers, else the last error after `timeout`."""
    deadline = clock() + timeout
    announced = False
    while True:
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return None
        except OperationalError as exc:
            if _is_auth_failure(exc) or clock() >= deadline:
                return exc
            if not announced:
                print(f"Waiting up to {int(timeout)}s for the database...", flush=True)
                announced = True
            sleep(1)


def blocking_revisions(connection, scripts: ScriptDirectory | None = None):
    """Pending revisions that refuse a populated database, and how populated it is.

    Returns `([], 0)` when nothing pending needs an empty database, or when the
    database holds no identity — those revisions then run as normal.
    """
    scripts = scripts or _scripts()
    current = MigrationContext.configure(connection).get_current_heads()
    try:
        applied = {
            rev.revision for head in current for rev in scripts.iterate_revisions(head, "base")
        }
    except CommandError:
        # A revision this checkout does not know: the database is newer than
        # the code. `alembic upgrade` says so in its own words.
        return [], 0
    pending = [s for s in scripts.walk_revisions() if s.revision not in applied]
    blockers = [s for s in pending if getattr(s.module, "REQUIRES_EMPTY_DATABASE", False)]
    if not blockers or not inspect(connection).has_table("users"):
        return [], 0
    identities = connection.execute(text("SELECT count(*) FROM users")).scalar()
    return (blockers, identities) if identities else ([], 0)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--wait", type=float, default=0, help="seconds to wait for the database")
    args = parser.parse_args(argv)

    from database import SQLALCHEMY_DATABASE_URL, engine

    error = wait_for_database(engine, args.wait)
    if error is not None:
        print("ERROR: the database is unreachable — refusing to migrate.", file=sys.stderr)
        print(f"  {str(error.orig or error).strip().splitlines()[0]}", file=sys.stderr)
        if _is_auth_failure(error):
            print(
                "  backend/.env does not hold this database's password. A Postgres volume\n"
                "  keeps the password it was created with; if backend/.env was generated\n"
                "  after the volume, see `scripts/init_env.sh --adopt-volume`.",
                file=sys.stderr,
            )
        else:
            host = SQLALCHEMY_DATABASE_URL.rsplit("@", 1)[-1]
            print(
                f"  Is it running? ({host})\n"
                "  docker compose --env-file backend/.env up -d postgres redis",
                file=sys.stderr,
            )
        return 1

    with engine.connect() as conn:
        blockers, identities = blocking_revisions(conn)
    if blockers:
        print("ERROR: this update cannot be applied to this database.", file=sys.stderr)
        print(
            f"  It holds {identities} identities, and these pending revisions require an"
            " empty database:",
            file=sys.stderr,
        )
        for s in blockers:
            print(f"    {s.revision}  {s.doc.strip().splitlines()[0]}", file=sys.stderr)
        print(
            "  Nothing has been changed. Back up first (scripts/backup.sh), then follow\n"
            '  DEPLOYMENT.md, "Deploying an update".',
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
