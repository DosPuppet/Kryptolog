#!/usr/bin/env python3
"""Mint invite codes for the Kryptolog access filter (audit §5).

Seeds admin invite codes directly into the database so the first users can
register when KRYPTOLOG_REQUIRE_INVITE is enabled. Run from the backend dir so
it picks up the same PostgreSQL database the app uses (DATABASE_URL).

Examples:
    python generate_invites.py                 # 1 single-use code, no expiry
    python generate_invites.py 10              # 10 single-use codes
    python generate_invites.py 5 --max-uses 3  # 5 codes, each usable 3 times
    python generate_invites.py 1 --expires-days 7
"""

import argparse

import invites
from database import SessionLocal, engine


def _schema_is_current() -> bool:
    """True when the database is migrated to the newest Alembic revision.

    This script used to call `Base.metadata.create_all()` "to make sure the table
    exists" (audit 2026-09-11 F-7). On a fresh database that built every table
    WITHOUT stamping a revision, so the `alembic upgrade head` that start_all.sh
    and serve.sh run next tried to create them all again and failed — a server
    that refused to start because someone minted an invite first. Invites are
    on by default now (audit 2026-10-12 K-09), which makes this the first thing
    a new deployment runs, so it checks instead of creating.
    """
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory

    heads = set(ScriptDirectory.from_config(Config("alembic.ini")).get_heads())
    with engine.connect() as conn:
        current = set(MigrationContext.configure(conn).get_current_heads())
    return current == heads


def main():
    parser = argparse.ArgumentParser(description="Mint Kryptolog invite codes.")
    parser.add_argument(
        "count", nargs="?", type=int, default=1, help="how many codes to mint (default 1)"
    )
    parser.add_argument(
        "--max-uses", type=int, default=1, help="redemptions allowed per code (default 1)"
    )
    parser.add_argument(
        "--expires-days", type=int, default=None, help="days until codes expire (default: never)"
    )
    args = parser.parse_args()

    if not _schema_is_current():
        raise SystemExit(
            "The database is not migrated to the current schema. Run "
            "`alembic upgrade head` (start_all.sh and serve.sh do) and try again."
        )

    db = SessionLocal()
    try:
        codes = invites.create_invites(
            db,
            count=args.count,
            created_by=None,  # admin-seeded
            max_uses=args.max_uses,
            expires_in_days=args.expires_days,
        )
    finally:
        db.close()

    suffix = []
    if args.max_uses != 1:
        suffix.append(f"max_uses={args.max_uses}")
    if args.expires_days is not None:
        suffix.append(f"expires in {args.expires_days}d")
    meta = (" (" + ", ".join(suffix) + ")") if suffix else ""

    print(f"# Minted {len(codes)} invite code(s){meta}:")
    for code in codes:
        print(code)


if __name__ == "__main__":
    main()
