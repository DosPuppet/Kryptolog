#!/usr/bin/env python3
"""Mint invite codes for the Kryptolog access filter (audit §5).

Seeds admin invite codes directly into the database so the first users can
register when KRYPTOLOG_REQUIRE_INVITE is enabled. Run from the backend dir so
it picks up the same SQLite DB the app uses.

Examples:
    python generate_invites.py                 # 1 single-use code, no expiry
    python generate_invites.py 10              # 10 single-use codes
    python generate_invites.py 5 --max-uses 3  # 5 codes, each usable 3 times
    python generate_invites.py 1 --expires-days 7
"""
import argparse

from database import SessionLocal
from models import Base
from database import engine
import invites


def main():
    parser = argparse.ArgumentParser(description="Mint Kryptolog invite codes.")
    parser.add_argument("count", nargs="?", type=int, default=1, help="how many codes to mint (default 1)")
    parser.add_argument("--max-uses", type=int, default=1, help="redemptions allowed per code (default 1)")
    parser.add_argument("--expires-days", type=int, default=None, help="days until codes expire (default: never)")
    args = parser.parse_args()

    # Make sure the table exists even on a fresh DB the app hasn't migrated yet.
    Base.metadata.create_all(bind=engine)

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
