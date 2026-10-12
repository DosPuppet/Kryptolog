"""Message retention: delete conversations' history past a configured age.

Nothing was ever deleted (audit 2026-09-11 M-6): messages, and with them the
record of who wrote to whom and when, were kept indefinitely. With
KRYPTOLOG_MESSAGE_RETENTION_DAYS set, DMs and group messages older than that
are purged; unset, nothing changes (config.message_retention_days).

**A session goes as a whole, never in part.** A message is readable only with
the key wrapped into the FIRST message of its session, and age-based deletion
takes the oldest rows first — so cutting at a timestamp would delete a session's
key while later messages under it were still within retention, leaving them on
screen as permanently undecryptable. Instead, an old row is kept while ANY
message of its session — same sender, same `sid` (a session has exactly one
sender since crypto-core 3.0.0) — was sent less than SESSION_GRACE after the
cutoff. Clients retire a session after 24 h (SESSION_MAX_AGE_MS), so the grace
covers every conforming session, and the effective retention is between N days
and N days plus the grace. A client that ignored the rotation could stretch a
session past it; then its oldest rows go first, which is the documented cost of
not following the protocol.

Rows that do not parse, or carry no `sid`, belong to no session and go by age.

Run on a timer by every worker (`run_forever`, started from main's lifespan),
serialized by a PostgreSQL advisory lock so concurrent workers do not repeat
the work. `python retention.py` runs one pass, for cron or a systemd timer.
"""

import asyncio
import json
import logging
from datetime import timedelta

from sqlalchemy import text
from sqlalchemy.orm import Session

import config
import models
from security.audit_log import audit_event
from utils.clock import utcnow_naive

logger = logging.getLogger("kryptolog.retention")

SESSION_GRACE = timedelta(hours=48)
PURGE_INTERVAL_SECONDS = 3600
_BATCH = 500
# Any constant: it names this job's lock among the database's advisory locks.
_ADVISORY_LOCK_ID = 0x6B72_7970_746F  # "krypto"

_MODELS = {"dm": models.Message, "group": models.GroupMessage}


def _session_of(row) -> tuple[str, str] | None:
    try:
        payload = json.loads(row.content)
    except (TypeError, ValueError):
        return None
    sid = payload.get("sid") if isinstance(payload, dict) else None
    return (row.sender_address, sid) if isinstance(sid, str) and sid else None


def purge_expired_messages(db: Session, days: int, now=None) -> dict[str, int]:
    """Delete messages older than `days`, whole sessions at a time. Returns the
    number deleted per kind. Commits."""
    now = now or utcnow_naive()
    cutoff = now - timedelta(days=days)
    deleted = {}
    for kind, model in _MODELS.items():
        # Sessions that are still alive just past the cutoff keep their older
        # rows — above all their first one, which carries the key.
        protected = {
            session
            for row in db.query(model.sender_address, model.content)
            .filter(model.created_at >= cutoff, model.created_at < cutoff + SESSION_GRACE)
            .yield_per(_BATCH)
            if (session := _session_of(row)) is not None
        }
        doomed = [
            row.id
            for row in db.query(model.id, model.sender_address, model.content)
            .filter(model.created_at < cutoff)
            .order_by(model.id)
            .yield_per(_BATCH)
            # A row with no session is never in `protected`: it goes by age.
            if _session_of(row) not in protected
        ]
        for start in range(0, len(doomed), _BATCH):
            db.query(model).filter(model.id.in_(doomed[start : start + _BATCH])).delete(
                synchronize_session=False
            )
        deleted[kind] = len(doomed)
    db.commit()
    return deleted


def run_once(session_factory) -> dict[str, int] | None:
    """One purge, if retention is configured and no other worker holds the lock."""
    days = config.message_retention_days()
    if days is None:
        return None
    db = session_factory()
    try:
        if db.get_bind().dialect.name == "postgresql":
            got = db.execute(
                text("SELECT pg_try_advisory_xact_lock(:id)"), {"id": _ADVISORY_LOCK_ID}
            ).scalar()
            if not got:
                return None  # another worker is on it
        deleted = purge_expired_messages(db, days)
        audit_event("retention.purge", days=days, **{f"deleted_{k}": v for k, v in deleted.items()})
        return deleted
    finally:
        db.close()


async def run_forever(session_factory) -> None:
    """The lifespan task: one pass at start-up, then every PURGE_INTERVAL_SECONDS.
    A failed pass is logged and retried at the next interval."""
    from starlette.concurrency import run_in_threadpool

    while True:
        try:
            await run_in_threadpool(run_once, session_factory)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "Message retention pass failed; retrying in %ss", PURGE_INTERVAL_SECONDS
            )
        await asyncio.sleep(PURGE_INTERVAL_SECONDS)


if __name__ == "__main__":
    from database import SessionLocal
    from security import audit_log

    logging.basicConfig(level=logging.INFO)
    audit_log.configure()
    result = run_once(SessionLocal)
    print("retention not configured" if result is None else f"deleted: {result}")
