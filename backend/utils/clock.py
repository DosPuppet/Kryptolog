"""The project's single naive-UTC clock.

Every `DateTime` column in models.py is declared without `timezone=True`, so
Postgres stores `timestamp without time zone` and reads back a naive value.
Writers, however, were split: column defaults and four routers built an aware
`datetime.now(UTC)`, while `authorization`, `invites` and `transfers` each kept
their own naive helper. Three spellings of "now" for one convention.

The aware halves worked by accident. Postgres drops the offset when an aware
value lands in a naive column, and the offset was always UTC — but a comparison
between a naive column and an aware parameter is resolved using the *session*
TimeZone, so an expiry check was correct only as long as the server ran in UTC.

This module lives under utils/ rather than security/ because models.py needs it
too, and security/authorization.py already imports models.
"""

from datetime import UTC, datetime


def utcnow_naive() -> datetime:
    """Current UTC as a naive datetime, matching the DateTime columns."""
    return datetime.now(UTC).replace(tzinfo=None)


def as_naive_utc(value: datetime | None) -> datetime | None:
    """Normalise a possibly-aware datetime to naive UTC for comparison.

    Rows read back are naive; a value that has just been built by a caller may
    still be aware. Comparing the two forms raises TypeError in Python and
    silently consults the session TimeZone in SQL, so both are funnelled here.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def to_wire_utc(value: datetime | None) -> str | None:
    """Render a stored datetime for the wire, with an explicit UTC offset.

    Naive is right in the database and wrong on the wire. `datetime.isoformat()`
    on a naive value emits no offset — `2026-09-10T15:06:06.550478` — and
    ECMA-262 parses that form as LOCAL time, so every non-UTC browser reads back
    an instant shifted by its own offset.

    Found by the manual pass on the grant-expiry feature, where the shift was
    not cosmetic: an hour-long share rendered "Expired" in a UTC+2 browser while
    the server went on honouring it, which reads as a broken security control
    rather than a broken clock.

    Lives here, next to the writers, because the readers are split — Pydantic
    response models go through schemas.UtcDateTime, and the four hand-built
    WebSocket payloads (which never touch a response model) call this directly.
    Two renderings of one convention is how the halves drift apart.
    """
    if value is None:
        return None
    return (value.replace(tzinfo=UTC) if value.tzinfo is None else value).isoformat()
