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
