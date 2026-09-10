"""The naive-UTC datetime convention, pinned.

Every DateTime column is declared without `timezone=True`, so storing an aware
value relies on Postgres silently dropping the offset, and comparing a naive
column against an aware parameter is resolved using the session TimeZone rather
than UTC. Both worked only because the offset happened to be zero.

These tests fail if a writer goes back to `datetime.now(UTC)`.
"""

import inspect
from datetime import UTC, datetime, timedelta, timezone

import models
from utils.clock import as_naive_utc, utcnow_naive


def test_utcnow_naive_is_naive_and_current():
    now = utcnow_naive()
    assert now.tzinfo is None
    assert abs((now - datetime.now(UTC).replace(tzinfo=None)).total_seconds()) < 5


def test_as_naive_utc_converts_offsets_rather_than_truncating():
    aware = datetime(2026, 9, 10, 12, 0, tzinfo=timezone(timedelta(hours=5)))
    assert as_naive_utc(aware) == datetime(2026, 9, 10, 7, 0)
    assert as_naive_utc(datetime(2026, 9, 10, 7, 0)) == datetime(2026, 9, 10, 7, 0)
    assert as_naive_utc(None) is None
    assert as_naive_utc(datetime.now(UTC)).tzinfo is None


def test_every_datetime_column_default_writes_naive():
    """No column may default to an aware value.

    Thirteen of them did, via `default=lambda: datetime.now(UTC)`.
    """
    offenders = []
    for mapper in models.Base.registry.mappers:
        for column in mapper.persist_selectable.columns:
            default = getattr(column.default, "arg", None)
            if default is None or not callable(default):
                continue
            try:
                value = default({}) if len(inspect.signature(default).parameters) else default()
            except TypeError:
                continue
            if isinstance(value, datetime) and value.tzinfo is not None:
                offenders.append(f"{column.table.name}.{column.name}")
    assert not offenders, f"aware default on naive DateTime column(s): {offenders}"


def test_stored_timestamps_read_back_naive(client, user1):
    """End to end: a row written through the API comes back naive."""
    token, _ = user1
    resp = client.post(
        "/secrets",
        json={
            "name": "clock",
            "type": "standard",
            "encrypted_data": "x",
            "encrypted_key": "k",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text

    from database import SessionLocal

    db = SessionLocal()
    try:
        row = db.query(models.Secret).filter_by(id=resp.json()["id"]).one()
        assert row.created_at.tzinfo is None
    finally:
        db.close()
