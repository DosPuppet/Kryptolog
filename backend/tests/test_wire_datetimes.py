"""Every datetime the API emits must carry an explicit UTC offset.

The columns are naive UTC (test_clock.py pins that end), and Pydantic renders a
naive value with no offset at all. ECMA-262 parses *that* form as local time, so
`new Date(grant.expires_at)` in a UTC+2 browser lands two hours before the
instant the server stored.

Found by the manual pass, and it did not look like a clock bug: a share with an
hour left rendered "Expired" in the owner's UI while the grantee kept their
access, because the server was still — correctly — honouring the grant. A
timezone bug that only moves a display is invisible; one that moves a display of
an *expiry* reads as a broken security feature.

These tests cover both halves: the convention holds for every field today, and
it still parses to the right instant from a non-UTC browser.
"""

import inspect
import json
import warnings
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import BaseModel

import schemas
from utils.clock import to_wire_utc, utcnow_naive

# The wire value for a known naive-UTC instant, as the serializer should render
# it. Written out rather than derived, so a change to to_wire_utc has to be
# made deliberately here too.
INSTANT = datetime(2026, 9, 10, 15, 6, 6, 550478)
EXPECTED = "2026-09-10T15:06:06.550478+00:00"


def _response_models():
    """Every Pydantic model in schemas.py, with the field names it declares."""
    for name, obj in vars(schemas).items():
        if inspect.isclass(obj) and issubclass(obj, BaseModel) and obj is not BaseModel:
            yield name, obj


def test_no_schema_field_serializes_a_bare_datetime():
    """The drift gate: a new `created_at: datetime` fails here, not in a browser.

    Checked by serializing rather than by reading the annotation, so aliasing
    `UtcDateTime` or hand-rolling a field_serializer both pass — what matters is
    the bytes on the wire, not how the field was spelled.
    """
    offenders = []
    for name, model in _response_models():
        for field_name, field in model.model_fields.items():
            annotation = str(field.annotation)
            if "datetime" not in annotation:
                continue
            rendered = _render(model, field_name)
            if rendered is not None and not _has_offset(rendered):
                offenders.append(f"{name}.{field_name} -> {rendered!r}")

    assert not offenders, (
        "datetime field(s) serialized with no UTC offset: "
        f"{offenders}. Annotate with schemas.UtcDateTime — a naive ISO string is "
        "parsed as LOCAL time by every browser."
    )


def _render(model, field_name):
    """Serialize one field of the real model holding INSTANT.

    `model_construct` skips validation so a single field can be set without
    building every sibling, and `include` narrows the dump to it. Going through
    the actual model matters: Pydantic flattens `Annotated` into the field's
    core schema, so probing `field.annotation` in a throwaway model loses the
    serializer and reports every field as broken.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # model_construct leaves siblings unset
        dumped = model.model_construct(**{field_name: INSTANT}).model_dump_json(
            include={field_name}
        )
    return json.loads(dumped).get(field_name)


def _has_offset(rendered) -> bool:
    return isinstance(rendered, str) and (rendered.endswith("Z") or rendered[-6] in "+-")


def test_no_router_hand_renders_a_datetime():
    """The other half of the surface: payloads that never see a response model.

    Four WebSocket pushes built their JSON by hand and called `.isoformat()` on
    a naive column value, so the live-update path carried the same shift as the
    REST path — a message arriving over the socket rendered at the wrong local
    time until a refetch replaced it. A response-model-only fix would have left
    them broken, and nothing about them looks like a datetime bug at a glance.
    """
    offenders = []
    for path in (Path(__file__).resolve().parent.parent / "routers").glob("*.py"):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if ".isoformat()" in line and not line.lstrip().startswith("#"):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")

    assert not offenders, (
        f"router(s) rendering a datetime by hand: {offenders}. Use "
        "utils.clock.to_wire_utc — a bare .isoformat() on a naive column emits "
        "no offset, and the client reads it as local time."
    )


def test_the_serializer_marks_utc_without_shifting_the_instant():
    assert to_wire_utc(INSTANT) == EXPECTED
    assert datetime.fromisoformat(EXPECTED).astimezone(UTC).replace(tzinfo=None) == INSTANT


def test_an_already_aware_value_is_left_alone():
    """Nothing writes one today, but truncating an offset would be a real shift."""
    aware = INSTANT.replace(tzinfo=UTC)
    assert to_wire_utc(aware) == EXPECTED


@pytest.mark.parametrize("offset_hours", [2, -5, 5.5])
def test_a_non_utc_client_reads_back_the_stored_instant(offset_hours):
    """What the browser does with the string, from three timezones.

    The pre-fix value ("...550478", no offset) is what a browser would have read
    as local time; asserting the shift is what makes this test fail if the
    offset is dropped again, rather than just checking a suffix.
    """
    client_tz = timedelta(hours=offset_hours)

    parsed = datetime.fromisoformat(to_wire_utc(INSTANT)).astimezone(UTC).replace(tzinfo=None)
    assert parsed == INSTANT

    naive_wire = INSTANT.isoformat()
    misread = (datetime.fromisoformat(naive_wire) - client_tz).replace(tzinfo=None)
    assert misread != INSTANT
    assert misread == INSTANT - client_tz


def test_a_live_grant_is_not_reported_expired_by_a_utc_plus_2_client(client, user1, user2):
    """The reported bug, end to end.

    An hour-long share, read the way the SPA reads it. Before the fix the client
    computed a negative remaining time and rendered "Expired" while the server
    kept serving the secret — the exact contradiction the manual pass hit.
    """
    token, _ = user1
    _, u2 = user2
    headers = {"Authorization": f"Bearer {token}"}

    secret = client.post(
        "/secrets",
        json={"name": "n", "type": "standard", "encrypted_data": "d", "encrypted_key": "k"},
        headers=headers,
    ).json()

    share = client.post(
        "/secrets/share",
        json={
            "secret_id": secret["id"],
            "grantee_address": u2["address"],
            "encrypted_key": "wrapped",
            "expires_in": 3600,
        },
        headers=headers,
    )
    assert share.status_code == 200, share.text

    wire = share.json()["expires_at"]
    assert _has_offset(wire), f"expiry went out with no offset: {wire!r}"

    # Parsed as an absolute instant, the way `new Date()` treats an offset-
    # bearing string, from a browser two hours ahead of UTC.
    remaining = datetime.fromisoformat(wire) - utcnow_naive().replace(tzinfo=UTC)
    assert timedelta(minutes=55) < remaining <= timedelta(hours=1)

    # And the server agrees it is live, which is the half that was never wrong.
    assert client.get(f"/secrets/{secret['id']}", headers=headers).status_code == 200
