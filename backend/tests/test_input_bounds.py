"""Every input the API accepts carries a size bound (audit 2026-09-23 Q-4, M-3).

`schemas.py` bounds its fields one decision at a time, and that is how
`SecretBase.type` was missed: the one free-text field on a model whose other
fields were all capped. It took four megabytes, stored them, and returned them
in every list response — undoing the audit O-3 work on list sizes, and reaching
other users through the shared and multisig lists (M-3).

So this does not list fields. It walks every request body model the app
actually routes to, recursively, and fails on any `str`, `list` or `dict` that
has no `max_length` — at the field AND inside containers, because a bounded
`list[str]` of unbounded strings is still unbounded. A Literal is bounded by
definition. Same idea as test_wire_datetimes.py: a gate a new field cannot
quietly slip past.
"""

import types
import typing

import annotated_types
import pytest
from conftest import TEST_USER_ADDRESS, identity_key_of
from fastapi.routing import APIRoute
from pydantic import BaseModel
from pydantic.fields import FieldInfo
from sqlalchemy.exc import IntegrityError

import main
import models

_SCALARS = (int, float, bool, type(None))


def _has_max_len(metadata) -> bool:
    for m in metadata:
        if isinstance(m, annotated_types.MaxLen) or getattr(m, "max_length", None) is not None:
            return True
        # `Annotated[str, Field(max_length=...)]` keeps its constraint INSIDE the
        # FieldInfo's own metadata, which is how schemas.Address is spelled.
        if isinstance(m, FieldInfo) and _has_max_len(m.metadata):
            return True
    return False


def _unwrap(tp):
    """(inner type, metadata) with Annotated peeled off."""
    if typing.get_origin(tp) is typing.Annotated:
        inner, *meta = typing.get_args(tp)
        return inner, list(meta)
    return tp, []


def _problems(tp, where, metadata, seen):
    tp, inner_meta = _unwrap(tp)
    metadata = list(metadata) + inner_meta
    origin = typing.get_origin(tp)

    if origin in (typing.Union, types.UnionType):
        for arg in typing.get_args(tp):
            if arg is not type(None):
                yield from _problems(arg, where, metadata, seen)
        return
    if origin is typing.Literal or tp in _SCALARS:
        return
    if tp is str:
        if not _has_max_len(metadata):
            yield f"{where}: unbounded str"
        return
    if origin in (list, set, tuple, dict):
        if not _has_max_len(metadata):
            yield f"{where}: unbounded {origin.__name__}"
        for i, arg in enumerate(typing.get_args(tp)):
            if arg is not Ellipsis:
                yield from _problems(arg, f"{where}[{i}]", [], seen)
        return
    if isinstance(tp, type) and issubclass(tp, BaseModel):
        if tp in seen:
            return
        seen.add(tp)
        for name, field in tp.model_fields.items():
            yield from _problems(field.annotation, f"{tp.__name__}.{name}", field.metadata, seen)
        return
    yield f"{where}: unrecognised type {tp!r} — teach this test about it"


def _api_routes(routes):
    """Every APIRoute, including those of included routers.

    FastAPI >= 0.143 no longer flattens `include_router` into `app.routes`: it
    keeps an included-router entry whose `original_router` holds the real
    routes. Walking only the top level found nothing at all — which the test
    below exists to notice, and did.
    """
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from _api_routes(inner.routes)


def _body_models():
    for route in _api_routes(main.app.routes):
        if route.body_field is not None:
            yield route.path, route.body_field.field_info.annotation


def test_every_request_body_field_is_bounded():
    problems = []
    seen = set()
    for path, model in _body_models():
        problems.extend(f"{path} {p}" for p in _problems(model, model.__name__, [], seen))
    assert not problems, "inputs without a size bound:\n" + "\n".join(sorted(set(problems)))


def test_the_walk_reaches_the_models_it_exists_for():
    """A walker that silently found nothing would pass the test above."""
    names = {getattr(m, "__name__", str(m)) for _, m in _body_models()}
    assert {"SecretCreate", "MultisigWorkflowCreate", "AccessGrantCreate"} <= names


def test_the_walk_catches_a_nested_unbounded_string():
    class Inner(BaseModel):
        ok: typing.Annotated[str, annotated_types.MaxLen(5)]
        loose: list[str] = []

    found = list(_problems(Inner, "Inner", [], set()))
    assert "Inner.loose: unbounded list" in found
    assert "Inner.loose[0]: unbounded str" in found
    assert not any(f.startswith("Inner.ok") for f in found)


def test_the_database_refuses_an_unknown_secret_type(db_session):
    """The CHECK constraint behind schemas.SecretType (migration d0e1f2a3b4c5):
    a writer that skips the request model still cannot store a label."""

    db_session.add(
        models.User(
            address=TEST_USER_ADDRESS, identity_public_key=identity_key_of(TEST_USER_ADDRESS)
        )
    )
    db_session.commit()
    db_session.add(models.Secret(owner_address=TEST_USER_ADDRESS, name="n", type="x" * 10))
    with pytest.raises(IntegrityError):
        db_session.commit()


def test_a_secret_type_outside_the_three_is_a_422(client, user1):
    token, _ = user1
    r = client.post(
        "/secrets",
        json={"name": "n", "type": "x" * 4096, "encrypted_data": "d", "encrypted_key": "k"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 422


def test_share_expiry_must_be_positive(client, user1, user2):
    """0 is falsy and made a grant PERMANENT; a negative value made one born
    expired (audit 2026-09-11 Q-3). None still means "no expiry"."""
    token, _ = user1
    _, other = user2
    headers = {"Authorization": f"Bearer {token}"}
    sid = client.post(
        "/secrets",
        json={"name": "n", "type": "standard", "encrypted_data": "d", "encrypted_key": "k"},
        headers=headers,
    ).json()["id"]

    def share(expires_in):
        body = {"secret_id": sid, "grantee_address": other["address"], "encrypted_key": "w"}
        if expires_in != "omit":
            body["expires_in"] = expires_in
        return client.post("/secrets/share", json=body, headers=headers)

    assert share(0).status_code == 422
    assert share(-60).status_code == 422
    assert share("omit").json()["expires_at"] is None
    assert share(60).json()["expires_at"] is not None
