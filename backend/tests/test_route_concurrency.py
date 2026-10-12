"""No route runs synchronous database work on the event loop (audit 2026-09-23 Q-2).

Nine `async def` routes did: FastAPI runs an `async def` body ON the loop, so
every query and commit they made through the sync Session stalled every other
request and every WebSocket on the worker for its duration. A `def` route runs
in a worker thread instead, and those routes now hand their socket frames to
BackgroundTasks, which awaits them on the loop after the response.

The rule this pins: an `async def` endpoint that takes a Session must be one
that moves its database work off the loop itself, and says so here.
"""

import inspect

from sqlalchemy.orm import Session
from test_input_bounds import _api_routes

import main

# Each entry is an async endpoint that takes a Session on purpose, and why.
OFF_LOOP_BY_HAND = {
    # Its whole synchronous core is one run_in_threadpool call (2026-09-12
    # L-4), and the broadcast tail has to await. test_account_deletion pins
    # the threadpool call itself.
    "delete_account",
}


def _takes_a_session(endpoint) -> bool:
    return any(p.annotation is Session for p in inspect.signature(endpoint).parameters.values())


def test_no_async_route_uses_the_sync_session_on_the_loop():
    offenders = sorted(
        route.endpoint.__name__
        for route in _api_routes(main.app.routes)
        if inspect.iscoroutinefunction(route.endpoint)
        and _takes_a_session(route.endpoint)
        and route.endpoint.__name__ not in OFF_LOOP_BY_HAND
    )
    assert not offenders, f"async routes doing sync DB work on the event loop: {offenders}"


def test_the_walk_sees_session_routes_at_all():
    # A check that inspected nothing would pass vacuously.
    assert sum(_takes_a_session(r.endpoint) for r in _api_routes(main.app.routes)) > 30
