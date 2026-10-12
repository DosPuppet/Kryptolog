"""Every route documents itself (audit 2026-10-12; 2026-09-23 Q-7).

FastAPI publishes a handler's docstring as its OpenAPI description, so an
undocumented route is a blank entry in `/docs` — which is how 37 of 44 routes
looked. Production turns `/docs` off; development and integrators still read it.
"""

import inspect

from test_input_bounds import _api_routes

import main


def test_every_route_has_a_docstring():
    missing = sorted(
        f"{sorted(r.methods)[0]} {r.path}"
        for r in _api_routes(main.app.routes)
        if not inspect.getdoc(r.endpoint)
    )
    assert not missing, f"undocumented routes: {missing}"
