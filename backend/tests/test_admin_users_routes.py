"""P11-T02: what `web/routers/admin_users.py` is, without a database (the behaviour is in
`test_admin_users.py`, on a scratch database).

The role gate is the security property of the module, so it is read off the router itself: every
route carries `require_role("admin")` and nothing else answers the five paths. This file runs in
`make test`, not only in the database suite.
"""

from __future__ import annotations

import inspect

from app.web import main
from app.web.routers import admin_users


def test_the_constants_the_card_names():
    assert admin_users.PASSWORD_MIN_CHARS == 12
    assert admin_users.USERNAME_RE == r"^[a-z0-9._-]{3,32}$"


def test_the_routes_are_these_five_and_every_one_needs_the_admin_role():
    methods = {(m, r.path) for r in admin_users.router.routes for m in r.methods}
    assert methods == {
        ("GET", "/api/admin/users"),
        ("POST", "/api/admin/users"),
        ("PATCH", "/api/admin/users/{user_id}"),
        ("POST", "/api/admin/users/{user_id}/password"),
        ("POST", "/api/admin/users/{user_id}/unlock"),
    }
    for route in admin_users.router.routes:
        gates = [
            call
            for call in (dep.call for dep in route.dependant.dependencies)
            if getattr(call, "__qualname__", "").startswith("require_role.")
        ]
        assert len(gates) == 1, route.path
        assert inspect.getclosurevars(gates[0]).nonlocals["roles"] == ("admin",), route.path
    mounted = main.app.openapi()["paths"]
    assert set(mounted["/api/admin/users"]) == {"get", "post"}
    assert set(mounted["/api/admin/users/{user_id}"]) == {"patch"}
    assert set(mounted["/api/admin/users/{user_id}/password"]) == {"post"}
    assert set(mounted["/api/admin/users/{user_id}/unlock"]) == {"post"}
