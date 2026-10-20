"""P11-T20 part 4, finding M2 — every `/api/admin/*` route of the app is behind `require_role("admin")`.

Each admin module has a test that lists its own routes and finds the guard on them (users, llm,
overview, digest, audit, labels), and two had none: `admin_rules.py` (`/api/admin/rules*`) and
the inventory reload in `web/main.py`. A new module under `routers/` that forgets its guard
would equally pass every existing test. This one test walks the whole app:

- the routes of every router `iter_routers()` finds, and `main.app`'s own routes. FastAPI 0.141
  keeps an included router as one lazy node in `app.routes`, so `app.routes` alone lists neither
  the routers' routes nor, therefore, what is wrong with them: the routers are walked, not it;
- each route whose path starts with `/api/admin/` must carry, anywhere in its dependency tree
  (the decorator's `dependencies=[...]` and every parameter, sub-dependencies included), a
  dependency that IS `require_role("admin")`: the function `require_role` returns, whose closure
  holds `roles == ("admin",)`. A guard for another role (`require_role("tier1")`, or
  `("admin", "tier1")`), a route that only reads the user (`current_user`), and a guard in name
  only are all refused;
- the set of routes it walked is the set the OpenAPI document lists under `/api/admin/`, so a
  route mounted by some path the walk does not take (another `include_router`, a mount) cannot
  hide from it.

No database: the dependencies are inspected, never called.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from app.web import deps, main
from app.web.routers import iter_routers
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

ADMIN_PREFIX = "/api/admin/"
METHODS_NOT_LISTED = {"HEAD", "OPTIONS"}


def _routes() -> list[APIRoute]:
    """Every API route of the app: the routers' (`iter_routers()`), then `main.app`'s own."""
    found: list[APIRoute] = []
    for router in iter_routers():
        found += [r for r in router.routes if isinstance(r, APIRoute)]
    found += [r for r in main.app.routes if isinstance(r, APIRoute)]
    return found


def _admin_routes() -> list[APIRoute]:
    return [r for r in _routes() if r.path.startswith(ADMIN_PREFIX)]


def _calls(dependant: Dependant) -> Iterator[Callable[..., Any]]:
    """Every callable in a dependency tree, the route's own dependencies and theirs."""
    for sub in dependant.dependencies:
        if sub.call is not None:
            yield sub.call
        yield from _calls(sub)


def _roles_of(call: Callable[..., Any]) -> tuple[str, ...] | None:
    """The `roles` of a dependency made by `require_role(*roles)`, or `None` for anything else.
    `require_role` returns a closure over `roles`; that closure is what is looked for, by its
    qualified name and by the cell it holds, not by the name of a variable in some module."""
    code = getattr(call, "__code__", None)
    closure = getattr(call, "__closure__", None)
    if code is None or closure is None or call.__qualname__ != "require_role.<locals>.dependency":
        return None
    cells = dict(zip(code.co_freevars, (cell.cell_contents for cell in closure), strict=True))
    roles = cells.get("roles")
    return tuple(roles) if roles is not None else None


def _guarded_for_admin(route: APIRoute) -> bool:
    return any(_roles_of(call) == ("admin",) for call in _calls(route.dependant))


def _pairs(routes: list[APIRoute]) -> set[tuple[str, str]]:
    return {
        (method, route.path)
        for route in routes
        for method in route.methods
        if method not in METHODS_NOT_LISTED
    }


# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------


def test_every_api_admin_route_carries_require_role_admin() -> None:
    unguarded = sorted(
        f"{','.join(sorted(r.methods))} {r.path}"
        for r in _admin_routes()
        if not _guarded_for_admin(r)
    )
    assert (
        unguarded == []
    ), f"routes under {ADMIN_PREFIX} with no require_role('admin'): {unguarded}"


def test_the_walk_finds_the_routes_it_is_there_for() -> None:
    """The walk is not vacuous: it reaches the modules that had no test of their own (rules) and
    the route kept in `web/main.py`, as well as one of each of the others."""
    found = _pairs(_admin_routes())
    for pair in {
        ("GET", "/api/admin/rules"),
        ("POST", "/api/admin/rules"),
        ("PATCH", "/api/admin/rules"),
        ("POST", "/api/admin/rules/simulate"),
        ("POST", "/api/admin/reload-inventory"),
        ("GET", "/api/admin/overview"),
        ("POST", "/api/admin/jobs/{job_id}/retry"),
        ("GET", "/api/admin/audit"),
        ("GET", "/api/admin/digest"),
        ("GET", "/api/admin/llm/usage"),
        ("PUT", "/api/admin/llm/limits"),
        ("GET", "/api/admin/labels/next"),
        ("GET", "/api/admin/users"),
    }:
        assert pair in found, f"the walk does not reach {pair}"


def test_the_walk_reaches_exactly_the_routes_the_openapi_document_lists() -> None:
    """Nothing under `/api/admin/` is mounted by a path this walk does not take."""
    listed = {
        (method.upper(), path)
        for path, item in main.app.openapi()["paths"].items()
        if path.startswith(ADMIN_PREFIX)
        for method in item
    }
    assert _pairs(_admin_routes()) == listed


def test_a_route_of_the_main_module_is_walked_beside_the_routers() -> None:
    own = [
        r for r in main.app.routes if isinstance(r, APIRoute) and r.path.startswith(ADMIN_PREFIX)
    ]
    assert [r.path for r in own] == ["/api/admin/reload-inventory"]
    assert _guarded_for_admin(own[0])


# ---------------------------------------------------------------------------
# The detector itself: what it accepts and what it refuses
# ---------------------------------------------------------------------------


def _route_with(*dependencies: Callable[..., Any], param: Callable[..., Any] | None = None):
    from fastapi import APIRouter, Depends

    router = APIRouter()

    if param is None:

        @router.get("/api/admin/x", dependencies=[Depends(d) for d in dependencies])
        def handler() -> dict:
            return {}

    else:

        @router.get("/api/admin/x", dependencies=[Depends(d) for d in dependencies])
        def handler(_: Any = Depends(param)) -> dict:  # noqa: B008 - FastAPI's own idiom
            return {}

    return router.routes[0]


def test_the_detector_takes_the_admin_guard_wherever_it_sits_in_the_tree() -> None:
    assert _guarded_for_admin(_route_with(deps.require_role("admin")))
    assert _guarded_for_admin(_route_with(param=deps.require_role("admin")))

    def wrapper(claims: Any = deps.Depends(deps.require_role("admin"))) -> Any:  # noqa: B008
        return claims

    assert _guarded_for_admin(_route_with(param=wrapper))  # a sub-dependency counts


@pytest.mark.parametrize(
    "guard",
    [
        pytest.param(lambda: deps.require_role("tier1"), id="another role"),
        pytest.param(lambda: deps.require_role("admin", "tier1"), id="admin among others"),
        pytest.param(lambda: deps.require_role(), id="no role at all"),
        pytest.param(lambda: deps.current_user, id="the user, with no role check"),
        pytest.param(lambda: deps.get_conn, id="a connection"),
    ],
)
def test_the_detector_refuses_a_route_without_the_admin_guard(guard) -> None:
    assert not _guarded_for_admin(_route_with(guard()))
    assert not _guarded_for_admin(_route_with(param=guard()))


def test_the_detector_refuses_a_route_with_no_dependency_at_all() -> None:
    assert not _guarded_for_admin(_route_with())


def test_the_detector_is_not_fooled_by_a_look_alike_named_like_the_guard() -> None:
    def require_role(*roles: str) -> Callable[..., Any]:
        def dependency() -> None:
            return None

        return dependency

    assert not _guarded_for_admin(_route_with(require_role("admin")))
