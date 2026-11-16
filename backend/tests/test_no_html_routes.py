"""P11-T19 (spec §8, DEC-205) — port 8000 serves `/api/*`, `/webhook/alerts`, `/webhook/soar-notices` (SR-T1) and `/health`, and
nothing that renders a page. The Jinja admin pages (`/admin/rules`, `/admin/digest`, `/admin/labels`)
and the sign-in pages (`/login`, `/logout`, `/`) are gone; the React UI on port 8080 is the only
admin console.

The route list is read four ways, so a page cannot come back by a door one of them does not see:

  - the app's own top-level routes (`app.routes`);
  - the routers it includes: FastAPI 0.141 keeps each as one lazy node with no `path` in
    `app.routes` (measured), so the routes of every module `iter_routers()` finds are read directly,
    and the number of such nodes must equal the number of routers (a router included from
    anywhere else would leave a node with no router behind it);
  - `app.openapi()["paths"]`, with the content type of every response it documents;
  - the answer to a request for each removed path, on a connection that fails the test if it is
    touched: a route that still exists would reach it (a `Conn`, a `page_user`) or answer something
    other than 404.

No database: nothing here needs one, so this runs in `make test` as well as `make test-db`.
"""

from __future__ import annotations

import uuid

import pytest
from app.web import deps, main
from app.web.routers import iter_routers
from fastapi.datastructures import DefaultPlaceholder
from fastapi.responses import HTMLResponse
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from starlette.routing import Mount

#: The routes outside `/api/` that the application is meant to answer (`web/routers/health.py`,
#: `web/routers/webhook.py`, and `web/routers/webhook_soar_notices.py`, SR-T1).
OPS_PATHS = {"/health", "/webhook/alerts", "/webhook/soar-notices"}

#: `FastAPI()` adds these four itself (Swagger UI, ReDoc, the schema and the Swagger redirect). They
#: are the framework's, not a page of this application's, and removing them is a separate decision
#: (P11-T19 report). Named here so the allowance is exact: any other extra path fails the test.
FRAMEWORK_DOC_PATHS = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}

#: What each route of the Jinja pages answered, and the P10-T13 pages before them. With a placeholder
#: id where the path has one.
_RULE_ID = str(uuid.uuid4())
REMOVED_ROUTES = [
    ("GET", "/"),
    ("GET", "/login"),
    ("POST", "/login"),
    ("POST", "/logout"),
    ("GET", "/admin/rules"),
    ("POST", "/admin/rules/preview"),
    ("POST", "/admin/rules"),
    ("POST", f"/admin/rules/{_RULE_ID}/toggle"),
    ("GET", "/admin/digest"),
    ("POST", "/admin/digest/x/review"),
    ("GET", "/admin/labels"),
    ("POST", "/admin/labels"),
    ("POST", "/admin/labels/undo"),
    # P10-T13 (the Tier-1 and Tier-2 pages)
    ("GET", "/queue"),
    ("GET", "/alerts/x"),
    ("POST", "/alerts/x/acknowledge"),
    ("POST", "/alerts/x/decide"),
    ("POST", "/alerts/x/escalate"),
    ("POST", "/alerts/x/reopen"),
    ("GET", "/cases"),
    ("GET", "/cases/x"),
    ("POST", "/cases/x/notes"),
    ("POST", "/cases/x/conclude"),
    ("GET", "/cases/x/investigation"),
    ("POST", "/cases/x/analyze"),
]


def _top_level_routes() -> list:
    """What `app.routes` lists by itself: the routes that have a path."""
    return [route for route in main.app.routes if hasattr(route, "path")]


def _included_nodes() -> list:
    """What `app.routes` lists for an included router: a node with no path of its own."""
    return [route for route in main.app.routes if not hasattr(route, "path")]


def _included_routes() -> list:
    return [route for router in iter_routers() for route in router.routes]


def _every_route() -> list:
    return _top_level_routes() + _included_routes()


def _every_path() -> set[str]:
    paths = {route.path for route in _every_route()}
    return paths | set(main.app.openapi()["paths"])


def _is_html(response_class: object) -> bool:
    if isinstance(response_class, DefaultPlaceholder):
        response_class = response_class.value
    return isinstance(response_class, type) and issubclass(response_class, HTMLResponse)


def test_every_router_the_app_includes_is_one_the_routes_were_read_from() -> None:
    """The walk below sees the routes of `iter_routers()`. This is what makes that all of them:
    one node in `app.routes` per router, and no other path-less thing in there."""
    assert len(_included_nodes()) == len(iter_routers())
    assert len(iter_routers()) > 0


def test_the_app_answers_api_paths_and_the_three_ops_paths_only() -> None:
    paths = _every_path()
    outside_api = {p for p in paths if not p.startswith("/api/")}
    # exactly the three ops paths, plus the framework's own four: nothing else outside /api/
    assert outside_api - FRAMEWORK_DOC_PATHS == OPS_PATHS, sorted(outside_api)
    # the test is not vacuous: the API is there
    assert {"/api/auth/login", "/api/auth/me", "/api/admin/rules", "/api/tier1/queue"} <= paths
    assert any(p.startswith("/api/admin/labels") for p in paths)
    assert any(p.startswith("/api/admin/digest") for p in paths)


def test_no_route_of_the_app_has_an_html_response_class() -> None:
    html = [
        (route.path, sorted(route.methods))
        for route in _every_route()
        if isinstance(route, APIRoute) and _is_html(route.response_class)
    ]
    assert html == []


def test_no_path_is_mounted() -> None:
    """A `Mount` is a whole app under a prefix: static files, a second UI. None is mounted."""
    mounted = [route.path for route in _every_route() if isinstance(route, Mount)]
    assert mounted == []


def test_no_documented_response_is_html() -> None:
    html = []
    for path, operations in main.app.openapi()["paths"].items():
        for method, operation in operations.items():
            for status, response in operation.get("responses", {}).items():
                if "text/html" in response.get("content", {}):
                    html.append((method.upper(), path, status))
    assert html == []


class _NoSql:
    """A connection that fails the test if anything touches it."""

    def __getattr__(self, name):
        raise AssertionError(f"a removed route reached the connection ({name})")


@pytest.mark.parametrize(
    ("method", "path"),
    REMOVED_ROUTES,
    ids=[f"{method} {path}" for method, path in REMOVED_ROUTES],
)
def test_a_removed_page_route_is_a_404_for_a_caller_with_no_session(method, path) -> None:
    main.app.dependency_overrides[deps.get_conn] = lambda: _NoSql()
    try:
        response = TestClient(main.app, follow_redirects=False).request(method, path)
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
    # 404, not a redirect to /login, not a 401 and not a 200: the route does not exist
    assert response.status_code == 404, (response.status_code, response.text[:200])
