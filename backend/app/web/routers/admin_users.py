"""`web/routers/admin_users.py` — users and roles for the admin console (P11-T02, DEC-200, spec §5.1):
`GET|POST /api/admin/users`, `PATCH /api/admin/users/{user_id}`,
`POST /api/admin/users/{user_id}/password` and `POST /api/admin/users/{user_id}/unlock`. Every
route is `require_role("admin")`; a refusal writes `authz.denied` (`web/deps.py`).

The last active admin. An actor is always an active admin, so a lone request can never remove the
last one: the other admin, the actor, remains. Two admins acting at once can — A demotes B while B
demotes A, each request alone leaving one admin. `update_user` therefore locks, for any change of
`role` or `is_active`, every active admin row (`ORDER BY user_id FOR UPDATE`, one fixed order, so
two admins acting on each other queue instead of deadlocking) and only then the target row. The
second request waits for the first one's commit, re-reads who is still an active admin, and is
refused with `last_active_admin` if the target is the only one left.

Sessions. A role change, a deactivation and a password reset set `sessions_invalid_before` in the
same transaction. The stamp is `clock_timestamp()`, not `now()`: `now()` is the start of the
request's transaction, which may have waited on those locks, and a login that completed after the
start but before the change would carry a token newer than the stamp.

Bodies are read by hand, not by a Pydantic model. FastAPI's own 422 for a model repeats the
rejected value in `input` — here that value may be a password — and its `detail` is a list, where
this API's `detail` is an object (`{"field", "reason", ...}`). Only a malformed uuid in the path is
left to FastAPI's own 422, as the card says. Nothing here logs a body, and no payload, response or
error carries a password or a hash.

`infra/db.transaction()` is not used: it issues its own BEGIN/COMMIT and would commit the
request's transaction. The route's connection (`Conn`) commits on a 2xx and rolls back on any
raise, so a refused call (409, 422, 404) leaves nothing behind.
"""

from __future__ import annotations

import re
import unicodedata
import uuid
from typing import Annotated, Any

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from psycopg import errors, sql
from psycopg.rows import dict_row

from app.audit.events import write_event
from app.infra import auth
from app.infra.auth import ROLES, Claims
from app.web.deps import Conn, require_role

router = APIRouter()

Admin = Annotated[Claims, Depends(require_role("admin"))]

PASSWORD_MIN_CHARS = 12  # spec decision 1: the web create and reset; the CLI keeps its own rule
PASSWORD_MAX_CHARS = 256
USERNAME_RE = r"^[a-z0-9._-]{3,32}$"
DISPLAY_NAME_MAX_CHARS = 100

_USERNAME = re.compile(USERNAME_RE)

# The one column list every read and every `RETURNING` of this module shares: a `UserRow` is
# exactly these, in the dict the database returns. Never `password_hash` (a test pins the keys).
_COLUMNS = (
    "user_id, username, display_name, role, is_active, locked_until, failed_logins, "
    "last_login_at, created_at"
)

#: What PATCH may change, in the order the changes are written and reported.
_UPDATABLE = ("role", "display_name", "is_active")


class UserConflict(Exception):
    """`reason` ∈ last_active_admin | self_change. The route answers `409 {reason}`."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class UserNotFound(Exception):
    """No user has that id."""


# --------------------------------------------------------------------------
# the store
# --------------------------------------------------------------------------


def _fetch(conn: psycopg.Connection, query: str, params: Any = ()) -> list[dict[str, Any]]:
    with conn.cursor(row_factory=dict_row) as cursor:
        cursor.execute(query, params)
        return cursor.fetchall()


def _user_row(row: dict[str, Any]) -> dict[str, Any]:
    return {**row, "user_id": str(row["user_id"])}


def update_user(
    conn: psycopg.Connection, *, actor_id: str, target_id: str, changes: dict[str, Any]
) -> dict[str, Any]:
    """Apply `changes` (⊆ role, display_name, is_active; values already validated) to one user, in
    the caller's transaction, and return the new `UserRow`. The caller commits.

    Raises `UserNotFound`, or `UserConflict` (`self_change`, `last_active_admin`). A value equal to
    the current one is not a change: when nothing differs, nothing is written and the sessions
    stand. The audit row is `admin.user_updated` with `before`/`after` over the changed fields
    only, signed by the admin `actor_id`.
    """
    unknown = set(changes) - set(_UPDATABLE)
    if unknown:
        raise ValueError(f"changes: not updatable: {sorted(unknown)}")
    actor_id, target_id = str(uuid.UUID(actor_id)), str(uuid.UUID(target_id))

    active_admins: list[str] = []
    if "role" in changes or "is_active" in changes:
        # Every active admin, locked in one fixed order, before the target. The re-read after a
        # wait is what makes the second of two racing requests see the first one's commit.
        active_admins = [
            str(row["user_id"])
            for row in _fetch(
                conn,
                "SELECT user_id FROM users WHERE role = 'admin' AND is_active "
                "ORDER BY user_id FOR UPDATE",
            )
        ]
    found = _fetch(
        conn, f"SELECT {_COLUMNS} FROM users WHERE user_id = %s FOR UPDATE", (target_id,)
    )
    if not found:
        raise UserNotFound(target_id)
    current = found[0]

    changed = {
        key: changes[key] for key in _UPDATABLE if key in changes and changes[key] != current[key]
    }
    if not changed:
        return _user_row(current)

    if actor_id == target_id and ("role" in changed or "is_active" in changed):
        raise UserConflict("self_change")
    was_active_admin = current["role"] == "admin" and current["is_active"]
    stays_active_admin = (
        changed.get("role", current["role"]) == "admin"
        and changed.get("is_active", current["is_active"]) is True
    )
    others = [admin for admin in active_admins if admin != target_id]
    if was_active_admin and not stays_active_admin and not others:
        raise UserConflict("last_active_admin")

    assignments = [sql.SQL("{} = %s").format(sql.Identifier(key)) for key in changed]
    if "role" in changed or changed.get("is_active") is False:
        assignments.append(sql.SQL("sessions_invalid_before = clock_timestamp()"))
    query = sql.SQL("UPDATE users SET {} WHERE user_id = %s RETURNING {}").format(
        sql.SQL(", ").join(assignments), sql.SQL(_COLUMNS)
    )
    [updated] = _fetch(conn, query, (*changed.values(), target_id))
    write_event(
        conn,
        "admin.user_updated",
        target_id,
        "admin",
        actor_id=actor_id,
        payload={
            "username": updated["username"],
            "before": {key: current[key] for key in changed},
            "after": dict(changed),
        },
    )
    return _user_row(updated)


# --------------------------------------------------------------------------
# the body: a JSON object, checked by hand (see the module docstring)
# --------------------------------------------------------------------------


def _bad(field: str | None, reason: str, **extra: Any) -> HTTPException:
    detail: dict[str, Any] = (
        {"reason": reason} if field is None else {"field": field, "reason": reason}
    )
    return HTTPException(status_code=422, detail={**detail, **extra})


async def _json_object(request: Request) -> dict[str, Any]:
    """The request body as a dict. A content type other than JSON is refused as FastAPI's own
    parsing would (so a cross-site form post cannot carry an action), and nothing the client sent
    is repeated in the answer."""
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type and content_type != "application/json" and not content_type.endswith("+json"):
        raise _bad("body", "invalid")
    try:
        value = await request.json()
    except ValueError:  # JSONDecodeError and UnicodeDecodeError both
        raise _bad("body", "invalid") from None
    if not isinstance(value, dict):
        raise _bad("body", "invalid")
    return value


JsonObject = Annotated[dict[str, Any], Depends(_json_object)]


def _no_unknown_keys(body: dict[str, Any], allowed: tuple[str, ...]) -> None:
    # The field is "body", not the key: the key is the client's text.
    if set(body) - set(allowed):
        raise _bad("body", "invalid")


def _username(value: Any) -> str:
    if value is None:
        raise _bad("username", "empty")
    if not isinstance(value, str) or _USERNAME.fullmatch(value) is None:  # not `$`: it admits "\n"
        raise _bad("username", "invalid")
    return value


def _display_name(value: Any) -> str:
    if value is None:
        raise _bad("display_name", "empty")
    if not isinstance(value, str):
        raise _bad("display_name", "invalid")
    name = value.strip()
    if not name:
        raise _bad("display_name", "empty")
    if len(name) > DISPLAY_NAME_MAX_CHARS:
        raise _bad("display_name", "too_long", max=DISPLAY_NAME_MAX_CHARS)
    # A control character, and a lone surrogate (legal JSON, illegal UTF-8), would be a 500 at the
    # driver — a text column cannot hold NUL — or at least text no screen should show.
    if any(unicodedata.category(char) in ("Cc", "Cs") for char in name):
        raise _bad("display_name", "invalid")
    return name


def _role(value: Any) -> str:
    if value is None:
        raise _bad("role", "empty")
    if not isinstance(value, str) or value not in ROLES:
        raise _bad("role", "invalid")
    return value


def _is_active(value: Any) -> bool:
    if value is None:
        raise _bad("is_active", "empty")
    if not isinstance(value, bool):
        raise _bad("is_active", "invalid")
    return value


def _password(value: Any) -> str:
    if value is None:
        raise _bad("password", "empty")
    if not isinstance(value, str):
        raise _bad("password", "invalid")
    if len(value) < PASSWORD_MIN_CHARS:
        raise _bad("password", "too_short", min=PASSWORD_MIN_CHARS)
    if len(value) > PASSWORD_MAX_CHARS:
        raise _bad("password", "too_long", max=PASSWORD_MAX_CHARS)
    try:
        value.encode("utf-8")  # a lone surrogate is legal JSON; argon2 would raise on it
    except UnicodeEncodeError:
        raise _bad("password", "invalid") from None
    return value


def _request_body(properties: dict[str, str], required: list[str]) -> dict[str, Any]:
    """OpenAPI text for a body this module reads itself (FastAPI cannot infer it)."""
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {name: {"type": kind} for name, kind in properties.items()},
        "additionalProperties": False,
    }
    if required:  # an empty `required` is not valid in every JSON Schema dialect
        schema["required"] = required
    return {"requestBody": {"required": True, "content": {"application/json": {"schema": schema}}}}


# --------------------------------------------------------------------------
# the routes
# --------------------------------------------------------------------------


@router.get("/api/admin/users")
def api_list_users(conn: Conn, claims: Admin) -> dict[str, list[dict[str, Any]]]:
    rows = _fetch(conn, f'SELECT {_COLUMNS} FROM users ORDER BY username COLLATE "C"')
    return {"users": [_user_row(row) for row in rows]}


@router.post(
    "/api/admin/users",
    status_code=201,
    openapi_extra=_request_body(
        {"username": "string", "display_name": "string", "role": "string", "password": "string"},
        ["username", "display_name", "role", "password"],
    ),
)
def api_create_user(conn: Conn, claims: Admin, body: JsonObject) -> dict[str, str]:
    _no_unknown_keys(body, ("username", "display_name", "role", "password"))
    username = _username(body.get("username"))
    display_name = _display_name(body.get("display_name"))
    role = _role(body.get("role"))
    password = _password(body.get("password"))
    try:
        user_id = auth.create_user(
            conn,
            username=username,
            display_name=display_name,
            role=role,
            password=password,
            actor_id=claims.user_id,
        )
    except errors.UniqueViolation as exc:
        # The failed INSERT aborts the transaction; the raise below rolls the request back, and the
        # user row, its audit row and nothing else were in it.
        if exc.diag.constraint_name != "users_username_key":
            raise
        raise HTTPException(status_code=409, detail={"reason": "username_taken"}) from exc
    return {"user_id": user_id}


@router.patch(
    "/api/admin/users/{user_id}",
    openapi_extra=_request_body(
        {"role": "string", "display_name": "string", "is_active": "boolean"}, []
    ),
)
def api_update_user(
    user_id: uuid.UUID, conn: Conn, claims: Admin, body: JsonObject
) -> dict[str, Any]:
    _no_unknown_keys(body, _UPDATABLE)
    if not body:
        raise _bad(None, "empty")
    validators = {"role": _role, "display_name": _display_name, "is_active": _is_active}
    changes = {key: validators[key](body[key]) for key in _UPDATABLE if key in body}
    try:
        return update_user(conn, actor_id=claims.user_id, target_id=str(user_id), changes=changes)
    except UserNotFound as exc:
        raise HTTPException(status_code=404, detail={"reason": "not_found"}) from exc
    except UserConflict as exc:
        raise HTTPException(status_code=409, detail={"reason": exc.reason}) from exc


@router.post(
    "/api/admin/users/{user_id}/password",
    status_code=204,
    openapi_extra=_request_body({"password": "string"}, ["password"]),
)
def api_reset_password(user_id: uuid.UUID, conn: Conn, claims: Admin, body: JsonObject) -> Response:
    _no_unknown_keys(body, ("password",))
    password = _password(body.get("password"))
    username = auth.admin_set_password(conn, str(user_id), password)
    if username is None:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    write_event(
        conn,
        "admin.user_updated",
        str(user_id),
        "admin",
        actor_id=claims.user_id,
        payload={"username": username, "action": "password_reset"},
    )
    return Response(status_code=204)


@router.post("/api/admin/users/{user_id}/unlock", status_code=204)
def api_unlock_user(user_id: uuid.UUID, conn: Conn, claims: Admin) -> Response:
    username = auth.unlock(conn, str(user_id))
    if username is None:
        raise HTTPException(status_code=404, detail={"reason": "not_found"})
    write_event(
        conn,
        "admin.user_updated",
        str(user_id),
        "admin",
        actor_id=claims.user_id,
        payload={"username": username, "action": "unlock"},
    )
    return Response(status_code=204)
