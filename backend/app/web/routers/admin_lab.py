"""`web/routers/admin_lab.py` — the admin API of the lab runs and labels (P14-T09, DEC-213, spec §6): the
data behind the "Gán nhãn lab" page (P14-T10). Every route is `Admin` only; `iter_routers()` discovers this
module. All logic is `app.lab`; this module reads the request, maps the refusals to status codes and shapes
the answers.

    GET    /api/admin/lab/runs                                  200 {runs: [run]}
    POST   /api/admin/lab/runs   {name, purpose, starts_at, ends_at}   201 run; 409 overlap; 422
    GET    /api/admin/lab/runs/{run_id}/alerts?after=&limit=    200 {run, alerts, next_after}; 404
    PUT    /api/admin/lab/labels/{alert_id}   {label}           200 {alert_id, run_id, label}; 404; 409; 422
    DELETE /api/admin/lab/labels/{alert_id}                     204

A `run` is `{run_id, name, purpose, starts_at, ends_at, total, labelled}`: `total` is the queue heads
received in the window and `labelled` how many of them carry a label (an unlabelled alert is not scored and
is counted as such). Runs come latest window first.

**Create.** `purpose` is `kb` or `test`; `starts_at` and `ends_at` are ISO 8601 with a zone (`Z` or an
offset; a time with none is ambiguous and refused). The window is half-open, `[starts_at, ends_at)`, and
may not overlap another run's. A run starts where another ends. `409 {"detail": {"reason": "overlap"}}`
when it does. `422 {"detail": {"field", "reason"}}` otherwise: `field` is `name`, `purpose`, `starts_at`,
`ends_at` or `body`, and `reason` is `required`, `empty`, `too_long`, `invalid`, `taken` (the name is in
use) or `not_after_starts` (`ends_at` is not after `starts_at`).

**A run's alerts** are its queue heads (`duplicate_of IS NULL`) received inside the window, oldest first,
blind: each carries the alert's own fields and its `label` (`true_positive`, `false_positive` or null) and
nothing of ① (`tier1.visibility.strip(..., mode="labeling")`, see `lab/labels.py`). `limit` is 1..200 (100
by default); `after` is the last `alert_id` of the page before. `next_after` is the last alert's id when
the page is full, else null. `404 {"detail": {"reason": "not_found"}}` for a run that does not exist; a
`run_id` that is no uuid is a `422` and one with a control character a `404` (`deps.clean_path_id`).

**Label.** The run is the one the alert's `received_at` falls in; the admin does not choose it. The
`alert_id` is `deps.AlertId`, as on the tier1 routes. `PUT` sets or changes the label: `404 not_found` for an
alert that does not exist, `409 outside_every_run` for one received outside every window, `422` for a label
other than `true_positive | false_positive`. `DELETE` clears it; clearing what is not there is a `204` too,
and writes nothing.

Every route that changes something asks for a JSON content type after the role check
(`deps.require_json_type`): `POST` and `PUT` read their body by hand, `DELETE` carries no body and says
only the type. There is no cookie to forge a request with, and a no-cors `fetch` or a form post cannot set
that type. The bodies are read by hand so a 422 repeats nothing the client sent (`admin_users.py`'s
reasoning). The refusals are `{"detail": {"reason": ...}}`, as the other admin routers give them.

The request's connection (`Conn`) commits on a 2xx and rolls back on any raise, so a label and its
`lab.labeled` event, or a run and its `lab.run_created`, land together or not at all.
"""

from __future__ import annotations

import json
import unicodedata
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import AfterValidator, BeforeValidator

from app.infra.auth import Claims
from app.lab import labels as lab_labels
from app.lab import runs as lab_runs
from app.web.deps import AlertId, Conn, JsonType, clean_path_id, require_json_type, require_role

router = APIRouter()

require_admin = require_role("admin")
Admin = Annotated[Claims, Depends(require_admin)]

#: The same cap the audit page puts on a page; a lab run is a handful of hours of alerts.
DEFAULT_LIMIT = lab_labels.DEFAULT_LIMIT
MAX_LIMIT = lab_labels.MAX_LIMIT

#: A run's id in a path: a uuid, and a control character in it names nothing (404), as an alert id's does.
RunId = Annotated[UUID, BeforeValidator(clean_path_id)]


def _refuse(status_code: int, reason: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"reason": reason})


def _bad(field: str, reason: str) -> HTTPException:
    return HTTPException(status_code=422, detail={"field": field, "reason": reason})


def _no_control(value: str | None) -> str | None:
    """An `after` with a control character (a NUL the driver would refuse with a 500) is a 422."""
    if value is not None and any(unicodedata.category(char) == "Cc" for char in value):
        raise ValueError("must not contain a control character")
    return value


# ── the request body ──────────────────────────────────────────────────────────────────────────


async def _read_object(request: Request) -> dict[str, Any]:
    """The body as a dict. The JSON content type is required first (`deps.require_json_type`), after the
    role check: the parameter that asks for this body is declared after `claims`. An empty body, a body
    that is not JSON and one that is not an object are the same 422; nothing the client sent is repeated.
    """
    require_json_type(request)
    try:
        value = json.loads(await request.body())
    except ValueError:  # JSONDecodeError and UnicodeDecodeError both
        raise _bad("body", "invalid") from None
    if not isinstance(value, dict):
        raise _bad("body", "invalid")
    return value


JsonBody = Annotated[dict[str, Any], Depends(_read_object)]


def _only(body: dict[str, Any], allowed: tuple[str, ...]) -> None:
    # The field is "body", not the key: the key is the client's text.
    if set(body) - set(allowed):
        raise _bad("body", "invalid")


def _required(body: dict[str, Any], field: str) -> Any:
    value = body.get(field)
    if value is None:
        raise _bad(field, "required")
    return value


def _instant(body: dict[str, Any], field: str) -> datetime:
    """ISO 8601 text with a zone. A date alone, a time with no zone, a number and anything else is
    `invalid`: the zone is the admin's to state."""
    value = _required(body, field)
    if not isinstance(value, str):
        raise _bad(field, "invalid")
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        raise _bad(field, "invalid") from None
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise _bad(field, "invalid")
    return moment


def _request_body(properties: dict[str, str], required: list[str]) -> dict[str, Any]:
    """OpenAPI text for a body this module reads itself (FastAPI cannot infer it)."""
    schema = {
        "type": "object",
        "properties": {name: {"type": kind} for name, kind in properties.items()},
        "additionalProperties": False,
        "required": required,
    }
    return {"requestBody": {"required": True, "content": {"application/json": {"schema": schema}}}}


# ── what is sent back ─────────────────────────────────────────────────────────────────────────


def _run_json(conn: psycopg.Connection, run: lab_runs.LabRun) -> dict[str, Any]:
    counts = lab_runs.run_counts(conn, run)
    return {
        "run_id": run.run_id,
        "name": run.name,
        "purpose": run.purpose,
        "starts_at": run.starts_at,
        "ends_at": run.ends_at,
        "total": counts.total,
        "labelled": counts.labelled,
    }


# ── the runs ──────────────────────────────────────────────────────────────────────────────────


@router.get("/api/admin/lab/runs")
def api_list_runs(conn: Conn, claims: Admin) -> dict[str, list[dict[str, Any]]]:
    return {"runs": [_run_json(conn, run) for run in lab_runs.list_runs(conn)]}


@router.post(
    "/api/admin/lab/runs",
    status_code=201,
    openapi_extra=_request_body(
        {"name": "string", "purpose": "string", "starts_at": "string", "ends_at": "string"},
        ["name", "purpose", "starts_at", "ends_at"],
    ),
)
def api_create_run(conn: Conn, claims: Admin, body: JsonBody) -> dict[str, Any]:
    _only(body, ("name", "purpose", "starts_at", "ends_at"))
    name = _required(body, "name")
    purpose = _required(body, "purpose")
    starts_at = _instant(body, "starts_at")
    ends_at = _instant(body, "ends_at")
    try:
        run = lab_runs.create_run(
            conn,
            name=name,
            purpose=purpose,
            starts_at=starts_at,
            ends_at=ends_at,
            admin_id=claims.user_id,
        )
    except lab_runs.InvalidRun as exc:
        raise _bad(exc.field, exc.reason) from None
    except lab_runs.RunOverlap:
        raise _refuse(409, "overlap") from None
    return _run_json(conn, run)


@router.get("/api/admin/lab/runs/{run_id}/alerts")
def api_run_alerts(
    conn: Conn,
    claims: Admin,
    run_id: RunId,
    after: Annotated[
        str | None, Query(min_length=1, max_length=256), AfterValidator(_no_control)
    ] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> dict[str, Any]:
    run = lab_runs.get_run(conn, run_id)
    if run is None:
        raise _refuse(404, "not_found")
    alerts = lab_labels.run_alerts(conn, run.run_id, after=after, limit=limit)
    return {
        "run": _run_json(conn, run),
        "alerts": alerts,
        "next_after": alerts[-1]["alert_id"] if len(alerts) == limit else None,
    }


# ── the labels ────────────────────────────────────────────────────────────────────────────────


@router.put(
    "/api/admin/lab/labels/{alert_id}",
    openapi_extra=_request_body({"label": "string"}, ["label"]),
)
def api_put_label(conn: Conn, claims: Admin, alert_id: AlertId, body: JsonBody) -> dict[str, Any]:
    _only(body, ("label",))
    label = _required(body, "label")
    try:
        run_id = lab_labels.set_label(conn, alert_id, label, claims.user_id)
    except lab_labels.InvalidLabel:
        raise _bad("label", "invalid") from None
    except lab_labels.UnknownAlert:
        raise _refuse(404, "not_found") from None
    except lab_labels.OutsideEveryRun:
        raise _refuse(409, "outside_every_run") from None
    return {"alert_id": alert_id, "run_id": run_id, "label": label}


@router.delete("/api/admin/lab/labels/{alert_id}", status_code=204)
def api_delete_label(conn: Conn, claims: Admin, alert_id: AlertId, _json: JsonType) -> Response:
    lab_labels.clear_label(conn, alert_id, claims.user_id)
    return Response(status_code=204)
