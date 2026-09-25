"""`web/routers/labels.py` — the blind labelling page (P6-T02): the two §6.4
operations `GET /api/admin/labels/next` and `POST /api/admin/labels`, and the
HTML routes `GET`/`POST /admin/labels` and `POST /admin/labels/undo`.

All logic is `app.tier1.labels`; this module binds the labeller to the session
(P6-tasks.md planning decision 7: a `labeler` that is not the caller's
`user_id` is `403`, so one person can never draw the other's order or write the
other's row) and maps the logic's refusals to status codes.

The file paths are read from `app.tier1.labels` at request time — never bound
as defaults at import — so a test points them at `tmp_path` with `monkeypatch`.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, field_validator

from app.infra.auth import Claims
from app.tier1 import labels
from app.web import templating
from app.web.deps import Cfg, Conn, require_role
from app.web.routers.pages import page_user

router = APIRouter()

#: One dependency object, so `Depends` resolves it once per request.
require_admin = require_role("admin")
Admin = Annotated[Claims, Depends(require_admin)]

_LABELER_MISMATCH = "labeler must be the current user"

_STATUS_FOR: dict[type[labels.LabelError], int] = {
    labels.InvalidSubmission: 422,
    labels.UnknownCluster: 404,
    labels.AlreadyLabelled: 409,
    labels.Frozen: 409,
}
_DETAIL_FOR: dict[type[labels.LabelError], str] = {
    labels.UnknownCluster: "cluster is not a gold candidate",
    labels.AlreadyLabelled: "already labelled by this labeler",
    labels.Frozen: "the gold set is frozen",
}
_FLASH_FOR: dict[type[labels.LabelError], str] = {
    labels.InvalidSubmission: "Nhãn không hợp lệ",
    labels.UnknownCluster: "Cụm này không nằm trong danh sách ứng viên",
    labels.AlreadyLabelled: "Bạn đã gán nhãn cụm này rồi",
    labels.Frozen: "Tập vàng đã đóng băng — không hoàn tác được",
}


def _bind(labeler: str, claims: Claims) -> None:
    if labeler != claims.user_id:
        raise HTTPException(status_code=403, detail=_LABELER_MISMATCH)


def _next_payload(conn: Any, labeler_id: str) -> dict[str, Any]:
    """`{cluster_id, done, total, cluster}` — `cluster` is `cluster_view`'s
    allowlisted dict, or `None` when the labeller is finished (or there are no
    candidates, `total == 0`)."""
    candidates = labels.load_candidates(path=labels.CANDIDATES_PATH)
    order = labels.labeler_order(candidates, labeler_id)
    progress = labels.next_unlabelled(conn, order, labeler_id)
    view = None
    if progress.cluster_id is not None:
        candidate = next(c for c in candidates if c.cluster_id == progress.cluster_id)
        view = labels.cluster_view(
            conn, candidate, g1_clusters=labels.load_g1_clusters(path=labels.G1_CLUSTERS_PATH)
        )
    return {
        "cluster_id": progress.cluster_id,
        "done": progress.done,
        "total": progress.total,
        "cluster": view,
    }


def _submit(conn: Any, labeler_id: str, **fields: Any) -> labels.SubmitResult:
    return labels.submit_label(
        conn, labeler_id=labeler_id, candidates_path=labels.CANDIDATES_PATH, **fields
    )


# ---------------------------------------------------------------------------
# §6.4 — the two API operations
# ---------------------------------------------------------------------------


class LabelIn(BaseModel):
    labeler: str
    cluster_id: str
    label: Literal["false_positive", "benign", "escalate"]
    confidence: Literal[1, 2, 3]
    note: str | None = None

    @field_validator("note")
    @classmethod
    def _note(cls, value: str | None) -> str | None:
        try:
            return labels.clean_note(value)
        except labels.InvalidSubmission as exc:
            raise ValueError(str(exc)) from exc


@router.get("/api/admin/labels/next")
def api_next(conn: Conn, claims: Admin, labeler: Annotated[str, Query()]) -> dict[str, Any]:
    _bind(labeler, claims)
    return _next_payload(conn, claims.user_id)


@router.post("/api/admin/labels", status_code=201)
def api_post(conn: Conn, claims: Admin, body: LabelIn) -> dict[str, Any]:
    _bind(body.labeler, claims)
    try:
        result = _submit(
            conn,
            claims.user_id,
            cluster_id=body.cluster_id,
            label=body.label,
            confidence=body.confidence,
            note=body.note,
        )
    except labels.LabelError as exc:
        status = _STATUS_FOR[type(exc)]
        raise HTTPException(status_code=status, detail=_DETAIL_FOR.get(type(exc), str(exc))) from exc
    return {"cluster_id": result.cluster_id, "done": result.done, "total": result.total, "next": result.next}


# ---------------------------------------------------------------------------
# The page — the labeller is the session's user, never a form field
# ---------------------------------------------------------------------------


def _page(
    request: Request,
    conn: Any,
    cfg: Any,
    user: Claims,
    *,
    flash: dict[str, str] | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    payload = _next_payload(conn, user.user_id)
    page = templating.render(
        request,
        "labels.html",
        user=user,
        flash=flash,
        tz=cfg.DISPLAY_TZ,
        progress=payload,
        view=payload["cluster"],
        candidates_present=labels.CANDIDATES_PATH.is_file(),
        undo_allowed=not labels.FREEZE_MARKER.exists(),
    )
    page.status_code = status_code
    return page


@router.get("/admin/labels", response_class=HTMLResponse)
def labels_page(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Annotated[Claims, Depends(page_user)],
    _: Admin,
) -> HTMLResponse:
    return _page(request, conn, cfg, user)


@router.post("/admin/labels", response_class=HTMLResponse)
def labels_submit(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Annotated[Claims, Depends(page_user)],
    _: Admin,
    cluster_id: Annotated[str, Form()],
    label: Annotated[str, Form()],
    confidence: Annotated[int, Form()],
    note: Annotated[str | None, Form()] = None,
):
    try:
        _submit(conn, user.user_id, cluster_id=cluster_id, label=label, confidence=confidence, note=note)
    except labels.LabelError as exc:
        # Nothing was written (the INSERT sits in a savepoint), so redrawing
        # the page from inside the request's transaction is safe.
        flash = {"level": "error", "text": _FLASH_FOR[type(exc)]}
        return _page(request, conn, cfg, user, flash=flash, status_code=_STATUS_FOR[type(exc)])
    return RedirectResponse("/admin/labels", status_code=303)


@router.post("/admin/labels/undo", response_class=HTMLResponse)
def labels_undo(
    request: Request,
    conn: Conn,
    cfg: Cfg,
    user: Annotated[Claims, Depends(page_user)],
    _: Admin,
):
    try:
        labels.undo_last(conn, user.user_id, freeze_marker=labels.FREEZE_MARKER)
    except labels.Frozen:
        flash = {"level": "error", "text": _FLASH_FOR[labels.Frozen]}
        return _page(request, conn, cfg, user, flash=flash, status_code=409)
    return RedirectResponse("/admin/labels", status_code=303)
