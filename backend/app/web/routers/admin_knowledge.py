"""`web/routers/admin_knowledge.py` — the admin review API of the learned knowledge (P13-T05, DEC-210,
spec §7.5): the drafts the model wrote from the analysts' conclusions, the entries an admin approved,
and the closed tag vocabulary. Every route is `Admin` only; `iter_routers()` discovers this module.
The page that reads these shapes is `/admin/knowledge` (P13-T06).

    GET  /api/admin/knowledge/drafts?status=pending|approved|merged|rejected&limit=&offset=
    GET  /api/admin/knowledge/drafts/{draft_id}                 -> {draft, source}
    POST /api/admin/knowledge/drafts/{draft_id}/approve         {edited?}      -> {entry_id}
    POST /api/admin/knowledge/drafts/{draft_id}/reject          {reason}       -> {draft_id, status}
    GET  /api/admin/knowledge/entries?status=active|retired&limit=&offset=
    GET  /api/admin/knowledge/entries/{entry_id}
    POST /api/admin/knowledge/entries/{entry_id}/retire         {reason}       -> {entry_id, status}
    GET  /api/admin/knowledge/tags                              -> {tags, descriptions}

**The draft list** is a plain JSON list of rows, `pending` by default. Pending: the drafts in conflict
with an active entry first (the admin must see those), then the oldest first. The other statuses: the
newest first (by the review, else the creation). A row has no text but its `title` (null for a draft the
job could not write); `has_text` says whether `draft` holds a draft at all.

**The draft detail** is `{draft, source}`. `draft` is the row (`draft.draft` is the twelve fields, or `{}`
for a draft with no text, `warnings` what the job could not do). `source` is what the admin judges the draft
against, read-only, by calling the functions of the routes the analysts use, so it is the same JSON:

* `kind`, `id`: `alert` or `case`, and the alert id or the case uuid;
* an alert draft: `alert` = `tier1.queue.get_alert_view` (what `GET /api/tier1/alerts/{id}` answers,
  `mode="analyst"`: a decided alert shows ①'s suggestion, DEC-206), `case` and `investigation` null;
* a case draft: `case` = what `GET /api/tier2/cases/{id}` answers (`routers.tier2.case_detail`) and
  `investigation` = what `GET /api/tier2/cases/{id}/investigation` answers
  (`tier2.investigation_view.build_investigation` and `case_open`), `alert` null;
* `decision`: the newest `tier1.decided` (alert) or `tier2.concluded` (case) event, `{event_type,
  actor_id, actor_name, at, payload}`, or null; the payload goes through the audit page's redaction;
* `notes`: the case's notes (the same list as `case.notes`), `[]` for an alert;
* `enrichment`: the SOAR `enrichment` block of the payload (`alerts.raw_payload -> enrichment`), redacted
  as the audit payloads are: for an alert the block or null, for a case a map `{head alert id: block}`
  of the heads that have one;
* `conflict_entry`: the active entry the draft was found to conflict with, rendered (`entry_json`, with
  its Markdown `content`), or null.

**Approve** takes `{edited?: {...}}`: the model fields only (`title, summary, distinguishing_signals,
check_next_time, confidence_note, tags`); a key that is not one of them is refused (a closed field is
never taken from the request). `rag.publish.approve_published` tidies, validates against the subject's
current source, writes the entry and its file in the request's transaction, and this module commits
through `commit_publication`, which removes the file if the commit fails.

    200 {entry_id}
    404 {"detail": {"reason": "not_found"}}
    409 {"detail": {"reason": "not_pending"}}      (or "source_changed", or "unpublishable")
    422 {"faults": ["v3_ipv4:summary", ...]}        V1-V5 by rule and field (`rag.draft.FAULT_VOCABULARY`)
    422 {"detail": {"field": "body"|"edited", "reason": "invalid"}}    the request itself is malformed
    503 {"detail": {"reason": "publish_failed"}}    the file could not be written; nothing was stored

**Reject** and **retire** take `{reason}` of 1-500 characters; a reason that is not is `422 {"detail":
{"field": "reason", "reason": "required"|"invalid"}}`. Retire of an entry that is not active is `409
{"detail": {"reason": "not_active"}}`.

Every route that changes something asks for a JSON content type after the role check
(`deps.require_json_type`); the bodies are read by hand, so a 422 repeats nothing the client sent
(`admin_users.py`'s reasoning).

The tree the files live in is `KB_LEARNED_ROOT`, read at call time from this module, so a test points it
at a temporary directory.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from functools import cache
from pathlib import Path
from typing import Annotated, Any, Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from app.infra.auth import Claims
from app.rag import publish
from app.rag.entries import KB_LEARNED_ROOT, Entry, entry_by_id, file_matches, sha256_text
from app.rag.tags import TAGS_FILE, load_tags, read_tags_file
from app.tier1 import queue
from app.tier2 import investigation_view
from app.web.deps import Cfg, Conn, require_json_type, require_role
from app.web.routers import admin_audit
from app.web.routers import tier2 as tier2_routes
from app.web.routers.tier2_runs import OPEN_CASE_STATUS

router = APIRouter()

require_admin = require_role("admin")
Admin = Annotated[Claims, Depends(require_admin)]

logger = logging.getLogger(__name__)

DraftStatus = Literal["pending", "approved", "merged", "rejected"]
EntryStatus = Literal["active", "retired"]

DEFAULT_LIMIT = 200
MAX_LIMIT = 500
_OFFSET_MAX = 2**31 - 1

#: The title is the first `# ` heading of an entry's Markdown (`render_entry_markdown` writes exactly
#: one, after the front matter, and folds the title onto one line).
_TITLE = re.compile(r"\n# ([^\n]*)\n")
_TITLE_SQL = r"substring(content from '\n# ([^\n]*)\n')"


def _root() -> Path:
    """The `kb_learned` tree, looked up when the request runs."""
    return KB_LEARNED_ROOT


def _refuse(status_code: int, reason: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"reason": reason})


def _bad(field: str, reason: str) -> HTTPException:
    return HTTPException(status_code=422, detail={"field": field, "reason": reason})


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


# ── what is sent back ─────────────────────────────────────────────────────────────────────────


def _safe(value: Any) -> Any:
    """`value` through the audit page's redaction (a secret key, a URL with a password), or a
    marker when it is too deep to walk."""
    try:
        return admin_audit.redact(value)
    except (ValueError, RecursionError):
        return {"truncated": True}


_DRAFT_COLUMNS = (
    "d.draft_id, d.source_kind, d.source_id, d.conclusion, d.status, d.draft, d.warnings,"
    " d.llm_run_id, d.duplicate_of_entry, d.conflict_with_entry, d.created_at, d.reviewed_by,"
    " u.username, d.reviewed_at, d.review_note"
)
_DRAFT_FROM = " FROM knowledge_drafts d LEFT JOIN users u ON u.user_id = d.reviewed_by"


def _draft_json(row: tuple) -> dict[str, Any]:
    (
        draft_id,
        kind,
        source_id,
        conclusion,
        status,
        draft,
        warnings,
        llm_run_id,
        duplicate_of,
        conflict_with,
        created_at,
        reviewed_by,
        reviewed_by_name,
        reviewed_at,
        review_note,
    ) = row
    return {
        "draft_id": str(draft_id),
        "source_kind": kind,
        "source_id": source_id,
        "conclusion": conclusion,
        "status": status,
        "draft": draft,
        "warnings": warnings,
        "llm_run_id": _text(llm_run_id),
        "duplicate_of_entry": _text(duplicate_of),
        "conflict_with_entry": _text(conflict_with),
        "created_at": created_at,
        "reviewed_by": _text(reviewed_by),
        "reviewed_by_name": reviewed_by_name,
        "reviewed_at": reviewed_at,
        "review_note": review_note,
    }


def title_of(content: str) -> str | None:
    """The title of an entry's Markdown, or None."""
    found = _TITLE.search(content)
    return None if found is None else found.group(1)


def entry_json(entry: Entry, conn: psycopg.Connection, root: Path) -> dict[str, Any]:
    """An entry, whole: every column but the generated index value, its `title`, who approved it, and
    whether it is intact (`integrity.content_ok`: `content` hashes to `content_sha256`;
    `integrity.file_ok`: the published file is exactly that, V-R1). `content` is the rendered Markdown.
    """
    approver = None
    if entry.approved_by is not None:
        row = conn.execute(
            "SELECT username FROM users WHERE user_id = %s", (entry.approved_by,)
        ).fetchone()
        approver = None if row is None else row[0]
    return {
        "entry_id": entry.entry_id,
        "version": entry.version,
        "status": entry.status,
        "title": title_of(entry.content),
        "conclusion": entry.conclusion,
        "category": entry.category,
        "mitre_ids": list(entry.mitre_ids),
        "tags": list(entry.tags),
        "soar_scenario": entry.soar_scenario,
        "rule_ids": list(entry.rule_ids),
        "log_source": entry.log_source,
        "fingerprint": entry.fingerprint,
        "content": entry.content,
        "content_sha256": entry.content_sha256,
        "file_path": entry.file_path,
        "source_alert_ids": list(entry.source_alert_ids),
        "source_case_ids": list(entry.source_case_ids),
        "evidence": entry.evidence,
        "approved_by": entry.approved_by,
        "approved_by_name": approver,
        "approved_at": entry.approved_at,
        "supersedes_entry": entry.supersedes_entry,
        "integrity": {
            "content_ok": sha256_text(entry.content) == entry.content_sha256,
            "file_ok": file_matches(entry, root),
        },
    }


# ── the drafts ────────────────────────────────────────────────────────────────────────────────

_PENDING_ORDER = "(d.conflict_with_entry IS NOT NULL) DESC, d.created_at, d.draft_id"
_REVIEWED_ORDER = "coalesce(d.reviewed_at, d.created_at) DESC, d.draft_id"


@router.get("/api/admin/knowledge/drafts")
def api_list_drafts(
    conn: Conn,
    claims: Admin,
    status: DraftStatus = "pending",
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0, le=_OFFSET_MAX)] = 0,
) -> list[dict[str, Any]]:
    order = _PENDING_ORDER if status == "pending" else _REVIEWED_ORDER
    rows = conn.execute(
        "SELECT d.draft_id, d.source_kind, d.source_id, d.conclusion, d.status,"
        " d.draft ->> 'title', d.draft <> '{}'::jsonb, d.warnings, d.conflict_with_entry,"
        " d.duplicate_of_entry, d.created_at, d.reviewed_by, u.username, d.reviewed_at,"
        f" d.review_note{_DRAFT_FROM} WHERE d.status = %s ORDER BY {order} LIMIT %s OFFSET %s",
        (status, limit, offset),
    ).fetchall()
    return [
        {
            "draft_id": str(draft_id),
            "source_kind": kind,
            "source_id": source_id,
            "conclusion": conclusion,
            "status": row_status,
            "title": title,
            "has_text": has_text,
            "warnings": warnings,
            "conflict_with_entry": _text(conflict_with),
            "duplicate_of_entry": _text(duplicate_of),
            "created_at": created_at,
            "reviewed_by": _text(reviewed_by),
            "reviewed_by_name": reviewed_by_name,
            "reviewed_at": reviewed_at,
            "review_note": review_note,
        }
        for (
            draft_id,
            kind,
            source_id,
            conclusion,
            row_status,
            title,
            has_text,
            warnings,
            conflict_with,
            duplicate_of,
            created_at,
            reviewed_by,
            reviewed_by_name,
            reviewed_at,
            review_note,
        ) in rows
    ]


def _decision(conn: psycopg.Connection, event_type: str, subject_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT e.event_type, e.actor_id, u.username, e.created_at, e.payload FROM audit_events e"
        " LEFT JOIN users u ON u.user_id = e.actor_id"
        " WHERE e.event_type = %s AND e.subject_id = %s ORDER BY e.audit_id DESC LIMIT 1",
        (event_type, subject_id),
    ).fetchone()
    if row is None:
        return None
    kind, actor_id, actor_name, at, payload = row
    return {
        "event_type": kind,
        "actor_id": _text(actor_id),
        "actor_name": actor_name,
        "at": at,
        "payload": _safe(payload),
    }


def _enrichment(conn: psycopg.Connection, alert_ids: list[str]) -> dict[str, Any]:
    """`{alert id: enrichment block}` for the alerts that have one (a JSON object under
    `raw_payload.enrichment`; anything else is no block)."""
    if not alert_ids:
        return {}
    rows = conn.execute(
        "SELECT alert_id, raw_payload -> 'enrichment' FROM alerts WHERE alert_id = ANY(%s)"
        " AND jsonb_typeof(raw_payload -> 'enrichment') = 'object' ORDER BY alert_id",
        (alert_ids,),
    ).fetchall()
    return {alert_id: _safe(block) for alert_id, block in rows}


def _alert_source(conn: psycopg.Connection, alert_id: str) -> dict[str, Any]:
    return {
        "alert": queue.get_alert_view(conn, alert_id, mode="analyst"),
        "case": None,
        "investigation": None,
        "decision": _decision(conn, "tier1.decided", alert_id),
        "notes": [],
        "enrichment": _enrichment(conn, [alert_id]).get(alert_id),
    }


def _case_source(conn: psycopg.Connection, cfg: Any, case_id: str) -> dict[str, Any]:
    case = tier2_routes.case_detail(conn, case_id)
    investigation = None
    if case is not None:
        investigation = {
            **investigation_view.build_investigation(conn, cfg, case_id, None),
            "case_open": case["status"] == OPEN_CASE_STATUS,
        }
    heads = [] if case is None else [head["alert_id"] for head in case["heads"]]
    return {
        "alert": None,
        "case": case,
        "investigation": investigation,
        "decision": _decision(conn, "tier2.concluded", case_id),
        "notes": [] if case is None else case["notes"],
        "enrichment": _enrichment(conn, heads),
    }


@router.get("/api/admin/knowledge/drafts/{draft_id}")
def api_draft(conn: Conn, cfg: Cfg, claims: Admin, draft_id: uuid.UUID) -> dict[str, Any]:
    row = conn.execute(
        f"SELECT {_DRAFT_COLUMNS}{_DRAFT_FROM} WHERE d.draft_id = %s", (draft_id,)
    ).fetchone()
    if row is None:
        raise _refuse(404, "not_found")
    draft = _draft_json(row)
    kind, source_id = draft["source_kind"], draft["source_id"]
    source: dict[str, Any] = {"kind": kind, "id": source_id}
    source.update(
        _alert_source(conn, source_id) if kind == "alert" else _case_source(conn, cfg, source_id)
    )
    conflict = None
    if draft["conflict_with_entry"] is not None:
        found = entry_by_id(conn, draft["conflict_with_entry"])
        conflict = None if found is None else entry_json(found, conn, _root())
    source["conflict_entry"] = conflict
    return {"draft": draft, "source": source}


# ── the request bodies ────────────────────────────────────────────────────────────────────────


async def _read_object(request: Request) -> dict[str, Any]:
    """The body as a dict, `{}` for an empty one. The JSON content type is required first
    (`deps.require_json_type`), after the role check: the parameter that asks for this body is
    declared after `claims`. Nothing the client sent is repeated in an answer."""
    require_json_type(request)
    raw = await request.body()
    if not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except ValueError:  # JSONDecodeError and UnicodeDecodeError both
        raise _bad("body", "invalid") from None
    if not isinstance(value, dict):
        raise _bad("body", "invalid")
    return value


JsonBody = Annotated[dict[str, Any], Depends(_read_object)]


def _only(body: dict[str, Any], allowed: tuple[str, ...]) -> None:
    if set(body) - set(allowed):
        raise _bad("body", "invalid")


def _reason(body: dict[str, Any]) -> str:
    _only(body, ("reason",))
    value = body.get("reason")
    if value is None or (isinstance(value, str) and not value.strip()):
        raise _bad("reason", "required")
    try:
        return publish.check_reason(value)
    except publish.InvalidReason:
        raise _bad("reason", "invalid") from None


# ── approve, reject ───────────────────────────────────────────────────────────────────────────


@router.post("/api/admin/knowledge/drafts/{draft_id}/approve")
def api_approve(conn: Conn, claims: Admin, draft_id: uuid.UUID, body: JsonBody) -> Any:
    _only(body, ("edited",))
    edited = body.get("edited")
    if edited is not None and not isinstance(edited, dict):
        raise _bad("edited", "invalid")
    try:
        published = publish.approve_published(
            conn, draft_id, claims.user_id, edited=edited, root=_root()
        )
    except publish.DraftInvalid as exc:
        # raised before anything was written: the request's transaction has nothing to undo
        return JSONResponse(status_code=422, content={"faults": exc.faults})
    except publish.UnknownDraft:
        raise _refuse(404, "not_found") from None
    except publish.StaleDraft as exc:
        raise _refuse(409, exc.reason) from None
    except publish.PublishError:
        raise _refuse(409, "unpublishable") from None
    except OSError as exc:
        # the file could not be written: the savepoint already took the rows back
        logger.warning(
            "approve %s: the file could not be written (%s)", draft_id, type(exc).__name__
        )
        raise _refuse(503, "publish_failed") from None
    publish.commit_publication(conn, published)  # a failed commit removes the file
    return {"entry_id": str(published.entry_id)}


@router.post("/api/admin/knowledge/drafts/{draft_id}/reject")
def api_reject(conn: Conn, claims: Admin, draft_id: uuid.UUID, body: JsonBody) -> dict[str, Any]:
    reason = _reason(body)
    try:
        publish.reject(conn, draft_id, claims.user_id, reason)
    except publish.UnknownDraft:
        raise _refuse(404, "not_found") from None
    except publish.StaleDraft as exc:
        raise _refuse(409, exc.reason) from None
    return {"draft_id": str(draft_id), "status": "rejected"}


# ── the entries ───────────────────────────────────────────────────────────────────────────────


@router.get("/api/admin/knowledge/entries")
def api_list_entries(
    conn: Conn,
    claims: Admin,
    status: EntryStatus = "active",
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0, le=_OFFSET_MAX)] = 0,
) -> list[dict[str, Any]]:
    """Without the Markdown, the fingerprint and the evidence: the entry's own route has them."""
    rows = conn.execute(
        f"SELECT e.entry_id, e.version, e.status, {_TITLE_SQL}, e.conclusion, e.category,"
        " e.mitre_ids, e.tags, e.soar_scenario, e.rule_ids, e.log_source, e.file_path,"
        " e.content_sha256, jsonb_array_length(e.evidence), e.approved_by, u.username,"
        " e.approved_at FROM knowledge_entries e LEFT JOIN users u ON u.user_id = e.approved_by"
        " WHERE e.status = %s ORDER BY e.approved_at DESC NULLS LAST, e.entry_id LIMIT %s OFFSET %s",
        (status, limit, offset),
    ).fetchall()
    return [
        {
            "entry_id": str(entry_id),
            "version": version,
            "status": row_status,
            "title": title,
            "conclusion": conclusion,
            "category": category,
            "mitre_ids": mitre_ids,
            "tags": tags,
            "soar_scenario": soar_scenario,
            "rule_ids": rule_ids,
            "log_source": log_source,
            "file_path": file_path,
            "content_sha256": sha,
            "evidence_count": evidence_count,
            "approved_by": _text(approved_by),
            "approved_by_name": approved_by_name,
            "approved_at": approved_at,
        }
        for (
            entry_id,
            version,
            row_status,
            title,
            conclusion,
            category,
            mitre_ids,
            tags,
            soar_scenario,
            rule_ids,
            log_source,
            file_path,
            sha,
            evidence_count,
            approved_by,
            approved_by_name,
            approved_at,
        ) in rows
    ]


@router.get("/api/admin/knowledge/entries/{entry_id}")
def api_entry(conn: Conn, claims: Admin, entry_id: uuid.UUID) -> dict[str, Any]:
    found = entry_by_id(conn, entry_id)
    if found is None:
        raise _refuse(404, "not_found")
    return entry_json(found, conn, _root())


@router.post("/api/admin/knowledge/entries/{entry_id}/retire")
def api_retire(conn: Conn, claims: Admin, entry_id: uuid.UUID, body: JsonBody) -> dict[str, Any]:
    reason = _reason(body)
    try:
        retired = publish.retire_published(conn, entry_id, claims.user_id, reason, root=_root())
    except publish.UnknownEntry:
        raise _refuse(404, "not_found") from None
    except publish.StaleEntry:
        raise _refuse(409, "not_active") from None
    except OSError as exc:
        logger.warning("retire %s: the file could not be moved (%s)", entry_id, type(exc).__name__)
        raise _refuse(503, "publish_failed") from None
    publish.commit_publication(conn, retired)  # a failed commit moves the file back
    return {"entry_id": str(entry_id), "status": "retired"}


# ── the tags ──────────────────────────────────────────────────────────────────────────────────


@cache
def _descriptions() -> dict[str, str]:
    return read_tags_file(TAGS_FILE)[0]


@router.get("/api/admin/knowledge/tags")
def api_tags(claims: Admin) -> dict[str, Any]:
    """The closed vocabulary a draft's tags must come from (`rag/tags.yaml`): the names, sorted,
    and a one-line description of each."""
    names = sorted(load_tags())
    described = _descriptions()
    return {"tags": names, "descriptions": {name: described.get(name, "") for name in names}}
