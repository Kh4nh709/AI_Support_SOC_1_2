"""tier2/investigation_view.py — the ② investigation view behind
`GET /api/tier2/cases/{id}/investigation`, the JSON the React case page (P10-T11) reads (P10-T03).

Moved here **verbatim** from the Jinja case-analyze page's router (P5-T05, DEC-151 wave 4) so
that the page and the JSON API were built by one function, `build_investigation`. The Jinja
page retired in P10-T13 and the JSON API is the only caller now. Nothing here imports `web`: the
constants, the SQL and the functions are the ones the page had, with the leading underscore
dropped from the functions.

**The state is read from the database, not over HTTP.** It is derived from `jobs` and
`llm_runs` directly:

* the case's newest `investigate` job has its FINAL row (`run_id_for_job(job_id)`) -> the
  result, whatever the job's status (a live job with a row is `done`, as `GET
  /api/tier2/runs/{id}` treats it);
* no row and the job is `pending`/`running` -> `running` — unless the job is *stalled* (review
  round 1, S2): `pending` for more than `STALL_TIMEOUT_FACTOR` x `JOB_LOCK_TIMEOUT_S` since
  `scheduled_at`, or `running` for more than that since `locked_at`, by the database's `now()`.
  A stalled job reports the whole minutes it has waited. The view does not say the worker is
  dead: a triage backlog can legitimately delay the job;
* no row and the job is `failed` -> `failed` (a last attempt that dies without an LLM error
  — a statement timeout while the dossier is built — leaves no row, so the API answers 404
  after the 202);
* no usable job -> the newest row that is not a transient attempt (`stopped_by !=
  'transient'`: a non-final failed attempt writes one under an attempt-scoped id, P5-T04
  round 1 B1, and is not an outcome), else `idle`.

A caller may also pass the `run_id` of the 202. If the server finds nothing at all behind it
(no job, no row) that is the API's 404, and it is reported as `failed` rather than `idle`. It
only ever turns `idle` into `failed`: a real running or finished state wins.

`llm_runs` is read here (not through `GET /api/tier2/runs/{id}`, which returns neither
`agent_trace` nor `created_at` and does not check that the run belongs to a case), always
filtered by `subject_id = <this case>`.

**The model's own conclusion and why it was held (P14-T02, DEC-213).** A done run carries
`model_conclusion` - what the model itself answered, from `evidence_check.model_conclusion` - and
`held_by`, the closed causes the system had for storing `need_more_data` instead
(`no_verified_evidence`, `high_severity_injection_finding`). A run written before P14-T02 has no
`model_conclusion`; it gives `None` and `[]` and is not guessed at. Both are derived from what the job
already stores, so the view adds no column and no new stored key beyond `model_conclusion` itself.

**The RAG beside the conclusion (P14-T07, DEC-213).** A done or stopped run carries `rag`, `{"best_pct",
"not_applied", "below_floor_pct", "floor_pct"}` (`llm.rag_view`): `best_pct`, the best match of the lookup the
run's prompt held (`llm_runs.rag_lookup_id`), and `not_applied`, the closed kind of the run's
`rag_not_applied:<kind>` warning (`citation_warnings`; a stopped run carries it too). DEC-220 (trial) adds
`below_floor_pct`, the best candidate the rerank scored (that lookup's `ranked`) when the lookup kept no match,
and `floor_pct`, the `cfg.RAG_MIN_SCORE` it was under. All of it comes out of the statement that reads the run (a
scalar subquery each for the lookup's `matches` and `ranked`), so there is no second read; a run from before T06
gives the empty pair. The case page has no blind arm, so the key is always there.

Model output is untrusted. It leaves here as plain values (strings, lists, dicts) and the React
UI renders it as text. This module builds no markup (`test_investigation_view_guard.py` scans
its source for anything that would mark a string as safe).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

import psycopg

from app.llm import rag_view, results, verdicts
from app.rag.failures import FAILURE_KINDS
from app.tier2.investigate import (
    HELD_BY,  # noqa: F401 - the view's public name for the closed causes (test_investigation_view_api pins it)
    MIN_QUOTE_CHARS,
    held_causes,
    run_id_for_job,
)

#: `llm_runs.result.suggested_conclusion` in Vietnamese: the keys are `verdicts.GATED_CONCLUSIONS` - the
#: three conclusions of `docs/phase-7-tier2.md` the model may give (`investigate_v3` and `investigate_v4`, the same wording
#: the retired Jinja case page's status labels used for them) plus the value only the system sets,
#: `need_more_data` (P14-T02). `tests/test_conclusions.py` ties the keys to the tuple.
CONCLUSION_LABELS: dict[str, str] = {
    "false_positive": "Không phải sự cố",
    "policy_violation": "Có vi phạm nội quy, không phải tấn công",
    "confirmed_incident": "Là sự cố thật",
    "need_more_data": "Cần thêm dữ liệu",
}

#: `llm_runs.stopped_by` for a row with no `result` (P5-T04's closed set).
STOPPED_TEXT: dict[str, str] = {
    "cap": "đã chạm hạn mức chi phí LLM",
    # R4/INT-T02: a provider 402 is `permanent` too (`LLMUnavailable` is an `LLMPermanent`), so the
    # sentence names the provider as well as the model.
    "permanent": "nhà cung cấp hoặc mô hình từ chối yêu cầu (ví dụ hết số dư, 402), không thử lại",
    "linter": "dữ liệu của case không qua bộ kiểm tra an toàn trước khi gửi cho mô hình",
    "schema": "mô hình trả lời sai định dạng, kể cả sau một lần sửa",
    "transient": "mô hình không phản hồi sau nhiều lần thử",
}

#: `evidence_check.rejected[].reason` — the three `_check_evidence` writes.
REJECT_TEXT: dict[str, str] = {
    "not_in_case": "alert này không thuộc case",
    "quote_not_found": "trích dẫn không có trong log hay mô tả của alert",
    "quote_too_short": f"trích dẫn ngắn hơn {MIN_QUOTE_CHARS} ký tự nên không kiểm chứng được",
}
REJECT_TEXT_UNKNOWN = "chưa được đối chiếu với log của alert"

#: `evidence_check.forced_by`, in words.
FORCED_BY_TEXT: dict[str, str] = {
    "high_severity_injection_finding": (
        "dữ liệu của case chứa dấu hiệu tiêm lệnh (prompt injection) mức cao, "
        "nên không được kết luận là dương tính giả (false_positive)"
    ),
}
OVERRULE_NO_EVIDENCE = "không có bằng chứng nào kiểm chứng được với log của case"

_LIVE_JOB_STATUSES = ("pending", "running")

#: A live job is *stalled* when it has waited longer than this many `JOB_LOCK_TIMEOUT_S`
#: (review round 1, S2). The bound is the worker's own lock timeout, the one `reclaim_stale`
#: already uses, doubled so a job that is merely being reclaimed is not called stalled; it needs
#: no new config key and no schema change.
STALL_TIMEOUT_FACTOR = 2

#: `age_s` is measured by the database's `now()` (never the web host's clock): for a pending job
#: since `scheduled_at` — not `created_at`, because a retry's backoff moves `scheduled_at` — and
#: for a running job since `locked_at` (a running row with no lock stamp falls back to
#: `scheduled_at`, which is only older). A pending job scheduled in the future (backoff) has a
#: negative age and is never stalled.
_LATEST_JOB_SQL = (
    "SELECT job_id, status, "
    "CASE status "
    "WHEN 'pending' THEN extract(epoch FROM (now() - scheduled_at)) "
    "WHEN 'running' THEN extract(epoch FROM (now() - coalesce(locked_at, scheduled_at))) "
    "END::float8 "
    "FROM jobs WHERE job_type = 'investigate' AND subject_id = %s "
    "ORDER BY job_id DESC LIMIT 1"
)
# P14-T07: `citation_warnings` and the `matches` of the lookup the run's prompt held (`rag_lookup_id`, NULL when
# it held none) are the last columns, and DEC-220 adds that lookup's `ranked` (every candidate the rerank scored);
# `present_run` makes `rag` of them. `lookup_id` is the primary key of `rag_results`, so each subquery answers at
# most one row.
_RUN_COLUMNS = (
    "run_id, created_at, stopped_by, result, evidence_check, agent_trace, citation_warnings, "
    "(SELECT g.matches FROM rag_results g WHERE g.lookup_id = llm_runs.rag_lookup_id), "
    "(SELECT g.ranked FROM rag_results g WHERE g.lookup_id = llm_runs.rag_lookup_id)"
)
_RUN_BY_ID_SQL = (
    f"SELECT {_RUN_COLUMNS} FROM llm_runs "
    "WHERE run_id = %s AND pipeline = 'investigate' AND subject_id = %s"
)
_LATEST_FINAL_RUN_SQL = (
    f"SELECT {_RUN_COLUMNS} FROM llm_runs "
    "WHERE pipeline = 'investigate' AND subject_id = %s "
    "AND stopped_by IS DISTINCT FROM 'transient' "
    "ORDER BY created_at DESC, run_id DESC LIMIT 1"
)

#: The same three numbers `tier2.dossier.build` records as the run's snapshot — heads plus
#: the duplicates absorbed into them, the heads' `occurrence_count` summed, the newest
#: `last_seen_at` among the heads — read now, so the page can show them beside the recorded
#: ones. (`alerts.occurrence_count` on a head already counts its merged duplicates.)
_CURRENT_SQL = """
    WITH heads AS (
        SELECT alert_id, occurrence_count, last_seen_at FROM alerts
        WHERE alert_id IN (SELECT alert_id FROM case_alerts WHERE case_id = %s)
    )
    SELECT (SELECT count(*) FROM heads)
             + (SELECT count(*) FROM alerts WHERE duplicate_of IN (SELECT alert_id FROM heads)),
           (SELECT coalesce(sum(occurrence_count), 0) FROM heads),
           (SELECT max(last_seen_at) FROM heads)
"""


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def case_status(conn: psycopg.Connection, case_id: str) -> str | None:
    row = conn.execute("SELECT status FROM cases WHERE case_id = %s", (case_id,)).fetchone()
    return None if row is None else row[0]


def latest_final_row(conn: psycopg.Connection, case_id: str) -> tuple | None:
    return conn.execute(_LATEST_FINAL_RUN_SQL, (case_id,)).fetchone()


def current_values(conn: psycopg.Connection, case_id: str) -> dict[str, Any]:
    alert_count, total_occurrences, last_seen_at = conn.execute(_CURRENT_SQL, (case_id,)).fetchone()
    return {
        "alert_count": int(alert_count),
        "total_occurrences": int(total_occurrences),
        "last_seen_at": last_seen_at,
    }


def derive_view(
    conn: psycopg.Connection, cfg: Any, case_id: str, run_id_hint: uuid.UUID | None
) -> dict[str, Any]:
    """`{"state": idle|running|stalled|done|failed, "run_id": ..., "run_row": ...}` — see the
    module docstring for the rules."""
    job = conn.execute(_LATEST_JOB_SQL, (case_id,)).fetchone()
    if job is not None:
        job_id, job_status, age_s = job
        final_id = run_id_for_job(job_id)
        row = conn.execute(_RUN_BY_ID_SQL, (str(final_id), case_id)).fetchone()
        if row is not None:
            return {"state": "done", "run_row": row}
        if job_status in _LIVE_JOB_STATUSES:
            if age_s is not None and age_s > STALL_TIMEOUT_FACTOR * cfg.JOB_LOCK_TIMEOUT_S:
                return {"state": "stalled", "run_id": str(final_id), "minutes": int(age_s // 60)}
            return {"state": "running", "run_id": str(final_id)}
        if job_status == "failed":
            return {"state": "failed", "run_row": latest_final_row(conn, case_id)}
    row = latest_final_row(conn, case_id)
    if row is not None:
        return {"state": "done", "run_row": row}
    if run_id_hint is not None:
        return {"state": "failed", "run_row": None}
    return {"state": "idle", "run_row": None}


# ---------------------------------------------------------------------------
# Presentation — model output becomes plain values here.
# ---------------------------------------------------------------------------


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def stopped_text(stopped_by: str | None) -> str:
    if stopped_by is None:
        return "không rõ lý do"
    return STOPPED_TEXT.get(stopped_by, f"dừng ở bước {stopped_by}")


def evidence_rows(result: dict[str, Any], check: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per `result.evidence[i]`, marked from `evidence_check`. An item is verified
    only if its index is in `verified` and not in `rejected`; with no usable check nothing
    is verified — a mark is never assumed."""
    verified = {
        i for i in as_list(check.get("verified")) if isinstance(i, int) and not isinstance(i, bool)
    }
    rejected: dict[int, Any] = {}
    for entry in as_list(check.get("rejected")):
        if isinstance(entry, dict) and isinstance(entry.get("index"), int):
            rejected[entry["index"]] = entry.get("reason")

    rows: list[dict[str, Any]] = []
    for index, item in enumerate(as_list(result.get("evidence"))):
        item = item if isinstance(item, dict) else {}
        is_verified = index in verified and index not in rejected
        rows.append(
            {
                "alert_id": item.get("alert_id"),
                "quote": item.get("quote"),
                "why": item.get("why"),
                "verified": is_verified,
                "reason_text": (
                    None
                    if is_verified
                    else REJECT_TEXT.get(rejected.get(index), REJECT_TEXT_UNKNOWN)
                ),
            }
        )
    return rows


def labelled(code: Any) -> str:
    """ "Không phải sự cố (false_positive)": the Vietnamese label beside the code (review round 1,
    N3), so the reader who knows the codes and the reader who knows the words both find theirs. An
    unknown value is shown as it is — as data; the React UI renders it as text."""
    if isinstance(code, str) and code in CONCLUSION_LABELS:
        return f"{CONCLUSION_LABELS[code]} ({code})"
    return str(code)


def overrule_text(result: dict[str, Any], check: dict[str, Any]) -> str | None:
    """Said only when `_check_evidence`'s caller recorded `original_conclusion` — the model
    was overruled, not merely doubted."""
    original = check.get("original_conclusion")
    if not original:
        return None
    now = result.get("suggested_conclusion") or "need_more_data"
    forced_by = check.get("forced_by")
    if forced_by:
        cause = FORCED_BY_TEXT.get(forced_by, f"quy tắc {forced_by}")
    else:
        cause = OVERRULE_NO_EVIDENCE
    return (
        f"Mô hình đề xuất {labelled(original)} nhưng kết luận đã bị hạ xuống "
        f"{labelled(now)}: {cause}."
    )


def model_conclusion(check: dict[str, Any]) -> str | None:
    """What the model itself concluded (`evidence_check.model_conclusion`, written by every run since
    P14-T02), or `None` for a run that carries none - one from before P14-T02 - and for a value that is
    not one of `verdicts.MODEL_CONCLUSIONS`: a closed vocabulary leaves here, nothing else. The model can
    no longer answer `need_more_data`, so it is not a value the model's own conclusion can have."""
    value = check.get("model_conclusion")
    return value if isinstance(value, str) and value in verdicts.MODEL_CONCLUSIONS else None


def held_by(check: dict[str, Any]) -> list[str]:
    """Why the system held the model's conclusion back as `need_more_data`: `[]` when it did not, or
    when the run carries no `model_conclusion` (an old run is not guessed at); otherwise the causes the
    check records, in `HELD_BY`'s order - `no_verified_evidence` (no cited evidence verified) and
    `high_severity_injection_finding` (`evidence_check.forced_by`). Only the two closed values leave.
    """
    if model_conclusion(check) is None:
        return []
    return held_causes(check)


def snapshot(agent_trace: Any) -> dict[str, Any] | None:
    """`{alert_count, total_occurrences, last_seen_at}` from `llm_runs.agent_trace` (P5-T04
    `_snapshot_trace`), or `None` when the row carries none."""
    if not isinstance(agent_trace, dict):
        return None
    try:
        alert_count = int(agent_trace["alert_count"])
        total_occurrences = int(agent_trace["total_occurrences"])
    except (KeyError, TypeError, ValueError):
        return None
    raw = agent_trace.get("last_seen_at")
    last_seen_at = None
    if isinstance(raw, str):
        try:
            last_seen_at = datetime.fromisoformat(raw)
        except ValueError:
            last_seen_at = None
    return {
        "alert_count": alert_count,
        "total_occurrences": total_occurrences,
        "last_seen_at": last_seen_at,
    }


def present_run(row: tuple, rag_min_score: float | None = None) -> dict[str, Any]:
    """`row` is a row of `_RUN_COLUMNS`. `rag_min_score` is `RAG_MIN_SCORE` of the running configuration, the floor
    the run's best candidate was under (DEC-220): without it `rag` carries no `below_floor_pct`."""
    (
        run_id,
        created_at,
        stopped_by,
        result,
        evidence_check,
        agent_trace,
        citation_warnings,
        lookup_matches,
        lookup_ranked,
    ) = row
    rag = rag_view.rag_view(
        lookup_matches,
        citation_warnings,
        FAILURE_KINDS,
        ranked=lookup_ranked,
        floor=rag_min_score,
    )
    base: dict[str, Any] = {"run_id": str(run_id), "created_at": created_at, "rag": rag}
    if not isinstance(result, dict):
        return {**base, "result": None, "stopped_text": stopped_text(stopped_by)}

    check = evidence_check if isinstance(evidence_check, dict) else {}
    conclusion = result.get("suggested_conclusion")
    return {
        **base,
        "result": result,
        "conclusion": conclusion,
        "conclusion_label": CONCLUSION_LABELS.get(conclusion, "Chưa rõ kết luận"),
        "confidence": result.get("confidence"),
        "summary": result.get("summary"),
        "narrative": result.get("attack_narrative"),
        "hypotheses": [
            {
                "text": h.get("noi_dung"),
                "evidence_for": as_list(h.get("evidence_for")),
                "evidence_against": as_list(h.get("evidence_against")),
            }
            for h in as_list(result.get("gia_thuyet"))
            if isinstance(h, dict)
        ],
        "evidence": evidence_rows(result, check),
        # a version 4 run stores `{step, priority}` rows (DEC-221): this page reads the text of each step, as it
        # always has; a version 3 run's strings are themselves
        "next_steps": results.next_step_texts(result.get("next_steps")),
        "playbook_used": result.get("playbook_used"),
        "overruled": overrule_text(result, check),
        "model_conclusion": model_conclusion(check),
        "held_by": held_by(check),
        "snapshot": snapshot(agent_trace),
        "changed": False,
    }


# ---------------------------------------------------------------------------
# The view
# ---------------------------------------------------------------------------


def build_investigation(
    conn: psycopg.Connection, cfg: Any, case_id: str, run_id_hint: uuid.UUID | None
) -> dict[str, Any]:
    """`{"state": idle|running|stalled|done|failed, "run_id": str | None, "minutes": int | None,
    "run": dict | None, "current": dict | None}`. `run` is `present_run`'s dict — with `changed`
    set when the case's heads have grown since the run's recorded snapshot — for every state but
    `running` / `stalled` (a live job hides the previous result); `current` is the case's numbers
    now, and is set only when the run recorded a snapshot to compare them with. Read-only: the
    caller ends its transaction."""
    view = derive_view(conn, cfg, case_id, run_id_hint)
    run = None
    current = None
    if view["state"] not in ("running", "stalled") and view.get("run_row") is not None:
        # DEC-220: the floor is the running configuration's; a `cfg` that carries none (a partial one) gives no number
        run = present_run(view["run_row"], getattr(cfg, "RAG_MIN_SCORE", None))
        if run.get("snapshot") is not None:
            current = current_values(conn, case_id)
            snap = run["snapshot"]
            run["changed"] = (
                snap["alert_count"],
                snap["total_occurrences"],
                snap["last_seen_at"],
            ) != (current["alert_count"], current["total_occurrences"], current["last_seen_at"])
    return {
        "state": view["state"],
        "run_id": view.get("run_id"),
        "minutes": view.get("minutes"),
        "run": run,
        "current": current,
    }
