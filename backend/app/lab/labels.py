"""The lab labels (P14-T09, DEC-213, spec §6): the admin's hand label of an alert, and the blind list a run's
alerts are labelled from.

**A label** is `true_positive` (a real attack) or `false_positive` (not an attack), one per alert, in the run
the alert's `received_at` falls in. `set_label` derives that run (`runs.run_of`); the admin never chooses it,
so a label cannot say the alert belongs to a run it was not received in. Setting a label that exists
changes it (the same row; `labeled_by` and `labeled_at` move to the latest admin), and every call writes one
`lab.labeled {alert_id, run_id, label}` event for the admin; `clear_label` deletes the row and writes the
same event with `label` null. An alert nobody labelled is simply not scored.

**The list is blind.** The page shows the alert and not ①'s output, so the label is not biased by the AI
(spec §6, DEC-101). Two layers, as the gold-set labelling page has them (`tier1/labels.py`):

* what is read is an allowlist: `_SQL` selects the columns of `ITEM_KEYS` and `lab_labels.label`, and
  nothing of ① (`triage_status`, `risk_*`, `status`, `suggestion_visible`, the `llm_runs`, `rag_results`
  and `gate_result` rows) ever enters the process;
* the dict then passes `tier1.visibility.strip(..., mode="labeling")`, which drops every key of the labeller's
  denylist at any depth whatever the arm the alert is on. The two flags it takes are the fail-closed ones
  (`status=""`, `suggestion_visible=False`), as `tier1/labels.py:cluster_view` passes them: this module does
  not read either column.

Only queue heads are listed (`duplicate_of IS NULL`), oldest first by `received_at`, then `alert_id`; a page
continues after an `alert_id` (`after`).

Every function runs in the caller's transaction and commits nothing.
"""

from __future__ import annotations

from typing import Any

import psycopg

from app.audit.events import write_event
from app.lab.runs import LabError, UnknownRun, get_run, run_of
from app.tier1 import visibility

#: The same figure as the gold-set page's (`tier1.labels.RAW_LOG_DISPLAY_BYTES`), written again here and not
#: imported: that module loads the playbooks and the correlation code, and this one needs neither.
#: `test_lab_labels.py` holds the two equal.
RAW_LOG_DISPLAY_BYTES = 32_768

LABELS: tuple[str, ...] = ("true_positive", "false_positive")

DEFAULT_LIMIT = 100
MAX_LIMIT = 200

#: Every key of an item but `label`, in the order `_SQL` selects them: the whole of what a labeller is shown.
ITEM_KEYS: tuple[str, ...] = (
    "alert_id",
    "received_at",
    "alert_time",
    "rule_id",
    "rule_level",
    "severity",
    "description",
    "agent_name",
    "alert_user",
    "srcip",
    "dstip",
    "category",
    "mitre_ids",
    "occurrence_count",
    "raw_log",
    "raw_log_truncated_for_display",
)

_SQL = """
SELECT a.alert_id, a.received_at, a.alert_time, a.rule_id, a.rule_level, a.severity, a.description,
       a.agent_name, a.alert_user, a.srcip, a.dstip, a.category, a.mitre_ids, a.occurrence_count,
       left(a.raw_log, %(cap)s), length(a.raw_log) > %(cap)s, l.label
  FROM alerts a
  LEFT JOIN lab_labels l ON l.alert_id = a.alert_id
 WHERE a.received_at >= %(starts)s AND a.received_at < %(ends)s
   AND a.duplicate_of IS NULL
   AND (%(after)s::text IS NULL
        OR (a.received_at, a.alert_id) > (SELECT received_at, alert_id FROM alerts
                                           WHERE alert_id = %(after)s))
 ORDER BY a.received_at, a.alert_id
 LIMIT %(limit)s
"""


class UnknownAlert(LabError):
    """No alert has this id (404)."""


class OutsideEveryRun(LabError):
    """The alert was received outside every run's window, so it belongs to no run (409)."""


class InvalidLabel(LabError):
    """The label is not one of `LABELS` (422)."""


def set_label(conn: psycopg.Connection, alert_id: str, label: str, admin_id: str) -> str:
    """Label `alert_id` `label` for `admin_id`, in the run its `received_at` falls in; returns that run's id.
    A label that exists is changed. `InvalidLabel` is checked first (the request is malformed), then
    `UnknownAlert`, then `OutsideEveryRun`; nothing is written for any of them."""
    if not isinstance(label, str) or label not in LABELS:
        raise InvalidLabel(f"label: must be one of {'|'.join(LABELS)}")
    row = conn.execute("SELECT received_at FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()
    if row is None:
        raise UnknownAlert(alert_id)
    run = run_of(conn, row[0])
    if run is None:
        raise OutsideEveryRun(alert_id)
    conn.execute(
        "INSERT INTO lab_labels (alert_id, run_id, label, labeled_by) VALUES (%s, %s, %s, %s) "
        "ON CONFLICT (alert_id) DO UPDATE SET run_id = EXCLUDED.run_id, label = EXCLUDED.label, "
        "labeled_by = EXCLUDED.labeled_by, labeled_at = now()",
        (alert_id, run.run_id, label, admin_id),
    )
    write_event(
        conn,
        "lab.labeled",
        alert_id,
        "admin",
        actor_id=admin_id,
        payload={"alert_id": alert_id, "run_id": run.run_id, "label": label},
    )
    return run.run_id


def clear_label(conn: psycopg.Connection, alert_id: str, admin_id: str) -> None:
    """Remove the label of `alert_id` and write `lab.labeled` with a null label. Clearing what is not there
    changes nothing and writes nothing."""
    row = conn.execute(
        "DELETE FROM lab_labels WHERE alert_id = %s RETURNING run_id::text", (alert_id,)
    ).fetchone()
    if row is None:
        return
    write_event(
        conn,
        "lab.labeled",
        alert_id,
        "admin",
        actor_id=admin_id,
        payload={"alert_id": alert_id, "run_id": row[0], "label": None},
    )


def _for_display(text: str | None, cut_by_the_database: bool) -> tuple[str, bool]:
    """`raw_log` as shown: at most `RAW_LOG_DISPLAY_BYTES` bytes, cut on a character boundary, and whether
    anything was cut. The database cut it to that many characters already; a multibyte log can still be over
    the bytes."""
    log = text or ""
    encoded = log.encode("utf-8")
    if len(encoded) <= RAW_LOG_DISPLAY_BYTES:
        return log, cut_by_the_database
    return encoded[:RAW_LOG_DISPLAY_BYTES].decode("utf-8", errors="ignore"), True


def run_alerts(
    conn: psycopg.Connection,
    run_id: str,
    *,
    after: str | None = None,
    limit: int = DEFAULT_LIMIT,
) -> list[dict[str, Any]]:
    """The queue heads received inside the run's window, oldest first, each as `ITEM_KEYS` through
    `visibility.strip(..., mode="labeling")` plus `label` (`true_positive`, `false_positive` or None).
    `after` is the last `alert_id` of the page before; one that names no alert gives nothing. `UnknownRun`
    for a run that does not exist; `ValueError` for a `limit` that is not a whole number from 1 to
    `MAX_LIMIT`."""
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit: a whole number from 1 to {MAX_LIMIT}")
    run = get_run(conn, run_id)
    if run is None:
        raise UnknownRun(str(run_id))
    rows = conn.execute(
        _SQL,
        {
            "cap": RAW_LOG_DISPLAY_BYTES,
            "starts": run.starts_at,
            "ends": run.ends_at,
            "after": after,
            "limit": limit,
        },
    ).fetchall()
    items: list[dict[str, Any]] = []
    for *columns, label in rows:
        view = dict(zip(ITEM_KEYS, columns, strict=True))
        view["raw_log"], view["raw_log_truncated_for_display"] = _for_display(
            view["raw_log"], view["raw_log_truncated_for_display"]
        )
        item = visibility.strip(view, status="", suggestion_visible=False, mode="labeling")
        item["label"] = label
        items.append(item)
    return items
