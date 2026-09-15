"""One intake row to one alert: parse, dedup, enrich, auto-close, queue.

`run_pipeline_job(conn, job)` is the `pipeline` job handler (§6.5); the worker
(`infra/worker.py`, via the composition root `web/worker.py`) opens the 3 s
transaction and calls this with `job.subject_id` = the `intake_id`. One
intake row -> one outcome in one transaction (the advisory-lock region
excepted): `jobs('triage')` lands in the same transaction as `queued_tier1`
or `auto_closed` (E6 — see `domain.transitions.finish_enrichment`/`open_alert`),
the `intake` receipt is written exactly once, at the end of whichever branch
ran (G12).

This is the one module G1 allowlists to import `ingest/` (`("soar.pipeline",
"ingest")`, P2-tasks.md planning decision 10): dedup and auto-close are
`ingest/` tier code, and `soar/pipeline.py` is the orchestrator that owns the
transaction they run inside.

Idempotency (design note 2 step 1): a re-claimed job whose `intake` row
already carries `processed_at` returns immediately without touching anything
else — the case that matters is a worker killed between the main
transaction's COMMIT and `finish_job` (see `test_pipeline.py`'s E6 test, and
`SOC_CRASH_AFTER` below). It also means a `pipeline` job can never legitimately
fail twice on the same row: 017 pins `intake.error` once set, and the second
write a retried job would attempt is exactly what that pin exists to refuse
(see `_write_rejection_receipt`, exercised directly by `test_pipeline.py`'s
"error never rewritten" test — acceptance 10).
"""

from __future__ import annotations

import hashlib
import json
import os

import psycopg
from psycopg.types.json import Jsonb

from app.domain import transitions
from app.domain.alert import Alert, AlertContext
from app.enrichment import lookups
from app.infra import config
from app.infra.errors import PermanentError, classify
from app.infra.jobs import Job
from app.ingest import autoclose, dedup
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.soar.risk import compute_risk_score

#: Only set by test_pipeline.py's E6 test, in a subprocess: crash right after
#: `finish_enrichment` returns and before the receipt write, to prove the two
#: are one transaction (design note 5).
_CRASH_AFTER_ENV = "SOC_CRASH_AFTER"


def run_pipeline_job(conn: psycopg.Connection, job: Job) -> None:
    intake_id = int(job.subject_id)
    row = conn.execute(
        "SELECT raw_text, via, processed_at FROM intake WHERE intake_id = %s",
        (intake_id,),
    ).fetchone()
    if row is None:
        raise PermanentError(f"run_pipeline_job: no intake row with intake_id={intake_id}")
    raw_text, via, processed_at = row
    if processed_at is not None:
        # Idempotent re-run after a crash between COMMIT and finish_job — the
        # row already carries a receipt, so there is nothing left to do.
        return

    try:
        _process(conn, intake_id, raw_text, via)
    except Exception as exc:  # classified below (transient/permanent), then re-raised
        if classify(exc) == "permanent":
            conn.rollback()
            _write_rejection_receipt(conn, intake_id, str(exc)[:1000])
        # Transient: write nothing to intake — a fresh claim retries the whole
        # row from scratch, and the worker's own rollback undoes this attempt.
        raise


def _process(conn: psycopg.Connection, intake_id: int, raw_text: str, via: str) -> None:
    doc = json.loads(raw_text)
    result = parse_wazuh_alert(doc)
    if result.alert is None:
        _reject(conn, intake_id, doc, result.rejection)
        return
    alert = result.alert

    source = _derive_source(via, result.envelope)
    suggestion_visible = _suggestion_visible(alert.alert_id)

    # Cache rule (phase-3 §Cache): loaded before the advisory lock so no rule
    # query runs inside the serialised region.
    rules = autoclose.load_rules(conn)

    dedup.cluster_lock(conn, alert.rule_id, alert.srcip, alert.dstip, alert.agent_name)
    head = dedup.find_open_cluster(conn, alert)
    if head is not None:
        dedup.bump_parent(conn, head.alert_id)
        transitions.open_alert(
            conn,
            alert,
            kind="duplicate",
            source=source,
            suggestion_visible=suggestion_visible,
            duplicate_of=head.alert_id,
        )
        _finish_receipt(conn, intake_id, "duplicate")
        return

    # Internal enrichment — always, for every non-duplicate alert (E1, M1).
    ctx = _build_context(conn, alert)
    risk_score, risk_components = compute_risk_score(alert.severity, ctx, 1)

    decision = autoclose.evaluate(conn, alert, ctx, rules=rules)
    if decision.match is not None:
        transitions.open_alert(
            conn,
            alert,
            kind="auto_closed",
            source=source,
            suggestion_visible=suggestion_visible,
            rule=decision.match,
            context=ctx,
            risk_score=risk_score,
            risk_components=risk_components,
        )
        _finish_receipt(conn, intake_id, "auto_closed")
        return

    transitions.open_alert(
        conn, alert, kind="received", source=source, suggestion_visible=suggestion_visible
    )
    transitions.start_enrichment(conn, alert.alert_id)
    # A5/A6 and the `triage` enqueue are one function in `domain` (E6 holds
    # because of that, not because of anything here) — see module docstring.
    transitions.finish_enrichment(
        conn,
        alert.alert_id,
        context=ctx,
        risk_score=risk_score,
        risk_components=risk_components,
    )
    if os.environ.get(_CRASH_AFTER_ENV) == "finish_enrichment":
        os._exit(3)
    _finish_receipt(conn, intake_id, "alert")


def _build_context(conn: psycopg.Connection, alert: Alert) -> AlertContext:
    asset = lookups.lookup_asset(conn, alert.agent_name, alert.origin_host)
    identity = lookups.lookup_identity(conn, alert.alert_user)
    ioc = lookups.lookup_ioc(
        conn,
        alert.srcip,
        alert.dstip,
        srcip_is_private=alert.srcip_is_private,
        dstip_is_private=alert.dstip_is_private,
    )
    return AlertContext(
        asset["present"],
        asset["criticality"],
        asset["owner"],
        asset["role"],
        identity["is_privileged"],
        ioc["reputation"],
        {"asset": asset["status"], "identity": identity["status"], "ioc": ioc["status"]},
    )


def _derive_source(via: str, envelope: str) -> str:
    """Planning decision 3 (INBOX 2026-09-06 · P2-T10/P2-T13, DEC-035): a
    replay row is recognised by document shape, not by `via` alone — a webhook
    row is always `'wazuh'` whatever its shape."""
    return "replay" if via == "pull" and envelope == "bare" else "wazuh"


def _suggestion_visible(alert_id: str) -> bool:
    """A stable digest of `alert_id` (D13, `prompts/P2.md`) — sha256, never
    Python's per-process-salted builtin."""
    fraction = config.load().EVAL_BLIND_FRACTION
    digest = int(hashlib.sha256(alert_id.encode("utf-8")).hexdigest()[:8], 16)
    if fraction == 0.5:
        return digest % 2 == 0
    return (digest % 100) >= int(fraction * 100)


def _reject(conn: psycopg.Connection, intake_id: int, doc: object, reason: str | None) -> None:
    conn.execute(
        "INSERT INTO rejected_alerts (raw_payload, reason, source_ip) VALUES (%s, %s, %s)",
        (Jsonb(doc), reason, ""),
    )
    _finish_receipt(conn, intake_id, "rejected", error=reason)


def _finish_receipt(
    conn: psycopg.Connection, intake_id: int, outcome: str, *, error: str | None = None
) -> None:
    """The one G12 receipt write, in the same transaction as everything else
    in this branch — never a second write to the same row (017 pins each of
    `processed_at`/`outcome`/`error` once set)."""
    conn.execute(
        "UPDATE intake SET processed_at = now(), outcome = %s, error = %s WHERE intake_id = %s",
        (outcome, error, intake_id),
    )


def _write_rejection_receipt(conn: psycopg.Connection, intake_id: int, message: str) -> None:
    """Design note 2 step 9's fresh, short transaction: on a *permanent*
    exception the caller has already rolled back the main one, so this is a
    clean write. 017's trigger pins `error` once set — a second call on a row
    that already carries one is refused (`intake row … receipt columns are
    pinned once set`), which is what stops a retried job from ever rewriting
    the first failure's reason; the refusal itself becomes the *next*
    exception, classified and recorded in `jobs.last_error` by the caller."""
    conn.execute(
        "UPDATE intake SET processed_at = now(), outcome = 'rejected', error = %s "
        "WHERE intake_id = %s",
        (message, intake_id),
    )
    conn.commit()
