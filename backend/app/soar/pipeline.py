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

Three of its steps are switches (all default `true`, so a `.env` that names none of them is the
pipeline of before; read with `config.load()` per alert): `DEDUP_ENABLED` (DEC-165), and, for a
stream that arrives already enriched and closed by an external SOAR flow (DEC-207),
`AUTOCLOSE_ENABLED` (no rule is loaded or evaluated) and `ENRICHMENT_ENABLED` (no
`assets`/`identities`/`iocs` lookup; the context is the one SOAR put in the payload's `enrichment`
block, DEC-208, or the "unknown" one when the payload has no valid block). The risk score runs
either way.

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
import logging
import os
import re

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

logger = logging.getLogger(__name__)


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

    cfg = config.load()

    # Cache rule (phase-3 §Cache): loaded before the advisory lock so no rule
    # query runs inside the serialised region. DEC-207: with AUTOCLOSE_ENABLED=false
    # no rule is loaded (nor evaluated below) — the external SOAR stream owns the
    # decision to close.
    rules = autoclose.load_rules(conn) if cfg.AUTOCLOSE_ENABLED else None

    # DEC-165: with DEDUP_ENABLED=false nothing is grouped. The advisory lock, the
    # head lookup and the bump are all skipped, so no cluster lock is taken and no
    # head's `occurrence_count` moves; the alert falls through to the non-duplicate
    # path below and is its own head with its own enrichment and triage job. The
    # switch is forward-only: heads that are already open are neither closed nor
    # bumped, they simply stop receiving new members. Receipt-level idempotency
    # (`intake`'s (manager_id, source_alert_id) key) is upstream of this and untouched.
    if cfg.DEDUP_ENABLED:
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

    # Internal enrichment — for every non-duplicate alert (E1, M1), unless
    # ENRICHMENT_ENABLED=false (DEC-207): then `_build_context` looks nothing up and the
    # alert carries the context SOAR put in its payload (DEC-208), or the "unknown" one.
    # The risk score runs either way, and its occurrence addend is 0 (a count of 1).
    ctx = _build_context(conn, alert, cfg=cfg)
    risk_score, risk_components = compute_risk_score(alert.severity, ctx, 1)

    if cfg.AUTOCLOSE_ENABLED:
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


def _unknown_context() -> AlertContext:
    """DEC-207: what an alert knows about its asset, account and addresses when nothing is looked
    up and the payload tells nothing usable (DEC-208: no valid `enrichment` block). Every field is
    the vocabulary's own "unknown": `asset_present` false and criticality "unknown" (the gate treats
    both as a block, never as a pass), the account's privilege `None`, the IoC reputation and all
    three lookup statuses `skipped` (not a security signal, so the risk score adds nothing for them).
    """
    return AlertContext(
        False,
        "unknown",
        None,
        None,
        None,
        "skipped",
        {"asset": "skipped", "identity": "skipped", "ioc": "skipped"},
    )


# ---------------------------------------------------------------------------------------------
# DEC-208 (as amended 23/10): the context an external SOAR flow put in the payload.
#
# The body is the Wazuh-shaped alert plus `enrichment`, schema `1.x` (the team only adds fields
# in 1.x). Read with `ENRICHMENT_ENABLED=false`, in place of the internal lookups:
#   asset_criticality    <- asset.criticality   high|medium|low|unknown   (absent: unknown)
#   asset_present        <- asset.in_inventory  boolean                   (absent: false)
#   identity_privileged  <- asset.user_is_admin boolean: as given for an alert that names an
#                           account (`alert.alert_user`, which holds the parser's own reading and
#                           its `enrichment.asset.user` fallback); with no account a `true` is still
#                           kept and a `false` is dropped; null or absent: None, identity `skipped`
#   ioc_reputation       <- the worst of ti[].verdict and ioc.verdict, malicious > suspicious >
#                           clean (no block: `skipped`)
#   asset_owner          <- asset.owner  string (absent/null: None) — a local annotation the SIEM
#   asset_role           <- asset.role   string (absent/null: None)   adds (DEC-210 S5); display
#                           only, rendered in the `context` block, never a fact
# `asset.critical` is SOAR's own scoring flag, not an inventory level, and is not read. A value
# outside its vocabulary or of the wrong type anywhere makes the WHOLE context "unknown": a context
# trusted in part is not built. What is logged is the field's name and the kind of fault, never the
# value (it is attacker-controlled text).
# ---------------------------------------------------------------------------------------------

_SCHEMA_VERSION_RE = re.compile(r"1\.[0-9]+")  # ASCII digits: `\d` takes Arabic-Indic ones too
_CRITICALITIES = frozenset({"high", "medium", "low", "unknown"})
#: A verdict's rank; the reputation of the alert is the highest one found.
_VERDICT_RANK = {"clean": 0, "suspicious": 1, "malicious": 2}


class _InvalidField(Exception):
    """A payload field that cannot be read. Carries the field's dotted name and a fixed word for the
    fault, and never the value."""

    def __init__(self, field: str, fault: str) -> None:
        super().__init__(field, fault)
        self.field = field
        self.fault = fault


def _object(parent: dict, key: str, field: str) -> dict:
    """The mapping under `parent[key]`; an absent key or a `null` is an empty one (no block)."""
    value = parent.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise _InvalidField(field, "wrong type")
    return value


def _optional_bool(parent: dict, key: str, field: str) -> bool | None:
    """A boolean, or `None` when the key is absent or `null`. Anything else (a string, a number: `1`
    is not `true`) is a fault."""
    value = parent.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise _InvalidField(field, "wrong type")
    return value


def _optional_str(parent: dict, key: str, field: str) -> str | None:
    """A string, or `None` when the key is absent or `null`. Anything else is a fault. The value is
    free text that reaches the model only inside the `context` block (§7.1), so it is not inspected
    further here."""
    value = parent.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _InvalidField(field, "wrong type")
    return value


def _verdict(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise _InvalidField(field, "wrong type")
    if value not in _VERDICT_RANK:
        raise _InvalidField(field, "outside its vocabulary")
    return value


def _read_enrichment(document: object, *, names_account: bool) -> AlertContext:
    """The context of one payload, or `_InvalidField` naming the first field that cannot be read.
    `names_account`: the alert has an account (`alert.alert_user`), whoever supplied it."""
    enrichment = document.get("enrichment") if isinstance(document, dict) else None
    if enrichment is None:
        raise _InvalidField("enrichment", "missing")
    if not isinstance(enrichment, dict):
        raise _InvalidField("enrichment", "wrong type")
    version = enrichment.get("schema_version")
    if not isinstance(version, str) or _SCHEMA_VERSION_RE.fullmatch(version) is None:
        raise _InvalidField("enrichment.schema_version", "missing or not 1.x")

    asset = _object(enrichment, "asset", "enrichment.asset")
    criticality = "unknown"
    if "criticality" in asset:
        value = asset["criticality"]
        if not isinstance(value, str):
            raise _InvalidField("enrichment.asset.criticality", "wrong type")
        if value not in _CRITICALITIES:
            raise _InvalidField("enrichment.asset.criticality", "outside its vocabulary")
        criticality = value
    in_inventory: bool | None = None
    if "in_inventory" in asset:
        value = asset["in_inventory"]
        if not isinstance(value, bool):
            raise _InvalidField("enrichment.asset.in_inventory", "wrong type")
        in_inventory = value

    # S5 (DEC-210, Owner decision B): owner and role are local annotations the SIEM adds to the
    # enrichment. They are display-only text (the `context` block, §7.1) — never facts — so they do
    # not reach the gate; a value of the wrong type still fails the whole context (DEC-208 item 3).
    owner = _optional_str(asset, "owner", "enrichment.asset.owner")
    role = _optional_str(asset, "role", "enrichment.asset.role")

    user = asset.get("user")
    if user is not None and not isinstance(user, str):
        raise _InvalidField("enrichment.asset.user", "wrong type")
    user_is_admin = _optional_bool(asset, "user_is_admin", "enrichment.asset.user_is_admin")
    # A `false` says something only about an account the alert names: SOAR writes `false` for an
    # alert with none (the pfSense sample), and nothing was looked up for it. A `true` is never
    # dropped, whoever the account is (review finding 1): it blocks a `false_positive` at gate step
    # 4 and adds to the risk score, and a privileged flag lost is the worse mistake. "Names an
    # account" is the alert's own `alert_user` (the parser's reading, or its fallback to
    # `asset.user`), so the pipeline and the parser cannot disagree on who is named.
    privileged = user_is_admin if names_account or user_is_admin is True else None

    verdicts: list[str] = []
    ti = enrichment.get("ti")
    if ti is not None:
        if not isinstance(ti, list):
            raise _InvalidField("enrichment.ti", "wrong type")
        for entry in ti:
            if not isinstance(entry, dict):
                raise _InvalidField("enrichment.ti[]", "wrong type")
            verdicts.append(_verdict(entry.get("verdict"), "enrichment.ti[].verdict"))
    ioc = enrichment.get("ioc")
    if ioc is not None:  # a `null` is no block; `{}` is a block with no verdict, and a fault
        if not isinstance(ioc, dict):
            raise _InvalidField("enrichment.ioc", "wrong type")
        verdicts.append(_verdict(ioc.get("verdict"), "enrichment.ioc.verdict"))

    return AlertContext(
        in_inventory is True,
        criticality,
        owner,
        role,
        privileged,
        max(verdicts, key=_VERDICT_RANK.__getitem__) if verdicts else "skipped",
        {
            "asset": (
                "skipped" if in_inventory is None else "found" if in_inventory else "not_found"
            ),
            "identity": "skipped" if privileged is None else "found",
            "ioc": "found" if verdicts else "skipped",
        },
    )


def _context_from_payload(alert: Alert) -> AlertContext:
    """`alert.raw_payload`'s `enrichment` block as the alert's context (DEC-208), or the "unknown"
    context when the block is absent, is not schema `1.x`, or holds any field `_read_enrichment`
    refuses. The refusal is logged by field name and fault, never by value."""
    try:
        return _read_enrichment(
            alert.raw_payload, names_account=bool((alert.alert_user or "").strip())
        )
    except _InvalidField as exc:
        logger.warning(
            "soar context unknown: alert=%r field=%s fault=%s", alert.alert_id, exc.field, exc.fault
        )
        return _unknown_context()


def _build_context(
    conn: psycopg.Connection, alert: Alert, *, cfg: config.Config | None = None
) -> AlertContext:
    """`_process` passes the `cfg` it already holds, so the switches are read from one object per
    alert; `None` (a caller outside the pipeline, `test_adversarial`'s) loads it.

    With `ENRICHMENT_ENABLED=false` no statement is sent: the context is the payload's own
    (`_context_from_payload`, DEC-208). With it on, the internal lookups, exactly as before."""
    if not (cfg if cfg is not None else config.load()).ENRICHMENT_ENABLED:
        return _context_from_payload(alert)
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
