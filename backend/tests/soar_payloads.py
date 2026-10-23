"""The SOAR team's two real payload samples, and the helpers that derive variants from them (P12-T02).

`fixtures/soar_payload_sample_1.0.json` is a Defender alert of scenario MW03 as the team first sent
it (before `asset.in_inventory` and `asset.criticality` existed); `fixtures/soar_payload_sample_sc03_1.0.json`
is a pfSense port scan in the current shape. Both are copies of the files under `docs/plan/tasks/P12/`.

Every function returns a fresh document, so a test may edit what it gets. `edit(doc, "a.b.c", value)`
sets a dotted path, or removes the key when no value is given. `stream_config`, `receive` and `run` are the
steps of the stream the Owner will run: every switch off, `intake.receive` (the webhook's own function),
then the `pipeline` job.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path

import psycopg
from app.infra import config, intake
from app.infra.jobs import Job
from app.llm import triage as T
from app.soar import pipeline

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SWITCHES = ("DEDUP_ENABLED", "PULL_ENABLED", "AUTOCLOSE_ENABLED", "ENRICHMENT_ENABLED")
MISSING = object()
T0 = datetime(2026, 10, 16, 3, 25, 22, tzinfo=UTC)


def sample(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def mw03(**asset_fields: object) -> dict:
    """The Defender sample as the team first sent it, with `asset_fields` set on `enrichment.asset`."""
    doc = sample("soar_payload_sample_1.0.json")
    doc["enrichment"]["asset"].update(asset_fields)
    return doc


def sc03() -> dict:
    """The pfSense port-scan sample: `high`, in the inventory, no account, one `clean` TI entry."""
    return sample("soar_payload_sample_sc03_1.0.json")


def ti(verdict: object) -> dict:
    """One `enrichment.ti` entry, shaped like the one in the SC03 sample."""
    return {"type": "ip", "value": "79.79.78.202", "looked_up": True, "verdict": verdict}


def edit(doc: dict, path: str, value: object = MISSING) -> dict:
    """`doc` with the dotted `path` set to `value`, or the key removed when no value is given."""
    *parents, leaf = path.split(".")
    node = doc
    for key in parents:
        node = node[key]
    if value is MISSING:
        del node[leaf]
    else:
        node[leaf] = value
    return doc


def with_wazuh_id(doc: dict, alert_id: str) -> dict:
    """① renders an alert id only in the Wazuh form `\\d+.\\d+` (`llm/builder.py` `ID_PATTERNS`); the
    samples carry the Graylog event id (`gl-…`), so a test that runs ① gives its alert one."""
    doc["id"] = alert_id
    return doc


def stream_config(monkeypatch) -> config.Config:
    """The stream the Owner will run: dedup, pull, auto-close and internal enrichment all off."""
    for name in SWITCHES:
        monkeypatch.setenv(name, "false")
    cfg = dataclasses.replace(config.load(env_file="/dev/null"), WEBHOOK_API_KEY="k")
    assert not any(getattr(cfg, name) for name in SWITCHES)
    return cfg


def receive(conn: psycopg.Connection, cfg: config.Config, doc: dict) -> int:
    """`intake.receive` of `doc` as a webhook body; returns the `intake_id`."""
    receipt = intake.receive(conn, json.dumps(doc).encode("utf-8"), "10.0.0.7", cfg)
    assert receipt.kind == "alert" and receipt.intake_id is not None
    return receipt.intake_id


def run(conn: psycopg.Connection, intake_id: int) -> None:
    pipeline.run_pipeline_job(
        conn, Job(job_id=-1, job_type="pipeline", subject_id=str(intake_id), attempts=1)
    )


def receive_and_run(conn: psycopg.Connection, cfg: config.Config, doc: dict) -> None:
    run(conn, receive(conn, cfg, doc))


def llm_cfg() -> config.Config:
    return dataclasses.replace(
        config.Config(), LLM_MODEL_PROPOSER="proposer-model", LLM_MODEL_VERIFIER="verifier-model"
    )


def triage_input(**overrides) -> T.TriageInput:
    """A medium malware alert whose context is known and which meets every condition of `mal-1`
    but the occurrence one."""
    base = {
        "alert_id": "1789200000.300001",
        "rule_id": "100140",
        "rule_level": 5,
        "alert_time": T0,
        "severity": "medium",
        "category": "malware",
        "categories": ("malware",),
        "occurrence_count": 3,
        "risk_score": 38,
        "description": "Microsoft Defender: Malware Detected",
        "raw_log": "Defender detected Virus:DOS/EICAR_Test_File",
        "raw_log_truncated": False,
        "agent_name": "Windows_Endpoint",
        "origin_host": "Windows_Endpoint",
        "agent_id": "001",
        "alert_user": "hr01",
        "mitre_ids": (),
        "asset_context": {"present": True, "criticality": "medium", "owner": None, "role": None},
        "identity_context": {"privileged": False},
        "ioc_context": {"reputation": "clean"},
        "lookup_status": {"asset": "found", "identity": "found", "ioc": "found"},
        "first_seen_at": T0,
        "last_seen_at": T0,
    }
    base.update(overrides)
    return T.TriageInput(**base)
