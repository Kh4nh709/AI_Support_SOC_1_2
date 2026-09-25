"""P4-T08 — `infra/intake.py:receive` and `POST /webhook/alerts`.

Real commit/rollback semantics matter for one case here (planning decision 3:
a `400` must leave its `rejected_alerts` row committed, surviving the
`Conn`-scope rollback that follows any raised `HTTPException`), so — exactly
like `test_auth.py` — this module builds its own scratch database
(`sdb`/`scratch_dsn`) rather than using the shared `db` fixture, whose
isolation depends on nothing ever being committed. Every alert/document id
below carries a `uuid4` suffix so committed rows from one test never collide
with another's assertions inside the scratch database's lifetime (one
`dropdb`/`createdb` per test session, not per test).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from dataclasses import replace
from pathlib import Path

import psycopg
import pytest
from app.infra import config
from app.infra.jobs import Job
from app.soar.pipeline import run_pipeline_job
from app.web import deps, main
from fastapi.testclient import TestClient

from tests import conftest

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

ALLOWED_HOST = "10.0.0.7"
OUTSIDE_HOST = "192.0.2.9"
KEY = "k"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


ALERT_HIT = _load("alert_40112.json")  # _index/_id/_source/fields/sort envelope
ALERT_BARE = ALERT_HIT["_source"]  # the alert object alone — a webhook body shape
ARCHIVE_LINE = _load("archive_line_5503.json")
ARCHIVE_BARE = json.loads(ARCHIVE_LINE["event"]["original"])  # the manager's own bare object


def _uid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _copy_with_id(base: dict, new_id: str) -> dict:
    doc = json.loads(json.dumps(base))
    doc["id"] = new_id
    return doc


def _heartbeat_from(base: dict, new_id: str) -> dict:
    doc = _copy_with_id(base, new_id)
    doc["rule"] = {**doc.get("rule", {}), "id": config.Config.HEARTBEAT_RULE_ID}
    return doc


def _cfg(**overrides) -> config.Config:
    fields = {"WEBHOOK_API_KEY": KEY, "WEBHOOK_IP_ALLOWLIST": ["10.0.0.0/8"], **overrides}
    return replace(config.Config(), **fields)


def _bytes(doc: dict) -> bytes:
    return json.dumps(doc).encode("utf-8")


def _post(client: TestClient, body: bytes, *, key: str | None = KEY) -> object:
    headers = {} if key is None else {"X-API-Key": key}
    return client.post("/webhook/alerts", content=body, headers=headers)


# --------------------------------------------------------------------------
# scratch database — mirrors test_auth.py's sdb/scratch_dsn exactly, and for
# the same reason: this module needs real commit-then-later-rollback-is-a-
# no-op semantics, which the shared `db` fixture's never-commit isolation
# cannot exercise.
# --------------------------------------------------------------------------


def _scratch_dbname() -> str:
    session = os.environ.get("TEST_DATABASE_URL", conftest.DEFAULT_TEST_DATABASE_URL)
    return f"{conftest._dbname(session)}_webhook_test"


@pytest.fixture(scope="module")
def scratch_dsn():
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the webhook scratch database")
    dbname = _scratch_dbname()
    subprocess.run(["dropdb", "--if-exists", dbname], check=True, capture_output=True)
    subprocess.run(["createdb", dbname], check=True, capture_output=True)
    dsn = f"postgresql:///{dbname}"
    result = subprocess.run(
        ["bash", "scripts/migrate.sh", dsn],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"scratch migrate failed:\n{result.stderr}"
    try:
        yield dsn
    finally:
        subprocess.run(["dropdb", "--if-exists", dbname], check=False, capture_output=True)


@pytest.fixture
def sdb(scratch_dsn):
    conn = psycopg.connect(scratch_dsn)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture(autouse=True)
def _require_db_marker_for_scratch(request):
    uses = {"sdb", "scratch_dsn", "client"} & set(request.fixturenames)
    if uses and request.node.get_closest_marker("db") is None:
        pytest.fail(f"{request.node.nodeid} uses {sorted(uses)} without @pytest.mark.db")


@pytest.fixture
def client(sdb):
    """`Conn`'s real shape (commit on success, rollback on any exception —
    `HTTPException` included), against the scratch database."""

    def get_conn():
        try:
            yield sdb
        except BaseException:
            sdb.rollback()
            raise
        else:
            sdb.commit()

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg()
    try:
        yield TestClient(main.app, client=(ALLOWED_HOST, 1234))
    finally:
        main.app.dependency_overrides.pop(deps.get_conn, None)
        main.app.dependency_overrides.pop(deps.get_config, None)


# --------------------------------------------------------------------------
# alert / heartbeat paths — 201s
# --------------------------------------------------------------------------


@pytest.mark.db
def test_post_bare_alert_is_201_with_intake_id_and_one_pipeline_job(client, sdb) -> None:
    doc = _copy_with_id(ALERT_BARE, _uid("bare"))
    response = _post(client, _bytes(doc))
    assert response.status_code == 201, response.text
    intake_id = response.json()["intake_id"]
    assert isinstance(intake_id, int)

    row = sdb.execute(
        "SELECT manager_id, source_alert_id, via, outcome FROM intake WHERE intake_id = %s",
        (intake_id,),
    ).fetchone()
    assert row == ("IA1803", doc["id"], "webhook", None)

    (job_count,) = sdb.execute(
        "SELECT count(*) FROM jobs WHERE job_type = 'pipeline' AND subject_id = %s",
        (str(intake_id),),
    ).fetchone()
    assert job_count == 1


@pytest.mark.db
def test_post_indexer_hit_shape_is_201(client, sdb) -> None:
    doc = json.loads(json.dumps(ALERT_HIT))
    doc["_source"] = _copy_with_id(doc["_source"], _uid("hit"))
    response = _post(client, _bytes(doc))
    assert response.status_code == 201, response.text
    intake_id = response.json()["intake_id"]

    row = sdb.execute(
        "SELECT manager_id, source_alert_id, via FROM intake WHERE intake_id = %s",
        (intake_id,),
    ).fetchone()
    assert row == ("IA1803", doc["_source"]["id"], "webhook")


@pytest.mark.db
def test_same_body_again_is_409_and_no_second_job(client, sdb) -> None:
    doc = _copy_with_id(ALERT_BARE, _uid("dup"))
    body = _bytes(doc)
    first = _post(client, body)
    assert first.status_code == 201, first.text
    intake_id = first.json()["intake_id"]

    second = _post(client, body)
    assert second.status_code == 409
    assert second.json() == {"detail": "duplicate"}

    (job_count,) = sdb.execute(
        "SELECT count(*) FROM jobs WHERE job_type = 'pipeline' AND subject_id = %s",
        (str(intake_id),),
    ).fetchone()
    assert job_count == 1


# --------------------------------------------------------------------------
# auth / allowlist / disabled — 401 / 403 / 503, writing nothing
# --------------------------------------------------------------------------


@pytest.mark.db
def test_missing_key_is_401_and_writes_nothing(client, sdb) -> None:
    doc = _copy_with_id(ALERT_BARE, _uid("nokey"))
    (before,) = sdb.execute("SELECT count(*) FROM rejected_alerts").fetchone()
    response = _post(client, _bytes(doc), key=None)
    assert response.status_code == 401

    (count,) = sdb.execute(
        "SELECT count(*) FROM intake WHERE source_alert_id = %s", (doc["id"],)
    ).fetchone()
    assert count == 0
    (after,) = sdb.execute("SELECT count(*) FROM rejected_alerts").fetchone()
    assert after == before  # a missing key must write nothing at all, not even a rejection


@pytest.mark.db
def test_wrong_key_is_401_and_writes_nothing(client, sdb) -> None:
    doc = _copy_with_id(ALERT_BARE, _uid("wrongkey"))
    (before,) = sdb.execute("SELECT count(*) FROM rejected_alerts").fetchone()
    response = _post(client, _bytes(doc), key="not-the-key")
    assert response.status_code == 401

    (count,) = sdb.execute(
        "SELECT count(*) FROM intake WHERE source_alert_id = %s", (doc["id"],)
    ).fetchone()
    assert count == 0
    (after,) = sdb.execute("SELECT count(*) FROM rejected_alerts").fetchone()
    assert after == before  # a wrong key must write nothing at all, not even a rejection


@pytest.mark.db
def test_empty_key_config_is_503(client) -> None:
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(WEBHOOK_API_KEY="")
    doc = _copy_with_id(ALERT_BARE, _uid("disabled"))
    response = _post(client, _bytes(doc))
    assert response.status_code == 503
    assert response.json() == {"detail": "webhook disabled"}


@pytest.mark.db
def test_ip_outside_allowlist_is_403(client) -> None:
    outsider = TestClient(main.app, client=(OUTSIDE_HOST, 1))
    doc = _copy_with_id(ALERT_BARE, _uid("outside"))
    response = _post(outsider, _bytes(doc))
    assert response.status_code == 403


@pytest.mark.db
def test_empty_allowlist_denies_all(client, sdb) -> None:
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(WEBHOOK_IP_ALLOWLIST=[])
    doc = _copy_with_id(ALERT_BARE, _uid("emptyallow"))
    response = _post(client, _bytes(doc))
    assert response.status_code == 403

    (count,) = sdb.execute(
        "SELECT count(*) FROM intake WHERE source_alert_id = %s", (doc["id"],)
    ).fetchone()
    assert count == 0


# --------------------------------------------------------------------------
# size cap, and the two rejected_alerts shapes
# --------------------------------------------------------------------------


@pytest.mark.db
def test_oversize_body_is_413_before_parsing(client, sdb) -> None:
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(MAX_PAYLOAD_BYTES=1024)
    body = b"x" * 1025  # not JSON either — a 413 must win before any parse attempt
    response = _post(client, body)
    assert response.status_code == 413

    (count,) = sdb.execute(
        "SELECT count(*) FROM rejected_alerts WHERE raw_payload->>'body' = %s",
        (body.decode("utf-8"),),
    ).fetchone()
    assert count == 0


@pytest.mark.db
def test_missing_id_is_400_naming_id_with_one_rejected_row(client, sdb) -> None:
    doc = json.loads(json.dumps(ALERT_BARE))
    del doc["id"]
    marker = _uid("noid-rule")
    doc["rule"] = {**doc["rule"], "id": marker}
    response = _post(client, _bytes(doc))
    assert response.status_code == 400
    assert response.json() == {"detail": {"missing": "id"}}

    rows = sdb.execute(
        "SELECT reason, source_ip, raw_payload FROM rejected_alerts "
        "WHERE raw_payload->'rule'->>'id' = %s",
        (marker,),
    ).fetchall()
    assert len(rows) == 1
    reason, source_ip, raw_payload = rows[0]
    assert reason == "id"
    assert source_ip == ALLOWED_HOST
    assert "id" not in raw_payload


@pytest.mark.db
def test_not_json_is_400_not_json(client, sdb) -> None:
    body = b"{not valid json at all"
    response = _post(client, body)
    assert response.status_code == 400
    assert response.json() == {"detail": {"missing": "not_json"}}

    reason, payload = sdb.execute(
        "SELECT reason, raw_payload FROM rejected_alerts WHERE raw_payload->>'body' = %s",
        (body.decode("utf-8"),),
    ).fetchone()
    assert reason == "not_json"
    assert payload == {"body": body.decode("utf-8")}


# --------------------------------------------------------------------------
# heartbeat — 201, no job, source_heartbeat touched
# --------------------------------------------------------------------------


@pytest.mark.db
def test_heartbeat_bare_and_hit_shapes_are_201_no_job_and_touch_source_heartbeat(
    client, sdb
) -> None:
    bare = _heartbeat_from(ALERT_BARE, _uid("hb-bare"))
    hit_doc = json.loads(json.dumps(ALERT_HIT))
    hit_doc["_source"] = _heartbeat_from(hit_doc["_source"], _uid("hb-hit"))

    before = sdb.execute(
        "SELECT last_seen_at FROM source_heartbeat WHERE manager_id = 'indexer'"
    ).fetchone()

    for body in (_bytes(bare), _bytes(hit_doc)):
        response = _post(client, body)
        assert response.status_code == 201, response.text
        assert response.json() == {"heartbeat": True}

    for source_alert_id in (bare["id"], hit_doc["_source"]["id"]):
        outcome, processed_at = sdb.execute(
            "SELECT outcome, processed_at FROM intake WHERE source_alert_id = %s",
            (source_alert_id,),
        ).fetchone()
        assert outcome == "heartbeat"
        assert processed_at is not None
        (job_count,) = sdb.execute(
            "SELECT count(*) FROM jobs WHERE job_type = 'pipeline' AND subject_id = ("
            "SELECT intake_id::text FROM intake WHERE source_alert_id = %s)",
            (source_alert_id,),
        ).fetchone()
        assert job_count == 0

    after = sdb.execute(
        "SELECT last_seen_at FROM source_heartbeat WHERE manager_id = 'indexer'"
    ).fetchone()
    assert after is not None
    assert before is None or after[0] >= before[0]


# --------------------------------------------------------------------------
# G9 — raw_text byte identity
# --------------------------------------------------------------------------


@pytest.mark.db
def test_raw_text_is_byte_identical_for_irregular_whitespace(client, sdb) -> None:
    source_alert_id = _uid("raw")
    body = (
        b'{\n  "id":   "' + source_alert_id.encode() + b'",\n'
        b'  "manager":{"name":"IA1803"},\n'
        b'  "rule":  {  "id" : "40112" , "description":"x"  },\n'
        b'  "timestamp":"2026-09-20T00:00:00+0700",\n'
        b'  "full_log":"a   b\\tc"\n}\n'
    )
    response = _post(client, body)
    assert response.status_code == 201, response.text

    (raw_text,) = sdb.execute(
        "SELECT raw_text FROM intake WHERE source_alert_id = %s", (source_alert_id,)
    ).fetchone()
    assert raw_text.encode("utf-8") == body
    (control,) = sdb.execute(
        "SELECT raw_payload::text != raw_text FROM intake WHERE source_alert_id = %s",
        (source_alert_id,),
    ).fetchone()
    assert control is True  # jsonb collapses whitespace; raw_text does not (DEC-023)


# --------------------------------------------------------------------------
# DEC-035 — via='webhook' always derives source='wazuh', bare body included
# --------------------------------------------------------------------------


@pytest.mark.db
def test_via_is_webhook_and_pipeline_derives_wazuh(client, sdb) -> None:
    alert_id = _uid("src")
    doc = _copy_with_id(ALERT_BARE, alert_id)
    response = _post(client, _bytes(doc))
    assert response.status_code == 201, response.text
    intake_id = response.json()["intake_id"]

    (via,) = sdb.execute("SELECT via FROM intake WHERE intake_id = %s", (intake_id,)).fetchone()
    assert via == "webhook"

    run_pipeline_job(
        sdb, Job(job_id=-1, job_type="pipeline", subject_id=str(intake_id), attempts=1)
    )
    (source,) = sdb.execute("SELECT source FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()
    assert source == "wazuh"


# --------------------------------------------------------------------------
# archive-line fixture sanity — ARCHIVE_BARE is a usable, envelope-free body
# --------------------------------------------------------------------------


@pytest.mark.db
def test_archive_line_bare_body_is_accepted(client, sdb) -> None:
    doc = _copy_with_id(ARCHIVE_BARE, _uid("archive"))
    response = _post(client, _bytes(doc))
    assert response.status_code == 201, response.text
    intake_id = response.json()["intake_id"]
    (via,) = sdb.execute("SELECT via FROM intake WHERE intake_id = %s", (intake_id,)).fetchone()
    assert via == "webhook"


def test_intake_module_has_no_forbidden_imports() -> None:
    source = Path("backend/app/infra/intake.py").read_text(encoding="utf-8")
    for pkg in (
        "app.audit",
        "app.domain",
        "app.tier1",
        "app.web",
        "app.kb",
        "app.llm",
        "app.security",
        "app.soar",
        "app.ingest",
        "app.enrichment",
    ):
        assert f"import {pkg}" not in source and f"from {pkg}" not in source
