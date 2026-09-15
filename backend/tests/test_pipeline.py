"""Tests for app.soar.pipeline.run_pipeline_job — one intake row to one outcome.

Every db-marked test here calls `run_pipeline_job` directly with a hand-built
`app.infra.jobs.Job` rather than going through `infra.worker.run_forever`:
`run_pipeline_job` never commits on its own success path (the caller owns the
transaction — design note 2), so driving it directly keeps every test inside
the `db` fixture's own transaction, rolled back at teardown (conftest.py) —
tests never see each other's alerts/intake/jobs rows even though several
reuse the same two fixture documents. `TEST_DATABASE_URL=postgresql:///soc_p2t10_test`
on every db-marked invocation (DEC-023 item 8).

The one exception is the E6 crash test (acceptance 7): it must cross a real
process boundary (`SOC_CRASH_AFTER` only works in a subprocess that can
actually `os._exit`), so it commits for real — against its own scratch
database (`soc_p2t10_e6_test`, dropped and freshly migrated by its own
fixture), never the shared `soc_p2t10_test` the `db`/`_test_database`
fixtures serve every other test here: acceptance 14's `make test-db` runs the
whole suite against one `TEST_DATABASE_URL`, and other files' db-marked tests
(e.g. `test_schema_v3_017.py`'s row-count assertions) assume a table this
test would otherwise leave non-empty.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import psycopg
import pytest
from app.enrichment import inventory
from app.infra.errors import classify
from app.infra.jobs import Job, claim_job, enqueue, finish_job
from app.soar.pipeline import _suggestion_visible, _write_rejection_receipt, run_pipeline_job
from psycopg.types.json import Jsonb

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
PIPELINE_SOURCE = (Path(__file__).resolve().parents[1] / "app" / "soar" / "pipeline.py").read_text(
    encoding="utf-8"
)

ADMIN_USER_ID = "00000000-0000-0000-0000-00000000a010"


def _raw(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


RULE_5503 = _raw("indexer_sample_rule5503.json")  # medium severity, agent user1-IA1803
ALERT_40112 = _raw("alert_40112.json")  # critical severity, agent user1-IA1803


def _hit(base_raw: str, *, id_: str, srcip: str | None = None, sort: int = 1) -> str:
    """`base_raw` (an indexer-hit fixture) with `_source.id` — and, when given,
    `_source.data.srcip` — overridden, so a test controls both alert identity
    and cluster key without hand-building a whole document."""
    doc = json.loads(base_raw)
    doc["_source"] = dict(doc["_source"])
    doc["_source"]["id"] = id_
    if srcip is not None:
        doc["_source"]["data"] = dict(doc["_source"].get("data") or {})
        doc["_source"]["data"]["srcip"] = srcip
    doc["_id"] = id_
    doc["sort"] = [sort]
    return json.dumps(doc)


def _insert_intake(
    conn: psycopg.Connection,
    *,
    manager_id: str = "IA1803",
    source_alert_id: str,
    raw_text: str,
    via: str = "pull",
    sort_key: int | None = None,
) -> int:
    row = conn.execute(
        "INSERT INTO intake (manager_id, source_alert_id, raw_text, sort_key, via) "
        "VALUES (%s, %s, %s, %s, %s) RETURNING intake_id",
        (manager_id, source_alert_id, raw_text, sort_key, via),
    ).fetchone()
    return row[0]


def _job_for(intake_id: int) -> Job:
    return Job(job_id=-1, job_type="pipeline", subject_id=str(intake_id), attempts=1)


def _seed_admin_user(conn: psycopg.Connection) -> None:
    conn.execute(
        "INSERT INTO users (user_id, username, display_name, role, password_hash) "
        "VALUES (%s, 'p2t10-admin', 'p2t10-admin', 'admin', 'x') "
        "ON CONFLICT (user_id) DO NOTHING",
        (ADMIN_USER_ID,),
    )


# ---------------------------------------------------------------------------
# Acceptance 4 — the three outcomes on the real path
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_three_outcomes_new_head_duplicate_and_a_second_cluster(db):
    id_head = "p2t10-t4-head"
    id_dup = "p2t10-t4-dup"
    id_other = "p2t10-t4-other"
    cluster_srcip = "198.51.100.10"

    intake_head = _insert_intake(
        db,
        source_alert_id=id_head,
        raw_text=_hit(RULE_5503, id_=id_head, srcip=cluster_srcip, sort=1),
    )
    intake_dup = _insert_intake(
        db,
        source_alert_id=id_dup,
        raw_text=_hit(RULE_5503, id_=id_dup, srcip=cluster_srcip, sort=2),
    )
    intake_other = _insert_intake(
        db,
        source_alert_id=id_other,
        raw_text=_hit(ALERT_40112, id_=id_other, srcip="198.51.100.11", sort=3),
    )

    run_pipeline_job(db, _job_for(intake_head))
    run_pipeline_job(db, _job_for(intake_dup))
    run_pipeline_job(db, _job_for(intake_other))

    outcomes = dict(
        db.execute(
            "SELECT intake_id, outcome FROM intake WHERE intake_id = ANY(%s)",
            ([intake_head, intake_dup, intake_other],),
        ).fetchall()
    )
    assert outcomes[intake_head] == "alert"
    assert outcomes[intake_dup] == "duplicate"
    assert outcomes[intake_other] == "alert"

    head_row = db.execute(
        "SELECT status, duplicate_of, occurrence_count, risk_score FROM alerts WHERE alert_id = %s",
        (id_head,),
    ).fetchone()
    assert head_row[0] == "queued_tier1"
    assert head_row[1] is None
    assert head_row[2] == 2  # bumped once by the duplicate
    assert head_row[3] is not None

    dup_row = db.execute(
        "SELECT status, duplicate_of, closed_at, sealed_at FROM alerts WHERE alert_id = %s",
        (id_dup,),
    ).fetchone()
    assert dup_row[0] == "duplicate"
    assert dup_row[1] == id_head
    assert dup_row[2] is not None
    assert dup_row[3] is not None

    other_row = db.execute(
        "SELECT status, risk_score FROM alerts WHERE alert_id = %s", (id_other,)
    ).fetchone()
    assert other_row[0] == "queued_tier1"  # critical, never auto-closed, no rule anyway
    assert other_row[1] is not None

    triage_jobs = db.execute(
        "SELECT job_type, subject_id, status FROM jobs WHERE subject_id = ANY(%s) ORDER BY 1, 2",
        ([id_head, id_other],),
    ).fetchall()
    assert triage_jobs == [
        ("triage", id_head, "pending"),
        ("triage", id_other, "pending"),
    ]
    no_triage_for_dup = db.execute(
        "SELECT count(*) FROM jobs WHERE job_type = 'triage' AND subject_id = %s", (id_dup,)
    ).fetchone()[0]
    assert no_triage_for_dup == 0


# ---------------------------------------------------------------------------
# Acceptance 5 — auto-close path
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_auto_close_path_with_a_match_everything_rule(db):
    _seed_admin_user(db)
    inventory.load(db, paths=[str(REPO_ROOT / "conf" / "inventory.yaml.example")])
    db.execute(
        "INSERT INTO autoclose_rules "
        "(autoclose_rule_id, name, enabled, match, reason, created_by, created_at) "
        "VALUES (gen_random_uuid(), 'p2t10-match-everything', true, %s, 'test rule', %s, now())",
        (Jsonb([]), ADMIN_USER_ID),
    )

    alert_id = "p2t10-t5-autoclose"
    # user1-IA1803 is `medium` criticality in conf/inventory.yaml.example — present,
    # not `high` — so none of the six G8' hard blocks fire; rule_5503 is `medium`
    # severity (not critical).
    intake_id = _insert_intake(
        db, source_alert_id=alert_id, raw_text=_hit(RULE_5503, id_=alert_id, srcip="198.51.100.20")
    )

    run_pipeline_job(db, _job_for(intake_id))

    row = db.execute(
        "SELECT status, closed_at, sealed_at, autoclose_rule_id, asset_context "
        "FROM alerts WHERE alert_id = %s",
        (alert_id,),
    ).fetchone()
    assert row[0] == "auto_closed"
    assert row[1] is not None  # closed_at set
    assert row[2] is None  # sealed_at NOT set — auto_closed still absorbs duplicates (M4)
    assert row[3] is not None  # autoclose_rule_id set
    assert row[4] is not None  # asset_context non-null (M1)

    job = db.execute(
        "SELECT status FROM jobs WHERE job_type = 'triage' AND subject_id = %s", (alert_id,)
    ).fetchone()
    assert job is not None and job[0] == "pending"  # D8


# ---------------------------------------------------------------------------
# Acceptance 6 — rejected path
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_rejected_path_names_the_missing_field(db):
    raw_text = json.dumps({"rule": {"id": "1"}})  # missing the top-level "id"
    intake_id = _insert_intake(db, source_alert_id="p2t10-t6-rejected", raw_text=raw_text)

    run_pipeline_job(db, _job_for(intake_id))

    row = db.execute(
        "SELECT outcome, error, processed_at FROM intake WHERE intake_id = %s", (intake_id,)
    ).fetchone()
    assert row[0] == "rejected"
    assert row[1] == "id"
    assert row[2] is not None

    rejected = db.execute(
        "SELECT reason, source_ip FROM rejected_alerts WHERE raw_payload = %s::jsonb",
        (raw_text,),
    ).fetchone()
    assert rejected == ("id", "")


# ---------------------------------------------------------------------------
# Scratch databases — for the two tests below that must commit for real
# (a subprocess crash, and `_write_rejection_receipt`'s own fresh-transaction
# `conn.commit()`): `intake` is append-only even against the owner (017's
# `trg_intake_immutable` blocks DELETE for everyone), so a row committed to
# the shared `soc_p2t10_test` can never be cleaned up afterward — it would
# sit there for every later file's db-marked tests in the same acceptance-14
# `make test-db` session. See the module docstring.
# ---------------------------------------------------------------------------


def _build_scratch_db(dbname: str) -> tuple[str, psycopg.Connection]:
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
    return dsn, psycopg.connect(dsn)


def _drop_scratch_db(dbname: str, conn: psycopg.Connection) -> None:
    conn.close()
    subprocess.run(["dropdb", "--if-exists", dbname], check=False, capture_output=True)


@pytest.fixture
def e6_scratch_db():
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the E6 scratch database")
    dbname = "soc_p2t10_e6_test"
    dsn, conn = _build_scratch_db(dbname)
    try:
        yield dsn, conn
    finally:
        _drop_scratch_db(dbname, conn)


@pytest.fixture
def pin_scratch_db():
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the pin scratch database")
    dbname = "soc_p2t10_pin_test"
    _dsn, conn = _build_scratch_db(dbname)
    try:
        yield conn
    finally:
        _drop_scratch_db(dbname, conn)


# ---------------------------------------------------------------------------
# Acceptance 7 — E6 as a crash, not a mock (design note 5)
# ---------------------------------------------------------------------------


def _run_worker_once(dsn: str, *, crash_after: str | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = "backend"
    env["DATABASE_URL"] = dsn
    if crash_after is None:
        env.pop("SOC_CRASH_AFTER", None)
    else:
        env["SOC_CRASH_AFTER"] = crash_after
    return subprocess.run(
        [sys.executable, "-m", "app.web.worker", "--once"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


@pytest.mark.db
def test_e6_crash_after_finish_enrichment_commits_nothing_then_recovers(e6_scratch_db):
    dsn, conn = e6_scratch_db
    alert_id = "p2t10-t7-e6"
    intake_id = _insert_intake(
        conn,
        source_alert_id=alert_id,
        raw_text=_hit(RULE_5503, id_=alert_id, srcip="198.51.100.40"),
    )
    enqueue(conn, "pipeline", str(intake_id))
    conn.commit()

    crashed = _run_worker_once(dsn, crash_after="finish_enrichment")
    assert crashed.returncode == 3, crashed.stdout + crashed.stderr

    queued = conn.execute(
        "SELECT count(*) FROM alerts WHERE alert_id = %s AND status = 'queued_tier1'", (alert_id,)
    ).fetchone()[0]
    assert queued == 0
    triage = conn.execute(
        "SELECT count(*) FROM jobs WHERE job_type = 'triage' AND subject_id = %s", (alert_id,)
    ).fetchone()[0]
    assert triage == 0
    intake_row = conn.execute(
        "SELECT processed_at FROM intake WHERE intake_id = %s", (intake_id,)
    ).fetchone()
    assert intake_row[0] is None

    job_row = conn.execute(
        "SELECT status, locked_at FROM jobs WHERE job_type = 'pipeline' AND subject_id = %s",
        (str(intake_id),),
    ).fetchone()
    assert job_row[0] == "running"
    assert job_row[1] is not None

    conn.execute(
        "UPDATE jobs SET locked_at = now() - interval '301 seconds' "
        "WHERE job_type = 'pipeline' AND subject_id = %s",
        (str(intake_id),),
    )
    conn.commit()

    recovered = _run_worker_once(dsn)
    assert recovered.returncode == 0, recovered.stdout + recovered.stderr

    queued_after = conn.execute(
        "SELECT count(*) FROM alerts WHERE alert_id = %s AND status = 'queued_tier1'", (alert_id,)
    ).fetchone()[0]
    assert queued_after == 1
    triage_after = conn.execute(
        "SELECT count(*) FROM jobs WHERE job_type = 'triage' AND subject_id = %s AND status = 'pending'",
        (alert_id,),
    ).fetchone()[0]
    assert triage_after == 1
    outcome_after = conn.execute(
        "SELECT outcome FROM intake WHERE intake_id = %s", (intake_id,)
    ).fetchone()[0]
    assert outcome_after == "alert"


# ---------------------------------------------------------------------------
# Acceptance 8 — `source` derivation
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_source_derivation_replay_vs_wazuh(db):
    bare = json.loads(RULE_5503)["_source"]

    bare_pull = dict(bare)
    bare_pull["id"] = "p2t10-t8-bare-pull"
    intake_bare_pull = _insert_intake(
        db, source_alert_id="p2t10-t8-bare-pull", raw_text=json.dumps(bare_pull), via="pull"
    )

    bare_webhook = dict(bare)
    bare_webhook["id"] = "p2t10-t8-bare-webhook"
    intake_bare_webhook = _insert_intake(
        db,
        source_alert_id="p2t10-t8-bare-webhook",
        raw_text=json.dumps(bare_webhook),
        via="webhook",
    )

    hit_pull_id = "p2t10-t8-hit-pull"
    intake_hit_pull = _insert_intake(
        db,
        source_alert_id=hit_pull_id,
        raw_text=_hit(RULE_5503, id_=hit_pull_id, srcip="198.51.100.50"),
        via="pull",
    )

    run_pipeline_job(db, _job_for(intake_bare_pull))
    run_pipeline_job(db, _job_for(intake_bare_webhook))
    run_pipeline_job(db, _job_for(intake_hit_pull))

    def _source(alert_id: str) -> str:
        return db.execute("SELECT source FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()[
            0
        ]

    assert _source("p2t10-t8-bare-pull") == "replay"
    assert _source("p2t10-t8-bare-webhook") == "wazuh"
    assert _source(hit_pull_id) == "wazuh"


# ---------------------------------------------------------------------------
# Acceptance 9 — suggestion_visible: stable, split, never Python's hash()
# ---------------------------------------------------------------------------


def test_suggestion_visible_is_stable_across_two_calls():
    ids = [f"178690{1000 + i}.{100000 + i}" for i in range(30)]
    first = [_suggestion_visible(i) for i in ids]
    second = [_suggestion_visible(i) for i in ids]
    assert first == second


def test_suggestion_visible_share_is_between_30_and_70_percent():
    ids = [f"178690{1000 + i}.{100000 + i}" for i in range(30)]
    visible = [_suggestion_visible(i) for i in ids]
    share = sum(visible) / len(visible)
    assert 0.30 <= share <= 0.70, f"visible share {share:.2%} out of band"


def test_pipeline_never_uses_pythons_salted_hash():
    """The guard acceptance 9 names: `grep -nE "[^a-z_]hash\\(" pipeline.py` must
    find nothing. Watched red: temporarily inserting ` hash(x)` into a copy of
    the source makes this pattern match — see the report for the paste."""
    assert re.search(r"[^a-z_]hash\(", PIPELINE_SOURCE) is None


def test_pythons_hash_guard_actually_fires_on_a_violation():
    """The failing case for the guard above, without touching the real file."""
    tampered = PIPELINE_SOURCE + "\nx = hash(alert_id)\n"
    assert re.search(r"[^a-z_]hash\(", tampered) is not None


# ---------------------------------------------------------------------------
# Acceptance 10 — receipt written once, error never rewritten
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_receipt_error_is_never_rewritten_after_a_permanent_failure(pin_scratch_db):
    conn = pin_scratch_db
    intake_id = _insert_intake(
        conn, source_alert_id="p2t10-t10-pin", raw_text=json.dumps({"rule": {"id": "1"}})
    )
    enqueue(conn, "pipeline", str(intake_id))
    conn.commit()

    job = claim_job(conn, ["pipeline"])
    conn.commit()
    assert job is not None

    _write_rejection_receipt(conn, intake_id, "first permanent failure")
    first = conn.execute(
        "SELECT outcome, error, processed_at FROM intake WHERE intake_id = %s", (intake_id,)
    ).fetchone()
    assert first[0] == "rejected"
    assert first[1] == "first permanent failure"
    assert first[2] is not None

    # A retried job can never legitimately reach this function a second time
    # on the same row (run_pipeline_job's own idempotency check returns first
    # — see the module docstring), so this calls the low-level write directly
    # to prove 017's pin holds end-to-end and that the refusal itself is what
    # a retried job's `jobs.last_error` would carry.
    with pytest.raises(psycopg.Error) as excinfo:
        _write_rejection_receipt(conn, intake_id, "second permanent failure")
    conn.rollback()
    assert "pinned once set" in str(excinfo.value)

    second_message = str(excinfo.value)[:1000]
    finish_job(conn, job, outcome=classify(excinfo.value), error=second_message)
    conn.commit()

    second = conn.execute(
        "SELECT outcome, error, processed_at FROM intake WHERE intake_id = %s", (intake_id,)
    ).fetchone()
    assert second == first  # unchanged

    last_error = conn.execute(
        "SELECT last_error FROM jobs WHERE job_id = %s", (job.job_id,)
    ).fetchone()[0]
    assert last_error == second_message
    assert last_error != first[1]
