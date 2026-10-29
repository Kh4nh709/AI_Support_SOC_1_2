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

import copy
import dataclasses
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
from app.infra import config
from app.infra.errors import classify
from app.infra.intake import Duplicate, receive
from app.infra.jobs import Job, claim_job, enqueue, finish_job
from app.soar import pipeline as pipeline_module
from app.soar.pipeline import _suggestion_visible, _write_rejection_receipt, run_pipeline_job
from app.tier1.triage import run_triage_job
from psycopg.types.json import Jsonb

from tests.fakes.llm import TRIAGE_V2_FALSE_POSITIVE, FakeLLM

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


# ---------------------------------------------------------------------------
# P10-T15 / DEC-165 — `DEDUP_ENABLED`: the per-alert workflow
#
# One variable across the whole block: the flag. `pipeline._process` reads it with
# `config.load()` (an environment variable wins, as for every key), so each test sets it with
# `monkeypatch.setenv`. The default and `true` keep the phase-2 behaviour, which the
# acceptance-4/5 tests above already pin unchanged; the controls here prove that the very same
# inputs DO group when the flag is on, so a green "two separate alerts" cannot be an accident
# of the fixtures.
# ---------------------------------------------------------------------------

_PAIR_SRCIP = "198.51.100.77"


def _post_pair(db: psycopg.Connection, tag: str, *, base: str = RULE_5503) -> list[str]:
    """Two alerts with the same rule, srcip, dstip and agent — one cluster key — received a
    second apart (their `sort_key`s differ by 1); returns the alert ids, arrival order."""
    ids = [f"p10t15-{tag}-a", f"p10t15-{tag}-b"]
    for n, alert_id in enumerate(ids, start=1):
        _insert_intake(
            db,
            source_alert_id=alert_id,
            raw_text=_hit(base, id_=alert_id, srcip=_PAIR_SRCIP, sort=n),
            sort_key=n,
        )
    return ids


def _run_all(db: psycopg.Connection, ids: list[str]) -> None:
    """Run the `pipeline` job of every alert id in `ids`, in the order given."""
    for alert_id in ids:
        intake_id = db.execute(
            "SELECT intake_id FROM intake WHERE source_alert_id = %s", (alert_id,)
        ).fetchone()[0]
        run_pipeline_job(db, _job_for(intake_id))


def _alert_rows(db: psycopg.Connection, ids: list[str]) -> dict[str, tuple]:
    rows = db.execute(
        "SELECT alert_id, status, duplicate_of, occurrence_count, risk_score, "
        "risk_score_components, asset_context, closed_at, sealed_at, autoclose_rule_id "
        "FROM alerts WHERE alert_id = ANY(%s)",
        (ids,),
    ).fetchall()
    return {row[0]: row[1:] for row in rows}


def _outcomes(db: psycopg.Connection, ids: list[str]) -> dict[str, str]:
    return dict(
        db.execute(
            "SELECT source_alert_id, outcome FROM intake WHERE source_alert_id = ANY(%s)", (ids,)
        ).fetchall()
    )


def _triage_jobs(db: psycopg.Connection, ids: list[str]) -> list[tuple]:
    return db.execute(
        "SELECT subject_id, status FROM jobs WHERE job_type = 'triage' AND subject_id = ANY(%s) "
        "ORDER BY 1",
        (ids,),
    ).fetchall()


def _advisory_locks_held(db: psycopg.Connection) -> int:
    """Advisory locks this session holds right now. `cluster_lock` is `pg_advisory_xact_lock`,
    so it stays in `pg_locks` until the `db` fixture's transaction ends — a real probe of
    "a cluster lock was taken", independent of any Python-level spy."""
    return db.execute(
        "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND pid = pg_backend_pid()"
    ).fetchone()[0]


def _match_everything_rule(db: psycopg.Connection) -> None:
    _seed_admin_user(db)
    inventory.load(db, paths=[str(REPO_ROOT / "conf" / "inventory.yaml.example")])
    db.execute(
        "INSERT INTO autoclose_rules "
        "(autoclose_rule_id, name, enabled, match, reason, created_by, created_at) "
        "VALUES (gen_random_uuid(), 'p10t15-match-everything', true, %s, 'test rule', %s, now())",
        (Jsonb([]), ADMIN_USER_ID),
    )


@pytest.mark.db
def test_switch_off_two_identical_alerts_become_two_alerts(db, monkeypatch):
    monkeypatch.setenv("DEDUP_ENABLED", "false")
    ids = _post_pair(db, "two")

    _run_all(db, ids)

    rows = _alert_rows(db, ids)
    assert set(rows) == set(ids)
    for alert_id in ids:
        status, duplicate_of, occurrence, risk, components, asset_ctx, closed, sealed, rule = rows[
            alert_id
        ]
        assert status == "queued_tier1", alert_id  # neither is `duplicate`
        assert duplicate_of is None, alert_id
        assert occurrence == 1, alert_id
        assert risk is not None and components is not None, alert_id  # its own risk
        assert asset_ctx is not None, alert_id  # its own enrichment (`finish_enrichment`)
        assert closed is None and sealed is None and rule is None, alert_id
    assert _outcomes(db, ids) == dict.fromkeys(ids, "alert")
    # each queued alert has its own triage job — ① runs once per alert
    assert _triage_jobs(db, ids) == [(ids[0], "pending"), (ids[1], "pending")]
    merged = db.execute(
        "SELECT count(*) FROM alerts WHERE status = 'duplicate' AND alert_id = ANY(%s)", (ids,)
    ).fetchone()[0]
    assert merged == 0


@pytest.mark.db
@pytest.mark.parametrize("flag", [None, "true"], ids=["default", "explicit-true"])
def test_switch_on_or_unset_still_groups_the_same_pair(db, monkeypatch, flag):
    """The control for the test above: the same two alerts, flag unset or `true` — grouped
    exactly as before, and the advisory cluster lock is held."""
    if flag is None:
        monkeypatch.delenv("DEDUP_ENABLED", raising=False)
    else:
        monkeypatch.setenv("DEDUP_ENABLED", flag)
    ids = _post_pair(db, f"ctl-{flag}")

    _run_all(db, ids)

    rows = _alert_rows(db, ids)
    assert rows[ids[0]][0] == "queued_tier1" and rows[ids[0]][2] == 2  # head, bumped once
    assert rows[ids[1]][0] == "duplicate" and rows[ids[1]][1] == ids[0]
    assert _outcomes(db, ids) == {ids[0]: "alert", ids[1]: "duplicate"}
    assert _triage_jobs(db, ids) == [(ids[0], "pending")]
    assert _advisory_locks_held(db) == 1  # the probe the switch-off test relies on does see it


class _NoDedup:
    """Stands in for the `dedup` module: any attribute read is a failure, so none of
    `cluster_lock`, `find_open_cluster`, `bump_parent` (or anything else) can be reached."""

    def __getattr__(self, name: str):
        raise AssertionError(f"dedup.{name} was reached with DEDUP_ENABLED=false")


@pytest.mark.db
def test_switch_off_never_touches_dedup_and_takes_no_cluster_lock(db, monkeypatch):
    monkeypatch.setenv("DEDUP_ENABLED", "false")
    monkeypatch.setattr(pipeline_module, "dedup", _NoDedup())
    ids = _post_pair(db, "nolock")

    _run_all(db, ids)  # would raise AssertionError on any dedup.* access

    assert _alert_rows(db, ids)[ids[1]][0] == "queued_tier1"
    assert _advisory_locks_held(db) == 0  # nothing in the database took a lock either


@pytest.mark.db
@pytest.mark.parametrize(
    "flag, expected",
    [
        ("false", ["auto_closed", "auto_closed"]),
        ("true", ["auto_closed", "duplicate"]),  # control: an auto-closed head absorbs the twin
    ],
)
def test_switch_off_auto_closes_each_alert_on_its_own(db, monkeypatch, flag, expected):
    monkeypatch.setenv("DEDUP_ENABLED", flag)
    _match_everything_rule(db)
    ids = _post_pair(db, f"ac-{flag}")

    _run_all(db, ids)

    rows = _alert_rows(db, ids)
    assert [rows[i][0] for i in ids] == expected
    if flag == "false":
        for alert_id in ids:
            _status, duplicate_of, occurrence, risk, _c, asset_ctx, closed, sealed, rule = rows[
                alert_id
            ]
            assert duplicate_of is None and occurrence == 1, alert_id
            assert closed is not None and sealed is None, alert_id  # auto-closed, not sealed
            assert rule is not None and asset_ctx is not None and risk is not None, alert_id
        assert _outcomes(db, ids) == dict.fromkeys(ids, "auto_closed")
        # ① runs on auto-closed alerts too (D8): one triage job each
        assert _triage_jobs(db, ids) == [(ids[0], "pending"), (ids[1], "pending")]


@pytest.mark.db
def test_switch_off_is_forward_only_an_open_cluster_is_not_bumped(db, monkeypatch):
    """DEC-165 item 2: turning the switch off never reopens or splits a cluster. An alert that
    WOULD have joined the open head does not bump it and is its own head."""
    monkeypatch.setenv("DEDUP_ENABLED", "true")
    head, merged = _post_pair(db, "fwd")
    _run_all(db, [head, merged])
    before = _alert_rows(db, [head, merged])
    assert before[head][0] == "queued_tier1" and before[head][2] == 2  # the open cluster
    assert before[merged][0] == "duplicate"

    monkeypatch.setenv("DEDUP_ENABLED", "false")
    newcomer = "p10t15-fwd-c"
    _insert_intake(
        db,
        source_alert_id=newcomer,
        raw_text=_hit(RULE_5503, id_=newcomer, srcip=_PAIR_SRCIP, sort=3),
        sort_key=3,
    )
    _run_all(db, [newcomer])

    after = _alert_rows(db, [head, merged, newcomer])
    assert after[head] == before[head]  # occurrence_count still 2, status, everything unchanged
    assert after[merged] == before[merged]  # the sealed duplicate stays sealed
    status, duplicate_of, occurrence = after[newcomer][:3]
    assert (status, duplicate_of, occurrence) == ("queued_tier1", None, 1)  # its own head
    assert _outcomes(db, [newcomer]) == {newcomer: "alert"}
    assert _triage_jobs(db, [newcomer]) == [(newcomer, "pending")]


@pytest.mark.db
def test_switch_off_leaves_receipt_level_idempotency_alone(db, monkeypatch):
    """The same alert id posted twice is `intake`'s `(manager_id, source_alert_id)` conflict —
    a receipt, not dedup — so it is refused with the switch off exactly as with it on."""
    monkeypatch.setenv("DEDUP_ENABLED", "false")
    cfg = dataclasses.replace(config.Config(), DEDUP_ENABLED=False)
    alert_id = "1790150001.150001"  # the Wazuh form: the webhook refuses any other (INT-T02)
    body = _hit(RULE_5503, id_=alert_id, srcip=_PAIR_SRCIP).encode("utf-8")

    first = receive(db, body, "127.0.0.1", cfg)
    assert first.kind == "alert" and first.intake_id is not None
    with pytest.raises(Duplicate):
        receive(db, body, "127.0.0.1", cfg)

    intake_rows = db.execute(
        "SELECT count(*) FROM intake WHERE source_alert_id = %s", (alert_id,)
    ).fetchone()[0]
    pipeline_jobs = db.execute(
        "SELECT count(*) FROM jobs WHERE job_type = 'pipeline' AND subject_id = %s",
        (str(first.intake_id),),
    ).fetchone()[0]
    assert (intake_rows, pipeline_jobs) == (1, 1)

    run_pipeline_job(db, _job_for(first.intake_id))
    alerts = db.execute("SELECT count(*) FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone()[
        0
    ]
    assert alerts == 1


# ---------------------------------------------------------------------------
# P12-T01 / DEC-207 — `AUTOCLOSE_ENABLED`, `ENRICHMENT_ENABLED`, and the combination the Owner runs
#
# The alerts now arrive from an external SOAR stream that has already enriched, grouped and
# closed them. Each switch turns one of this pipeline's own steps off and defaults to `true`, so a
# `.env` that names none of them is the pipeline of before. `pipeline._process` reads them with
# `config.load()` (an environment variable wins, as for every key), so each test sets them with
# `monkeypatch.setenv`.
#
# Two proofs per switch, because "the alert ended up in the right state" does not say that the
# step did not run: the module is replaced by one that fails on any attribute read, and the
# statements that reached the connection are recorded (the `rec` fixture) and searched for the
# tables the step reads. Every "off" test has an "on" twin that finds the same statements — the
# control that shows the recorder can see them (DEC-025).
# ---------------------------------------------------------------------------

_SWITCHES = ("DEDUP_ENABLED", "PULL_ENABLED", "AUTOCLOSE_ENABLED", "ENRICHMENT_ENABLED")
_LOOKUP_TABLES = re.compile(r"\b(assets|identities|iocs)\b", re.IGNORECASE)
_RULES_TABLE = re.compile(r"\bautoclose_rules\b", re.IGNORECASE)
#: A public address (the parser treats the documentation ranges as private, and a private
#: address is not looked up), listed as malicious by `_seed_lookup_inventory`.
_MALICIOUS_IP = "45.33.32.156"
_IOCS_CSV = (
    "value,reputation,expires_at,source\n"
    + f"{_MALICIOUS_IP},malicious,2030-12-31T00:00:00Z,test\n"
)
_UNKNOWN_LOOKUPS = {"asset": "skipped", "identity": "skipped", "ioc": "skipped"}


def _switches(monkeypatch, **values: str | None) -> None:
    """Every switch unset, except the ones named: `"true"` / `"false"`, or `None` for unset."""
    for name in _SWITCHES:
        value = values.get(name)
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


class _Unreachable:
    """Stands in for a module: any attribute read is a failure, so none of its functions can
    be reached (`_NoDedup`, above, is the same thing for `dedup`)."""

    def __init__(self, module: str, switch: str) -> None:
        self._what = f"{module} was reached with {switch}=false"

    def __getattr__(self, name: str):
        raise AssertionError(f"{self._what} (.{name})")


def _statement_text(query, conn) -> str:
    if isinstance(query, bytes):
        return query.decode("utf-8", "replace")
    if hasattr(query, "as_string"):
        return query.as_string(conn)
    return str(query)


@pytest.fixture
def rec(_test_database):
    """`(connection, statements)`: a connection to the test database that records the text of
    every statement sent through it. `Connection.execute` and `Connection.cursor()` both build
    their cursor with `cursor_factory`, so nothing a module sends can go round the record."""
    statements: list[str] = []

    class _RecordingCursor(psycopg.Cursor):
        def execute(self, query, params=None, **kwargs):
            statements.append(_statement_text(query, self.connection))
            return super().execute(query, params, **kwargs)

        def executemany(self, query, params_seq, **kwargs):
            statements.append(_statement_text(query, self.connection))
            return super().executemany(query, params_seq, **kwargs)

    conn = psycopg.connect(_test_database, cursor_factory=_RecordingCursor)
    try:
        yield conn, statements
    finally:
        conn.rollback()
        conn.close()


def _seed_lookup_inventory(
    conn: psycopg.Connection,
    tmp_path: Path,
    *,
    agent_criticality: str = "medium",
    root_privileged: bool = True,
) -> None:
    """Everything the three lookups could find: the fixtures' agent `user1-IA1803` at
    `agent_criticality`, a `high` domain controller, the account `root` (the 5503 fixture's
    `dstuser`) and one malicious public address. With `root_privileged` and a `medium` agent
    the three addends are 10 + 15 + 25 = 50, which `CONTEXT_CAP` holds to 25."""
    inventory_file = tmp_path / "inventory.yaml"
    inventory_file.write_text(
        "version: 1\nassets:\n"
        f"  - hostname: user1-IA1803\n    criticality: {agent_criticality}\n"
        "  - hostname: example-dc-01\n    criticality: high\n",
        encoding="utf-8",
    )
    identities_file = tmp_path / "identities.yaml"
    identities_file.write_text(
        f"version: 1\nidentities:\n  - username: root\n    is_privileged: {str(root_privileged).lower()}\n",
        encoding="utf-8",
    )
    iocs_file = tmp_path / "iocs.csv"
    iocs_file.write_text(_IOCS_CSV, encoding="utf-8")
    inventory.load(conn, paths=[inventory_file, identities_file, iocs_file])


def _insert_match_everything_rule(conn: psycopg.Connection) -> None:
    """The rule `_match_everything_rule` inserts, without its inventory: a `[]` match holds for
    every alert, so only the hard blocks (G8') keep one from closing."""
    _seed_admin_user(conn)
    conn.execute(
        "INSERT INTO autoclose_rules "
        "(autoclose_rule_id, name, enabled, match, reason, created_by, created_at) "
        "VALUES (gen_random_uuid(), 'p12t01-match-everything', true, %s, 'test rule', %s, now())",
        (Jsonb([]), ADMIN_USER_ID),
    )


def _post_alert(
    conn: psycopg.Connection,
    alert_id: str,
    *,
    base: str = RULE_5503,
    srcip: str,
    sort: int = 1,
    agent: str | None = None,
) -> None:
    raw = _hit(base, id_=alert_id, srcip=srcip, sort=sort)
    if agent is not None:
        doc = json.loads(raw)
        doc["_source"]["agent"] = {**doc["_source"]["agent"], "name": agent}
        raw = json.dumps(doc)
    _insert_intake(conn, source_alert_id=alert_id, raw_text=raw, sort_key=sort)


_ROW_COLUMNS = (
    "status",
    "duplicate_of",
    "occurrence_count",
    "closed_at",
    "autoclose_rule_id",
    "risk_score",
    "risk_score_components",
    "asset_context",
    "identity_context",
    "ioc_context",
    "lookup_status",
)


def _row(conn: psycopg.Connection, alert_id: str) -> dict:
    record = conn.execute(
        f"SELECT {', '.join(_ROW_COLUMNS)} FROM alerts WHERE alert_id = %s", (alert_id,)
    ).fetchone()
    assert record is not None, alert_id
    return dict(zip(_ROW_COLUMNS, record, strict=True))


# -- AUTOCLOSE_ENABLED ------------------------------------------------------


@pytest.mark.db
@pytest.mark.parametrize(
    "flag, status, outcome",
    [
        ("false", "queued_tier1", "alert"),
        ("true", "auto_closed", "auto_closed"),
        (None, "auto_closed", "auto_closed"),
    ],
    ids=["off", "on", "unset"],
)
def test_autoclose_switch_decides_whether_a_matching_rule_closes_the_alert(
    rec, monkeypatch, tmp_path, flag, status, outcome
):
    conn, log = rec
    _switches(monkeypatch, AUTOCLOSE_ENABLED=flag)
    if flag == "false":
        monkeypatch.setattr(
            pipeline_module, "autoclose", _Unreachable("autoclose", "AUTOCLOSE_ENABLED")
        )
    _seed_lookup_inventory(conn, tmp_path, root_privileged=False)
    _insert_match_everything_rule(conn)
    log.clear()  # what is left is what the pipeline sends
    alert_id = f"p12t01-ac-{flag}"
    _post_alert(conn, alert_id, srcip="198.51.100.31")

    _run_all(conn, [alert_id])

    row = _row(conn, alert_id)
    assert row["status"] == status
    assert _outcomes(conn, [alert_id]) == {alert_id: outcome}
    assert _triage_jobs(conn, [alert_id]) == [(alert_id, "pending")]  # ① runs either way (D8)
    rule_reads = [s for s in log if _RULES_TABLE.search(s)]
    if flag == "false":
        assert row["closed_at"] is None and row["autoclose_rule_id"] is None
        assert rule_reads == []  # the rules table was never read: no `load_rules`, no `evaluate`
        assert row["risk_score"] is not None  # the alert was still enriched and scored
    else:
        assert row["closed_at"] is not None and row["autoclose_rule_id"] is not None
        assert rule_reads  # the control: the recorder does see a rules query


@pytest.mark.db
@pytest.mark.parametrize("flag", ["false", "true"])
@pytest.mark.parametrize("kind", ["critical", "high_asset"])
def test_a_critical_alert_and_a_high_asset_are_never_closed_whatever_the_switch(
    db, monkeypatch, tmp_path, flag, kind
):
    """G8' on the way in and DEC-207 on the way out meet at the same place: nothing closes. With
    the switch on the hard block holds the alert; with it off no rule is evaluated at all."""
    _switches(monkeypatch, AUTOCLOSE_ENABLED=flag)
    if flag == "false":
        monkeypatch.setattr(
            pipeline_module, "autoclose", _Unreachable("autoclose", "AUTOCLOSE_ENABLED")
        )
    _seed_lookup_inventory(db, tmp_path, root_privileged=False)  # only the alert itself blocks
    _insert_match_everything_rule(db)
    alert_id = f"p12t01-hard-{kind}-{flag}"
    if kind == "critical":
        _post_alert(db, alert_id, base=ALERT_40112, srcip="198.51.100.32")
    else:
        _post_alert(db, alert_id, srcip="198.51.100.33", agent="example-dc-01")

    _run_all(db, [alert_id])

    row = _row(db, alert_id)
    assert row["status"] == "queued_tier1"
    assert row["closed_at"] is None and row["autoclose_rule_id"] is None
    assert _outcomes(db, [alert_id]) == {alert_id: "alert"}
    assert _triage_jobs(db, [alert_id]) == [(alert_id, "pending")]


# -- ENRICHMENT_ENABLED -----------------------------------------------------


@pytest.mark.db
def test_enrichment_off_sends_no_statement_on_assets_identities_or_iocs(rec, monkeypatch, tmp_path):
    conn, log = rec
    _switches(monkeypatch, ENRICHMENT_ENABLED="false")
    monkeypatch.setattr(pipeline_module, "lookups", _Unreachable("lookups", "ENRICHMENT_ENABLED"))
    _seed_lookup_inventory(conn, tmp_path)  # everything a lookup could find is there
    log.clear()
    alert_id = "p12t01-en-off"
    _post_alert(conn, alert_id, srcip=_MALICIOUS_IP)

    _run_all(conn, [alert_id])

    assert [s for s in log if _LOOKUP_TABLES.search(s)] == []
    row = _row(conn, alert_id)
    assert row["status"] == "queued_tier1"
    assert row["lookup_status"] == _UNKNOWN_LOOKUPS
    assert row["asset_context"] == {
        "present": False,
        "criticality": "unknown",
        "owner": None,
        "role": None,
    }
    assert row["identity_context"] == {"privileged": None}
    assert row["ioc_context"] == {"reputation": "skipped"}
    components = row["risk_score_components"]
    assert (components["asset"], components["identity"], components["ioc"]) == (0, 0, 0)
    assert components["context_capped"] == 0
    assert row["risk_score"] == components["base"] == 28  # medium: the severity base alone


@pytest.mark.db
@pytest.mark.parametrize("flag", ["true", None], ids=["on", "unset"])
def test_enrichment_on_or_unset_still_reads_the_inventory_and_scores_it(
    rec, monkeypatch, tmp_path, flag
):
    """The twin of the test above, same alert and same inventory: the three lookups run, their
    statements are on the record, and the addends are in the score."""
    conn, log = rec
    _switches(monkeypatch, ENRICHMENT_ENABLED=flag)
    _seed_lookup_inventory(conn, tmp_path)
    log.clear()
    alert_id = f"p12t01-en-{flag}"
    _post_alert(conn, alert_id, srcip=_MALICIOUS_IP)

    _run_all(conn, [alert_id])

    touched = {m.group(1).lower() for s in log for m in _LOOKUP_TABLES.finditer(s)}
    assert touched == {"assets", "identities", "iocs"}
    row = _row(conn, alert_id)
    assert row["lookup_status"] == {"asset": "found", "identity": "found", "ioc": "found"}
    assert row["asset_context"]["present"] is True
    assert row["asset_context"]["criticality"] == "medium"
    assert row["identity_context"] == {"privileged": True}
    assert row["ioc_context"] == {"reputation": "malicious"}
    components = row["risk_score_components"]
    assert (components["asset"], components["identity"], components["ioc"]) == (10, 15, 25)
    assert components["context_capped"] == 25
    assert row["risk_score"] == 28 + 25


# -- `_build_context` takes the config `_process` already holds (fix round 1, finding 4) -----


def _parsed_alert():
    from app.ingest.wazuh_parser import parse_wazuh_alert

    result = parse_wazuh_alert(json.loads(_hit(RULE_5503, id_="p12t01-ctx", srcip=_MALICIOUS_IP)))
    assert result.alert is not None
    return result.alert


def test_build_context_with_a_given_config_does_not_read_the_environment(monkeypatch):
    """No connection and no `config.load`: the given config says "off", so nothing is read."""

    alert = _parsed_alert()  # the parser itself reads the configuration: before the patch

    def _load_is_a_failure(*args, **kwargs):
        raise AssertionError("config.load() was called although a cfg was given")

    monkeypatch.setattr(pipeline_module.config, "load", _load_is_a_failure)
    cfg = dataclasses.replace(config.Config(), ENRICHMENT_ENABLED=False)

    ctx = pipeline_module._build_context(None, alert, cfg=cfg)

    assert ctx.asset_criticality == "unknown" and ctx.asset_present is False
    assert dict(ctx.lookup_status) == _UNKNOWN_LOOKUPS


def test_build_context_without_a_config_loads_it_as_before(monkeypatch):
    """`cfg=None` is `test_adversarial`'s call: the environment decides."""
    monkeypatch.setenv("ENRICHMENT_ENABLED", "false")
    ctx = pipeline_module._build_context(None, _parsed_alert())
    assert dict(ctx.lookup_status) == _UNKNOWN_LOOKUPS


@pytest.mark.db
def test_build_context_given_a_config_follows_it_and_not_the_environment(
    rec, monkeypatch, tmp_path
):
    """The environment says off, the given config says on: the lookups run (the other direction
    of the test above, so the argument is what decides)."""
    conn, log = rec
    monkeypatch.setenv("ENRICHMENT_ENABLED", "false")
    _seed_lookup_inventory(conn, tmp_path)
    log.clear()

    ctx = pipeline_module._build_context(conn, _parsed_alert(), cfg=config.Config())

    assert ctx.asset_criticality == "medium"
    assert {m.group(1).lower() for s in log for m in _LOOKUP_TABLES.finditer(s)} == {
        "assets",
        "identities",
        "iocs",
    }


@pytest.mark.db
def test_process_hands_its_own_config_to_build_context(db, monkeypatch):
    """One read of the environment per alert for the switches: `_process` loads the config once and
    passes that object down, so the context is built from the very config the rest of `_process`
    used."""
    _switches(monkeypatch, ENRICHMENT_ENABLED="false")
    seen: list = []
    real = pipeline_module._build_context

    def spy(conn, alert, *, cfg=None):
        seen.append(cfg)
        return real(conn, alert, cfg=cfg)

    monkeypatch.setattr(pipeline_module, "_build_context", spy)
    alert_id = "p12t01-cfg-pass"
    _post_alert(db, alert_id, srcip="198.51.100.61")

    _run_all(db, [alert_id])

    assert len(seen) == 1 and seen[0] is not None
    assert seen[0].ENRICHMENT_ENABLED is False


# -- the defaults: a `.env` that names none of the switches is `a0398c2` ----------------


@pytest.mark.db
@pytest.mark.parametrize("flag", [None, "true"], ids=["unset", "explicit-true"])
def test_with_no_switch_named_the_outcomes_are_those_of_before_dec_207(
    db, monkeypatch, tmp_path, flag
):
    """One scenario, run with every switch unset and with every switch `true`: a rule that
    matches closes the first alert, the second alert of its cluster is a duplicate that bumps the
    head, a critical alert is queued, and the closed head carries its enrichment and its risk."""
    _switches(monkeypatch, **dict.fromkeys(_SWITCHES, flag))
    _seed_lookup_inventory(db, tmp_path, root_privileged=False)
    _insert_match_everything_rule(db)
    head, twin, critical = (f"p12t01-def-{flag}-{n}" for n in "htc")
    _post_alert(db, head, srcip="198.51.100.41", sort=1)
    _post_alert(db, twin, srcip="198.51.100.41", sort=2)
    _post_alert(db, critical, base=ALERT_40112, srcip="198.51.100.42", sort=3)

    _run_all(db, [head, twin, critical])

    rows = {alert_id: _row(db, alert_id) for alert_id in (head, twin, critical)}
    assert [rows[a]["status"] for a in (head, twin, critical)] == [
        "auto_closed",
        "duplicate",
        "queued_tier1",
    ]
    assert rows[twin]["duplicate_of"] == head
    assert rows[head]["occurrence_count"] == 2  # the twin bumped it
    assert rows[head]["autoclose_rule_id"] is not None
    assert rows[head]["lookup_status"] == {"asset": "found", "identity": "found", "ioc": "skipped"}
    assert rows[head]["asset_context"]["criticality"] == "medium"
    assert rows[head]["identity_context"] == {"privileged": False}
    assert rows[head]["risk_score_components"]["asset"] == 10  # and the addends are scored
    assert _outcomes(db, [head, twin, critical]) == {
        head: "auto_closed",
        twin: "duplicate",
        critical: "alert",
    }
    assert set(_triage_jobs(db, [head, twin, critical])) == {
        (head, "pending"),
        (critical, "pending"),
    }  # the duplicate has none: its head carries the triage
    assert _advisory_locks_held(db) == 2  # dedup ran: one cluster lock per cluster key


# -- the combination the Owner will run --------------------------------------------------


@pytest.mark.db
def test_all_four_switches_off_two_alerts_with_one_cluster_key_are_two_heads(
    rec, monkeypatch, tmp_path
):
    """`DEDUP_ENABLED=false` with the three new switches off (DEC-207, the stream the Owner will
    run): no grouping, no inventory read, no rule read; each alert is its own head in the Tier-1
    queue with its own `triage` job, the "unknown" context and the severity base as its score."""
    conn, log = rec
    _switches(
        monkeypatch,
        DEDUP_ENABLED="false",
        PULL_ENABLED="false",
        AUTOCLOSE_ENABLED="false",
        ENRICHMENT_ENABLED="false",
    )
    monkeypatch.setattr(pipeline_module, "dedup", _NoDedup())
    monkeypatch.setattr(
        pipeline_module, "autoclose", _Unreachable("autoclose", "AUTOCLOSE_ENABLED")
    )
    monkeypatch.setattr(pipeline_module, "lookups", _Unreachable("lookups", "ENRICHMENT_ENABLED"))
    _seed_lookup_inventory(conn, tmp_path)
    _insert_match_everything_rule(conn)  # would close both, if anything read it
    log.clear()
    ids = _post_pair(conn, "all-off")

    _run_all(conn, ids)

    rows = {alert_id: _row(conn, alert_id) for alert_id in ids}
    for alert_id in ids:
        row = rows[alert_id]
        assert row["status"] == "queued_tier1", alert_id  # neither a duplicate nor auto-closed
        assert row["duplicate_of"] is None and row["occurrence_count"] == 1, alert_id
        assert row["closed_at"] is None and row["autoclose_rule_id"] is None, alert_id
        assert row["lookup_status"] == _UNKNOWN_LOOKUPS, alert_id
        assert row["asset_context"]["present"] is False, alert_id
        assert row["risk_score"] == row["risk_score_components"]["base"] == 28, alert_id
    assert _outcomes(conn, ids) == dict.fromkeys(ids, "alert")
    assert _triage_jobs(conn, ids) == [(ids[0], "pending"), (ids[1], "pending")]
    assert [s for s in log if _LOOKUP_TABLES.search(s) or _RULES_TABLE.search(s)] == []
    assert _advisory_locks_held(conn) == 0  # and no cluster lock either


# -- the consequence DEC-207 item 3 records: the gate ------------------------------------
#
# With the "unknown" context every alert carries, gate step 4 cannot keep a `false_positive`:
# `asset_criticality = unknown` is one of the conditions that force `needs_review` (and the
# playbook rule cannot hold on `unknown` facts either). This documents that consequence end to
# end, through the pipeline and then ①, with the fake adapter: the very same alert and the very
# same answer from the model keep their `false_positive` when the switch is on and the inventory
# knows the host.


class _FakeComplete(FakeLLM):
    """`FakeLLM` plus the `model` keyword the real adapter's `complete()` takes."""

    def complete(self, *, system, user, response_format=None, timeout_s=None, model=None):
        return super().complete(
            system=system, user=user, response_format=response_format, timeout_s=timeout_s
        )


def _false_positive_answer(*, ioc: str, asset: str, identity: str) -> dict:
    """① says `false_positive` under `sbf-1`; its `structured_basis` equals the facts of the alert
    (a mismatch forces `needs_review` at step 2 by itself) and it quotes the rule description."""
    answer = copy.deepcopy(TRIAGE_V2_FALSE_POSITIVE)
    answer["structured_basis"] = {
        "severity": "medium",
        "ioc_reputation": ioc,
        "asset_criticality": asset,
        "identity_privileged": identity,
        "occurrence_count": 1,
        "playbook_rule_applied": "sbf-1",
    }
    answer["reasons"][0]["quote"] = "PAM: User login failed."
    return answer


def _verifier_agrees(verdict: str) -> dict:
    return {
        "agree": True,
        "structured_only_verdict": verdict,
        "reason": f"Structured facts alone give {verdict}.",
    }


def _gate_result_after_triage(conn: psycopg.Connection, alert_id: str, answers: list[dict]) -> dict:
    job = Job(job_id=1, job_type="triage", subject_id=alert_id, attempts=1)
    run_triage_job(conn, job, adapter=_FakeComplete(responses=answers))
    return conn.execute(
        "SELECT gate_result FROM llm_runs WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()[0]


@pytest.mark.db
def test_the_unknown_context_forces_a_false_positive_to_needs_review_at_step_4(
    db, monkeypatch, tmp_path
):
    monkeypatch.setenv("LLM_MODEL_PROPOSER", "fake-deepseek")
    _switches(monkeypatch, ENRICHMENT_ENABLED="false")
    _seed_lookup_inventory(db, tmp_path, agent_criticality="low", root_privileged=False)
    alert_id = "1789000001.100001"  # ① takes Wazuh-shaped ids only
    _post_alert(db, alert_id, srcip="45.33.32.157")
    _run_all(db, [alert_id])
    assert _row(db, alert_id)["asset_context"]["criticality"] == "unknown"

    gate_result = _gate_result_after_triage(
        db,
        alert_id,
        [
            _false_positive_answer(ioc="skipped", asset="unknown", identity="unknown"),
            _verifier_agrees("needs_review"),
        ],
    )

    assert gate_result["facts"]["asset_criticality"] == "unknown"
    assert gate_result["proposed_verdict"] == "false_positive"
    assert gate_result["final_verdict"] == "needs_review"
    assert gate_result["forced"] is True
    assert gate_result["forced_by"] == ["step4"]
    assert "asset_criticality" in gate_result["missing"]
    result = db.execute(
        "SELECT result->>'suggested_action' FROM llm_runs "
        "WHERE subject_id = %s AND role = 'proposer'",
        (alert_id,),
    ).fetchone()
    assert result == ("needs_review",)  # and that is all an analyst can be shown (G11)


@pytest.mark.db
def test_the_same_alert_with_a_known_host_keeps_its_false_positive(db, monkeypatch, tmp_path):
    """The control of the test above (DEC-025): nothing differs but the switch and what the
    inventory says about the host, so the forcing is the context's doing."""
    monkeypatch.setenv("LLM_MODEL_PROPOSER", "fake-deepseek")
    _switches(monkeypatch)  # every switch unset: on
    _seed_lookup_inventory(db, tmp_path, agent_criticality="low", root_privileged=False)
    alert_id = "1789000002.100002"
    _post_alert(db, alert_id, srcip="45.33.32.157")
    _run_all(db, [alert_id])
    assert _row(db, alert_id)["asset_context"]["criticality"] == "low"

    gate_result = _gate_result_after_triage(
        db,
        alert_id,
        [
            _false_positive_answer(ioc="not_found", asset="low", identity="false"),
            _verifier_agrees("false_positive"),
        ],
    )

    assert gate_result["final_verdict"] == "false_positive"
    assert gate_result["forced"] is False
    assert gate_result["steps"]["4"] == "ok"
