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
    alert_id = "p10t15-receipt"
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
