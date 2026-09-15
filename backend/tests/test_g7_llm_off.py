"""G7 (context pack §2) — no state depends on a model call: with the LLM
disabled, an alert pulled from the indexer reaches `queued_tier1` in under
30 seconds.

Real components throughout — the actual `pull_job` and `run_pipeline_job`
handlers, the actual `infra.worker.run_forever` claim/dispatch loop — with
only the indexer's HTTP call replaced by `httpx.MockTransport` (the same
transport-injection P2-T11's own tests use, `backend/tests/test_puller.py`).

This is the one test in the P2-T10 suite besides `test_pipeline.py`'s E6 test
that must commit for real: `pull_job` writes the `source_cursor`/
`source_heartbeat` singletons (keyed by the literal `'indexer'`, not by alert
id), and there is no way to exercise the claim/dispatch loop without
committing between claims. It therefore runs against its own scratch
database (`soc_p2t10_g7_test`, dropped and freshly migrated by the fixture
below) rather than the shared `soc_p2t10_test` the `db`/`_test_database`
fixtures serve every other file — a shared `TEST_DATABASE_URL` is exactly
what acceptance 14's `make test-db` uses to run the *whole* suite in one
session, and `test_puller.py`'s own tests assert there is *no* prior cursor.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path

import httpx
import psycopg
import pytest
from app.infra.config import Config
from app.infra.config import load as load_config
from app.infra.jobs import Job
from app.infra.puller import pull_job
from app.infra.worker import run_forever
from app.soar.pipeline import run_pipeline_job

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
_MAX_ITERATIONS = 20
_SCRATCH_DBNAME = "soc_p2t10_g7_test"

_EMPTY_PAGE = json.dumps(
    {
        "took": 1,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": 0, "relation": "eq"}, "max_score": None, "hits": []},
    }
)


@pytest.fixture
def scratch_db():
    """A throwaway, freshly migrated database, isolated from every other
    file's db-marked tests — see the module docstring."""
    if shutil.which("psql") is None or shutil.which("createdb") is None:
        pytest.skip("psql/createdb not on PATH — cannot build the G7 scratch database")
    subprocess.run(["dropdb", "--if-exists", _SCRATCH_DBNAME], check=True, capture_output=True)
    subprocess.run(["createdb", _SCRATCH_DBNAME], check=True, capture_output=True)
    dsn = f"postgresql:///{_SCRATCH_DBNAME}"
    result = subprocess.run(
        ["bash", "scripts/migrate.sh", dsn],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"scratch migrate failed:\n{result.stderr}"
    conn = psycopg.connect(dsn)
    try:
        yield conn
    finally:
        conn.close()
        subprocess.run(["dropdb", "--if-exists", _SCRATCH_DBNAME], check=False, capture_output=True)


def _tagged_page() -> tuple[str, list[str]]:
    doc = json.loads((FIXTURES / "indexer_search_page.json").read_text(encoding="utf-8"))
    ids: list[str] = []
    for i, hit in enumerate(doc["hits"]["hits"]):
        new_id = f"p2t10-g7-{i}"
        hit["_source"] = dict(hit["_source"])
        hit["_source"]["id"] = new_id
        hit["_id"] = new_id
        ids.append(new_id)
    return json.dumps(doc), ids


def _mock_client(page: str) -> httpx.Client:
    state = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["n"] += 1
        body = page if state["n"] == 1 else _EMPTY_PAGE
        return httpx.Response(200, text=body, headers={"content-type": "application/json"})

    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.mark.db
def test_g7_pulled_alert_reaches_queued_tier1_in_under_30s_with_llm_off(scratch_db, monkeypatch):
    monkeypatch.setenv("LLM_MODEL_PROPOSER", "")
    cfg = load_config()
    assert cfg.llm_enabled is False

    page, alert_ids = _tagged_page()

    t0 = time.perf_counter()

    pull_job(
        scratch_db,
        Job(job_id=-1, job_type="pull", subject_id="indexer", attempts=1),
        cfg=Config(INDEXER_URL="https://mock-indexer"),  # client_factory bypasses the rest
        client_factory=lambda _cfg: _mock_client(page),
    )
    scratch_db.commit()

    handlers = {"pipeline": run_pipeline_job}
    for _ in range(_MAX_ITERATIONS):
        pending = scratch_db.execute(
            "SELECT count(*) FROM jobs WHERE job_type = 'pipeline' AND status = 'pending'"
        ).fetchone()[0]
        if pending == 0:
            break
        run_forever(lambda: scratch_db, handlers, once=True)
    else:
        pytest.fail("pipeline jobs still pending after 20 iterations")

    elapsed = time.perf_counter() - t0
    print(f"G7 elapsed: {elapsed:.3f}s")
    assert elapsed < 30, f"G7: elapsed {elapsed:.3f}s did not stay under 30s"

    unprocessed = scratch_db.execute(
        "SELECT count(*) FROM intake WHERE source_alert_id = ANY(%s) AND processed_at IS NULL",
        (alert_ids,),
    ).fetchone()[0]
    assert unprocessed == 0

    queued_with_triage = scratch_db.execute(
        "SELECT count(*) FROM alerts a "
        "JOIN jobs j ON j.subject_id = a.alert_id AND j.job_type = 'triage' AND j.status = 'pending' "
        "WHERE a.alert_id = ANY(%s) AND a.status = 'queued_tier1'",
        (alert_ids,),
    ).fetchone()[0]
    assert queued_with_triage >= 1

    llm_runs = scratch_db.execute("SELECT count(*) FROM llm_runs").fetchone()[0]
    assert llm_runs == 0
