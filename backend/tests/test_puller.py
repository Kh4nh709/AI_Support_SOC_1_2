"""Offline tests for app.infra.puller: pull_once, the cursor, the overlap,
heartbeat handling, and the `pull` job.

Every indexer call goes through `httpx.MockTransport` fed from fixtures in
`backend/tests/fixtures/` — nothing here opens a socket to anything but
PostgreSQL. The heartbeat fixture (`indexer_heartbeat_hit.json`) is one real
document recorded from the live indexer on 15/09 (rule 100999 fires on the
manager's own 600 s cadence, DEC-068).
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import psycopg
import pytest
from app.infra import puller as puller_module
from app.infra.config import Config
from app.infra.errors import ConfigError, TransientError
from app.infra.jobs import Job, Reschedule
from app.infra.puller import PullResult, build_client, fetch_page, is_heartbeat, pull_job, pull_once

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _raw(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


PAGE_1 = _raw("indexer_search_page.json")
PAGE_2 = _raw("indexer_search_page_2.json")
HEARTBEAT_HIT = _raw("indexer_heartbeat_hit.json").strip()

# The six alert ids across page 1 (4) and page 2 (2) — used to scope job/intake
# assertions precisely instead of a bare count(*) against tables the rest of
# the suite also writes to.
PAGE_ALERT_IDS = [
    "1786903016.121311",
    "1786903020.121512",
    "1786903283.122004",
    "1786903451.122388",
    "1786903787.122501",
    "1786903812.122777",
]

EMPTY_PAGE = json.dumps(
    {
        "took": 1,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": 0, "relation": "eq"}, "max_score": None, "hits": []},
    }
)

# The real heartbeat document embedded verbatim (not re-serialised) inside a
# hand-built envelope, so slicing it back out still recovers the exact bytes
# recorded from the indexer.
HEARTBEAT_PAGE = (
    '{"took":1,"timed_out":false,"_shards":{"total":6,"successful":6,"skipped":0,"failed":0},'
    '"hits":{"total":{"value":1,"relation":"eq"},"max_score":null,"hits":[' + HEARTBEAT_HIT + "]}}"
)

NO_MANAGER_HIT_PAGE = (
    '{"took":1,"timed_out":false,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0},'
    '"hits":{"total":{"value":1,"relation":"eq"},"max_score":null,"hits":['
    '{"_index":"wazuh-alerts-4.x-2026.09.01","_id":"zzz","_source":{"rule":{"id":"5503"},'
    '"id":"1786900000.999999","timestamp":"2026-09-01T00:00:00.000+0000"},'
    '"fields":{"timestamp":["2026-09-01T00:00:00.000Z"]},"sort":[1786900000000]}'
    "]}}"
)

# page 1 (4 hits) then page 2 (2 hits) then empty — PULL_PAGE=2 in every test
# that uses this sequence makes both real pages "not fewer than PULL_PAGE" so
# the loop asks for a third page, exactly as design note 7 describes.
DOUBLE_PAGE_SEQUENCE = [(200, PAGE_1), (200, PAGE_2), (200, EMPTY_PAGE)]


def _base_cfg(**overrides) -> Config:
    fields = {
        "INDEXER_URL": "https://mock-indexer",
        "INDEXER_INDEX": "wazuh-alerts-*",
        "INDEXER_USER": "soc_ro",
        "INDEXER_PASSWORD": "s3cr3t-do-not-print",
        "INDEXER_CA": "/dev/null",
        "PULL_PAGE": 2,
        "PULL_OVERLAP_S": 60,
        "PULL_START": "2026-08-01",
        "HEARTBEAT_RULE_ID": "100999",
    }
    fields.update(overrides)
    return Config(**fields)


def _paged_handler(pages, requests=None):
    """Serves `pages` (a list of `(status, body_text)`) one per call, in
    order; the last entry repeats for any further request. Every request is
    appended to `requests`, in order, when given."""
    state = {"n": 0}

    def handler(request):
        if requests is not None:
            requests.append(request)
        idx = min(state["n"], len(pages) - 1)
        state["n"] += 1
        status, body_text = pages[idx]
        return httpx.Response(status, text=body_text, headers={"content-type": "application/json"})

    return handler


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _independent_slice(body: str, alert_id: str) -> str:
    """A from-scratch re-implementation of the position-tracking decode — not
    calling into `puller`'s own `_slice_hits` — so the byte-compare test below
    is a real cross-check against the fixture file, not a tautology."""
    outer = body.find('"hits"')
    inner = body.find('"hits"', outer + 1)
    bracket = body.find("[", inner)
    decoder = json.JSONDecoder()
    idx = bracket + 1
    while True:
        while body[idx] in " \t\r\n,":
            idx += 1
        if body[idx] == "]":
            raise AssertionError(f"{alert_id!r} not found in body")
        obj, end = decoder.raw_decode(body, idx)
        if obj["_source"]["id"] == alert_id:
            return body[idx:end]
        idx = end


# ---------------------------------------------------------------------------
# is_heartbeat
# ---------------------------------------------------------------------------


def test_is_heartbeat_true_for_the_configured_rule_id():
    assert is_heartbeat({"_source": {"rule": {"id": "100999"}}}) is True


def test_is_heartbeat_false_for_any_other_rule_id():
    assert is_heartbeat({"_source": {"rule": {"id": "5503"}}}) is False


def test_is_heartbeat_false_when_rule_or_source_is_missing():
    assert is_heartbeat({}) is False
    assert is_heartbeat({"_source": {}}) is False


# ---------------------------------------------------------------------------
# build_client — no insecure mode, ConfigError naming the missing key
# ---------------------------------------------------------------------------


def test_build_client_rejects_missing_indexer_ca():
    cfg = _base_cfg(INDEXER_CA="")
    with pytest.raises(ConfigError, match="INDEXER_CA"):
        build_client(cfg)


def test_build_client_rejects_unreadable_indexer_ca(tmp_path):
    cfg = _base_cfg(INDEXER_CA=str(tmp_path / "does-not-exist.pem"))
    with pytest.raises(ConfigError, match="INDEXER_CA"):
        build_client(cfg)


def test_build_client_rejects_empty_credentials_even_with_a_good_ca_path(tmp_path):
    ca = tmp_path / "root-ca.pem"
    ca.write_text("placeholder — only its path/readability is checked here")
    cfg = _base_cfg(INDEXER_CA=str(ca), INDEXER_USER="", INDEXER_PASSWORD="")
    with pytest.raises(ConfigError, match="INDEXER_USER"):
        build_client(cfg)


def test_build_client_passes_the_ca_path_and_basic_auth_to_httpx(tmp_path, monkeypatch):
    """Exercises the actual wiring without asking OpenSSL to parse a fixture
    PEM: httpx.Client is swapped for a recorder so this stays hermetic."""
    ca = tmp_path / "root-ca.pem"
    ca.write_text("placeholder")
    cfg = _base_cfg(INDEXER_CA=str(ca))

    captured = {}

    def fake_client(**kwargs):
        captured.update(kwargs)
        return "sentinel-client"

    monkeypatch.setattr(puller_module.httpx, "Client", fake_client)
    result = build_client(cfg)

    assert result == "sentinel-client"
    assert captured["verify"] == str(ca)
    assert isinstance(captured["auth"], httpx.BasicAuth)


# ---------------------------------------------------------------------------
# fetch_page
# ---------------------------------------------------------------------------


def test_fetch_page_returns_hits_and_the_raw_body_unchanged():
    client = _mock_client(_paged_handler([(200, PAGE_1)]))
    try:
        hits, body = fetch_page(client, _base_cfg(), gte_ms=1786900000000)
    finally:
        client.close()
    assert len(hits) == 4
    assert {"_id", "_source", "sort", "fields"} <= hits[0].keys()
    assert body == PAGE_1


# ---------------------------------------------------------------------------
# pull_once — the double pull / rewind idempotency story (acceptance 2)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_first_pull_inserts_all_hits_and_enqueues_pipeline_jobs(db):
    cfg = _base_cfg()
    client = _mock_client(_paged_handler(DOUBLE_PAGE_SEQUENCE))
    try:
        result = pull_once(db, client, cfg)
    finally:
        client.close()

    assert result == PullResult(hits=6, new=6, duplicates=0, heartbeats=0, last_sort=1786903812004)

    jobs_count = db.execute(
        """
        SELECT count(*) FROM jobs j
        JOIN intake i ON i.intake_id::text = j.subject_id
        WHERE i.source_alert_id = ANY(%s) AND j.job_type = 'pipeline'
        """,
        (PAGE_ALERT_IDS,),
    ).fetchone()[0]
    assert jobs_count == 6


@pytest.mark.db
def test_second_pull_in_the_same_window_finds_no_new_alerts(db):
    cfg = _base_cfg()
    client1 = _mock_client(_paged_handler(DOUBLE_PAGE_SEQUENCE))
    try:
        first = pull_once(db, client1, cfg)
    finally:
        client1.close()
    assert first.new == 6

    client2 = _mock_client(_paged_handler(DOUBLE_PAGE_SEQUENCE))
    try:
        second = pull_once(db, client2, cfg)
    finally:
        client2.close()

    assert second == PullResult(hits=6, new=0, duplicates=6, heartbeats=0, last_sort=1786903812004)

    jobs_count = db.execute(
        """
        SELECT count(*) FROM jobs j
        JOIN intake i ON i.intake_id::text = j.subject_id
        WHERE i.source_alert_id = ANY(%s) AND j.job_type = 'pipeline'
        """,
        (PAGE_ALERT_IDS,),
    ).fetchone()[0]
    assert jobs_count == 6  # unchanged from the first pull


@pytest.mark.db
def test_cursor_rewound_by_one_day_still_finds_nothing_new(db):
    cfg = _base_cfg()
    client1 = _mock_client(_paged_handler(DOUBLE_PAGE_SEQUENCE))
    try:
        pull_once(db, client1, cfg)
    finally:
        client1.close()

    db.execute(
        "UPDATE source_cursor SET last_sort = last_sort - 86400000 WHERE manager_id = 'indexer'"
    )

    client2 = _mock_client(_paged_handler(DOUBLE_PAGE_SEQUENCE))
    try:
        result = pull_once(db, client2, cfg)
    finally:
        client2.close()

    assert result.new == 0
    assert result.duplicates == 6


@pytest.mark.db
def test_a_plain_insert_bypassing_on_conflict_hits_the_unique_violation(db):
    """The failing case acceptance 2 names: drop ON CONFLICT ... DO NOTHING and
    the overlap's second sighting of the same alert raises instead of
    counting as a duplicate."""
    db.execute(
        "INSERT INTO intake (manager_id, source_alert_id, raw_text, sort_key, via) "
        "VALUES ('IA1803', 'uq-check-1', '{}', 1, 'pull')"
    )
    with pytest.raises(psycopg.errors.UniqueViolation) as exc_info:
        db.execute(
            "INSERT INTO intake (manager_id, source_alert_id, raw_text, sort_key, via) "
            "VALUES ('IA1803', 'uq-check-1', '{}', 1, 'pull')"
        )
    assert exc_info.value.diag.constraint_name == "uq_intake_manager_source"
    db.rollback()


# ---------------------------------------------------------------------------
# G9 — the byte-compare with its control (acceptance 3)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_g9_byte_compare_with_control_for_the_irregular_hit(db):
    cfg = _base_cfg()
    client = _mock_client(_paged_handler(DOUBLE_PAGE_SEQUENCE))
    try:
        pull_once(db, client, cfg)
    finally:
        client.close()

    irregular_alert_id = "1786903812.122777"
    raw_text, raw_payload_text = db.execute(
        "SELECT raw_text, raw_payload::text FROM intake WHERE source_alert_id = %s",
        (irregular_alert_id,),
    ).fetchone()

    expected = _independent_slice(PAGE_2, irregular_alert_id)
    assert raw_text == expected
    assert raw_payload_text != raw_text

    # The failing case (acceptance 3): building raw_text via json.dumps of the
    # parsed hit would not reproduce this fixture's irregular whitespace and
    # reordered keys.
    assert json.dumps(json.loads(raw_text)) != raw_text


# ---------------------------------------------------------------------------
# Request bodies (acceptance 4)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_request_bodies_carry_fields_size_gte_and_search_after(db):
    cfg = _base_cfg()
    requests = []
    client = _mock_client(_paged_handler(DOUBLE_PAGE_SEQUENCE, requests=requests))
    db.execute(
        "INSERT INTO source_cursor (manager_id, last_sort) VALUES ('indexer', %s)",
        (1786903000000,),
    )
    try:
        pull_once(db, client, cfg)
    finally:
        client.close()

    assert len(requests) == 3

    body1 = json.loads(requests[0].content)
    assert body1["fields"] == ["timestamp"]
    assert body1["size"] == cfg.PULL_PAGE
    assert body1["query"]["range"]["timestamp"]["gte"] == 1786903000000 - 60000
    assert "search_after" not in body1

    body2 = json.loads(requests[1].content)
    assert body2["fields"] == ["timestamp"]
    assert body2["search_after"] == [1786903451275]  # page 1's last sort


@pytest.mark.db
def test_first_ever_pull_uses_pull_start_not_a_prior_cursor(db):
    """No `source_cursor` row at all -> gte is PULL_START, not cursor - overlap."""
    cfg = _base_cfg(PULL_START="2026-08-01")
    requests = []
    client = _mock_client(_paged_handler(DOUBLE_PAGE_SEQUENCE, requests=requests))
    try:
        pull_once(db, client, cfg)
    finally:
        client.close()

    body1 = json.loads(requests[0].content)
    assert body1["query"]["range"]["timestamp"]["gte"] == 1785542400000  # 2026-08-01T00:00:00Z


# ---------------------------------------------------------------------------
# Heartbeat (acceptance 5) — a real document recorded from the live indexer
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_heartbeat_hit_updates_heartbeat_row_and_creates_no_job(db):
    cfg = _base_cfg()
    client = _mock_client(_paged_handler([(200, HEARTBEAT_PAGE)]))
    try:
        result = pull_once(db, client, cfg)
    finally:
        client.close()

    assert result.heartbeats == 1
    assert result.new == 0
    assert result.duplicates == 0

    heartbeat_seen = db.execute(
        "SELECT last_seen_at IS NOT NULL FROM source_heartbeat WHERE manager_id = 'indexer'"
    ).fetchone()
    assert heartbeat_seen == (True,)

    heartbeat_alert_id = json.loads(HEARTBEAT_HIT)["_source"]["id"]
    row = db.execute(
        "SELECT outcome, processed_at IS NOT NULL, count(*) FROM intake "
        "WHERE source_alert_id = %s GROUP BY 1, 2",
        (heartbeat_alert_id,),
    ).fetchone()
    assert row == ("heartbeat", True, 1)

    intake_id = db.execute(
        "SELECT intake_id FROM intake WHERE source_alert_id = %s", (heartbeat_alert_id,)
    ).fetchone()[0]
    jobs_for_it = db.execute(
        "SELECT count(*) FROM jobs WHERE subject_id = %s", (str(intake_id),)
    ).fetchone()[0]
    assert jobs_for_it == 0


@pytest.mark.db
def test_a_heartbeat_hit_does_not_advance_last_alert_at(db):
    """The failing case behind design note 2's `last_alert_at` rule: a version
    that set it for every hit, heartbeats included, would not distinguish a
    silent manager from one that is only pushing heartbeats."""
    cfg = _base_cfg()
    client = _mock_client(_paged_handler([(200, HEARTBEAT_PAGE)]))
    try:
        pull_once(db, client, cfg)
    finally:
        client.close()

    last_alert_at = db.execute(
        "SELECT last_alert_at FROM source_heartbeat WHERE manager_id = 'indexer'"
    ).fetchone()[0]
    assert last_alert_at is None


# ---------------------------------------------------------------------------
# Cursor semantics on failure and on an empty page (acceptance 6)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_transient_error_sets_last_error_and_leaves_cursor_unchanged(db):
    cfg = _base_cfg()
    db.execute(
        "INSERT INTO source_cursor (manager_id, last_sort, last_pull_at) "
        "VALUES ('indexer', 1786903000000, now() - interval '1 hour')"
    )
    db.commit()  # survives pull_once's own rollback of the failed attempt
    try:
        client = _mock_client(_paged_handler([(503, "Service Unavailable")]))
        try:
            with pytest.raises(TransientError):
                pull_once(db, client, cfg)
        finally:
            client.close()

        row = db.execute(
            "SELECT last_sort, last_error IS NOT NULL FROM source_cursor "
            "WHERE manager_id = 'indexer'"
        ).fetchone()
        assert row == (1786903000000, True)
    finally:
        db.execute("DELETE FROM source_cursor WHERE manager_id = 'indexer'")
        db.execute("DELETE FROM source_heartbeat WHERE manager_id = 'indexer'")
        db.commit()


@pytest.mark.db
def test_a_4xx_response_is_not_treated_as_transient(db):
    """The failing case behind the `< 500` check: a 4xx (bad query, bad auth
    at runtime) is a configuration problem, not something backoff fixes, and
    must not be swallowed into the same retryable path as a 503."""
    cfg = _base_cfg()
    client = _mock_client(_paged_handler([(401, "Unauthorized")]))
    try:
        with pytest.raises(httpx.HTTPStatusError):
            pull_once(db, client, cfg)
    finally:
        client.close()

    row = db.execute("SELECT last_error FROM source_cursor WHERE manager_id = 'indexer'").fetchone()
    assert row is None  # no error row written for a non-transient failure


@pytest.mark.db
def test_empty_page_advances_last_pull_at_but_leaves_last_sort_unchanged(db):
    cfg = _base_cfg()
    db.execute(
        "INSERT INTO source_cursor (manager_id, last_sort, last_pull_at) "
        "VALUES ('indexer', 1786903000000, now() - interval '1 hour')"
    )
    client = _mock_client(_paged_handler([(200, EMPTY_PAGE)]))
    try:
        result = pull_once(db, client, cfg)
    finally:
        client.close()

    assert result == PullResult(hits=0, new=0, duplicates=0, heartbeats=0, last_sort=1786903000000)

    row = db.execute(
        "SELECT last_sort, last_pull_at > now() - interval '1 minute' "
        "FROM source_cursor WHERE manager_id = 'indexer'"
    ).fetchone()
    assert row == (1786903000000, True)


@pytest.mark.db
def test_no_prior_cursor_and_an_empty_first_page_leaves_last_sort_null(db):
    cfg = _base_cfg()
    client = _mock_client(_paged_handler([(200, EMPTY_PAGE)]))
    try:
        result = pull_once(db, client, cfg)
    finally:
        client.close()
    assert result.last_sort is None
    row = db.execute("SELECT last_sort FROM source_cursor WHERE manager_id = 'indexer'").fetchone()
    assert row == (None,)


# ---------------------------------------------------------------------------
# Reschedule (acceptance 7)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_pull_job_reschedules_after_pull_interval_s_default(db):
    cfg = _base_cfg()
    client = _mock_client(_paged_handler([(200, EMPTY_PAGE)]))
    job = Job(job_id=1, job_type="pull", subject_id="indexer", attempts=1)
    result = pull_job(db, job, cfg=cfg, client_factory=lambda _cfg: client)
    assert result == Reschedule(60)


@pytest.mark.db
def test_pull_job_reschedules_using_pull_interval_s_env_override(db, monkeypatch):
    monkeypatch.setenv("PULL_INTERVAL_S", "5")
    monkeypatch.setenv("INDEXER_URL", "https://mock-indexer")
    client = _mock_client(_paged_handler([(200, EMPTY_PAGE)]))
    job = Job(job_id=1, job_type="pull", subject_id="indexer", attempts=1)
    result = pull_job(db, job, client_factory=lambda _cfg: client)  # cfg=None -> config.load()
    assert result == Reschedule(5)


# ---------------------------------------------------------------------------
# Edge cases discovered while implementing (rule 2)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_a_hit_with_no_manager_name_defaults_to_default(db):
    cfg = _base_cfg()
    client = _mock_client(_paged_handler([(200, NO_MANAGER_HIT_PAGE)]))
    try:
        pull_once(db, client, cfg)
    finally:
        client.close()

    manager_id = db.execute(
        "SELECT manager_id FROM intake WHERE source_alert_id = '1786900000.999999'"
    ).fetchone()[0]
    assert manager_id == "default"


@pytest.mark.db
def test_raw_payload_never_named_in_the_insert_so_a_generated_column_stays_generated(db):
    """Not a grep — a live proof: intake accepts a row without raw_payload in
    the column list and the database fills it in from raw_text."""
    cfg = _base_cfg()
    client = _mock_client(_paged_handler([(200, NO_MANAGER_HIT_PAGE)]))
    try:
        pull_once(db, client, cfg)
    finally:
        client.close()
    raw_text, raw_payload = db.execute(
        "SELECT raw_text, raw_payload FROM intake WHERE source_alert_id = '1786900000.999999'"
    ).fetchone()
    assert raw_payload == json.loads(raw_text)
