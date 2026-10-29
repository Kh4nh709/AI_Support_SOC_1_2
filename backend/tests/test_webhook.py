"""P4-T08 — `infra/intake.py:receive` and `POST /webhook/alerts`.

Real commit/rollback semantics matter for one case here (planning decision 3:
a `400` must leave its `rejected_alerts` row committed, surviving the
`Conn`-scope rollback that follows any raised `HTTPException`), so — exactly
like `test_auth.py` — this module builds its own scratch database
(`sdb`/`scratch_dsn`) rather than using the shared `db` fixture, whose
isolation depends on nothing ever being committed. Every alert/document id
below is made fresh from a `uuid4` (a Wazuh-form `<epoch>.<n>`: the webhook
refuses any other shape, INT-T02) so committed rows from one test never collide
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
from app.infra import config, intake
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


def _uid(_label: str) -> str:
    """A fresh alert id of the Wazuh form `<epoch>.<n>`, the one a test can always post: the webhook
    refuses any id off ①'s `alert_id` pattern (INT-T02, DEC-211 R6). `_label` only says, at the call
    site, what the id is for."""
    return _wazuh_id()


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


@pytest.mark.db
def test_same_alert_id_again_is_409_with_dedup_disabled(client, sdb) -> None:
    """P10-T15 (DEC-165): the grouping switch does not touch receipt-level
    idempotency. With DEDUP_ENABLED=false the same alert_id posted twice is
    still one intake row, one pipeline job and a 409 for the second copy."""
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(DEDUP_ENABLED=False)
    doc = _copy_with_id(ALERT_BARE, _uid("nodedup"))
    body = _bytes(doc)
    first = _post(client, body)
    assert first.status_code == 201, first.text
    intake_id = first.json()["intake_id"]

    second = _post(client, body)
    assert second.status_code == 409
    assert second.json() == {"detail": "duplicate"}

    (intake_rows,) = sdb.execute(
        "SELECT count(*) FROM intake WHERE manager_id = 'IA1803' AND source_alert_id = %s",
        (doc["id"],),
    ).fetchone()
    assert intake_rows == 1
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


# --------------------------------------------------------------------------
# INT-T02 / DEC-211 R6 item A — the webhook refuses an `id` that is not ①'s exact `alert_id` shape
#
# `builder.ID_PATTERNS["alert_id"]` (DEC-209): a Wazuh `<epoch>.<n>` or a SOAR `gl-<ULID>-<uuid>`.
# Anything else (the n8n test generator's `gl-TEST-<rule>-<epoch ms>` included) could never be
# rendered to ①, so it is refused at the door with the reason `id`, like an empty id: a rejected
# row, a 400, and nothing in `intake`, `alerts` or `jobs`.
# --------------------------------------------------------------------------

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _wazuh_id() -> str:
    """A fresh id of the Wazuh form `<epoch>.<n>`."""
    return f"{1_790_000_000 + uuid.uuid4().int % 10_000_000}.{uuid.uuid4().int % 10**9}"


def _soar_id(*, ulid: str | None = None, uuid_text: str | None = None) -> str:
    """A fresh id of the SOAR form `gl-<ULID>-<uuid>` (upper-case Crockford ULID, lower-case uuid)."""
    entropy = uuid.uuid4().bytes + uuid.uuid4().bytes
    ulid = ulid or "".join(_CROCKFORD[b % 32] for b in entropy)[:26]
    return f"gl-{ulid}-{uuid_text or uuid.uuid4()}"


def _counts(sdb) -> dict[str, int]:
    return {
        table: sdb.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
        for table in ("intake", "alerts", "jobs", "rejected_alerts")
    }


_OFF_PATTERN_IDS = [
    pytest.param("not-a-soar-id", id="free-text"),
    pytest.param("gl-TEST-100191-1793289654049", id="the-n8n-test-generator"),
    # a real id with its ULID in lower case, with its uuid in upper case, and with an `I` in the ULID
    # (Crockford's alphabet has no I, L, O or U)
    pytest.param(
        "gl-01k7zd2q5t8yj3vnq4e6r9xwbm-6f1c2a4e-8d3b-4c7a-9e21-5b0a7d6c3f84", id="lower-case-ulid"
    ),
    pytest.param(
        "gl-01K7ZD2Q5T8YJ3VNQ4E6R9XWBM-6F1C2A4E-8D3B-4C7A-9E21-5B0A7D6C3F84", id="upper-case-uuid"
    ),
    pytest.param(
        "gl-01K7ZD2Q5T8YJ3VNQ4E6R9XWBI-6f1c2a4e-8d3b-4c7a-9e21-5b0a7d6c3f84", id="ulid-with-an-i"
    ),
    pytest.param("1790888852.28168897\n", id="trailing-newline"),
    pytest.param(" 1790888852.28168897", id="leading-space"),
    pytest.param("1790888852", id="no-dot"),
    pytest.param(123, id="int"),
    pytest.param(1790888852.28168897, id="float"),
    pytest.param(True, id="bool"),
    pytest.param(["1790888852.28168897"], id="list"),
    pytest.param({"id": "1790888852.28168897"}, id="object"),
]


@pytest.mark.db
@pytest.mark.parametrize("bad_id", _OFF_PATTERN_IDS)
def test_an_id_off_the_alert_id_pattern_is_400_naming_id_with_one_rejected_row(
    client, sdb, bad_id
) -> None:
    marker = _wazuh_id()  # the rule id of this document: finds its rejected row
    doc = _copy_with_id(ALERT_BARE, bad_id)
    doc["rule"] = {**doc["rule"], "id": marker}
    before = _counts(sdb)

    response = _post(client, _bytes(doc))

    assert response.status_code == 400, response.text
    assert response.json() == {"detail": {"missing": "id"}}  # the same body as an empty id
    rows = sdb.execute(
        "SELECT reason, source_ip, raw_payload FROM rejected_alerts "
        "WHERE raw_payload->'rule'->>'id' = %s",
        (marker,),
    ).fetchall()
    assert len(rows) == 1
    reason, source_ip, raw_payload = rows[0]
    assert (reason, source_ip) == ("id", ALLOWED_HOST)
    assert raw_payload["id"] == bad_id  # the document as received, id and all
    after = _counts(sdb)
    assert after == {**before, "rejected_alerts": before["rejected_alerts"] + 1}
    # nothing reached the pipeline: no intake row (so no `alerts` row and no `pipeline` job)
    assert after["intake"] == before["intake"]
    assert after["alerts"] == before["alerts"] and after["jobs"] == before["jobs"]


@pytest.mark.db
def test_a_refused_id_inside_an_indexer_hit_is_400_too(client, sdb) -> None:
    doc = json.loads(json.dumps(ALERT_HIT))
    doc["_source"] = _copy_with_id(doc["_source"], "gl-TEST-100191-1793289654049")
    before = _counts(sdb)

    response = _post(client, _bytes(doc))

    assert response.status_code == 400 and response.json() == {"detail": {"missing": "id"}}
    after = _counts(sdb)
    assert after == {**before, "rejected_alerts": before["rejected_alerts"] + 1}


@pytest.mark.db
def test_a_wazuh_id_and_a_real_soar_id_are_still_201(client, sdb) -> None:
    """The control of the tests above (DEC-025): the same body, an id that fits, accepted. The two
    literals are the shapes DEC-209 names (a Wazuh id, and a Graylog `gl-<ULID>-<uuid>`); the
    generated pair is there so the test can be run twice on one database."""
    for given in (
        "1790888852.28168897",
        "gl-01K7ZD2Q5T8YJ3VNQ4E6R9XWBM-6f1c2a4e-8d3b-4c7a-9e21-5b0a7d6c3f84",
        _wazuh_id(),
        _soar_id(),
    ):
        # the literals may already be there from an earlier run of this module on a kept database
        sdb.execute("DELETE FROM intake WHERE source_alert_id = %s", (given,))
        sdb.commit()
        response = _post(client, _bytes(_copy_with_id(ALERT_BARE, given)))
        assert response.status_code == 201, (given, response.text)
        (stored,) = sdb.execute(
            "SELECT source_alert_id FROM intake WHERE intake_id = %s",
            (response.json()["intake_id"],),
        ).fetchone()
        assert stored == given


@pytest.mark.db
def test_a_heartbeat_with_an_id_off_the_pattern_is_refused_like_any_other(client, sdb) -> None:
    """The id is judged before the heartbeat branch, as the empty id always was: a real 100999
    keepalive carries a Wazuh id, so nothing real is lost."""
    bare = _heartbeat_from(ALERT_BARE, "gl-TEST-100999-1793289654049")
    before = _counts(sdb)

    response = _post(client, _bytes(bare))

    assert response.status_code == 400 and response.json() == {"detail": {"missing": "id"}}
    assert _counts(sdb)["intake"] == before["intake"]


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
# P12-T01 / DEC-207 item 2 (amended in fix round 1) — with `PULL_ENABLED=false`, every alert the
# webhook accepts stamps the heartbeat; with it on or unset, none does
#
# With `PULL_ENABLED=false` nothing else moves `source_heartbeat`, and the `heartbeat` health
# check would call the source lost. The stamp is `(last_seen_at, last_alert_at) = now()`, the
# puller's own `_update_heartbeat(saw_alert=True)`; the heartbeat branch keeps its own
# (`saw_alert=False`: `last_alert_at` untouched). With the pull on (the default) the webhook
# stamps nothing, exactly as before DEC-207: a pull that died still turns the alarm red beside
# a webhook that keeps receiving.
# --------------------------------------------------------------------------

_DAY_S = 86_400
_HOUR_S = 3_600
_RECENT_S = 120  # "just now", with room for a slow test host


def _set_heartbeat(sdb, *, seen_s: int, alert_s: int | None) -> None:
    """The `indexer` row as it was `seen_s` / `alert_s` seconds ago (`None`: never)."""
    sdb.execute("DELETE FROM source_heartbeat WHERE manager_id = 'indexer'")
    sdb.execute(
        "INSERT INTO source_heartbeat (manager_id, last_seen_at, last_alert_at) VALUES "
        "('indexer', now() - make_interval(secs => %s), "
        " CASE WHEN %s::int IS NULL THEN NULL ELSE now() - make_interval(secs => %s) END)",
        (seen_s, alert_s, alert_s),
    )
    sdb.commit()


def _heartbeat_ages(sdb) -> tuple[float, float | None]:
    """`(seconds since last_seen_at, seconds since last_alert_at or None)` of the `indexer` row."""
    sdb.commit()  # a fresh transaction, so `now()` is the present
    row = sdb.execute(
        "SELECT extract(epoch FROM now() - last_seen_at), extract(epoch FROM now() - last_alert_at)"
        " FROM source_heartbeat WHERE manager_id = 'indexer'"
    ).fetchone()
    assert row is not None, "source_heartbeat has no 'indexer' row"
    return float(row[0]), None if row[1] is None else float(row[1])


def _no_heartbeat_row(sdb) -> bool:
    sdb.commit()
    return (
        sdb.execute(
            "SELECT count(*) FROM source_heartbeat WHERE manager_id = 'indexer'"
        ).fetchone()[0]
        == 0
    )


def _use_cfg(**overrides) -> None:
    """The config the route sees (the `client` fixture removes the override at teardown)."""
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(**overrides)


@pytest.mark.db
@pytest.mark.parametrize(
    "preset",
    [None, (_DAY_S, None), (_DAY_S, _DAY_S)],
    ids=["no-row", "old-seen-never-alerted", "old-seen-old-alert"],
)
def test_with_the_pull_off_an_accepted_alert_stamps_last_seen_and_last_alert(
    client, sdb, preset
) -> None:
    _use_cfg(PULL_ENABLED=False)
    if preset is None:
        sdb.execute("DELETE FROM source_heartbeat WHERE manager_id = 'indexer'")
        sdb.commit()
    else:
        _set_heartbeat(sdb, seen_s=preset[0], alert_s=preset[1])

    response = _post(client, _bytes(_copy_with_id(ALERT_BARE, _uid("hb-stamp"))))

    assert response.status_code == 201, response.text
    seen, alert = _heartbeat_ages(sdb)
    assert seen < _RECENT_S
    assert alert is not None and alert < _RECENT_S


@pytest.mark.db
@pytest.mark.parametrize("cfg", [{}, {"PULL_ENABLED": True}], ids=["unset", "explicit-true"])
@pytest.mark.parametrize(
    "preset",
    [None, (_DAY_S, None), (_DAY_S, _DAY_S)],
    ids=["no-row", "old-seen-never-alerted", "old-seen-old-alert"],
)
def test_with_the_pull_on_or_unset_an_accepted_alert_leaves_the_heartbeat_untouched(
    client, sdb, preset, cfg
) -> None:
    """The behaviour of before DEC-207, and the control of the test above (DEC-025): the same
    alert, the same rows, the pull on. A pull that died then still turns the alarm red beside a
    webhook that keeps receiving."""
    _use_cfg(**cfg)
    if preset is None:
        sdb.execute("DELETE FROM source_heartbeat WHERE manager_id = 'indexer'")
        sdb.commit()
    else:
        _set_heartbeat(sdb, seen_s=preset[0], alert_s=preset[1])

    response = _post(client, _bytes(_copy_with_id(ALERT_BARE, _uid("hb-on"))))

    assert response.status_code == 201, response.text
    if preset is None:
        assert _no_heartbeat_row(sdb)  # not even a row is made
    else:
        seen, alert = _heartbeat_ages(sdb)
        assert seen == pytest.approx(_DAY_S, abs=60)
        assert (alert is None) if preset[1] is None else alert == pytest.approx(_DAY_S, abs=60)


@pytest.mark.db
def test_an_accepted_alert_stamps_with_every_switch_off(client, sdb) -> None:
    """The point of the stamp: the pull is off, the other three steps are SOAR's, and the
    alert still proves the source alive."""
    main.app.dependency_overrides[deps.get_config] = lambda: _cfg(
        PULL_ENABLED=False,
        AUTOCLOSE_ENABLED=False,
        ENRICHMENT_ENABLED=False,
        DEDUP_ENABLED=False,
    )
    _set_heartbeat(sdb, seen_s=_DAY_S, alert_s=_DAY_S)

    response = _post(client, _bytes(_copy_with_id(ALERT_BARE, _uid("hb-off"))))

    assert response.status_code == 201, response.text
    seen, alert = _heartbeat_ages(sdb)
    assert seen < _RECENT_S and alert is not None and alert < _RECENT_S


@pytest.mark.db
def test_with_the_pull_off_the_indexer_hit_shape_stamps_too(client, sdb) -> None:
    _use_cfg(PULL_ENABLED=False)
    _set_heartbeat(sdb, seen_s=_DAY_S, alert_s=None)
    doc = json.loads(json.dumps(ALERT_HIT))
    doc["_source"] = _copy_with_id(doc["_source"], _uid("hb-hit-shape"))

    assert _post(client, _bytes(doc)).status_code == 201

    seen, alert = _heartbeat_ages(sdb)
    assert seen < _RECENT_S and alert is not None and alert < _RECENT_S


@pytest.mark.db
@pytest.mark.parametrize("pull_enabled", [False, True], ids=["pull-off", "pull-on"])
def test_a_409_duplicate_does_not_stamp(sdb, pull_enabled) -> None:
    """Called on `receive` itself, not through the route: the route's rollback on a 409 would
    undo a stamp made before the conflict was found and hide the defect. In both states: with
    the pull off the first copy stamps (the positive control) and the 409 must not; with it on
    nothing stamps at all."""
    cfg = _cfg(PULL_ENABLED=pull_enabled)
    body = _bytes(_copy_with_id(ALERT_BARE, _uid("hb-dup")))
    _set_heartbeat(sdb, seen_s=_DAY_S, alert_s=_DAY_S)
    intake.receive(sdb, body, ALLOWED_HOST, cfg)  # the first copy: accepted
    first = sdb.execute(
        "SELECT extract(epoch FROM now() - last_seen_at), extract(epoch FROM now() - last_alert_at)"
        " FROM source_heartbeat WHERE manager_id = 'indexer'"
    ).fetchone()
    if pull_enabled:
        assert float(first[0]) == pytest.approx(_DAY_S, abs=60)  # the pull on: no stamp
    else:
        assert float(first[0]) < _RECENT_S and float(first[1]) < _RECENT_S  # the positive control
    sdb.execute(  # as if nothing had been heard for a day
        "UPDATE source_heartbeat SET last_seen_at = now() - interval '1 day', "
        "last_alert_at = now() - interval '1 day' WHERE manager_id = 'indexer'"
    )

    with pytest.raises(intake.Duplicate):
        intake.receive(sdb, body, ALLOWED_HOST, cfg)

    seen, alert = sdb.execute(
        "SELECT extract(epoch FROM now() - last_seen_at), extract(epoch FROM now() - last_alert_at)"
        " FROM source_heartbeat WHERE manager_id = 'indexer'"
    ).fetchone()
    assert float(seen) == pytest.approx(_DAY_S, abs=5)  # still a day old
    assert float(alert) == pytest.approx(_DAY_S, abs=5)


@pytest.mark.db
@pytest.mark.parametrize("pull_enabled", [False, True], ids=["pull-off", "pull-on"])
@pytest.mark.parametrize(
    "body, reason",
    [
        (b"not json at all", "not_json"),
        (b"[1, 2]", "not_an_object"),
        (b"{}", "id"),
        (b'{"id": "gl-TEST-100191-1793289654049", "rule": {"id": "100191"}}', "id"),
        (b"x" * (config.Config().MAX_PAYLOAD_BYTES + 1), "too_large"),  # the 413
    ],
    ids=["not_json", "not_an_object", "id", "id-off-pattern", "too_large"],
)
def test_a_rejected_body_does_not_stamp(sdb, body, reason, pull_enabled) -> None:
    """The 400s and the 413, with the pull off so that a stamp would be visible (and on, where
    none may appear either)."""
    _set_heartbeat(sdb, seen_s=_DAY_S, alert_s=_DAY_S)

    if reason == "too_large":
        with pytest.raises(intake.PayloadTooLarge):
            intake.receive(sdb, body, ALLOWED_HOST, _cfg(PULL_ENABLED=pull_enabled))
    else:
        with pytest.raises(intake.Rejected) as excinfo:
            intake.receive(sdb, body, ALLOWED_HOST, _cfg(PULL_ENABLED=pull_enabled))
        assert excinfo.value.reason == reason
    seen, alert = _heartbeat_ages(sdb)
    assert seen == pytest.approx(_DAY_S, abs=60) and alert == pytest.approx(_DAY_S, abs=60)


@pytest.mark.db
def test_the_heartbeat_document_still_stamps_last_seen_and_leaves_last_alert_alone(
    client, sdb
) -> None:
    _set_heartbeat(sdb, seen_s=_DAY_S, alert_s=_HOUR_S)

    response = _post(client, _bytes(_heartbeat_from(ALERT_BARE, _uid("hb-doc"))))

    assert response.status_code == 201 and response.json() == {"heartbeat": True}
    seen, alert = _heartbeat_ages(sdb)
    assert seen < _RECENT_S  # `last_seen_at` moved
    assert alert == pytest.approx(_HOUR_S, abs=60)  # `last_alert_at` is the hour-old value


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
