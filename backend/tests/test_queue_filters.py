"""DB tests for the P10-T02 queue filters — `list_queue(band=, category=, agent=, status=,
actor_id=)`, `QueuePage.counts_by_band` and `GET /api/tier1/queue?band=&category=&agent=
&status=`.

The React queue (P10-T09) consumes them: the band chips read `counts_by_band`, the status
select reads `mine`. "Mức" is the **risk band** (`risk_band(risk_score)`), never the alert's
`severity`. The row's own `risk_band` stays the Vietnamese label `risk_band` returns today
(the unfiltered rows are unchanged); the filter and the counts speak the four API codes
`low|medium|high|critical`, which `_CODE_OF_LABEL` below pins against the labels.

Fixtures are `test_queue.py`'s (`_alert`, `_set`, the `_queued` transition chain renamed
`_insert_alert`, `_insert_run`), copied — that file is not touched. `_score_for(band)` derives a
score inside a band from `queue._BANDS`, the constant `risk_band` itself reads. Every test runs
inside the `db` fixture's transaction and is rolled back (conftest.py).
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from app.domain import transitions
from app.domain.alert import Alert, AlertContext
from app.domain.transitions import finish_enrichment, open_alert, start_enrichment
from app.infra import config
from app.infra.auth import Claims
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.tier1 import queue
from app.tier1.queue import list_queue, risk_band
from app.web import deps, main
from fastapi.testclient import TestClient

pytestmark = pytest.mark.db

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_CANONICAL: Alert = parse_wazuh_alert(
    json.loads((FIXTURES / "alert_40112.json").read_text(encoding="utf-8"))
).alert
assert _CANONICAL is not None
_T = _CANONICAL.alert_time

USER_A = "00000000-0000-0000-0000-000000100a01"
USER_B = "00000000-0000-0000-0000-000000100a02"

#: The pinned vocabulary: the four codes the API speaks, against the labels `risk_band` returns.
_CODE_OF_LABEL = {"Thấp": "low", "Vừa": "medium", "Cao": "high", "Rất cao": "critical"}
_CODES = ("critical", "high", "medium", "low")

_EMPTY_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={},
)

# P3-T10's proposer row, as in test_queue.py.
RESULT: dict[str, Any] = {
    "suggested_action": "false_positive",
    "confidence": "high",
    "structured_basis": {"severity": "critical", "occurrence_count": 1},
    "reasons": [{"claim": "c", "quote": "q", "source": "wazuh_raw_log"}],
    "playbook_used": None,
}
GATE: dict[str, Any] = {
    "proposed_verdict": "false_positive",
    "final_verdict": "false_positive",
    "forced": False,
    "forced_by": [],
    "warnings": [],
    "facts": {"correlated_clusters": 1},
    "verifier_verdict": "false_positive",
}

_counter = itertools.count()
_arrival = itertools.count()


# ---------------------------------------------------------------------------
# Fixture helpers (test_queue.py's, copied)
# ---------------------------------------------------------------------------


def _hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def _alert(**overrides: Any) -> Alert:
    n = next(_counter)
    alert_id = overrides.pop("alert_id", f"p10t02-{n}")
    fields: dict[str, Any] = {"alert_id": alert_id, "event_bucket_hash": _hash(alert_id)}
    fields.update(overrides)
    return dataclasses.replace(_CANONICAL, **fields)


def _set(conn: psycopg.Connection, alert_id: str, **columns: Any) -> None:
    """Direct UPDATE of non-`status` columns (`risk_score`, `first_seen_at`, ...)."""
    assert "status" not in columns
    assignments = ", ".join(f"{column} = %s" for column in columns)
    conn.execute(
        f"UPDATE alerts SET {assignments} WHERE alert_id = %s", (*columns.values(), alert_id)
    )


def _insert_alert(
    conn: psycopg.Connection,
    *,
    risk_score: int | None = 50,
    suggestion_visible: bool = True,
    source: str = "wazuh",
    acknowledged_by: str | None = None,
    **overrides: Any,
) -> str:
    """A `queued_tier1` head through the real transitions (`test_queue._queued`), or a
    `tier1_active` one when `acknowledged_by` names a user. `first_seen_at` is set to an
    ever-later instant so that ties on `risk_score` order by arrival, deterministically."""
    alert = _alert(**overrides)
    open_alert(conn, alert, kind="received", source=source, suggestion_visible=suggestion_visible)
    start_enrichment(conn, alert.alert_id)
    finish_enrichment(
        conn,
        alert.alert_id,
        context=_EMPTY_CONTEXT,
        risk_score=risk_score if risk_score is not None else 0,
        risk_components={},
    )
    if risk_score is None:
        _set(conn, alert.alert_id, risk_score=None)
    _set(conn, alert.alert_id, first_seen_at=_T + timedelta(seconds=next(_arrival)))
    if acknowledged_by is not None:
        transitions.acknowledge(conn, alert.alert_id, acknowledged_by)
    return alert.alert_id


def _insert_run(conn: psycopg.Connection, alert_id: str) -> str:
    row = conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result, role, gate_result) "
        "VALUES (gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', %s::jsonb, 'proposer', "
        "%s::jsonb) RETURNING run_id",
        (alert_id, json.dumps(RESULT), json.dumps(GATE)),
    ).fetchone()
    return str(row[0])


def _seed_users(conn: psycopg.Connection) -> None:
    for user_id, name in ((USER_A, "P10-T02 A"), (USER_B, "P10-T02 B")):
        conn.execute(
            "INSERT INTO users (user_id, username, display_name, role, password_hash) "
            "VALUES (%s, %s, %s, 'tier1', 'x') ON CONFLICT (user_id) DO NOTHING",
            (user_id, f"p10t02-{user_id[-2:]}", name),
        )


def _score_for(band: str) -> int:
    """A score inside `band` (`low|medium|high|critical`), from the same `queue._BANDS`
    constants `risk_band` reads — the lower edge of the band's range."""
    label = next(label for label, code in _CODE_OF_LABEL.items() if code == band)
    lower = 0
    for upper, name in queue._BANDS:
        if name == label:
            return lower
        lower = upper + 1
    raise AssertionError(f"no band {band}")  # pragma: no cover


def _ids(page: queue.QueuePage) -> list[str]:
    return [row["alert_id"] for row in page.rows]


@pytest.fixture
def users(db):
    _seed_users(db)


# ---------------------------------------------------------------------------
# The vocabulary
# ---------------------------------------------------------------------------


def test_score_for_lands_in_the_band_it_names():
    for code in _CODES:
        assert _CODE_OF_LABEL[risk_band(_score_for(code))] == code


# ---------------------------------------------------------------------------
# Unfiltered = today
# ---------------------------------------------------------------------------


def test_unfiltered_call_is_unchanged(db, users):
    """Five heads across the bands, in the phase-6 order: `needs_retriage` first, then
    `risk_score DESC`, then `first_seen_at ASC`. A synthetic head, a `tier1_active` head and
    a NULL-risk head are seeded too: the first two are never listed, the NULL sorts last."""
    low = _insert_alert(db, risk_score=10)
    medium = _insert_alert(db, risk_score=30)
    high_first = _insert_alert(db, risk_score=60)
    critical = _insert_alert(db, risk_score=90)
    high_second = _insert_alert(db, risk_score=60)  # arrives after high_first: sorts after it
    null_risk = _insert_alert(db, risk_score=None)
    synthetic = _insert_alert(db, risk_score=99)
    _set(db, synthetic, is_synthetic=True)
    _insert_alert(db, risk_score=80, acknowledged_by=USER_A)  # tier1_active: not queued

    page = list_queue(db)

    assert _ids(page) == [critical, high_first, high_second, medium, low, null_risk]
    assert page.total == 6
    assert (page.page, page.page_size) == (1, queue.PAGE_SIZE_DEFAULT)
    assert [r["risk_band"] for r in page.rows] == [
        "Rất cao",
        "Cao",
        "Cao",
        "Vừa",
        "Thấp",
        None,
    ]
    assert all("risk_score" not in r for r in page.rows)
    # The paged arithmetic is what it was: page 2 of size 4 holds the last two.
    page2 = list_queue(db, page=2, page_size=4)
    assert _ids(page2) == [low, null_risk]
    assert page2.total == 6


# ---------------------------------------------------------------------------
# The band filter
# ---------------------------------------------------------------------------


def test_band_filter_keeps_only_that_band(db):
    high = _insert_alert(db, risk_score=_score_for("high"))
    low = _insert_alert(db, risk_score=_score_for("low"))
    page = queue.list_queue(db, band="high")
    ids = [r["alert_id"] for r in page.rows]
    assert high in ids and low not in ids
    assert page.total == 1


@pytest.mark.parametrize("code", _CODES)
def test_band_filter_agrees_with_risk_band_at_every_edge(db, code):
    """Every edge of every band (0, 24, 25, 49, 50, 74, 75, 100) plus a NULL score: the SQL
    ranges pick exactly the heads `risk_band()` labels with that band, and never a NULL."""
    scores = [0, 24, 25, 49, 50, 74, 75, 100]
    by_score = {s: _insert_alert(db, risk_score=s) for s in scores}
    null_id = _insert_alert(db, risk_score=None)
    expected = {by_score[s] for s in scores if _CODE_OF_LABEL[risk_band(s)] == code}
    assert len(expected) == 2  # each band has two edges among the eight scores

    page = list_queue(db, band=code, page_size=200)

    assert set(_ids(page)) == expected
    assert null_id not in _ids(page)
    assert page.total == len(expected)
    assert {_CODE_OF_LABEL[r["risk_band"]] for r in page.rows} == {code}
    # The chips must agree with the list: `counts_by_band`'s CASE puts every edge score in the
    # same band as `risk_band()` and the band filter do — two per band, and the NULL in none.
    assert page.counts_by_band == dict.fromkeys(_CODES, 2)
    assert page.counts_by_band == {
        c: sum(_CODE_OF_LABEL[risk_band(s)] == c for s in scores) for c in _CODES
    }


def test_band_filter_pages_over_the_filtered_set(db):
    highs = [_insert_alert(db, risk_score=60) for _ in range(3)]
    _insert_alert(db, risk_score=10)
    first = list_queue(db, band="high", page=1, page_size=2)
    second = list_queue(db, band="high", page=2, page_size=2)
    assert _ids(first) == highs[:2] and _ids(second) == highs[2:]
    assert first.total == second.total == 3


def test_unknown_band_raises_value_error(db):
    with pytest.raises(ValueError, match="band"):
        list_queue(db, band="Cao")  # the label is not the code
    with pytest.raises(ValueError, match="band"):
        list_queue(db, band="")


# ---------------------------------------------------------------------------
# category, agent
# ---------------------------------------------------------------------------


def test_category_and_agent_filters_combine(db):
    both = _insert_alert(db, category="malware", agent_name="host-a")
    only_cat = _insert_alert(db, category="malware", agent_name="host-b")
    only_agent = _insert_alert(db, category="recon", agent_name="host-a")
    neither = _insert_alert(db, category="recon", agent_name="host-b")

    assert set(_ids(list_queue(db, category="malware"))) == {both, only_cat}
    assert set(_ids(list_queue(db, agent="host-a"))) == {both, only_agent}
    combined = list_queue(db, category="malware", agent="host-a")
    assert _ids(combined) == [both]
    assert combined.total == 1
    assert neither not in _ids(list_queue(db, category="malware", agent="host-a"))
    assert list_queue(db, category="malware", agent="host-a", band="low").total == 0


def test_filter_values_are_parameters_not_sql(db):
    _insert_alert(db, category="malware", agent_name="host-a")
    for hostile in ("x' OR '1'='1", "malware'; DROP TABLE alerts; --", "%s", "%(actor_id)s"):
        assert list_queue(db, category=hostile).total == 0
        assert list_queue(db, agent=hostile).total == 0
    assert list_queue(db).total == 1  # the table is still there


def test_a_nul_byte_in_a_filter_is_a_value_error(db):
    with pytest.raises(ValueError, match="NUL"):
        list_queue(db, category="mal\x00ware")
    with pytest.raises(ValueError, match="NUL"):
        list_queue(db, agent="host\x00a")


# ---------------------------------------------------------------------------
# status: queued | mine
# ---------------------------------------------------------------------------


def test_mine_lists_only_my_tier1_active_heads(db, users):
    mine = _insert_alert(db, risk_score=40, acknowledged_by=USER_A)
    theirs = _insert_alert(db, risk_score=40, acknowledged_by=USER_B)
    waiting = _insert_alert(db, risk_score=40)

    page = list_queue(db, status="mine", actor_id=USER_A)
    assert _ids(page) == [mine]
    assert page.total == 1
    assert _ids(list_queue(db, status="mine", actor_id=USER_B)) == [theirs]
    # The default is today's: only the waiting head, none of the tier1_active ones.
    assert _ids(list_queue(db)) == [waiting]
    assert _ids(list_queue(db, status="queued", actor_id=USER_A)) == [waiting]


def test_mine_without_an_actor_is_a_value_error(db):
    with pytest.raises(ValueError, match="actor_id"):
        list_queue(db, status="mine")


def test_unknown_status_raises_value_error(db):
    with pytest.raises(ValueError, match="status"):
        list_queue(db, status="closed")
    with pytest.raises(ValueError, match="status"):
        list_queue(db, status="")


def test_mine_combines_with_the_other_filters(db, users):
    keep = _insert_alert(
        db, risk_score=_score_for("high"), category="malware", acknowledged_by=USER_A
    )
    _insert_alert(db, risk_score=_score_for("low"), category="malware", acknowledged_by=USER_A)
    _insert_alert(db, risk_score=_score_for("high"), category="recon", acknowledged_by=USER_A)
    page = list_queue(db, status="mine", actor_id=USER_A, band="high", category="malware")
    assert _ids(page) == [keep]


# ---------------------------------------------------------------------------
# counts_by_band
# ---------------------------------------------------------------------------


def test_counts_by_band_zero_fills_all_four_keys(db):
    assert list_queue(db).counts_by_band == {"critical": 0, "high": 0, "medium": 0, "low": 0}
    _insert_alert(db, risk_score=_score_for("medium"))
    assert list_queue(db).counts_by_band == {"critical": 0, "high": 0, "medium": 1, "low": 0}
    assert set(list_queue(db).counts_by_band) == set(_CODES)


def test_counts_by_band_ignore_the_band_filter_but_honour_the_others(db, users):
    _insert_alert(db, risk_score=_score_for("critical"), category="malware", agent_name="host-a")
    _insert_alert(db, risk_score=_score_for("high"), category="malware", agent_name="host-a")
    _insert_alert(db, risk_score=_score_for("high"), category="malware", agent_name="host-a")
    _insert_alert(db, risk_score=_score_for("high"), category="malware", agent_name="host-b")
    _insert_alert(db, risk_score=_score_for("medium"), category="malware", agent_name="host-a")
    _insert_alert(db, risk_score=_score_for("low"), category="recon", agent_name="host-a")
    _insert_alert(db, risk_score=None, category="malware", agent_name="host-a")  # in no band
    _insert_alert(  # not queued: never counted under the default status
        db, risk_score=_score_for("high"), category="malware", agent_name="host-a",
        acknowledged_by=USER_A,
    )  # fmt: skip

    everything = {"critical": 1, "high": 3, "medium": 1, "low": 1}
    assert list_queue(db).counts_by_band == everything
    # `band` narrows rows and total, never the counts.
    high_only = list_queue(db, band="high")
    assert high_only.total == 3
    assert high_only.counts_by_band == everything
    # category and agent narrow the counts.
    malware = list_queue(db, band="high", category="malware", agent="host-a")
    assert malware.total == 2
    assert malware.counts_by_band == {"critical": 1, "high": 2, "medium": 1, "low": 0}
    # status narrows them too: A's one tier1_active head.
    mine = list_queue(db, band="low", status="mine", actor_id=USER_A)
    assert mine.total == 0
    assert mine.counts_by_band == {"critical": 0, "high": 1, "medium": 0, "low": 0}


# ---------------------------------------------------------------------------
# The blind arm holds under every filter
# ---------------------------------------------------------------------------

_HIDDEN = ("suggested_action", "confidence", "gate_forced", "triage_status", "run_id")


def test_blind_rows_stay_stripped_under_every_filter(db, users):
    blind = _insert_alert(
        db,
        risk_score=_score_for("high"),
        category="malware",
        agent_name="host-a",
        suggestion_visible=False,
    )
    _insert_run(db, blind)
    blind_mine = _insert_alert(
        db,
        risk_score=_score_for("high"),
        category="malware",
        agent_name="host-a",
        suggestion_visible=False,
        acknowledged_by=USER_A,
    )
    _insert_run(db, blind_mine)
    visible = _insert_alert(
        db, risk_score=_score_for("high"), category="malware", agent_name="host-a"
    )
    _insert_run(db, visible)

    calls: list[dict[str, Any]] = [
        {},
        {"band": "high"},
        {"category": "malware"},
        {"agent": "host-a"},
        {"band": "high", "category": "malware", "agent": "host-a"},
        {"status": "mine", "actor_id": USER_A},
        {"status": "mine", "actor_id": USER_A, "band": "high", "category": "malware"},
    ]
    seen_blind = 0
    for kwargs in calls:
        page = list_queue(db, **kwargs)
        for row in page.rows:
            if row["alert_id"] in (blind, blind_mine):
                seen_blind += 1
                assert row["suggestion_visible"] is False
                for key in _HIDDEN:
                    assert key not in row, (kwargs, key)
            elif row["alert_id"] == visible:
                assert row["suggested_action"] == "false_positive", kwargs
        assert "false_positive" not in json.dumps(
            [r for r in page.rows if r["alert_id"] in (blind, blind_mine)], default=str
        )
    assert seen_blind >= 6  # the filters did return the blind rows, so the check ran


# ---------------------------------------------------------------------------
# Synthetic rows
# ---------------------------------------------------------------------------


def test_synthetic_rows_never_listed(db, users):
    real = _insert_alert(db, risk_score=_score_for("high"), category="malware")
    fake = _insert_alert(db, risk_score=_score_for("high"), category="malware")
    fake_mine = _insert_alert(
        db, risk_score=_score_for("high"), category="malware", acknowledged_by=USER_A
    )
    _set(db, fake, is_synthetic=True)
    _set(db, fake_mine, is_synthetic=True)

    for kwargs in (
        {},
        {"band": "high"},
        {"category": "malware"},
        {"status": "mine", "actor_id": USER_A},
    ):
        page = list_queue(db, **kwargs)
        assert fake not in _ids(page) and fake_mine not in _ids(page), kwargs
    assert _ids(list_queue(db, band="high")) == [real]
    assert list_queue(db).total == 1
    assert list_queue(db).counts_by_band["high"] == 1
    assert list_queue(db, status="mine", actor_id=USER_A).total == 0
    assert list_queue(db, status="mine", actor_id=USER_A).counts_by_band["high"] == 0


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class _Client:
    """`TestClient` plus the user/role the overridden auth dependency answers as
    (`test_tier2_api.py`'s pattern)."""

    def __init__(self, user_id: str, role: str = "tier1") -> None:
        self.http = TestClient(main.app, follow_redirects=False)
        self.user_id = user_id
        self.role = role

    def claims(self) -> Claims:
        return Claims(user_id=self.user_id, username=self.user_id, role=self.role, iat=0.0, exp=0.0)


@pytest.fixture
def client(db, users):
    c = _Client(USER_A)

    def get_conn():
        # `deps.get_conn`'s shape minus the success commit: the shared `db` fixture's
        # transaction is rolled back at teardown, so a commit here would leak.
        try:
            yield db
        except BaseException:
            db.rollback()
            raise

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config()
    main.app.dependency_overrides[deps.current_user] = c.claims
    try:
        yield c
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)


def test_api_response_carries_the_filtered_total_and_counts(db, client):
    _insert_alert(db, risk_score=_score_for("high"), category="malware")
    _insert_alert(db, risk_score=_score_for("high"), category="recon")
    _insert_alert(db, risk_score=_score_for("low"), category="malware")

    body = client.http.get(
        "/api/tier1/queue", params={"band": "high", "category": "malware", "page_size": 10}
    ).json()

    assert set(body) == {"rows", "total", "page", "page_size", "counts_by_band"}
    assert body["total"] == 1 and len(body["rows"]) == 1
    assert body["counts_by_band"] == {"critical": 0, "high": 1, "medium": 0, "low": 1}
    assert (body["page"], body["page_size"]) == (1, 10)
    # No filters: exactly today's three keys of paging and every row.
    plain = client.http.get("/api/tier1/queue").json()
    assert plain["total"] == 3
    assert plain["counts_by_band"] == {"critical": 0, "high": 2, "medium": 0, "low": 1}


def test_api_rejects_an_unknown_band_with_422(db, client):
    resp = client.http.get("/api/tier1/queue", params={"band": "urgent"})
    assert resp.status_code == 422, resp.text
    assert "band" in resp.json()["detail"]
    # The label `risk_band` prints is not an API code.
    assert client.http.get("/api/tier1/queue", params={"band": "Cao"}).status_code == 422


def test_api_rejects_an_unknown_status_with_422(db, client):
    resp = client.http.get("/api/tier1/queue", params={"status": "closed"})
    assert resp.status_code == 422, resp.text
    assert "status" in resp.json()["detail"]


def test_api_rejects_a_nul_byte_in_a_filter_with_422(db, client):
    assert client.http.get("/api/tier1/queue", params={"category": "a\x00b"}).status_code == 422
    assert client.http.get("/api/tier1/queue", params={"agent": "a\x00b"}).status_code == 422


def test_api_mine_uses_the_callers_id(db, client):
    mine = _insert_alert(db, risk_score=40, acknowledged_by=USER_A)
    theirs = _insert_alert(db, risk_score=40, acknowledged_by=USER_B)
    waiting = _insert_alert(db, risk_score=40)

    def listed(user_id: str, **params: str) -> list[str]:
        client.user_id = user_id
        resp = client.http.get("/api/tier1/queue", params={"status": "mine", **params})
        assert resp.status_code == 200, resp.text
        return [r["alert_id"] for r in resp.json()["rows"]]

    assert listed(USER_A) == [mine]
    assert listed(USER_B) == [theirs]
    # `status` omitted is `queued`: the waiting head, whoever asks.
    client.user_id = USER_A
    assert [r["alert_id"] for r in client.http.get("/api/tier1/queue").json()["rows"]] == [waiting]
