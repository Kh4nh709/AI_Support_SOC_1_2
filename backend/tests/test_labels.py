"""P6-T02 — the blind labelling API: `app.tier1.labels`, `app.web.routers.labels`. (The Jinja page
this file was first written against, `templates/labels.html`, was retired in P11-T19; what it
had to hide is the same list as what the JSON must not carry, and the JSON half of each test
is what is kept.)

The API must give a labeller one cluster at a time, in their own seeded order,
and never anything LLM-derived, any pilot decision, `alerts.source`, or the other
labeller's label (architecture §6 "Giao thức gán nhãn", DEC-019). The fixture is
built to leak if it can: the canonical alert 40112 is inserted with
`suggestion_visible = true` **and** an `llm_runs` proposer row suggesting
`false_positive` with a `gate_result`; a second candidate's stored `source` is
`'replay'`; the candidates file carries `source` values; and 40112's
`description`/`raw_log` deliberately contain the words `wazuh` and `lab`, so the
free-text exemption of the token test is exercised rather than vacuous.

Every test runs inside the `db` fixture's transaction and is rolled back: the
overridden `get_conn` yields that connection and never commits. The auth
dependency (`deps.current_user`) is overridden to run as user A or user B —
`require_role("admin")` itself still runs on those claims.
"""

from __future__ import annotations

import csv
import dataclasses
import hashlib
import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from app.domain.alert import Alert, AlertContext
from app.domain.transitions import finish_enrichment, open_alert, start_enrichment
from app.infra import config
from app.infra.auth import Claims
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.tier1 import labels
from app.web import deps, main
from app.web.routers import labels as labels_router
from fastapi.testclient import TestClient

FIXTURES = Path(__file__).resolve().parent / "fixtures"

USER_A = "00000000-0000-0000-0000-00000060a002"
USER_B = "00000000-0000-0000-0000-00000060b002"

# The allowlist of card note 3, spelled out here rather than imported from the
# module under test — a key added there must turn these tests red.
ALLOWED_VIEW_KEYS = {
    "alert_id",
    "rule_id",
    "rule_level",
    "severity",
    "description",
    "agent_name",
    "alert_time",
    "alert_user",
    "srcip",
    "dstip",
    "category",
    "raw_log",
    "raw_log_truncated_for_display",
    "occurrence_count",
    "first_seen",
    "last_seen",
    "playbook",
    "correlation",
    "gold_cluster_id",
}
CORRELATION_ROW_KEYS = {
    "rule_id",
    "category",
    "cluster_count",
    "alert_count",
    "first_seen",
    "last_seen",
}
SAMPLE_KEYS = {
    "alert_id",
    "rule_id",
    "category",
    "severity",
    "occurrence_count",
    "alert_time",
    "description",
    "raw_log",
}
FORBIDDEN_SUBSTRINGS = (
    "suggested_action",
    "gate_result",
    "llm_",
    "verifier",
    "needs_review",
    "triage_status",
    "suggestion_visible",
    "risk_score",
    "asset_context",
    "identity_context",
    "ioc_context",
    "lookup_status",
    "duplicate_of",
    "closed_at",
    "case_id",
    '"status"',
    '"source"',
)
SOURCE_TOKENS = re.compile(r"\b(replay|wazuh|lab)\b", re.IGNORECASE)
FREE_TEXT_KEYS = {"raw_log", "description"}

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def _parse(name: str) -> Alert:
    doc = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    alert = parse_wazuh_alert(doc.get("_source", doc)).alert
    assert alert is not None
    return alert


_CANONICAL = _parse("alert_40112.json")
_A40112: Alert = dataclasses.replace(
    _CANONICAL,
    description=_CANONICAL.description + " (forwarded by the wazuh agent in the lab)",
    raw_log=_CANONICAL.raw_log + " wazuh lab",
)
_A5503: Alert = _parse("indexer_sample_rule5503.json")
_T = _A40112.alert_time  # 2026-08-16 17:56:56.13 UTC
_T_G2 = datetime(2026, 9, 10, 10, 0, tzinfo=UTC)
G2_AGENT = "p6t02-g2-agent"
G2_USER = "p6t02-g2-user"

_EMPTY_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={},
)


def _copy(alert_id: str, **overrides: Any) -> Alert:
    fields: dict[str, Any] = {
        "alert_id": alert_id,
        "event_bucket_hash": hashlib.sha256(alert_id.encode()).hexdigest(),
    }
    fields.update(overrides)
    return dataclasses.replace(_CANONICAL, **fields)


_G2_HEAD = _copy(
    "p6t02-g2-head",
    rule_id="5710",
    agent_name=G2_AGENT,
    alert_user=G2_USER,
    srcip="",
    alert_time=_T_G2,
    description="sshd: attempt to login using a non-existent user",
)
# Two correlated clusters of one (rule_id, category), left in two different
# statuses — the page must show one row for them, with no status.
_G2_NEAR_RECEIVED = _copy(
    "p6t02-g2-near-1",
    agent_name=G2_AGENT,
    alert_user=G2_USER,
    srcip="",
    alert_time=_T_G2 + timedelta(minutes=30),
)
_G2_NEAR_QUEUED = _copy(
    "p6t02-g2-near-2",
    agent_name=G2_AGENT,
    alert_user=G2_USER,
    srcip="",
    alert_time=_T_G2 + timedelta(minutes=60),
)
_G2_FAR = _copy(
    "p6t02-g2-far",
    agent_name=G2_AGENT,
    alert_user=G2_USER,
    srcip="",
    alert_time=_T_G2 + timedelta(hours=5),
)

PROPOSER_RESULT = {
    "suggested_action": "false_positive",
    "confidence": "high",
    "structured_basis": {"severity": "critical", "occurrence_count": 1},
    "reasons": [{"claim": "c", "quote": "q", "source": "wazuh_raw_log"}],
    "playbook_used": None,
}
GATE_RESULT = {
    "proposed_verdict": "false_positive",
    "final_verdict": "false_positive",
    "forced": False,
    "forced_by": [],
    "warnings": [],
    "facts": {},
    "verifier_verdict": "false_positive",
}

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

CANDIDATE_HEADER = [
    "cluster_id",
    "gold_set",
    "alert_id",
    "category",
    "severity",
    "source",
    "stratum",
    "occurrence_count",
    "first_seen",
    "last_seen",
    "agent_name",
    "rule_id",
]
G1_HEADER = [
    "cluster_id",
    "alert_id",
    "rule_id",
    "category",
    "severity",
    "agent_name",
    "alert_user",
    "srcip",
    "dstip",
    "first_seen",
    "last_seen",
    "occurrence_count",
    "closed_by",
    "excluded_reason",
]

G2_FILE_OCCURRENCE = 5
G2_FILE_FIRST = _T_G2
G2_FILE_LAST = _T_G2 + timedelta(minutes=20)


def _iso(value: datetime) -> str:
    return value.isoformat()


def _candidate_rows() -> list[dict[str, Any]]:
    return [
        {
            "cluster_id": _A40112.alert_id,
            "gold_set": "G1",
            "alert_id": _A40112.alert_id,
            "category": "ssh_brute_force",
            "severity": "critical",
            "source": "replay",
            "stratum": "ssh_brute_force|critical",
            "occurrence_count": 3,
            "first_seen": _iso(_T),
            "last_seen": _iso(_T + timedelta(minutes=2)),
            "agent_name": _A40112.agent_name,
            "rule_id": "40112",
        },
        {
            "cluster_id": _A5503.alert_id,
            "gold_set": "G1",
            "alert_id": _A5503.alert_id,
            "category": "ssh_brute_force",
            "severity": "medium",
            "source": "replay",
            "stratum": "ssh_brute_force|medium",
            "occurrence_count": 1,
            "first_seen": _iso(_A5503.alert_time),
            "last_seen": _iso(_A5503.alert_time),
            "agent_name": _A5503.agent_name,
            "rule_id": "5503",
        },
        {
            "cluster_id": _G2_HEAD.alert_id,
            "gold_set": "G2",
            "alert_id": _G2_HEAD.alert_id,
            "category": "ssh_brute_force",
            "severity": "critical",
            "source": "lab",
            "stratum": "ssh_brute_force|critical",
            "occurrence_count": G2_FILE_OCCURRENCE,
            "first_seen": _iso(G2_FILE_FIRST),
            "last_seen": _iso(G2_FILE_LAST),
            "agent_name": G2_AGENT,
            "rule_id": "5710",
        },
    ]


def _g1(
    cluster_id: str,
    rule_id: str,
    agent: str,
    user: str,
    srcip: str,
    first: datetime,
    last: datetime,
    occurrence: int,
) -> dict[str, Any]:
    return {
        "cluster_id": cluster_id,
        "alert_id": cluster_id,
        "rule_id": rule_id,
        "category": "ssh_brute_force",
        "severity": "medium",
        "agent_name": agent,
        "alert_user": user,
        "srcip": srcip,
        "dstip": "",
        "first_seen": _iso(first),
        "last_seen": _iso(last),
        "occurrence_count": occurrence,
        "closed_by": "idle_gap",
        "excluded_reason": "",
    }


def _g1_rows() -> list[dict[str, Any]]:
    agent = _A40112.agent_name
    return [
        _g1(
            _A40112.alert_id, "40112", agent, "user1", "127.0.0.1", _T, _T + timedelta(minutes=2), 3
        ),
        # hit on agent_name only, 30 minutes after the head
        _g1(
            "g1-hit-agent",
            "5503",
            agent,
            "someone",
            "",
            _T + timedelta(minutes=30),
            _T + timedelta(minutes=34),
            4,
        ),
        # hit on alert_user only, before the head
        _g1(
            "g1-hit-user",
            "5710",
            "OTHER-HOST",
            "user1",
            "",
            _T - timedelta(minutes=90),
            _T - timedelta(minutes=80),
            2,
        ),
        # hit on srcip only; starts before the window, ends inside it
        _g1(
            "g1-hit-srcip",
            "5760",
            "OTHER-HOST-2",
            "",
            "127.0.0.1",
            _T - timedelta(hours=3),
            _T - timedelta(minutes=110),
            6,
        ),
        # miss: same agent, 5 hours later
        _g1(
            "g1-miss-late",
            "5503",
            agent,
            "someone",
            "",
            _T + timedelta(hours=5),
            _T + timedelta(hours=5, minutes=3),
            9,
        ),
        # miss: in the window, but no key in common
        _g1(
            "g1-miss-keys",
            "5503",
            "UNRELATED",
            "bob",
            "10.9.9.9",
            _T + timedelta(minutes=10),
            _T + timedelta(minutes=12),
            5,
        ),
        # the second G1 candidate's own cluster, weeks away
        _g1(
            _A5503.alert_id,
            "5503",
            _A5503.agent_name,
            "root",
            "202.165.25.8",
            _A5503.alert_time,
            _A5503.alert_time,
            1,
        ),
    ]


def _write_csv(path: Path, header: list[str], rows: list[dict[str, Any]]) -> Path:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)
    return path


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _seed_users(conn: psycopg.Connection) -> None:
    for user_id, name in ((USER_A, "p6t02-a"), (USER_B, "p6t02-b")):
        conn.execute(
            "INSERT INTO users (user_id, username, display_name, role, password_hash) "
            "VALUES (%s, %s, %s, 'admin', 'x')",
            (user_id, name, name),
        )


def _insert_proposer_run(conn: psycopg.Connection, alert_id: str) -> None:
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, "
        "user_message, result, role, gate_result) "
        "VALUES (gen_random_uuid(), 'triage', 'alert', %s, 's', 'u', %s::jsonb, 'proposer', "
        "%s::jsonb)",
        (alert_id, json.dumps(PROPOSER_RESULT), json.dumps(GATE_RESULT)),
    )


def _open(
    conn: psycopg.Connection,
    alert: Alert,
    *,
    source: str = "wazuh",
    suggestion_visible: bool = True,
) -> None:
    open_alert(conn, alert, kind="received", source=source, suggestion_visible=suggestion_visible)


@pytest.fixture
def seeded(db, tmp_path, monkeypatch):
    """Users, alerts, the `llm_runs` row and both files; the module's paths
    point at `tmp_path` (the freeze marker too — absent until a test writes it)."""
    _seed_users(db)
    _open(db, _A40112, suggestion_visible=True)
    _insert_proposer_run(db, _A40112.alert_id)
    _open(db, _A5503)
    db.execute("UPDATE alerts SET source = 'replay' WHERE alert_id = %s", (_A5503.alert_id,))

    _open(db, _G2_HEAD)
    # The DB's numbers for the G2 head differ from the file's on purpose.
    db.execute(
        "UPDATE alerts SET occurrence_count = 77, first_seen_at = %s, last_seen_at = %s "
        "WHERE alert_id = %s",
        (_T_G2 - timedelta(days=3), _T_G2 + timedelta(days=3), _G2_HEAD.alert_id),
    )
    _open(db, _G2_NEAR_RECEIVED)
    _open(db, _G2_NEAR_QUEUED)
    start_enrichment(db, _G2_NEAR_QUEUED.alert_id)
    finish_enrichment(
        db, _G2_NEAR_QUEUED.alert_id, context=_EMPTY_CONTEXT, risk_score=10, risk_components={}
    )
    _open(db, _G2_FAR)

    candidates = _write_csv(tmp_path / "gold_candidates.csv", CANDIDATE_HEADER, _candidate_rows())
    g1 = _write_csv(tmp_path / "g1_clusters.csv", G1_HEADER, _g1_rows())
    monkeypatch.setattr(labels, "CANDIDATES_PATH", candidates)
    monkeypatch.setattr(labels, "G1_CLUSTERS_PATH", g1)
    monkeypatch.setattr(labels, "FREEZE_MARKER", tmp_path / "gold_v1.sha256")
    return tmp_path


class _Client:
    """`TestClient` plus the user the overridden auth dependencies answer as."""

    def __init__(self) -> None:
        self.http = TestClient(main.app, follow_redirects=False)
        self.user_id = USER_A

    def as_user(self, user_id: str) -> _Client:
        self.user_id = user_id
        return self

    def claims(self) -> Claims:
        return Claims(user_id=self.user_id, username=self.user_id, role="admin", iat=0.0, exp=0.0)


@pytest.fixture
def client(db, seeded):
    c = _Client()

    def get_conn():
        yield db  # never committed: the `db` fixture rolls everything back

    main.app.dependency_overrides[deps.get_conn] = get_conn
    main.app.dependency_overrides[deps.get_config] = lambda: config.Config()
    main.app.dependency_overrides[deps.current_user] = c.claims
    try:
        yield c
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user):
            main.app.dependency_overrides.pop(dep, None)


def _label_directly(
    conn: psycopg.Connection,
    user_id: str,
    alert_id: str,
    label: str = "benign",
    note: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO triage_labels (alert_id, labeler_id, source, label, confidence, note) "
        "VALUES (%s, %s, 'gold_offline', %s, '2', %s)",
        (alert_id, user_id, label, note),
    )


def _make_next(conn: psycopg.Connection, user_id: str, cluster_id: str) -> None:
    """Label every other candidate for `user_id`, so `cluster_id` is their next."""
    for row in _candidate_rows():
        if row["cluster_id"] != cluster_id:
            _label_directly(conn, user_id, row["cluster_id"])


def _next(client: _Client, cluster_id: str | None = None) -> dict[str, Any]:
    resp = client.http.get("/api/admin/labels/next", params={"labeler": client.user_id})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    if cluster_id is not None:
        assert body["cluster_id"] == cluster_id
    return body


def _string_values(value: Any, *, skip: set[str]) -> list[str]:
    """Every string value in a JSON tree, except under keys in `skip`."""
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key not in skip:
                found.extend(_string_values(item, skip=skip))
    elif isinstance(value, list):
        for item in value:
            found.extend(_string_values(item, skip=skip))
    elif isinstance(value, str):
        found.append(value)
    return found


def _count_labels(conn: psycopg.Connection, user_id: str) -> int:
    return conn.execute(
        "SELECT count(*) FROM triage_labels WHERE labeler_id = %s", (user_id,)
    ).fetchone()[0]


def _post(client: _Client, cluster_id: str, **overrides: Any):
    body = {
        "labeler": client.user_id,
        "cluster_id": cluster_id,
        "label": "benign",
        "confidence": 2,
        "note": "looks like a password typo",
    }
    body.update(overrides)
    return client.http.post("/api/admin/labels", json=body)


# ---------------------------------------------------------------------------
# Order and progress
# ---------------------------------------------------------------------------


def _synthetic(n: int) -> list[labels.Candidate]:
    return [
        labels.Candidate(
            cluster_id=f"c{i:03d}",
            gold_set="G1",
            alert_id=f"c{i:03d}",
            category="unknown",
            severity="low",
            occurrence_count=1,
            first_seen=_T,
            last_seen=_T,
        )
        for i in range(n)
    ]


def test_order_is_seeded_permutation_and_differs_per_labeler() -> None:
    candidates = _synthetic(50)
    order_a = labels.labeler_order(candidates, USER_A)
    order_b = labels.labeler_order(candidates, USER_B)
    assert sorted(order_a) == sorted(order_b) == sorted(c.cluster_id for c in candidates)
    assert order_a != order_b
    # a pure function: same call, same order; the file's row order does not matter
    assert labels.labeler_order(candidates, USER_A) == order_a
    assert labels.labeler_order(list(reversed(candidates)), USER_A) == order_a
    # the seed matters
    assert labels.labeler_order(candidates, USER_A, seed=1) != order_a


def test_label_order_seed_agrees_with_build_gold() -> None:
    text = (Path(__file__).resolve().parents[2] / "eval" / "build_gold.py").read_text("utf-8")
    assert f"EVAL_SEED = {labels.LABEL_ORDER_SEED}" in text


@pytest.mark.db
def test_next_skips_labelled_and_counts_progress(client, db) -> None:
    order = labels.labeler_order(labels.load_candidates(path=labels.CANDIDATES_PATH), USER_A)
    first = _next(client, order[0])
    assert (first["done"], first["total"]) == (0, 3)

    assert _post(client, order[0]).status_code == 201
    second = _next(client, order[1])
    assert (second["done"], second["total"]) == (1, 3)

    # user B's labels count for nothing in A's progress
    _label_directly(db, USER_B, order[1])
    assert _next(client, order[1])["done"] == 1


@pytest.mark.db
def test_next_returns_null_when_finished(client, db) -> None:
    for row in _candidate_rows():
        _label_directly(db, USER_A, row["cluster_id"])
    body = _next(client)
    # P11-T08: the two flags ride along; the labelling fields are what they were.
    assert body == {
        "cluster_id": None,
        "done": 3,
        "total": 3,
        "cluster": None,
        "frozen": False,
        "candidates_present": True,
    }


@pytest.mark.db
def test_missing_candidates_file_says_so(client, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(labels, "CANDIDATES_PATH", tmp_path / "absent.csv")
    assert _next(client) == {
        "cluster_id": None,
        "done": 0,
        "total": 0,
        "cluster": None,
        "frozen": False,
        "candidates_present": False,
    }


def test_load_candidates_discards_source_and_friends(tmp_path) -> None:
    path = _write_csv(tmp_path / "c.csv", CANDIDATE_HEADER, _candidate_rows())
    candidate = labels.load_candidates(path=path)[0]
    fields = {f.name for f in dataclasses.fields(candidate)}
    assert fields.isdisjoint({"source", "stratum", "agent_name", "rule_id"})


#: P6-T07's trailing candidate columns (`eval/build_gold.py` `CANDIDATE_COLUMNS`),
#: spelled out here rather than imported — tests do not import across the `eval`
#: boundary. The window truth rides in the same file this page reads (DEC-117).
TRUTH_COLUMNS = ["scenario_id", "kind", "truth_label"]


def test_load_candidates_drops_the_window_truth_columns(tmp_path) -> None:
    """P6-T10 (DEC-117): the input boundary of blindness. A candidates file that
    carries P6-T07's `scenario_id`/`kind`/`truth_label` yields `Candidate`s with
    none of them — neither as a field nor as a value. The allowlist tests on the
    JSON and the page are the second barrier; this is the first."""
    truth = {"scenario_id": "ZZSCN-TRUTH1", "kind": "attack", "truth_label": "escalate"}
    rows = [{**row, **truth} for row in _candidate_rows()]
    path = _write_csv(tmp_path / "c.csv", CANDIDATE_HEADER + TRUTH_COLUMNS, rows)
    candidates = labels.load_candidates(path=path)
    assert len(candidates) == len(rows)
    for candidate in candidates:
        fields = {f.name for f in dataclasses.fields(candidate)}
        assert fields.isdisjoint(TRUTH_COLUMNS)
        values = {str(v) for v in dataclasses.asdict(candidate).values()}
        assert values.isdisjoint(truth.values())


# ---------------------------------------------------------------------------
# What reaches the JSON response
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_json_response_keys_are_allowlisted(client, db) -> None:
    for cluster_id in (_A40112.alert_id, _G2_HEAD.alert_id):
        db.execute("DELETE FROM triage_labels WHERE labeler_id = %s", (USER_A,))
        _make_next(db, USER_A, cluster_id)
        body = _next(client, cluster_id)
        # P11-T08: `frozen` and `candidates_present` are the only fields beside the four.
        assert set(body) == {
            "cluster_id",
            "done",
            "total",
            "cluster",
            "frozen",
            "candidates_present",
        }
        view = body["cluster"]
        assert set(view) == ALLOWED_VIEW_KEYS
        assert set(view["correlation"]) == {"rows", "samples"}
        assert view["correlation"]["rows"], "the fixture correlates: rows must be exercised"
        assert view["correlation"]["samples"], "the fixture correlates: samples must be exercised"
        for row in view["correlation"]["rows"]:
            assert set(row) == CORRELATION_ROW_KEYS
        for sample in view["correlation"]["samples"]:
            assert set(sample) <= SAMPLE_KEYS


@pytest.mark.db
def test_allowlist_holds_without_p4_filter(db, seeded, monkeypatch) -> None:
    """The allowlist is the mechanism, P4's filter the second layer: with the
    filter neutralised the view is still exactly the allowlist, with no `source`
    value and no `status` anywhere."""
    monkeypatch.setattr(labels.visibility, "strip", lambda view, **_: dict(view))
    g1_clusters = labels.load_g1_clusters(path=labels.G1_CLUSTERS_PATH)
    for candidate in labels.load_candidates(path=labels.CANDIDATES_PATH):
        view = labels.cluster_view(db, candidate, g1_clusters=g1_clusters)
        assert set(view) == ALLOWED_VIEW_KEYS
        for row in view["correlation"]["rows"]:
            assert set(row) == CORRELATION_ROW_KEYS
        for sample in view["correlation"]["samples"]:
            assert set(sample) <= SAMPLE_KEYS
        values = _string_values(json.loads(json.dumps(view, default=str)), skip=FREE_TEXT_KEYS)
        assert [v for v in values if SOURCE_TOKENS.search(v)] == []


@pytest.mark.db
def test_json_response_has_no_forbidden_substrings_with_suggestion_visible_true(client, db) -> None:
    visible, run = db.execute(
        "SELECT a.suggestion_visible, count(r.run_id) FROM alerts a "
        "LEFT JOIN llm_runs r ON r.subject_id = a.alert_id AND r.role = 'proposer' "
        "WHERE a.alert_id = %s GROUP BY a.suggestion_visible",
        (_A40112.alert_id,),
    ).fetchone()
    assert visible is True and run == 1, "the fixture must be the leaky one"

    _make_next(db, USER_A, _A40112.alert_id)
    body = _next(client, _A40112.alert_id)
    # The playbook is the category's static KB text, the same for every alert of
    # the category: it names enrichment fields (`ioc_context`, ...) as things to
    # check and carries no alert's data. It is the one exempt value (report,
    # Deviations) — and the exemption is exercised, not vacuous:
    assert "ioc_context" in body["cluster"]["playbook"]
    body["cluster"]["playbook"] = ""
    text = json.dumps(body)
    for forbidden in FORBIDDEN_SUBSTRINGS:
        assert forbidden not in text, forbidden
    assert "false_positive" not in text


@pytest.mark.db
def test_source_value_tokens_never_in_json_outside_free_text_and_free_text_has_them(
    client, db
) -> None:
    for cluster_id in (_A40112.alert_id, _A5503.alert_id, _G2_HEAD.alert_id):
        db.execute("DELETE FROM triage_labels WHERE labeler_id = %s", (USER_A,))
        _make_next(db, USER_A, cluster_id)
        body = _next(client, cluster_id)
        leaked = [v for v in _string_values(body, skip=FREE_TEXT_KEYS) if SOURCE_TOKENS.search(v)]
        assert leaked == [], (cluster_id, leaked)

    db.execute("DELETE FROM triage_labels WHERE labeler_id = %s", (USER_A,))
    _make_next(db, USER_A, _A40112.alert_id)
    view = _next(client, _A40112.alert_id)["cluster"]
    for key in FREE_TEXT_KEYS:
        assert SOURCE_TOKENS.search(view[key]), key


# ---------------------------------------------------------------------------
# What else reaches a labeller (the page that rendered it was retired in P11-T19)
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_raw_log_is_cut_for_display_and_flagged(client, db) -> None:
    long_log = "x" * (labels.RAW_LOG_DISPLAY_BYTES + 100)
    db.execute("UPDATE alerts SET raw_log = %s WHERE alert_id = %s", (long_log, _A40112.alert_id))
    _make_next(db, USER_A, _A40112.alert_id)
    view = _next(client, _A40112.alert_id)["cluster"]
    assert view["raw_log_truncated_for_display"] is True
    assert len(view["raw_log"]) == labels.RAW_LOG_DISPLAY_BYTES


@pytest.mark.db
def test_other_labelers_label_never_appears(client, db) -> None:
    secret = "B-PRIVATE-NOTE-7f3a"
    client.as_user(USER_B)
    assert _post(client, _A40112.alert_id, label="escalate", note=secret).status_code == 201

    client.as_user(USER_A)
    _make_next(db, USER_A, _A40112.alert_id)
    resp = client.http.get("/api/admin/labels/next", params={"labeler": USER_A})
    assert resp.json()["cluster_id"] == _A40112.alert_id  # B's label does not skip it for A
    assert secret not in resp.text
    assert USER_B not in resp.text
    assert "escalate" not in resp.text

    # A's own POST: the event payload names A's label and nothing of B's
    assert _post(client, _A40112.alert_id, label="benign").status_code == 201
    payload = db.execute(
        "SELECT payload FROM audit_events WHERE event_type = 'label.created' AND actor_id = %s",
        (USER_A,),
    ).fetchone()[0]
    assert payload["label"] == "benign"
    assert secret not in json.dumps(payload) and "escalate" not in json.dumps(payload)


# ---------------------------------------------------------------------------
# POST
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_post_writes_row_and_label_created_event(client, db) -> None:
    resp = _post(client, _A40112.alert_id, confidence=3, note="  one\nline  ")
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert set(body) == {"cluster_id", "done", "total", "next"}
    assert (body["cluster_id"], body["done"], body["total"]) == (_A40112.alert_id, 1, 3)
    assert body["next"] != _A40112.alert_id and body["next"] is not None

    row = db.execute(
        "SELECT source, label, confidence, note FROM triage_labels "
        "WHERE alert_id = %s AND labeler_id = %s",
        (_A40112.alert_id, USER_A),
    ).fetchone()
    assert row == ("gold_offline", "benign", "3", "one line")

    event = db.execute(
        "SELECT subject_id, actor_role, actor_id::text, payload FROM audit_events "
        "WHERE event_type = 'label.created' AND actor_id = %s",
        (USER_A,),
    ).fetchall()
    assert len(event) == 1
    subject, role, actor, payload = event[0]
    assert (subject, role, actor) == (_A40112.alert_id, "admin", USER_A)
    assert payload == {
        "alert_id": _A40112.alert_id,
        "labeler_id": USER_A,
        "label": "benign",
        "confidence": 3,
        "gold_set": "G1",
    }


@pytest.mark.db
def test_post_duplicate_is_409(client, db) -> None:
    assert _post(client, _A40112.alert_id, label="benign").status_code == 201
    resp = _post(client, _A40112.alert_id, label="escalate")
    assert resp.status_code == 409
    assert resp.json() == {"detail": "already labelled by this labeler"}
    label = db.execute(
        "SELECT label FROM triage_labels WHERE alert_id = %s AND labeler_id = %s",
        (_A40112.alert_id, USER_A),
    ).fetchone()[0]
    assert label == "benign"  # never overwritten


@pytest.mark.db
def test_post_unknown_cluster_is_404(client, db) -> None:
    # an alert that exists in `alerts` but is not a gold candidate
    resp = _post(client, _G2_FAR.alert_id)
    assert resp.status_code == 404
    assert _count_labels(db, USER_A) == 0


@pytest.mark.db
@pytest.mark.parametrize(
    "override",
    [
        {"label": "needs_review"},
        {"label": "FALSE_POSITIVE"},
        {"confidence": 0},
        {"confidence": 4},
        {"confidence": "high"},
        {"note": "n" * (labels.NOTE_MAX_CHARS + 1)},
    ],
)
def test_post_invalid_label_or_confidence_is_422(client, db, override) -> None:
    resp = _post(client, _A40112.alert_id, **override)
    assert resp.status_code == 422, resp.text
    assert _count_labels(db, USER_A) == 0


@pytest.mark.db
def test_labeler_mismatch_is_403(client, db) -> None:
    resp = client.http.get("/api/admin/labels/next", params={"labeler": USER_B})
    assert resp.status_code == 403
    assert resp.json() == {"detail": "labeler must be the current user"}

    resp = _post(client, _A40112.alert_id, labeler=USER_B)
    assert resp.status_code == 403
    assert resp.json() == {"detail": "labeler must be the current user"}
    assert _count_labels(db, USER_A) == 0

    # labeler is required on GET
    assert client.http.get("/api/admin/labels/next").status_code == 422


# ---------------------------------------------------------------------------
# Correlation and the file's numbers
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_g1_correlation_from_file_three_way_or_and_window(seeded) -> None:
    clusters = labels.load_g1_clusters(path=labels.G1_CLUSTERS_PATH)
    head = next(c for c in clusters if c.cluster_id == _A40112.alert_id)
    rows = labels.g1_correlation(clusters, head, window_hours=2)
    assert [(r.rule_id, r.cluster_count, r.alert_count) for r in rows] == [
        ("5760", 1, 6),  # srcip only, overlapping the window's start
        ("5503", 1, 4),  # agent only, +30 min — the +5 h cluster of the same rule is not in it
        ("5710", 1, 2),  # alert_user only
    ]
    assert all(not hasattr(r, "status") for r in rows)

    # an empty alert_user / srcip on the head matches nothing by that key
    blank = dataclasses.replace(head, agent_name="NOBODY", alert_user="", srcip="")
    others = [dataclasses.replace(c, alert_user="", srcip="") for c in clusters]
    assert labels.g1_correlation(others, blank) == []

    # a 6-hour window reaches the +5 h cluster
    wide = labels.g1_correlation(clusters, head, window_hours=6)
    assert next(r for r in wide if r.rule_id == "5503").cluster_count == 2


@pytest.mark.db
def test_g2_correlation_from_db_drops_status(client, db) -> None:
    statuses = dict(
        db.execute(
            "SELECT alert_id, status FROM alerts WHERE alert_id = ANY(%s)",
            ([_G2_NEAR_RECEIVED.alert_id, _G2_NEAR_QUEUED.alert_id],),
        ).fetchall()
    )
    assert len(set(statuses.values())) == 2, "the two correlated clusters must differ in status"

    _make_next(db, USER_A, _G2_HEAD.alert_id)
    view = _next(client, _G2_HEAD.alert_id)["cluster"]
    rows = view["correlation"]["rows"]
    # one row for the two clusters of rule 40112 — re-grouped once status is gone;
    # the +5 h alert is outside the window
    assert [(r["rule_id"], r["cluster_count"], r["alert_count"]) for r in rows] == [("40112", 2, 2)]
    for item in rows + view["correlation"]["samples"]:
        assert "status" not in item
    assert {s["alert_id"] for s in view["correlation"]["samples"]} == {
        _G2_NEAR_RECEIVED.alert_id,
        _G2_NEAR_QUEUED.alert_id,
    }
    text = json.dumps(view)
    for status in statuses.values():
        assert f'"{status}"' not in text


@pytest.mark.db
def test_cluster_numbers_come_from_file_not_db(client, db) -> None:
    _make_next(db, USER_A, _G2_HEAD.alert_id)
    view = _next(client, _G2_HEAD.alert_id)["cluster"]
    assert view["occurrence_count"] == G2_FILE_OCCURRENCE != 77
    assert datetime.fromisoformat(view["first_seen"]) == G2_FILE_FIRST
    assert datetime.fromisoformat(view["last_seen"]) == G2_FILE_LAST

    db.execute("DELETE FROM triage_labels WHERE labeler_id = %s", (USER_A,))
    _make_next(db, USER_A, _A40112.alert_id)
    g1 = _next(client, _A40112.alert_id)["cluster"]
    assert g1["occurrence_count"] == 3  # the file's; the DB row says 1


@pytest.mark.db
def test_playbook_fallback_for_unknown_category(db, seeded) -> None:
    candidate = dataclasses.replace(
        labels.load_candidates(path=labels.CANDIDATES_PATH)[0], category="unknown"
    )
    view = labels.cluster_view(db, candidate, g1_clusters=[])
    assert view["playbook"] == labels.NO_PLAYBOOK_TEXT


# ---------------------------------------------------------------------------
# Undo
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_undo_last_own_label_only_and_refused_after_freeze(client, db, seeded) -> None:
    older, newer = _A40112.alert_id, _A5503.alert_id
    assert _post(client, older).status_code == 201
    assert _post(client, newer).status_code == 201
    # one transaction has one now(): order the two rows explicitly
    db.execute(
        "UPDATE triage_labels SET created_at = created_at - interval '1 minute' "
        "WHERE alert_id = %s AND labeler_id = %s",
        (older, USER_A),
    )
    client.as_user(USER_B)
    assert _post(client, newer).status_code == 201
    db.execute(
        "UPDATE triage_labels SET created_at = created_at + interval '1 minute' "
        "WHERE labeler_id = %s",
        (USER_B,),
    )  # B's row is the newest of all — A's undo must still not reach it

    client.as_user(USER_A)
    resp = _undo(client)
    assert resp.status_code == 200, resp.text
    assert resp.json()["undone_cluster_id"] == newer

    remaining = set(
        db.execute("SELECT alert_id, labeler_id::text FROM triage_labels ORDER BY 1, 2").fetchall()
    )
    assert remaining == {(older, USER_A), (newer, USER_B)}
    undo = db.execute(
        "SELECT payload FROM audit_events WHERE event_type = 'label.created' "
        "AND actor_id = %s AND payload ? 'undo'",
        (USER_A,),
    ).fetchall()
    assert [row[0]["alert_id"] for row in undo] == [newer]
    assert undo[0][0]["undo"] is True

    (seeded / "gold_v1.sha256").write_text("frozen\n", encoding="utf-8")
    assert _next(client)["frozen"] is True
    resp = _undo(client)
    assert resp.status_code == 409
    assert (
        db.execute(
            "SELECT count(*) FROM triage_labels WHERE labeler_id = %s", (USER_A,)
        ).fetchone()[0]
        == 1
    )
    with pytest.raises(labels.Frozen):
        labels.undo_last(db, USER_A, freeze_marker=labels.FREEZE_MARKER)


# ---------------------------------------------------------------------------
# P11-T08 — `POST /api/admin/labels/undo` and `next`'s two flags (spec §4.6, §5.7)
#
# A 409/404 body is `{"detail": {"reason": ...}}`, the shape `admin_overview` uses (spec §3).
# The tier1 403s and the one-transaction proof need a connection that really commits: they are
# in `test_admin_labels_api.py`, on a scratch database. Everything here runs inside the `db`
# fixture's transaction, which the overridden `get_conn` never commits.
# ---------------------------------------------------------------------------

UNDO = "/api/admin/labels/undo"
NEXT_KEYS = {"cluster_id", "done", "total", "cluster", "frozen", "candidates_present"}
#: Keys that must appear nowhere in a labelling payload, at any depth (blind labelling,
#: DEC-019, DEC-101): the stored `source`, the pilot's status, the suggestion and its risk,
#: and the window truth the candidates file carries (DEC-117).
FORBIDDEN_KEYS = {
    "source",
    "stratum",
    "status",
    "triage_status",
    "suggestion_visible",
    "suggested_action",
    "gate_result",
    "risk_score",
    "scenario_id",
    "kind",
    "truth_label",
}
NO_CANDIDATES = {"cluster_id": None, "done": 0, "total": 0, "cluster": None}


def _undo(client: _Client, body: Any = None):
    return client.http.post(UNDO, json={} if body is None else body)


def _undo_events(conn: psycopg.Connection, user_id: str) -> list[Any]:
    return conn.execute(
        "SELECT subject_id, actor_role, actor_id::text, payload FROM audit_events "
        "WHERE event_type = 'label.created' AND actor_id = %s AND payload ? 'undo' "
        "ORDER BY audit_id",
        (user_id,),
    ).fetchall()


def _shift(conn: psycopg.Connection, user_id: str, alert_id: str, minutes: int) -> None:
    """One transaction has one `now()`: give two rows an order by moving one."""
    conn.execute(
        "UPDATE triage_labels SET created_at = created_at + make_interval(mins => %s) "
        "WHERE alert_id = %s AND labeler_id = %s",
        (minutes, alert_id, user_id),
    )


def _all_keys(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(key)
            found |= _all_keys(item)
    elif isinstance(value, list):
        for item in value:
            found |= _all_keys(item)
    return found


def _my_order(client: _Client) -> list[str]:
    candidates = labels.load_candidates(path=labels.CANDIDATES_PATH)
    return labels.labeler_order(candidates, client.user_id)


@pytest.mark.db
def test_api_undo_deletes_the_last_label_and_answers_cluster_and_progress(client, db) -> None:
    order = _my_order(client)
    assert _post(client, order[0]).status_code == 201
    assert _post(client, order[1]).status_code == 201
    _shift(db, USER_A, order[0], -1)  # order[1] is the last
    assert _next(client, order[2])["done"] == 2

    resp = _undo(client)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"undone_cluster_id": order[1], "done": 1, "total": 3}
    assert db.execute(
        "SELECT alert_id FROM triage_labels WHERE labeler_id = %s", (USER_A,)
    ).fetchall() == [(order[0],)]
    ((subject, role, actor, payload),) = _undo_events(db, USER_A)
    assert (subject, role, actor) == (order[1], "admin", USER_A)
    assert payload == {"undo": True, "alert_id": order[1], "labeler_id": USER_A}
    # the undone cluster is the labeller's next again, and the progress agrees
    again = _next(client)
    assert (again["cluster_id"], again["done"], again["total"]) == (order[1], 1, 3)

    # a second undo takes the one before it, a third finds nothing
    second = _undo(client)
    assert second.status_code == 200 and second.json() == {
        "undone_cluster_id": order[0],
        "done": 0,
        "total": 3,
    }
    assert _undo(client).status_code == 404


@pytest.mark.db
def test_api_undo_with_nothing_to_undo_is_404(client, db) -> None:
    resp = _undo(client)
    assert resp.status_code == 404
    assert resp.json() == {"detail": {"reason": "nothing_to_undo"}}
    assert _undo_events(db, USER_A) == []


@pytest.mark.db
def test_api_undo_is_409_frozen_while_the_marker_exists_and_deletes_nothing(
    client, db, tmp_path, monkeypatch
) -> None:
    order = _my_order(client)
    assert _post(client, order[0]).status_code == 201
    marker = tmp_path / "gold-freeze-marker"
    marker.write_text("frozen\n", encoding="utf-8")
    monkeypatch.setattr(labels, "FREEZE_MARKER", marker)

    resp = _undo(client)
    assert resp.status_code == 409
    assert resp.json() == {"detail": {"reason": "frozen"}}
    assert _count_labels(db, USER_A) == 1
    assert _undo_events(db, USER_A) == []
    # frozen is answered before "nothing to undo": a labeller with no rows gets the 409 too
    assert _undo(client.as_user(USER_B)).status_code == 409
    assert _undo_events(db, USER_B) == []

    marker.unlink()  # the marker is read per request: with it gone the undo works
    assert _undo(client.as_user(USER_A)).status_code == 200
    assert _count_labels(db, USER_A) == 0


@pytest.mark.db
def test_api_undo_takes_only_the_callers_own_last_label(client, db) -> None:
    older, newer = _A40112.alert_id, _A5503.alert_id
    assert _post(client, older).status_code == 201
    assert _post(client, newer).status_code == 201
    _shift(db, USER_A, older, -1)
    client.as_user(USER_B)
    assert _post(client, newer).status_code == 201
    _shift(db, USER_B, newer, 1)  # B's row is the newest of all: A's undo must not reach it
    mine = {(older, USER_A), (newer, USER_A)}
    theirs = (newer, USER_B)

    def rows() -> set[tuple[str, str]]:
        return set(db.execute("SELECT alert_id, labeler_id::text FROM triage_labels").fetchall())

    assert rows() == mine | {theirs}
    client.as_user(USER_A)
    first = _undo(client)
    assert first.status_code == 200 and first.json()["undone_cluster_id"] == newer
    assert rows() == {(older, USER_A), theirs}
    second = _undo(client)
    assert second.status_code == 200 and second.json()["undone_cluster_id"] == older
    assert rows() == {theirs}
    # A has nothing left; B's row is not A's to undo
    assert _undo(client).status_code == 404
    assert rows() == {theirs}
    assert _undo_events(db, USER_B) == []

    done = _undo(client.as_user(USER_B))
    assert done.status_code == 200 and done.json()["undone_cluster_id"] == newer
    assert rows() == set()


@pytest.mark.db
@pytest.mark.parametrize("body", [{}, {"labeler": USER_A}, {"labeler": None}])
def test_api_undo_accepts_an_empty_object_or_the_caller_as_labeler(client, db, body) -> None:
    assert _post(client, _my_order(client)[0]).status_code == 201
    resp = _undo(client, body)
    assert resp.status_code == 200, resp.text
    assert _count_labels(db, USER_A) == 0


@pytest.mark.db
def test_api_undo_with_another_labeler_is_403_like_next_and_post(client, db) -> None:
    assert _post(client, _my_order(client)[0]).status_code == 201
    resp = _undo(client, {"labeler": USER_B})
    assert resp.status_code == 403
    assert resp.json() == {"detail": "labeler must be the current user"}
    assert _count_labels(db, USER_A) == 1
    assert _undo_events(db, USER_A) == []


#: Raw JSON text, so `null` can be sent (`json=None` sends nothing at all).
_BAD_JSON_BODIES = [
    '{"cluster_id": "x"}',
    json.dumps({"labeler": USER_A, "extra": 1}),
    "[]",
    "null",
    '"x"',
    "{",
]


@pytest.mark.db
@pytest.mark.parametrize("text", _BAD_JSON_BODIES)
def test_api_undo_refuses_a_body_that_is_not_an_empty_object_or_the_labeler(
    client, db, text
) -> None:
    assert _post(client, _my_order(client)[0]).status_code == 201
    resp = client.http.post(
        UNDO, content=text.encode(), headers={"content-type": "application/json"}
    )
    assert resp.status_code == 422, resp.text
    assert _count_labels(db, USER_A) == 1
    assert _undo_events(db, USER_A) == []


#: Each is a request a page of another site could make with a no-cors `fetch` or an HTML form: a
#: Blob or text body, a form, nothing at all. (Until P11-T19 the session cookie would have signed
#: such a request in; now only this content-type rule is left, and it is still the route's.)
_NOT_JSON = {
    "nothing at all": {},
    "no content type": {"content": b"{}"},
    "text/plain": {"content": b"{}", "headers": {"content-type": "text/plain"}},
    "text/plain with a labeler": {
        "content": json.dumps({"labeler": USER_A}).encode(),
        "headers": {"content-type": "text/plain;charset=UTF-8"},
    },
    "urlencoded form": {"data": {"labeler": USER_A}},
    "multipart form": {"files": {"labeler": (None, USER_A)}},
    "json type, empty body": {"content": b"", "headers": {"content-type": "application/json"}},
}


@pytest.mark.db
@pytest.mark.parametrize("kwargs", list(_NOT_JSON.values()), ids=list(_NOT_JSON))
def test_api_undo_without_a_json_body_is_422_and_deletes_nothing(client, db, kwargs) -> None:
    assert _post(client, _my_order(client)[0]).status_code == 201
    resp = client.http.post(UNDO, **kwargs)
    assert resp.status_code == 422, resp.text
    if "content" in kwargs and "headers" not in kwargs:
        assert "content-type" not in resp.request.headers  # the case is what it says it is
    assert _count_labels(db, USER_A) == 1
    assert _undo_events(db, USER_A) == []


@pytest.mark.db
def test_api_undo_maps_the_alert_back_to_the_candidates_cluster_id(
    client, db, tmp_path, monkeypatch
) -> None:
    """`triage_labels` holds the head's `alert_id`; the answer names the candidate's
    `cluster_id`, found in `gold_candidates.csv` by that alert id."""
    rows = _candidate_rows()
    renamed = "gold-cluster-for-5503"
    rows[1] = {**rows[1], "cluster_id": renamed}  # its alert_id is still _A5503's
    path = _write_csv(tmp_path / "renamed.csv", CANDIDATE_HEADER, rows)
    monkeypatch.setattr(labels, "CANDIDATES_PATH", path)
    assert _post(client, renamed).status_code == 201
    assert db.execute(
        "SELECT alert_id FROM triage_labels WHERE labeler_id = %s", (USER_A,)
    ).fetchall() == [(_A5503.alert_id,)]

    resp = _undo(client)
    assert resp.status_code == 200
    assert resp.json()["undone_cluster_id"] == renamed != _A5503.alert_id


@pytest.mark.db
def test_api_undo_still_works_when_the_candidates_file_is_gone(
    client, db, tmp_path, monkeypatch
) -> None:
    """Nothing to map the alert through: the answer is the alert id, which is the cluster id of
    both gold sets (`next_unlabelled`), and the progress is the empty one."""
    assert _post(client, _A40112.alert_id).status_code == 201
    monkeypatch.setattr(labels, "CANDIDATES_PATH", tmp_path / "absent.csv")
    resp = _undo(client)
    assert resp.status_code == 200
    assert resp.json() == {"undone_cluster_id": _A40112.alert_id, "done": 0, "total": 0}
    assert _count_labels(db, USER_A) == 0


@pytest.mark.db
@pytest.mark.parametrize("frozen", [False, True], ids=["unfrozen", "frozen"])
@pytest.mark.parametrize("present", [True, False], ids=["candidates", "no candidates"])
def test_next_carries_frozen_and_candidates_present(
    client, tmp_path, monkeypatch, frozen, present
) -> None:
    marker = tmp_path / "gold-freeze-marker"
    if frozen:
        marker.write_text("frozen\n", encoding="utf-8")
    monkeypatch.setattr(labels, "FREEZE_MARKER", marker)
    if not present:
        monkeypatch.setattr(labels, "CANDIDATES_PATH", tmp_path / "absent.csv")

    body = _next(client)
    assert set(body) == NEXT_KEYS
    assert body["frozen"] is frozen
    assert body["candidates_present"] is present
    if present:
        assert body["total"] == 3 and body["cluster"] is not None
    else:  # the behaviour that was: 200, no cluster, 0 of 0
        assert {k: body[k] for k in NO_CANDIDATES} == NO_CANDIDATES


@pytest.mark.db
def test_next_says_no_candidates_for_an_unreadable_file_or_a_directory(
    client, tmp_path, monkeypatch
) -> None:
    unreadable = tmp_path / "unreadable.csv"
    unreadable.write_text("cluster_id\n", encoding="utf-8")
    unreadable.chmod(0)
    for path in (unreadable, tmp_path):
        if path is unreadable and os.access(path, os.R_OK):
            continue  # root reads a mode-000 file: nothing to show for it
        monkeypatch.setattr(labels, "CANDIDATES_PATH", path)
        body = _next(client)
        assert body == {**NO_CANDIDATES, "frozen": False, "candidates_present": False}


@pytest.mark.db
def test_next_payload_is_blind_top_level_and_cluster_keys_are_exactly_the_documented_set(
    client, db
) -> None:
    g1 = labels.load_g1_clusters(path=labels.G1_CLUSTERS_PATH)
    candidates = {c.cluster_id: c for c in labels.load_candidates(path=labels.CANDIDATES_PATH)}
    for cluster_id in (_A40112.alert_id, _A5503.alert_id, _G2_HEAD.alert_id):
        db.execute("DELETE FROM triage_labels WHERE labeler_id = %s", (USER_A,))
        _make_next(db, USER_A, cluster_id)
        body = _next(client, cluster_id)
        assert set(body) == NEXT_KEYS
        # `cluster` is `cluster_view`'s dict in labelling mode and nothing more, whatever the
        # route adds around it
        expected = labels.cluster_view(db, candidates[cluster_id], g1_clusters=g1)
        assert set(body["cluster"]) == set(expected) == ALLOWED_VIEW_KEYS
        keys = _all_keys(body)
        assert keys.isdisjoint(FORBIDDEN_KEYS), keys & FORBIDDEN_KEYS
        documented = NEXT_KEYS | ALLOWED_VIEW_KEYS | {"rows", "samples"}
        assert keys <= documented | CORRELATION_ROW_KEYS | SAMPLE_KEYS, keys - documented
    # a finished labeller still gets the same top level, and a null cluster
    _label_directly(db, USER_A, _G2_HEAD.alert_id)  # the last of the three
    finished = _next(client)
    assert set(finished) == NEXT_KEYS and finished["cluster"] is None


def test_every_route_of_the_labels_router_carries_the_admin_dependency() -> None:
    routes = {(m, r.path) for r in labels_router.router.routes for m in r.methods}
    assert ("POST", "/api/admin/labels/undo") in routes
    assert ("GET", "/api/admin/labels/next") in routes
    for route in labels_router.router.routes:
        calls = [d.call for d in route.dependant.dependencies]
        assert labels_router.require_admin in calls, route.path


# ---------------------------------------------------------------------------
# P11-T20 part 2, rows 28-30 (P11-T08 review F1-F3): three gaps in the undo's tests.
#
# Tests only: the code was right. Every path goes through `seeded`'s `tmp_path` and
# `monkeypatch`; nothing here reads or writes anything under `eval/`.
# ---------------------------------------------------------------------------


def _label_with_source(conn: psycopg.Connection, user_id: str, alert_id: str, source: str) -> None:
    conn.execute(
        "INSERT INTO triage_labels (alert_id, labeler_id, source, label, confidence) "
        "VALUES (%s, %s, %s, 'benign', '2')",
        (alert_id, user_id, source),
    )


def _label_rows(conn: psycopg.Connection, user_id: str) -> list[tuple[str, str]]:
    return conn.execute(
        "SELECT alert_id, source FROM triage_labels WHERE labeler_id = %s ORDER BY 1, 2",
        (user_id,),
    ).fetchall()


@pytest.mark.db
@pytest.mark.parametrize("other", ["digest", "disagreement", "lab"])
def test_undo_takes_only_gold_offline_never_a_newer_label_of_another_source(
    client, db, other
) -> None:
    """Row 28. The caller's newest row of ALL sources is not what undo deletes: the filter is
    `source = 'gold_offline'`. Without it the caller's newer `digest` verdict (or the
    `disagreement` row `label_export freeze` writes) would be deleted instead of the gold label."""
    gold, newer = _A40112.alert_id, _A5503.alert_id
    assert _post(client, gold).status_code == 201
    _label_with_source(db, USER_A, newer, other)
    _shift(db, USER_A, gold, -1)  # one now() per transaction: the other row is the newest
    newest = db.execute(
        "SELECT source FROM triage_labels WHERE labeler_id = %s ORDER BY created_at DESC LIMIT 1",
        (USER_A,),
    ).fetchone()
    assert newest == (other,)  # the premise: the newest row is not a gold_offline one

    resp = _undo(client)
    assert resp.status_code == 200, resp.text
    assert resp.json()["undone_cluster_id"] == gold
    assert _label_rows(db, USER_A) == [(newer, other)]
    ((subject, _, _, payload),) = _undo_events(db, USER_A)
    assert subject == gold and payload["alert_id"] == gold

    # nothing gold_offline is left, so the next undo is a 404 and the other row stays
    again = _undo(client)
    assert again.status_code == 404
    assert again.json() == {"detail": {"reason": "nothing_to_undo"}}
    assert _label_rows(db, USER_A) == [(newer, other)]
    assert len(_undo_events(db, USER_A)) == 1


@pytest.mark.db
def test_undo_leaves_a_digest_and_a_disagreement_row_newer_than_the_gold_label(client, db) -> None:
    """The same, with both of the other kinds present, one of them on the gold label's own alert."""
    gold = _A40112.alert_id
    assert _post(client, gold).status_code == 201
    _label_with_source(db, USER_A, _A5503.alert_id, "digest")
    _label_with_source(db, USER_A, gold, "disagreement")  # the same alert, another source
    db.execute(
        "UPDATE triage_labels SET created_at = created_at - interval '5 minutes' "
        "WHERE labeler_id = %s AND source = 'gold_offline'",
        (USER_A,),
    )
    assert _undo(client).status_code == 200
    kept = [(gold, "disagreement"), (_A5503.alert_id, "digest")]
    assert _label_rows(db, USER_A) == kept
    assert _undo(client).status_code == 404
    assert _label_rows(db, USER_A) == kept


#: Each is a request an undo must never act on. The expected status is the one the request
#: really gets: a well-formed string that is not the caller is the 403 `_bind` gives, a body
#: that is not JSON, or has a key the model does not have, is the 422.
_UNDO_HOSTILE_BODIES: dict[str, tuple[bytes, int]] = {
    "escaped NUL in labeler": (b'{"labeler": "a\\u0000b"}', 403),
    "escaped NUL alone": (b'{"labeler": "\\u0000"}', 403),
    "raw NUL byte in the labeler": (b'{"labeler": "a\x00b"}', 422),
    "raw NUL byte after the object": (b"{}\x00", 422),
    "raw NUL byte alone": (b"\x00", 422),
    "NUL in a key": (b'{"\\u0000": 1}', 422),
    "raw NUL in a key": (b'{"a\x00b": 1}', 422),
    "C0 control in labeler": (b'{"labeler": "a\\u0001b"}', 403),
    "escaped newline and tab in labeler": (b'{"labeler": "a\\n\\tb"}', 403),
    "DEL in labeler": (b'{"labeler": "a\\u007fb"}', 403),
    "raw C0 control in the labeler": (b'{"labeler": "a\x01b"}', 422),
    "C1 control in labeler": (b'{"labeler": "a\\u0085b"}', 403),
    "NUL after the caller's id": (json.dumps({"labeler": USER_A + "\x00"}).encode(), 403),
    "a control character in a key": (b'{"a\\u0001": 1}', 422),
}


@pytest.mark.db
@pytest.mark.parametrize(
    ("raw", "status"), list(_UNDO_HOSTILE_BODIES.values()), ids=list(_UNDO_HOSTILE_BODIES)
)
def test_undo_with_a_nul_or_control_character_in_the_body_is_refused_and_the_label_is_intact(
    client, db, raw, status
) -> None:
    """Row 29. 403 or 422, never a 500 and never a deletion."""
    assert _post(client, _my_order(client)[0]).status_code == 201
    rows_before = _label_rows(db, USER_A)
    events_before = db.execute("SELECT count(*) FROM audit_events").fetchone()[0]

    resp = client.http.post(UNDO, content=raw, headers={"content-type": "application/json"})
    assert resp.status_code in (403, 422), resp.text
    assert resp.status_code == status, resp.text
    assert _label_rows(db, USER_A) == rows_before
    assert _undo_events(db, USER_A) == []
    assert db.execute("SELECT count(*) FROM audit_events").fetchone()[0] == events_before


@pytest.mark.db
def test_the_undo_while_frozen_writes_nothing(client, db, seeded) -> None:
    """Row 30. The 409 of `POST /api/admin/labels/undo` changes no row and writes no event: not an
    undo event, and no audit event of any kind. (It was written against the Jinja undo, which
    P11-T19 retired; the JSON route is the one left, and the one this runs on.)"""
    first, second = _A40112.alert_id, _A5503.alert_id
    assert _post(client, first).status_code == 201
    assert _post(client, second).status_code == 201
    _shift(db, USER_A, first, -1)
    rows_sql = (
        "SELECT alert_id, labeler_id::text, source, label, confidence, note, created_at "
        "FROM triage_labels ORDER BY 1, 2, 3"
    )
    snapshot = db.execute(rows_sql).fetchall()
    audit_before = db.execute("SELECT count(*), max(audit_id) FROM audit_events").fetchone()
    assert len(snapshot) == 2 and _undo_events(db, USER_A) == []

    (seeded / "gold_v1.sha256").write_text("frozen\n", encoding="utf-8")  # tmp_path, via `seeded`
    assert labels.FREEZE_MARKER == seeded / "gold_v1.sha256"
    resp = _undo(client)
    assert resp.status_code == 409

    assert _undo_events(db, USER_A) == []
    assert db.execute("SELECT count(*), max(audit_id) FROM audit_events").fetchone() == audit_before
    assert db.execute(rows_sql).fetchall() == snapshot
    # a second frozen request still writes nothing
    assert _undo(client).status_code == 409
    assert db.execute("SELECT count(*), max(audit_id) FROM audit_events").fetchone() == audit_before
    assert db.execute(rows_sql).fetchall() == snapshot
