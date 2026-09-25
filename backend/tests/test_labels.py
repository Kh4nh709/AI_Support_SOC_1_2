"""P6-T02 — the blind labelling page: `app.tier1.labels`, `app.web.routers.labels`,
`templates/labels.html`.

The page must show a labeller one cluster at a time, in their own seeded order,
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
dependencies (`deps.current_user`, `pages.page_user`) are overridden to run as
user A or user B — `require_role("admin")` itself still runs on those claims.
"""

from __future__ import annotations

import csv
import dataclasses
import hashlib
import json
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
from app.web.routers import pages
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


def _g1(cluster_id: str, rule_id: str, agent: str, user: str, srcip: str, first: datetime,
        last: datetime, occurrence: int) -> dict[str, Any]:
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
        _g1(_A40112.alert_id, "40112", agent, "user1", "127.0.0.1", _T, _T + timedelta(minutes=2), 3),
        # hit on agent_name only, 30 minutes after the head
        _g1("g1-hit-agent", "5503", agent, "someone", "", _T + timedelta(minutes=30),
            _T + timedelta(minutes=34), 4),
        # hit on alert_user only, before the head
        _g1("g1-hit-user", "5710", "OTHER-HOST", "user1", "", _T - timedelta(minutes=90),
            _T - timedelta(minutes=80), 2),
        # hit on srcip only; starts before the window, ends inside it
        _g1("g1-hit-srcip", "5760", "OTHER-HOST-2", "", "127.0.0.1", _T - timedelta(hours=3),
            _T - timedelta(minutes=110), 6),
        # miss: same agent, 5 hours later
        _g1("g1-miss-late", "5503", agent, "someone", "", _T + timedelta(hours=5),
            _T + timedelta(hours=5, minutes=3), 9),
        # miss: in the window, but no key in common
        _g1("g1-miss-keys", "5503", "UNRELATED", "bob", "10.9.9.9", _T + timedelta(minutes=10),
            _T + timedelta(minutes=12), 5),
        # the second G1 candidate's own cluster, weeks away
        _g1(_A5503.alert_id, "5503", _A5503.agent_name, "root", "202.165.25.8",
            _A5503.alert_time, _A5503.alert_time, 1),
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


def _open(conn: psycopg.Connection, alert: Alert, *, source: str = "wazuh",
          suggestion_visible: bool = True) -> None:
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
    main.app.dependency_overrides[pages.page_user] = c.claims
    try:
        yield c
    finally:
        for dep in (deps.get_conn, deps.get_config, deps.current_user, pages.page_user):
            main.app.dependency_overrides.pop(dep, None)


def _label_directly(conn: psycopg.Connection, user_id: str, alert_id: str,
                    label: str = "benign", note: str | None = None) -> None:
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


def _page(client: _Client) -> str:
    resp = client.http.get("/admin/labels")
    assert resp.status_code == 200, resp.text
    return resp.text


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


def _without_elements(html: str, *patterns: str) -> str:
    for pattern in patterns:
        html = re.sub(pattern, "", html, flags=re.DOTALL)
    return html


_FREE_TEXT_ELEMENTS = (
    r'<pre data-field="raw_log">.*?</pre>',
    r'<span data-field="description">.*?</span>',
)
_PLAYBOOK_ELEMENT = r'<pre data-field="playbook">.*?</pre>'
_LABEL_FORM = r'<form id="label-form".*?</form>'


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
    assert body == {"cluster_id": None, "done": 3, "total": 3, "cluster": None}
    html = _page(client)
    assert 'id="finished"' in html
    assert 'id="label-form"' not in html


@pytest.mark.db
def test_missing_candidates_file_says_so(client, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(labels, "CANDIDATES_PATH", tmp_path / "absent.csv")
    assert _next(client) == {"cluster_id": None, "done": 0, "total": 0, "cluster": None}
    html = _page(client)
    assert "eval/gold_candidates.csv</code> is not present" in html
    assert 'id="finished"' not in html


def test_load_candidates_discards_source_and_friends(tmp_path) -> None:
    path = _write_csv(tmp_path / "c.csv", CANDIDATE_HEADER, _candidate_rows())
    candidate = labels.load_candidates(path=path)[0]
    fields = {f.name for f in dataclasses.fields(candidate)}
    assert fields.isdisjoint({"source", "stratum", "agent_name", "rule_id"})


# ---------------------------------------------------------------------------
# What reaches the JSON response
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_json_response_keys_are_allowlisted(client, db) -> None:
    for cluster_id in (_A40112.alert_id, _G2_HEAD.alert_id):
        db.execute("DELETE FROM triage_labels WHERE labeler_id = %s", (USER_A,))
        _make_next(db, USER_A, cluster_id)
        body = _next(client, cluster_id)
        assert set(body) == {"cluster_id", "done", "total", "cluster"}
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
# What reaches the rendered page
# ---------------------------------------------------------------------------

_ALLOWED_DATA_FIELDS = ALLOWED_VIEW_KEYS | {"progress"}


@pytest.mark.db
def test_html_data_fields_are_allowlisted(client, db) -> None:
    for cluster_id in (_A40112.alert_id, _G2_HEAD.alert_id):
        db.execute("DELETE FROM triage_labels WHERE labeler_id = %s", (USER_A,))
        _make_next(db, USER_A, cluster_id)
        html = _page(client)
        fields = set(re.findall(r'data-field="([^"]+)"', html))
        assert fields <= _ALLOWED_DATA_FIELDS, fields - _ALLOWED_DATA_FIELDS
        # the page does render the representative alert, not an empty shell
        assert {"raw_log", "description", "correlation", "playbook", "progress"} <= fields


@pytest.mark.db
def test_html_has_no_forbidden_substrings_outside_free_text(client, db) -> None:
    _make_next(db, USER_A, _A40112.alert_id)
    html = _page(client)
    assert "ioc_context" in re.search(_PLAYBOOK_ELEMENT, html, re.DOTALL).group(0)
    outside = _without_elements(html, _PLAYBOOK_ELEMENT)
    for forbidden in FORBIDDEN_SUBSTRINGS:
        assert forbidden not in outside, forbidden

    outside_free_text = _without_elements(html, *_FREE_TEXT_ELEMENTS)
    assert SOURCE_TOKENS.findall(outside_free_text) == []
    # ... while the free text itself does carry them
    free_text = "".join(
        m.group(0) for p in _FREE_TEXT_ELEMENTS for m in re.finditer(p, html, re.DOTALL)
    )
    assert SOURCE_TOKENS.search(free_text)


@pytest.mark.db
def test_html_false_positive_only_inside_label_form(client, db) -> None:
    _make_next(db, USER_A, _A40112.alert_id)
    html = _page(client)
    form = re.search(_LABEL_FORM, html, re.DOTALL)
    assert form is not None
    assert form.group(0).count("false_positive") == 1
    assert 'value="false_positive"' in form.group(0)
    assert _without_elements(html, _LABEL_FORM).count("false_positive") == 0


@pytest.mark.db
def test_html_marks_raw_log_cut_for_display(client, db) -> None:
    long_log = "x" * (labels.RAW_LOG_DISPLAY_BYTES + 100)
    db.execute("UPDATE alerts SET raw_log = %s WHERE alert_id = %s", (long_log, _A40112.alert_id))
    _make_next(db, USER_A, _A40112.alert_id)
    view = _next(client, _A40112.alert_id)["cluster"]
    assert view["raw_log_truncated_for_display"] is True
    assert len(view["raw_log"]) == labels.RAW_LOG_DISPLAY_BYTES
    assert "[cut for display at 32 KB]" in _page(client)


@pytest.mark.db
def test_other_labelers_label_never_appears(client, db) -> None:
    secret = "B-PRIVATE-NOTE-7f3a"
    client.as_user(USER_B)
    assert _post(client, _A40112.alert_id, label="escalate", note=secret).status_code == 201

    client.as_user(USER_A)
    _make_next(db, USER_A, _A40112.alert_id)
    resp = client.http.get("/api/admin/labels/next", params={"labeler": USER_A})
    assert resp.json()["cluster_id"] == _A40112.alert_id  # B's label does not skip it for A
    html = _page(client)
    for text in (resp.text, html):
        assert secret not in text
        assert USER_B not in text
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


@pytest.mark.db
def test_page_form_post_labels_as_session_user(client, db) -> None:
    resp = client.http.post(
        "/admin/labels",
        data={"cluster_id": _A40112.alert_id, "label": "escalate", "confidence": "1", "note": "n"},
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/admin/labels"
    owner = db.execute(
        "SELECT labeler_id::text FROM triage_labels WHERE alert_id = %s", (_A40112.alert_id,)
    ).fetchone()[0]
    assert owner == USER_A

    again = client.http.post(
        "/admin/labels",
        data={"cluster_id": _A40112.alert_id, "label": "benign", "confidence": "1"},
    )
    assert again.status_code == 409
    assert 'id="flash"' in again.text


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
    assert 'id="undo-form"' in _page(client)
    resp = client.http.post("/admin/labels/undo")
    assert resp.status_code == 303

    remaining = set(
        db.execute(
            "SELECT alert_id, labeler_id::text FROM triage_labels ORDER BY 1, 2"
        ).fetchall()
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
    assert 'id="undo-form"' not in _page(client)
    resp = client.http.post("/admin/labels/undo")
    assert resp.status_code == 409
    assert db.execute(
        "SELECT count(*) FROM triage_labels WHERE labeler_id = %s", (USER_A,)
    ).fetchone()[0] == 1
    with pytest.raises(labels.Frozen):
        labels.undo_last(db, USER_A, freeze_marker=labels.FREEZE_MARKER)
