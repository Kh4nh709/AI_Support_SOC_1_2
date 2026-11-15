"""DB tests for DEC-221, card AP-T2: the Tier 1 alert view carries `analysis`
(`docs/superpowers/specs/2026-11-15-ai-analysis-panel-redesign.md` section 5), built from the very row of the newest
proposer run the suggestion is built from, with the lookup it held and the knowledge entries it lists.

Fixtures are `test_queue.py`'s (a head through the real transitions) and `test_analysis_view.py`'s stored documents;
`llm_runs`, `rag_results` and `knowledge_entries` rows are inserted in the shape `tier1/triage.py`, `rag/lookup.py` and
`rag/entries.py` write them. Every test runs in the `db` fixture's transaction.

What is pinned here that the pure files cannot: the statements (what the view runs, and that nothing selects a model
column), the model's name nowhere in what the Tier 1 view and queue serve (walked at every depth, for a run whose
`model_id` is a distinctive string), the blind arm and the labelling page (walked), the withholding for a run the RAG
default applied to (through the real statement, the stored row untouched), and a garbled stored document.
"""

from __future__ import annotations

import copy
import json
import re
import uuid
from typing import Any

import pytest
from app.domain.transitions import acknowledge, decide
from app.rag import entries
from app.tier1 import queue
from app.tier1.queue import get_alert_view, latest_suggestions, list_queue
from app.tier1.visibility import ANALYST_HIDE, LABELING_DENYLIST
from psycopg.types.json import Jsonb

from tests.rag_data import add_entry
from tests.test_analysis_view import BASIS, RAW, REASONS, STEPS, TEXTS, _gate
from tests.test_queue import USER_ID, _duplicate, _queued, _seed_user, _walk_keys

pytestmark = pytest.mark.db


@pytest.fixture(autouse=True)
def _floor_half(monkeypatch):
    """The floor `rag_view` compares a lookup's best candidate with is `RAG_MIN_SCORE` of the running configuration;
    a test pins it through the environment, as every config-reading test does."""
    monkeypatch.setenv("RAG_MIN_SCORE", "0.5")


#: A name no real model has: if it shows in anything the Tier 1 pages are served, the model's name leaked (goal G5).
MODEL_ID = "zz-distinct-model-id-9000"
VERIFIER_MODEL_ID = "zz-distinct-verifier-model-7000"

ENTRY_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ENTRY_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
ENTRY_C = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"

HISTORY = {
    "level": 3,
    "key_name": "rule_host",
    "total": 15,
    "by_conclusion": {
        "tier1_closed_fp": 0,
        "tier1_closed_benign": 1,
        "escalated_open": 0,
        "concluded_fp": 2,
        "concluded_policy_violation": 0,
        "confirmed_incident": 12,
    },
    "last_seen": "2026-11-14T10:00:00+00:00",
    "examples": ["a-1", "a-2"],
}


def _entry(conn, entry_id: str, title: str, conclusion: str, *, status: str = "active") -> None:
    content = entries.render_entry_markdown(
        {
            "entry_id": entry_id,
            "version": 1,
            "title": title,
            "conclusion": conclusion,
            "category": "recon",
            "summary": "Tóm tắt.",
        }
    )
    add_entry(conn, entry_id=entry_id, conclusion=conclusion, content=content, status=status)


def _lookup(
    conn,
    alert_id: str,
    *,
    matches: list[dict] | None = None,
    ranked: list[dict] | None = None,
    history: dict | None = None,
    status: str = "ok",
) -> str:
    lookup_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO rag_results (lookup_id, subject_kind, subject_id, status, history, matches, ranked,"
        " match_notes) VALUES (%s, 'alert', %s, %s, %s, %s, %s, %s)",
        (
            lookup_id,
            alert_id,
            status,
            Jsonb(history) if history is not None else None,
            Jsonb(matches if matches is not None else []),
            Jsonb(ranked) if ranked is not None else None,
            Jsonb({}),
        ),
    )
    return lookup_id


def _match(entry_id: str, score: float) -> dict:
    return {"entry_id": entry_id, "level": "giong", "content_sha256": "0" * 64, "score": score}


def _insert_run(
    conn,
    alert_id: str,
    *,
    result: Any = None,
    gate_result: Any = None,
    role: str = "proposer",
    model_id: str | None = MODEL_ID,
    lookup_id: str | None = None,
    warnings: list[str] | None = None,
    offset_s: int = 0,
    input_tokens: int | None = 1200,
    output_tokens: int | None = 340,
    latency_ms: int | None = 2100,
    cost_usd: str | None = "0.01234",
    stopped_by: str | None = None,
) -> str:
    """One `llm_runs` row of ① in the shape `tier1/triage.py` writes (the columns this card reads, and `model_id`,
    which it must never serve)."""
    run_id = str(uuid.uuid4())
    result = copy.deepcopy(RAW) if result is None else result
    gate_result = _gate() if gate_result is None else gate_result
    conn.execute(
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt, user_message, result,"
        " role, gate_result, stopped_by, rag_lookup_id, citation_warnings, model_id, input_tokens, output_tokens,"
        " latency_ms, cost_usd, created_at) VALUES (%s, 'triage', 'alert', %s, 's', 'u', %s, %s, %s, %s, %s, %s,"
        " %s, %s, %s, %s, %s, now() + %s * interval '1 second')",
        (
            run_id,
            alert_id,
            Jsonb(result) if result != "NULL" else None,
            role,
            Jsonb(gate_result),
            stopped_by,
            lookup_id,
            Jsonb(warnings) if warnings is not None else None,
            model_id,
            input_tokens,
            output_tokens,
            latency_ms,
            cost_usd,
            offset_s,
        ),
    )
    return run_id


def _strings(value: Any):
    """Every key and every string value of a served view, at every depth."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)
    elif value is not None:
        yield str(value)


class _Statements:
    """Records every statement the connection runs inside the block."""

    def __init__(self, conn):
        self.conn = conn
        self.statements: list[str] = []

    def __enter__(self):
        self.original = self.conn.execute

        def spy(query, *args, **kwargs):
            self.statements.append(str(query))
            return self.original(query, *args, **kwargs)

        self.conn.execute = spy  # type: ignore[method-assign]
        return self.statements

    def __exit__(self, *exc):
        self.conn.execute = self.original  # type: ignore[method-assign]


# ── the analysis of the newest run ──────────────────────────────────────────────────────────────


def test_the_view_carries_the_analysis_of_the_newest_run(db):
    _entry(db, ENTRY_A, "Quét cổng nội bộ", "confirmed_incident")
    _entry(db, ENTRY_B, "Đăng nhập lặp", "closed_fp")
    alert_id = _queued(db, suggestion_visible=True)
    lookup = _lookup(
        db,
        alert_id,
        matches=[_match(ENTRY_A, 0.87)],
        ranked=[{"entry_id": ENTRY_A, "score": 0.87}, {"entry_id": ENTRY_B, "score": 0.47}],
        history=HISTORY,
    )
    gate = _gate(rag_rule={"threshold": 80, "best_pct": 87, "applied": False, "changed": False})
    _insert_run(db, alert_id, gate_result=gate, lookup_id=lookup)

    view = get_alert_view(db, alert_id)
    built = view["analysis"]

    assert built["summary"] == TEXTS["summary"]
    assert built["reading_attack"] == TEXTS["reading_attack"]
    assert built["next_checks"] == TEXTS["next_checks"][:3]
    assert [r["claim"] for r in built["reasons"]] == [r["claim"] for r in REASONS]
    assert built["facts"][0] == {
        "field": "severity",
        "system": "high",
        "model": "high",
        "match": True,
    }
    assert built["rag"] == {
        "state": "matched",
        "failure": None,
        "best_pct": 87,
        "floor_pct": 50,
        "threshold_pct": 80,
        "scored": 2,
        "candidates": [
            {"pct": 87, "title": "Quét cổng nội bộ", "conclusion": "confirmed_incident"},
            {"pct": 47, "title": "Đăng nhập lặp", "conclusion": "closed_fp"},
        ],
    }
    assert built["history"] == {
        "key": "rule_host",
        "total": 15,
        "by_conclusion": HISTORY["by_conclusion"],
        "last_seen": "2026-11-14T10:00:00+00:00",
    }
    assert built["playbook"] == {
        "name": "brute_force_v1",
        "rule_id": "bf-2",
        "rule_action": "true_positive",
    }
    assert built["tech"]["input_tokens"] == 1200 and built["tech"]["output_tokens"] == 340
    assert built["tech"]["latency_ms"] == 2100 and built["tech"]["cost_usd"] == 0.01234
    assert built["tech"]["analysed_at"] == view["suggestion"]["created_at"]
    assert built["tech"]["mitre_ids"] == view["mitre_ids"]
    assert built["tech"]["correlated_at_analysis"] == 2
    # the pair the page already had agrees with the panel for the same run
    assert view["rag"]["best_pct"] == built["rag"]["best_pct"] == 87
    assert [row["id"] for row in built["checks"]] == ["1", "2", "3", "3r", "4", "5", "6"]


def test_an_alert_with_no_run_has_no_analysis_and_no_statement_for_one(db):
    alert_id = _queued(db, suggestion_visible=True)
    with _Statements(db) as statements:
        view = get_alert_view(db, alert_id)
    assert view["analysis"] is None
    assert not [s for s in statements if "knowledge_entries" in s]
    assert (
        len([s for s in statements if "FROM llm_runs" in s]) == 2
    )  # the run and the stop reason, as before


def test_a_run_whose_result_is_null_has_no_analysis_and_an_older_run_does_not_stand_in(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, offset_s=0)
    _insert_run(db, alert_id, result="NULL", stopped_by="schema", offset_s=5)

    view = get_alert_view(db, alert_id)

    assert view["suggestion"] is None and view["analysis"] is None


def test_the_analysis_is_the_newest_runs_not_an_older_ones(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result={**RAW, "summary": "OLD"}, offset_s=0)
    _insert_run(db, alert_id, result={**RAW, "summary": "NEW"}, offset_s=5)
    assert get_alert_view(db, alert_id)["analysis"]["summary"] == "NEW"


def test_a_verifier_row_never_stands_in_for_the_proposer(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result={**RAW, "summary": "PROPOSER"}, offset_s=0)
    _insert_run(
        db,
        alert_id,
        result={"agree": True},
        role="verifier",
        offset_s=9,
        model_id=VERIFIER_MODEL_ID,
    )
    assert get_alert_view(db, alert_id)["analysis"]["summary"] == "PROPOSER"


def test_a_duplicates_view_carries_its_heads_analysis(db):
    head = _queued(db, suggestion_visible=True)
    _insert_run(db, head, result={**RAW, "summary": "HEAD"})
    duplicate = _duplicate(db, head)
    view = get_alert_view(db, duplicate)
    assert view["requested_alert_id"] == duplicate and view["analysis"]["summary"] == "HEAD"


# ── the statements ──────────────────────────────────────────────────────────────────────────────


def test_a_run_with_no_lookup_costs_no_statement_beyond_the_two_it_always_ran(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id)
    with _Statements(db) as statements:
        get_alert_view(db, alert_id)
    assert len([s for s in statements if "FROM llm_runs" in s]) == 2
    assert not [s for s in statements if "knowledge_entries" in s]
    assert not [s for s in statements if "FROM rag_results" in s and "FROM llm_runs" not in s]


def test_the_candidates_cost_one_read_statement_that_touches_only_the_entries(db):
    _entry(db, ENTRY_A, "A", "closed_fp")
    alert_id = _queued(db, suggestion_visible=True)
    lookup = _lookup(
        db,
        alert_id,
        matches=[],
        ranked=[{"entry_id": ENTRY_A, "score": 0.4}, {"entry_id": ENTRY_B, "score": 0.3}],
    )
    _insert_run(db, alert_id, lookup_id=lookup)
    with _Statements(db) as statements:
        view = get_alert_view(db, alert_id)
    reads = [s for s in statements if "knowledge_entries" in s]
    assert len(reads) == 1 and reads[0].lstrip().upper().startswith("SELECT")
    assert len([s for s in statements if "FROM llm_runs" in s]) == 2
    assert view["analysis"]["rag"]["candidates"] == [
        {"pct": 40, "title": "A", "conclusion": "closed_fp"},
        {"pct": 30, "title": None, "conclusion": None},  # an entry that is gone
    ]


def test_no_statement_the_view_runs_selects_a_model_column(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id)
    with _Statements(db) as statements:
        get_alert_view(db, alert_id)
        list_queue(db)
    assert statements
    for statement in statements:
        assert "model_id" not in statement and "model" not in statement.lower(), statement[:80]


def test_the_view_only_reads(db):
    """Nothing the analysis reads is written back: no statement that changes data."""
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id)
    with _Statements(db) as statements:
        get_alert_view(db, alert_id)
    for statement in statements:
        assert statement.lstrip().split()[0].upper() in {"SELECT", "WITH"}, statement[:60]


# ── G5: the model's name ────────────────────────────────────────────────────────────────────────


def _leaks(value: Any) -> list[str]:
    return [
        text
        for text in _strings(value)
        if MODEL_ID in text.lower() or VERIFIER_MODEL_ID in text.lower()
    ]


def test_the_model_id_is_in_the_database_and_nowhere_in_what_the_tier_1_view_and_queue_serve(db):
    """The run's `model_id` is a distinctive string. Everything the alert view serves (the existing keys and `analysis`,
    on the visible arm and on the decided blind arm) and every queue row and the digest's reader are walked, every key
    and every value at every depth."""
    _seed_user(db)
    _entry(db, ENTRY_A, "T", "closed_fp")
    visible = _queued(db, suggestion_visible=True)
    lookup = _lookup(
        db,
        visible,
        matches=[_match(ENTRY_A, 0.9)],
        ranked=[{"entry_id": ENTRY_A, "score": 0.9}],
        history=HISTORY,
    )
    _insert_run(db, visible, lookup_id=lookup, offset_s=0)
    _insert_run(
        db,
        visible,
        result={"agree": True, "structured_only_verdict": "true_positive"},
        role="verifier",
        model_id=VERIFIER_MODEL_ID,
        offset_s=1,
    )
    blind = _queued(db, suggestion_visible=False)
    _insert_run(db, blind, offset_s=0)
    acknowledge(db, blind, USER_ID)
    decide(
        db,
        blind,
        USER_ID,
        decision="closed_benign",
        reason="benign",
        seen_occurrence_count=1,
        llm_suggestion=None,
        llm_confidence=None,
    )

    stored = db.execute(
        "SELECT count(*) FROM llm_runs WHERE model_id IN (%s, %s)", (MODEL_ID, VERIFIER_MODEL_ID)
    ).fetchone()[0]
    assert stored >= 3  # the control: the strings really are in the database

    views = [get_alert_view(db, visible), get_alert_view(db, blind)]
    assert (
        views[0]["analysis"] is not None and views[1]["analysis"] is not None
    )  # the walk is not of an empty view
    for view in views:
        assert _leaks(view) == []
        assert "model_id" not in set(_walk_keys(view))
    assert _leaks(get_alert_view(db, visible, mode="labeling")) == []
    for row in list_queue(db).rows:
        assert _leaks(row) == []
    assert (
        _leaks({k: v.to_dict() for k, v in latest_suggestions(db, [visible, blind]).items()}) == []
    )
    assert _leaks(queue.latest_suggestion_analysis(db, visible, mitre_ids=[])[4]) == []


def _key_paths(value: Any, prefix: str = ""):
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{prefix}.{key}" if prefix else str(key)
            yield here
            yield from _key_paths(item, here)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            yield from _key_paths(item, f"{prefix}[{index}]")


def test_the_only_key_of_the_view_with_model_in_its_name_is_the_facts_declared_value(db):
    """`analysis.facts[].model` is the value the MODEL declared for a field (spec section 5: `{field, system, model,
    match}`), not a model's name: it holds `high`, `malicious`, a count. No other key of the view says "model".
    """
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id)
    paths = [
        p
        for p in _key_paths(get_alert_view(db, alert_id))
        if "model" in p.lower().rsplit(".", 1)[-1]
    ]
    assert paths and all(re.fullmatch(r"analysis\.facts\[\d\]\.model", p) for p in paths), paths


# ── the blind arm and the labelling page ────────────────────────────────────────────────────────

SENTINEL_TEXTS = {
    "summary": "ZQX-SUMMARY-WORDS",
    "reading_attack": "ZQX-ATTACK-WORDS",
    "reading_benign": "ZQX-BENIGN-WORDS",
    "would_change": "ZQX-WOULD-CHANGE-WORDS",
    "next_checks": ["ZQX-NEXT-CHECK-WORDS"],
}


def _blind_run(db, alert_id):
    lookup = _lookup(
        db,
        alert_id,
        matches=[_match(ENTRY_A, 0.9)],
        ranked=[{"entry_id": ENTRY_A, "score": 0.9}],
        history=HISTORY,
    )
    return _insert_run(db, alert_id, result={**RAW, **SENTINEL_TEXTS}, lookup_id=lookup)


def _no_words(view):
    text = json.dumps(view, default=str)
    for words in ("ZQX-", "claim one", "quote one", '"name": "brute_force_v1"', "Quét cổng"):
        assert words not in text, words


def test_a_blind_undecided_view_has_no_analysis_and_none_of_its_words(db):
    _entry(db, ENTRY_A, "Quét cổng nội bộ", "closed_fp")
    alert_id = _queued(db, suggestion_visible=False)
    _blind_run(db, alert_id)

    view = get_alert_view(db, alert_id)

    assert "analysis" not in view and "suggestion" not in view
    assert "analysis" not in set(_walk_keys(view))
    _no_words(view)
    control = get_alert_view(db, _visible_twin(db))
    assert control["analysis"] is not None  # the control: the same run on the visible arm has it


def _visible_twin(db) -> str:
    """The same run on the visible arm (the entry ENTRY_A is already there)."""
    alert_id = _queued(db, suggestion_visible=True)
    _blind_run(db, alert_id)
    return alert_id


def test_a_decision_brings_the_analysis_back_on_the_blind_arm(db):
    _seed_user(db)
    _entry(db, ENTRY_A, "Quét cổng nội bộ", "closed_fp")
    alert_id = _queued(db, suggestion_visible=False, risk_score=30)
    _blind_run(db, alert_id)
    acknowledge(db, alert_id, USER_ID)
    assert "analysis" not in get_alert_view(db, alert_id)  # still undecided, still blind

    decide(
        db,
        alert_id,
        USER_ID,
        decision="closed_benign",
        reason="benign",
        seen_occurrence_count=1,
        llm_suggestion=None,
        llm_confidence=None,
    )
    view = get_alert_view(db, alert_id)

    assert view["status"] == "closed_benign"
    assert view["analysis"]["summary"] == "ZQX-SUMMARY-WORDS"


@pytest.mark.parametrize("suggestion_visible", [True, False], ids=["visible", "blind"])
def test_the_labelling_page_never_has_it_at_any_depth(db, suggestion_visible):
    _entry(db, ENTRY_A, "Quét cổng nội bộ", "closed_fp")
    alert_id = _queued(db, suggestion_visible=suggestion_visible)
    _blind_run(db, alert_id)

    labelling = get_alert_view(db, alert_id, mode="labeling")

    keys = set(_walk_keys(labelling))
    assert "analysis" not in keys and not keys & LABELING_DENYLIST
    _no_words(labelling)
    analyst = get_alert_view(db, alert_id)  # the control
    assert ("analysis" in analyst) is suggestion_visible


def test_the_queue_rows_never_carry_analysis(db):
    for visible in (True, False):
        alert_id = _queued(db, suggestion_visible=visible)
        _insert_run(db, alert_id)
    for row in list_queue(db).rows:
        assert "analysis" not in row


def test_analysis_is_in_both_hidden_sets():
    assert "analysis" in ANALYST_HIDE and "analysis" in LABELING_DENYLIST


# ── DEC-219: a run the RAG default applied to ───────────────────────────────────────────────────

APPLIED_STEPS = {**STEPS, "3r": "changed", "4": "ok", "6": "disagree"}


def _applied_gate(*, changed: bool) -> dict:
    return _gate(
        proposed_verdict="true_positive" if changed else "false_positive",
        final_verdict="false_positive",
        flagged_by=["step6"] if changed else [],
        steps={
            **APPLIED_STEPS,
            "3r": "changed" if changed else "applied",
            "6": "disagree" if changed else "agree",
        },
        rag_rule={"threshold": 80, "best_pct": 62, "applied": True, "changed": changed},
        verifier_verdict="needs_review" if changed else "false_positive",
    )


@pytest.mark.parametrize("changed", [True, False], ids=["changed", "applied-unchanged"])
def test_for_a_run_the_rule_applied_to_the_model_own_answer_is_not_served(db, changed):
    _entry(db, ENTRY_A, "Quét cổng nội bộ", "confirmed_incident")
    alert_id = _queued(db, suggestion_visible=True)
    lookup = _lookup(
        db,
        alert_id,
        matches=[_match(ENTRY_A, 0.62)],
        ranked=[{"entry_id": ENTRY_A, "score": 0.62}],
        history=HISTORY,
    )
    _insert_run(
        db,
        alert_id,
        result={**RAW, "suggested_action": "false_positive", "confidence": "high"},
        gate_result=_applied_gate(changed=changed),
        lookup_id=lookup,
    )
    before = db.execute(
        "SELECT result, gate_result FROM llm_runs WHERE subject_id = %s", (alert_id,)
    ).fetchall()

    view = get_alert_view(db, alert_id)
    built = view["analysis"]

    assert (
        built["reading_attack"] is None
        and built["reading_benign"] is None
        and built["would_change"] is None
    )
    assert all(row["model"] is None and row["match"] is None for row in built["facts"])
    assert all(row["system"] is not None for row in built["facts"])
    assert [row["id"] for row in built["checks"]] == ["1", "2", "3", "3r", "4", "5"]
    assert built["check_totals"] == {"passed": 6, "applicable": 6, "warnings": 0}
    assert built["summary"] == TEXTS["summary"] and built["next_checks"] == TEXTS["next_checks"][:3]
    assert len(built["reasons"]) == 3
    assert built["rag"]["state"] == "matched" and built["history"]["total"] == 15
    assert built["tech"]["input_tokens"] == 1200
    # the existing keys of the view keep withholding what they withheld (DEC-219): the analysis adds nothing to it
    assert (
        view["suggestion"]["confidence"] is None
        and view["suggestion"]["gate"]["verifier_verdict"] is None
    )
    # nothing stored was changed
    assert (
        db.execute(
            "SELECT result, gate_result FROM llm_runs WHERE subject_id = %s", (alert_id,)
        ).fetchall()
        == before
    )


def test_a_changed_run_and_an_unchanged_one_are_served_the_same_analysis(db):
    """Nothing served may give away what the model answered: two stored runs that differ in everything the model's
    answer touches give one analysis (the whole object, through the real statement)."""
    _entry(db, ENTRY_A, "Quét cổng nội bộ", "confirmed_incident")
    served = []
    for changed in (True, False):
        alert_id = _queued(db, suggestion_visible=True)
        lookup = _lookup(
            db,
            alert_id,
            matches=[_match(ENTRY_A, 0.62)],
            ranked=[{"entry_id": ENTRY_A, "score": 0.62}],
            history=HISTORY,
        )
        raw = {
            **RAW,
            "suggested_action": "true_positive" if changed else "false_positive",
            "confidence": "high" if changed else "low",
            "reading_attack": "attack words" if changed else "other words",
            "structured_basis": BASIS if changed else {**BASIS, "severity": "low"},
        }
        _insert_run(
            db,
            alert_id,
            result={**raw, "suggested_action": "false_positive"},
            gate_result=_applied_gate(changed=changed) | {"proposer_raw": raw},
            lookup_id=lookup,
        )
        view = get_alert_view(db, alert_id)["analysis"]
        view["tech"] = {**view["tech"], "analysed_at": None}
        served.append(view)
    assert served[0] == served[1]


# ── stored documents of any age and any shape ───────────────────────────────────────────────────


def test_a_version_1_gate_and_a_version_3_result_still_give_an_analysis(db):
    alert_id = _queued(db, suggestion_visible=True)
    v3 = {k: v for k, v in RAW.items() if k not in TEXTS}
    v1 = _gate(
        version=1,
        proposed_verdict="false_positive",
        final_verdict="needs_review",
        forced=True,
        forced_by=["step3"],
        steps={
            "1": "ok",
            "2": "ok",
            "3": "dropped:3",
            "4": "n/a",
            "5": "findings:0",
            "6": "agree",
            "7": "ok",
        },
        dropped_reasons=[{"index": i, "why": "not_substring"} for i in range(3)],
        proposer_raw=v3,
    )
    for key in ("flagged_by", "rag_rule", "step1_errors"):
        del v1[key]
    _insert_run(
        db,
        alert_id,
        result={**v3, "suggested_action": "needs_review", "reasons": []},
        gate_result=v1,
    )

    built = get_alert_view(db, alert_id)["analysis"]

    assert built["summary"] is None and built["next_checks"] == []
    assert [(r["verified"], r["why"]) for r in built["reasons"]] == [(False, "not_substring")] * 3
    rows = {row["id"]: row for row in built["checks"]}
    assert rows["3"] == {"id": "3", "outcome": "warn", "detail": "no_verified_quote"}
    assert rows["4"]["detail"] == "not_run" and rows["3r"]["detail"] == "rag_rule_off"


@pytest.mark.parametrize(
    "gate",
    [
        [],
        "junk",
        7,
        {"steps": "x", "facts": [1], "proposer_raw": 5, "dropped_reasons": "no", "rag_rule": []},
    ],
)
def test_a_garbled_gate_document_gives_less_not_an_error(db, gate):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, gate_result=gate)

    view = get_alert_view(db, alert_id)

    assert view["analysis"] is not None
    assert view["analysis"]["check_totals"] == {"passed": 0, "applicable": 0, "warnings": 0}
    assert (
        view["analysis"]["summary"] == TEXTS["summary"]
    )  # the result is intact: its texts are served


@pytest.mark.parametrize(
    "history",
    [
        None,
        [],
        "x",
        {},
        {"total": "many"},
        {"total": 3, "by_conclusion": [1], "last_seen": 5, "key_name": ["x"]},
    ],
)
def test_a_garbled_stored_history_gives_none_or_less(db, history):
    alert_id = _queued(db, suggestion_visible=True)
    lookup = _lookup(db, alert_id, matches=[], ranked=[], history=history)
    _insert_run(db, alert_id, lookup_id=lookup)
    got = get_alert_view(db, alert_id)["analysis"]["history"]
    assert got is None or set(got) == {"key", "total", "by_conclusion", "last_seen"}


@pytest.mark.parametrize(
    "ranked", [[{"entry_id": 5, "score": 0.4}, "x", None, {"score": 0.3}], {"a": 1}, "junk"]
)
def test_a_garbled_stored_ranking_gives_less_not_an_error(db, ranked):
    alert_id = _queued(db, suggestion_visible=True)
    lookup = _lookup(db, alert_id, matches=[], ranked=ranked)
    _insert_run(db, alert_id, lookup_id=lookup)
    assert get_alert_view(db, alert_id)["analysis"]["rag"]["state"] in (
        "below_floor",
        "no_candidate",
    )


def test_the_model_texts_of_a_result_that_are_not_text_are_none(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(
        db, alert_id, result={**RAW, "summary": 5, "reading_attack": ["x"], "next_checks": "one"}
    )
    built = get_alert_view(db, alert_id)["analysis"]
    assert (
        built["summary"] is None and built["reading_attack"] is None and built["next_checks"] == []
    )


def test_a_run_with_no_cost_columns_gives_none_figures(db):
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(
        db,
        alert_id,
        input_tokens=None,
        output_tokens=None,
        latency_ms=None,
        cost_usd=None,
        model_id=None,
    )
    tech = get_alert_view(db, alert_id)["analysis"]["tech"]
    assert (tech["input_tokens"], tech["output_tokens"], tech["latency_ms"], tech["cost_usd"]) == (
        None,
    ) * 4


# ── what the existing keys keep ─────────────────────────────────────────────────────────────────


def test_the_existing_keys_of_the_view_are_what_they_were(db):
    """`analysis` is one more key: every key the view had keeps its value (the suggestion, the held reasons, the rag
    pair), read from the same row."""
    alert_id = _queued(db, suggestion_visible=True)
    run_id = _insert_run(db, alert_id)
    view = get_alert_view(db, alert_id)
    assert view["suggestion"]["run_id"] == run_id
    assert view["suggestion"]["suggested_action"] == "true_positive"
    assert view["proposed_action"] == "true_positive" and view["held_by"] == []
    assert view["rag"] == {
        "best_pct": None,
        "not_applied": None,
        "below_floor_pct": None,
        "floor_pct": None,
    }
    assert {"analysis", "suggestion", "rag", "held_by", "proposed_action", "llm_stopped_by"} <= set(
        view
    )


# ── rag.entries.entry_cards ─────────────────────────────────────────────────────────────────────


def test_entry_cards_reads_title_and_conclusion_of_the_entries_that_exist(db):
    _entry(db, ENTRY_A, "Tiêu đề A", "confirmed_incident")
    _entry(
        db, ENTRY_B, "Tiêu đề B", "closed_benign", status="retired"
    )  # a retired entry is still an entry
    got = entries.entry_cards(db, [ENTRY_A, ENTRY_B, ENTRY_C])
    assert got == {
        ENTRY_A: ("Tiêu đề A", "confirmed_incident"),
        ENTRY_B: ("Tiêu đề B", "closed_benign"),
    }


def test_entry_cards_keys_are_the_ids_as_given(db):
    _entry(db, ENTRY_A, "A", "closed_fp")
    shouted = ENTRY_A.upper()
    assert entries.entry_cards(db, [shouted]) == {shouted: ("A", "closed_fp")}


def test_entry_cards_with_nothing_to_read_runs_no_statement(db):
    with _Statements(db) as statements:
        assert entries.entry_cards(db, []) == {}
        assert entries.entry_cards(db, ["not-a-uuid", "", "123"]) == {}
    assert statements == []


def test_entry_cards_skips_what_is_not_a_uuid_and_keeps_the_transaction_alive(db):
    _entry(db, ENTRY_A, "A", "closed_fp")
    assert entries.entry_cards(db, ["entry-1", ENTRY_A]) == {ENTRY_A: ("A", "closed_fp")}
    assert db.execute("SELECT 1").fetchone() == (1,)  # not poisoned


def test_an_entry_with_no_heading_has_no_title(db):
    add_entry(db, entry_id=ENTRY_C, conclusion="closed_fp", content="no heading here\n")
    assert entries.entry_cards(db, [ENTRY_C]) == {ENTRY_C: (None, "closed_fp")}


def test_entry_cards_is_one_read_only_statement(db):
    _entry(db, ENTRY_A, "A", "closed_fp")
    with _Statements(db) as statements:
        entries.entry_cards(db, [ENTRY_A, ENTRY_B, ENTRY_C, ENTRY_A])
    assert len(statements) == 1 and statements[0].lstrip().upper().startswith("SELECT")
