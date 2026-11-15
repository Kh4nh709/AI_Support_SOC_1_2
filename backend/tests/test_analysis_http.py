"""DEC-221, AP-T2 follow-up F: the REAL FastAPI route `GET /api/tier1/alerts/{id}` serves `analysis` over HTTP.

The view is a dict with datetimes (`tech.analysed_at`, the suggestion's `created_at`) and the figures of a `numeric`
column; the route serialises it with FastAPI's encoder. These tests go through `TestClient` and the route's own
dependencies (`test_tier1_api.py`'s fixture: the `db` fixture's connection and a role override), and read the
response as JSON text, as the browser does:

* a normal run: the response is valid JSON, `analysed_at` is an ISO 8601 string that parses back to the stored time,
  the cost is a JSON number, the checks, facts and highlights are there, and the model's id is nowhere in the body;
* a run the RAG default applied to (DEC-219): the same, with the withheld parts `null` and no verifier row;
* the blind arm's response has no `analysis` key and none of its words, for every role that may read an alert;
* the queue's response has no `analysis`.
"""

# ruff: noqa: F811
from __future__ import annotations

import datetime as dt
import json

import pytest

from tests.test_analysis_db import (
    ENTRY_A,
    HISTORY,
    MODEL_ID,
    VERIFIER_MODEL_ID,
    _applied_gate,
    _entry,
    _insert_run,
    _lookup,
    _match,
    _verifier_row,
)
from tests.test_analysis_view import RAW, TEXTS
from tests.test_tier1_api import ADMIN_ID, TIER1_ID, TIER2_ID, _queued, client  # noqa: F401

pytestmark = pytest.mark.db

SENTINEL = {
    "summary": "ZQX-HTTP-SUMMARY",
    "reading_attack": "ZQX-HTTP-ATTACK",
    "reading_benign": "ZQX-HTTP-BENIGN",
    "would_change": "ZQX-HTTP-WOULD-CHANGE",
    "next_checks": ["ZQX-HTTP-NEXT"],
}


def _normal_alert(db, *, visible: bool = True, result=None) -> str:
    _entry(db, ENTRY_A, "Quét cổng nội bộ", "confirmed_incident")
    alert_id = _queued(db, suggestion_visible=visible)
    lookup = _lookup(
        db,
        alert_id,
        matches=[_match(ENTRY_A, 0.87)],
        ranked=[{"entry_id": ENTRY_A, "score": 0.87}],
        history=HISTORY,
    )
    proposer = _insert_run(db, alert_id, lookup_id=lookup, result=result)
    _verifier_row(db, alert_id, proposer)
    return alert_id


def _get(client, alert_id, role="tier1", user_id=TIER1_ID):
    client.as_role(role, user_id)
    response = client.http.get(f"/api/tier1/alerts/{alert_id}")
    assert response.status_code == 200, response.text
    return response


def test_a_normal_run_is_served_as_valid_json_with_datetimes_and_numbers(db, client):
    alert_id = _normal_alert(db)

    response = _get(client, alert_id)
    body = json.loads(response.text)  # valid JSON text, not only a parsed object
    built = body["analysis"]

    assert (
        built["summary"] == TEXTS["summary"] and built["reading_attack"] == TEXTS["reading_attack"]
    )
    tech = built["tech"]
    analysed = dt.datetime.fromisoformat(tech["analysed_at"])  # an ISO 8601 string
    assert analysed.tzinfo is not None
    assert analysed.isoformat() == body["suggestion"][
        "created_at"
    ] or analysed == dt.datetime.fromisoformat(body["suggestion"]["created_at"])
    assert isinstance(tech["cost_usd"], float) and tech["cost_usd"] == pytest.approx(0.01444)
    assert (tech["input_tokens"], tech["output_tokens"], tech["latency_ms"]) == (1500, 420, 3000)
    assert [row["id"] for row in built["checks"]] == ["1", "2", "3", "3r", "4", "5", "6"]
    assert (
        built["check_totals"]["applicable"]
        == built["check_totals"]["passed"] + built["check_totals"]["warnings"]
    )
    assert built["facts"][0] == {
        "field": "severity",
        "system": "high",
        "model": "high",
        "match": True,
    }
    assert (
        built["rag"]["state"] == "matched"
        and built["rag"]["candidates"][0]["title"] == "Quét cổng nội bộ"
    )
    assert built["history"]["total"] == 15 and built["playbook"]["name"] == "brute_force_v1"
    assert {row["direction"] for row in built["highlights"]} <= {"up", "down", "warn"}
    assert (
        MODEL_ID not in response.text and VERIFIER_MODEL_ID not in response.text
    )  # goal G5, over the wire
    assert '"model_id"' not in response.text


def test_the_response_is_the_same_object_the_view_builds(db, client):
    """Nothing is lost or invented between the view and the wire except what JSON cannot say (a datetime)."""
    from app.tier1.queue import get_alert_view

    alert_id = _normal_alert(db)
    wire = json.loads(_get(client, alert_id).text)["analysis"]
    built = get_alert_view(db, alert_id)["analysis"]
    built["tech"] = {**built["tech"], "analysed_at": built["tech"]["analysed_at"].isoformat()}
    assert wire["tech"]["analysed_at"] == built["tech"]["analysed_at"] or dt.datetime.fromisoformat(
        wire["tech"]["analysed_at"]
    ) == dt.datetime.fromisoformat(built["tech"]["analysed_at"])
    wire["tech"].pop("analysed_at"), built["tech"].pop("analysed_at")
    assert wire == json.loads(json.dumps(built))


def test_a_run_the_rag_default_applied_to_is_served_without_the_withheld_parts(db, client):
    _entry(db, ENTRY_A, "Quét cổng nội bộ", "confirmed_incident")
    alert_id = _queued(db, suggestion_visible=True)
    lookup = _lookup(
        db,
        alert_id,
        matches=[_match(ENTRY_A, 0.62)],
        ranked=[{"entry_id": ENTRY_A, "score": 0.62}],
        history=HISTORY,
    )
    proposer = _insert_run(
        db,
        alert_id,
        result={**RAW, "suggested_action": "false_positive"},
        gate_result=_applied_gate(changed=True),
        lookup_id=lookup,
    )
    _verifier_row(db, alert_id, proposer)

    response = _get(client, alert_id)
    body = json.loads(response.text)
    built = body["analysis"]

    assert (
        built["reading_attack"] is None
        and built["reading_benign"] is None
        and built["would_change"] is None
    )
    assert all(row["model"] is None and row["match"] is None for row in built["facts"])
    assert [row["id"] for row in built["checks"]] == ["1", "2", "3", "3r", "4", "5"]
    assert built["summary"] == TEXTS["summary"] and built["rag"]["threshold_pct"] == 80
    assert dt.datetime.fromisoformat(built["tech"]["analysed_at"])
    assert isinstance(built["tech"]["cost_usd"], float)
    # the existing keys keep withholding what DEC-219 withholds
    assert (
        body["suggestion"]["confidence"] is None
        and body["suggestion"]["gate"]["verifier_verdict"] is None
    )
    assert body["suggestion"]["gate"]["warnings"] == []
    assert MODEL_ID not in response.text and VERIFIER_MODEL_ID not in response.text


@pytest.mark.parametrize(
    ("role", "user_id"), [("tier1", TIER1_ID), ("tier2", TIER2_ID), ("admin", ADMIN_ID)]
)
def test_the_blind_arms_response_has_no_analysis(db, client, role, user_id):
    alert_id = _normal_alert(db, visible=False, result={**RAW, **SENTINEL})

    response = _get(client, alert_id, role, user_id)
    body = json.loads(response.text)

    assert "analysis" not in body and "suggestion" not in body
    assert "ZQX-HTTP" not in response.text and "Quét cổng nội bộ" not in response.text
    assert "brute_force_v1" not in response.text.replace("ssh_brute_force_v1", "")
    # the control: the same run on the visible arm is served the analysis
    visible = _get(client, _normal_alert_twin(db), role, user_id)
    assert json.loads(visible.text)["analysis"]["summary"] == SENTINEL["summary"]


def _normal_alert_twin(db) -> str:
    alert_id = _queued(db, suggestion_visible=True)
    _insert_run(db, alert_id, result={**RAW, **SENTINEL})
    return alert_id


def test_the_queue_response_never_carries_analysis(db, client):
    _normal_alert(db)
    client.as_role("tier1", TIER1_ID)
    response = client.http.get("/api/tier1/queue")
    assert response.status_code == 200, response.text
    assert "analysis" not in response.text
    assert MODEL_ID not in response.text
