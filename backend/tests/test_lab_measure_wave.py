"""P14 final fix wave - the lab measurement tool (`eval/lab_measure.py`): C1 and section B of the brief.

* **C1 (items 3, 4, 5).** ① gets an `as_of` like ②'s: the `created_at` of the alert's first ① proposer run, else
  `received_at + RAG_TRIAGE_DELAY_S`. Each row records which of the two was used, the report counts both, and
  the burst count, the correlation section and the RAG-on arm of ① are those of that instant. The caveat and the
  module docstring say what is still not bounded (the neighbours' CURRENT status, the decision history) and that
  the count of subjects it can have touched is an estimate.
* **B (items 6-11).** `evaluation_error` in the Markdown, and an error row's failed lookup under its kind; `null`
  (not `[]`/`false`/`0`) for what the leak pass did not compute; "during" the leak pass; a second paired line
  over the subjects whose RAG-on prompt carried a match; ①'s budget cut that drops the entries counts no match;
  the Voyage message when the key is missing.

The scratch lab is the module `test_lab_measure.py` builds (two runs, a knowledge base, eight alerts, four cases, a
fake model); a second, small one holds a burst whose later alerts arrive after the first one was looked at.
Nothing here calls a model or Voyage; no test prints a DSN.
"""

from __future__ import annotations

import dataclasses
import re
from datetime import timedelta
from types import SimpleNamespace

import pytest
from app.lab import labels as lab_labels
from app.lab import runs as lab_runs
from app.llm.builder import LEARNED_ENTRIES_DROPPED_WARNING
from app.rag.subject import Subject

from tests.scratch_db import insert_user, scratch_database
from tests.test_lab_measure import (
    FP,
    TP,
    Lab,
    LabFake,
    _connect,
    _entry,
    _entry_match,
    _history,
    _lab_fake,
    _put_first_look,
    _put_lookup,
    _report,
    _row,
    _run_tool,
    _stray_alert,
    at,
    lm,
    seed_lab,
)
from tests.test_triage_job import _FP_ALERT, _seed_alert

# ═══════════════════════════════════════════════════════════════════════════════════════════
# the scratch labs
# ═══════════════════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def scratch_dsn():
    with scratch_database("labwave") as dsn:
        yield dsn


@pytest.fixture(scope="module")
def lab(scratch_dsn) -> Lab:
    return seed_lab(scratch_dsn)


@pytest.fixture(scope="module")
def burst_dsn():
    with scratch_database("labburst") as dsn:
        yield dsn


def _burst_id(n: int) -> str:
    return f"17901{n:05d}.{300000 + n}"


def seed_burst_lab(dsn) -> Lab:
    """One test run (6 h to 10 h) with a burst of three alerts of one key (rule, source, destination, agent):

        B1 received 6.50 h  TP  first looked at 6.55 h (before B2 existed), a lookup stored at 6.56 h (after it)
        B2 received 6.60 h  FP  no ① run: its `as_of` is received + RAG_TRIAGE_DELAY_S; a lookup stored at 6.605 h
        B3 received 9.00 h  FP  no ① run either; B1 was looked at again at 9.5 h (not its first look)

    At its first look B1 saw a burst of 1; read now it is 3. B2 saw 2 (B1 and itself)."""
    key = {
        "rule_id": "92001",
        "agent_name": "burst-agent",
        "alert_user": "burst-user",
        "srcip": "10.98.0.1",
        "first_seen_at": at(6.5),
        "last_seen_at": at(6.5),
        **_FP_ALERT,
    }
    with _connect(dsn) as conn:
        admin = insert_user(conn, "admin")
        lab_runs.create_run(
            conn, name="burst-test", purpose="test", starts_at=at(6), ends_at=at(10), admin_id=admin
        )
        ids = {}
        for name, n, received in (("b1", 1, at(6.5)), ("b2", 2, at(6.6)), ("b3", 3, at(9))):
            ids[name] = _seed_alert(
                conn,
                alert_id=_burst_id(n),
                received_at=received,
                description=f"BURST-{name.upper()}",
                **key,
            )
        _put_first_look(conn, ids["b1"], at(6.55))
        _put_first_look(conn, ids["b1"], at(9.5))
        _put_lookup(conn, "alert", ids["b1"], at(6.56))
        _put_lookup(conn, "alert", ids["b2"], at(6.605), total=1)
        lab_labels.set_label(conn, ids["b1"], TP, admin)
        lab_labels.set_label(conn, ids["b2"], FP, admin)
        lab_labels.set_label(conn, ids["b3"], FP, admin)
        conn.commit()
    return Lab(str(dsn), admin, ids, {}, {}, {}, {})


@pytest.fixture(scope="module")
def burst_lab(burst_dsn) -> Lab:
    return seed_burst_lab(burst_dsn)


def _burst_fake(burst: Lab) -> LabFake:
    ids = burst.ids
    return LabFake(
        triage={ids["b1"]: (TP, TP, False), ids["b2"]: (FP, FP, False), ids["b3"]: (FP, FP, False)},
        cases={},
    )


@dataclasses.dataclass
class Burst:
    code: int
    report: dict
    markdown: str
    fake: LabFake


@pytest.fixture(scope="module")
def burst_run(burst_lab, tmp_path_factory) -> Burst:
    tmp = tmp_path_factory.mktemp("burst")
    fake = _burst_fake(burst_lab)
    with pytest.MonkeyPatch.context() as mp:
        code, out = _run_tool(
            burst_lab, tmp, mp, fake, "measure", "--tiers", "1", "--yes", DEDUP_ENABLED="false"
        )
    (md,) = out.glob("lab_measure_*.md")
    return Burst(code, _report(out), md.read_text(encoding="utf-8"), fake)


def _prompts_of(burst_run: Burst, alert_id: str) -> list[str]:
    """The proposer's user messages for one alert, one per arm, in the order they were sent."""
    return [
        user
        for tier, user in burst_run.fake.prompts
        if tier == 1
        and "## Alert" in user
        and re.search(r"alert_id: (\S+)", user).group(1) == alert_id
    ]


# ═══════════════════════════════════════════════════════════════════════════════════════════
# C1 in the tool
# ═══════════════════════════════════════════════════════════════════════════════════════════


@pytest.mark.db
def test_tier_1_as_of_is_the_first_proposer_run_else_received_plus_the_triage_delay(burst_lab):
    with _connect(burst_lab.dsn) as conn:
        runs = lm.load_runs(conn)
        subjects = {s.alert_id: s for s in lm.load_alert_subjects(conn, runs, triage_delay_s=45)}
        later = {s.alert_id: s for s in lm.load_alert_subjects(conn, runs, triage_delay_s=120)}
    b1, b2, b3 = (subjects[burst_lab.ids[name]] for name in ("b1", "b2", "b3"))
    assert (b1.as_of, b1.as_of_source) == (
        at(6.55),
        "first_look",
    )  # the FIRST run, not the one at 9.5 h
    assert (b2.as_of, b2.as_of_source) == (at(6.6) + timedelta(seconds=45), "delay")
    assert (b3.as_of, b3.as_of_source) == (at(9) + timedelta(seconds=45), "delay")
    assert later[burst_lab.ids["b2"]].as_of == at(6.6) + timedelta(seconds=120)
    assert later[burst_lab.ids["b1"]].as_of == at(6.55)  # a first look does not move with the delay


@pytest.mark.db
def test_measure_shows_tier_1_the_burst_as_it_stood_at_its_first_look(burst_lab, burst_run):
    """The scratch-lab test of C1: B1 was looked at before B2 and B3 existed, so it saw a burst of 1 (read now:
    3); B2 saw 2; B3, the last, saw all 3. The later alerts' descriptions are not in an earlier prompt.
    """
    assert burst_run.code == 0
    ids = burst_lab.ids
    expected = {"b1": 1, "b2": 2, "b3": 3}
    for name, count in expected.items():
        prompts = _prompts_of(burst_run, ids[name])
        assert len(prompts) == 2  # both arms
        for prompt in prompts:
            assert f"occurrence_count: {count} " in prompt, name
            assert all(
                f"occurrence_count: {other}" not in prompt for other in (1, 2, 3) if other != count
            )
    b1_prompt = _prompts_of(burst_run, ids["b1"])[0]
    assert "BURST-B2" not in b1_prompt and "BURST-B3" not in b1_prompt
    b2_prompt = _prompts_of(burst_run, ids["b2"])[0]
    assert "BURST-B1" in b2_prompt and "BURST-B3" not in b2_prompt
    b3_prompt = _prompts_of(burst_run, ids["b3"])[0]
    assert "BURST-B1" in b3_prompt and "BURST-B2" in b3_prompt


@pytest.mark.db
def test_the_rag_on_arm_of_tier_1_reads_the_lookup_that_existed_at_the_first_look(
    burst_lab, burst_run
):
    rows = {(r["subject"], r["arm"]): r for r in burst_run.report["rows"]}
    ids = burst_lab.ids
    # B1's lookup was stored at 6.56 h, after its first look at 6.55 h: it was not there
    assert rows[(ids["b1"], "on")]["lookup"]["status"] == "none"
    # B2's was stored at 6.605 h, before 6.6 h + 45 s
    assert rows[(ids["b2"], "on")]["lookup"]["status"] == "ok"


@pytest.mark.db
def test_each_row_records_which_as_of_it_used_and_the_report_counts_both(burst_lab, burst_run):
    ids = burst_lab.ids
    rows = {(r["subject"], r["arm"]): r for r in burst_run.report["rows"]}
    for arm in ("off", "on"):
        assert rows[(ids["b1"], arm)]["as_of_source"] == "first_look"
        assert rows[(ids["b1"], arm)]["as_of"] == at(6.55).isoformat()
        assert rows[(ids["b2"], arm)]["as_of_source"] == "delay"
        assert rows[(ids["b3"], arm)]["as_of_source"] == "delay"
    tier = burst_run.report["tiers"]["1"]
    assert tier["as_of_sources"] == {"first_look": 1, "delay": 2}
    assert tier["triage_delay_s"] == 45
    md = burst_run.markdown
    assert "first ① proposer run" in md and "RAG_TRIAGE_DELAY_S" in md
    assert "1 by the first" in md and "2 by received_at" in md


@pytest.mark.db
def test_the_correlation_count_is_bounded_by_the_first_look_too(lab):
    """`received_before` narrows the neighbours to those received before the instant, as the section is."""
    t1, t2 = lab.ids["t1"], lab.ids["t2"]
    long_ago = at(0)
    with _connect(lab.dsn) as conn:
        # t1's section is read at its first look (6.6 h): t2 (received 7.0 h, escalated 7.4 h) is not in it
        assert lm.alert_correlation_after(conn, t1, long_ago) is True  # today's count, unbounded
        assert lm.alert_correlation_after(conn, t1, long_ago, received_before=at(6.6)) is False
        # t2's section is read at 7.1 h: t1 (received 6.5 h) is in it, escalated at 8.8 h
        assert lm.alert_correlation_after(conn, t2, at(7.1), received_before=at(7.1)) is True


@pytest.mark.db
def test_the_caveat_and_the_header_say_the_inputs_are_bounded_at_the_first_look(burst_run):
    caveat = burst_run.report["caveat"]
    assert caveat == lm.CAVEAT
    assert caveat.count(". ") == 0 and caveat.endswith(".")  # still one sentence
    for needle in (
        "first look",
        "received before",
        "current status",
        "history_same_run",
        "estimate",
        "over-count",
        "under-count",
        "cap",
    ):
        assert needle in caveat, needle
    assert caveat in burst_run.markdown
    # the old claim, that a prompt may show alerts that arrived later, is not made any more
    assert "arrived (that is" not in caveat


def test_the_module_docstring_says_what_is_bounded_and_what_is_not():
    doc = lm.__doc__
    assert "as_of" in doc and "first ① proposer run" in doc
    assert "received before" in doc
    assert "CURRENT status" in doc and "history_same_run" in doc
    assert "estimate" in doc and "OVER-counts" in doc and "UNDER-counts" in doc


# ═══════════════════════════════════════════════════════════════════════════════════════════
# B - the report
# ═══════════════════════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def measured_wave(lab, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("wave-measure")
    with pytest.MonkeyPatch.context() as mp:
        code, out = _run_tool(lab, tmp, mp, _lab_fake(lab), "measure", "--yes")
    (md,) = out.glob("lab_measure_*.md")
    return SimpleNamespace(
        code=code, report=_report(out), markdown=md.read_text(encoding="utf-8"), out=out
    )


@pytest.mark.db
def test_evaluation_error_is_in_the_markdown_with_the_numbers_of_the_json(measured_wave):
    """Item 51. The count of evaluations that raised has its own row in the table; a clean run says 0."""
    for tier_key in ("1", "2"):
        failed = _arm_wave(measured_wave, tier_key)["rag"]["failed_lookups"]
        assert failed["evaluation_error"] == 0
    assert "evaluation error" in measured_wave.markdown


def _arm_wave(measured, tier: str, arm: str = "on") -> dict:
    return measured.report["tiers"][tier]["arms"][arm]


def test_the_markdown_table_has_the_evaluation_error_row_with_its_count():
    on = lm.summarise(
        [
            _row("a", TP, True, arm="on", seen=lm.Seen("ok", None, (("e1", 80),))),
            _row("b", FP, None, outcome="error", arm="on", seen=lm.Seen("error", None, ())),
            _row("c", FP, None, outcome="error", arm="on", seen=lm.Seen("error", None, ())),
        ]
    )
    off = lm.summarise([_row("a", TP, True), _row("b", FP, None), _row("c", FP, None)])
    table = "\n".join(lm._tier_table({"arms": {"off": off, "on": on}}))
    assert re.search(r"\| evaluation error[^|]*\| - \| 2 \|", table), table


def test_an_error_row_whose_newest_lookup_failed_is_counted_under_its_kind():
    """Item 51, second half. The evaluation raised, so nothing is known of its prompt (`error`), but the lookup
    row says why the RAG could not have acted: it stays in `by_kind`, and in `evaluation_error` too.
    """
    rows = [
        _row("a", FP, False, arm="on", seen=lm.Seen("failed", "rate_limit", ())),
        _row("b", FP, None, outcome="error", arm="on", seen=lm.Seen("error", "rate_limit", ())),
        _row("c", FP, None, outcome="error", arm="on", seen=lm.Seen("error", "timeout", ())),
        _row("d", FP, None, outcome="error", arm="on", seen=lm.Seen("error", None, ())),
    ]
    failed = lm.summarise(rows)["rag"]["failed_lookups"]
    assert failed["by_kind"] == {"rate_limit": 2, "timeout": 1}
    assert failed["evaluation_error"] == 3


@pytest.mark.db
def test_an_evaluation_that_raised_keeps_the_failed_lookup_it_had(lab, monkeypatch):
    alert = _stray_alert(lab.dsn)
    with _connect(lab.dsn) as conn:
        _put_lookup(conn, "alert", alert, at(1), status="failed", failure_kind="quota")
        conn.commit()
        assert lm.error_seen(conn, Subject("alert", alert)) == lm.Seen("error", "quota", ())
        other = _stray_alert(lab.dsn)
        assert lm.error_seen(conn, Subject("alert", other)) == lm.Seen("error", None, ())
        # `before`: at 0.5 h the failed row did not exist yet
        assert lm.error_seen(conn, Subject("alert", alert), before=at(0.5)).failure_kind is None
        # a failed row with no stored kind is told as the lookup tells it
        bare = _stray_alert(lab.dsn)
        _put_lookup(conn, "alert", bare, at(1), status="failed")
        conn.commit()
        assert lm.error_seen(conn, Subject("alert", bare)).failure_kind == lm.UNKNOWN_FAILURE_KIND


def test_the_row_json_says_null_for_what_the_leak_pass_did_not_compute():
    """Item 52. `[]`, `false` and `0` would read as 'checked, nothing found'."""
    seen = lm.Seen("ok", None, (("e1", 80),), 2, at(1), ("x",))
    row = _row("a", TP, True, arm="on", seen=seen)
    done = row.to_json()
    assert (done["leaks"], done["history_same_run"], done["unplaceable"]) == ([], False, 0)
    unknown = row.to_json(leaks_computed=False)
    assert (unknown["leaks"], unknown["history_same_run"], unknown["unplaceable"]) == (
        None,
        None,
        None,
    )
    assert unknown["lookup"]["matches"] == 1  # what does not need the pass is still there
    assert "leaks" not in _row("a", TP, True).to_json(leaks_computed=False)  # an arm with no lookup


@pytest.mark.db
def test_a_partial_report_has_null_leaks_in_its_rows_and_says_during(
    lab, tmp_path, monkeypatch, capsys
):
    def dead(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(lm, "with_leaks", dead)
    code, out = _run_tool(
        lab, tmp_path, monkeypatch, _lab_fake(lab), "measure", "--tiers", "1", "--yes"
    )
    capsys.readouterr()
    report = _report(out)
    assert code == lm.EXIT_PARTIAL
    on_rows = [r for r in report["rows"] if r["arm"] == "on"]
    assert on_rows
    for row in on_rows:
        assert (
            row["leaks"] is None and row["history_same_run"] is None and row["unplaceable"] is None
        )
    off_rows = [r for r in report["rows"] if r["arm"] == "off"]
    assert all("leaks" not in r for r in off_rows)
    (md_path,) = out.glob("lab_measure_*.md")
    md = md_path.read_text(encoding="utf-8")
    assert "the run stopped during the leak pass" in md and "stopped before the leak pass" not in md


def test_summarise_says_during_the_leak_pass():
    doc = lm.summarise.__doc__
    assert "during" in doc and "did not run" not in doc


def test_a_second_paired_line_covers_the_subjects_whose_prompt_carried_a_match():
    """Recommendation 2. Where the RAG could act: the RAG-on prompt kept at least one match. A failed, an empty and
    a no-lookup subject are in the first paired line and not in this one."""
    hit = lm.Seen("ok", None, (("e1", 80),))
    off = [
        _row("a", TP, False),  # matched; the RAG fixes it
        _row("b", FP, False),  # matched; right both ways
        _row("c", FP, True),  # no match: the RAG could not act
        _row("d", TP, True),  # failed lookup
        _row("e", FP, None, outcome="schema"),  # matched but unanswered off: in neither pair
    ]
    on = [
        _row("a", TP, True, arm="on", seen=hit),
        _row("b", FP, False, arm="on", seen=hit),
        _row("c", FP, True, arm="on", seen=lm.Seen("none", None, ())),
        _row("d", TP, True, arm="on", seen=lm.Seen("failed", "auth", ())),
        _row("e", FP, False, arm="on", seen=hit),
    ]
    assert lm.paired(off, on)["n"] == 4
    got = lm.paired(off, on, with_matches=True)
    assert got == {
        "n": 2,
        "off": {"correct": 1, "accuracy": 0.5},
        "on": {"correct": 2, "accuracy": 1.0},
    }
    assert lm.paired([], [], with_matches=True)["off"]["accuracy"] is None


@pytest.mark.db
def test_each_tier_reports_the_paired_line_where_the_rag_could_act(lab, measured_wave):
    """The scratch lab: ① t1, t2 and t4 had a match in the prompt (t3's lookup failed). RAG off: t1 right, t2
    wrong, t4 right. RAG on: all three right. ②: only C1 had one (C2's lookup failed): off wrong, on right.
    """
    tier1 = measured_wave.report["tiers"]["1"]["paired_with_matches"]
    assert tier1 == {
        "n": 3,
        "off": {"correct": 2, "accuracy": 2 / 3},
        "on": {"correct": 3, "accuracy": 1.0},
    }
    tier2 = measured_wave.report["tiers"]["2"]["paired_with_matches"]
    assert tier2 == {
        "n": 1,
        "off": {"correct": 0, "accuracy": 0.0},
        "on": {"correct": 1, "accuracy": 1.0},
    }
    md = measured_wave.markdown
    assert md.count("where the RAG could act") == 2  # one line per tier
    assert "same 3 subjects" in md and "same 1 subjects" in md


@pytest.mark.db
def test_the_no_lookup_line_says_it_may_hide_a_429(measured_wave):
    """Deferred item 28, documented and not changed in `rag/lookup.py`: a 429 whose retry came too late stores
    nothing, so the report's count of failed lookups by kind cannot see it. Said once under each RAG-on table.
    """
    md = measured_wave.markdown
    assert md.count("may hide a 429") == 2  # one per tier
    assert lm.NO_LOOKUP_NOTE in md


# ── M2: the budget cut that drops the entries and keeps the history ─────────────────────────


@pytest.mark.db
def test_a_cut_that_dropped_the_entries_counts_no_match_but_keeps_the_history(lab):
    alert = _stray_alert(lab.dsn)
    subject = Subject("alert", alert)
    content = "# stray\n\nan approved entry called cut-entries"
    with _connect(lab.dsn) as conn:
        entry = _entry(conn, content)
        used = _put_lookup(
            conn,
            "alert",
            alert,
            at(1),
            matches=[_entry_match(entry, content, 0.8)],
            history=_history(2, at(1), ["x.1"]),
        )
        conn.commit()
        kept = lm.seen_for(conn, subject, applied=used)
        assert [e for e, _p in kept.matches] == [entry]
        cut = lm.seen_for(conn, subject, applied=used, entries_dropped=True)
        assert cut.matches == () and cut.best_pct is None
        assert (cut.status, cut.history_total, cut.history_examples) == ("ok", 2, ("x.1",))
        assert cut.history_in_prompt  # the history did reach the prompt


@pytest.mark.db
def test_run_alert_reads_the_cut_from_the_evaluations_warnings(lab, monkeypatch):
    alert = _stray_alert(lab.dsn)
    content = "# stray\n\nan approved entry called cut-run"
    with _connect(lab.dsn) as conn:
        entry = _entry(conn, content)
        used = _put_lookup(
            conn, "alert", alert, at(1), matches=[_entry_match(entry, content, 0.8)], total=2
        )
        conn.commit()

        def evaluation(warnings):
            built = SimpleNamespace(warnings=warnings)
            return SimpleNamespace(
                outcome="ok",
                proposed_verdict=FP,
                final_verdict=FP,
                cost_usd=0.0,
                rag_lookup_id=used,
                built=built,
            )

        subject = lm.AlertSubject(alert, "run", FP, at(0.5))
        for warnings, matches in (([], 1), ([LEARNED_ENTRIES_DROPPED_WARNING], 0)):
            monkeypatch.setattr(lm, "evaluate_alert", lambda *a, w=warnings, **k: evaluation(w))
            rows = lm.run_alert(
                conn, subject, FP, adapter=SimpleNamespace(), cfg=lm.config.Config()
            )
            on = next(row for row in rows if row.arm == "on")
            assert len(on.seen.matches) == matches
            assert on.seen.status == "ok" and on.seen.history_total == 2


# ── M3: the calibrate message ───────────────────────────────────────────────────────────────


@pytest.mark.db
def test_a_missing_or_refused_voyage_key_is_worded_as_both(lab, tmp_path, monkeypatch, capsys):
    from app.rag.failures import RagUnavailable

    def refused(query, documents, *, cfg, client=None):
        raise RagUnavailable("auth")

    monkeypatch.setattr(lm.voyage, "rerank", refused)
    monkeypatch.setenv("VOYAGE_API_KEY", "")
    code, _out = _run_tool(
        lab,
        tmp_path,
        monkeypatch,
        None,
        "calibrate",
        "--runs",
        "kb-1",
        "--rerank-model",
        "rerank-3",
        "--yes",
    )
    err = capsys.readouterr().err
    assert code == lm.EXIT_NOT_READY
    assert "the Voyage key is missing or was refused (auth)" in err
    assert "VOYAGE_API_KEY" in err
    assert "Voyage refused the request (auth)" not in err


# ── the standard lab, as_of None ────────────────────────────────────────────────────────────


def test_an_alert_subject_without_an_as_of_is_evaluated_without_one():
    """`AlertSubject(...)` as the existing tests build it still has no `as_of`: it is today's evaluation."""
    subject = lm.AlertSubject("a", "run", FP, at(1))
    assert (subject.as_of, subject.as_of_source) == (None, None)
