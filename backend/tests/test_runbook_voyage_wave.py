"""`docs/runbook.md`, the Voyage section - the last of the whole-branch review's edits (P14 final fix wave, E24-E26).

* **24 (M3).** Step 5 RECREATES `app` and `worker` (`up -d --force-recreate`), so they see the keys step 1 wrote into
  `.env`; `calibrate --rerank-model` runs in `app` and needs `VOYAGE_API_KEY`. The step's own test is in
  `test_runbook_voyage.py` (`test_step_5_...`).
* **25 (recommendation 3).** After the first lab lookups the operator reads what they cost against the dashboard:
  `select count(*), max(input_tokens), avg(input_tokens) from llm_runs where pipeline = 'rag_lookup'`, two requests
  per alert, up to 40 candidates in the rerank, and pace the runs when the tier cannot carry them.
* **26 (T08's last minors).** Step 4's failed-copy recovery sits under the backup paste (before the `ls -t` paste)
  and has an else branch; the `GATES` comment does not say step 4 has nothing to wait for; the monthly cap is per
  tool run, so the estimate is read as the sum of the figures plus the month's earlier lab runs. Every check-then-act
  pair stays in its own pastes (`test_runbook_voyage.py`'s `GATES`, which this file does not touch).

PURE. No database, no socket, no docker.
"""

from __future__ import annotations

import pathlib
import re

from tests.test_runbook_voyage import REPO_ROOT, _fenced, _flat, _pastes, _steps, _sub

CHECK = "select count(*), max(input_tokens), avg(input_tokens) from llm_runs where pipeline = 'rag_lookup'"


# ── 25 ─────────────────────────────────────────────────────────────────────────────────────


def test_step_8_has_the_usage_check_in_a_paste_of_its_own_and_says_to_pace_the_runs():
    step = _steps()[8]
    pastes = _pastes(step)
    assert len(pastes) == 1
    before, block = pastes[0]
    assert block.strip() == f'psql "$DATABASE_URL" -Atc "{CHECK}"'
    assert "only when" in before.lower()
    flat = _flat(step)
    for needle in (
        "After the first lab lookups",
        "**two** Voyage requests",
        "up to 40",
        "requests per minute",
        "tokens per minute",
        "the dashboard",
        "pace the runs",
        "free tier cannot carry",
    ):
        assert needle in flat, f"step 8 no longer says {needle!r}"
    # the query is the one the review gave, against a pipeline and a column the code writes
    lookup = (REPO_ROOT / "backend" / "app" / "rag" / "lookup.py").read_text(encoding="utf-8")
    assert 'pipeline="rag_lookup"' in lookup
    assert "input_tokens=attempt.embed_tokens + attempt.rerank_tokens" in lookup


def test_the_usage_check_is_not_in_the_paste_that_acts_in_any_other_step():
    """It reads; it is the only fenced `psql` of step 8, and step 9's drain count is a different query."""
    assert sum(CHECK in line for line in _fenced(_steps()[9])) == 0
    assert sum(CHECK in line for line in _fenced(_steps()[8])) == 1


# ── 26 ─────────────────────────────────────────────────────────────────────────────────────


def test_step_4_failed_copy_recovery_is_under_the_backup_paste_with_an_else_branch():
    step = _steps()[4]
    pastes = _pastes(step)
    assert len(pastes) == 2
    backup, naming = pastes[0][1], pastes[1][1]
    assert "bash scripts/backup.sh" in backup and "ls -t backups/soc-*.dump" in naming
    # position: after the backup paste's closing fence and before the `ls -t` paste
    first_fence_end = step.index("```", step.index("```bash") + 7) + 3
    recovery = step.index("**If the copy fails**")
    assert first_fence_end < recovery < step.index("ls -t backups/soc-*.dump | head -1")
    assert step.count("If the copy fails") == 1  # moved, not copied
    flat = _flat(step)
    for needle in (
        "no backup was taken",
        "`ls ~/soc-trial-keep/`",
        "if the pre-lab dump is there, run `bash scripts/backup.sh` alone",
        # the else branch
        "If the pre-lab dump is in neither `backups/` nor `~/soc-trial-keep/`",
        "run `bash scripts/backup.sh` alone all the same",
        "and then find the pre-lab dump",
        "before the next backup can prune it",
    ):
        assert needle in flat, f"step 4 no longer says {needle!r}"
    # the paste that names the new dump still waits for the three lines of the backup
    assert "only when" in pastes[1][0].lower()


def test_the_gates_comment_does_not_say_step_4_has_nothing_to_wait_for():
    source = pathlib.Path(__file__).with_name("test_runbook_voyage.py").read_text(encoding="utf-8")
    raw = source.split("GATES = [", 1)[0].rsplit('#: The "check, then act" pairs', 1)[1]
    comment = " ".join(
        raw.replace("#:", " ").split()
    )  # the comment as one line, whatever its wrapping
    assert "steps 2, 3, 4, 6 and 8" not in comment
    assert "Step 4 has a gate of its own" in comment and "its own test" in comment
    assert re.search(r"steps 2, 3, 6 and 8", comment)


def test_the_estimate_is_read_as_the_sum_of_the_figures_plus_the_months_earlier_lab_runs():
    measuring = _sub("Measuring")
    flat = _flat(measuring)
    for needle in (
        "checked per tool run, not for the month",
        "the tool writes no `llm_runs` row",
        "the small run (the second paste), a `--tiers 1` run and every earlier lab run of the month",
        "their sum plus this month's earlier lab runs",
    ):
        assert needle in flat, f"Measuring no longer says {needle!r}"
    first = _pastes(measuring)[0]
    after_first_paste = measuring.split(first[1], 1)[1].split("```")[
        1
    ]  # the prose between pastes 1 and 2
    assert "their sum plus this month's earlier lab runs" in _flat(after_first_paste)
    assert "Read the two figures against the month's cap and give them to the Owner" not in flat
