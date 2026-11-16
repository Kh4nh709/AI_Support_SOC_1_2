"""`docs/runbook.md` and `docs/limitations.md` — the sentences the earlier P14 cards made false, and the limits P14
adds (P14-T08, DEC-213).

WHY A TEST FOR A DOCUMENT. The runbook was written card by card. P14-T04 said "no Voyage call in any code yet" and
"no worker claims it yet" when `knowledge_embed` had no worker; P14-T05 gave it one, P14-T06 took the model out of
the lookup and added `rag_lookup_failures`, and P14-T02 took `need_more_data` out of ②'s answers. None of those
cards had the runbook in its scope, so each sentence stayed true to its card and false to the next. This file pins
the corrected ones: the drain query lists the three job types `rag-worker` claims; the Alarms table has
`rag_lookup_failures` with what to do, and `llm_null_ratio` leaves the lookup's runs out; the model-API row says
the lookup calls no model; the start-everything row's counts sum to the migration files; and the limitations the
brief and the Director name are in `docs/limitations.md` with their four parts. The section itself is
`test_runbook_voyage.py`. It does not judge prose.

PURE. No database, no socket, no docker.
"""

from __future__ import annotations

import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNBOOK = REPO_ROOT / "docs" / "runbook.md"
LIMITATIONS = REPO_ROOT / "docs" / "limitations.md"
SCHEMA_DIR = REPO_ROOT / "docs" / "Schema"
HEALTH = REPO_ROOT / "backend" / "app" / "infra" / "health.py"

#: The queue DEC-210's rollback drains before `rag-worker` is removed: the three job types it claims
#: (`web/rag_worker.py`). The Voyage rollback stops `vectordb` and counts the two that use it (fix round 1, M1).
DRAIN = (
    "select count(*) from jobs where job_type in ('rag_lookup','knowledge_embed','knowledge_draft') "
    "and status in ('pending','running')"
)
DRAIN_VECTORDB = (
    "select count(*) from jobs where job_type in ('rag_lookup','knowledge_embed') "
    "and status in ('pending','running')"
)


def _text(path: pathlib.Path = RUNBOOK) -> str:
    assert path.exists(), f"{path} does not exist"
    return path.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _code(text: str) -> list[str]:
    """Every `inline code` span of `text`."""
    return re.findall(r"`([^`]+)`", text)


def _migration_files() -> list[str]:
    return sorted(p.stem for p in SCHEMA_DIR.glob("[0-9][0-9][0-9]_*.sql"))


def _row(starts: str) -> str:
    return next(ln for ln in _text().splitlines() if ln.startswith(starts))


def test_the_drain_queries_list_knowledge_embed_and_the_vectordb_one_leaves_the_draft_out():
    """DEC-210's rollback removes `rag-worker`, so it waits for all three job types; the Voyage rollback only
    stops `vectordb`, which a draft never touches: its count has the two types that do (M1)."""
    text = _text()
    queries = re.findall(
        r"select count\(\*\) from jobs where job_type in \(([^)]*)\) and status in", text
    )
    assert len(queries) == 2, queries
    assert sorted(queries) == sorted(
        ["'rag_lookup','knowledge_embed','knowledge_draft'", "'rag_lookup','knowledge_embed'"]
    )
    rollback = next(
        p for p in text.split("\n\n") if p.startswith("**Rollback.** Set `RAG_ENABLED=false`")
    )
    assert DRAIN in rollback and DRAIN_VECTORDB not in rollback
    step = text.split("**9 · Rollback.**", 1)[1].split("#### Lab procedure", 1)[0]
    blocks = re.findall(r"```bash\n(.*?)```", step, re.DOTALL)
    assert DRAIN_VECTORDB in "".join(blocks) and "knowledge_draft" not in "".join(blocks)
    # every other place that names the RAG job types names the third
    for starts in ("| `job_backlog` |", "| **Worker stuck**"):
        assert "`knowledge_embed`" in _row(starts), starts
    running = next(p for p in text.split("\n\n") if p.startswith("**Running `rag-worker`.**"))
    assert "`knowledge_embed`" in running


def test_the_alarms_table_has_rag_lookup_failures_with_its_label_threshold_and_what_to_do():
    row = _row("| `rag_lookup_failures` |")
    flat = _flat(row)
    for needle in (
        "Tra cứu RAG thất bại liên tục",
        "5 failed lookups",
        "60 minutes",
        "alarms at 5 or more",
        "n/a — RAG off",
        "`auth`",
        "`quota`",
        "`rate_limit`",
        "`timeout`",
        "`provider_error`",
        "`vectordb_unreachable`",
        "docker compose up -d --force-recreate rag-worker",
        "docker compose ps vectordb",
        "**Voyage vector RAG (DEC-213)**",
    ):
        assert needle in flat, f"the rag_lookup_failures row no longer says {needle!r}"
    assert "(P14-T08)" not in flat, "the row still points at a runbook that was to come"
    source = _text(HEALTH)
    assert (
        "_RAG_LOOKUP_FAILURES_MAX = 5" in source
        and "_RAG_LOOKUP_FAILURES_WINDOW_MIN = 60" in source
    )
    assert '"n/a — RAG off"' in source


def test_llm_null_ratio_leaves_rag_lookup_out_in_the_row_and_in_its_sql():
    row = _row("| `llm_null_ratio` |")
    assert "AND pipeline <> 'rag_lookup'" in _text(
        HEALTH
    ), "health.py no longer leaves rag_lookup out"
    assert "pipeline <> 'rag_lookup'" in row, "the first-look SQL counts rag_lookup runs"
    flat = _flat(row)
    assert "`rag_lookup_failures`" in flat and "Voyage" in flat
    sql = next(c for c in _code(row) if c.startswith('psql "$DATABASE_URL"'))
    assert "interval '1 hour'" in sql and "result is null" in sql


def test_model_api_down_says_the_lookup_calls_no_model():
    row = _row("| **Model API down**")
    flat = _flat(row)
    assert "a RAG lookup is stored `failed` (its run `permanent`)" not in flat
    assert "calls no model" in flat and "`rag_lookup_failures`" in flat
    assert (
        "a knowledge draft is stored empty with the warning `llm_permanent`" in flat
    )  # still true


def test_the_start_everything_row_is_consistent_with_the_25_migrations():
    row = _row("| start everything |")
    total = len(_migration_files())
    assert total == 25
    pairs = re.findall(r"`migrate: (\d+) applied, (\d+) already present`", row)
    assert pairs, "no `migrate: N applied, M already present` in the row"
    for applied, present in pairs:
        assert int(applied) + int(present) == total, (applied, present)
    flat = _flat(row)
    # the trial's database stands at 20 after the wipe (spec §11): 021, 022, 023, 024, 025 are applied
    assert (
        "`migrate: 5 applied, 20 already present` on a dump taken after 020 or on the trial database"
        in flat
    )
    assert "on the trial database today" not in flat
    assert "`migrate: 4 applied, 21 already present` on a dump taken after 021 (" in flat
    # the refusal belongs to a database that holds an escalate, not inside the list of counts for one that does not
    counts = flat.split("The counts for a database or a dump that holds no ① `escalate`", 1)[1]
    assert (
        "**refuses" not in counts
    ), "the list of counts for a database with no escalate talks of a refusal"
    assert "has no count" in counts  # a database that does hold one stops at 022: no count at all
    assert "`migrate: 0 applied, 25 already present` after that." in flat


def test_the_lookup_is_no_longer_said_to_call_deepseek_and_the_old_stubs_are_gone():
    text = _text()
    flat = _flat(text)
    for stale in (
        "no worker claims it yet",
        "There is no Voyage call in any code yet",
        "and call DeepSeek only. **Both switches",
        "Each lookup is one more DeepSeek call",
        "(the DeepSeek call failed after its repair or its retries)",
        "The page that uses the API is P14-T10 and the tool that reads the labels is P14-T11",
    ):
        assert stale not in flat, f"the runbook still says {stale!r}"
    intro = flat.split("**Both switches default to `false`**", 1)[0]
    assert "Only `knowledge_draft` calls DeepSeek" in intro
    step9 = next(ln for ln in text.splitlines() if ln.startswith("| 9 · lookup on |"))
    assert "two Voyage calls" in step9 and "no working Voyage key" in step9
    lookups = next(ln for ln in text.splitlines() if ln.startswith("| lookups |"))
    assert "`failure_kind`" in lookups


def test_the_runbook_header_says_how_p14_t08_was_checked():
    header = _text().split("\n## Start and stop")[0]
    assert "P14-T08" in _flat(header)
    # fix round 1, M8: the sentence has no bold inside its bold
    line = next(ln for ln in header.splitlines() if "P14-T08's additions and edits" in ln)
    assert "**Environment keys**" not in line
    assert line.count("**") % 2 == 0, "the bold of the header paragraph is not balanced"


def test_the_admin_console_lists_the_seven_pages_the_ui_has():
    """M2: the runbook said seven pages; `AdminLayout.tsx` listed nine (the knowledge page of DEC-210 and the
    lab page of DEC-213). DEC-214 (P15) took the rules page and the digest page out, so it lists seven again. The
    sentence names exactly the routes the layout has."""
    layout = _text(REPO_ROOT / "frontend" / "src" / "features" / "admin" / "AdminLayout.tsx")
    pages = re.findall(r'\{ to: "(/admin/[a-z]+)"', layout)
    assert len(pages) == 7, pages
    sentence = next(
        ln for ln in _text().splitlines() if ln.startswith("The admin console is the React UI:")
    )
    assert "has nine pages" not in sentence and "has seven pages" in sentence
    named = re.findall(r"`(/admin/[a-z]+)`", sentence.split("has seven pages", 1)[1])
    assert sorted(named) == sorted(pages), (named, pages)


def test_on_the_trial_a_restore_goes_through_the_voyage_step_7_never_through_the_dec_210_block():
    """Fix round 2: DEC-210's restore block has no dump check; on the trial it would restore anything."""
    before_commands = _text().split("### After `make db-restore`\n", 1)[1].split("```bash", 1)[0]
    flat = _flat(before_commands)
    assert "On the trial a restore goes through step 7 of **Voyage vector RAG (DEC-213)**" in flat
    assert "never through this block" in flat and "dump check" in flat


def test_the_dec_210_restore_section_agrees_with_itself_about_the_trial():
    """Fix round 3 (m3): the sentence before its block says a trial restore never goes through it; the one after the
    block must not say the trial rebuilds the index 'after these four commands' (as if the block were run there).
    """
    section = _text().split("### After `make db-restore`\n", 1)[1].split("\n## ", 1)[0]
    flat = _flat(section)
    assert "never through this block" in flat
    assert "rebuilt after these four commands as well" not in flat
    assert (
        "On the trial, with the Voyage RAG (P14), step 7 of **Voyage vector RAG (DEC-213)** runs these four commands"
        " after its dump check, then rebuilds the vector index" in flat
    )


def test_the_job_loop_row_counts_the_three_job_types_rag_worker_claims():
    from_code = _text(REPO_ROOT / "backend" / "app" / "web" / "rag_worker.py")
    assert 'CLAIM_ORDER = [["rag_lookup"], ["knowledge_embed"], ["knowledge_draft"]]' in from_code
    row = _flat(_row("| the job loop |"))
    assert "claims neither type" not in row
    assert "none of the three types" in row and "`knowledge_embed`" in row


def test_the_rag_model_row_says_what_the_key_is_now_that_the_lookup_calls_no_model():
    """M2: `RAG_MODEL` was "the model of the lookup's ranking call and the draft call". Since P14 the lookup calls no
    model (`rag/agent.py` is read by the draft only)."""
    agent = _text(REPO_ROOT / "backend" / "app" / "rag" / "agent.py")
    assert "return cfg.RAG_MODEL or cfg.LLM_MODEL_PROPOSER" in agent
    for module in ("rag/lookup.py", "rag/match.py"):
        assert "rag_model(" not in _text(REPO_ROOT / "backend" / "app" / module), module
    row = _flat(_row("| `RAG_MODEL` |"))
    assert "lookup's ranking call" not in row
    assert "the model of the draft calls" in row and "the lookup calls no model" in row
    assert "empty means `LLM_MODEL_PROPOSER`" in row


# --------------------------------------------------------------------------- limitations


def _limitation(heading: str) -> str:
    text = _text(LIMITATIONS)
    start = text.index(heading)
    following = re.search(r"^##+ ", text[start + 4 :], re.MULTILINE)
    item = text[start:] if following is None else text[start : start + 4 + following.start()]
    return _flat(item)


FOUR_PARTS = ("- **Statement.**", "- **Measured.**", "- **Source.**", "- **Affects.**")


def test_limitation_l_says_what_voyage_does_with_the_data_and_what_the_free_tier_cannot_do():
    item = _limitation("### (l) · Voyage vector RAG")
    for label in FOUR_PARTS:
        assert label in item, label
    for needle in (
        "DEC-213",
        "trial only",
        "cannot opt out of training",
        "payment method",
        "MongoDB",
        "retention",
        "unverified",
        "rate limits",
        "`rate_limit`",
        'scored "RAG on" with no RAG',
        "counted",
        "approval-time embeddings",
        "`knowledge_embed`",
        "outside the budget",
        "`RAG_MONTHLY_USD_CAP`",
        "never sent",
        "raw log",
    ):
        assert needle in item, f"limitation (l) no longer says {needle!r}"


def test_limitation_li_says_what_the_lab_measurement_cannot_show():
    item = _limitation("### (li) · The lab measurement")
    for label in FOUR_PARTS:
        assert label in item, label
    for needle in (
        "DEC-213",
        "unseen scenario",
        "not measured",
        "provisional until calibration",
        "`RAG_MIN_SCORE`",
        "`RAG_LEVEL_GIONG`",
        "`RAG_LEVEL_RAT_GIONG`",
        "flattered",
        "neighbours' current status",
        "`history_same_run`",
        "`DEDUP_ENABLED=true`",
        "neither listed nor labelled",
        "2000",
        "2099",
        "`eval/investigate_measure.py`",
        "`investigate_v2`",
        "the lab tool does not use it",
    ):
        assert needle in item, f"limitation (li) no longer says {needle!r}"
