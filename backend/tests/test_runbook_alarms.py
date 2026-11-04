"""`docs/runbook.md` — the `## Alarms` table keeps itself honest against
`infra/health.py` (P5-T13).

WHY A TEST FOR A DOCUMENT. `test_runbook_pilot.py` pins P4-T07's `## Pilot`
section for the same reason this file pins P5-T13's: a runbook drifts
silently. Design note 4 of `docs/plan/tasks/P5/P5-T13.prompt.md` (and
`STATE.md`'s own P5-T13 row, "kiểm hai chiều") asks for a **two-directional**
check: every check name in `infra/health.py` has a row in the `## Alarms`
table, and every row in the table names a check that still exists in
`infra/health.py`. One direction alone would pass forever while the other
side rotted — a check added to the code with no row, or a row renamed
without renaming the check, both have to go red, in opposite ways.

This file also pins the two smaller honesty properties P5-T13 added:
`## Restore drill (P8)` exists exactly once, names the full signed record
(`docs/restore-drill.md`, P8-T02) and carries a "Last drill: … — PASS|FAIL —
signed by the Owner …" line and the clean-up rule — the empty ten-field
template this section held before P8-T02 ran and was signed (29/09) is gone,
at the Director's follow-up, once there was a real drill to point at instead
— and `## ② operations` (filled in once P5-T04 merged, DEC-151): one tolerant test
(the heading exists once, with some content) and one exact test that pins every fact the
section must state, each with its own message, so removing one names it. A third test
checks the defaults the section quotes against `backend/app/infra/config.py`.

PURE. No database, no socket, no fixture: reads `docs/runbook.md` and
`backend/app/infra/health.py` as text only. Runs anywhere the repository is
checked out, exactly like `test_runbook_pilot.py`.

Review round 1, finding 7: check names are extracted from `infra/health.py`
by `ast`, not a regex. A regex anchored on `CheckResult(\"` has three blind
spots, each a *silent* undercount rather than a red test: a check named by
keyword (`CheckResult(name=...)`, M4) never matches because the pattern
expects the string right after the opening paren; a name containing a digit
(M5) is never followed by the closing quote where the character class
`[a-z_]+` stops, so the match fails outright; and a name held in a variable
or constant (`CheckResult(_NAME, ...)`, M6) is not a quoted string at all.
`_extract_check_names` walks the AST instead: a string literal is a string
literal regardless of position (positional or `name=`) or spelling (digits
included), which handles M4 and M5 for free, and a `CheckResult(...)` whose
name argument is *not* a string literal now fails loudly, naming the file
and line, instead of silently vanishing from the set (M6).
"""

import ast
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNBOOK_PATH = REPO_ROOT / "docs" / "runbook.md"
HEALTH_PATH = REPO_ROOT / "backend" / "app" / "infra" / "health.py"

H2_RE = re.compile(r"^## (.*)$", re.MULTILINE)
TABLE_ROW_RE = re.compile(r"^\|.*\|\s*$", re.MULTILINE)
# A cell boundary is an unescaped pipe; `\|` inside a cell is a literal pipe
# (test_runbook_pilot.py's own convention — a psql `-A` sample or a piped
# shell command inside one cell).
CELL_SPLIT_RE = re.compile(r"(?<!\\)\|")
NAME_CELL_RE = re.compile(r"^`([a-z_]+)`$")
# The quick-reference "Last drill" line's shape, not its literal date, so a
# later, real drill re-running this line does not have to touch this test —
# only the line's format is pinned (verdict word, "signed by the Owner", and
# the pointer to the full record).
LAST_DRILL_RE = re.compile(
    r"Last drill: \d{2}/\d{2}/\d{4} \d{2}:\d{2} UTC — (PASS|FAIL) — signed by the Owner"
    r" — full record `docs/restore-drill\.md`"
)


def _text() -> str:
    assert RUNBOOK_PATH.exists(), f"{RUNBOOK_PATH} does not exist"
    return RUNBOOK_PATH.read_text(encoding="utf-8")


def _mask_fences(text: str) -> str:
    """`text` with every line inside a ``` fence blanked out (same length,
    newlines kept), so a heading regex cannot match a bash comment inside a
    command block. `test_runbook_pilot.py`'s own helper, duplicated rather
    than imported so the two doc-honesty files stay independent."""
    out, fenced = [], False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            out.append(" " * len(line))
        else:
            out.append(" " * len(line) if fenced else line)
    return "\n".join(out)


def _section(text: str, heading: str) -> str:
    """The body **after** `## <heading>` up to the next `## ` heading (or
    EOF), fences ignored for heading detection."""
    heads = list(H2_RE.finditer(_mask_fences(text)))
    matches = [m for m in heads if m.group(1).strip() == heading]
    assert len(matches) == 1, f"expected exactly one '## {heading}' heading, found {len(matches)}"
    start = matches[0].end()
    later = [m.start() for m in heads if m.start() > matches[0].start()]
    end = later[0] if later else len(text)
    return text[start:end]


def _table_rows(body: str) -> list[list[str]]:
    """Every pipe-table row in `body` as a list of stripped cells (separator
    rows dropped) — `test_runbook_pilot.py`'s own parser."""
    rows = []
    for line in body.splitlines():
        if not TABLE_ROW_RE.match(line):
            continue
        inner = line.strip()[1:-1]
        cells = [c.strip().replace("\\|", "|") for c in CELL_SPLIT_RE.split(inner)]
        if all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
            continue
        rows.append(cells)
    return rows


def _extract_check_names(source: str, *, where: str) -> set[str]:
    """Every `CheckResult(...)` call's check name in `source`, by AST
    (review round 1, finding 7 — see the module docstring for M4/M5/M6).
    `where` is a filename used only for `ast.parse` and in an assertion
    message; it need not exist on disk (the M4/M5/M6 tests below pass a
    synthetic snippet, not a real file)."""
    tree = ast.parse(source, filename=where)
    names: set[str] = set()
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "CheckResult"
        ):
            continue
        arg = (
            node.args[0]
            if node.args
            else next((kw.value for kw in node.keywords if kw.arg == "name"), None)
        )
        assert arg is not None, (
            f"{where}:{node.lineno}: a CheckResult(...) call with neither a positional "
            "first argument nor a name= keyword"
        )
        assert isinstance(arg, ast.Constant) and isinstance(arg.value, str), (
            f"{where}:{node.lineno}: CheckResult's name is not a string literal "
            f"({ast.dump(arg)}) — a name held in a variable or constant cannot be "
            "checked against ## Alarms"
        )
        names.add(arg.value)
    return names


def _health_check_names() -> set[str]:
    text = HEALTH_PATH.read_text(encoding="utf-8")
    names = _extract_check_names(text, where=str(HEALTH_PATH))
    assert names, f"no CheckResult(...) calls found in {HEALTH_PATH}"
    return names


def _alarm_table_check_names() -> set[str]:
    section = _section(_text(), "Alarms")
    rows = _table_rows(section)
    assert rows, "no table in ## Alarms"
    header = [c.lower() for c in rows[0]]
    assert header[0] == "check", f"unexpected Alarms table header: {rows[0]}"
    names = set()
    for row in rows[1:]:
        m = NAME_CELL_RE.match(row[0])
        assert m, f"Alarms table row's first cell is not a single `name`: {row[0]!r}"
        names.add(m.group(1))
    return names


# --------------------------------------------------------------------------- tests


def test_extract_check_names_finds_a_keyword_name_argument():
    """M4 — a regex anchored on `CheckResult("` misses this; ast does not
    care whether the name arrived positionally or by keyword."""
    src = 'x = CheckResult(name="disk_free", ok=True, value=1, threshold=2, detail="d")\n'
    assert _extract_check_names(src, where="<m4>") == {"disk_free"}


def test_extract_check_names_finds_a_name_with_a_digit():
    """M5 — a regex character class of `[a-z_]+` cannot match a digit, so it
    is never followed by the closing quote where the class stops: the match
    fails outright and the name silently vanishes. ast reads the string
    literal whole, digit included."""
    src = 'x = CheckResult("digest_unreviewed_2", True, 1, 2, "d")\n'
    assert _extract_check_names(src, where="<m5>") == {"digest_unreviewed_2"}


def test_extract_check_names_fails_loudly_on_a_name_held_in_a_constant():
    """M6 — a regex requires a literal `"` right after `CheckResult(` and
    silently finds nothing for `CheckResult(_NAME, ...)`: the check
    disappears from the set with no error, which would misreport later as
    `## Alarms` naming a check that "does not exist". ast can tell a `Name`
    node from a string `Constant` and raises here, naming the line, instead
    of a silent undercount."""
    src = '_NAME = "disk_free"\nx = CheckResult(_NAME, True, 1, 2, "d")\n'
    with pytest.raises(AssertionError, match=r"<m6>:2: .*not a string literal"):
        _extract_check_names(src, where="<m6>")


def test_alarms_heading_appears_once():
    # Not a substring count: review round 1's preamble fix (finding 15)
    # cross-references `` `## Alarms` `` in prose several times, so a naive
    # `_text().count(...)` over-counts. `_section` anchors on the heading
    # line itself (`H2_RE`, start of line) and already asserts there is
    # exactly one; calling it is the test.
    _section(_text(), "Alarms")


def test_alarm_table_has_exactly_fourteen_rows_on_both_sides():
    # ten (§3.9), since P13-T05 (DEC-210) knowledge_queue, knowledge_integrity and rag_budget, and since
    # P14-T06 (DEC-213) rag_lookup_failures
    assert len(_health_check_names()) == 14, sorted(_health_check_names())
    assert len(_alarm_table_check_names()) == 14, sorted(_alarm_table_check_names())


def test_alarm_table_matches_health_py_both_directions():
    """Design note 4 / STATE.md's "kiểm hai chiều": a check with no row, and
    a row with no check, must each be caught — the two failure shapes are
    different assertions on purpose, so either direction of drift names
    itself in the message rather than the two sets just comparing unequal."""
    code_names = _health_check_names()
    doc_names = _alarm_table_check_names()
    missing_from_doc = code_names - doc_names
    assert (
        not missing_from_doc
    ), f"infra/health.py has a check with no ## Alarms row: {sorted(missing_from_doc)}"
    extra_in_doc = doc_names - code_names
    assert (
        not extra_in_doc
    ), f"## Alarms names a check that does not exist in infra/health.py: {sorted(extra_in_doc)}"


def test_restore_drill_heading_appears_once():
    # Same reasoning as test_alarms_heading_appears_once: the preamble now
    # cross-references `` `## Restore drill (P8)` `` in prose too.
    _section(_text(), "Restore drill (P8)")


def test_restore_drill_section_points_at_the_full_record_and_a_current_result():
    """P8-T02 ran and was signed (29/09) before this card's follow-up: the
    empty ten-field template is gone (the Director's own call — nothing left
    to leave empty once a real, signed drill exists), replaced by how to run
    one, a pointer to the full record, and the clean-up rule."""
    section = _section(_text(), "Restore drill (P8)")
    assert "docs/restore-drill.md" in section, "no pointer to the full signed record"
    assert (
        "scripts/backup.sh" in section and "scripts/restore.sh" in section
    ), "no how-to-run-a-drill steps"
    assert (
        "before" in section and "restored" in section and "after" in section
    ), "no before/restored/after criterion"
    assert LAST_DRILL_RE.search(section), (
        "no 'Last drill: <date> UTC — PASS|FAIL — signed by the Owner — "
        "full record `docs/restore-drill.md`' line"
    )
    assert "drop database" in section and "soc_restore_drill" in section, "no clean-up rule"
    assert 'psql "$DATABASE_URL_OWNER"' in section, (
        "the clean-up command should be `psql \"$DATABASE_URL_OWNER\" -c 'drop database ...'` "
        "(review round 1, finding 4) — a bare `dropdb` reaches libpq's default socket, the "
        "wrong server on this host; a prose mention warning against it is fine, the command "
        "itself must not be the bare form"
    )


def test_two_circle_operations_heading_present_with_some_content():
    """Tolerant on purpose: this assertion only requires the heading to exist once
    with a non-empty body, so a later rewording of the ② section does not have to
    touch it. The exact facts are pinned by the test below."""
    # Anchored on the heading line via _section (not a substring count —
    # see test_alarms_heading_appears_once), so a future prose
    # cross-reference to `` `## ② operations` `` elsewhere cannot break this.
    body = _section(_text(), "② operations").strip()
    assert body, "## ② operations has no content"


# Every fact the filled ② section must state (Director 1's addendum to P5-T13,
# DEC-151), as (what it says, a substring that proves it). Each was read out of the
# merged P5-T04 / P5-T05 code; the substrings are wording the section uses, so a
# rewording that drops one has to say the fact again or update this list on purpose.
TWO_CIRCLE_REQUIRED_FACTS: list[tuple[str, str]] = [
    # scope (P5-T13 acceptance 3)
    ("the confirmed_incident scope: it records, it does not contain", "`confirmed_incident`"),
    ("... and nothing is contained or remediated", "contains nothing and remediates nothing"),
    # 1. how to run an analysis
    ("the button label", "**Phân tích**"),
    ("the running state", "`Đang phân tích…`"),
    ("the 3 s poll", "every 3 s"),
    ("the failed state text", "`Phân tích thất bại — có thể thử lại`"),
    ("the analyze endpoint", "`POST /api/tier2/cases/{id}/analyze`"),
    ("the run endpoint", "`GET /api/tier2/runs/{run_id}`"),
    ("the 202 answer", "`202 {run_id, job_id}`"),
    ("a concluded case is 409", "`409` `case đã kết luận`"),
    ("already running is 409", "`409` `an investigation is already running for this case`"),
    ("the quota is 429 on the API", "`429` `analyze quota exceeded for today`"),
    ("the quota key", "`ANALYZE_QUOTA_PER_USER_DAY`"),
    ("the quota is counted from audit_events", "`audit_events`"),
    ("the quota's one-over race", "**one over**"),
    # 2. what (2) does
    ("the nine-block dossier", "nine-block dossier"),
    ("the 60k token budget", "`CASE_PROMPT_BUDGET_TOKENS` (default 60,000"),
    ("the cut steps are recorded", "`agent_trace.truncations`"),
    ("the linter", "It lints the prompt (G6')"),
    ("one call, no tools", "no tools"),
    ("at most one repair", "**at most one** repair"),
    ("the per-block injection scan", "scans each dossier block for prompt injection"),
    ("the evidence check", "checks the cited evidence"),
    ("G7: no status changes", "**It changes no case or alert status (G7)"),
    ("the only writes", "`llm_runs` and `cases.last_analyzed_at`"),
    # 3. need_more_data (P14-T08, DEC-213: the model no longer answers it; only the override sets it)
    ("need_more_data is the system's hold", "`need_more_data` is **the system's hold**"),
    ("the model never answers it", "never the model's answer"),
    ("the schema refuses it", "`investigate_v3`"),
    ("the model's own conclusion is kept on every run", "`evidence_check.model_conclusion`"),
    ("an overrule", "**overrule**"),
    ("overrule on no verified evidence", "**no cited evidence verified**"),
    ("overrule on a high injection finding", "**high-severity injection finding**"),
    ("the original conclusion is kept", "`evidence_check.original_conclusion`"),
    ("forced_by is kept", "`forced_by = high_severity_injection_finding`"),
    # 4. the evidence marks
    ("verified: verbatim substring", "verbatim substring"),
    ("verified: NFKC", "NFKC"),
    ("verified: plain or HTML-escaped", "HTML-escaped"),
    ("verified: duplicates count", "duplicate of a case alert"),
    ("the verified mark", "`Đã kiểm chứng`"),
    ("the unverified mark", "`Chưa kiểm chứng`"),
    ("reason not_in_case", "`not_in_case`"),
    ("reason quote_not_found", "`quote_not_found`"),
    ("reason quote_too_short", "`quote_too_short`"),
    ("the 8-character floor", "under `8` characters"),
    # 5. cost and failures
    ("every paid call is costed", "**Every paid call is costed**"),
    ("a non-final attempt's row", "`stopped_by = 'transient'` under an attempt-scoped `run_id`"),
    ("the monthly cap key", "`LLM_MONTHLY_USD_CAP`"),
    ("the cap stops a run with 0 calls", "**0 model calls**"),
    ("stopped_by cap", "| `cap` |"),
    ("stopped_by permanent", "| `permanent` |"),
    ("stopped_by linter", "| `linter` |"),
    ("stopped_by schema", "| `schema` |"),
    ("stopped_by transient", "| `transient` |"),
    (
        "a timeout is not retried in the adapter",
        "`LLMTimeout` is not retried inside the model adapter",
    ),
    ("the retry count", "`JOB_MAX_ATTEMPTS` (3)"),
    ("the backoff", "10 s, then 60 s"),
    ("job.exhausted", "`job.exhausted`"),
    ("a no-result run's screen line", "`Phân tích không có kết quả: <reason>`"),
    (
        "the read-only runs query: the command",
        'psql "$DATABASE_URL" -Atc "select created_at, stopped_by, cost_usd, run_id from llm_runs',
    ),
    (
        "the read-only runs query: the filter",
        "pipeline = 'investigate' and subject_id = '<case_id>'",
    ),
    # 6. operations
    ("the 5 s statement timeout", "`5 s` statement timeout"),
    (
        "the idle timeout is raised",
        "raises the idle-in-transaction timeout from `10 s` to `JOB_LOCK_TIMEOUT_S`",
    ),
    ("the timeout relation", "`2 × LLM_TIMEOUT_S < JOB_LOCK_TIMEOUT_S`"),
    ("restart after a merge", "`docker compose restart app worker`"),
    ("the compose rule", "`docker compose up -d`"),
    ("a pending job while the worker is down", "a queued job stays `pending`"),
    ("... and what the page does", "re-fetching every 3 s"),
    # 7. limitations
    ("not measured on the gold set", "**built but not measured**"),
    ("P7 measured (1) only", "run through ① only (P7)"),
    ("the [truncated] marker reads as medium", "**medium** finding"),
    ("the quota race is repeated in the limits", "The quota can be exceeded by one per race"),
    # what the agent could not run
    ("unrun commands are marked", "*(not run by the agent)*"),
]


def test_two_circle_operations_states_every_required_fact():
    """The filled section, not just "non-empty" (separated from the tolerant test above
    so this one, and only this one, fails when a required fact is removed or reworded)."""
    body = _section(_text(), "② operations")
    assert "Điền khi P5-T04 merge" not in body, "the DEC-151 stub line is still in the section"
    missing = [(what, needle) for what, needle in TWO_CIRCLE_REQUIRED_FACTS if needle not in body]
    assert not missing, "## ② operations no longer states: " + "; ".join(
        f"{what} (expected {needle!r})" for what, needle in missing
    )
    # P14-T08: it used to say "Two different things wear the same label" and "the model's own answer"
    assert "Two different things wear the same label" not in body
    assert "**the model's own answer**" not in body


CONFIG_PATH = REPO_ROOT / "backend" / "app" / "infra" / "config.py"


def test_two_circle_operations_defaults_match_config():
    """The three defaults the section quotes (`CASE_PROMPT_BUDGET_TOKENS` 60,000,
    `ANALYZE_QUOTA_PER_USER_DAY` 30, `LLM_MONTHLY_USD_CAP` 30) and the 2 x 120 < 300
    relation are read from `config.py` as text, so a changed default fails here instead
    of leaving the runbook quoting the old one. Pure: no import of the product."""
    config = CONFIG_PATH.read_text(encoding="utf-8")

    def default(name: str) -> int:
        m = re.search(rf"^    {name}: int = ([\d_]+)$", config, re.MULTILINE)
        assert m, f"no `{name}: int = <default>` field in {CONFIG_PATH}"
        return int(m.group(1).replace("_", ""))

    body = _section(_text(), "② operations")
    assert default("CASE_PROMPT_BUDGET_TOKENS") == 60_000 and "default 60,000" in body
    assert default("ANALYZE_QUOTA_PER_USER_DAY") == 30 and "(default 30)" in body
    assert default("LLM_MONTHLY_USD_CAP") == 30 and "`LLM_MONTHLY_USD_CAP`, default 30" in body
    assert default("JOB_MAX_ATTEMPTS") == 3 and "`JOB_MAX_ATTEMPTS` (3)" in body
    assert 2 * default("LLM_TIMEOUT_S") < default("JOB_LOCK_TIMEOUT_S"), (
        "the defaults no longer satisfy 2 x LLM_TIMEOUT_S < JOB_LOCK_TIMEOUT_S, "
        "which the section states as a rule"
    )


HANDLERS_DIR = REPO_ROOT / "backend" / "app" / "web" / "handlers"
JOB_TYPE_RE = re.compile(r'^JOB_TYPE = "([a-z_]+)"$', re.MULTILINE)


def _handler_job_types() -> list[str]:
    """Every `JOB_TYPE = "..."` declared in `backend/app/web/handlers/`, read as text."""
    found = []
    for path in sorted(HANDLERS_DIR.glob("*.py")):
        if path.name == "__init__.py":
            continue
        m = JOB_TYPE_RE.search(path.read_text(encoding="utf-8"))
        if m:
            found.append(m.group(1))
    return found


def test_start_and_stop_lists_every_worker_handler():
    """Stale once P5-T04 merged (Director 1's follow-up to the ② addendum):
    `## Start and stop` must name every `JOB_TYPE` in `backend/app/web/handlers/` and
    must not say a handler is still to come."""
    job_types = _handler_job_types()
    assert "investigate" in job_types, f"no handler declares JOB_TYPE 'investigate': {job_types}"
    start_and_stop = _section(_text(), "Start and stop")
    # The list itself ("`worker` runs the `a`, `b` and `c` jobs"), not the parenthesis after
    # it, which may mention a job type without listing it.
    lists = re.findall(r"`worker` runs the (.*?) jobs", start_and_stop)
    assert len(lists) == 1, "expected exactly one '`worker` runs the ... jobs' list"
    missing = [j for j in job_types if f"`{j}`" not in lists[0]]
    assert not missing, f"## Start and stop does not list the worker handlers: {missing}"
    assert "joins once" not in start_and_stop, "## Start and stop still says a handler is to come"


def test_environment_keys_rows_for_the_two_circle_settings_name_their_readers():
    """The `CASE_PROMPT_BUDGET_TOKENS` and `ANALYZE_QUOTA_PER_USER_DAY` rows said "read by
    nothing" until P5-T04 merged. They must now name the files that read them, and those
    files must still mention the key (so the row cannot go stale a second time)."""
    rows = {
        row[0]: row[1] for row in _table_rows(_section(_text(), "Environment keys")) if len(row) > 1
    }
    readers_by_key = {
        "CASE_PROMPT_BUDGET_TOKENS": ["tier2/dossier.py"],
        "ANALYZE_QUOTA_PER_USER_DAY": ["web/routers/tier2_runs.py"],
    }
    for key, readers in readers_by_key.items():
        what = rows.get(f"`{key}`")
        assert what is not None, f"## Environment keys has no row for {key}"
        assert "read by nothing" not in what, f"{key}: still says 'read by nothing': {what}"
        for reader in readers:
            assert reader in what, f"{key}: the row does not name {reader}: {what}"
            source = (REPO_ROOT / "backend" / "app" / reader).read_text(encoding="utf-8")
            assert key in source, f"{reader} no longer reads {key} — the row is stale again"
