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
— and `## ② operations` exists with *some* content, worded so a later
fill-in (once P5-T04 merges, DEC-151) does not have to touch this test.

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


def test_alarm_table_has_exactly_ten_rows_on_both_sides():
    assert len(_health_check_names()) == 10, sorted(_health_check_names())
    assert len(_alarm_table_check_names()) == 10, sorted(_alarm_table_check_names())


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
    """Tolerant on purpose (Director 1's follow-up fills this in once
    P5-T04 merges, DEC-151): today it must be the one-line DEC-151 stub, but
    this assertion only requires the heading to exist once with a non-empty
    body, so a later real ② write-up does not have to touch this test."""
    # Anchored on the heading line via _section (not a substring count —
    # see test_alarms_heading_appears_once), so a future prose
    # cross-reference to `` `## ② operations` `` elsewhere cannot break this.
    body = _section(_text(), "② operations").strip()
    assert body, "## ② operations has no content — at least the DEC-151 stub line is required"


def test_two_circle_operations_is_today_the_dec_151_stub():
    """Today's actual content, not just "non-empty" — separated from the
    tolerant test above so this one, and only this one, needs to change
    when P5-T04 merges and Director 1's follow-up fills the section in."""
    body = _section(_text(), "② operations").strip()
    assert body == "Điền khi P5-T04 merge (DEC-151).", body
