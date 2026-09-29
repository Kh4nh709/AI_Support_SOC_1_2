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
"""

import pathlib
import re

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
# Every `CheckResult(...)` call in infra/health.py names its check first,
# either on the same line or (the multi-line early-return form) the next one.
CHECK_RESULT_RE = re.compile(r'CheckResult\(\s*"([a-z_]+)"')
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


def _health_check_names() -> set[str]:
    text = HEALTH_PATH.read_text(encoding="utf-8")
    names = set(CHECK_RESULT_RE.findall(text))
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


def test_alarms_heading_appears_once():
    assert _text().count("## Alarms") == 1


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
    assert _text().count("## Restore drill (P8)") == 1


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
    assert "dropdb" in section and "soc_restore_drill" in section, "no clean-up rule"


def test_two_circle_operations_heading_present_with_some_content():
    """Tolerant on purpose (Director 1's follow-up fills this in once
    P5-T04 merges, DEC-151): today it must be the one-line DEC-151 stub, but
    this assertion only requires the heading to exist once with a non-empty
    body, so a later real ② write-up does not have to touch this test."""
    text = _text()
    assert text.count("## ② operations") == 1
    body = _section(text, "② operations").strip()
    assert body, "## ② operations has no content — at least the DEC-151 stub line is required"


def test_two_circle_operations_is_today_the_dec_151_stub():
    """Today's actual content, not just "non-empty" — separated from the
    tolerant test above so this one, and only this one, needs to change
    when P5-T04 merges and Director 1's follow-up fills the section in."""
    body = _section(_text(), "② operations").strip()
    assert body == "Điền khi P5-T04 merge (DEC-151).", body
