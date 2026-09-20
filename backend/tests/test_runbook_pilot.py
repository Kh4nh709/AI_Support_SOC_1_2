"""`docs/runbook.md` — the `## Pilot` section a person executes on 23–24/09 (P4-T07).

WHY A TEST FOR A DOCUMENT. The pilot checklist is the one artifact the Owner and the
advisor act on without an agent in the loop (context pack §11): if a precondition loses
its proof command, if the advisor's rule loses one of its two languages, or if the seed
command quietly grows a `--password` flag, nobody's test goes red — the pilot just starts
wrong. This file pins the structure the card asks for, so an edit that drops a piece
fails `make test` instead of failing on the day.

WHAT IT PINS, AND WHAT IT LEAVES ALONE. Headings, the preconditions table's shape, a
handful of literal strings the card names, the two quoted rules verbatim, and three
prohibitions: no file-based alert check (DEC-091 — the file is unreadable to `user1`
and the application never reads it), no indexer value restated (DEC-070 — the checklist
reads `$INDEXER_URL` from `.env`), and no password on a command line (DEC-095). It does
not judge prose. P8 extends the same file with its own sections; this test looks only
inside `## Pilot`.

PURE. No database, no socket, no fixture: `python3 -m pytest -c backend/pyproject.toml
backend/tests/test_runbook_pilot.py` runs anywhere the repository is checked out.
"""

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNBOOK_PATH = REPO_ROOT / "docs" / "runbook.md"

# The two sentences the Owner says aloud to the advisor before the pilot (card design
# note 4). Verbatim, backticks included — a paraphrase is not the rule.
ADVISOR_RULE_VI = (
    "Quyết trước; không bao giờ mở `llm_runs`, không hỏi ① đã nói gì, trước khi bấm quyết "
    "định. Khoảng một nửa alert không hiện gợi ý — đó là thiết kế, không phải lỗi."
)
ADVISOR_RULE_EN = (
    "Decide first; never open `llm_runs` or ask what ① said before you press decide. "
    "About half the alerts show no suggestion — by design, not a bug."
)

# Literal strings the card requires at least once (design note 10). The filter sentence
# may be in either language, so it is a tuple of alternatives.
REQUIRED_STRINGS = [
    "JWT_SECRET",
    "make run-worker",
    "source_cursor",
    "seed-users",
    "make run-app",
    "127.0.0.1:8000/login",
    "Tiếp nhận",
    "llm_runs",
    "source='lab'",
    "alert.reopened",
    "383",
    "HR-computer",
    ("not a reason to add a filter", "không phải lý do để thêm bộ lọc"),
    "Secure",
    "REVIEW_DELTA_TOLERANCE",
]

# DEC-091: the manager's alert file is never a check. Any spelling of its path is out.
FILE_CHECK_FORBIDDEN = ["alerts.json", "/var/ossec/logs/alerts", "/data/wazuh/logs"]

# DEC-070: no indexer value is restated in any P4 artifact; `.env` is the only source.
INDEXER_VALUE_FORBIDDEN = ["wazuh.indexer", "127.0.0.1:19200", "9400"]

H2_RE = re.compile(r"^## (.*)$", re.MULTILINE)
H3_RE = re.compile(r"^### (.*)$", re.MULTILINE)
TABLE_ROW_RE = re.compile(r"^\|.*\|\s*$")
# A cell boundary is an unescaped pipe; `\|` inside a cell is a literal pipe (GFM tables),
# which psql's `-A` output (`4|2`) and a `2>&1 | tee` command both need.
CELL_SPLIT_RE = re.compile(r"(?<!\\)\|")


def _text() -> str:
    assert RUNBOOK_PATH.exists(), f"{RUNBOOK_PATH} does not exist"
    return RUNBOOK_PATH.read_text(encoding="utf-8")


def _pilot_section(text: str) -> str:
    """The body from `## Pilot` to the next `## ` heading (or EOF)."""
    heads = [m for m in H2_RE.finditer(text)]
    pilot = [m for m in heads if m.group(1).strip() == "Pilot"]
    assert len(pilot) == 1, f"expected exactly one '## Pilot' heading, found {len(pilot)}"
    start = pilot[0].start()
    later = [m.start() for m in heads if m.start() > start]
    end = later[0] if later else len(text)
    return text[start:end]


def _subsections(section: str) -> list[str]:
    return [m.group(1).strip() for m in H3_RE.finditer(section)]


def _subsection_body(section: str, number: str) -> str:
    """The body of the `### <number> …` subsection, up to the next `### `."""
    heads = list(H3_RE.finditer(section))
    for i, m in enumerate(heads):
        if m.group(1).strip().split()[0] == number:
            end = heads[i + 1].start() if i + 1 < len(heads) else len(section)
            return section[m.end() : end]
    raise AssertionError(f"no '### {number} …' subsection in ## Pilot")


def _table_rows(body: str) -> list[list[str]]:
    """Every pipe-table row in `body` as a list of stripped cells (separator rows dropped)."""
    rows = []
    for line in body.splitlines():
        if not TABLE_ROW_RE.match(line):
            continue
        inner = line.strip()[1:-1]  # drop the leading and trailing pipe only
        cells = [c.strip().replace("\\|", "|") for c in CELL_SPLIT_RE.split(inner)]
        if all(re.fullmatch(r":?-{3,}:?", c) for c in cells):
            continue
        rows.append(cells)
    return rows


def _seed_commands() -> list[str]:
    """Every `python3 -m app.infra.auth seed-users` invocation that creates users, each with
    its `\\`-continued lines joined into one string. A `seed-users --help` probe is not one."""
    lines = _text().splitlines()
    found = []
    for i, line in enumerate(lines):
        if "python3 -m app.infra.auth seed-users" not in line:
            continue
        joined = [line.rstrip()]
        j = i
        while joined[-1].endswith("\\") and j + 1 < len(lines):
            j += 1
            joined.append(lines[j].rstrip())
        cmd = " ".join(part.rstrip("\\").strip() for part in joined)
        if "--user" in cmd:
            found.append(cmd)
    assert found, "no `python3 -m app.infra.auth seed-users … --user …` command in the runbook"
    return found


# --------------------------------------------------------------------------- tests


def test_header_says_p8_extends_this_file():
    head = _text().splitlines()[:3]
    assert head[0].startswith("# "), f"line 1 is not a title: {head[0]!r}"
    assert any(
        "P8" in line and "extend" in line for line in head
    ), "the first three lines must say P8 extends this file"


def test_pilot_section_and_eight_subsections_in_order():
    section = _pilot_section(_text())
    subs = _subsections(section)
    numbered = [s.split()[0] for s in subs if s and s.split()[0].isdigit()]
    # The card enumerates `0 …` through `8 …` and asks for them in order; its own
    # acceptance 2 counts `^### ` ≥ 9, so the enumeration (nine headings) is what is pinned.
    assert numbered == [str(n) for n in range(9)], f"numbered subsections out of order: {numbered}"
    assert len(subs) <= len(numbered) + 1, f"more than one unnumbered subsection: {subs}"
    for n in range(9):
        assert _subsection_body(section, str(n)).strip(), f"subsection {n} is empty"


def test_preconditions_table_rows_have_commands():
    body = _subsection_body(_pilot_section(_text()), "1")
    rows = _table_rows(body)
    assert rows, "no table in subsection 1"
    header = [c.lower() for c in rows[0]]
    assert header == ["#", "check", "command", "expected"], f"unexpected header: {rows[0]}"
    data = rows[1:]
    assert len(data) >= 8, f"preconditions table has {len(data)} rows, expected ≥ 8"
    command_col = header.index("command")
    for row in data:
        assert len(row) == 4, f"row does not have four cells: {row}"
        assert "`" in row[command_col], f"row {row[0]} has no pasteable command: {row}"


@pytest.mark.parametrize(
    "needle",
    REQUIRED_STRINGS,
    ids=[n if isinstance(n, str) else n[0] for n in REQUIRED_STRINGS],
)
def test_required_strings_present(needle):
    text = _text()
    alternatives = (needle,) if isinstance(needle, str) else needle
    assert any(alt in text for alt in alternatives), f"missing: {alternatives}"


def test_no_file_based_alert_check():
    text = _text()
    hits = [s for s in FILE_CHECK_FORBIDDEN if s in text]
    assert not hits, f"DEC-091: file-based alert check present: {hits}"


def test_no_indexer_value_restated():
    text = _text()
    hits = [s for s in INDEXER_VALUE_FORBIDDEN if s in text]
    assert not hits, f"DEC-070: indexer value restated: {hits}"


def test_advisor_rule_in_both_languages():
    text = _text()
    assert ADVISOR_RULE_VI in text, "the advisor's rule is missing in Vietnamese"
    assert ADVISOR_RULE_EN in text, "the advisor's rule is missing in English"


def test_seed_users_command_has_four_users_and_no_password():
    commands = _seed_commands()
    assert len(commands) == 1, f"the seed command should be written once, found {len(commands)}"
    cmd = commands[0]
    users = re.findall(r"--user\s+\S+\s+(tier1|tier2|admin)\b", cmd)
    assert len(users) >= 4, f"expected four --user triples, found {len(users)}: {cmd}"
    assert sorted(users) == ["admin", "admin", "tier1", "tier2"], users
    assert "--password" not in cmd, "a password never travels on argv (DEC-095)"
    assert "--env-file .env" in cmd, "the Owner runs it against .env's DSN (planning decision 12)"
    inline_env = re.findall(r"SEED_PASSWORD_\w*=", _text())
    assert not inline_env, f"inline SEED_PASSWORD_…= form lands in shell history: {inline_env}"


def test_no_secret_or_dsn_value():
    text = _text()
    assert not re.search(r"JWT_SECRET=[0-9A-Za-z]{16,}", text), "a JWT_SECRET value is written"
    assert not re.search(r"postgresql://[^\s:/]+:[^@\s]+@", text), "a DSN with a password"
