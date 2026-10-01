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
not judge prose. P8 extends the same file with its own sections: the structure, the
required strings, the two rules and the seed command are asserted inside `## Pilot`
only, so a P8 section that mentions `JWT_SECRET` cannot stand in for the Pilot section
losing it; the prohibitions apply to the whole file, as the card's acceptance-2 greps do.

PURE. No database, no socket, no fixture: `python3 -m pytest -c backend/pyproject.toml
backend/tests/test_runbook_pilot.py` runs anywhere the repository is checked out.
"""

import pathlib
import re
import unicodedata

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
    "Nhận xử lý",
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


def _mask_fences(text: str) -> str:
    """`text` with every line inside a ``` fence replaced by spaces of the same length, so a
    heading regex cannot match a bash comment such as `## step 2` inside a command block.
    Lengths and newlines are kept, so an index into the masked text is valid in `text`."""
    out, fenced = [], False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            out.append(" " * len(line))
        else:
            out.append(" " * len(line) if fenced else line)
    return "\n".join(out)


def _pilot_section(text: str) -> str:
    """The body from `## Pilot` to the next `## ` heading (or EOF), fences ignored for headings."""
    heads = [m for m in H2_RE.finditer(_mask_fences(text))]
    pilot = [m for m in heads if m.group(1).strip() == "Pilot"]
    assert len(pilot) == 1, f"expected exactly one '## Pilot' heading, found {len(pilot)}"
    start = pilot[0].start()
    later = [m.start() for m in heads if m.start() > start]
    end = later[0] if later else len(text)
    return text[start:end]


def _subsections(section: str) -> list[str]:
    return [m.group(1).strip() for m in H3_RE.finditer(_mask_fences(section))]


def _first_word(heading: str) -> str:
    words = heading.split()
    return words[0] if words else ""


def _subsection_body(section: str, number: str) -> str:
    """The body of the `### <number> …` subsection, up to the next `### `."""
    heads = list(H3_RE.finditer(_mask_fences(section)))
    for i, m in enumerate(heads):
        if _first_word(m.group(1)) == number:
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
    lines = _pilot_section(_text()).splitlines()
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
    numbered = [_first_word(s) for s in subs if _first_word(s).isdigit()]
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
    text = _pilot_section(_text())
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
    text = _pilot_section(_text())
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
    assert not re.search(
        r"JWT_SECRET=[\"']?[0-9A-Za-z]{16,}", text
    ), "a JWT_SECRET value is written"
    assert not re.search(r"postgres(ql)?://[^\s:/]+:[^@\s]+@", text), "a DSN with a password"
    assert not re.search(r"PGPASSWORD=\S+", text), "a PGPASSWORD value is written"


# ----------------------------------------------------- P10-T13, fix round 1: the React UI


def _precondition_row(label: str) -> list[str]:
    body = _subsection_body(_pilot_section(_text()), "1")
    rows = [row for row in _table_rows(body) if row and row[0] == label]
    assert len(rows) == 1, f"expected one precondition row {label!r}, found {len(rows)}"
    return rows[0]


def test_the_pilot_can_start_on_the_react_ui():
    """The Jinja queue and alert pages are gone (P10-T13): the app precondition must not wait for
    them, and a `ui` row must prove the React UI answers and its proxy reaches the app."""
    h = _precondition_row("h")
    assert "cannot start without" not in " ".join(h), f"row h still waits for P4-T05: {h}"
    assert "docker compose logs app" in h[3], "row h must say where the access log now is"

    ui = _precondition_row("ui")
    assert "docker compose up -d --build ui" in ui[2], ui
    assert "http://127.0.0.1:8080/" in ui[2], ui
    assert "http://127.0.0.1:8080/api/auth/me" in ui[2], ui
    assert "200" in ui[3] and "401" in ui[3], ui


def test_the_409_count_reads_the_containers_log_not_a_file_nothing_writes():
    """`make run-app` is `docker compose up -d --wait db app`; nothing pipes it into a file."""
    section = _pilot_section(_text())
    commands = re.findall(r"`([^`\n]+)`", section)
    for command in commands:
        assert "tee -a" not in command, f"a tee into a log file nothing writes any more: {command}"
        assert not re.search(r"grep\b.*pilot-app\.log", command), command
    limitations = _subsection_body(section, "7")
    assert re.search(r"docker compose logs[^`\n]*\bapp\b[^`\n]*\| grep -c [^`\n]*409", limitations)
    assert (
        "cookie is not `Secure`" not in limitations
    ), "the React UI's credential is a Bearer token"
    assert "Bearer token" in limitations


# ---------------------------------------------- P10-T13, fix round 2: the labels the pilot names
#
# The pilot text names what is on the analyst's screen ("presses Tiếp nhận"). That was the Jinja
# button; the React UI's is "Nhận xử lý", and no test went red. The React UI's words all live in
# `frontend/src/strings.ts`, so a label the runbook quotes must be one of them, verbatim.

STRINGS_TS = REPO_ROOT / "frontend" / "src" / "strings.ts"

# A label is written in the runbook in prose, in one of three ways: in quotes, plain "…" or curly “…”
# (with or without `*` or `**` around the quotes: the convention the section already had), or unquoted
# in bold, `**…**`. Code is never a label: a fenced block is dropped, and a span that holds an inline
# code span is skipped, so a `"` or a `**` inside a command cannot match, and neither can the advisor's
# rule, which quotes `llm_runs` (it is pinned verbatim by `test_advisor_rule_in_both_languages`).
PLAIN_QUOTE_RE = re.compile(r'"([^"\n]+)"')
CURLY_QUOTE_RE = re.compile("\u201c([^\u201d\n]+)\u201d")
BOLD_RE = re.compile(r"\*\*([^*\n]+)\*\*")
INLINE_CODE_RE = re.compile(r"`[^`\n]*`")
CODE = "\x00"  # stands for an inline code span in the prose

# Quoted and on no screen: a sentence quoted from the architecture, the wording the P8 report attaches
# to the visible-branch numbers, a line of STATE.md that the seed step names, and a scare quote.
QUOTED_BUT_NOT_UI = [
    "Thí điểm trực tuyến … là mô tả, không phải kiểm định",
    "có thể thiên lệch",
    "20/09 — KIỂM 2/2",
    "fixes",
]

# An unquoted bold span is judged only when it is shaped like a label: at most this many words, no digit,
# no sentence ending, no code, and not a step id (`d1`, `a–f′`, `ui`). Bold that is shaped like one and is
# emphasis, not a label, is listed here by name (a new one is a one-line addition, and the test below
# keeps the list from outliving the text).
MAX_UNQUOTED_LABEL_WORDS = 4
STEP_ID_RE = re.compile(r"^[a-z][0-9]?\u2032?(\u2013[a-z][0-9]?\u2032?)?$|^ui$")
BOLD_NOT_UI = [
    "no",
    "blind branch",
    "never the file",
    "before",
    "itself",
    "Reopened alerts",
    "not audited",
    "from the primary checkout",
    "restarted after that merge",
    "(d) ⚑ beside a suggestion",
    "Leave the worker running",
]

# What the pilot text has to name, so that the extraction cannot pass by finding nothing.
LABELS_THE_PILOT_NAMES = ["Nhận xử lý", "ẩn — nhánh mù", "chưa có", "Đang phân tích…"]


def _nfc(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def _strings_ts_literals() -> set[str]:
    """Every double-quoted string literal of `strings.ts` outside a whole-line comment (a comment
    that quotes a word, `// "có thể", not "sẽ"`, is not a label)."""
    assert STRINGS_TS.is_file(), f"{STRINGS_TS} does not exist"
    code = [
        line
        for line in STRINGS_TS.read_text(encoding="utf-8").splitlines()
        if not line.lstrip().startswith(("//", "/*", "*"))
    ]
    literal = re.compile(r"\"((?:[^\"\\\n]|\\.)*)\"")
    return {_nfc(m.group(1)) for m in literal.finditer("\n".join(code))}


def _pilot_prose(text: str) -> str:
    """The Pilot section with every fenced block blanked and every inline code span replaced by `CODE`."""
    return INLINE_CODE_RE.sub(CODE, _mask_fences(_pilot_section(text)))


def _pilot_quoted_spans(text: str) -> list[str]:
    """Every span the Pilot section's prose puts in quotes, plain or curly (so `*"…"*` and `**"…"**`
    too), NFC, in reading order; one with code inside is not a label and is left out."""
    prose = _pilot_prose(text)
    spans = [m for rx in (PLAIN_QUOTE_RE, CURLY_QUOTE_RE) for m in rx.finditer(prose)]
    spans.sort(key=lambda m: m.start())
    return [_nfc(m.group(1).strip()) for m in spans if CODE not in m.group(1)]


def _pilot_bold_candidates(text: str) -> list[str]:
    """The unquoted bold spans of the Pilot section's prose that are shaped like a label."""
    found = []
    for m in BOLD_RE.finditer(_pilot_prose(text)):
        span = _nfc(m.group(1).strip())
        words = [w for w in span.split() if any(c.isalpha() for c in w)]
        if not span or CODE in span or '"' in span or "\u201c" in span:
            continue  # code is never a label; a quoted span is judged with the quotes
        if STEP_ID_RE.match(span) or span[-1] in ".:;!?" or any(c.isdigit() for c in span):
            continue
        if 0 < len(words) <= MAX_UNQUOTED_LABEL_WORDS:
            found.append(span)
    return found


def _pilot_ui_labels(text: str) -> list[str]:
    """The labels the pilot section quotes, minus the ones that are not on a screen."""
    not_ui = {_nfc(s) for s in QUOTED_BUT_NOT_UI}
    return [label for label in _pilot_quoted_spans(text) if label not in not_ui]


def _labels_missing_from_the_react_ui(text: str) -> list[str]:
    """What the Pilot section names as a label and `strings.ts` does not have: a quoted span, plain or
    curly, or an unquoted bold one that is shaped like a label and not listed in `BOLD_NOT_UI`."""
    known = _strings_ts_literals()
    emphasis = {_nfc(s) for s in BOLD_NOT_UI}
    missing = [label for label in _pilot_ui_labels(text) if label not in known]
    return missing + [
        span for span in _pilot_bold_candidates(text) if span not in known and span not in emphasis
    ]


def test_every_ui_label_the_pilot_names_is_a_string_the_react_ui_shows():
    missing = _labels_missing_from_the_react_ui(_text())
    assert (
        not missing
    ), f"the pilot section quotes labels that are not in frontend/src/strings.ts: {missing}"


def test_the_pilot_names_the_labels_it_is_supposed_to_and_finds_them_in_strings_ts():
    expected = {_nfc(label) for label in LABELS_THE_PILOT_NAMES}
    named = set(_pilot_ui_labels(_text()))
    assert expected <= named, f"no longer named in the pilot section: {sorted(expected - named)}"
    assert expected <= _strings_ts_literals(), "not in strings.ts any more"
    assert len(named) >= 10, f"the extraction found {len(named)} labels: {sorted(named)}"


# ---------------------------------------------- P10-T17 item 8d: the guard sees every way to write a label
#
# The extraction above found `*"…"*` and `**"…"**` only: a stale label written as plain "…", as curly “…”
# or as unquoted bold passed. These tests run the same guard on small runbooks of their own, one form at a
# time, so that a form it cannot see goes red here and not on the day (the real runbook is judged above).


def _pilot_runbook(body: str, after: str = "") -> str:
    return f"# Runbook\n\n## Pilot\n\n{body}\n\n## Next\n\n{after}\n"


STALE = "Tiếp nhận"  # the Jinja button; the React one is "Nhận xử lý"
CURRENT = "Nhận xử lý"

LABEL_FORMS = [
    pytest.param('presses *"{}"* to take it', id="italic-quoted"),
    pytest.param('presses **"{}"** to take it', id="bold-quoted"),
    pytest.param('presses "{}" to take it', id="plain-quoted"),
    pytest.param("presses \u201c{}\u201d to take it", id="curly-quoted"),
    pytest.param("presses **{}** to take it", id="unquoted-bold"),
    pytest.param("| row | presses **{}** | x |", id="unquoted-bold-in-a-table-cell"),
]


@pytest.mark.parametrize("form", LABEL_FORMS)
def test_a_stale_label_is_caught_in_every_form(form):
    text = _pilot_runbook(form.format(STALE))
    assert _labels_missing_from_the_react_ui(text) == [_nfc(STALE)]


@pytest.mark.parametrize("form", LABEL_FORMS)
def test_a_current_label_passes_in_every_form(form):
    assert _labels_missing_from_the_react_ui(_pilot_runbook(form.format(CURRENT))) == []


@pytest.mark.parametrize(
    "body",
    [
        pytest.param('run `grep "{0}" file` first', id="in-a-code-span"),
        pytest.param("run `echo **{0}**` first", id="bold-in-a-code-span"),
        pytest.param('```bash\necho "{0}"\necho **{0}**\n```', id="in-a-fenced-block"),
    ],
)
def test_a_label_in_code_is_not_a_label(body):
    assert _labels_missing_from_the_react_ui(_pilot_runbook(body.format(STALE))) == []


def test_a_stale_label_outside_the_pilot_section_is_not_judged():
    text = _pilot_runbook("nothing here", after=f'presses "{STALE}" and **{STALE}**')
    assert _labels_missing_from_the_react_ui(text) == []


@pytest.mark.parametrize(
    "emphasis",
    [
        "d1",  # a step id
        "a\u2013f\u2032",  # a range of step ids
        "ui",
        "That first decision is the pilot start.",  # a sentence
        "Pause or stop the pilot:",
        "26/09/2026 (P8-T03)",  # a date, a card
        "3,941",
        "run block 1f below once",  # digits
        "Restart the worker after every merge that touches the file",  # longer than a label
        "UI (service `ui`)",  # code in it: never a label
    ],
)
def test_bold_that_is_not_shaped_like_a_label_is_not_judged(emphasis):
    assert _labels_missing_from_the_react_ui(_pilot_runbook(f"**{emphasis}** in prose")) == []


def test_a_short_bold_phrase_that_is_not_a_ui_string_is_judged_unless_it_is_listed():
    assert _labels_missing_from_the_react_ui(_pilot_runbook("**Quite new**")) == ["Quite new"]
    listed = BOLD_NOT_UI[0]
    assert _labels_missing_from_the_react_ui(_pilot_runbook(f"**{listed}**")) == []


def test_a_quote_on_no_screen_is_listed_by_name_and_the_listing_is_not_dead():
    """Every entry of the two allow-lists is quoted (or bold) in the real Pilot section, so an entry that
    nothing uses any more (the advisor's rule had two, which the old pattern could never match) fails here.
    """
    text = _text()
    quoted = set(_pilot_quoted_spans(text))
    bold = set(_pilot_bold_candidates(text))
    dead = [e for e in QUOTED_BUT_NOT_UI if _nfc(e) not in quoted]
    dead += [e for e in BOLD_NOT_UI if _nfc(e) not in bold]
    assert not dead, f"allow-listed, and not in the Pilot section as such: {dead}"
