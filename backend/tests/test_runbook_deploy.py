"""`docs/runbook.md` — the `## Admin console v1.1 — deploy (DEC-205)` block, and the two other
documents that say how a database is brought to the same migration (P11-T20 part 4, finding I2
of the whole-branch review).

WHY A TEST FOR A DOCUMENT. v1.1's code reads what migration 019 creates (`settings`,
`users.last_login_at`). Run on the 018 schema it fails closed: every login is a 500, every ①
run in the window is recorded `stopped_by='cap'` and loses its suggestion, ② answers 503 and
the health alarm fires. Nothing in the code can stop an operator who restarts a container
before `make migrate`; the only guard is that the document the Owner follows says the right
order, so a test holds the order: an edit that moves a step, drops the check that 019 is in, or
loses the sentence on what the wrong order breaks, fails `make test` and not a Tuesday morning.

WHAT IT PINS. The five steps of the block, in order, one table row each, with the command and
the output it expects; that the migration count they expect is the number of migration files;
the sentence on an early restart, and the rollback note; the React console's address in the
UI section; and that `docs/db-docker.md` and `docs/migration-runbook.md` start the database,
migrate, and only then start the application, as the block does. It does not judge prose.

PURE. No database, no socket: `python3 -m pytest -c backend/pyproject.toml
backend/tests/test_runbook_deploy.py` runs anywhere the repository is checked out.
"""

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNBOOK = REPO_ROOT / "docs" / "runbook.md"
DB_DOCKER = REPO_ROOT / "docs" / "db-docker.md"
MIGRATION_RUNBOOK = REPO_ROOT / "docs" / "migration-runbook.md"
SCHEMA_DIR = REPO_ROOT / "docs" / "Schema"

HEADING = "## Admin console v1.1 — deploy (DEC-205)"

#: The five steps, in the order DEC-205 item 2 gives them: the command each row carries, and
#: what that row says to expect (None: nothing a test can hold the row to).
STEPS: list[tuple[str, str, str | None]] = [
    ("1", "git merge --ff-only director/admin-v1-1", "Fast-forward"),
    # 020 (P13-T01, DEC-210) is the newest migration: a database already at 019 applies one.
    ("2", "make migrate PY=.venv/bin/python", "migrate: 1 applied, 19 already present"),
    (
        "3",
        'psql "$DATABASE_URL_OWNER" -Atc "select count(*) from schema_migrations"',
        "`20`",
    ),
    ("4", "docker compose up -d --build ui", None),
    ("5", "docker compose restart app worker", None),
]


def _text(path: pathlib.Path = RUNBOOK) -> str:
    assert path.exists(), f"{path} does not exist"
    return path.read_text(encoding="utf-8")


def _section(text: str, heading: str = HEADING) -> str:
    """The body after `heading`, up to the next `## ` heading. The heading must be there once."""
    starts = [m.start() for m in re.finditer(rf"^{re.escape(heading)}$", text, re.MULTILINE)]
    assert len(starts) == 1, f"expected exactly one {heading!r} heading, found {len(starts)}"
    body = text[starts[0] + len(heading) :]
    following = re.search(r"^## ", body, re.MULTILINE)
    return body if following is None else body[: following.start()]


def _cells(row: str) -> list[str]:
    """The cells of a table row; `\\|` inside a cell is a literal pipe."""
    return [c.strip() for c in re.split(r"(?<!\\)\|", row.strip())[1:-1]]


def _rows(section: str) -> list[list[str]]:
    """Every data row of the section's tables (not the header and not the `---` rule)."""
    rows = []
    for line in section.splitlines():
        if not line.startswith("|"):
            continue
        cells = _cells(line)
        if cells and not set("".join(cells)) <= set("-: ") and cells[0] != "step":
            rows.append(cells)
    return rows


def _step_rows(section: str) -> list[list[str]]:
    return [r for r in _rows(section) if r[0][:1].isdigit()]


def _migration_files() -> int:
    return len(list(SCHEMA_DIR.glob("[0-9][0-9][0-9]_*.sql")))


# --------------------------------------------------------------------------- the block


def test_the_block_exists_once_and_is_a_section_of_its_own():
    assert HEADING in _text()
    assert _section(_text()).strip()


def test_the_five_steps_are_there_in_order_one_row_each():
    rows = _step_rows(_section(_text()))
    assert [r[0].split()[0] for r in rows] == [n for n, _, _ in STEPS], rows
    for row, (number, command, _) in zip(rows, STEPS, strict=True):
        assert len(row) == 3, f"step {number} is not a three-cell row: {row}"
        assert command in row[1], f"step {number}'s command cell is {row[1]!r}, not {command!r}"


def test_a_command_is_in_exactly_one_row_so_no_step_is_listed_twice():
    section = _section(_text())
    for _, command, _ in STEPS:
        assert section.count(command) >= 1, command
        rows_with_it = [r for r in _step_rows(section) if command in r[1]]
        assert len(rows_with_it) == 1, f"{command!r} is in {len(rows_with_it)} step rows"


@pytest.mark.parametrize(("number", "command", "expected"), [s for s in STEPS if s[2]])
def test_a_step_says_what_to_expect(number, command, expected):
    row = next(r for r in _step_rows(_section(_text())) if r[0].startswith(number))
    assert expected in row[2], f"step {number} expects {row[2]!r}, not {expected!r}"


def test_the_expected_counts_are_the_number_of_migration_files():
    """`1 applied, 18 already present` and `19` are one count seen from two sides: the files in
    `docs/Schema`. A migration 020 makes this fail until the block is updated."""
    total = _migration_files()
    rows = _step_rows(_section(_text()))
    assert f"1 applied, {total - 1} already present" in rows[1][2]
    assert f"`{total}`" in rows[2][2]


def test_step_3_stops_the_operator_until_the_count_holds():
    row = _step_rows(_section(_text()))[2]
    assert "Do not go on before this holds" in row[2]


def test_the_check_reads_the_count_without_printing_a_dsn():
    section = _section(_text())
    assert '"$DATABASE_URL_OWNER"' in section
    assert not re.search(r"postgres(ql)?://", section), "a DSN is written in the block"
    assert "-Atc" in section  # tuples only, no header, no alignment: the count and nothing else


def test_step_4_comes_after_the_check_and_says_why():
    """`up -d --build ui` can recreate `app` on the new code, so it may not precede step 3."""
    section = _section(_text())
    rows = _step_rows(section)
    assert "can recreate `app`" in rows[3][2]
    assert "step 3" in rows[3][2]
    assert section.index(rows[2][1]) < section.index(rows[3][1])


def test_the_block_says_what_a_restart_before_the_migration_breaks():
    section = _section(_text())
    sentence = next(
        (p for p in section.split("\n\n") if p.startswith("**What an app restart before step 2")),
        None,
    )
    assert sentence is not None, "the paragraph on an early restart is gone"
    for needle in (
        "every login fails",
        "last_login_at",
        "`stopped_by='cap'`",
        "② answers 503",
        "health check fails",
    ):
        assert needle in sentence, f"the early-restart paragraph no longer says {needle!r}"
    for command in ("restart app", "up -d --build ui"):
        assert command in sentence, f"it no longer names {command!r} as what not to run first"


def test_the_block_has_a_rollback_note_with_the_two_facts():
    section = _section(_text())
    note = next((p for p in section.split("\n\n") if p.startswith("**Rollback.**")), None)
    assert note is not None, "the rollback note is gone"
    assert "`019` stays under the old code" in note
    assert "ignored" in note and "`.env`" in note  # the web limits are ignored; the cap is `.env`'s


# --------------------------------------------------------------------------- the other places


def test_the_ui_section_says_where_the_react_console_is_and_that_the_jinja_pages_went():
    """On the v1.1 tip this said the Jinja pages stay on port 8000 until the retire step; on the
    retire branch (P11-T19) the retire step is part of the tree, so it says they went with it."""
    ui = _section(_text(), "## UI (service `ui`)")
    assert "`http://127.0.0.1:8080/admin`" in ui
    assert "went with the retire step" in ui
    for page in ("overview", "users", "llm", "rules", "digest", "labels", "audit"):
        assert f"`/admin/{page}`" in ui, page


def test_start_everything_and_the_restart_row_send_the_reader_to_the_block():
    text = _text()
    start = next(line for line in text.splitlines() if line.startswith("| start everything"))
    assert "the order is `make db-up`, `make migrate`, `make up`" in start
    assert "**before** `app` and `worker` run the v1.1 code" in start
    restart = next(line for line in text.splitlines() if line.startswith("| restart |"))
    assert "Admin console v1.1 — deploy" in restart and "migrate first" in restart


def _order_in(text: str, commands: list[str]) -> None:
    positions = []
    for command in commands:
        found = [m.start() for m in re.finditer(rf"^{re.escape(command)}", text, re.MULTILINE)]
        assert found, f"{command!r} is not at the start of a line"
        positions.append(found[0])
    assert positions == sorted(positions), f"{commands} are out of order"


def test_db_docker_migrates_before_it_starts_the_application():
    """`docs/db-docker.md`'s fresh-machine restore: `make up` first would run the v1.1 code on the
    dump's 017 or 018 schema until `make migrate` ran."""
    section = _text(DB_DOCKER).split("## Restore on a fresh machine")[1].split("\n## ")[0]
    _order_in(section, ["make db-up", "make migrate", "make up"])


def test_migration_runbook_migrates_before_it_starts_the_application():
    """`docs/migration-runbook.md` 3.4 then 3.5: `make db-up`, `make migrate`, then `make up`."""
    text = _text(MIGRATION_RUNBOOK)
    section = text.split("### 3.4")[1].split("### 3.6")[0]
    _order_in(section, ["make db-up", "make migrate", "make up"])


def test_no_document_tells_the_reader_to_migrate_after_make_up():
    """The runbook's own `Then make migrate` after `make up`, the wording that sent a reader to
    the wrong order, is gone from every place that said it."""
    for path in (RUNBOOK, DB_DOCKER, MIGRATION_RUNBOOK):
        assert "Then `make migrate` brings" not in _text(path), path.name
