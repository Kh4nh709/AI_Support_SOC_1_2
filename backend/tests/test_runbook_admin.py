"""P11-T19 (DEC-205) — `docs/runbook.md`: the console's address, and the Owner's TWO steps as one
procedure, in order.

One story, not two. The deploy block (`## Admin console v1.1 — deploy (DEC-205)`, held row by row
by `test_runbook_deploy.py`) is the first Owner step; the retire step of this branch is the
second, in the same block, after the gate. This file pins the whole order across both:
fast-forward `main` to `director/admin-v1-1`, `make migrate`, the check that 19 migrations are in,
`docker compose up -d --build ui`, `docker compose restart app worker`; the Owner uses the React
pages; then fast-forward `main` to `director/admin-v1-1-retire` and `docker compose restart app
worker`: a code-only change, no migration and no UI rebuild. A runbook that swaps two of those
would be followed to the letter by the one person who runs it.

It also pins that the steps are written once (the `## Admin console` section points to the block
and repeats none), and that no liveness check of the stack uses a page port 8000 no longer has.

No database; reads the one file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RUNBOOK = Path(__file__).resolve().parents[2] / "docs" / "runbook.md"
BLOCK = "## Admin console v1.1 — deploy (DEC-205)"
CONSOLE = "## Admin console"


def _text() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def _section(heading: str) -> str:
    """The body after the `heading` line, up to the next `## ` heading; the heading is there once."""
    text = _text()
    starts = [m.end() for m in re.finditer(rf"^{re.escape(heading)}$", text, re.MULTILINE)]
    assert len(starts) == 1, f"expected one {heading!r} heading, found {len(starts)}"
    following = re.search(r"^## ", text[starts[0] :], re.MULTILINE)
    return text[starts[0] :] if following is None else text[starts[0] :][: following.start()]


def _retire_row() -> str:
    rows = [ln for ln in _section(BLOCK).splitlines() if ln.startswith("| **retire step**")]
    assert len(rows) == 1, f"expected one retire-step row in the deploy block, found {len(rows)}"
    return rows[0]


def test_the_admin_console_is_on_port_8080_under_admin() -> None:
    section = _section(CONSOLE)
    assert "`http://<host>:8080/admin`" in section
    # and the section says what port 8000 serves now
    assert "`/api/*`, `POST /webhook/alerts` and `GET /health`" in section
    assert "renders no page" in section


def test_the_two_owner_steps_are_one_procedure_in_dec_205s_order() -> None:
    block = _section(BLOCK)
    in_order = [
        "git merge --ff-only director/admin-v1-1` (on `main`)",  # the v1.1 deploy, rows 1 to 5
        "make migrate PY=.venv/bin/python",
        'select count(*) from schema_migrations"',
        "docker compose up -d --build ui",
        "docker compose restart app worker",  # row 5
        "the gate of spec §8",  # the Owner uses the React pages
        "fast-forward `main` to `director/admin-v1-1-retire`",  # the retire step
    ]
    positions = [block.index(step) for step in in_order]
    assert positions == sorted(positions), dict(zip(in_order, positions))
    # the retire step's own restart comes after its fast-forward, in its own row
    row = _retire_row()
    assert row.index("director/admin-v1-1-retire") < row.index(
        "`docker compose restart app worker`"
    )
    assert positions[-1] == block.index(row) + row.index("fast-forward")


def test_the_retire_step_is_a_fast_forward_and_a_restart_and_nothing_else() -> None:
    row = _retire_row()
    command = row.split("|")[2]
    assert "fast-forward `main` to `director/admin-v1-1-retire`" in command
    for forbidden in ("make migrate", "--build", "docker compose up"):
        assert forbidden not in command, forbidden
    assert "no migration and no `ui` rebuild" in row


def test_the_retire_step_waits_for_the_deploy_and_the_migration_count() -> None:
    block = _section(BLOCK)
    paragraph = next(p for p in block.split("\n\n") if p.startswith("**The retire step"))
    assert "only after the deploy above" in paragraph
    assert "reads `19`" in paragraph  # stacked on v1.1: it carries all of v1.1's code


def test_the_steps_are_written_once() -> None:
    """The `## Admin console` section points to the block and carries no copy of the commands, and
    each command of the release is in the block only (not in the `UI` or the `Admin console`
    sections, which may name a branch but never give the command)."""
    text = _text()
    assert "git merge --ff-only director/admin-v1-1" in _section(BLOCK)
    assert text.count("git merge --ff-only director/admin-v1-1") == 1
    assert text.count("fast-forward `main` to `director/admin-v1-1-retire`") == 1
    console = _section(CONSOLE)
    for command in ("make migrate", "docker compose up -d --build ui", "docker compose restart"):
        assert command not in console, f"the Admin console section repeats {command!r}"
    assert BLOCK.removeprefix("## ") in console  # and it says where the steps are


@pytest.mark.parametrize(
    "first_cells", ["**up?** `app` |", "h |"], ids=["start-and-stop up? app", "pilot row h"]
)
def test_no_liveness_check_of_the_app_uses_the_page_port_8000_no_longer_has(
    first_cells: str,
) -> None:
    lines = [ln for ln in _text().splitlines() if ln.startswith(f"| {first_cells}")]
    assert len(lines) == 1, (first_cells, len(lines))
    line = lines[0]
    assert "127.0.0.1:8000/api/auth/me" in line
    assert "127.0.0.1:8000/login" not in line


def test_no_curl_asks_port_8000_for_a_page_except_to_expect_the_404() -> None:
    """A `curl` of `:8000/login` or `:8000/admin…` in the runbook is only ever the check that the
    page is GONE (the retire step's `404`), never a way to see the stack is up."""
    bad = []
    for number, line in enumerate(_text().splitlines(), start=1):
        for match in re.finditer(r"curl[^`|]*?:8000/(login|logout|admin)[^`|]*", line):
            if "`404`" not in line:
                bad.append((number, match.group(0)))
    assert bad == []
