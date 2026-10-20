"""P11-T19 (DEC-205) — `docs/runbook.md`, the `## Admin console` section: where the admin console is,
and the Owner's two ordered steps (the v1.1 deploy, then the retire step).

The order is the point. DEC-205 item 2: fast-forward `main` to `director/admin-v1-1`, then `make
migrate`, then `docker compose up -d --build ui`, then `docker compose restart app worker`; migrate
before the restart, or login breaks (`users.last_login_at`) and every model call stops (the limits
accessor fails closed). Later, fast-forward `main` to `director/admin-v1-1-retire` and `docker
compose restart app worker`: a code-only change, no migration and no UI rebuild. A runbook that
swaps two of those would be followed to the letter by the one person who runs it.

Also pinned: no liveness check of the stack uses a page that port 8000 no longer has.

No database; reads the one file.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RUNBOOK = Path(__file__).resolve().parents[2] / "docs" / "runbook.md"


def _text() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def _section() -> str:
    text = _text()
    start = text.index("\n## Admin console\n")
    end = text.index("\n## ", start + 1)
    return text[start:end]


def _row(first_cell: str) -> str:
    rows = [ln for ln in _section().splitlines() if ln.startswith(f"| {first_cell}")]
    assert len(rows) == 1, f"expected one row starting {first_cell!r}, found {len(rows)}"
    return rows[0]


def test_the_admin_console_is_on_port_8080_under_admin() -> None:
    section = _section()
    assert "`http://<host>:8080/admin`" in section
    # and the section says what port 8000 serves now
    assert "`/api/*`, `POST /webhook/alerts` and `GET /health`" in section
    assert "renders no page" in section


def test_the_v1_1_deploy_runs_in_the_order_of_dec_205_and_migrates_before_the_restart() -> None:
    row = _row("**1. v1.1 deploy**")
    order = [
        "fast-forward `main` to `director/admin-v1-1`",
        "`make migrate`",
        "`docker compose up -d --build ui`",
        "`docker compose restart app worker`",
    ]
    positions = [row.index(step) for step in order]
    assert positions == sorted(positions), dict(zip(order, positions))
    assert "Migrate before the restart" in row
    assert "last_login_at" in row and "fails closed" in row  # the two things the wrong order breaks


def test_the_retire_step_is_a_fast_forward_and_a_restart_and_nothing_else() -> None:
    row = _row("**2. retire step**")
    command = row.split("|")[2]
    assert "fast-forward `main` to `director/admin-v1-1-retire`" in command
    assert command.index("director/admin-v1-1-retire") < command.index(
        "`docker compose restart app worker`"
    )
    for forbidden in ("make migrate", "--build", "docker compose up"):
        assert forbidden not in command, forbidden
    assert "no migration and no `ui` rebuild" in row


def test_the_retire_step_comes_after_the_v1_1_deploy_and_the_use_of_the_react_pages() -> None:
    section = _section()
    deploy = section.index("**1. v1.1 deploy**")
    use = section.index("*use the React pages*")
    retire = section.index("**2. retire step**")
    assert deploy < use < retire


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
