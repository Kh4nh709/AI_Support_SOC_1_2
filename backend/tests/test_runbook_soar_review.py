"""SR-T1 fix round 1 (m9) — the runbook says the new migration count where it describes the CURRENT state, and leaves the PAST
procedure as it was.

The P14 deploy of the Voyage RAG (step 3, step 7) is a procedure that was written and run when the database held 24 migrations: it
says `021 to 024`, `4 applied, 20 already present` and a count of `24`. Migration 025 (the SOAR review tickets) came after it, so the
number 25 belongs to the rows that describe the state of the system now ("start everything", the pilot's precondition b) and to the new
section of the feature; it does not rewrite a procedure that was carried out. Pure: reads `docs/runbook.md`.
"""

from __future__ import annotations

import pathlib
import re

RUNBOOK = pathlib.Path(__file__).resolve().parents[2] / "docs" / "runbook.md"


def _text() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def _step(number: int) -> str:
    """One step of the Voyage deploy procedure, from its bold number to the next one."""
    text = _text()
    match = re.search(rf"(?m)^\*\*{number} · .*?(?=^\*\*{number + 1} · |^## |\Z)", text, re.DOTALL)
    assert match, f"step {number} of the Voyage procedure is gone"
    return match.group(0)


def _section() -> str:
    text = _text()
    assert "\n## SOAR review tickets on the web (SR-T1)\n" in text
    return text.split("\n## SOAR review tickets on the web (SR-T1)\n", 1)[1].split("\n## ", 1)[0]


def test_the_past_p14_procedure_still_says_it_took_the_database_to_24():
    step3 = _step(3)
    assert "what 021 to 024 create" in step3
    assert "`migrate: 4 applied, 20 already present`" in step3
    assert "which records all 24" in step3 and "must be `24`" in step3
    assert "Do not go on before the count reads `24`" in step3
    assert (
        "025" not in step3
    ), "step 3 of the P14 procedure was rewritten for a migration that came after it"


def test_step_7_of_the_past_procedure_still_expects_24():
    step7 = _step(7)
    assert "go on only when it printed `24`" in step7
    assert "(24 migrations)" in step7
    assert "25" not in step7


def test_the_rows_that_describe_the_state_now_say_25():
    text = _text()
    start = next(line for line in text.splitlines() if line.startswith("| start everything |"))
    assert "brings the database to **25**" in start
    assert "`migrate: 0 applied, 25 already present` after that." in start
    precondition = next(
        line for line in text.splitlines() if line.startswith("| b | migrations current |")
    )
    assert "`25` (" in precondition and "025_soar_reviews.sql" in precondition


def test_the_start_everything_row_points_at_the_new_section_for_025_not_at_step_3():
    start = next(line for line in _text().splitlines() if line.startswith("| start everything |"))
    assert "SOAR review tickets on the web" in start
    assert "step 3 applies 021 to 024" in start


def test_the_new_section_says_how_025_reaches_a_database_that_has_the_p14_migrations():
    section = _section()
    assert "025_soar_reviews.sql" in section
    assert "migrate: applying 025_soar_reviews" in section
    assert "`migrate: 1 applied, 24 already present`" in section and "`25`" in section
    assert "docker compose up -d --force-recreate app" in section
    for key in (
        "SOAR_NOTICE_API_KEY",
        "SOAR_NOTICE_IP_ALLOWLIST",
        "N8N_APPROVAL_URL",
        "N8N_APPROVAL_SECRET",
    ):
        assert f"`{key}`" in section, key


def test_the_new_section_names_the_port_the_stand_in_and_the_checks():
    section = _section()
    assert (
        ":8001" in section and ":8081" in section
    )  # the app's port; the UI's, which must not be used
    assert "scripts/mock_n8n_approval.py" in section
    assert re.search(r"N8N_APPROVAL_SECRET=\S+ python3 scripts/mock_n8n_approval\.py", section)
    assert "--secret" not in section
    assert "soar_reviews" in section and "soar.review_decided" in section


def test_the_new_section_does_not_sit_inside_the_environment_keys_table():
    text = _text()
    keys = text.split("\n## Environment keys", 1)[1].split("\n## ", 1)[0]
    assert "SOAR review tickets on the web (SR-T1)" not in keys
