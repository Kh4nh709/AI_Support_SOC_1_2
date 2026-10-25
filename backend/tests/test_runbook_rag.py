"""`docs/runbook.md` — the `## Learned knowledge and RAG (DEC-210)` section, and the four other places
that say what P13 changed (P13-T09).

WHY A TEST FOR A DOCUMENT. The Owner switches learned knowledge on by hand, from this section, and no
agent runs a line of it. The order is part of the release, as it was for the admin console v1.1
(`test_runbook_deploy.py`): the database moves before any container runs the new code; the directory
exists, owned by the host user, before `docker compose up -d` (or Docker creates it as `root` and `app`
cannot write an entry file); the drafts are switched on first and the lookup only after the first
entries are approved; and after a `make db-restore` the files come back from the database with
`python -m app.rag.publish --rebuild`, not from a backup (backups are `pg_dump` only). A step moved, a
check dropped, or the rollback turned into something that deletes data fails `make test`, not a
Tuesday morning.

WHAT IT PINS. The nine steps in three blocks, in order, one table row each, with the command and the
output they expect; that the migration count they expect is the number of migration files up to
`020_learned_knowledge.sql`; the switch order and the `rag_budget` note; the checks, none of which prints
the environment or a DSN; the rollback, which removes nothing; the `make db-restore` order. Beside the
section: the pointer from **Backup and restore**, the four limitations of `docs/limitations.md`, the
context pack's package row (kind) and §6.2 note, and the `rag` package docstring. It does not judge
prose.

PURE. No database, no socket.
"""

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNBOOK = REPO_ROOT / "docs" / "runbook.md"
LIMITATIONS = REPO_ROOT / "docs" / "limitations.md"
PACK = REPO_ROOT / "docs" / "plan" / "00-context-pack.md"
RAG_INIT = REPO_ROOT / "backend" / "app" / "rag" / "__init__.py"
SCHEMA_DIR = REPO_ROOT / "docs" / "Schema"

HEADING = "## Learned knowledge and RAG (DEC-210)"
DSN = 'psql "$DATABASE_URL_OWNER" -Atc "select count(*) from schema_migrations"'

#: The nine steps, in the order the section gives them: the text each row's command cell carries, and
#: what the row says to expect (None: nothing a test can hold the row to).
STEPS: list[tuple[str, str, str | None]] = [
    ("1", "git merge --ff-only director/rag-knowledge", "Fast-forward"),
    ("2", "make migrate PY=.venv/bin/python", "migrate: 1 applied, 19 already present"),
    ("3", DSN, "`20`"),
    ("4", "mkdir kb_learned", "HOST_UID"),
    ("5", "COMPOSE_FILE=docker-compose.yml:docker-compose.rag.yml", "rag-worker"),
    ("6", "docker compose up -d", None),
    ("7", "KNOWLEDGE_DRAFT_ENABLED=true", "n/a — RAG off"),
    ("8", "knowledge_entries where status = 'active'", None),
    ("9", "RAG_ENABLED=true", "RAG_TRIAGE_DELAY_S"),
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
    return [c.strip() for c in re.split(r"(?<!\\)\|", row.strip())[1:-1]]


def _step_rows(section: str) -> list[list[str]]:
    """Every table row whose first cell starts with a digit: the numbered steps, in the order written."""
    rows = []
    for line in section.splitlines():
        if line.startswith("|"):
            cells = _cells(line)
            if cells and cells[0][:1].isdigit():
                rows.append(cells)
    return rows


def _rows_named(section: str, prefix: str) -> list[list[str]]:
    return [
        _cells(line)
        for line in section.splitlines()
        if line.startswith("|") and _cells(line)[0].startswith(prefix)
    ]


def _paragraph(section: str, start: str) -> str:
    found = next((p for p in section.split("\n\n") if p.startswith(start)), None)
    assert found is not None, f"no paragraph starts with {start!r}"
    return found


def _migrations_up_to_020() -> int:
    files = sorted(p.name for p in SCHEMA_DIR.glob("[0-9][0-9][0-9]_*.sql") if p.name[:3] <= "020")
    assert files[-1] == "020_learned_knowledge.sql", files[-3:]
    return len(files)


# --------------------------------------------------------------------------- the section


def test_the_section_exists_once_and_has_its_four_parts():
    section = _section(_text())
    assert section.strip()
    for part in (
        "### Migration 020 (the database moves first)",
        "### The directory, the second compose file and the containers",
        "### The switches: drafts first, the lookup after the first entries",
        "### Checks",
        "### Rollback",
        "### After `make db-restore`",
    ):
        assert section.count(f"\n{part}\n") == 1, f"{part!r} is not one heading of the section"


def test_the_section_sits_before_the_environment_keys_and_after_the_v1_1_deploy():
    text = _text()
    assert (
        text.index("## Admin console v1.1 — deploy (DEC-205)")
        < text.index(HEADING)
        < text.index("## Environment keys")
    )


def test_the_nine_steps_are_there_in_order_one_row_each():
    rows = _step_rows(_section(_text()))
    assert [r[0].split()[0] for r in rows] == [n for n, _, _ in STEPS], [r[0] for r in rows]
    for row, (number, command, _) in zip(rows, STEPS, strict=True):
        assert len(row) == 3, f"step {number} is not a three-cell row: {row}"
        assert command in row[1], f"step {number}'s command cell is {row[1]!r}, not {command!r}"


@pytest.mark.parametrize(("number", "command", "expected"), [s for s in STEPS if s[2]])
def test_a_step_says_what_to_expect(number, command, expected):
    row = next(r for r in _step_rows(_section(_text())) if r[0].startswith(number))
    assert expected in row[2], f"step {number} expects {row[2]!r}, not {expected!r}"


def test_the_steps_stay_in_their_blocks():
    section = _section(_text())
    blocks = re.split(r"^### ", section, flags=re.MULTILINE)
    by_title = {b.split("\n", 1)[0]: b for b in blocks[1:]}
    migration = by_title["Migration 020 (the database moves first)"]
    containers = by_title["The directory, the second compose file and the containers"]
    switches = by_title["The switches: drafts first, the lookup after the first entries"]
    assert [r[0].split()[0] for r in _step_rows(migration)] == ["1", "2", "3"]
    assert [r[0].split()[0] for r in _step_rows(containers)] == ["4", "5", "6"]
    assert [r[0].split()[0] for r in _step_rows(switches)] == ["7", "8", "9"]


# --------------------------------------------------------------------------- the migration block


def test_the_migration_counts_are_the_files_up_to_020_and_020_is_named():
    """`1 applied, 19 already present` and `20` are the files of `docs/Schema` up to
    `020_learned_knowledge.sql`: the block is for that migration, and 021 does not move it."""
    total = _migrations_up_to_020()
    assert total == 20
    rows = _step_rows(_section(_text()))
    assert f"1 applied, {total - 1} already present" in rows[1][2]
    assert f"`{total}`" in rows[2][2]
    assert "`020_learned_knowledge.sql`" in rows[1][2]
    assert "2 applied, 18 already present" in rows[1][2]  # a database still at 018 applies two


def test_step_3_stops_the_operator_until_the_count_holds():
    assert "Do not go on before this holds" in _step_rows(_section(_text()))[2][2]


def test_the_check_reads_the_count_without_printing_a_dsn():
    section = _section(_text())
    assert '"$DATABASE_URL_OWNER"' in section
    assert not re.search(r"postgres(ql)?://", section), "a DSN is written in the section"


def test_the_section_says_what_a_restart_before_the_migration_breaks():
    paragraph = _paragraph(_section(_text()), "**What a restart before step 2")
    for needle in (
        "knowledge_queue",
        "knowledge_integrity",
        "overview",
        "restart",
        "up -d",
        "step 3",
        "`20`",
    ):
        assert needle in paragraph, f"the early-restart paragraph no longer says {needle!r}"


# --------------------------------------------------------------------------- the directory and the file


def test_the_directory_is_made_before_up_d_and_by_the_host_user():
    section = _section(_text())
    rows = _step_rows(section)
    # the first `docker compose up -d` the section tells the reader to run is step 6's, and the
    # directory is made before it, not in the same breath after it
    assert section.index("mkdir kb_learned") < section.index("docker compose up -d")
    assert "docker compose up" not in rows[3][1], "step 4 starts containers"
    assert "`root`" in rows[3][2] and "cannot write" in rows[3][2]
    assert "sudo" not in rows[3][1], "the directory must not be made with sudo"


def test_step_5_adds_the_compose_file_line_and_lists_services_without_printing_the_environment():
    row = _step_rows(_section(_text()))[4]
    assert "COMPOSE_FILE=docker-compose.yml:docker-compose.rag.yml" in row[1]
    assert "docker compose config --services" in row[1]
    # plain `docker compose config` prints the interpolated environment, passwords included
    assert not re.search(r"docker compose config(?! --services)[^`]*`", row[1])
    assert "`docker compose config`" in row[2], "the row no longer warns off plain `config`"
    assert "make up" in row[2] and "make down" in row[2]


def test_step_6_creates_rag_worker_and_restarts_the_worker_on_the_new_code():
    row = _step_rows(_section(_text()))[5]
    assert "docker compose restart worker" in row[1]
    assert "`app` recreated" in row[2] and "`rag-worker`" in row[2]


# --------------------------------------------------------------------------- the switches


def test_the_draft_switch_comes_before_the_lookup_switch_with_the_first_entries_between():
    section = _section(_text())
    rows = _step_rows(section)
    drafts, entries, lookup = rows[6][1], rows[7][1], rows[8][1]
    assert section.index(drafts) < section.index(entries) < section.index(lookup)
    assert "KNOWLEDGE_DRAFT_ENABLED=true" in drafts and "RAG_ENABLED=true" in lookup
    assert "only after the first approved entries" in section
    assert "docker compose up -d --force-recreate app worker rag-worker" in drafts
    assert "docker compose up -d --force-recreate app worker rag-worker" in lookup


def test_rag_budget_reports_na_while_both_switches_are_off():
    row = _step_rows(_section(_text()))[6]
    assert "`rag_budget`" in row[2] and "`n/a — RAG off`" in row[2]
    assert "RAG_ENABLED" in row[2] and "KNOWLEDGE_DRAFT_ENABLED" in row[2]


def test_the_lookup_step_says_what_it_costs_the_analyst_and_the_cap():
    row = _step_rows(_section(_text()))[8]
    for needle in ("RAG_TRIAGE_DELAY_S", "45", "RAG_MONTHLY_USD_CAP", "LLM_MONTHLY_USD_CAP"):
        assert needle in row[2], f"step 9 no longer says {needle!r}"


# --------------------------------------------------------------------------- the checks


def _checks(section: str) -> str:
    return section.split("\n### Checks\n", 1)[1].split("\n### ", 1)[0]


def test_the_checks_name_the_variables_they_print_and_never_the_whole_environment():
    checks = _checks(_section(_text()))
    assert "printenv RAG_ENABLED KNOWLEDGE_DRAFT_ENABLED" in checks
    # a bare `printenv` prints DATABASE_URL, the LLM key and the JWT secret
    assert not re.search(r"printenv(?![ ]+[A-Z])", checks), "a bare printenv in the checks"
    assert not re.search(r"postgres(ql)?://", checks)


def test_the_checks_read_rag_results_llm_runs_per_pipeline_and_the_knowledge_counts():
    checks = _checks(_section(_text()))
    assert "select status, count(*) from rag_results" in checks
    assert "select pipeline, count(*) from llm_runs" in checks
    for pipeline in ("rag_lookup", "knowledge_draft", "triage", "investigate"):
        assert f"`{pipeline}\\|N`" in checks, f"the llm_runs check no longer shows {pipeline}"
    assert "from knowledge_drafts" in checks and "from knowledge_entries" in checks
    assert "`knowledge`" in checks and "`pending`" in checks and "`conflicts`" in checks
    for status in ("ok", "empty", "failed", "budget"):
        assert f"`{status}\\|N`" in checks, f"the rag_results check no longer shows {status}"


def test_the_checks_prove_the_three_mount_modes_inside_the_containers():
    rows = _rows_named(_checks(_section(_text())), "mounts")
    assert len(rows) == 1
    command, expected = rows[0][1], rows[0][2]
    assert (
        "exec -T app" in command and "exec -T rag-worker" in command and "exec -T worker" in command
    )
    assert "/srv/kb_learned" in command
    assert "writable" in expected and "Read-only file system" in expected
    assert "No such file or directory" in expected


def test_the_checks_name_the_three_health_checks():
    checks = _checks(_section(_text()))
    for name in ("knowledge_queue", "knowledge_integrity", "rag_budget"):
        assert f"`{name}`" in checks, name
    assert "KNOWLEDGE_QUEUE_MAX" in checks and "RAG_MONTHLY_USD_CAP" in checks
    assert "**Alarms**" in checks


# --------------------------------------------------------------------------- rollback and restore


def test_the_rollback_turns_the_switches_off_recreates_and_removes_nothing():
    section = _section(_text())
    note = _paragraph(section, "**Rollback.**")
    for needle in (
        "RAG_ENABLED=false",
        "KNOWLEDGE_DRAFT_ENABLED=false",
        "docker compose up -d --force-recreate app worker rag-worker",
        "Entries stay",
        "no data is removed",
        "no down-migration",
    ):
        assert needle in note, f"the rollback no longer says {needle!r}"
    # read-only means read-only: nothing in the section deletes, drops or truncates
    for forbidden in (
        r"delete from",
        r"truncate ",
        r"drop table",
        r"drop database",
        r"down -v",
        r"rm -r",
    ):
        assert not re.search(forbidden, section, re.IGNORECASE), f"the section says {forbidden!r}"


def test_after_a_db_restore_the_files_come_back_from_the_database_in_this_order():
    after = _section(_text()).split("\n### After `make db-restore`\n", 1)[1]
    commands = [
        "docker compose stop rag-worker",
        "make db-restore FILE=backups/soc-<UTC stamp>.dump",
        "docker compose exec app python -m app.rag.publish --rebuild",
        "docker compose up -d rag-worker",
    ]
    positions = [after.index(c) for c in commands]
    assert positions == sorted(positions), "the restore steps are out of order"
    for needle in (
        "--root PATH",
        "`knowledge_integrity`",
        '"rebuilt"',
        "pg_dump",
        "stops `app` and `worker`",
    ):
        assert needle in after, f"the restore step no longer says {needle!r}"


def test_the_rebuild_runs_in_app_the_one_container_with_the_read_write_mount():
    """`app` mounts `kb_learned/` read-write; `rag-worker` has it `:ro` (the rebuild would fail) and
    `worker` has none. So the section says where it runs, in the sentence before the commands and
    in every place it names the command (the README, the Alarms row of `knowledge_integrity`)."""
    after = _section(_text()).split("\n### After `make db-restore`\n", 1)[1]
    before_commands = after.split("```bash", 1)[0]
    assert "Run the rebuild in `app`" in before_commands
    assert "read-write" in before_commands and "`rag-worker`" in before_commands
    command = "docker compose exec app python -m app.rag.publish --rebuild"
    readme = (REPO_ROOT / "kb_learned" / "README.md").read_text(encoding="utf-8")
    assert command in readme
    alarm = next(
        line
        for line in _section(_text(), "## Alarms").splitlines()
        if line.startswith("| `knowledge_integrity` |")
    )
    assert (
        command in alarm
    ), "the knowledge_integrity row repairs with a command that is not run in app"


@pytest.mark.parametrize("check", ["knowledge_queue", "rag_budget"])
def test_an_alarm_row_that_raises_a_cap_in_env_recreates_worker_and_rag_worker(check):
    """`.env` is read only when a container is created, and the health check runs in `worker`: a
    `restart` of `rag-worker` alone changes neither (P13-T05 review, M1)."""
    alarm = next(
        line
        for line in _section(_text(), "## Alarms").splitlines()
        if line.startswith(f"| `{check}` |")
    )
    assert "in `.env`, then `docker compose up -d --force-recreate worker rag-worker`" in alarm
    assert "restart rag-worker" not in alarm


def test_backup_and_restore_sends_the_reader_to_the_section():
    backup = _section(_text(), "## Backup and restore")
    assert "Learned knowledge and RAG (DEC-210)" in backup
    assert "docker compose stop rag-worker" in backup


# --------------------------------------------------------------------------- the other documents


def _limitation(heading: str = "### (xlvii) · Learned knowledge and RAG") -> str:
    """One item of `docs/limitations.md`, its lines joined: the file wraps at 110 columns, and a
    phrase the test looks for may be split by a line end."""
    text = _text(LIMITATIONS)
    start = text.index(heading)
    following = re.search(r"^##+ ", text[start + 4 :], re.MULTILINE)
    item = text[start:] if following is None else text[start : start + 4 + following.start()]
    return " ".join(item.split())


def test_limitations_says_the_harness_b4_is_not_the_live_deployment():
    item = _limitation()
    for needle in ("`RAG_ENABLED=true`", "B4", "not the live deployment", "spec §7.8", "DEPLOYED"):
        assert needle in item, f"the limitation no longer says {needle!r}"


def test_limitations_says_full_text_search_is_simple_with_no_accent_folding():
    item = _limitation()
    assert "`simple`" in item and "no accent folding" in item


def test_limitations_says_the_queue_volume_is_an_expectation_not_measured():
    item = _limitation()
    assert "an expectation, not measured" in item and "`KNOWLEDGE_QUEUE_MAX`" in item


def test_limitations_says_the_rag_spend_is_capped_monthly_and_is_part_of_the_global_cap():
    item = _limitation()
    for needle in ("`RAG_MONTHLY_USD_CAP`", "global cap", "`LLM_MONTHLY_USD_CAP`", "per month"):
        assert needle in item, f"the limitation no longer says {needle!r}"


def test_limitations_item_has_the_four_labelled_parts_and_its_source():
    item = _limitation()
    for label in ("- **Statement.**", "- **Measured.**", "- **Source.**", "- **Affects.**"):
        assert label in item, label
    assert "DEC-210" in item


def test_limitations_says_the_injection_detector_is_english_and_a_vietnamese_phrase_passes_v4():
    item = _limitation("### (xlviii) · ")
    for needle in (
        "phrase list is English",
        "Vietnamese",
        "V4",
        "Bỏ qua mọi chỉ dẫn trước đó",
        "`security/detector.py`",
        "the admin's approval is the gate",
        "- **Statement.**",
        "- **Measured.**",
        "- **Source.**",
        "- **Affects.**",
        "DEC-210",
    ):
        assert needle in item, f"the injection limitation no longer says {needle!r}"
    # the one Vietnamese pattern the detector has is named, so the claim is not stronger than the code
    assert "hướng dẫn" in item and "chỉ thị" in item


def test_context_pack_gives_rag_the_lower_layer_kind_of_llm_and_infra():
    rows = {
        _cells(line)[0].strip("`"): _cells(line)
        for line in _text(PACK).splitlines()
        if re.match(r"^\| `[a-z_0-9]+/` \|", line)
    }
    assert rows["rag/"][1] == "infra" == rows["llm/"][1] == rows["kb/"][1], rows["rag/"]
    assert rows["rag/"][1] != "tier"
    # the tiers keep theirs
    assert rows["tier1/"][1] == rows["tier2/"][1] == "tier"


def test_context_pack_6_2_names_the_two_rag_only_schemas_beside_output_schemas():
    text = _text(PACK)
    section = text.split("### 6.2", 1)[1].split("### 6.3", 1)[0]
    after_block = section.split("```", 2)[2]  # what follows the §6.2 JSON block
    for needle in ("`rag_match_v1`", "`knowledge_draft_v1`", "`backend/app/rag/schemas.json`"):
        assert needle in after_block, f"§6.2 no longer says {needle!r} after its block"
    assert "output_schemas.json" in after_block
    # the block itself is the three schemas of output_schemas.json and nothing else
    block = section.split("```json", 1)[1].split("```", 1)[0]
    assert "rag_match_v1" not in block and "knowledge_draft_v1" not in block


def test_the_rag_package_docstring_names_the_draft_module():
    doc = _text(RAG_INIT)
    assert "* `draft`:" in doc
    for module in (
        "subject",
        "tags",
        "generalise",
        "fingerprint",
        "history",
        "entries",
        "candidates",
    ):
        assert f"* `{module}`" in doc, module
    for module in ("agent", "match", "budget", "runs", "lookup"):
        assert f"* `{module}`" in doc, module
