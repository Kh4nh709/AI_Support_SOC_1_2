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
    ("4", "mkdir -p kb_learned && ls -ldn kb_learned", "HOST_UID"),
    ("5", "COMPOSE_FILE=docker-compose.yml:docker-compose.rag.yml", "rag-worker"),
    ("6", "docker compose up -d --build ui", "`200`"),
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


def test_the_020_intro_lists_the_three_indexes_the_migration_creates():
    """The intro said "one index"; the migration creates three (T09 review, M6). The names are read
    from the SQL, so an index added or renamed there fails here until the intro says so."""
    sql = (SCHEMA_DIR / "020_learned_knowledge.sql").read_text(encoding="utf-8")
    names = re.findall(r"^CREATE (?:UNIQUE )?INDEX (\w+)", sql, re.MULTILINE)
    assert len(names) == 3, names
    intro = _section(_text()).split("### Migration 020", 1)[1].split("| step |", 1)[0]
    for name in names:
        assert f"`{name}`" in intro, f"the 020 intro does not name the index {name}"
    assert "adds one index" not in intro and "adds three indexes" in intro
    assert "GIN" in intro


def test_what_to_watch_counts_the_alarms_the_alarms_table_has():
    """ "beyond the ten alarms" was true before the three RAG checks (P13-T05) joined the table."""
    text = _text()
    rows = [
        line
        for line in _section(text, "## Alarms").splitlines()
        if re.match(r"^\| `[a-z_]+` \|", line)
    ]
    assert len(rows) == 13, [_cells(r)[0] for r in rows]
    assert "## What to watch (manual checks, beyond the thirteen alarms)" in text
    assert "beyond the ten alarms" not in text


def test_the_config_comment_calls_the_queue_max_an_alarm_threshold_and_not_a_cap():
    source = (REPO_ROOT / "backend" / "app" / "infra" / "config.py").read_text(encoding="utf-8")
    comment = re.sub(r"\s*\n\s*#\s*", " ", source)  # a comment wrapped over lines, joined
    assert "most pending drafts the queue takes" not in comment
    assert "is the pending-draft count above which `knowledge_queue` alarms" in comment
    assert "it caps nothing" in comment


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


def test_the_directory_step_does_not_fail_on_the_directory_the_merge_already_made():
    """`kb_learned/README.md` is tracked, so step 1's merge creates `kb_learned/`: a plain `mkdir`
    would exit 1 ("File exists") on every deploy and the owner would never be shown (T09 review, I1).
    """
    section = _section(_text())
    rows = _step_rows(section)
    assert not re.search(r"mkdir (?!-p)", section), "a plain mkdir is back in the section"
    assert "mkdir -p kb_learned && ls -ldn kb_learned" in rows[3][1]
    assert "git already made it" in rows[3][2] and "`kb_learned/README.md` is tracked" in rows[3][2]
    assert "<uid> <gid>" in rows[3][2] and "`HOST_UID`" in rows[3][2] and "`HOST_GID`" in rows[3][2]
    assert 'sudo chown "$(id -u):$(id -g)" kb_learned' in rows[3][2]
    assert (REPO_ROOT / "kb_learned" / "README.md").exists(), "the premise: the README is tracked"


def test_the_directory_is_checked_before_up_d_and_by_the_host_user():
    section = _section(_text())
    rows = _step_rows(section)
    # the first `docker compose up -d` the section tells the reader to run is step 6's, and the
    # directory is checked before it, not in the same breath after it
    assert section.index("mkdir -p kb_learned") < section.index("docker compose up -d")
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


def test_step_5_writes_the_key_on_its_own_line_and_expects_exactly_one():
    """`echo … >> .env` glues the key onto the last line when `.env` has no trailing newline (T09
    review, M2): the leading `\\n` of `printf` ends that line first. The grep that follows reads `1`.
    """
    row = _step_rows(_section(_text()))[4]
    printf = "printf '\\nCOMPOSE_FILE=docker-compose.yml:docker-compose.rag.yml\\n' >> .env"
    assert printf in row[1]
    assert "echo" not in row[1]
    assert row[1].index(printf) < row[1].index("grep -c '^COMPOSE_FILE=' .env")
    assert row[1].index("grep -c '^COMPOSE_FILE=' .env") < row[1].index("docker compose config")
    assert "`1`" in row[2] and "`2`" in row[2], "the row no longer says what 1 and 2 mean"


def test_step_6_creates_rag_worker_and_restarts_the_worker_on_the_new_code():
    row = _step_rows(_section(_text()))[5]
    assert "docker compose restart worker" in row[1]
    assert "`app` recreated" in row[2] and "`rag-worker`" in row[2]


def test_step_6_rebuilds_the_ui_image_because_the_branch_changes_frontend():
    """The Overview's `knowledge` block and the admin knowledge page are in `frontend/`, and the `ui`
    image holds the build (it is not a mount, **UI (service `ui`)**): without `up -d --build ui` step 8
    has no page to approve a draft on (T09 review, I2). Mirrors the v1.1 deploy's step 4."""
    section = _section(_text())
    row = _step_rows(section)[5]
    plain_up = re.search(r"docker compose up -d(?! --)", row[1])
    assert plain_up is not None, "the plain `docker compose up -d` (it creates rag-worker) is gone"
    build = row[1].index("docker compose up -d --build ui")
    assert plain_up.start() < build < row[1].index("docker compose restart worker")
    assert (
        "curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:8080/admin/overview" in row[1]
    )
    assert "`200`" in row[2] and "`frontend/`" in row[2] and "not a mount" in row[2]
    # after the migration: the build must not come before step 3
    assert section.index(DSN) < section.index("docker compose up -d --build ui")


def test_the_section_says_how_to_keep_rag_worker_running():
    paragraph = _paragraph(_section(_text()), "**Running `rag-worker`.**")
    for needle in (
        "docker compose restart rag-worker",
        "`backend/app/rag/`",
        "`job_backlog`",
        "`rag_lookup`",
        "`knowledge_draft`",
        "the main `worker` claims neither",
    ):
        assert needle in paragraph, f"the paragraph on running rag-worker no longer says {needle!r}"


def test_the_generic_operations_rows_name_rag_worker():
    """A fourth long-running container needs a place in the rows an operator reads under pressure
    (T09 review, M3): the restart rule, `job_backlog`, Worker stuck, Database container down."""
    text = _text()
    restart = next(line for line in text.splitlines() if line.startswith("| restart |"))
    assert "`backend/app/rag/`" in restart and "docker compose restart rag-worker" in restart
    assert "--force-recreate app worker rag-worker" in restart
    backlog = next(line for line in text.splitlines() if line.startswith("| `job_backlog` |"))
    assert (
        "`rag-worker`" in backlog and "`rag_lookup`" in backlog and "`knowledge_draft`" in backlog
    )
    stuck = next(line for line in text.splitlines() if line.startswith("| **Worker stuck**"))
    assert "docker compose restart rag-worker" in stuck and "`rag_lookup`" in stuck
    down = next(
        line for line in text.splitlines() if line.startswith("| **Database container down**")
    )
    assert "`rag-worker`" in down


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
    # M4: the `rag-worker` probe cleans up after itself, and the row says what a success means
    probe = "touch /srv/kb_learned/.probe && rm /srv/kb_learned/.probe"
    assert command.count(probe) == 2, "both probes must remove the file they create"
    assert "if `touch` succeeds" in expected.lower() and "read-write" in expected


def test_the_switch_check_says_what_a_missing_line_means():
    """No line from `printenv` means the key is not in `.env`: the code's default, `false`, applies
    (T09 review, M5)."""
    row = _rows_named(_checks(_section(_text())), "switches")[0]
    assert "absent from `.env`" in row[2] and "default" in row[2] and "`false`" in row[2]


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
    # M1: the shell that sourced `.env` still exports COMPOSE_FILE, so taking the line out of `.env`
    # alone leaves the override in force for `docker compose up -d --remove-orphans`
    assert "unset COMPOSE_FILE" in note and "fresh shell" in note
    assert note.index("unset COMPOSE_FILE") < note.index("docker compose up -d --remove-orphans")
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


# --------------------------------------------------------------------------- the P13 fix wave (items 11, 23-26, 28, 29)


def _row(starts: str) -> str:
    return next(line for line in _text().splitlines() if line.startswith(starts))


def test_the_restart_rule_of_rag_worker_is_any_merge_under_backend_app():
    """Item 25 (Minor 5): `rag-worker` imports `llm/`, `security/`, `infra/`, `audit/` and `domain/` too, so
    a merge that touches none of `rag/`, `web/rag_worker.py` and `web/rag_handlers/` still needs the restart.
    The runbook's restart row, its paragraph on running `rag-worker`, and the compose file say so.
    """
    compose = " ".join(
        line.removeprefix("# ")
        for line in (REPO_ROOT / "docker-compose.rag.yml").read_text(encoding="utf-8").splitlines()
        if line.startswith("#")
    )
    places = {
        "restart row": _row("| restart |"),
        "paragraph": _paragraph(_section(_text()), "**Running `rag-worker`.**"),
        "compose file": compose,
    }
    for where, text in places.items():
        flat = " ".join(text.replace("`", "").split())
        assert "merge under backend/app" in flat, where
        assert "not only" in flat, where
        for package in ("llm/", "security/", "infra/", "audit/", "domain/"):
            assert package in flat, f"the {where} does not name {package}"


def test_the_requirements_clause_also_rebuilds_and_recreates_rag_worker():
    """Item 11: `rag-worker` runs `app`'s image, built from `backend/requirements.txt`."""
    restart = _row("| restart |")
    assert (
        "docker compose build app worker rag-worker && docker compose up -d app worker rag-worker"
        in restart
    )


def test_the_what_to_watch_paragraph_counts_thirteen_checks():
    """Item 11: the file says thirteen alarms in its heading and its table; the paragraph said ten."""
    text = _text()
    paragraph = text.split("## What to watch (manual checks, beyond the thirteen alarms)", 1)[
        1
    ].split("\n\n", 2)[1]
    assert "the thirteen checks of **Alarms**" in paragraph
    assert "the thirteen checks do not cover" in paragraph
    assert "ten checks" not in paragraph


def test_the_runbook_says_the_triage_delay_is_paid_even_when_no_lookup_can_run():
    """Item 11: `RAG_ENABLED` on and no working RAG model (or `rag-worker` stopped) still delays ①."""
    section = _section(_text())
    step9 = next(r for r in _step_rows(section) if r[0].startswith("9"))
    assert "no working RAG model" in step9[1] + step9[2] and "RAG_TRIAGE_DELAY_S" in step9[2]
    assert "still delayed" in step9[2]
    assert "even when no lookup can run" in _row("| `RAG_TRIAGE_DELAY_S` |")


def test_the_rollback_drains_the_rag_queue_before_anything_is_removed():
    """Item 24 (Minor 4): the main worker claims neither RAG job type, so a job left `pending` after
    `rag-worker` is gone is a `job_backlog` alarm for ever. The count must print 0 first."""
    section = _section(_text())
    note = _paragraph(section, "**Rollback.**")
    count = (
        "select count(*) from jobs where job_type in ('rag_lookup','knowledge_draft') "
        "and status in ('pending','running')"
    )
    assert count in note and "prints `0`" in note
    assert note.index(count) < note.index("unset COMPOSE_FILE")
    assert note.index(count) < note.index("docker compose up -d --remove-orphans")
    assert "Only when that count is `0`" in note
    assert "never clears" in note


def test_the_runbook_lists_exactly_what_breaks_on_a_019_host_with_the_switches_off():
    """Item 28: the review found `runbook :98` claimed more than there is."""
    breaks = _paragraph(_section(_text()), "**What a restart before step 2 breaks.**")
    for needle in (
        "`knowledge_queue` and `knowledge_integrity`",
        "alarm",
        "overview page shows an **error**",
        "`/admin/knowledge`",
        "**500**",
        "`rag_budget` is `n/a — RAG off`",
        "① and ② keep working",
    ):
        assert needle in breaks, f"the paragraph no longer says {needle!r}"


def test_a_pre_020_dump_is_restored_with_both_switches_off():
    """Item 23 (Minor 3)."""
    after = _section(_text()).split("\n### After `make db-restore`\n", 1)[1]
    assert (
        "before restoring one, set `RAG_ENABLED=false` and `KNOWLEDGE_DRAFT_ENABLED=false`" in after
    )


def test_the_readme_of_kb_learned_gives_the_retired_path_and_says_there_is_no_versioning():
    """Item 26 (Minor 6)."""
    readme = _text(REPO_ROOT / "kb_learned" / "README.md")
    assert "retired/<category>/<id>.md" in readme
    assert "retired/<entry_id>.md" not in readme
    assert "approving a new version" not in readme
    assert "no\n  versioning" in readme or "There is no versioning" in " ".join(readme.split())


def test_limitations_xlix_names_the_three_limits_of_the_wave():
    """Item 29."""
    item = _limitation("### (xlix) · Learned knowledge")
    for needle in (
        "reads log text an attacker can shape",
        "force the auto-merge",
        "force a conflict",
        "Đã gộp",
        "One `rag-worker` only",
        "`JOB_LOCK_TIMEOUT_S`",
        "pay for it twice",
        "One `app_rw` role serves `app`, `worker` and `rag-worker`",
    ):
        assert needle in item, f"limitation xlix no longer says {needle!r}"
