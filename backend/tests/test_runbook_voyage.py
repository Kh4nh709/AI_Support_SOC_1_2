"""`docs/runbook.md` — the operator's section of the Voyage vector RAG, and the sentences P14 made false
(P14-T08, DEC-213).

WHY A TEST FOR A DOCUMENT. The Owner runs this section by hand on the trial, and no agent runs a line of it.
The order is part of the procedure: the keys go into `.env` with `printf` and are never printed; the wipe
check comes before the migration (022 refuses while a `triage` run still says `escalate`); the database moves
before any container runs the P14 code; the vector index is rebuilt after the containers are up and again after
a `make db-restore`; and the rollback drains the RAG queue before `vectordb` is stopped. A step moved, a secret
printed, or a command that names an option, a service or a file that is not there fails `make test`, not a
lab run.

WHAT IT PINS. The eight steps in the order of the brief (one change: the migration comes before `up -d`, as
for 019 and 020), the two subsections after them (**Lab procedure**, **Measuring**), the secrets rules, every
command against the code or compose file it names (services, options, make targets, modules, the mount of
`eval/`), and the sentences earlier cards made false: the drain query, the Alarms table, the model-API row, the
start-everything row. `eval/lab_measure.py` (P14-T11) is on its own branch until it merges: the cross-check
of the doc against its options and exit codes runs when the file is in the tree, and the doc is held to the
frozen list below until then. It does not judge prose.

PURE. No database, no socket, no docker.
"""

from __future__ import annotations

import ast
import pathlib
import re
import shlex

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNBOOK = REPO_ROOT / "docs" / "runbook.md"
LIMITATIONS = REPO_ROOT / "docs" / "limitations.md"
COMPOSE = REPO_ROOT / "docker-compose.yml"
COMPOSE_RAG = REPO_ROOT / "docker-compose.rag.yml"
SCHEMA_DIR = REPO_ROOT / "docs" / "Schema"
MAKEFILE = REPO_ROOT / "Makefile"
HEALTH = REPO_ROOT / "backend" / "app" / "infra" / "health.py"
VECTOR_INDEX = REPO_ROOT / "backend" / "app" / "rag" / "vector_index.py"
ADMIN_LAB = REPO_ROOT / "backend" / "app" / "web" / "routers" / "admin_lab.py"
ROUTES = REPO_ROOT / "frontend" / "src" / "routes.tsx"
# P14-T11: on its own branch until it merges; the cross-check below skips while it is not in the tree.
LAB_MEASURE = REPO_ROOT / "eval" / "lab_measure.py"

TITLE = "Voyage vector RAG (DEC-213)"

#: The brief's order, with the migration before `up -d` and (fix round 1) a backup step after the migration.
STEPS = [
    (1, "The keys"),
    (2, "The wipe check"),
    (3, "`make migrate`"),
    (4, "The backup"),
    (5, "`docker compose up -d`"),
    (6, "The index"),
    (7, "After `make db-restore`"),
    (8, "The free-tier limits"),
    (9, "Rollback"),
]

#: The queue the Voyage rollback drains before `vectordb` is stopped: the two job types that use it
#: (`knowledge_draft` never touches `vectordb`; DEC-210's rollback, which removes `rag-worker`, drains all three).
DRAIN = (
    "select count(*) from jobs where job_type in ('rag_lookup','knowledge_embed') "
    "and status in ('pending','running')"
)


def _text(path: pathlib.Path = RUNBOOK) -> str:
    assert path.exists(), f"{path} does not exist"
    return path.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _voyage() -> str:
    """The body of `### Voyage vector RAG (DEC-213)`, inside `## Environment keys`. A `####` heading does not
    end it (the split is on a `###` followed by a space)."""
    keys = _text().split("\n## Environment keys")[1].split("\n## ")[0] + "\n"
    heading = f"\n### {TITLE}\n"
    assert heading in keys, "the runbook has no 'Voyage vector RAG' section"
    return keys.split(heading)[1].split("\n### ")[0]


STEP_RE = re.compile(r"^\*\*(\d) · (.+?)\*\*", re.MULTILINE)


def _steps() -> dict[int, str]:
    """Each step's text, from its `**N · Title.**` lead-in to the next lead-in (the last: to `#### `)."""
    section = _voyage().split("\n#### ")[0]
    marks = list(STEP_RE.finditer(section))
    found: dict[int, str] = {}
    for index, mark in enumerate(marks):
        end = marks[index + 1].start() if index + 1 < len(marks) else len(section)
        found[int(mark.group(1))] = section[mark.start() : end]
    return found


def _sub(title: str) -> str:
    body = _voyage()
    marker = f"\n#### {title}\n"
    assert marker in body, f"the Voyage section has no '#### {title}' subsection"
    return body.split(marker)[1].split("\n#### ")[0]


def _code(text: str) -> list[str]:
    """Every line inside a ``` fence and every `inline code` span outside one."""
    lines: list[str] = []
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            lines.append(line)
        else:
            lines.extend(re.findall(r"`([^`]+)`", line))
    return lines


def _fenced(text: str) -> list[str]:
    """Only the lines inside a ``` fence: what the operator pastes (prose may name a command to warn off it)."""
    lines: list[str] = []
    fenced = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif fenced:
            lines.append(line)
    return lines


def _commands(text: str) -> list[str]:
    """The code lines of `text` that are commands, a trailing `# comment` cut."""
    return [line.split("  #")[0].strip() for line in _code(text) if line.strip()]


def _migration_files() -> list[str]:
    return sorted(p.stem for p in SCHEMA_DIR.glob("[0-9][0-9][0-9]_*.sql"))


def _services() -> set[str]:
    names: set[str] = set()
    for path in (COMPOSE, COMPOSE_RAG):
        names |= set(yaml.safe_load(path.read_text(encoding="utf-8"))["services"])
    return names


def _row(starts: str) -> str:
    return next(ln for ln in _text().splitlines() if ln.startswith(starts))


# --------------------------------------------------------------------------- the steps, in order


def test_the_nine_steps_are_there_in_order():
    steps = _steps()
    assert list(steps) == [n for n, _ in STEPS], list(steps)
    for number, title in STEPS:
        lead = steps[number].splitlines()[0]
        assert title in lead, f"step {number} is not '{title}': {lead!r}"


def test_the_two_subsections_follow_the_steps_in_order():
    body = _voyage()
    last_step = body.index("**9 · ")
    assert last_step < body.index("\n#### Lab procedure\n") < body.index("\n#### Measuring\n")
    assert (
        body.count("\n#### ") == 2
    ), "the section has more subsections than the two the brief names"


def test_the_section_still_opens_with_trial_only_never_on_live():
    first = next(line for line in _voyage().splitlines() if line.strip())
    assert first.startswith("**Trial only, never on live.**"), first
    assert "never merged into `main`" in first


def test_the_database_moves_before_the_containers_run_the_p14_code():
    """Rule of 019 and 020 (above): `make migrate` first, `up -d` after. The brief lists `up -d` before the
    migration; the order here is the runbook's own rule (flagged in the card's report)."""
    steps = _steps()
    assert "docker compose up -d" not in steps[3], "step 3 starts containers"
    assert "make migrate" in steps[3] and "docker compose up -d" in steps[5]
    flat = _flat(steps[3])
    # the trial as it stands (20 migrations) applies 021 to 024; a database the wipe recreated with the P14
    # checkout (its schema.sql records 24) applies none: both are right, and the gate is the total (fix round 1, I2)
    assert "migrate: 4 applied, 20 already present" in flat
    assert "migrate: 0 applied, 24 already present" in flat
    assert "Do not go on before the count reads `24`" in flat
    assert "Do not go on before this holds" not in flat  # it was false on the re-wipe branch
    stems = _migration_files()
    assert len(stems) == 24 and stems[-4:] == [
        "021_archive",
        "022_true_positive",
        "023_vector_rag",
        "024_lab",
    ]
    for stem in stems[-4:]:
        assert f"migrate: applying {stem}" in flat, stem
    assert "`24`" in flat
    assert 4 + 20 == 0 + 24 == len(stems)  # both answers quote the files' own total
    assert "no alert has arrived since the wipe" in flat or "no worker holds a transaction" in flat


# --------------------------------------------------------------------------- the keys and the secrets


def test_the_two_secrets_are_written_with_printf_never_echo():
    code = _code(_steps()[1])
    writes = [ln for ln in code if ">> .env" in ln]
    assert len(writes) == 2, writes
    for line in writes:
        assert "printf " in line and not re.search(r"\becho\b", line), line
        # the runbook's own rule (step 5 of the DEC-210 section): a leading newline ends an `.env` that has none
        assert line.startswith("printf '\\n"), line
    password = next(ln for ln in writes if "VECTOR_DB_PASSWORD=%s" in ln)
    assert "openssl rand -hex 24" in password, "the password is not made by `openssl rand -hex 24`"
    assert any("VOYAGE_API_KEY=%s" in ln for ln in writes)
    # the Voyage key is typed at a hidden prompt: no history, no `ps` line; the block is bash, and says so
    assert any(re.search(r"\bread -rs\b", ln) for ln in code)
    step = _steps()[1]
    assert "**bash**" in step and "POSIX `sh`" in step
    # two pastes: the checks (they decide whether to go on), then the writes
    assert step.count("```bash") == 2, "step 1 is not two pastes"
    first, second = step.split("```bash")[1:3]
    assert "docker compose config --quiet" in first and "printf" not in first
    assert "printf" in second and ">> .env" in second
    # nowhere in the section does `echo` meet `.env` or a secret
    for line in _code(_voyage()):
        if re.search(r"\becho\b", line):
            assert not re.search(r"\.env|PASSWORD|API_KEY|VOYAGE|SECRET|openssl", line), line


def test_no_line_prints_a_secret_variable_or_a_dsn():
    section = _voyage()
    code = "\n".join(_code(section))
    for pattern, what in (
        (r"\$\{?VOYAGE_API_KEY", "$VOYAGE_API_KEY"),
        (r"\$\{?VECTOR_DB_PASSWORD", "$VECTOR_DB_PASSWORD"),
        (r"postgres(ql)?://", "a DSN"),
        (r"\bprintenv\b", "printenv"),
        (
            r"\b(?:cat|less|more|head|tail|bat|sed|awk|cut|strings|xxd|od|nl|tac|rev|sort|uniq|tee)\b[^\n]*\.env\b",
            "the .env file printed",
        ),
        (r"\becho\b[^\n]*\$", "echo of a variable"),
        # whatever lists the environment lists the key and both DSNs (fix round 1, M6)
        (r"(?<![\w./$-])env(?![\w=./-])", "env"),
        (r"\bexport\s+-p\b", "export -p"),
        (r"\bdeclare\s+-[a-zA-Z]*p\b", "declare -p"),
        (r"\bdocker\s+(?:compose\s+)?inspect\b", "docker inspect"),
        (r"/proc/[^\s]*environ", "/proc/.../environ"),
        (r"(?:^|[;&|]\s*)set\s*(?:$|[;&|>])", "a bare `set`"),
    ):
        assert not re.search(pattern, code, re.MULTILINE), f"the section prints {what}"
    # a plain `docker compose config` prints the interpolated environment, passwords included: prose may warn
    # against it, a block the operator pastes may not run it
    for line in _fenced(section):
        assert not re.search(
            r"\bdocker compose (?:-f \S+ )*config(?! --quiet| --services)\b", line
        ), line
        assert "--dsn" not in line, "a DSN on a command line"
        assert "docker compose -f" not in line, "a -f pair drops docker-compose.trial.yml"
    # `.env` is only counted, never listed
    for line in code.splitlines():
        if re.search(r"\bgrep\b", line) and ".env" in line:
            assert re.search(r"\bgrep -[cq]\b", line), line
    # the one use of the vector address is the empty test of the existing check
    stripped = code.replace('test -z "$VECTOR_DATABASE_URL"', "")
    assert not re.search(r"\$\{?VECTOR_DATABASE_URL", stripped)
    # a secret variable is only ever an argument of a `printf` that writes it to `.env`
    for line in code.splitlines():
        if "$VOYAGE_KEY" in line or "$(openssl" in line:
            assert "printf " in line and ">> .env" in line, line


def test_the_compose_config_is_checked_without_and_with_the_password_before_up_d():
    """Ruling 2: once without (it must fail on the missing password) and once with it (it must pass), before
    `up -d`. The trial's `.env` sets `COMPOSE_FILE` to the three files, so the plain command is the right one:
    a `-f` pair would drop `docker-compose.trial.yml`."""
    steps = _steps()
    step = steps[1]
    commands = [
        line.split("  #")[0].strip() for line in _fenced(step)
    ]  # what is pasted, not what is named
    config = [i for i, c in enumerate(commands) if c == "docker compose config --quiet"]
    write = next(i for i, c in enumerate(commands) if "VECTOR_DB_PASSWORD=%s" in c)
    assert len(config) == 2 and config[0] < write < config[1], (config, write)
    flat = _flat(step)
    message = re.search(r"\$\{VECTOR_DB_PASSWORD:\?([^}]+)\}", _text(COMPOSE_RAG))
    assert message is not None
    assert (
        message.group(1) in flat
    ), "step 1 does not quote the refusal docker-compose.rag.yml gives"
    assert "must fail" in flat or "fails" in flat
    assert "docker-compose.yml:docker-compose.rag.yml:docker-compose.trial.yml" in _flat(_voyage())
    assert "docker-compose.trial.yml" in flat or "`-f`" in _flat(_voyage())
    assert not re.search(r"docker compose -f", "\n".join(_code(_voyage())))
    # before `up -d`: steps 1 to 4 start no container
    before = "\n".join(_code(steps[1] + steps[2] + steps[3] + steps[4]))
    assert "docker compose up" not in before and "docker compose restart" not in before


def test_the_wipe_check_counts_what_migration_022_refuses_on():
    step = _steps()[2]
    sql = (SCHEMA_DIR / "022_true_positive.sql").read_text(encoding="utf-8")
    block = sql.split("SELECT count(*) INTO still_escalate", 1)[1].split("IF still_escalate", 1)[0]
    places = re.findall(r"(?:gate_result|result)->>'\w+'", block)
    assert len(places) == 4, places
    query = next(c for c in _commands(step) if c.startswith('psql "$DATABASE_URL" -Atc'))
    for place in places:
        assert place in query, f"the wipe check does not count {place}"
    assert "from llm_runs" in query and "pipeline = 'triage'" in query and "'escalate' in" in query
    flat = _flat(step)
    assert "`0`" in flat and "spec §11" in flat and "022" in flat and "refuses" in flat
    assert "before step 3" in flat or "before `make migrate`" in flat


def test_step_4_takes_a_backup_of_the_migrated_trial_and_says_which_dumps_are_never_restored():
    """Fix round 1, I1: the trial's `backups/` holds only the pre-wipe dump and the 17-migration `latest.dump`;
    `backup.sh` writes `backups/soc-<UTC stamp>.dump`, refreshes `latest.dump` and keeps the 14 newest `soc-*`.
    """
    step = _steps()[4]
    commands = _commands(step)
    assert "bash scripts/backup.sh" in commands
    script = _text(REPO_ROOT / "scripts" / "backup.sh")
    assert 'OUT="backups/soc-$STAMP.dump"' in script and 'KEEP="${BACKUP_KEEP:-14}"' in script
    assert 'mv -f -- "$LATEST_TMP" backups/latest.dump' in script  # it overwrites latest.dump
    for line in (
        "backup: wrote backups/soc-<UTC stamp>.dump",
        "backup: refreshed backups/latest.dump",
        "backup: kept N of at most 14 (BACKUP_KEEP), pruned M",
    ):
        assert f"`{line.split(' (')[0]}" in step or line in step, line
    assert 'say "wrote $OUT (' in script and 'say "refreshed backups/latest.dump"' in script
    assert 'echo "backup: kept $kept of at most $KEEP (BACKUP_KEEP), pruned $pruned"' in script
    flat = _flat(step)
    for needle in (
        "`soc-trial-pre-lab-*.dump`",
        "`latest.dump`",
        "are never restored onto the P14 trial",
        "the backup of the wipe",
        "fifteenth backup",
        "do not commit it",
        "`DATABASE_URL_OWNER`",
    ):
        assert needle in flat, f"step 4 no longer says {needle!r}"
    # the backup comes after the migration and before any container runs the P14 code
    body = _voyage()
    assert body.index("**3 · ") < body.index("**4 · ") < body.index("**5 · ")


def test_step_5_creates_vectordb_and_recreates_rag_worker_and_checks_the_address():
    step = _steps()[5]
    commands = _commands(step)
    assert commands.index("docker compose up -d") < commands.index(
        "docker compose up -d --build ui"
    )
    # fix round 1: the ui binds the host's LAN address too (a DHCP one); check it is up before anything starts
    fenced = [line.split("  #")[0].strip() for line in _fenced(step)]
    assert fenced.index("ip -4 addr") < fenced.index("docker compose up -d")
    assert any(c.startswith("grep -n '8081:80' docker-compose.trial.yml") for c in fenced)
    flat_step = _flat(step)
    for needle in (
        "`docker-compose.trial.yml`",
        "LAN address",
        "DHCP",
        "exits at start",
        "boot race",
        "docker compose up -d --force-recreate ui",
        "`RAG_ENABLED=true`",
        "`KNOWLEDGE_DRAFT_ENABLED=true`",
    ):
        assert needle in flat_step, f"step 5 no longer says {needle!r}"
    assert "docker compose restart app worker" in commands
    flat = _flat(step)
    image = yaml.safe_load(_text(COMPOSE_RAG))["services"]["vectordb"]["image"]
    assert image in flat, "the step does not name the image docker-compose.rag.yml pins"
    for needle in ("`vectordb`", "`rag-worker`", "(healthy)", "`200`", "/admin/lab", "`none`"):
        assert needle in flat, needle
    assert "frontend/" in flat and "not a mount" in flat  # the lab page needs the rebuilt ui
    assert 'path="/admin/lab"' in _text(ROUTES)


# --------------------------------------------------------------------------- the index


def test_step_6_rebuilds_then_checks_with_the_commands_of_the_cli():
    step = _steps()[6]
    commands = _commands(step)
    rebuild = "docker compose exec rag-worker python -m app.rag.vector_index --rebuild"
    check = "docker compose exec rag-worker python -m app.rag.vector_index --check"
    assert commands.index(rebuild) < commands.index(check)
    source = _text(VECTOR_INDEX)
    for flag in ("--check", "--rebuild", "--force"):
        assert f'"{flag}"' in source, f"{flag} is not an option of vector_index.py"
    assert 'prog="python -m app.rag.vector_index"' in source
    services = yaml.safe_load(_text(COMPOSE_RAG))["services"]
    assert (
        "VECTOR_DATABASE_URL" in services["rag-worker"]["environment"]
    )  # the one container that has it
    flat = _flat(step)
    for counter in ("active", "current", "missing", "stale", "orphan"):
        assert f'print(f"{counter}:' in source and f"`{counter}: " in flat, counter
    for needle in (
        "`embedded: ",
        "`deleted: ",
        "`tokens: ",
        "exit 0",
        "exit 1",
        "`--rebuild --force`",
        "`RAG_EMBED_MODEL`",
        "`RAG_EMBED_DIMS`",
        "while the RAG was off",
        "`VOYAGE_API_KEY`",
    ):
        assert needle in flat, f"step 6 no longer says {needle!r}"
    # entries approved or retired with the RAG off reach the index only through the rebuild
    assert "switched on" in flat and "approved or retired" in flat
    # fix round 1, M4: exit 0 on an empty index proves nothing about the key; say where the first lookup shows
    for needle in (
        "Exit 0 on an empty index does not prove the key",
        "sends Voyage nothing",
        "The first real test of `VOYAGE_API_KEY` is the first lab lookup",
        "`rag_lookup_failures`",
        "Không áp dụng RAG",
        "`failed|auth|N`",
    ):
        assert needle in flat, f"step 6 no longer says {needle!r}"
    lookup = next(
        c for c in _commands(step) if c.startswith('psql "$DATABASE_URL" -Atc "select status')
    )
    assert "from rag_results" in lookup and "failure_kind" in lookup
    assert "no backup of its own" in _flat(_voyage())


def test_step_7_rebuilds_the_index_after_a_db_restore_and_names_the_dump():
    step = _steps()[7]
    commands = _commands(step)
    order = [
        "pg_restore --data-only -t schema_migrations -f - backups/soc-<UTC stamp>.dump",
        "docker compose stop rag-worker",
        "make db-restore FILE=backups/soc-<UTC stamp>.dump",
        "docker compose exec app python -m app.rag.publish --rebuild",
        "docker compose up -d rag-worker",
        "docker compose exec rag-worker python -m app.rag.vector_index --rebuild",
        "docker compose exec rag-worker python -m app.rag.vector_index --check",
    ]
    positions = [next(i for i, c in enumerate(commands) if c.startswith(o)) for o in order]
    assert positions == sorted(positions) and len(set(positions)) == len(order), positions
    after = _flat(_text().split("### After `make db-restore`\n", 1)[1].split("\n## ", 1)[0])
    assert (
        "**Voyage vector RAG (DEC-213)**" in after and "step 7" in after
    )  # the DEC-210 block points here
    # fix round 1, I1: which dump, and the two that are never restored onto the P14 trial
    flat = _flat(step)
    for needle in (
        "taken on the trial after step 3",
        "step 4",
        "`soc-trial-pre-lab-*.dump`",
        "`latest.dump`",
        "are never restored onto the P14 trial",
        "022 would refuse",
        "go on only when it is `24`",
        "(24 migrations)",
    ):
        assert needle in flat, f"step 7 no longer says {needle!r}"
    # the migration count of the dump is read before anything is stopped, and the command prints only a count
    check = next(c for c in commands if c.startswith("pg_restore "))
    assert check.endswith("| grep -c '^[0-9][0-9][0-9]_'") and "-t schema_migrations" in check
    # the line `make db-restore` ends with, and the number it prints (the Makefile counts schema_migrations)
    makefile = _text(MAKEFILE)
    assert 'echo "db-restore: $$f → $$db ($$(' in makefile
    assert "from schema_migrations') migrations)" in makefile


def test_step_8_sends_the_operator_to_the_voyage_dashboard_before_a_lab_run():
    flat = _flat(_steps()[8])
    for needle in (
        "Voyage dashboard",
        "not published",
        "before a lab run",
        "`rate_limit`",
        "`rag_lookup_failures`",
        "2 000 requests per minute",
    ):
        assert needle in flat, needle


def test_step_9_rolls_back_by_switching_off_draining_and_stopping_vectordb():
    step = _steps()[9]
    commands = _commands(step)
    flat = _flat(step)
    off = flat.index("RAG_ENABLED=false")
    drain = flat.index(DRAIN)
    stop = next(i for i, c in enumerate(commands) if c == "docker compose stop vectordb")
    assert off < drain and flat.index("docker compose stop vectordb") > drain
    assert "docker compose up -d --force-recreate app worker rag-worker" in commands
    # fix round 1, M1: only the two types that use `vectordb` are counted (a draft never touches it)
    assert "knowledge_draft" not in DRAIN
    queries = re.findall(r"job_type in \(([^)]*)\)", flat)
    assert queries == ["'rag_lookup','knowledge_embed'"], queries
    assert "`knowledge_draft` is left out of this count on purpose" in flat
    for draft_file in ("rag/draft.py", "rag/draft_rank.py", "web/rag_handlers/draft.py"):
        # the premise: a draft never reads or writes vectordb
        assert "vector_store" not in _text(REPO_ROOT / "backend" / "app" / draft_file), draft_file
    # ... and switching on again starts `vectordb` first, then the containers that use it
    again = flat.split("Switching the RAG on again", 1)[1]
    assert again.index("docker compose up -d vectordb") < again.index("`RAG_ENABLED=true`")
    assert "(healthy)" in again
    for needle in (
        "prints `0`",
        "entries stay",
        "admin console",
        "`vectordata`",
        "nothing is deleted",
    ):
        assert needle.lower() in flat.lower(), needle
    assert stop >= 0
    # nothing in the section deletes, except the Owner's removal of a lab run recorded by mistake
    code = "\n".join(_code(_voyage()))
    without = code.replace("delete from lab_runs where run_id = '...'", "").replace(
        "delete from lab_labels where run_id = '...'", ""
    )
    for forbidden in (
        r"delete from",
        r"truncate ",
        r"drop table",
        r"drop database",
        r"down -v",
        r"rm -r",
    ):
        assert not re.search(forbidden, without, re.IGNORECASE), forbidden


# --------------------------------------------------------------------------- every command is real


def test_every_docker_compose_command_names_a_service_the_compose_files_define():
    services = _services()
    seen = 0
    for command in _commands(_voyage()):
        if not command.startswith("docker compose "):
            continue
        seen += 1
        tokens = shlex.split(command)[2:]
        if not tokens:  # prose naming the program, `docker compose`
            seen -= 1
            continue
        sub = next(t for t in tokens if not t.startswith("-"))
        rest = tokens[tokens.index(sub) + 1 :]
        if sub == "config":
            assert set(rest) <= {"--quiet", "--services"}, command
        elif sub == "exec":
            positional = [t for t in rest if not t.startswith("-")]
            assert positional[0] in services, command
        elif sub == "cp":
            assert rest[0].split(":")[0] in services, command
        elif sub in {"up", "restart", "stop", "ps", "logs"}:
            named = [t for t in rest if not t.startswith("-")]
            assert set(named) <= services, command
        else:
            pytest.fail(f"a docker compose subcommand the section was not checked for: {command}")
    assert seen >= 12, seen


def test_every_make_target_and_python_module_the_section_runs_exists():
    makefile = _text(MAKEFILE)
    for command in _commands(_voyage()):
        match = re.match(r"make (\S+)", command)
        if match:
            assert re.search(rf"^{re.escape(match.group(1))}:", makefile, re.MULTILINE), command
        for module in re.findall(r"python -m (app(?:\.\w+)+)", command):
            assert (REPO_ROOT / "backend" / (module.replace(".", "/") + ".py")).exists(), module
        for script in re.findall(r"python (eval/\S+\.py)", command):
            assert (REPO_ROOT / script).exists(), script


# --------------------------------------------------------------------------- the lab procedure


def test_the_lab_procedure_says_what_the_owner_does_for_each_run():
    flat = _flat(_sub("Lab procedure"))
    for needle in (
        "Gán nhãn lab",
        "`/admin/lab`",
        "before each attack run",
        "`kb`",
        "`test`",
        "Vietnam time",
        "UTC+7",
        "half-open",
        "overlap",
        "after it ends",
        "TP",
        "FP",
        "only the queue heads",
        "`DEDUP_ENABLED=false`",
        "approve",
        "concluded",
        "`/admin/knowledge`",
        "do not approve",
        "until the measurement is done",
        "n8n",
        "`:8001`",
        "before the first run",
        # fix round 1 (M3): the trial has both switches on already
        "already has `RAG_ENABLED=true` and `KNOWLEDGE_DRAFT_ENABLED=true`",
        "nothing in this section switches the lookup on",
        # fix round 1: the trial's webhook credential, by the name of its key and never its value
        "n8n must send the trial's webhook credential, not live's",
        "`WEBHOOK_API_KEY`",
        "`X-API-Key`",
        "`WEBHOOK_IP_ALLOWLIST`",
        "`401`",
        "`403`",
    ):
        assert needle.lower() in flat.lower(), f"the lab procedure no longer says {needle!r}"
    assert flat.index("`:8001`") < flat.index(
        "before each attack run"
    )  # the webhook is the first thing
    webhook = _text(REPO_ROOT / "backend" / "app" / "web" / "routers" / "webhook.py")
    assert 'request.headers.get("x-api-key", "")' in webhook and "status_code=401" in webhook
    assert "status_code=403" in webhook and "WEBHOOK_IP_ALLOWLIST" in webhook
    # the trial's switches are not restated as values: counts only
    assert "grep -c '^RAG_ENABLED=true$' .env" in flat


def test_the_lab_procedure_names_where_the_refusals_are_listed_and_they_are_there():
    flat = _flat(_sub("Lab procedure"))
    assert "module docstring of `backend/app/web/routers/admin_lab.py`" in flat
    docstring = ast.get_docstring(ast.parse(_text(ADMIN_LAB)))
    assert docstring
    named = re.findall(
        r"`(overlap|taken|not_after_starts|not_a_queue_head|outside_every_run)`", flat
    )
    assert len(set(named)) >= 4, named
    for reason in set(named):
        assert reason in docstring, f"{reason} is not in the module docstring of admin_lab.py"
    assert "2000" in flat and "2099" in flat and "UTC" in flat  # the year bound of a run's instants
    assert "year" in flat


# --------------------------------------------------------------------------- measuring

#: What P14-T11 settled (its docstring and `build_parser`), held here until the file is in the tree.
LAB_MEASURE_OPTIONS = {
    "measure": {"--test-runs", "--kb-cutoff", "--tiers", "--env-file", "--out", "--dsn", "--yes"},
    "calibrate": {"--runs", "--rerank-model", "--env-file", "--out", "--dsn", "--yes"},
}
LAB_MEASURE_EXIT_CODES = {0, 2, 3, 4, 5, 6, 7, 8}


def lab_measure_facts(source: str) -> tuple[dict[str, set[str]], set[int]]:
    """The options of each sub-command, and the exit-code values, read from `eval/lab_measure.py` as text."""
    tree = ast.parse(source)
    options: dict[str, set[str]] = {"measure": set(), "calibrate": set()}
    common: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_argument"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
            and node.args[0].value.startswith("--")
        ):
            owner = node.func.value
            name = node.args[0].value
            if isinstance(owner, ast.Name) and owner.id in options:
                options[owner.id].add(name)
            elif isinstance(owner, ast.Name) and owner.id == "p":
                common.add(name)
    for key in options:
        options[key] |= common
    codes = {
        node.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id.startswith("EXIT_") for t in node.targets)
        and isinstance(node.value, ast.Constant)
    }
    return options, codes


def test_the_extractor_reads_options_and_exit_codes_from_a_source():
    source = (
        "EXIT_OK = 0\nEXIT_APPROVAL = 5\n"
        "def build_parser():\n"
        "    measure = sub.add_parser('measure')\n"
        "    measure.add_argument('--test-runs', nargs='+')\n"
        "    def common(p):\n"
        "        p.add_argument('--yes', action='store_true')\n"
        "    calibrate = sub.add_parser('calibrate')\n"
        "    calibrate.add_argument('--runs', nargs='+')\n"
    )
    options, codes = lab_measure_facts(source)
    assert options == {"measure": {"--test-runs", "--yes"}, "calibrate": {"--runs", "--yes"}}
    assert codes == {0, 5}


def test_the_measuring_subsection_matches_the_options_and_exit_codes_of_lab_measure():
    """P14-T11 is in the tree since fix round 1 (it was a skipped guard before): this one must pass."""
    assert LAB_MEASURE.exists(), "eval/lab_measure.py (P14-T11) is not in the tree"
    options, codes = lab_measure_facts(_text(LAB_MEASURE))
    assert (
        options == LAB_MEASURE_OPTIONS
    ), "P14-T11 changed its options: the runbook and this list follow"
    assert codes == LAB_MEASURE_EXIT_CODES, "P14-T11 changed its exit codes: the runbook follows"


def test_the_measuring_subsection_runs_the_tool_in_app_where_eval_is_mounted():
    measuring = _sub("Measuring")
    flat = _flat(measuring)
    app = yaml.safe_load(_text(COMPOSE))["services"]["app"]
    assert "./eval:/srv/eval:ro" in app["volumes"], "eval/ is no longer mounted in app, read-only"
    assert "docker compose exec app python eval/lab_measure.py measure" in flat
    assert "docker compose exec app python eval/lab_measure.py calibrate" in flat
    # the mount is read-only, so the default --out (eval/results/lab/) cannot be written in the container
    assert "`:ro`" in flat and "--out /tmp/lab" in flat and "docker compose cp app:/tmp/lab" in flat
    assert "WORKDIR /srv" in _text(REPO_ROOT / "backend" / "Dockerfile")
    assert "PYTHONPATH=/srv/backend" in _text(REPO_ROOT / "backend" / "Dockerfile")


def test_every_lab_measure_option_the_section_uses_is_one_the_tool_has():
    used: dict[str, set[str]] = {"measure": set(), "calibrate": set()}
    for command in _commands(_sub("Measuring")):
        match = re.search(r"eval/lab_measure\.py (measure|calibrate)\b(.*)", command)
        if match:
            used[match.group(1)] |= set(re.findall(r"--[a-z-]+", match.group(2)))
    for sub, options in used.items():
        assert options, f"no `{sub}` command in the section"
        assert options <= LAB_MEASURE_OPTIONS[sub], (sub, options - LAB_MEASURE_OPTIONS[sub])
    assert "--dsn" not in used["measure"] | used["calibrate"]  # a DSN on a command line
    assert {"--test-runs", "--yes", "--tiers"} <= used["measure"]
    assert {"--runs", "--rerank-model"} <= used["calibrate"]


def test_the_measuring_subsection_runs_the_estimate_first_then_a_small_run_then_the_full_one():
    commands = [c for c in _commands(_sub("Measuring")) if "lab_measure.py measure" in c]
    assert len(commands) >= 4, commands
    estimate, small_estimate, small, full = commands[:4]
    assert "--yes" not in estimate and "--test-runs" not in estimate
    assert "--test-runs" in small_estimate and "--yes" not in small_estimate
    assert "--test-runs" in small and "--yes" in small
    assert "--yes" in full and "--test-runs" not in full
    # fix round 1 (M7): no `--yes` command without the same command, without `--yes`, before it
    for index, command in enumerate(commands):
        if " --yes" in command:
            twin = command.replace(" --yes", "")
            assert twin in commands[:index], f"{command!r} has no estimate before it"
    # run names are quoted: the option takes several names, so a name with a space splits and exits 2
    for command in _commands(_sub("Measuring")):
        for option in ("--test-runs", "--runs"):
            if f" {option} " in command and "<" in command:
                assert f'{option} "<' in command, command
    flat = _flat(_sub("Measuring"))
    # the exit table is complete (T11's own messages: an empty LLM_MODEL_PROPOSER, a kb run given to measure,
    # calibrate with no stored ranking)
    source = _text(LAB_MEASURE)
    assert "measure needs the LLM" in source and "LLM_MODEL_PROPOSER is empty" in source
    assert "a kb run: it built the knowledge base" in source
    assert "has a stored ranking" in source
    for needle in (
        "`LLM_MODEL_PROPOSER`",
        "a `kb` run given to `measure`",
        "`calibrate` finds no labelled alert with a stored ranking",
    ):
        assert needle in flat, f"the exit table no longer says {needle!r}"
    for code, meaning in (
        ("0", "done"),
        ("2", "usage"),
        ("3", "not ready"),
        ("4", "unusable"),
        ("5", "go-ahead"),
        ("6", "cap"),
        ("7", "nothing was answered"),
        ("8", "PARTIAL"),
    ):
        assert re.search(rf"`{code}`[^`]*{re.escape(meaning)}", flat), (code, meaning)
    assert "exit 5" in flat and "the estimate only" in flat


def test_the_measuring_subsection_gives_the_caveats_and_what_calibrate_decides():
    flat = _flat(_sub("Measuring"))
    for needle in (
        "neighbours' current status",
        "correlation section",
        "`history_same_run`",
        "RAG-on arm",
        "`--tiers 1`",
        "before analysts work",
        "first-look",
        "not written to `llm_runs`",
        "monthly cap",
        "`.env`",
        "saved on the admin",
        "`calibrate`",
        "`kb` runs",
        "never the test set",
        "`RAG_MIN_SCORE`",
        "`RAG_LEVEL_GIONG`",
        "`RAG_LEVEL_RAT_GIONG`",
        "`rerank-2.5`",
        "`rerank-3`",
        "`after_cutoff`",
        "`--kb-cutoff`",
        "READ ONLY",
        "Ctrl-C",
        # fix round 1 (M7, M3)
        "do not restart or recreate `app`",
        "no report",
        "a name with a space splits into two and exits 2",
        "whose alerts arrived with the RAG on and with entries already indexed",
        "exit 3",
        "Choose them before the first `test` run",
    ):
        assert needle in flat, f"the measuring subsection no longer says {needle!r}"
    # the recreate that applies the thresholds comes last, and only when no measurement is going on
    assert flat.rindex(
        "`docker compose up -d --force-recreate app worker rag-worker`"
    ) > flat.index("only when no `lab_measure.py` run is going on")
    assert flat.index("calibrate") < flat.index("only when no `lab_measure.py` run is going on")
