"""P5-T12 — `scripts/backup.sh`, `scripts/restore.sh` and `conf/soc-backup.cron`, tested as shell.

These scripts dump, create and drop databases, so the rails come first:

- every database a test touches is derived from TEST_DATABASE_URL's own name
  (`<name>_<role>_test`, the test_auth.py convention): the `_test` rail holds for all of them,
  and a Coder's run and a Reviewer's run on different DSNs cannot collide;
- every subprocess gets an environment built here (`_env`) with DATABASE_URL, DATABASE_URL_OWNER
  and BACKUP_KEEP removed, so no script can inherit the live DSN from the caller's shell;
- no password can reach a failure report (DEC-122). pytest prints the arguments of every frame in
  a failing traceback — fixture values, and library frames such as `psycopg.connect(conninfo)` —
  so every DSN here is a `_Dsn` and every environment an `_Env`, both with a redacted repr; a DSN
  is never a subprocess argument (DSNs travel in the environment) and never part of an assert.

The tests without a `db` mark need no server. Each one points the scripts at a port nothing
listens on, so a missing guard shows up as a connection failure (exit 1) and never as a pass.
"""

from __future__ import annotations

import dataclasses
import filecmp
import getpass
import os
import re
import subprocess
import time
import urllib.parse
from pathlib import Path

import psycopg
import pytest
from app.infra import config
from psycopg import sql

from tests import conftest

REPO_ROOT = conftest.REPO_ROOT
BACKUP = REPO_ROOT / "scripts" / "backup.sh"
RESTORE = REPO_ROOT / "scripts" / "restore.sh"
CRON = REPO_ROOT / "conf" / "soc-backup.cron"

FIVE = ("alerts", "intake", "llm_runs", "jobs", "audit_events")
# Port 9 (discard): nothing listens there, so a script that gets past a guard fails to connect.
NOWHERE = "postgresql://nobody@127.0.0.1:9/{}"
_SCRUBBED = {"DATABASE_URL", "DATABASE_URL_OWNER", "BACKUP_KEEP", "PGDATABASE", "PGSERVICE"}
_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")
_ENV_LINE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=")
_RECORD_LINE = re.compile(
    r"^\s+(schema_migrations|alerts|intake|llm_runs|jobs|audit_events)\s+(\d+)\b", re.MULTILINE
)

# Committed rows for the round trip's source: a different count per table, so a restore that
# lost data, or swapped two tables, cannot pass as 0 == 0.
_SEED = (
    (
        "INSERT INTO alerts (alert_id, rule_id, rule_level, severity, description, agent_name,"
        " alert_time, category, resolved_by, mapping_version, event_bucket_hash, raw_payload)"
        " SELECT '1790000000.' || g, '5710', 5, 'medium', 'round trip', 'rt-agent', now(),"
        " 'other', 'none', 'v1', encode(sha256(g::text::bytea), 'hex'), '{}'::jsonb"
        " FROM generate_series(1, 3) g"
    ),
    (
        "INSERT INTO intake (manager_id, source_alert_id, raw_text, via)"
        " SELECT 'rt', 'rt-' || g, '{\"n\": ' || g || '}', 'pull' FROM generate_series(1, 4) g"
    ),
    (
        "INSERT INTO llm_runs (run_id, pipeline, subject_type, subject_id, system_prompt,"
        " user_message) SELECT gen_random_uuid(), 'triage', 'alert', '1790000000.1', 'JSON', 'rt'"
        " FROM generate_series(1, 2)"
    ),
    "INSERT INTO jobs (job_type, subject_id) SELECT 'triage', 'rt-' || g FROM generate_series(1, 5) g",
    (
        "INSERT INTO audit_events (event_type, subject_id, actor_role)"
        " SELECT 'alert.received', 'rt-' || g, 'system' FROM generate_series(1, 6) g"
    ),
)

# What the 20/09 cutover compared (docs/db-docker.md): tables, indexes, constraints, triggers,
# grants to app_rw. A restore that dropped the append-only triggers would fail here.
_CATALOG = """
SELECT (SELECT count(*) FROM pg_tables WHERE schemaname = 'public'),
       (SELECT count(*) FROM pg_indexes WHERE schemaname = 'public'),
       (SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
         WHERE n.nspname = 'public'),
       (SELECT count(*) FROM pg_trigger t JOIN pg_class r ON r.oid = t.tgrelid
          JOIN pg_namespace n ON n.oid = r.relnamespace
         WHERE n.nspname = 'public' AND NOT t.tgisinternal),
       (SELECT count(*) FROM information_schema.role_table_grants WHERE grantee = 'app_rw')
"""


# --- redaction ----------------------------------------------------------------------------


class _Dsn(str):
    """A DSN whose repr hides its password (see the module docstring)."""

    def __repr__(self) -> str:
        return repr(conftest.redact_dsn(str(self)))


class _Env(dict):
    """A subprocess environment whose repr is only its size: it may hold PGPASSWORD."""

    def __repr__(self) -> str:
        return f"<environment of {len(self)} variables>"


# --- helpers ------------------------------------------------------------------------------


def _env(**extra: str) -> _Env:
    env = _Env((k, v) for k, v in os.environ.items() if k not in _SCRUBBED)
    env.update(extra)
    return env


def _run(args, *, env: _Env, cwd: Path = REPO_ROOT) -> tuple[int, str, str]:
    """(exit code, stdout, stderr) as plain values, so no CompletedProcess repr ever lands in
    an assertion message."""
    proc = subprocess.run(
        [str(a) for a in args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _with_db(dsn: str, dbname: str) -> _Dsn:
    """`dsn` pointed at `dbname`: same server, credentials and query string."""
    parts = urllib.parse.urlsplit(dsn)
    query = f"?{parts.query}" if parts.query else ""
    return _Dsn(f"{parts.scheme}://{parts.netloc}/{dbname}{query}")


def _maintenance(dsn: str) -> _Dsn:
    return _Dsn(conftest._maintenance_dsn(dsn))


def _derived(session_dsn: str, role: str) -> str:
    name = f"{conftest._dbname(session_dsn)}_{role}_test"
    conftest.require_test_dsn(_with_db(session_dsn, name))
    return name


def _drop(session_dsn: str, dbname: str) -> None:
    if not (dbname.endswith("_test") and _NAME.match(dbname)):
        pytest.fail(f"refusing to drop {dbname!r}: not a derived _test name")
    with psycopg.connect(_maintenance(session_dsn), autocommit=True) as conn:
        conn.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(dbname)))


def _create(session_dsn: str, dbname: str) -> None:
    with psycopg.connect(_maintenance(session_dsn), autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))


def _counts(dsn: _Dsn) -> dict[str, int]:
    with psycopg.connect(dsn) as conn:
        return {
            t: conn.execute(
                sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(t))
            ).fetchone()[0]
            for t in ("schema_migrations", *FIVE)
        }


def _catalog(dsn: _Dsn) -> tuple[int, ...]:
    with psycopg.connect(dsn) as conn:
        return tuple(conn.execute(_CATALOG).fetchone())


def _has_marker(dsn: _Dsn) -> bool:
    with psycopg.connect(dsn) as conn:
        return conn.execute("SELECT to_regclass('public.restore_marker')").fetchone()[0] is not None


def _server_major(dsn: _Dsn) -> int:
    with psycopg.connect(dsn) as conn:
        return int(conn.execute("SHOW server_version_num").fetchone()[0]) // 10000


def _printed_counts(out: str) -> dict[str, int]:
    return {m.group(1): int(m.group(2)) for m in _RECORD_LINE.finditer(out)}


def _stubs(backups: Path, n: int = 20) -> list[str]:
    """`n` stub dumps, 30+ days old, whose mtime order is a permutation of their name order
    (rank = 7·i mod n; 7 and 20 are coprime) — only a prune that sorts by mtime keeps the
    right ones."""
    base = time.time() - 40 * 86400
    names = []
    for i in range(n):
        name = f"soc-202608{i + 1:02d}T020000Z.dump"
        path = backups / name
        path.write_bytes(b"stub")
        stamp = base + ((i * 7) % n) * 3600
        os.utime(path, (stamp, stamp))
        names.append(name)
    return names


def _newest_stubs(names: list[str], keep: int) -> set[str]:
    n = len(names)
    return {name for i, name in enumerate(names) if (i * 7) % n >= n - keep}


def _script(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _backup_hour() -> int:
    """§6.3's BACKUP_HOUR from the dataclass default — no Config is built (DEC-122)."""
    return next(f.default for f in dataclasses.fields(config.Config) if f.name == "BACKUP_HOUR")


def _cron_job_line() -> str:
    lines = CRON.read_text(encoding="utf-8").splitlines()
    jobs = [
        line
        for line in lines
        if line.strip() and not line.lstrip().startswith("#") and not _ENV_LINE.match(line)
    ]
    assert len(jobs) == 1, jobs
    return jobs[0]


def _cron_env(home: Path, dsn: str) -> _Env:
    """What cron hands a job (HOME, LOGNAME, PATH=/usr/bin:/bin, SHELL=/bin/sh), plus the test
    database's password, which the scratch .env leaves out so it never sits in a file."""
    env = _Env(PATH="/usr/bin:/bin", HOME=str(home), SHELL="/bin/sh", LOGNAME=getpass.getuser())
    password = urllib.parse.urlsplit(dsn).password
    if password is not None:
        env["PGPASSWORD"] = urllib.parse.unquote(password)
    return env


def _without_password(dsn: str) -> str:
    parts = urllib.parse.urlsplit(dsn)
    if parts.password is None:
        return str(dsn)
    netloc = f"{parts.username}@{parts.hostname}" + (f":{parts.port}" if parts.port else "")
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{netloc}{parts.path}{query}"


def _restore(dump: Path, target: str, *extra: str, env: _Env) -> tuple[int, str]:
    rc, out, err = _run(["bash", RESTORE, dump, "--into", target, *extra], env=env)
    return rc, out + err


# --- fixtures -----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def session_dsn(_test_database) -> _Dsn:
    """The session database's DSN, redacted in every traceback. Tests in this file request this,
    never `_test_database` itself."""
    return _Dsn(_test_database)


@pytest.fixture(scope="module")
def session_dump(session_dsn, tmp_path_factory) -> Path:
    """One dump of the session database, made by backup.sh itself."""
    work = tmp_path_factory.mktemp("session_dump")
    rc, out, err = _run(
        ["bash", BACKUP, "--quiet"], cwd=work, env=_env(DATABASE_URL_OWNER=session_dsn)
    )
    assert rc == 0, out + err
    (dump,) = sorted((work / "backups").glob("soc-*.dump"))
    return dump


@pytest.fixture
def source_db(session_dsn):
    """A private, migrated database with committed rows in each of the five tables."""
    name = _derived(session_dsn, "source")
    dsn = _with_db(session_dsn, name)
    _drop(session_dsn, name)
    _create(session_dsn, name)
    try:
        rc, out, err = _run(["bash", "scripts/migrate.sh"], env=_env(DATABASE_URL_OWNER=dsn))
        assert rc == 0, out + err
        with psycopg.connect(dsn) as conn:
            for statement in _SEED:
                conn.execute(statement)
        yield dsn
    finally:
        _drop(session_dsn, name)


# --- (a) backup.sh writes a file and refreshes latest.dump ---------------------------------


@pytest.mark.db
def test_backup_writes_a_dump_and_refreshes_latest(session_dsn, tmp_path):
    rc, out, err = _run(
        ["bash", BACKUP, "--quiet"], cwd=tmp_path, env=_env(DATABASE_URL_OWNER=session_dsn)
    )
    assert rc == 0, out + err
    backups = tmp_path / "backups"
    dumps = sorted(p.name for p in backups.glob("soc-*.dump"))
    assert len(dumps) == 1, dumps
    same = filecmp.cmp(backups / dumps[0], backups / "latest.dump", shallow=False)
    assert same, "latest.dump is not a copy of the dump this run wrote"
    leftovers = sorted(p.name for p in backups.iterdir() if p.name not in {dumps[0], "latest.dump"})
    assert leftovers == []
    # --quiet is the cron path: exactly one line per run, so the log shows every night it ran.
    lines = out.splitlines()
    assert len(lines) == 1 and lines[0].startswith("backup: ok "), out
    # Made by the pg_dump of the server's own major version when the host has one: a newer
    # pg_dump writes an archive the server's pg_restore cannot read (measured 26/09: pg_dump 18
    # writes archive 1.16, and pg_restore 16 answers "unsupported version (1.16)").
    rc, listing, err = _run(["pg_restore", "--list", backups / dumps[0]], env=_env())
    assert rc == 0, err
    assert "TABLE DATA public schema_migrations" in listing
    found = re.search(r"Dumped by pg_dump version: (\d+)", listing)
    assert found, listing[:400]
    dumped_by = int(found.group(1))
    server_major = _server_major(session_dsn)
    if Path(f"/usr/lib/postgresql/{server_major}/bin/pg_dump").exists():
        assert dumped_by == server_major


# --- (b) retention: the 14 newest soc-*.dump by mtime, latest.dump never pruned ------------


@pytest.mark.db
def test_retention_keeps_the_14_newest_dumps_and_latest(session_dsn, tmp_path):
    backups = tmp_path / "backups"
    backups.mkdir()
    names = _stubs(backups)
    latest = backups / "latest.dump"
    latest.write_bytes(b"previous latest")
    os.utime(latest, (time.time() - 90 * 86400,) * 2)  # older than every stub

    rc, out, err = _run(["bash", BACKUP], cwd=tmp_path, env=_env(DATABASE_URL_OWNER=session_dsn))
    assert rc == 0, out + err

    remaining = {p.name for p in backups.glob("soc-*.dump")}
    written = remaining - set(names)
    assert len(written) == 1, sorted(written)  # the dump this run wrote
    kept = len(remaining)
    assert kept == 14
    assert remaining == _newest_stubs(names, 13) | written
    assert latest.exists() and latest.read_bytes() != b"previous latest"
    assert out.count("backup: pruned ") == 7, out


@pytest.mark.parametrize("keep", ["0", "-1", "x", "14x", "014"])
def test_backup_refuses_a_bad_backup_keep_before_dumping(tmp_path, keep):
    """0 would prune the dump just written; an empty value means the default, 14."""
    backups = tmp_path / "backups"
    backups.mkdir()
    names = _stubs(backups)
    env = _env(DATABASE_URL_OWNER=NOWHERE.format("nowhere_test"), BACKUP_KEEP=keep)
    rc, out, err = _run(["bash", BACKUP], cwd=tmp_path, env=env)
    assert rc == 2, out + err
    assert "BACKUP_KEEP" in err
    after = sorted(p.name for p in backups.iterdir())
    assert after == sorted(names)


def test_a_failed_dump_leaves_no_file_and_prunes_nothing(tmp_path):
    """A half-written dump must never be taken for a backup: P5-T11's age check reads
    backups/, and pruning would push a good dump out of the 14."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # A server major no host has binaries for (so the PATH pg_dump is used), and a pg_dump
    # that dies half-way through writing its file.
    _script(bin_dir / "psql", "#!/bin/sh\necho 99\n")
    _script(
        bin_dir / "pg_dump",
        "#!/bin/sh\n"
        'for a in "$@"; do case "$a" in --file=*) printf partial > "${a#--file=}";; esac; done\n'
        'echo "pg_dump: error: simulated failure" >&2\n'
        "exit 1\n",
    )
    backups = tmp_path / "backups"
    backups.mkdir()
    names = _stubs(backups)
    (backups / "latest.dump").write_bytes(b"previous latest")
    env = _env(
        DATABASE_URL_OWNER=NOWHERE.format("nowhere_test"),
        PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
    )

    rc, out, err = _run(["bash", BACKUP, "--quiet"], cwd=tmp_path, env=env)

    assert rc != 0, out + err
    assert "backup: FAILED" in err
    after = sorted(p.name for p in backups.iterdir())
    assert after == sorted([*names, "latest.dump"])
    assert (backups / "latest.dump").read_bytes() == b"previous latest"


# --- (c) restore.sh refuses the live database, and anything it must not touch ---------------


@pytest.mark.parametrize("var", ["DATABASE_URL", "DATABASE_URL_OWNER"])
def test_restore_refuses_the_live_database(tmp_path, var):
    """The guard most worth having watched fail (DEC-025): with it gone, restore.sh goes on to
    connect — to a port nothing listens on — and exits 1, not 2."""
    dump = tmp_path / "any.dump"
    dump.write_bytes(b"never read")
    live = "soc_probe_live_test"
    env = _env(DATABASE_URL=NOWHERE.format("soc_probe_other_test"))
    env[var] = NOWHERE.format(live)

    rc, out = _restore(dump, live, env=env)

    assert rc == 2, out
    assert "REFUSED" in out
    assert re.search(rf"^restore:\s+target\s+\(--into\)\s+{live}$", out, re.MULTILINE), out
    assert re.search(rf"^restore:\s+live\s+\({var}\)\s+{live}$", out, re.MULTILINE), out


_REFUSALS = {
    "no arguments": ([], {}, r"usage: "),
    "no --into": (["{dump}"], {}, r"--into"),
    "an unknown option": (["{dump}", "--into", "soc_probe_x_test", "--fast"], {}, r"--fast"),
    "no DATABASE_URL": (
        ["{dump}", "--into", "soc_probe_x_test"],
        {"DATABASE_URL": None},
        r"DATABASE_URL is unset",
    ),
    "DATABASE_URL not a URI": (
        ["{dump}", "--into", "soc_probe_x_test"],
        {"DATABASE_URL": "dbname=soc_probe_live_test"},
        r"postgresql://",
    ),
    "a system database": (["{dump}", "--into", "template1"], {}, r"system database"),
    "not a plain name": (["{dump}", "--into", "soc;drop"], {}, r"plain database name"),
    "--force on a non-_test name": (
        ["{dump}", "--into", "soc_probe_x", "--force"],
        {},
        r"--force.*_test",
    ),
    "a missing dump": (["{missing}", "--into", "soc_probe_x_test"], {}, r"no such dump"),
}


@pytest.mark.parametrize("case", list(_REFUSALS))
def test_restore_refuses_before_touching_anything(tmp_path, case):
    args, env_changes, message = _REFUSALS[case]
    dump = tmp_path / "any.dump"
    dump.write_bytes(b"never read")
    env = _env(DATABASE_URL=NOWHERE.format("soc_probe_live_test"))
    for key, value in env_changes.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    argv = [a.format(dump=dump, missing=tmp_path / "missing.dump") for a in args]

    rc, out, err = _run(["bash", RESTORE, *argv], env=env)

    assert rc == 2, out + err
    assert re.search(message, err), err


@pytest.mark.db
def test_restore_refuses_a_non_empty_target_without_force(session_dsn, session_dump):
    target = _derived(session_dsn, "nonempty")
    target_dsn = _with_db(session_dsn, target)
    _drop(session_dsn, target)
    try:
        rc, out = _restore(session_dump, target, env=_env(DATABASE_URL=session_dsn))
        assert rc == 0, out
        with psycopg.connect(target_dsn, autocommit=True) as conn:
            conn.execute("CREATE TABLE restore_marker (x int)")  # only a restore could remove it

        rc, out = _restore(session_dump, target, env=_env(DATABASE_URL=session_dsn))
        assert rc == 2, out
        assert "not empty" in out
        assert _has_marker(target_dsn), "a refused restore touched the target"

        # Acceptance 4's stand-in: the same non-empty database, named as the live one.
        rc, out = _restore(session_dump, target, "--force", env=_env(DATABASE_URL=target_dsn))
        assert rc == 2, out
        assert re.search(rf"^restore:\s+target\s+\(--into\)\s+{target}$", out, re.MULTILINE), out
        assert re.search(
            rf"^restore:\s+live\s+\(DATABASE_URL\)\s+{target}$", out, re.MULTILINE
        ), out
        assert _has_marker(target_dsn), "the live-database guard let a restore through"

        rc, out = _restore(session_dump, target, "--force", env=_env(DATABASE_URL=session_dsn))
        assert rc == 0, out
        assert not _has_marker(target_dsn), "--force did not start from an empty database"
        printed = _printed_counts(out)
        assert printed.get("schema_migrations") == 17, out
    finally:
        _drop(session_dsn, target)


# --- (d) the round trip P8's drill will run ----------------------------------------------


@pytest.mark.db
def test_round_trip_restores_into_a_second_database(session_dsn, source_db, tmp_path):
    target = _derived(session_dsn, "restore")
    target_dsn = _with_db(session_dsn, target)
    _drop(session_dsn, target)
    try:
        rc, out, err = _run(["bash", BACKUP], cwd=tmp_path, env=_env(DATABASE_URL_OWNER=source_db))
        assert rc == 0, out + err
        (dump,) = sorted((tmp_path / "backups").glob("soc-*.dump"))

        # As in the drill: DATABASE_URL names the database the dump came from.
        rc, out = _restore(dump, target, env=_env(DATABASE_URL=source_db))
        assert rc == 0, out

        printed = _printed_counts(out)
        expected = _counts(source_db)
        restored = _counts(target_dsn)
        assert printed == expected
        assert restored == expected
        assert expected["schema_migrations"] == 17
        seeded = {t: expected[t] for t in FIVE}
        assert seeded == {"alerts": 3, "intake": 4, "llm_runs": 2, "jobs": 5, "audit_events": 6}
        source_catalog = _catalog(source_db)
        restored_catalog = _catalog(target_dsn)
        assert restored_catalog == source_catalog
        assert "://" not in out  # the record names databases, never a DSN
    finally:
        _drop(session_dsn, target)


# --- (e) the schedule: one user-crontab line, no container runtime anywhere ----------------


def test_cron_file_parses():
    text = CRON.read_text(encoding="utf-8")
    runtime_words = re.findall(r"docker|compose", text, flags=re.IGNORECASE)
    assert runtime_words == []  # DEC-018/DEC-021, as a test instead of a sentence
    assert re.search(r'^MAILTO=""$', text, re.MULTILINE)
    # The Owner's check after installing is `crontab -l | grep -c backup.sh` → 1, so no comment
    # line may name the script.
    naming_lines = [line for line in text.splitlines() if "backup.sh" in line]
    assert len(naming_lines) == 1, naming_lines

    fields = _cron_job_line().split(None, 5)
    assert len(fields) == 6, fields
    minute, hour, day, month, weekday, command = fields
    backup_hour = _backup_hour()
    assert (minute, hour, day, month, weekday) == ("0", str(backup_hour), "*", "*", "*")

    script = re.search(r"(\S+)/scripts/backup\.sh\b", command)
    assert script, command
    root = script.group(1)
    assert root.startswith("/"), root  # an absolute path to backup.sh
    assert f"cd {root} " in command  # run from the repository root
    assert ". ./.env" in command  # the DSN sourced from .env
    assert "--quiet" in command
    assert re.search(r'>>\s*"\$HOME/[^"\s]+"\s+2>&1', command), command  # stdout AND stderr


@pytest.mark.db
def test_the_cron_line_itself_writes_a_dump(session_dsn, tmp_path):
    """The scheduled command, run by /bin/sh with cron's environment — with the repository path
    swapped for a scratch copy whose .env names the test database, so the real checkout (and
    its .env) is never used."""
    command = _cron_job_line().split(None, 5)[5]
    root = re.search(r"cd (\S+) ", command).group(1)
    log_name = re.search(r'"\$HOME/([^"]+)"', command).group(1)

    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    (repo / "scripts" / "backup.sh").symlink_to(BACKUP)
    (repo / ".env").write_text(
        f"DATABASE_URL_OWNER={_without_password(session_dsn)}\n", encoding="utf-8"
    )
    home = tmp_path / "home"
    home.mkdir()

    local = command.replace(root, str(repo))
    still_real = root in local
    assert not still_real  # never run the line against the real checkout

    proc = subprocess.run(
        ["/bin/sh", "-c", local],
        env=_cron_env(home, session_dsn),
        cwd=home,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    rc = proc.returncode
    log = (home / log_name).read_text(encoding="utf-8")

    assert rc == 0, log
    dumps = sorted(p.name for p in (repo / "backups").glob("soc-*.dump"))
    assert len(dumps) == 1, dumps
    assert (repo / "backups" / "latest.dump").is_file()
    log_lines = log.splitlines()
    assert len(log_lines) == 1 and log_lines[0].startswith("backup: ok "), log
