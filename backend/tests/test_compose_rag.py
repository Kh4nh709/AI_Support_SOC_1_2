"""`docker-compose.rag.yml` — the learned-knowledge override (P13-T09, DEC-210, spec §7.1 and §7.2).

WHY A TEST FOR A COMPOSE FILE. Three facts only the compose files hold, and a mistake in any of them
passes every native test (the lesson of `test_compose_mounts.py`, DEC-135):

* The repository is mirrored under `/srv` in the containers, so `rag.entries.KB_LEARNED_ROOT` is
  `/srv/kb_learned` there. The directory exists in a container only as a bind mount. `app` writes the
  entry files (the admin approve route), so it mounts it read-write; `rag-worker` only reads them (the
  V-R1 hash check), so it mounts it `:ro`; `worker` must not see it at all (spec §7.2: the main
  worker answers ① from the database alone). The base file gives `worker` the very volume list of
  `app` through `<<: *backend`, so the override may add the mount to `app` without `worker` getting
  it, and a "tidy-up" that rewrites the override to share one list would hand `worker` the directory.
* `rag-worker` is a service of the override and nothing of the base file: it must carry the base
  `app`'s image, user, environment, env file, mounts and host entries, because it is the same code in
  the same layout; and no port, or it would collide with `app`'s 8000.
* The base file stays as it is: switching the feature on is `COMPOSE_FILE` in `.env` and nothing else,
  and switching it off again leaves a compose file that never heard of it.

PURE. No docker, no database: it parses the two YAML files.
"""

import shutil
import subprocess
from pathlib import Path, PurePosixPath

import pytest
import yaml
from app.rag.entries import KB_LEARNED_ROOT

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE = REPO_ROOT / "docker-compose.yml"
OVERRIDE = REPO_ROOT / "docker-compose.rag.yml"
CONTAINER_ROOT = PurePosixPath("/srv")
MOUNT = "/srv/kb_learned"
VECTOR_URL_KEY = "VECTOR_DATABASE_URL"
VECTOR_URL = "postgresql://vector:${VECTOR_DB_PASSWORD}@vectordb:5432/vectors"
VECTOR_PASSWORD = "${VECTOR_DB_PASSWORD:?set VECTOR_DB_PASSWORD in .env (runbook, DEC-213)}"


def _load(path: Path) -> dict:
    assert path.exists(), f"{path.name} does not exist"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _split(volume: str) -> tuple[str, str, str]:
    """`./host:/container[:mode]` -> (host, container, mode); no mode means read-write."""
    host, container, *rest = volume.split(":")
    return host, container, rest[0] if rest else "rw"


def _effective_volumes(service: str) -> list[str]:
    """The service's volumes once Compose has merged the override over the base: the lists are
    joined and an entry of the override replaces the base's entry of the same container path."""
    base = _load(BASE)["services"].get(service, {}).get("volumes", [])
    over = _load(OVERRIDE)["services"].get(service, {}).get("volumes", [])
    replaced = {_split(v)[1] for v in over}
    return [v for v in base if _split(v)[1] not in replaced] + list(over)


def _services() -> dict:
    return _load(OVERRIDE)["services"]


# --------------------------------------------------------------------------- what the mount must be


def test_the_mount_is_where_the_code_looks_for_the_directory():
    """`KB_LEARNED_ROOT` is `<repository>/kb_learned`; in the container the repository is `/srv`."""
    relative = KB_LEARNED_ROOT.resolve().relative_to(REPO_ROOT.resolve())
    assert relative.parts == ("kb_learned",), relative
    assert str(CONTAINER_ROOT / "kb_learned") == MOUNT


def test_the_override_defines_only_app_rag_worker_and_vectordb():
    """No other service is redefined: `worker`, `db` and `ui` are exactly the base file's. `vectordb` is
    the one service P14-T04 (DEC-213) adds, and its named volume the one top-level key."""
    assert set(_services()) == {"app", "rag-worker", "vectordb"}
    assert set(_load(OVERRIDE)) <= {"services", "volumes"}, "the override adds a top-level key"
    assert set(_load(OVERRIDE)["volumes"]) == {"vectordata"}


# --------------------------------------------------------------------------- the three mounts


def test_app_mounts_kb_learned_read_write():
    mounts = {_split(v)[1]: _split(v) for v in _effective_volumes("app")}
    assert MOUNT in mounts, sorted(mounts)
    host, _, mode = mounts[MOUNT]
    assert host == "./kb_learned"
    assert mode == "rw", f"app must write the entry files, its mount is {mode!r}"


def test_app_keeps_every_mount_it_had():
    base = _load(BASE)["services"]["app"]["volumes"]
    effective = _effective_volumes("app")
    for volume in base:
        assert volume in effective, f"app lost {volume!r}"
    assert len(effective) == len(base) + 1


def test_rag_worker_mounts_kb_learned_read_only():
    mounts = {_split(v)[1]: _split(v) for v in _services()["rag-worker"]["volumes"]}
    assert MOUNT in mounts
    host, _, mode = mounts[MOUNT]
    assert host == "./kb_learned"
    assert mode == "ro", f"rag-worker only reads the entry files, its mount is {mode!r}"
    assert _services()["rag-worker"]["volumes"][-1].endswith(":ro")


def test_worker_has_no_kb_learned_in_its_effective_volumes():
    effective = _effective_volumes("worker")
    assert effective, "the base worker lost its volumes"
    assert not [v for v in effective if "kb_learned" in v], effective


def test_worker_is_the_base_workers_and_the_override_does_not_name_it():
    assert "worker" not in _services()
    assert _effective_volumes("worker") == _load(BASE)["services"]["worker"]["volumes"]


# --------------------------------------------------------------------------- the rag-worker service


def test_rag_worker_runs_the_rag_worker_module():
    command = _services()["rag-worker"]["command"]
    assert command == "python -m app.web.rag_worker"
    assert (REPO_ROOT / "backend" / "app" / "web" / "rag_worker.py").exists()


def test_rag_worker_is_the_base_app_in_every_key_but_command_ports_volumes_and_one_variable():
    """Every key, not a hand-picked list (T09 review, M7): a key added to the base `app` later (a
    `healthcheck`, `stop_grace_period`, a new `environment` entry) must reach `rag-worker` too, or this
    fails and names it. `command` differs by design, `ports` must be absent, and `volumes` has its own
    tests (one extra read-only mount). `environment` is the base app's plus exactly one variable,
    `VECTOR_DATABASE_URL` (P14-T04, DEC-213): the vector database's address, given to this service only.
    """
    app = _load(BASE)["services"]["app"]
    rag = _services()["rag-worker"]
    exempt = {"command", "ports", "volumes", "environment"}
    keys = (set(app) | set(rag)) - exempt
    assert {"build", "image", "user", "env_file", "extra_hosts"} <= keys
    for key in sorted(keys):
        assert rag.get(key) == app.get(key), f"rag-worker's {key} is not the base app's"
    extra = {k: v for k, v in rag["environment"].items() if k not in app["environment"]}
    assert set(extra) == {VECTOR_URL_KEY}, f"rag-worker's extra environment keys: {sorted(extra)}"
    assert {k: v for k, v in rag["environment"].items() if k != VECTOR_URL_KEY} == app[
        "environment"
    ]


def test_rag_worker_has_the_base_apps_other_mounts_in_the_same_order():
    app = _load(BASE)["services"]["app"]["volumes"]
    rag = _services()["rag-worker"]["volumes"]
    assert [v for v in rag if "kb_learned" not in v] == app


def test_rag_worker_waits_for_the_database_and_restarts_like_the_others():
    app = _load(BASE)["services"]["app"]
    rag = _services()["rag-worker"]
    assert rag["depends_on"] == app["depends_on"]
    assert rag["restart"] == app["restart"] == "unless-stopped"


def test_rag_worker_publishes_no_port():
    """`app` publishes 8000; a second service on it would stop `up -d`."""
    assert not _services()["rag-worker"].get("ports")


def test_the_app_entry_adds_only_the_mount():
    assert set(_services()["app"]) == {"volumes"}
    assert _services()["app"]["volumes"] == ["./kb_learned:/srv/kb_learned"]


# --------------------------------------------------------------------------- the vectordb service (P14-T04, DEC-213)


def _vectordb() -> dict:
    return _services()["vectordb"]


def test_vectordb_is_the_pinned_pgvector_image_for_postgres_16():
    assert _vectordb()["image"] == "pgvector/pgvector:0.8.0-pg16"


def test_vectordb_publishes_nothing_to_the_host_or_the_lan():
    """No `ports`, and no `expose` either: only a service on the Compose network reaches it."""
    vectordb = _vectordb()
    assert "ports" not in vectordb, "vectordb publishes a port: nothing may reach it from the host"
    assert not vectordb.get("ports")
    assert "expose" not in vectordb
    assert "network_mode" not in vectordb


def test_vectordb_password_is_the_required_compose_variable_with_the_runbook_message():
    environment = _vectordb()["environment"]
    assert environment["POSTGRES_PASSWORD"] == VECTOR_PASSWORD
    assert environment["POSTGRES_USER"] == "vector"
    assert environment["POSTGRES_DB"] == "vectors"
    assert set(environment) == {"POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB"}


def test_vectordb_holds_its_data_in_its_own_named_volume_and_mounts_nothing_else():
    assert _vectordb()["volumes"] == ["vectordata:/var/lib/postgresql/data"]
    assert "vectordata" in _load(OVERRIDE)["volumes"]
    assert "vectordata" not in (_load(BASE).get("volumes") or {})
    assert _load(BASE)["volumes"].keys() == {"pgdata"}, "the base file's volumes changed"


def test_vectordb_has_a_pg_isready_healthcheck_and_restarts_like_the_others():
    vectordb = _vectordb()
    assert vectordb["healthcheck"]["test"] == ["CMD-SHELL", "pg_isready -U vector -d vectors"]
    for key in ("interval", "timeout", "retries"):
        assert key in vectordb["healthcheck"], key
    assert vectordb["restart"] == "unless-stopped"


def test_vectordb_gets_no_env_file_and_depends_on_nothing():
    """The main `.env` (LLM key, JWT secret, database passwords) must not reach this container; and it
    waits for nothing: `rag-worker` does not wait for it either."""
    vectordb = _vectordb()
    assert "env_file" not in vectordb
    assert "depends_on" not in vectordb
    assert "build" not in vectordb and "user" not in vectordb


def test_only_rag_worker_is_given_the_vector_database_url():
    rag = _services()["rag-worker"]
    assert rag["environment"][VECTOR_URL_KEY] == VECTOR_URL
    base = _load(BASE)["services"]
    for name, service in {**base, **_services()}.items():
        if name == "rag-worker":
            continue
        assert VECTOR_URL_KEY not in (service.get("environment") or {}), name
    # nor does the `app` entry of the override, nor `worker` through it
    assert set(_services()["app"]) == {"volumes"}
    assert "worker" not in _services()


def test_rag_worker_does_not_depend_on_vectordb_so_that_a_dead_one_is_a_failure_kind_not_a_start_failure():
    depends = _services()["rag-worker"]["depends_on"]
    assert "vectordb" not in depends
    assert set(depends) == set(_load(BASE)["services"]["app"]["depends_on"]) == {"db"}


def test_no_other_service_depends_on_vectordb():
    for name, service in {**_load(BASE)["services"], **_services()}.items():
        depends = service.get("depends_on") or {}
        assert "vectordb" not in depends, name


def test_the_header_says_what_vectordb_is_and_that_this_branch_is_trial_only():
    text = OVERRIDE.read_text(encoding="utf-8")
    header = text.split("\nservices:")[0]
    flat = " ".join(line.lstrip("# ").strip() for line in header.splitlines())
    for phrase in (
        "vectordb",
        "pgvector",
        "derived index",  # it holds nothing the main database does not: rebuilt, never backed up
        "only `rag-worker` reaches it",
        "no `ports`",
        "never merged into `main`",
        "trial",
        "VECTOR_DB_PASSWORD",
        "DEC-213",
    ):
        assert phrase in flat, f"the header no longer says {phrase!r}"


# --------------------------------------------------------------------------- the base file is left alone


def test_the_base_compose_file_does_not_mention_the_feature():
    text = BASE.read_text(encoding="utf-8")
    for needle in (
        "kb_learned",
        "rag-worker",
        "rag_worker",
        "docker-compose.rag",
        "vectordb",
        "pgvector",
        "vectordata",
        "VECTOR_DATABASE_URL",
        "VECTOR_DB_PASSWORD",
    ):
        assert (
            needle not in text
        ), f"docker-compose.yml names {needle!r}: the feature lives in the override"


def test_the_override_says_how_it_is_switched_on_and_off():
    text = OVERRIDE.read_text(encoding="utf-8")
    assert "COMPOSE_FILE=docker-compose.yml:docker-compose.rag.yml" in text
    assert "docs/runbook.md" in text  # where the steps are, not restated here


def test_the_override_says_the_directory_comes_with_the_checkout_and_must_be_owned_by_the_host_user():
    """`kb_learned/README.md` is tracked, so the merge creates the directory (T09 review, I1)."""
    text = OVERRIDE.read_text(encoding="utf-8")
    assert "mkdir -p kb_learned && ls -ldn kb_learned" in text
    assert "its README.md is tracked" in text and "HOST_UID:HOST_GID" in text
    assert (
        "BEFORE the first `up -d`" not in text
    ), "the old instruction (make it before up -d) is back"


# --------------------------------------------------------------------------- the directory on the host


def test_kb_learned_has_a_readme_and_git_ignores_everything_else_in_it():
    readme = REPO_ROOT / "kb_learned" / "README.md"
    assert readme.exists(), "kb_learned/README.md is the one tracked file of the directory"
    lines = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert lines.index("kb_learned/*") < lines.index("!kb_learned/README.md")


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
def test_check_ignore_agrees_about_which_files_of_the_directory_are_ignored():
    def ignored(path: str) -> bool:
        # --no-index: judge the rules, not whether the file is already tracked.
        command = ["git", "check-ignore", "--no-index", "-q", path]
        return subprocess.run(command, cwd=REPO_ROOT, check=False).returncode == 0

    assert ignored("kb_learned/entries/malware/00000000-0000-0000-0000-000000000000.md")
    assert ignored("kb_learned/retired/00000000-0000-0000-0000-000000000000.md")
    assert not ignored("kb_learned/README.md")


def test_the_readme_says_what_the_directory_is():
    text = (REPO_ROOT / "kb_learned" / "README.md").read_text(encoding="utf-8").lower()
    for needle in (
        "entries/<category>/<entry_id>.md",
        "retired/",
        "python -m app.rag.publish --rebuild",
        "the database is the source",
        "never edit a file here by hand",
        "docs/runbook.md",
        "this file is tracked",
        "ls -ldn kb_learned",
        "`host_uid`:`host_gid`",
    ):
        assert needle in text, f"the README no longer says {needle!r}"
