"""P14 final fix wave, section C of the brief - the small code and docstring fixes.

* **19 (deferred 2, point 2).** `Config.__repr__` and `Config.dump()` hid the Voyage key and the vector DSN but
  showed `DATABASE_URL`, `DATABASE_URL_OWNER` and `TEST_DATABASE_URL`, whose passwords a log line or a traceback
  would have printed. They are in `_SECRET_FIELDS` now; the field itself still holds the real value.
* **15 (M4).** The health check `rag_lookup_failures` counted a `failed` row with no stored kind as `unknown`; the
  lookup, the UI and the lab measurement say `provider_error`. The word is defined once, in `infra.errors`
  (`infra` may import nothing from `rag`, so the health check cannot import `rag.lookup`; `rag.lookup` imports it
  from `infra`). The count itself is `test_health.py`'s `test_rag_lookup_failures_says_which_kinds_failed`.
* **13, 14, 16, 17, 18, 20.** Sentences that were false (or a line too long): the run rows of a retried lookup, the
  four checks of `_read_or_none`, the handler of `knowledge_embed`, the lookup the admin page shows and the kind of
  a pre-023 row, the 155-column line of `admin_lab.py`, and what `RAG_MODEL` is. A document is not judged; the
  stale sentence is shown gone and the true one there.

PURE. No database, no socket.
"""

from __future__ import annotations

import ast
import importlib.util
import pathlib
import re

import pytest
from app.infra import errors, health
from app.infra.config import Config, load
from app.rag import lookup
from app.rag.failures import FAILURE_KINDS

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
APP = REPO_ROOT / "backend" / "app"


def _source(*parts: str) -> str:
    return APP.joinpath(*parts).read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


# ── 19 ─────────────────────────────────────────────────────────────────────────────────────

_DSN_FIELDS = ("DATABASE_URL", "DATABASE_URL_OWNER", "TEST_DATABASE_URL")
_PASSWORD = "PW-SENTINEL-0f3a9c"


def _with_dsns(monkeypatch) -> Config:
    for key in _DSN_FIELDS:
        monkeypatch.setenv(key, f"postgresql://{key.lower()}:{_PASSWORD}-{key}@127.0.0.1:5432/soc")
    return load(env_file="/dev/null")


def test_a_dsn_with_a_password_is_masked_in_repr_str_and_dump(monkeypatch):
    cfg = _with_dsns(monkeypatch)
    text = repr(cfg) + str(cfg) + repr(cfg.dump()) + str(cfg.dump())
    assert _PASSWORD not in text and "PW-SENTINEL" not in text
    for key in _DSN_FIELDS:
        assert f"{key}='***'" in repr(cfg), key
        assert cfg.dump()[key] == "***"
    # what the code connects with is untouched
    for key in _DSN_FIELDS:
        assert getattr(cfg, key).endswith(f"{_PASSWORD}-{key}@127.0.0.1:5432/soc")


def test_the_other_fields_still_show(monkeypatch):
    cfg = _with_dsns(monkeypatch)
    dumped = cfg.dump()
    assert dumped["LLM_MONTHLY_USD_CAP"] == cfg.LLM_MONTHLY_USD_CAP != "***"
    assert dumped["DISPLAY_TZ"] == cfg.DISPLAY_TZ


def test_an_empty_dsn_is_not_masked_into_a_false_positive(monkeypatch):
    for key in _DSN_FIELDS:
        monkeypatch.delenv(key, raising=False)
    assert load(env_file="/dev/null").dump()["DATABASE_URL"] == ""


def test_no_caller_of_dump_needs_a_dsn_back():
    """The only caller of `dump()` in the product is `__repr__`: no code reads a DSN out of a dump."""
    callers = []
    for path in sorted(APP.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "dump"
                and not node.args
            ):
                callers.append(str(path.relative_to(APP)))
    assert callers == ["infra/config.py"], callers


# ── 15 ─────────────────────────────────────────────────────────────────────────────────────


def test_the_unknown_failure_kind_is_defined_once_and_three_modules_agree():
    assert errors.UNKNOWN_FAILURE_KIND == "provider_error"
    assert errors.UNKNOWN_FAILURE_KIND in FAILURE_KINDS
    assert lookup.UNKNOWN_FAILURE_KIND is errors.UNKNOWN_FAILURE_KIND
    assert health.UNKNOWN_FAILURE_KIND is errors.UNKNOWN_FAILURE_KIND
    holders = [
        str(path.relative_to(APP))
        for path in sorted(APP.rglob("*.py"))
        if re.search(r"^UNKNOWN_FAILURE_KIND\s*=", path.read_text(encoding="utf-8"), re.MULTILINE)
    ]
    assert holders == ["infra/errors.py"], holders  # one definition, not a copy per module


def test_the_health_check_does_not_say_unknown_any_more():
    source = _source("infra", "health.py")
    assert "coalesce(failure_kind, 'unknown')" not in source
    assert "coalesce(failure_kind, %s)" in source and "UNKNOWN_FAILURE_KIND" in source


# ── 13, 14, 16, 17, 18 ─────────────────────────────────────────────────────────────────────


def test_the_run_row_sentence_of_the_lookup_counts_attempts_not_lookups():
    flat = _flat(_source("rag", "lookup.py"))
    assert "Every lookup that sent a request has one run row, whatever its outcome" not in flat
    for needle in (
        "counted per ATTEMPT, not per lookup",
        "a retried lookup has two",
        "a 429 whose retry comes too late (1b) has only that one",
        "has none",
    ):
        assert needle in flat, needle


def test_the_late_429_is_said_to_be_stored_nowhere():
    flat = _flat(_source("rag", "lookup.py"))
    assert "no `failed` row, no `rag.lookup_failed` event" in flat
    assert '"no lookup" can hide it' in flat


def test_read_or_none_names_its_four_checks_and_both_migrations():
    source = _source("infra", "health.py")
    flat = _flat(source)
    assert "These three checks read tables migration 020 made" not in flat
    assert "These four checks read what migrations 020 and 023 made" in flat
    assert len(re.findall(r"return _read_or_none\(conn, read\)", source)) == 4  # the number it says


def test_jobs_no_longer_says_the_embed_job_has_no_handler():
    flat = _flat(_source("infra", "jobs.py"))
    assert "registers NO handler" not in flat
    assert "neither worker claims or reclaims it" not in flat
    assert "P14-T05 registered its handler there" in flat
    order = _source("web", "rag_worker.py")
    assert 'CLAIM_ORDER = [["rag_lookup"], ["knowledge_embed"], ["knowledge_draft"]]' in order
    assert "second in `web/rag_worker.CLAIM_ORDER`" in flat


def test_the_admin_knowledge_docstring_says_the_row_one_reads_and_the_pre_023_kind():
    flat = _flat(_source("web", "routers", "admin_knowledge.py"))
    assert "the row ① and ② read at prompt time" not in flat
    assert "null for any other status and for a `failed` row older than the column" not in flat
    for needle in (
        "the row ① reads at prompt time",
        "For ② the row a prompt may use differs",
        "reads as `provider_error`",
        "`rag.lookup.UNKNOWN_FAILURE_KIND`",
    ):
        assert needle in flat, needle


def test_the_admin_lab_module_docstring_has_no_overlong_line():
    doc = ast.get_docstring(ast.parse(_source("web", "routers", "admin_lab.py")), clean=False)
    assert doc is not None
    widest = max(len(line) for line in doc.splitlines())
    assert (
        widest <= 120
    ), f"a docstring line of {widest} columns"  # its neighbours reach 118; the line was 155


# ── 20 ─────────────────────────────────────────────────────────────────────────────────────


def test_rag_model_is_the_model_of_the_draft_calls_in_the_three_places_that_say_it():
    example = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    line = next(ln for ln in example.splitlines() if ln.startswith("RAG_MODEL="))
    pack = (REPO_ROOT / "docs" / "plan" / "00-context-pack.md").read_text(encoding="utf-8")
    in_pack = re.search(r"RAG_MODEL\(([^)]*)\)", pack)
    assert in_pack is not None
    for where, text in ((".env.example", line), ("context pack §6.3", in_pack.group(1))):
        flat = _flat(text)
        assert "ranking" not in flat, where
        assert "knowledge-draft calls" in flat, where
        assert "LLM_MODEL_PROPOSER" in flat, where
        assert "the lookup calls no model" in flat, where
    config_text = _flat(re.sub(r"\s*#\s*", " ", _source("infra", "config.py")))
    assert "RAG_MODEL is the model of the knowledge-draft calls" in config_text
    assert "resolved by the ranking agent" not in config_text


@pytest.mark.parametrize("key", ["RAG_MODEL"])
def test_the_key_is_still_in_the_pack_and_the_example_is_what_the_generator_renders(key):
    """`make lint` runs `gen_env_example.py --check`; this holds it in `make test` too. The generator keeps the
    value (and the comment) `.env.example` already carries, so a comment is changed on that line, and the block
    must still be exactly what the generator renders from §6.3."""
    spec = importlib.util.spec_from_file_location(
        "gen_env_example_wave", REPO_ROOT / "scripts" / "gen_env_example.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert key in module.keys_from_pack()
    assert module.render() in (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
