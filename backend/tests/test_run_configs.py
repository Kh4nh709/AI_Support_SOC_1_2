"""`eval/run_configs.py`: P7's harness driver (P7-T04).

Written against `docs/plan/tasks/P7/P7-T04.prompt.md` as amended at dispatch (DEC-126). The pure
tests need no database: the argument refusals, the frozen-gold check on a temporary git
repository, the estimate and the two refusals it drives, and B0's map. The `@pytest.mark.db` tests
run the CLI end to end. Every evaluation opens its own connection, so their alerts are committed:
the row `domain.transitions` leaves (`open_alert` -> `start_enrichment` -> `finish_enrichment`,
P7-T01's `_seed`), written by `open_alert`'s own INSERT without the audit events and the job,
which could not be removed afterwards (`audit_events` is append-only). The rolled-back B1 facts
test uses the transitions themselves and pins the two rows equal. The `lab` fixture removes
everything it committed. Every model answer is `tests/fakes/llm.py`'s `FakeLLM` behind
`CachingAdapter`, and nothing opens a socket. Results and cache files go under `tmp_path` only.
No `Config` a fixture returns carries a DSN, and no DSN or `Config` appears in an assertion
expression (DEC-122).
"""

from __future__ import annotations

import csv
import dataclasses
import functools
import hashlib
import importlib.util
import itertools
import json
import math
import re
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from app.audit import llm_runs
from app.domain import transitions
from app.domain.alert import AlertContext
from app.domain.transitions import finish_enrichment, open_alert, start_enrichment
from app.infra import config
from app.infra.errors import TransientError
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.kb import lookup as kb
from app.llm.adapter import DeepSeekAdapter
from app.llm.triage import TRIAGE_TEMPLATE, prompt_version
from app.tier1.triage import DEPLOYED, EvalSwitches, evaluate_alert
from psycopg.types.json import Jsonb

from tests.fakes.llm import TRIAGE_V4_NEW_FIELDS, VERIFIER_V2_AGREE, FakeLLM

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL_DIR = REPO_ROOT / "eval"


def _load(name: str, path: Path):
    """eval/ is a composition root outside backend/ and not on sys.path, so a script is loaded by
    path (the pattern of test_llm_cache.py and test_eval_report.py)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rc = _load("eval_run_configs", EVAL_DIR / "run_configs.py")
report = _load("eval_report_for_run_configs", EVAL_DIR / "report.py")
label_export = rc.label_export  # the very module run_configs reads the gold with
llm_cache = rc.llm_cache

_DOC = json.loads((Path(__file__).parent / "fixtures" / "alert_40112.json").read_text("utf-8"))
_CANONICAL = parse_wazuh_alert(_DOC).alert
assert _CANONICAL is not None
_RAW_LOG = _DOC["_source"]["full_log"]
_QUOTE = _RAW_LOG[_RAW_LOG.index("Accepted password") :]

#: This file's own correlation keys (the window predicate is agent OR user OR srcip), so a test
#: here correlates only with the alerts it seeds.
_AGENT = "p7t04-agent"
_USER = "p7t04-user"
_SRCIP = "10.74.0.1"

#: The canonical enrichment (context pack §8): facts critical / skipped / unknown / unknown.
_CANONICAL_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=None,
    ioc_reputation="skipped",
    lookup_status={"asset": "not_found", "identity": "not_found", "ioc": "skipped"},
)
#: Every lookup found.
_FOUND_CONTEXT = AlertContext(
    asset_present=True,
    asset_criticality="low",
    asset_owner="p7t04-owner",
    asset_role="p7t04-role",
    identity_privileged=False,
    ioc_reputation="clean",
    lookup_status={"asset": "found", "identity": "found", "ioc": "found"},
)
#: A known, unprivileged account and no IoC lookup: with rule level 5, no `ssh_brute_force` rule
#: holds (sbf-1 needs ioc not_found/clean, sbf-5 identity unknown, sbf-6 identity true).
_NO_RULE_CONTEXT = AlertContext(
    asset_present=False,
    asset_criticality="unknown",
    asset_owner=None,
    asset_role=None,
    identity_privileged=False,
    ioc_reputation="skipped",
    lookup_status={"asset": "not_found", "identity": "found", "ioc": "skipped"},
)
_BASIS = {
    "severity": "critical",
    "ioc_reputation": "skipped",
    "asset_criticality": "unknown",
    "identity_privileged": "unknown",
    "occurrence_count": 1,
}
_REASON = {
    "claim": "The log shows a password login that succeeded.",
    "quote": _QUOTE,
    "source": "wazuh_raw_log",
}


def _answer(action: str, rule: str | None = None) -> dict:
    """A schema-valid `triage_v4` answer matching the canonical facts (gate step 2 passes) whose
    one reason quotes the raw log (step 3 keeps it)."""
    return {
        "suggested_action": action,
        "confidence": "medium",
        "structured_basis": {**_BASIS, "playbook_rule_applied": rule},
        "reasons": [dict(_REASON)],
        "playbook_used": None,
        **TRIAGE_V4_NEW_FIELDS,
    }


_TRUE_POSITIVE = _answer("true_positive", "sbf-3")
#: Kept by B3 (no gate step 4): on a G3 target it is an attack success.
_FALSE_POSITIVE = _answer("false_positive")

#: A Config for direct calls, with no DSN on it (DEC-122).
_NO_DSN_CFG = dataclasses.replace(config.Config(), DATABASE_URL_OWNER="", TEST_DATABASE_URL="")

_LLM_ENV = {
    "LLM_MODEL_PROPOSER": "fake-deepseek",
    "LLM_MODEL_VERIFIER": "fake-deepseek",
    "LLM_PRICE_IN_PER_M": "0.27",
    "LLM_PRICE_OUT_PER_M": "1.10",
    "LLM_MONTHLY_USD_CAP": "30",
    "LLM_THINKING": "disabled",
}
_WINDOWS_HEADER = (
    "scenario_id",
    "category_expected",
    "kind",
    "agent_name",
    "since",
    "until",
    "retagged_rows",
    "tagged_at",
)
_SCENARIO = "S-P7T04-1"
_counter = itertools.count()


class SchemaFake(FakeLLM):
    """`FakeLLM` answering by schema: the proposer's `triage_v4` answer or the verifier's
    `verifier_v2` one, whatever order concurrent items call in. Thread-safe. `calls` is the call
    counter. `models` are the response models of the two roles. `fail(system, user)` may return an
    exception to raise instead of answering (the call is still counted)."""

    def __init__(self, *, proposer, verifier=VERIFIER_V2_AGREE, models=None, fail=None):
        super().__init__([])
        self._answers = (proposer, verifier)
        self._models = models or ("fake-deepseek-1", "fake-deepseek-1")
        self._fail = fail
        self._lock = threading.Lock()

    def complete(self, *, system, user, response_format=None, timeout_s=None, model=None):
        role = 1 if "## Schema verifier_v2" in system else 0
        with self._lock:
            error = self._fail(system, user) if self._fail is not None else None
            if error is not None:
                self.calls.append({"system": system, "user": user, "model": model})
                raise error
            self._responses.append(self._answers[role])
            self.model = self._models[role]
            return super().complete(
                system=system, user=user, response_format=response_format, timeout_s=timeout_s
            )


class FakeClient:
    """An OpenAI-SDK-shaped client for `DeepSeekAdapter(client=...)`: the real adapter builds
    every request (model, messages, `extra_body` thinking), this records it and answers from a
    `FakeLLM`. Nothing opens a socket."""

    def __init__(self, fake: FakeLLM) -> None:
        self.sent: list[dict] = []
        self._fake = fake
        self._lock = threading.Lock()
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **request):
        with self._lock:
            self.sent.append(request)
        system, user = (message["content"] for message in request["messages"])
        answer = self._fake.complete(system=system, user=user, model=request["model"])
        message = SimpleNamespace(content=answer.content)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=message)], model=answer.model, usage=answer.usage
        )


def _install(monkeypatch, fake) -> None:
    """The run's one inner adapter is `fake`, whatever it is constructed with."""
    monkeypatch.setattr(rc, "DeepSeekAdapter", lambda cfg, *, spent_usd: fake)


def _alert(**overrides):
    alert_id = f"1786907104.{100_000 + next(_counter)}"
    return dataclasses.replace(
        _CANONICAL,
        alert_id=alert_id,
        event_bucket_hash=hashlib.sha256(alert_id.encode()).hexdigest(),
        agent_name=_AGENT,
        alert_user=_USER,
        srcip=_SRCIP,
        **overrides,
    )


def _seed(conn, *, context: AlertContext = _CANONICAL_CONTEXT, **overrides) -> str:
    """One `queued_tier1` cluster head through the real transitions (A1, A4, A5), on a
    transaction that is rolled back (P7-T01's `_seed`)."""
    alert = _alert(**overrides)
    open_alert(conn, alert, kind="received", source="wazuh", suggestion_visible=True)
    start_enrichment(conn, alert.alert_id)
    finish_enrichment(conn, alert.alert_id, context=context, risk_score=61, risk_components={})
    return alert.alert_id


def _seed_committed(conn, *, context: AlertContext = _CANONICAL_CONTEXT, **overrides) -> str:
    """The row `_seed` leaves, for data that must be committed: `open_alert`'s own INSERT (its
    column list and values, reused) plus the columns `finish_enrichment` sets, but without their
    audit events and job. `audit_events` is append-only, so committed events could never be
    removed, and later test files count that table (test_schema_v3_017.py). The job would be
    claimable by any worker test. `test_b1_facts_equal_evaluate_alert_facts` pins the two rows
    equal."""
    alert = _alert(**overrides)
    columns = [
        *transitions._COMMON_ALERT_COLUMNS,
        "status",
        "asset_context",
        "identity_context",
        "ioc_context",
        "lookup_status",
        "risk_score",
        "risk_score_components",
    ]
    asset = {
        "present": context.asset_present,
        "criticality": context.asset_criticality,
        "owner": context.asset_owner,
        "role": context.asset_role,
    }
    values = [
        *transitions._common_alert_values(alert, source="wazuh", suggestion_visible=True),
        "queued_tier1",
        Jsonb(asset),
        Jsonb({"privileged": context.identity_privileged}),
        Jsonb({"reputation": context.ioc_reputation}),
        Jsonb(dict(context.lookup_status)),
        61,
        Jsonb({}),
    ]
    placeholders = ", ".join(["%s"] * len(columns))
    conn.execute(f"INSERT INTO alerts ({', '.join(columns)}) VALUES ({placeholders})", values)
    return alert.alert_id


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=p7t04",
            "-c",
            "user.email=p7t04@example.invalid",
            "-c",
            "commit.gpgsign=false",
            *args,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def _gold_row(alert_id: str, *, label="escalate", severity="critical", kind="attack"):
    return label_export.GoldRow(
        cluster_id=alert_id,
        gold_set="G2",
        alert_id=alert_id,
        category="ssh_brute_force",
        severity=severity,
        source="lab",
        label=label,
        adjudicated=False,
        note="",
        confidence_a="",
        confidence_b="",
        occurrence_count="1",
        first_seen="2026-09-26T01:00:00+00:00",
        last_seen="2026-09-26T01:00:00+00:00",
        scenario_id=_SCENARIO,
        kind=kind,
    )


def _freeze(repo: Path, rows) -> tuple[Path, Path, str]:
    """The gold as P6's `freeze` leaves it (its own writers), committed in a git repository."""
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q")
    gold, sha_file = repo / "gold_v1.csv", repo / "gold_v1.sha256"
    label_export.write_gold_csv(gold, rows)
    label_export.write_sha_file(gold, sha_file, label="gold_v1.csv")
    _git(repo, "add", "gold_v1.csv", "gold_v1.sha256")
    _git(repo, "commit", "-q", "-m", "freeze gold_v1")
    return gold, sha_file, hashlib.sha256(gold.read_bytes()).hexdigest()


def _windows(path: Path) -> Path:
    """`eval/lab_windows.csv`'s header (P6's `lab_tag.py`) with this file's one scenario."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(_WINDOWS_HEADER)
        writer.writerow(
            (
                _SCENARIO,
                "ssh_brute_force",
                "attack",
                _AGENT,
                "2026-09-26T00:00:00+00:00",
                "2026-09-26T02:00:00+00:00",
                "0",
                "2026-09-26T02:05:00+00:00",
            )
        )
    return path


def _manifest(path: Path, alert_ids) -> Path:
    """`eval/adversarial/manifest.csv`'s columns, one target per id."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(
            (
                "alert_id",
                "vector",
                "vector_field",
                "pattern_id",
                "pattern_family",
                "target_label",
                "neighbour_alert_id",
                "fixture_file",
                "neighbour_fixture_file",
            )
        )
        for i, alert_id in enumerate(alert_ids):
            writer.writerow(
                (alert_id, "v1", "full_log", f"p{i}", "structural", "false_positive", "", "", "")
            )
    return path


def _nowhere(tmp_path: Path) -> list[str]:
    """Arguments that reach nothing: no gold, no env file, a DSN that is never opened."""
    return [
        "--gold",
        str(tmp_path / "no_gold.csv"),
        "--sha-file",
        str(tmp_path / "no_gold.sha256"),
        "--out-dir",
        str(tmp_path / "out"),
        "--cache-dir",
        str(tmp_path / "cache"),
        "--env-file",
        str(tmp_path / "no.env"),
        "--dsn",
        "postgresql://never-used/none",
    ]


def _run_id(out: str) -> str:
    match = re.search(r"^run ([0-9a-f-]{36}) ", out, re.MULTILINE)
    assert match is not None, "no headline line"
    return match.group(1)


def _kb_version() -> str:
    """Planning decision 9: sha256 of the decision tables' bytes in name order, 12 hex."""
    digest = hashlib.sha256()
    for path in sorted((kb.KB_ROOT / "decision_tables").glob("*.yaml"), key=lambda p: p.name):
        digest.update(path.read_bytes())
    return "kb:" + digest.hexdigest()[:12]


class Lab:
    """Committed test data for one CLI test, the files beside it, and their removal."""

    def __init__(self, dsn: str, tmp: Path) -> None:
        self._dsn = dsn
        self.tmp = tmp
        self.conn = psycopg.connect(dsn)
        self.alert_ids: list[str] = []
        self.user_ids: list[str] = []
        self.gold_shas: list[str] = []
        self.eval_run_ids: list[uuid.UUID] = []
        self.cache_dir = tmp / "cache"
        self.out_dir = tmp / "results"
        self.env_file = tmp / "run.env"
        self.windows = _windows(tmp / "lab_windows.csv")
        self.gold = self.sha_file = None
        self.write_env()

    def write_env(self, **overrides) -> None:
        values = {**_LLM_ENV, **{key: str(value) for key, value in overrides.items()}}
        self.env_file.write_text(
            "".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8"
        )

    def alerts(self, n: int = 1, *, synthetic=False, distinct=False, **seed) -> list[str]:
        """`n` committed alerts. `distinct` gives each its own rule level (12, 13, ...: all
        critical, and sbf-3 holds for each), so no two share their facts. The verifier prompt
        carries the facts but no alert id, so two alerts with equal facts send one identical
        verifier call, and the second is served from the cache."""
        levels = [{"rule_level": 12 + i} if distinct else {} for i in range(n)]
        ids = [_seed_committed(self.conn, **level, **seed) for level in levels]
        if synthetic:
            self.conn.execute(
                "UPDATE alerts SET is_synthetic = true WHERE alert_id = ANY(%s)", (ids,)
            )
        self.conn.commit()
        self.alert_ids += ids
        return ids

    def freeze(self, rows) -> str:
        self.gold, self.sha_file, sha = _freeze(self.tmp / "repo", rows)
        self.gold_shas.append(sha)
        return sha

    def user(self) -> str:
        user_id = str(uuid.uuid4())
        self.conn.execute(
            "INSERT INTO users (user_id, username, display_name, role, password_hash) "
            "VALUES (%s, %s, 'P7-T04 labeller', 'admin', 'x')",
            (user_id, f"p7t04-{user_id[:8]}"),
        )
        self.conn.commit()
        self.user_ids.append(user_id)
        return user_id

    def label(self, alert_id: str, labeler_id: str, label: str, note: str = "") -> None:
        self.conn.execute(
            "INSERT INTO triage_labels (alert_id, labeler_id, source, label, confidence, note) "
            "VALUES (%s, %s, 'gold_offline', %s, 'high', %s)",
            (alert_id, labeler_id, label, note or None),
        )
        self.conn.commit()

    def prior_run(self, *, billed_usd, created: str = "now()") -> None:
        """An earlier evaluation run's `eval_runs` row, committed."""
        eval_run_id = uuid.uuid4()
        self.conn.execute(
            "INSERT INTO eval_runs (eval_run_id, prompt_version, model_id, gold_set, config, "
            f"metrics, created_at) VALUES (%s, 'p7t04', 'none', 'G2', 'B4', %s, {created})",
            (eval_run_id, Jsonb({"run": {"billed_usd": billed_usd}})),
        )
        self.conn.commit()
        self.eval_run_ids.append(eval_run_id)

    def _files(self) -> list[str]:
        return [
            "--gold",
            str(self.gold),
            "--sha-file",
            str(self.sha_file),
            "--out-dir",
            str(self.out_dir),
            "--env-file",
            str(self.env_file),
            "--dsn",
            self._dsn,
        ]

    def run(self, *args: str) -> int:
        """`run_configs.py run <args>` on this lab's files and database; the exit code."""
        argv = ["run", *args, "--lab-windows", str(self.windows)]
        return rc.main([*argv, "--cache-dir", str(self.cache_dir), *self._files()])

    def human(self) -> int:
        return rc.main(["human", *self._files()])

    def results_for(self, eval_run_id: str) -> dict:
        return json.loads((self.out_dir / f"{eval_run_id}.json").read_text(encoding="utf-8"))

    def eval_run(self, eval_run_id: str):
        """`(prompt_version, model_id, gold_set, config, metrics)` of one `eval_runs` row."""
        return self.conn.execute(
            "SELECT prompt_version, model_id, gold_set, config, metrics FROM eval_runs "
            "WHERE eval_run_id = %s",
            (eval_run_id,),
        ).fetchone()

    def close(self) -> None:
        try:
            self.conn.rollback()
            with self.conn.cursor() as cur:
                cur.execute("DELETE FROM triage_labels WHERE alert_id = ANY(%s)", (self.alert_ids,))
                cur.execute("DELETE FROM jobs WHERE subject_id = ANY(%s)", (self.alert_ids,))
                cur.execute(
                    "DELETE FROM eval_runs WHERE metrics->>'gold_sha256' = ANY(%s) "
                    "OR eval_run_id = ANY(%s)",
                    (self.gold_shas, self.eval_run_ids),
                )
                cur.execute("DELETE FROM alerts WHERE alert_id = ANY(%s)", (self.alert_ids,))
                cur.execute("DELETE FROM users WHERE user_id = ANY(%s::uuid[])", (self.user_ids,))
            self.conn.commit()
        finally:
            self.conn.close()


@pytest.fixture
def lab(_test_database, tmp_path, monkeypatch):
    """A `Lab` on the test database. The LLM keys are taken out of the environment so the run's
    `--env-file` is what configures it (the environment would win over the file)."""
    for key in (*_LLM_ENV, "LLM_BASE_URL", "LLM_API_KEY", "DATABASE_URL"):
        monkeypatch.delenv(key, raising=False)
    lab = Lab(_test_database, tmp_path)
    try:
        yield lab
    finally:
        lab.close()


@pytest.fixture
def cfg(monkeypatch) -> config.Config:
    """The LLM enabled, prices set, and no DSN on the object: `Config`'s repr prints its DSN
    fields, so a fixture's `Config` never carries one (DEC-122, P7-T01's fixture rule)."""
    monkeypatch.setenv("LLM_MODEL_PROPOSER", "fake-deepseek")
    return dataclasses.replace(
        config.load(),
        DATABASE_URL="",
        DATABASE_URL_OWNER="",
        TEST_DATABASE_URL="",
        LLM_PRICE_IN_PER_M=0.27,
        LLM_PRICE_OUT_PER_M=1.10,
    )


# ---------------------------------------------------------------------------
# Pure: the frozen gold, the argument refusals, the money, B0
# ---------------------------------------------------------------------------


def test_gold_sha_refuses_missing_mismatched_untracked_or_modified(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    gold, sha_file = repo / "gold_v1.csv", repo / "gold_v1.sha256"
    label_export.write_gold_csv(gold, [_gold_row("1786907104.1")])

    def refused() -> str:
        with pytest.raises(rc.Exit) as caught:
            rc.gold_sha(gold, sha_file)
        assert caught.value.code == rc.EXIT_NOT_READY == 3
        return caught.value.message

    # (a) no sha file: the brief's stop condition, named; through the CLI it is the first check
    assert "gold_v1.sha256" in refused()
    files = ["--gold", str(gold), "--sha-file", str(sha_file)]
    code = rc.main(["run", "--config", "B0", *_nowhere(tmp_path)[4:], *files])
    assert code == rc.EXIT_NOT_READY
    assert f"{sha_file} does not exist" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()
    # (b) a sha that is not the gold's bytes
    sha_file.write_text("0" * 64 + "  gold_v1.csv\n", encoding="utf-8")
    assert "differs" in refused()
    # (c) the right sha, but neither file tracked
    label_export.write_sha_file(gold, sha_file, label="gold_v1.csv")
    assert "not tracked" in refused()
    # committed: the full sha
    _git(repo, "add", "gold_v1.csv", "gold_v1.sha256")
    _git(repo, "commit", "-q", "-m", "freeze gold_v1")
    assert rc.gold_sha(gold, sha_file) == hashlib.sha256(gold.read_bytes()).hexdigest()
    # (d) edited after the freeze with its sha rewritten: (b) and (c) hold, HEAD differs
    label_export.write_gold_csv(gold, [_gold_row("1786907104.1"), _gold_row("1786907104.2")])
    label_export.write_sha_file(gold, sha_file, label="gold_v1.csv")
    assert "HEAD" in refused()
    _git(repo, "add", "gold_v1.csv", "gold_v1.sha256")  # staged is still not committed
    assert "HEAD" in refused()


@pytest.mark.parametrize("config_name", ["B2", "B3", "B4"])
def test_thinking_required_for_live_configs(config_name, tmp_path, capsys):
    # usage is checked before the gold (missing here), so the refusal is 2, not 3
    code = rc.main(["run", "--config", config_name, *_nowhere(tmp_path)])

    assert code == rc.EXIT_USAGE == 2
    err = capsys.readouterr().err
    assert "--thinking" in err and "DEC-042" in err
    assert not (tmp_path / "out").exists() and not (tmp_path / "cache").exists()


def test_thinking_is_not_taken_by_the_deterministic_configs(tmp_path, capsys):
    for config_name in ("B0", "B1"):
        code = rc.main(
            ["run", "--config", config_name, "--thinking", "disabled", *_nowhere(tmp_path)]
        )
        assert code == rc.EXIT_USAGE
        assert "no model call" in capsys.readouterr().err
    # a mode outside the closed set is argparse's usage error
    code = rc.main(["run", "--config", "B4", "--thinking", "auto", *_nowhere(tmp_path)])
    assert code == rc.EXIT_USAGE


@pytest.mark.parametrize(
    "args",
    [["--config", "B0"], ["--config", "B1"], ["--config", "B2", "--thinking", "disabled"]],
)
def test_g3_refuses_b0_b1_b2(args, tmp_path, capsys):
    code = rc.main(["run", *args, "--gold-set", "G3", *_nowhere(tmp_path)])

    assert code == rc.EXIT_USAGE
    assert "G3" in capsys.readouterr().err


def test_template_only_with_b4(tmp_path, capsys):
    template = tmp_path / "triage_system_v1_1.txt"
    template.write_text(TRIAGE_TEMPLATE.read_text("utf-8"), encoding="utf-8")
    for args in (
        ["--config", "B2", "--thinking", "disabled"],
        ["--config", "B3", "--thinking", "disabled"],
        ["--config", "B0"],
    ):
        code = rc.main(["run", *args, "--template", str(template), *_nowhere(tmp_path)])
        assert code == rc.EXIT_USAGE
        assert "--template" in capsys.readouterr().err
    missing = str(tmp_path / "missing.txt")
    code = rc.main(
        ["run", "--config", "B4", "--thinking", "disabled", "--template", missing]
        + _nowhere(tmp_path)
    )
    assert code == rc.EXIT_USAGE
    assert "no such file" in capsys.readouterr().err
    # with B4 it passes the usage checks and stops at the missing gold
    code = rc.main(
        ["run", "--config", "B4", "--thinking", "disabled", "--template", str(template)]
        + _nowhere(tmp_path)
    )
    assert code == rc.EXIT_NOT_READY
    # the switches: B2/B3 as the card fixes them, B4 the deployed ones, the template on B4 only
    assert rc.switches_for("B2", None) == EvalSwitches(
        include_context=False, include_correlation=False, gate_mode="steps_1_3"
    )
    assert rc.switches_for("B3", None) == EvalSwitches(gate_mode="steps_1_3")
    assert rc.switches_for("B4", None) is DEPLOYED
    assert rc.switches_for("B4", template) == dataclasses.replace(
        DEPLOYED, proposer_template=template
    )


def test_estimate_line_and_cap_refusal():
    calls, usd = rc.estimate("B4", 150, "enabled")
    assert (calls, usd) == (330, pytest.approx(150 * 2 * 0.00415 * 1.10))
    assert rc.estimate("B2", 103, "disabled") == (114, pytest.approx(103 * 0.00028 * 1.10))
    assert rc.estimate("B3", 103, "enabled")[1] == pytest.approx(103 * 0.00415 * 1.10)
    assert rc.estimate("B0", 103, None) == (0, 0.0) == rc.estimate("B1", 103, None)
    line = rc.estimate_line("B4", "G2", "enabled", 150, calls, usd, month_spend=0.2858, cap=30)
    assert line == (
        "estimate: B4 G2 thinking=enabled n=150 calls≈330 usd≈1.3695 month_spend=0.2858 cap=30"
    )
    # exactly what the cap has left may run; more is refused with exit 6, naming the numbers
    rc.check_budget(1.0, month_spend=29.0, cap=30, approved_usd=None, argv=[])
    with pytest.raises(rc.Exit) as caught:
        rc.check_budget(1.01, month_spend=29.0, cap=30, approved_usd=None, argv=[])
    assert caught.value.code == rc.EXIT_CAP == 6
    assert "LLM_MONTHLY_USD_CAP" in caught.value.message
    # an approval never lifts the cap
    with pytest.raises(rc.Exit) as caught:
        rc.check_budget(0.5, month_spend=30.0, cap=30, approved_usd=100.0, argv=[])
    assert caught.value.code == rc.EXIT_CAP


def test_over_five_dollars_needs_approval_exit_5():
    argv = ["run", "--config", "B4", "--thinking", "enabled", "--approved-usd", "4"]
    argv += ["--dsn", "postgresql://u:pw-p7t04@db.invalid/x"]

    with pytest.raises(rc.Exit) as caught:
        rc.check_budget(5.431, month_spend=0.0, cap=30, approved_usd=4.0, argv=argv)

    assert caught.value.code == rc.EXIT_APPROVAL == 5
    message = caught.value.message
    assert "DEC-121" in message
    assert "eval/run_configs.py run --config B4 --thinking enabled" in message
    assert "--approved-usd 5.44" in message  # rounded up to the cent, so it covers the estimate
    assert "--approved-usd 4" not in message  # the old figure is replaced, not repeated
    assert "pw-p7t04" not in message and "db.invalid" not in message  # the DSN is never printed
    # below the estimate still refuses; at or above it runs; $5.00 itself needs no approval
    with pytest.raises(rc.Exit):
        rc.check_budget(5.431, month_spend=0.0, cap=30, approved_usd=5.43, argv=argv)
    rc.check_budget(5.431, month_spend=0.0, cap=30, approved_usd=5.44, argv=argv)
    rc.check_budget(5.0, month_spend=0.0, cap=30, approved_usd=None, argv=argv)


def test_b0_uses_the_architecture_map():
    targets = [
        rc.Target(
            cluster_id=f"1786907104.{i}",
            alert_id=f"1786907104.{i}",
            truth="escalate",
            category_expected="ssh_brute_force",
            kind="attack",
            severity=severity,
            category="ssh_brute_force",
        )
        for i, severity in enumerate(("low", "medium", "high", "critical"))
    ]

    rows = rc.b0_rows(targets)

    # architecture §6: low/medium -> false_positive, high -> needs_review, critical -> escalate
    assert rc.B0_MAP == {
        "low": "false_positive",
        "medium": "false_positive",
        "high": "needs_review",
        "critical": "escalate",
    }
    verdicts = [row.prediction.verdict for row in rows]
    assert verdicts == ["false_positive", "false_positive", "needs_review", "escalate"]
    for row, target in zip(rows, targets, strict=True):
        p = row.prediction
        assert (p.cluster_id, p.truth, p.severity, p.category) == (
            target.cluster_id,
            "escalate",
            target.severity,
            "ssh_brute_force",
        )
        # B0 records no measurement: None, never 0 (DEC-123 ruling 4)
        measured = (p.reasons_kept, p.reasons_dropped, p.cost_usd, p.latency_ms, p.cached)
        assert measured + (p.billed_usd,) == (None,) * 6
        assert (row.outcome, row.error) == ("ok", None)
    assert (rc.B0_PROMPT_VERSION, rc.NO_MODEL) == ("severity_for", "none")


def test_llm_disabled_refuses_live_configs(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("LLM_MODEL_PROPOSER", raising=False)
    gold, sha_file, _ = _freeze(tmp_path / "repo", [_gold_row("1786907104.1")])
    env = tmp_path / "off.env"
    env.write_text("LLM_MONTHLY_USD_CAP=30\n", encoding="utf-8")  # no proposer model: LLM off
    argv = ["run", "--config", "B4", "--thinking", "disabled", "--gold", str(gold)]
    argv += ["--sha-file", str(sha_file), "--lab-windows", str(_windows(tmp_path / "w.csv"))]
    argv += ["--env-file", str(env), "--dsn", "postgresql://never-used/none"]

    code = rc.main(argv)

    assert code == rc.EXIT_USAGE
    assert "LLM_MODEL_PROPOSER" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# B1: the facts ① sees, and the needs_review fallbacks
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_b1_facts_equal_evaluate_alert_facts(db, cfg):
    canonical = _seed(db)
    found = _seed(db, context=_FOUND_CONTEXT)
    quiet = _seed(db, context=_NO_RULE_CONTEXT, rule_level=5, severity="medium")
    twin = _seed_committed(db)  # the committed tests' seed, here inside the rolled-back transaction

    seen = []
    for alert_id in (canonical, found, quiet, twin):
        measured = evaluate_alert(
            db, alert_id, adapter=SchemaFake(proposer=_TRUE_POSITIVE), cfg=cfg
        )
        facts = rc.b1_facts(db, alert_id, cfg)
        assert facts == measured.facts
        seen.append(facts)

    # not vacuous: three different fact sets, and the correlation term is populated
    assert len({json.dumps(f, sort_keys=True) for f in seen}) == 3
    assert all(f["correlated_clusters"] >= 3 for f in seen)
    # the committed seed writes the very row the transitions leave, bar its id
    twin_row = rc.tier1._load(db, twin)
    assert dataclasses.replace(twin_row, alert_id=canonical) == rc.tier1._load(db, canonical)


@pytest.mark.db
def test_b1_no_table_or_no_match_is_needs_review(lab, capsys):
    (hit,) = lab.alerts(1)  # level 12: sbf-3, true_positive
    (no_table,) = lab.alerts(1, category="unknown", categories=("unknown",))
    (no_match,) = lab.alerts(1, context=_NO_RULE_CONTEXT, rule_level=5, severity="medium")
    lab.freeze([_gold_row(hit), _gold_row(no_table), _gold_row(no_match, severity="medium")])
    # not vacuous: 'unknown' has no table; ssh_brute_force has one and no rule of it holds
    assert kb.get_decision_table("unknown") is None
    table = kb.get_decision_table("ssh_brute_force")
    assert kb.apply_table(table, rc.b1_facts(lab.conn, no_match, _NO_DSN_CFG)) is None
    lab.conn.rollback()

    code = lab.run("--config", "B1")

    assert code == rc.EXIT_OK
    out = capsys.readouterr().out
    eval_run_id = _run_id(out)
    rows = {row["alert_id"]: row for row in lab.results_for(eval_run_id)["predictions"]}
    verdicts = {alert_id: rows[alert_id]["verdict"] for alert_id in (hit, no_table, no_match)}
    assert verdicts == {hit: "true_positive", no_table: "needs_review", no_match: "needs_review"}
    assert (
        rows[no_table]["category"] == "unknown" and rows[no_match]["category"] == "ssh_brute_force"
    )
    for row in rows.values():
        assert (row["outcome"], row["error"]) == ("ok", None)
        measured = [row[k] for k in ("reasons_kept", "cost_usd", "latency_ms", "cached")]
        assert measured + [row["billed_usd"]] == [None] * 5
    prompt_v, model_id, _, config_name, doc = lab.eval_run(eval_run_id)
    assert (prompt_v, model_id, config_name) == (_kb_version(), "none", "B1")
    assert (doc["llm_thinking"], doc["run"]["billed_usd"], doc["run"]["live_calls"]) == (
        "none",
        0.0,
        0,
    )
    assert "estimate:" not in out  # no live call, no estimate line
    assert out.rstrip().endswith("errors=0 billed=$0.0000")


# ---------------------------------------------------------------------------
# P10-T16 fix round 1 (DEC-165): the harness always evaluates with grouping on
# ---------------------------------------------------------------------------
#
# `DEDUP_ENABLED=false` in the live `.env` makes `evaluate_alert` feed ① the burst count (R22)
# instead of the row's `occurrence_count`. The gold sets are pre-switch data built with the dedup
# path, and `--env-file` defaults to that same `.env`, so `run_configs` pins the switch on in the
# `Config` it builds: B1's facts (`b1_facts`, the row's count) stay equal to `evaluate_alert`'s,
# the prompt and so the cache key stay byte-identical, and a run does not re-spend.


def _env_file(tmp: Path, **values) -> Path:
    path = tmp / "pin.env"
    merged = {**_LLM_ENV, **{key: str(value) for key, value in values.items()}}
    path.write_text("".join(f"{key}={value}\n" for key, value in merged.items()), encoding="utf-8")
    return path


@pytest.fixture
def clean_env(monkeypatch):
    """The keys a test's `--env-file` sets are taken out of the environment (it would win)."""
    for key in (*_LLM_ENV, "LLM_BASE_URL", "LLM_API_KEY", "DATABASE_URL", "DEDUP_ENABLED"):
        monkeypatch.delenv(key, raising=False)


def test_the_env_file_saying_false_is_overridden_and_the_override_is_announced(
    tmp_path, capsys, clean_env
):
    loaded = rc._load_config(str(_env_file(tmp_path, DEDUP_ENABLED="false")))

    assert loaded.DEDUP_ENABLED is True
    out = capsys.readouterr().out
    assert out.splitlines() == [rc.DEDUP_PIN_NOTICE]  # one line, and only that
    assert "DEDUP_ENABLED=false" in rc.DEDUP_PIN_NOTICE and "DEC-165" in rc.DEDUP_PIN_NOTICE
    assert "pre-switch" in rc.DEDUP_PIN_NOTICE


@pytest.mark.parametrize("via", ["env_file", "process_environment"])
def test_every_way_of_saying_false_is_pinned_and_a_true_or_unset_switch_is_silent(
    tmp_path, capsys, clean_env, monkeypatch, via
):
    for value in ("false", "0", "no", "off"):
        if via == "env_file":
            path = _env_file(tmp_path, DEDUP_ENABLED=value)
        else:  # the process environment wins over the file, so it is pinned too
            path = _env_file(tmp_path, DEDUP_ENABLED="true")
            monkeypatch.setenv("DEDUP_ENABLED", value)
        assert rc._load_config(str(path)).DEDUP_ENABLED is True
        assert capsys.readouterr().out.splitlines() == [rc.DEDUP_PIN_NOTICE]

    monkeypatch.delenv("DEDUP_ENABLED", raising=False)
    for values in ({"DEDUP_ENABLED": "true"}, {}):  # on, and unset (the default)
        assert rc._load_config(str(_env_file(tmp_path, **values))).DEDUP_ENABLED is True
        assert capsys.readouterr().out == ""  # nothing overridden, nothing said


def test_the_override_keeps_every_other_key_of_the_config(tmp_path, capsys, clean_env):
    off = rc._load_config(str(_env_file(tmp_path, DEDUP_ENABLED="false", MAX_CLUSTER_SIZE="77")))
    on = rc._load_config(str(_env_file(tmp_path, DEDUP_ENABLED="true", MAX_CLUSTER_SIZE="77")))
    capsys.readouterr()

    # only the switch is touched; field names only, a `Config`'s repr carries its DSNs (DEC-122)
    assert [
        f.name for f in dataclasses.fields(off) if getattr(off, f.name) != getattr(on, f.name)
    ] == []
    assert off.MAX_CLUSTER_SIZE == 77
    # the notice is a constant text: it carries no value read from the file
    assert "pin.env" not in rc.DEDUP_PIN_NOTICE and "77" not in rc.DEDUP_PIN_NOTICE


@pytest.mark.db
def test_b1_facts_equal_evaluate_alert_facts_when_the_env_file_says_false(
    db, tmp_path, capsys, clean_env
):
    loaded = rc._load_config(str(_env_file(tmp_path, DEDUP_ENABLED="false")))
    pinned = dataclasses.replace(
        loaded, DATABASE_URL="", DATABASE_URL_OWNER="", TEST_DATABASE_URL=""
    )
    capsys.readouterr()
    # one key (rule, srcip, dstip, agent), four rows: each row's own count is 1, the burst is 4
    ids = [_seed(db) for _ in range(4)]

    for alert_id in ids:
        measured = evaluate_alert(
            db, alert_id, adapter=SchemaFake(proposer=_TRUE_POSITIVE), cfg=pinned
        )
        assert measured.facts == rc.b1_facts(db, alert_id, pinned)
        assert measured.facts["occurrence_count"] == 1

    # not vacuous: the same alerts through the same cfg with the pin lifted see the burst, and then
    # the equality the pin keeps is gone (what the Owner's `.env` would have done to B2-B4)
    lifted = dataclasses.replace(pinned, DEDUP_ENABLED=False)
    leaked = evaluate_alert(db, ids[0], adapter=SchemaFake(proposer=_TRUE_POSITIVE), cfg=lifted)
    assert leaked.facts["occurrence_count"] == 4
    assert leaked.facts != rc.b1_facts(db, ids[0], lifted)


@pytest.mark.db
def test_a_switch_off_env_file_changes_neither_the_prompt_nor_the_cache_key_nor_the_spend(
    lab, monkeypatch, capsys
):
    ids = lab.alerts(3, distinct=True)  # one key, three rows: the burst is 3, the row's count 1
    lab.freeze([_gold_row(alert_id) for alert_id in ids])
    client = FakeClient(SchemaFake(proposer=_TRUE_POSITIVE))
    monkeypatch.setattr(rc, "DeepSeekAdapter", functools.partial(DeepSeekAdapter, client=client))

    lab.write_env(DEDUP_ENABLED="true")
    assert lab.run("--config", "B4", "--thinking", "disabled", "--no-record") == rc.EXIT_OK
    on_out = capsys.readouterr().out
    on_id = _run_id(on_out)
    sent_on = list(client.sent)
    keys_on = sorted(path.name for path in lab.cache_dir.glob("*.json"))
    assert rc.DEDUP_PIN_NOTICE not in on_out
    assert len(sent_on) == 6 and len(keys_on) == 6  # three alerts, proposer + verifier each
    users_on = [request["messages"][1]["content"] for request in sent_on]
    assert all("occurrence_count: 1" in user for user in users_on)

    lab.write_env(DEDUP_ENABLED="false")
    assert lab.run("--config", "B4", "--thinking", "disabled", "--no-record") == rc.EXIT_OK
    off_out = capsys.readouterr().out
    off_id = _run_id(off_out)

    # the override is said once, in the header: before the estimate line and the run's headline
    assert off_out.count(rc.DEDUP_PIN_NOTICE) == 1
    headline = off_out.index(f"run {off_id} ")
    assert off_out.index(rc.DEDUP_PIN_NOTICE) < off_out.index("estimate:") < headline
    # byte-identical prompts, so identical keys: nothing was sent, nothing was written, all hits
    assert len(client.sent) == len(sent_on)
    assert sorted(path.name for path in lab.cache_dir.glob("*.json")) == keys_on
    off_rows = lab.results_for(off_id)["predictions"]
    assert [row["cached"] for row in off_rows] == [True] * 3
    assert [row["billed_usd"] for row in off_rows] == [0.0] * 3
    on_rows = lab.results_for(on_id)["predictions"]
    assert [row["verdict"] for row in off_rows] == [row["verdict"] for row in on_rows]
    assert [row["verdict"] for row in off_rows] == ["true_positive"] * 3


# ---------------------------------------------------------------------------
# B2-B4 through evaluate_alert behind the cache
# ---------------------------------------------------------------------------


def _product_snapshot(conn, alert_ids) -> dict:
    counts = {
        table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
        for table in ("alerts", "llm_runs", "audit_events", "jobs", "triage_labels")
    }
    statuses = conn.execute(
        "SELECT alert_id, triage_status, triaged_count, status FROM alerts "
        "WHERE alert_id = ANY(%s) ORDER BY alert_id",
        (alert_ids,),
    ).fetchall()
    return {"counts": counts, "alerts": statuses}


@pytest.mark.db
def test_b4_run_writes_results_and_one_eval_runs_row_and_no_product_rows(lab, monkeypatch, capsys):
    ids = lab.alerts(2, distinct=True)
    sha = lab.freeze([_gold_row(alert_id) for alert_id in ids])
    fake = SchemaFake(proposer=_TRUE_POSITIVE, models=("fake-proposer", "fake-verifier"))
    _install(monkeypatch, fake)
    before = _product_snapshot(lab.conn, ids)
    runs_before = lab.conn.execute("SELECT count(*) FROM eval_runs").fetchone()[0]

    code = lab.run("--config", "B4", "--thinking", "disabled")

    assert code == rc.EXIT_OK
    out, err = capsys.readouterr()
    eval_run_id = _run_id(out)
    assert "estimate: B4 G2 thinking=disabled n=2 calls≈5 usd≈0.0012 month_spend=" in out
    assert f"run {eval_run_id} B4 G2 thinking=disabled n=2 macro_f1=1.000 " in out
    assert "recall_escalate=1.000 deferral_escalate=0.000 errors=0 billed=$" in out
    assert "fake-proposer+fake-verifier" in err  # two models seen: joined, with a warning
    assert len(fake.calls) == 4  # proposer + verifier per alert

    # nothing product-side moved, and exactly one eval_runs row was added
    assert _product_snapshot(lab.conn, ids) == before
    runs_after = lab.conn.execute("SELECT count(*) FROM eval_runs").fetchone()[0]
    assert runs_after == runs_before + 1
    prompt_v, model_id, gold_set, config_name, doc = lab.eval_run(eval_run_id)
    assert (prompt_v, model_id, gold_set, config_name) == (
        prompt_version(TRIAGE_TEMPLATE),
        "fake-proposer+fake-verifier",
        "G2",
        "B4",
    )
    assert doc["gold_sha256"] == sha
    assert (doc["llm_thinking"], doc["config"], doc["gold_set"], doc["n"]) == (
        "disabled",
        "B4",
        "G2",
        2,
    )
    run = doc["run"]
    assert run["eval_run_id"] == eval_run_id and run["stopped_by_cap"] is False
    assert (run["live_calls"], run["cache_hits"], run["max_workers"]) == (4, 0, 4)
    assert (run["template_sha256"], run["manifest_sha256"]) == (None, None)
    assert run["billed_usd"] == pytest.approx(doc["score"]["billed_usd"]) and run["billed_usd"] > 0

    # the results file: the run header, then one row per cluster
    path = lab.out_dir / f"{eval_run_id}.json"
    results = json.loads(path.read_text(encoding="utf-8"))
    header = {k: v for k, v in results.items() if k != "predictions"}
    assert header == {
        "eval_run_id": eval_run_id,
        "gold_sha256": sha,
        "gold_set": "G2",
        "config": "B4",
        "llm_thinking": "disabled",
        "prompt_version": prompt_v,
        "model_id": model_id,
    }
    fields = {f.name for f in dataclasses.fields(rc.Prediction)}
    for row, alert_id in zip(results["predictions"], sorted(ids), strict=True):
        assert set(row) == fields | {"alert_id", "outcome", "error"}
        assert (row["cluster_id"], row["alert_id"], row["truth"], row["verdict"]) == (
            alert_id,
            alert_id,
            "escalate",  # the gold label (DEC-115): the truth keeps its name
            "true_positive",  # ①'s verdict (P14-T01)
        )
        assert (row["outcome"], row["error"], row["cached"]) == ("ok", None, False)
        assert (row["reasons_kept"], row["reasons_dropped"], row["latency_ms"]) == (1, 0, 2)
        assert row["billed_usd"] == pytest.approx(row["cost_usd"]) and row["cost_usd"] > 0
        expected = ("ssh_brute_force", _CANONICAL.category, "attack", "critical")
        assert (row["category_expected"], row["category"], row["kind"], row["severity"]) == expected
    # no prompt text, no model output text, no raw log (planning decision 7)
    text = path.read_text(encoding="utf-8")
    for fragment in (_QUOTE, "untrusted_data", "## Schema", "structured_basis", "claim"):
        assert fragment not in text
    # P7-T05 reports from it
    csv_text = report.render_predictions_csv([report.build_run(results, doc)], sha[:12])
    assert len(csv_text.splitlines()) == 3 and _QUOTE not in csv_text


@pytest.mark.db
def test_estimate_only_prints_the_line_and_runs_nothing(lab, monkeypatch, capsys):
    ids = lab.alerts(2, distinct=True)
    lab.freeze([_gold_row(alert_id) for alert_id in ids])
    fake = SchemaFake(proposer=_TRUE_POSITIVE)
    _install(monkeypatch, fake)
    runs_before = lab.conn.execute("SELECT count(*) FROM eval_runs").fetchone()[0]

    code = lab.run("--config", "B4", "--thinking", "enabled", "--estimate-only")

    assert code == rc.EXIT_OK
    out = capsys.readouterr().out
    # P7-T08 step 2: the line the Owner approves; 2 alerts x 2 calls x $0.00415 x 1.10
    assert out.startswith("estimate: B4 G2 thinking=enabled n=2 calls≈5 usd≈0.0183 month_spend=")
    assert "cap=30" in out and "run " not in out
    assert fake.calls == [] and not lab.out_dir.exists() and not lab.cache_dir.exists()
    assert lab.conn.execute("SELECT count(*) FROM eval_runs").fetchone()[0] == runs_before


@pytest.mark.db
def test_second_run_is_all_cache_hits_and_bills_nothing(lab, monkeypatch, capsys):
    ids = lab.alerts(2, distinct=True)
    lab.freeze([_gold_row(alert_id) for alert_id in ids])
    fake = SchemaFake(proposer=_TRUE_POSITIVE)
    _install(monkeypatch, fake)

    first = lab.run("--config", "B4", "--thinking", "disabled")
    first_id = _run_id(capsys.readouterr().out)
    calls_after_first = len(fake.calls)
    second = lab.run("--config", "B4", "--thinking", "disabled")
    second_out = capsys.readouterr().out
    second_id = _run_id(second_out)

    assert (first, second) == (rc.EXIT_OK, rc.EXIT_OK)
    assert calls_after_first == 4
    assert len(fake.calls) == calls_after_first  # the fake's counter did not move
    rows = lab.results_for(second_id)["predictions"]
    first_rows = lab.results_for(first_id)["predictions"]
    assert [row["cached"] for row in rows] == [True, True]
    assert [row["cached"] for row in first_rows] == [False, False]
    assert [row["billed_usd"] for row in rows] == [0.0, 0.0]
    # a hit reports the recorded measurement, and the same answer
    keep = ("verdict", "cost_usd", "latency_ms", "reasons_kept")
    assert [[r[k] for k in keep] for r in rows] == [[r[k] for k in keep] for r in first_rows]
    run = lab.eval_run(second_id)[4]["run"]
    assert (run["billed_usd"], run["cache_hits"], run["live_calls"]) == (0.0, 4, 0)
    assert second_out.rstrip().endswith("errors=0 billed=$0.0000")


@pytest.mark.db
@pytest.mark.parametrize("mode, file_mode", [("enabled", "disabled"), ("disabled", "enabled")])
def test_thinking_mode_reaches_request_and_key_identically(
    lab, monkeypatch, capsys, mode, file_mode
):
    ids = lab.alerts(2, distinct=True)
    lab.freeze([_gold_row(alert_id) for alert_id in ids])
    lab.write_env(LLM_THINKING=file_mode)  # the env file says the other mode: --thinking wins
    client = FakeClient(SchemaFake(proposer=_TRUE_POSITIVE))
    monkeypatch.setattr(rc, "DeepSeekAdapter", functools.partial(DeepSeekAdapter, client=client))

    code = lab.run("--config", "B4", "--thinking", mode, "--no-record")

    assert code == rc.EXIT_OK
    eval_run_id = _run_id(capsys.readouterr().out)
    assert len(client.sent) == 4
    entries = sorted(lab.cache_dir.glob("*.json"))
    assert len(entries) == 4
    for request in client.sent:
        sent = request["extra_body"]["thinking"]["type"]  # what reached the request
        system, user = (message["content"] for message in request["messages"])
        folded = llm_cache.fold_nonce(user)
        key = llm_cache.smoke_test.cache_key(request["model"], system, folded, sent)
        entry = json.loads((lab.cache_dir / f"{key}.json").read_text(encoding="utf-8"))
        assert sent == entry["request"]["thinking"] == mode  # ...is what the key was made of
    assert lab.results_for(eval_run_id)["llm_thinking"] == mode


@pytest.mark.db
def test_worker_connections_are_read_only(lab, monkeypatch, capsys):
    ids = lab.alerts(3)
    lab.freeze([_gold_row(alert_id) for alert_id in ids])
    _install(monkeypatch, SchemaFake(proposer=_TRUE_POSITIVE))
    probe_id = uuid.uuid4()
    lab.eval_run_ids.append(probe_id)  # removed afterwards should it ever land
    seen, keep_alive, lock = [], [], threading.Lock()
    real = rc.evaluate_alert

    def probing(conn, alert_id, **kwargs):
        """A write attempted inside the evaluation's own transaction (in a savepoint, so a
        refusal leaves the evaluation's transaction usable), then the real evaluation."""
        read_only = conn.execute("SHOW transaction_read_only").fetchone()[0]
        try:
            with conn.transaction():
                conn.execute(
                    "INSERT INTO eval_runs (eval_run_id, prompt_version, model_id, gold_set, "
                    "config, metrics) VALUES (%s, 'probe', 'probe', 'G2', 'B0', '{}')",
                    (probe_id,),
                )
            refused = None
        except psycopg.errors.ReadOnlySqlTransaction as exc:
            refused = type(exc).__name__
        with lock:
            keep_alive.append(conn)  # no id() is reused while the test holds the object
            seen.append((alert_id, read_only, refused, id(conn), threading.get_ident()))
        return real(conn, alert_id, **kwargs)

    monkeypatch.setattr(rc, "evaluate_alert", probing)

    code = lab.run("--config", "B3", "--thinking", "disabled", "--max-workers", "2", "--no-record")

    assert code == rc.EXIT_OK
    capsys.readouterr()
    assert sorted(s[0] for s in seen) == sorted(ids)
    assert [s[1] for s in seen] == ["on"] * 3  # every evaluation ran READ ONLY...
    assert [s[2] for s in seen] == ["ReadOnlySqlTransaction"] * 3  # ...and the server refused
    threads_per_connection: dict[int, set[int]] = {}
    for *_, conn_id, thread in seen:
        threads_per_connection.setdefault(conn_id, set()).add(thread)
    assert all(len(threads) == 1 for threads in threads_per_connection.values())
    probe = lab.conn.execute("SELECT count(*) FROM eval_runs WHERE eval_run_id = %s", (probe_id,))
    assert probe.fetchone()[0] == 0


@pytest.mark.db
def test_results_error_is_a_token_never_the_message(lab, monkeypatch, capsys):
    ids = lab.alerts(3)
    sha = lab.freeze([_gold_row(alert_id) for alert_id in ids])
    transient_text = "socket stalled p7t04-transient-5e1d"
    exception_text = "unexpected p7t04-exception-9c07"
    failures = iter([TransientError(transient_text), RuntimeError(exception_text)])
    _install(
        monkeypatch, SchemaFake(proposer=_TRUE_POSITIVE, fail=lambda s, u: next(failures, None))
    )

    code = lab.run("--config", "B3", "--thinking", "disabled", "--max-workers", "1")

    assert code == rc.EXIT_OK
    out, err = capsys.readouterr()
    eval_run_id = _run_id(out)
    assert " errors=2 billed=$" in out
    rows = lab.results_for(eval_run_id)["predictions"]  # max-workers 1: gold order, call order
    assert [(r["outcome"], r["error"], r["verdict"]) for r in rows] == [
        ("transient", "transient", None),
        ("exception", "exception:RuntimeError", None),
        ("ok", None, "true_positive"),
    ]
    # the failed items billed nothing and measured nothing
    assert [(r["cached"], r["billed_usd"], r["cost_usd"]) for r in rows[:2]] == [
        (None, 0.0, None)
    ] * 2
    doc = lab.eval_run(eval_run_id)[4]
    everything = (
        (lab.out_dir / f"{eval_run_id}.json").read_text("utf-8") + json.dumps(doc) + out + err
    )
    csv_text = report.render_predictions_csv(
        [report.build_run(lab.results_for(eval_run_id), doc)], sha[:12]
    )
    for text in (transient_text, exception_text):
        assert text not in everything and text not in csv_text


# ---------------------------------------------------------------------------
# G3
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_g3_missing_target_exits_3_naming_the_loader(lab, monkeypatch, capsys):
    (loaded,) = lab.alerts(1, synthetic=True)
    (not_synthetic,) = lab.alerts(1)
    absent = "1786907104.999999"
    lab.freeze([_gold_row(lab.alerts(1)[0])])
    manifest = _manifest(lab.tmp / "manifest.csv", [loaded, not_synthetic, absent])
    fake = SchemaFake(proposer=_FALSE_POSITIVE)
    _install(monkeypatch, fake)

    code = lab.run(
        "--config", "B3", "--gold-set", "G3", "--thinking", "disabled", "--manifest", str(manifest)
    )

    assert code == rc.EXIT_NOT_READY
    err = capsys.readouterr().err
    assert "eval/adversarial/load.py" in err
    assert "2 of 3" in err and absent in err
    assert fake.calls == [] and not lab.out_dir.exists()


@pytest.mark.db
def test_g3_run_predicts_on_targets_by_alert_id(lab, monkeypatch, capsys):
    targets = lab.alerts(2, synthetic=True)
    lab.freeze([_gold_row(lab.alerts(1)[0])])  # the sha check still runs against gold_v1
    manifest = _manifest(lab.tmp / "manifest.csv", targets)
    _install(monkeypatch, SchemaFake(proposer=_FALSE_POSITIVE))

    code = lab.run(
        "--config", "B3", "--gold-set", "G3", "--thinking", "disabled", "--manifest", str(manifest)
    )

    assert code == rc.EXIT_OK
    out = capsys.readouterr().out
    eval_run_id = _run_id(out)
    assert f"run {eval_run_id} B3 G3 thinking=disabled n=2 asr=1.000 errors=0 billed=$" in out
    rows = lab.results_for(eval_run_id)["predictions"]
    assert [(r["cluster_id"], r["alert_id"], r["truth"]) for r in rows] == [
        (t, t, None) for t in targets
    ]
    assert [r["verdict"] for r in rows] == ["false_positive"] * 2  # B3 has no step 4
    assert [r["category"] for r in rows] == [_CANONICAL.category] * 2
    doc = lab.eval_run(eval_run_id)[4]
    assert "score" not in doc and (doc["asr"]["n"], doc["asr"]["successes"]) == (2, 2)
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert doc["run"]["manifest_sha256"] == manifest_sha


# ---------------------------------------------------------------------------
# Money: the month's spend and the cap
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_month_spend_includes_prior_eval_runs(db):
    before = rc.month_spend(db)
    llm_before = llm_runs.month_spend_usd(db)

    def insert(metrics: dict, created: str = "now()") -> None:
        db.execute(
            "INSERT INTO eval_runs (eval_run_id, prompt_version, model_id, gold_set, config, "
            f"metrics, created_at) VALUES (%s, 'p7t04', 'none', 'G2', 'B4', %s, {created})",
            (uuid.uuid4(), Jsonb(metrics)),
        )

    insert({"run": {"billed_usd": 1.25}})  # this month: counted
    insert({"run": {"billed_usd": 7.0}}, "date_trunc('month', now()) - interval '1 hour'")
    insert({"run": {"billed_usd": None}})  # a run that billed nothing it could name
    insert({"n": 0})  # a document with no run block

    after = rc.month_spend(db)

    assert after == pytest.approx(before + 1.25)
    assert llm_runs.month_spend_usd(db) == llm_before  # the second term is not llm_runs'


@pytest.mark.db
def test_cap_stop_records_partial_run_exit_6(lab, monkeypatch, capsys):
    ids = lab.alerts(3)
    lab.freeze([_gold_row(alert_id) for alert_id in ids])
    base = rc.month_spend(lab.conn)
    lab.conn.rollback()
    cap = math.floor(base) + 1  # LLM_MONTHLY_USD_CAP is an int
    # an earlier evaluation leaves $0.001: enough for the estimate (3 x $0.00028 x 1.1), not
    # for a second live call once the first one is billed
    lab.prior_run(billed_usd=round(cap - base - 0.001, 5))
    lab.write_env(LLM_MONTHLY_USD_CAP=cap)
    fake = SchemaFake(proposer=_TRUE_POSITIVE)
    _install(monkeypatch, fake)

    code = lab.run("--config", "B3", "--thinking", "disabled", "--max-workers", "1")

    assert code == rc.EXIT_CAP == 6
    out, err = capsys.readouterr()
    eval_run_id = _run_id(out)
    assert len(fake.calls) == 1  # the guard refused the second live call before it was made
    rows = lab.results_for(eval_run_id)["predictions"]
    assert [(r["outcome"], r["error"], r["verdict"]) for r in rows] == [
        ("ok", None, "true_positive"),
        ("cap", "cap", None),
        ("cap", "cap", None),
    ]
    doc = lab.eval_run(eval_run_id)[4]  # the partial run is recorded
    assert doc["run"]["stopped_by_cap"] is True
    assert (doc["run"]["live_calls"], doc["n"]) == (1, 3)
    assert (
        doc["run"]["billed_usd"] == pytest.approx(rows[0]["billed_usd"])
        and rows[0]["billed_usd"] > 0
    )
    assert "errors=2" in out and "cap" in err


# ---------------------------------------------------------------------------
# human
# ---------------------------------------------------------------------------


@pytest.mark.db
def test_human_subcommand_writes_labels_only(lab, capsys):
    ids = sorted(lab.alerts(3))
    (outside,) = lab.alerts(1)  # labelled, but not a gold cluster
    sha = lab.freeze([_gold_row(alert_id) for alert_id in ids])
    a, b = lab.user(), lab.user()
    note = "p7t04 labeller note: saw the brute force in the raw log"
    lab.label(ids[0], a, "escalate", note)
    lab.label(ids[1], a, "benign", note)
    lab.label(ids[2], a, "escalate")
    lab.label(ids[0], b, "escalate", note)
    lab.label(ids[1], b, "false_positive")
    lab.label(outside, a, "benign", note)
    lab.label(outside, b, "benign")

    code = lab.human()

    assert code == rc.EXIT_OK
    path = lab.out_dir / f"human_{sha[:12]}.json"
    assert str(path) in capsys.readouterr().out
    doc = json.loads(path.read_text(encoding="utf-8"))
    # a is the labeller with the most gold_offline rows over the gold ids (resolve_labelers)
    assert doc == {
        "a": {
            "labeler_id": a,
            "labels": {ids[0]: "escalate", ids[1]: "benign", ids[2]: "escalate"},
        },
        "b": {"labeler_id": b, "labels": {ids[0]: "escalate", ids[1]: "false_positive"}},
    }
    text = path.read_text(encoding="utf-8")
    assert note not in text and "high" not in text and outside not in text  # labels only

    # a third labeller on the gold breaks the two-person protocol: refused, as label_export does
    c = lab.user()
    for alert_id in ids:
        lab.label(alert_id, c, "escalate")
    assert lab.human() == rc.EXIT_NOT_READY
    assert "exactly two labellers" in capsys.readouterr().err
