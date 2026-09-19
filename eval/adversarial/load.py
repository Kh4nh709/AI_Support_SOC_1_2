#!/usr/bin/env python3
"""Run in P7 only, after `eval/gold_v1.sha256` is committed — G3 is never shown to the model before evaluation.

Insert the G3 fixtures (`eval/adversarial/manifest.csv` + `fixtures/*.json`) into a
database as `received`, `is_synthetic = true`, `source = 'lab'` heads with real
enrichment context and **no job** (P6-tasks.md planning decision 4). P7 runs ① on
them by `alert_id` from the manifest, never through the pilot queue.

    PYTHONPATH=backend python3 eval/adversarial/load.py [--dsn DSN | --env-file .env]
        [--manifest eval/adversarial/manifest.csv] [--fixtures-dir eval/adversarial/fixtures]
        [--dry-run] [--i-know-the-gold-is-not-frozen]

What one fixture becomes, in one transaction per fixture: `json.load` ->
`parse_wazuh_alert` (the product parser; a rejection is exit 1 naming the file,
never a skip -- every fixture is parsed before the first transaction, so a
generator bug writes nothing) -> skip if a row with that `alert_id` exists
(idempotent) -> `domain.transitions.open_alert(kind="received", source="lab",
suggestion_visible=False)` (G2: `status` is only ever written by `domain/`, and
this loader never names that column) -> the three inventory lookups
`soar.pipeline` runs, in the same order, into an `AlertContext` ->
`compute_risk_score(severity, ctx, 1)` -> one `UPDATE` that sets `is_synthetic`
and the same six enrichment columns, with the same JSON shapes, that the A5
transition writes (`transitions.py:324-331`, `:337-347`), so P7's facts builder
sees a row indistinguishable from a real one except for `status`.

What is deliberately **not** done, each proven by a test: no dedup (every fixture
is its own head, `occurrence_count = 1`, which is what lets vector 5's neighbour
be found by the +/-2 h correlation query), no auto-close evaluation, no A4/A5
transition (the `triage` job is created there -- and a `triage` job is exactly
how the model would see G3 before P7), no `intake` row (a fixture was never
received; G9/G12 are about received documents), no job of any kind. After the
loop the loader counts `triage` jobs over the loaded ids and refuses (exit 1) on
anything but zero -- a defence against a future `open_alert` that creates one.

The per-fixture transaction is psycopg's `conn.transaction()`: `BEGIN`/`COMMIT`
on the fresh connection `main()` opens, a savepoint when a test runs the loader
inside its fixture's already-open transaction (so the `audit_events` row
`open_alert` appends -- append-only, migration 017 -- never outlives the test).

`main()` refuses (exit 1) while `eval/gold_v1.sha256` does not exist next to this
repository root, unless `--i-know-the-gold-is-not-frozen` is passed: the flag
exists for a test database, where no gold set will ever be frozen, and its name
is deliberately unpleasant. Never run this against `soc_dev` before the freeze,
with or without the flag. A DSN is read, never printed.

Exit codes: 0 done (including a run that skipped everything); 1 refused --
freeze marker absent, a fixture the parser rejects, a `triage` job found; 2 the
DSN could not be resolved, the database could not be reached, or the manifest
or a fixture file could not be read.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

import psycopg
from app.domain import transitions
from app.domain.alert import Alert, AlertContext
from app.enrichment import lookups
from app.infra import config, db
from app.ingest.wazuh_parser import parse_wazuh_alert
from app.soar.risk import compute_risk_score
from psycopg.types.json import Jsonb

REPO_ROOT = Path(__file__).resolve().parents[2]
FREEZE_MARKER = REPO_ROOT / "eval" / "gold_v1.sha256"
DEFAULT_MANIFEST = REPO_ROOT / "eval" / "adversarial" / "manifest.csv"
DEFAULT_FIXTURES_DIR = REPO_ROOT / "eval" / "adversarial" / "fixtures"
FREEZE_FLAG = "--i-know-the-gold-is-not-frozen"

SOURCE = "lab"
EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_ENV = 2


class Refusal(Exception):
    """Exit 1: the run is refused for a reason the message explains."""


class FixtureRejected(Refusal):
    """The product parser rejected a fixture -- a generator bug, never skipped."""


class EnvironmentProblem(Exception):
    """Exit 2: DSN, database or files unreachable."""


@dataclass(frozen=True)
class Planned:
    """One fixture, parsed and ready: `role` is `target` or `neighbour`."""

    role: str
    vector: str
    pattern_id: str
    path: Path
    alert: Alert


@dataclass(frozen=True)
class LoadReport:
    loaded_targets: int
    loaded_neighbours: int
    skipped: int
    triage_jobs: int
    dry_run: bool

    @property
    def loaded(self) -> int:
        return self.loaded_targets + self.loaded_neighbours


def read_manifest(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except OSError as exc:
        raise EnvironmentProblem(f"cannot read manifest {path}: {exc}") from exc
    if not rows:
        raise Refusal(f"manifest {path} has no rows")
    return rows


def _parse_fixture(path: Path) -> Alert:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise EnvironmentProblem(f"cannot read fixture {path}: {exc}") from exc
    except ValueError as exc:
        raise FixtureRejected(f"{path}: not JSON ({exc})") from exc
    result = parse_wazuh_alert(document)
    if result.alert is None:
        raise FixtureRejected(f"{path}: rejected by parse_wazuh_alert ({result.rejection})")
    return result.alert


def plan(manifest_path: Path, fixtures_dir: Path) -> list[Planned]:
    """Every manifest row's target, then its neighbour when present, parsed.
    The manifest's `fixture_file` is repository-relative; only its basename is
    used under `fixtures_dir`, so `--fixtures-dir` can point anywhere."""
    planned: list[Planned] = []
    for row in read_manifest(manifest_path):
        target_path = fixtures_dir / Path(row["fixture_file"]).name
        planned.append(
            Planned(
                role="target",
                vector=row["vector"],
                pattern_id=row["pattern_id"],
                path=target_path,
                alert=_parse_fixture(target_path),
            )
        )
        if row["neighbour_fixture_file"]:
            neighbour_path = fixtures_dir / Path(row["neighbour_fixture_file"]).name
            planned.append(
                Planned(
                    role="neighbour",
                    vector=row["vector"],
                    pattern_id=row["pattern_id"],
                    path=neighbour_path,
                    alert=_parse_fixture(neighbour_path),
                )
            )
    return planned


def build_context(conn: psycopg.Connection, alert: Alert) -> AlertContext:
    """The three lookups `soar.pipeline` runs for a non-duplicate alert, in the
    same order and into the same `AlertContext` -- copied, because that helper
    is private to the pipeline (card rule 6)."""
    asset = lookups.lookup_asset(conn, alert.agent_name, alert.origin_host)
    identity = lookups.lookup_identity(conn, alert.alert_user)
    ioc = lookups.lookup_ioc(
        conn,
        alert.srcip,
        alert.dstip,
        srcip_is_private=alert.srcip_is_private,
        dstip_is_private=alert.dstip_is_private,
    )
    return AlertContext(
        asset["present"],
        asset["criticality"],
        asset["owner"],
        asset["role"],
        identity["is_privileged"],
        ioc["reputation"],
        {"asset": asset["status"], "identity": identity["status"], "ioc": ioc["status"]},
    )


def _exists(conn: psycopg.Connection, alert_id: str) -> bool:
    return (
        conn.execute("SELECT 1 FROM alerts WHERE alert_id = %s", (alert_id,)).fetchone() is not None
    )


#: The six columns the A5 transition sets (transitions.py:337-347), plus `is_synthetic`.
#: `status` is not named here and never will be (G2).
_MARK_SYNTHETIC_SQL = (
    "UPDATE alerts SET is_synthetic = true, asset_context = %s, identity_context = %s, "
    "ioc_context = %s, lookup_status = %s, risk_score = %s, risk_score_components = %s "
    "WHERE alert_id = %s"
)


def insert_synthetic(conn: psycopg.Connection, alert: Alert) -> None:
    """`open_alert` + context + risk + the synthetic mark, on the caller's transaction."""
    transitions.open_alert(conn, alert, kind="received", source=SOURCE, suggestion_visible=False)
    ctx = build_context(conn, alert)
    risk_score, risk_components = compute_risk_score(alert.severity, ctx, 1)
    # The same JSON shapes as transitions.py:324-331.
    asset_context = {
        "present": ctx.asset_present,
        "criticality": ctx.asset_criticality,
        "owner": ctx.asset_owner,
        "role": ctx.asset_role,
    }
    identity_context = {"privileged": ctx.identity_privileged}
    ioc_context = {"reputation": ctx.ioc_reputation}
    conn.execute(
        _MARK_SYNTHETIC_SQL,
        (
            Jsonb(asset_context),
            Jsonb(identity_context),
            Jsonb(ioc_context),
            Jsonb(dict(ctx.lookup_status)),
            risk_score,
            Jsonb(risk_components),
            alert.alert_id,
        ),
    )


def count_triage_jobs(conn: psycopg.Connection, alert_ids: Sequence[str]) -> int:
    return conn.execute(
        "SELECT count(*) FROM jobs WHERE job_type = 'triage' AND subject_id = ANY(%s)",
        (list(alert_ids),),
    ).fetchone()[0]


def load_planned(
    conn: psycopg.Connection,
    planned: Sequence[Planned],
    *,
    dry_run: bool = False,
    out: TextIO = sys.stdout,
) -> LoadReport:
    """One transaction per fixture; `dry_run` only reads (the existence check) and
    prints the plan. The `triage` count is reported, never asserted here --
    `main()` refuses on it; a test asserts it directly."""
    loaded_targets = loaded_neighbours = skipped = 0
    for item in planned:
        label = (
            f"{item.alert.alert_id} {item.vector}/{item.pattern_id} {item.role} {item.path.name}"
        )
        with conn.transaction():
            if _exists(conn, item.alert.alert_id):
                skipped += 1
                print(f"load: skip {label}: already loaded", file=out)
                continue
            if dry_run:
                print(f"load: would load {label}", file=out)
            else:
                insert_synthetic(conn, item.alert)
                print(f"load: loaded {label}", file=out)
        if item.role == "target":
            loaded_targets += 1
        else:
            loaded_neighbours += 1
    triage_jobs = count_triage_jobs(conn, [item.alert.alert_id for item in planned])
    return LoadReport(
        loaded_targets=loaded_targets,
        loaded_neighbours=loaded_neighbours,
        skipped=skipped,
        triage_jobs=triage_jobs,
        dry_run=dry_run,
    )


def load_manifest(
    conn: psycopg.Connection,
    manifest_path: Path,
    fixtures_dir: Path,
    *,
    dry_run: bool = False,
    out: TextIO = sys.stdout,
) -> LoadReport:
    return load_planned(conn, plan(manifest_path, fixtures_dir), dry_run=dry_run, out=out)


def _resolve_dsn(dsn: str | None, env_file: str) -> str:
    if dsn:
        return dsn
    resolved = config.load(env_file=env_file).DATABASE_URL
    if not resolved:
        raise EnvironmentProblem(
            "no DSN: pass --dsn, or set DATABASE_URL in the file named by --env-file"
        )
    return resolved


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="load.py",
        description=(
            "Insert the G3 adversarial fixtures as received, is_synthetic, source='lab' heads "
            "with enrichment context and no job. Run in P7 only, after the gold freeze."
        ),
        epilog="Exit codes: 0 done, 1 refused (explained on stderr), 2 environment problem.",
    )
    parser.add_argument("--dsn", default=None, metavar="DSN")
    parser.add_argument("--env-file", default=".env", metavar="PATH")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), metavar="PATH")
    parser.add_argument("--fixtures-dir", default=str(DEFAULT_FIXTURES_DIR), metavar="DIR")
    parser.add_argument(
        "--dry-run", action="store_true", help="parse every fixture, print the plan, write nothing"
    )
    parser.add_argument(
        FREEZE_FLAG,
        action="store_true",
        help="skip the eval/gold_v1.sha256 check -- for a test database only",
    )
    return parser


def _plan_counts(planned: Sequence[Planned]) -> tuple[int, int]:
    targets = sum(1 for item in planned if item.role == "target")
    return targets, len(planned) - targets


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.i_know_the_gold_is_not_frozen and not FREEZE_MARKER.exists():
        print(
            f"load: refusing -- {FREEZE_MARKER} does not exist, so the gold set is not "
            "frozen and G3 must not enter any database yet (run in P7 only; "
            f"pass {FREEZE_FLAG} on a test database, never on soc_dev)",
            file=sys.stderr,
        )
        return EXIT_REFUSED

    try:
        planned = plan(Path(args.manifest), Path(args.fixtures_dir))
    except Refusal as exc:
        print(f"load: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except EnvironmentProblem as exc:
        print(f"load: {exc}", file=sys.stderr)
        return EXIT_ENV

    try:
        conn = db.connect(_resolve_dsn(args.dsn, args.env_file))
    except EnvironmentProblem as exc:
        print(f"load: {exc}", file=sys.stderr)
        return EXIT_ENV
    except psycopg.OperationalError:
        print("load: could not reach the database (DSN not shown)", file=sys.stderr)
        return EXIT_ENV

    try:
        report = load_planned(conn, planned, dry_run=args.dry_run)
        targets, neighbours = _plan_counts(planned)
        if args.dry_run:
            print(
                f"load: dry run -- {len(planned)} fixtures ({targets} targets + {neighbours} "
                f"neighbours): would load {report.loaded}, skip {report.skipped} existing; "
                "nothing written"
            )
            return EXIT_OK
        print(
            f"loaded {report.loaded} ({report.loaded_targets} targets + "
            f"{report.loaded_neighbours} neighbours), skipped {report.skipped} existing, "
            f"triage jobs {report.triage_jobs}"
        )
        if report.triage_jobs != 0:
            print(
                f"load: refusing -- {report.triage_jobs} triage job(s) exist for the loaded ids; "
                "open_alert must never create one (planning decision 4)",
                file=sys.stderr,
            )
            return EXIT_REFUSED
        return EXIT_OK
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
