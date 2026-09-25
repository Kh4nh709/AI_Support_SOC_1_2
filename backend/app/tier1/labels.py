"""The blind labelling page's logic (P6-T02): which cluster a labeller sees next,
what they see of it, and the one row their label becomes.

The page serves the gold-set labelling protocol (architecture §6 "Giao thức gán
nhãn"): no ① output, a random order per labeller, independent labellers, a label
in three values plus a confidence and a one-line note. Three mechanisms carry it:

- **Order** — `labeler_order` is a pure function of `(seed, labeler_id)`: two
  labellers get different permutations of the same set, and a restart changes
  nothing (P6-tasks.md planning decision 8).
- **What is shown is an allowlist** — `cluster_view` builds its dict from
  `VIEW_KEYS` only, and reads `alerts` with an explicit column list, so
  `source`, `status` and everything LLM-derived never enter the process
  (planning decision 9, DEC-019). The dict then passes through P4's
  `visibility.strip(..., mode="labeling")` — the allowlist is the mechanism,
  the filter is P4's guarantee.
- **The numbers are the file's** — `occurrence_count`, `first_seen`, `last_seen`
  come from `eval/gold_candidates.csv`; for G1 the DB's values are the replay
  afternoon's clock (P6-tasks.md §5), and G1's correlation is computed over
  `eval/g1_clusters.csv` for the same reason (`g1_correlation`).

Both CSVs are read per call (400 and 3,051 rows: milliseconds) — no module-level
cache a test would have to invalidate. Every public function takes its path as a
keyword argument defaulting to the constants below.
"""

from __future__ import annotations

import csv
import hashlib
import random
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
from psycopg import errors

from app.audit.events import write_event
from app.domain.correlation import summarize_for_prompt
from app.kb.lookup import get_playbook
from app.tier1 import visibility

#: `backend/app/tier1/labels.py` -> `tier1` -> `app` -> `backend` -> repo root
#: (the construction `kb/lookup.py` uses for `kb/`).
REPO_ROOT = Path(__file__).resolve().parents[3]
CANDIDATES_PATH = REPO_ROOT / "eval" / "gold_candidates.csv"
G1_CLUSTERS_PATH = REPO_ROOT / "eval" / "g1_clusters.csv"
#: P6-T03's `freeze` writes this; once it exists the undo is refused.
FREEZE_MARKER = REPO_ROOT / "eval" / "gold_v1.sha256"

#: The same literal as `eval/build_gold.py`'s `EVAL_SEED` — two literals, no
#: import across the `eval` boundary (P6-tasks.md rule 10).
LABEL_ORDER_SEED = 20260904

LABELS: tuple[str, ...] = ("false_positive", "benign", "escalate")
CONFIDENCES: tuple[int, ...] = (1, 2, 3)
NOTE_MAX_CHARS = 200

#: `raw_log` is shown whole up to this many bytes; beyond it the display is cut
#: and `raw_log_truncated_for_display` says so on the page.
RAW_LOG_DISPLAY_BYTES = 32_768

NO_PLAYBOOK_TEXT = "No playbook covers this category."
CORRELATION_MAX_ROWS = 20
CORRELATION_MAX_SAMPLES = 5

#: Every key `cluster_view` may return (planning decision 9 / card note 3).
VIEW_KEYS: tuple[str, ...] = (
    "alert_id",
    "rule_id",
    "rule_level",
    "severity",
    "description",
    "agent_name",
    "alert_time",
    "alert_user",
    "srcip",
    "dstip",
    "category",
    "raw_log",
    "raw_log_truncated_for_display",
    "occurrence_count",
    "first_seen",
    "last_seen",
    "playbook",
    "correlation",
    "gold_cluster_id",
)

#: The only `alerts` columns this module ever selects — `source`, `status`,
#: `suggestion_visible`, `risk_score`, the `*_context` columns and the DB's
#: `occurrence_count` are not among them, so they never enter the process.
_ALERT_COLUMNS: tuple[str, ...] = (
    "alert_id",
    "rule_id",
    "rule_level",
    "severity",
    "description",
    "agent_name",
    "alert_time",
    "alert_user",
    "srcip",
    "dstip",
    "category",
    "raw_log",
)
_ALERT_SQL = f"SELECT {', '.join(_ALERT_COLUMNS)} FROM alerts WHERE alert_id = %s"


class LabelError(Exception):
    """Base of the refusals `submit_label`/`undo_last` raise; `web` maps each to a status."""


class InvalidSubmission(LabelError):
    """A label, confidence or note outside the protocol (422)."""


class UnknownCluster(LabelError):
    """`cluster_id` is not a gold candidate — this page labels nothing else (404)."""


class AlreadyLabelled(LabelError):
    """This labeller already labelled this cluster; labels are never overwritten (409)."""


class Frozen(LabelError):
    """The gold set is frozen (`FREEZE_MARKER` exists); no undo (409)."""


@dataclass(frozen=True)
class Candidate:
    """One row of `eval/gold_candidates.csv`. The file's `source`, `stratum`,
    `agent_name` and `rule_id` columns are read and discarded — there is no
    `source` attribute here, so it cannot leak by accident (DEC-019)."""

    cluster_id: str
    gold_set: str
    alert_id: str
    category: str
    severity: str
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True)
class G1Cluster:
    """One row of `eval/g1_clusters.csv` (that file has no `source` column)."""

    cluster_id: str
    rule_id: str
    category: str
    severity: str
    agent_name: str
    alert_user: str
    srcip: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int


@dataclass(frozen=True)
class CorrelationView:
    """One grouped correlation row — the shape both gold sets produce, so the
    template has one loop. No `status`: a correlated cluster's pilot decision is
    human context the labeller must not see."""

    rule_id: str
    category: str
    cluster_count: int
    alert_count: int
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True)
class NextResult:
    cluster_id: str | None
    done: int
    total: int


@dataclass(frozen=True)
class SubmitResult:
    cluster_id: str
    done: int
    total: int
    next: str | None


# ---------------------------------------------------------------------------
# The two files
# ---------------------------------------------------------------------------


def load_candidates(*, path: Path = CANDIDATES_PATH) -> list[Candidate]:
    """`eval/gold_candidates.csv` as `Candidate`s; `[]` when the file is absent
    (the page then says so)."""
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as fh:
        return [
            Candidate(
                cluster_id=row["cluster_id"],
                gold_set=row["gold_set"],
                alert_id=row["alert_id"],
                category=row["category"],
                severity=row["severity"],
                occurrence_count=int(row["occurrence_count"]),
                first_seen=datetime.fromisoformat(row["first_seen"]),
                last_seen=datetime.fromisoformat(row["last_seen"]),
            )
            for row in csv.DictReader(fh)
        ]


def load_g1_clusters(*, path: Path = G1_CLUSTERS_PATH) -> list[G1Cluster]:
    """`eval/g1_clusters.csv` as `G1Cluster`s; `[]` when the file is absent."""
    if not path.is_file():
        return []
    with path.open(encoding="utf-8", newline="") as fh:
        return [
            G1Cluster(
                cluster_id=row["cluster_id"],
                rule_id=row["rule_id"],
                category=row["category"],
                severity=row["severity"],
                agent_name=row["agent_name"],
                alert_user=row["alert_user"],
                srcip=row["srcip"],
                first_seen=datetime.fromisoformat(row["first_seen"]),
                last_seen=datetime.fromisoformat(row["last_seen"]),
                occurrence_count=int(row["occurrence_count"]),
            )
            for row in csv.DictReader(fh)
        ]


# ---------------------------------------------------------------------------
# Order and progress
# ---------------------------------------------------------------------------


def labeler_order(
    candidates: Iterable[Candidate], labeler_id: str, *, seed: int = LABEL_ORDER_SEED
) -> list[str]:
    """This labeller's permutation of the candidates' `cluster_id`s — a pure
    function of `(seed, labeler_id)` and the set, never of the file's row order."""
    ids = sorted(c.cluster_id for c in candidates)
    rng = random.Random(int(hashlib.sha256(f"{seed}:{labeler_id}".encode()).hexdigest()[:16], 16))
    rng.shuffle(ids)
    return ids


def next_unlabelled(conn: psycopg.Connection, order: Sequence[str], labeler_id: str) -> NextResult:
    """The first id in `order` this labeller has no `gold_offline` row for, and
    `done/total` over `order`. Only this labeller's rows are read.

    `order` holds cluster ids, compared with `triage_labels.alert_id`: a G1/G2
    cluster's id *is* its head's `alert_id` (`eval/build_gold.py`: `cluster_id =
    alert_id = members[0]`), and `submit_label` writes the head's `alert_id`."""
    labelled = {
        row[0]
        for row in conn.execute(
            "SELECT alert_id FROM triage_labels "
            "WHERE labeler_id = %s AND source = 'gold_offline' AND alert_id = ANY(%s)",
            (labeler_id, list(order)),
        ).fetchall()
    }
    upcoming = next((cid for cid in order if cid not in labelled), None)
    return NextResult(cluster_id=upcoming, done=len(labelled), total=len(order))


# ---------------------------------------------------------------------------
# What the labeller sees
# ---------------------------------------------------------------------------


def _alert_row(conn: psycopg.Connection, alert_id: str) -> dict[str, Any] | None:
    cur = conn.execute(_ALERT_SQL, (alert_id,))
    row = cur.fetchone()
    if row is None:
        return None
    return dict(zip(_ALERT_COLUMNS, row, strict=True))


def _raw_log_for_display(raw_log: str | None) -> tuple[str, bool]:
    text = raw_log or ""
    encoded = text.encode("utf-8")
    if len(encoded) <= RAW_LOG_DISPLAY_BYTES:
        return text, False
    return encoded[:RAW_LOG_DISPLAY_BYTES].decode("utf-8", errors="ignore"), True


def g1_correlation(
    g1_clusters: Sequence[G1Cluster], head: G1Cluster, window_hours: int = 2
) -> list[CorrelationView]:
    """The ±`window_hours` correlation of a G1 head, computed over the fold's
    clusters (`eval/g1_clusters.csv`) rather than `alerts` — for G1 the DB's
    clock is the replay afternoon's (P6-tasks.md §5). Public: P7 imports it.

    The predicate is phase-4 P4-2's three-way OR — same `agent_name`, or the same
    non-empty `alert_user`, or the same non-empty `srcip` — and a cluster counts
    when its `[first_seen, last_seen]` intersects `[head.first_seen − window,
    head.first_seen + window]`; the head itself never counts. Grouped by
    `(rule_id, category)`, `alert_count` = the sum of `occurrence_count`,
    ordered by `alert_count` desc (then `rule_id`, `category` for a stable
    order), at most 20 rows.
    """
    return _group(correlated_g1_clusters(g1_clusters, head, window_hours=window_hours))


def correlated_g1_clusters(
    g1_clusters: Sequence[G1Cluster], head: G1Cluster, *, window_hours: int = 2
) -> list[G1Cluster]:
    """The clusters `g1_correlation` groups, ungrouped (the page's samples)."""
    window = timedelta(hours=window_hours)
    lo, hi = head.first_seen - window, head.first_seen + window
    return [
        c
        for c in g1_clusters
        if c.cluster_id != head.cluster_id
        and (
            c.agent_name == head.agent_name
            or (head.alert_user and c.alert_user == head.alert_user)
            or (head.srcip and c.srcip == head.srcip)
        )
        and c.first_seen <= hi
        and c.last_seen >= lo
    ]


def _group(clusters: Iterable[G1Cluster]) -> list[CorrelationView]:
    groups: dict[tuple[str, str], list[G1Cluster]] = {}
    for c in clusters:
        groups.setdefault((c.rule_id, c.category), []).append(c)
    views = [
        CorrelationView(
            rule_id=rule_id,
            category=category,
            cluster_count=len(members),
            alert_count=sum(m.occurrence_count for m in members),
            first_seen=min(m.first_seen for m in members),
            last_seen=max(m.last_seen for m in members),
        )
        for (rule_id, category), members in groups.items()
    ]
    views.sort(key=lambda v: (-v.alert_count, v.rule_id, v.category))
    return views[:CORRELATION_MAX_ROWS]


def _g1_samples(conn: psycopg.Connection, clusters: Sequence[G1Cluster]) -> list[dict[str, Any]]:
    """Up to 5 correlated heads (highest `occurrence_count`, newest first — the
    order `domain.correlation.samples_query` uses), numbers from the file,
    `description`/`raw_log` from `alerts` by the explicit-column query."""
    ranked = sorted(clusters, key=lambda c: (-c.occurrence_count, -c.first_seen.timestamp()))
    samples = []
    for c in ranked[:CORRELATION_MAX_SAMPLES]:
        row = _alert_row(conn, c.cluster_id) or {}
        samples.append(
            {
                "alert_id": c.cluster_id,
                "rule_id": c.rule_id,
                "category": c.category,
                "severity": c.severity,
                "occurrence_count": c.occurrence_count,
                "alert_time": c.first_seen,
                "description": row.get("description"),
                "raw_log": row.get("raw_log"),
            }
        )
    return samples


@dataclass(frozen=True)
class _Subject:
    """What `summarize_for_prompt` reads off an alert (it is duck-typed)."""

    alert_id: str
    agent_name: str
    alert_user: str
    srcip: str
    alert_time: datetime


def _g2_correlation(conn: psycopg.Connection, alert: dict[str, Any]) -> dict[str, Any]:
    """`domain.correlation.summarize_for_prompt` with `status` dropped from every
    row and sample. Its rows are grouped by `(rule_id, category, status)`, so
    dropping `status` re-groups them by `(rule_id, category)` — two rows left
    side by side would still say "these clusters were decided differently"."""
    summary = summarize_for_prompt(
        conn,
        _Subject(
            alert_id=alert["alert_id"],
            agent_name=alert["agent_name"],
            alert_user=alert["alert_user"],
            srcip=alert["srcip"],
            alert_time=alert["alert_time"],
        ),
    )
    groups: dict[tuple[str, str], list[Any]] = {}
    for r in summary.rows:
        groups.setdefault((r.rule_id, r.category), []).append(r)
    rows = [
        CorrelationView(
            rule_id=rule_id,
            category=category,
            cluster_count=sum(r.cluster_count for r in members),
            alert_count=sum(r.alert_count for r in members),
            first_seen=min(r.first_seen for r in members),
            last_seen=max(r.last_seen for r in members),
        )
        for (rule_id, category), members in groups.items()
    ]
    rows.sort(key=lambda v: (-v.alert_count, v.rule_id, v.category))
    samples = [{k: v for k, v in s.items() if k != "status"} for s in summary.samples]
    return {"rows": [asdict(r) for r in rows], "samples": samples}


def _g1_head(
    candidate: Candidate, alert: dict[str, Any], g1_clusters: Sequence[G1Cluster]
) -> G1Cluster:
    for c in g1_clusters:
        if c.cluster_id == candidate.cluster_id:
            return c
    # Not in the fold file (a hand-built candidates file): the head from the
    # candidate's numbers and the alert's correlation keys.
    return G1Cluster(
        cluster_id=candidate.cluster_id,
        rule_id=alert["rule_id"],
        category=candidate.category,
        severity=candidate.severity,
        agent_name=alert["agent_name"] or "",
        alert_user=alert["alert_user"] or "",
        srcip=alert["srcip"] or "",
        first_seen=candidate.first_seen,
        last_seen=candidate.last_seen,
        occurrence_count=candidate.occurrence_count,
    )


def cluster_view(
    conn: psycopg.Connection, candidate: Candidate, *, g1_clusters: Sequence[G1Cluster]
) -> dict[str, Any]:
    """Everything the page shows of one cluster, and nothing else: exactly the
    keys of `VIEW_KEYS`, passed through P4's filter in `labeling` mode.
    `occurrence_count`/`first_seen`/`last_seen` are the candidate's (the file's),
    never the DB's."""
    alert = _alert_row(conn, candidate.alert_id)
    if alert is None:
        raise UnknownCluster(candidate.cluster_id)

    raw_log, cut = _raw_log_for_display(alert["raw_log"])
    playbook = get_playbook(candidate.category) or NO_PLAYBOOK_TEXT

    if candidate.gold_set == "G1":
        head = _g1_head(candidate, alert, g1_clusters)
        correlated = correlated_g1_clusters(g1_clusters, head)
        correlation = {
            "rows": [asdict(r) for r in _group(correlated)],
            "samples": _g1_samples(conn, correlated),
        }
    else:
        correlation = _g2_correlation(conn, alert)

    view = {
        "alert_id": alert["alert_id"],
        "rule_id": alert["rule_id"],
        "rule_level": alert["rule_level"],
        "severity": alert["severity"],
        "description": alert["description"],
        "agent_name": alert["agent_name"],
        "alert_time": alert["alert_time"],
        "alert_user": alert["alert_user"],
        "srcip": alert["srcip"],
        "dstip": alert["dstip"],
        "category": alert["category"],
        "raw_log": raw_log,
        "raw_log_truncated_for_display": cut,
        "occurrence_count": candidate.occurrence_count,
        "first_seen": candidate.first_seen,
        "last_seen": candidate.last_seen,
        "playbook": playbook,
        "correlation": correlation,
        "gold_cluster_id": candidate.cluster_id,
    }
    assert tuple(view) == VIEW_KEYS
    # Labeling mode ignores both flags (it always strips); neither column is
    # selected here, so the fail-closed values are passed.
    return visibility.strip(view, status="", suggestion_visible=False, mode="labeling")


# ---------------------------------------------------------------------------
# Writing a label, undoing one
# ---------------------------------------------------------------------------


def clean_note(note: str | None) -> str | None:
    """Stripped, newlines replaced by spaces, `None` when empty; `InvalidSubmission`
    beyond `NOTE_MAX_CHARS`."""
    if note is None:
        return None
    text = " ".join(note.splitlines()).strip()
    if len(text) > NOTE_MAX_CHARS:
        raise InvalidSubmission(f"note: at most {NOTE_MAX_CHARS} characters")
    return text or None


def submit_label(
    conn: psycopg.Connection,
    *,
    labeler_id: str,
    cluster_id: str,
    label: str,
    confidence: int,
    note: str | None,
    candidates_path: Path = CANDIDATES_PATH,
) -> SubmitResult:
    """One `triage_labels(source='gold_offline')` row plus its `label.created`
    event, in the caller's transaction. A second label for the same cluster by
    the same labeller is `AlreadyLabelled`, never an overwrite."""
    if label not in LABELS:
        raise InvalidSubmission(f"label: must be one of {'|'.join(LABELS)}")
    if confidence not in CONFIDENCES or isinstance(confidence, bool):
        raise InvalidSubmission("confidence: must be 1, 2 or 3")
    note = clean_note(note)

    candidates = load_candidates(path=candidates_path)
    candidate = next((c for c in candidates if c.cluster_id == cluster_id), None)
    if candidate is None:
        raise UnknownCluster(cluster_id)

    try:
        with conn.transaction():  # a savepoint: a duplicate leaves the caller's transaction usable
            conn.execute(
                "INSERT INTO triage_labels (alert_id, labeler_id, source, label, confidence, note) "
                "VALUES (%s, %s, 'gold_offline', %s, %s, %s)",
                (candidate.alert_id, labeler_id, label, str(confidence), note),
            )
    except errors.UniqueViolation as exc:
        raise AlreadyLabelled(cluster_id) from exc

    write_event(
        conn,
        "label.created",
        candidate.alert_id,
        "admin",
        actor_id=labeler_id,
        payload={
            "alert_id": candidate.alert_id,
            "labeler_id": labeler_id,
            "label": label,
            "confidence": confidence,
            "gold_set": candidate.gold_set,
        },
    )
    progress = next_unlabelled(conn, labeler_order(candidates, labeler_id), labeler_id)
    return SubmitResult(
        cluster_id=cluster_id, done=progress.done, total=progress.total, next=progress.cluster_id
    )


def undo_last(
    conn: psycopg.Connection, labeler_id: str, *, freeze_marker: Path = FREEZE_MARKER
) -> str | None:
    """Delete this labeller's most recent `gold_offline` row — their own only —
    and record it as `label.created` with `"undo": true` (the event CHECK set has
    no `label.deleted`; the payload says what happened). `None` when there is
    nothing to undo; `Frozen` once the gold set is frozen."""
    if freeze_marker.exists():
        raise Frozen(str(freeze_marker))
    row = conn.execute(
        "DELETE FROM triage_labels WHERE (alert_id, labeler_id, source) = ("
        "  SELECT alert_id, labeler_id, source FROM triage_labels"
        "  WHERE labeler_id = %s AND source = 'gold_offline'"
        "  ORDER BY created_at DESC LIMIT 1"
        ") RETURNING alert_id",
        (labeler_id,),
    ).fetchone()
    if row is None:
        return None
    alert_id = row[0]
    write_event(
        conn,
        "label.created",
        alert_id,
        "admin",
        actor_id=labeler_id,
        payload={"undo": True, "alert_id": alert_id, "labeler_id": labeler_id},
    )
    return alert_id
