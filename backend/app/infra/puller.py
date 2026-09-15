"""Poll the indexer every 60 s with search_after, a persistent cursor, and 60 s overlap.

Flow (context pack §5): indexer `wazuh-alerts-*` -> `pull_once` -> `intake` rows
(UNIQUE `manager_id, source_alert_id`, the overlap's dedup) plus a `pipeline`
job per new alert; heartbeats are recorded but never turned into alerts or jobs.

The cursor and heartbeat rows are keyed by the literal `'indexer'`
(`source_cursor.manager_id = source_heartbeat.manager_id = 'indexer'`), not by
the alert's own `manager.name` — the query this module runs is per index
pattern, not per manager, and one indexer serves one manager on this host
(design note 4). If a second manager ever ships alerts into the same index,
this cursor still resumes correctly for the pattern as a whole; the `intake`
rows still disambiguate managers through their own `manager_id` column and the
`UNIQUE(manager_id, source_alert_id)` constraint.

G9 (re-worded by DEC-023): `raw_text` is the hit object's exact text, sliced by
byte position out of the response body — never `json.dumps` of the parsed
object, which reorders nothing in this Python version but still normalises
whitespace and escapes and is therefore not the received document.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx
import psycopg
import yaml
from psycopg.types.json import Json

from app.infra import config
from app.infra.config import Config
from app.infra.errors import ConfigError, PermanentError, TransientError
from app.infra.jobs import Job, Reschedule, enqueue

# The pull loop's own key (design note 4) — distinct from any alert's
# `manager.name`, which is recorded per `intake` row instead.
_CURSOR_KEY = "indexer"

_SEARCH_TIMEOUT_S = 30.0


@dataclasses.dataclass(frozen=True)
class PullResult:
    """One `pull_once` call's outcome — logged as one line, never a hit's bytes."""

    hits: int
    new: int
    duplicates: int
    heartbeats: int
    last_sort: int | None


def is_heartbeat(doc: dict) -> bool:
    """Design note 5 — a string compare against the frozen `rule.id`; `rule.id`
    is always text in a Wazuh document."""
    rule = (doc.get("_source") or {}).get("rule") or {}
    return str(rule.get("id")) == Config.HEARTBEAT_RULE_ID


def build_client(cfg: Config, *, timeout: float = _SEARCH_TIMEOUT_S) -> httpx.Client:
    """The TLS client — verified against `INDEXER_CA` always; there is no
    insecure mode (§6.3). `INDEXER_CA` is checked before the credentials so
    that a run missing both still names the certificate problem, which is the
    one this module can do nothing about at the call site."""
    if not cfg.INDEXER_CA:
        raise ConfigError("INDEXER_CA: must be set to connect to the indexer (no insecure mode)")
    ca_path = Path(cfg.INDEXER_CA)
    if not (ca_path.is_file() and os.access(ca_path, os.R_OK)):
        raise ConfigError(
            f"INDEXER_CA={cfg.INDEXER_CA!r} does not point at a readable file "
            f"(resolved to {ca_path})"
        )
    if not cfg.INDEXER_USER or not cfg.INDEXER_PASSWORD:
        raise ConfigError("INDEXER_USER/INDEXER_PASSWORD: both must be set to connect")
    return httpx.Client(
        verify=str(ca_path),
        auth=httpx.BasicAuth(cfg.INDEXER_USER, cfg.INDEXER_PASSWORD),
        timeout=timeout,
    )


def _pull_start_ms(pull_start: str) -> int:
    dt = datetime.strptime(pull_start, "%Y-%m-%d").replace(tzinfo=UTC)
    return int(dt.timestamp() * 1000)


def _post_search(
    client: httpx.Client,
    cfg: Config,
    gte_ms: int,
    after: list | None,
    *,
    lt_ms: int | None = None,
) -> httpx.Response:
    """Design note 1's exact shape — `fields: ["timestamp"]` so the indexer adds
    `fields.timestamp[0]` and the parser's primary path applies to live pulls.

    `lt_ms` is exposed for `backfill --until` (P2-T13); `pull_once` never passes
    it, so the live pull's request body is byte-for-byte unchanged."""
    range_filter: dict = {"gte": gte_ms}
    if lt_ms is not None:
        range_filter["lt"] = lt_ms
    body: dict = {
        "size": cfg.PULL_PAGE,
        "sort": [{"timestamp": "asc"}],
        "fields": ["timestamp"],
        "query": {"range": {"timestamp": range_filter}},
    }
    if after:
        body["search_after"] = list(after)
    response = client.post(f"{cfg.INDEXER_URL}/{cfg.INDEXER_INDEX}/_search", json=body)
    response.raise_for_status()
    return response


def _slice_hits(body: str) -> list[tuple[dict, str]]:
    """G9 — position-tracking decode instead of `response.json()`: locate the
    `"hits": {"hits": [` array, then `json.JSONDecoder().raw_decode` each
    element in turn so `body[start:end]` is that hit's exact received text.

    The response envelope always orders `hits.total`, `hits.max_score` before
    `hits.hits` (the indexer's own serialisation, matched by every fixture
    here), so the second `"hits"` occurrence in the body is always the array
    key, never a coincidental match inside a hit's own content.
    """
    outer = body.find('"hits"')
    inner = body.find('"hits"', outer + 1) if outer != -1 else -1
    bracket = body.find("[", inner) if inner != -1 else -1
    if outer == -1 or inner == -1 or bracket == -1:
        raise PermanentError("puller: response body has no hits.hits array")

    decoder = json.JSONDecoder()
    idx = bracket + 1
    pairs: list[tuple[dict, str]] = []
    while True:
        while idx < len(body) and body[idx] in " \t\r\n,":
            idx += 1
        if idx >= len(body) or body[idx] == "]":
            break
        obj, end = decoder.raw_decode(body, idx)
        pairs.append((obj, body[idx:end]))
        idx = end
    return pairs


def fetch_page(
    client: httpx.Client, cfg: Config, gte_ms: int, after: list | None = None
) -> tuple[list[dict], str]:
    """One `search_after` page: the parsed hits, and the raw response body they
    came from (`pull_once` re-slices the body itself for G9's byte-exact
    `raw_text`, rather than trusting these already-parsed dicts)."""
    response = _post_search(client, cfg, gte_ms, after)
    body = response.text
    hits = [obj for obj, _raw in _slice_hits(body)]
    return hits, body


def _fetch_page_with_raw(
    client: httpx.Client,
    cfg: Config,
    gte_ms: int,
    after: list | None,
    *,
    lt_ms: int | None = None,
) -> list[tuple[dict, str]]:
    response = _post_search(client, cfg, gte_ms, after, lt_ms=lt_ms)
    return _slice_hits(response.text)


def _manager_id(source: dict) -> str:
    return (source.get("manager") or {}).get("name") or "default"


def _insert_alert(
    conn: psycopg.Connection, source: dict, raw_text: str, sort_value: int
) -> int | None:
    row = conn.execute(
        """
        INSERT INTO intake (manager_id, source_alert_id, raw_text, sort_key, via)
        VALUES (%s, %s, %s, %s, 'pull')
        ON CONFLICT (manager_id, source_alert_id) DO NOTHING
        RETURNING intake_id
        """,
        (_manager_id(source), source["id"], raw_text, sort_value),
    ).fetchone()
    return row[0] if row else None


def _insert_heartbeat(
    conn: psycopg.Connection, source: dict, raw_text: str, sort_value: int
) -> None:
    """§3.1: "không tạo alert, không xếp job" — complete on arrival (G12), no job."""
    conn.execute(
        """
        INSERT INTO intake (manager_id, source_alert_id, raw_text, sort_key, via, outcome, processed_at)
        VALUES (%s, %s, %s, %s, 'pull', 'heartbeat', now())
        ON CONFLICT (manager_id, source_alert_id) DO NOTHING
        """,
        (_manager_id(source), source["id"], raw_text, sort_value),
    )


def _record_pull_error(conn: psycopg.Connection, message: str) -> None:
    """A short transaction of its own — the caller's has already rolled back
    (design note 2)."""
    conn.execute(
        """
        INSERT INTO source_cursor (manager_id, last_error)
        VALUES (%s, %s)
        ON CONFLICT (manager_id) DO UPDATE SET last_error = EXCLUDED.last_error
        """,
        (_CURSOR_KEY, message),
    )
    conn.commit()


def _update_heartbeat(conn: psycopg.Connection, saw_alert: bool) -> None:
    conn.execute(
        """
        INSERT INTO source_heartbeat (manager_id, last_seen_at, last_alert_at)
        VALUES (%s, now(), CASE WHEN %s THEN now() ELSE NULL END)
        ON CONFLICT (manager_id) DO UPDATE SET
            last_seen_at = EXCLUDED.last_seen_at,
            last_alert_at = CASE WHEN %s THEN now() ELSE source_heartbeat.last_alert_at END
        """,
        (_CURSOR_KEY, saw_alert, saw_alert),
    )


def _update_cursor(conn: psycopg.Connection, last_sort: int | None) -> None:
    """No hits this call -> `last_sort` here is unchanged from what was read at
    the top of `pull_once`, so this never moves the cursor back."""
    conn.execute(
        """
        INSERT INTO source_cursor (manager_id, last_sort, last_pull_at, last_error)
        VALUES (%s, %s, now(), NULL)
        ON CONFLICT (manager_id) DO UPDATE SET
            last_sort = EXCLUDED.last_sort,
            last_pull_at = EXCLUDED.last_pull_at,
            last_error = NULL
        """,
        (_CURSOR_KEY, last_sort),
    )


def pull_once(conn: psycopg.Connection, client: httpx.Client, cfg: Config) -> PullResult:
    """One transaction the caller owns (design note 2). Pages through `_search`
    with `search_after` until a page returns fewer than `cfg.PULL_PAGE` hits."""
    cursor_row = conn.execute(
        "SELECT last_sort FROM source_cursor WHERE manager_id = %s", (_CURSOR_KEY,)
    ).fetchone()
    last_sort: int | None = cursor_row[0] if cursor_row else None
    gte_ms = (
        last_sort - cfg.PULL_OVERLAP_S * 1000
        if last_sort is not None
        else _pull_start_ms(cfg.PULL_START)
    )

    hits_total = new_count = dup_count = heartbeat_count = 0
    final_sort = last_sort
    saw_alert = False
    after: list | None = None

    try:
        while True:
            pairs = _fetch_page_with_raw(client, cfg, gte_ms, after)
            if not pairs:
                break
            for hit, raw_text in pairs:
                hits_total += 1
                sort_value = hit["sort"][0]
                final_sort = sort_value
                source = hit["_source"]
                if is_heartbeat(hit):
                    heartbeat_count += 1
                    _insert_heartbeat(conn, source, raw_text, sort_value)
                else:
                    saw_alert = True
                    intake_id = _insert_alert(conn, source, raw_text, sort_value)
                    if intake_id is not None:
                        new_count += 1
                        enqueue(conn, "pipeline", str(intake_id))
                    else:
                        dup_count += 1
            if len(pairs) < cfg.PULL_PAGE:
                break
            after = pairs[-1][0]["sort"]
    except (httpx.TransportError, httpx.HTTPStatusError) as exc:
        if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code < 500:
            raise
        conn.rollback()
        _record_pull_error(conn, str(exc)[:1000])
        raise TransientError(f"pull_once: indexer request failed: {exc}") from exc

    _update_heartbeat(conn, saw_alert)
    _update_cursor(conn, final_sort)

    return PullResult(
        hits=hits_total,
        new=new_count,
        duplicates=dup_count,
        heartbeats=heartbeat_count,
        last_sort=final_sort,
    )


def pull_job(
    conn: psycopg.Connection,
    job: Job,
    *,
    cfg: Config | None = None,
    client_factory: Callable[[Config], httpx.Client] | None = None,
) -> Reschedule:
    """§6.5's `pull` handler: build the client from `Config` (or an injected
    `client_factory` — tests inject `httpx.MockTransport`), run one pull, log
    the result as one line, and re-arm for `PULL_INTERVAL_S` seconds. P2-T02's
    worker loop re-enqueues it only after this run is marked `succeeded`."""
    del job  # the pull loop is single-flight by job_type/subject_id already
    cfg = cfg or config.load()
    factory = client_factory or build_client
    with factory(cfg) as client:
        result = pull_once(conn, client, cfg)
    # Not `json.dumps` (acceptance 10 forbids the name outright in this file):
    # a `PullResult` is five ints, never a hit's bytes, so there is nothing
    # here for that guard to actually be protecting.
    print(json.JSONEncoder().encode(dataclasses.asdict(result)))
    return Reschedule(cfg.PULL_INTERVAL_S)


# =============================================================================
# P2-T13 — the backfill CLI: `backfill --since` (indexer, live source) and
# `replay --archive-file` (manager archive, history source). DEC-019: "both".
# =============================================================================

# Design note 3, verbatim — printed by `--help` and by the refusal below.
OWNER_PROCEDURE = r"""# RUN AS user1. Only the read of the manager's dailies needs root (14/09: the directory is
# gid 999 and no `wazuh` group exists any more, so the 07/09 `sg wazuh` form cannot work).
# The globs are expanded by root inside `sh -c`; the redirect stays OUTSIDE the quotes so the
# output file is created by user1's shell and belongs to user1 — no chown, no chmod.
mkdir -p /home/user1/archive
sudo sh -c 'zcat -f /data/wazuh/logs/alerts/2026/*/ossec-alerts-*.json.gz \
                    /data/wazuh/logs/alerts/2026/*/ossec-alerts-*.json' \
    > /home/user1/archive/alerts-<first-day>_<last-day>.jsonl
wc -l /home/user1/archive/alerts-<first-day>_<last-day>.jsonl
# What `2026/` holds on the new manager is NOT visible from user1 (measured 14/09) — the Owner
# sees it with `sudo ls /data/wazuh/logs/alerts/2026/`. The 08/08–07/09 export already exists:
# /home/user1/archive/alerts-2026-08-08_09-07.jsonl, 92,030 lines, 113,379,904 bytes, intact on
# 14/09 — that file IS the G1 corpus (DEC-053, 3,070 clusters). A second export is only for
# days after 07/09 the Owner decides to add to G1; it is a decision, not a default.
# Why `zcat -f` and two explicit globs — three failures the first attempt actually hit:
#  * `zcat -f` reads BOTH shapes; a bare `cat` of `Sep/ossec-alerts-0[1-6].json` matched
#    nothing, because September's dailies are `.gz`. It silently lost the whole month.
#  * that non-zero `cat` broke the `&&` chain, so `chown` and `chmod` never ran — one bug,
#    two symptoms. The second accidentally saved the first: `chmod 600` on a root-owned
#    file would have locked user1 out of the export entirely.
#  * the two explicit globs exclude the `.sum` checksum files that a `*` would sweep in.
# `sudo mkdir` would leave /home/user1/archive root-owned inside user1's own home; `mkdir`
# runs as user1 here. Expect one gap in the old export: 2026-09-02's source file is 0 bytes.
# Then, as user1, from the repository root with .env present:
PYTHONPATH=backend python3 -m app.infra.puller replay --archive-file /home/user1/archive/alerts-2026-08-08_09-07.jsonl
make run-worker                                                 # processes the pipeline jobs; stop it when `select count(*) from intake where processed_at is null` reaches 0
"""

_FORBIDDEN_ARCHIVE_PREFIXES: tuple[str, ...] = ("/var/ossec", "/data/wazuh")


def _is_forbidden_archive_path(path: str) -> bool:
    """Design note 3 — a pure string check against the manager's live tree, run
    before any `stat`/`open` so a path that happens to be readable (14/09:
    `/data/wazuh/logs/alerts/alerts.json` is mode 777) is refused all the same.
    D3 stays cut as an application path *by choice* (G9/G12), not by constraint."""
    normalized = os.path.normpath(os.path.abspath(path))
    return any(
        normalized == prefix or normalized.startswith(prefix + os.sep)
        for prefix in _FORBIDDEN_ARCHIVE_PREFIXES
    )


def _print_refusal(path: str, reason: str) -> None:
    print(f"puller: refusing --archive-file {path!r}: {reason}", file=sys.stderr)
    print(OWNER_PROCEDURE, file=sys.stderr)


# ---------------------------------------------------------------------------
# backfill — the P2-T11 page loop from `--since`, without the cursor
# ---------------------------------------------------------------------------


def _backfill_loop(
    conn: psycopg.Connection,
    client: httpx.Client,
    cfg: Config,
    gte_ms: int,
    until_ms: int | None = None,
    *,
    on_page: Callable[[PullResult], None] | None = None,
) -> PullResult:
    """Design note 1's `backfill` — the same page-walk `pull_once` runs, but it
    neither reads nor writes `source_cursor` (the live cursor is untouched) and
    reports per page through `on_page` instead of a `source_heartbeat` row."""
    hits_total = new_count = dup_count = heartbeat_count = 0
    final_sort: int | None = None
    after: list | None = None

    while True:
        pairs = _fetch_page_with_raw(client, cfg, gte_ms, after, lt_ms=until_ms)
        if not pairs:
            break
        page_hits = page_new = page_dup = page_heartbeats = 0
        for hit, raw_text in pairs:
            page_hits += 1
            sort_value = hit["sort"][0]
            final_sort = sort_value
            source = hit["_source"]
            if is_heartbeat(hit):
                page_heartbeats += 1
                _insert_heartbeat(conn, source, raw_text, sort_value)
            else:
                intake_id = _insert_alert(conn, source, raw_text, sort_value)
                if intake_id is not None:
                    page_new += 1
                    enqueue(conn, "pipeline", str(intake_id))
                else:
                    page_dup += 1
        hits_total += page_hits
        new_count += page_new
        dup_count += page_dup
        heartbeat_count += page_heartbeats
        if on_page is not None:
            on_page(PullResult(page_hits, page_new, page_dup, page_heartbeats, final_sort))
        if len(pairs) < cfg.PULL_PAGE:
            break
        after = pairs[-1][0]["sort"]

    return PullResult(
        hits=hits_total,
        new=new_count,
        duplicates=dup_count,
        heartbeats=heartbeat_count,
        last_sort=final_sort,
    )


def _cmd_backfill(args: argparse.Namespace) -> int:
    cfg = config.load(env_file=args.env_file)
    gte_ms = _pull_start_ms(args.since)
    until_ms = _pull_start_ms(args.until) if args.until else None
    dsn = cfg.DATABASE_URL_OWNER or cfg.DATABASE_URL

    page_no = 0

    def on_page(page: PullResult) -> None:
        nonlocal page_no
        page_no += 1
        print(
            f"backfill: page {page_no} hits={page.hits} new={page.new} "
            f"duplicates={page.duplicates} heartbeats={page.heartbeats}"
        )

    conn = psycopg.connect(dsn)
    try:
        with build_client(cfg) as client:
            result = _backfill_loop(conn, client, cfg, gte_ms, until_ms, on_page=on_page)
        conn.commit()
    finally:
        conn.close()

    print(
        f"backfill: total hits={result.hits} new={result.new} "
        f"duplicates={result.duplicates} heartbeats={result.heartbeats}"
    )
    if result.new == 0:
        print(
            "backfill: new=0 is expected, not a failure, for a --since before "
            "2026-09-02 — the indexer holds no history earlier than that (DEC-017)"
        )
    return 0


# ---------------------------------------------------------------------------
# replay — the manager archive, ingested byte-identical as `via='pull'` rows
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ReplayResult:
    """One `replay_lines` call's outcome — design note 1's summary line."""

    lines: int
    new: int
    duplicates: int
    heartbeats: int
    bad: int


_REJECT_BAD_JSON = "not valid json"
_REJECT_MISSING_ID = "missing id"
_REJECT_BAD_TIMESTAMP = "bad timestamp"

_TZ_NO_COLON_RE = re.compile(r"([+-]\d{2})(\d{2})$")


def _parse_replay_line(raw_text: str) -> tuple[dict | None, str | None]:
    """`(doc, None)` for a usable line, `(None, reason)` for a `bad` one —
    never raises, so the caller never has to guess what to catch."""
    try:
        doc = json.loads(raw_text)
    except json.JSONDecodeError:
        return None, _REJECT_BAD_JSON
    if not isinstance(doc, dict) or not doc.get("id"):
        return None, _REJECT_MISSING_ID
    return doc, None


def _replay_sort_key(timestamp: str) -> int:
    """DEC-019's one new derivation — epoch-millis of the line's own timestamp.
    `+0700 -> +07:00`, then `fromisoformat` (design note 1)."""
    normalized = _TZ_NO_COLON_RE.sub(r"\1:\2", timestamp)
    return int(datetime.fromisoformat(normalized).timestamp() * 1000)


def _insert_rejected(conn: psycopg.Connection, raw_text: str, reason: str) -> None:
    """Phase-1:459's `rejected_alerts` row — never a silent drop. Not
    `json.dumps` (acceptance 7 forbids the name outright in this file): `Json`
    is psycopg's own adapter, so the literal name never appears here either."""
    conn.execute(
        "INSERT INTO rejected_alerts (raw_payload, reason) VALUES (%s, %s)",
        (Json({"line": raw_text}), reason),
    )


def replay_lines(conn: psycopg.Connection, data: bytes, *, batch: int = 500) -> ReplayResult:
    """Design note 1's `replay` core: `data` split on `\n`, blank lines
    skipped, one `intake`/`rejected_alerts` row per line, committed every
    `batch` lines so a crash loses at most one batch and a re-run (the UNIQUE)
    skips what is already there."""
    lines = new_count = dup_count = heartbeat_count = bad_count = 0
    since_commit = 0

    for raw_bytes in data.split(b"\n"):
        if not raw_bytes:
            continue
        lines += 1
        try:
            raw_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            bad_count += 1
            _insert_rejected(conn, raw_bytes.decode("utf-8", errors="replace"), "not valid utf-8")
        else:
            doc, reason = _parse_replay_line(raw_text)
            if doc is None:
                bad_count += 1
                _insert_rejected(conn, raw_text, reason)
            else:
                try:
                    sort_value = _replay_sort_key(doc["timestamp"])
                except (KeyError, TypeError, ValueError):
                    bad_count += 1
                    _insert_rejected(conn, raw_text, _REJECT_BAD_TIMESTAMP)
                else:
                    if is_heartbeat({"_source": doc}):
                        heartbeat_count += 1
                        _insert_heartbeat(conn, doc, raw_text, sort_value)
                    else:
                        intake_id = _insert_alert(conn, doc, raw_text, sort_value)
                        if intake_id is not None:
                            new_count += 1
                            enqueue(conn, "pipeline", str(intake_id))
                        else:
                            dup_count += 1
        since_commit += 1
        if since_commit >= batch:
            conn.commit()
            since_commit = 0

    conn.commit()
    return ReplayResult(
        lines=lines, new=new_count, duplicates=dup_count, heartbeats=heartbeat_count, bad=bad_count
    )


@dataclasses.dataclass
class _AgentStats:
    count: int = 0
    first_date: str = ""
    last_date: str = ""


def _known_hostnames(cfg: Config) -> set[str]:
    """Design note 3b — read straight from `conf/inventory.yaml` (via
    `cfg.INVENTORY_PATHS`, matched by content per `docs/inventory-format.md`,
    not position). Not `app.enrichment.inventory`: G1 gives `infra` nothing to
    import (acceptance 8), and `validate()` would answer the wrong question —
    it checks the file's own consistency, not the estate."""
    names: set[str] = set()
    for raw_path in cfg.INVENTORY_PATHS:
        path = Path(raw_path)
        if not path.is_file():
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict) and isinstance(doc.get("assets"), list):
            for item in doc["assets"]:
                if isinstance(item, dict) and item.get("hostname"):
                    names.add(str(item["hostname"]))
    return names


def _unknown_agents(data: bytes, cfg: Config) -> dict[str, _AgentStats]:
    """Design note 3b — every `agent.name` the archive contains that the
    inventory does not, with its count and date span. A report, not a filter:
    the caller still ingests these rows (G8′ pins them to `needs_review`)."""
    known = _known_hostnames(cfg)
    stats: dict[str, _AgentStats] = {}
    for raw_bytes in data.split(b"\n"):
        if not raw_bytes:
            continue
        try:
            doc = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if not isinstance(doc, dict):
            continue
        name = (doc.get("agent") or {}).get("name")
        timestamp = doc.get("timestamp")
        if not name or not isinstance(timestamp, str) or len(timestamp) < 10:
            continue
        date = timestamp[:10]
        entry = stats.setdefault(name, _AgentStats())
        entry.count += 1
        if not entry.first_date or date < entry.first_date:
            entry.first_date = date
        if not entry.last_date or date > entry.last_date:
            entry.last_date = date
    return {name: s for name, s in stats.items() if name not in known}


def _cmd_replay(args: argparse.Namespace) -> int:
    if _is_forbidden_archive_path(args.archive_file):
        _print_refusal(
            args.archive_file,
            "resolves under /var/ossec/ or /data/wazuh/ — D3 stays cut (DEC-060); the "
            "puller is the only live path by choice (G9/G12), not because this file "
            "cannot be opened",
        )
        return 2
    try:
        data = Path(args.archive_file).read_bytes()
    except OSError:
        _print_refusal(args.archive_file, "unreadable")
        return 2

    cfg = config.load(env_file=args.env_file)

    for name, agent_stats in sorted(_unknown_agents(data, cfg).items()):
        print(
            f"replay: agent {name!r} not in inventory — {agent_stats.count} alerts, "
            f"{agent_stats.first_date}..{agent_stats.last_date} (ingested anyway; pins "
            "to needs_review under G8′)"
        )

    dsn = cfg.DATABASE_URL_OWNER or cfg.DATABASE_URL
    conn = psycopg.connect(dsn)
    try:
        result = replay_lines(conn, data, batch=args.batch)
    finally:
        conn.close()

    print(
        f"replay: lines={result.lines} new={result.new} duplicates={result.duplicates} "
        f"heartbeats={result.heartbeats} bad={result.bad}"
    )
    return 0


# ---------------------------------------------------------------------------
# entry point (design note 1)
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m app.infra.puller",
        description=(
            "backfill --since YYYY-MM-DD [--until YYYY-MM-DD] re-pulls the indexer "
            "from a date without moving the live source_cursor (the live-source half "
            "of the P2 gate item, DEC-019). replay --archive-file PATH [--batch 500] "
            "stores a manager archive export's lines byte-identical as via='pull' "
            "intake rows with sort_key = epoch-millis of each line's own timestamp "
            "(the history half). Both connect using DATABASE_URL_OWNER, falling back "
            "to DATABASE_URL, exactly as scripts/migrate.sh does; both take an "
            "optional --env-file (default .env)."
        ),
        epilog=OWNER_PROCEDURE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    backfill = subparsers.add_parser(
        "backfill", help="re-pull the indexer from --since without moving source_cursor"
    )
    backfill.add_argument("--since", required=True, help="YYYY-MM-DD, UTC 00:00:00")
    backfill.add_argument("--until", help="YYYY-MM-DD, exclusive upper bound, UTC 00:00:00")
    backfill.add_argument("--env-file", default=".env")

    replay = subparsers.add_parser(
        "replay",
        help="ingest a manager archive export as via='pull' intake rows (source='replay')",
        epilog=OWNER_PROCEDURE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    replay.add_argument("--archive-file", required=True)
    replay.add_argument("--batch", type=int, default=500)
    replay.add_argument("--env-file", default=".env")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "backfill":
        return _cmd_backfill(args)
    return _cmd_replay(args)


if __name__ == "__main__":
    raise SystemExit(main())
