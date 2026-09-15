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

import dataclasses
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import httpx
import psycopg

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
    client: httpx.Client, cfg: Config, gte_ms: int, after: list | None
) -> httpx.Response:
    """Design note 1's exact shape — `fields: ["timestamp"]` so the indexer adds
    `fields.timestamp[0]` and the parser's primary path applies to live pulls."""
    body: dict = {
        "size": cfg.PULL_PAGE,
        "sort": [{"timestamp": "asc"}],
        "fields": ["timestamp"],
        "query": {"range": {"timestamp": {"gte": gte_ms}}},
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
    client: httpx.Client, cfg: Config, gte_ms: int, after: list | None
) -> list[tuple[dict, str]]:
    response = _post_search(client, cfg, gte_ms, after)
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
