#!/usr/bin/env python3
"""Probe the Wazuh alert indexer: documents per index day, the earliest index
day, and one ``search_after`` page.

The three sections it prints answer three open questions at once: how much
history the index still holds (which sizes the G1 gold set), how the documents
are spread over the days since ``PULL_START``, and whether the paging strategy
P2's puller will use actually returns documents.

TLS is always verified against ``INDEXER_CA`` (context pack §6.3: the key is
required and there is no unverified mode). This file offers no switch to turn
verification off, and ``backend/tests/test_indexer_probe.py`` asserts that no
such switch is ever added.

The credential is read from ``INDEXER_USER`` / ``INDEXER_PASSWORD`` and sent as
HTTP Basic auth. ``INDEXER_PASSWORD`` is never printed, logged or written into
a saved sample.

Run it from the repository root::

    python3 eval/indexer_probe.py
    python3 eval/indexer_probe.py --json
    python3 eval/indexer_probe.py --save-samples 5

Exit codes: 0 ok · 2 configuration problem · 3 transport or TLS failure ·
4 the indexer answered with a non-2xx status.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_FILE = REPO_ROOT / ".env"
DEFAULT_SAMPLES_DIR = REPO_ROOT / "backend" / "tests" / "fixtures"
DEFAULT_PAGE = 500
TIMEOUT_S = 30.0
BODY_EXCERPT_CHARS = 300

# The field the puller pages on. The canonical document (context pack §8) has
# sort value 1786903016130, the epoch-millis of fields.timestamp[0], and
# source_cursor.last_sort is a bigint, so the assumption fits — but it can only
# be confirmed against the live index, which is why it is printed in the header.
SORT_FIELD = "timestamp"

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_TRANSPORT = 3
EXIT_HTTP = 4

REQUIRED_KEYS = (
    "INDEXER_URL",
    "INDEXER_USER",
    "INDEXER_PASSWORD",
    "INDEXER_CA",
    "INDEXER_INDEX",
    "PULL_START",
)

# wazuh-alerts-4.x-YYYY.MM.dd — a name without that suffix is not a day index.
INDEX_DATE_RE = re.compile(r"(?P<y>\d{4})\.(?P<m>\d{2})\.(?P<d>\d{2})$")
ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

CREDENTIAL_HINT = (
    "INDEXER_USER / INDEXER_PASSWORD are empty because the read-only indexer "
    "user soc_ro does not exist yet — see docs/plan/INBOX.md "
    "(2026-09-05 · P0 / P2 · BLOCKER). This is an Owner action; the probe "
    "cannot be run for real until it is cleared."
)


@dataclass(frozen=True, repr=False)
class Config:
    """Everything the probe needs, already validated."""

    url: str
    user: str
    password: str
    ca: str
    index: str
    since: str
    page: int

    def __repr__(self) -> str:
        # Never let a traceback or a debug print leak the credential.
        return (
            f"Config(url={self.url!r}, user={self.user!r}, password='<redacted>', "
            f"ca={self.ca!r}, index={self.index!r}, since={self.since!r}, page={self.page})"
        )


class IndexerHTTPError(Exception):
    """The indexer answered, but not with a 2xx."""

    def __init__(self, response: httpx.Response) -> None:
        self.status_code = response.status_code
        self.url = safe_url(response.request.url)
        self.excerpt = response.text[:BODY_EXCERPT_CHARS]
        super().__init__(f"HTTP {self.status_code} from {self.url}")


def safe_url(url: httpx.URL | str) -> str:
    """The URL without userinfo, so a credential pasted into INDEXER_URL by
    mistake is still never printed."""
    return str(httpx.URL(url).copy_with(userinfo=b""))


# --- configuration ---------------------------------------------------------


def read_env_file(path: Path) -> dict[str, str]:
    """A ten-line stdlib .env reader — no python-dotenv (it is not a pinned
    dependency and this file needs six keys, not a parser)."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip().strip("\"'")
    return values


def resolve_ca_path(value: str) -> Path:
    """`.env` ships `INDEXER_CA=conf/root-ca.pem`, a repository-relative path,
    so a relative value is resolved against the repository root rather than the
    current directory."""
    path = Path(value).expanduser()
    return path if path.is_absolute() else REPO_ROOT / path


def load_config(
    env_file: Path, since: str | None = None, page: int | None = None
) -> tuple[Config | None, list[str]]:
    """Return the config, or ``None`` plus every configuration problem found.

    All problems are collected into one list instead of stopping at the first,
    and the readability of ``INDEXER_CA`` is checked last so that its message
    is never hidden behind an earlier empty key.
    """
    from_file = read_env_file(env_file)

    def lookup(key: str) -> str:
        # A real environment variable wins over the file, even when it is empty.
        return os.environ[key] if key in os.environ else from_file.get(key, "")

    values = {key: lookup(key) for key in REQUIRED_KEYS}
    if since:
        values["PULL_START"] = since

    problems = [
        f"{key} is empty or missing (looked in the environment, then {env_file})"
        for key in REQUIRED_KEYS
        if not values[key].strip()
    ]
    if not values["INDEXER_USER"].strip() or not values["INDEXER_PASSWORD"].strip():
        problems.append(CREDENTIAL_HINT)

    start = values["PULL_START"].strip()
    if start and not ISO_DATE_RE.match(start):
        source = "--since" if since else "PULL_START"
        problems.append(f"{source}={start!r} is not a YYYY-MM-DD date")

    # Last, so acceptance 4 sees INDEXER_CA named even when other keys are set.
    ca_path = resolve_ca_path(values["INDEXER_CA"]) if values["INDEXER_CA"].strip() else None
    if ca_path is not None and not (ca_path.is_file() and os.access(ca_path, os.R_OK)):
        problems.append(
            f"INDEXER_CA={values['INDEXER_CA']} does not point at a readable file "
            f"(resolved to {ca_path}). It is required: TLS is always verified "
            f"against it and there is no unverified mode."
        )

    if problems:
        return None, problems

    assert ca_path is not None
    return (
        Config(
            url=values["INDEXER_URL"].strip().rstrip("/"),
            user=values["INDEXER_USER"],
            password=values["INDEXER_PASSWORD"],
            ca=str(ca_path),
            index=values["INDEXER_INDEX"].strip(),
            since=start,
            page=resolve_page(page, lookup("PULL_PAGE")),
        ),
        [],
    )


def resolve_page(flag: int | None, configured: str) -> int:
    """``--page`` wins over ``PULL_PAGE`` wins over the default. Optional by
    contract, so a bad value warns and falls back — it is never exit 2."""
    if flag is not None:
        if flag > 0:
            return flag
        print(
            f"indexer_probe: --page {flag} is not a positive integer — ignored",
            file=sys.stderr,
        )
    if configured.strip():
        try:
            value = int(configured.strip().replace("_", ""))
        except ValueError:
            value = 0
        if value > 0:
            return value
        print(
            f"indexer_probe: PULL_PAGE={configured!r} is not a positive integer — "
            f"using {DEFAULT_PAGE}",
            file=sys.stderr,
        )
    return DEFAULT_PAGE


# --- the two requests ------------------------------------------------------


def build_client(cfg: Config) -> httpx.Client:
    return httpx.Client(
        verify=cfg.ca,
        timeout=TIMEOUT_S,
        auth=httpx.BasicAuth(cfg.user, cfg.password),
    )


def _checked(response: httpx.Response) -> httpx.Response:
    if not response.is_success:
        raise IndexerHTTPError(response)
    return response


def fetch_index_table(client: httpx.Client, base: str, index: str) -> list[dict[str, Any]]:
    """`_cat/indices` for the index pattern, one row per concrete index."""
    response = client.get(
        f"{base.rstrip('/')}/_cat/indices/{index}",
        params={"format": "json", "h": "index,docs.count,store.size", "s": "index"},
    )
    return _checked(response).json()


def fetch_page(
    client: httpx.Client,
    base: str,
    index: str,
    since: str,
    page: int,
    after: Sequence[Any] | None = None,
) -> dict[str, Any]:
    """One ``search_after`` page — the exact query shape P2's puller will use.

    ``after`` is the ``sort`` array of the last hit of the previous page.
    """
    body: dict[str, Any] = {
        "size": page,
        "sort": [{SORT_FIELD: "asc"}],
        "query": {"range": {SORT_FIELD: {"gte": since}}},
    }
    if after:
        body["search_after"] = list(after)
    response = client.post(f"{base.rstrip('/')}/{index}/_search", json=body)
    return _checked(response).json()


# --- the report ------------------------------------------------------------


def summarize_days(rows: Iterable[dict[str, Any]], since: str) -> dict[str, Any]:
    """Per-day counts on or after ``since``, plus the earliest index date over
    the *unfiltered* set — that one is the retention answer and must not move
    when ``--since`` does."""
    days: list[dict[str, Any]] = []
    all_dates: list[str] = []
    for row in rows:
        name = str(row.get("index") or "").strip()
        match = INDEX_DATE_RE.search(name)
        if not match:
            continue  # not a day index (rollover, system index, …)
        date = f"{match['y']}-{match['m']}-{match['d']}"
        all_dates.append(date)
        if date < since:
            continue
        days.append(
            {
                "date": date,
                "index": name,
                "docs_count": int(str(row.get("docs.count") or "0").strip() or 0),
                "store_size": str(row.get("store.size") or "").strip(),
            }
        )
    days.sort(key=lambda day: day["date"])
    return {
        "days": days,
        "total_docs": sum(day["docs_count"] for day in days),
        "earliest_index_date": min(all_dates) if all_dates else None,
    }


def format_day_table(rows: Iterable[dict[str, Any]], since: str) -> str:
    """The per-day table as text, with the same field names the --json report
    uses."""
    summary = summarize_days(rows, since)
    lines = [f"{'date':<12}{'index':<36}{'docs_count':>11}  {'store_size':>11}"]
    for day in summary["days"]:
        lines.append(
            f"{day['date']:<12}{day['index']:<36}{day['docs_count']:>11}  {day['store_size']:>11}"
        )
    if not summary["days"]:
        lines.append(f"(no day index on or after {since})")
    lines.append(f"{'total_docs':<48}{summary['total_docs']:>11}")
    return "\n".join(lines)


def pick_samples(hits: Sequence[dict[str, Any]], n: int) -> list[dict[str, Any]]:
    """Up to ``n`` hits, at most one per distinct ``_source.rule.id``."""
    picked: list[dict[str, Any]] = []
    seen: set[str] = set()
    for hit in hits:
        if len(picked) >= n:
            break
        rule = (hit.get("_source") or {}).get("rule") or {}
        rule_id = str(rule.get("id") or "").strip()
        if not rule_id or rule_id in seen:
            continue
        seen.add(rule_id)
        picked.append(hit)
    return picked


def save_samples(hits: Sequence[dict[str, Any]], n: int, samples_dir: Path) -> list[Path]:
    """Write one document per distinct rule id. Values are re-serialised
    unchanged — only whitespace differs from what the indexer returned (G9)."""
    samples_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for hit in pick_samples(hits, n):
        rule_id = hit["_source"]["rule"]["id"]
        path = samples_dir / f"indexer_sample_rule{rule_id}.json"
        path.write_text(json.dumps(hit, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written.append(path)
    return written


# --- entry point -----------------------------------------------------------


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="indexer_probe.py",
        description=(
            "Report documents per index day since PULL_START, the earliest index "
            "date, and one search_after page from the Wazuh alert indexer."
        ),
        epilog=(
            "TLS is always verified against INDEXER_CA; verification cannot be "
            "turned off from the command line or the environment.\n"
            "Exit codes: 0 ok, 2 configuration problem, 3 transport or TLS "
            "failure, 4 non-2xx answer."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--env-file",
        metavar="PATH",
        default=str(DEFAULT_ENV_FILE),
        help="file to read INDEXER_*/PULL_* from (default: %(default)s); a real "
        "environment variable always wins over the file",
    )
    parser.add_argument(
        "--since",
        metavar="YYYY-MM-DD",
        help="override PULL_START for both the day filter and the search range",
    )
    parser.add_argument(
        "--page",
        metavar="N",
        type=int,
        help=f"page size for the search_after page (default: PULL_PAGE, else {DEFAULT_PAGE})",
    )
    parser.add_argument(
        "--save-samples",
        metavar="N",
        type=int,
        default=0,
        help="write up to N returned documents with distinct rule ids as "
        "indexer_sample_rule<id>.json",
    )
    parser.add_argument(
        "--samples-dir",
        metavar="DIR",
        default=str(DEFAULT_SAMPLES_DIR),
        help="where --save-samples writes (default: %(default)s)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the same three sections as one JSON object on stdout and nothing else",
    )
    return parser.parse_args(argv)


def main(
    argv: Sequence[str] | None = None,
    client_factory: Callable[[Config], httpx.Client] = build_client,
) -> int:
    args = parse_args(argv)
    cfg, problems = load_config(Path(args.env_file), since=args.since, page=args.page)
    if cfg is None:
        print("indexer_probe: configuration error", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        with client_factory(cfg) as client:
            rows = fetch_index_table(client, cfg.url, cfg.index)
            page = fetch_page(client, cfg.url, cfg.index, cfg.since, cfg.page)
    except httpx.TransportError as exc:
        print(
            f"indexer_probe: {type(exc).__name__} talking to {safe_url(cfg.url)} — "
            f"TLS is verified against {cfg.ca} and cannot be turned off",
            file=sys.stderr,
        )
        return EXIT_TRANSPORT
    except IndexerHTTPError as exc:
        print(f"indexer_probe: HTTP {exc.status_code} from {exc.url}", file=sys.stderr)
        print(f"  body[:{BODY_EXCERPT_CHARS}]: {exc.excerpt}", file=sys.stderr)
        return EXIT_HTTP

    summary = summarize_days(rows, cfg.since)
    hits = ((page.get("hits") or {}).get("hits")) or []
    page_report = {
        "requested": cfg.page,
        "hits": len(hits),
        "first_sort": hits[0].get("sort") if hits else None,
        "last_sort": hits[-1].get("sort") if hits else None,
        "first_index": hits[0].get("_index") if hits else None,
    }
    written = (
        save_samples(hits, args.save_samples, Path(args.samples_dir))
        if args.save_samples > 0
        else []
    )

    if args.json:
        print(
            json.dumps(
                {
                    "indexer_url": cfg.url,
                    "index_pattern": cfg.index,
                    "since": cfg.since,
                    "sort_field": SORT_FIELD,
                    "days": summary["days"],
                    "total_docs": summary["total_docs"],
                    "earliest_index_date": summary["earliest_index_date"],
                    "page": page_report,
                    "samples": [str(path) for path in written],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        return EXIT_OK

    print(
        f"indexer_probe · {cfg.url} · index {cfg.index} · since {cfg.since} "
        f"· page {cfg.page} · sort field: {SORT_FIELD}"
    )
    print()
    print(format_day_table(rows, cfg.since))
    print()
    print(
        f"earliest_index_date: {summary['earliest_index_date'] or '(none)'}"
        "   — oldest day still in the index; this is the retention answer that sizes G1"
    )
    print()
    print(
        f"search_after page · hits: {page_report['hits']}"
        f" · first_sort: {page_report['first_sort']}"
        f" · last_sort: {page_report['last_sort']}"
        f" · first_index: {page_report['first_index']}"
    )
    for path in written:
        print(f"wrote {path}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
