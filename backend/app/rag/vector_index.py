"""Check and rebuild the vector index: `python -m app.rag.vector_index --check | --rebuild` (P14-T05, DEC-213,
spec §5.1 and §5.2). Run it in `rag-worker`, the one container that has `VECTOR_DATABASE_URL`:

    docker compose exec rag-worker python -m app.rag.vector_index --check

The vector database is a derived index (spec §5.1): the main database is the only source of an entry's
content, status and hash. The index needs no backup of its own; after `make db-restore`, or after losing
the `vectordata` volume, `--rebuild` makes it again. The comparison is five numbers:

    active   the entries whose status is `active` in the main database
    current  active, and the stored row has the entry's `content_sha256`, `RAG_EMBED_MODEL` and
             `RAG_EMBED_DIMS`
    missing  active, and no stored row
    stale    active, and a stored row that differs in hash, model or dims (an entry edited since, or a
             changed model or size)
    orphan   a stored row whose entry is not active: retired, or not in the main database at all

**--check** prints them as `name: n` lines and exits 0 only when `missing`, `stale` and `orphan` are all 0.
It writes nothing and asks Voyage nothing, so it works with no key. A vector database with no table yet is
all `missing`, and `--check` does not create one.

**--rebuild** makes the schema (`ensure_schema`), deletes the orphans, embeds every entry that is missing or
stale in batches of 32 as `document`s (their digests, `match.entry_digest`), upserts each batch as it
arrives, and prints `embedded`, `deleted` and `tokens`. An entry that is current is not sent again, so it can
be run again after a failure and only does the rest. It exits 0 when it is done, and 1 with the failure kind
on standard error when Voyage or the vector database failed (the counts so far are printed first).

Neither prints an address or the key, and a provider's words are never kept (`rag.failures`): the only text
about a failure is its kind. Exit 2 is a bad command line or a main database with no address.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx
import psycopg

from app.infra import config
from app.infra import db as infra_db
from app.infra.errors import ConfigError
from app.rag import match, vector_store, voyage
from app.rag.entries import SELECT_ENTRY, Entry
from app.rag.failures import RagUnavailable

#: Entries per Voyage request. A digest is a few hundred tokens, so a batch is far under the API's limits.
BATCH_SIZE = 32


@dataclass(frozen=True)
class Comparison:
    """The main database's active entries against what the index holds."""

    active: int
    current: list[str]
    missing: list[Entry]
    stale: list[Entry]
    orphan: list[str]

    @property
    def whole(self) -> bool:
        return not (self.missing or self.stale or self.orphan)


@dataclass
class Rebuilt:
    """What `rebuild` did, and the kind of failure that stopped it (None: it finished)."""

    embedded: int = 0
    deleted: int = 0
    tokens: int = 0
    failed: str | None = field(default=None)


def active_entries(conn: psycopg.Connection) -> list[Entry]:
    """Every active entry of the main database, ordered by id."""
    rows = conn.execute(SELECT_ENTRY + " WHERE status = 'active' ORDER BY entry_id").fetchall()
    return [Entry.from_row(row) for row in rows]


def compare(
    entries: Sequence[Entry], stored: dict[str, tuple[str, str, int]], cfg: config.Config
) -> Comparison:
    """Classify the entries and the stored rows (module doc)."""
    current: list[str] = []
    missing: list[Entry] = []
    stale: list[Entry] = []
    for entry in entries:
        have = stored.get(entry.entry_id)
        if have is None:
            missing.append(entry)
        elif have == (entry.content_sha256, cfg.RAG_EMBED_MODEL, cfg.RAG_EMBED_DIMS):
            current.append(entry.entry_id)
        else:
            stale.append(entry)
    live = {entry.entry_id for entry in entries}
    orphan = sorted(entry_id for entry_id in stored if entry_id not in live)
    return Comparison(len(entries), current, missing, stale, orphan)


def check(conn: psycopg.Connection, vconn: Any, cfg: config.Config) -> Comparison:
    """The comparison, reading only. A vector database with no table yet holds nothing."""
    try:
        stored = vector_store.stored(vconn)
    except psycopg.errors.UndefinedTable:
        stored = {}
    return compare(active_entries(conn), stored, cfg)


def rebuild(
    conn: psycopg.Connection,
    vconn: Any,
    cfg: config.Config,
    *,
    client: httpx.Client | None = None,
) -> Rebuilt:
    """Make the index what the main database says (module doc). A `RagUnavailable` stops it and is
    returned as `failed`; what was done before it stays done."""
    done = Rebuilt()
    try:
        vector_store.ensure_schema(vconn)
        found = compare(active_entries(conn), vector_store.stored(vconn), cfg)
        for entry_id in found.orphan:
            vector_store.delete(vconn, entry_id)
            done.deleted += 1
        todo = sorted([*found.missing, *found.stale], key=lambda entry: entry.entry_id)
        for start in range(0, len(todo), BATCH_SIZE):
            batch = todo[start : start + BATCH_SIZE]
            vectors, usage = voyage.embed(
                [match.entry_digest(entry) for entry in batch],
                input_type="document",
                cfg=cfg,
                client=client,
            )
            for entry, vector in zip(batch, vectors, strict=True):
                vector_store.upsert(
                    vconn,
                    entry_id=entry.entry_id,
                    content_sha256=entry.content_sha256,
                    model=cfg.RAG_EMBED_MODEL,
                    vector=vector,
                )
            done.embedded += len(batch)
            done.tokens += usage.total_tokens
    except RagUnavailable as exc:
        done.failed = exc.kind
    return done


def _fail(message: str) -> None:
    print(f"vector_index: {message}", file=sys.stderr)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.rag.vector_index",
        description="Check or rebuild the vector index of the approved knowledge entries.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check",
        action="store_true",
        help="print active/current/missing/stale/orphan; exit 0 only when the last three are 0",
    )
    mode.add_argument(
        "--rebuild",
        action="store_true",
        help="embed the entries that are missing or stale, delete the orphans, print the counts",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    conn: psycopg.Connection | None = None,
    vconn: Any | None = None,
    client: httpx.Client | None = None,
) -> int:
    """The command (module doc). `conn`, `vconn` and `client` default to a connection of the main database,
    one of the vector database and a Voyage client of their own; every test passes its own. What the
    command opens it closes."""
    args = _parser().parse_args(argv)
    opened: list[Any] = []
    try:
        cfg = config.load()
        if conn is None:
            try:
                conn = infra_db.connect()
            except psycopg.OperationalError:
                _fail("the main database cannot be reached")
                return 1
            opened.append(conn)
        if vconn is None:
            vconn = vector_store.connect(cfg)
            opened.append(vconn)

        if args.check:
            found = check(conn, vconn, cfg)
            print(f"active: {found.active}")
            print(f"current: {len(found.current)}")
            print(f"missing: {len(found.missing)}")
            print(f"stale: {len(found.stale)}")
            print(f"orphan: {len(found.orphan)}")
            return 0 if found.whole else 1

        done = rebuild(conn, vconn, cfg, client=client)
        print(f"embedded: {done.embedded}")
        print(f"deleted: {done.deleted}")
        print(f"tokens: {done.tokens}")
        if done.failed is not None:
            _fail(done.failed)
            return 1
        return 0
    except ConfigError as exc:
        _fail(str(exc))
        return 2
    except RagUnavailable as exc:
        _fail(exc.kind)
        return 1
    finally:
        for resource in opened:
            resource.close()


if __name__ == "__main__":
    sys.exit(main())
