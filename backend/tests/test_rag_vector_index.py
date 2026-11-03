"""P14-T05 / DEC-213, spec §5.1 and §5.2 — `python -m app.rag.vector_index --check | --rebuild`.

The vector database is a derived index (spec §5.1): the main database is the only source of an entry's
text, status and hash. This command compares the two and repairs the index.

    --check    prints `active`, `current`, `missing`, `stale` and `orphan`, one `name: n` line each, and
               exits 0 only when the last three are 0. It reads; it writes nothing and asks Voyage nothing.
    --rebuild  `ensure_schema`, then embeds every entry that needs it (missing or stale) in batches of 32
               as `document`s, upserts them, deletes the orphans, and prints `embedded`, `deleted` and
               `tokens`. It prints no DSN and no key.

    active   the entries whose status is `active` in the main database
    current  active, and the stored row has the entry's hash, the configured model and the configured dims
    missing  active, and no stored row
    stale    active, and a stored row that differs in hash, model or dims
    orphan   a stored row whose entry is not active (retired, or not there at all)

Every test runs over a dictionary and over a real pgvector (`tests/vector_data.py`).
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from contextlib import ExitStack

import httpx
import psycopg
import pytest
from app.infra import config
from app.rag import vector_index, vector_store
from app.rag.failures import RagUnavailable

from tests.test_rag_voyage import CFG, DIMS, KEY, PROVIDER_WORDS, embed_reply
from tests.vector_data import STORE_KINDS, MemoryStore, entry, make_store

INDEX_CFG = dataclasses.replace(CFG, VECTOR_DATABASE_URL="")


@pytest.fixture(params=STORE_KINDS)
def store(request, monkeypatch):
    with ExitStack() as stack:
        yield make_store(request.param, monkeypatch, stack)


@pytest.fixture(autouse=True)
def index_config(monkeypatch):
    monkeypatch.setattr(config, "load", lambda *a, **kw: INDEX_CFG)


class Batches:
    """A Voyage that answers any batch (`n` vectors for `n` inputs) and remembers each request."""

    def __init__(self, *, tokens_each: int = 10, fail_on: int | None = None, status: int = 429):
        self.tokens_each = tokens_each
        self.fail_on = fail_on
        self.status = status
        self.inputs: list[list[str]] = []
        self.input_types: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.inputs.append(body["input"])
        self.input_types.append(body["input_type"])
        if self.fail_on is not None and len(self.inputs) == self.fail_on:
            return httpx.Response(self.status, json={"detail": PROVIDER_WORDS})
        n = len(body["input"])
        return httpx.Response(200, json=embed_reply(n, tokens=self.tokens_each * n))

    @property
    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))

    @property
    def sizes(self) -> list[int]:
        return [len(batch) for batch in self.inputs]


def counts(out: str) -> dict[str, int]:
    """`name: n` lines of the output."""
    found = {}
    for line in out.splitlines():
        name, sep, value = line.partition(": ")
        if sep and value.strip().lstrip("-").isdigit():
            found[name.strip()] = int(value)
    return found


def sha_of(db, entry_id: str) -> str:
    return db.execute(
        "SELECT content_sha256 FROM knowledge_entries WHERE entry_id = %s", (entry_id,)
    ).fetchone()[0]


def make_current(db, store, entry_id: str) -> None:
    store.put(entry_id, sha_of(db, entry_id), "voyage-4", [0.5] * DIMS)


def check(db, store, capsys) -> tuple[int, dict[str, int]]:
    code = vector_index.main(["--check"], conn=db, vconn=store.conn)
    return code, counts(capsys.readouterr().out)


def rebuild(db, store, capsys, batches: Batches | None = None):
    batches = batches if batches is not None else Batches()
    code = vector_index.main(["--rebuild"], conn=db, vconn=store.conn, client=batches.client)
    out = capsys.readouterr()
    return code, counts(out.out), out, batches


# ── --check ───────────────────────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_check_of_nothing_is_all_zero_and_exits_zero(db, store, capsys) -> None:
    code, found = check(db, store, capsys)
    assert code == 0
    assert found == {"active": 0, "current": 0, "missing": 0, "stale": 0, "orphan": 0}


@pytest.mark.db
def test_check_counts_missing_stale_and_orphan_and_exits_one(db, store, capsys) -> None:
    current = entry(db)
    make_current(db, store, current)
    missing = entry(db)
    stale_hash = entry(db)
    store.put(stale_hash, "f" * 64, "voyage-4", [0.5] * DIMS)
    stale_model = entry(db)
    store.put(stale_model, sha_of(db, stale_model), "voyage-3", [0.5] * DIMS)
    stale_dims = entry(db)
    store.put(stale_dims, sha_of(db, stale_dims), "voyage-4", [0.5] * 3)
    retired = entry(db, status="retired")
    store.put(retired, sha_of(db, retired), "voyage-4", [0.5] * DIMS)
    ghost = str(uuid.uuid4())
    store.put(ghost, "e" * 64, "voyage-4", [0.5] * DIMS)
    unrelated_retired = entry(db, status="retired")  # retired, and no row: nothing to report

    code, found = check(db, store, capsys)

    assert unrelated_retired and missing
    assert found == {"active": 5, "current": 1, "missing": 1, "stale": 3, "orphan": 2}
    assert code == 1


@pytest.mark.db
@pytest.mark.parametrize("fault", ["missing", "stale", "orphan"])
def test_check_exits_zero_only_when_missing_stale_and_orphan_are_all_zero(
    db, store, capsys, fault
) -> None:
    ok = entry(db)
    make_current(db, store, ok)
    assert check(db, store, capsys)[0] == 0
    if fault == "missing":
        entry(db)
    elif fault == "stale":
        other = entry(db)
        store.put(other, "f" * 64, "voyage-4", [0.5] * DIMS)
    else:
        store.put(str(uuid.uuid4()), "e" * 64, "voyage-4", [0.5] * DIMS)
    code, found = check(db, store, capsys)
    assert code == 1 and found[fault] == 1


@pytest.mark.db
def test_check_reads_only_and_asks_voyage_nothing(db, store, capsys, monkeypatch) -> None:
    entry(db)
    store.put(str(uuid.uuid4()), "e" * 64, "voyage-4", [0.5] * DIMS)
    before = store.rows()

    def boom(*args, **kwargs):
        raise AssertionError("--check called Voyage")

    monkeypatch.setattr(vector_index.voyage, "embed", boom)
    monkeypatch.setattr(
        config, "load", lambda *a, **kw: dataclasses.replace(INDEX_CFG, VOYAGE_API_KEY="")
    )
    code, _ = check(db, store, capsys)

    assert code == 1 and store.rows() == before


@pytest.mark.db
def test_check_prints_no_key_and_no_address(db, store, capsys) -> None:
    entry(db)
    vector_index.main(["--check"], conn=db, vconn=store.conn)
    seen = capsys.readouterr()
    assert KEY not in seen.out + seen.err and "postgresql://" not in seen.out + seen.err


@pytest.mark.db
def test_check_follows_a_change_of_the_configured_model_or_dims(
    db, store, capsys, monkeypatch
) -> None:
    entry_id = entry(db)
    make_current(db, store, entry_id)
    assert check(db, store, capsys) == (
        0,
        {"active": 1, "current": 1, "missing": 0, "stale": 0, "orphan": 0},
    )

    monkeypatch.setattr(
        config,
        "load",
        lambda *a, **kw: dataclasses.replace(INDEX_CFG, RAG_EMBED_MODEL="voyage-4-lite"),
    )
    code, found = check(db, store, capsys)
    assert code == 1 and found["stale"] == 1 and found["current"] == 0


@pytest.mark.db
def test_check_with_no_table_yet_says_everything_is_missing_and_creates_nothing(
    db, store, capsys
) -> None:
    """A fresh `vectordb` has no table: `--check` reports it, and `--rebuild` makes it."""
    entry(db)
    store.drop_schema()
    code, found = check(db, store, capsys)
    assert code == 1 and found["missing"] == 1 and found["active"] == 1
    assert not store.has_schema()  # read-only


# ── --rebuild ─────────────────────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_rebuild_embeds_what_is_missing_or_stale_and_deletes_the_orphans(db, store, capsys) -> None:
    current = entry(db)
    make_current(db, store, current)
    missing = entry(db)
    stale = entry(db)
    store.put(stale, "f" * 64, "voyage-4", [0.5] * 3)
    retired = entry(db, status="retired")
    store.put(retired, sha_of(db, retired), "voyage-4", [0.5] * DIMS)
    ghost = str(uuid.uuid4())
    store.put(ghost, "e" * 64, "voyage-4", [0.5] * DIMS)
    current_vector = store.vector(current)

    code, found, _, batches = rebuild(db, store, capsys, Batches(tokens_each=7))

    assert code == 0
    assert found == {"embedded": 2, "deleted": 2, "tokens": 14}
    assert batches.sizes == [2] and batches.input_types == [
        "document"
    ]  # the current one is not sent again
    assert store.rows() == {
        current: (sha_of(db, current), "voyage-4", DIMS),
        missing: (sha_of(db, missing), "voyage-4", DIMS),
        stale: (sha_of(db, stale), "voyage-4", DIMS),
    }
    assert store.vector(current) == current_vector
    code, after = check(db, store, capsys)
    assert code == 0 and after == {"active": 3, "current": 3, "missing": 0, "stale": 0, "orphan": 0}


@pytest.mark.db
def test_rebuild_sends_the_digest_of_each_entry_and_stores_it_under_the_right_id(
    db, store, capsys
) -> None:
    from app.rag import match
    from app.rag.entries import entry_by_id

    first = entry(db, title="Một")
    second = entry(db, title="Hai")
    third = entry(db, title="Ba")
    _, _, _, batches = rebuild(db, store, capsys)

    (inputs,) = batches.inputs
    by_id = sorted([first, second, third])  # the order is the entry id's
    assert inputs == [match.entry_digest(entry_by_id(db, i)) for i in by_id]
    assert sorted(store.rows()) == by_id


@pytest.mark.db
def test_rebuild_sends_batches_of_thirty_two(db, store, capsys) -> None:
    ids = [entry(db, title=f"Mục {n}") for n in range(70)]
    code, found, _, batches = rebuild(db, store, capsys, Batches(tokens_each=3))

    assert code == 0 and batches.sizes == [32, 32, 6]
    assert found == {"embedded": 70, "deleted": 0, "tokens": 210}
    assert sorted(store.rows()) == sorted(ids)
    assert set(batches.input_types) == {"document"}
    assert check(db, store, capsys)[0] == 0


@pytest.mark.db
def test_rebuild_of_exactly_thirty_two_is_one_request(db, store, capsys) -> None:
    for n in range(32):
        entry(db, title=f"Mục {n}")
    _, found, _, batches = rebuild(db, store, capsys)
    assert batches.sizes == [32] and found["embedded"] == 32


@pytest.mark.db
def test_rebuild_of_an_index_that_is_whole_asks_voyage_nothing(db, store, capsys) -> None:
    for n in range(3):
        make_current(db, store, entry(db, title=f"Mục {n}"))
    code, found, _, batches = rebuild(db, store, capsys)
    assert code == 0 and batches.inputs == []
    assert found == {"embedded": 0, "deleted": 0, "tokens": 0}


@pytest.mark.db
def test_rebuild_makes_the_schema_first_on_a_vector_database_that_has_none(
    db, store, capsys
) -> None:
    """M3: on the real pgvector too, not only in the dictionary: no table, then a table with the row."""
    entry_id = entry(db)
    store.drop_schema()
    assert not store.has_schema()

    code, found, _, _ = rebuild(db, store, capsys)

    assert code == 0 and found["embedded"] == 1
    assert store.has_schema() and list(store.rows()) == [entry_id]


@pytest.mark.db
def test_rebuild_fixes_a_change_of_model_by_embedding_again(db, store, capsys, monkeypatch) -> None:
    entry_id = entry(db)
    make_current(db, store, entry_id)
    monkeypatch.setattr(
        config,
        "load",
        lambda *a, **kw: dataclasses.replace(INDEX_CFG, RAG_EMBED_MODEL="voyage-4-lite"),
    )
    code, found, _, batches = rebuild(db, store, capsys)
    assert code == 0 and batches.sizes == [1] and found["embedded"] == 1
    assert store.rows() == {entry_id: (sha_of(db, entry_id), "voyage-4-lite", DIMS)}


@pytest.mark.db
def test_rebuild_reads_the_index_before_the_entries_like_check_does(
    db, store, capsys, monkeypatch
) -> None:
    """M2. Read in this order, a rebuild cannot make an orphan: an entry retired after the index was read
    is not in the entries read next, so its vector is deleted. Read the other way round the entry would
    still be listed active, look current, and keep its vector. (An entry approved and embedded in between
    is only seen as missing and embedded again, which is harmless.)"""
    keep = entry(db, title="Còn hiệu lực")
    make_current(db, store, keep)
    retired_meanwhile = entry(db, title="Bị gỡ giữa chừng")
    make_current(db, store, retired_meanwhile)
    read_stored = vector_store.stored

    def stored_then_a_retirement(vconn):
        found = read_stored(vconn)
        db.execute(
            "UPDATE knowledge_entries SET status = 'retired' WHERE entry_id = %s",
            (retired_meanwhile,),
        )
        return found

    monkeypatch.setattr(vector_store, "stored", stored_then_a_retirement)
    code, found, _, batches = rebuild(db, store, capsys)

    assert code == 0 and found == {"embedded": 0, "deleted": 1, "tokens": 0}
    assert list(store.rows()) == [keep] and batches.inputs == []


@pytest.mark.db
def test_rebuild_with_a_failing_batch_exits_one_keeps_the_batches_before_it_and_names_the_kind(
    db, store, capsys
) -> None:
    for n in range(40):
        entry(db, title=f"Mục {n}")
    code, found, out, batches = rebuild(db, store, capsys, Batches(fail_on=2, status=429))

    assert code == 1 and batches.sizes == [32, 8]
    assert len(store.rows()) == 32  # the first batch stays: a rerun only does the rest
    assert "rate_limit" in out.err
    assert PROVIDER_WORDS not in out.out + out.err and KEY not in out.out + out.err
    assert found.get("embedded") == 32

    code, found, _, again = rebuild(db, store, capsys)
    assert code == 0 and again.sizes == [8] and len(store.rows()) == 40


@pytest.mark.db
@pytest.mark.parametrize(
    ("status", "kind"), [(401, "auth"), (402, "quota"), (500, "provider_error")]
)
def test_rebuild_names_the_kind_of_a_failure_and_nothing_the_provider_wrote(
    db, store, capsys, status, kind
) -> None:
    entry(db)
    code, _, out, _ = rebuild(db, store, capsys, Batches(fail_on=1, status=status))
    assert code == 1 and kind in out.err
    assert PROVIDER_WORDS not in out.out + out.err and store.rows() == {}


@pytest.mark.db
def test_rebuild_with_no_key_and_work_to_do_is_auth_and_sends_nothing(
    db, store, capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        config, "load", lambda *a, **kw: dataclasses.replace(INDEX_CFG, VOYAGE_API_KEY="")
    )
    entry(db)
    code, _, out, batches = rebuild(db, store, capsys)
    assert code == 1 and "auth" in out.err and batches.inputs == []


@pytest.mark.db
def test_rebuild_with_no_key_and_nothing_to_embed_still_deletes_the_orphans(
    db, store, capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        config, "load", lambda *a, **kw: dataclasses.replace(INDEX_CFG, VOYAGE_API_KEY="")
    )
    store.put(str(uuid.uuid4()), "e" * 64, "voyage-4", [0.5] * DIMS)
    code, found, _, _ = rebuild(db, store, capsys)
    assert code == 0 and found["deleted"] == 1 and store.rows() == {}


@pytest.mark.db
def test_rebuild_prints_no_key_and_no_address(db, store, capsys) -> None:
    entry(db)
    _, _, out, _ = rebuild(db, store, capsys)
    assert KEY not in out.out + out.err and "postgresql://" not in out.out + out.err


# ── --rebuild --force (Director ruling b) ────────────────────────────────────────────────────


def force(db, store, capsys, batches: Batches | None = None):
    batches = batches if batches is not None else Batches()
    code = vector_index.main(
        ["--rebuild", "--force"], conn=db, vconn=store.conn, client=batches.client
    )
    out = capsys.readouterr()
    return code, counts(out.out), out, batches


@pytest.mark.db
def test_force_embeds_every_active_entry_whether_current_or_not(db, store, capsys) -> None:
    current = entry(db, title="Hiện hành")
    make_current(db, store, current)
    old_vector = store.vector(current)
    missing = entry(db, title="Thiếu")
    stale = entry(db, title="Cũ")
    store.put(stale, "f" * 64, "voyage-4", [0.5] * 3)
    orphan = str(uuid.uuid4())
    store.put(orphan, "e" * 64, "voyage-4", [0.5] * DIMS)

    code, found, _, batches = force(db, store, capsys, Batches(tokens_each=4))

    assert code == 0 and found == {"embedded": 3, "deleted": 1, "tokens": 12}
    assert batches.sizes == [3] and set(batches.input_types) == {"document"}
    assert store.rows() == {i: (sha_of(db, i), "voyage-4", DIMS) for i in (current, missing, stale)}
    assert store.vector(current) != old_vector  # the current row was replaced, not skipped
    assert check(db, store, capsys)[0] == 0


@pytest.mark.db
def test_plain_rebuild_still_leaves_a_current_entry_alone(db, store, capsys) -> None:
    current = entry(db)
    make_current(db, store, current)
    before = store.vector(current)
    code, found, _, batches = rebuild(db, store, capsys)
    assert code == 0 and found["embedded"] == 0 and batches.inputs == []
    assert store.vector(current) == before


@pytest.mark.db
def test_force_sends_batches_of_thirty_two_too(db, store, capsys) -> None:
    for n in range(40):
        make_current(db, store, entry(db, title=f"Mục {n}"))
    _, found, _, batches = force(db, store, capsys)
    assert batches.sizes == [32, 8] and found["embedded"] == 40


@pytest.mark.db
def test_force_with_no_key_is_auth_and_changes_no_row(db, store, capsys, monkeypatch) -> None:
    monkeypatch.setattr(
        config, "load", lambda *a, **kw: dataclasses.replace(INDEX_CFG, VOYAGE_API_KEY="")
    )
    current = entry(db)
    make_current(db, store, current)
    before = store.rows()
    code, _, out, batches = force(db, store, capsys)
    assert code == 1 and "auth" in out.err and batches.inputs == []
    assert store.rows() == before


@pytest.mark.parametrize("argv", [["--check", "--force"], ["--force"]])
def test_force_belongs_to_rebuild_alone(argv, capsys) -> None:
    with pytest.raises(SystemExit) as caught:
        vector_index.main(argv)
    assert caught.value.code == 2
    assert "--force" in capsys.readouterr().err


# ── main ──────────────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("argv", [[], ["--check", "--rebuild"], ["--nothing"], ["check"]])
def test_exactly_one_of_check_and_rebuild_is_required(argv, capsys) -> None:
    with pytest.raises(SystemExit) as caught:
        vector_index.main(argv)
    assert caught.value.code == 2


@pytest.mark.db
@pytest.mark.parametrize("flag", ["--check", "--rebuild"])
def test_an_unreachable_vector_database_is_named_and_exits_one(db, capsys, flag) -> None:
    """No `vconn` given and `VECTOR_DATABASE_URL` empty: one line with the kind, no traceback."""
    entry(db)
    code = vector_index.main([flag], conn=db, client=Batches().client)
    seen = capsys.readouterr()
    assert code == 1 and "vectordb_unreachable" in seen.err
    assert "Traceback" not in seen.out + seen.err


def test_a_missing_main_database_address_is_named_and_exits_two(capsys, monkeypatch) -> None:
    code = vector_index.main(["--check"])
    seen = capsys.readouterr()
    assert code == 2 and "DATABASE_URL" in seen.err and "Traceback" not in seen.err


@pytest.mark.db
def test_the_connection_the_command_opened_is_closed(db, monkeypatch, capsys) -> None:
    store = MemoryStore(monkeypatch)
    monkeypatch.setattr(vector_store, "connect", lambda cfg: store.conn)
    vector_index.main(["--check"], conn=db)
    assert store.conn.closed
    store.conn.closed = False

    def lost(cfg):
        raise RagUnavailable("vectordb_unreachable")

    monkeypatch.setattr(vector_store, "connect", lost)
    assert vector_index.main(["--check"], conn=db) == 1


def test_a_main_database_that_cannot_be_reached_is_named_without_the_librarys_words(
    capsys, monkeypatch
) -> None:
    def refused():
        raise psycopg.OperationalError("connection to server at secret-host.internal failed")

    monkeypatch.setattr(vector_index.infra_db, "connect", refused)
    code = vector_index.main(["--check"], vconn=object())
    seen = capsys.readouterr()
    assert code == 1 and "OperationalError" in seen.err
    assert "secret-host" not in seen.out + seen.err and "Traceback" not in seen.err


@pytest.mark.parametrize(
    "dsn",
    [
        "postgresql://app:SENTINELpw%zz@host/db",  # an unescaped % in the password
        "postgresq://app:SENTINELpw@host/db",  # a mistyped scheme
        "postgres:/app:SENTINELpw@host/db",  # a scheme missing a slash
    ],
)
def test_a_malformed_main_database_address_leaks_no_password_and_exits_one(
    capsys, monkeypatch, dsn
) -> None:
    """I1. libpq's parse error for such an address quotes the address, password included, and psycopg
    raises it as a `ProgrammingError` (not an `OperationalError`): uncaught, the traceback prints it.
    The real `infra.db.connect` raises it here; nothing is patched but the config."""
    monkeypatch.setattr(
        config, "load", lambda *a, **kw: dataclasses.replace(INDEX_CFG, DATABASE_URL=dsn)
    )
    with pytest.raises(psycopg.ProgrammingError) as raw:  # the premise: the library does leak
        psycopg.connect(dsn)
    assert "SENTINELpw" in str(raw.value)

    code = vector_index.main(["--check"], vconn=object())

    seen = capsys.readouterr()
    assert code == 1 and "database" in seen.err
    assert "SENTINELpw" not in seen.out + seen.err and "Traceback" not in seen.out + seen.err


@pytest.mark.db
@pytest.mark.parametrize("flag", ["--check", "--rebuild"])
def test_any_database_error_is_named_by_its_class_only(
    db, store, capsys, monkeypatch, flag
) -> None:
    """The same rule for what a statement raises: the class of the error, never its text."""

    def refused(vconn):
        raise psycopg.errors.InsufficientPrivilege("permission denied for user SENTINELpw")

    monkeypatch.setattr(vector_store, "ensure_schema", refused)
    monkeypatch.setattr(vector_store, "stored", refused)
    code = vector_index.main([flag], conn=db, vconn=store.conn, client=Batches().client)
    seen = capsys.readouterr()
    assert code == 1 and "InsufficientPrivilege" in seen.err
    assert "SENTINELpw" not in seen.out + seen.err and "Traceback" not in seen.out + seen.err
