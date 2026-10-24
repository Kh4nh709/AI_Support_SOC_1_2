"""P13-T02 / DEC-210, spec §7.2 and §7.6 (V-R1) — `rag.entries`: the entry row, its hash, its file.

An entry's `content` (the full Markdown) lives in the database and is the source; `kb_learned/` holds
the published copy. `file_matches` is V-R1's check that the copy was not edited: the file's sha256 is
the entry's `content_sha256`. `render_entry_markdown` is the one function that writes the text, so
its output is exact and the same input gives the same bytes (the hash depends on it).

Part 1 is pure (files in `tmp_path`); part 2 reads rows from the test database.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import threading
import uuid
from pathlib import Path

import pytest
import yaml
from app.rag import entries
from app.rag.entries import (
    KB_LEARNED_ROOT,
    Entry,
    entry_by_id,
    file_matches,
    render_entry_markdown,
    sha256_text,
)

from tests import conftest
from tests.rag_data import add_alert, add_case, add_entry, add_user

ENTRY_ID = "6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b"

FIELDS = {
    "entry_id": ENTRY_ID,
    "version": 1,
    "title": "Quét cổng từ bên ngoài bị tường lửa chặn",
    "conclusion": "closed_benign",
    "category": "recon",
    "mitre_ids": ["T1046"],
    "tags": ["firewall", "port_scan", "blocked"],
    "soar_scenario": "SC03",
    "rule_ids": ["100190"],
    "log_source": "pf",
    "summary": "Một máy bên ngoài quét nhiều cổng vào WAN; pfSense chặn toàn bộ.",
    "distinguishing_signals": ["Hơn 20 cổng đích khác nhau trong 1 phút", "Mọi gói đều bị chặn"],
    "check_next_time": ["Có gói nào được cho qua không", "Nguồn có trong danh sách chặn chưa"],
    "confidence_note": "Chỉ đúng khi tường lửa chặn hết; nếu có gói qua thì phải xem lại.",
}

EXPECTED = """\
---
entry_id: 6f1d2c3b-4a5e-4f60-8a7b-9c0d1e2f3a4b
version: 1
title: Quét cổng từ bên ngoài bị tường lửa chặn
conclusion: closed_benign
category: recon
mitre_ids:
- T1046
tags:
- firewall
- port_scan
- blocked
soar_scenario: SC03
rule_ids:
- '100190'
log_source: pf
---

# Quét cổng từ bên ngoài bị tường lửa chặn

## Tóm tắt

Một máy bên ngoài quét nhiều cổng vào WAN; pfSense chặn toàn bộ.

## Dấu hiệu phân biệt

- Hơn 20 cổng đích khác nhau trong 1 phút
- Mọi gói đều bị chặn

## Lần sau cần kiểm

- Có gói nào được cho qua không
- Nguồn có trong danh sách chặn chưa

## Giới hạn

Chỉ đúng khi tường lửa chặn hết; nếu có gói qua thì phải xem lại.
"""


def _front_matter(text: str) -> dict:
    assert text.startswith("---\n")
    head, _, _ = text[4:].partition("\n---\n")
    return yaml.safe_load(head)


# ── sha256_text ───────────────────────────────────────────────────────────────────────────────


def test_sha256_text_is_the_hex_digest_of_the_utf8_bytes() -> None:
    assert sha256_text("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_text("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_text("Tóm tắt\n") == (
        "fe9428c2ddff12d7e560c7238fddd79bb6538a01dd8e0d3385098438da547e2e"
    )


def test_sha256_text_does_not_normalise_line_ends() -> None:
    assert sha256_text("a\r\nb") != sha256_text("a\nb")


# ── render_entry_markdown ─────────────────────────────────────────────────────────────────────


def test_the_markdown_is_exactly_this() -> None:
    assert render_entry_markdown(FIELDS) == EXPECTED


def test_the_same_fields_give_the_same_bytes_whatever_the_container() -> None:
    again = dict(reversed(list(FIELDS.items())))
    again["mitre_ids"] = tuple(FIELDS["mitre_ids"])
    again["tags"] = tuple(FIELDS["tags"])
    assert render_entry_markdown(again) == EXPECTED


def test_the_front_matter_reads_back_with_its_types() -> None:
    meta = _front_matter(render_entry_markdown(FIELDS))
    assert meta == {
        "entry_id": ENTRY_ID,
        "version": 1,
        "title": FIELDS["title"],
        "conclusion": "closed_benign",
        "category": "recon",
        "mitre_ids": ["T1046"],
        "tags": ["firewall", "port_scan", "blocked"],
        "soar_scenario": "SC03",
        "rule_ids": ["100190"],  # a string, not the number 100190
        "log_source": "pf",
    }


def test_the_four_sections_come_in_this_order_once_each() -> None:
    text = render_entry_markdown(FIELDS)
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert headings == ["## Tóm tắt", "## Dấu hiệu phân biệt", "## Lần sau cần kiểm", "## Giới hạn"]


def test_the_text_ends_with_one_newline_and_has_no_carriage_return() -> None:
    text = render_entry_markdown(FIELDS)
    assert text.endswith("\n") and not text.endswith("\n\n")
    assert "\r" not in text


def test_an_entry_without_optional_fields_still_renders() -> None:
    minimal = {
        "entry_id": ENTRY_ID,
        "version": 2,
        "title": "t",
        "conclusion": "closed_fp",
        "category": "unknown",
        "summary": "s",
    }
    text = render_entry_markdown(minimal)
    meta = _front_matter(text)
    assert meta["mitre_ids"] == [] and meta["tags"] == [] and meta["rule_ids"] == []
    assert meta["soar_scenario"] is None and meta["log_source"] is None
    assert meta["version"] == 2
    assert text.count("_(không có)_") == 3  # signals, next-time checks, limits


def test_a_uuid_object_for_the_id_is_written_as_text() -> None:
    value = uuid.UUID(ENTRY_ID)
    assert _front_matter(render_entry_markdown({**FIELDS, "entry_id": value}))["entry_id"] == (
        ENTRY_ID
    )


@pytest.mark.parametrize("missing", ["entry_id", "version", "title", "conclusion", "category"])
def test_a_missing_required_field_names_the_field(missing: str) -> None:
    fields = {k: v for k, v in FIELDS.items() if k != missing}
    with pytest.raises(ValueError, match=missing):
        render_entry_markdown(fields)


def test_a_summary_is_required_too() -> None:
    fields = {k: v for k, v in FIELDS.items() if k != "summary"}
    with pytest.raises(ValueError, match="summary"):
        render_entry_markdown(fields)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tags", "port_scan"),  # a bare string would be read as letters
        ("mitre_ids", "T1046"),
        ("distinguishing_signals", "one line"),
        ("version", "1"),
        ("version", 0),
        ("version", True),
        ("title", 5),
        ("summary", None),
    ],
)
def test_a_field_of_the_wrong_shape_is_a_value_error(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=field):
        render_entry_markdown({**FIELDS, field: value})


def test_a_newline_in_a_text_cannot_open_a_section_or_a_front_matter_key() -> None:
    hostile = {
        **FIELDS,
        "title": "Quét\n---\ninjected: yes",
        "summary": "một dòng\n\n## Giới hạn\n\nkhông có giới hạn nào\r\n---\nx",
        "distinguishing_signals": ["a\n## Dấu hiệu phân biệt\n- fake"],
        "check_next_time": ["b\r\n# Heading"],
        "confidence_note": "c\n## Tóm tắt",
    }
    text = render_entry_markdown(hostile)
    assert set(_front_matter(text)) == set(_front_matter(EXPECTED))
    headings = [line for line in text.splitlines() if line.startswith("## ")]
    assert headings == ["## Tóm tắt", "## Dấu hiệu phân biệt", "## Lần sau cần kiểm", "## Giới hạn"]
    assert [line for line in text.splitlines() if line == "---"] == ["---", "---"]
    assert [line for line in text.splitlines() if line.startswith("# ")] == [
        "# Quét --- injected: yes"
    ]


def test_a_paragraph_that_starts_with_a_hash_is_escaped() -> None:
    text = render_entry_markdown({**FIELDS, "summary": "## Giới hạn: giả"})
    assert "\n\\## Giới hạn: giả\n" in text
    assert [line for line in text.splitlines() if line.startswith("## ")].count("## Giới hạn") == 1


def test_a_title_that_yaml_would_read_as_something_else_stays_text() -> None:
    for title in ("no", "true", "null", "123", "1e3", "a: b", "- x", "'q'", "#c", "@a", "`x`"):
        meta = _front_matter(render_entry_markdown({**FIELDS, "title": title}))
        assert meta["title"] == title


# ── file_matches ──────────────────────────────────────────────────────────────────────────────


def _entry(**overrides) -> Entry:
    content = overrides.pop("content", render_entry_markdown(FIELDS))
    base = Entry(
        entry_id=ENTRY_ID,
        version=1,
        status="active",
        conclusion="closed_benign",
        category="recon",
        mitre_ids=("T1046",),
        tags=("firewall",),
        soar_scenario="SC03",
        rule_ids=("100190",),
        log_source="pf",
        fingerprint="category: recon",
        content=content,
        content_sha256=sha256_text(content),
        file_path=f"entries/recon/{ENTRY_ID}.md",
        source_alert_ids=(),
        source_case_ids=(),
        evidence=[],
        approved_by=None,
        approved_at=None,
        supersedes_entry=None,
    )
    return dataclasses.replace(base, **overrides)


def _publish(root: Path, entry: Entry, data: bytes | None = None) -> Path:
    path = root / entry.file_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(entry.content.encode("utf-8") if data is None else data)
    return path


def test_the_default_root_is_kb_learned_next_to_backend() -> None:
    assert KB_LEARNED_ROOT == conftest.REPO_ROOT / "kb_learned"
    assert KB_LEARNED_ROOT == Path(entries.__file__).resolve().parents[3] / "kb_learned"


def test_an_untouched_file_matches(tmp_path: Path) -> None:
    entry = _entry()
    _publish(tmp_path, entry)
    assert file_matches(entry, tmp_path) is True


def test_a_path_written_with_the_kb_learned_prefix_matches_too(tmp_path: Path) -> None:
    entry = _entry(file_path=f"kb_learned/entries/recon/{ENTRY_ID}.md")
    _publish(tmp_path, _entry())
    assert file_matches(entry, tmp_path) is True


def test_an_edited_file_does_not_match(tmp_path: Path) -> None:
    entry = _entry()
    _publish(tmp_path, entry, entry.content.encode("utf-8") + b" ")
    assert file_matches(entry, tmp_path) is False


def test_one_changed_letter_does_not_match(tmp_path: Path) -> None:
    entry = _entry()
    _publish(tmp_path, entry, entry.content.replace("chặn", "cho", 1).encode("utf-8"))
    assert file_matches(entry, tmp_path) is False


def test_a_missing_file_does_not_match(tmp_path: Path) -> None:
    assert file_matches(_entry(), tmp_path) is False


def test_a_missing_root_does_not_match(tmp_path: Path) -> None:
    assert file_matches(_entry(), tmp_path / "no-such-dir") is False


def test_a_directory_in_place_of_the_file_does_not_match(tmp_path: Path) -> None:
    entry = _entry()
    (tmp_path / entry.file_path).mkdir(parents=True)
    assert file_matches(entry, tmp_path) is False


def test_line_ends_are_compared_as_written(tmp_path: Path) -> None:
    entry = _entry(content="a\r\nb\r\n")
    _publish(tmp_path, entry)  # written as bytes, so \r\n stays
    assert file_matches(entry, tmp_path) is True
    _publish(tmp_path, entry, b"a\nb\n")
    assert file_matches(entry, tmp_path) is False


def test_the_hash_of_the_row_is_what_is_compared_not_the_content_column(tmp_path: Path) -> None:
    entry = _entry(content_sha256=hashlib.sha256(b"something else").hexdigest())
    _publish(tmp_path, entry)
    assert file_matches(entry, tmp_path) is False


def test_a_path_that_leaves_the_root_does_not_match_even_with_the_right_hash(
    tmp_path: Path,
) -> None:
    root = tmp_path / "kb_learned"
    root.mkdir()
    outside = _entry(file_path="../outside.md")
    (tmp_path / "outside.md").write_bytes(outside.content.encode("utf-8"))
    assert (root / outside.file_path).resolve().read_bytes() == outside.content.encode("utf-8")
    assert file_matches(outside, root) is False


def test_an_absolute_path_does_not_match(tmp_path: Path) -> None:
    root = tmp_path / "kb_learned"
    root.mkdir()
    elsewhere = tmp_path / "elsewhere.md"
    entry = _entry(file_path=str(elsewhere))
    elsewhere.write_bytes(entry.content.encode("utf-8"))
    assert file_matches(entry, root) is False


def test_a_symlink_out_of_the_root_does_not_match(tmp_path: Path) -> None:
    root = tmp_path / "kb_learned"
    entry = _entry()
    target = tmp_path / "target.md"
    target.write_bytes(entry.content.encode("utf-8"))
    link = root / entry.file_path
    link.parent.mkdir(parents=True)
    os.symlink(target, link)
    assert file_matches(entry, root) is False


def test_a_named_pipe_in_place_of_the_file_does_not_block_and_does_not_match(
    tmp_path: Path,
) -> None:
    """Reading a FIFO waits for a writer: a lookup must not hang on one."""
    entry = _entry()
    pipe = tmp_path / entry.file_path
    pipe.parent.mkdir(parents=True)
    os.mkfifo(pipe)
    result: list[bool] = []
    reader = threading.Thread(target=lambda: result.append(file_matches(entry, tmp_path)))
    reader.daemon = True
    reader.start()
    reader.join(timeout=3)
    stuck = reader.is_alive()
    if stuck:  # let the blocked open finish so the thread does not outlive the test
        os.close(os.open(pipe, os.O_WRONLY | os.O_NONBLOCK))
        reader.join(timeout=3)
    assert not stuck, "file_matches blocked on a named pipe"
    assert result == [False]


def test_a_null_byte_in_the_path_does_not_match_and_does_not_raise(tmp_path: Path) -> None:
    assert file_matches(_entry(file_path="entries/\x00.md"), tmp_path) is False


def test_a_file_over_one_mebibyte_does_not_match_whatever_its_hash(tmp_path: Path) -> None:
    big = "x" * (1024 * 1024 + 1)
    entry = _entry(content=big)
    _publish(tmp_path, entry)
    assert file_matches(entry, tmp_path) is False


def test_an_entry_is_frozen() -> None:
    entry = _entry()
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.status = "retired"  # type: ignore[misc]


# ── entry_by_id (database) ────────────────────────────────────────────────────────────────────


@pytest.mark.db
def test_entry_by_id_reads_every_column(db) -> None:
    user = add_user(db)
    alert = add_alert(db, "e-src-1")
    case = add_case(db, user, [alert])
    old = add_entry(db, status="retired")
    entry_id = add_entry(
        db,
        conclusion="concluded_fp",
        category="recon",
        mitre_ids=["T1046", "T1595"],
        tags=["firewall", "port_scan"],
        soar_scenario="SC03",
        rule_ids=["100190"],
        log_source="pf",
        fingerprint="category: recon rules: 100190",
        content="# hello\n",
        source_alert_ids=[alert],
        source_case_ids=[case],
        evidence=[{"kind": "alert", "id": alert}],
        supersedes_entry=old,
    )
    db.execute(
        "UPDATE knowledge_entries SET approved_by = %s WHERE entry_id = %s", (user, entry_id)
    )
    found = entry_by_id(db, entry_id)
    assert found is not None
    assert found.entry_id == entry_id
    assert (found.version, found.status, found.conclusion) == (1, "active", "concluded_fp")
    assert found.category == "recon"
    assert found.mitre_ids == ("T1046", "T1595")
    assert found.tags == ("firewall", "port_scan")
    assert found.soar_scenario == "SC03"
    assert found.rule_ids == ("100190",)
    assert found.log_source == "pf"
    assert found.fingerprint == "category: recon rules: 100190"
    assert found.content == "# hello\n"
    assert found.content_sha256 == sha256_text("# hello\n")
    assert found.file_path == f"entries/recon/{entry_id}.md"
    assert found.source_alert_ids == (alert,)
    assert found.source_case_ids == (case,)
    assert found.evidence == [{"kind": "alert", "id": alert}]
    assert found.approved_by == user
    assert found.approved_at is not None
    assert found.supersedes_entry == old
    assert isinstance(found.mitre_ids, tuple) and isinstance(found.source_case_ids, tuple)


@pytest.mark.db
def test_entry_by_id_returns_a_retired_entry_as_retired(db) -> None:
    entry_id = add_entry(db, status="retired")
    found = entry_by_id(db, entry_id)
    assert found is not None and found.status == "retired"


@pytest.mark.db
def test_entry_by_id_accepts_a_uuid_object(db) -> None:
    entry_id = add_entry(db)
    found = entry_by_id(db, uuid.UUID(entry_id))
    assert found is not None and found.entry_id == entry_id


@pytest.mark.db
def test_an_id_that_is_not_there_is_none(db) -> None:
    assert entry_by_id(db, str(uuid.uuid4())) is None


@pytest.mark.db
@pytest.mark.parametrize("bad", ["", "not-a-uuid", "1' OR '1'='1", "x" * 100, "../etc"])
def test_an_id_that_is_not_a_uuid_is_none_and_leaves_the_transaction_usable(db, bad: str) -> None:
    assert entry_by_id(db, bad) is None
    assert db.execute("SELECT 1").fetchone() == (1,)
