"""Learned-knowledge entries: the row, its hash, its published file, its Markdown (P13-T02, DEC-210).

The database is the source of an entry's content: `knowledge_entries.content` is the full Markdown,
front matter included, and `content_sha256` its hash. `kb_learned/entries/<category>/<entry_id>.md`
is the published copy the app writes on approval. `file_matches` is V-R1's check that the copy is
the entry (spec §7.7): the sha256 of the file's bytes equals the entry's `content_sha256`; an edited,
missing, oversized or out-of-tree file is a mismatch, never an error.

`knowledge_entries.file_path` is relative to `KB_LEARNED_ROOT` (`entries/<category>/<entry_id>.md`);
a leading `kb_learned/` is tolerated and dropped.

`render_entry_markdown` is the one function that writes an entry's text, and it is deterministic:
the same fields give the same bytes, which is what the hash depends on. Every text field is folded
onto one line, so a value cannot open a section or a front-matter key of its own.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import psycopg
import yaml

#: `backend/app/rag/entries.py` -> `rag` -> `app` -> `backend` -> repo root, then `kb_learned`.
KB_LEARNED_ROOT = Path(__file__).resolve().parents[3] / "kb_learned"

#: Larger than any entry the schema allows (a few kilobytes); the bound keeps one bad file from
#: being read whole into memory by a lookup.
MAX_FILE_BYTES = 1024 * 1024

#: The columns of `knowledge_entries`, in `Entry`'s order, minus `fingerprint_tsv`: a generated
#: index value, not data anyone reads.
ENTRY_COLUMNS = (
    "entry_id",
    "version",
    "status",
    "conclusion",
    "category",
    "mitre_ids",
    "tags",
    "soar_scenario",
    "rule_ids",
    "log_source",
    "fingerprint",
    "content",
    "content_sha256",
    "file_path",
    "source_alert_ids",
    "source_case_ids",
    "evidence",
    "approved_by",
    "approved_at",
    "supersedes_entry",
)


@dataclass(frozen=True)
class Entry:
    """One `knowledge_entries` row. Ids are text; the array columns are tuples."""

    entry_id: str
    version: int
    status: str
    conclusion: str
    category: str
    mitre_ids: tuple[str, ...]
    tags: tuple[str, ...]
    soar_scenario: str | None
    rule_ids: tuple[str, ...]
    log_source: str | None
    fingerprint: str
    content: str
    content_sha256: str
    file_path: str
    source_alert_ids: tuple[str, ...]
    source_case_ids: tuple[str, ...]
    evidence: Any
    approved_by: str | None
    approved_at: datetime | None
    supersedes_entry: str | None

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> Entry:
        """From a row selected in `ENTRY_COLUMNS` order."""
        (
            entry_id,
            version,
            status,
            conclusion,
            category,
            mitre_ids,
            tags,
            soar_scenario,
            rule_ids,
            log_source,
            fingerprint,
            content,
            content_sha256,
            file_path,
            source_alert_ids,
            source_case_ids,
            evidence,
            approved_by,
            approved_at,
            supersedes_entry,
        ) = row
        return cls(
            entry_id=str(entry_id),
            version=version,
            status=status,
            conclusion=conclusion,
            category=category,
            mitre_ids=tuple(mitre_ids),
            tags=tuple(tags),
            soar_scenario=soar_scenario,
            rule_ids=tuple(rule_ids),
            log_source=log_source,
            fingerprint=fingerprint,
            content=content,
            content_sha256=content_sha256,
            file_path=file_path,
            source_alert_ids=tuple(source_alert_ids),
            source_case_ids=tuple(str(case_id) for case_id in source_case_ids),
            evidence=evidence,
            approved_by=None if approved_by is None else str(approved_by),
            approved_at=approved_at,
            supersedes_entry=None if supersedes_entry is None else str(supersedes_entry),
        )


SELECT_ENTRY = "SELECT " + ", ".join(ENTRY_COLUMNS) + " FROM knowledge_entries"


def sha256_text(s: str) -> str:
    """The hex sha256 of `s` as UTF-8. No newline translation: the hash is of the bytes written."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def entry_by_id(conn: psycopg.Connection, entry_id: str | uuid.UUID) -> Entry | None:
    """The entry with this id, of any status, or None. An id that is not a UUID is None: the
    ranking agent's answer reaches this function, and it must not poison the transaction."""
    try:
        wanted = str(uuid.UUID(str(entry_id)))
    except ValueError:
        return None
    row = conn.execute(SELECT_ENTRY + " WHERE entry_id = %s", (wanted,)).fetchone()
    return None if row is None else Entry.from_row(row)


def _published_path(entry: Entry, root: Path) -> Path | None:
    """Where the entry's file is, or None when `file_path` leaves `root` (an absolute path,
    `..`, a symlink out of the tree)."""
    relative = entry.file_path.removeprefix("kb_learned/")
    try:
        base = root.resolve()
        path = (base / relative).resolve()
    except (OSError, ValueError, RuntimeError):
        return None
    return path if path.is_relative_to(base) else None


def file_matches(entry: Entry, root: Path = KB_LEARNED_ROOT) -> bool:
    """V-R1: the published file's sha256 equals `entry.content_sha256`. False, never an error, for
    a file that is missing, not a file, over `MAX_FILE_BYTES`, outside `root` or different."""
    path = _published_path(entry, root)
    if path is None:
        return False
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return False
        data = path.read_bytes()
    except (OSError, ValueError):
        return False
    return hmac.compare_digest(hashlib.sha256(data).hexdigest(), entry.content_sha256)


# ── rendering ─────────────────────────────────────────────────────────────────────────────────

_REQUIRED = ("entry_id", "version", "title", "conclusion", "category", "summary")
_NOTHING = "_(không có)_"
_WHITESPACE = re.compile(r"\s+")


def _text(fields: Mapping[str, Any], name: str, *, required: bool = False) -> str | None:
    value = fields.get(name)
    if value is None:
        if required:
            raise ValueError(f"render_entry_markdown: missing field {name!r}")
        return None
    if isinstance(value, uuid.UUID):
        value = str(value)
    if not isinstance(value, str):
        raise ValueError(  # noqa: TRY004 — one error type for every bad input
            f"render_entry_markdown: field {name!r} must be text"
        )
    return value


def _words(fields: Mapping[str, Any], name: str) -> list[str]:
    value = fields.get(name)
    if value is None:
        return []
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(  # noqa: TRY004 — one error type for every bad input
            f"render_entry_markdown: field {name!r} must be a list of text"
        )
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"render_entry_markdown: field {name!r} must be a list of text")
    return list(value)


def _one_line(value: str) -> str:
    return _WHITESPACE.sub(" ", value).strip()


def _escaped(line: str) -> str:
    """A leading `#` is escaped so the line cannot read as a heading."""
    return "\\" + line if line.startswith("#") else line


def _paragraph(value: str) -> str:
    """One line; a leading `#` is escaped so the line cannot read as a heading."""
    return _escaped(_one_line(value))


def _bullets(items: Sequence[str]) -> str:
    """One `- item` line per non-empty item, each folded onto one line with a leading `#` escaped as a
    paragraph's is (`- ## x` is a heading inside a list item)."""
    lines = [f"- {_escaped(_one_line(item))}" for item in items if _one_line(item)]
    return "\n".join(lines) if lines else _NOTHING


def render_entry_markdown(fields: Mapping[str, Any]) -> str:
    """The entry's Markdown: YAML front matter (the closed fields, `entry_id`, `version`, `title`),
    then Tóm tắt, Dấu hiệu phân biệt, Lần sau cần kiểm, Giới hạn.

    Required: `entry_id`, `version`, `title`, `conclusion`, `category`, `summary`. Optional:
    `mitre_ids`, `tags`, `rule_ids`, `distinguishing_signals`, `check_next_time` (lists of text),
    `soar_scenario`, `log_source`, `confidence_note`. A missing or ill-typed field is a
    `ValueError` naming the field, never its value."""
    for name in _REQUIRED:
        if fields.get(name) is None:
            raise ValueError(f"render_entry_markdown: missing field {name!r}")
    version = fields["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError("render_entry_markdown: field 'version' must be an integer >= 1")
    title = _one_line(_text(fields, "title", required=True) or "")
    summary = _text(fields, "summary", required=True) or ""
    note = _text(fields, "confidence_note")
    meta = {
        "entry_id": _text(fields, "entry_id", required=True),
        "version": version,
        "title": title,
        "conclusion": _text(fields, "conclusion", required=True),
        "category": _text(fields, "category", required=True),
        "mitre_ids": _words(fields, "mitre_ids"),
        "tags": _words(fields, "tags"),
        "soar_scenario": _text(fields, "soar_scenario"),
        "rule_ids": _words(fields, "rule_ids"),
        "log_source": _text(fields, "log_source"),
    }
    front = yaml.safe_dump(
        meta, sort_keys=False, allow_unicode=True, default_flow_style=False, width=10_000
    )
    sections = [
        f"---\n{front}---",
        f"# {title}",
        "## Tóm tắt",
        _paragraph(summary) or _NOTHING,
        "## Dấu hiệu phân biệt",
        _bullets(_words(fields, "distinguishing_signals")),
        "## Lần sau cần kiểm",
        _bullets(_words(fields, "check_next_time")),
        "## Giới hạn",
        (_paragraph(note) if note else "") or _NOTHING,
    ]
    return "\n\n".join(sections) + "\n"
