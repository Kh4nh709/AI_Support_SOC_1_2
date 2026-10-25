"""Approval, rejection, retirement and the published files of learned knowledge (P13-T05, DEC-210,
spec §7.2 and §7.5): `python -m app.rag.publish --rebuild`.

An admin reviews the drafts the `knowledge_draft` job wrote (`rag.draft`). **Approving** a draft makes an
entry: a `knowledge_entries` row, whose `content` is the full Markdown and `content_sha256` its hash (the
database is the source of the content), and a file `entries/<category>/<entry_id>.md` under
`KB_LEARNED_ROOT` with exactly those bytes (the published copy, which V-R1 checks before any lookup uses
the entry). **Retiring** moves the file to `retired/<category>/<entry_id>.md` and the entry is never
retrieved again. **Rebuilding** rewrites every active entry's file from the database (after `make
db-restore`, which restores rows and not files).

**Approve** (`approve_published`; `approve` returns just the id), in the caller's transaction:

1. the draft is locked `FOR UPDATE`: a status other than `pending` is `StaleDraft` (two admins, or a
   double click: the second waits for the first, then finds the draft approved, so one entry, one file
   and one event); an unknown one is `UnknownDraft`; a source that is no longer a decided alert or a
   concluded case is `StaleDraft` too. The UPDATE that marks the draft repeats `status = 'pending'`
   in its WHERE: the lock and the condition each stop a second approval, so neither is the only guard;
2. the fields are the stored draft's, with `edited` laid over the model fields (`MODEL_FIELDS`) and
   NOTHING else: a key of `edited` that is not a model field is refused (`v1_schema:unexpected_key`),
   and the six closed fields (`conclusion, category, mitre_ids, soar_scenario, rule_ids, log_source`)
   are always the source's, read now, never the request's and never the stored draft's;
3. the same tidy as the job (`rag.draft._tidy`: invisible code points deleted, control characters
   spaces, runs of whitespace one space, so a pasted soft hyphen or BOM is removed, never refused), and
   then V1-V5 (`rag.draft.validate_draft`) against the subject's CURRENT source record. Faults are
   `DraftInvalid(faults)` and nothing has been written. The text validated is the text stored;
4. the content is exactly `render_entry_markdown` of those fields with a new `entry_id` and `version` 1 (never
   an admin's own Markdown), `content_sha256` its hash, `fingerprint` the source's (`alert_fingerprint` /
   `case_fingerprint`; the full-text search matches its `rules:` and `rule:` lines), `source_alert_ids` the
   alert (or the case's head alerts), `source_case_ids` the case;
5. in ONE savepoint: the row, the draft set to `approved` (its text is what was published), the event
   `knowledge.approved {draft_id, entry_id}`, and last the file (a temporary name in the same directory,
   `fsync`, `rename`). A file that cannot be written raises, the savepoint rolls the rows back, and no
   entry survives, even if the caller goes on in the same transaction.

The commit is the caller's. A file that was renamed into place and a commit that then fails would leave a
file with no entry, so the caller commits through `commit_publication`, which removes the file (best
effort) when the commit raises. `Published` and `Retired` are what it undoes.

**Reject** and **retire** take a reason of 1-500 characters (`check_reason`). Retire locks the entry,
refuses one that is not active (`StaleEntry`), sets it `retired` with its `file_path` the retired one,
writes `knowledge.retired {entry_id, reason}` and moves the file; a file that is missing is nothing to
move (the database is the truth), and one whose path leaves the root is never touched. An entry
whose category is no directory name is still retired (its file goes to `retired/unknown/`).

Audit payloads, exactly (the admin audit page reads these keys): `knowledge.approved {draft_id,
entry_id}`, `knowledge.rejected {draft_id, reason}`, `knowledge.retired {entry_id, reason}`. The first two
are filed under the draft's source (like `knowledge.drafted`), the last under the entry (like
`rag.integrity_failed`).

A category is a directory name here, so it must be `[a-z0-9_]{1,64}` (`entry_path`): the categories are a
closed vocabulary, and a value that could leave the tree is `PublishError`, not a path.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sys
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from app.audit.events import write_event
from app.infra import db as infra_db
from app.infra.errors import ConfigError, PermanentError
from app.rag.draft import (
    DRAFT_FIELDS,
    LIST_FIELDS,
    MODEL_FIELDS,
    SourceRecord,
    _tidy,
    _tidy_list,
    source_record,
    strip_invisible,
    validate_draft,
)
from app.rag.entries import KB_LEARNED_ROOT, render_entry_markdown, sha256_text
from app.rag.fingerprint import alert_fingerprint, case_fingerprint
from app.rag.subject import Subject, parse_subject
from app.rag.tags import load_tags

REASON_MAX = 500
_CATEGORY = re.compile(r"[a-z0-9_]{1,64}")
#: What a text column and a jsonb value cannot hold: NUL, and a lone surrogate (not UTF-8).
_UNSTORABLE = re.compile("[\x00\ud800-\udfff]")
_LEGACY_PREFIX = "kb_learned/"

#: The first fault name for a key of `edited` that is not a model field, and for a body that is not
#: a mapping (both are in `rag.draft.FAULT_VOCABULARY`).
FAULT_UNEXPECTED_KEY = "v1_schema:unexpected_key"
FAULT_ROOT = "v1_schema:root"


# ── errors ────────────────────────────────────────────────────────────────────────────────────


class PublishError(Exception):
    """The publication cannot be done as asked (a path that leaves the tree, a category that is not a
    directory name). The route says 409; nothing has been written."""


class UnknownDraft(PublishError):
    """No draft has this id."""


class UnknownEntry(PublishError):
    """No entry has this id."""


class StaleDraft(PublishError):
    """The draft is no longer for approval: another admin already approved, rejected or merged it
    (`reason` "not_pending"), or its source is no longer a decided alert or a concluded case
    ("source_changed")."""

    def __init__(self, reason: str = "not_pending") -> None:
        super().__init__(f"draft is not for approval: {reason}")
        self.reason = reason


class StaleEntry(PublishError):
    """The entry is not active (it is already retired)."""


class InvalidReason(PublishError, ValueError):
    """A reason is 1-500 characters of text a database can hold."""


class DraftInvalid(PublishError):
    """The final text fails V1-V5. `faults` are the NAMES of the rules broken (`rule:field`, the
    closed vocabulary of `rag.draft.FAULT_VOCABULARY`), never a value."""

    def __init__(self, faults: Sequence[str]) -> None:
        self.faults = list(faults)
        super().__init__("draft invalid: " + ", ".join(self.faults))


# ── what a publication did to the files, and its undo ─────────────────────────────────────────


@dataclass(frozen=True)
class Published:
    """An entry that was approved: its id and the file written for it."""

    entry_id: uuid.UUID
    path: Path

    def undo(self) -> None:
        """Remove the file. Best effort: this runs when the commit failed."""
        with contextlib.suppress(OSError):
            self.path.unlink()


@dataclass(frozen=True)
class Moved:
    """A file moved from `source` to `target`."""

    source: Path
    target: Path

    def undo(self) -> None:
        with contextlib.suppress(OSError):
            os.replace(self.target, self.source)


@dataclass(frozen=True)
class Retired:
    """An entry that was retired, and the move of its file (None: there was no file to move)."""

    entry_id: uuid.UUID
    moved: Moved | None

    def undo(self) -> None:
        if self.moved is not None:
            self.moved.undo()


def commit_publication(conn: Any, action: Published | Retired) -> None:
    """`conn.commit()`; when it raises, undo what was done to the files (best effort) and re-raise. A
    commit that fails after the rename would otherwise leave a file for an entry that was not stored.
    A connection that is lost during the COMMIT may have committed: then the file is gone and the entry
    is not, which `knowledge_integrity` shows and `--rebuild` repairs."""
    try:
        conn.commit()
    except BaseException:
        action.undo()
        raise


# ── paths and files ───────────────────────────────────────────────────────────────────────────


def _directory(category: str) -> str:
    if not isinstance(category, str) or not _CATEGORY.fullmatch(category):
        raise PublishError("category: not a directory name")
    return category


def entry_path(category: str, entry_id: str) -> str:
    """Where an active entry's file is, relative to the root: `entries/<category>/<entry_id>.md`."""
    return f"entries/{_directory(category)}/{entry_id}.md"


def retired_path(category: str, entry_id: str) -> str:
    """Where a retired entry's file is, relative to the root."""
    return f"retired/{_directory(category)}/{entry_id}.md"


def _inside(root: Path, relative: str) -> Path:
    """The absolute path of `relative` under `root`, symlinks resolved; `PublishError` when it is the
    root itself or leaves it (an absolute path, `..`, a symlink that points out)."""
    base = root.resolve()
    target = (base / relative).resolve()
    if target == base or not target.is_relative_to(base):
        raise PublishError("path: outside the root")
    return target


def _sync_directory(directory: Path) -> None:
    """Make a rename durable; best effort (not every filesystem can sync a directory)."""
    with contextlib.suppress(OSError):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write_file(root: Path, relative: str, data: bytes) -> Path:
    """Publish `data` as `root/relative`: a temporary name in the same directory, `fsync`, then
    `rename`, so a reader sees the old file or the whole new one, never half. The temporary file is
    removed on any failure. Returns the absolute path. `PublishError` for a path outside `root`;
    `OSError` for a root that cannot be written."""
    path = _inside(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise
    _sync_directory(path.parent)
    return path


def move_file(root: Path, source: str, target: str) -> Moved | None:
    """Move `root/source` to `root/target` (a rename, the directory made). None when there is no such
    file. `PublishError` when either path leaves `root`."""
    src = _inside(root, source)
    dst = _inside(root, target)
    if not src.is_file():
        return None
    dst.parent.mkdir(parents=True, exist_ok=True)
    os.replace(src, dst)
    _sync_directory(dst.parent)
    _sync_directory(src.parent)
    return Moved(src, dst)


def _relative(file_path: str) -> str:
    return file_path.removeprefix(_LEGACY_PREFIX)


# ── reasons ───────────────────────────────────────────────────────────────────────────────────


def check_reason(reason: object) -> str:
    """The reason of a rejection or a retirement, trimmed: 1-500 characters of text. `InvalidReason`
    otherwise (and for a NUL or a lone surrogate, which no database column can hold)."""
    if not isinstance(reason, str):
        raise InvalidReason("reason: expected text")
    text = reason.strip()
    if not 1 <= len(text) <= REASON_MAX or _UNSTORABLE.search(text):
        raise InvalidReason(f"reason: expected 1-{REASON_MAX} characters of text")
    return text


# ── the final text of a draft ─────────────────────────────────────────────────────────────────


def _is_text_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _tidy_field(name: str, value: Any) -> Any:
    """The job's tidy for one model field; a value of the wrong type is left for V1 to name."""
    if name == "tags":
        return (
            list(dict.fromkeys(strip_invisible(tag) for tag in value))
            if _is_text_list(value)
            else value
        )
    if name in LIST_FIELDS:
        return _tidy_list(value) if _is_text_list(value) else value
    return _tidy(value) if isinstance(value, str) else value


def final_draft(
    stored: Any, edited: Mapping[str, Any] | None, source: SourceRecord
) -> dict[str, Any]:
    """The fields to validate and publish: the stored draft's model fields with `edited` laid over
    them, tidied; the closed fields from `source`. Only the keys of `DRAFT_FIELDS` are read, by name,
    and the result is in that order (the stored JSON has no order to depend on). `DraftInvalid` for an
    `edited` that is not a mapping or names a key that is not a model field."""
    changes: Mapping[str, Any] = {} if edited is None else edited
    if not isinstance(changes, Mapping):
        raise DraftInvalid([FAULT_ROOT])
    if any(key not in MODEL_FIELDS for key in changes):
        raise DraftInvalid([FAULT_UNEXPECTED_KEY])
    base: Mapping[str, Any] = stored if isinstance(stored, Mapping) else {}
    closed: dict[str, Any] = {
        "conclusion": source.conclusion,
        "category": source.category,
        "mitre_ids": list(source.mitre_ids),
        "soar_scenario": source.soar_scenario,
        "rule_ids": list(source.rule_ids),
        "log_source": source.log_source,
    }
    model = {
        name: _tidy_field(name, changes[name] if name in changes else base[name])
        for name in MODEL_FIELDS
        if name in changes or name in base
    }
    combined = {**model, **closed}
    return {name: combined[name] for name in DRAFT_FIELDS if name in combined}


def _source_ids(conn: psycopg.Connection, subject: Subject) -> tuple[list[str], list[str]]:
    """`(source_alert_ids, source_case_ids)`: the alert, or the case and its head alerts."""
    if subject.kind == "alert":
        return [subject.id], []
    heads = conn.execute(
        "SELECT alert_id FROM case_alerts WHERE case_id = %s ORDER BY alert_id", (subject.id,)
    ).fetchall()
    return [alert_id for (alert_id,) in heads], [subject.id]


def _as_uuid(value: object) -> uuid.UUID | None:
    try:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except ValueError:
        return None


# ── approve ───────────────────────────────────────────────────────────────────────────────────


def approve_published(
    conn: psycopg.Connection,
    draft_id: uuid.UUID,
    admin_id: str,
    *,
    edited: Mapping[str, Any] | None = None,
    root: Path = KB_LEARNED_ROOT,
) -> Published:
    """Approve a draft (module doc): the entry row, the draft marked, the event and the file, in the
    caller's transaction. The caller commits through `commit_publication`."""
    wanted = _as_uuid(draft_id)
    row = (
        None
        if wanted is None
        else conn.execute(
            "SELECT source_kind, source_id, status, draft FROM knowledge_drafts"
            " WHERE draft_id = %s FOR UPDATE",
            (wanted,),
        ).fetchone()
    )
    if row is None:
        raise UnknownDraft("draft: not found")
    kind, source_id, status, stored = row
    if status != "pending":
        raise StaleDraft("not_pending")
    try:
        subject = parse_subject(f"{kind}:{source_id}")
        source = source_record(conn, subject)
    except (ValueError, PermanentError):
        raise StaleDraft("source_changed") from None

    final = final_draft(stored, edited, source)
    faults = validate_draft(final, source, tags=load_tags())
    if faults:
        raise DraftInvalid(faults)

    entry_id = uuid.uuid4()
    relative = entry_path(source.category, str(entry_id))
    content = render_entry_markdown({**final, "entry_id": str(entry_id), "version": 1})
    fingerprint = (
        alert_fingerprint(conn, subject.id)
        if subject.kind == "alert"
        else case_fingerprint(conn, subject.id)
    )
    alert_ids, case_ids = _source_ids(conn, subject)

    with conn.transaction():
        conn.execute(
            "INSERT INTO knowledge_entries (entry_id, version, status, conclusion, category,"
            " mitre_ids, tags, soar_scenario, rule_ids, log_source, fingerprint, content,"
            " content_sha256, file_path, source_alert_ids, source_case_ids, evidence,"
            " approved_by, approved_at)"
            " VALUES (%(entry_id)s, 1, 'active', %(conclusion)s, %(category)s, %(mitre_ids)s,"
            " %(tags)s, %(soar_scenario)s, %(rule_ids)s, %(log_source)s, %(fingerprint)s,"
            " %(content)s, %(sha)s, %(file_path)s, %(alerts)s, %(cases)s::uuid[],"
            " jsonb_build_array(jsonb_build_object('subject', %(subject)s::text, 'at', now())),"
            " %(admin)s, now())",
            {
                "entry_id": entry_id,
                "conclusion": final["conclusion"],
                "category": final["category"],
                "mitre_ids": final["mitre_ids"],
                "tags": final["tags"],
                "soar_scenario": final["soar_scenario"],
                "rule_ids": final["rule_ids"],
                "log_source": final["log_source"],
                "fingerprint": fingerprint.text,
                "content": content,
                "sha": sha256_text(content),
                "file_path": relative,
                "alerts": alert_ids,
                "cases": case_ids,
                "subject": subject.key,
                "admin": admin_id,
            },
        )
        marked = conn.execute(
            "UPDATE knowledge_drafts SET status = 'approved', draft = %s, reviewed_by = %s,"
            " reviewed_at = now() WHERE draft_id = %s AND status = 'pending' RETURNING draft_id",
            (Jsonb(final), admin_id, wanted),
        ).fetchone()
        if marked is None:  # the row lock above makes this unreachable: a second line of defence
            raise StaleDraft("not_pending")
        write_event(
            conn,
            "knowledge.approved",
            subject.id,
            "admin",
            actor_id=admin_id,
            payload={"draft_id": str(wanted), "entry_id": str(entry_id)},
        )
        # last: a file that cannot be written takes the rows above back (the savepoint)
        path = write_file(root, relative, content.encode("utf-8"))
    return Published(entry_id, path)


def approve(
    conn: psycopg.Connection,
    draft_id: uuid.UUID,
    admin_id: str,
    *,
    edited: Mapping[str, Any] | None = None,
    root: Path = KB_LEARNED_ROOT,
) -> uuid.UUID:
    """`approve_published`, returning the new entry's id. A caller that commits itself should use
    `approve_published` and `commit_publication`, so a failed commit removes the file."""
    return approve_published(conn, draft_id, admin_id, edited=edited, root=root).entry_id


# ── reject ────────────────────────────────────────────────────────────────────────────────────


def reject(conn: psycopg.Connection, draft_id: uuid.UUID, admin_id: str, reason: str) -> None:
    """Reject a pending draft with a reason of 1-500 characters (`check_reason`), in the caller's
    transaction. `UnknownDraft`; `StaleDraft` for a draft that is not pending."""
    text = check_reason(reason)
    wanted = _as_uuid(draft_id)
    row = (
        None
        if wanted is None
        else conn.execute(
            "SELECT source_id, status FROM knowledge_drafts WHERE draft_id = %s FOR UPDATE",
            (wanted,),
        ).fetchone()
    )
    if row is None:
        raise UnknownDraft("draft: not found")
    source_id, status = row
    if status != "pending":
        raise StaleDraft("not_pending")
    marked = conn.execute(
        "UPDATE knowledge_drafts SET status = 'rejected', reviewed_by = %s, reviewed_at = now(),"
        " review_note = %s WHERE draft_id = %s AND status = 'pending' RETURNING draft_id",
        (admin_id, text, wanted),
    ).fetchone()
    if marked is None:  # the row lock above makes this unreachable: a second line of defence
        raise StaleDraft("not_pending")
    write_event(
        conn,
        "knowledge.rejected",
        source_id,
        "admin",
        actor_id=admin_id,
        payload={"draft_id": str(wanted), "reason": text},
    )


# ── retire ────────────────────────────────────────────────────────────────────────────────────


def retire_published(
    conn: psycopg.Connection,
    entry_id: uuid.UUID | str,
    admin_id: str,
    reason: str,
    *,
    root: Path = KB_LEARNED_ROOT,
) -> Retired:
    """Retire an active entry (module doc): the row, the event and the file's move, in the caller's
    transaction. The caller commits through `commit_publication`."""
    text = check_reason(reason)
    wanted = _as_uuid(entry_id)
    row = (
        None
        if wanted is None
        else conn.execute(
            "SELECT status, category, file_path FROM knowledge_entries"
            " WHERE entry_id = %s FOR UPDATE",
            (wanted,),
        ).fetchone()
    )
    if row is None:
        raise UnknownEntry("entry: not found")
    status, category, file_path = row
    if status != "active":
        raise StaleEntry("entry: not active")
    try:
        target = retired_path(category, str(wanted))
    except PublishError:  # a category that is no directory name: the entry can still be retired
        target = retired_path("unknown", str(wanted))

    with conn.transaction():
        marked = conn.execute(
            "UPDATE knowledge_entries SET status = 'retired', file_path = %s"
            " WHERE entry_id = %s AND status = 'active' RETURNING entry_id",
            (target, wanted),
        ).fetchone()
        if marked is None:  # the row lock above makes this unreachable: a second line of defence
            raise StaleEntry("entry: not active")
        write_event(
            conn,
            "knowledge.retired",
            str(wanted),
            "admin",
            actor_id=admin_id,
            payload={"entry_id": str(wanted), "reason": text},
        )
        try:
            moved = move_file(root, _relative(file_path), target)
        except PublishError:  # a path that leaves the tree is not ours to move
            moved = None
    return Retired(wanted, moved)


def retire(
    conn: psycopg.Connection,
    entry_id: uuid.UUID | str,
    admin_id: str,
    reason: str,
    *,
    root: Path = KB_LEARNED_ROOT,
) -> None:
    """`retire_published`, returning nothing (see `approve`)."""
    retire_published(conn, entry_id, admin_id, reason, root=root)


# ── rebuild ───────────────────────────────────────────────────────────────────────────────────


def _warn(payload: dict[str, Any]) -> None:
    print(json.dumps(payload), file=sys.stderr)


def rebuild(conn: psycopg.Connection, root: Path = KB_LEARNED_ROOT) -> int:
    """Rewrite the file of every active entry from its `content`; returns how many were written.
    The restore step after `make db-restore` (rows come back, files do not) and the repair of a file
    changed by hand. An entry whose `content` no longer hashes to its `content_sha256`, or whose
    `file_path` leaves `root`, is skipped with a line on stderr: a file for it could never pass V-R1.
    Retired entries are left where they are."""
    rows = conn.execute(
        "SELECT entry_id, file_path, content, content_sha256 FROM knowledge_entries"
        " WHERE status = 'active' ORDER BY approved_at NULLS LAST, entry_id"
    ).fetchall()
    written = 0
    for entry_id, file_path, content, expected in rows:
        if sha256_text(content) != expected:
            _warn({"rebuild": "skipped", "entry_id": str(entry_id), "reason": "content_sha256"})
            continue
        try:
            write_file(root, _relative(file_path), content.encode("utf-8"))
        except PublishError:
            _warn({"rebuild": "skipped", "entry_id": str(entry_id), "reason": "path"})
            continue
        written += 1
    return written


def main(argv: Sequence[str] | None = None, *, conn: psycopg.Connection | None = None) -> int:
    """`python -m app.rag.publish --rebuild [--root PATH]`. `conn` is a test seam."""
    parser = argparse.ArgumentParser(
        prog="python -m app.rag.publish",
        description="Rewrite every active learned-knowledge entry's file from the database.",
    )
    parser.add_argument(
        "--rebuild", action="store_true", help="rewrite the files of active entries"
    )
    parser.add_argument("--root", type=Path, default=None, help="the kb_learned directory")
    args = parser.parse_args(argv)
    if not args.rebuild:
        parser.error("nothing to do: pass --rebuild")
    root = KB_LEARNED_ROOT if args.root is None else args.root
    owned = conn is None
    try:
        connection = infra_db.connect() if conn is None else conn
    except ConfigError as exc:
        print(f"publish: {exc}", file=sys.stderr)
        return 1
    try:
        count = rebuild(connection, root)
        connection.rollback()  # read-only: end the transaction
    finally:
        if owned:
            connection.close()
    print(json.dumps({"rebuilt": count, "root": str(root)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
