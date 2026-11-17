"""`kb.mitre` — the local MITRE ATT&CK reference (DEC-223, spec §4.3).

`kb/mitre/enterprise-attack.json` is the committed extract of the official ATT&CK Enterprise bundle
(built by `scripts/mitre_extract.py`; ATT&CK 20.1 today). This module loads it once per process, as
`kb/lookup.py` loads the playbooks, checks its header and its shape, and answers `lookup(id)` the
way `ingest/category.py`'s tiers match an id: the exact id first, then its parent
(`T1059.003` -> `T1059`) when the exact id is not in the reference.

A revoked or deprecated id answers with **its own** entry — its own name, tactics and description —
exactly like a live one. The extract holds nothing about what replaced it (the bundle's `revoked-by`
links are not read, Owner 17/11), so there is nothing to follow and nothing to show. `Entry.status`
is kept for tests and a later reader; the prompt does not show it.

A missing or damaged file is not an error of the alert: `version()` and `lookup()` answer `None`
("no reference"), the caller builds its prompt without the reference section and carries the warning
`mitre_reference_unavailable`. The reason is logged once, when the file is first read. A failed read
is remembered like a good one (until `reset_cache`): the file is part of the deployment, and a bad
one is not worth re-parsing on every alert.

`kb` may import only `infra` (and `lookup`, its sibling): the id pattern below is a transcription of
`llm/builder.py`'s `mitre` pattern, as `lookup._ACTIONS` is of `llm/verdicts.py`'s.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.kb.lookup import KB_ROOT

log = logging.getLogger(__name__)

#: The committed extract (`kb/` is mounted read-only into the app and worker containers).
MITRE_FILE: Path = KB_ROOT / "mitre" / "enterprise-attack.json"
#: The longest an entry's description is, `…` included (`scripts/mitre_extract.py` cuts there).
DESCRIPTION_MAX_CHARS = 600

_DOMAIN = "enterprise-attack"
_STATUSES = frozenset({"live", "revoked", "deprecated"})
#: `llm/builder.py`'s `mitre` pattern.
_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.ASCII)


@dataclass(frozen=True)
class Entry:
    id: str
    name: str
    tactics: tuple[str, ...]
    parent: str | None
    status: str
    description: str


@dataclass(frozen=True)
class Found:
    entry: Entry
    #: `"exact"` — the id itself is in the reference; `"parent"` — only its parent is, and
    #: `entry` is the parent's.
    via: str


class _Malformed(Exception):
    """The extract's header or shape is wrong (the message names where)."""


#: The loaded reference by path: `(version, {id: Entry})`, or `None` for "no usable reference".
_CACHE: dict[Path, tuple[str, dict[str, Entry]] | None] = {}


def reset_cache() -> None:
    """Forget what was loaded (tests)."""
    _CACHE.clear()


def _parse_entry(technique_id: str, raw: Any) -> Entry:
    if not isinstance(technique_id, str) or not _ID_RE.match(technique_id):
        raise _Malformed(f"technique key {technique_id!r} is not an ATT&CK id")
    if not isinstance(raw, dict):
        raise _Malformed(f"{technique_id}: entry is not an object")
    name, tactics = raw.get("name"), raw.get("tactics")
    parent, status, description = raw.get("parent"), raw.get("status"), raw.get("description")
    if not isinstance(name, str) or not name:
        raise _Malformed(f"{technique_id}: no name")
    if not isinstance(tactics, list) or not all(isinstance(t, str) for t in tactics):
        raise _Malformed(f"{technique_id}: tactics is not a list of strings")
    if status not in _STATUSES:
        raise _Malformed(f"{technique_id}: status {status!r}")
    if not isinstance(description, str):
        raise _Malformed(f"{technique_id}: description is not a string")
    expected_parent = technique_id.split(".")[0] if "." in technique_id else None
    if "parent" not in raw or parent != expected_parent:
        raise _Malformed(f"{technique_id}: parent is not {expected_parent!r}")
    return Entry(
        id=technique_id,
        name=name,
        tactics=tuple(tactics),
        parent=parent,
        status=status,
        description=description,
    )


def _parse(raw: Any) -> tuple[str, dict[str, Entry]]:
    if not isinstance(raw, dict):
        raise _Malformed("the file is not a JSON object")
    header, techniques = raw.get("header"), raw.get("techniques")
    if not isinstance(header, dict):
        raise _Malformed("no header")
    if header.get("domain") != _DOMAIN:
        raise _Malformed(f"header domain is {header.get('domain')!r}, not {_DOMAIN!r}")
    version = header.get("version")
    if not isinstance(version, str) or not version:
        raise _Malformed("header has no version")
    if not isinstance(techniques, dict):
        raise _Malformed("techniques is not an object")
    return version, {tid: _parse_entry(tid, entry) for tid, entry in techniques.items()}


def _load(path: Path) -> tuple[str, dict[str, Entry]] | None:
    if path in _CACHE:
        return _CACHE[path]
    loaded: tuple[str, dict[str, Entry]] | None
    try:
        loaded = _parse(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, _Malformed) as exc:  # ValueError: bad JSON, bad UTF-8
        log.warning("MITRE reference unavailable (%s): %s", path.name, exc)
        loaded = None
    _CACHE[path] = loaded
    return loaded


def version(*, path: Path | None = None) -> str | None:
    """The ATT&CK version of the reference ("20.1"), or `None` when there is no usable one."""
    loaded = _load(path if path is not None else MITRE_FILE)
    return None if loaded is None else loaded[0]


def lookup(technique_id: str, *, path: Path | None = None) -> Found | None:
    """MITRE's entry for `technique_id`: the id's own, else its parent's (`via="parent"`).

    `None` when the id is not in the reference, is not shaped like an ATT&CK id
    (`T1234` or `T1234.567`, case and surrounding white space aside), or there is no
    reference. A `T1234.xyz` never reaches `T1234` through a split on the dot."""
    if not isinstance(technique_id, str):
        return None
    tid = technique_id.strip().upper()
    if not _ID_RE.match(tid):
        return None
    loaded = _load(path if path is not None else MITRE_FILE)
    if loaded is None:
        return None
    entries = loaded[1]
    if tid in entries:
        return Found(entry=entries[tid], via="exact")
    if "." in tid:
        parent = entries.get(tid.split(".")[0])
        if parent is not None:
            return Found(entry=parent, via="parent")
    return None
