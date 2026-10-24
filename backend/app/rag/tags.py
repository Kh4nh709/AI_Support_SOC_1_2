"""The closed tag vocabulary and the rule-group mapping, read from `tags.yaml` (P13-T02, DEC-210).

`load_tags()` is the vocabulary a draft's tags must be a subset of (V1). `tags_from_rule_groups()`
turns an alert's Wazuh rule groups into tags for the fingerprint: it maps only the groups the file
lists (each means one thing) and ignores every other group and every value that is not a string.

The file is read and checked once per process. A malformed file is a `ValueError` naming what is
wrong, so a bad edit fails the test suite and the first lookup, never silently half-loads.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

TAGS_FILE = Path(__file__).with_name("tags.yaml")
_TAG = re.compile(r"[a-z][a-z0-9_]{1,39}")


def read_tags_file(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """The checked contents of a tags file: `(tags -> description, rule group -> tag)`."""
    document: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) != {"tags", "rule_groups"}:
        raise ValueError("tags file: expected exactly the keys 'tags' and 'rule_groups'")
    tags, groups = document["tags"], document["rule_groups"]
    if not isinstance(tags, dict) or not tags:
        raise ValueError("tags file: 'tags' must be a non-empty mapping of tag -> description")
    if not isinstance(groups, dict):
        raise ValueError(  # noqa: TRY004 — a malformed file is a ValueError, whatever its shape
            "tags file: 'rule_groups' must be a mapping of group -> tag"
        )
    for tag, description in tags.items():
        if not isinstance(tag, str) or not _TAG.fullmatch(tag):
            raise ValueError("tags file: a tag must be lower-case words joined by '_'")
        if not isinstance(description, str) or not description.strip():
            raise ValueError(f"tags file: tag {tag!r} has no description")
    for group, tag in groups.items():
        if not isinstance(group, str) or group != group.strip().lower() or not group:
            raise ValueError("tags file: a rule group must be written lower-case and trimmed")
        if tag not in tags:
            raise ValueError(f"tags file: rule group {group!r} maps to a tag that is not listed")
    return dict(tags), dict(groups)


@functools.cache
def _loaded() -> tuple[frozenset[str], dict[str, str]]:
    tags, groups = read_tags_file(TAGS_FILE)
    return frozenset(tags), groups


def load_tags() -> frozenset[str]:
    """The closed vocabulary, from `tags.yaml`."""
    return _loaded()[0]


def tags_from_rule_groups(groups: Sequence[str]) -> tuple[str, ...]:
    """The tags the mapped rule groups stand for: sorted, each once. Unmapped groups, and values
    that are not strings, are ignored."""
    mapping = _loaded()[1]
    found = {
        mapping[key]
        for group in groups
        if isinstance(group, str) and (key := group.strip().lower()) in mapping
    }
    return tuple(sorted(found))
