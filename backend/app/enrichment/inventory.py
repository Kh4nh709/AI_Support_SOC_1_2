"""Validation and loading of the three hand-maintained inventory files (P0-T05, P2-T08).

`conf/inventory.yaml`, `conf/identities.yaml` and `conf/iocs.csv` are written by
hand; `docs/inventory-format.md` is the format they follow. `validate()` is what
tells the Owner whether those files are usable before any of their content
reaches a database; it reads files and does nothing else — standard library plus
PyYAML, no infrastructure module, no driver, no network.

`load()` (P2-T08) is the other half: it validates first (a half-loaded inventory
is worse than the old one), then upserts each file's rows into `assets`,
`identities` and `iocs`, stamping `source`, `loaded_at` and `active`. It needs a
real connection, so it is the one place in this module that imports `psycopg`
and `app.infra.errors` — both allowed under `enrichment → infra` (context pack §4).

Vocabulary (DEC-004): `assets.criticality` is `high | medium | low | unknown`,
the same closed set as `structured_basis.asset_criticality` in the §6.2 output
schema, so gate step 2 can compare the two field by field. The four-value v1 set
is gone and there is nothing to map.
"""

from __future__ import annotations

import csv
import dataclasses
import json
import os
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import yaml

from app.infra.errors import PermanentError

DEFAULT_PATHS: tuple[str, ...] = (
    "conf/inventory.yaml",
    "conf/identities.yaml",
    "conf/iocs.csv",
)

ASSET_CRITICALITY: tuple[str, ...] = ("high", "medium", "low", "unknown")
#: Values a copy from a pre-DEC-004 document will contain; named in the message.
RETIRED_CRITICALITY: tuple[str, ...] = ("crown_jewel", "normal")
IOC_REPUTATION: tuple[str, ...] = ("malicious", "suspicious", "clean")

ASSET_KEYS: tuple[str, ...] = ("hostname", "criticality", "owner", "role")
IDENTITY_KEYS: tuple[str, ...] = ("username", "is_privileged")
IOC_KEYS: tuple[str, ...] = ("value", "reputation", "expires_at", "source")

#: `assets.owner`, `assets.role` — nullable text columns, kept short because they
#: are rendered into a prompt inside an `<untrusted_data>` block (§7.1).
MAX_TEXT_LEN = 200

WARNING = "warning: "


def validate(paths: Sequence[str | Path] | None = None) -> list[str]:
    """Return human-readable problems, one per line; an empty list means the files are usable.

    `paths` defaults to `INVENTORY_PATHS` from the environment, else the three
    `conf/` defaults.

    DEC-007: `INVENTORY_PATHS` is stored as a JSON array (context pack §6.3 and
    `.env.example` both write it that way), so it is parsed with `json.loads` and
    must be a list of `str`. Anything else — bad JSON, or JSON that is not a list
    of `str` — is a configuration error naming `INVENTORY_PATHS`, never a silent
    fallback to the `conf/` defaults. Only an unset or empty variable falls back.

    DEC-007: each path is routed to a checker by **content**, never by position
    and never by basename: a CSV goes to `validate_iocs()`, a YAML file to
    `validate_assets()` or `validate_identities()` according to its top-level key.

    Entries prefixed `warning: ` describe a file that will load but is not what
    the Owner meant (an already-expired IoC row). Callers that want errors only
    may filter on that prefix; the list is still non-empty, which is what
    `make`-style checks key on.
    """
    if paths is None:
        resolved, problems = _paths_from_env()
        if problems:
            return problems
    else:
        resolved = [Path(p) for p in paths]

    out: list[str] = []
    for path in resolved:
        out.extend(_validate_file(path))
    return out


@dataclasses.dataclass(frozen=True)
class LoadReport:
    """What one `load()` call did — the counts the reload route returns as JSON."""

    assets: int
    identities: int
    iocs: int
    deactivated: int
    warnings: list[str]


def load(conn: psycopg.Connection, paths: Sequence[str | Path] | None = None) -> LoadReport:
    """Validate the three files, then upsert their rows into `assets`, `identities`
    and `iocs` on `conn` — one transaction the *caller* owns (this function never
    calls `commit`/`rollback`).

    Any problem `validate()` reports that is not a `warning: ` line aborts the
    load before anything is written: `PermanentError` lists the problems
    (`docs/inventory-format.md` §4 — a half-loaded inventory is worse than the
    old one). `warning: ` lines (e.g. an already-expired IoC) load anyway and
    come back on `LoadReport.warnings`.

    Absent rows are flipped `active = false`, never `DELETE`d — the enrichment
    history of past alerts stays intact (§4). `assets`/`identities` upsert on
    their file's own primary key and scope deactivation to rows that came from
    the *same* file (`source` = its basename); `iocs` upserts on `(value,
    source)` — its own CSV column, not the loader's file name — and deactivates
    every active row whose pair is absent from the file, file-scoping making no
    sense there since the primary key does not include a file name.
    """
    problems = validate(paths)
    errors = [p for p in problems if not p.startswith(WARNING)]
    if errors:
        raise PermanentError("\n".join(errors))
    warnings = [p for p in problems if p.startswith(WARNING)]

    resolved = [Path(p) for p in paths] if paths is not None else _paths_from_env()[0]

    assets = identities = iocs = deactivated = 0
    for path in resolved:
        text = path.read_text(encoding="utf-8")
        if _is_csv(path, text):
            rows, _ = _read_csv(text, str(path))
            n, deact = _load_iocs(conn, rows)
            iocs += n
        else:
            doc, _ = _read_yaml(text, str(path))
            if isinstance(doc, Mapping) and "assets" in doc:
                n, deact = _load_assets(conn, doc["assets"], path.name)
                assets += n
            elif isinstance(doc, Mapping) and "identities" in doc:
                n, deact = _load_identities(conn, doc["identities"], path.name)
                identities += n
            else:
                continue
        deactivated += deact

    return LoadReport(
        assets=assets, identities=identities, iocs=iocs, deactivated=deactivated, warnings=warnings
    )


def _load_assets(conn: psycopg.Connection, items: list[Mapping], source: str) -> tuple[int, int]:
    hostnames = [str(item["hostname"]).strip() for item in items]
    for item, hostname in zip(items, hostnames, strict=True):
        conn.execute(
            """
            INSERT INTO assets (hostname, criticality, owner, role, source, loaded_at, active,
                                 updated_at)
            VALUES (%s, %s, %s, %s, %s, now(), true, now())
            ON CONFLICT (hostname) DO UPDATE SET
                criticality = EXCLUDED.criticality,
                owner       = EXCLUDED.owner,
                role        = EXCLUDED.role,
                source      = EXCLUDED.source,
                loaded_at   = EXCLUDED.loaded_at,
                active      = true,
                updated_at  = now()
            """,
            (hostname, item["criticality"], item.get("owner"), item.get("role"), source),
        )
    result = conn.execute(
        "UPDATE assets SET active = false, updated_at = now() "
        "WHERE source = %s AND active AND hostname <> ALL(%s::text[])",
        (source, hostnames),
    )
    return len(items), result.rowcount


def _load_identities(
    conn: psycopg.Connection, items: list[Mapping], source: str
) -> tuple[int, int]:
    usernames = [str(item["username"]).strip() for item in items]
    for item, username in zip(items, usernames, strict=True):
        conn.execute(
            """
            INSERT INTO identities (username, is_privileged, source, loaded_at, active,
                                     updated_at)
            VALUES (%s, %s, %s, now(), true, now())
            ON CONFLICT (username) DO UPDATE SET
                is_privileged = EXCLUDED.is_privileged,
                source        = EXCLUDED.source,
                loaded_at     = EXCLUDED.loaded_at,
                active        = true,
                updated_at    = now()
            """,
            (username, bool(item.get("is_privileged")), source),
        )
    result = conn.execute(
        "UPDATE identities SET active = false, updated_at = now() "
        "WHERE source = %s AND active AND username <> ALL(%s::text[])",
        (source, usernames),
    )
    return len(items), result.rowcount


def _load_iocs(conn: psycopg.Connection, rows: Iterable[Mapping[str, str]]) -> tuple[int, int]:
    rows = list(rows)
    values = [row["value"].strip() for row in rows]
    sources = [(row.get("source") or "").strip() or "internal" for row in rows]
    for row, value, source in zip(rows, values, sources, strict=True):
        conn.execute(
            """
            INSERT INTO iocs (value, source, reputation, expires_at, loaded_at, active,
                               updated_at)
            VALUES (%s, %s, %s, %s, now(), true, now())
            ON CONFLICT (value, source) DO UPDATE SET
                reputation  = EXCLUDED.reputation,
                expires_at  = EXCLUDED.expires_at,
                loaded_at   = EXCLUDED.loaded_at,
                active      = true,
                updated_at  = now()
            """,
            (value, source, row["reputation"].strip(), row["expires_at"].strip()),
        )
    result = conn.execute(
        """
        UPDATE iocs SET active = false, updated_at = now()
        WHERE active AND NOT EXISTS (
            SELECT 1 FROM unnest(%s::text[], %s::text[]) AS f(value, source)
            WHERE f.value = iocs.value AND f.source = iocs.source
        )
        """,
        (values, sources),
    )
    return len(rows), result.rowcount


def validate_assets(doc: object, source: str) -> list[str]:
    """Check one parsed `conf/inventory.yaml` document; `source` names it in messages."""
    items, out = _envelope(doc, "assets", source)
    if items is None:
        return out

    seen: dict[str, str] = {}
    for index, item in enumerate(items):
        label = f"assets[{index}]"
        where = f"{source}: {label}"
        if not isinstance(item, Mapping):
            kind = _kind(item)
            out.append(f"{where}: expected a mapping with 'hostname' and 'criticality', got {kind}")
            continue
        out.extend(_unknown_keys(item, ASSET_KEYS, where))
        out.extend(_identifier(item, "hostname", where, label, seen))
        out.extend(_criticality(item, where))
        for field in ("owner", "role"):
            out.extend(_optional_text(item, field, where))
    return out


def validate_identities(doc: object, source: str) -> list[str]:
    """Check one parsed `conf/identities.yaml` document; `source` names it in messages."""
    items, out = _envelope(doc, "identities", source)
    if items is None:
        return out

    seen: dict[str, str] = {}
    for index, item in enumerate(items):
        label = f"identities[{index}]"
        where = f"{source}: {label}"
        if not isinstance(item, Mapping):
            out.append(f"{where}: expected a mapping with 'username', got {_kind(item)}")
            continue
        out.extend(_unknown_keys(item, IDENTITY_KEYS, where))
        out.extend(_identifier(item, "username", where, label, seen))
        out.extend(_is_privileged(item, where))
    return out


def validate_iocs(rows: Iterable[Mapping[str, str]], source: str) -> list[str]:
    """Check the data rows of one `conf/iocs.csv`; `source` names the file in messages.

    Rows are what `csv.DictReader` yields: comment and blank lines are already
    gone (DEC-007). An entry prefixed `warning: ` marks a row that has expired —
    it loads, but the lookup `... AND expires_at > now()` will never see it.
    """
    out: list[str] = []
    seen: dict[str, str] = {}
    reported_columns: set[str] = set()

    for index, row in enumerate(rows):
        label = f"iocs[{index}]"
        where = f"{source}: {label}"
        if not isinstance(row, Mapping):
            out.append(f"{where}: expected a mapping of column name to value, got {_kind(row)}")
            continue

        out.extend(_unknown_columns(row, where, reported_columns))

        value = row.get("value")
        out.extend(_identifier(row, "value", where, label, seen))
        ident = where
        if isinstance(value, str) and value.strip():
            ident = f"{where} value {value.strip()!r}"

        out.extend(_reputation(row, ident))
        out.extend(_expires_at(row, ident))
    return out


# ---------------------------------------------------------------------------
# paths and files
# ---------------------------------------------------------------------------


def _paths_from_env() -> tuple[list[Path], list[str]]:
    raw = os.environ.get("INVENTORY_PATHS", "").strip()
    if not raw:
        return [Path(p) for p in DEFAULT_PATHS], []

    example = json.dumps(list(DEFAULT_PATHS))
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        message = (
            f"INVENTORY_PATHS: not valid JSON ({_one_line(exc)}); "
            f"expected a JSON array of file paths, e.g. {example}"
        )
        return [], [message]
    if not isinstance(parsed, list) or not all(isinstance(p, str) for p in parsed):
        message = (
            f"INVENTORY_PATHS: expected a JSON array of strings, got {parsed!r}; e.g. {example}"
        )
        return [], [message]
    if not parsed:
        message = (
            f"INVENTORY_PATHS: the array is empty, so nothing would be checked or loaded; "
            f"unset the variable to use the defaults {example}"
        )
        return [], [message]
    return [Path(p) for p in parsed], []


def _validate_file(path: Path) -> list[str]:
    source = str(path)
    if not path.is_file():
        return [f"{source}: file not found; INVENTORY_PATHS (or the conf/ default) points here"]

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [f"{source}: cannot be read: {_one_line(exc)}"]

    # DEC-007: route by content, never by position and never by basename — the
    # .example files, and any file the Owner renames, must land on the same
    # checker as their real counterparts.
    if _is_csv(path, text):
        rows, problems = _read_csv(text, source)
        if problems:
            return problems
        return validate_iocs(rows, source)

    doc, problems = _read_yaml(text, source)
    if problems:
        return problems
    if isinstance(doc, Mapping) and "assets" in doc:
        return validate_assets(doc, source)
    if isinstance(doc, Mapping) and "identities" in doc:
        return validate_identities(doc, source)
    message = (
        f"{source}: unrecognised file; expected a CSV of IoCs, or a YAML mapping "
        f"whose top-level key is 'assets' or 'identities'"
    )
    return [message]


def _is_csv(path: Path, text: str) -> bool:
    """True for a `.csv` anywhere in the suffixes, or a first line that is the IoC header."""
    if ".csv" in (suffix.lower() for suffix in path.suffixes):
        return True
    lines = _meaningful_lines(text)
    if not lines:
        return False
    columns = {column.strip().strip('"').lower() for column in lines[0].split(",")}
    return {"value", "reputation"} <= columns


def _meaningful_lines(text: str) -> list[str]:
    """The lines a CSV reader sees: DEC-007 drops blanks and `#` comment lines.

    A `#` inside a quoted field is left alone — only the first non-space
    character of the line is looked at.
    """
    return [
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]


def _read_yaml(text: str, source: str) -> tuple[object, list[str]]:
    try:
        return yaml.safe_load(text), []
    except yaml.YAMLError as exc:
        return None, [f"{source}: YAML parse error: {_one_line(exc)}"]


def _read_csv(text: str, source: str) -> tuple[list[Mapping[str, str]], list[str]]:
    lines = _meaningful_lines(text)
    header = ",".join(IOC_KEYS)
    if not lines:
        return [], [f"{source}: no rows; expected a header row '{header}'"]

    try:
        reader = csv.DictReader(lines)
        rows = list(reader)
    except csv.Error as exc:
        return [], [f"{source}: CSV parse error: {_one_line(exc)}"]

    names = reader.fieldnames or []
    missing = [name for name in ("value", "reputation", "expires_at") if name not in names]
    if missing:
        message = (
            f"{source}: header row is missing the column(s) {', '.join(missing)}; "
            f"expected '{header}'"
        )
        return [], [message]
    return rows, []


# ---------------------------------------------------------------------------
# field rules
# ---------------------------------------------------------------------------


def _envelope(doc: object, key: str, source: str) -> tuple[list[object] | None, list[str]]:
    """Check `version: 1` plus the expected list key; return (items, problems)."""
    if not isinstance(doc, Mapping):
        message = (
            f"{source}: top level: expected a mapping with 'version: 1' and a "
            f"'{key}' list, got {_kind(doc)}"
        )
        return None, [message]

    out: list[str] = []
    if "version" not in doc:
        out.append(f"{source}: version: missing; expected 'version: 1'")
    elif doc["version"] != 1:
        out.append(f"{source}: version: expected 1, got {doc['version']!r}")

    for extra in sorted(str(k) for k in doc if k not in ("version", key)):
        out.append(
            f"{source}: unknown top-level key {extra!r}; expected only 'version' and '{key}'"
        )

    items = doc.get(key)
    if not isinstance(items, list):
        out.append(f"{source}: {key}: expected a list of entries, got {_kind(items)}")
        return None, out
    return items, out


def _identifier(
    item: Mapping[object, object],
    field: str,
    where: str,
    label: str,
    seen: dict[str, str],
) -> list[str]:
    """The primary key of the row: present, a non-empty str, unique within the file."""
    if field not in item or item[field] is None:
        return [f"{where}.{field}: missing; expected a non-empty string"]
    value = item[field]
    if not isinstance(value, str) or not value.strip():
        return [f"{where}.{field}: expected a non-empty string, got {value!r}"]
    value = value.strip()
    if value in seen:
        message = (
            f"{where}.{field}: duplicate {value!r}, already used at {seen[value]}; "
            f"{field} is the primary key and must be unique within the file"
        )
        return [message]
    seen[value] = label
    return []


def _criticality(item: Mapping[object, object], where: str) -> list[str]:
    allowed = _joined(ASSET_CRITICALITY)
    if "criticality" not in item or item["criticality"] is None:
        return [f"{where}.criticality: missing; expected one of {allowed}"]
    value = item["criticality"]
    if isinstance(value, str) and value in RETIRED_CRITICALITY:
        message = (
            f"{where}.criticality: {value!r} no longer exists — DEC-004 moved the database "
            f"onto the {allowed} vocabulary; there is no mapping, choose one of those four"
        )
        return [message]
    if value not in ASSET_CRITICALITY:
        return [f"{where}.criticality: expected one of {allowed}, got {value!r}"]
    return []


def _is_privileged(item: Mapping[object, object], where: str) -> list[str]:
    # Absent means false, exactly as the column's DEFAULT does.
    if "is_privileged" not in item or item["is_privileged"] is None:
        return []
    value = item["is_privileged"]
    if not isinstance(value, bool):
        message = (
            f"{where}.is_privileged: expected a boolean written unquoted (true or false), "
            f"got {value!r}"
        )
        return [message]
    return []


def _optional_text(item: Mapping[object, object], field: str, where: str) -> list[str]:
    if field not in item or item[field] is None:
        return []
    value = item[field]
    if not isinstance(value, str):
        return [f"{where}.{field}: expected a string, got {value!r}"]
    if len(value) > MAX_TEXT_LEN:
        return [f"{where}.{field}: expected at most {MAX_TEXT_LEN} characters, got {len(value)}"]
    return []


def _reputation(row: Mapping[str, str], ident: str) -> list[str]:
    allowed = _joined(IOC_REPUTATION)
    value = row.get("reputation")
    if value is None or (isinstance(value, str) and not value.strip()):
        return [f"{ident}: reputation: missing; expected one of {allowed}"]
    if not isinstance(value, str) or value.strip() not in IOC_REPUTATION:
        return [f"{ident}: reputation: expected one of {allowed}, got {value!r}"]
    return []


def _expires_at(row: Mapping[str, str], ident: str) -> list[str]:
    example = "2030-12-31T00:00:00Z"
    value = row.get("expires_at")
    if value is None or (isinstance(value, str) and not value.strip()):
        return [f"{ident}: expires_at: missing; expected an ISO-8601 UTC timestamp, e.g. {example}"]
    if not isinstance(value, str):
        return [f"{ident}: expires_at: expected a string, got {value!r}"]

    text = value.strip()
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        message = (
            f"{ident}: expires_at: {text!r} is not an ISO-8601 timestamp; expected e.g. {example}"
        )
        return [message]
    if moment.tzinfo is None or moment.utcoffset() is None:
        message = (
            f"{ident}: expires_at: {text!r} carries no timezone; "
            f"expected a UTC offset, e.g. {example}"
        )
        return [message]
    if moment <= _now():
        message = (
            f"{WARNING}{ident}: expires_at: {text!r} is already in the past, so the row is "
            f"invisible to the lookup (... AND expires_at > now()); extend it or delete it"
        )
        return [message]
    return []


def _unknown_keys(item: Mapping[object, object], allowed: tuple[str, ...], where: str) -> list[str]:
    return [
        f"{where}: unknown key {extra!r}; expected only {_joined(allowed, ', ')}"
        for extra in sorted(str(k) for k in item if k not in allowed)
    ]


def _unknown_columns(row: Mapping[str, str], where: str, reported: set[str]) -> list[str]:
    """Column typos are reported once per column, not once per row."""
    out: list[str] = []
    for name in row:
        if name is None:
            # csv.DictReader's restkey: this row has more fields than the header.
            if "" not in reported:
                reported.add("")
                message = (
                    f"{where}: more fields than the header row has columns; "
                    f"expected '{','.join(IOC_KEYS)}'"
                )
                out.append(message)
            continue
        if name not in IOC_KEYS and name not in reported:
            reported.add(name)
            out.append(f"{where}: unknown column {name!r}; expected only {_joined(IOC_KEYS, ', ')}")
    return out


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    # Control timestamps come from the database, but validate() runs with no
    # database at all; this only decides whether to print a warning line.
    return datetime.now(UTC)


def _joined(values: tuple[str, ...], separator: str = " | ") -> str:
    return separator.join(values)


def _kind(value: object) -> str:
    if value is None:
        return "nothing"
    return type(value).__name__


def _one_line(exc: BaseException) -> str:
    return " ".join(str(exc).split())
