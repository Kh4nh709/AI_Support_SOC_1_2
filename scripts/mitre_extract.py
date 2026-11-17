#!/usr/bin/env python3
"""mitre_extract.py — turns the official MITRE ATT&CK Enterprise STIX bundle into the small
extract `kb/mitre/enterprise-attack.json` that the product reads (DEC-223, spec §4.1-§4.2).

  python3 scripts/mitre_extract.py BUNDLE [--out kb/mitre/enterprise-attack.json]
                                          [--source-url URL]
    exit 0 — the extract was written (a one-line summary is printed)
    exit 2 — a usage error, an unreadable file, or a file that is not an ATT&CK Enterprise bundle
             (nothing is written)

BUNDLE is a path on this machine, never a URL: the tool makes no network call (anti-goal A1) and
the 55 MB bundle is never committed (A5). The output is deterministic — techniques sorted by id,
keys sorted, no clock, no host name — so two runs on one bundle give the same bytes.

What the extract holds, per technique or sub-technique of the Enterprise domain: `name`, `tactics`
(ATT&CK's own kill-chain phase names, in its order), `parent` (the id before the dot of a
sub-technique, else null), `status` (live, deprecated or revoked), `platforms`, and `description`:
the first paragraph of MITRE's text, cleaned (citation marks removed, Markdown links reduced to
their text, HTML tags removed, white space collapsed) and cut at 600 characters on a word boundary.
Nothing is added or reworded (A2).

A revoked or deprecated technique keeps its own name, tactics and description. Nothing about what
replaced it is read or stored (Owner, 17/11): the bundle's `revoked-by` relationships are ignored,
and MITRE's deprecation notice — the first paragraph of a deprecated technique, "This technique has
been deprecated. Please use X" — is not a description, so the next paragraph is.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

#: The domain this tool extracts and the loader (`backend/app/kb/mitre.py`) accepts.
DOMAIN = "enterprise-attack"
#: This tool's name, recorded in the extract's header.
EXTRACTED_BY = "scripts/mitre_extract.py"
#: Where the official bundles live; `main` appends the bundle's file name unless `--source-url`.
SOURCE_URL_BASE = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/"
)
#: The longest a description may be, the ` …` included. `backend/app/kb/mitre.py` has the same
#: number; `tests/test_kb_mitre.py` ties the two together.
DESCRIPTION_MAX_CHARS = 600
ELLIPSIS = " …"
#: MITRE's licence for ATT&CK, which asks for its copyright designation and this licence to be
#: reproduced in any copy (the copyright line itself is read from the bundle).
TERMS = (
    "The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use"
    " ATT&CK for research, development, and commercial purposes. Any copy you make for such"
    " purposes is authorized provided that you reproduce MITRE's copyright designation and this"
    " license in any such copy. ATT&CK Terms of Use:"
    " https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"
)

_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.ASCII)
#: A citation mark, with the white space before it: `(Citation: Name of the source)`.
_CITATION_RE = re.compile(r"\s*\(Citation:[^)]*\)")
#: `[text](url)` -> `text`. MITRE's links hold no nested bracket or parenthesis.
_LINK_RE = re.compile(r"\[([^\]]*)\]\([^)]*\)")
#: The HTML tags MITRE's text uses for formatting. Placeholders it writes between angle brackets
#: (`<DOMAIN>`, `<username>`) are its text, not markup, and stay.
_HTML_TAG_RE = re.compile(r"</?(?:code|pre|b|i|u|em|strong|p|br|sub|sup)\s*/?>", re.IGNORECASE)
_BREAK_RE = re.compile(r"<br\s*/?>", re.IGNORECASE)
_PARAGRAPH_RE = re.compile(r"\n[ \t]*\n")
_SPACE_RE = re.compile(r"\s+")
#: MITRE's own first paragraph of a deprecated technique: `**This technique has been deprecated.
#: Please use [X](...) where appropriate.**`, or `This technique is deprecated due to ...`. It is a
#: word about status and, mostly, a replacement; the description is the paragraph after it.
_NOTICE_RE = re.compile(r"^\W*this (?:sub-?)?technique (?:has been|is) deprecated", re.IGNORECASE)
#: The same bold notice pasted by mistake inside a sentence of MITRE's text (T1153 in 20.1 has it in
#: the middle of a `<code>` span): it is dropped wherever it stands.
_INLINE_NOTICE_RE = re.compile(
    r"\*\*This (?:sub-?)?technique has been deprecated[^*]*\*\*", re.IGNORECASE
)


class NotAnEnterpriseBundle(ValueError):
    """The file is not an ATT&CK Enterprise STIX bundle."""


def clean_description(text: str) -> str:
    """The description of one technique: MITRE's first paragraph, cleaned and cut.

    A leading deprecation notice is skipped (see the module docstring). The result is at most
    `DESCRIPTION_MAX_CHARS` characters, ` …` included, and is empty when MITRE's text has no
    paragraph but the notice."""
    if not isinstance(text, str):
        return ""
    paragraphs = [p for p in _PARAGRAPH_RE.split(text.strip()) if p.strip()]
    while paragraphs and _NOTICE_RE.match(paragraphs[0].strip()):
        paragraphs.pop(0)
    if not paragraphs:
        return ""
    paragraph = paragraphs[0]
    paragraph = _INLINE_NOTICE_RE.sub("", paragraph)
    paragraph = _CITATION_RE.sub("", paragraph)
    paragraph = _LINK_RE.sub(r"\1", paragraph)
    paragraph = _BREAK_RE.sub(" ", paragraph)
    paragraph = _HTML_TAG_RE.sub("", paragraph)
    paragraph = _SPACE_RE.sub(" ", paragraph).strip()
    return _cut(paragraph)


def _cut(text: str) -> str:
    if len(text) <= DESCRIPTION_MAX_CHARS:
        return text
    limit = DESCRIPTION_MAX_CHARS - len(ELLIPSIS)
    head = text[:limit]
    if not text[limit].isspace() and " " in head:  # the limit falls inside a word: back up
        head = head.rsplit(" ", 1)[0]
    return head.rstrip() + ELLIPSIS


def _technique_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id")
            if isinstance(external_id, str) and _ID_RE.match(external_id):
                return external_id
    return None


def _status(obj: dict[str, Any]) -> str:
    if obj.get("revoked") is True:
        return "revoked"
    if obj.get("x_mitre_deprecated") is True:
        return "deprecated"
    return "live"


def _tactics(obj: dict[str, Any]) -> list[str]:
    return [
        phase["phase_name"]
        for phase in obj.get("kill_chain_phases") or []
        if isinstance(phase, dict)
        and phase.get("kill_chain_name") == "mitre-attack"
        and isinstance(phase.get("phase_name"), str)
    ]


def _copyright(objects: list[Any], collection: dict[str, Any]) -> str:
    """The statement of the marking the collection carries, else the first copyright statement."""
    statements: dict[str, str] = {}
    for obj in objects:
        if isinstance(obj, dict) and obj.get("type") == "marking-definition":
            statement = (obj.get("definition") or {}).get("statement")
            if isinstance(statement, str) and isinstance(obj.get("id"), str):
                statements[obj["id"]] = statement
    for ref in collection.get("object_marking_refs") or []:
        if ref in statements:
            return statements[ref]
    for statement in statements.values():
        if statement.startswith("Copyright"):
            return statement
    return ""


def build_extract(bundle: dict, *, source_sha256: str, source_url: str) -> dict:
    """The extract of an ATT&CK Enterprise bundle (spec §4.2) as a plain dict.

    Raises `NotAnEnterpriseBundle` when `bundle` is not one: not a STIX bundle, no
    `x-mitre-collection` with a version, or no technique of the `enterprise-attack` domain."""
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise NotAnEnterpriseBundle("not a STIX bundle")
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise NotAnEnterpriseBundle("a STIX bundle has an `objects` list")
    objects = [o for o in objects if isinstance(o, dict)]
    collections = [o for o in objects if o.get("type") == "x-mitre-collection"]
    if len(collections) != 1:
        raise NotAnEnterpriseBundle("expected exactly one x-mitre-collection object")
    collection = collections[0]
    version, modified = collection.get("x_mitre_version"), collection.get("modified")
    if not (isinstance(version, str) and version and isinstance(modified, str) and modified):
        raise NotAnEnterpriseBundle("the x-mitre-collection has no version or no modified date")

    techniques: dict[str, dict[str, Any]] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if DOMAIN not in (obj.get("x_mitre_domains") or []):
            continue
        technique_id = _technique_id(obj)
        name = obj.get("name")
        if technique_id is None or not isinstance(name, str) or not name:
            continue
        techniques[technique_id] = {
            "name": name,
            "tactics": _tactics(obj),
            "parent": technique_id.split(".")[0] if "." in technique_id else None,
            "status": _status(obj),
            "platforms": [p for p in obj.get("x_mitre_platforms") or [] if isinstance(p, str)],
            "description": clean_description(obj.get("description") or ""),
        }
    if not techniques:
        raise NotAnEnterpriseBundle(f"no technique of the {DOMAIN} domain")

    return {
        "header": {
            "domain": DOMAIN,
            "version": version,
            "modified": modified,
            "source_sha256": source_sha256,
            "source_url": source_url,
            "copyright": _copyright(objects, collection),
            "terms": TERMS,
            "extracted_by": EXTRACTED_BY,
        },
        "techniques": dict(sorted(techniques.items())),
    }


def render(extract: dict) -> str:
    """The stable text of an extract: sorted keys, text kept as it is, a trailing newline."""
    return json.dumps(extract, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def _default_out() -> Path:
    return Path(__file__).resolve().parents[1] / "kb" / "mitre" / "enterprise-attack.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mitre_extract.py",
        description="Extract the ATT&CK Enterprise techniques from an official STIX bundle.",
    )
    parser.add_argument("bundle", help="path of the bundle on this machine (never a URL)")
    parser.add_argument(
        "--out", default=None, help="where to write (default: kb/mitre/enterprise-attack.json)"
    )
    parser.add_argument(
        "--source-url",
        default=None,
        help="where the bundle was downloaded from, recorded in the header"
        " (default: the official repository's URL for the bundle's file name)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exit_:  # argparse: 2 on a usage error, 0 for --help
        return int(exit_.code or 0)
    bundle_path = Path(args.bundle)
    if "://" in args.bundle:
        print("mitre_extract: BUNDLE is a path on this machine, not a URL", file=sys.stderr)
        return 2
    try:
        raw = bundle_path.read_bytes()
    except OSError as exc:
        print(f"mitre_extract: cannot read {bundle_path}: {exc.strerror or exc}", file=sys.stderr)
        return 2
    try:
        bundle = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        print(
            f"mitre_extract: {bundle_path} is not an ATT&CK Enterprise bundle (not JSON)",
            file=sys.stderr,
        )
        return 2
    source_url = args.source_url or SOURCE_URL_BASE + bundle_path.name
    try:
        extract = build_extract(
            bundle, source_sha256=hashlib.sha256(raw).hexdigest(), source_url=source_url
        )
    except NotAnEnterpriseBundle as exc:
        print(
            f"mitre_extract: {bundle_path} is not an ATT&CK Enterprise bundle ({exc})",
            file=sys.stderr,
        )
        return 2
    out = Path(args.out) if args.out else _default_out()
    out.parent.mkdir(parents=True, exist_ok=True)
    text = render(extract)
    out.write_bytes(text.encode("utf-8"))
    counts = {"live": 0, "revoked": 0, "deprecated": 0}
    for entry in extract["techniques"].values():
        counts[entry["status"]] += 1
    print(
        f"mitre_extract: wrote {out} — ATT&CK {extract['header']['version']},"
        f" {len(extract['techniques'])} techniques"
        f" ({counts['live']} live, {counts['revoked']} revoked, {counts['deprecated']} deprecated),"
        f" {len(text.encode('utf-8'))} bytes"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
