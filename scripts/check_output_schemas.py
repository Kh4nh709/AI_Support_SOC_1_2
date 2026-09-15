#!/usr/bin/env python3
"""check_output_schemas.py — proves output_schemas.json and the context pack agree.

Same shape as docs/Schema/build_schema.py and scripts/gen_env_example.py: a
transcribed artifact whose drift from its source would otherwise be invisible
gets a --check wired into `make lint` (DEC-047). Unlike those two,
output_schemas.json is not machine-generated from its source — §6.2 is a
frozen contract, hand-transcribed once (P3-T05) — so this script only checks,
it never writes.

  python3 scripts/check_output_schemas.py --check
    exit 0 — the two parse to equal structures; prints the one-line confirmation
    exit 1 — they differ; prints a unified diff of the two pretty-printed forms
    exit 2 — either source is unreadable (missing file, bad JSON, no §6.2 block)

The comparison is by parsed value (json.loads equality), never by text —
backend/app/llm/templates/output_schemas.json's own pretty-printing is free;
only meaning is pinned.
"""

from __future__ import annotations

import difflib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "docs" / "plan" / "00-context-pack.md"
SCHEMAS = ROOT / "backend" / "app" / "llm" / "templates" / "output_schemas.json"


def context_pack_block_text() -> str:
    """The first ```json fenced block after the line starting '### 6.2'."""
    lines = PACK.read_text(encoding="utf-8").splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("### 6.2")), None)
    if start is None:
        raise ValueError(f"{PACK}: no line starting '### 6.2'")
    fence_open = next(
        (i for i in range(start + 1, len(lines)) if lines[i].strip() == "```json"), None
    )
    if fence_open is None:
        raise ValueError(f"{PACK}: no ```json fence found after '### 6.2'")
    fence_close = next(
        (i for i in range(fence_open + 1, len(lines)) if lines[i].strip() == "```"), None
    )
    if fence_close is None:
        raise ValueError(f"{PACK}: unterminated ```json fence after '### 6.2'")
    return "\n".join(lines[fence_open + 1 : fence_close])


def main() -> int:
    try:
        pack_obj = json.loads(context_pack_block_text())
    except Exception as exc:  # noqa: BLE001 — reported to the caller, not swallowed
        print(f"check_output_schemas: cannot read §6.2 from {PACK}: {exc}", file=sys.stderr)
        return 2

    try:
        file_obj = json.loads(SCHEMAS.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"check_output_schemas: cannot read {SCHEMAS}: {exc}", file=sys.stderr)
        return 2

    if file_obj == pack_obj:
        print("output_schemas.json == context pack §6.2")
        return 0

    file_pretty = json.dumps(file_obj, indent=2, sort_keys=True).splitlines()
    pack_pretty = json.dumps(pack_obj, indent=2, sort_keys=True).splitlines()
    print("output_schemas.json != context pack §6.2. Diff (file vs pack):")
    for line in difflib.unified_diff(
        file_pretty,
        pack_pretty,
        str(SCHEMAS.relative_to(ROOT)),
        "context pack §6.2",
        lineterm="",
    ):
        print("  " + line)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
