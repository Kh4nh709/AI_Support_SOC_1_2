#!/usr/bin/env python3
"""Generate .env.example's contract block from context pack §6.3 — the single source.

Same shape as docs/Schema/build_schema.py, which regenerates schema.sql from the
migrations and has never drifted. §6.3 and .env.example have drifted twice (DEC-003
added three keys by hand; DEC-013/DEC-024 changed two defaults by hand), which is why
this exists and why P0-T02's acceptance 7 had to compare them by script.

  python3 scripts/gen_env_example.py            # rewrite the block in place
  python3 scripts/gen_env_example.py --check    # exit 1 if .env.example has drifted

Only the CONTRACT block is generated, between the two markers below. Everything else in
.env.example — the Compose-only variables DEC-003 deliberately kept out of §6.3, comments,
host-specific defaults — is hand-written and preserved untouched.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACK = ROOT / "docs" / "plan" / "00-context-pack.md"
ENV = ROOT / ".env.example"
BEGIN = (
    "# --- BEGIN generated from context pack §6.3 — edit §6.3, then run scripts/gen_env_example.py"
)
END = "# --- END generated from context pack §6.3"


def keys_from_pack() -> list[str]:
    """Every KEY named in §6.3's fenced block, in the order §6.3 lists them."""
    text = PACK.read_text(encoding="utf-8")
    block = text.split("### 6.3 Config constants")[1].split("```")[1]
    # Drop parenthetical annotations first. §6.3 documents keys inline, e.g.
    # `DATABASE_URL(app runtime, role app_rw - a LOGIN role over TCP ...)`, and the
    # uppercase prose inside those parens is not a key. Stripping them is what keeps
    # this from inventing LOGIN and TCP as config constants.
    block = re.sub(r"\([^)]*\)", "", block)
    out: list[str] = []
    for match in re.finditer(r"(?m)(?:^|\s)([A-Z][A-Z0-9_]{2,})(?=\s*[=(\s]|$)", block):
        key = match.group(1)
        if key not in out:
            out.append(key)
    return out


def existing_values() -> dict[str, str]:
    """Keep whatever value .env.example already carries; only the key SET is derived."""
    values: dict[str, str] = {}
    if ENV.exists():
        for line in ENV.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^\s*([A-Z][A-Z0-9_]{2,})=(.*)$", line)
            if m:
                values[m.group(1)] = m.group(2)
    return values


def render() -> str:
    values = existing_values()
    lines = [BEGIN, "#     Do not add or rename a key here — §6.3 is a frozen contract (DEC-003)."]
    for key in keys_from_pack():
        lines.append(f"{key}={values.get(key, '')}")
    lines.append(END)
    return "\n".join(lines)


def main() -> int:
    check = "--check" in sys.argv
    generated = render()
    current = ENV.read_text(encoding="utf-8") if ENV.exists() else ""

    if BEGIN in current and END in current:
        head, rest = current.split(BEGIN, 1)
        _, tail = rest.split(END, 1)
        updated = head + generated + tail
    else:
        # First run: MIGRATE, do not append. The contract keys already exist as
        # hand-written lines; appending the block would duplicate all 53 of them.
        # Lift them out, and put the generated block where the first one stood so
        # the file's comment structure and its Compose-only block survive.
        contract = set(keys_from_pack())
        kept: list[str] = []
        placed = False
        for line in current.splitlines():
            m = re.match(r"^\s*([A-Z][A-Z0-9_]{2,})=", line)
            if m and m.group(1) in contract:
                if not placed:
                    kept.append(generated)
                    placed = True
                continue  # its value is already carried into the block
            kept.append(line)
        if not placed:
            kept.append("")
            kept.append(generated)
        updated = "\n".join(kept).rstrip("\n") + "\n"

    if check:
        if updated != current:
            missing = set(keys_from_pack()) - set(existing_values())
            print(
                "gen_env_example: .env.example has DRIFTED from context pack §6.3", file=sys.stderr
            )
            if missing:
                print(
                    f"  keys in §6.3 and absent from .env.example: {sorted(missing)}",
                    file=sys.stderr,
                )
            print("  run: python3 scripts/gen_env_example.py", file=sys.stderr)
            return 1
        print(f"gen_env_example: .env.example matches §6.3 · {len(keys_from_pack())} keys")
        return 0

    ENV.write_text(updated, encoding="utf-8")
    print(f"gen_env_example: wrote {len(keys_from_pack())} contract keys into .env.example")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
