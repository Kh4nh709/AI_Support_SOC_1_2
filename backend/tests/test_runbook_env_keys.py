"""`docs/runbook.md` `## Environment keys` against `.env.example` and context pack §6.3 (P10-T16).

The table is "the N keys of `.env.example`, one row each". `.env.example` is the §6.3 keys plus the
Compose-only variables DEC-003 kept out of §6.3, and `scripts/gen_env_example.py` (checked by
`make lint`) keeps it equal to §6.3. Nothing kept the runbook's table equal to either: P10-T15 added
`DEDUP_ENABLED` to §6.3 and `.env.example`, and the table stayed at 62 rows with "The 62 keys" above
it. These tests pin the table to both sources, and its count sentence to its rows.

PURE. No database, no socket, no fixture: reads `docs/runbook.md`, `.env.example` and context pack
§6.3 (through the generator's own parser).
"""

from __future__ import annotations

import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import gen_env_example

RUNBOOK_PATH = REPO_ROOT / "docs" / "runbook.md"
ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"

# A table row whose first cell is one backticked KEY. The `###` subsections that follow the table
# are inside `## Environment keys` (the split is on `\n## `, which `\n### ` does not match).
KEY_ROW_RE = re.compile(r"(?m)^\| `([A-Z][A-Z0-9_]+)` \| (.*)$")
COUNT_SENTENCE_RE = re.compile(r"The (\d+) keys of `\.env\.example`")


def _keys_section() -> str:
    text = RUNBOOK_PATH.read_text(encoding="utf-8")
    return text.split("\n## Environment keys")[1].split("\n## ")[0]


def _rows() -> dict[str, str]:
    rows: dict[str, str] = {}
    for key, rest in KEY_ROW_RE.findall(_keys_section()):
        assert key not in rows, f"## Environment keys has two rows for {key}"
        rows[key] = rest
    return rows


def _env_example_keys() -> list[str]:
    keys = []
    for line in ENV_EXAMPLE_PATH.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\s*([A-Z][A-Z0-9_]{2,})=", line)
        if match:
            keys.append(match.group(1))
    return keys


def test_every_context_pack_key_has_a_row():
    missing = sorted(set(gen_env_example.keys_from_pack()) - set(_rows()))
    assert not missing, f"context pack §6.3 keys with no runbook row: {missing}"


def test_the_table_is_the_env_example_keys_and_nothing_else():
    rows, example = set(_rows()), set(_env_example_keys())
    assert example - rows == set(), f".env.example keys with no row: {sorted(example - rows)}"
    assert rows - example == set(), f"rows that are not .env.example keys: {sorted(rows - example)}"


def test_the_row_count_is_the_pack_keys_plus_the_compose_only_keys():
    pack = set(gen_env_example.keys_from_pack())
    compose_only = set(_env_example_keys()) - pack
    assert compose_only, "the Compose-only variables (DEC-003) are no longer in .env.example"
    assert len(_rows()) == len(pack) + len(compose_only)


def test_the_count_sentence_is_the_number_of_rows():
    found = COUNT_SENTENCE_RE.findall(_keys_section())
    assert len(found) == 1, "## Environment keys must say 'The N keys of `.env.example`' once"
    assert int(found[0]) == len(_rows())


def test_the_dedup_enabled_row_says_default_true_forward_only_and_how_to_apply_it():
    row = _rows()["DEDUP_ENABLED"]
    what, who, secret = (cell.strip() for cell in row.rstrip("|").split(" | "))
    # By the table's own legend: *default* is `.env.example`'s value, changed only by a DEC; the
    # live value here (false) differs from it and is the Owner's, set in `.env` (DEC-165).
    assert who == "Owner" and secret == "no"
    assert "`true`" in what and "DEC-165" in what
    assert "forward-only" in what
    # the recreate command the Owner runs: a plain `restart` keeps the container's old environment
    assert "docker compose up -d --force-recreate app worker" in what
    assert "Grouping switch" in what


# --- P12-T01 / DEC-207: the three SOAR intake switches ------------------------------------------

_SOAR_KEYS = ("PULL_ENABLED", "AUTOCLOSE_ENABLED", "ENRICHMENT_ENABLED")
SOAR_HEADING = "\n### SOAR intake (DEC-207)\n"


def _soar_section() -> str:
    text = RUNBOOK_PATH.read_text(encoding="utf-8")
    assert SOAR_HEADING in text, "the runbook has no 'SOAR intake (DEC-207)' section"
    return text.split(SOAR_HEADING)[1].split("\n## ")[0]


@pytest.mark.parametrize("key", _SOAR_KEYS)
def test_a_soar_switch_row_says_true_false_dec_207_and_where_the_how_to_is(key):
    row = _rows()[key]
    what, who, secret = (cell.strip() for cell in row.rstrip("|").split(" | "))
    assert who == "Owner" and secret == "no"  # the live value is the Owner's, in `.env`
    assert "`true`" in what and "`false`" in what and "(DEC-207)" in what
    assert "recreate the containers" in what  # a plain `restart` keeps the old environment
    assert "**SOAR intake (DEC-207)**" in what


@pytest.mark.parametrize("key", _SOAR_KEYS)
def test_a_soar_switch_is_a_pack_key_and_an_env_example_key_with_a_true_default(key):
    assert key in gen_env_example.keys_from_pack()
    assert key in _env_example_keys()
    assert f"\n{key}=true" in ENV_EXAMPLE_PATH.read_text(encoding="utf-8")


def test_the_soar_intake_section_is_inside_the_environment_keys_section():
    assert SOAR_HEADING in _keys_section() + "\n"  # `_keys_section` is cut at the next `## `


def test_the_soar_intake_section_lists_the_four_switches_all_true_by_default():
    section = _soar_section()
    assert "all `true` by default" in section
    for key in (*_SOAR_KEYS, "DEDUP_ENABLED"):
        assert f"\n- `{key}=false`: " in section, key
    # a bullet, not a `| `KEY` |` row: `_rows()` reads every such line of `## Environment keys` as
    # a key's row, and a second row for one key is an error
    assert not [ln for ln in section.splitlines() if KEY_ROW_RE.match(ln)]


def test_the_soar_intake_section_says_up_d_not_restart_and_how_to_check_with_printenv():
    section = _soar_section()
    assert "**`up -d`, not `restart`**" in section
    assert "docker compose up -d app worker" in section
    assert "printenv | grep -E" in section
    for key in ("DEDUP", "PULL", "AUTOCLOSE", "ENRICHMENT"):
        assert key in section.split("printenv | grep -E")[1].split("\n")[0], key
    assert "--force-recreate" in section  # the fallback when a value did not change
    assert "`docker compose restart app worker`" in section  # the merge itself is code-only


def test_the_soar_intake_section_gives_the_three_rollback_levels_in_order():
    section = _soar_section()
    levels = ["1. **The flags.**", "2. **The code.**", "3. **The data.**"]
    positions = [section.index(level) for level in levels]
    assert positions == sorted(positions)
    assert "checkpoint/pre-soar-intake" in section
    assert "make db-restore FILE=" in section
    assert "make backup" in section  # taken before switching
    assert "no migration" in section  # why levels 1 and 2 never need level 3


def test_the_soar_intake_section_names_the_consequences_of_the_unknown_context():
    section = _soar_section()
    assert "forces every ① `false_positive` to `needs_review`" in section
    assert "severity base alone" in section
    assert "auto-close digest is empty" in section
    assert "`n/a — enrichment off`" in section  # the inventory_empty alarm
    assert "stamped by every alert the webhook accepts" in section  # the heartbeat
