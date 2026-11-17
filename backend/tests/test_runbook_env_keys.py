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


def test_the_autoclose_switch_row_warns_that_the_pages_to_review_its_rules_are_gone():
    """P15-T01 (DEC-214): with `true`, an alert is closed by a rule; the UI has no page that shows the rules or
    reviews the digest any more, so the row says it is not switched on again before the pages come back.
    """
    what, who, secret = (
        cell.strip() for cell in _rows()["AUTOCLOSE_ENABLED"].rstrip("|").split(" | ")
    )
    assert who == "Owner" and secret == "no"
    assert "DEC-214" in what
    assert "no rules page and no digest page" in what
    assert "no page shows" in what and "nobody can review" in what
    assert "unless the two pages come back first" in what


def test_the_rule_width_row_says_only_the_api_reports_it_now():
    """P15-T01 fix round 1 (D2): the rules page that showed the width and its warning is gone (DEC-214); the
    threshold is still read by `GET /api/admin/rules` (`width_threshold_pct`), and the row says so.
    """
    what, who, secret = (
        cell.strip() for cell in _rows()["AUTOCLOSE_RULE_WIDTH_PCT"].rstrip("|").split(" | ")
    )
    assert who == "default" and secret == "no"
    assert "reported as too wide" not in what
    assert "DEC-214" in what and "GET /api/admin/rules" in what and "`width_threshold_pct`" in what


def test_the_dec_207_limitation_says_the_pages_are_gone_and_no_page_shows_the_digest():
    """P15-T01 (DEC-214; fix round 1, D1): item 3 says the table and the backend stay and the two pages are gone;
    item 5's sentence on the default count of 1 names only the pages that still show it."""
    text = (REPO_ROOT / "docs" / "limitations.md").read_text(encoding="utf-8")
    item = " ".join(text.split("### (xlvi) ")[1].split("\n### ")[0].split())
    assert "the `autoclose_rules` table and the backend stay" in item
    assert "the rules page and the digest page are gone from the UI, DEC-214" in item
    assert "the queue and the alert page show it" in item
    assert "the alert page and the digest show it" not in item


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
    # DEC-217: step 4 is a warning beside the model's verdict now, no longer a hold as `needs_review`
    assert "flags every ① `false_positive`" in section
    assert "forces every ① `false_positive` to `needs_review`" not in section
    assert "severity base alone" in section
    assert "auto-close digest is empty" in section
    assert "`n/a — enrichment off`" in section  # the inventory_empty alarm


def test_the_soar_intake_section_says_the_heartbeat_is_stamped_only_with_the_pull_off():
    """Fix round 1 (review finding 2, the Director's ruling): the stamp is a SOAR-mode thing."""
    section = _soar_section()
    bullet = [ln for ln in section.splitlines() if ln.startswith("- **The heartbeat**")]
    assert len(bullet) == 1, "the heartbeat bullet is gone"
    text = bullet[0]
    assert "only when `PULL_ENABLED=false`" in text
    assert "stamped by every alert the webhook accepts" in text
    assert "(not by a `409`, and not by a body that is refused)" in text
    # with the pull on, as before DEC-207: a dead pull still turns the alarm red
    assert (
        "With the pull on" in text
        and "a pull that died still turns the `heartbeat` alarm red" in text
    )
    # and the intro's "merging the change alters nothing" is true again: the defaults stamp nothing
    assert "merging the change alters nothing" in section


def test_rollback_level_1_warns_of_the_pull_catch_up_and_the_cursor_check():
    """Fix rounds 1 and 2 (review findings): turning the pull back on is not "the behaviour of
    before, for alerts that arrive afterwards"; it pulls in the whole off-window, and after SOAR
    mode that window holds every alert SOAR already posted, under keys the intake does not match."""
    section = _soar_section()
    level_1 = section.split("1. **The flags.**")[1].split("2. **The code.**")[0]
    # the window, in one unit (milliseconds; the overlap is in seconds)
    assert "catches up" in level_1 and "`last_sort - PULL_OVERLAP_S × 1000`" in level_1
    assert "`last_sort - PULL_OVERLAP_S`" not in level_1  # the mixed-unit spelling
    # what the catch-up costs: a ① run on every alert not grouped as a duplicate, auto-closed
    # ones included (D8), and those fill the next 08:00 digest
    assert "not grouped as a duplicate" in level_1 and "① run" in level_1
    assert "the auto-closed ones included (D8)" in level_1 and "08:00 digest" in level_1
    # stated plainly: the alerts SOAR already posted come in again, under other keys
    assert "re-ingests every alert SOAR already posted" in level_1
    assert "`gl-…`" in level_1 and "`graylog`" in level_1 and "second ① run" in level_1
    assert "dropped by the intake key" not in level_1  # the claim that is not true of SOAR's keys
    # unless the Owner wants that: the cursor is moved BEFORE the pull is turned on, by the Owner
    assert "moved to the switch-back time before the pull is turned on" in level_1
    assert "the Owner's decision" in level_1 and "never done silently" in level_1
    check = 'psql "$DATABASE_URL" -Atc "select last_sort, last_pull_at from source_cursor"'
    assert check in level_1  # the read-only check
    assert "update source_cursor" not in level_1.lower()  # and no statement that changes it
    # the row of What to watch while the pull is off: first column false, second says the last
    # pull's outcome
    assert "a pull in the last 5 min" in level_1 and "`f|…`" in level_1
    assert "`f|t`" in level_1 and "`f|f`" in level_1
    assert "behaviour of before, for alerts that arrive afterwards" not in level_1


def test_no_file_still_says_every_alert_carries_the_unknown_context():
    """P12-T02 fix round 1 (DEC-209 item 3): since DEC-208 the context of an alert comes from the
    payload's `enrichment`, and only an alert without a valid block gets the unknown one. The runbook
    key row, its switch bullet and its "what to expect" paragraph, the `.env.example` line, the context
    pack's switch line and the comment in `infra/config.py` all say so, and none says "every alert".
    """
    pack = (REPO_ROOT / "docs" / "plan" / "00-context-pack.md").read_text(encoding="utf-8")
    switch_line = next(ln for ln in pack.splitlines() if ln.startswith("PULL_ENABLED=true"))
    env_line = next(
        ln
        for ln in ENV_EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()
        if ln.startswith("ENRICHMENT_ENABLED=")
    )
    config_py = (REPO_ROOT / "backend" / "app" / "infra" / "config.py").read_text(encoding="utf-8")
    config_comment = config_py.split("ENRICHMENT_ENABLED=false:")[1].split("PULL_ENABLED: bool")[0]
    row = _rows()["ENRICHMENT_ENABLED"]
    section = _soar_section()
    bullet = next(
        ln for ln in section.splitlines() if ln.startswith("- `ENRICHMENT_ENABLED=false`:")
    )
    paragraph = next(
        ln for ln in section.splitlines() if ln.startswith("- **The context comes from")
    )

    for name, text in (
        ("runbook key row", row),
        ("runbook switch bullet", bullet),
        ("runbook paragraph", paragraph),
        (".env.example", env_line),
        ("context pack §6.3 line", switch_line),
        ("config.py comment", config_comment),
    ):
        flat = " ".join(text.split())
        assert "every alert carries the" not in flat, name
        assert "DEC-208" in flat, name
        assert "else the unknown context" in flat or "else the unknown" in flat, name
    assert "payload's `enrichment`" in row and "payload's `enrichment`" in bullet
    # the consequences stay, for an alert that has the unknown context
    assert "for an alert with the unknown context" in paragraph


# --- P14-T04 / DEC-213: the one runbook section of the Voyage vector RAG --------------------------

VOYAGE_TITLE = "Voyage vector RAG (DEC-213)"
VOYAGE_HEADING = f"\n### {VOYAGE_TITLE}\n"
OLD_TITLE = "Vector database (DEC-213)"
COMPOSE_RAG_PATH = REPO_ROOT / "docker-compose.rag.yml"


def _voyage_section() -> str:
    assert (
        VOYAGE_HEADING in _keys_section() + "\n"
    ), "the runbook has no 'Voyage vector RAG' section"
    return (_keys_section() + "\n").split(VOYAGE_HEADING)[1].split("\n### ")[0]


def test_the_voyage_section_comes_first_with_trial_only_never_on_live():
    section = _voyage_section()
    first = next(line for line in section.splitlines() if line.strip())
    assert first.startswith("**Trial only, never on live.**"), first
    assert "never merged into `main`" in first
    assert not [ln for ln in section.splitlines() if KEY_ROW_RE.match(ln)]  # no second key row


def test_the_old_title_is_gone_and_the_three_references_name_the_new_one():
    for path in (RUNBOOK_PATH, COMPOSE_RAG_PATH, ENV_EXAMPLE_PATH):
        assert OLD_TITLE not in path.read_text(encoding="utf-8"), path.name
    assert f'docs/runbook.md, "{VOYAGE_TITLE}"' in COMPOSE_RAG_PATH.read_text(encoding="utf-8")
    env_line = next(
        ln
        for ln in ENV_EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()
        if ln.startswith("VOYAGE_API_KEY=")
    )
    assert VOYAGE_TITLE in env_line
    assert f"**{VOYAGE_TITLE.rsplit(' (', 1)[0]}**" in _rows()["VECTOR_DATABASE_URL"]


def test_the_section_says_only_rag_worker_can_reach_vectordb_because_of_the_internal_network():
    section = " ".join(_voyage_section().split())
    assert "only `rag-worker` can reach `vectordb`" in section
    assert "`vector`" in section and "`internal: true`" in section
    assert "no `ports:`" in section
    assert "`app`, `worker` and `ui` are not on `vector`" in section
    assert "by address" not in section and "no address for it" not in section


def test_the_check_is_the_test_z_one_for_app_and_worker_and_prints_no_value():
    section = _voyage_section()
    for service in ("app", "worker"):
        check = f"docker compose exec -T {service} sh -c 'test -z \"$VECTOR_DATABASE_URL\" && echo none'"
        assert check in section, service
    assert "wc -c" not in section and "printenv" not in section


def test_the_section_says_what_is_true_now_that_the_voyage_rag_is_built():
    """P14-T04 wrote the section when the contracts were all there was ("no Voyage call in any code yet",
    "no worker claims it yet", "an empty pgvector server"). P14-T05/T06 built the rest and P14-T08 wrote the
    steps: the section must say what exists, with the rebuild and check commands, and not the stub.
    """
    section = " ".join(_voyage_section().split())
    for stale in (
        "no Voyage call in any code yet",
        "There is no Voyage call in any code yet",
        "no worker claims it yet",
        "is an empty pgvector server: it has no table",
    ):
        assert stale not in section, stale
    for now in (
        "which `rag-worker` claims",
        "calls **no model**",
        "no fallback to an LLM ranker",
        "python -m app.rag.vector_index --rebuild",
        "python -m app.rag.vector_index --check",
    ):
        assert now in section, now


def test_the_migration_row_of_start_everything_names_the_trial_and_the_p14_migrations():
    """022 (P14-T01, the rename: it refuses while a triage run still says `escalate`), 023 (P14-T04,
    the Voyage RAG contracts) and 024 (P14-T09, the lab: all three on the trial branch only) are in the row.
    P14-T08: the trial's database stands at 20 after the wipe (spec §11), so it is the `4 applied, 20 already
    present` entry that names it, and the entry for a dump taken after 021 does not carry the refusal (the
    list holds the counts of a database with no `escalate`; one that has any stops at 022, above it).
    """
    row = next(
        ln
        for ln in RUNBOOK_PATH.read_text(encoding="utf-8").splitlines()
        if ln.startswith("| start everything |")
    )
    assert "on a dump taken after 020 or on the trial database as the wipe left it" in row
    assert "on a dump taken after 021 (it applies `022_true_positive.sql`" in row
    assert (
        "refuses while a `triage` run still says `escalate`" in row
        and "`023_vector_rag.sql`" in row
    )
    assert "on the live database today" not in row and "on the trial database today" not in row
    assert "there is no 022" not in row and "the number belongs to another card" not in row
    assert "`024_lab.sql`: the lab runs and labels" in row  # P14-T09: the trial takes all three
    assert "`migrate: 6 applied, 20 already present`" in row  # 021 to 026 (DEC-224 T1 added 026)
    assert "`migrate: 5 applied, 21 already present`" in row
    assert "`026_threat_intel.sql`" in row
    assert "`migrate: 0 applied, 26 already present` after that." in row
