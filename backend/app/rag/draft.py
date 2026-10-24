"""Drafts of learned knowledge from conclusions: the source record, V1-V5, and the `knowledge_draft`
job (P13-T04, DEC-210, spec §7.3, §7.4 and §7.7).

When an analyst closes an alert (`transitions.decide`) or concludes a case (`transitions.conclude_case`),
`rag-worker` runs `run_draft_job` for that subject. It writes a `knowledge_drafts` row an admin reviews
(P13-T05); nothing here reaches a prompt of ① or ②, and nothing is published.

**The source record** (`source_record`). Everything the draft is made of, read from the database:

* the closed fields, from the T02 fingerprint of the subject (`alert_fingerprint` / `case_fingerprint`),
  which checks each one's shape; the `conclusion` from the decision itself (`alerts.status`
  `closed_fp` / `closed_benign`, or `cases.status`). The model writes none of them (spec §7.4);
* `hostnames`, which V3 forbids in the text: the record's own and the inventory's;
* `facts_text`: the conclusion and the fingerprint (generalised), so the model sees no literal address;
* `analyst_texts`: the decision reason, or the case's `conclusion_reason` and its newest `MAX_NOTES`
  `case_notes`; `ai_texts`: ①'s latest proposer result for the alert, or ②'s latest result for the case.

**The prompt** (`build_prompt`). Facts and AI results are `context` blocks; the analyst's reason and
notes are `analyst_note` blocks, always through `security/wrap.untrusted_block`; one request sentence
follows, a template constant. The first message is held to `PROMPT_BUDGET_TOKENS` as the ranking prompt
is: the longest analyst and AI blocks are cut first (halved down to a floor), and, were that not enough,
the last ones dropped.

**Two shapes, one name.** Spec §7.4 calls the draft `knowledge_draft_v1`, a record of twelve fields.
It is written by two hands, so it exists in two forms:

* the model's ANSWER is six fields (`title, tags, summary, distinguishing_signals, check_next_time,
  confidence_note`). That is `knowledge_draft_v1` in `rag/schemas.json`, the schema `agent.call_json`
  validates the answer against; a model that writes a closed key is refused, which is safe but costs
  the whole answer;
* the STORED draft (`knowledge_drafts.draft`, what the admin edits and `validate_draft` checks) has
  twelve: the model's six, tidied, plus the six closed ones (`conclusion, category, mitre_ids,
  soar_scenario, rule_ids, log_source`) that the job copies from the source record (`DRAFT_FIELDS`).

**V1-V5** (`validate_draft`) return fault NAMES, never a value (the names go into `warnings` an admin
reads, and into the retry message, whose every word the linter must know):

    v1_schema:<field>   the draft is not the stored shape (a field missing or of the wrong type, a
                        control character, an invisible one: format, private-use or unassigned
                        Unicode, or any `Default_Ignorable_Code_Point` such as tag characters, bidi
                        controls, soft hyphen, word joiner, BOM, variation selectors, the combining
                        grapheme joiner, the Hangul fillers; and the braille blank),
                        `v1_schema:unexpected_key`, `v1_schema:root`;
                        `v1_tags:unknown_tag` (a tag outside `tags.yaml`)
    v2_closed:<field>   a closed field is not the source's
    v3_<kind>:<field>   a literal of `generalise.FINDING_NAMES` kind in a free-text field
    v4_detector / v4_delimiter / v4_nonce : <field>
                        `security.detector.scan` found something, a `<untrusted_data` tag in any
                        spelling, a token of the shape of a nonce (16 hex characters)
    v5_length / v5_count / v5_empty : <field>   the bounds of spec §7.4

**The job**, in order (`run_draft_job`):

0. idempotency: a `knowledge_drafts` row for `(source_kind, source_id)` -> return. The unique key is the
   backstop (`ON CONFLICT DO NOTHING`): a reclaimed job, or two that race, draft once;
1. the source record; 2. the candidates, with an empty exclusion (the source is new), each checked
   before it is sent exactly as the lookup does (V-R1, A4);
3. the ranking agent (`rag.match.rank`) when there is a candidate; its call is a `knowledge_draft` /
   `drafter` run of its own, so it counts toward the RAG sub-cap;
4. the merge rule, over the entries rated `rat_giong` (`conclusions_agree` says whether a conclusion is
   the source's: by family, so Tier-1 `closed_fp` agrees with Tier-2 `concluded_fp`, and every other
   pair is strict, `confirmed_incident` agreeing only with itself). A conflict comes first: if ANY
   `rat_giong` entry disagrees, the draft goes on as `pending` with `conflict_with_entry` set to the
   first that does, nothing is merged and no evidence is appended, even when another `rat_giong` entry
   agrees; the admin must see the conflict. Otherwise the first agreeing `rat_giong` entry takes the
   draft: `merged`, `duplicate_of_entry` set, `{subject, at}` appended to the entry's `evidence` and
   the source appended to its `source_alert_ids` / `source_case_ids` (so the entry cannot be retrieved
   for its own source, A5), event `knowledge.merged`, and no draft call;
5. the draft call, validated by V1-V5; a failure is retried once with the fault names added to the
   message; 6. stored `pending`: a draft that passes with `knowledge.drafted`; two failures with
   `draft = {}` and the faults of the last attempt in `warnings`; no budget with `["budget"]`.

A model that cannot be asked does not block the conclusion, which is already committed: the budget gives
`["budget"]`, the provider's refusal `["llm_permanent"]`, an attempt that timed out on the job's last
attempt `["llm_transient"]` (an earlier attempt writes its run row, commits it and re-raises, so the queue
retries, as `tier2/investigate.py` and the lookup do), a prompt that fails our own linter `["linter"]`.
A ranking that gave no answer does not stop the draft: it goes on, with the warning `rank_unavailable`
(no duplicate was looked for). A subject that is not a decided alert or a concluded case is a
`PermanentError`. No model configured: nothing is done, as for ① and ② (G7).
"""

from __future__ import annotations

import json
import re
import unicodedata
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import cache, partial
from pathlib import Path
from typing import Any

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb

from app.audit.events import write_event
from app.infra import config
from app.infra.errors import PermanentError
from app.infra.jobs import Job
from app.llm import schemas
from app.llm.adapter import (
    DeepSeekAdapter,
    LLMBudgetExceeded,
    LLMPermanent,
    cost_usd,
    estimate_tokens,
)
from app.llm.builder import BULLET, HEADING_REPAIR, SENTENCE_REPAIR, KbLearnedLevel
from app.llm.triage import prompt_version
from app.rag import agent
from app.rag.budget import rag_limits, rag_spent_or_exhausted
from app.rag.candidates import candidates
from app.rag.entries import KB_LEARNED_ROOT, Entry, file_matches, sha256_text
from app.rag.fingerprint import Fingerprint, alert_fingerprint, case_fingerprint
from app.rag.generalise import FINDING_NAMES, literal_findings
from app.rag.history import Exclusion
from app.rag.match import PROMPT_BUDGET_TOKENS, Match, injection_findings, rank, select_candidates
from app.rag.match import TEMPLATE_PATH as MATCH_TEMPLATE_PATH
from app.rag.runs import write_rag_run
from app.rag.subject import Subject, parse_subject
from app.rag.tags import TAGS_FILE, load_tags, read_tags_file
from app.security import detector, wrap

SCHEMA_NAME = "knowledge_draft_v1"
TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "draft_system.txt"
_TAGS_MARKER = "<<TAGS>>"

#: What the model writes (the keys of `knowledge_draft_v1`), and what the job copies from the source.
MODEL_FIELDS = (
    "title",
    "tags",
    "summary",
    "distinguishing_signals",
    "check_next_time",
    "confidence_note",
)
CLOSED_FIELDS = ("conclusion", "category", "mitre_ids", "soar_scenario", "rule_ids", "log_source")
#: A stored draft, in the order of the table in spec §7.4.
DRAFT_FIELDS = (
    "title",
    "conclusion",
    "category",
    "mitre_ids",
    "soar_scenario",
    "rule_ids",
    "log_source",
    "tags",
    "summary",
    "distinguishing_signals",
    "check_next_time",
    "confidence_note",
)
FREE_TEXT_FIELDS = (
    "title",
    "summary",
    "distinguishing_signals",
    "check_next_time",
    "confidence_note",
)
LIST_FIELDS = ("distinguishing_signals", "check_next_time")

#: Spec §7.4's bounds, in characters.
TITLE_MAX = 120
SUMMARY_MAX = 600
ITEM_MAX = 160
MAX_ITEMS = 6
NOTE_MAX = 200
_TEXT_MAX = {"title": TITLE_MAX, "summary": SUMMARY_MAX, "confidence_note": NOTE_MAX}

#: V3 and V4 read at most this much of a field: a longer field already fails V5, and a scan of an
#: admin's two-megabyte paste is not worth the time. The first characters are the ones that count.
MAX_SCAN_CHARS = 10_000
#: The newest case notes the prompt may carry.
MAX_NOTES = 30

#: The sentence outside a block: a template constant for the linter.
SENTENCE_REQUEST_DRAFT = "Trả về DUY NHẤT một đối tượng JSON theo schema knowledge_draft_v1."

#: Bytes a block may hold before the budget cuts it (`wrap.truncate_block` says so inside the block).
FACTS_LIMIT_BYTES = 6_000
AI_LIMIT_BYTES = 8_000
ANALYST_LIMIT_BYTES = 4_000
#: The budget cuts a block no further than this.
CUT_FLOOR_BYTES = 200


def _fault_vocabulary() -> frozenset[str]:
    names = {"v1_schema:root", "v1_schema:unexpected_key", "v1_tags:unknown_tag"}
    names.update(f"v1_schema:{field}" for field in DRAFT_FIELDS)
    names.update(f"v2_closed:{field}" for field in CLOSED_FIELDS)
    names.update(f"v3_{kind}:{field}" for kind in FINDING_NAMES for field in FREE_TEXT_FIELDS)
    for rule in ("v4_detector", "v4_delimiter", "v4_nonce"):
        names.update(f"{rule}:{field}" for field in FREE_TEXT_FIELDS)
    names.update(f"v5_length:{field}" for field in FREE_TEXT_FIELDS)
    names.update(f"v5_count:{field}" for field in LIST_FIELDS)
    names.update(f"v5_empty:{field}" for field in ("title", "summary"))
    return frozenset(names)


#: Every name `validate_draft` can return: the retry message says only these, and the linter knows them.
FAULT_VOCABULARY = _fault_vocabulary()
EXTRA_CONSTANTS = frozenset({SENTENCE_REQUEST_DRAFT}) | FAULT_VOCABULARY

#: What `knowledge_drafts.warnings` holds besides the V names (the job could not draft, or not check).
WARNING_BUDGET = "budget"
WARNING_TRANSIENT = "llm_transient"
WARNING_PERMANENT = "llm_permanent"
WARNING_LINTER = "linter"
WARNING_RANK = "rank_unavailable"

_NO_EXCLUSION = Exclusion(frozenset(), frozenset())


# ── the source record ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SourceRecord:
    """What a draft is made of and checked against (module doc). Closed fields are the source's,
    never the model's; `analyst_texts` and `ai_texts` are text other people and other models wrote,
    and only ever reach a prompt inside an untrusted block."""

    subject: Subject
    conclusion: str
    category: str
    mitre_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]
    soar_scenario: str | None
    log_source: str | None
    hostnames: frozenset[str] = frozenset()
    facts_text: str = ""
    analyst_texts: tuple[str, ...] = ()
    ai_texts: tuple[str, ...] = ()


_ALERT_CONCLUSIONS = frozenset({"closed_fp", "closed_benign"})
_CASE_CONCLUSIONS = frozenset({"concluded_fp", "concluded_policy_violation", "confirmed_incident"})
_ASSET_HOST = (
    "CASE WHEN jsonb_typeof(a.raw_payload #> '{enrichment,asset,host}') = 'string'"
    " THEN a.raw_payload #>> '{enrichment,asset,host}' END"
)


def _inventory_hostnames(conn: psycopg.Connection) -> set[str]:
    return {name for (name,) in conn.execute("SELECT hostname FROM assets LIMIT 10000") if name}


def _latest_result(
    conn: psycopg.Connection, pipeline: str, subject_type: str, role: str, subject_id: str
) -> list[str]:
    row = conn.execute(
        "SELECT result FROM llm_runs WHERE pipeline = %s AND subject_type = %s AND role = %s"
        " AND subject_id = %s AND result IS NOT NULL ORDER BY created_at DESC, run_id DESC LIMIT 1",
        (pipeline, subject_type, role, subject_id),
    ).fetchone()
    return [] if row is None else [json.dumps(row[0], ensure_ascii=False, sort_keys=True)]


def _texts(values: Sequence[Any]) -> tuple[str, ...]:
    return tuple(text.strip() for text in values if isinstance(text, str) and text.strip())


def _alert_source(conn: psycopg.Connection, subject: Subject) -> tuple[SourceRecord, Fingerprint]:
    row = conn.execute(
        f"SELECT a.status, a.close_reason, a.occurrence_count, a.agent_name, {_ASSET_HOST}"
        " FROM alerts a WHERE a.alert_id = %s",
        (subject.id,),
    ).fetchone()
    if row is None:
        raise PermanentError("source_record: the alert does not exist")
    status, close_reason, occurrences, agent_name, asset_host = row
    if status not in _ALERT_CONCLUSIONS:
        raise PermanentError(
            f"source_record: the alert is {status!r}, not closed_fp or closed_benign by an analyst"
        )
    fp = alert_fingerprint(conn, subject.id)
    hostnames = _inventory_hostnames(conn) | {name for name in (agent_name, asset_host) if name}
    facts = "\n".join(
        ["kind: alert", f"conclusion: {status}", f"occurrences: {occurrences}", fp.text]
    )
    return (
        SourceRecord(
            subject=subject,
            conclusion=status,
            category=fp.category,
            mitre_ids=fp.mitre_ids,
            rule_ids=fp.rule_ids,
            soar_scenario=fp.soar_scenario,
            log_source=fp.log_source or None,
            hostnames=frozenset(hostnames),
            facts_text=facts,
            analyst_texts=_texts([close_reason]),
            ai_texts=tuple(_latest_result(conn, "triage", "alert", "proposer", subject.id)),
        ),
        fp,
    )


def _case_source(conn: psycopg.Connection, subject: Subject) -> tuple[SourceRecord, Fingerprint]:
    try:
        case_id = str(uuid.UUID(subject.id))
    except ValueError:
        raise PermanentError("source_record: the case id is not a UUID") from None
    row = conn.execute(
        "SELECT status, conclusion_reason FROM cases WHERE case_id = %s", (case_id,)
    ).fetchone()
    if row is None:
        raise PermanentError("source_record: the case does not exist")
    status, conclusion_reason = row
    if status not in _CASE_CONCLUSIONS:
        raise PermanentError(f"source_record: the case is {status!r}, not concluded")
    fp = case_fingerprint(conn, case_id)
    heads = conn.execute(
        f"SELECT a.agent_name, {_ASSET_HOST} FROM case_alerts ca"
        " JOIN alerts a ON a.alert_id = ca.alert_id WHERE ca.case_id = %s",
        (case_id,),
    ).fetchall()
    hostnames = _inventory_hostnames(conn) | {name for head in heads for name in head if name}
    notes = conn.execute(
        "SELECT body FROM (SELECT body, created_at, note_id FROM case_notes WHERE case_id = %s"
        " ORDER BY created_at DESC, note_id DESC LIMIT %s) newest ORDER BY created_at, note_id",
        (case_id, MAX_NOTES),
    ).fetchall()
    facts = "\n".join(["kind: case", f"conclusion: {status}", f"alerts: {len(heads)}", fp.text])
    return (
        SourceRecord(
            subject=Subject("case", case_id),
            conclusion=status,
            category=fp.category,
            mitre_ids=fp.mitre_ids,
            rule_ids=fp.rule_ids,
            soar_scenario=fp.soar_scenario,
            log_source=fp.log_source or None,
            hostnames=frozenset(hostnames),
            facts_text=facts,
            analyst_texts=_texts([conclusion_reason, *(body for (body,) in notes)]),
            ai_texts=tuple(_latest_result(conn, "investigate", "case", "investigator", case_id)),
        ),
        fp,
    )


def _build_source(conn: psycopg.Connection, subject: Subject) -> tuple[SourceRecord, Fingerprint]:
    return _alert_source(conn, subject) if subject.kind == "alert" else _case_source(conn, subject)


def source_record(conn: psycopg.Connection, subject: Subject) -> SourceRecord:
    """The source record of a decided alert or a concluded case (module doc). `PermanentError` for a
    subject that is not there, an alert no analyst closed as false positive or benign, a case still
    being investigated: the job cannot succeed by waiting."""
    return _build_source(conn, subject)[0]


# ── V1-V5 ─────────────────────────────────────────────────────────────────────────────────────

# NUL, the control characters but tab and newline, and lone surrogates: PostgreSQL's jsonb refuses a NUL
# and a lone surrogate, and a Markdown file has no use for the rest.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff]")
_NONCE_SHAPED = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{16}(?![0-9A-Za-z])")
_BOUNDARY_TAG = re.compile(r"<\s*/?\s*untrusted_data")

#: Code points a reader cannot see, or sees as something else. Text that carries them can hold an
#: instruction or a literal that the admin reviewing the draft does not see, and that
#: `security.detector` (four code points) and V3 (a literal split by one) miss. Two tests, either of
#: which makes a code point invisible:
#:
#: * the Unicode general category is format (Cf: tag characters, bidi controls, soft hyphen, word
#:   joiner, zero-width characters, the BOM), private use (Co) or unassigned (Cn);
#: * the code point is in `INVISIBLE_RANGES`: the Unicode `Default_Ignorable_Code_Point` property,
#:   which also holds characters that are NOT Cf, such as the variation selectors (Mn: U+FE00-FE0F, and
#:   U+E0100-E01EF, which can smuggle a whole instruction behind one emoji, while U+FE0F alone splits an
#:   address), the combining grapheme joiner (Mn), the Hangul fillers (Lo) and the Mongolian and Khmer
#:   ones, plus the braille blank U+2800 (So), which draws nothing either.
_INVISIBLE_CATEGORIES = frozenset({"Cf", "Co", "Cn"})

#: `Default_Ignorable_Code_Point`, Unicode 15.0, `DerivedCoreProperties.txt`, as inclusive ranges. A
#: hard-coded table: `unicodedata` has no such property, and a table does not move with the
#: interpreter's Unicode version (the category test above does, in the safe direction: a code point
#: assigned later is still stripped as long as it is in a range here).
DEFAULT_IGNORABLE_RANGES: tuple[tuple[int, int], ...] = (
    (0x00AD, 0x00AD),  # SOFT HYPHEN
    (0x034F, 0x034F),  # COMBINING GRAPHEME JOINER
    (0x061C, 0x061C),  # ARABIC LETTER MARK
    (0x115F, 0x1160),  # HANGUL CHOSEONG FILLER, HANGUL JUNGSEONG FILLER
    (0x17B4, 0x17B5),  # KHMER VOWEL INHERENT AQ, AA
    (0x180B, 0x180F),  # MONGOLIAN FREE VARIATION SELECTORS, VOWEL SEPARATOR
    (0x200B, 0x200F),  # ZERO WIDTH SPACE .. RIGHT-TO-LEFT MARK
    (0x202A, 0x202E),  # LEFT-TO-RIGHT EMBEDDING .. RIGHT-TO-LEFT OVERRIDE
    (0x2060, 0x206F),  # WORD JOINER .. NOMINAL DIGIT SHAPES
    (0x3164, 0x3164),  # HANGUL FILLER
    (0xFE00, 0xFE0F),  # VARIATION SELECTOR-1..16
    (0xFEFF, 0xFEFF),  # ZERO WIDTH NO-BREAK SPACE (the BOM)
    (0xFFA0, 0xFFA0),  # HALFWIDTH HANGUL FILLER
    (0xFFF0, 0xFFF8),  # reserved
    (0x1BCA0, 0x1BCA3),  # SHORTHAND FORMAT LETTER OVERLAP .. UP STEP
    (0x1D173, 0x1D17A),  # MUSICAL SYMBOL BEGIN BEAM .. END PHRASE
    (0xE0000, 0xE0FFF),  # tag characters, VARIATION SELECTOR-17..256, reserved
)
#: Invisible though not default-ignorable: BRAILLE PATTERN BLANK, which draws a blank cell.
EXTRA_INVISIBLE_RANGES: tuple[tuple[int, int], ...] = ((0x2800, 0x2800),)
INVISIBLE_RANGES = (*DEFAULT_IGNORABLE_RANGES, *EXTRA_INVISIBLE_RANGES)
_INVISIBLE_CODE_POINTS = frozenset(
    code_point for low, high in INVISIBLE_RANGES for code_point in range(low, high + 1)
)


def _is_invisible(char: str) -> bool:
    return (
        ord(char) in _INVISIBLE_CODE_POINTS or unicodedata.category(char) in _INVISIBLE_CATEGORIES
    )


def strip_invisible(text: str) -> str:
    """`text` without its invisible code points (`_is_invisible`), which are deleted, not
    replaced: `79.79<U+2060>.78.202` becomes the address it displays as."""
    return text if text.isascii() else "".join(ch for ch in text if not _is_invisible(ch))


def _has_invisible(text: str) -> bool:
    return not text.isascii() and any(_is_invisible(ch) for ch in text)


def _is_text(value: Any) -> bool:
    return isinstance(value, str)


def _is_text_list(value: Any) -> bool:
    return isinstance(value, list) and all(_is_text(item) for item in value)


def _has_control(value: Any) -> bool:
    """A control character, a lone surrogate or an invisible code point in a text or a list of texts."""
    items = [value] if _is_text(value) else value if _is_text_list(value) else []
    return any(_CONTROL.search(item) or _has_invisible(item) for item in items)


def _v1(draft: Mapping[str, Any], tags: frozenset[str]) -> list[str]:
    present = {name: draft[name] for name in MODEL_FIELDS if name in draft}
    problems = schemas.validate_against(agent.schema_node(SCHEMA_NAME), present)
    broken = {error.partition(": ")[0].split(".")[0].split("[")[0] for error in problems}
    faults = []
    for name in DRAFT_FIELDS:
        if (
            name not in draft
            or name in broken
            or (name in MODEL_FIELDS and _has_control(draft[name]))
        ):
            faults.append(f"v1_schema:{name}")
    if any(key not in DRAFT_FIELDS for key in draft):
        faults.append("v1_schema:unexpected_key")
    given = draft.get("tags")
    if _is_text_list(given) and not set(given) <= tags:
        faults.append("v1_tags:unknown_tag")
    return faults


def _v2(draft: Mapping[str, Any], source: SourceRecord) -> list[str]:
    expected = {
        "conclusion": source.conclusion,
        "category": source.category,
        "mitre_ids": list(source.mitre_ids),
        "soar_scenario": source.soar_scenario,
        "rule_ids": list(source.rule_ids),
        "log_source": source.log_source,
    }
    faults = []
    for name in CLOSED_FIELDS:
        if name not in draft:
            continue  # V1 named it
        value = draft[name]
        if isinstance(value, tuple):
            value = list(value)
        if value != expected[name]:
            faults.append(f"v2_closed:{name}")
    return faults


def _free_texts(draft: Mapping[str, Any]) -> dict[str, str]:
    """The free-text fields that are well formed, each as one text (a list joined by newlines)."""
    found = {}
    for name in FREE_TEXT_FIELDS:
        value = draft.get(name)
        if name in LIST_FIELDS and _is_text_list(value):
            found[name] = "\n".join(value)
        elif name not in LIST_FIELDS and _is_text(value):
            found[name] = value
    return found


def _v3(texts: Mapping[str, str], source: SourceRecord) -> list[str]:
    faults = []
    for name, text in texts.items():
        # read as displayed: an address split by a word joiner is the address (V1 names the joiner)
        found = literal_findings(strip_invisible(text[:MAX_SCAN_CHARS]), source.hostnames)
        faults.extend(f"v3_{kind}:{name}" for kind in found)
    return faults


def _v4(texts: Mapping[str, str]) -> list[str]:
    faults = []
    nonce = wrap.new_nonce()
    for name, text in texts.items():
        raw = text[:MAX_SCAN_CHARS]
        scanned = strip_invisible(raw)  # a tag or a phrase split by an invisible character is whole
        if _BOUNDARY_TAG.search(unicodedata.normalize("NFKC", scanned).lower()):
            faults.append(f"v4_delimiter:{name}")
        if _NONCE_SHAPED.search(scanned):
            faults.append(f"v4_nonce:{name}")
        # the detector reads the text as written (it flags hidden characters) and as displayed
        views = [raw] if scanned == raw else [raw, scanned]
        if detector.scan([wrap.untrusted_block(view, "kb_learned", nonce=nonce) for view in views]):
            faults.append(f"v4_detector:{name}")
    return faults


def _v5(draft: Mapping[str, Any]) -> list[str]:
    faults = []
    for name, limit in _TEXT_MAX.items():
        value = draft.get(name)
        if not _is_text(value):
            continue
        if len(value) > limit:
            faults.append(f"v5_length:{name}")
        if name in ("title", "summary") and not value.strip():
            faults.append(f"v5_empty:{name}")
    for name in LIST_FIELDS:
        items = draft.get(name)
        if not _is_text_list(items):
            continue
        if len(items) > MAX_ITEMS:
            faults.append(f"v5_count:{name}")
        if any(len(item) > ITEM_MAX for item in items):
            faults.append(f"v5_length:{name}")
    return faults


def validate_draft(
    draft: Mapping[str, Any], source: SourceRecord, *, tags: frozenset[str]
) -> list[str]:
    """V1-V5 of spec §7.7 over a draft (a stored one: the six fields of the model and the six closed
    ones). The NAMES of the rules it breaks, in rule order, each once; `[]` when it passes. Never a
    value: the names are the closed vocabulary `FAULT_VOCABULARY`. Pure; changes nothing it is given.
    The job runs it on what the model wrote, and the admin's approval (P13-T05) on the final text.
    """
    if not isinstance(draft, Mapping):
        return ["v1_schema:root"]
    texts = _free_texts(draft)
    faults = [
        *_v1(draft, tags),
        *_v2(draft, source),
        *_v3(texts, source),
        *_v4(texts),
        *_v5(draft),
    ]
    return list(dict.fromkeys(faults))


# ── the prompt ────────────────────────────────────────────────────────────────────────────────


@cache
def _tag_lines() -> str:
    described = read_tags_file(TAGS_FILE)[0]
    return "\n".join(f"- {tag}: {described[tag]}" for tag in sorted(described))


def system_prompt() -> str:
    """`draft_system.txt` with the closed tag vocabulary, from `tags.yaml`, in place of its marker."""
    return TEMPLATE_PATH.read_text(encoding="utf-8").replace(_TAGS_MARKER, _tag_lines())


@dataclass(frozen=True)
class _Part:
    source: str  # the block source
    text: str
    limit: int  # bytes
    attrs: tuple[tuple[str, str], ...] = ()
    cuttable: bool = False


def _parts(source: SourceRecord) -> list[_Part]:
    parts = [_Part("context", source.facts_text, FACTS_LIMIT_BYTES, (("part", "facts"),))]
    parts.extend(
        _Part("context", text, AI_LIMIT_BYTES, (("part", "ai_result"),), cuttable=True)
        for text in source.ai_texts
    )
    parts.extend(
        _Part("analyst_note", text, ANALYST_LIMIT_BYTES, cuttable=True)
        for text in source.analyst_texts
    )
    return parts


def _render(
    parts: Sequence[_Part], limits: Sequence[int], dropped: set[int], nonce: str
) -> list[wrap.Block]:
    return [
        wrap.untrusted_block(
            part.text, part.source, nonce=nonce, limit_bytes=limits[index], **dict(part.attrs)
        )
        for index, part in enumerate(parts)
        if index not in dropped
    ]


def _message(blocks: Sequence[wrap.Block]) -> str:
    return "\n\n".join([*(block.rendered for block in blocks), SENTENCE_REQUEST_DRAFT])


def build_prompt(source: SourceRecord, nonce: str) -> tuple[list[wrap.Block], str]:
    """The blocks and the user message of the draft call, cut to `PROMPT_BUDGET_TOKENS`
    (`llm.adapter.estimate_tokens`, on the whole message): while it is too long, the longest analyst
    or AI block still above `CUT_FLOOR_BYTES` has its limit halved; were every one at the floor, the
    last of them are dropped. The facts block is never cut. A block is as long whatever the nonce is.
    """
    parts = _parts(source)
    limits = [part.limit for part in parts]
    dropped: set[int] = set()
    blocks = _render(parts, limits, dropped, nonce)
    message = _message(blocks)
    cuttable = [index for index, part in enumerate(parts) if part.cuttable]
    while estimate_tokens(message) > PROMPT_BUDGET_TOKENS:
        sizes = {
            index: len(block.rendered)
            for index, block in zip(
                (i for i in range(len(parts)) if i not in dropped), blocks, strict=True
            )
        }
        live = [i for i in cuttable if i not in dropped and limits[i] > CUT_FLOOR_BYTES]
        if live:
            longest = max(live, key=lambda index: sizes[index])
            limits[longest] = max(CUT_FLOOR_BYTES, limits[longest] // 2)
        else:
            remaining = [i for i in cuttable if i not in dropped]
            if not remaining:
                break  # only the facts are left: they have their own bound
            dropped.add(remaining[-1])
        blocks = _render(parts, limits, dropped, nonce)
        message = _message(blocks)
    return blocks, message


def build_user(source: SourceRecord, nonce: str) -> str:
    """The user message of the draft call (`build_prompt`)."""
    return build_prompt(source, nonce)[1]


def retry_user(user: str, faults: Sequence[str]) -> str:
    """The message of the second attempt: the first, and the repair heading and sentence with a bullet
    for each fault. A fault is a name of `FAULT_VOCABULARY`, so no word of the model's is in it."""
    lines = [
        HEADING_REPAIR,
        SENTENCE_REPAIR,
        *(f"{BULLET}{f}" for f in faults if f in FAULT_VOCABULARY),
    ]
    return f"{user}\n\n" + "\n".join(lines)


# ── the answer ────────────────────────────────────────────────────────────────────────────────


def _tidy(value: str) -> str:
    """One printable line: invisible code points (`strip_invisible`) are deleted, control characters
    (and a NUL, and a lone surrogate) become spaces, runs of whitespace one space. The entry's Markdown
    folds its text onto one line anyway. It runs before V1-V5, so the text validated is the text stored
    and what the model hid in it, or split a literal with, is gone before the rules read it."""
    return " ".join(_CONTROL.sub(" ", strip_invisible(value)).split())


def _tidy_list(items: Sequence[str]) -> list[str]:
    return [line for line in (_tidy(item) for item in items) if line]


def _assemble(parsed: Mapping[str, Any], source: SourceRecord) -> dict[str, Any]:
    """The stored draft: the model's six fields (tidied; tags once each) and the source's six."""
    tags = (
        [tag for tag in dict.fromkeys(parsed["tags"])] if isinstance(parsed["tags"], list) else []
    )
    record: dict[str, Any] = {
        "title": _tidy(parsed["title"]),
        "conclusion": source.conclusion,
        "category": source.category,
        "mitre_ids": list(source.mitre_ids),
        "soar_scenario": source.soar_scenario,
        "rule_ids": list(source.rule_ids),
        "log_source": source.log_source,
        "tags": tags,
        "summary": _tidy(parsed["summary"]),
        "distinguishing_signals": _tidy_list(parsed["distinguishing_signals"]),
        "check_next_time": _tidy_list(parsed["check_next_time"]),
        "confidence_note": _tidy(parsed["confidence_note"]),
    }
    return {name: record[name] for name in DRAFT_FIELDS}


def _schema_faults(errors: Sequence[str]) -> list[str]:
    """`v1_schema:` names for the messages of a schema the answer failed. The message of an
    `unexpected key` carries the model's key as its path, so it is named without it."""
    faults = []
    for error in errors:
        if error.endswith(": unexpected key"):
            faults.append("v1_schema:unexpected_key")
            continue
        path = error.partition(": ")[0]
        root = re.split(r"[.\[]", path, maxsplit=1)[0]
        faults.append(f"v1_schema:{root}" if root in MODEL_FIELDS else "v1_schema:root")
    return list(dict.fromkeys(faults))


# ── what is stored ────────────────────────────────────────────────────────────────────────────


def _log(payload: dict[str, Any]) -> None:
    print(json.dumps(payload))


def _raise_idle_timeout(conn: psycopg.Connection, cfg: config.Config) -> None:
    """The handler's first statement, `rag.lookup`'s (duplicated: that one is not this card's to
    change). `infra/db.py::transaction()` sets `idle_in_transaction_session_timeout` to 10 s; a model
    call is idle time to PostgreSQL, so the job raises it to `JOB_LOCK_TIMEOUT_S`."""
    conn.execute(
        sql.SQL("SET LOCAL idle_in_transaction_session_timeout = {}").format(
            sql.Literal(f"{cfg.JOB_LOCK_TIMEOUT_S}s")
        )
    )


def _exists(conn: psycopg.Connection, subject: Subject) -> bool:
    row = conn.execute(
        "SELECT 1 FROM knowledge_drafts WHERE source_kind = %s AND source_id = %s",
        (subject.kind, subject.id),
    ).fetchone()
    return row is not None


def _store_draft(
    conn: psycopg.Connection,
    source: SourceRecord,
    *,
    status: str,
    draft: Mapping[str, Any],
    warnings: Sequence[str],
    run_id: uuid.UUID | None,
    duplicate_of: str | None = None,
    conflict_with: str | None = None,
) -> uuid.UUID | None:
    """Insert the draft; None when a draft of this source is already stored (the unique key, the
    backstop of step 0: whoever lost the race writes nothing else)."""
    row = conn.execute(
        "INSERT INTO knowledge_drafts (source_kind, source_id, conclusion, status, draft, warnings,"
        " llm_run_id, duplicate_of_entry, conflict_with_entry)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
        " ON CONFLICT (source_kind, source_id) DO NOTHING RETURNING draft_id",
        (
            source.subject.kind,
            source.subject.id,
            source.conclusion,
            status,
            Jsonb(dict(draft)),
            Jsonb(list(warnings)),
            run_id,
            duplicate_of,
            conflict_with,
        ),
    ).fetchone()
    _log({"knowledge_draft": status, "subject": source.subject.key})
    return None if row is None else row[0]


def _store_empty(
    conn: psycopg.Connection,
    source: SourceRecord,
    warnings: Sequence[str],
    run_id: uuid.UUID | None,
    **links: str | None,
) -> None:
    """A `pending` draft with no text: the admin writes it by hand or rejects it."""
    _store_draft(
        conn, source, status="pending", draft={}, warnings=warnings, run_id=run_id, **links
    )


def _append_source(conn: psycopg.Connection, entry_id: str, source: SourceRecord) -> bool:
    """A merge, in one statement: `{subject, at}` is appended to the entry's `evidence`, and the source
    to `source_alert_ids` / `source_case_ids` (for a case: the case and its head alerts), so the entry
    cannot be retrieved for the source it absorbed (A5). The entry's content is untouched. False when
    nothing was changed: the entry is no longer active, or already holds this source."""
    if source.subject.kind == "alert":
        alert_ids, case_ids = [source.subject.id], []
    else:
        heads = conn.execute(
            "SELECT alert_id FROM case_alerts WHERE case_id = %s ORDER BY alert_id",
            (source.subject.id,),
        ).fetchall()
        alert_ids, case_ids = [alert_id for (alert_id,) in heads], [source.subject.id]
    row = conn.execute(
        "UPDATE knowledge_entries SET"
        " evidence = evidence || jsonb_build_array(jsonb_build_object("
        "   'subject', %(subject)s::text, 'at', now())),"
        " source_alert_ids = source_alert_ids ||"
        "   ARRAY(SELECT a FROM unnest(%(alerts)s::text[]) AS a WHERE a <> ALL(source_alert_ids)),"
        " source_case_ids = source_case_ids ||"
        "   ARRAY(SELECT c FROM unnest(%(cases)s::uuid[]) AS c WHERE c <> ALL(source_case_ids))"
        " WHERE entry_id = %(entry)s AND status = 'active'"
        " AND NOT (evidence @> jsonb_build_array(jsonb_build_object('subject', %(subject)s::text)))"
        " RETURNING entry_id",
        {
            "subject": source.subject.key,
            "alerts": alert_ids,
            "cases": case_ids,
            "entry": entry_id,
        },
    ).fetchone()
    return row is not None


def _record_run(
    conn: psycopg.Connection,
    cfg: config.Config,
    tape: agent.Tape,
    subject: Subject,
    findings: list[detector.Finding],
    template: Path,
    *,
    stopped_by: str | None,
    result: dict | None,
    gate_result: dict,
) -> uuid.UUID | None:
    """This stage's one `llm_runs` row: the prompt of its first call and whatever its answered calls
    cost, so a failure still carries what was paid for. None when nothing was sent."""
    if not tape.sent:
        return None
    system, user = tape.sent[0]
    usage = tape.usage
    priced = tape.calls > 0 and "prompt_tokens" in usage and "completion_tokens" in usage
    return write_rag_run(
        conn,
        run_id=uuid.uuid4(),
        pipeline="knowledge_draft",
        role="drafter",
        subject=subject,
        system_prompt=system,
        user_message=user,
        result=result,
        gate_result=gate_result,
        injection_findings=detector.as_json(findings),
        input_tokens=usage.get("prompt_tokens"),
        output_tokens=usage.get("completion_tokens"),
        latency_ms=tape.latency_ms if tape.calls else None,
        model_id=tape.model,
        prompt_version=prompt_version(template),
        cost_usd=cost_usd(usage, cfg) if priced else None,
        stopped_by=stopped_by,
    )


# ── the job ───────────────────────────────────────────────────────────────────────────────────


def _over_budget(conn: psycopg.Connection, cfg: config.Config) -> bool:
    """The question the adapter asks before each attempt, asked once before the job starts."""
    return rag_spent_or_exhausted(conn, cfg) >= cfg.RAG_MONTHLY_USD_CAP


def _sendable(conn: psycopg.Connection, fp: Fingerprint) -> tuple[list[Entry], list[str], int]:
    """The candidates the ranking agent may see: each one checked before it is sent (V-R1, A4: an
    entry changed after approval reaches no prompt) and the rest cut to the prompt budget. Returns
    them, the ids that failed the check (each wrote `rag.integrity_failed`) and the count cut."""
    intact: list[Entry] = []
    failed: list[str] = []
    for cand in candidates(conn, fp, _NO_EXCLUSION):
        if sha256_text(cand.content) == cand.content_sha256 and file_matches(cand, KB_LEARNED_ROOT):
            intact.append(cand)
            continue
        failed.append(cand.entry_id)
        write_event(
            conn,
            "rag.integrity_failed",
            cand.entry_id,
            "system",
            payload={"entry_id": cand.entry_id},
        )
    sendable = select_candidates(fp, intact)
    return sendable, failed, len(intact) - len(sendable)


#: A Tier-1 closure and a Tier-2 conclusion that say the same thing: `closed_fp` and `concluded_fp`.
#: No other pair is one (`closed_benign` is not `concluded_policy_violation`, and `confirmed_incident`
#: agrees only with itself).
_SAME_FAMILY = frozenset({"closed_fp", "concluded_fp"})


def conclusions_agree(first: str, second: str) -> bool:
    """Whether two conclusions agree for the merge rule: the same one, or `closed_fp` with
    `concluded_fp`. Every other pair is strict."""
    return first == second or {first, second} == _SAME_FAMILY


def _merge_and_conflict(
    matches: Sequence[Match], sent: Sequence[Entry], source: SourceRecord
) -> tuple[Entry | None, Entry | None]:
    """The entry to merge into and the entry in conflict (module doc, step 4), among the matches rated
    `rat_giong`, in the agent's order. A conflict takes precedence: if any of them disagrees with the
    source, the first that does is the conflict and nothing is merged, even when another agrees;
    otherwise the first that agrees is the one to merge into."""
    by_id = {entry.entry_id: entry for entry in sent}
    very_like = [
        by_id[m.entry_id]
        for m in matches
        if m.level is KbLearnedLevel.RAT_GIONG and m.entry_id in by_id
    ]
    other = next(
        (e for e in very_like if not conclusions_agree(e.conclusion, source.conclusion)), None
    )
    if other is not None:
        return None, other
    same = next((e for e in very_like if conclusions_agree(e.conclusion, source.conclusion)), None)
    return same, None


def run_draft_job(conn: psycopg.Connection, job: Job, *, adapter: Any | None = None) -> None:
    """Run one `knowledge_draft` job (module doc). `adapter` defaults to a `DeepSeekAdapter` limited
    to the RAG budget; every test passes a fake."""
    cfg = config.load()
    _raise_idle_timeout(conn, cfg)

    if not agent.rag_model(cfg):  # no model configured: the AI is off, as for ① and ② (G7)
        _log({"knowledge_draft": "skipped", "reason": "no_model"})
        return

    try:
        subject = parse_subject(job.subject_id)
    except ValueError:
        raise PermanentError(
            "knowledge_draft: the job's subject is neither 'alert:<id>' nor 'case:<uuid>'"
        ) from None

    if _exists(conn, subject):  # 0: a reclaimed job must not draft twice
        _log({"knowledge_draft": "exists", "subject": subject.key})
        return

    source, fp = _build_source(conn, subject)  # PermanentError when there is no conclusion
    if _over_budget(conn, cfg):
        _store_empty(conn, source, [WARNING_BUDGET], None)
        return

    model = agent.rag_model(cfg)
    shared = (
        adapter
        if adapter is not None
        else DeepSeekAdapter(
            cfg,
            spent_usd=partial(rag_spent_or_exhausted, conn, cfg),
            limits=partial(rag_limits, conn, cfg),
        )
    )

    # ── 2-3: the candidates and the ranking ──────────────────────────────────────────────────
    sendable, integrity_failed, dropped = _sendable(conn, fp)
    warnings: list[str] = []
    same: Entry | None = None
    conflicting: Entry | None = None
    rank_run_id: uuid.UUID | None = None

    if sendable:
        rank_tape = agent.Tape(shared)
        rank_findings = injection_findings(fp, sendable)
        rank_gate = {
            "stage": "rank",
            "integrity_failed": integrity_failed,
            "candidates_dropped_for_budget": dropped,
        }

        def record_rank(stopped_by: str | None, **fields: Any) -> uuid.UUID | None:
            gate = {**rank_gate, **fields.pop("gate", {})}
            return _record_run(
                conn,
                cfg,
                rank_tape,
                subject,
                rank_findings,
                MATCH_TEMPLATE_PATH,
                stopped_by=stopped_by,
                gate_result=gate,
                result=fields.pop("result", None),
            )

        try:
            matches, _notes, ranked = rank(rank_tape, fp, sendable, cfg=cfg)
        except LLMBudgetExceeded:
            _store_empty(conn, source, [WARNING_BUDGET], record_rank("cap"))
            return
        except LLMPermanent:
            rank_run_id = record_rank("permanent")
            warnings.append(WARNING_RANK)
        except PermanentError:
            # our own prompt failed the linter: a template defect, not a model outcome
            rank_run_id = record_rank("linter")
            warnings.append(WARNING_RANK)
        except Exception as exc:
            if not agent.is_transient(exc):
                raise  # a bug: the worker will classify it, and nothing here hides it
            if job.attempts < cfg.JOB_MAX_ATTEMPTS:
                # the paid call must outlive the handler's rolled-back transaction
                record_rank("transient")
                conn.commit()
                raise
            rank_run_id = record_rank("transient")  # the last attempt: go on without a ranking
            warnings.append(WARNING_RANK)
        else:
            if ranked.parsed is None:  # the schema refused the answer and its repair: no match
                gate = {"faults": [], "schema_errors": ranked.schema_errors}
                rank_run_id = record_rank("schema", gate=gate)
                warnings.append(WARNING_RANK)
            else:
                rank_run_id = record_rank(
                    None, result=ranked.parsed, gate={"faults": [], "matches": len(matches)}
                )
                same, conflicting = _merge_and_conflict(matches, sendable, source)

    # ── 4: the merge rule ────────────────────────────────────────────────────────────────────
    if same is not None and _append_source(conn, same.entry_id, source):
        draft_id = _store_draft(
            conn,
            source,
            status="merged",
            draft={},
            warnings=[],
            run_id=rank_run_id,
            duplicate_of=same.entry_id,
        )
        if draft_id is not None:
            write_event(
                conn,
                "knowledge.merged",
                subject.id,
                "system",
                payload={"draft_id": str(draft_id), "entry_id": same.entry_id},
            )
        return
    conflict_with = None if conflicting is None else conflicting.entry_id

    # ── 5: the draft call, validated, retried once ───────────────────────────────────────────
    nonce = wrap.new_nonce()
    blocks, user = build_prompt(source, nonce)
    findings = detector.scan(blocks)
    system = system_prompt()
    tape = agent.Tape(shared)
    vocabulary = load_tags()
    faults: list[str] = []
    parsed: dict | None = None
    final: dict | None = None
    attempts = 0

    def record_draft(stopped_by: str | None) -> uuid.UUID | None:
        gate = {
            "stage": "draft",
            "attempts": attempts,
            "faults": faults,
            "conflict_with_entry": conflict_with,
        }
        return _record_run(
            conn,
            cfg,
            tape,
            subject,
            findings,
            TEMPLATE_PATH,
            stopped_by=stopped_by,
            result=parsed,
            gate_result=gate,
        )

    def give_up(warning: str, stopped_by: str) -> None:
        run_id = record_draft(stopped_by)
        _store_empty(conn, source, [*warnings, warning], run_id, conflict_with=conflict_with)

    for attempt in (1, 2):
        attempts = attempt
        message = user if attempt == 1 else retry_user(user, faults)
        try:
            result = agent.call_json(
                tape,
                system=system,
                user=message,
                nonce=nonce,
                schema_name=SCHEMA_NAME,
                extra_constants=EXTRA_CONSTANTS,
                model=model,
                cfg=cfg,
            )
        except LLMBudgetExceeded:
            give_up(WARNING_BUDGET, "cap")
            return
        except LLMPermanent:
            give_up(WARNING_PERMANENT, "permanent")
            return
        except PermanentError:
            # our own prompt failed the linter: a template defect, not a model outcome
            give_up(WARNING_LINTER, "linter")
            return
        except Exception as exc:
            if not agent.is_transient(exc):
                raise  # a bug: the worker will classify it, and nothing here hides it
            if job.attempts < cfg.JOB_MAX_ATTEMPTS:
                # the paid call must outlive the handler's rolled-back transaction
                record_draft("transient")
                conn.commit()
                raise
            give_up(WARNING_TRANSIENT, "transient")
            return

        parsed = result.parsed
        if parsed is None:  # the schema refused the answer, and its repair
            faults = _schema_faults(result.schema_errors)
            continue
        candidate = _assemble(parsed, source)
        faults = validate_draft(candidate, source, tags=vocabulary)
        if not faults:
            final = candidate
            break

    stopped_by = None if final is not None else "schema" if parsed is None else "validation"
    run_id = record_draft(stopped_by)
    if final is None:
        _store_empty(conn, source, [*warnings, *faults], run_id, conflict_with=conflict_with)
        return
    draft_id = _store_draft(
        conn,
        source,
        status="pending",
        draft=final,
        warnings=warnings,
        run_id=run_id,
        conflict_with=conflict_with,
    )
    if draft_id is not None:
        write_event(
            conn,
            "knowledge.drafted",
            subject.id,
            "system",
            payload={"draft_id": str(draft_id)},
        )
