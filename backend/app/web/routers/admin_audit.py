"""`web/routers/admin_audit.py` — the audit log page's API (P11-T09, spec §4.7 and §5.8):
`GET /api/admin/audit?range=24h|7d|30d&group=&actor=&subject=&cursor=&limit=`. `Admin` only;
`iter_routers()` discovers this module. Read-only: it writes no audit event of its own.

**What a row is.** `{audit_id, created_at, event_type, actor_role, actor_username, subject_id,
payload}`, newest first by `audit_id` (insertion order, which the primary key serves: no new
index). `actor_username` comes from a LEFT JOIN on `users`, made only for an `analyst` or `admin`
row: it is `null` for `system` and `llm` (even if an `llm` row carries an `actor_id`, which the
CHECK allows) and for an actor with no `users` row (`audit_events.actor_id` has no FK on purpose:
a deleted user's rows stay).

**Filters**, all optional, all ANDed, every value a bound parameter (the WHERE is built from the
fixed fragments in `_filters`, never from a request value):
- `range`: `24h`, `7d` (default) or `30d`, on `created_at`, against the database's clock;
- `group`: a key of `GROUPS`; an unknown one is a 422;
- `actor`: `system` or `llm` is an `actor_role`; anything else is a username, matched exactly as
  login matches it (case-sensitive), through the `actor_id` of an `analyst` or `admin` row (the
  join's own condition). An unknown username matches nothing: an
  empty list, not an error. A text value holding a NUL byte, or an empty one, is a 422 (the
  driver cannot send a NUL, and would answer a 500);
- `subject`: an exact `subject_id`;
- `cursor`: the last `audit_id` seen; rows with `audit_id < cursor`. `limit` is 1..100, 50 by default.
  `next_cursor` is the last row's id when the page is FULL, else `null` (a full last page still
  has one; the page after it is empty).

**Timeouts.** The page runs in a savepoint (`conn.transaction()` inside the request's
transaction) after `SET LOCAL statement_timeout = QUERY_TIMEOUT`; a cancelled query answers
`503 {"detail": {"reason": "timeout"}}` (spec §3: a `detail` that is an object carries a
machine-readable `reason`). `total` is `count(*)` of the same filter, WITHOUT the cursor, in a
savepoint of its own under `TOTAL_TIMEOUT`; it is `null` when that count times out or fails for
any reason, and the page is served regardless: the savepoint rollback keeps the request's
transaction usable. `infra/db.transaction()` is NOT used: it issues its own
`BEGIN`/`COMMIT`/`ROLLBACK`, which inside a request would commit (or roll back) the transaction
`deps.Conn` owns. Both timeouts are module constants read when a request runs, so a test shortens
them.

**Payloads** (spec §5.8, and Review Focus 3 of the plan). The size is decided in the database:
a payload whose `jsonb::text` is over `PAYLOAD_MAX_BYTES` (64 KiB, measured in bytes) never leaves
it, and the row carries `{"truncated": true, "size": <bytes>}` instead. That way a 1 MB string
is never read into this process and one event cannot blow up a page (100 rows at most, 64 KiB
each). Every other payload is parsed and `redact`ed, at any depth, through lists and dicts, and
nothing else is changed (no stringifying, no cutting). Three rules (spec §5.8, DEC-203 item 2):
- **The key rule** (spec §5.8 as amended at `b9fe528`): a dict key that `is_secret_key` names has
  its value replaced by `"[đã ẩn]"`. Lower-case the key, drop `_` and `-` (camelCase needs no
  split of its own: lower-casing `apiKey` is `apikey`), and redact when the result equals or ends
  with one of `REDACT_SUFFIXES` (DEC-203 adds `passwd` and `pwd`). That catches `access_token`,
  `client_secret`, `apiKey`, `api-key`, `db_password`, `secret_key`, `privateKey`, `passphrase`,
  `db_passwd` and leaves `key`, `token_count`, `tokens_in`, `passwords`, `token_hash` visible.
- **The value rule** (DEC-203 item 2a as amended 18/10): a STRING that `is_secret_value` names, one
  that CONTAINS `scheme://user:pass@` anywhere (`URL_WITH_PASSWORD`, no `^` anchor), is replaced as
  a whole, whatever its key, or none (a list item, a bare payload). That covers `DATABASE_URL*`,
  `conn_str` and a DSN in the middle of an error text. The cost is accepted by the decision: a
  harmless `see http://h:80/a@b` is hidden too (`h` reads as the user, `80/a` as the password).
- **Flags are never redacted**: a `bool` or `null` value stays as it is even under a secret key
  (`has_password`, `is_secret`, `"password": null`): a flag carries no secret, and hiding it
  hides what the event says. A number, a text or a container under a secret key still goes whole.
- **A labeller's verdict is hidden** (DEC-204, spec §5.8): in the payload of every `label.created`
  event (`BLIND_EVENT_TYPES`) the keys `label` and `confidence` (`LABEL_KEYS`, matched like the
  secret keys: lower case, `_` and `-` dropped, the whole name) are replaced by `"[đã ẩn]"` at any
  depth, whatever the value (a `null` `confidence`, as the digest's event has, goes too: the rule
  is on the key), for EVERY viewer. Labelling is blind between the two labellers (DEC-019, DEC-101)
  and both are admins, so the page's role guard cannot separate them. The event stays listed with
  its time, `labeler_id`, `alert_id`, `gold_set` and `undo`; the Owner reads the verdicts from
  `triage_labels` and the export tools. The model's `confidence` in `triage.suggested` is not a
  labeller's (on a blind head it goes by the next rule).
- **The blind arm** (DEC-101, context pack §6.4; DEC-206 as amended, P11-T20 part 4 finding I1 and
  round 2 N1): the suggestion of ① is removed from any response, for every role, while the alert
  is blind (`NOT suggestion_visible`) and not yet decided (`status NOT IN visibility.SHOW_STATES`:
  the rule of `tier1/visibility.py`, not a copy of it, its state list passed as a parameter).
  - **Left out.** The rows of `BLIND_OMITTED_EVENT_TYPES` about such an alert are not on the
    page and not in `total`: `triage.suggested`; `llm.gate_forced` (the gate only ever forces
    `needs_review`, `security/gate.py`, and `triage.py` writes the event only when it did, so its
    bare presence tells the verdict); `llm.builder_violation` (it tells that ① produced none,
    the `triage_status` fact `ANALYST_HIDE` hides). The test is a fragment of the page's own WHERE
    (`_BLIND_OMIT`, a primary-key lookup per candidate row), so it applies BEFORE the `LIMIT`:
    pages stay full, the cursor chain stays whole, and `_total` counts the same rows because it
    shares the clauses. They come back once the alert is decided.
  - **Masked.** `autoclose.reviewed` stays listed, a person's event whose presence tells no
    verdict, with the keys of `SUGGESTION_HIDE` (`suggested_action`, `run_id`, written while the
    alert was auto-closed and so visible; a `wrong` verdict reopens it, blind again) replaced by
    `"[đã ẩn]"` at any depth, whatever the value. The page LEFT JOINs `alerts` for the rows of
    `SUGGESTION_EVENT_TYPES` after the page is cut and tells `_payload` which are blind;
    `SUGGESTION_HIDE` is `visibility.ANALYST_HIDE` (so a key added there is hidden here too)
    plus the events' own names. The two other suggestion events are masked the same way there,
    which the first rule makes unreachable: a second line, not a second rule.
  - A subject with no `alerts` row has nothing to say it is blind and is listed as written. No
    other event type is touched (`tier1.decided` carries a suggestion, but an alert is decided
    when it is written, and the only way back to `queued_tier1` is A17, from `auto_closed`,
    which no analyst decided).

Payloads should never carry a credential (DEC-159 item 6); this is the second layer. One
addition to the spec, for the same reason as the
size cut: a payload nested in more than `MAX_PAYLOAD_DEPTH` (32) dicts and lists takes the
truncated shape too (and so does one the JSON parser itself cannot read, a `RecursionError`
from about 9,000 levels). Both fit well under 64 KiB, and FastAPI's serialiser fails on about
250 levels, so one such row would turn the whole page, and every page after it, into a 500.
The browser renders every value as text (v1.0 §6).
"""

from __future__ import annotations

import json
import logging
import re
from datetime import timedelta
from typing import Annotated, Any, Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query
from psycopg import sql
from pydantic import AfterValidator

from app.infra.auth import Claims
from app.tier1 import visibility
from app.web.deps import Conn, require_role

router = APIRouter()

require_admin = require_role("admin")
Admin = Annotated[Claims, Depends(require_admin)]

logger = logging.getLogger(__name__)

#: The page query's `SET LOCAL statement_timeout`, and the total's. Read when a request runs.
QUERY_TIMEOUT = "3s"
TOTAL_TIMEOUT = "1s"

DEFAULT_LIMIT = 50
MAX_LIMIT = 100
_BIGINT_MAX = 2**63 - 1

#: A payload over this many bytes (its `jsonb::text`) is not sent; see the module docstring.
PAYLOAD_MAX_BYTES = 64 * 1024
#: A payload nested in more dicts and lists than this is not sent either. No event the system
#: writes goes past a handful; FastAPI's own JSON serialiser gives up (a 500) a little under 250,
#: and PostgreSQL will store about 15,000, so without a cap one such row would break the page.
MAX_PAYLOAD_DEPTH = 32

#: What a redacted value is replaced by.
REDACTED = "[đã ẩn]"
#: A dict key is redacted when its normalised name (`normalise_key`) equals or ends with one of
#: these. They are written in normalised form: no `_` or `-`, lower case. The first six are spec
#: §5.8; `secretkey`, `privatekey` and `passphrase` were added by the Director's ruling on the fix
#: round (a `token_hash` stays visible: it is a digest, not a credential); `passwd` and `pwd` by
#: DEC-203 item 2b.
REDACT_SUFFIXES = (
    "password",
    "passwordhash",
    "secret",
    "token",
    "dsn",
    "apikey",
    "secretkey",
    "privatekey",
    "passphrase",
    "passwd",
    "pwd",
)
#: DEC-203 item 2a (as amended 18/10): a string that CONTAINS a URL carrying a password
#: (`scheme://user:pass@`), anywhere in it, is redacted whatever its key. `[a-z]` is read
#: case-insensitively: a scheme is not case-sensitive, so `POSTGRESQL://u:p@h` is as much a
#: credential as the lower-case one. This is the DEFINITION of the rule, and what the tests hold
#: `is_secret_value` to; the function does not run it with `search`, because searched as it stands
#: it is quadratic (about 16 s on `"a" * 65536`: every start position rescans the run of scheme
#: characters), and a payload may be 64 KiB.
URL_WITH_PASSWORD = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s]+@", re.IGNORECASE)
_SCHEME_START = re.compile(r"[a-z]", re.IGNORECASE)
_SCHEME_CHAR = re.compile(r"[a-z0-9+.-]", re.IGNORECASE)
#: DEC-204: the keys of a labeller's verdict (`tier1/labels.py` writes both), in normalised form,
#: and the event types whose payload they are hidden in, for every viewer.
LABEL_KEYS = ("label", "confidence")
BLIND_EVENT_TYPES = frozenset({"label.created"})
#: The events whose payload carries the suggestion of ①, and which the blind arm masks it in
#: (module docstring). The page LEFT JOINs `alerts` for these and for no other.
SUGGESTION_EVENT_TYPES = frozenset({"triage.suggested", "llm.gate_forced", "autoclose.reviewed"})
#: DEC-206 as amended (round 2 N1): the events whose bare presence under a blind, undecided alert
#: tells ①'s verdict, or that it produced none. They are left out of the page and of its total.
BLIND_OMITTED_EVENT_TYPES = frozenset(
    {"triage.suggested", "llm.gate_forced", "llm.builder_violation"}
)

#: `?range=` -> the window. Anything else is a 422 from the `Literal` below.
_WINDOWS: dict[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
RangeName = Literal["24h", "7d", "30d"]

#: `?actor=` values that are an `audit_events.actor_role`, not a username.
_ROLE_ACTORS = ("system", "llm")

#: Spec §5.8: the event groups, one table, every name written out (no wildcards) so a test can
#: compare sets. `strings.ts` mirrors it. Every name in `audit.events.EVENT_TYPES` is in exactly
#: one group (`test_admin_audit.py` asserts it), so a new event type must be placed here.
GROUPS: dict[str, tuple[str, ...]] = {
    "users": (
        "admin.user_created",
        "admin.user_updated",
        "authz.denied",
    ),
    "configuration": (
        "admin.autoclose_rule_toggled",
        "admin.settings_changed",
        "autoclose.reviewed",
        "rule.suspected_wrong",
        "label.created",
        # P13-T01 (DEC-210): what an admin did to the learned knowledge.
        "knowledge.approved",
        "knowledge.rejected",
        "knowledge.retired",
        "knowledge.redraft_requested",
    ),
    "alerts_cases": (
        "alert.received",
        "alert.duplicate_merged",
        "alert.auto_closed",
        "alert.autoclose_blocked_critical",
        "alert.enrich_started",
        "alert.enriched",
        "alert.reopened",
        "alert.acknowledged",
        "tier1.decided",
        "tier1.escalated",
        "case.opened",
        "case.truncated",
        "tier2.concluded",
    ),
    "model": (
        "triage.suggested",
        "case.analyzed",
        "llm.gate_forced",
        "llm.builder_violation",
        # P13-T01 (DEC-210): a draft the model wrote, and a draft the model merged into an entry
        # (no admin acts on a merge).
        "knowledge.drafted",
        "knowledge.merged",
    ),
    "system": (
        "job.exhausted",
        "admin.job_retried",
        "health.alarm",
        # P13-T01 (DEC-210): a lookup that failed, and an entry file that no longer matches its hash.
        "rag.lookup_failed",
        "rag.integrity_failed",
    ),
}
#: `?group=` is one of the table's keys (an enum in the OpenAPI schema); anything else is a 422.
GroupName = Literal[tuple(GROUPS)]


def _no_nul(value: str) -> str:
    """PostgreSQL text cannot hold a NUL byte: the driver would raise and the answer be a 500."""
    if "\x00" in value:
        raise ValueError("must not contain a NUL byte")
    return value


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


class PayloadTooDeep(ValueError):
    """A payload nested in more than `MAX_PAYLOAD_DEPTH` dicts and lists."""


def normalise_key(key: str) -> str:
    """Lower case, with `_` and `-` dropped: `apiKey`, `api-key`, `API_KEY` are all `apikey`.

    The spec's "split camelCase" step has no effect of its own here: the split is undone as soon as
    the separators are dropped and the letters lower-cased, so `apiKey` is `apikey` either way."""
    return key.lower().replace("_", "").replace("-", "")


#: The normalised key names hidden in the payload of a `SUGGESTION_EVENT_TYPES` event on a blind,
#: undecided alert: everything `visibility` hides, plus the names `triage.py` gives the verdict in
#: `llm.gate_forced` (`proposed`, `final`, `forced_by`, and `missing`, the gate conditions that
#: were not met, which say what the model proposed) and `forced` of `triage.suggested`.
SUGGESTION_HIDE = frozenset(normalise_key(key) for key in visibility.ANALYST_HIDE) | frozenset(
    normalise_key(key) for key in ("forced", "proposed", "final", "forced_by", "missing")
)


def is_secret_key(key: Any) -> bool:
    """True when the key's normalised name equals or ends with one of `REDACT_SUFFIXES`.

    A suffix, not a substring: `access_token`, `client_secret` and `db_password` are caught, while
    `key`, `token_count`, `tokens_in` and `passwords` are not. A JSON key is always a string; any
    other type is never a secret name."""
    return isinstance(key, str) and normalise_key(key).endswith(REDACT_SUFFIXES)


def _holds_url_password_before(text: str, start: int, at: int) -> bool:
    """Whether `text[start:at]`, a stretch with no whitespace and no `@`, holds a
    `scheme://user:password` that ends exactly at `at` (the `@` that follows it)."""
    sep = text.find("://", start, at)
    while sep != -1:
        # the scheme: a run of scheme characters ending at `://` that holds a letter to begin at
        run = sep
        while run > start and _SCHEME_CHAR.match(text[run - 1]):
            run -= 1
        has_scheme = any(_SCHEME_START.match(ch) for ch in text[run:sep])
        # the user: one or more characters up to a `:`, none of them `/` (a `:` ends it too)
        after = sep + 3
        end = after
        while end < at and text[end] not in "/:":
            end += 1
        # the password: one or more characters up to the `@`
        if has_scheme and end > after and end + 1 < at and text[end] == ":":
            return True
        sep = text.find("://", sep + 1, at)
    return False


def is_secret_value(value: Any) -> bool:
    """True when `value` is a string that contains a URL carrying a password: exactly the strings
    `URL_WITH_PASSWORD.search` finds, in time linear in the length (a test compares the two).

    A match is `scheme://user:password@` with no whitespace and no `@` before its own, so it lies
    wholly between two such characters. The scan therefore takes each `@`, looks back to the
    previous `@` or whitespace, and asks `_holds_url_password_before` about that stretch alone:
    every character is read a bounded number of times. Nothing but a string can be a secret value.
    """
    if not isinstance(value, str) or "@" not in value or "://" not in value:
        return False
    at = value.find("@")
    while at != -1:
        start = at
        while start > 0 and value[start - 1] != "@" and not value[start - 1].isspace():
            start -= 1
        if _holds_url_password_before(value, start, at):
            return True
        at = value.find("@", at + 1)
    return False


def _is_flag(value: Any) -> bool:
    """A `bool` or `None`: a value that cannot carry a secret (checked by type, so `0` is not
    `False` here)."""
    return value is None or isinstance(value, bool)


def _hidden(key: Any, item: Any, hide: frozenset[str]) -> bool:
    """Whether the value `item` under `key` is replaced: the key is one of `hide` (normalised
    names, DEC-204: whatever the value is), or a secret key and the value is not a flag."""
    if isinstance(key, str) and normalise_key(key) in hide:
        return True
    return is_secret_key(key) and not _is_flag(item)


def redact(value: Any, _level: int = 0, *, hide: frozenset[str] = frozenset()) -> Any:
    """A copy of a JSON value with every secret replaced by `REDACTED`, by the rules of the
    module docstring.

    A key matches when `is_secret_key` says so, at any depth, through lists and nested dicts; the
    whole value under such a key goes, whatever it is, unless it is a `bool` or `None` (a flag is
    never redacted). A string that `is_secret_value` names goes under any key. `hide` is a set of
    NORMALISED key names (`LABEL_KEYS` for a `label.created` event, DEC-204) whose value goes at
    any depth whatever it is, flags included; it is empty unless the caller passes it. Everything
    else is returned as it is: the same numbers, strings and `None`, in the same structure. The
    input is never modified. `_level` is the number of containers already entered: a value
    nested in more than `MAX_PAYLOAD_DEPTH` of them raises `PayloadTooDeep` rather than
    recursing on."""
    if isinstance(value, (dict, list)):
        if _level >= MAX_PAYLOAD_DEPTH:
            raise PayloadTooDeep(f"nested deeper than {MAX_PAYLOAD_DEPTH} levels")
        if isinstance(value, dict):
            return {
                key: REDACTED if _hidden(key, item, hide) else redact(item, _level + 1, hide=hide)
                for key, item in value.items()
            }
        return [redact(item, _level + 1, hide=hide) for item in value]
    return REDACTED if is_secret_value(value) else value


def _payload(text: str | None, size: int | None, event_type: str, blind: bool = False) -> Any:
    """The `payload` of one row from its two SQL columns: `text` is the jsonb as text, or NULL
    when it was over the size limit; `size` is its byte length, or NULL for a SQL NULL payload;
    `event_type` is the row's, and decides whether a labeller's verdict is hidden in it
    (`BLIND_EVENT_TYPES`, DEC-204); `blind` is the page query's verdict on the row's alert (a
    `SUGGESTION_EVENT_TYPES` event on a blind, undecided alert: the keys of `SUGGESTION_HIDE` go,
    P11-T20 part 4 finding I1). A payload that cannot be returned whole (too big, too deep,
    too deep for the JSON parser itself, or holding a number that parser refuses) is
    `{"truncated": true, "size": <bytes>}`; one of those never leaks a secret or a verdict, it
    is not sent at all.

    `ValueError` is the parser's own refusals (`JSONDecodeError`, and the integer-string limit
    of 4,300 digits, which jsonb does not have) and `PayloadTooDeep`; `RecursionError` is the
    parser running out of stack. None of them may take the whole page down."""
    if size is None:
        return None
    if text is None:
        return {"truncated": True, "size": size}
    hide = frozenset(LABEL_KEYS) if event_type in BLIND_EVENT_TYPES else frozenset()
    if blind:
        hide |= SUGGESTION_HIDE
    try:
        return redact(json.loads(text), hide=hide)
    except (ValueError, RecursionError):
        return {"truncated": True, "size": size}


# ---------------------------------------------------------------------------
# The two queries
# ---------------------------------------------------------------------------

_SET_TIMEOUT = sql.SQL("SET LOCAL statement_timeout = {}")

# The page is selected FIRST (the inner `ORDER BY audit_id DESC LIMIT n`, which the primary key
# serves, or a Sort over the filter's rows when a `subject` or `group` filter picks another index).
# Only then is each of its (at most 100) rows' payload turned into text, ONCE, in the fenced
# LATERAL: `OFFSET 0` keeps the planner from flattening `b` back into the select list, where the
# CASE test, its ELSE branch and the size column would each repeat the conversion, and for every
# row a Sort plan orders, not only the page's. Measured on the scratch server (payloads of 1.36 MB
# of text, 15.6 KB stored): 600 of them under one subject took the old query 3.3 s (a 503), this
# one 0.27 s. `size` is NULL for a SQL NULL payload; the outer ORDER BY restores the page's order
# after the join (100 rows). The last column is the blind arm's verdict on the row (module
# docstring): the join to `alerts` is by its primary key, made only for the three suggestion
# events, after the page is cut; the decided states are `visibility.SHOW_STATES`, a parameter.
_PAGE = sql.SQL("""
    SELECT p.audit_id, p.created_at, p.event_type, p.actor_role, u.username, p.subject_id,
           CASE WHEN t.size > %(max_bytes)s THEN NULL ELSE t.body END,
           t.size,
           COALESCE(NOT al.suggestion_visible AND al.status <> ALL(%(show_states)s), false)
    FROM (
        SELECT a.audit_id, a.created_at, a.event_type, a.actor_role, a.actor_id, a.subject_id,
               a.payload
        FROM audit_events a
        WHERE {where}
        ORDER BY a.audit_id DESC
        LIMIT %(limit)s
    ) p
    LEFT JOIN users u ON u.user_id = p.actor_id AND p.actor_role IN ('analyst', 'admin')
    LEFT JOIN alerts al ON al.alert_id = p.subject_id
                       AND p.event_type = ANY(%(suggestion_events)s)
    CROSS JOIN LATERAL (
        SELECT b.body, octet_length(b.body) AS size
        FROM (SELECT p.payload::text AS body OFFSET 0) b
    ) t
    ORDER BY p.audit_id DESC
    """)

_COUNT = sql.SQL("SELECT count(*) FROM audit_events a WHERE {where}")

# The rows of `BLIND_OMITTED_EVENT_TYPES` whose alert is blind and undecided are not selected: a
# fragment of the WHERE, so the inner page selection applies it before its `LIMIT` and the total
# counts the same rows. A SCALAR subquery (a primary-key lookup, run only for a row whose type is
# in the list: the type test is the cheap one and the planner puts it first), not NOT EXISTS,
# which the planner may turn into an anti join that reads every alert. NULL (no `alerts` row)
# is false: nothing says such a subject is blind.
_BLIND_OMIT = sql.SQL(
    "NOT (a.event_type = ANY(%(omitted_events)s) AND COALESCE("
    "(SELECT NOT al.suggestion_visible AND al.status <> ALL(%(show_states)s) "
    "FROM alerts al WHERE al.alert_id = a.subject_id), false))"
)
# The same predicate for the total, as an anti join. The total reads every row of the window, and
# the planner runs this form as a parallel hash anti join over the blind alerts (measured on the
# scratch server, 250,000 events and 60,000 alerts: 37 ms against 280 ms for the scalar form, a
# lookup per row); the page reads a few dozen rows, where the scalar form is a handful of index
# lookups (1.3 ms) and an anti join is not wanted. Two spellings, one meaning, held together by a
# test that counts with both.
_BLIND_OMIT_COUNT = sql.SQL(
    "NOT EXISTS (SELECT 1 FROM alerts al WHERE al.alert_id = a.subject_id "
    "AND a.event_type = ANY(%(omitted_events)s) AND NOT al.suggestion_visible "
    "AND al.status <> ALL(%(show_states)s))"
)


def _filters(
    window: timedelta, group: str | None, actor: str | None, subject: str | None
) -> tuple[list[sql.SQL], dict[str, Any]]:
    """The WHERE's fixed fragments and the parameters they name. A request value only ever
    reaches the parameter dict; a fragment is chosen by which filters were given. `_BLIND_OMIT`
    is always there (and so are its two parameters, `show_states` for the page's own join too)."""
    clauses = [sql.SQL("a.created_at >= now() - %(window)s"), _BLIND_OMIT]
    params: dict[str, Any] = {
        "window": window,
        "omitted_events": sorted(BLIND_OMITTED_EVENT_TYPES),
        "show_states": sorted(visibility.SHOW_STATES),
    }
    if group is not None:
        clauses.append(sql.SQL("a.event_type = ANY(%(types)s)"))
        params["types"] = list(GROUPS[group])
    if actor in _ROLE_ACTORS:
        clauses.append(sql.SQL("a.actor_role = %(actor_role)s"))
        params["actor_role"] = actor
    elif actor is not None:
        # Only an `analyst` or `admin` row has a user to name (spec §5.8: null for system and llm;
        # the CHECK would let an `llm` row carry an `actor_id`), the same condition as the page's
        # join. An unknown username makes the subquery NULL, and `actor_id = NULL` matches no row.
        clauses.append(
            sql.SQL(
                "a.actor_role IN ('analyst', 'admin') AND "
                "a.actor_id = (SELECT u2.user_id FROM users u2 WHERE u2.username = %(actor)s)"
            )
        )
        params["actor"] = actor
    if subject is not None:
        clauses.append(sql.SQL("a.subject_id = %(subject)s"))
        params["subject"] = subject
    return clauses, params


def _where(clauses: list[sql.SQL]) -> sql.Composed:
    return sql.SQL(" AND ").join(clauses)


def _page_statement(
    clauses: list[sql.SQL], params: dict[str, Any], cursor: int | None, limit: int
) -> tuple[sql.Composed, dict[str, Any]]:
    """The page query and its parameters: the filter's fragments, plus the cursor's when given.
    The inputs are not modified (the same `clauses` and `params` also feed the total)."""
    clauses = list(clauses)
    params = {
        **params,
        "max_bytes": PAYLOAD_MAX_BYTES,
        "limit": limit,
        "suggestion_events": sorted(SUGGESTION_EVENT_TYPES),
    }
    if cursor is not None:
        clauses.append(sql.SQL("a.audit_id < %(cursor)s"))
        params["cursor"] = cursor
    return _PAGE.format(where=_where(clauses)), params


def _fetch_page(
    conn: Any, clauses: list[sql.SQL], params: dict[str, Any], cursor: int | None, limit: int
) -> list[tuple[Any, ...]]:
    """One page, in a savepoint under `QUERY_TIMEOUT`. A cancelled query is the 503; any other
    database error is left to be the 500 it is."""
    statement, bound = _page_statement(clauses, params, cursor, limit)
    try:
        with conn.transaction():
            conn.execute(_SET_TIMEOUT.format(sql.Literal(QUERY_TIMEOUT)))
            return conn.execute(statement, bound).fetchall()
    except psycopg.errors.QueryCanceled as exc:
        # The log carries the fact, not the filter values (they are request text).
        logger.warning("audit page query cancelled by statement_timeout=%s", QUERY_TIMEOUT)
        raise HTTPException(status_code=503, detail={"reason": "timeout"}) from exc


def _count_matching(conn: Any, where: sql.Composable, params: dict[str, Any]) -> int:
    (count,) = conn.execute(_COUNT.format(where=where), params).fetchone()
    return count


def _total(conn: Any, clauses: list[sql.SQL], params: dict[str, Any]) -> int | None:
    """`count(*)` of the filter in a savepoint of its own under `TOTAL_TIMEOUT`; `None` when it
    is cancelled or fails. The rollback of the savepoint is what leaves the transaction usable."""
    try:
        with conn.transaction():
            conn.execute(_SET_TIMEOUT.format(sql.Literal(TOTAL_TIMEOUT)))
            counted = [_BLIND_OMIT_COUNT if clause is _BLIND_OMIT else clause for clause in clauses]
            return _count_matching(conn, _where(counted), params)
    except psycopg.Error as exc:
        # The class and SQLSTATE only: the message can hold SQL text.
        logger.warning("audit total unavailable: %s %s", type(exc).__name__, exc.sqlstate)
        return None


# ---------------------------------------------------------------------------
# The route
# ---------------------------------------------------------------------------


@router.get("/api/admin/audit")
def api_audit(
    conn: Conn,
    claims: Admin,
    range_: Annotated[RangeName, Query(alias="range")] = "7d",
    group: Annotated[GroupName | None, Query()] = None,
    actor: Annotated[str | None, Query(min_length=1), AfterValidator(_no_nul)] = None,
    subject: Annotated[str | None, Query(min_length=1), AfterValidator(_no_nul)] = None,
    cursor: Annotated[int | None, Query(ge=1, le=_BIGINT_MAX)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
) -> dict[str, Any]:
    clauses, params = _filters(_WINDOWS[range_], group, actor, subject)
    rows = _fetch_page(conn, clauses, params, cursor, limit)
    events = [
        {
            "audit_id": audit_id,
            "created_at": created_at,
            "event_type": event_type,
            "actor_role": actor_role,
            "actor_username": username,
            "subject_id": subject_id,
            "payload": _payload(text, size, event_type, blind),
        }
        for (
            audit_id,
            created_at,
            event_type,
            actor_role,
            username,
            subject_id,
            text,
            size,
            blind,
        ) in rows
    ]
    return {
        "events": events,
        "next_cursor": events[-1]["audit_id"] if len(events) == limit else None,
        "total": _total(conn, clauses, params),
    }
