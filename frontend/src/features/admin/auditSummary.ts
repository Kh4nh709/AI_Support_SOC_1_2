// What the audit page makes of an event (spec §4.7): the one-line summary of each of the 36 event types, built
// client-side from the payload; the link of a subject that is an alert or a case; the payload as text; and the
// escape of the characters a person cannot see.
//
// A payload is whatever the writers of the events put there (a person's free text among it), and the server
// has only cut it down and redacted it, so nothing here trusts its shape: every key is read with `own`, a
// value of the wrong kind is the same as a missing one, a number that is not finite is never printed, and a
// free text is put on one line and cut. Everything returned is text for React to show as text.
import type { AuditEvent } from "../../api/admin";
import { S, labelOf } from "../../strings";

const A = S.admin.auditPage.summary;

type Obj = Readonly<Record<string, unknown>>;

/**
 * What the server puts in the place of a value it withholds: a secret (spec §5.8), a labeller's verdict (DEC-204)
 * and, since P11-T20 part 4, ①'s suggestion on an alert that is blind and not yet decided (DEC-101, context pack
 * §6.4). `REDACTED` of admin_audit.py, which adminTypes.test.ts compares.
 */
export const REDACTED = "[đã ẩn]";

// --- the characters a person cannot see -------------------------------------------------------------------------

// The C0 controls but tab, line feed and carriage return; DEL and the C1 controls; the soft hyphen; the
// combining grapheme joiner; the Arabic letter mark; the Hangul fillers (U+115F, U+1160, U+3164, U+FFA0); the
// mongolian vowel separator; the zero-width and bidi marks, the line and paragraph separators, the word joiner
// and its invisible neighbours; the blank braille pattern; the variation selectors (U+FE00 to U+FE0F); the
// byte-order mark; the interlinear annotation marks; and the Tag characters (U+E0001, U+E0020 to U+E007F),
// which spell ASCII text a person cannot see and a model may read. A right-to-left override among them could
// make one name read as another. The Tag characters are outside the BMP, so the pattern has the `u` flag.
// Text in other scripts (Vietnamese in NFC or NFD, CJK, Arabic, Hebrew) is none of these and is left alone.
const INVISIBLE_RANGES: readonly (readonly [number, number])[] = [
  [0x00, 0x08],
  [0x0b, 0x0c],
  [0x0e, 0x1f],
  [0x7f, 0x9f],
  [0xad, 0xad],
  [0x34f, 0x34f],
  [0x61c, 0x61c],
  [0x115f, 0x1160],
  [0x180e, 0x180e],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x206f],
  [0x2800, 0x2800],
  [0x3164, 0x3164],
  [0xfe00, 0xfe0f],
  [0xfeff, 0xfeff],
  [0xffa0, 0xffa0],
  [0xfff9, 0xfffb],
  [0xe0001, 0xe0001],
  [0xe0020, 0xe007f],
];
/** The escape of a code point as the text shows it: four hex digits, or `{...}` for one outside the BMP. */
const escapeOf = (code: number): string =>
  code > 0xffff ? `\\u{${code.toString(16)}}` : `\\u${code.toString(16).padStart(4, "0")}`;
// The ranges as the inside of a character class, each end an escape: no control character is written into
// the source, and none can be lost from it.
const CLASS = INVISIBLE_RANGES.map(
  ([from, to]) => `${escapeOf(from)}${from === to ? "" : `-${escapeOf(to)}`}`,
).join("");
const INVISIBLE = new RegExp(`[${CLASS}]`, "gu");

/** True when the text holds a character a person cannot see. */
export const hasInvisible = (text: string): boolean => new RegExp(`[${CLASS}]`, "u").test(text);

/**
 * A text with each character a person cannot see written as its escape (`\u` and four hex digits, or
 * `\u{...}` outside the BMP), so what is shown is what is there.
 */
export function visible(text: string): string {
  return text.replace(INVISIBLE, (ch) => escapeOf(ch.codePointAt(0) ?? 0));
}

// --- reading a payload that may be anything ---------------------------------------------------------------------

const asObject = (value: unknown): Obj | null =>
  typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Obj) : null;

/** A key of the object itself, never one the prototype chain would answer (`constructor`, `__proto__`). */
const own = (object: Obj | null, key: string): unknown =>
  object !== null && Object.hasOwn(object, key) ? object[key] : undefined;

/** True when the server withheld the value under `key`: any one of `keys` holds the marker. */
const withheld = (object: Obj | null, ...keys: string[]): boolean =>
  keys.some((key) => own(object, key) === REDACTED);

const str = (object: Obj | null, key: string): string | null => {
  const value = own(object, key);
  return typeof value === "string" && value !== "" ? value : null;
};
const num = (object: Obj | null, key: string): number | null => {
  const value = own(object, key);
  return typeof value === "number" && Number.isFinite(value) ? value : null;
};
const list = (object: Obj | null, key: string): unknown[] | null => {
  const value = own(object, key);
  return Array.isArray(value) ? value : null;
};
const texts = (items: unknown[] | null): string[] =>
  (items ?? []).filter((item): item is string => typeof item === "string" && item !== "");

/** The longest free text a summary carries, in characters; the whole payload is one click away. */
const FREE_MAX = 120;

/** A text from the payload, on one line and cut to `FREE_MAX` characters, with an ellipsis where it was cut. */
function free(value: string): string {
  const line = value.replace(/\s+/g, " ").trim();
  if (line.length <= FREE_MAX) return line;
  let cut = line.slice(0, FREE_MAX - 1);
  const last = cut.charCodeAt(cut.length - 1);
  if (last >= 0xd800 && last <= 0xdbff) cut = cut.slice(0, -1); // not half of a surrogate pair
  return `${cut}…`;
}

const bytes = new Intl.NumberFormat("vi-VN");

// --- the payload the server did not send ------------------------------------------------------------------------

/**
 * The size of a payload the server cut (`{"truncated": true, "size": <bytes>}`, over 64 KiB or nested too deep:
 * admin_audit.py), or null for any other payload. The marker has exactly those two keys, so a payload that
 * only has a key of that name is not mistaken for it.
 */
export function tooBigSize(payload: unknown): number | null {
  const object = asObject(payload);
  if (object === null || Object.keys(object).length !== 2) return null;
  const size = own(object, "size");
  return own(object, "truncated") === true &&
    typeof size === "number" &&
    Number.isInteger(size) &&
    size >= 0
    ? size
    : null;
}

// --- one summary per event type ---------------------------------------------------------------------------------

type Builder = (payload: Obj | null) => string[];

/** A clause for a text that may be missing: nothing when it is. */
const when = <T>(value: T | null, clause: (value: T) => string): string[] =>
  value === null ? [] : [clause(value)];

/** The clause naming a draft by its id, or nothing. */
const draftClause = (p: Obj | null): string[] =>
  when(str(p, "draft_id"), (id) => A.draftId(free(id)));
/** The clause naming an entry by its id, or nothing. */
const entryClause = (p: Obj | null): string[] =>
  when(str(p, "entry_id"), (id) => A.entryId(free(id)));
/** The admin's reason, on one line and cut, or nothing. */
const reasonClause = (p: Obj | null): string[] =>
  when(str(p, "reason"), (reason) => A.reason(free(reason)));

/** The summary of an event type is its clauses, the first one standing alone when the payload says no more. */
const BUILDERS: Readonly<Record<string, Builder>> = {
  "alert.received": () => [A.received],
  "alert.duplicate_merged": (p) => {
    const parent = str(p, "parent");
    return parent === null
      ? [A.mergedUnknown]
      : [A.mergedInto(free(parent)), ...when(num(p, "occurrence"), A.occurrence)];
  },
  "alert.auto_closed": (p) => [
    ...(str(p, "rule_name") === null
      ? [A.autoClosed]
      : when(str(p, "rule_name"), (name) => A.autoClosedBy(free(name)))),
    ...when(str(p, "reason"), (reason) => A.reason(free(reason))),
  ],
  "alert.autoclose_blocked_critical": (p) => [
    A.blockedCritical,
    ...when(str(p, "rule_id"), (rule) => A.blockedRule(free(rule))),
  ],
  "alert.enrich_started": () => [A.enrichStarted],
  "alert.enriched": (p) => [
    A.enriched,
    ...when(num(p, "risk_score"), A.riskScore),
    ...(own(p, "exhausted") === true ? [A.enrichExhausted] : []),
  ],
  "alert.reopened": (p) => [A.reopened, ...when(str(p, "reason"), (r) => A.reason(free(r)))],
  "alert.acknowledged": () => [A.acknowledged],
  "tier1.decided": (p) => {
    const decision = str(p, "decision");
    return [
      decision === null ? A.decidedUnknown : A.decided(free(labelOf(S.status, decision))),
      ...when(str(p, "reason"), (reason) => A.reason(free(reason))),
    ];
  },
  "tier1.escalated": (p) => {
    const caseId = str(p, "case_id");
    const alerts = list(p, "alert_ids");
    return [
      caseId === null ? A.escalatedUnknown : A.escalated(free(caseId)),
      ...when(alerts, (items) => A.alertCount(items.length)),
    ];
  },
  "case.opened": (p) => {
    const trigger = str(p, "trigger_alert_id");
    const count = num(p, "alert_count");
    const correlated = num(p, "correlated_count");
    return [
      trigger === null ? A.caseOpenedUnknown : A.caseOpened(free(trigger)),
      ...(count !== null && correlated !== null ? [A.caseSize(count, correlated)] : []),
    ];
  },
  "case.truncated": (p) => {
    // The writer sends a count; a list of what was dropped is read as its length.
    const dropped = own(p, "dropped");
    const n = Array.isArray(dropped) ? dropped.length : num(p, "dropped");
    return [n === null ? A.truncatedUnknown : A.truncated(n)];
  },
  "tier2.concluded": (p) => {
    const conclusion = str(p, "conclusion");
    return [
      conclusion === null
        ? A.concludedUnknown
        : A.concluded(free(labelOf(S.conclusion, conclusion))),
      ...when(str(p, "reason"), (reason) => A.reason(free(reason))),
    ];
  },
  "case.analyzed": (p) => [A.analyzed, ...when(num(p, "job_id"), A.job)],
  "triage.suggested": (p) => {
    // Withheld by the server: one line, whichever of the keys it took, and none of what is left is read.
    // (The server leaves such a row out since DEC-206's amendment; this is for a row an older one masked.)
    if (withheld(p, "suggested_action", "confidence", "forced", "run_id"))
      return [A.suggestionHidden];
    const action = str(p, "suggested_action");
    if (action === null) return [A.suggestedUnknown];
    return [
      A.suggested(free(labelOf(S.ai1.action, action))),
      ...when(str(p, "confidence"), (level) => A.confidence(free(labelOf(S.confidence, level)))),
      ...(own(p, "forced") === true ? [A.gateForced] : []),
    ];
  },
  "llm.gate_forced": (p) => {
    if (withheld(p, "proposed", "final", "forced_by", "missing")) return [A.gateForcedHidden];
    const proposed = str(p, "proposed");
    const final = str(p, "final");
    return [
      proposed !== null && final !== null
        ? A.gateForcedBy(free(labelOf(S.ai1.action, proposed)), free(labelOf(S.ai1.action, final)))
        : A.gateForcedUnknown,
      ...when(str(p, "forced_by"), (who) => A.forcedBy(free(who))),
    ];
  },
  "llm.builder_violation": (p) => {
    const n = num(p, "violations_count");
    return [n === null ? A.builderViolationUnknown : A.builderViolation(n)];
  },
  "job.exhausted": (p) => {
    const attempts = num(p, "attempts");
    return [
      attempts === null ? A.exhaustedUnknown : A.exhausted(attempts),
      ...when(str(p, "reason"), (reason) => A.reason(free(labelOf(A.exhaustedReason, reason)))),
    ];
  },
  "admin.user_created": (p) => [
    ...(str(p, "username") === null
      ? [A.userCreatedUnknown]
      : when(str(p, "username"), (name) => A.userCreated(free(name)))),
    ...when(str(p, "role"), (role) => A.roleIs(free(labelOf(S.role, role)))),
  ],
  "admin.user_updated": (p) => {
    const before = asObject(own(p, "before"));
    const after = asObject(own(p, "after"));
    const action = str(p, "action");
    const clauses: string[] = [];
    if (action === "password_reset") clauses.push(A.userPassword);
    if (action === "unlock") clauses.push(A.userUnlock);
    // `before` and `after` hold the fields that changed, and only those; a field that is the same in both
    // (a payload that lists more than it changed) is not a change.
    const changed = (key: string) => {
      const now = own(after, key);
      return now !== undefined && own(before, key) !== now;
    };
    const role = changed("role") ? str(after, "role") : null;
    if (role !== null) {
      const was = str(before, "role");
      clauses.push(
        was === null
          ? A.roleIs(free(labelOf(S.role, role)))
          : A.userRole(free(labelOf(S.role, was)), free(labelOf(S.role, role))),
      );
    }
    const active = changed("is_active") ? own(after, "is_active") : undefined;
    if (active === true) clauses.push(A.userActivated);
    if (active === false) clauses.push(A.userDeactivated);
    if (changed("display_name")) clauses.push(A.userRenamed);
    // What the server does to the sessions: a role change, a deactivation and a reset end them.
    if (action === "password_reset" || role !== null || active === false) {
      clauses.push(A.userSessionsEnded);
    }
    if (clauses.length === 0) clauses.push(A.userUpdatedUnknown);
    const username = str(p, "username");
    return username === null ? clauses : [`${free(username)}: ${clauses[0]}`, ...clauses.slice(1)];
  },
  "admin.job_retried": (p) => {
    const type = str(p, "job_type");
    const id = num(p, "job_id") ?? str(p, "job_id");
    return [
      type !== null && id !== null
        ? A.jobRetried(free(type), free(String(id)))
        : A.jobRetriedUnknown,
      ...when(num(p, "attempts_before"), A.attemptsBefore),
    ];
  },
  "authz.denied": (p) => {
    const required = texts(list(p, "required"));
    const role = str(p, "role");
    const clauses = [
      ...(required.length === 0
        ? []
        : [A.deniedNeeds(required.map((r) => free(labelOf(S.role, r))).join(" hoặc "))]),
      ...when(role, (r) => A.denied(free(labelOf(S.role, r)))),
      ...(own(p, "reason") === "actor_no_longer_admin" ? [A.deniedRoleChanged] : []),
    ];
    if (clauses.length === 0) clauses.push(A.deniedUnknown);
    const method = str(p, "method");
    return method === null ? clauses : [`${free(method)}: ${clauses[0]}`, ...clauses.slice(1)];
  },
  "admin.autoclose_rule_toggled": (p) => {
    const name = str(p, "name");
    const before = own(p, "before");
    const after = own(p, "after");
    if (name === null || typeof before !== "boolean" || typeof after !== "boolean") {
      return [A.ruleToggledUnknown];
    }
    return [A.ruleToggled(free(name), before ? A.on : A.off, after ? A.on : A.off)];
  },
  "autoclose.reviewed": (p) => [
    ...(str(p, "verdict") === null
      ? [A.reviewedUnknown]
      : when(str(p, "verdict"), (v) => A.reviewed(free(labelOf(S.admin.verdict, v))))),
    ...(withheld(p, "suggested_action", "run_id")
      ? [A.suggestionHidden]
      : when(str(p, "suggested_action"), (action) =>
          A.suggested(free(labelOf(S.ai1.action, action))),
        )),
  ],
  "rule.suspected_wrong": (p) => {
    const count = num(p, "wrong_count");
    if (count === null) return [A.suspectedUnknown];
    const window = str(p, "window");
    const days = window === null ? null : /^(\d{1,4}) days?$/.exec(window);
    const span =
      window === null ? A.recently : days === null ? free(window) : A.window(Number(days[1]));
    return [A.suspectedWrong(count, span)];
  },
  "label.created": (p) => {
    // That someone labelled a cluster, or undid it: the cluster, the gold set, the undo flag. Never the
    // verdict (DEC-204): the line does not read `label` or `confidence`, whether the server redacted them or
    // not, nor `source` (a digest review labels "false_positive", and saying it came from one would say so).
    const cluster = str(p, "alert_id");
    const base =
      own(p, "undo") === true
        ? cluster === null
          ? A.labelUndoneUnknown
          : A.labelUndone(free(cluster))
        : cluster === null
          ? A.labelledUnknown
          : A.labelled(free(cluster));
    return [base, ...when(str(p, "gold_set"), (name) => A.goldSet(free(name)))];
  },
  "admin.settings_changed": (p) => {
    const changes = (list(p, "changes") ?? []).flatMap((entry) => {
      const change = asObject(entry);
      const key = str(change, "key");
      const from = shown(own(change, "old"));
      const to = shown(own(change, "new"));
      return key === null || from === null || to === null
        ? []
        : [A.limitChange(free(labelOf(A.limitName, key)), from, to)];
    });
    return changes.length === 0 ? [A.limitUnknown] : changes;
  },
  "health.alarm": (p) => {
    const names = (items: unknown[] | null) =>
      texts(items)
        .slice(0, 10)
        .map((name) => free(labelOf(S.admin.overviewPage.health.check, name)))
        .join(", ");
    const added = names(list(p, "new"));
    const failing = names(list(p, "failing"));
    const clauses = [
      ...(added === "" ? [] : [A.alarmNew(added)]),
      ...(failing === "" ? [] : [A.alarmFailing(failing)]),
    ];
    return clauses.length === 0 ? [A.alarmUnknown] : clauses;
  },
  // The learned-knowledge events (DEC-210). Each reads at most an id and the admin's reason; none reads what a
  // draft or an entry says, whatever else the payload holds.
  "knowledge.drafted": (p) => [A.knowledgeDrafted, ...draftClause(p)],
  "knowledge.approved": (p) => [A.knowledgeApproved, ...entryClause(p)],
  "knowledge.rejected": (p) => [A.knowledgeRejected, ...draftClause(p), ...reasonClause(p)],
  "knowledge.retired": (p) => [A.knowledgeRetired, ...entryClause(p), ...reasonClause(p)],
  "knowledge.merged": (p) => [A.knowledgeMerged, ...entryClause(p)],
  "knowledge.redraft_requested": (p) => [A.knowledgeRedraft, ...draftClause(p)],
  "rag.lookup_failed": () => [A.lookupFailed],
  "rag.integrity_failed": (p) => [A.integrityFailed, ...entryClause(p)],
};

/** A value of a limit change as text: a finite number or a text; anything else is not a value. */
function shown(value: unknown): string | null {
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return typeof value === "string" && value !== "" ? free(value) : null;
}

/**
 * The one-line summary of an event: its clauses joined with "; ", with what a person cannot see written out.
 * An event type this client has no line for is a dash, never a blank; a payload the server cut says so.
 */
export function summaryOf(event: Pick<AuditEvent, "event_type" | "payload">): string {
  if (!Object.hasOwn(BUILDERS, event.event_type)) return S.common.missing;
  const size = tooBigSize(event.payload);
  if (size !== null) return visible(A.tooBig(bytes.format(size)));
  const build = BUILDERS[event.event_type] as Builder;
  return visible(build(asObject(event.payload)).join("; "));
}

// --- the subject ------------------------------------------------------------------------------------------------

/** The events whose subject is an alert (`alert_id`), by event type. */
const ALERT_SUBJECT: ReadonlySet<string> = new Set([
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
  "triage.suggested",
  "llm.gate_forced",
  "llm.builder_violation",
  "autoclose.reviewed",
  "label.created",
]);

/** The events whose subject is a case (`case_id`). */
const CASE_SUBJECT: ReadonlySet<string> = new Set([
  "case.opened",
  "case.truncated",
  "case.analyzed",
  "tier2.concluded",
]);

/**
 * The in-app path of an event's subject when it is an alert or a case, else null: a rule, a user, a job, a
 * limit, a request path and a health check have no page of their own to open. The id is encoded, so it stays one
 * path segment whatever it holds. (`job.exhausted` names a job's subject, which is an alert, a case or a day
 * depending on the job, and the event does not say: no link.)
 */
export function subjectPathOf(event: Pick<AuditEvent, "event_type" | "subject_id">): string | null {
  const id = event.subject_id;
  if (typeof id !== "string" || id === "") return null;
  if (ALERT_SUBJECT.has(event.event_type)) return `/alerts/${encodeURIComponent(id)}`;
  if (CASE_SUBJECT.has(event.event_type)) return `/cases/${encodeURIComponent(id)}`;
  return null;
}

// --- the payload ------------------------------------------------------------------------------------------------

/**
 * The payload as the text of the block that shows it: pretty-printed JSON with two spaces, empty for no
 * payload. JSON writes a control character as an escape already; `visible` writes the rest of what a person
 * cannot see. A value `JSON.stringify` cannot write (a cycle, a bigint: not what the server sends, but it is
 * not for this function to throw) is its string form, and one with none is empty.
 */
export function payloadText(payload: unknown): string {
  if (payload === null || payload === undefined) return "";
  try {
    const json = JSON.stringify(payload, null, 2);
    if (json !== undefined) return visible(json);
  } catch {
    // fall through to the string form
  }
  try {
    return visible(String(payload));
  } catch {
    return "";
  }
}

/** The event types whose rows the canvas tints: a refusal and an alarm. */
const ALARM_EVENTS: ReadonlySet<string> = new Set(["authz.denied", "health.alarm"]);
export const isAlarmEvent = (eventType: string): boolean => ALARM_EVENTS.has(eventType);
