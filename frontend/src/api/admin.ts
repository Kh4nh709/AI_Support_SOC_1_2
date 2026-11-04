// The admin routes (P11-T10), one typed function each, written by hand against the handlers: the backend
// answers with plain dicts, so there is no generated schema to import. The handlers are
//   web/routers/admin_users.py, admin_llm.py, admin_overview.py, admin_rules.py, admin_digest.py,
//   labels.py, admin_audit.py, admin_knowledge.py (the learned knowledge, DEC-210), and
//   `POST /api/admin/reload-inventory` in web/main.py.
// Every string a person or the model wrote arrives as text and is rendered as text; nothing here is markup.
//
// Two rules of the client:
//   - Every write sends a JSON body, `{}` when it has nothing to say. `admin_users.py` reads its bodies by
//     hand and answers a POST with no `Content-Type: application/json` with a 422 (`unlock` is the case that
//     bit: P11-T02 review, m3), and the labels undo asks for a JSON body too. The routes that read none
//     (the job retry, the inventory reload) ignore it, so one rule covers every write.
//   - An error is read by `adminErrorOf`, never by a status alone: the server's `detail` is an object with a
//     machine-readable `reason` (spec §3), and the pages map it to text through `S.admin.reason`.
//
// The types follow the handlers as merged (P11-T06 and P11-T08 included): a key the handler always sends is
// a required key here, and `adminTypes.test.ts` compares every type with the keys the backend builds, so
// a field cannot go optional, or missing, without a test failing.
import { ApiError, api } from "./client";
import type { AlertView } from "./tier1";
import type { CaseDetail, CaseNote, InvestigationView } from "./tier2";
import type { Role } from "./types";

const enc = encodeURIComponent;

// --- shared vocabulary ------------------------------------------------------------------------------------

/** `?range=` of the overview and the audit page. */
export const ADMIN_RANGES = ["24h", "7d", "30d"] as const;
export type AdminRange = (typeof ADMIN_RANGES)[number];

/** `?range=` of the LLM usage page: the three above and the calendar month. */
export const LLM_RANGES = ["24h", "7d", "30d", "month"] as const;
export type LlmRange = (typeof LLM_RANGES)[number];

/** The groups of the audit page (`GROUPS` of admin_audit.py), in the order the filter lists them. */
export const AUDIT_GROUPS = ["users", "configuration", "alerts_cases", "model", "system"] as const;
export type AuditGroup = (typeof AUDIT_GROUPS)[number];

/** The six G8' hard blocks, in the order of `_HARD_BLOCK_ORDER` (admin_rules.py): `ingest/autoclose.py`'s codes. */
export const HARD_BLOCK_CODES = [
  "critical",
  "never_autoclose_agent",
  "asset_high",
  "asset_not_in_inventory",
  "identity_privileged",
  "ioc_bad",
] as const;
export type HardBlockCode = (typeof HARD_BLOCK_CODES)[number];

/** The verdicts of a digest review (`_VERDICT_LABEL` of admin_digest.py). */
export const DIGEST_VERDICTS = ["correct", "wrong", "unsure"] as const;
export type DigestVerdict = (typeof DIGEST_VERDICTS)[number];

/** The labels and confidences of blind labelling (`LabelIn` of labels.py). */
export const LABEL_CHOICES = ["false_positive", "benign", "escalate"] as const;
export type LabelChoice = (typeof LABEL_CHOICES)[number];
export const LABEL_CONFIDENCES = [1, 2, 3] as const;
export type LabelConfidence = (typeof LABEL_CONFIDENCES)[number];

/**
 * What the forms may check before they post, equal to the constants of the routes (a test reads them):
 * `PASSWORD_MIN_CHARS`, `PASSWORD_MAX_CHARS`, `USERNAME_RE` and `DISPLAY_NAME_MAX_CHARS` of admin_users.py,
 * `NOTE_MAX_CHARS` of tier1/labels.py. The server still has the last word.
 */
export const ADMIN_LIMITS = {
  passwordMin: 12,
  passwordMax: 256,
  displayNameMax: 100,
  noteMax: 200,
  username: /^[a-z0-9._-]{3,32}$/,
  /**
   * Usernames the create route refuses with `{field: "username", reason: "reserved"}` (P11-T20): `system` and
   * `llm` are the two `actor_role`s of an audit row that is not a person, which the audit page's actor filter
   * reads as roles (`_ROLE_ACTORS` of admin_audit.py, which a test compares). They fit `username`, so the
   * create form checks this list too, before it posts.
   */
  reservedUsernames: ["system", "llm"],
} as const;

// --- errors -----------------------------------------------------------------------------------------------

/**
 * Every reason code the admin routes answer with, read from the handlers. A code that is not here is read
 * as `other`; `strings.ts` has a text for each (`S.admin.reason`), and a test pins both.
 *
 * - admin_users.py: `username_taken`, `last_active_admin`, `self_change` (409); `not_found` (404); the 422
 *   field reasons `empty`, `invalid`, `too_short`, `too_long`, and `reserved` (a username of `system` or
 *   `llm`, P11-T20; see `ADMIN_LIMITS.reservedUsernames`).
 * - admin_llm.py: `unknown`, `not_integer`, `out_of_range` (422, with `field`); `limits_unavailable` (503);
 *   `timeout`, `query_failed` (503, the usage page).
 * - admin_overview.py: `not_found` (404), `not_failed`, `already_queued` (409); `timeout`, `query_failed`
 *   (the `errors[]` of a section).
 * - admin_digest.py: `bad_day`, `invalid` (422); `not_in_digest` (404); `already_reviewed`,
 *   `not_auto_closed` (409).
 * - labels.py (P11-T08's undo): `frozen` (409), `nothing_to_undo` (404).
 * - admin_audit.py: `timeout` (503).
 * - plain-text details of the older routes, read as the reason they stand for (`LEGACY_DETAIL` below):
 *   `forbidden`, `rule_not_found`, `unknown_cluster`, `already_labelled`, `labeler_mismatch`, and the
 *   labels route's "the gold set is frozen" as `frozen`.
 */
export const ADMIN_REASONS = [
  "username_taken",
  "last_active_admin",
  "self_change",
  "not_found",
  "empty",
  "invalid",
  "too_short",
  "too_long",
  "reserved",
  "unknown",
  "not_integer",
  "out_of_range",
  "limits_unavailable",
  "timeout",
  "query_failed",
  "not_failed",
  "already_queued",
  "bad_day",
  "not_in_digest",
  "already_reviewed",
  "not_auto_closed",
  "frozen",
  "nothing_to_undo",
  "forbidden",
  "rule_not_found",
  "unknown_cluster",
  "already_labelled",
  "labeler_mismatch",
] as const;
export type AdminReason = (typeof ADMIN_REASONS)[number];

/**
 * What a failed admin call said, as a discriminated value. Every kind carries the HTTP `status` of the
 * answer (`ApiError.status`), or 0 when there was no answer (a network failure):
 * - `reason`: `{reason}` or a known plain text. `extra` holds the rest of the object (the `row` of a digest
 *   `already_reviewed`; `conflictRow` reads it);
 * - `field`: `{field, reason, min?, max?}`, a 422 about one field, shown at the field;
 * - `message`: any other text, as the server wrote it, and only on a 422: the 422 of a rule or of a label
 *   says what is wrong with it. A text at any other status is English meant for a log (FastAPI's "Not
 *   Found" and "Method Not Allowed", the 503 "auth disabled: ..."), never for the admin: it is `other`;
 * - `messages`: a list of texts, again only on a 422 (the file errors of a refused inventory reload);
 * - `other`: anything else, FastAPI's own list-shaped 422 (`[{type, loc, msg, input}]`) included, a 401, a
 *   network failure, an object with a reason this client does not know. The page says `S.common.unknownError`.
 */
export type AdminError =
  | {
      kind: "reason";
      status: number;
      reason: AdminReason;
      extra: Readonly<Record<string, unknown>>;
    }
  | {
      kind: "field";
      status: number;
      field: string;
      reason: AdminReason;
      min?: number;
      max?: number;
    }
  | { kind: "message"; status: number; message: string }
  | { kind: "messages"; status: number; messages: string[] }
  | { kind: "other"; status: number };

/** The plain-text `detail`s the older routes answer with, by the reason each one stands for. */
const LEGACY_DETAIL: Readonly<Record<string, AdminReason>> = {
  forbidden: "forbidden", // require_role: 403 (also the actor of a PATCH who stopped being admin)
  "rule not found": "rule_not_found", // PATCH /api/admin/rules: 404
  "cluster is not a gold candidate": "unknown_cluster", // POST /api/admin/labels: 404
  "already labelled by this labeler": "already_labelled", // POST /api/admin/labels: 409
  "the gold set is frozen": "frozen", // labels: 409
  "labeler must be the current user": "labeler_mismatch", // labels: 403
  // `deps.clean_path_id`: a control character in an alert id, e.g. on the digest review path (lower case,
  // unlike FastAPI's own "Not Found" for a path that is not a route, which stays `other`).
  "not found": "not_found",
};

function isReason(value: unknown): value is AdminReason {
  return typeof value === "string" && (ADMIN_REASONS as readonly string[]).includes(value);
}

/** The status of the one answer a 422's text is for: a text or a list of texts is shown only at this one. */
const UNPROCESSABLE = 422;

/**
 * Reads the `detail` of an error answer (`ApiError.detail`) given at HTTP `status`. Never throws, whatever it
 * is handed. A text is a `message`, and a list of texts `messages`, only at 422; at another status an
 * unmapped text is `other` (see `AdminError`).
 */
export function parseAdminDetail(detail: unknown, status: number): AdminError {
  const other: AdminError = { kind: "other", status };
  if (typeof detail === "string") {
    if (detail === "") return other;
    const reason = Object.hasOwn(LEGACY_DETAIL, detail) ? LEGACY_DETAIL[detail] : undefined;
    if (reason !== undefined) return { kind: "reason", status, reason, extra: {} };
    return status === UNPROCESSABLE ? { kind: "message", status, message: detail } : other;
  }
  if (Array.isArray(detail)) {
    const texts = detail.filter((item): item is string => typeof item === "string");
    return status === UNPROCESSABLE && texts.length > 0 && texts.length === detail.length
      ? { kind: "messages", status, messages: texts }
      : other;
  }
  if (typeof detail !== "object" || detail === null) return other;
  const object = detail as Record<string, unknown>;
  if (!isReason(object.reason)) return other;
  const reason = object.reason;
  if ("field" in object) {
    if (typeof object.field !== "string") return other;
    const error: Extract<AdminError, { kind: "field" }> = {
      kind: "field",
      status,
      field: object.field,
      reason,
    };
    if (typeof object.min === "number" && Number.isFinite(object.min)) error.min = object.min;
    if (typeof object.max === "number" && Number.isFinite(object.max)) error.max = object.max;
    return error;
  }
  const extra = Object.fromEntries(Object.entries(object).filter(([key]) => key !== "reason"));
  return { kind: "reason", status, reason, extra };
}

/**
 * Reads what a failed call threw: an `ApiError`'s `detail` and `status`; anything else (a network failure)
 * is `other` with status 0.
 */
export function adminErrorOf(error: unknown): AdminError {
  return error instanceof ApiError
    ? parseAdminDetail(error.detail, error.status)
    : { kind: "other", status: 0 };
}

/** The row an `already_reviewed` answer carries (the review on file), or null for any other error. */
export function conflictRow(error: AdminError): DigestRow | null {
  if (error.kind !== "reason" || error.reason !== "already_reviewed") return null;
  const row = error.extra.row;
  if (typeof row !== "object" || row === null || Array.isArray(row)) return null;
  const candidate = row as Record<string, unknown>;
  const ok =
    typeof candidate.alert_id === "string" &&
    typeof candidate.occurrence_count === "number" &&
    typeof candidate.disagreement === "boolean";
  return ok ? (row as DigestRow) : null;
}

// --- users (admin_users.py) -------------------------------------------------------------------------------

/** One row of `GET /api/admin/users`. Never carries a hash (a backend test pins the keys). */
export type UserRow = {
  user_id: string;
  username: string;
  display_name: string | null;
  role: Role;
  is_active: boolean;
  /** ISO 8601; set while the account is locked after failed logins, and still there after it passes. */
  locked_until: string | null;
  failed_logins: number;
  /** Null: the account never logged in (`chưa đăng nhập`). */
  last_login_at: string | null;
  created_at: string;
};

/** `GET /api/admin/users`: ordered by username. */
export type UsersResponse = { users: UserRow[] };

/** The body of `POST /api/admin/users`. The password travels here once and is never shown again. */
export type NewUser = { username: string; display_name: string; role: Role; password: string };

/** The body of `PATCH /api/admin/users/{id}`: any of the three, at least one. */
export type UserChanges = { role?: Role; display_name?: string; is_active?: boolean };

export function listUsers(): Promise<UsersResponse> {
  return api<UsersResponse>("/admin/users");
}

/** `201 {user_id}`; `409 username_taken`; `422 {field, reason}`. */
export function createUser(body: NewUser): Promise<{ user_id: string }> {
  return api<{ user_id: string }>("/admin/users", { method: "POST", json: body });
}

/** The row as it is now. A role change or a deactivation ends the user's sessions; `409 self_change`, `409 last_active_admin`. */
export function updateUser(userId: string, changes: UserChanges): Promise<UserRow> {
  return api<UserRow>(`/admin/users/${enc(userId)}`, { method: "PATCH", json: changes });
}

/** `204`. The user's sessions end too; an admin may reset their own password. */
export async function resetPassword(userId: string, password: string): Promise<void> {
  await api<null>(`/admin/users/${enc(userId)}/password`, { method: "POST", json: { password } });
}

/** `204`. The body is `{}`: the route refuses a POST with no JSON content type (P11-T02 review, m3). */
export async function unlockUser(userId: string): Promise<void> {
  await api<null>(`/admin/users/${enc(userId)}/unlock`, { method: "POST", json: {} });
}

// --- LLM usage and limits (admin_llm.py) ------------------------------------------------------------------

/** The three editable limits, as the PUT body and the answer name them. */
export const LIMIT_FIELDS = ["cap_usd", "quota_per_24h", "timeout_s"] as const;
export type LimitField = (typeof LIMIT_FIELDS)[number];

/** The same three as settings (`KEYS` of infra/settings.py): what `limits.sources` is keyed by. */
export const LIMIT_KEYS = [
  "LLM_MONTHLY_USD_CAP",
  "ANALYZE_QUOTA_PER_USER_DAY",
  "LLM_TIMEOUT_S",
] as const;
export type LimitKey = (typeof LIMIT_KEYS)[number];

/** The setting each request/response field is, for reading `limits.sources[LIMIT_KEY_OF_FIELD[field]]`. */
export const LIMIT_KEY_OF_FIELD = {
  cap_usd: "LLM_MONTHLY_USD_CAP",
  quota_per_24h: "ANALYZE_QUOTA_PER_USER_DAY",
  timeout_s: "LLM_TIMEOUT_S",
} as const satisfies Record<LimitField, LimitKey>;

/** Where one limit came from: the `.env` (`env`) or a save on the web (`web`, with who and when). */
export type LimitSource = {
  source: "env" | "web";
  updated_at: string | null;
  updated_by_name: string | null;
  /** A stored timeout above its ceiling: the value shown is the ceiling (DEC-202). */
  clamped: boolean;
};

/** `limits_out` of admin_llm.py: the effective values, where each came from, and the bounds of the form. */
export type LimitsOut = {
  cap_usd: number;
  quota_per_24h: number;
  timeout_s: number;
  /** Keyed by the setting's name (`LIMIT_KEYS`), not by the field: read it with `LIMIT_KEY_OF_FIELD`. */
  sources: Record<LimitKey, LimitSource>;
  /** The form's min and max for each field; the timeout's max is derived from the job lock (DEC-202). */
  bounds: Record<LimitField, { min: number; max: number }>;
};

/** One `(pipeline, role)` row of the usage page. `role` is null on a v1 row. */
export type PipelineRoleRow = {
  pipeline: string;
  role: string | null;
  calls: number;
  /** Runs with a result (`result IS NOT NULL`). */
  with_result: number;
  /** `stopped_by` -> count, the runs with none left out. */
  stopped: Record<string, number>;
  input_tokens: number;
  output_tokens: number;
  latency_p50_ms: number | null;
  latency_p95_ms: number | null;
  cost_usd: number;
};

/** One of the last 20 runs. It never carries a prompt, a trace or the model's text. */
export type RecentRun = {
  run_id: string;
  created_at: string;
  pipeline: string;
  role: string | null;
  subject_type: string | null;
  /** Null for a run on an alert that is blind and not yet decided (DEC-101), and only then for an alert. */
  subject_id: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
  latency_ms: number | null;
  /**
   * The verdict or conclusion, or `stopped:<stopped_by>`; null when the run has neither, and null (with a null
   * `subject_id`) for a run on an alert that is blind and not yet decided: the server withholds ① there
   * (DEC-101, context pack §6.4).
   */
  outcome: string | null;
  cost_usd: number | null;
};

/** `GET /api/admin/llm/usage`. */
export type LlmUsage = {
  range: LlmRange;
  /** The calendar month, whatever the range. `cap_usd` and `pct` are null when the limits cannot be read. */
  month: { spent_usd: number; cap_usd: number | null; pct: number | null; projected_usd: number };
  by_pipeline_role: PipelineRoleRow[];
  /** ② runs per person in the last 24 hours (never "since midnight"); `limit` is null when unreadable. */
  quota: {
    limit: number | null;
    window: "24h";
    users: {
      username: string;
      display_name: string | null;
      used: number;
      remaining: number | null;
    }[];
  };
  recent: RecentRun[];
  /** Null, with `limits_error`, when the limits cannot be read: the page is read-only and fails closed. */
  limits: LimitsOut | null;
  limits_error: "limits_unavailable" | null;
  /** Always 0 (spec decision 4). */
  tool_calls: number;
};

/** `?range=`; a 503 `timeout` or `query_failed` fails the whole answer. */
export function getLlmUsage(range: LlmRange): Promise<LlmUsage> {
  return api<LlmUsage>(`/admin/llm/usage?${new URLSearchParams({ range })}`);
}

/** The body of `PUT /api/admin/llm/limits`: any of the three, each a JSON integer inside `limits.bounds`. */
export type LimitsChange = Partial<Record<LimitField, number>>;

/** `200 {limits}`; `422 {field, reason: unknown | not_integer | out_of_range, min?, max?}`; `503 limits_unavailable`. */
export function putLlmLimits(body: LimitsChange): Promise<{ limits: LimitsOut }> {
  return api<{ limits: LimitsOut }>("/admin/llm/limits", { method: "PUT", json: body });
}

// --- overview (admin_overview.py, web/main.py) ------------------------------------------------------------

/**
 * The eleven sections of the overview; each fails alone (`errors[]`). `llm_month` is DEC-203's, `knowledge` (the
 * last) DEC-210's.
 */
export const OVERVIEW_SECTIONS = [
  "alerts_by_day",
  "by_source",
  "top_agents",
  "funnel",
  "waiting",
  "cases_open",
  "health",
  "failed_jobs",
  "inventory",
  "llm_month",
  "knowledge",
] as const;
export type OverviewSection = (typeof OVERVIEW_SECTIONS)[number];

export type HealthCheck = {
  name: string;
  ok: boolean;
  value: number | string | null;
  threshold: number | string | null;
  detail: string;
};

export type FailedJob = {
  job_id: number;
  job_type: string;
  subject_id: string;
  attempts: number;
  /** Cut to 200 characters by the server; null when the job recorded none. */
  last_error: string | null;
  locked_at: string | null;
  created_at: string;
};

/**
 * `GET /api/admin/overview`. A section that failed is `null` and has an entry in `errors`; the others
 * are served. The API lists only the days and the statuses that occur, so a page zero-fills.
 */
export type OverviewResponse = {
  range: AdminRange;
  errors: { section: OverviewSection; error: "timeout" | "query_failed" }[];
  /** Ascending by day; a day with no alert is absent. `day` is `YYYY-MM-DD` in the display zone. */
  alerts_by_day: { day: string; total: number; heads: number; duplicates: number }[] | null;
  by_source: { rows: { source: string; alerts: number; heads: number }[]; rejected: number } | null;
  top_agents: { agent_name: string; alerts: number }[] | null;
  /** Heads only. `triage` counts ① per head: `none` is a head with no triage status. */
  funnel: {
    by_status: Record<string, number>;
    triage: { ready: number; unavailable: number; pending: number; none: number };
  } | null;
  /** Heads waiting for Tier 1 now, not bounded by the range. */
  waiting: { count: number; oldest_received_at: string | null } | null;
  cases_open: number | null;
  /** The newest `system_health` row; null before the first run (not an error). */
  health: { checked_at: string; ok: boolean; checks: HealthCheck[] } | null;
  /** At most 50, the newest attempt first. */
  failed_jobs: FailedJob[] | null;
  inventory: {
    assets: number;
    identities: number;
    iocs: number;
    loaded_at: string | null;
  } | null;
  /**
   * The calendar month's LLM spend against the cap (DEC-203): the figures of `LlmUsage["month"]`, from the same
   * code. `pct` is floored to one decimal; `cap_usd` and `pct` are null when the limits cannot be read (not an
   * error). The section itself is null, with an `errors` entry, only when the spend query failed.
   */
  llm_month: { spent_usd: number; cap_usd: number | null; pct: number | null } | null;
  /**
   * The learned-knowledge drafts waiting for an admin, and how many of them conflict with an active entry
   * (DEC-210, P13-T05). What is there now: the range does not bound it.
   */
  knowledge: { pending: number; conflicts: number } | null;
};

export function getOverview(range: AdminRange): Promise<OverviewResponse> {
  return api<OverviewResponse>(`/admin/overview?${new URLSearchParams({ range })}`);
}

/** `POST /api/admin/jobs/{id}/retry`: `404 not_found`, `409 not_failed`, `409 already_queued`. */
export function retryJob(jobId: number): Promise<{ job_id: number; status: "pending" }> {
  return api<{ job_id: number; status: "pending" }>(`/admin/jobs/${enc(String(jobId))}/retry`, {
    method: "POST",
    json: {},
  });
}

/** `dataclasses.asdict(LoadReport)`: what a reload did. `warnings` keep their `warning: ` prefix. */
export type LoadReport = {
  assets: number;
  identities: number;
  iocs: number;
  deactivated: number;
  warnings: string[];
};

/** `POST /api/admin/reload-inventory`. A 422's `detail` is a list of file errors (`messages`); nothing changed. */
export function reloadInventory(): Promise<LoadReport> {
  return api<LoadReport>("/admin/reload-inventory", { method: "POST", json: {} });
}

// --- auto-close rules (admin_rules.py) --------------------------------------------------------------------

/** One condition of a rule: `field op value`, from `autoclose._WHITELIST`. */
export type RuleCondition = { field: string; op: string; value: unknown };

/** One row of `GET /api/admin/rules`. */
export type RuleRow = {
  rule_id: string;
  name: string;
  enabled: boolean;
  match: RuleCondition[];
  /** `match` as JSON text, for the old form; the page reads `match`. */
  match_json: string;
  reason: string;
  created_by: string;
  created_at: string;
  /** The rule's share of the 7-day volume when it is over the threshold, else null. */
  width_pct: number | null;
  /** `AUTOCLOSE_RULE_WIDTH_PCT`, on every row: the threshold `width_pct` is measured against. */
  width_threshold_pct: number;
};

/**
 * When a preview closes no cluster, why: how many clusters the rule's conditions match, and for each hard
 * block how many of them it stopped (the six blocks, the largest count first).
 */
export type HardBlockTally = { matched: number; blocks: { code: HardBlockCode; count: number }[] };

/** `POST /api/admin/rules/simulate`: the last 30 days, hard blocks included. */
export type SimulateResult = {
  clusters: number;
  alerts: number;
  by_severity: Record<string, number>;
  by_asset_criticality: Record<string, number>;
  /** Up to 20 alert ids, linking to `/alerts/:id`. */
  samples: string[];
  /** Always sent: the tally when `clusters` is 0, `null` otherwise. */
  hard_block_tally: HardBlockTally | null;
};

export function listRules(): Promise<RuleRow[]> {
  return api<RuleRow[]>("/admin/rules");
}

/** `422`: the detail is a text (`message`), or FastAPI's own list for a body of the wrong shape (`other`). */
export function simulateRule(match: RuleCondition[]): Promise<SimulateResult> {
  return api<SimulateResult>("/admin/rules/simulate", { method: "POST", json: { match } });
}

/** `201 {rule_id, name, enabled: true}`; the same 422 as `simulateRule`. */
export function createRule(body: {
  name: string;
  reason: string;
  match: RuleCondition[];
}): Promise<{ rule_id: string; name: string; enabled: boolean }> {
  return api<{ rule_id: string; name: string; enabled: boolean }>("/admin/rules", {
    method: "POST",
    json: body,
  });
}

/** `PATCH /api/admin/rules`: the id is in the body, not the path. `404 rule_not_found`. */
export function toggleRule(
  ruleId: string,
  enabled: boolean,
): Promise<{ rule_id: string; name: string; enabled: boolean }> {
  return api<{ rule_id: string; name: string; enabled: boolean }>("/admin/rules", {
    method: "PATCH",
    json: { rule_id: ruleId, enabled },
  });
}

// --- daily digest (admin_digest.py) -----------------------------------------------------------------------

/** One cluster of the digest (`DigestRowOut`). */
export type DigestRow = {
  alert_id: string;
  rule_id: string;
  description: string;
  severity: string;
  category: string;
  agent_name: string;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  autoclose_rule_id: string | null;
  autoclose_rule_name: string | null;
  /**
   * The suggestion of ① (`false_positive`, `needs_review`, `true_positive`), or null when it has none, and null on a
   * row a "Sai" review reopened while the alert is blind and not yet decided (DEC-101: a reopened alert is blind
   * again, and the server leaves ① off it, with `disagreement` false).
   */
  suggested_action: string | null;
  /** ① did not suggest closing it. */
  disagreement: boolean;
  reviewed_verdict: DigestVerdict | null;
  reviewed_by_name: string | null;
  reviewed_at: string | null;
  /** A "Sai" review reopened it: the row stays on the list with its verdict. */
  reopened_by_review: boolean;
};

/** `GET /api/admin/digest`. */
export type DigestResponse = {
  /** The day shown, `YYYY-MM-DD` in the display zone. */
  day: string;
  today: string;
  rules_enabled: boolean;
  rows: DigestRow[];
};

/** `?day=YYYY-MM-DD`, or none for today. `422 bad_day` for anything else: the page falls back by itself. */
export function getDigest(day?: string): Promise<DigestResponse> {
  const query = day === undefined ? "" : `?${new URLSearchParams({ day })}`;
  return api<DigestResponse>(`/admin/digest${query}`);
}

/** `409 already_reviewed` carries the recorded `row` (`conflictRow`); `409 not_auto_closed`; `404 not_in_digest`. */
export function reviewDigest(
  alertId: string,
  day: string,
  verdict: DigestVerdict,
): Promise<{ row: DigestRow; reopened: boolean }> {
  return api<{ row: DigestRow; reopened: boolean }>(`/admin/digest/${enc(alertId)}/review`, {
    method: "POST",
    json: { day, verdict },
  });
}

// --- blind labelling (labels.py) --------------------------------------------------------------------------

/** A grouped correlation row (±2 h): no `status`, which would tell the labeller what was decided. */
export type CorrelationRow = {
  rule_id: string;
  category: string;
  cluster_count: number;
  alert_count: number;
  first_seen: string;
  last_seen: string;
};

/** A correlated head, shown as a sample; the columns a labeller may see and no more. */
export type CorrelationSample = {
  alert_id: string;
  rule_id: string | null;
  category: string | null;
  severity: string | null;
  occurrence_count: number;
  alert_time: string | null;
  description: string | null;
  raw_log: string | null;
};

/**
 * What `labels.cluster_view` returns: exactly `VIEW_KEYS`, passed through the labelling filter (DEC-019,
 * DEC-101). The page renders these fields and fetches nothing else about the cluster.
 */
export type LabelCluster = {
  alert_id: string;
  rule_id: string | null;
  rule_level: number | null;
  severity: string | null;
  description: string | null;
  agent_name: string | null;
  alert_time: string | null;
  alert_user: string | null;
  srcip: string | null;
  dstip: string | null;
  category: string | null;
  /** Cut at 32 KB; `raw_log_truncated_for_display` says so. */
  raw_log: string;
  raw_log_truncated_for_display: boolean;
  occurrence_count: number;
  first_seen: string;
  last_seen: string;
  playbook: string;
  correlation: { rows: CorrelationRow[]; samples: CorrelationSample[] };
  gold_cluster_id: string;
};

/**
 * `GET /api/admin/labels/next`. `cluster` is null when the labeller is finished or there is no candidate
 * (`total` 0). `frozen` and `candidates_present` are on every answer (spec §5.7); `frozen` is true while
 * `eval/gold_v1.sha256` exists, which is the state of the gold set today.
 */
export type LabelsNext = {
  cluster_id: string | null;
  done: number;
  total: number;
  cluster: LabelCluster | null;
  frozen: boolean;
  candidates_present: boolean;
};

/** `labeler` must be the caller's own user id (`GET /api/auth/me`), or the route answers 403. */
export function getLabelsNext(labelerId: string): Promise<LabelsNext> {
  return api<LabelsNext>(`/admin/labels/next?${new URLSearchParams({ labeler: labelerId })}`);
}

/** The body of `POST /api/admin/labels`; `note` is at most 200 characters. */
export type NewLabel = {
  labeler: string;
  cluster_id: string;
  label: LabelChoice;
  confidence: LabelConfidence;
  note?: string;
};

/** `201`; `404 unknown_cluster`, `409 already_labelled`, `403 labeler_mismatch`. `next` is the next cluster id or null. */
export function postLabel(
  body: NewLabel,
): Promise<{ cluster_id: string; done: number; total: number; next: string | null }> {
  return api<{ cluster_id: string; done: number; total: number; next: string | null }>(
    "/admin/labels",
    { method: "POST", json: body },
  );
}

/** `200`; `409 frozen`, `404 nothing_to_undo` (P11-T08). The body is `{}`: the route needs a JSON body. */
export function undoLabel(): Promise<{ undone_cluster_id: string; done: number; total: number }> {
  return api<{ undone_cluster_id: string; done: number; total: number }>("/admin/labels/undo", {
    method: "POST",
    json: {},
  });
}

// --- audit log (admin_audit.py) ---------------------------------------------------------------------------

/** `actor_role` of an audit row: a person's role is `analyst` (tier1 and tier2) or `admin`. */
export type AuditActorRole = "analyst" | "admin" | "system" | "llm";

/** One row of the audit page. */
export type AuditEvent = {
  /** Insertion order; the cursor is the last one seen. */
  audit_id: number;
  created_at: string;
  event_type: string;
  actor_role: AuditActorRole;
  /** Null for `system`, `llm` and an actor with no `users` row. */
  actor_username: string | null;
  subject_id: string;
  /**
   * Parsed JSON with secret-named keys replaced by "[đã ẩn]", and so is ①'s suggestion in an
   * `autoclose.reviewed` event while its alert is blind and not yet decided (DEC-101). The rows of
   * `triage.suggested`, `llm.gate_forced` and `llm.builder_violation` of such an alert are not listed at all, and
   * not counted in `total`: their bare presence would tell ①'s verdict (DEC-206); they are listed once the alert
   * is decided. `{truncated: true, size}` when too big. Render as text.
   */
  payload: unknown;
};

/** `GET /api/admin/audit`. `next_cursor` is null on a page that is not full; `total` is null when its count timed out. */
export type AuditResponse = {
  events: AuditEvent[];
  next_cursor: number | null;
  total: number | null;
};

/** The filters of the audit page, which keeps them in the URL. An unset or empty one is not sent. */
export type AuditFilters = {
  range: AdminRange;
  group?: AuditGroup;
  /** A username, or `system` or `llm`. */
  actor?: string;
  /** An exact `subject_id`: an alert, case, rule, user or job id. */
  subject?: string;
  /** The last `audit_id` of the page before. */
  cursor?: number;
  /** 1 to 100, 50 by default. */
  limit?: number;
};

export function getAudit(filters: AuditFilters): Promise<AuditResponse> {
  const query = new URLSearchParams({ range: filters.range });
  if (filters.group) query.set("group", filters.group);
  if (filters.actor) query.set("actor", filters.actor);
  if (filters.subject) query.set("subject", filters.subject);
  if (filters.cursor !== undefined) query.set("cursor", String(filters.cursor));
  if (filters.limit !== undefined) query.set("limit", String(filters.limit));
  return api<AuditResponse>(`/admin/audit?${query}`);
}

// --- learned knowledge (admin_knowledge.py, rag/draft.py, rag/publish.py; DEC-210, P13-T05) --------------------
//
// The drafts the model wrote from the analysts' conclusions, the entries an admin approved, and the closed tag
// vocabulary. Every text in them (a title, a summary, an analyst's reason, an entry's Markdown) was written by a
// person or a model: it is rendered as text and never as markup.

/** `?status=` of the draft list. The page reads `pending`, `merged` and `rejected`; `approved` drafts are entries. */
export const KNOWLEDGE_DRAFT_STATUSES = ["pending", "approved", "merged", "rejected"] as const;
export type KnowledgeDraftStatus = (typeof KNOWLEDGE_DRAFT_STATUSES)[number];

/** `?status=` of the entry list. */
export const KNOWLEDGE_ENTRY_STATUSES = ["active", "retired"] as const;
export type KnowledgeEntryStatus = (typeof KNOWLEDGE_ENTRY_STATUSES)[number];

/** The six fields the model writes and an admin may edit (`MODEL_FIELDS` of rag/draft.py), in its order. */
export const KNOWLEDGE_MODEL_FIELDS = [
  "title",
  "tags",
  "summary",
  "distinguishing_signals",
  "check_next_time",
  "confidence_note",
] as const;
export type KnowledgeModelField = (typeof KNOWLEDGE_MODEL_FIELDS)[number];

/** The six fields the source owns (`CLOSED_FIELDS` of rag/draft.py): shown, never sent. */
export const KNOWLEDGE_CLOSED_FIELDS = [
  "conclusion",
  "category",
  "mitre_ids",
  "soar_scenario",
  "rule_ids",
  "log_source",
] as const;
export type KnowledgeClosedField = (typeof KNOWLEDGE_CLOSED_FIELDS)[number];

/**
 * The bounds of spec §7.4 and of a reason, equal to the constants of the backend (a test reads them): `TITLE_MAX`,
 * `SUMMARY_MAX`, `ITEM_MAX`, `MAX_ITEMS` and `NOTE_MAX` of rag/draft.py, `REASON_MAX` of rag/publish.py, and the
 * `DEFAULT_LIMIT` of the lists. The form words them in its hints; the server still has the last word (V5).
 */
export const KNOWLEDGE_LIMITS = {
  titleMax: 120,
  summaryMax: 600,
  itemMax: 160,
  maxItems: 6,
  noteMax: 200,
  reasonMax: 500,
  /** The rows a list route sends when the request names no `limit` (`DEFAULT_LIMIT` of admin_knowledge.py). */
  listDefault: 200,
} as const;

/** The twelve fields of a stored draft (`DRAFT_FIELDS`): the model's six, tidied, and the source's six. */
export type KnowledgeDraftFields = {
  title: string;
  conclusion: string;
  category: string;
  mitre_ids: string[];
  soar_scenario: string | null;
  rule_ids: string[];
  log_source: string | null;
  tags: string[];
  summary: string;
  distinguishing_signals: string[];
  check_next_time: string[];
  confidence_note: string;
};

/** One row of `GET /api/admin/knowledge/drafts`. `title` is null for a draft the job could not write. */
export type KnowledgeDraftRow = {
  draft_id: string;
  source_kind: "alert" | "case";
  /** The alert id, or the case's uuid. */
  source_id: string;
  conclusion: string;
  status: KnowledgeDraftStatus;
  title: string | null;
  /** False for a draft with no text (the job wrote none); `warnings` says why. */
  has_text: boolean;
  /** What the job could not do or check: V1-V5 fault names, or `budget`, `llm_transient`, `llm_permanent`, `linter`, `rank_unavailable`. */
  warnings: string[];
  /** The active entry this draft disagrees with: the admin must see these first. */
  conflict_with_entry: string | null;
  /** The entry a `merged` draft was folded into. */
  duplicate_of_entry: string | null;
  created_at: string;
  reviewed_by: string | null;
  reviewed_by_name: string | null;
  reviewed_at: string | null;
  /** The reason of a rejection. */
  review_note: string | null;
};

/** The `draft` of `GET /api/admin/knowledge/drafts/{id}`: the row, and the twelve fields (`{}` for a draft with no text). */
export type KnowledgeDraft = {
  draft_id: string;
  source_kind: "alert" | "case";
  source_id: string;
  conclusion: string;
  status: KnowledgeDraftStatus;
  draft: Partial<KnowledgeDraftFields>;
  warnings: string[];
  llm_run_id: string | null;
  duplicate_of_entry: string | null;
  conflict_with_entry: string | null;
  created_at: string;
  reviewed_by: string | null;
  reviewed_by_name: string | null;
  reviewed_at: string | null;
  review_note: string | null;
};

/** The newest `tier1.decided` / `tier2.concluded` event of the source. `payload` went through the audit page's redaction. */
export type KnowledgeDecision = {
  event_type: string;
  actor_id: string | null;
  actor_name: string | null;
  at: string;
  payload: unknown;
};

/**
 * What the admin judges a draft against, read-only. `alert` is exactly `GET /api/tier1/alerts/{id}` and `case` and
 * `investigation` exactly `GET /api/tier2/cases/{id}` and `.../investigation`, so the pages of the analysts render
 * them. A part whose row is gone is null. `enrichment` is the SOAR block of an alert (or null), or a map
 * `{head alert id: block}` for a case. `conflict_entry` is the whole entry, Markdown included.
 */
export type KnowledgeSource = {
  kind: "alert" | "case";
  id: string;
  alert: AlertView | null;
  case: CaseDetail | null;
  investigation: InvestigationView | null;
  decision: KnowledgeDecision | null;
  notes: CaseNote[];
  enrichment: unknown;
  conflict_entry: KnowledgeEntry | null;
};

/** `GET /api/admin/knowledge/drafts/{id}`. */
export type KnowledgeDraftDetail = { draft: KnowledgeDraft; source: KnowledgeSource };

/** One row of `GET /api/admin/knowledge/entries`: no Markdown, no fingerprint, no evidence list. */
export type KnowledgeEntryRow = {
  entry_id: string;
  version: number;
  status: KnowledgeEntryStatus;
  title: string | null;
  conclusion: string;
  category: string;
  mitre_ids: string[];
  tags: string[];
  soar_scenario: string | null;
  rule_ids: string[];
  log_source: string | null;
  file_path: string;
  content_sha256: string;
  evidence_count: number;
  approved_by: string | null;
  approved_by_name: string | null;
  approved_at: string | null;
};

/** `GET /api/admin/knowledge/entries/{id}`. `content` is the entry's Markdown, rendered as text. */
export type KnowledgeEntry = {
  entry_id: string;
  version: number;
  status: KnowledgeEntryStatus;
  title: string | null;
  conclusion: string;
  category: string;
  mitre_ids: string[];
  tags: string[];
  soar_scenario: string | null;
  rule_ids: string[];
  log_source: string | null;
  fingerprint: string;
  content: string;
  content_sha256: string;
  file_path: string;
  source_alert_ids: string[];
  source_case_ids: string[];
  /** One `{subject, at}` for the draft's own source, and one for each draft merged into the entry later. */
  evidence: { subject: string; at: string }[];
  approved_by: string | null;
  approved_by_name: string | null;
  approved_at: string | null;
  supersedes_entry: string | null;
  /** `content_ok`: `content` hashes to `content_sha256`. `file_ok`: the published file is exactly that. */
  integrity: { content_ok: boolean; file_ok: boolean };
};

/** `GET /api/admin/knowledge/tags`: the closed vocabulary (sorted) and a line about each tag. */
export type KnowledgeTags = { tags: string[]; descriptions: Record<string, string> };

/** The `edited` of an approval: only the model's six fields, each optional. A closed field is refused by the route. */
export type KnowledgeEdit = {
  title?: string;
  tags?: string[];
  summary?: string;
  distinguishing_signals?: string[];
  check_next_time?: string[];
  confidence_note?: string;
};

/** The route lists `pending` conflicts first, then the oldest; the others newest review first. 200 rows by default. */
export function listKnowledgeDrafts(status: KnowledgeDraftStatus): Promise<KnowledgeDraftRow[]> {
  return api<KnowledgeDraftRow[]>(`/admin/knowledge/drafts?${new URLSearchParams({ status })}`);
}

/** `404 not_found`. */
export function getKnowledgeDraft(draftId: string): Promise<KnowledgeDraftDetail> {
  return api<KnowledgeDraftDetail>(`/admin/knowledge/drafts/${enc(draftId)}`);
}

/**
 * Approves a draft as it is (`{}`) or with `edited`: the model's six fields only. Whatever else is in `edited` is
 * not sent, so a closed field can never reach the route, which answers it with `422 {"faults":
 * ["v1_schema:unexpected_key"]}`. `422 {faults}` (V1-V5 over the final text), `404 not_found`,
 * `409 {reason: not_pending | source_changed | unpublishable}`, `503 publish_failed` (nothing was stored).
 */
export function approveKnowledgeDraft(
  draftId: string,
  edited?: KnowledgeEdit,
): Promise<{ entry_id: string }> {
  const fields: Record<string, unknown> = {};
  for (const name of KNOWLEDGE_MODEL_FIELDS) {
    if (edited !== undefined && Object.hasOwn(edited, name)) fields[name] = edited[name];
  }
  const json = Object.keys(fields).length === 0 ? {} : { edited: fields };
  return api<{ entry_id: string }>(`/admin/knowledge/drafts/${enc(draftId)}/approve`, {
    method: "POST",
    json,
  });
}

/** `reason` is 1 to 500 characters (`422 {field: reason, reason: required | invalid}`); `404`, `409`. */
export function rejectKnowledgeDraft(
  draftId: string,
  reason: string,
): Promise<{ draft_id: string; status: "rejected" }> {
  return api<{ draft_id: string; status: "rejected" }>(
    `/admin/knowledge/drafts/${enc(draftId)}/reject`,
    { method: "POST", json: { reason } },
  );
}

/**
 * The warnings (`REDRAFTABLE_WARNINGS` of rag/draft.py; a test reads them) of a draft the model could not be asked
 * for: its budget, a refusal, a timeout, a ranking that gave no answer. A text-less pending draft whose warnings
 * are all of these can be made again.
 */
export const KNOWLEDGE_REDRAFTABLE_WARNINGS = [
  "budget",
  "llm_transient",
  "llm_permanent",
  "rank_unavailable",
] as const;

/**
 * Asks for a text-less draft to be made again: the route deletes it and queues the job for its source.
 * `404 not_found`, `409 {reason: not_pending | not_redraftable | drafts_disabled}`.
 */
export function redraftKnowledgeDraft(
  draftId: string,
): Promise<{ draft_id: string; queued: true }> {
  return api<{ draft_id: string; queued: true }>(
    `/admin/knowledge/drafts/${enc(draftId)}/redraft`,
    { method: "POST", json: {} },
  );
}

/** Newest approval first. */
export function listKnowledgeEntries(status: KnowledgeEntryStatus): Promise<KnowledgeEntryRow[]> {
  return api<KnowledgeEntryRow[]>(`/admin/knowledge/entries?${new URLSearchParams({ status })}`);
}

/** `404 not_found`. */
export function getKnowledgeEntry(entryId: string): Promise<KnowledgeEntry> {
  return api<KnowledgeEntry>(`/admin/knowledge/entries/${enc(entryId)}`);
}

/** Retires an active entry and moves its file. The same reason as a rejection; `409 not_active`, `404`, `503 publish_failed`. */
export function retireKnowledgeEntry(
  entryId: string,
  reason: string,
): Promise<{ entry_id: string; status: "retired" }> {
  return api<{ entry_id: string; status: "retired" }>(
    `/admin/knowledge/entries/${enc(entryId)}/retire`,
    { method: "POST", json: { reason } },
  );
}

export function getKnowledgeTags(): Promise<KnowledgeTags> {
  return api<KnowledgeTags>("/admin/knowledge/tags");
}

/**
 * One fault of a `422 {"faults": ["<rule>:<field>", ...]}`: V1-V5 over the final text of a draft (`FAULT_VOCABULARY`
 * of rag/draft.py). The names carry no value. `field` is what follows the first colon: a field of the draft, or
 * something that is not one (`root`, `unexpected_key`, `unknown_tag`); null when the name has no colon.
 */
export type KnowledgeFault = { rule: string; field: string | null };

/**
 * What a failed write of the knowledge page said, as a value; every kind carries the HTTP `status` of the answer
 * (0 when there was none).
 * - `faults`: a 422 with the fault list of V1-V5;
 * - `field`: a 422 about one field of the request (`reason`, `edited`, `body`), shown at that field;
 * - `stale`: a 409, whatever its reason: the draft was handled, or its source changed, or the entry is not active;
 * - `publish_failed`: the 503 of a file that could not be written; nothing was stored, so asking again is fine;
 * - `not_found`: the 404 of a draft or an entry that is gone;
 * - `other`: everything else, FastAPI's own list-shaped 422 and a network failure included.
 */
export type KnowledgeError =
  | { kind: "faults"; status: number; faults: KnowledgeFault[] }
  | { kind: "field"; status: number; field: string; reason: string }
  | { kind: "stale"; status: number; reason: string }
  | { kind: "publish_failed"; status: number }
  | { kind: "not_found"; status: number }
  | { kind: "other"; status: number };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** The text under `key` of an object, only when the object itself holds it. */
const ownText = (object: Record<string, unknown>, key: string): string | null => {
  const value = Object.hasOwn(object, key) ? object[key] : undefined;
  return typeof value === "string" ? value : null;
};

function faultsOf(body: unknown): KnowledgeFault[] | null {
  if (!isRecord(body) || !Object.hasOwn(body, "faults")) return null;
  const list = body.faults;
  if (!Array.isArray(list) || list.length === 0) return null;
  const faults: KnowledgeFault[] = [];
  for (const item of list) {
    if (typeof item !== "string" || item === "") return null;
    const colon = item.indexOf(":");
    faults.push(
      colon === -1
        ? { rule: item, field: null }
        : { rule: item.slice(0, colon), field: item.slice(colon + 1) },
    );
  }
  return faults;
}

/** Reads what a failed call of the knowledge routes threw. Never throws, whatever it is handed. */
export function knowledgeErrorOf(error: unknown): KnowledgeError {
  if (!(error instanceof ApiError)) return { kind: "other", status: 0 };
  const { status, detail, body } = error;
  const reason = isRecord(detail) ? ownText(detail, "reason") : null;
  if (status === 422) {
    const faults = faultsOf(body);
    if (faults !== null) return { kind: "faults", status, faults };
    const field = isRecord(detail) ? ownText(detail, "field") : null;
    if (field !== null && reason !== null) return { kind: "field", status, field, reason };
  } else if (status === 409) {
    return { kind: "stale", status, reason: reason ?? "unknown" };
  } else if (status === 503 && reason === "publish_failed") {
    return { kind: "publish_failed", status };
  } else if (status === 404 && reason === "not_found") {
    return { kind: "not_found", status };
  }
  return { kind: "other", status };
}
