// The Tier-1 routes, one typed function each: the queue (P10-T09), the alert page and the decisions
// (P10-T10). The shapes are written by hand against the backend (web/routers/tier1.py, tier1/queue.py,
// tier1/decide.py): the backend answers with plain dicts.
import { api } from "./client";
import type { RagWire } from "./rag";
import type { BandCode } from "./types";

/**
 * One row of the queue. The blind arm (DEC-101) is decided by the server: on a blind, undecided head the
 * keys of the ① suggestion are ABSENT (not null), with `suggestion_visible` false. So `suggested_action`
 * and its four neighbours are optional here, and `"suggested_action" in row` is the test for "stripped".
 * R17: `triaged_count` and `needs_retriage` are absent on such a head too, for a count that ticks or a ⟳
 * that lights up would say that ① ran. Absent means "nothing to show", never "zero" or "no".
 */
export type QueueRow = {
  alert_id: string;
  rule_id: string;
  description: string;
  category: string;
  severity: string;
  agent_name: string;
  /**
   * P10-T15 (DEC-165): whose alert it is (`alert_user`, null when the log names nobody) and where it came
   * from (`srcip`, '' when there is none). The server sends both raw, on blind and visible rows alike:
   * neither comes from ① (R12). Optional here only so a page that meets an older server shows a dash.
   */
  alert_user?: string | null;
  srcip?: string | null;
  occurrence_count: number;
  triaged_count?: number;
  first_seen_at: string;
  last_seen_at: string;
  alert_time: string;
  suggestion_visible: boolean;
  status: string;
  needs_retriage?: boolean;
  /** The Vietnamese label (`Thấp`, `Vừa`, `Cao`, `Rất cao`) of ruling R8, or null with no score. */
  risk_band: string | null;
  triage_status?: string | null;
  run_id?: string | null;
  /**
   * ①'s verdict as Tier 1 is served it: `false_positive` or `true_positive` (DEC-217: never `needs_review`, also for a
   * run stored before it, which is served the model's own answer), null when ① has no result.
   */
  suggested_action?: string | null;
  confidence?: string | null;
  /** True only for a run the gate forced (a version 1 run, before DEC-217); false for a new one. */
  gate_forced?: boolean | null;
  /**
   * P14-T03 (DEC-213): what the model itself concluded (`false_positive` or `true_positive`) and, DEC-217, which
   * checks of the gate raised a warning beside it (`llm.verdicts.HELD_REASONS`, the same closed codes as before;
   * `[]` when none did). The verdict is not held back: the list can be non-empty beside a verdict. Absent on a
   * blind, undecided head, like the keys above.
   */
  proposed_action?: string | null;
  held_by?: string[];
};

/** `GET /api/tier1/queue`. `counts_by_band` counts under every filter but `band`. */
export type QueueResponse = {
  rows: QueueRow[];
  total: number;
  page: number;
  page_size: number;
  counts_by_band: Record<BandCode, number>;
};

/** What the queue filters on; an unset filter is left out of the request (an empty one is a 422). */
export type QueueFilters = {
  band?: BandCode;
  category?: string;
  agent?: string;
  /** `queued` (the server's default, so it is not sent) or `mine`: `tier1_active` held by the caller. */
  status: "queued" | "mine";
};

/**
 * The orders the server offers besides the default risk order (P10-T14, DEC-164): last seen, occurrences,
 * agent. These are the whole list — the server's whitelist has exactly these and `risk`, and no key derived
 * from ① is one of them (R17): the ① column has no sort.
 */
export type QueueSortKey = "time" | "occurrences" | "agent";
export type QueueSortDir = "asc" | "desc";
/** A sort of the queue. The default risk order is the absence of a `QueueSort`, never a value of it. */
export type QueueSort = { key: QueueSortKey; dir: QueueSortDir };

/** The direction a key starts in on the first click: newest, most, A to Z (the server's default too). */
export const SORT_DEFAULT_DIR: Record<QueueSortKey, QueueSortDir> = {
  time: "desc",
  occurrences: "desc",
  agent: "asc",
};

export function isSortKey(value: string | null): value is QueueSortKey {
  return value !== null && Object.hasOwn(SORT_DEFAULT_DIR, value);
}

export function isSortDir(value: string | null): value is QueueSortDir {
  return value === "asc" || value === "desc";
}

/** The rows of a page the queue asks for. The server's own default is 50 and its ceiling 200. */
export const QUEUE_PAGE_SIZE = 50;

/**
 * The request path of one page of the queue. Only the filters that are set appear in it, and a sort is
 * sent as `sort` and `dir` together: the risk order (no sort) sends neither, for the server refuses a `dir`
 * that comes with `sort=risk`.
 */
export function queuePath(
  filters: QueueFilters,
  page: number,
  sort?: QueueSort,
  pageSize = QUEUE_PAGE_SIZE,
): string {
  const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (filters.band) query.set("band", filters.band);
  if (filters.category) query.set("category", filters.category);
  if (filters.agent) query.set("agent", filters.agent);
  if (filters.status === "mine") query.set("status", "mine");
  if (sort) {
    query.set("sort", sort.key);
    query.set("dir", sort.dir);
  }
  return `/tier1/queue?${query}`;
}

export function fetchQueue(
  filters: QueueFilters,
  page: number,
  sort?: QueueSort,
  signal?: AbortSignal,
): Promise<QueueResponse> {
  return api<QueueResponse>(queuePath(filters, page, sort), { signal });
}

/** One reason of ①: what it claims, the log text it quotes (none when it cites no log), and where from. */
export type SuggestionReason = {
  claim: string;
  quote?: string | null;
  source?: string | null;
};

/**
 * The RAG rule of a ① run (DEC-219, trial, amended): "a RAG match exists and its best is below `threshold` percent:
 * `false_positive` is ①'s default answer". `threshold` is 0 when the rule is switched off, `best_pct` the number the
 * page shows as "trùng X% với tri thức đã duyệt" (null when the run has none), `applied` whether the rule applied (a
 * match below the threshold), and `changed` whether the model had answered `true_positive` and the default replaced
 * it. For a run the rule applied to the server serves the verdict ① ended with (`false_positive`) as the view's
 * `proposed_action` and the gate's `proposed_verdict`, never the model's own answer, and the gate is not forced
 * (`forced` false, `forced_by` empty): `changed` makes no difference to what the page says.
 */
export type RagRule = {
  threshold: number;
  best_pct: number | null;
  applied: boolean;
  changed: boolean;
};

/**
 * What the ① gate did (`queue.latest_suggestion`). `forced_by` is a list of gate rules, or absent. `forced` and
 * `forced_by` are the gate's own record: only a version 1 run (before DEC-217) was ever forced, and its
 * `final_verdict` may be `needs_review` there; a new run has `forced` false and `final_verdict` as `proposed_verdict`,
 * the RAG default of DEC-219 included. `rag_rule` is null or absent for a run stored before DEC-219.
 */
export type SuggestionGate = {
  forced?: boolean | null;
  forced_by?: string[] | string | null;
  proposed_verdict?: string | null;
  final_verdict?: string | null;
  verifier_verdict?: string | null;
  warnings?: unknown[] | null;
  rag_rule?: RagRule | null;
};

/** The latest ① result of an alert. Present only where the server shows it (the blind arm never gets it). */
export type Suggestion = {
  run_id?: string;
  suggested_action: string | null;
  confidence: string | null;
  reasons?: SuggestionReason[] | null;
  gate?: SuggestionGate | null;
  /** The number of ±2 h clusters ① saw; compare with the view's `correlated_now`. */
  correlated_at_analysis?: number | null;
  created_at?: string | null;
};

/**
 * `ck_alerts_status`: the eleven values of `alerts.status`, `archived` (021, DEC-212: the old queue closed out
 * without review) last. A response may still carry a word the UI does not know (the fields below stay `string`
 * and render it as it came); `archived` is a status no person decided, so it is in no group of decided ones.
 */
export const ALERT_STATUSES = [
  "received",
  "duplicate",
  "auto_closed",
  "enriching",
  "queued_tier1",
  "tier1_active",
  "escalated_tier2",
  "closed_fp",
  "closed_benign",
  "closed_confirmed",
  "archived",
] as const;
export type AlertStatus = (typeof ALERT_STATUSES)[number];

export type CorrelationRow = {
  rule_id: string;
  category: string | null;
  status: string;
  cluster_count?: number;
  alert_count: number;
  first_seen: string | null;
  last_seen: string | null;
  src_ip_count: number;
};

export type CorrelationSample = {
  alert_id: string;
  rule_id?: string | null;
  category?: string | null;
  severity?: string | null;
  status?: string | null;
  occurrence_count?: number | null;
  alert_time?: string | null;
  description?: string | null;
  raw_log?: string | null;
};

/** `lookup_status` says, per enrichment source, whether it found something, found nothing, or was skipped. */
export type LookupStatus = Record<string, string>;

/**
 * `view.soar` (S3): the SIEM's SOAR enrichment of the alert, made by `tier1/soar_view.py` from the stored
 * payload. Every key of every block is optional: the server leaves out what the SIEM did not send, and keeps
 * `case_number: null` for an alert whose SOAR score was too low for a TheHive case. The values are the SIEM's
 * free text (a signal text, a dedup key, filterlog lines) and are shown as text, never read as markup. The
 * score and the signal are the SIEM's opinion, displayed only: nothing in ① or its gate reads them.
 */
export type SoarCase = {
  /** Null (kept) when no TheHive case was made; a number otherwise. */
  case_number?: number | string | null;
  thehive_alert_id?: string;
  dedup_key?: string;
  case_id?: string;
};
export type SoarAction = { type?: string; target?: string; tier?: string; mode?: string };
export type SoarScenario = { id?: string; name?: string };
export type SoarTriage = { score?: number; signal_text?: string; signal_codes?: string[] };
export type SoarHistory = {
  rule_7d_total?: number;
  rule_7d_host?: number;
  rule_7d_hosts?: number;
  last_seen?: string;
  first_seen_host?: boolean;
};
/** The GEO01 fields: a text, a number or a flag each; the server sends only those the SIEM did. */
export type SoarGeoValue = string | number | boolean;
export type SoarGeo = {
  country?: SoarGeoValue;
  country_simulated?: SoarGeoValue;
  src_ip_type?: SoarGeoValue;
  first_seen_country_30d?: SoarGeoValue;
  seen_count_30d?: SoarGeoValue;
  prior_failures_30m?: SoarGeoValue;
  impossible_travel?: SoarGeoValue;
  off_hours?: SoarGeoValue;
};
export type SoarScan = {
  sampled_packets?: number;
  distinct_dst_ports_sampled?: number;
  /** A bounded sample; `ports_total` is how many the SIEM sent. */
  ports_sampled?: string[];
  ports_total?: number;
  dst_ips?: string[];
  actions?: string[];
  /** The filterlog lines, cut on a line boundary by the server (`previous_output_truncated`). */
  previous_output?: string;
  previous_output_truncated?: boolean;
  previous_output_lines?: number;
};
export type SoarTi = { type?: string; value?: string; verdict?: string };
export type SoarBlob = {
  case?: SoarCase;
  action?: SoarAction;
  scenario?: SoarScenario;
  triage?: SoarTriage;
  history?: SoarHistory;
  geo?: SoarGeo;
  scan?: SoarScan;
  ti?: SoarTi[];
};

/**
 * `GET /api/tier1/alerts/{id}`: the analyst view of one alert (`queue.get_alert_view(mode="analyst")`),
 * written by hand against the backend. The keys `aiStateOfView` reads and the ones every view carries are
 * required; the rest are optional because a section is shown only when the view carries its data, and a
 * value the database may leave empty is `| null`.
 *
 * The blind arm (DEC-101) is decided by the server: on a blind, undecided head, `suggestion` (and with it
 * `triage_status`, `run_id`, `triaged_count`, `needs_retriage`, `llm_stopped_by`) is ABSENT, not null, and
 * `suggestion_visible` is false. The page never infers anything about ① from any other key.
 *
 * A duplicate resolves to its head: `alert_id` is the head's id, and `requested_alert_id` the one asked for.
 */
export type AlertView = {
  alert_id: string;
  status: string;
  suggestion_visible: boolean;
  triage_status?: string | null;
  suggestion?: Suggestion | null;
  /**
   * `llm_runs.stopped_by` of the newest ① proposer run (INT-T02, DEC-211 R6): `unavailable` for a provider
   * refusal (a 402), `cap`, `schema`, `transient`, `linter`; null when that run did not stop or there is none.
   * It goes with `suggestion`: absent on a blind, undecided head. Only `aiStateOfView` reads it.
   */
  llm_stopped_by?: string | null;
  /**
   * What the model itself concluded, and which checks of the gate raised a warning beside it (P14-T03, DEC-213;
   * DEC-217): the same two keys as a queue row. They go with `suggestion` on the blind arm: absent on a blind,
   * undecided head.
   */
  proposed_action?: string | null;
  held_by?: string[];
  /**
   * How strongly the lookup ①'s prompt held matched approved knowledge, and the closed kind of the failure when the
   * RAG was left out (P14-T07, DEC-213): `{best_pct, not_applied}`, read through `ragNoteOf`. It goes with
   * `suggestion` on the blind arm: absent on a blind, undecided head. The queue rows carry none.
   */
  rag?: RagWire;

  requested_alert_id?: string;
  duplicate_of?: string | null;
  rule_id?: string | null;
  rule_level?: number | null;
  description?: string | null;
  category?: string | null;
  categories?: string[] | null;
  severity?: string | null;
  /** The Vietnamese band label (`Thấp`, `Vừa`, `Cao`, `Rất cao`), or null with no score. */
  risk_band?: string | null;
  agent_name?: string | null;
  origin_host?: string | null;
  alert_time?: string | null;
  event_time?: string | null;
  alert_user?: string | null;
  srcip?: string | null;
  dstip?: string | null;
  src_port?: number | string | null;
  dst_port?: number | string | null;
  decoder?: string | null;
  mitre_ids?: string[] | null;
  rule_groups?: string[] | null;
  raw_log?: string | null;
  raw_log_truncated?: boolean | null;
  source?: string | null;
  occurrence_count?: number;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  acknowledged_at?: string | null;
  /** The user id of the acknowledger, and the name to show. */
  acknowledged_by?: string | number | null;
  acknowledged_by_name?: string | null;
  closed_at?: string | null;
  close_reason?: string | null;
  case_id?: number | string | null;

  asset_context?: {
    present?: boolean | null;
    criticality?: string | null;
    owner?: string | null;
    role?: string | null;
  } | null;
  identity_context?: { privileged?: boolean | null } | null;
  ioc_context?: { reputation?: string | null } | null;
  lookup_status?: LookupStatus | null;

  targeted_accounts?: string[] | null;
  correlation?: { rows?: CorrelationRow[] | null; samples?: CorrelationSample[] | null } | null;
  correlated_now?: number | null;
  /** The playbook of the category: the text of its markdown file, or null. */
  playbook?: string | null;
  /**
   * The SIEM's SOAR enrichment (S3), or null for an alert that carries none. SIEM context, not ① output: the
   * blind arm gets it too, and the labelling page never does (the server strips it there).
   */
  soar?: SoarBlob | null;
};

export function fetchAlertView(alertId: string, signal?: AbortSignal): Promise<AlertView> {
  return api<AlertView>(`/tier1/alerts/${encodeURIComponent(alertId)}`, { signal });
}

/** The two closing decisions of a Tier-1 analyst. */
export type Decision = "false_positive" | "benign";
export type CaseSeverity = "critical" | "high" | "medium" | "low";
export const CASE_SEVERITIES: readonly CaseSeverity[] = ["critical", "high", "medium", "low"];

/** `POST .../acknowledge`: idempotent for the holder; `first` is false when it was already held. */
export type AcknowledgeResult = {
  alert_id: string;
  status: string;
  acknowledged_by?: string | number | null;
  acknowledged_by_name?: string | null;
  acknowledged_at?: string | null;
  first?: boolean;
};
/** `POST .../decide`: `closed_count` is every alert the decision closed, the head itself included (1 when it had no duplicates). */
export type DecideResult = {
  alert_id: string;
  status: string;
  closed_count: number;
  case_id: number | string | null;
};
/** `POST .../escalate` (201): the case it opened. `head_count` is 1: the case is the alert alone (and its copies). */
export type EscalateResult = {
  alert_id: string;
  case_id: number | string;
  status: string;
  head_count?: number;
};
/** `POST .../reopen`. */
export type ReopenResult = { alert_id: string; status: string };

const alertPath = (alertId: string, action: string) =>
  `/tier1/alerts/${encodeURIComponent(alertId)}/${action}`;

export function postAcknowledge(alertId: string): Promise<AcknowledgeResult> {
  return api<AcknowledgeResult>(alertPath(alertId, "acknowledge"), { method: "POST" });
}

export function postDecide(
  alertId: string,
  body: { decision: Decision; reason: string; seen_occurrence_count: number },
): Promise<DecideResult> {
  return api<DecideResult>(alertPath(alertId, "decide"), { method: "POST", json: body });
}

export function postEscalate(
  alertId: string,
  body: { title: string; severity?: CaseSeverity },
): Promise<EscalateResult> {
  return api<EscalateResult>(alertPath(alertId, "escalate"), { method: "POST", json: body });
}

export function postReopen(alertId: string, body: { reason: string }): Promise<ReopenResult> {
  return api<ReopenResult>(alertPath(alertId, "reopen"), { method: "POST", json: body });
}

/** What a decision call answers with (each route returns the decide module's dict). */
export type DecisionResult = AcknowledgeResult | DecideResult | EscalateResult | ReopenResult;

/**
 * The body of a 409 (`decide.DecisionConflict.body`, sent flat: `ApiError.detail` is this object). Every
 * kind carries the alert's current `status`; the count fields belong to `cluster_grew`, the decider to
 * `already_decided`.
 */
export type ConflictBody = {
  kind: "cluster_grew" | "already_decided" | "not_active" | "already_in_case" | "not_reopenable";
  status?: string;
  occurrence_count?: number;
  seen_occurrence_count?: number;
  delta?: number;
  tolerance?: number;
  decided_by?: string | null;
  decision?: string | null;
  decided_at?: string | null;
  acknowledged_by?: string | number | null;
};
