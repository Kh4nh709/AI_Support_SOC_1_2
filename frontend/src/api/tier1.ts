// The Tier-1 routes, one typed function each: the queue (P10-T09), the alert page and the decisions
// (P10-T10). The shapes are written by hand against the backend (web/routers/tier1.py, tier1/queue.py,
// tier1/decide.py): the backend answers with plain dicts.
import { api } from "./client";
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
  suggested_action?: string | null;
  confidence?: string | null;
  gate_forced?: boolean | null;
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

/** What the ① gate did (`queue.latest_suggestion`). `forced_by` is a list of gate rules, or absent. */
export type SuggestionGate = {
  forced?: boolean | null;
  forced_by?: string[] | string | null;
  proposed_verdict?: string | null;
  final_verdict?: string | null;
  verifier_verdict?: string | null;
  warnings?: unknown[] | null;
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
 * `GET /api/tier1/alerts/{id}`: the analyst view of one alert (`queue.get_alert_view(mode="analyst")`),
 * written by hand against the backend. The keys `aiStateOfView` reads and the ones every view carries are
 * required; the rest are optional because a section is shown only when the view carries its data, and a
 * value the database may leave empty is `| null`.
 *
 * The blind arm (DEC-101) is decided by the server: on a blind, undecided head, `suggestion` (and with it
 * `triage_status`, `run_id`, `triaged_count`, `needs_retriage`) is ABSENT, not null, and
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
/** `POST .../decide`: `closed_count` is the alerts the fan-out closed with the head. */
export type DecideResult = {
  alert_id: string;
  status: string;
  closed_count: number;
  case_id: number | string | null;
};
/** `POST .../escalate` (201): the case it opened. */
export type EscalateResult = {
  alert_id: string;
  case_id: number | string;
  status: string;
  head_count?: number;
  truncated?: boolean;
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
