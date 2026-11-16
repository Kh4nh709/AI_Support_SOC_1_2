// The SOAR review routes (spec 2026-11-16-soar-review-web-design.md section 4), one typed function each. The shapes are
// written by hand against the spec, as the other route files are against the backend. Everything in a review that came
// from n8n (titles, labels, notes, hosts, results, errors, the raw body) is TEXT: the pages render it as text and build
// no URL, class name or attribute from it. The closed sets are unions here, and the pages read them through `labelOf`,
// so a code this UI has no word for is shown as the code and never crashes anything.
import { api } from "./client";

export const SOAR_KINDS = ["review", "notice"] as const;
export type SoarKind = (typeof SOAR_KINDS)[number];

/** `processing` is the web's own (a decision is in flight); `info` is a notice's. */
export const SOAR_STATUSES = [
  "open",
  "processing",
  "kept",
  "undone",
  "false_positive",
  "expired",
  "info",
] as const;
export type SoarStatus = (typeof SOAR_STATUSES)[number];

export const SOAR_SEVERITIES = ["info", "warning", "error"] as const;
export type SoarSeverity = (typeof SOAR_SEVERITIES)[number];

export const SOAR_ACTION_TYPES = [
  "block_ip",
  "sinkhole_domain",
  "isolate_host",
  "disable_user",
  "disable_xp_cmdshell",
  "kill_process",
] as const;
export type SoarActionType = (typeof SOAR_ACTION_TYPES)[number];

export const SOAR_DECISIONS = ["keep", "undo", "fp"] as const;
export type SoarDecision = (typeof SOAR_DECISIONS)[number];

export type SoarButton = { decision: SoarDecision; label: string };

/** What the decision route says n8n did (section 4, step 6). */
export type SoarOutcome = "ok" | "failed" | "unavailable" | "conflict";

/** The served review object, the same on every route (section 4). Timestamps are ISO 8601 with an offset. */
export type SoarReview = {
  id: string;
  kind: SoarKind;
  /** The EFFECTIVE status: a lock older than two minutes is served with the status the row had before it. */
  status: SoarStatus;
  severity: SoarSeverity | null;
  title: string | null;
  simulated: boolean;
  case_id: string | null;
  case_number: number | null;
  action_type: SoarActionType | null;
  action_text: string | null;
  action_target: string | null;
  action_via: "pfsense" | "wazuh" | null;
  action_agent: string | null;
  host: string | null;
  agent_id: string | null;
  user_name: string | null;
  src_ip: string | null;
  domain: string | null;
  scenario_id: string | null;
  scenario_name: string | null;
  score: number | null;
  note: string | null;
  buttons: SoarButton[];
  created_at: string;
  auto_expire_at: string | null;
  remind_every_minutes: number | null;
  next_remind_at: string | null;
  decided_by: string | null;
  decided_at: string | null;
  result: string | null;
  last_error: string | null;
  locked_by: string | null;
  locked_at: string | null;
  last_sent_at: string | null;
  /** The clock of the web when it first stored the row; never changed. */
  received_at: string | null;
  /** Moves on every write of the row (a webhook update, the lock, the finish). */
  updated_at: string | null;
  /** For THIS caller: valid for the state AND allowed for the role. */
  allowed_decisions: SoarDecision[];
  /** `action_type` is `isolate_host`, or `host_critical`. */
  strong_warning: boolean;
  /**
   * The host is one the configuration of the web lists as critical (`SOAR_AD_HOSTS`, the domain controller among them). Absent
   * on an older server, which reads as false: the pages never say a host is important unless this is true.
   */
  host_critical?: boolean;
};

/** `GET /api/soar/reviews`. */
export type SoarListResponse = {
  rows: SoarReview[];
  total: number;
  page: number;
  page_size: number;
};

/** `GET /api/soar/reviews/count`. */
/**
 * `GET /api/soar/reviews/count`. `latest_received_at` is the clock of the WEB at the first arrival of the newest open
 * review (the `created_at` of n8n can be older than a ticket already shown when a delivery is late): the signal compares it.
 */
export type SoarCountResponse = { count: number; latest_received_at: string | null };

/** One event of a review's history: an audit event whose subject is the review's id. */
export type SoarHistoryEvent = {
  at: string;
  event: string;
  actor: string | null;
  actor_role: string | null;
  /** `soar.review_received`: {event, kind, outcome, reason, status, sent_at}. `soar.review_decided`: {decision, note, outcome, status_before, status_after, message}. */
  payload: Record<string, unknown> | null;
};

/** An alert of the same case (section 5), as the queue row names its fields; no AI field. */
export type SoarRelatedAlert = {
  alert_id: string;
  alert_time: string;
  agent_name: string | null;
  description: string | null;
  severity: string | null;
  status: string | null;
  occurrence_count: number;
};

/** `GET /api/soar/reviews/{id}`: the review, the last body n8n sent, its history and the alerts of the same case. */
export type SoarReviewDetail = SoarReview & {
  raw: unknown;
  history: SoarHistoryEvent[];
  related_alerts: SoarRelatedAlert[];
  related_total: number;
  /** True when older events were left out of `history` (the newest 200 are served). Absent reads as false. */
  history_truncated?: boolean;
};

/** `POST /api/soar/reviews/{id}/decision`. HTTP errors are only the local ones (401, 403, 404, 409, 422, 503). */
export type SoarDecisionAnswer = {
  outcome: SoarOutcome;
  message: string | null;
  review: SoarReview;
};

/** The rows of a page the list asks for; the server's own default is 50 and its ceiling 200. */
export const SOAR_PAGE_SIZE = 50;

/** What the list filters on. A filter that is not set is left out of the request (an empty one is a 422). */
export type SoarListQuery = {
  /** Repeated in the request: `status=open&status=processing`. */
  status?: readonly string[];
  kind?: SoarKind;
  /** The search box: a case number, or part of an IP, a host, a target, a user, a domain. At most 100 characters. */
  q?: string;
  page: number;
  pageSize?: number;
};

export function soarListPath(query: SoarListQuery): string {
  const params = new URLSearchParams({
    page: String(query.page),
    page_size: String(query.pageSize ?? SOAR_PAGE_SIZE),
  });
  for (const status of query.status ?? []) params.append("status", status);
  if (query.kind) params.set("kind", query.kind);
  if (query.q) params.set("q", query.q);
  return `/soar/reviews?${params}`;
}

export function fetchSoarReviews(
  query: SoarListQuery,
  signal?: AbortSignal,
): Promise<SoarListResponse> {
  return api<SoarListResponse>(soarListPath(query), { signal });
}

export function fetchSoarCount(signal?: AbortSignal): Promise<SoarCountResponse> {
  return api<SoarCountResponse>("/soar/reviews/count", { signal });
}

const reviewPath = (id: string, tail = ""): string =>
  `/soar/reviews/${encodeURIComponent(id)}${tail}`;

export function fetchSoarReview(id: string, signal?: AbortSignal): Promise<SoarReviewDetail> {
  return api<SoarReviewDetail>(reviewPath(id), { signal });
}

export function postSoarDecision(
  id: string,
  body: { decision: SoarDecision; note?: string },
): Promise<SoarDecisionAnswer> {
  return api<SoarDecisionAnswer>(reviewPath(id, "/decision"), { method: "POST", json: body });
}
