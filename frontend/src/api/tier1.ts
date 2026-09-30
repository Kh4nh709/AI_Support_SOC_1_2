// The Tier-1 routes, one typed function each. This file holds the queue (P10-T09); the alert page and the
// decisions (P10-T10) add theirs below. The shapes are written by hand against the backend
// (web/routers/tier1.py, tier1/queue.py): the backend answers with plain dicts.
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

/** The rows of a page the queue asks for. The server's own default is 50 and its ceiling 200. */
export const QUEUE_PAGE_SIZE = 50;

/** The request path of one page of the queue. Only the filters that are set appear in it. */
export function queuePath(filters: QueueFilters, page: number, pageSize = QUEUE_PAGE_SIZE): string {
  const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
  if (filters.band) query.set("band", filters.band);
  if (filters.category) query.set("category", filters.category);
  if (filters.agent) query.set("agent", filters.agent);
  if (filters.status === "mine") query.set("status", "mine");
  return `/tier1/queue?${query}`;
}

export function fetchQueue(
  filters: QueueFilters,
  page: number,
  signal?: AbortSignal,
): Promise<QueueResponse> {
  return api<QueueResponse>(queuePath(filters, page), { signal });
}

/**
 * `GET /api/tier1/alerts/{id}`: the analyst view of one alert. Only what the ① state reads is typed here
 * (`aiStateOfView`); P10-T10 completes the shape. `suggestion` is absent on a blind, undecided alert,
 * `null` when no ① result exists, and an object when there is one.
 */
export type AlertView = {
  alert_id: string;
  status: string;
  suggestion_visible: boolean;
  triage_status?: string | null;
  suggestion?: {
    suggested_action: string | null;
    confidence: string | null;
    gate?: { forced?: boolean | null } | null;
  } | null;
};
