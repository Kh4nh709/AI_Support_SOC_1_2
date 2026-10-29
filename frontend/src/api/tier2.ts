// The Tier-2 routes (backend/app/web/routers/tier2.py and tier2_runs.py), written by hand: the backend
// answers with plain dicts, so there is no generated schema to import. Every string a person or the model
// wrote arrives as `unknown`-tolerant text and is rendered as text; nothing here is markup.
import { ApiError, api } from "./client";

/** `cases.status` of a case that is still being worked; every other value is a conclusion. */
export const OPEN_CASE_STATUS = "investigating";

/** The case list is paged by offset, this many rows a page (the route allows up to 200). */
export const CASE_PAGE_SIZE = 50;

/** One row of `GET /api/tier2/cases`. */
export type CaseRow = {
  case_id: string;
  title: string;
  status: string;
  severity: string | null;
  created_at: string;
  last_analyzed_at: string | null;
  cluster_count: number;
  /** Heads plus the duplicates merged into them. */
  occurrence_count: number;
};

/** A head of a case, with what `case_view.enrich_heads` adds (never `risk_score`). */
export type CaseHead = {
  alert_id: string;
  rule_id: string | null;
  severity: string | null;
  description: string | null;
  agent_name: string | null;
  alert_time: string | null;
  srcip: string | null;
  category: string | null;
  occurrence_count: number;
  status: string;
  /** Up to about 1000 KB of log text; `raw_log_truncated` says the server cut it. */
  raw_log: string | null;
  raw_log_truncated: boolean;
  /** The server's label of the band ("Thấp", "Vừa", "Cao", "Rất cao"), read through `bandCodeOfLabel`. */
  risk_band: string | null;
  last_seen_at: string | null;
};

export type CaseNote = {
  note_id: number;
  case_id: string;
  author_id: string;
  author_name: string | null;
  body: string;
  created_at: string;
};

/** The newest ② run of a case (`case_view.last_run`). */
export type CaseLastRun = {
  created_at: string;
  has_result: boolean;
};

/** `GET /api/tier2/cases/{id}`; a conclusion (`POST .../conclude`) answers with the same shape. */
export type CaseDetail = {
  case_id: string;
  title: string;
  status: string;
  severity: string | null;
  created_by: string | null;
  created_at: string;
  /** When a ② run WITH a result last finished; what `ongoing` and the timeline are counted from. */
  last_analyzed_at: string | null;
  /**
   * The newest ② run, whatever it did (INT-T02, DEC-211 R6): `has_result` is false for a run that stopped
   * without one (a provider 402 is `permanent`), which leaves `last_analyzed_at` untouched. Null when ② has
   * never run on the case. The summary's "Phân tích gần nhất" reads this.
   */
  last_run: CaseLastRun | null;
  concluded_by: string | null;
  concluded_at: string | null;
  conclusion_reason: string | null;
  concluded_by_name: string | null;
  ongoing: boolean;
  ongoing_last_seen: string | null;
  heads: CaseHead[];
  notes: CaseNote[];
};

/** The body of the 409 of `POST .../conclude`: someone concluded the case first. */
export type ConcludeConflict = {
  status: string;
  concluded_by?: string;
  concluded_at?: string | null;
};

export const CONCLUSIONS = [
  "concluded_fp",
  "concluded_policy_violation",
  "confirmed_incident",
] as const;
export type Conclusion = (typeof CONCLUSIONS)[number];

export type Snapshot = {
  alert_count: number;
  total_occurrences: number;
  last_seen_at: string | null;
};

export type EvidenceRow = {
  alert_id: string | null;
  quote: string | null;
  why: string | null;
  /** True only when the server checked the quote against the alert's log. */
  verified: boolean;
  /** Why a quote was refused, in the server's words; null for a verified one. */
  reason_text: string | null;
};

export type HypothesisRow = {
  text: string | null;
  evidence_for: unknown[];
  evidence_against: unknown[];
};

/**
 * A run of ② as `investigation_view.present_run` builds it. A run that stopped with no result carries
 * `result: null` and `stopped_text` only, so every other field is optional.
 */
export type RunView = {
  run_id: string;
  created_at: string | null;
  result: unknown;
  stopped_text?: string;
  conclusion?: string | null;
  conclusion_label?: string;
  confidence?: string | null;
  summary?: string | null;
  narrative?: string | null;
  hypotheses?: HypothesisRow[];
  evidence?: EvidenceRow[];
  next_steps?: unknown[];
  playbook_used?: string | null;
  /** The sentence saying the model's conclusion was lowered, or null. */
  overruled?: string | null;
  snapshot?: Snapshot | null;
  /** The case has changed since the run's snapshot. */
  changed?: boolean;
};

export const INVESTIGATION_STATES = ["idle", "running", "stalled", "done", "failed"] as const;
export type InvestigationState = (typeof INVESTIGATION_STATES)[number];

export function isInvestigationState(value: unknown): value is InvestigationState {
  return typeof value === "string" && (INVESTIGATION_STATES as readonly string[]).includes(value);
}

/** `GET /api/tier2/cases/{id}/investigation`. */
export type InvestigationView = {
  state: InvestigationState;
  /** The job's run: set while `running` or `stalled`; a `done` view carries `run.run_id` instead. */
  run_id: string | null;
  /** Whole minutes a `stalled` job has waited. */
  minutes: number | null;
  run: RunView | null;
  /** The case's numbers now, set only when the run recorded a snapshot to compare them with. */
  current: Snapshot | null;
  case_open: boolean;
};

/** `POST .../analyze` answers 202 with the run to poll and the job behind it. */
export type Accepted = { run_id: string; job_id: number };

/** The HTTP status of a failed call, or null when it did not fail with an answer from the server. */
export function statusOf(error: unknown): number | null {
  return error instanceof ApiError ? error.status : null;
}

const enc = encodeURIComponent;

export function listCases(offset: number, limit: number = CASE_PAGE_SIZE): Promise<CaseRow[]> {
  return api<CaseRow[]>(`/tier2/cases?offset=${offset}&limit=${limit}`);
}

export function getCase(caseId: string): Promise<CaseDetail> {
  return api<CaseDetail>(`/tier2/cases/${enc(caseId)}`);
}

export function addNote(caseId: string, body: string): Promise<CaseNote> {
  return api<CaseNote>(`/tier2/cases/${enc(caseId)}/notes`, { method: "POST", json: { body } });
}

export function concludeCase(
  caseId: string,
  conclusion: Conclusion,
  reason: string,
): Promise<CaseDetail> {
  return api<CaseDetail>(`/tier2/cases/${enc(caseId)}/conclude`, {
    method: "POST",
    json: { conclusion, reason },
  });
}

/** The ② view; `runId` is the run of the 202, so a poll that finds nothing behind it says `failed`. */
export function getInvestigation(caseId: string, runId: string | null): Promise<InvestigationView> {
  const query = runId === null ? "" : `?run_id=${enc(runId)}`;
  return api<InvestigationView>(`/tier2/cases/${enc(caseId)}/investigation${query}`);
}

export function postAnalyze(caseId: string): Promise<Accepted> {
  return api<Accepted>(`/tier2/cases/${enc(caseId)}/analyze`, { method: "POST" });
}
