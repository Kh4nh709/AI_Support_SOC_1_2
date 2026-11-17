// The Tier-2 routes (backend/app/web/routers/tier2.py and tier2_runs.py), written by hand: the backend
// answers with plain dicts, so there is no generated schema to import. Every string a person or the model
// wrote arrives as `unknown`-tolerant text and is rendered as text; nothing here is markup.
import { ApiError, api } from "./client";
import type { RagWire } from "./rag";

/** `cases.status` of a case that is still being worked; every other value is closed. */
export const OPEN_CASE_STATUS = "investigating";

/**
 * `cases.status` of a case the archive of the old queue set aside without review (INT-T03, DEC-212). It is
 * closed, and nobody concluded it: no `concluded_by`, and it is none of the three conclusions.
 */
export const ARCHIVED_CASE_STATUS = "archived";

/** `ck_cases_status`: the five values of `cases.status`, `archived` (021) last. A row may still carry a word the UI does not know. */
export const CASE_STATUSES = [
  OPEN_CASE_STATUS,
  "concluded_fp",
  "concluded_policy_violation",
  "confirmed_incident",
  ARCHIVED_CASE_STATUS,
] as const;
export type CaseStatus = (typeof CASE_STATUSES)[number];

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
  /** The newest ② run, as on the case page (INT-T02 fix round 1): the list's "Phân tích gần nhất" reads it. */
  last_run: CaseLastRun | null;
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

/** The closed values of a hypothesis's `likelihood` and a next step's `priority` (`investigate_v4`). */
export const LEVELS = ["low", "medium", "high"] as const;
export type Level = (typeof LEVELS)[number];

export type HypothesisRow = {
  text: string | null;
  evidence_for: unknown[];
  evidence_against: unknown[];
  /** DEC-221: `null` for a run stored before version 4, which has none; absent from an older server. */
  likelihood?: Level | null;
};

/**
 * One row of the timeline of a version 4 run (DEC-221). `time` is the alert's own time, taken by the server from the
 * alert the row names; the model writes none. The rows come sorted by it, at most 50, never one naming an alert outside
 * the case. `tactic` and `technique` are the model's text, or null.
 *
 * DEC-223: `technique_name` and `technique_known` are what the server made of `technique` against the local MITRE
 * ATT&CK document (`kb/mitre/`): MITRE's own name and `true` for an id the document holds; `null` and `false` for a
 * value shaped like an id that it does not hold; `null` and `null` for anything else, and for every row when the
 * server has no such document. They are `undefined` from an older server. `technique` itself is what the model wrote.
 */
export type TimelineRow = {
  alert_id: string;
  time: string | null;
  what: string;
  tactic: string | null;
  technique: string | null;
  technique_name?: string | null;
  technique_known?: boolean | null;
};

/** A next step with its priority (DEC-221): `priority` is null for a run stored before version 4. */
export type NextStepRow = { step: string; priority: Level | null };

/**
 * The scope of a run (DEC-221): the hosts and accounts the model named (`[]` for a run stored before version 4), and
 * what the system knows of the case's alerts (`system`).
 */
export type ScopeView = {
  hosts: string[];
  accounts: string[];
  system: { hosts: string[]; accounts: string[]; alert_count: number };
};

/**
 * The technical figures of a run (DEC-221). There is no model in it, and none is shown: the Owner asked for the
 * model's name to be out of the page (G5). `alerts_read` is null when the run recorded no snapshot.
 */
export type TechView = {
  input_tokens: number | null;
  output_tokens: number | null;
  latency_ms: number | null;
  cost_usd: number | null;
  analysed_at: string | null;
  playbook: string | null;
  alerts_read: number | null;
};

/** How many quotes the run cited, and how many of them the server found in the log. */
export type EvidenceSummary = { cited: number; verified: number };

/** What the knowledge lookup of a run came to (`llm.rag_view.rag_panel`): five states, and a failure kind for one. */
export const KNOWLEDGE_STATES = [
  "matched",
  "below_floor",
  "no_candidate",
  "failed",
  "no_lookup",
] as const;
export type KnowledgeState = (typeof KNOWLEDGE_STATES)[number];

/**
 * `run.knowledge` (DEC-221): `best_pct` is the best kept match (`matched`) or the best candidate under the floor
 * (`below_floor`, cut down), else null; `floor_pct` is the floor the candidates were held to, null when the lookup
 * had no ranking; `scored` is how many candidates were scored. `candidates` is at most three, best first, only for
 * `matched` and `below_floor`; a title or a conclusion is null when the entry is gone.
 */
export type KnowledgeView = {
  state: string;
  failure: string | null;
  best_pct: number | null;
  floor_pct: number | null;
  threshold_pct: number;
  scored: number | null;
  candidates: { pct: number; title: string | null; conclusion: string | null }[];
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
  /**
   * P14-T02/T03 (DEC-213): the model's own conclusion (`false_positive`, `policy_violation` or
   * `confirmed_incident`), and why the system held it as `need_more_data` (`no_verified_evidence`,
   * `high_severity_injection_finding`; `[]` when it did not). A run from before P14-T02 has `null` and `[]`.
   */
  model_conclusion?: string | null;
  held_by?: string[];
  /**
   * How strongly the lookup ②'s prompt held matched approved knowledge, and the closed kind of the failure when the
   * RAG was left out (P14-T07, DEC-213): `{best_pct, not_applied}`, read through `ragNoteOf`; and, for a lookup that
   * kept no match, the best candidate's percentage and the floor it was under (DEC-220, trial): `below_floor_pct`,
   * `floor_pct`. A run from before T06 has `{best_pct: null, not_applied: null, below_floor_pct: null, floor_pct:
   * null}`; a stopped run carries the kind but the page words it only beside a conclusion.
   */
  rag?: RagWire;
  snapshot?: Snapshot | null;
  /** The case has changed since the run's snapshot. */
  changed?: boolean;
  /**
   * DEC-221 (the Tier 2 panel). Every key below is absent from an older server and may be empty or null for a run
   * stored before version 4: the page reads each one as optional (`runModel.ts`).
   */
  evidence_summary?: EvidenceSummary;
  timeline?: TimelineRow[];
  scope?: ScopeView;
  /** `next_steps` with the priority of each step; the list of strings above stays until the old page is gone. */
  next_steps_rows?: NextStepRow[];
  tech?: TechView;
  knowledge?: KnowledgeView;
  /**
   * DEC-223: how many served timeline rows name an ATT&CK id the local document does not hold
   * (`technique_known: false`); `null` when the server has no such document. The page marks each such row itself.
   */
  checks?: { technique_not_in_reference: number | null };
};

/**
 * What the model may conclude on a case (`llm.verdicts.MODEL_CONCLUSIONS`, P14-T02). `need_more_data` is not one:
 * only the system stores it, when it holds a conclusion back. A copy; strings.test.ts reads the Python source and
 * compares the two.
 */
export const MODEL_CONCLUSIONS = [
  "false_positive",
  "policy_violation",
  "confirmed_incident",
] as const;

/** The conclusion the system stores in place of the model's own when it holds one back. */
export const HELD_CONCLUSION = "need_more_data";

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
