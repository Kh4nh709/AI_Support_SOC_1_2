// What the Tier 2 panel reads out of a run (DEC-221), key by key. A run is what `investigation_view.present_run`
// serves, but a key may be missing (an older server), `null` or empty (a result stored before version 4 has no timeline,
// no likelihood, no priority), or of the wrong kind: a stored document is data. Every reader here takes a run and
// answers with a value the panel can draw without a crash; none of them throws, and none invents a value the run does
// not carry. Pure: no component, no query.
import { ragNoteOf } from "../../api/rag";
import {
  HELD_CONCLUSION,
  LEVELS,
  MODEL_CONCLUSIONS,
  type Level,
  type RunView,
  type Snapshot,
  type TimelineRow,
} from "../../api/tier2";
import { S } from "../../strings";
import type { Tone } from "../analysis/styles";
import { asText } from "./parts";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** A string that says something; anything else is nothing. */
const text = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value : null;

/** The strings of a list, in their order; anything that is not a list is an empty one. */
const texts = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string" && item !== "")
    : [];

const isLevel = (value: unknown): value is Level =>
  typeof value === "string" && (LEVELS as readonly string[]).includes(value);

/** A whole percentage from 0 to 100, else null (`api/rag.ts` holds the lookup's pair to the same rule). */
const pct = (value: unknown): number | null =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 100 ? value : null;

const count = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

const wholeCount = (value: unknown): number | null =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;

// ── the conclusion ───────────────────────────────────────────────────────────────────────────────

/**
 * Whether the system held the model's conclusion back as `need_more_data` and why (P14-T02/T03, DEC-213). The causes
 * are the ones the server named. The system held the conclusion when it named one, and also when the stored conclusion
 * is `need_more_data` over one of the three the model may give: the stored word is the system's own, so a `held_by`
 * that came out empty does not turn the override into the model's answer. A run from before P14-T02 carries no
 * `model_conclusion` and is never held.
 */
export function heldOf(run: RunView): {
  modelConclusion: string | null;
  causes: string[];
  held: boolean;
} {
  const modelConclusion = text(run.model_conclusion);
  const causes = texts(run.held_by);
  const held =
    modelConclusion !== null &&
    (causes.length > 0 ||
      (run.conclusion === HELD_CONCLUSION &&
        (MODEL_CONCLUSIONS as readonly string[]).includes(modelConclusion)));
  return { modelConclusion, causes, held };
}

/**
 * The server's sentence saying the conclusion was lowered, when the page should say it: for an older run, which has no
 * `model_conclusion`, and for a held one that names no cause. A held conclusion that names its causes says them
 * itself, and the sentence would repeat them.
 */
export function overruledShown(run: RunView): string | null {
  const { modelConclusion, causes, held } = heldOf(run);
  const sentence = text(run.overruled);
  if (sentence === null) return null;
  return modelConclusion === null || (held && causes.length === 0) ? sentence : null;
}

/** The colour of a conclusion's tile: an incident is critical, a violation high, a false positive calm. */
const VERDICT_TONE: Record<string, Tone> = {
  confirmed_incident: "critical",
  policy_violation: "high",
  false_positive: "low",
  need_more_data: "medium",
};

export type VerdictTile = { label: string; tone: Tone; note: string };

/**
 * The Kết luận tile. The label is the stored conclusion's own (the system's `need_more_data` when it held the
 * model's conclusion back or lowered it), and the line under it says whose word that is: the assistant's suggestion,
 * a conclusion the system held, or one an older run had lowered. What the model itself concluded, and why the system
 * held it, are in "Cần lưu ý" on the overview.
 */
export function verdictTile(run: RunView): VerdictTile {
  const code = text(run.conclusion);
  const known =
    code !== null && Object.hasOwn(S.ai2.suggestedConclusion, code)
      ? (S.ai2.suggestedConclusion as Record<string, string>)[code]
      : undefined;
  const label = known ?? text(run.conclusion_label) ?? S.common.missing;
  const tone: Tone =
    code !== null && Object.hasOwn(VERDICT_TONE, code)
      ? (VERDICT_TONE[code] ?? "neutral")
      : "neutral";
  const note = heldOf(run).held
    ? S.ai2.tile.verdictNote.held
    : overruledShown(run) !== null
      ? S.ai2.tile.verdictNote.overruled
      : S.ai2.tile.verdictNote.plain;
  return { label, tone, note };
}

/** The Độ tin cậy tile: the word and the level of the meter. A level this page has no scale for has no meter. */
export function confidenceOf(run: RunView): { level: Level | null; word: string } {
  const value: unknown = run.confidence;
  if (isLevel(value)) return { level: value, word: S.analysis.level[value] };
  return { level: null, word: text(value) ?? S.common.missing };
}

// ── the knowledge lookup ─────────────────────────────────────────────────────────────────────────

export type Candidate = { pct: number; title: string | null; conclusion: string | null };

/** What the lookup of a run came to, as the panel reads it (`KnowledgeView` with every key made safe). */
export type Knowledge = {
  state: string;
  failure: string | null;
  best_pct: number | null;
  floor_pct: number | null;
  scored: number | null;
  candidates: Candidate[];
};

/** At most three candidates are listed, best first, as the server sends them. */
const CANDIDATES_SHOWN = 3;

function candidatesOf(value: unknown): Candidate[] {
  if (!Array.isArray(value)) return [];
  return value
    .flatMap((row): Candidate[] => {
      if (!isRecord(row)) return [];
      const percentage = pct(row.pct);
      if (percentage === null) return [];
      return [{ pct: percentage, title: text(row.title), conclusion: text(row.conclusion) }];
    })
    .slice(0, CANDIDATES_SHOWN);
}

/**
 * The lookup of a run: `run.knowledge` when the server sends one, else what the older `rag` pair says
 * (`api/rag.ts`): a failure kind, a kept match, or the best candidate under the floor. Null when neither says anything.
 */
export function knowledgeOf(run: RunView): Knowledge | null {
  const raw: unknown = run.knowledge;
  if (isRecord(raw) && typeof raw.state === "string") {
    return {
      state: raw.state,
      failure: text(raw.failure),
      best_pct: pct(raw.best_pct),
      floor_pct: pct(raw.floor_pct),
      scored: wholeCount(raw.scored),
      candidates: candidatesOf(raw.candidates),
    };
  }
  const note = ragNoteOf(run.rag);
  const none = { scored: null, candidates: [] };
  if (note.notApplied !== null) {
    return { state: "failed", failure: note.notApplied, best_pct: null, floor_pct: null, ...none };
  }
  if (note.pct !== null) {
    return { state: "matched", failure: null, best_pct: note.pct, floor_pct: null, ...none };
  }
  if (note.belowFloor !== undefined) {
    return {
      state: "below_floor",
      failure: null,
      best_pct: note.belowFloor.pct,
      floor_pct: note.belowFloor.floor,
      ...none,
    };
  }
  return null;
}

export type RagTile = { value: string; note: string };

/**
 * The Tri thức (RAG) tile: the number for a lookup that kept a match or scored candidates under the floor, and a dash
 * with a short line for the other three states and for each failure kind.
 */
export function ragTile(run: RunView): RagTile {
  const N = S.ai2.tile.ragNote;
  const k = knowledgeOf(run);
  const noData: RagTile = { value: S.common.missing, note: N.noData };
  if (k === null) return noData;
  switch (k.state) {
    case "matched":
      return k.best_pct === null ? noData : { value: `${k.best_pct}%`, note: N.matched };
    case "below_floor":
      return k.best_pct === null
        ? noData
        : { value: `${k.best_pct}%`, note: N.belowFloor(k.floor_pct) };
    case "no_candidate":
      return { value: S.common.missing, note: N.noCandidate };
    case "no_lookup":
      return { value: S.common.missing, note: N.noLookup };
    case "failed":
      return {
        value: S.common.missing,
        note:
          k.failure !== null && Object.hasOwn(N.failedKind, k.failure)
            ? (N.failedKind as Record<string, string>)[k.failure]!
            : N.failed,
      };
    default:
      return noData;
  }
}

// ── the evidence ─────────────────────────────────────────────────────────────────────────────────

/** How many quotes the run cited and how many the server found in the log: its own summary, else the rows counted. */
export function evidenceCounts(run: RunView): { cited: number; verified: number } {
  const summary: unknown = run.evidence_summary;
  if (isRecord(summary)) {
    const cited = wholeCount(summary.cited);
    const verified = wholeCount(summary.verified);
    if (cited !== null && verified !== null) return { cited, verified: Math.min(verified, cited) };
  }
  const rows: unknown[] = Array.isArray(run.evidence) ? run.evidence : [];
  return {
    cited: rows.length,
    verified: rows.filter((row) => isRecord(row) && row.verified === true).length,
  };
}

export type EvidenceTile = { value: string; note: string; warn: boolean };

/** The Dẫn chứng tile: verified over cited, in the warning colour when a quote was not found. */
export function evidenceTile(run: RunView): EvidenceTile {
  const { cited, verified } = evidenceCounts(run);
  if (cited === 0) {
    return { value: S.common.missing, note: S.ai2.tile.evidenceNone, warn: false };
  }
  return { value: `${verified}/${cited}`, note: S.ai2.tile.evidenceNote, warn: verified < cited };
}

// ── the timeline and the scope ───────────────────────────────────────────────────────────────────

/**
 * The timeline as the server serves it, sorted by the alerts' own times: the rows that name an alert and say what
 * happened. A run stored before version 4 has none.
 */
export function timelineOf(run: RunView): TimelineRow[] {
  const raw: unknown = run.timeline;
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((row): TimelineRow[] => {
    if (!isRecord(row)) return [];
    const alertId = text(row.alert_id);
    const what = text(row.what);
    if (alertId === null || what === null) return [];
    return [
      {
        alert_id: alertId,
        time: text(row.time),
        what,
        tactic: text(row.tactic),
        technique: text(row.technique),
      },
    ];
  });
}

/** The MITRE steps of a timeline: how many rows name a tactic or a technique, and the one the last of them ends at. */
export function mitreSteps(rows: readonly TimelineRow[]): { count: number; endsAt: string | null } {
  const steps = rows.filter((row) => row.tactic !== null || row.technique !== null);
  const last = steps.at(-1);
  return {
    count: steps.length,
    endsAt: last === undefined ? null : (last.technique ?? last.tactic),
  };
}

export type ScopeSide = { model: string[]; system: string[] };

/** The hosts and the accounts the model named, beside the ones the system knows from the case's alerts. */
export function scopeOf(run: RunView): { hosts: ScopeSide; accounts: ScopeSide } {
  const scope: Record<string, unknown> = isRecord(run.scope) ? run.scope : {};
  const system: Record<string, unknown> = isRecord(scope.system) ? scope.system : {};
  return {
    hosts: { model: texts(scope.hosts), system: texts(system.hosts) },
    accounts: { model: texts(scope.accounts), system: texts(system.accounts) },
  };
}

// ── the steps, the hypotheses, the figures ───────────────────────────────────────────────────────

export type NextStep = { step: string; priority: Level | null };

/**
 * The next steps with their priority. A server that sends no rows is read through its list of strings, each a step
 * with no priority; so is a version 3 run's, whose rows the server builds the same way.
 */
export function nextStepsOf(run: RunView): NextStep[] {
  const rows: unknown = run.next_steps_rows;
  if (Array.isArray(rows)) {
    return rows.flatMap((row): NextStep[] => {
      if (!isRecord(row)) return [];
      const step = text(row.step);
      return step === null ? [] : [{ step, priority: isLevel(row.priority) ? row.priority : null }];
    });
  }
  return texts(run.next_steps).map((step) => ({ step, priority: null }));
}

export type Hypothesis = {
  text: string | null;
  likelihood: Level | null;
  support: string[];
  counter: string[];
};

/** Each hypothesis: its text, how likely the model thinks it is (version 4 only), the evidence for and against. */
export function hypothesesOf(run: RunView): Hypothesis[] {
  const raw: unknown = run.hypotheses;
  if (!Array.isArray(raw)) return [];
  const lines = (value: unknown): string[] => (Array.isArray(value) ? value.map(asText) : []);
  return raw.flatMap((row): Hypothesis[] => {
    if (!isRecord(row)) return [];
    return [
      {
        text: typeof row.text === "string" ? row.text : null,
        likelihood: isLevel(row.likelihood) ? row.likelihood : null,
        support: lines(row.evidence_for),
        counter: lines(row.evidence_against),
      },
    ];
  });
}

export type Tech = {
  inputTokens: number | null;
  outputTokens: number | null;
  latencyMs: number | null;
  costUsd: number | null;
  analysedAt: string | null;
  playbook: string | null;
  alertsRead: number | null;
  alertsTotal: number | null;
};

/**
 * The figures of the technical tab. There is no model in them and none is read from anywhere else (G5). A server that
 * sends no `tech` is read through the run's own keys: when it was made, the playbook it names, the snapshot's alert
 * count; its tokens, time and cost are then unknown. The total is the case's alert count, from the scope of the run or,
 * failing that, from what the case has now.
 */
export function techOf(run: RunView, current: Snapshot | null): Tech {
  const tech: unknown = run.tech;
  const total = count(scopeSystemAlertCount(run)) ?? count(current?.alert_count);
  if (!isRecord(tech)) {
    return {
      inputTokens: null,
      outputTokens: null,
      latencyMs: null,
      costUsd: null,
      analysedAt: text(run.created_at),
      playbook: text(run.playbook_used),
      alertsRead: count(run.snapshot?.alert_count),
      alertsTotal: total,
    };
  }
  return {
    inputTokens: count(tech.input_tokens),
    outputTokens: count(tech.output_tokens),
    latencyMs: count(tech.latency_ms),
    costUsd: count(tech.cost_usd),
    analysedAt: text(tech.analysed_at),
    playbook: text(tech.playbook),
    alertsRead: count(tech.alerts_read),
    alertsTotal: total,
  };
}

function scopeSystemAlertCount(run: RunView): unknown {
  const scope: unknown = run.scope;
  if (!isRecord(scope) || !isRecord(scope.system)) return null;
  return scope.system.alert_count;
}
