// What the Tier 1 panel reads out of the alert view's `analysis` (DEC-221, AP-T4), key by key. The object is what
// `backend/app/tier1/analysis.py` builds from a stored run, but a stored document is data: a key may be missing (an older
// server), null or empty (a run stored before version 4 has none of the model's five texts), or of another kind. Every
// reader here takes the view (or what `analysisOf` made of it) and answers with a value the panel can draw without a
// crash; none throws, none invents a value the run does not carry, and a closed code this page has no words for is shown
// as the code, never dropped. Pure: no component, no query.
//
// The model's name is not an input and not an output (G5): nothing below reads a key that could hold one, and the
// technical figures are the six the Owner approved. `facts[].model` is the value the model DECLARED for a field.
import type { AlertView } from "../../api/tier1";
import { formatTime } from "../../format";
import { S, labelOf, failureKindLabel, type HighlightWords } from "../../strings";
import type { MeterLevel } from "../analysis/ConfidenceMeter";
import type { Tone } from "../analysis/styles";
import { conclusionOf, type AiState } from "./aiState";

const P = S.ai1.panel;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** A string that says something; anything else is nothing. */
const text = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value : null;

/** A finite number, else null (a bool, a string and NaN are not a figure). */
const figure = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) ? value : null;

const wholeCount = (value: unknown): number | null =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : null;

/** A whole percentage from 0 to 100, else null. */
const pct = (value: unknown): number | null =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 100 ? value : null;

const list = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

/** The word of a code in a table, or the code itself when the table has none; never the prototype chain's. */
const wordOf = (table: object, code: string): string =>
  Object.hasOwn(table, code) ? String((table as Record<string, unknown>)[code]) : code;

/** At most three next checks and three candidates are served; a longer list is cut as the server cuts it. */
const SHOWN = 3;

// ── the shape of what the panel draws ────────────────────────────────────────────────────────────

export type HighlightRow = { direction: "up" | "down" | "warn"; text: string };
export type ReasonRow = {
  claim: string;
  quote: string | null;
  /** The product's words for the source, or the code of a source it has none for; null when the reason names none. */
  source: string | null;
  verified: boolean;
  /** Why the quote was not verified, in words (or the code); null when it was. */
  why: string | null;
};
export type CheckRow = { id: string; name: string; outcome: "pass" | "warn" | "na"; text: string };
export type FactRow = {
  field: string;
  system: string;
  declared: string | null;
  match: boolean | null;
};
export type CandidateRow = { pct: number; title: string | null; conclusion: string | null };
export type RagModel = {
  state: string;
  failure: string | null;
  best: number | null;
  floor: number | null;
  threshold: number;
  scored: number | null;
  candidates: CandidateRow[];
};
export type PlaybookModel = {
  name: string;
  ruleId: string | null;
  /** The words of the matched rule's action, or null when no rule matched. */
  action: string | null;
  reviewed: boolean | null;
};
export type TechModel = {
  inputTokens: number | null;
  outputTokens: number | null;
  latencyMs: number | null;
  costUsd: number | null;
  analysedAt: string | null;
  mitre: string[];
  correlated: number | null;
};
export type AnalysisModel = {
  summary: string | null;
  readingAttack: string | null;
  readingBenign: string | null;
  wouldChange: string | null;
  nextChecks: string[];
  highlights: HighlightRow[];
  reasons: ReasonRow[];
  evidence: { verified: number; total: number };
  facts: FactRow[];
  /** Whether the facts table has the model's column and the agreement: a run with no declared value has neither. */
  showDeclared: boolean;
  checks: CheckRow[];
  totals: { passed: number; applicable: number; warnings: number };
  rag: RagModel | null;
  history: { line: string } | null;
  playbook: PlaybookModel | null;
  tech: TechModel;
};

// ── the highlights ───────────────────────────────────────────────────────────────────────────────

/**
 * The sentence of a highlight: its code's words, from the params the server sent. A param that is missing or not a
 * number leaves a plainer sentence, and a code with no words is the code itself.
 */
export function highlightText(code: string, params: unknown): string {
  if (!Object.hasOwn(P.highlight, code)) return code;
  const bag = isRecord(params) ? params : {};
  const conclusion = text(bag.conclusion);
  const failure = text(bag.failure);
  const words: HighlightWords = {
    count: wholeCount(bag.count),
    total: wholeCount(bag.total),
    pct: pct(bag.pct),
    floor: pct(bag.floor_pct),
    conclusion: conclusion === null ? null : labelOf(S.analysis.knowledge.conclusion, conclusion),
    reason: failureKindLabel(failure),
  };
  const say = (P.highlight as Record<string, (w: HighlightWords) => string>)[code];
  return say === undefined ? code : say(words);
}

function highlightsOf(value: unknown): HighlightRow[] {
  return list(value).flatMap((row): HighlightRow[] => {
    if (!isRecord(row)) return [];
    const code = text(row.code);
    if (code === null) return [];
    const direction = row.direction === "up" || row.direction === "down" ? row.direction : "warn";
    return [{ direction, text: highlightText(code, row.params) }];
  });
}

// ── the reasons ──────────────────────────────────────────────────────────────────────────────────

function reasonsOf(value: unknown): ReasonRow[] {
  return list(value).flatMap((row): ReasonRow[] => {
    if (!isRecord(row)) return [];
    const source = text(row.source);
    const verified = row.verified === true;
    const why = text(row.why);
    return [
      {
        claim: text(row.claim) ?? S.common.missing,
        quote: text(row.quote),
        source: source === null ? null : wordOf(P.evidence.source, source),
        verified,
        why: verified || why === null ? null : wordOf(P.evidence.why, why),
      },
    ];
  });
}

// ── the facts ────────────────────────────────────────────────────────────────────────────────────

/** A fact's value in words: a dash for none, the product's word for a closed value that has one, else as it came. */
function factValue(field: string, value: unknown): string | null {
  if (value === null || value === undefined) return null;
  const raw = typeof value === "string" || typeof value === "number" ? String(value) : null;
  if (raw === null) return null;
  const table: unknown = Object.hasOwn(P.facts.value, field)
    ? (P.facts.value as Record<string, unknown>)[field]
    : undefined;
  return isRecord(table) ? wordOf(table, raw) : raw;
}

type RawFact = {
  field: string;
  system: string | null;
  declared: string | null;
  match: boolean | null;
};

function rawFactsOf(value: unknown): RawFact[] {
  return list(value).flatMap((row): RawFact[] => {
    if (!isRecord(row)) return [];
    const field = text(row.field);
    if (field === null) return [];
    return [
      {
        field,
        system: factValue(field, row.system),
        declared: factValue(field, row.model),
        match: typeof row.match === "boolean" ? row.match : null,
      },
    ];
  });
}

// ── the checks ───────────────────────────────────────────────────────────────────────────────────

const OUTCOMES = ["pass", "warn", "na"] as const;

function checksOf(
  value: unknown,
  facts: readonly RawFact[],
  evidence: { verified: number; total: number },
): CheckRow[] {
  return list(value).flatMap((row): CheckRow[] => {
    if (!isRecord(row)) return [];
    const id = text(row.id);
    const detail = text(row.detail);
    if (id === null || detail === null) return [];
    const outcome = (OUTCOMES as readonly unknown[]).includes(row.outcome)
      ? (row.outcome as CheckRow["outcome"])
      : "na";
    let words = wordOf(P.checks.detail, detail);
    // The closed word, with the figures the page already has: which fields step 2 flagged, how many quotes held.
    if (detail === "facts_mismatch") {
      const flagged = facts.filter(
        (fact) => fact.match === false && fact.system !== null && fact.declared !== null,
      );
      if (flagged.length > 0) {
        words = flagged
          .map((fact) =>
            P.checks.mismatch(
              wordOf(P.facts.field, fact.field),
              fact.declared ?? "",
              fact.system ?? "",
            ),
          )
          .join(P.checks.mismatchJoin);
      }
    } else if (
      (detail === "quotes_verified" || detail === "quotes_some_dropped") &&
      evidence.total > 0
    ) {
      words = P.checks.quotes(evidence.verified, evidence.total);
    }
    return [{ id, name: wordOf(P.checks.step, id), outcome, text: words }];
  });
}

/** `{passed, applicable, warnings}` as the server sent them, or counted from the rows when it sent none. */
function totalsOf(
  value: unknown,
  checks: readonly CheckRow[],
): { passed: number; applicable: number; warnings: number } {
  if (isRecord(value)) {
    const passed = wholeCount(value.passed);
    const applicable = wholeCount(value.applicable);
    const warnings = wholeCount(value.warnings);
    if (passed !== null && applicable !== null && warnings !== null) {
      return { passed: Math.min(passed, applicable), applicable, warnings };
    }
  }
  const passed = checks.filter((row) => row.outcome === "pass").length;
  const warnings = checks.filter((row) => row.outcome === "warn").length;
  return { passed, applicable: passed + warnings, warnings };
}

// ── the lookup, the history, the playbook, the figures ───────────────────────────────────────────

function ragOf(value: unknown): RagModel | null {
  if (!isRecord(value) || typeof value.state !== "string") return null;
  const candidates = list(value.candidates)
    .flatMap((row): CandidateRow[] => {
      if (!isRecord(row)) return [];
      const percentage = pct(row.pct);
      return percentage === null
        ? []
        : [{ pct: percentage, title: text(row.title), conclusion: text(row.conclusion) }];
    })
    .slice(0, SHOWN);
  const threshold = wholeCount(value.threshold_pct);
  return {
    state: value.state,
    failure: text(value.failure),
    best: pct(value.best_pct),
    floor: pct(value.floor_pct),
    threshold: threshold ?? 0,
    scored: wholeCount(value.scored),
    candidates,
  };
}

function historyOf(value: unknown): { line: string } | null {
  if (!isRecord(value)) return null;
  const total = wholeCount(value.total);
  if (total === null || total <= 0) return null;
  const counts = isRecord(value.by_conclusion) ? value.by_conclusion : {};
  const count = (name: string): number => wholeCount(counts[name]) ?? 0;
  const key = text(value.key);
  const scope =
    key !== null && Object.hasOwn(P.history.scope, key)
      ? wordOf(P.history.scope, key)
      : P.history.generic;
  let line = P.history.line(scope, total, count("confirmed_incident"));
  const rest = Object.keys(P.history.conclusion)
    .filter((name) => name !== "confirmed_incident" && count(name) > 0)
    .map((name) => `${count(name)} ${wordOf(P.history.conclusion, name)}`);
  if (rest.length > 0) line += P.history.rest(rest.join(", "));
  const lastSeen = text(value.last_seen);
  if (lastSeen !== null) line += P.history.lastSeen(formatTime(lastSeen));
  return { line };
}

function playbookOf(value: unknown): PlaybookModel | null {
  if (!isRecord(value)) return null;
  const name = text(value.name);
  if (name === null) return null;
  const action = text(value.rule_action);
  return {
    name,
    ruleId: text(value.rule_id),
    action: action === null ? null : wordOf(P.playbook.action, action),
    reviewed: typeof value.rule_table_reviewed === "boolean" ? value.rule_table_reviewed : null,
  };
}

function techOf(value: unknown): TechModel {
  const tech: Record<string, unknown> = isRecord(value) ? value : {};
  return {
    inputTokens: figure(tech.input_tokens),
    outputTokens: figure(tech.output_tokens),
    latencyMs: figure(tech.latency_ms),
    costUsd: figure(tech.cost_usd),
    analysedAt: text(tech.analysed_at),
    mitre: list(tech.mitre_ids).filter((id): id is string => typeof id === "string" && id !== ""),
    correlated: wholeCount(tech.correlated_at_analysis),
  };
}

// ── the object ───────────────────────────────────────────────────────────────────────────────────

/** The view's `analysis` as the panel reads it, or null when the view carries none (or one that is not an object). */
export function analysisOf(view: AlertView): AnalysisModel | null {
  const raw: unknown = view.analysis;
  if (!isRecord(raw)) return null;
  const reasons = reasonsOf(raw.reasons);
  const evidence = { verified: reasons.filter((r) => r.verified).length, total: reasons.length };
  const facts = rawFactsOf(raw.facts);
  const checks = checksOf(raw.checks, facts, evidence);
  return {
    summary: text(raw.summary),
    readingAttack: text(raw.reading_attack),
    readingBenign: text(raw.reading_benign),
    wouldChange: text(raw.would_change),
    nextChecks: list(raw.next_checks)
      .flatMap((item) => (text(item) === null ? [] : [item as string]))
      .slice(0, SHOWN),
    highlights: highlightsOf(raw.highlights),
    reasons,
    evidence,
    facts: facts.map((fact) => ({
      field: wordOf(P.facts.field, fact.field),
      system: fact.system ?? S.common.missing,
      declared: fact.declared,
      match: fact.match,
    })),
    showDeclared: facts.some((fact) => fact.declared !== null),
    checks,
    totals: totalsOf(raw.check_totals, checks),
    rag: ragOf(raw.rag),
    history: historyOf(raw.history),
    playbook: playbookOf(raw.playbook),
    tech: techOf(raw.tech),
  };
}

// ── the four tiles ───────────────────────────────────────────────────────────────────────────────

type Concluded = Extract<AiState, { kind: "ready" | "decided" }>;

export type VerdictTile = { label: string; tone: Tone; note: string | null; forced: boolean };

/**
 * The Kết luận tile: the verdict ① ended with (`conclusionOf`: the action when it is one of the model's two, else the
 * model's own answer for a `needs_review` stored before DEC-217), TP in the high-severity orange and FP in the calm blue.
 * For a run the RAG default applied to (DEC-219) the line under it is the existing "(dưới 80%: mặc định FP)", the
 * same whatever the model had answered. A verdict this page has no scale for is shown as it came, neutral, with no
 * line. The flag is the gate's own (a version 1 row, before DEC-217): a new run never carries it.
 */
export function verdictTile(state: Concluded): VerdictTile {
  const forced = state.kind === "ready" && state.forced;
  const conclusion = conclusionOf(state);
  if (conclusion === null) {
    return { label: labelOf(S.ai1.action, state.action), tone: "neutral", note: null, forced };
  }
  const note =
    state.ragDefaultBelow !== undefined
      ? S.ai1.ragDefault(state.ragDefaultBelow)
      : wordOf(P.tile.verdictNote, conclusion);
  return {
    label: labelOf(S.ai1.action, conclusion),
    tone:
      conclusion === "true_positive" ? "high" : conclusion === "false_positive" ? "low" : "neutral",
    note:
      Object.hasOwn(P.tile.verdictNote, conclusion) || state.ragDefaultBelow !== undefined
        ? note
        : null,
    forced,
  };
}

export type ConfidenceTile =
  | { kind: "level"; level: MeterLevel; word: string }
  | { kind: "word"; word: string }
  | { kind: "none"; word: string; note: string };

/**
 * The Độ tin cậy tile: the word and the meter for low, medium or high; the word alone for a level the page has no scale
 * for; a dash for none. A verdict the RAG default decided (DEC-219) has no confidence of its own to show (it is the
 * model's, in its own answer), and the tile says it does not apply.
 */
export function confidenceTile(state: Concluded): ConfidenceTile {
  if (state.ragDefaultBelow !== undefined) {
    return { kind: "none", word: S.common.missing, note: P.tile.confidenceNone };
  }
  const level = state.confidence;
  if (level === "low" || level === "medium" || level === "high") {
    return { kind: "level", level, word: S.analysis.level[level] };
  }
  return { kind: "word", word: level !== null && level !== "" ? level : S.common.missing };
}

export type RagTile = { value: string; note: string };

/**
 * The Tri thức (RAG) tile: the number for a lookup that kept a match and for one whose candidates all scored under the
 * floor, and a dash with a short line for the other three states and for each failure kind: the words of the Tier 2
 * tile (`S.analysis.ragNote`).
 */
export function ragTile(rag: RagModel | null): RagTile {
  const N = S.analysis.ragNote;
  const noData: RagTile = { value: S.common.missing, note: N.noData };
  if (rag === null) return noData;
  switch (rag.state) {
    case "matched":
      return rag.best === null ? noData : { value: `${rag.best}%`, note: N.matched };
    case "below_floor":
      return rag.best === null ? noData : { value: `${rag.best}%`, note: N.belowFloor(rag.floor) };
    case "no_candidate":
      return { value: S.common.missing, note: N.noCandidate };
    case "no_lookup":
      return { value: S.common.missing, note: N.noLookup };
    case "failed":
      return {
        value: S.common.missing,
        note:
          rag.failure !== null && Object.hasOwn(N.failedKind, rag.failure)
            ? (N.failedKind as Record<string, string>)[rag.failure]!
            : N.failed,
      };
    default:
      return noData;
  }
}

export type ChecksTile = { value: string; note: string; warn: boolean };

/** The Kiểm chứng tile: checks passed over the checks that apply, and the warnings in the warning colour. */
export function checksTile(model: AnalysisModel): ChecksTile {
  const { passed, applicable, warnings } = model.totals;
  if (applicable === 0) {
    return { value: S.common.missing, note: P.tile.checksNote.none, warn: false };
  }
  return {
    value: `${passed}/${applicable}`,
    note: warnings > 0 ? P.tile.checksNote.warnings(warnings) : P.tile.checksNote.clean,
    warn: warnings > 0,
  };
}
