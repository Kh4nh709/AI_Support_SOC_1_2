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
import { knowledgeFrom, type Knowledge } from "../analysis/knowledge";
import type { Tone } from "../analysis/styles";
import { conclusionOf, heldByOf, type AiState } from "./aiState";

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
export type CheckRow = {
  id: string;
  name: string;
  outcome: "pass" | "warn" | "na";
  text: string;
  /** The closed `detail` code the line was worded from: what decides whether the line already says a held reason. */
  detail: string;
  /** The held reasons and gate warnings of this step, in words: what the line above them cannot say. */
  notes: string[];
};
/**
 * The gate's own account of the run, read from the keys of the view beside `analysis` (spec G2: which checks warned, and
 * why): `held` is every held reason in words (the Kiểm chứng tab says each one, under its step's line or in a note),
 * `overview` the ones the overview's line still names (not those a drawn warning highlight already says), `loose` the
 * ones no step row of the page carries, `extra` how many held reasons no drawn warning row accounts for (the tile counts
 * them beside the server's figure), and `forced` the verdict before and after the gate for a run the gate forced (a
 * version 1 row).
 */
export type GateNotes = {
  held: string[];
  overview: string[];
  loose: string[];
  extra: number;
  forced: { proposed: string | null; final: string | null } | null;
};
export type FactRow = {
  field: string;
  system: string;
  declared: string | null;
  match: boolean | null;
};
/** The lookup of the run, in the shape both tiers read (`analysis/knowledge.ts`). Nothing of the RAG rule: DEC-225. */
export type RagModel = Knowledge;
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
  gate: GateNotes;
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
export function highlightText(code: string, params: unknown, scope: string | null = null): string {
  if (!Object.hasOwn(P.highlight, code)) return code;
  const bag = isRecord(params) ? params : {};
  const conclusion = text(bag.conclusion);
  const failure = text(bag.failure);
  const words: HighlightWords = {
    count: wholeCount(bag.count),
    total: wholeCount(bag.total),
    pct: pct(bag.pct),
    floor: pct(bag.floor_pct),
    scope,
    conclusion: conclusion === null ? null : labelOf(S.analysis.knowledge.conclusion, conclusion),
    reason: failureKindLabel(failure),
  };
  const say = (P.highlight as Record<string, (w: HighlightWords) => string>)[code];
  return say === undefined ? code : say(words);
}

/**
 * The scope of the decision history as the middle of a sentence: the words of the Tri thức tab's line for the history's
 * key ("Cùng kịch bản và cùng máy" is "cùng kịch bản và cùng máy"), or null when the run has no history or names a key
 * this page has no words for (the highlight then says "tương tự", and the history line shows the key as it came).
 */
function scopeOf(history: unknown): string | null {
  const key = isRecord(history) ? text(history.key) : null;
  if (key === null || !Object.hasOwn(P.history.scope, key)) return null;
  const words = wordOf(P.history.scope, key);
  return words.charAt(0).toLowerCase() + words.slice(1);
}

function highlightsOf(value: unknown, scope: string | null): HighlightRow[] {
  return list(value).flatMap((row): HighlightRow[] => {
    if (!isRecord(row)) return [];
    const code = text(row.code);
    if (code === null) return [];
    const direction = row.direction === "up" || row.direction === "down" ? row.direction : "warn";
    return [{ direction, text: highlightText(code, row.params, scope) }];
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
    return [{ id, name: wordOf(P.checks.step, id), outcome, text: words, detail, notes: [] }];
  });
}

// ── the gate's own account ───────────────────────────────────────────────────────────────────────

/** The gate step each closed held reason belongs to (`llm.verdicts.held_reasons`); null for a code that names none. */
function stepOfHeld(code: string): string | null {
  if (code === "facts_mismatch") return "2";
  if (code === "no_verified_quote") return "3";
  if (code.startsWith("fp_policy:")) return "4";
  if (code === "verifier_disagrees" || code === "verifier_invalid") return "6";
  return null;
}

/** The verifier's verdict in the product's verdict labels ("FP", "TP", "Cần xem xét"), or null when it gave none. */
function verifierWords(gate: Record<string, unknown>): string | null {
  const verdict = text(gate.verifier_verdict);
  return verdict === null ? null : labelOf(S.ai1.action, verdict);
}

/**
 * The step line that says a held reason in its own words: the step and the closed `detail` of its row. A reason whose
 * line says it draws no note under the line (the note would repeat it in vaguer words); a reason whose line says
 * something else, or no line at all, is named.
 */
const SAID_BY_LINE: Record<string, { step: string; detail: string }> = {
  facts_mismatch: { step: "2", detail: "facts_mismatch" },
  no_verified_quote: { step: "3", detail: "no_verified_quote" },
  "fp_policy:playbook_rule": { step: "4", detail: "fp_policy_playbook" },
  verifier_disagrees: { step: "6", detail: "verifier_disagrees" },
  verifier_invalid: { step: "6", detail: "verifier_invalid" },
};

/**
 * The warning highlight that says a held reason too, in the same words or vaguer ones. The overview's line leaves a
 * reason out when this highlight is drawn, and names it when it is not (the server serves at most four highlights, and
 * the cap can cut it). The reasons about a fact of the alert have none: the one highlight of step 4 does not say which
 * fact, and the reason does.
 */
const COVERED_BY_HIGHLIGHT: Record<string, string> = {
  facts_mismatch: "warning_facts_mismatch",
  no_verified_quote: "warning_no_verified_quote",
  "fp_policy:playbook_rule": "warning_fp_policy_playbook",
  verifier_disagrees: "warning_verifier_disagrees",
  verifier_invalid: "warning_verifier_invalid",
};

/** The codes of the highlights the overview draws: every row that has a code, as `highlightsOf` reads them. */
function drawnHighlightCodes(value: unknown): Set<string> {
  return new Set(
    list(value).flatMap((row) => {
      const code = isRecord(row) ? text(row.code) : null;
      return code === null ? [] : [code];
    }),
  );
}

/**
 * What the view says of the gate beside `analysis` and the panel must not leave unread (spec G2): the held reasons
 * (`held_by`) and the reasons the step-4 rule check wrote (`gate.warnings`), each on the row of the step it belongs to,
 * in the words of the flat column, unless the line of that step already says it; the verifier's verdict beside step 6;
 * the verdict before and after the gate of a run the gate forced. For a run the RAG rule decided (DEC-219, DEC-225) the
 * server serves a gate and a `held_by` with nothing that would tell what the model answered (no verifier verdict, no
 * `verifier_disagrees`, none of the warnings of the rule it cited), and the page reads them as they are: it does not
 * know that a rule exists. A reason whose step has no row, and a code that names no step, is
 * listed apart and never dropped, and the tile counts it (`extra`).
 */
function withGate(
  view: AlertView,
  checks: CheckRow[],
  drawn: ReadonlySet<string>,
): { checks: CheckRow[]; gate: GateNotes } {
  const suggestion: unknown = view.suggestion;
  const gateRaw: unknown = isRecord(suggestion) ? suggestion.gate : null;
  const gate: Record<string, unknown> = isRecord(gateRaw) ? gateRaw : {};

  const heldCodes = [...new Set(heldByOf(view))];
  const held = heldCodes.map((code) => labelOf(S.ai1.heldReason, code));
  const warnings = list(gate.warnings).map((w) =>
    typeof w === "string" ? wordOf(P.checks.ruleWarning, w) : JSON.stringify(w),
  );

  const rows = new Map(checks.map((row) => [row.id, row]));
  const loose: string[] = [];
  let extra = 0;
  /** Puts words under the row of a step (unless its line says them), or in the loose list; counts what no warning accounts for. */
  const place = (step: string | null, words: string, said: boolean): void => {
    const row = step === null ? undefined : rows.get(step);
    if (row === undefined) {
      loose.push(words);
      extra += 1;
      return;
    }
    if (!said) row.notes.push(words);
    if (row.outcome !== "warn") extra += 1;
  };
  heldCodes.forEach((code, index) => {
    const line = Object.hasOwn(SAID_BY_LINE, code) ? SAID_BY_LINE[code] : undefined;
    const said = line !== undefined && rows.get(line.step)?.detail === line.detail;
    place(stepOfHeld(code), held[index] ?? code, said);
  });
  for (const words of warnings) place("4", words, false);

  // The verifier's own verdict, beside the outcome of step 6 (the server serves none for a run the RAG rule decided).
  const verifier = verifierWords(gate);
  const verifierRow = rows.get("6");
  if (verifier !== null && verifierRow !== undefined) {
    verifierRow.text += P.checks.verifierSaid(verifier);
  }

  const pair = (value: unknown): string | null => {
    const verdict = text(value);
    return verdict === null ? null : labelOf(S.ai1.action, verdict);
  };
  const overview = heldCodes.flatMap((code, index) => {
    const cover = Object.hasOwn(COVERED_BY_HIGHLIGHT, code)
      ? COVERED_BY_HIGHLIGHT[code]
      : undefined;
    return cover !== undefined && drawn.has(cover) ? [] : [held[index] ?? code];
  });
  return {
    checks,
    gate: {
      held,
      overview,
      loose,
      extra,
      forced:
        gate.forced === true
          ? { proposed: pair(gate.proposed_verdict), final: pair(gate.final_verdict) }
          : null,
    },
  };
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

/** The lookup, read by the reader both tiers share. */
function ragOf(value: unknown): RagModel | null {
  return knowledgeFrom(value);
}

function historyOf(value: unknown): { line: string } | null {
  if (!isRecord(value)) return null;
  const total = wholeCount(value.total);
  if (total === null || total <= 0) return null;
  const counts = isRecord(value.by_conclusion) ? value.by_conclusion : {};
  const count = (name: string): number => wholeCount(counts[name]) ?? 0;
  // A key this page has no words for is shown as it came; a history with no key is "Alert tương tự".
  const key = text(value.key);
  const scope = key === null ? P.history.generic : wordOf(P.history.scope, key);
  let line = P.history.line(scope, total, count("confirmed_incident"));
  const rest = Object.keys(P.history.conclusion)
    .filter((name) => name !== "confirmed_incident" && count(name) > 0)
    .map((name) => `${count(name)} ${wordOf(P.history.conclusion, name)}`);
  if (rest.length > 0) line += P.history.rest(rest);
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
  const rag = ragOf(raw.rag);
  const { checks, gate } = withGate(
    view,
    checksOf(raw.checks, facts, evidence),
    drawnHighlightCodes(raw.highlights),
  );
  return {
    summary: text(raw.summary),
    readingAttack: text(raw.reading_attack),
    readingBenign: text(raw.reading_benign),
    wouldChange: text(raw.would_change),
    nextChecks: list(raw.next_checks)
      .flatMap((item) => (text(item) === null ? [] : [item as string]))
      .slice(0, SHOWN),
    highlights: highlightsOf(raw.highlights, scopeOf(raw.history)),
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
    gate,
    totals: totalsOf(raw.check_totals, checks),
    rag,
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
 * model's own answer for a `needs_review` stored before DEC-217), TP in the high-severity orange and FP in the calm blue,
 * with the words of the verdict under it ("tấn công thật", "dương tính giả"). A verdict this page has no scale for is
 * shown as it came, neutral, with no line. The flag is the gate's own (a version 1 row, before DEC-217): a new run
 * never carries it. A run the RAG rule decided (DEC-219, DEC-225) reads like any other: the page is not told.
 */
export function verdictTile(state: Concluded): VerdictTile {
  const forced = state.kind === "ready" && state.forced;
  const conclusion = conclusionOf(state);
  if (conclusion === null) {
    return { label: labelOf(S.ai1.action, state.action), tone: "neutral", note: null, forced };
  }
  return {
    label: labelOf(S.ai1.action, conclusion),
    tone:
      conclusion === "true_positive" ? "high" : conclusion === "false_positive" ? "low" : "neutral",
    note: Object.hasOwn(P.tile.verdictNote, conclusion)
      ? wordOf(P.tile.verdictNote, conclusion)
      : null,
    forced,
  };
}

export type ConfidenceTile =
  { kind: "level"; level: MeterLevel; word: string } | { kind: "word"; word: string };

/**
 * The Độ tin cậy tile: the word and the meter for low, medium or high; the word alone for a level the page has no scale
 * for; a dash for none (the server serves no confidence for a run the RAG rule decided, and the page does not say why).
 */
export function confidenceTile(state: Concluded): ConfidenceTile {
  const level = state.confidence;
  if (level === "low" || level === "medium" || level === "high") {
    return { kind: "level", level, word: S.analysis.level[level] };
  }
  return { kind: "word", word: level !== null && level !== "" ? level : S.common.missing };
}

// The Tri thức (RAG) tile is `analysis/knowledge.ts`'s `ragTile`, the one both tiers say it with.

export type ChecksTile = { value: string; note: string; warn: boolean };

/** The Kiểm chứng tile: checks passed over the checks that apply, and the warnings in the warning colour. */
export function checksTile(model: AnalysisModel): ChecksTile {
  const { passed, applicable } = model.totals;
  // The figure is the server's. The note adds the held reasons no drawn row accounts for, so that it cannot say "no
  // warning" while the page lists one.
  const warnings = model.totals.warnings + model.gate.extra;
  if (applicable === 0 && warnings === 0) {
    return { value: S.common.missing, note: P.tile.checksNote.none, warn: false };
  }
  return {
    value: applicable === 0 ? S.common.missing : `${passed}/${applicable}`,
    note: warnings > 0 ? P.tile.checksNote.warnings(warnings) : P.tile.checksNote.clean,
    warn: warnings > 0,
  };
}
