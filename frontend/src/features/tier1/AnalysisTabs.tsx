// The five tabs of the Tier 1 panel (DEC-221): what each one draws of a run. Everything the model or a person wrote is
// rendered as text, never as markup. A key a run does not carry (an older run, an older server) is read through
// `analysisModel.ts` and leaves its part out, with no empty heading, or says plainly that it is not there; nothing here
// throws on a missing key. There is no model among the technical rows and no model name anywhere (G5).
import { useId, type ReactNode } from "react";
import { S } from "../../strings";
import { formatDateTime } from "../../format";
import { Card, FactRows, IconLine } from "../analysis/Cards";
import { EvidenceBlock } from "../analysis/EvidenceBlock";
import { formatCost, formatCount, formatSeconds } from "../analysis/figures";
import { KnowledgeCandidates } from "../analysis/KnowledgeCandidates";
import { CAPTION, CARD } from "../analysis/styles";
import type { SuggestionGate } from "../../api/tier1";
import { GateLine } from "./FlatAiColumn";
import type { AnalysisModel, RagModel } from "./analysisModel";

const P = S.ai1.panel;
const SEPARATOR = S.analysis.separator;

/**
 * A name or an id the server sends has no space to break at: it wraps anywhere inside the column. `break-words` does not
 * reach the cells of an auto-layout table (it keeps their minimum width at the word's), `anywhere` does.
 */
const WRAP = "[overflow-wrap:anywhere]";
const CODE = `font-mono text-xs ${WRAP}`;

// ── Tổng quan ────────────────────────────────────────────────────────────────────────────────────

/** One of the two readings: the attack's in the orange of a high severity, the benign one's in the calm blue. */
function Reading({
  title,
  tone,
  children,
}: {
  title: string;
  tone: "high" | "low";
  children: string;
}) {
  const id = useId();
  return (
    <section
      aria-labelledby={id}
      className="flex flex-col gap-1.5 rounded-lg border border-border p-3"
    >
      <h3
        id={id}
        className={`text-xs font-semibold tracking-[0.06em] uppercase ${tone === "high" ? "text-high" : "text-low"}`}
      >
        {title}
      </h3>
      <p className="text-[13px] leading-[19px] break-words whitespace-pre-wrap">{children}</p>
    </section>
  );
}

export function OverviewTab({ model }: { model: AnalysisModel }) {
  const T = P.overview;
  const { summary, readingAttack, readingBenign, wouldChange, nextChecks, highlights } = model;
  const held = model.gate.held;
  const empty =
    summary === null &&
    highlights.length === 0 &&
    held.length === 0 &&
    readingAttack === null &&
    readingBenign === null &&
    wouldChange === null &&
    nextChecks.length === 0;
  if (empty) return <p className="text-sm text-muted">{T.none}</p>;
  const readings = [
    readingAttack === null ? null : (
      <Reading key="attack" title={T.attack} tone="high">
        {readingAttack}
      </Reading>
    ),
    readingBenign === null ? null : (
      <Reading key="benign" title={T.benign} tone="low">
        {readingBenign}
      </Reading>
    ),
  ].filter((node) => node !== null);
  return (
    <div className="flex flex-col gap-3.5">
      {summary !== null && (
        <p className="text-[15px] leading-[22px] break-words whitespace-pre-wrap">{summary}</p>
      )}

      {(highlights.length > 0 || held.length > 0) && (
        <Card title={T.highlights}>
          {highlights.map((row, index) => (
            <IconLine key={index} kind={row.direction}>
              {row.text}
            </IconLine>
          ))}
          {/* Every check that raised a warning, in words: the reputation of an IOC has no highlight of its own. */}
          {held.length > 0 && <IconLine kind="warn">{T.held(held)}</IconLine>}
        </Card>
      )}

      {readings.length > 0 && (
        <div
          className={`grid gap-2.5 ${readings.length > 1 ? "grid-cols-1 sm:grid-cols-2" : "grid-cols-1"}`}
        >
          {readings}
        </div>
      )}

      {wouldChange !== null && (
        <p className="text-[13px] leading-[19px] break-words whitespace-pre-wrap">
          <span className="text-muted">{T.wouldChange}</span> {wouldChange}
        </p>
      )}

      {nextChecks.length > 0 && (
        <Card title={T.nextChecks}>
          <ol className="flex list-decimal flex-col gap-1 pl-5 text-[13px] leading-[19px]">
            {nextChecks.map((item, index) => (
              <li key={index} className="break-words whitespace-pre-wrap">
                {item}
              </li>
            ))}
          </ol>
        </Card>
      )}
    </div>
  );
}

// ── Bằng chứng ───────────────────────────────────────────────────────────────────────────────────

export function EvidenceTab({ model }: { model: AnalysisModel }) {
  const T = P.evidence;
  const { reasons, evidence } = model;
  if (reasons.length === 0) return <p className="text-sm">{T.none}</p>;
  return (
    <div className="flex flex-col gap-2.5">
      <p className="text-[13px] text-muted">{T.summary(evidence.verified, evidence.total)}</p>
      <ul aria-label={P.tabs.evidence} className="flex flex-col gap-2.5">
        {reasons.map((reason, index) => {
          // Where the quote is from, then what became of it: "Log gốc của alert · khớp nguyên văn".
          const unverified =
            reason.source === null
              ? S.analysis.evidence.unverified
              : S.analysis.evidence.unverifiedInline;
          const outcome = reason.verified ? T.matched : (reason.why ?? unverified);
          return (
            <li key={index}>
              <EvidenceBlock
                claim={reason.claim}
                quote={reason.quote}
                verified={reason.verified}
                source={reason.source === null ? outcome : `${reason.source}${SEPARATOR}${outcome}`}
              />
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// ── Tri thức ─────────────────────────────────────────────────────────────────────────────────────

/** The one sentence that says what the lookup came to, in the words of its state. */
function stateSentence(rag: RagModel): string {
  const S2 = P.knowledge.state;
  switch (rag.state) {
    case "matched":
      return S2.matched(rag.best_pct, rag.floor_pct);
    case "below_floor":
      return S2.below_floor(rag.floor_pct);
    case "no_candidate":
      return S2.no_candidate();
    case "no_lookup":
      return S2.no_lookup();
    case "failed":
      return S2.failed(failureWords(rag.failure));
    default:
      // a state this page has no words for is shown as it came
      return rag.state;
  }
}

const failureWords = (kind: string | null): string | null =>
  kind !== null && Object.hasOwn(S.rag.failureKind, kind)
    ? (S.rag.failureKind as Record<string, string>)[kind]!
    : null;

/** Whether the rule of DEC-219 applied to this run, and so what the card says of it (it never says what the model answered). */
function ruleSentence(threshold: number, applied: boolean): string {
  const R = P.knowledge.rule;
  if (applied) return R.applied(threshold);
  return threshold > 0 ? R.notApplied(threshold) : R.off;
}

export function KnowledgeTab({
  model,
  ruleApplied,
}: {
  model: AnalysisModel;
  /** The threshold of the rule of DEC-219 when the run's verdict is that rule's default, else undefined. */
  ruleApplied: number | undefined;
}) {
  const { rag, history, playbook } = model;
  return (
    <div className="flex flex-col gap-3">
      <Card
        title={S.analysis.knowledge.heading}
        variant="title"
        aside={
          rag !== null && rag.scored !== null && rag.scored > 0
            ? S.analysis.knowledge.scored(rag.scored)
            : undefined
        }
      >
        {rag !== null && rag.candidates.length > 0 && <KnowledgeCandidates rows={rag.candidates} />}
        <p className="text-[13px] leading-[19px]">
          {rag === null
            ? S.analysis.ragNote.noData
            : `${stateSentence(rag)} ${ruleSentence(ruleApplied ?? rag.threshold, ruleApplied !== undefined)}`}
        </p>
      </Card>

      <Card title={P.history.heading} variant="title">
        <p className="text-[13px]">{history === null ? P.history.none : history.line}</p>
      </Card>

      <Card title={P.playbook.heading} variant="title">
        {playbook === null ? (
          <p className="text-[13px] leading-[19px]">{P.playbook.none}</p>
        ) : (
          <>
            <p className="text-[13px] leading-[19px]">
              {P.playbook.playbook} <code className={CODE}>{playbook.name}</code>
              {". "}
              {playbook.ruleId === null ? (
                P.playbook.ruleNone
              ) : (
                <>
                  {P.playbook.ruleHead} <code className={CODE}>{playbook.ruleId}</code>{" "}
                  {P.playbook.ruleMatches(playbook.action ?? S.common.missing)}
                </>
              )}
            </p>
            {playbook.reviewed === false && (
              <p className="text-xs text-medium">{P.playbook.unsigned}</p>
            )}
          </>
        )}
      </Card>
    </div>
  );
}

// ── Kiểm chứng ───────────────────────────────────────────────────────────────────────────────────

/** The facts the system recorded beside what the model declared. A run with no declared value has the system's column only. */
function FactsTable({ model }: { model: AnalysisModel }) {
  const C = P.facts.column;
  const { facts, showDeclared } = model;
  if (facts.length === 0) return null;
  const head = `${CAPTION} text-left font-normal`;
  return (
    <div className={CARD}>
      <table
        aria-label={P.facts.label}
        className="w-full border-separate border-spacing-y-2 text-[13px]"
      >
        <thead>
          <tr>
            <th scope="col" className={head}>
              {C.fact}
            </th>
            <th scope="col" className={head}>
              {C.system}
            </th>
            {showDeclared && (
              <>
                <th scope="col" className={head}>
                  {C.declared}
                </th>
                <th scope="col" className={head}>
                  {C.match}
                </th>
              </>
            )}
          </tr>
        </thead>
        <tbody>
          {facts.map((fact, index) => (
            <tr key={index}>
              <th scope="row" className={`pr-3 text-left font-normal break-words ${WRAP}`}>
                {fact.field}
              </th>
              <td className={`pr-3 font-mono break-words ${WRAP}`}>{fact.system}</td>
              {showDeclared && (
                <>
                  <td
                    className={`pr-3 font-mono break-words ${WRAP} ${fact.match === false ? "text-medium" : ""}`}
                  >
                    {fact.declared ?? S.common.missing}
                  </td>
                  <td className={WRAP}>
                    {fact.match === null ? (
                      <span className="text-muted">{S.common.missing}</span>
                    ) : (
                      <span
                        data-tone={fact.match ? "ok" : "warn"}
                        className={fact.match ? "text-ok" : "text-medium"}
                      >
                        {fact.match ? P.facts.match.yes : P.facts.match.no}
                      </span>
                    )}
                  </td>
                </>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * One line per gate step with the reasons the gate held for it under the line (spec G2), the reasons that stand under no
 * step, and, for a run the gate forced (a version 1 row, before DEC-217), the gate's line with the verdict before and
 * after it. Then the facts the system recorded beside what the model declared.
 */
export function ChecksTab({ model, gate }: { model: AnalysisModel; gate: SuggestionGate | null }) {
  const { checks } = model;
  const { forced, loose } = model.gate;
  return (
    <div className="flex flex-col gap-3">
      {checks.length === 0 ? (
        <p className="text-sm text-muted">{P.tile.checksNote.none}</p>
      ) : (
        <ul aria-label={P.checks.listLabel} className={`${CARD} flex flex-col gap-2`}>
          {checks.map((row, index) => (
            <li key={index} className="flex flex-col gap-1">
              <IconLine kind={row.outcome}>
                <span className="font-medium">{row.name}</span>{" "}
                <span className={row.outcome === "warn" ? "text-medium" : "text-muted"}>
                  {`${P.checks.dash} ${row.text}`}
                </span>
              </IconLine>
              {row.notes.length > 0 && (
                <ul className="ml-6 flex list-disc flex-col gap-0.5 pl-4 text-xs break-words text-medium">
                  {row.notes.map((note, at) => (
                    <li key={at}>{note}</li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
      )}
      {loose.length > 0 && (
        <Card title={P.checks.loose} variant="title">
          <ul className="flex list-disc flex-col gap-0.5 pl-5 text-[13px] break-words text-medium">
            {loose.map((words, index) => (
              <li key={index}>{words}</li>
            ))}
          </ul>
        </Card>
      )}
      {forced !== null && gate !== null && (
        <div role="group" aria-label={S.ai1.gate} className={`${CARD} flex flex-col gap-2`}>
          <GateLine gate={gate} forced />
          <dl className="flex flex-col gap-1 text-sm">
            {(
              [
                [S.ai1.gateProposed, forced.proposed],
                [S.ai1.gateFinal, forced.final],
              ] as const
            ).map(([label, verdict]) =>
              verdict === null ? null : (
                <div key={label} className="flex flex-wrap gap-x-2">
                  <dt className="text-muted">{label}</dt>
                  <dd>{verdict}</dd>
                </div>
              ),
            )}
          </dl>
        </div>
      )}
      <FactsTable model={model} />
    </div>
  );
}

// ── Kỹ thuật ─────────────────────────────────────────────────────────────────────────────────────

/** Tokens, time, cost, when, the alert's MITRE ids and the clusters at the analysis. No model: none is read from anywhere (G5). */
export function TechTab({ model }: { model: AnalysisModel }) {
  const { tech } = model;
  const tokens: ReactNode =
    tech.inputTokens === null && tech.outputTokens === null
      ? S.common.missing
      : S.analysis.tech.tokenLine(formatCount(tech.inputTokens), formatCount(tech.outputTokens));
  return (
    <FactRows
      rows={[
        { label: S.analysis.tech.tokens, value: tokens },
        { label: S.analysis.tech.time, value: formatSeconds(tech.latencyMs) },
        { label: S.analysis.tech.cost, value: formatCost(tech.costUsd) },
        { label: S.analysis.tech.analysedAt, value: formatDateTime(tech.analysedAt) },
        {
          label: P.tech.mitre,
          value: tech.mitre.length > 0 ? tech.mitre.join(", ") : S.common.missing,
        },
        { label: P.tech.correlated, value: tech.correlated ?? S.common.missing },
      ]}
    />
  );
}
