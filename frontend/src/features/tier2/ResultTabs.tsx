// The five tabs of the Tier 2 panel (DEC-221): what each one draws of a run. Everything the model or a person wrote is
// rendered as text, never as markup. A key a run does not carry (an older run, an older server) is read through
// `runModel.ts` and leaves its part out or says plainly that it is not there; nothing here throws on a missing key.
import { Link } from "react-router";
import type { RunView, Snapshot } from "../../api/tier2";
import { formatClock, formatDateTime, formatTime } from "../../format";
import { S, failureKindLabel, labelOf } from "../../strings";
import { Card, FactRows, Figures, IconLine } from "../analysis/Cards";
import { EvidenceBlock } from "../analysis/EvidenceBlock";
import { formatCost, formatCount, formatSeconds } from "../analysis/figures";
import { KnowledgeCandidates } from "../analysis/KnowledgeCandidates";
import { CARD, FOCUS } from "../analysis/styles";
import { useId } from "react";
import { asText } from "./parts";
import {
  evidenceCounts,
  heldOf,
  hypothesesOf,
  knowledgeOf,
  mitreSteps,
  nextStepsOf,
  overruledShown,
  scopeOf,
  techOf,
  timelineOf,
  type Knowledge,
  type ScopeSide,
} from "./runModel";

/** The link to an alert the case page draws for each of its heads. */
function AlertLink({ id }: { id: string }) {
  return (
    <Link
      to={`/alerts/${encodeURIComponent(id)}`}
      className={`text-ai-accent underline-offset-2 hover:underline ${FOCUS}`}
    >
      {id}
    </Link>
  );
}

const nonEmpty = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value : null;

// ── Tổng quan ────────────────────────────────────────────────────────────────────────────────────

const PRIORITY_TONE = { high: "critical", medium: "medium", low: "muted" } as const;
const PRIORITY_INK = { high: "text-critical", medium: "text-medium", low: "text-muted" } as const;

function scopeItem(label: string, side: ScopeSide) {
  const T = S.ai2.overview.scope;
  return {
    label,
    value: side.model.length > 0 ? T.model(side.model.join(", ")) : T.modelNone,
    note: side.system.length > 0 ? T.system(side.system.join(", ")) : T.systemNone,
  };
}

export function OverviewTab({ run }: { run: RunView }) {
  const T = S.ai2.overview;
  const scope = scopeOf(run);
  const steps = mitreSteps(timelineOf(run));
  const nextSteps = nextStepsOf(run);
  const anyPriority = nextSteps.some((row) => row.priority !== null);

  // What to look at twice: the conclusion the system held or lowered, and the quotes that were not found.
  const { modelConclusion, causes, held } = heldOf(run);
  const attention: string[] = [];
  if (held && modelConclusion !== null) {
    attention.push(
      `${S.ai2.conclusion}: ${labelOf(S.ai2.suggestedConclusion, modelConclusion)} ${S.ai2.heldLine(
        causes.map((cause) => labelOf(S.ai2.heldReason, cause)),
      )}`,
    );
  }
  const overruled = overruledShown(run);
  if (overruled !== null) attention.push(overruled);
  const { cited, verified } = evidenceCounts(run);
  if (verified < cited) attention.push(T.unverified(cited - verified, cited));

  return (
    <div className="flex flex-col gap-3.5">
      <p className="text-[15px] leading-[22px] break-words whitespace-pre-wrap">
        {asText(run.summary)}
      </p>

      <Figures
        label={T.scope.label}
        items={[
          scopeItem(T.scope.hosts, scope.hosts),
          scopeItem(T.scope.accounts, scope.accounts),
          {
            label: T.scope.tactics,
            value: steps.count > 0 ? T.scope.steps(steps.count) : S.common.missing,
            note:
              steps.count === 0
                ? T.scope.noSteps
                : steps.endsAt !== null
                  ? T.scope.endsAt(steps.endsAt)
                  : undefined,
          },
        ]}
      />

      {nextSteps.length > 0 && (
        <Card title={T.nextSteps}>
          <ul
            className={`flex flex-col gap-1.5 text-[13px] leading-[19px] ${anyPriority ? "" : "list-disc pl-5"}`}
          >
            {nextSteps.map((row, index) =>
              anyPriority ? (
                <li key={index} className="grid grid-cols-[84px_1fr] items-baseline gap-x-3">
                  {row.priority === null ? (
                    <span />
                  ) : (
                    <span
                      data-tone={PRIORITY_TONE[row.priority]}
                      className={`text-xs ${PRIORITY_INK[row.priority]}`}
                    >
                      {T.priority[row.priority]}
                    </span>
                  )}
                  <span className="break-words">{row.step}</span>
                </li>
              ) : (
                <li key={index} className="break-words">
                  {row.step}
                </li>
              ),
            )}
          </ul>
        </Card>
      )}

      {attention.length > 0 && (
        <Card title={T.attention}>
          {attention.map((line, index) => (
            <IconLine key={index} kind="warn">
              {line}
            </IconLine>
          ))}
        </Card>
      )}
    </div>
  );
}

// ── Diễn biến ────────────────────────────────────────────────────────────────────────────────────

export function TimelineTab({ run }: { run: RunView }) {
  const rows = timelineOf(run);
  const narrative = nonEmpty(run.narrative);
  // The mock-up shows the time of day; a timeline that crosses midnight needs the day too.
  const days = new Set(rows.map((row) => formatTime(row.time).split(" ")[0]));
  const when = (time: string | null): string =>
    days.size > 1 ? formatTime(time) : formatClock(time);
  return (
    <div className="flex flex-col gap-3.5">
      {narrative !== null && (
        <p className="text-sm leading-5 break-words whitespace-pre-wrap">{narrative}</p>
      )}
      {rows.length === 0 ? (
        <p className="text-sm text-muted">{S.ai2.timeline.none}</p>
      ) : (
        <ol
          aria-label={S.ai2.timeline.label}
          className="grid grid-cols-[auto_14px_1fr] gap-x-2.5 rounded-[10px] border border-border bg-surface p-4 text-[13px]"
        >
          {rows.map((row, index) => {
            const last = index === rows.length - 1;
            const lead = [row.tactic, row.technique]
              .filter((part): part is string => part !== null)
              .join(S.analysis.separator);
            return (
              <li key={index} className="col-span-3 grid grid-cols-subgrid">
                <time
                  dateTime={row.time ?? undefined}
                  className="pt-px font-mono whitespace-nowrap text-muted"
                >
                  {when(row.time)}
                </time>
                <div aria-hidden="true" className="flex flex-col items-center">
                  <span
                    data-part="dot"
                    data-tone={last ? "critical" : "ai"}
                    className={`mt-[5px] size-2.5 shrink-0 rounded-full ${last ? "bg-critical" : "bg-ai-accent"}`}
                  />
                  {!last && <span className="w-0.5 grow bg-border" />}
                </div>
                <div className={`flex min-w-0 flex-col gap-1 ${last ? "" : "pb-3.5"}`}>
                  <span className="break-words">{row.what}</span>
                  <span data-part="meta" className="text-xs break-words text-muted">
                    {`${lead === "" ? "" : `${lead}${S.analysis.separator}`}${S.ai2.timeline.alert} `}
                    <AlertLink id={row.alert_id} />
                  </span>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}

// ── Giả thuyết ───────────────────────────────────────────────────────────────────────────────────

const LIKELIHOOD_TONE = { high: "critical", medium: "medium", low: "muted" } as const;
const LIKELIHOOD_INK = { high: "text-critical", medium: "text-medium", low: "text-muted" } as const;

function Evidence({ lines, label, ink }: { lines: readonly string[]; label: string; ink: string }) {
  const labelId = useId();
  return (
    <div className="text-[13px] leading-[19px]">
      <p id={labelId} className={ink}>
        {label}
      </p>
      <ul aria-labelledby={labelId} className="list-disc pl-5 break-words">
        {lines.map((line, index) => (
          <li key={index}>{line}</li>
        ))}
      </ul>
    </div>
  );
}

function KnowledgeCard({ knowledge }: { knowledge: Knowledge }) {
  const T = S.ai2.hypothesesTab;
  let sentence: string | null;
  switch (knowledge.state) {
    case "matched":
      sentence =
        knowledge.candidates.length === 0 && knowledge.best_pct !== null
          ? S.rag.match(knowledge.best_pct)
          : null;
      break;
    case "below_floor":
      sentence = T.knowledgeBelowFloor(knowledge.floor_pct);
      break;
    case "no_candidate":
      sentence = T.knowledgeNoCandidate;
      break;
    case "no_lookup":
      sentence = T.knowledgeNoLookup;
      break;
    case "failed":
      sentence = T.knowledgeFailed(failureKindLabel(knowledge.failure));
      break;
    default:
      return null;
  }
  return (
    <Card
      title={S.analysis.knowledge.heading}
      variant="title"
      aside={
        knowledge.scored !== null && knowledge.scored > 0
          ? S.analysis.knowledge.scored(knowledge.scored)
          : undefined
      }
    >
      {sentence !== null && <p className="text-[13px] leading-[19px]">{sentence}</p>}
      {knowledge.candidates.length > 0 && (
        <KnowledgeCandidates rows={knowledge.candidates} bar={false} />
      )}
    </Card>
  );
}

export function HypothesesTab({ run }: { run: RunView }) {
  const T = S.ai2.hypothesesTab;
  const hypotheses = hypothesesOf(run);
  const knowledge = knowledgeOf(run);
  return (
    <div className="flex flex-col gap-3">
      {hypotheses.length === 0 ? (
        <p className="text-sm text-muted">{T.none}</p>
      ) : (
        <ol aria-label={S.ai2.hypotheses} className="flex flex-col gap-3">
          {hypotheses.map((hypothesis, index) => (
            <li key={index} className={`${CARD} flex flex-col gap-2`}>
              <div className="flex items-baseline justify-between gap-3">
                <span className="font-semibold break-words">
                  {hypothesis.text ?? S.common.missing}
                </span>
                {hypothesis.likelihood !== null && (
                  <span
                    data-part="likelihood"
                    data-tone={LIKELIHOOD_TONE[hypothesis.likelihood]}
                    className={`shrink-0 text-xs ${LIKELIHOOD_INK[hypothesis.likelihood]}`}
                  >
                    {T.likelihood[hypothesis.likelihood]}
                  </span>
                )}
              </div>
              {hypothesis.support.length > 0 && (
                <Evidence lines={hypothesis.support} label={T.for} ink="text-ok" />
              )}
              {hypothesis.counter.length === 0 ? (
                <p className="rounded bg-medium-bg p-2 text-xs text-medium">
                  {S.ai2.noCounterEvidence}
                </p>
              ) : (
                <Evidence lines={hypothesis.counter} label={T.against} ink="text-medium" />
              )}
            </li>
          ))}
        </ol>
      )}
      {knowledge !== null && <KnowledgeCard knowledge={knowledge} />}
    </div>
  );
}

// ── Bằng chứng ───────────────────────────────────────────────────────────────────────────────────

export function EvidenceTab({ run }: { run: RunView }) {
  const T = S.ai2.evidenceTab;
  const rows: unknown[] = Array.isArray(run.evidence) ? run.evidence : [];
  const evidence = rows.filter(
    (row): row is NonNullable<RunView["evidence"]>[number] =>
      typeof row === "object" && row !== null,
  );
  if (evidence.length === 0) return <p className="text-sm">{S.ai2.noEvidence}</p>;
  const { cited, verified } = evidenceCounts(run);
  return (
    <div className="flex flex-col gap-2.5">
      <p className="text-[13px] text-muted">{T.summary(verified, cited)}</p>
      <ul aria-label={S.ai2.evidence} className="flex flex-col gap-2.5">
        {evidence.map((row, index) => {
          const ok = row.verified === true;
          const alertId = nonEmpty(row.alert_id);
          const outcome = ok ? T.matched : (nonEmpty(row.reason_text) ?? S.ai2.unverified);
          return (
            <li key={index}>
              <EvidenceBlock
                claim={asText(row.why)}
                quote={nonEmpty(row.quote)}
                verified={ok}
                source={
                  <>
                    {alertId !== null && (
                      <>
                        {`${T.alert} `}
                        <AlertLink id={alertId} />
                        {S.analysis.separator}
                      </>
                    )}
                    {outcome}
                  </>
                }
              />
            </li>
          );
        })}
      </ul>
    </div>
  );
}

// ── Kỹ thuật ─────────────────────────────────────────────────────────────────────────────────────

/** Tokens, time, cost, when, the playbook and the alerts read. There is no model among them, and none is read from anywhere (G5). */
export function TechTab({ run, current }: { run: RunView; current: Snapshot | null }) {
  const tech = techOf(run, current);
  const tokens =
    tech.inputTokens === null && tech.outputTokens === null
      ? S.common.missing
      : S.analysis.tech.tokenLine(formatCount(tech.inputTokens), formatCount(tech.outputTokens));
  const alerts =
    tech.alertsRead === null
      ? S.common.missing
      : tech.alertsTotal === null
        ? String(tech.alertsRead)
        : S.ai2.tech.alertsReadOf(tech.alertsRead, tech.alertsTotal);
  return (
    <FactRows
      rows={[
        { label: S.analysis.tech.tokens, value: tokens },
        { label: S.analysis.tech.time, value: formatSeconds(tech.latencyMs) },
        { label: S.analysis.tech.cost, value: formatCost(tech.costUsd) },
        { label: S.analysis.tech.analysedAt, value: formatDateTime(tech.analysedAt) },
        { label: S.ai2.tech.playbook, value: tech.playbook ?? S.common.missing },
        { label: S.ai2.tech.alertsRead, value: alerts },
      ]}
    />
  );
}
