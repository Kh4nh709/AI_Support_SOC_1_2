// The flat ① column of the alert page (spec §3.1, the violet column), as it was before the scorecard (DEC-221, AP-T4).
// The alert page now draws `AiColumn` (the four tiles over five tabs, `AnalysisPanel`), which keeps every state of this
// column inside its own frame and falls back on the pieces below for a view that has no `analysis` (an older server or
// a garbled document). The admin's knowledge-draft view still draws this column whole (`FlatAiColumn`), as the admin
// pages are not part of the redesign.
//
// WHAT it says is decided by `aiStateOfView` and by nothing else: this file words the six states and reads no other key
// of the view to guess at one. In particular the hidden state (the blind arm, DEC-101) shows `S.ai1.hidden` and nothing
// of ①: not the verdict, not "pending", not "failed", not "no result". The server dropped the keys; this column does not
// look for them, and it takes no state from a caller: the only way to a state is the view itself.
import { useId, type ReactNode } from "react";
import { ragNoteOf, type RagNote } from "../../api/rag";
import type { AlertView, Suggestion } from "../../api/tier1";
import { RagNotice } from "../../components/RagNotice";
import { formatDateTime } from "../../format";
import { S, labelOf } from "../../strings";
import { agreementOf, humanDecisionOf } from "./agreement";
import { aiStateOfView, conclusionOf, heldOf, type AiConclusion, type AiState } from "./aiState";

const MUTED = "text-muted";

/** No match and no notice: the pair of a view that carries none (an older server, a lookup that found nothing). */
const NO_RAG: RagNote = { pct: null, notApplied: null };

/** A titled block of the column, named for a screen reader by its own heading. */
function Block({ title, children }: { title: string; children: ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="space-y-2 border-t border-ai-border pt-3">
      <h3 id={id} className="text-xs font-medium text-muted">
        {title}
      </h3>
      {children}
    </section>
  );
}

/** A gate rule list arrives as a list, a string, or not at all. */
function forcedByOf(gate: NonNullable<Suggestion["gate"]>): string[] {
  const { forced_by: by } = gate;
  if (Array.isArray(by)) return by.filter((x): x is string => typeof x === "string" && x !== "");
  return typeof by === "string" && by !== "" ? [by] : [];
}

const asText = (x: unknown): string => (typeof x === "string" ? x : JSON.stringify(x));

/** The flag of a verdict the gate forced: only a version 1 row has one (DEC-217: a new run is never forced). */
function ForcedFlag() {
  return (
    <span role="img" aria-label={S.ai1.forcedLabel} title={S.ai1.forcedLabel} className="ml-2">
      {S.ai1.forced}
    </span>
  );
}

/**
 * What the AI concluded (P14-T03, DEC-213): "AI kết luận: **TP** (độ tin cậy cao)", and when the gate's checks raised
 * warnings, "… — **có cảnh báo kiểm chứng**: <reasons>" (DEC-217: the verdict is the model's own, the checks are
 * warnings beside it, and nothing is held back for a person). The conclusion is the verdict ① ended with, which is
 * the model's own answer except for a run below the RAG threshold (DEC-219, below), and the model's own answer for a
 * `needs_review` stored before DEC-217 that still arrives (`heldOf`'s guard half); a reason the UI has no label for
 * is shown as its code. All of it is text.
 *
 * The one component of that line, for the undecided column (`Verdict`) and for the decided one (`Decided`, in the
 * "Gợi ý ①" box): the two pages say the same thing in the same words, and what is added to the line is added here,
 * once. `forced` is the gate's flag, which only an undecided state knows.
 *
 * P14-T07 (DEC-213, spec 4.3): `rag` is the view's `rag` pair (`ragNoteOf`). The percentage joins the line, after the
 * confidence note and before the warning clause: "AI kết luận: **TP** (độ tin cậy cao) — trùng 87% với tri thức
 * đã duyệt", nothing when there was no match. The notice that the RAG was not applied is a sentence of its own
 * beside the line (`RagNotice`). The blind arm has no conclusion to draw this beside, so neither is ever drawn
 * there: the server drops the key, and this column draws a line only for a state that has a conclusion.
 *
 * DEC-220 (trial): a run whose lookup kept no match has no `pct`, and its best candidate under the floor takes the
 * place of the percentage, in the same spot: "AI kết luận: **TP** (độ tin cậy trung bình) — trùng cao nhất 47% với tri
 * thức đã duyệt (dưới mức tối thiểu 50%)". The rule of DEC-219 cannot apply to such a run, so no default clause
 * follows it.
 *
 * DEC-219 (trial, amended): for a run the RAG rule applied to (`state.ragDefaultBelow`, the threshold) `false_positive`
 * is ①'s default answer, and the line says so, the same whether the model had said FP itself or not: no confidence
 * note (it is the model's, in its own answer), then, after the percentage clause, a parenthesis, "(dưới 80%: mặc định
 * FP)", then the warning clause as before. With no percentage on the page the parenthesis follows the verdict. The line
 * never names the model's own answer. Any other run reads as it did.
 */
export function ConclusionLine({
  state,
  conclusion,
  forced = false,
  rag = NO_RAG,
}: {
  state: AiConclusion & { confidence: string | null };
  conclusion: string;
  forced?: boolean;
  rag?: RagNote;
}) {
  const reasons = state.heldBy.map((code) => labelOf(S.ai1.heldReason, code));
  const because = S.ai1.heldBecause(reasons);
  const defaultBelow = state.ragDefaultBelow;
  return (
    <>
      <p className="text-base text-ai-accent">
        {S.ai1.conclusion}: <strong className="text-lg">{labelOf(S.ai1.action, conclusion)}</strong>
        {defaultBelow === undefined &&
          state.confidence !== null &&
          ` ${S.ai1.confidenceNote(labelOf(S.confidence, state.confidence))}`}
        {rag.pct !== null && ` ${S.rag.dash} ${S.rag.match(rag.pct)}`}
        {rag.belowFloor !== undefined &&
          ` ${S.rag.dash} ${S.rag.belowFloor(rag.belowFloor.pct, rag.belowFloor.floor)}`}
        {defaultBelow !== undefined && ` ${S.ai1.ragDefault(defaultBelow)}`}
        {heldOf(state) && (
          <>
            {` ${S.ai1.heldDash} `}
            <strong>{S.ai1.held}</strong>
            {because}
          </>
        )}
        {forced && <ForcedFlag />}
      </p>
      {rag.notApplied !== null && <RagNotice kind={rag.notApplied} subject="alert" />}
    </>
  );
}

function Verdict({
  state,
  suggestion,
  rag,
}: {
  state: Extract<AiState, { kind: "ready" }>;
  suggestion: Suggestion | null;
  rag: RagNote;
}) {
  const conclusion = conclusionOf(state);
  const action = labelOf(S.ai1.action, state.action);
  const gate = suggestion?.gate ?? null;
  return (
    <div className="space-y-2">
      {conclusion !== null ? (
        <ConclusionLine state={state} conclusion={conclusion} forced={state.forced} rag={rag} />
      ) : (
        <>
          <div>
            <span className="text-xs text-muted">{S.ai1.verdict}</span>
            <p className="text-lg font-semibold text-ai-accent">
              <span>{action}</span>
              {action !== state.action && (
                <code className="ml-2 text-xs font-normal text-muted">{state.action}</code>
              )}
              {state.forced && <ForcedFlag />}
            </p>
          </div>
          {state.confidence !== null && (
            <p className="text-sm">
              {S.ai1.confidence}: {labelOf(S.confidence, state.confidence)}
            </p>
          )}
          {rag.notApplied !== null && <RagNotice kind={rag.notApplied} subject="alert" />}
        </>
      )}
      {gate !== null && <GateLine gate={gate} forced={state.forced} />}
    </div>
  );
}

/**
 * The gate in one line: whether it forced the verdict, and by which rules (a version 1 row; a new run reads "Không bị
 * ép" and names none, the RAG default of DEC-219 included: it is not a gate force). Exported to be drawn on its own.
 */
export function GateLine({
  gate,
  forced,
}: {
  gate: NonNullable<Suggestion["gate"]>;
  forced: boolean;
}) {
  const forcedBy = forcedByOf(gate);
  return (
    <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
      <span className={MUTED}>{S.ai1.gate}</span>
      <strong>{forced ? S.ai1.gateForced : S.ai1.gateNotForced}</strong>
      {forcedBy.length > 0 && (
        <>
          <span className={MUTED}>{S.ai1.gateForcedBy}</span>
          <code>{forcedBy.join(", ")}</code>
        </>
      )}
    </div>
  );
}

/**
 * What the gate did: the verdict ① proposed, the one it ended with (the same for a new run, DEC-217; for a run below
 * the RAG threshold, DEC-219, the server serves the verdict ① ended with in both places), the verifier, and the
 * gate's warnings. A row is drawn only for a verdict the server gave: a null verifier verdict (the server sends it for
 * a run below the RAG threshold, DEC-219) has no "Bộ kiểm chứng" row at all. A version 1 row shows what the gate
 * stored, `needs_review` included.
 */
export function GateSteps({ gate }: { gate: NonNullable<Suggestion["gate"]> }) {
  const warnings = gate.warnings ?? [];
  const rows: [string, string | null | undefined][] = [
    [S.ai1.gateProposed, gate.proposed_verdict],
    [S.ai1.gateFinal, gate.final_verdict],
    [S.ai1.verifier, gate.verifier_verdict],
  ];
  const shown = rows.filter(([, value]) => typeof value === "string" && value !== "");
  if (shown.length === 0 && warnings.length === 0) return null;
  return (
    <Block title={S.ai1.gateSteps}>
      <dl className="space-y-1 text-sm">
        {shown.map(([label, value]) => (
          <div key={label} className="flex flex-wrap gap-x-2">
            <dt className={MUTED}>{label}</dt>
            <dd>{label === S.ai1.verifier ? value : labelOf(S.ai1.action, value)}</dd>
          </div>
        ))}
      </dl>
      {warnings.length > 0 && (
        <div>
          <p className="text-xs text-muted">{S.ai1.gateWarnings}</p>
          <ul className="list-disc space-y-1 pl-5 text-sm text-medium">
            {warnings.map((w, i) => (
              <li key={i}>{asText(w)}</li>
            ))}
          </ul>
        </div>
      )}
    </Block>
  );
}

export function Reasons({ reasons }: { reasons: NonNullable<Suggestion["reasons"]> }) {
  if (reasons.length === 0) return null;
  return (
    <Block title={S.ai1.reasons}>
      <ul className="space-y-3">
        {reasons.map((reason, i) => (
          <li key={i} className="space-y-1 text-sm">
            <p>{reason.claim}</p>
            {reason.quote && (
              <blockquote className="border-l-2 border-ai-border pl-3 font-mono text-xs break-words text-muted">
                {reason.quote}
              </blockquote>
            )}
            {reason.source && (
              <p className="text-xs text-muted">
                {S.ai1.source}: <code>{reason.source}</code>
              </p>
            )}
          </li>
        ))}
      </ul>
    </Block>
  );
}

/** The facts ① worked from, and, when the clusters have moved since, the sentence that says so. */
function Facts({ then, now }: { then: number; now: number | null | undefined }) {
  return (
    <Block title={S.ai1.facts}>
      <dl className="text-sm">
        <div className="flex flex-wrap gap-x-2">
          <dt className={MUTED}>{S.ai1.correlatedThen}</dt>
          <dd>{then}</dd>
        </div>
      </dl>
      {now !== null && now !== undefined && now !== then && (
        <p className="text-sm text-medium">{S.ai1.correlatedChanged(then, now)}</p>
      )}
    </Block>
  );
}

/** A ready state drawn flat: the conclusion line, the gate, the reasons, the facts. */
export function Ready({
  view,
  state,
}: {
  view: AlertView;
  state: Extract<AiState, { kind: "ready" }>;
}) {
  const suggestion = view.suggestion ?? null;
  const analysedThen = suggestion?.correlated_at_analysis;
  return (
    <div className="space-y-3">
      <Verdict state={state} suggestion={suggestion} rag={ragNoteOf(view.rag)} />
      {suggestion?.gate && <GateSteps gate={suggestion.gate} />}
      {suggestion?.reasons && <Reasons reasons={suggestion.reasons} />}
      {typeof analysedThen === "number" && <Facts then={analysedThen} now={view.correlated_now} />}
      {suggestion?.created_at && (
        <p className="text-xs text-muted">
          {S.ai1.analysedAt}: {formatDateTime(suggestion.created_at)}
        </p>
      )}
    </div>
  );
}

export function Message({
  title,
  body,
  italic = false,
}: {
  title: string;
  body: string;
  italic?: boolean;
}) {
  return (
    <div className="space-y-2">
      <p className={`${MUTED} ${italic ? "italic" : ""}`}>{title}</p>
      <p className="text-sm text-muted">{body}</p>
    </div>
  );
}

/**
 * ① gave up. The reason is worded when one is given: the alert view carries it (`llm_stopped_by`, INT-T02),
 * so the column passes it on; a view with none names none. It is exported to be drawn on its own.
 */
export function Unavailable({ stoppedBy }: { stoppedBy: string | null }) {
  return (
    <div className="space-y-2">
      <Message title={S.ai1.unavailable} body={S.ai1.unavailableBody} />
      {stoppedBy !== null && (
        <p className="text-sm">
          <span className={MUTED}>{S.ai1.stoppedByLabel}</span>{" "}
          <span>{labelOf(S.ai1.stoppedBy, stoppedBy)}</span>
          {labelOf(S.ai1.stoppedBy, stoppedBy) !== stoppedBy && (
            <code className="ml-2 text-xs text-muted">{stoppedBy}</code>
          )}
        </p>
      )}
    </div>
  );
}

/** How ① and the person agree, in words; the mapping is agreement.ts's. */
const AGREEMENT_WORDS = {
  agree: S.ai1.matchAgree,
  disagree: S.ai1.matchDisagree,
  no_verdict: S.ai1.matchNoVerdict,
} as const;

/** The statuses a Tier 2 conclusion leaves on the alerts of its case (transitions.py `_CONCLUSION_TO_ALERT_STATUS`). */
const CONCLUSIONS: ReadonlySet<string> = new Set([
  "closed_fp",
  "closed_benign",
  "closed_confirmed",
]);

/**
 * The decision beside what ① said: evaluation material, shown only once the alert is closed or escalated.
 * A Tier 1 decision (closed as a false positive or benign, or escalated) names the person who took it: the
 * holder of an alert is the only one who can. An alert Tier 1 escalated stays an escalation when Tier 2 has
 * concluded it: the decision says so, the conclusion is added as Tier 2's, and it is compared with ① as an
 * escalation (the pilot report's count). A close by the system, or a Tier 2 conclusion with no escalation
 * behind it, has no Tier 1 person: nobody is named as its decider, and there is nothing to compare ① with.
 */
export function Decided({
  view,
  state,
}: {
  view: AlertView;
  state: Extract<AiState, { kind: "decided" }>;
}) {
  // What the pilot report counts as the human decision, read from the case as well as the status (agreement.ts):
  // `null` is a status that is not a Tier 1 decision (auto_closed, or a closed_confirmed with no case).
  const human = humanDecisionOf(view.status, view.case_id);
  // "Khớp" is the stored verdict's, as the pilot report counts it; the line beside it says what the AI concluded
  // and which checks warned (P14-T03, fix round 1; DEC-217), the same line the undecided column draws.
  const agreement = agreementOf(view.status, state.action, view.case_id);
  const conclusion = conclusionOf(state);
  // The percentage and the notice (P14-T07) are the view's own, like the line they stand beside: the decision lifts
  // the blind arm, so the server sends the key back.
  const rag = ragNoteOf(view.rag);
  const byTier1 = human !== null;
  // Tier 2 has concluded an alert Tier 1 escalated: the status is the conclusion's, the decision is still the
  // escalation. The holder of the alert is named on the escalation, never on the conclusion.
  const concluded = human === "escalated" && CONCLUSIONS.has(view.status);
  const decision =
    human === "escalated" ? S.status.escalated_tier2 : labelOf(S.status, view.status);
  return (
    <div className="space-y-3">
      <h3 className="text-sm font-medium">{S.ai1.decidedHeading}</h3>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="rounded border border-ai-border p-3">
          <span className="text-xs text-muted">{S.decision.heading}</span>
          <p className="text-sm">
            <span>{decision}</span>
            {byTier1 && view.acknowledged_by_name && (
              <span className={MUTED}> · {view.acknowledged_by_name}</span>
            )}
          </p>
          {concluded && (
            <p className="text-xs text-muted">
              {S.ai1.tier2Concluded(labelOf(S.status, view.status))}
            </p>
          )}
        </div>
        <div className="rounded border border-ai-border p-3">
          <span className="text-xs text-muted">{S.ai1.decidedAi}</span>
          {conclusion !== null ? (
            <ConclusionLine state={state} conclusion={conclusion} rag={rag} />
          ) : (
            <>
              <p className="text-sm">
                {state.action === null ? (
                  <span className={MUTED}>{S.ai1.none}</span>
                ) : (
                  <>
                    <span className="text-ai-accent">{labelOf(S.ai1.action, state.action)}</span>
                    {state.confidence !== null && (
                      <span className={MUTED}> · {labelOf(S.confidence, state.confidence)}</span>
                    )}
                  </>
                )}
              </p>
              {state.action !== null && rag.notApplied !== null && (
                <RagNotice kind={rag.notApplied} subject="alert" />
              )}
            </>
          )}
        </div>
      </div>
      {agreement === null ? (
        <p className="text-xs text-muted">{S.ai1.notTier1Decision}</p>
      ) : (
        <p className="text-sm">
          <span className={MUTED}>{S.ai1.match}</span> <strong>{AGREEMENT_WORDS[agreement]}</strong>
        </p>
      )}
    </div>
  );
}

export function FlatAiColumn({ view }: { view: AlertView }) {
  // The state is the view's own word, read by `aiStateOfView` and by nothing else.
  const state = aiStateOfView(view);
  const heading = useId();
  return (
    <section
      aria-labelledby={heading}
      className="space-y-4 rounded border border-ai-border bg-ai-surface p-4"
    >
      <header>
        <h2 id={heading} className="text-sm font-semibold tracking-wide text-ai-accent">
          {S.alert.aiHeading}
        </h2>
        <p className="text-xs text-muted">{S.alert.aiHint}</p>
      </header>
      {state.kind === "ready" && <Ready view={view} state={state} />}
      {state.kind === "hidden" && <Message title={S.ai1.hidden} body={S.ai1.hiddenBody} italic />}
      {state.kind === "pending" && <Message title={S.ai1.pending} body={S.ai1.pendingBody} />}
      {state.kind === "none" && <Message title={S.ai1.none} body={S.ai1.noneBody} />}
      {state.kind === "unavailable" && <Unavailable stoppedBy={state.stoppedBy} />}
      {state.kind === "decided" && <Decided view={view} state={state} />}
    </section>
  );
}
