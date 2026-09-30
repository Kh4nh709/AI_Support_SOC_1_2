// The ① column of the alert page (spec §3.1, the violet column). WHAT it says is decided by `aiStateOfView`
// and by nothing else: this file words the five states and reads no other key of the view to guess at one.
// In particular the hidden state (the blind arm, DEC-101) shows `S.ai1.hidden` and nothing of ①: not the
// verdict, not "pending", not "failed", not "no result". The server dropped the keys; this column does not
// look for them, and a column that is told `hidden` never reads `view.suggestion` at all.
import { useId, type ReactNode } from "react";
import type { AlertView, Suggestion } from "../../api/tier1";
import { formatDateTime } from "../../format";
import { S, labelOf } from "../../strings";
import { aiStateOfView, type AiState } from "./aiState";

const MUTED = "text-muted";

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

function Verdict({
  state,
  suggestion,
}: {
  state: Extract<AiState, { kind: "ready" }>;
  suggestion: Suggestion | null;
}) {
  const action = labelOf(S.ai1.action, state.action);
  const gate = suggestion?.gate ?? null;
  const forcedBy = gate ? forcedByOf(gate) : [];
  return (
    <div className="space-y-2">
      <div>
        <span className="text-xs text-muted">{S.ai1.verdict}</span>
        <p className="text-lg font-semibold text-ai-accent">
          <span>{action}</span>
          {action !== state.action && (
            <code className="ml-2 text-xs font-normal text-muted">{state.action}</code>
          )}
          {state.forced && (
            <span
              role="img"
              aria-label={S.ai1.forcedLabel}
              title={S.ai1.forcedLabel}
              className="ml-2"
            >
              {S.ai1.forced}
            </span>
          )}
        </p>
      </div>
      {state.confidence !== null && (
        <p className="text-sm">
          {S.ai1.confidence}: {labelOf(S.confidence, state.confidence)}
        </p>
      )}
      {gate !== null && (
        <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
          <span className={MUTED}>{S.ai1.gate}</span>
          <strong>{state.forced ? S.ai1.gateForced : S.ai1.gateNotForced}</strong>
          {forcedBy.length > 0 && (
            <>
              <span className={MUTED}>{S.ai1.gateForcedBy}</span>
              <code>{forcedBy.join(", ")}</code>
            </>
          )}
        </div>
      )}
    </div>
  );
}

/** What the gate did: the verdict ① proposed, the one it ended with, the verifier, and the gate's warnings. */
function GateSteps({ gate }: { gate: NonNullable<Suggestion["gate"]> }) {
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

function Reasons({ reasons }: { reasons: NonNullable<Suggestion["reasons"]> }) {
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

function Ready({ view, state }: { view: AlertView; state: Extract<AiState, { kind: "ready" }> }) {
  const suggestion = view.suggestion ?? null;
  const analysedThen = suggestion?.correlated_at_analysis;
  return (
    <div className="space-y-3">
      <Verdict state={state} suggestion={suggestion} />
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

function Message({
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

function Unavailable({ stoppedBy }: { stoppedBy: string | null }) {
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

/** The decision beside what ① said: evaluation material, shown only once a person has decided. */
function Decided({
  view,
  state,
}: {
  view: AlertView;
  state: Extract<AiState, { kind: "decided" }>;
}) {
  return (
    <div className="space-y-3">
      <h3 className="text-sm font-medium">{S.ai1.decidedHeading}</h3>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div className="rounded border border-ai-border p-3">
          <span className="text-xs text-muted">{S.decision.heading}</span>
          <p className="text-sm">
            <span>{labelOf(S.status, view.status)}</span>
            {view.acknowledged_by_name && (
              <span className={MUTED}> · {view.acknowledged_by_name}</span>
            )}
          </p>
        </div>
        <div className="rounded border border-ai-border p-3">
          <span className="text-xs text-muted">{S.ai1.decidedAi}</span>
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
        </div>
      </div>
    </div>
  );
}

export function AiColumn({
  view,
  state = aiStateOfView(view),
}: {
  view: AlertView;
  /** Given only by a test: the page lets the column read the state of the view itself. */
  state?: AiState;
}) {
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
      {state.kind === "unavailable" && <Unavailable stoppedBy={state.stoppedBy} />}
      {state.kind === "decided" && <Decided view={view} state={state} />}
    </section>
  );
}
