// The ① column of the alert page (spec §3.1; DEC-221, AP-T4): the Tier 1 scorecard. Under its heading ("PHÂN TÍCH AI ·
// TIER 1", the advisory line at the right) a run that has a conclusion and an `analysis` is four score tiles over five
// tabs (`AnalysisPanel`); every other state is drawn in the same frame as it always was.
//
// WHAT the column says is decided by `aiStateOfView` and by nothing else: this file words the six states and reads no
// other key of the view to guess at one. In particular the hidden state (the blind arm, DEC-101) shows `S.ai1.hidden` and
// nothing of ①: not the verdict, not "pending", not "failed", not "no result", and not the panel, whatever else the view
// carries. The server dropped the keys (`analysis` among them); this column does not look for them, and it takes no state
// from a caller: the only way to a state is the view itself. The scorecard is drawn only for a state that has a
// conclusion (`ready`, and `decided` beside the comparison); for a view with no `analysis` (an older server, a garbled
// document) the flat rendering of `FlatAiColumn` stays, rather than an empty panel.
import { useId } from "react";
import type { AlertView } from "../../api/tier1";
import { S } from "../../strings";
import { aiStateOfView } from "./aiState";
import { AnalysisPanel } from "./AnalysisPanel";
import { analysisOf } from "./analysisModel";
import { Decided, Message, Ready, Unavailable } from "./FlatAiColumn";

export function AiColumn({ view }: { view: AlertView }) {
  // The state is the view's own word, read by `aiStateOfView` and by nothing else.
  const state = aiStateOfView(view);
  const heading = useId();
  // The panel is for a state that has a conclusion; any other state has no panel, whatever `analysis` says.
  const concluded = state.kind === "ready" || state.kind === "decided";
  const model = concluded ? analysisOf(view) : null;
  return (
    <section
      aria-labelledby={heading}
      className="space-y-3.5 rounded border border-ai-border bg-ground p-4"
    >
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <h2 id={heading} className="text-xs font-semibold tracking-[0.08em] text-ai-accent">
          {S.alert.aiHeading}
        </h2>
        <span className="min-w-0 text-right text-xs text-muted">{S.alert.aiHint}</span>
      </div>
      {state.kind === "ready" &&
        (model !== null ? (
          <AnalysisPanel view={view} state={state} model={model} />
        ) : (
          <Ready view={view} state={state} />
        ))}
      {state.kind === "hidden" && <Message title={S.ai1.hidden} body={S.ai1.hiddenBody} italic />}
      {state.kind === "pending" && <Message title={S.ai1.pending} body={S.ai1.pendingBody} />}
      {state.kind === "none" && <Message title={S.ai1.none} body={S.ai1.noneBody} />}
      {state.kind === "unavailable" && <Unavailable stoppedBy={state.stoppedBy} />}
      {state.kind === "decided" && (
        <div className="flex flex-col gap-3.5">
          <Decided view={view} state={state} />
          {model !== null && (
            <AnalysisPanel view={view} state={state} model={model} ragNotice={false} />
          )}
        </div>
      )}
    </section>
  );
}
