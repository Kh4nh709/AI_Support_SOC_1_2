// The Tier 1 panel of a run that has an `analysis` (DEC-221, AP-T4): the notices that belong to the run, the four score
// tiles and the five tabs. It replaces what the flat column drew of a ready run (`FlatAiColumn`, which the admin's draft
// view still uses). The column (`AiColumn`) keeps the states around it: the blind arm, pending, none, unavailable and the
// decided comparison. The notices are the ones the flat column had: the clusters have changed since the analysis, and the
// RAG was not applied.
import { ragNoteOf } from "../../api/rag";
import type { AlertView } from "../../api/tier1";
import { RagNotice } from "../../components/RagNotice";
import { S } from "../../strings";
import { Tabs } from "../analysis/Tabs";
import type { AiState } from "./aiState";
import type { AnalysisModel } from "./analysisModel";
import { AnalysisTiles } from "./AnalysisTiles";
import { ChecksTab, EvidenceTab, KnowledgeTab, OverviewTab, TechTab } from "./AnalysisTabs";

const T = S.ai1.panel.tabs;

export function AnalysisPanel({
  view,
  state,
  model,
  ragNotice = true,
}: {
  view: AlertView;
  state: Extract<AiState, { kind: "ready" | "decided" }>;
  model: AnalysisModel;
  /** Whether the panel says that the RAG was not applied: the decided comparison's line says it already. */
  ragNotice?: boolean;
}) {
  const rag = ragNoteOf(view.rag);
  const suggestion = view.suggestion ?? null;
  const then = suggestion?.correlated_at_analysis;
  const now = view.correlated_now;
  const moved = typeof then === "number" && typeof now === "number" && now !== then;
  const gate = suggestion?.gate ?? null;
  // The gate forced the verdict: only a row stored before DEC-217 says so (`aiStateOfView` reads the same key).
  const forced = state.kind === "ready" && state.forced;
  return (
    <div className="flex flex-col gap-3.5">
      {moved && (
        <p className="rounded border border-medium/40 bg-medium-bg p-3 text-sm text-medium">
          {S.ai1.correlatedChanged(then, now)}
        </p>
      )}

      <AnalysisTiles state={state} model={model} />

      {ragNotice && rag.notApplied !== null && <RagNotice kind={rag.notApplied} subject="alert" />}

      {/* A new run starts on the first tab again: the open tab is the panel's own state. */}
      <Tabs
        key={String(suggestion?.run_id ?? "")}
        label={S.ai1.panel.tabsLabel}
        tabs={[
          { id: "overview", label: T.overview, content: <OverviewTab model={model} /> },
          { id: "evidence", label: T.evidence, content: <EvidenceTab model={model} /> },
          {
            id: "knowledge",
            label: T.knowledge,
            content: <KnowledgeTab model={model} ruleApplied={state.ragDefaultBelow} />,
          },
          {
            id: "checks",
            label: T.checks,
            content: <ChecksTab model={model} gate={gate} forced={forced} />,
          },
          { id: "tech", label: T.tech, content: <TechTab model={model} /> },
        ]}
      />
    </div>
  );
}
