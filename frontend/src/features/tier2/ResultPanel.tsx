// The Tier 2 panel of a run that has a result (DEC-221): the notices that belong to the run, the four score tiles, the
// five tabs and the advisory line. It replaces what the case column drew of a result (`RunResult`, which the admin's
// draft view still uses). The column keeps the states around it: loading, running, stalled, failed, a run with no
// result, and the button that starts a run.
import type { RunView, Snapshot } from "../../api/tier2";
import { ragNoteOf } from "../../api/rag";
import { RagNotice } from "../../components/RagNotice";
import { formatTime } from "../../format";
import { S } from "../../strings";
import { Tabs } from "../analysis/Tabs";
import { ResultTiles } from "./ResultTiles";
import { snapshotOf } from "./runModel";
import { EvidenceTab, HypothesesTab, OverviewTab, TechTab, TimelineTab } from "./ResultTabs";

export function ResultPanel({ run, current }: { run: RunView; current: Snapshot | null }) {
  const rag = ragNoteOf(run.rag);
  const T = S.ai2.tabs;
  // The numbers are said only when the server sent numbers (`snapshotOf`): a notice never prints what it does not have.
  const then = snapshotOf(run.snapshot);
  const now = snapshotOf(current);
  return (
    <div className="flex flex-col gap-3.5">
      {run.changed === true && (
        <div className="space-y-1 rounded border border-medium/40 bg-medium-bg p-3 text-sm text-medium">
          <p>{S.ai2.stale}</p>
          {then !== null && (
            <p>
              {S.ai2.snapshot(
                then.alert_count,
                then.total_occurrences,
                then.last_seen_at === null ? null : formatTime(then.last_seen_at),
              )}
            </p>
          )}
          {now !== null && (
            <p>
              {S.ai2.current(
                now.alert_count,
                now.total_occurrences,
                now.last_seen_at === null ? null : formatTime(now.last_seen_at),
              )}
            </p>
          )}
        </div>
      )}

      <ResultTiles run={run} />

      {rag.notApplied !== null && <RagNotice kind={rag.notApplied} subject="case" />}

      {/* A new run starts on the first tab again: the open tab is the panel's own state. */}
      <Tabs
        key={String(run.run_id)}
        label={T.label}
        tabs={[
          { id: "overview", label: T.overview, content: <OverviewTab run={run} /> },
          { id: "timeline", label: T.timeline, content: <TimelineTab run={run} /> },
          { id: "hypotheses", label: T.hypotheses, content: <HypothesesTab run={run} /> },
          { id: "evidence", label: T.evidence, content: <EvidenceTab run={run} /> },
          { id: "tech", label: T.tech, content: <TechTab run={run} current={current} /> },
        ]}
      />

      <p className="text-xs text-muted">{S.ai2.disclaimer}</p>
    </div>
  );
}
