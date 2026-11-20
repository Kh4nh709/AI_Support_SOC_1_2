// The four score tiles of the Tier 1 panel (DEC-221), above the tabs: the conclusion, the confidence, what the knowledge
// lookup came to, and how many of the gate's checks passed. What each tile says in each state is `analysisModel.ts`'s;
// this file lays them out with the pieces the Tier 2 panel uses (`ScoreTile`, `ConfidenceMeter`), so the two pages look
// alike.
import { S } from "../../strings";
import { ConfidenceMeter } from "../analysis/ConfidenceMeter";
import { ragTile } from "../analysis/knowledge";
import { ScoreTile } from "../analysis/ScoreTile";
import type { AiState } from "./aiState";
import { checksTile, confidenceTile, verdictTile, type AnalysisModel } from "./analysisModel";

const P = S.ai1.panel;

export function AnalysisTiles({
  state,
  model,
}: {
  state: Extract<AiState, { kind: "ready" | "decided" }>;
  model: AnalysisModel;
}) {
  const verdict = verdictTile(state);
  const confidence = confidenceTile(state);
  const rag = ragTile(model.rag);
  const checks = checksTile(model);
  // A verdict the page has a scale for is two letters: the mock-up's 28 px figure. Any other is a word.
  const letters = verdict.tone !== "neutral";
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      <ScoreTile
        label={P.tile.verdict}
        tone={verdict.tone}
        figure={letters}
        value={
          <>
            {verdict.label}
            {verdict.forced && (
              <span
                role="img"
                aria-label={S.ai1.forcedLabel}
                title={S.ai1.forcedLabel}
                className="ml-1 text-base"
              >
                {S.ai1.forced}
              </span>
            )}
          </>
        }
        note={verdict.note}
      />
      <ScoreTile label={P.tile.confidence} tone="ai">
        <ConfidenceMeter
          level={confidence.kind === "level" ? confidence.level : null}
          word={confidence.word}
        />
      </ScoreTile>
      <ScoreTile label={P.tile.rag} figure value={rag.value} note={rag.note} />
      <ScoreTile
        label={P.tile.checks}
        figure
        value={checks.value}
        note={checks.note}
        noteTone={checks.warn ? "warn" : "muted"}
      />
    </div>
  );
}
