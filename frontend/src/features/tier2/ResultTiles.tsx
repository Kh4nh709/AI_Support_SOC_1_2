// The four score tiles of the Tier 2 panel (DEC-221), above the tabs: the conclusion, the confidence, what the
// knowledge lookup came to, and how many of the quotes the server found in the log. What each tile says in each state is
// `runModel.ts`'s; this file lays them out.
import type { RunView } from "../../api/tier2";
import { S } from "../../strings";
import { ConfidenceMeter } from "../analysis/ConfidenceMeter";
import { ScoreTile } from "../analysis/ScoreTile";
import { confidenceOf, evidenceTile, ragTile, verdictTile } from "./runModel";

export function ResultTiles({ run }: { run: RunView }) {
  const verdict = verdictTile(run);
  const confidence = confidenceOf(run);
  const rag = ragTile(run);
  const evidence = evidenceTile(run);
  return (
    <div className="grid grid-cols-4 gap-2">
      <ScoreTile
        label={S.ai2.tile.verdict}
        tone={verdict.tone}
        value={verdict.label}
        note={verdict.note}
      />
      <ScoreTile label={S.ai2.tile.confidence} tone="ai">
        <ConfidenceMeter level={confidence.level} word={confidence.word} />
      </ScoreTile>
      <ScoreTile label={S.ai2.tile.rag} figure value={rag.value} note={rag.note} />
      <ScoreTile
        label={S.ai2.tile.evidence}
        figure
        value={evidence.value}
        note={evidence.note}
        noteTone={evidence.warn ? "warn" : "muted"}
      />
    </div>
  );
}
