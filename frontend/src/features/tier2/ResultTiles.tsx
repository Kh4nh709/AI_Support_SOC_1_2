// The four score tiles of the Tier 2 panel (DEC-221), above the tabs: the conclusion, the confidence, what the
// knowledge lookup came to, and how many of the quotes the server found in the log. What each tile says in each state is
// `runModel.ts`'s; this file lays them out.
import type { RunView } from "../../api/tier2";
import { S } from "../../strings";
import { ConfidenceMeter } from "../analysis/ConfidenceMeter";
import { ScoreTile } from "../analysis/ScoreTile";
import type { Tone } from "../analysis/styles";
import { confidenceOf, evidenceTile, ragTile, verdictTile } from "./runModel";

/** The text colour of a conclusion's tone: the tile's word, and the overview's first line. */
export const TONE_INK: Record<Tone, string> = {
  neutral: "text-text",
  ai: "text-text",
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
};

/** The line under the word: in the tile's own colour, grey on a quiet tile. */
const NOTE_INK: Record<Tone, string> = { ...TONE_INK, neutral: "text-muted", ai: "text-muted" };

/**
 * The size of the conclusion's word: the mock-up's 20 px. The tile is a quarter of a 528 px column, 100 px inside its
 * padding, and each of the four words ("Sự cố", "Vi phạm nội quy", "Không phải sự cố", "Cần thêm dữ liệu") must take two
 * lines at most there. Measured in Chromium at the column's real width (IBM Plex Sans 600): at 20 px the widest line
 * ("phải sự cố") is 94 px of 100, at 21 px 98 px (it still holds, with 2 px to spare, which another renderer's metrics
 * could take), at 22 px 101 px and "Không phải sự cố" takes three lines. 20 px is the largest that holds with room.
 */
const WORD = "text-[20px] leading-6";

/**
 * The Kết luận tile: one short word in the conclusion's colour and the line that says whose word it is. The server's
 * whole label is what a screen reader hears in the word's place, and is the first line of the overview. The tile is
 * drawn as the shared tile's own content (its children), because the shared tile's word is a fixed 16 px.
 */
function VerdictTile({ run }: { run: RunView }) {
  const verdict = verdictTile(run);
  const shortened = verdict.word !== verdict.label;
  return (
    <ScoreTile label={S.ai2.tile.verdict} tone={verdict.tone}>
      <span
        aria-hidden={shortened ? true : undefined}
        className={`${WORD} font-semibold break-words ${TONE_INK[verdict.tone]}`}
      >
        {verdict.word}
      </span>
      {shortened && <span className="sr-only">{verdict.label}</span>}
      <span className={`text-xs ${NOTE_INK[verdict.tone]}`}>{verdict.note}</span>
    </ScoreTile>
  );
}

export function ResultTiles({ run }: { run: RunView }) {
  const confidence = confidenceOf(run);
  const rag = ragTile(run);
  const evidence = evidenceTile(run);
  return (
    <div className="grid grid-cols-4 gap-2">
      <VerdictTile run={run} />
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
