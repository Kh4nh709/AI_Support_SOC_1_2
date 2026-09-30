// The ① cell of a queue row. What it says is decided by `aiStateOfRow` and by nothing else here: this file
// only words the state. A blind row (DEC-101) says "ẩn — nhánh mù" and never "chưa có": the second would
// tell the analyst that ① has nothing to say, when in fact they are not shown what it said.
import { S, labelOf } from "../../strings";
import type { AiState } from "./aiState";

const MUTED = "text-muted";

export function AiCell({ state }: { state: AiState }) {
  switch (state.kind) {
    case "hidden":
      return <span className={`${MUTED} italic`}>{S.ai1.hidden}</span>;
    case "pending":
      return <span className={MUTED}>{S.ai1.none}</span>;
    case "unavailable":
      return <span className={MUTED}>{S.ai1.unavailable}</span>;
    case "decided":
      return state.action === null ? (
        <span className={MUTED}>{S.ai1.none}</span>
      ) : (
        <span>{labelOf(S.ai1.action, state.action)}</span>
      );
    case "ready":
      return (
        <span className="text-ai-accent">
          {labelOf(S.ai1.action, state.action)}
          {state.confidence !== null && (
            <span className={MUTED}> ({labelOf(S.confidence, state.confidence)})</span>
          )}
          {state.forced && (
            <span
              role="img"
              aria-label={S.ai1.forcedLabel}
              title={S.ai1.forcedLabel}
              className="ml-1"
            >
              {S.ai1.forced}
            </span>
          )}
        </span>
      );
  }
}
