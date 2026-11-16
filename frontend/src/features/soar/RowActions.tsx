// The last cell of a row: the buttons of the ticket (one per entry of `buttons` that the caller may press, n8n's label as
// plain text), "Đang xử lý…" while a request of this row is out (the buttons then disabled), and what the last request
// said (an error line, or a note) and what the row itself stores as its last error.
import type { SoarDecision, SoarReview } from "../../api/soar";
import { S } from "../../strings";
import { buttonsOf } from "./model";
import { sameStamp, stampOf, type RowState } from "./useDecisions";

// Whole class names, written out: Tailwind finds a class by reading the source. A long label wraps inside its button.
const BUTTON =
  "max-w-56 rounded border border-border px-2 py-1 text-left text-xs wrap-anywhere hover:bg-surface disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-text";

export function RowActions({
  row,
  state,
  me,
  onPress,
}: {
  row: SoarReview;
  state: RowState | undefined;
  /** The signed-in username: a row held by it is a request of its own, which this page may have lost track of. */
  me: string | null;
  onPress: (row: SoarReview, decision: SoarDecision) => void;
}) {
  const buttons = buttonsOf(row);
  // A request of this person that the page no longer holds (they left the page, or pressed in another tab) is still running.
  const mine = row.status === "processing" && me !== null && row.locked_by === me;
  const running = state?.running === true || mine;
  // What the last request said is about the row as it was then: when n8n has changed the ticket since, it is old news.
  const lines =
    state !== undefined && !state.running && state.at !== null && sameStamp(state.at, stampOf(row))
      ? state.lines
      : [];
  const stored =
    typeof row.last_error === "string" && row.last_error.trim() !== "" ? row.last_error : null;
  const saidAlready = lines.some((line) => line.text === stored);
  return (
    <div className="flex min-w-0 flex-col gap-1.5">
      {buttons.length > 0 && (
        <div
          role="group"
          aria-label={S.soar.buttonsLabel(row.id)}
          className="flex flex-wrap gap-1.5"
        >
          {buttons.map((button) => (
            <button
              key={button.decision}
              type="button"
              disabled={running}
              onClick={() => onPress(row, button.decision)}
              className={BUTTON}
            >
              {button.label}
            </button>
          ))}
        </div>
      )}
      {running && (
        <p role="status" className="text-xs text-muted">
          {S.soar.working}
        </p>
      )}
      {lines.map((line, index) => (
        <p
          key={index}
          role={line.tone === "error" ? "alert" : "status"}
          className={`text-xs wrap-anywhere ${line.tone === "error" ? "text-critical" : "text-low"}`}
        >
          {line.text}
        </p>
      ))}
      {stored !== null && !saidAlready && (
        <p className="text-xs text-critical wrap-anywhere">{S.soar.lastError(stored)}</p>
      )}
    </div>
  );
}
