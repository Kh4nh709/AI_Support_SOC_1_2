// The last cell of a row: the buttons of the ticket (one per entry of `buttons` that the caller may press, n8n's label as
// plain text), "Đang xử lý…" while a request of this row is out (the buttons then disabled), and what the last request
// said (an error line, or a note) and what the row itself stores as its last error.
import { useEffect, useId, useRef } from "react";
import type { SoarDecision, SoarReview } from "../../api/soar";
import { S } from "../../strings";
import { buttonsOf, type ShownButton } from "./model";
import { sameStamp, stampOf, type RowState } from "./useDecisions";

/**
 * One button of a ticket: n8n label as text, and beside it the word of the WEB for the decision ("Giữ", "Gỡ", "Dương tính
 * giả"), which is the button's accessible description and, always, a small muted tag for the eye: a label n8n wrote can say
 * the opposite of what the button does (a keep labelled "Gỡ chặn (không giữ)" would read as an undo), so the word of the web is
 * never hidden, even when the label happens to contain it.
 */
function DecisionButton({
  button,
  disabled,
  onPress,
}: {
  button: ShownButton;
  disabled: boolean;
  onPress: () => void;
}) {
  const wordId = useId();
  const word = S.soar.decision[button.decision];
  const prefix = button.label.match(/^(?:✅|↩️?|🚫)\s+(?=\S)/u)?.[0] ?? "";
  return (
    <span className="soar-action-item">
      <button
        type="button"
        disabled={disabled}
        aria-describedby={wordId}
        onClick={onPress}
        // Holding Enter on a button repeats its click: the repeat is not a new press (a fast failure would send again).
        onKeyDown={(event) => {
          if (event.repeat) event.preventDefault();
        }}
        className="soar-decision max-w-full wrap-anywhere"
        data-decision={button.decision}
        aria-label={button.label}
      >
        <span>
          <span className="sr-only">{prefix}</span>
          {button.label.slice(prefix.length)}
        </span>
      </button>
      <span id={wordId} className="text-xs text-muted">
        {word}
      </span>
    </span>
  );
}

export function RowActions({
  row,
  state,
  me,
  focus,
  onPress,
}: {
  row: SoarReview;
  state: RowState | undefined;
  /** The signed-in username: a row held by it is a request of its own, which this page may have lost track of. */
  me: string | null;
  /** Set when a request of some row has just started: the row it names takes the focus (see `useDecisions`). */
  focus: { id: string } | null;
  onPress: (row: SoarReview, decision: SoarDecision) => void;
}) {
  const group = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (focus !== null && focus.id === row.id) group.current?.focus();
  }, [focus, row.id]);
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
    // The group is the whole cell: labelled by its ticket, and focusable by script (tabindex -1), so the focus has a place
    // to go when a button is disabled under it.
    <div
      ref={group}
      role="group"
      aria-label={S.soar.buttonsLabel(row.id)}
      tabIndex={-1}
      className="flex min-w-0 flex-col gap-1.5 focus-visible:outline-2 focus-visible:outline-text"
    >
      {buttons.length > 0 && (
        <div className="soar-actions">
          {buttons.map((button) => (
            <DecisionButton
              key={button.decision}
              button={button}
              disabled={running}
              onPress={() => onPress(row, button.decision)}
            />
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
