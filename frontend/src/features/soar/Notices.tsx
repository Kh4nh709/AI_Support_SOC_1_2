// The notices (`kind=notice`) above the table of a review tab: a line each, coloured by its severity and carrying the
// severity's word (error red, warning orange, info grey), each with a button that dismisses it. The ids dismissed are
// remembered by the page (`storage.ts`, capped). At most 20 lines are drawn; a sentence says how many more there are and
// that the filter "Thông báo" lists them all, dismissed or not.
import type { SoarReview } from "../../api/soar";
import { S, labelOf } from "../../strings";
import { severityWordClass } from "./SoarTable";

/** The most lines drawn above the table. */
export const NOTICE_LINES_MAX = 20;

// Whole class names: the box of a line by severity. Anything but error and warning is the grey of info.
const BOX: Record<string, string> = {
  error: "border-critical bg-critical-bg",
  warning: "border-high bg-high-bg",
};
const boxClass = (severity: unknown): string =>
  typeof severity === "string" && Object.hasOwn(BOX, severity)
    ? (BOX[severity] as string)
    : "border-border bg-surface";

const text = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value : null;

export function NoticeStrip({
  notices,
  dismissed,
  onDismiss,
}: {
  notices: readonly SoarReview[];
  dismissed: ReadonlySet<string>;
  onDismiss: (id: string) => void;
}) {
  const shown = notices.filter((notice) => !dismissed.has(notice.id));
  if (shown.length === 0) return null;
  const lines = shown.slice(0, NOTICE_LINES_MAX);
  const more = shown.length - lines.length;
  return (
    <section aria-label={S.soar.notice.heading} className="flex flex-col gap-2">
      <ul className="flex flex-col gap-2">
        {lines.map((notice) => (
          <li
            key={notice.id}
            className={`flex items-start gap-3 rounded border px-3 py-2 text-sm ${boxClass(notice.severity)}`}
          >
            <strong className={`shrink-0 ${severityWordClass(notice.severity)}`}>
              {labelOf(S.soar.severity, notice.severity)}
            </strong>
            <div className="min-w-0 flex-1 wrap-anywhere text-text">
              <p className="font-medium">{text(notice.title) ?? S.common.missing}</p>
              {text(notice.note) !== null && <p>{notice.note}</p>}
            </div>
            <button
              type="button"
              aria-label={S.soar.notice.dismissLabel(notice.id)}
              title={S.soar.notice.sessionOnly}
              onClick={() => onDismiss(notice.id)}
              className="shrink-0 rounded border border-border px-2 py-0.5 text-xs text-text hover:bg-ground focus-visible:outline-2 focus-visible:outline-text"
            >
              {S.soar.notice.dismiss}
            </button>
          </li>
        ))}
      </ul>
      {more > 0 && <p className="text-xs text-muted">{S.soar.notice.more(more)}</p>}
      <p className="text-xs text-muted">{S.soar.notice.sessionHint}</p>
    </section>
  );
}
