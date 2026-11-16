// The columns of the two tables of the page: the review tickets (time, case, scenario, host, target, action, score,
// status, and the buttons) and the notices. Every value n8n wrote is a React text child, never markup, and a cell that
// holds one wraps a long value inside itself (`wrap-anywhere`, a column width) so the table scrolls and the page does not.
import type { MouseEvent } from "react";
import type { SoarDecision, SoarReview } from "../../api/soar";
import type { Column } from "../../components/DataTable";
import { formatTime } from "../../format";
import { S, labelOf } from "../../strings";
import { SCORE_CLASS, actionTextOf, scoreTone, statusText } from "./model";
import { RowActions } from "./RowActions";
import { RowTimers } from "./Timers";
import type { RowState } from "./useDecisions";

const text = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== "" ? value : null;
const orDash = (value: unknown): string => text(value) ?? S.common.missing;

/** Whole class names: a wrapping cell of a width that cannot be pushed wider by what it holds. */
const WRAP = "max-w-56 wrap-anywhere";

export type OpenDetail = (id: string, opener: HTMLElement) => void;

export function reviewColumns(parts: {
  states: Readonly<Record<string, RowState>>;
  onPress: (row: SoarReview, decision: SoarDecision) => void;
  onOpen: OpenDetail;
}): Column<SoarReview>[] {
  return [
    {
      id: "id",
      header: S.soar.col.id,
      className: WRAP,
      cell: (row) => (
        <button
          type="button"
          aria-label={S.soar.detail.open(row.id)}
          onClick={(event: MouseEvent<HTMLButtonElement>) =>
            parts.onOpen(row.id, event.currentTarget)
          }
          className="text-left font-mono text-xs underline underline-offset-2 wrap-anywhere focus-visible:outline-2 focus-visible:outline-text"
        >
          {row.id}
        </button>
      ),
    },
    {
      id: "time",
      header: S.soar.col.time,
      className: "whitespace-nowrap",
      cell: (row) => formatTime(row.created_at),
    },
    {
      id: "case",
      header: S.soar.col.case,
      className: "whitespace-nowrap",
      cell: (row) =>
        typeof row.case_number === "number" ? S.soar.caseNumber(row.case_number) : S.common.missing,
    },
    {
      id: "scenario",
      header: S.soar.col.scenario,
      className: WRAP,
      cell: (row) => text(row.scenario_name) ?? orDash(row.scenario_id),
    },
    { id: "host", header: S.soar.col.host, className: WRAP, cell: (row) => orDash(row.host) },
    {
      id: "target",
      header: S.soar.col.target,
      className: `${WRAP} font-mono text-xs`,
      cell: (row) => orDash(row.action_target),
    },
    {
      id: "action",
      header: S.soar.col.action,
      className: WRAP,
      cell: (row) => (
        <>
          <span>{actionTextOf(row)}</span>
          {row.simulated === true && (
            <span className="ml-2 inline-block rounded border border-medium px-1.5 text-xs font-semibold text-medium">
              {S.soar.simulated}
            </span>
          )}
        </>
      ),
    },
    {
      id: "score",
      header: S.soar.col.score,
      cell: (row) =>
        typeof row.score === "number" && Number.isFinite(row.score) ? (
          <span
            className={`inline-block rounded border px-2 py-0.5 text-xs font-medium tabular-nums ${SCORE_CLASS[scoreTone(row.score)]}`}
          >
            {row.score}
          </span>
        ) : (
          S.common.missing
        ),
    },
    {
      id: "status",
      header: S.soar.col.status,
      className: WRAP,
      cell: (row) => (
        <>
          <span>{statusText(row)}</span>
          <RowTimers row={row} />
        </>
      ),
    },
    {
      id: "actions",
      header: S.soar.col.actions,
      className: WRAP,
      cell: (row) => <RowActions row={row} state={parts.states[row.id]} onPress={parts.onPress} />,
    },
  ];
}

/** The word of a notice's severity, in its colour: error red, warning orange, anything else (info) grey. */
export const SEVERITY_WORD: Record<string, string> = {
  error: "text-critical",
  warning: "text-high",
};
export const severityWordClass = (severity: unknown): string =>
  typeof severity === "string" && Object.hasOwn(SEVERITY_WORD, severity)
    ? (SEVERITY_WORD[severity] as string)
    : "text-muted";

export function noticeColumns(parts: {
  dismissed: ReadonlySet<string>;
  onDismiss: (id: string) => void;
  onOpen: OpenDetail;
}): Column<SoarReview>[] {
  return [
    {
      id: "time",
      header: S.soar.col.time,
      className: "whitespace-nowrap",
      cell: (row) => formatTime(row.created_at),
    },
    {
      id: "severity",
      header: S.soar.col.severity,
      className: "whitespace-nowrap",
      cell: (row) => (
        <span className={`font-medium ${severityWordClass(row.severity)}`}>
          {labelOf(S.soar.severity, row.severity)}
        </span>
      ),
    },
    {
      id: "title",
      header: S.soar.col.title,
      className: WRAP,
      cell: (row) => (
        <button
          type="button"
          onClick={(event: MouseEvent<HTMLButtonElement>) =>
            parts.onOpen(row.id, event.currentTarget)
          }
          className="text-left underline underline-offset-2 wrap-anywhere focus-visible:outline-2 focus-visible:outline-text"
        >
          {orDash(row.title)}
        </button>
      ),
    },
    { id: "note", header: S.soar.col.note, className: WRAP, cell: (row) => orDash(row.note) },
    { id: "host", header: S.soar.col.host, className: WRAP, cell: (row) => orDash(row.host) },
    {
      id: "case",
      header: S.soar.col.case,
      className: "whitespace-nowrap",
      cell: (row) =>
        typeof row.case_number === "number" ? S.soar.caseNumber(row.case_number) : S.common.missing,
    },
    {
      id: "shown",
      header: S.soar.col.shown,
      className: "whitespace-nowrap",
      cell: (row) =>
        parts.dismissed.has(row.id) ? (
          <span className="text-muted">{S.soar.notice.dismissed}</span>
        ) : (
          <button
            type="button"
            aria-label={S.soar.notice.dismissLabel(row.id)}
            onClick={() => parts.onDismiss(row.id)}
            className="rounded border border-border px-2 py-0.5 text-xs hover:bg-surface focus-visible:outline-2 focus-visible:outline-text"
          >
            {S.soar.notice.dismiss}
          </button>
        ),
    },
  ];
}
