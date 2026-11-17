// The columns of the IOC table: when it was first seen (GMT+7), the source, the type, the value (defanged, as text, the one button that
// opens the detail panel), the malware, the confidence (a dash when the feed gave none, never 0), the first tags, and the copy button.
// Every text is a React text child printed through `shown`, never markup. A value can be 2 048 bytes: its cell has a width it cannot be
// pushed past, wraps anywhere, and is cut to a few lines (the whole value is in the detail panel), so the table scrolls and the page
// does not break.
import type { MouseEvent } from "react";
import type { TiIoc } from "../../api/ti";
import type { Column } from "../../components/DataTable";
import { formatTime } from "../../format";
import { S, labelOf } from "../../strings";
import { CopyButton } from "./CopyButton";
import { shown, shownValue } from "./display";

/** Whole class names: a wrapping cell of a width that cannot be pushed wider by what it holds. */
const WRAP = "max-w-56 wrap-anywhere";
const VALUE_CELL = "max-w-md min-w-48 wrap-anywhere";
const TAGS_SHOWN = 3;

export type OpenDetail = (ioc: TiIoc, opener: HTMLElement) => void;

const orDash = (text: string | null): string =>
  text === null || text === "" ? S.common.missing : shown(text);

export function tiColumns(parts: { onOpen: OpenDetail }): Column<TiIoc>[] {
  return [
    {
      id: "time",
      header: S.ti.col.time,
      className: "whitespace-nowrap",
      cell: (row) => formatTime(row.first_seen),
    },
    {
      id: "source",
      header: S.ti.col.source,
      className: "whitespace-nowrap",
      cell: (row) => shown(labelOf(S.ti.source, row.source)),
    },
    {
      id: "type",
      header: S.ti.col.type,
      className: WRAP,
      cell: (row) => <span className="font-mono text-xs">{shown(row.type)}</span>,
    },
    {
      id: "value",
      header: S.ti.col.value,
      className: VALUE_CELL,
      cell: (row) => (
        <button
          type="button"
          aria-label={S.ti.detail.open(row.id)}
          onClick={(event: MouseEvent<HTMLButtonElement>) => parts.onOpen(row, event.currentTarget)}
          className="text-left font-mono text-xs underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-text"
        >
          <span className="line-clamp-3 wrap-anywhere">{shownValue(row)}</span>
        </button>
      ),
    },
    {
      id: "malware",
      header: S.ti.col.malware,
      className: WRAP,
      cell: (row) => orDash(row.malware),
    },
    {
      id: "confidence",
      header: S.ti.col.confidence,
      className: "whitespace-nowrap tabular-nums",
      cell: (row) =>
        typeof row.confidence === "number" ? String(row.confidence) : S.common.missing,
    },
    {
      id: "tags",
      header: S.ti.col.tags,
      className: WRAP,
      cell: (row) => {
        const tags = Array.isArray(row.tags) ? row.tags : [];
        const more = tags.length - TAGS_SHOWN;
        return (
          <div className="flex flex-wrap gap-1">
            {tags.slice(0, TAGS_SHOWN).map((tag, index) => (
              <span
                key={index}
                className="rounded border border-border px-1.5 text-xs wrap-anywhere"
              >
                {shown(tag)}
              </span>
            ))}
            {more > 0 && <span className="text-xs text-muted">{S.ti.moreTags(more)}</span>}
          </div>
        );
      },
    },
    {
      id: "copy",
      header: S.ti.col.copy,
      cell: (row) => <CopyButton value={row.value} id={row.id} />,
    },
  ];
}
