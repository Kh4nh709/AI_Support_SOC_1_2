import { useId, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import { Link } from "react-router";
import { S } from "../strings";

const NARROW = "(width < 48rem)";

function watchWidth(onChange: () => void) {
  const viewport = window.matchMedia?.(NARROW);
  viewport?.addEventListener("change", onChange);
  return () => viewport?.removeEventListener("change", onChange);
}

function isNarrow() {
  return window.matchMedia?.(NARROW).matches ?? false;
}

export type PickRecord<T> = (row: T) => ReactNode;

export function RecordWorkspace<T>({
  rows,
  rowKey,
  title,
  href,
  action,
  fields,
  list,
}: {
  rows: readonly T[];
  rowKey: (row: T) => string;
  title: (row: T) => string;
  href: (row: T) => string;
  action: string;
  fields: (row: T) => ReadonlyArray<readonly [string, ReactNode]>;
  list: (
    picked: string | undefined,
    select: PickRecord<T>,
    inline: (row: T) => ReactNode,
  ) => ReactNode;
}) {
  const [selection, setSelection] = useState<string>();
  const picked = rows.find((row) => rowKey(row) === selection) ?? rows[0];
  const selectedKey = picked === undefined ? undefined : rowKey(picked);
  const heading = useId();
  const previewSection = useRef<HTMLElement>(null);
  const narrow = useSyncExternalStore(watchWidth, isNarrow, () => false);

  function select(row: T) {
    return (
      <button
        type="button"
        aria-label={S.workspace.previewRow(title(row))}
        aria-pressed={rowKey(row) === selectedKey}
        onClick={() => {
          setSelection(rowKey(row));
          if (narrow) {
            requestAnimationFrame(() => previewSection.current?.focus());
          }
        }}
        className="shrink-0 rounded-md border border-border px-2 py-1 text-xs font-medium text-muted hover:border-ai-accent hover:text-text focus-visible:outline-2 focus-visible:outline-ai-accent"
      >
        {S.workspace.preview}
      </button>
    );
  }

  function preview(row: T) {
    return (
      <section
        ref={previewSection}
        aria-labelledby={heading}
        tabIndex={-1}
        className="min-w-0 space-y-3 rounded-xl border border-border bg-surface px-4 py-3 focus-visible:outline-2 focus-visible:outline-ai-accent"
      >
        <h2 id={heading} className="text-sm font-semibold">
          {S.workspace.preview}
        </h2>
        <h3 className="text-base font-semibold [overflow-wrap:anywhere]">{title(row)}</h3>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
          {fields(row).map(([label, value]) => (
            <div key={label} className="min-w-0 [overflow-wrap:anywhere]">
              <dt className="text-xs text-muted">{label}</dt>
              <dd className="mt-0.5">{value}</dd>
            </div>
          ))}
        </dl>
        <Link
          className="inline-flex min-h-9 items-center rounded-lg bg-ai-accent px-3 text-sm font-semibold text-ground hover:bg-ai-accent/90 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ai-accent"
          to={href(row)}
        >
          {action}
        </Link>
      </section>
    );
  }

  return (
    <div className="soc-record-layout">
      {list(selectedKey, select, (row) =>
        narrow && rowKey(row) === selectedKey ? preview(row) : null,
      )}
      {!narrow && picked !== undefined && preview(picked)}
    </div>
  );
}
