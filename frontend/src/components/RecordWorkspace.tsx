import {
  useId,
  useRef,
  useState,
  useSyncExternalStore,
  type MouseEvent,
  type ReactNode,
} from "react";
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

// A plain click anywhere on a card, its title link included, previews that record. A click with a modifier
// key (open in a new tab), a click on another control, a keyboard "click" (Enter on the link, `detail` 0)
// and the end of a text selection keep their own meaning.
function previewCard(event: MouseEvent<HTMLElement>) {
  const target = event.target as Element;
  if (
    event.button !== 0 ||
    event.ctrlKey ||
    event.metaKey ||
    event.shiftKey ||
    event.altKey ||
    event.detail === 0 ||
    target.closest("button, input, select, textarea") ||
    !(window.getSelection()?.isCollapsed ?? true)
  ) {
    return;
  }
  const pick = target
    .closest("[data-record]")
    ?.querySelector<HTMLButtonElement>("button[data-record-pick]");
  if (!pick) return;
  event.preventDefault();
  pick.click();
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

  // The card itself is what a pointer picks (`previewCard`), so the button is not drawn: it stays for the
  // keyboard and the screen reader, and the card is outlined while it has focus.
  function select(row: T) {
    return (
      <button
        type="button"
        data-record-pick=""
        aria-label={S.workspace.previewRow(title(row))}
        aria-pressed={rowKey(row) === selectedKey}
        onClick={() => {
          setSelection(rowKey(row));
          if (narrow) {
            requestAnimationFrame(() => previewSection.current?.focus());
          }
        }}
        className="sr-only"
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
    <div className="soc-record-layout" onClickCapture={previewCard}>
      {list(selectedKey, select, (row) =>
        narrow && rowKey(row) === selectedKey ? preview(row) : null,
      )}
      {!narrow && picked !== undefined && preview(picked)}
    </div>
  );
}
