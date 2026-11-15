// The tab strip under the tiles: a real tablist (WAI-ARIA tabs with automatic activation). One tab stop: the open tab
// is the only one in the Tab order, and the arrow keys, Home and End move between the tabs and open the one they land
// on. Only the open tab's panel is drawn. Which tab is open is this component's own state, so a new mount, a page
// load or another run starts on the first tab. The strip scrolls sideways when its labels do not fit the column (they
// leave no slack at 486 px): a tab keeps its width, and the strip never clips a tab or widens the page.
import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { FOCUS } from "./styles";

export type TabDef = { id: string; label: string; content: ReactNode };

export function Tabs({ label, tabs }: { label: string; tabs: readonly TabDef[] }) {
  const base = useId();
  const [picked, setPicked] = useState<string | null>(null);
  const buttons = useRef(new Map<string, HTMLButtonElement>());
  // A tab that is no longer in the list is not open: the first one is.
  const open = tabs.find((tab) => tab.id === picked) ?? tabs[0];
  if (open === undefined) return null;

  const go = (index: number): void => {
    const next = tabs[(index + tabs.length) % tabs.length];
    if (next === undefined) return;
    setPicked(next.id);
    buttons.current.get(next.id)?.focus();
  };

  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number): void => {
    switch (event.key) {
      case "ArrowRight":
        go(index + 1);
        break;
      case "ArrowLeft":
        go(index - 1);
        break;
      case "Home":
        go(0);
        break;
      case "End":
        go(tabs.length - 1);
        break;
      default:
        return;
    }
    event.preventDefault();
  };

  const tabId = (id: string): string => `${base}-tab-${id}`;
  const panelId = (id: string): string => `${base}-panel-${id}`;

  return (
    <div className="space-y-3.5">
      <div
        role="tablist"
        aria-label={label}
        className="flex max-w-full gap-1 overflow-x-auto border-b border-border"
      >
        {tabs.map((tab, index) => {
          const selected = tab.id === open.id;
          return (
            <button
              key={tab.id}
              ref={(node) => {
                if (node === null) buttons.current.delete(tab.id);
                else buttons.current.set(tab.id, node);
              }}
              type="button"
              role="tab"
              id={tabId(tab.id)}
              aria-selected={selected}
              aria-controls={selected ? panelId(tab.id) : undefined}
              tabIndex={selected ? 0 : -1}
              onClick={() => setPicked(tab.id)}
              onKeyDown={(event) => onKeyDown(event, index)}
              className={`min-h-[44px] shrink-0 border-b-2 px-3 text-sm whitespace-nowrap ${FOCUS} ${
                selected
                  ? "border-ai-accent font-semibold text-text"
                  : "border-transparent font-medium text-muted hover:text-text"
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
      <div
        role="tabpanel"
        id={panelId(open.id)}
        aria-labelledby={tabId(open.id)}
        tabIndex={0}
        className={`rounded ${FOCUS}`}
      >
        {open.content}
      </div>
    </div>
  );
}
