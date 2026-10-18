// The "more actions" of a table row (P11-T12, spec §4.2: "a row menu also offers Vô hiệu hoá"): a small button
// that shows the row's less common actions in place, under the row's main button. It is a disclosure (a
// button with `aria-expanded` that controls the list it shows), not an ARIA `menu`: the list is a few
// ordinary buttons in the page's flow, so it needs no arrow-key model, and it cannot be clipped by the
// table's own scroll area the way a floating panel would be.
//
//   - Enter or a click opens it and puts the focus on the first action; Escape closes it and puts the
//     focus back on the button; a press elsewhere, or Tab out of it, closes it;
//   - choosing an action closes the list and puts the focus back on the button first, so a dialog the
//     action opens returns the focus there when it closes (`ConfirmDialog` remembers who had it).
import {
  useEffect,
  useId,
  useRef,
  useState,
  type FocusEvent,
  type KeyboardEvent,
  type ReactNode,
} from "react";

export type RowMenuItem = {
  id: string;
  /** The visible text. */
  label: string;
  /** The accessible name, which starts with the visible text and names the row it acts on. */
  ariaLabel: string;
  onSelect: () => void;
};

const BUTTON =
  "h-[34px] rounded-md border border-[#2e3a48] px-3 text-[13px] text-[#c9d3df] hover:bg-ground focus-visible:outline-2 focus-visible:outline-text disabled:cursor-not-allowed disabled:opacity-50";

export function RowMenu({
  label,
  items,
  leading,
  disabled = false,
  title,
}: {
  /** The accessible name of the button ("Thêm thao tác cho lan.t1"). */
  label: string;
  items: readonly RowMenuItem[];
  /** The row's main button, drawn on the same line before the "more" button. A press on it closes the list. */
  leading?: ReactNode;
  /** The button cannot be pressed (the row is the caller's own). */
  disabled?: boolean;
  /** What a pointer over the disabled button reads: why it is disabled. */
  title?: string;
}) {
  const [open, setOpen] = useState(false);
  const listId = useId();
  const list = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const first = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    first.current?.focus();
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (!button.current?.contains(target) && !list.current?.contains(target)) setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (!open) return;
    if (event.key === "Escape") {
      // Not for the page's other listeners: a dialog's Escape is not this one's.
      event.stopPropagation();
      setOpen(false);
      button.current?.focus();
    }
  };

  // The focus moved to another element of the page (Tab): the list is closed, and the focus is left where it went.
  // A blur with no element to go to (a click on plain text, or the window losing focus) says nothing: the
  // pointer rule above closes the list for a press elsewhere, and Safari does not focus a button it was clicked on.
  const onBlur = (event: FocusEvent<HTMLDivElement>) => {
    const next = event.relatedTarget;
    if (next instanceof Node && !event.currentTarget.contains(next)) setOpen(false);
  };

  return (
    <div onKeyDown={onKeyDown} onBlur={onBlur} className="flex flex-col items-end gap-1.5">
      <div className="flex items-center gap-2">
        {leading}
        <button
          ref={button}
          type="button"
          aria-label={label}
          aria-expanded={open}
          aria-controls={open ? listId : undefined}
          disabled={disabled}
          title={disabled ? title : undefined}
          onClick={() => setOpen((current) => !current)}
          className={`${BUTTON} w-[34px] px-0`}
        >
          <span aria-hidden="true">⋯</span>
        </button>
      </div>
      {open && (
        <div ref={list} id={listId} className="flex flex-col items-end gap-1.5">
          {items.map((item, index) => (
            <button
              key={item.id}
              ref={index === 0 ? first : undefined}
              type="button"
              aria-label={item.ariaLabel}
              className={BUTTON}
              onClick={() => {
                setOpen(false);
                button.current?.focus();
                item.onSelect();
              }}
            >
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
