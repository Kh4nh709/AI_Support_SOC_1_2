// The confirmation dialog of the admin console (spec §3): a modal over a fixed overlay, with no portal
// library and no change to the CSP. A page mounts it while it is open and unmounts it to close it:
//
//   {pending && (
//     <ConfirmDialog title="Vô hiệu hoá tuan.t1?" confirmLabel="Vô hiệu hoá" tone="danger"
//                    busy={mutation.isPending} error={errorText}
//                    onConfirm={() => mutation.mutate()} onCancel={() => setPending(null)}>
//       Lê Tuấn bị đăng xuất ngay.
//     </ConfirmDialog>
//   )}
//
// What it does for the page:
//   - `role="dialog"`, `aria-modal="true"`, named by its title through `aria-labelledby` and described by
//     its body through `aria-describedby` (set only when there are children);
//   - focus: on open it moves to the cancel button of a `danger` dialog (a destructive action is never one
//     Enter away) and to the confirm button of a `primary` one, unless a field of the children already took
//     it (an `autoFocus` input); on close it returns to the element that had it when the dialog mounted,
//     if that element is still on the page;
//   - Tab and Shift+Tab stay inside the dialog, wherever the focus was, even when it was lost to the page;
//   - Esc cancels, unless the dialog is `busy`; a click on the overlay does not (a mistaken click must not
//     throw away what an admin typed);
//   - `busy` disables both buttons and swaps the confirm label for `S.admin.common.working` with
//     `aria-busy`, so a write in flight is neither pressed twice nor called off;
//   - `error` (a text or a node) is shown inside the dialog with `role="alert"`; the buttons stay usable, so
//     the admin can try again or give up. The dialog never closes by itself: the page does, on success.
//
// Two switches beyond the card's list, both optional (a page task needs them; the canvas draws both):
//   - `confirmDisabled`: the confirm button cannot be pressed yet (a form inside is not valid);
//   - `hideConfirm`: no confirm button, only the cancel one, worded `cancelLabel` ("Đóng"), for a refusal the
//     admin can only read (`409 last_active_admin`, AdminStates).
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { S } from "../../strings";

export type ConfirmDialogProps = {
  /** The heading, and the dialog's accessible name. */
  title: string;
  /** The body: what will happen. Rendered as given. */
  children?: ReactNode;
  confirmLabel: string;
  /** Default `S.admin.common.cancel` ("Huỷ"). */
  cancelLabel?: string;
  /** `danger` (red; the focus opens on cancel) or `primary` (blue; the focus opens on confirm). Default `primary`. */
  tone?: "danger" | "primary";
  /** A write is in flight. */
  busy?: boolean;
  /** The failure of the write, or any notice the admin must read before going on. */
  error?: ReactNode;
  /** The confirm button is shown but cannot be pressed. */
  confirmDisabled?: boolean;
  /** No confirm button. */
  hideConfirm?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
};

/** What Tab can reach: links, buttons, fields, anything with a tabindex. Disabled and `tabindex=-1` are dropped below. */
const FOCUSABLE =
  'a[href], area[href], button, input:not([type="hidden"]), select, textarea, summary, [tabindex], [contenteditable="true"]';

function focusables(box: HTMLElement): HTMLElement[] {
  return [...box.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
    (el) =>
      el.tabIndex >= 0 &&
      !(el as HTMLButtonElement).disabled &&
      el.closest("[hidden], [inert]") === null,
  );
}

/** Keeps a Tab press inside `box`: wraps at either end, and takes the focus back when it is outside. */
function trapTab(box: HTMLElement, event: KeyboardEvent): void {
  const items = focusables(box);
  const first = items[0];
  const last = items[items.length - 1];
  if (first === undefined || last === undefined) {
    // Nothing to land on (every button is disabled while busy): the dialog itself holds the focus.
    event.preventDefault();
    box.focus();
    return;
  }
  const active = document.activeElement;
  const index = active instanceof HTMLElement ? items.indexOf(active) : -1;
  if (index === -1) {
    event.preventDefault(); // the focus is on the page, on the dialog itself, or on something now disabled
    (event.shiftKey ? last : first).focus();
  } else if (event.shiftKey && active === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && active === last) {
    event.preventDefault();
    first.focus();
  }
}

export function ConfirmDialog(props: ConfirmDialogProps) {
  const {
    title,
    children,
    confirmLabel,
    cancelLabel,
    tone = "primary",
    busy = false,
    error,
    confirmDisabled = false,
    hideConfirm = false,
    onConfirm,
    onCancel,
  } = props;
  const titleId = useId();
  const bodyId = useId();
  const boxRef = useRef<HTMLDivElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  // Who had the focus when the dialog mounted, and which button it should open on: both are read once,
  // while the dialog is being built, before its own children can take the focus.
  const [opener] = useState<Element | null>(() => document.activeElement);
  const [opensOnConfirm] = useState(() => tone === "primary" && !confirmDisabled && !hideConfirm);
  // The listener below is bound once and must see the current values.
  const latest = useRef({ busy, onCancel });
  useEffect(() => {
    latest.current = { busy, onCancel };
  });

  useEffect(() => {
    const box = boxRef.current;
    if (box === null) return;
    if (!box.contains(document.activeElement)) {
      const button = opensOnConfirm ? confirmRef.current : cancelRef.current;
      (button !== null && !button.disabled ? button : box).focus();
    }
    return () => {
      // StrictMode runs this cleanup with the dialog still on the page: that is not a close.
      if (box.isConnected) return;
      if (opener instanceof HTMLElement && opener !== document.body && opener.isConnected) {
        opener.focus();
      }
    };
  }, [opener, opensOnConfirm]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const box = boxRef.current;
      if (box === null || event.defaultPrevented) return;
      if (event.key === "Escape") {
        if (latest.current.busy) return;
        event.preventDefault();
        latest.current.onCancel();
      } else if (event.key === "Tab") {
        trapTab(box, event);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  const hasError = error !== undefined && error !== null && error !== false && error !== "";
  // The body is what a screen reader should hear after the title ("what will happen"), so the dialog is
  // described by it; with no children there is no body to point at.
  const hasBody =
    children !== undefined && children !== null && children !== false && children !== "";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div
        ref={boxRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={hasBody ? bodyId : undefined}
        tabIndex={-1}
        className="flex w-full max-w-md flex-col gap-3 rounded-xl border border-console-outline-strong bg-console-dialog p-[18px] shadow-xl focus:outline-none"
      >
        <h2 id={titleId} className="text-[17px] font-semibold">
          {title}
        </h2>
        {hasBody && (
          <div id={bodyId} className="space-y-2 text-[13.5px] leading-relaxed text-console-body">
            {children}
          </div>
        )}
        {hasError && (
          <div
            role="alert"
            className="rounded-lg border border-console-danger-outline bg-critical-bg px-3.5 py-3 text-[13.5px] leading-snug text-console-danger-text"
          >
            {error}
          </div>
        )}
        <div className="flex justify-end gap-2">
          <button
            ref={cancelRef}
            type="button"
            disabled={busy}
            onClick={onCancel}
            className="h-10 rounded-lg border border-console-outline px-3.5 text-sm text-console-body hover:bg-ground focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text disabled:opacity-50"
          >
            {cancelLabel ?? S.admin.common.cancel}
          </button>
          {!hideConfirm && (
            <button
              ref={confirmRef}
              type="button"
              disabled={busy || confirmDisabled}
              aria-busy={busy || undefined}
              onClick={onConfirm}
              className={`h-10 rounded-lg px-3.5 text-sm font-semibold text-white focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text disabled:opacity-60 ${
                tone === "danger" ? "bg-red-600 hover:bg-red-500" : "bg-blue-600 hover:bg-blue-500"
              }`}
            >
              {busy ? S.admin.common.working : confirmLabel}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
