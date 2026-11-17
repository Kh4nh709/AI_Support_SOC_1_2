// The copy button of a row and of the detail panel: it copies the ORIGINAL value of the IOC (what the feed gave and the importer
// stored), never the defanged text that is on screen. The clipboard API exists only on a secure origin and may be refused, and this
// console is also served over plain http on the LAN: when the API is missing or refuses, the original value is put in a read-only box,
// selected and focused, and `execCommand("copy")` is tried on that selection; if even that is not allowed, the value stays selected
// for Ctrl+C. The box is inert text: the value is never a link, never fetched, and closes when the box loses the focus.
import { useCallback, useEffect, useRef, useState } from "react";
import { S } from "../../strings";

const COPIED_MS = 2000;
const BUTTON =
  "rounded border border-border px-2 py-0.5 text-xs hover:bg-ground focus-visible:outline-2 focus-visible:outline-text";

/** Whether the clipboard API took the text; false when there is none, or it refused. */
async function writeClipboard(text: string): Promise<boolean> {
  try {
    if (typeof navigator === "undefined" || typeof navigator.clipboard?.writeText !== "function") {
      return false;
    }
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function CopyButton({ value, id }: { value: string; id: number }) {
  const [state, setState] = useState<"idle" | "copied" | "select">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  const copied = useCallback(() => {
    setState("copied");
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setState("idle"), COPIED_MS);
  }, []);

  async function copy() {
    if (await writeClipboard(value)) copied();
    else setState("select");
  }

  // The fallback box has the focus and its text selected as soon as it is on the page (a ref callback of a fixed identity runs once, when
  // the box is mounted, so a later render never undoes what the person selects); the browser may still copy that selection.
  const attach = useCallback(
    (input: HTMLInputElement | null) => {
      if (input === null) return;
      input.focus();
      input.select();
      let done: boolean;
      try {
        done = typeof document.execCommand === "function" && document.execCommand("copy");
      } catch {
        done = false;
      }
      if (done) copied();
    },
    [copied],
  );

  return (
    <div className="flex flex-col items-start gap-1">
      <button
        type="button"
        aria-label={S.ti.copy.label(id)}
        onClick={() => void copy()}
        className={BUTTON}
      >
        {S.ti.copy.button}
      </button>
      <span aria-live="polite" className="text-xs text-low">
        {state === "copied" ? S.ti.copy.copied : ""}
      </span>
      {state === "select" && (
        <>
          <input
            ref={attach}
            readOnly
            value={value}
            aria-label={S.ti.copy.boxLabel}
            onBlur={() => setState("idle")}
            className="w-56 max-w-full rounded border border-border bg-ground px-2 py-1 font-mono text-xs text-text focus-visible:outline-2 focus-visible:outline-text"
          />
          <span role="status" className="text-xs text-muted">
            {S.ti.copy.fallback}
          </span>
        </>
      )}
    </div>
  );
}
