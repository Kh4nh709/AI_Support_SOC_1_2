// A log as text (Review Focus 1): the whole string is ONE text node of ONE <pre>, so a log of 200 KB is
// the same handful of elements as a log of one line, and nothing in it (a tag, </script>, an escape, a
// right-to-left override) is ever read as anything but characters. The box scrolls; it is focusable, so a
// keyboard user can scroll it. The copy button writes the text to the clipboard; a refusal is not an error.
import { useEffect, useRef, useState } from "react";
import { S } from "../strings";

const COPIED_MS = 2000;

export function LogBlock({
  text,
  truncated = false,
  label,
}: {
  text: string;
  truncated?: boolean;
  /**
   * What the block is, for the screen reader: the raw log when none is given, a payload where the audit page
   * shows one. A block that is given one also names its copy button after it ("Sao chép: <label>"), because
   * several may be on a page; the raw log's button stays "Sao chép".
   */
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      return; // the browser refused (no permission, no secure context): nothing was copied, nothing to say
    }
    setCopied(true);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(false), COPIED_MS);
  }

  return (
    <div className="space-y-2">
      <pre
        tabIndex={0}
        role="region"
        aria-label={label ?? S.alert.rawLog}
        className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded border border-border bg-ground p-3 font-mono text-xs focus-visible:outline-2 focus-visible:outline-text"
      >
        {text}
      </pre>
      <div className="flex items-center gap-3 text-xs">
        <button
          type="button"
          aria-label={label === undefined ? undefined : `${S.common.copy}: ${label}`}
          onClick={() => void copy()}
          className="rounded border border-border px-2 py-1 hover:bg-ground focus-visible:outline-2 focus-visible:outline-text"
        >
          {S.common.copy}
        </button>
        <span aria-live="polite" className="text-muted">
          {copied ? S.common.copied : ""}
        </span>
        {truncated && <span className="text-medium">{S.alert.rawLogTruncated}</span>}
      </div>
    </div>
  );
}
