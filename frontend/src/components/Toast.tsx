// A note that a thing was done, said politely to a screen reader (role="status") and dismissed with a
// button. It has no timer: the analyst reads it when they are ready, and the fan-out count or the case link
// it carries is not something to lose to a clock.
import type { ReactNode } from "react";
import { S } from "../strings";

export function Toast({ children, onClose }: { children: ReactNode; onClose: () => void }) {
  return (
    <div
      role="status"
      className="flex items-start justify-between gap-3 rounded border border-low bg-low-bg px-3 py-2 text-sm text-low"
    >
      <div className="space-y-1">{children}</div>
      <button
        type="button"
        onClick={onClose}
        className="shrink-0 rounded border border-low px-2 py-0.5 text-xs hover:bg-ground focus-visible:outline-2 focus-visible:outline-text"
      >
        {S.common.close}
      </button>
    </div>
  );
}
