// The one clock of the SOAR page: the instant "now" as a number, read again every second, so every countdown and every
// "reminder is due" of the table moves together from one timer and not one per row. The reading is injectable (`now`), so
// a test fixes it. Nothing here is a live region: a countdown is text that changes, and no screen reader is told of it.
import { createContext, useContext, useEffect, useState, type ReactNode } from "react";

const ClockContext = createContext<number>(0);

/** The instant the page is drawn for, in milliseconds. */
export function useNowMs(): number {
  return useContext(ClockContext);
}

export function SoarClock({ now, children }: { now: () => number; children: ReactNode }) {
  const [at, setAt] = useState(() => now());
  useEffect(() => {
    const timer = setInterval(() => setAt(now()), 1000);
    return () => clearInterval(timer);
  }, [now]);
  return <ClockContext.Provider value={at}>{children}</ClockContext.Provider>;
}
