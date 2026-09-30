// Every time the UI shows is in Asia/Ho_Chi_Minh (+07), whatever zone the browser is in (spec §4).
export const DISPLAY_TZ = "Asia/Ho_Chi_Minh";

const MISSING = "—";

// `hourCycle: "h23"`, not `hour12: false`: some ICU builds print midnight as "24:05" for the latter.
const formatter = new Intl.DateTimeFormat("vi-VN", {
  timeZone: DISPLAY_TZ,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
});

// A timestamp with no zone designator would be read in the browser's zone, the very thing this file
// exists to avoid. The backend stores UTC, so such a value is UTC.
const NO_ZONE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/;

type Parts = Record<string, string>;

function partsOf(iso: string): Parts | null {
  const date = new Date(NO_ZONE.test(iso) ? `${iso.replace(" ", "T")}Z` : iso);
  if (Number.isNaN(date.getTime())) return null;
  const parts: Parts = {};
  for (const part of formatter.formatToParts(date)) parts[part.type] = part.value;
  return parts;
}

/** "30/09 09:31" — the day and month, then the time. A missing value is "—"; an unreadable one is shown as it came. */
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return MISSING;
  const p = partsOf(iso);
  return p ? `${p.day}/${p.month} ${p.hour}:${p.minute}` : iso;
}

/** "30/09/2026 09:31:02". A missing value is "—"; an unreadable one is shown as it came. */
export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return MISSING;
  const p = partsOf(iso);
  return p ? `${p.day}/${p.month}/${p.year} ${p.hour}:${p.minute}:${p.second}` : iso;
}
