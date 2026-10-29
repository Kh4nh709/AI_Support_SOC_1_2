// The "Phân tích gần nhất" of the case page and of the case list, in one place so that one column title
// has one meaning (INT-T02 and its fix round 1): the time of the newest ② run, with "không có kết quả" when
// that run stopped without a result. `last_analyzed_at` only moves when a run has one, so reading it alone
// said "chưa phân tích" about a case ② had been run on (a provider 402 ends a run `permanent`, with none).
import type { CaseLastRun } from "../../api/tier2";
import { S } from "../../strings";

/**
 * `format` writes a time the way the place wants it (the page: the date and the time to the second; the list:
 * the day, the month and the minute). An answer with no `last_run` (an older server) is read as
 * `last_analyzed_at` was: its time, or "chưa phân tích" for none.
 */
export function lastAnalysedText(
  source: { last_run?: CaseLastRun | null; last_analyzed_at: string | null },
  format: (iso: string) => string,
): string {
  const run = source.last_run ?? null;
  if (run !== null) {
    const when = format(run.created_at);
    return run.has_result ? when : `${when} — ${S.case.noResult}`;
  }
  return source.last_analyzed_at === null ? S.case.neverAnalysed : format(source.last_analyzed_at);
}
