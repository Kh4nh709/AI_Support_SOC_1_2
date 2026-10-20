// What a failed login leaves on the page (P10-T12 parked item, P10-T17). Kept apart from fixtures.ts, which
// needs the scratch stack to be imported, so that Vitest can test it (src/e2eLoginFailure.test.ts).
//
// A test that fails keeps a snapshot of the page (error-context) and a screenshot, taken after the failure:
// a password input is masked in the screenshot, but the snapshot may quote the typed value. A login that did
// not lead home leaves the password in the field, so the field is emptied before the failure is rethrown.
import type { Locator } from "@playwright/test";

/** The part of a Playwright locator this module uses. */
export type Clearable = Pick<Locator, "fill">;

/** Long enough for a field that is there, short enough not to delay the failure of one that is gone. */
const CLEAR_TIMEOUT_MS = 2000;

/**
 * Playwright's matchers (`expect(locator).toBeVisible()`, `expect(page).toHaveURL()`) put a snapshot of the page,
 * taken at the instant they fail, on the error they throw (`matcherResult.ariaSnapshot`), and the report's
 * `error-context.md` is made from that: a field emptied afterwards is in it still, with the value it had. The snapshot
 * is taken off the error here, on the same error object (its message, its stack and its identity are as they were), and
 * the report then takes the snapshot it takes when a test ends, which is after the field has been emptied. (Playwright
 * 1.63 behaves so; before it, only that end-of-test snapshot existed and emptying the field was enough.)
 */
function withoutPageSnapshot(error: unknown): void {
  const result =
    error instanceof Error
      ? (error as { matcherResult?: { ariaSnapshot?: unknown } }).matcherResult
      : undefined;
  if (typeof result === "object" && result !== null) delete result.ariaSnapshot;
}

/**
 * Runs `step` (the submit of a login form and the wait for what follows it, or a create form that types a password).
 * When it fails, empties `field`, takes the matcher's early page snapshot off the error, and then rethrows that same
 * error. A field that cannot be emptied (the page moved on or closed) is not a second failure: the step's own is the
 * one the test reports.
 */
export async function clearingOnFailure<T>(field: Clearable, step: () => Promise<T>): Promise<T> {
  try {
    return await step();
  } catch (error) {
    try {
      await field.fill("", { timeout: CLEAR_TIMEOUT_MS });
    } catch {
      // nothing left to clear
    }
    withoutPageSnapshot(error);
    throw error;
  }
}
