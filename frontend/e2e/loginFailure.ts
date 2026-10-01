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
 * Runs `step` (the submit of a login form and the wait for what follows it). When it fails, empties `field`
 * and then rethrows that same error. A field that cannot be emptied (the page moved on or closed) is not a
 * second failure: the step's own is the one the test reports.
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
    throw error;
  }
}
