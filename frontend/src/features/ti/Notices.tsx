// What a section of the page says when its own read did not give it data. A 503 `{reason: timeout}` is "busy, try again" in the page's
// own words (a status, not an alert: nothing is wrong, the server is slow); a 403 is the web's own refusal text, as the other pages show;
// anything else is the section's error line. Each has a button to ask again. A 401 never gets here for long: the API client hands it to
// the session, which sends the visitor to the login page.
import { ApiError } from "../../api/client";
import { isTiBusy } from "../../api/ti";
import { S } from "../../strings";

const RETRY =
  "rounded border border-current px-2 py-0.5 hover:bg-surface focus-visible:outline-2 focus-visible:outline-text";

export function SectionError({
  error,
  message,
  onRetry,
}: {
  error: unknown;
  /** What this section says for a failure that is not busy and not a refusal. */
  message: string;
  onRetry: () => void;
}) {
  if (error instanceof ApiError && error.status === 403) {
    return (
      <p role="alert" className="rounded border border-high bg-high-bg px-4 py-2 text-sm text-high">
        {S.forbidden}
      </p>
    );
  }
  const slow = isTiBusy(error);
  return (
    <div
      role={slow ? "status" : "alert"}
      className={`flex flex-wrap items-center gap-3 rounded border px-3 py-2 text-sm ${
        slow ? "border-medium text-medium" : "border-critical text-critical"
      }`}
    >
      <span>{slow ? S.ti.busy : message}</span>
      <button type="button" onClick={onRetry} className={RETRY}>
        {S.common.retry}
      </button>
    </div>
  );
}
