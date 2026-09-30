// What a page shows when it could not get what it is about: a title, a way back to the queue, and, for a
// failure that may pass (a 5xx, the network), a button to ask again. A thing that is not there (a 404) has
// no retry, and is not announced as an alert: nothing went wrong, there is just nothing here.
import { Link } from "react-router";
import { S } from "../strings";

export function PageError({ title, onRetry }: { title: string; onRetry?: () => void }) {
  return (
    <div role={onRetry ? "alert" : undefined} className="space-y-3">
      <h1 className="text-lg font-semibold">{title}</h1>
      <div className="flex items-center gap-4 text-sm">
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="rounded border border-border px-3 py-1 hover:bg-surface focus-visible:outline-2 focus-visible:outline-text"
          >
            {S.common.retry}
          </button>
        )}
        <Link
          to="/queue"
          className="underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-text"
        >
          {S.nav.queue}
        </Link>
      </div>
    </div>
  );
}
