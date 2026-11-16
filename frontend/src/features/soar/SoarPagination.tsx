// The pages of the list, as the queue's pagination does them: which rows are on screen, previous and next, and the
// numbered links. Each link is an ordinary link to the same view (the tab and the search kept) on another page, so it can
// be opened in a new tab and shared. The numbers of the links are the queue's own (`pageList`).
import { Link } from "react-router";
import { S } from "../../strings";
import { pageList } from "../tier1/queueParams";
import { viewSearch, type SoarView } from "./soarParams";

const LINK =
  "rounded border border-border px-2 py-1 text-sm hover:bg-surface focus-visible:outline-2 focus-visible:outline-text";

export function SoarPagination({
  view,
  page,
  pageSize,
  total,
}: {
  /** The tab and the search of the view, which every link keeps; its own page is not used (the links name theirs). */
  view: SoarView;
  /** The page the answer is for. */
  page: number;
  pageSize: number;
  total: number;
}) {
  const last = Math.max(1, Math.ceil(total / Math.max(pageSize, 1)));
  if (last <= 1 && page <= 1) return null;
  const from = (page - 1) * pageSize + 1;
  return (
    <nav aria-label={S.soar.pagination} className="flex flex-wrap items-center gap-2">
      {total > 0 && from <= total && (
        <p className="mr-2 text-sm text-muted">
          {S.soar.range(from, Math.min(page * pageSize, total), total)}
        </p>
      )}
      {page > 1 && (
        <Link
          to={{ search: viewSearch({ ...view, page: Math.min(page - 1, last) }) }}
          className={LINK}
        >
          {S.common.prev}
        </Link>
      )}
      {pageList(page, last).map((entry, index) =>
        entry === "gap" ? (
          <span key={`gap-${index}`} aria-hidden="true" className="px-1 text-muted">
            …
          </span>
        ) : entry === page ? (
          <span
            key={entry}
            aria-current="page"
            className="rounded border border-text px-2 py-1 text-sm font-medium"
          >
            {entry}
          </span>
        ) : (
          <Link
            key={entry}
            to={{ search: viewSearch({ ...view, page: entry }) }}
            aria-label={S.soar.page(entry)}
            className={LINK}
          >
            {entry}
          </Link>
        ),
      )}
      {page < last && (
        <Link to={{ search: viewSearch({ ...view, page: page + 1 }) }} className={LINK}>
          {S.common.next}
        </Link>
      )}
    </nav>
  );
}
