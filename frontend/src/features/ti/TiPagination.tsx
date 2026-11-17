// The pages of the list, as the queue's and the SOAR page's pagination do them: which rows are on screen, previous and next, and the
// numbered links. Each link is an ordinary link to the same view (the filters kept) on another page, so it can be opened in a new tab
// and shared. The numbers of the links are the queue's own (`pageList`).
import { Link } from "react-router";
import { S } from "../../strings";
import { pageList } from "../tier1/queueParams";
import { viewSearch, type TiView } from "./tiParams";

const LINK =
  "rounded border border-border px-2 py-1 text-sm hover:bg-surface focus-visible:outline-2 focus-visible:outline-text";

export function TiPagination({
  view,
  page,
  pageSize,
  total,
}: {
  /** The filters of the view, which every link keeps; its own page is not used (the links name theirs). */
  view: TiView;
  /** The page the answer is for. */
  page: number;
  pageSize: number;
  total: number;
}) {
  const last = Math.max(1, Math.ceil(total / Math.max(pageSize, 1)));
  if (last <= 1 && page <= 1) return null;
  const from = (page - 1) * pageSize + 1;
  return (
    <nav aria-label={S.ti.pagination} className="flex flex-wrap items-center gap-2">
      {total > 0 && from <= total && (
        <p className="mr-2 text-sm text-muted">
          {S.ti.range(from, Math.min(page * pageSize, total), total)}
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
            aria-label={S.ti.page(entry)}
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
