// The queue's view (the filters, the sort and the page) as URL search params: a reload and a link shared to
// another tab keep them (spec §3). Only what differs from the default is written, and only what is
// understood is read: a band that is not one of the four codes, a sort the server does not offer, or a page
// that is not a whole number, is dropped here, so the server never sees it (an empty `band=`, `status=` or
// `sort=` is a 422 there).
//
// The sort (P10-T14, DEC-164) is `sort` and `dir`. The default risk order is the absence of both, so it has
// no value of its own: `QueueView.sort` is undefined then. A sort is always written with its direction.
import {
  SORT_DEFAULT_DIR,
  isSortDir,
  isSortKey,
  type QueueFilters,
  type QueueSort,
  type QueueSortKey,
} from "../../api/tier1";
import { isBandCode } from "../../api/types";

export type QueueView = { filters: QueueFilters; page: number; sort?: QueueSort };

/** The largest page a link may name; a longer number is not a page, and a Number would round it. */
const MAX_PAGE = 1_000_000;

function text(params: URLSearchParams, key: string): string | undefined {
  const value = params.get(key)?.trim();
  return value ? value : undefined;
}

export function readView(params: URLSearchParams): QueueView {
  const band = params.get("band");
  const filters: QueueFilters = { status: params.get("status") === "mine" ? "mine" : "queued" };
  if (isBandCode(band)) filters.band = band;
  const category = text(params, "category");
  if (category !== undefined) filters.category = category;
  const agent = text(params, "agent");
  if (agent !== undefined) filters.agent = agent;
  const raw = params.get("page") ?? "";
  const page = /^[1-9]\d{0,6}$/.test(raw) ? Number(raw) : 1;
  const view: QueueView = { filters, page: Math.min(page, MAX_PAGE) };
  const sort = readSort(params);
  if (sort) view.sort = sort;
  return view;
}

/**
 * The sort of the URL: a key the server offers, with its direction, or the default direction of the key when
 * `dir` is missing or not `asc`/`desc`. `sort=risk` and a `dir` alone are no sort: the risk order has no
 * direction, and the server refuses one.
 */
function readSort(params: URLSearchParams): QueueSort | undefined {
  const key = params.get("sort");
  if (!isSortKey(key)) return undefined;
  const dir = params.get("dir");
  return { key, dir: isSortDir(dir) ? dir : SORT_DEFAULT_DIR[key] };
}

/**
 * The sort after a click on the header of `key`: the key in its default direction, or, on the key that is
 * already sorted, the opposite direction.
 */
export function nextSort(current: QueueSort | undefined, key: QueueSortKey): QueueSort {
  if (current?.key === key) return { key, dir: current.dir === "asc" ? "desc" : "asc" };
  return { key, dir: SORT_DEFAULT_DIR[key] };
}

export function viewToParams({ filters, page, sort }: QueueView): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.band) params.set("band", filters.band);
  if (filters.category) params.set("category", filters.category);
  if (filters.agent) params.set("agent", filters.agent);
  if (filters.status === "mine") params.set("status", "mine");
  if (sort) {
    params.set("sort", sort.key);
    params.set("dir", sort.dir);
  }
  if (page > 1) params.set("page", String(page));
  return params;
}

/** The `?search` of a link to a view: empty for the default view, so the plain link stays plain. */
export function viewSearch(view: QueueView): string {
  const query = viewToParams(view).toString();
  return query === "" ? "" : `?${query}`;
}

/**
 * The numbered links of the pagination: the first and the last page and two on each side of the current
 * one, with a gap mark where more than one page is left out (one left out is shown: a gap of one number is
 * no shorter than the number).
 */
export function pageList(current: number, last: number): (number | "gap")[] {
  const end = Math.max(last, 1);
  const at = Math.min(Math.max(current, 1), end);
  const keep = new Set<number>([1, end]);
  for (let n = at - 2; n <= at + 2; n++) if (n >= 1 && n <= end) keep.add(n);
  const out: (number | "gap")[] = [];
  let previous = 0;
  for (const n of [...keep].sort((a, b) => a - b)) {
    if (previous !== 0 && n - previous === 2) out.push(previous + 1);
    else if (previous !== 0 && n - previous > 2) out.push("gap");
    out.push(n);
    previous = n;
  }
  return out;
}
