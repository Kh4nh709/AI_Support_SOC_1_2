// The view of the SOAR page (the tab, the search and the page) as URL search params, so a reload and a link shared to
// another tab keep it, and the request each view makes. Only what differs from the default is written, and only what is
// understood is read: a tab that is not one of the four, or a page that is not a whole number, is dropped here, so the
// server never sees it (an empty `q=` or `status=` is a 422 there).
import type { SoarListQuery } from "../../api/soar";

export const TABS = ["open", "done", "expired", "notice"] as const;
export type Tab = (typeof TABS)[number];

export type SoarView = { tab: Tab; q: string; page: number };

/** The longest search the server takes (spec section 4). */
export const Q_MAX = 100;
const MAX_PAGE = 1_000_000;

const isTab = (value: string | null): value is Tab =>
  value !== null && (TABS as readonly string[]).includes(value);

export function readView(params: URLSearchParams): SoarView {
  const tab = params.get("tab");
  const raw = params.get("page") ?? "";
  const page = /^[1-9]\d{0,6}$/.test(raw) ? Number(raw) : 1;
  return {
    tab: isTab(tab) ? tab : "open",
    q: (params.get("q") ?? "").trim().slice(0, Q_MAX),
    page: Math.min(page, MAX_PAGE),
  };
}

export function viewToParams({ tab, q, page }: SoarView): URLSearchParams {
  const params = new URLSearchParams();
  if (tab !== "open") params.set("tab", tab);
  if (q !== "") params.set("q", q);
  if (page > 1) params.set("page", String(page));
  return params;
}

/** The `?search` of a link to a view: empty for the default view, so the plain link stays plain. */
export function viewSearch(view: SoarView): string {
  const query = viewToParams(view).toString();
  return query === "" ? "" : `?${query}`;
}

/** The statuses each tab lists: waiting (open and held), handled, expired. The notices are `kind=notice`. */
const TAB_STATUSES: Record<Exclude<Tab, "notice">, readonly string[]> = {
  open: ["open", "processing"],
  done: ["kept", "undone", "false_positive"],
  expired: ["expired"],
};

export function listQueryOf(view: SoarView): SoarListQuery {
  const query: SoarListQuery = { page: view.page };
  // `kind` is sent on every tab: a notice has the status `info`, but no status filter may let one in among the tickets.
  if (view.tab === "notice") query.kind = "notice";
  else {
    query.kind = "review";
    query.status = TAB_STATUSES[view.tab];
  }
  if (view.q !== "") query.q = view.q;
  return query;
}
