// The filters of the page: the four tabs (Đang mở, Đã xử lý, Hết hạn, Thông báo) and the search box. Both only report
// a new view: the page puts it in the URL, and the query follows the URL. A tab is a link to the same view on another tab,
// so it can be opened in a new tab and shared, and `aria-current` says which one is on. The search acts when the form is
// sent, so a half-typed word is not a request.
import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { S } from "../../strings";
import { Q_MAX, TABS, viewSearch, type SoarView } from "./soarParams";

const TAB =
  "border-b-2 px-3 py-2 text-sm whitespace-nowrap focus-visible:outline-2 focus-visible:outline-text";
const BUTTON =
  "rounded border border-border px-3 py-1 text-sm hover:bg-surface focus-visible:outline-2 focus-visible:outline-text";

export function TabNav({ view }: { view: SoarView }) {
  return (
    <nav aria-label={S.soar.tabs.label} className="flex flex-wrap gap-1 border-b border-border">
      {TABS.map((tab) => (
        <Link
          key={tab}
          to={{ search: viewSearch({ tab, q: view.q, page: 1 }) }}
          aria-current={tab === view.tab ? "page" : undefined}
          className={`${TAB} ${tab === view.tab ? "border-text font-semibold text-text" : "border-transparent text-muted hover:text-text"}`}
        >
          {S.soar.tabs[tab]}
        </Link>
      ))}
    </nav>
  );
}

export function SearchForm({ view, onSearch }: { view: SoarView; onSearch: (q: string) => void }) {
  // The draft of the box. The page gives the form a key of the applied search, so the draft starts again when the URL
  // changes it (Xoá tìm kiếm, the back button) and not while somebody types.
  const [draft, setDraft] = useState(view.q);
  const send = (event: FormEvent) => {
    event.preventDefault();
    onSearch(draft.trim().slice(0, Q_MAX));
  };
  return (
    <form role="search" onSubmit={send} className="flex flex-wrap items-end gap-3">
      <label className="flex flex-col gap-1 text-xs text-muted">
        {S.soar.search.label}
        <input
          type="search"
          value={draft}
          maxLength={Q_MAX}
          onChange={(event) => setDraft(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          className="w-72 rounded border border-border bg-ground px-2 py-1 text-sm text-text focus-visible:outline-2 focus-visible:outline-text"
        />
      </label>
      <button type="submit" className={BUTTON}>
        {S.soar.search.submit}
      </button>
      {view.q !== "" && (
        <button type="button" className={BUTTON} onClick={() => onSearch("")}>
          {S.soar.search.clear}
        </button>
      )}
    </form>
  );
}
