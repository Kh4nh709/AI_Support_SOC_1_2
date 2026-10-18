// `/admin/audit` (P11-T17, spec §4.7): the audit log, the canvas's `AdminAudit` and the "AUDIT" cards of
// `AdminStates`. It is read-only: the one request is `GET /api/admin/audit`, and nothing here writes.
//
// The four filters (range, group, actor, subject) live in the URL, so a reload and a shared link keep them;
// the form sends them when it is submitted, and "Xoá lọc" clears them. The pages of the log are the API's
// cursor: it pages forward only, so "Trước" is a stack of the cursors already seen, kept here and dropped
// when a filter changes. Under the filters the page tells its states apart:
//   - loading: a skeleton, with the form already there;
//   - rows: the table, and the pager with what is on screen and, when the server counted, out of how many;
//   - no match (a filter is on) with "Xoá lọc", and an empty log;
//   - a page past the last, when the page before it was full and nothing is older;
//   - 503 `timeout` and `query_failed`, each in its words, with the form open to narrow the filter, and no
//     retry of its own (the query does not retry by itself; a button asks again);
//   - 422: the text at the filter it names, and a line above the table;
//   - 403: the card of a role that is not admin any more;
//   - anything else: the page's own error (`PageError`).
// A refresh that fails while rows are on screen leaves the rows, with a note.
import { useQuery } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import {
  ADMIN_RANGES,
  AUDIT_GROUPS,
  getAudit,
  type AuditFilters,
  type AuditResponse,
} from "../../api/admin";
import { PageError } from "../../components/PageError";
import { S, adminReasonText } from "../../strings";
import { adminKeys } from "./adminKeys";
import {
  PAGE_SIZE,
  auditFaultOf,
  isFiltered,
  readView,
  viewKey,
  viewToParams,
  type AuditFault,
  type AuditView,
  type FilterField,
} from "./auditParams";
import { visible } from "./auditSummary";
import { AuditTable } from "./AuditTable";

const P = S.admin.auditPage;

const NUMBER = new Intl.NumberFormat("vi-VN");

const CARD = "flex flex-col gap-3 rounded-[10px] border border-border bg-surface px-5 py-5";
const OUTLINE_BUTTON =
  "h-[38px] rounded-md border border-[#2e3a48] px-3 text-[13.5px] text-[#c9d3df] hover:bg-ground focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text";
const PAGER_BUTTON =
  "h-[34px] rounded-md border border-[#2e3a48] px-3 text-[13px] text-[#c9d3df] hover:bg-ground focus-visible:outline-2 focus-visible:outline-text disabled:cursor-not-allowed disabled:text-[#5e6b7a] disabled:hover:bg-transparent";
const CONTROL =
  "h-[38px] rounded-md border bg-[#0f141b] px-2.5 text-[13.5px] text-text focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text";

// --- the filter form --------------------------------------------------------------------------------------------

/** What is typed in the form, as the controls hold it: strings, an empty one meaning "not set". */
type Draft = { range: string; group: string; actor: string; subject: string };

const draftOf = (view: AuditView): Draft => ({
  range: view.range,
  group: view.group ?? "",
  actor: view.actor ?? "",
  subject: view.subject ?? "",
});

const EMPTY_DRAFT: Draft = draftOf({ range: "7d" });

/** One filter: its label, its control, and, under it, the text of a 422 that named it. */
function Field({
  label,
  htmlFor,
  fault,
  faultId,
  children,
}: {
  label: string;
  htmlFor: string;
  fault: boolean;
  faultId: string;
  children: ReactNode;
}) {
  return (
    <div className="flex flex-col gap-[5px]">
      <label htmlFor={htmlFor} className="text-xs text-muted">
        {label}
      </label>
      {children}
      {fault && (
        <p id={faultId} className="max-w-[220px] text-[12.5px] text-[#fda4af]">
          {P.fieldFault(label)}
        </p>
      )}
    </div>
  );
}

function FilterForm({
  view,
  fault,
  onApply,
  onClear,
}: {
  view: AuditView;
  /** The filter a 422 named, if it named one. */
  fault: FilterField | null;
  onApply: (next: AuditView) => void;
  onClear: () => void;
}) {
  const ids = { range: useId(), group: useId(), actor: useId(), subject: useId() };
  const faultIds = { range: useId(), group: useId(), actor: useId(), subject: useId() };
  const key = viewKey(view);
  // The drafts are the controls' own text. They start again when the URL gives the form another view (the
  // back button, "Xoá lọc"): state adjusted while rendering, keyed by what the URL holds, so typing is never
  // overwritten and the form is not remounted (a remount would take the focus off the button just pressed).
  const [draft, setDraft] = useState<{ key: string; values: Draft }>({
    key,
    values: draftOf(view),
  });
  if (draft.key !== key) setDraft({ key, values: draftOf(view) });
  const values = draft.values;
  const set = (name: keyof Draft, value: string) =>
    setDraft({ key, values: { ...values, [name]: value } });

  function submit(event: FormEvent) {
    event.preventDefault();
    // `readView` is the one reader of a view: it drops an unknown range or group and trims and drops an empty text.
    const next = readView(new URLSearchParams({ ...values }));
    setDraft({ key: viewKey(next), values: draftOf(next) });
    onApply(next);
  }

  function clear() {
    setDraft({ key: "", values: EMPTY_DRAFT });
    onClear();
  }

  const invalid = (name: FilterField) =>
    fault === name ? { "aria-invalid": true, "aria-describedby": faultIds[name] } : {};
  const border = (name: FilterField) => (fault === name ? "border-[#5a2e36]" : "border-[#2e3a48]");

  return (
    <form
      aria-label={P.filtersLabel}
      onSubmit={submit}
      className="flex flex-wrap items-start gap-3 rounded-[10px] border border-border bg-surface px-4 py-3.5"
    >
      <Field
        label={P.rangeLabel}
        htmlFor={ids.range}
        fault={fault === "range"}
        faultId={faultIds.range}
      >
        <select
          id={ids.range}
          value={values.range}
          onChange={(event) => set("range", event.target.value)}
          className={`${CONTROL} ${border("range")} w-[150px]`}
          {...invalid("range")}
        >
          {ADMIN_RANGES.map((range) => (
            <option key={range} value={range}>
              {S.admin.range[range]}
            </option>
          ))}
        </select>
      </Field>
      <Field
        label={P.groupLabel}
        htmlFor={ids.group}
        fault={fault === "group"}
        faultId={faultIds.group}
      >
        <select
          id={ids.group}
          value={values.group}
          onChange={(event) => set("group", event.target.value)}
          className={`${CONTROL} ${border("group")} w-[210px]`}
          {...invalid("group")}
        >
          <option value="">{P.groupAll}</option>
          {AUDIT_GROUPS.map((group) => (
            <option key={group} value={group}>
              {S.admin.auditGroup[group]}
            </option>
          ))}
        </select>
      </Field>
      <Field
        label={P.actorLabel}
        htmlFor={ids.actor}
        fault={fault === "actor"}
        faultId={faultIds.actor}
      >
        <input
          id={ids.actor}
          type="search"
          autoComplete="off"
          value={values.actor}
          onChange={(event) => set("actor", event.target.value)}
          placeholder={P.actorPlaceholder}
          className={`${CONTROL} ${border("actor")} w-[190px]`}
          {...invalid("actor")}
        />
      </Field>
      <Field
        label={P.subjectLabel}
        htmlFor={ids.subject}
        fault={fault === "subject"}
        faultId={faultIds.subject}
      >
        <input
          id={ids.subject}
          type="search"
          autoComplete="off"
          value={values.subject}
          onChange={(event) => set("subject", event.target.value)}
          placeholder={P.subjectPlaceholder}
          className={`${CONTROL} ${border("subject")} w-[220px]`}
          {...invalid("subject")}
        />
      </Field>
      <div className="flex flex-col gap-[5px]">
        {/* The height of a label, so the buttons stand on the line of the controls. */}
        <span aria-hidden="true" className="h-4" />
        <div className="flex gap-3">
          <button
            type="submit"
            className="h-[38px] rounded-md bg-[#2563eb] px-4 text-sm font-semibold text-white hover:bg-[#1d4fd8] focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text"
          >
            {P.apply}
          </button>
          <button type="button" onClick={clear} className={OUTLINE_BUTTON}>
            {P.clear}
          </button>
        </div>
      </div>
    </form>
  );
}

// --- the states -------------------------------------------------------------------------------------------------

function Skeleton() {
  return (
    <div
      role="status"
      aria-busy="true"
      className="space-y-2.5 rounded-[10px] border border-border bg-surface p-4"
    >
      <span className="sr-only">{S.common.loading}</span>
      {["a", "b", "c", "d", "e", "f", "g", "h"].map((key) => (
        <div key={key} className="h-11 animate-pulse rounded-md bg-[#1c2530]" />
      ))}
    </div>
  );
}

/** The filters that are on, as a sentence: the group, the actor, the subject, then the range. */
function describeView(view: AuditView): string {
  const parts = [
    ...(view.group ? [P.filterGroup(S.admin.auditGroup[view.group])] : []),
    ...(view.actor ? [P.filterActor(visible(view.actor))] : []),
    ...(view.subject ? [P.filterSubject(visible(view.subject))] : []),
    S.admin.range[view.range],
  ];
  return parts.join(", ");
}

function NoMatch({ view, onClear }: { view: AuditView; onClear: () => void }) {
  return (
    <div className={CARD}>
      <h2 className="text-[17px] font-semibold">{P.noMatchTitle}</h2>
      <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">
        {P.noMatchBody(describeView(view))}
      </p>
      <button type="button" onClick={onClear} className={`${OUTLINE_BUTTON} self-start`}>
        {P.clear}
      </button>
    </div>
  );
}

function EmptyLog({ view }: { view: AuditView }) {
  return (
    <div className={CARD}>
      <h2 className="text-[17px] font-semibold">{P.emptyTitle}</h2>
      <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">
        {P.emptyBody(S.admin.range[view.range])}
      </p>
    </div>
  );
}

function Forbidden() {
  return (
    <div className={CARD}>
      <h1 className="text-[17px] font-semibold">{P.forbiddenTitle}</h1>
      <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">{P.forbiddenBody}</p>
      <Link
        to="/queue"
        className="self-start text-sm text-[#7fb0ff] underline underline-offset-2 hover:text-[#a9cbff] focus-visible:outline-2 focus-visible:outline-text"
      >
        {P.forbiddenBack}
      </Link>
    </div>
  );
}

/** The 503s: an alert in the words of the reason, and a button to ask again. Neither retries by itself. */
function QueryFailure({
  kind,
  onRetry,
}: {
  kind: "timeout" | "query_failed";
  onRetry: () => void;
}) {
  const slow = kind === "timeout";
  return (
    <div className="flex flex-col gap-3">
      <div
        role="alert"
        className={`rounded-lg border px-3.5 py-3 text-[13.5px] leading-snug ${
          slow
            ? "border-[#5a3a14] bg-[#2a1a0a] text-[#fcd9a8]"
            : "border-[#5a2e36] bg-[#2a1016] text-[#fda4af]"
        }`}
      >
        {adminReasonText({ reason: kind })}
      </div>
      {slow && <p className="text-[12.5px] text-muted">{P.timeoutNote}</p>}
      <button type="button" onClick={onRetry} className={`${OUTLINE_BUTTON} self-start`}>
        {S.common.retry}
      </button>
    </div>
  );
}

function loadHint(status: number): string {
  return status === 0 ? P.loadErrorOffline : P.loadErrorServer(status);
}

// --- the page ---------------------------------------------------------------------------------------------------

const NO_CURSORS: readonly number[] = [];

/** One answer of the route, with the offset of its first row in the log under the filters (0 for the first page). */
type Page = AuditResponse & { offset: number };

export function AuditPage() {
  const [params, setParams] = useSearchParams();
  const view = readView(params);
  const key = viewKey(view);

  // The cursors of the pages already seen under this view: `cursors[i]` opens page `i + 1`. They belong to the
  // view that made them, so another view reads none.
  const [paging, setPaging] = useState<{ key: string; cursors: readonly number[] }>({
    key,
    cursors: NO_CURSORS,
  });
  const cursors = paging.key === key ? paging.cursors : NO_CURSORS;
  const cursor = cursors[cursors.length - 1];
  const page = cursors.length;

  const filters: AuditFilters = { ...view, limit: PAGE_SIZE };
  if (cursor !== undefined) filters.cursor = cursor;

  const query = useQuery({
    queryKey: adminKeys.audit(filters),
    // Each answer carries the offset of its first row, so what the pager says is always about the rows on
    // screen: while the next page is read, the rows (and the range) are still the page being left.
    queryFn: async (): Promise<Page> => ({
      ...(await getAudit(filters)),
      offset: page * PAGE_SIZE,
    }),
    // A query that ran out of time is not asked again by itself: the page says so and a button asks.
    retry: false,
    // The page being left stays on screen while the next one is read, but only under the same filters: the
    // rows of another view are not shown under this one.
    placeholderData: (previous, previousQuery) =>
      previousQuery !== undefined && viewKey(previousQuery.queryKey[2]) === key
        ? previous
        : undefined,
  });
  const data: Page | undefined = query.data;
  const fault: AuditFault | null =
    data === undefined && query.isError ? auditFaultOf(query.error) : null;
  const busy = query.isPlaceholderData;

  // After a page change the button that was pressed has been disabled while the page was read: the focus goes
  // back to it, or to the other one when it has no page left to go to.
  const prevRef = useRef<HTMLButtonElement>(null);
  const nextRef = useRef<HTMLButtonElement>(null);
  const refocus = useRef<"prev" | "next" | null>(null);
  useEffect(() => {
    const wanted = refocus.current;
    if (wanted === null || data === undefined || busy) return;
    refocus.current = null;
    const first = wanted === "prev" ? prevRef.current : nextRef.current;
    const second = wanted === "prev" ? nextRef.current : prevRef.current;
    (first && !first.disabled ? first : second)?.focus();
  });

  const apply = (next: AuditView) => {
    if (viewKey(next) === key) void query.refetch();
    else setParams(viewToParams(next));
  };
  const clear = () => setParams(new URLSearchParams());

  if (fault?.kind === "forbidden") return <Forbidden />;

  // The page's own error has the h1 of its own: there is one h1 in every state.
  const failed = fault?.kind === "load";
  const events = data?.events ?? [];
  const offset = data?.offset ?? 0;
  const from = offset + 1;
  const to = offset + events.length;
  const total = data?.total ?? null;
  const hasNext = data?.next_cursor !== null && data?.next_cursor !== undefined;
  const atEnd = total !== null && to >= total;

  const go = (direction: "prev" | "next") => {
    refocus.current = direction;
    if (direction === "prev") {
      setPaging({ key, cursors: cursors.slice(0, -1) });
    } else if (data?.next_cursor !== null && data?.next_cursor !== undefined) {
      setPaging({ key, cursors: [...cursors, data.next_cursor] });
    }
  };

  const pager = (
    <nav
      aria-label={P.pager}
      className="flex items-center gap-3 border-t border-[#1f2833] px-4 py-2.5 text-[13px] text-[#aeb9c6]"
    >
      <span className="grow">
        {events.length === 0
          ? ""
          : total === null
            ? P.shown(NUMBER.format(from), NUMBER.format(to))
            : P.shownOf(NUMBER.format(from), NUMBER.format(to), NUMBER.format(total))}
      </span>
      <button
        ref={prevRef}
        type="button"
        disabled={page === 0 || busy}
        onClick={() => go("prev")}
        className={PAGER_BUTTON}
      >
        {P.prev}
      </button>
      <button
        ref={nextRef}
        type="button"
        disabled={!hasNext || atEnd || busy}
        onClick={() => go("next")}
        className={PAGER_BUTTON}
      >
        {P.next}
      </button>
    </nav>
  );

  let region: ReactNode;
  if (data === undefined) {
    if (fault === null) {
      region = <Skeleton />;
    } else if (fault.kind === "timeout" || fault.kind === "query_failed") {
      region = <QueryFailure kind={fault.kind} onRetry={() => void query.refetch()} />;
    } else if (fault.kind === "filter" || fault.kind === "filters") {
      region = (
        <div
          role="alert"
          className="rounded-lg border border-[#5a2e36] bg-[#2a1016] px-3.5 py-3 text-[13.5px] leading-snug text-[#fda4af]"
        >
          {P.badFilter}
        </div>
      );
    } else {
      region = (
        <div className="space-y-3">
          <PageError title={S.admin.common.loadError} onRetry={() => void query.refetch()} />
          <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">
            {loadHint(fault.kind === "load" ? fault.status : 0)}
          </p>
        </div>
      );
    }
  } else if (events.length === 0 && offset === 0) {
    region = isFiltered(view) ? <NoMatch view={view} onClear={clear} /> : <EmptyLog view={view} />;
  } else if (events.length === 0) {
    region = (
      <section className="overflow-hidden rounded-[10px] border border-border bg-surface">
        <p className="px-4 py-6 text-center text-[13.5px] text-muted">{P.endOfLog}</p>
        {pager}
      </section>
    );
  } else {
    region = (
      <section className="overflow-hidden rounded-[10px] border border-border bg-surface">
        <AuditTable events={events} busy={busy} />
        {pager}
      </section>
    );
  }

  return (
    <div className="flex flex-col gap-[18px]">
      <div className="flex flex-col gap-1">
        {!failed && <h1 className="text-[26px] font-semibold">{S.admin.title.audit}</h1>}
        {!failed && <span className="text-sm text-[#aeb9c6]">{P.subtitle}</span>}
      </div>
      <FilterForm
        view={view}
        fault={fault?.kind === "filter" ? fault.field : null}
        onApply={apply}
        onClear={clear}
      />
      {data !== undefined && query.isRefetchError && (
        <div
          role="alert"
          className="flex items-center gap-3 rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-2.5 text-[13.5px] text-[#fcd9a8]"
        >
          <span className="grow">{P.refreshFailed}</span>
          <button type="button" onClick={() => void query.refetch()} className={OUTLINE_BUTTON}>
            {S.common.retry}
          </button>
        </div>
      )}
      {region}
    </div>
  );
}
