// `/admin/knowledge` (P13-T06, spec §7.5): the learned knowledge, for an admin. The model drafts an entry from each
// conclusion of an analyst; here an admin reads the draft beside the analyst's work, edits it, approves or rejects
// it, and retires an entry that was approved. Five tabs, each one read of its own, and only the tab on screen is read:
//
//   Chờ duyệt   drafts `pending`; the route sends the drafts in conflict with an active entry first, then the
//               oldest, and the page keeps that order and marks each conflict;
//   Đã duyệt    entries `active` (Gỡ is here);
//   Đã gộp      drafts `merged` into an entry that said the same;
//   Từ chối     drafts `rejected`, with who and why;
//   Đã gỡ       entries `retired`.
//
// A row opens its draft (`KnowledgeDraftView`) or its entry (`KnowledgeEntryView`) in place of the tabs, which stay
// mounted behind it, hidden: a write marks every list stale (`invalidateAfter`), the lists on screen or hidden are
// read again, and the page is back on the same tab with the row where it now belongs and a toast that says what
// was done. A tab with nothing in it says what it is for; it is not an error. A list that cannot be read says so
// with a Thử lại, and the tabs stay. Everything a person or a model wrote is text.
import { useQuery } from "@tanstack/react-query";
import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import {
  KNOWLEDGE_LIMITS,
  listKnowledgeDrafts,
  listKnowledgeEntries,
  type KnowledgeDraftRow,
  type KnowledgeDraftStatus,
  type KnowledgeEntryRow,
  type KnowledgeEntryStatus,
} from "../../api/admin";
import { DataTable, type Column } from "../../components/DataTable";
import { Toast } from "../../components/Toast";
import { formatDateTime } from "../../format";
import { S, labelOf } from "../../strings";
import { adminKeys } from "./adminKeys";
import { KnowledgeDraftView } from "./KnowledgeDraftView";
import { KnowledgeEntryView } from "./KnowledgeEntryView";
import { Mark, PANEL, ReadError, Waiting, conclusionLabel } from "./knowledgeParts";

const K = S.admin.knowledgePage;

const TABS = ["pending", "active", "merged", "rejected", "retired"] as const;
type Tab = (typeof TABS)[number];

/** What a row opens. */
type Open = { kind: "draft" | "entry"; id: string };

const OPEN_BUTTON =
  "h-8 rounded-md border border-border px-3 text-[13px] hover:bg-ground focus-visible:outline-2 focus-visible:outline-text";

export function KnowledgePage() {
  const base = useId();
  const [tab, setTab] = useState<Tab>("pending");
  const [open, setOpen] = useState<Open | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const refs = useRef<Partial<Record<Tab, HTMLButtonElement | null>>>({});

  function move(event: KeyboardEvent, from: Tab): void {
    const at = TABS.indexOf(from);
    const next =
      event.key === "ArrowRight"
        ? TABS[(at + 1) % TABS.length]
        : event.key === "ArrowLeft"
          ? TABS[(at + TABS.length - 1) % TABS.length]
          : event.key === "Home"
            ? TABS[0]
            : event.key === "End"
              ? TABS[TABS.length - 1]
              : undefined;
    if (next === undefined) return;
    event.preventDefault();
    setTab(next);
    refs.current[next]?.focus();
  }

  const done = (message: string) => {
    setOpen(null);
    setNotice(message);
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col gap-1">
        <h1 className="text-[26px] font-semibold">{S.admin.title.knowledge}</h1>
        <p className="text-sm text-[#aeb9c6]">{K.subtitle}</p>
      </div>

      {notice !== null && <Toast onClose={() => setNotice(null)}>{notice}</Toast>}

      {/* The tabs wait behind a draft or an entry, still mounted, so a write reads their lists again at once. */}
      <div hidden={open !== null} className="space-y-4">
        <div
          role="tablist"
          aria-label={K.tabsLabel}
          className="flex flex-wrap gap-2 border-b border-border"
        >
          {TABS.map((name) => (
            <button
              key={name}
              ref={(element) => {
                refs.current[name] = element;
              }}
              type="button"
              role="tab"
              id={`${base}-tab-${name}`}
              aria-selected={tab === name}
              aria-controls={`${base}-panel`}
              tabIndex={tab === name ? 0 : -1}
              onClick={() => setTab(name)}
              onKeyDown={(event) => move(event, name)}
              className={`-mb-px rounded-t-md border-b-2 px-4 py-2.5 text-sm focus-visible:outline-2 focus-visible:outline-text ${
                tab === name
                  ? "border-blue-500 font-semibold text-text"
                  : "border-transparent text-[#aeb9c6] hover:text-text"
              }`}
            >
              {K.tab[name]}
            </button>
          ))}
        </div>
        <div role="tabpanel" id={`${base}-panel`} aria-labelledby={`${base}-tab-${tab}`}>
          {tab === "pending" || tab === "merged" || tab === "rejected" ? (
            <DraftList
              key={tab}
              status={tab}
              onOpenDraft={(id) => setOpen({ kind: "draft", id })}
              onOpenEntry={(id) => setOpen({ kind: "entry", id })}
            />
          ) : (
            <EntryList key={tab} status={tab} onOpen={(id) => setOpen({ kind: "entry", id })} />
          )}
        </div>
      </div>

      {open?.kind === "draft" && (
        <KnowledgeDraftView draftId={open.id} onBack={() => setOpen(null)} onDone={done} />
      )}
      {open?.kind === "entry" && (
        <KnowledgeEntryView entryId={open.id} onBack={() => setOpen(null)} onDone={done} />
      )}
    </div>
  );
}

// --- one list --------------------------------------------------------------------------------------------------

/** What a list does in every tab: wait, fail with a way to ask again, say it is empty, or show its rows. */
function ListFrame<T>({
  tab,
  query,
  head,
  children,
}: {
  tab: Tab;
  query: { data: T[] | undefined; isError: boolean; isFetching: boolean; refetch: () => unknown };
  /** A line above the table, from the rows. */
  head?: (rows: T[]) => ReactNode;
  children: (rows: T[], busy: boolean) => ReactNode;
}) {
  const rows = query.data;
  if (rows === undefined) {
    return query.isError ? (
      <ReadError message={K.loadFailed} onRetry={() => void query.refetch()} />
    ) : (
      <Waiting />
    );
  }
  if (rows.length === 0) {
    return (
      <p className={`${PANEL} p-5 text-[13.5px] leading-relaxed text-[#c9d3df]`}>{K.empty[tab]}</p>
    );
  }
  return (
    <div className="space-y-2">
      {query.isError && <ReadError message={K.loadFailed} onRetry={() => void query.refetch()} />}
      {head?.(rows)}
      {children(rows, query.isFetching)}
      {rows.length >= KNOWLEDGE_LIMITS.listDefault && (
        <p className="px-1 text-xs text-muted">{K.listLimited(rows.length)}</p>
      )}
    </div>
  );
}

const sourceText = (row: KnowledgeDraftRow): string =>
  `${labelOf(K.sourceKind, row.source_kind)} ${row.source_id}`;

const draftTitle = (row: KnowledgeDraftRow): string => row.title ?? K.noTitle;

function DraftList({
  status,
  onOpenDraft,
  onOpenEntry,
}: {
  status: Extract<KnowledgeDraftStatus, "pending" | "merged" | "rejected">;
  onOpenDraft: (id: string) => void;
  onOpenEntry: (id: string) => void;
}) {
  const query = useQuery({
    queryKey: adminKeys.knowledgeDrafts(status),
    queryFn: () => listKnowledgeDrafts(status),
  });

  const title: Column<KnowledgeDraftRow> = {
    id: "title",
    header: K.col.title,
    cell: (row) =>
      row.title === null ? (
        <span className="text-muted italic">{K.noTitle}</span>
      ) : (
        <span className="font-semibold break-words">{row.title}</span>
      ),
  };
  const source: Column<KnowledgeDraftRow> = {
    id: "source",
    header: K.col.source,
    cell: (row) => <span className="text-[13px] break-all">{sourceText(row)}</span>,
  };
  const conclusion: Column<KnowledgeDraftRow> = {
    id: "conclusion",
    header: K.col.conclusion,
    cell: (row) => conclusionLabel(row.conclusion),
  };
  const created: Column<KnowledgeDraftRow> = {
    id: "created",
    header: K.col.created,
    className: "whitespace-nowrap",
    cell: (row) => formatDateTime(row.created_at),
  };
  const open: Column<KnowledgeDraftRow> = {
    id: "action",
    header: <span className="sr-only">{K.col.action}</span>,
    className: "text-right",
    cell: (row) => (
      <button
        type="button"
        aria-label={K.openDraft(draftTitle(row))}
        onClick={() => onOpenDraft(row.draft_id)}
        className={OPEN_BUTTON}
      >
        {K.open}
      </button>
    ),
  };
  const flags: Column<KnowledgeDraftRow> = {
    id: "flags",
    header: K.col.flags,
    cell: (row) => (
      <span className="flex flex-wrap gap-1.5">
        {row.conflict_with_entry !== null && (
          <span title={K.badge.conflictHint}>
            <Mark tone="warn">{K.badge.conflict}</Mark>
          </span>
        )}
        {!row.has_text && <Mark>{K.badge.noText}</Mark>}
        {row.warnings.length > 0 && <Mark>{K.badge.warnings(row.warnings.length)}</Mark>}
      </span>
    ),
  };
  const mergedInto: Column<KnowledgeDraftRow> = {
    id: "merged",
    header: K.col.mergedInto,
    cell: (row) =>
      row.duplicate_of_entry === null ? (
        S.common.missing
      ) : (
        <button
          type="button"
          aria-label={K.openEntry(row.duplicate_of_entry)}
          onClick={() => onOpenEntry(row.duplicate_of_entry as string)}
          className="font-mono text-xs break-all underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-text"
        >
          {row.duplicate_of_entry}
        </button>
      ),
  };
  const reviewed: Column<KnowledgeDraftRow> = {
    id: "reviewed",
    header: K.col.reviewed,
    cell: (row) =>
      K.reviewedBy(
        row.reviewed_by_name ?? S.common.missing,
        row.reviewed_at === null ? S.common.missing : formatDateTime(row.reviewed_at),
      ),
  };
  const reason: Column<KnowledgeDraftRow> = {
    id: "reason",
    header: K.col.reason,
    cell: (row) => (
      <span className="break-words whitespace-pre-wrap">{row.review_note ?? S.common.missing}</span>
    ),
  };

  const columns =
    status === "pending"
      ? [title, source, conclusion, created, flags, open]
      : status === "merged"
        ? [title, source, conclusion, mergedInto, created, open]
        : [title, source, conclusion, reviewed, reason, open];

  return (
    <ListFrame
      tab={status}
      query={query}
      head={(rows) =>
        status === "pending" ? (
          <p className="px-1 text-sm text-[#aeb9c6]">
            {K.pendingCount(
              rows.length,
              rows.filter((row) => row.conflict_with_entry !== null).length,
            )}
          </p>
        ) : null
      }
    >
      {(rows, busy) => (
        <DataTable
          label={K.tableLabel[status]}
          columns={columns}
          rows={rows}
          rowKey={(row) => row.draft_id}
          busy={busy}
        />
      )}
    </ListFrame>
  );
}

function EntryList({
  status,
  onOpen,
}: {
  status: KnowledgeEntryStatus;
  onOpen: (id: string) => void;
}) {
  const query = useQuery({
    queryKey: adminKeys.knowledgeEntries(status),
    queryFn: () => listKnowledgeEntries(status),
  });
  const columns: Column<KnowledgeEntryRow>[] = [
    {
      id: "title",
      header: K.col.title,
      cell: (row) =>
        row.title === null ? (
          <span className="text-muted italic">{K.noEntryTitle}</span>
        ) : (
          <span className="font-semibold break-words">{row.title}</span>
        ),
    },
    { id: "category", header: K.col.category, cell: (row) => row.category },
    { id: "conclusion", header: K.col.conclusion, cell: (row) => conclusionLabel(row.conclusion) },
    {
      id: "tags",
      header: K.col.tags,
      cell: (row) => (
        <span className="break-all">
          {row.tags.length === 0 ? S.common.missing : row.tags.join(", ")}
        </span>
      ),
    },
    {
      id: "approved",
      header: K.col.approvedBy,
      cell: (row) =>
        K.reviewedBy(
          row.approved_by_name ?? S.common.missing,
          row.approved_at === null ? S.common.missing : formatDateTime(row.approved_at),
        ),
    },
    { id: "evidence", header: K.col.evidence, cell: (row) => K.evidenceCount(row.evidence_count) },
    {
      id: "action",
      header: <span className="sr-only">{K.col.action}</span>,
      className: "text-right",
      cell: (row) => (
        <button
          type="button"
          aria-label={K.openEntry(row.title ?? K.noEntryTitle)}
          onClick={() => onOpen(row.entry_id)}
          className={OPEN_BUTTON}
        >
          {K.open}
        </button>
      ),
    },
  ];
  return (
    <ListFrame tab={status} query={query}>
      {(rows, busy) => (
        <DataTable
          label={K.tableLabel[status]}
          columns={columns}
          rows={rows}
          rowKey={(row) => row.entry_id}
          busy={busy}
        />
      )}
    </ListFrame>
  );
}
