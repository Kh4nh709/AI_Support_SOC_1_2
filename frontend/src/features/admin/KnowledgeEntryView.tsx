// One knowledge entry (P13-T06, spec §7.5): what an admin approved, whole, and Gỡ for an active one.
//
//   - Its fields, who approved it and when, the evidence it stands on and the alerts and cases it came from.
//   - Its integrity, active or retired: `content_ok` (the Markdown in the database hashes to the stored hash) and
//     `file_ok` (the file `kb_learned/` holds is exactly that). A failure is said in words, not left to a colour.
//   - Its Markdown, as TEXT in a box that scrolls. Approved Markdown may legally hold `<script>` or a
//     `[x](javascript:…)` link: nothing here turns it into elements. There is no Markdown renderer and no raw-HTML
//     escape hatch, and the only links on the screen are the ones this file makes, to the page of an alert or a case.
//   - Gỡ asks for a reason (1 to 500 characters) and retires the entry. 200 tells the page; 409 `not_active` says the
//     entry is no longer active and reads it again; 404 says it is gone; 503 `publish_failed` (the file could not be
//     moved, nothing was stored) leaves the dialog open so the same button asks again.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router";
import {
  getKnowledgeEntry,
  KNOWLEDGE_LIMITS,
  knowledgeErrorOf,
  retireKnowledgeEntry,
  type KnowledgeEntry,
  type KnowledgeError,
} from "../../api/admin";
import { ApiError } from "../../api/client";
import { formatDateTime } from "../../format";
import { S, labelOf } from "../../strings";
import { adminKeys, invalidateAfter } from "./adminKeys";
import {
  BUTTON_DANGER,
  BUTTON_OUTLINE,
  ERROR_CLASS,
  Mark,
  PANEL,
  ReadError,
  ReasonDialog,
  TextBox,
  Waiting,
  conclusionLabel,
} from "./knowledgeParts";
import { useSubmitLatch } from "./useSubmitLatch";

const K = S.admin.knowledgePage;
const E = K.entry;

const LINK = "underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-text";
/**
 * An id the page makes a link of: the ids of Wazuh, Graylog and the cases are made of these characters. Never `.`
 * or `..` whole: `/alerts/..` is a path the router resolves to `/`, a link to another page, not to an alert.
 */
const SAFE_ID = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,128}$/;

/** `alert:<id>` and `case:<id>` (the subject of an evidence row) as the page that shows it, or null. */
function pathOfSubject(subject: string): string | null {
  const colon = subject.indexOf(":");
  if (colon === -1) return null;
  const kind = subject.slice(0, colon);
  const id = subject.slice(colon + 1);
  if (!SAFE_ID.test(id)) return null;
  if (kind === "alert") return `/alerts/${encodeURIComponent(id)}`;
  if (kind === "case") return `/cases/${encodeURIComponent(id)}`;
  return null;
}

export function KnowledgeEntryView({
  entryId,
  onBack,
  onDone,
}: {
  entryId: string;
  onBack: () => void;
  /** The entry was retired: the text of the toast the page shows on the list it goes back to. */
  onDone: (message: string) => void;
}) {
  const query = useQuery({
    queryKey: adminKeys.knowledgeEntry(entryId),
    queryFn: () => getKnowledgeEntry(entryId),
  });
  if (query.data === undefined) {
    if (!query.isError) return <Waiting />;
    const gone = query.error instanceof ApiError && query.error.status === 404;
    return (
      <div className="space-y-3">
        <button type="button" onClick={onBack} className={BUTTON_OUTLINE}>
          {K.back}
        </button>
        {gone ? (
          <p role="status" className="text-sm">
            {K.notice.entryGone}
          </p>
        ) : (
          <ReadError message={E.loadFailed} onRetry={() => void query.refetch()} />
        )}
      </div>
    );
  }
  return <EntryScreen key={entryId} entry={query.data} onBack={onBack} onDone={onDone} />;
}

function EntryScreen({
  entry,
  onBack,
  onDone,
}: {
  entry: KnowledgeEntry;
  onBack: () => void;
  onDone: (message: string) => void;
}) {
  const client = useQueryClient();
  const [asked, setAsked] = useState(false);
  const [reason, setReason] = useState("");
  const [reasonError, setReasonError] = useState<string | null>(null);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  // The route answered 404: the entry is gone, whatever the page still holds of it.
  const [gone, setGone] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const title = entry.title ?? K.noEntryTitle;

  // The title takes the focus when the entry opens, so a keyboard or a screen reader lands on it.
  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const retire = useMutation({
    mutationFn: (text: string) => retireKnowledgeEntry(entry.entry_id, text),
    onSuccess: async () => {
      await invalidateAfter(client, "retireKnowledgeEntry");
      onDone(K.done.retired(title));
    },
    onError: (error) => refused(knowledgeErrorOf(error)),
  });
  const run = useSubmitLatch(retire);

  function refused(error: KnowledgeError): void {
    switch (error.kind) {
      case "stale":
      case "not_found":
        setNotice(error.kind === "stale" ? K.notice.entryHandled : K.notice.entryGone);
        if (error.kind === "not_found") setGone(true);
        setAsked(false);
        void invalidateAfter(client, "retireKnowledgeEntry");
        return;
      case "publish_failed":
        setDialogError(K.notice.publishFailed);
        return;
      case "field":
        if (error.field === "reason") {
          setReasonError(
            error.reason === "required"
              ? K.notice.reasonRequired
              : K.notice.reasonInvalid(KNOWLEDGE_LIMITS.reasonMax),
          );
        } else {
          setDialogError(K.notice.failed);
        }
        return;
      default:
        setDialogError(K.notice.failed);
    }
  }

  function ask(): void {
    retire.reset();
    setReason("");
    setReasonError(null);
    setDialogError(null);
    setAsked(true);
  }

  const items: [string, ReactNode][] = [
    [E.field.version, entry.version],
    [E.field.conclusion, conclusionLabel(entry.conclusion)],
    [E.field.category, entry.category],
    [E.field.mitre_ids, listOf(entry.mitre_ids)],
    [E.field.tags, listOf(entry.tags)],
    [E.field.soar_scenario, entry.soar_scenario ?? S.common.missing],
    [E.field.rule_ids, listOf(entry.rule_ids)],
    [E.field.log_source, entry.log_source ?? S.common.missing],
    [E.field.file_path, entry.file_path],
    [
      E.field.content_sha256,
      <span className="font-mono text-xs break-all">{entry.content_sha256}</span>,
    ],
    [
      E.field.approved,
      `${entry.approved_by_name ?? S.common.missing} · ${entry.approved_at === null ? S.common.missing : formatDateTime(entry.approved_at)}`,
    ],
  ];
  if (entry.supersedes_entry !== null) items.push([E.field.supersedes, entry.supersedes_entry]);

  return (
    <div className="space-y-4">
      <section aria-label={E.header} className={`${PANEL} space-y-3 p-4`}>
        <div className="flex flex-wrap items-center gap-3">
          <button type="button" onClick={onBack} className={BUTTON_OUTLINE}>
            {K.back}
          </button>
          <h2
            ref={headingRef}
            tabIndex={-1}
            className="min-w-0 flex-1 text-lg font-semibold break-words focus:outline-none"
          >
            {title}
          </h2>
          <Mark>{labelOf(E.status, entry.status)}</Mark>
          {entry.status === "active" && !gone && (
            <button type="button" onClick={ask} className={BUTTON_DANGER}>
              {E.retire}
            </button>
          )}
        </div>
        {notice !== null && (
          <p
            role="alert"
            className="rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-3 text-[13.5px] text-[#fcd9a8]"
          >
            {notice}
          </p>
        )}
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-3">
          {items.map(([label, value]) => (
            <div key={label} className="min-w-0">
              <dt className="text-xs text-muted">{label}</dt>
              <dd className="break-words">{value}</dd>
            </div>
          ))}
        </dl>
      </section>

      <Integrity entry={entry} />
      <Evidence entry={entry} />
      <section className="space-y-2">
        <TextBox value={entry.content} label={E.content} />
      </section>

      {asked && (
        <ReasonDialog
          title={E.retireTitle}
          body={E.retireBody}
          confirmLabel={E.retire}
          reasonLabel={E.reasonLabel}
          reason={reason}
          onReason={(text) => {
            setReason(text);
            setReasonError(null);
          }}
          reasonError={reasonError}
          error={dialogError}
          busy={retire.isPending}
          onConfirm={() => void run(reason.trim())}
          onCancel={() => {
            retire.reset();
            setAsked(false);
          }}
        />
      )}
    </div>
  );
}

const listOf = (items: readonly string[]): string =>
  items.length === 0 ? S.common.missing : items.join(", ");

/** The two checks, in words: an entry that passes both says so, one that fails says which. */
function Integrity({ entry }: { entry: KnowledgeEntry }) {
  const id = useId();
  const { content_ok: contentOk, file_ok: fileOk } = entry.integrity;
  return (
    <section aria-labelledby={id} className={`${PANEL} space-y-1 p-4`}>
      <h3 id={id} className="text-sm font-semibold">
        {E.integrity.heading}
      </h3>
      {contentOk && fileOk ? (
        <p className="text-sm text-[#9ff0c5]">{E.integrity.ok}</p>
      ) : (
        <ul className="list-disc pl-5">
          {!contentOk && <li className={ERROR_CLASS}>{E.integrity.contentBad}</li>}
          {!fileOk && <li className={ERROR_CLASS}>{E.integrity.fileBad}</li>}
        </ul>
      )}
    </section>
  );
}

function Evidence({ entry }: { entry: KnowledgeEntry }) {
  const id = useId();
  const alerts = entry.source_alert_ids;
  const cases = entry.source_case_ids;
  return (
    <section aria-labelledby={id} className={`${PANEL} space-y-2 p-4`}>
      <h3 id={id} className="text-sm font-semibold">
        {E.evidence.heading}
      </h3>
      {entry.evidence.length === 0 ? (
        <p className="text-sm text-muted">{E.evidence.empty}</p>
      ) : (
        <ul className="space-y-1 text-sm">
          {entry.evidence.map((row, index) => {
            const path = pathOfSubject(row.subject);
            return (
              <li key={index} className="flex flex-wrap gap-x-3">
                {path === null ? (
                  <span className="break-all">{row.subject}</span>
                ) : (
                  <Link to={path} className={`${LINK} break-all`}>
                    {row.subject}
                  </Link>
                )}
                <time dateTime={row.at} className="text-muted">
                  {formatDateTime(row.at)}
                </time>
              </li>
            );
          })}
        </ul>
      )}
      {(alerts.length > 0 || cases.length > 0) && (
        <p className="text-xs text-muted">
          {E.field.sources}:{" "}
          {alerts.map((alert) => (
            <SourceId key={`a:${alert}`} id={alert} base="/alerts/" />
          ))}
          {cases.map((caseId) => (
            <SourceId key={`c:${caseId}`} id={caseId} base="/cases/" />
          ))}
        </p>
      )}
    </section>
  );
}

/** An id of an alert or a case: a link to its page when it is made of the characters ids are made of, else text. */
function SourceId({ id, base }: { id: string; base: "/alerts/" | "/cases/" }) {
  return SAFE_ID.test(id) ? (
    <Link to={`${base}${encodeURIComponent(id)}`} className={`${LINK} mr-2`}>
      {id}
    </Link>
  ) : (
    <span className="mr-2 break-all">{id}</span>
  );
}
