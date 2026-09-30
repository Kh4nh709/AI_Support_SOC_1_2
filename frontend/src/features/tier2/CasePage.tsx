// `/cases/:caseId` (spec §4, the `Case` artboard): what is known of one case on the left (its heads,
// what happened when, the notes, the conclusion) and the ② analysis on the right. The case is loaded
// once and read again after a note; a conclusion answers with the case itself, so it is shown as it comes.
import { useCallback, useId, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router";
import {
  CONCLUSIONS,
  OPEN_CASE_STATUS,
  addNote,
  concludeCase,
  getCase,
  statusOf,
  type CaseDetail,
  type CaseHead,
  type Conclusion,
  type ConcludeConflict,
} from "../../api/tier2";
import { ApiError } from "../../api/client";
import { formatDateTime, formatTime } from "../../format";
import { S, labelOf } from "../../strings";
import { InvestigationColumn } from "./InvestigationColumn";
import { BUTTON, ERROR_TEXT, ErrorNotice, FIELD, HEADING, PANEL, BandBadge, asText } from "./parts";
import { useLoad } from "./useLoad";

const TH = "px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted";
const TD = "px-3 py-2 align-top";

export function CasePage() {
  const { caseId } = useParams();
  if (caseId === undefined) return <ErrorNotice message={S.case.notFound} />;
  // Another case is another page: nothing typed or opened for the last one is carried over.
  return <CaseView key={caseId} caseId={caseId} />;
}

function CaseView({ caseId }: { caseId: string }) {
  const fetcher = useCallback(() => getCase(caseId), [caseId]);
  const { data, error, reload, replace } = useLoad(fetcher);

  if (data === null) {
    if (error === null) return <p role="status">{S.common.loading}</p>;
    return statusOf(error) === 404 ? (
      <ErrorNotice message={S.case.notFound} />
    ) : (
      <ErrorNotice message={S.common.unknownError} onRetry={() => void reload()} />
    );
  }

  const open = data.status === OPEN_CASE_STATUS;
  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold">{asText(data.title)}</h1>

      {/* A read made again after the first one failed: the case on screen is the last one that loaded. */}
      {error !== null && (
        <ErrorNotice
          message={statusOf(error) === 404 ? S.case.notFound : S.common.unknownError}
          onRetry={() => void reload()}
        />
      )}

      <div className="flex items-start gap-6">
        <div className="min-w-0 flex-1 space-y-6">
          <h2 className="text-sm font-semibold tracking-wide text-ai-accent">
            {S.case.infoHeading}
          </h2>
          <Summary data={data} />
          <Heads data={data} />
          <Timeline data={data} />
          <Notes caseId={caseId} data={data} open={open} reload={reload} />
          <Conclusion caseId={caseId} data={data} open={open} reload={reload} replace={replace} />
        </div>
        <InvestigationColumn key={caseId} caseId={caseId} caseOpen={open} />
      </div>
    </div>
  );
}

function Summary({ data }: { data: CaseDetail }) {
  return (
    <section aria-label={S.case.summaryLabel} className={`${PANEL} space-y-3`}>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
        <dt className="text-muted">{S.case.col.status}</dt>
        <dd>{labelOf(S.caseStatus, data.status)}</dd>
        <dt className="text-muted">{S.case.col.severity}</dt>
        <dd>{labelOf(S.severity, data.severity)}</dd>
        <dt className="text-muted">{S.case.col.created}</dt>
        <dd>{formatDateTime(data.created_at)}</dd>
        <dt className="text-muted">{S.case.col.lastAnalysed}</dt>
        <dd>
          {data.last_analyzed_at === null
            ? S.case.neverAnalysed
            : formatDateTime(data.last_analyzed_at)}
        </dd>
        <dt className="text-muted">{S.case.col.clusters}</dt>
        <dd>{S.case.clusterCount(data.heads.length)}</dd>
      </dl>
      {data.ongoing && (
        <div className="space-y-1">
          <span className="inline-block rounded bg-high-bg px-2 py-0.5 text-xs font-medium text-high">
            {S.case.ongoing}
          </span>
          {data.ongoing_last_seen !== null && (
            <p className="text-sm">{S.case.ongoingHint(formatTime(data.ongoing_last_seen))}</p>
          )}
        </div>
      )}
    </section>
  );
}

function Heads({ data }: { data: CaseDetail }) {
  const titleId = useId();
  return (
    <section aria-labelledby={titleId} className="space-y-2">
      <h3 id={titleId} className={HEADING}>
        {S.case.heads}
      </h3>
      {data.heads.length === 0 ? (
        <p className="text-sm">{S.case.noHeads}</p>
      ) : (
        <div className={`${PANEL} overflow-x-auto p-0`}>
          <table aria-labelledby={titleId} className="w-full text-sm">
            <thead className="border-b border-border">
              <tr>
                <th scope="col" className={TH}>
                  {S.case.headCol.description}
                </th>
                <th scope="col" className={TH}>
                  {S.case.headCol.band}
                </th>
                <th scope="col" className={TH}>
                  {S.case.headCol.status}
                </th>
                <th scope="col" className={TH}>
                  {S.case.headCol.lastSeen}
                </th>
                <th scope="col" className={TH}>
                  {S.case.headCol.rawLog}
                </th>
              </tr>
            </thead>
            <tbody>
              {data.heads.map((head) => (
                <HeadRows key={head.alert_id} head={head} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/**
 * One head, and under it the row that holds its raw log. The log can be about 1000 KB, so it stays
 * out of the page until it is asked for, and then it is one `<pre>` of text and nothing else.
 */
function HeadRows({ head }: { head: CaseHead }) {
  const [open, setOpen] = useState(false);
  const logId = useId();
  const hintId = useId();
  const hasLog = head.raw_log !== null && head.raw_log !== "";
  return (
    <>
      <tr className="border-t border-border first:border-t-0">
        <td className={TD}>
          <Link
            to={`/alerts/${encodeURIComponent(head.alert_id)}`}
            className="text-ai-accent underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-text"
          >
            {head.description ?? head.alert_id}
          </Link>
          {head.rule_id !== null && (
            <span className="block text-xs text-muted">{head.rule_id}</span>
          )}
        </td>
        <td className={TD}>
          <BandBadge label={head.risk_band} />
        </td>
        <td className={TD}>{labelOf(S.headStatus, head.status)}</td>
        <td className={TD}>{formatTime(head.last_seen_at)}</td>
        <td className={TD}>
          {hasLog ? (
            <>
              <button
                type="button"
                className={BUTTON}
                aria-expanded={open}
                aria-controls={logId}
                aria-describedby={hintId}
                onClick={() => setOpen((was) => !was)}
              >
                {open ? S.case.hideLog : S.case.showLog}
              </button>
              <span id={hintId} className="sr-only">
                {S.case.rawLogOf(head.alert_id)}
              </span>
            </>
          ) : (
            S.common.missing
          )}
          {head.raw_log_truncated && (
            <span className="ml-2 text-xs text-muted">{S.case.truncated}</span>
          )}
        </td>
      </tr>
      <tr id={logId} hidden={!open}>
        <td colSpan={5} className="px-3 pb-3">
          {open && (
            <pre
              tabIndex={0}
              className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded border border-border bg-ground p-2 font-mono text-xs"
            >
              {head.raw_log}
            </pre>
          )}
        </td>
      </tr>
    </>
  );
}

type TimelineEvent = { at: string; text: string };

/** What the case detail itself records, oldest first: it is not a log of everything that ever happened. */
function timelineOf(data: CaseDetail): TimelineEvent[] {
  const events: TimelineEvent[] = [{ at: data.created_at, text: S.case.timelineCreated }];
  for (const note of data.notes) {
    events.push({
      at: note.created_at,
      text: S.case.timelineNote(note.author_name ?? note.author_id),
    });
  }
  if (data.last_analyzed_at !== null) {
    events.push({ at: data.last_analyzed_at, text: S.case.timelineAnalysed });
  }
  if (data.status !== OPEN_CASE_STATUS && data.concluded_at !== null) {
    const who = data.concluded_by_name ?? data.concluded_by ?? S.common.missing;
    events.push({
      at: data.concluded_at,
      text: S.case.timelineConcluded(who, labelOf(S.caseStatus, data.status)),
    });
  }
  // Array.prototype.sort is stable, so events of the same instant stay in the order they were added.
  const when = (event: TimelineEvent): number => {
    const t = Date.parse(event.at);
    return Number.isNaN(t) ? 0 : t;
  };
  return events.sort((a, b) => when(a) - when(b));
}

function Timeline({ data }: { data: CaseDetail }) {
  const titleId = useId();
  return (
    <section aria-labelledby={titleId} className="space-y-2">
      <h3 id={titleId} className={HEADING}>
        {S.case.timeline}
      </h3>
      <ol aria-labelledby={titleId} className="space-y-1 text-sm">
        {timelineOf(data).map((event, index) => (
          <li key={index} className="flex gap-3">
            <time dateTime={event.at} className="shrink-0 text-muted">
              {formatTime(event.at)}
            </time>
            <span>{event.text}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}

function Notes({
  caseId,
  data,
  open,
  reload,
}: {
  caseId: string;
  data: CaseDetail;
  open: boolean;
  reload: () => Promise<CaseDetail | null>;
}) {
  const titleId = useId();
  const boxId = useId();
  const [body, setBody] = useState("");
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    const text = body.trim();
    if (text === "" || saving) return;
    setSaving(true);
    setNotice(null);
    try {
      await addNote(caseId, text);
      setBody("");
      // The list is the server's, so the new note comes back with its id, its author and its time.
      await reload();
    } catch (failure) {
      setNotice(statusOf(failure) === 422 ? S.case.noteInvalid : S.common.unknownError);
    } finally {
      setSaving(false);
    }
  }

  return (
    <section aria-labelledby={titleId} className="space-y-2">
      <h3 id={titleId} className={HEADING}>
        {S.case.notes}
      </h3>
      {data.notes.length === 0 ? (
        <p className="text-sm">{S.case.noNotes}</p>
      ) : (
        <ul aria-labelledby={titleId} className="space-y-2">
          {data.notes.map((note) => (
            <li key={note.note_id} className={`${PANEL} space-y-1 p-3 text-sm`}>
              <div className="flex items-baseline gap-2">
                <strong>{note.author_name ?? note.author_id}</strong>
                <time dateTime={note.created_at} className="text-xs text-muted">
                  {formatTime(note.created_at)}
                </time>
              </div>
              <p className="whitespace-pre-wrap">{asText(note.body)}</p>
            </li>
          ))}
        </ul>
      )}
      {open && (
        <form onSubmit={(event) => void submit(event)} className="space-y-2">
          <label htmlFor={boxId} className="block text-sm">
            {S.case.addNote}
          </label>
          <textarea
            id={boxId}
            rows={3}
            className={FIELD}
            value={body}
            onChange={(event) => setBody(event.target.value)}
          />
          <button type="submit" className={BUTTON} disabled={saving || body.trim() === ""}>
            {S.case.saveNote}
          </button>
          {notice !== null && (
            <p role="alert" className={ERROR_TEXT}>
              {notice}
            </p>
          )}
        </form>
      )}
    </section>
  );
}

/** The 409 of a conclude carries who concluded the case first; anything else in it is ignored. */
function conflictOf(failure: unknown): ConcludeConflict | null {
  if (
    !(failure instanceof ApiError) ||
    typeof failure.detail !== "object" ||
    failure.detail === null
  ) {
    return null;
  }
  return failure.detail as ConcludeConflict;
}

function Conclusion({
  caseId,
  data,
  open,
  reload,
  replace,
}: {
  caseId: string;
  data: CaseDetail;
  open: boolean;
  reload: () => Promise<CaseDetail | null>;
  replace: (data: CaseDetail) => void;
}) {
  const titleId = useId();
  const reasonId = useId();
  const scopeId = useId();
  const [choice, setChoice] = useState<Conclusion | null>(null);
  const [reason, setReason] = useState("");
  const [sending, setSending] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  // Lives here, not in the form: the form goes away when the case turns out to be concluded.
  const [conflict, setConflict] = useState<string | null>(null);

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    const text = reason.trim();
    if (choice === null || text === "" || sending) return;
    setSending(true);
    setNotice(null);
    setConflict(null);
    try {
      replace(await concludeCase(caseId, choice, text));
    } catch (failure) {
      const status = statusOf(failure);
      if (status === 409) {
        // Read the case again first, so the alert names the person the server now records.
        const fresh = await reload();
        const seen = conflictOf(failure);
        const who =
          fresh?.concluded_by_name ?? fresh?.concluded_by ?? seen?.concluded_by ?? S.common.missing;
        const when = formatDateTime(fresh?.concluded_at ?? seen?.concluded_at ?? null);
        setConflict(`${S.case.conflict} ${S.case.concludedBy(who, when)}`);
      } else if (status === 503) {
        setNotice(S.decision.timeout);
      } else if (status === 422) {
        setNotice(S.case.concludeInvalid);
      } else {
        setNotice(S.common.unknownError);
      }
    } finally {
      setSending(false);
    }
  }

  return (
    <section aria-labelledby={titleId} className={`${PANEL} space-y-3`}>
      <h3 id={titleId} className={HEADING}>
        {S.case.conclusionHeading}
      </h3>

      {conflict !== null && (
        <p role="alert" className={ERROR_TEXT}>
          {conflict}
        </p>
      )}

      {open ? (
        <form onSubmit={(event) => void submit(event)} className="space-y-3">
          <fieldset className="space-y-2">
            <legend className="text-sm">{S.case.pickConclusion}</legend>
            {CONCLUSIONS.map((code) => (
              <div key={code} data-conclusion={code} className="space-y-1">
                <label className="flex items-center gap-2 text-sm">
                  <input
                    type="radio"
                    name="conclusion"
                    value={code}
                    checked={choice === code}
                    aria-describedby={code === "confirmed_incident" ? scopeId : undefined}
                    onChange={() => setChoice(code)}
                  />
                  {S.conclusion[code]}
                </label>
                {code === "confirmed_incident" && (
                  <p id={scopeId} className="pl-6 text-xs text-muted">
                    {S.case.scopeNote}
                  </p>
                )}
              </div>
            ))}
          </fieldset>
          <div className="space-y-1">
            <label htmlFor={reasonId} className="block text-sm">
              {S.case.reasonRequired}
            </label>
            <textarea
              id={reasonId}
              rows={3}
              className={FIELD}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </div>
          <button
            type="submit"
            className={BUTTON}
            disabled={sending || choice === null || reason.trim() === ""}
          >
            {S.case.concludeSubmit}
          </button>
          {notice !== null && (
            <p role="alert" className={ERROR_TEXT}>
              {notice}
            </p>
          )}
        </form>
      ) : (
        <div className="space-y-2 text-sm">
          <strong>{labelOf(S.caseStatus, data.status)}</strong>
          {data.conclusion_reason !== null && (
            <p className="whitespace-pre-wrap">{asText(data.conclusion_reason)}</p>
          )}
          <p className="text-muted">
            {S.case.concludedBy(
              data.concluded_by_name ?? data.concluded_by ?? S.common.missing,
              formatDateTime(data.concluded_at),
            )}
          </p>
          {data.status === "confirmed_incident" && (
            <p className="text-xs text-muted">{S.case.scopeNote}</p>
          )}
        </div>
      )}
    </section>
  );
}
