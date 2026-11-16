// The detail panel of a ticket (spec section 7), opened from a row: every field, who decided and when, the result and the
// last error, the history (time, event, who, outcome), the alerts of the same case as links to our own alert page, and
// the body n8n sent in a block that is closed until opened. It reads `GET /api/soar/reviews/{id}` and asks again every 20 s
// beside the list. Its open state is the page's: a refetch neither closes it nor moves it. EVERYTHING n8n wrote is a text
// child here; the only link is to `/alerts/<our alert id, encoded>`.
import { useQuery } from "@tanstack/react-query";
import { useEffect, useId, useRef, type KeyboardEvent, type ReactNode } from "react";
import { Link } from "react-router";
import { ApiError } from "../../api/client";
import {
  fetchSoarReview,
  type SoarHistoryEvent,
  type SoarRelatedAlert,
  type SoarReviewDetail,
} from "../../api/soar";
import { DataTable, type Column } from "../../components/DataTable";
import { KeyValueGrid, type KeyValueItem } from "../../components/KeyValueGrid";
import { formatDateTime, formatTime } from "../../format";
import { S, labelOf } from "../../strings";
import { actionTextOf, statusText } from "./model";
import { SOAR_LIST_POLL_MS, soarKeys } from "./soarQueries";

const D = S.soar.detail;
const BUTTON =
  "rounded border border-border px-3 py-1 text-sm hover:bg-ground focus-visible:outline-2 focus-visible:outline-text";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
/** A text to show, or null for nothing (a field with no value is left out). */
const text = (value: unknown): string | null =>
  typeof value === "string" && value.trim() !== ""
    ? value
    : typeof value === "number"
      ? String(value)
      : null;
const time = (value: unknown): string | null =>
  typeof value === "string" && value !== "" ? formatDateTime(value) : null;

/** The fields of the review, each with its label; a field that has no value is left out by the grid. */
function fieldsOf(r: SoarReviewDetail): KeyValueItem[] {
  const F = D.field;
  const scenarioId = text(r.scenario_id);
  const scenarioName = text(r.scenario_name);
  const buttons = (Array.isArray(r.buttons) ? r.buttons : [])
    .map((button) => text(isRecord(button) ? button.label : null))
    .filter((label) => label !== null);
  const allowed = (Array.isArray(r.allowed_decisions) ? r.allowed_decisions : []).map((d) =>
    labelOf(S.soar.decision, d),
  );
  return [
    { label: F.id, value: <span className="font-mono">{r.id}</span> },
    { label: F.kind, value: labelOf(S.soar.kind, r.kind) },
    { label: F.status, value: statusText(r) },
    {
      label: F.severity,
      value: text(r.severity) === null ? null : labelOf(S.soar.severity, r.severity),
    },
    { label: F.title, value: text(r.title) },
    { label: F.simulated, value: r.simulated === true ? S.soar.simulated : null },
    {
      label: F.case,
      value: typeof r.case_number === "number" ? S.soar.caseNumber(r.case_number) : null,
    },
    { label: F.caseId, value: text(r.case_id) },
    {
      label: F.action,
      value: text(r.action_type) === null && text(r.action_text) === null ? null : actionTextOf(r),
    },
    {
      label: F.actionType,
      value: text(r.action_type) === null ? null : labelOf(S.soar.actionType, r.action_type),
    },
    { label: F.target, value: text(r.action_target) },
    { label: F.via, value: text(r.action_via) === null ? null : labelOf(S.soar.via, r.action_via) },
    { label: F.actionAgent, value: text(r.action_agent) },
    { label: F.host, value: text(r.host) },
    { label: F.agentId, value: text(r.agent_id) },
    { label: F.user, value: text(r.user_name) },
    { label: F.srcIp, value: text(r.src_ip) },
    { label: F.domain, value: text(r.domain) },
    {
      label: F.scenario,
      value:
        scenarioId !== null && scenarioName !== null
          ? D.scenario(scenarioId, scenarioName)
          : (scenarioName ?? scenarioId),
    },
    { label: F.score, value: text(r.score) },
    { label: F.note, value: text(r.note) },
    { label: F.createdAt, value: time(r.created_at) },
    { label: F.autoExpireAt, value: time(r.auto_expire_at) },
    {
      label: F.remind,
      value:
        typeof r.remind_every_minutes === "number" && r.remind_every_minutes > 0
          ? D.remindEvery(r.remind_every_minutes)
          : null,
    },
    { label: F.nextRemindAt, value: time(r.next_remind_at) },
    { label: F.decidedBy, value: text(r.decided_by) },
    { label: F.decidedAt, value: time(r.decided_at) },
    { label: F.result, value: text(r.result) },
    { label: F.lastError, value: text(r.last_error) },
    { label: F.lockedBy, value: text(r.locked_by) },
    { label: F.lockedAt, value: time(r.locked_at) },
    { label: F.lastSentAt, value: time(r.last_sent_at) },
    { label: F.receivedAt, value: time(r.received_at) },
    { label: F.updatedAt, value: time(r.updated_at) },
    { label: F.buttons, value: buttons.length > 0 ? buttons.join(D.listSeparator) : null },
    { label: F.allowed, value: allowed.length > 0 ? allowed.join(D.listSeparator) : null },
    { label: F.strong, value: r.strong_warning === true ? D.yes : null },
  ];
}

type HistoryRow = SoarHistoryEvent & { index: number };

/** Who did it: the actor (the system has a word), and the role beside it when the audit event has both. */
function whoOf(event: SoarHistoryEvent): string {
  const actor = text(event.actor);
  if (actor === null) return S.common.missing;
  const name = labelOf(D.history.actor, actor);
  const role = text(event.actor_role);
  return role === null ? name : D.history.who(name, labelOf(S.role, role));
}

/** The lines of an event's detail, from the payload the audit event carries; a payload that is no object says nothing. */
function linesOf(event: SoarHistoryEvent): string[] {
  const payload = isRecord(event.payload) ? event.payload : {};
  const H = D.history;
  const lines: string[] = [];
  if (event.event === "soar.review_decided") {
    const decision = text(payload.decision);
    if (decision !== null) lines.push(H.decided(labelOf(S.soar.decision, decision)));
    const note = text(payload.note);
    if (note !== null) lines.push(H.noteLine(note));
    const before = text(payload.status_before);
    const after = text(payload.status_after);
    if (before !== null && after !== null) {
      lines.push(H.change(labelOf(S.soar.status, before), labelOf(S.soar.status, after)));
    }
    const message = text(payload.message);
    if (message !== null) lines.push(message);
  } else if (event.event === "soar.review_received") {
    const sent = text(payload.event);
    const status = text(payload.status);
    if (sent !== null && status !== null) {
      lines.push(H.received(labelOf(H.n8nEvent, sent), labelOf(S.soar.status, status)));
    }
    const reason = text(payload.reason);
    if (reason !== null) lines.push(H.reasonLine(labelOf(H.reason, reason)));
  }
  return lines;
}

const HISTORY_COLUMNS: Column<HistoryRow>[] = [
  {
    id: "time",
    header: D.history.col.time,
    className: "whitespace-nowrap",
    cell: (e) => formatDateTime(e.at),
  },
  {
    id: "event",
    header: D.history.col.event,
    className: "wrap-anywhere",
    cell: (e) => labelOf(D.history.event, e.event),
  },
  { id: "who", header: D.history.col.who, className: "wrap-anywhere", cell: (e) => whoOf(e) },
  {
    id: "outcome",
    header: D.history.col.outcome,
    className: "wrap-anywhere",
    cell: (e) => {
      const outcome = isRecord(e.payload) ? text(e.payload.outcome) : null;
      return outcome === null ? S.common.missing : labelOf(D.history.outcome, outcome);
    },
  },
  {
    id: "detail",
    header: D.history.col.detail,
    className: "wrap-anywhere",
    cell: (e) => (
      <div className="flex flex-col gap-0.5">
        {linesOf(e).map((line, index) => (
          <p key={index}>{line}</p>
        ))}
      </div>
    ),
  },
];

/** The body n8n sent, as text: a string as it is, anything else as indented JSON. */
function rawText(raw: unknown): string | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === "string") return raw;
  try {
    return JSON.stringify(raw, null, 2);
  } catch {
    return String(raw);
  }
}

function RelatedAlerts({ alerts, total }: { alerts: readonly SoarRelatedAlert[]; total: number }) {
  const more = total - alerts.length;
  return (
    <section className="flex flex-col gap-2">
      <h3 className="text-sm font-semibold">{D.related.heading}</h3>
      {alerts.length === 0 ? (
        <p className="text-sm text-muted">{D.related.empty}</p>
      ) : (
        <ul aria-label={D.related.label} className="flex flex-col gap-2 text-sm">
          {alerts.map((alert) => (
            <li
              key={alert.alert_id}
              className="flex flex-col gap-0.5 rounded border border-border px-3 py-2 wrap-anywhere"
            >
              <Link
                to={`/alerts/${encodeURIComponent(alert.alert_id)}`}
                className="underline underline-offset-2 focus-visible:outline-2 focus-visible:outline-text"
              >
                {text(alert.description) ?? alert.alert_id}
              </Link>
              <span className="text-xs text-muted">{formatTime(alert.alert_time)}</span>
              <span className="text-xs">{text(alert.agent_name) ?? S.common.missing}</span>
              {text(alert.severity) !== null && (
                <span className="text-xs">
                  {D.related.severity(labelOf(S.severity, alert.severity))}
                </span>
              )}
              {typeof alert.occurrence_count === "number" && (
                <span className="text-xs">{D.related.occurrences(alert.occurrence_count)}</span>
              )}
              <span className="text-xs">{labelOf(S.status, alert.status)}</span>
            </li>
          ))}
        </ul>
      )}
      {more > 0 && <p className="text-sm">{D.related.more(more)}</p>}
    </section>
  );
}

function Body({ detail }: { detail: SoarReviewDetail }) {
  const history: HistoryRow[] = (Array.isArray(detail.history) ? detail.history : []).map(
    (e, index) => ({ ...e, index }),
  );
  const raw = rawText(detail.raw);
  const related = Array.isArray(detail.related_alerts) ? detail.related_alerts : [];
  return (
    <div className="flex min-w-0 flex-col gap-5">
      <KeyValueGrid items={fieldsOf(detail)} columns={1} />
      <section className="flex flex-col gap-2">
        <h3 className="text-sm font-semibold">{D.history.heading}</h3>
        {history.length === 0 ? (
          <p className="text-sm text-muted">{D.history.empty}</p>
        ) : (
          <DataTable
            label={D.history.label}
            columns={HISTORY_COLUMNS}
            rows={history}
            rowKey={(e) => String(e.index)}
          />
        )}
      </section>
      <RelatedAlerts
        alerts={related}
        total={typeof detail.related_total === "number" ? detail.related_total : related.length}
      />
      {raw === null ? (
        <p className="text-sm text-muted">{D.raw.empty}</p>
      ) : (
        <details className="text-sm">
          <summary className="cursor-pointer">{D.raw.summary}</summary>
          <pre className="mt-2 max-h-96 overflow-auto rounded border border-border bg-ground p-2 text-xs whitespace-pre-wrap wrap-anywhere">
            {raw}
          </pre>
        </details>
      )}
    </div>
  );
}

export function DetailPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const titleId = useId();
  const box = useRef<HTMLElement>(null);
  const query = useQuery({
    queryKey: soarKeys.detail(id),
    queryFn: ({ signal }) => fetchSoarReview(id, signal),
    refetchInterval: SOAR_LIST_POLL_MS,
  });
  // The focus goes to the panel when it opens or moves to another ticket: the person asked for it.
  useEffect(() => {
    box.current?.focus();
  }, [id]);

  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key !== "Escape" || event.defaultPrevented) return;
    event.preventDefault();
    onClose();
  };

  let body: ReactNode;
  if (query.data !== undefined) {
    body = <Body detail={query.data} />;
  } else if (query.isError) {
    body =
      query.error instanceof ApiError && query.error.status === 404 ? (
        <p className="text-sm">{D.notFound}</p>
      ) : (
        <div role="alert" className="flex flex-col items-start gap-2 text-sm text-critical">
          <span>{D.loadError}</span>
          <button type="button" onClick={() => void query.refetch()} className={BUTTON}>
            {S.common.retry}
          </button>
        </div>
      );
  } else {
    body = (
      <p role="status" className="text-sm text-muted">
        {D.loading}
      </p>
    );
  }

  return (
    <section
      ref={box}
      aria-labelledby={titleId}
      tabIndex={-1}
      onKeyDown={onKeyDown}
      className="flex min-w-0 w-[30rem] max-w-[40%] shrink-0 flex-col gap-4 self-start rounded border border-border bg-surface p-4 focus:outline-none"
    >
      <div className="flex items-start justify-between gap-3">
        <h2 id={titleId} className="min-w-0 text-base font-semibold wrap-anywhere">
          {D.title(id)}
        </h2>
        <button type="button" onClick={onClose} className={`shrink-0 ${BUTTON}`}>
          {D.close}
        </button>
      </div>
      {body}
    </section>
  );
}
