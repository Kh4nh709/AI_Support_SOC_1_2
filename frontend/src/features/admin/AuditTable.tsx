// The table of the audit page (spec §4.7, the canvas's `AdminAudit`): one row for each event, and under a row the
// admin opened, one more with its payload in a `LogBlock`. It is not the shared `DataTable` because that holds
// one `<tr>` for each row and the canvas draws the payload as a full-width row of its own beneath its event.
//
// Everything shown is text: the payload is pretty-printed JSON in the one text node of a `<pre>`, and the event
// type, the username, the subject and the summary are React text nodes, with what a person cannot see written
// as its escape (`visible`). The subject is a link only when it is an alert or a case (`subjectPathOf`).
import { Fragment, useState } from "react";
import { Link } from "react-router";
import type { AuditEvent } from "../../api/admin";
import { LogBlock } from "../../components/LogBlock";
import { formatDateTime, formatTime } from "../../format";
import { S, labelOf } from "../../strings";
import {
  isAlarmEvent,
  payloadText,
  subjectPathOf,
  summaryOf,
  tooBigSize,
  visible,
} from "./auditSummary";

const P = S.admin.auditPage;

const BYTES = new Intl.NumberFormat("vi-VN");

/** The badge of an actor's role, in the canvas's colours. A role it has no colour for is shown in the plain one. */
const ROLE_TONE: Readonly<Record<string, string>> = {
  admin: "bg-[#2a1f12] text-[#fcd9a8]",
  analyst: "bg-[#13203a] text-[#a9cbff]",
  system: "bg-[#1c2530] text-[#aeb9c6]",
  llm: "bg-[#17142a] text-[#c4b5fd]",
};
const PLAIN_TONE = "border border-border text-muted";

function RoleBadge({ role }: { role: string }) {
  const tone = Object.hasOwn(ROLE_TONE, role) ? ROLE_TONE[role] : PLAIN_TONE;
  return (
    <span
      className={`ml-1 inline-block rounded px-1.5 py-px text-[11px] font-semibold whitespace-nowrap ${tone}`}
    >
      {visible(role)}
    </span>
  );
}

const MONO = "font-mono text-[12.5px] break-all";

function Subject({ event }: { event: AuditEvent }) {
  const text = visible(event.subject_id);
  const path = subjectPathOf(event);
  return path === null ? (
    <span className={MONO}>{text}</span>
  ) : (
    <Link
      to={path}
      className={`${MONO} text-[#7fb0ff] underline-offset-2 hover:text-[#a9cbff] hover:underline focus-visible:outline-2 focus-visible:outline-text`}
    >
      {text}
    </Link>
  );
}

function Payload({ event }: { event: AuditEvent }) {
  const text = payloadText(event.payload);
  const size = tooBigSize(event.payload);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-baseline gap-2.5 text-xs">
        <span className="text-muted">{P.payload}</span>
        <span className="text-[#5e6b7a]">{P.payloadNote}</span>
      </div>
      {size !== null && (
        <p className="text-xs text-[#fcd9a8]">{P.payloadTooBig(BYTES.format(size))}</p>
      )}
      {text === "" ? (
        <p className="text-[13px] text-muted">{P.noPayload}</p>
      ) : (
        <LogBlock text={text} label={P.payloadLabel(event.audit_id)} />
      )}
    </div>
  );
}

const TOGGLE =
  "rounded px-1.5 py-0.5 text-[#aeb9c6] hover:bg-ground focus-visible:outline-2 focus-visible:outline-text";

export function AuditTable({ events, busy }: { events: readonly AuditEvent[]; busy: boolean }) {
  // The audit ids of the rows that are open. A row stays open when the list is read again, and a page that is
  // left takes its rows' ids with it (they are never shown again, and a new page has new ids).
  const [open, setOpen] = useState<ReadonlySet<number>>(new Set());
  const toggle = (id: number) =>
    setOpen((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <div className="overflow-x-auto">
      <table
        aria-busy={busy}
        className={`w-full border-collapse text-left text-[13px] ${busy ? "opacity-60" : ""}`}
      >
        <caption className="sr-only">{P.table}</caption>
        <thead>
          <tr className="bg-[#18202a] text-muted">
            <th scope="col" className="w-10 px-2 py-[11px] font-medium">
              <span className="sr-only">{P.colToggle}</span>
            </th>
            <th scope="col" className="w-[130px] px-2.5 py-[11px] font-medium">
              {P.colAt}
            </th>
            <th scope="col" className="w-[260px] px-2.5 py-[11px] font-medium">
              {P.colEvent}
            </th>
            <th scope="col" className="w-[170px] px-2.5 py-[11px] font-medium">
              {P.colActor}
            </th>
            <th scope="col" className="w-[190px] px-2.5 py-[11px] font-medium">
              {P.colSubject}
            </th>
            <th scope="col" className="px-4 py-[11px] font-medium">
              {P.colSummary}
            </th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => {
            const isOpen = open.has(event.audit_id);
            const payloadId = `audit-payload-${event.audit_id}`;
            const label = visible(labelOf(S.admin.eventType, event.event_type));
            const time = formatTime(event.created_at);
            const alarm = isAlarmEvent(event.event_type);
            return (
              <Fragment key={event.audit_id}>
                <tr
                  data-audit-id={event.audit_id}
                  data-alarm={alarm ? "true" : undefined}
                  className={`border-t border-[#1f2833] align-top ${alarm ? "bg-[#1a1418]" : ""}`}
                >
                  <td className="px-2 py-[11px]">
                    <button
                      type="button"
                      aria-expanded={isOpen}
                      aria-controls={isOpen ? payloadId : undefined}
                      aria-label={isOpen ? P.hide(label, time) : P.show(label, time)}
                      onClick={() => toggle(event.audit_id)}
                      className={TOGGLE}
                    >
                      <span aria-hidden="true">{isOpen ? "▾" : "▸"}</span>
                    </button>
                  </td>
                  <td className="px-2.5 py-[11px] whitespace-nowrap text-[#aeb9c6]">
                    <time dateTime={event.created_at} title={formatDateTime(event.created_at)}>
                      {time}
                    </time>
                  </td>
                  <td className="px-2.5 py-[11px]">
                    <div>{label}</div>
                    <div className="mt-0.5 font-mono text-[11.5px] break-all text-muted">
                      {visible(event.event_type)}
                    </div>
                  </td>
                  <td className="px-2.5 py-[11px]">
                    {event.actor_username !== null && (
                      <>
                        <span className="font-mono text-[12.5px] break-all">
                          {visible(event.actor_username)}
                        </span>{" "}
                      </>
                    )}
                    <RoleBadge role={event.actor_role} />
                  </td>
                  <td className="px-2.5 py-[11px]">
                    <Subject event={event} />
                  </td>
                  <td className="px-4 py-[11px] text-[#c9d3df]">{summaryOf(event)}</td>
                </tr>
                {isOpen && (
                  <tr id={payloadId} className="bg-[#10151c]">
                    <td colSpan={6} className="pr-4 pb-3.5 pl-[146px]">
                      <Payload event={event} />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
