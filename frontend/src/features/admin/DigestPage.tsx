// `/admin/digest` (spec §4.5, P11-T15): the clusters a rule auto-closed on one day, to be reviewed one by one.
//
// One read, `GET /api/admin/digest[?day=]`, owns the page. Four rules it follows:
//   - the day lives in the URL (`?day=YYYY-MM-DD`), so a reload or a shared link keeps it; with no day the
//     server's default (today) is read. The day and "today" shown are the server's answer, never the browser's
//     date, and a review is posted with the day of the answer;
//   - a day the server refuses (`422 bad_day`) is not a page error: the page replaces the URL by the default
//     day (`<Navigate replace>`) and says so in a notice, carried in the location state;
//   - a review (`POST .../{alert_id}/review`) answers for one row, so a refusal is said in that row: a 409
//     `already_reviewed` replaces the row by the verdict on file (it carries it), and a 409 `not_auto_closed`,
//     a 404 take the buttons away; a 422 or a failed write says so and leaves the buttons;
//   - what a review recorded is put in the list at once (a server answer, not a guess) and the list is read
//     again through `invalidateAfter("reviewDigest")`.
// Two clicks in the same tick must send one POST, which a disabled button cannot promise (TanStack tells React a
// mutation is pending a tick late), so each row holds a ref latch while its POST is out.
// No element has a `style` attribute: the CSP forbids one.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, Navigate, useLocation, useSearchParams } from "react-router";
import {
  DIGEST_VERDICTS,
  adminErrorOf,
  conflictRow,
  getDigest,
  reviewDigest,
  type AdminError,
  type DigestResponse,
  type DigestRow,
  type DigestVerdict,
} from "../../api/admin";
import type { BandCode } from "../../api/types";
import { Badge } from "../../components/Badge";
import { PageError } from "../../components/PageError";
import { formatTime } from "../../format";
import { S, adminReasonText, labelOf } from "../../strings";
import { adminKeys, invalidateAfter } from "./adminKeys";
import {
  alertTail,
  formatDay,
  isBadDay,
  markReopened,
  spanText,
  summarise,
  withRow,
} from "./digestFigures";

const D = S.admin.digestPage;

const PATH = "/admin/digest";

const PANEL = "flex flex-col gap-3 rounded-[10px] border border-border bg-surface px-5 py-5";
const MUTED = "text-[#aeb9c6]";
const AMBER = "text-[#fcd9a8]";
const FOCUS = "focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text";

// --- the row's own words ---------------------------------------------------------------------------------------

/** What a refused review said, in the row it was for. `locked`: the buttons cannot work, so they are gone. */
type RowNote = { text: string; tone: "warn" | "error"; locked: boolean };

/** The note of a failed review. A code this page has no sentence for is said by `S.admin.reason`. */
function noteOf(failure: AdminError, alertId: string): RowNote {
  if (failure.kind === "reason") {
    switch (failure.reason) {
      case "already_reviewed":
        return { text: S.admin.reason.already_reviewed, tone: "warn", locked: true };
      case "not_auto_closed":
        return { text: D.notAutoClosed(alertTail(alertId)), tone: "warn", locked: true };
      case "not_in_digest":
      case "not_found":
        return { text: adminReasonText(failure), tone: "warn", locked: true };
      default:
        return { text: adminReasonText(failure), tone: "error", locked: false };
    }
  }
  if (failure.kind === "field") {
    const text =
      failure.field === "verdict" && failure.reason === "invalid"
        ? D.invalidVerdict
        : adminReasonText(failure);
    return { text, tone: "error", locked: false };
  }
  // A text of the server's, FastAPI's list of errors, a 5xx or no answer: English or nothing, never shown.
  return { text: D.saveFailed(failure.status), tone: "error", locked: false };
}

const NOTE_TONE: Record<RowNote["tone"], string> = {
  warn: "border-[#5a3a14] bg-[#2a1a0a] text-[#fcd9a8]",
  error: "border-[#5a2e36] bg-[#2a1016] text-[#fda4af]",
};

// --- the cells -------------------------------------------------------------------------------------------------

/** `severity` is the word of the alert (`S.severity`); its colour is the band of the same code. */
function Severity({ code }: { code: string }) {
  const label = labelOf(S.severity, code);
  return Object.hasOwn(S.band, code) ? (
    <Badge band={code as BandCode}>{label}</Badge>
  ) : (
    <Badge>{label}</Badge>
  );
}

const BUTTON = `h-8 rounded-md border px-2.5 text-[12.5px] disabled:cursor-not-allowed disabled:opacity-60 ${FOCUS}`;
// Whole class names: Tailwind finds a class by reading the source.
const VERDICT_TONE: Record<DigestVerdict, string> = {
  correct: "border-[#2e5a44] bg-[#102a20] text-[#9ff0c5]",
  wrong: "border-[#5a2e36] bg-[#2a1016] text-[#fda4af]",
  unsure: "border-[#2e3a48] bg-transparent text-[#c9d3df]",
};

function Reviewed({ row }: { row: DigestRow }) {
  const verdict = row.reviewed_verdict ?? "";
  return (
    <div className="space-y-0.5">
      <p className="font-semibold">{D.reviewed(labelOf(S.admin.verdict, verdict))}</p>
      <p className="text-xs text-muted">
        {`${row.reviewed_by_name || S.common.missing} · ${formatTime(row.reviewed_at)}`}
      </p>
      {row.reopened_by_review && <p className={`text-xs ${AMBER}`}>{D.reopened}</p>}
    </div>
  );
}

// --- one row -----------------------------------------------------------------------------------------------------

function DigestRowView({
  row,
  day,
  onRecorded,
}: {
  row: DigestRow;
  /** The day of the answer: what a review is posted with. */
  day: string;
  /** The row the server recorded, to put in the list. */
  onRecorded: (row: DigestRow) => void;
}) {
  const client = useQueryClient();
  const [note, setNote] = useState<RowNote | null>(null);
  // Held from the click to the settling of its POST. `mutation.isPending` reaches React a tick after the
  // click, so two clicks in one tick would both pass `disabled`; a ref changes at once.
  const latch = useRef(false);
  // The buttons the admin pressed disappear when the row is answered; the focus goes to the answer, so a
  // keyboard or a screen reader does not fall back to the top of the page.
  const answer = useRef<HTMLDivElement>(null);
  const handoff = useRef(false);

  const mutation = useMutation({
    mutationFn: (verdict: DigestVerdict) => reviewDigest(row.alert_id, day, verdict),
    onSuccess: async ({ row: recorded, reopened }) => {
      setNote(null);
      onRecorded(markReopened(recorded, reopened));
      await invalidateAfter(client, "reviewDigest");
    },
    onError: (error) => {
      const failure = adminErrorOf(error);
      const next = noteOf(failure, row.alert_id);
      setNote(next);
      const onFile = conflictRow(failure);
      // Buttons that are still there keep the focus where it was: a later read must not take it.
      if (!next.locked && onFile === null) handoff.current = false;
      if (onFile !== null) {
        // The 409 carries the review that is on file: the row is that, with nothing to read again.
        onRecorded(onFile);
      } else if (failure.kind === "reason" && failure.reason === "already_reviewed") {
        // It said "already reviewed" and gave no row to show: read the day again to learn which.
        void invalidateAfter(client, "reviewDigest");
      }
    },
  });

  const review = (verdict: DigestVerdict) => {
    if (latch.current) return;
    latch.current = true;
    handoff.current = true;
    setNote(null);
    mutation.mutate(verdict, {
      onSettled: () => {
        latch.current = false;
      },
    });
  };

  const reviewed = row.reviewed_verdict !== null;
  const locked = note?.locked === true;
  useEffect(() => {
    if ((reviewed || locked) && handoff.current) {
      handoff.current = false;
      answer.current?.focus();
    }
  }, [reviewed, locked]);
  const tone = reviewed
    ? row.disagreement
      ? "bg-[#2a1a0a] text-[#aeb9c6]"
      : "bg-[#10151c] text-muted"
    : row.disagreement
      ? "bg-[#2a1a0a]"
      : "";

  return (
    <tr
      data-alert-id={row.alert_id}
      data-state={reviewed ? "reviewed" : "open"}
      data-disagreement={row.disagreement ? "true" : "false"}
      aria-busy={mutation.isPending || undefined}
      className={`border-t border-border align-top ${tone}`}
    >
      <td className="px-3.5 py-3">{row.autoclose_rule_name || S.common.missing}</td>
      <td className="px-2.5 py-3">
        <div>
          <span className="font-mono">{row.rule_id}</span>
          {` · ${row.category}`}
        </div>
        <div className="mt-0.5 text-[12.5px] text-muted">{row.description}</div>
      </td>
      <td className="px-2.5 py-3">
        <Severity code={row.severity} />
      </td>
      <td className="px-2.5 py-3 font-mono text-[12.5px]">{row.agent_name}</td>
      <td className="px-2.5 py-3 text-right tabular-nums">{row.occurrence_count}</td>
      <td className={`px-2.5 py-3 ${MUTED}`}>{spanText(row.first_seen_at, row.last_seen_at)}</td>
      <td className="px-2.5 py-3">
        <div>
          {row.suggested_action === null
            ? D.noSuggestion
            : labelOf(S.ai1.action, row.suggested_action)}
        </div>
        {row.disagreement && (
          <div className={`mt-1 text-xs font-semibold ${AMBER}`}>{D.disagreement}</div>
        )}
      </td>
      <td className="px-3.5 py-3">
        <div ref={answer} tabIndex={-1} className={`outline-none ${FOCUS}`}>
          {note !== null && (
            <p
              role="alert"
              className={`mb-2 rounded-lg border px-3 py-2 text-[12.5px] leading-snug ${NOTE_TONE[note.tone]}`}
            >
              {note.text}
            </p>
          )}
          {reviewed ? (
            <Reviewed row={row} />
          ) : (
            !locked && (
              <div
                role="group"
                aria-label={D.group(row.rule_id, row.agent_name)}
                className="flex gap-1.5"
              >
                {DIGEST_VERDICTS.map((verdict) => (
                  <button
                    key={verdict}
                    type="button"
                    disabled={mutation.isPending}
                    onClick={() => review(verdict)}
                    className={`${BUTTON} ${VERDICT_TONE[verdict]}`}
                  >
                    {S.admin.verdict[verdict]}
                  </button>
                ))}
              </div>
            )
          )}
        </div>
      </td>
    </tr>
  );
}

// --- the table and what is round it -------------------------------------------------------------------------

const COLUMNS: { id: string; header: string; className: string }[] = [
  { id: "rule", header: D.table.colRule, className: "px-3.5" },
  { id: "ruleDesc", header: D.table.colRuleDesc, className: "px-2.5" },
  { id: "severity", header: D.table.colSeverity, className: "w-20 px-2.5" },
  { id: "agent", header: D.table.colAgent, className: "w-32 px-2.5" },
  { id: "count", header: D.table.colCount, className: "w-16 px-2.5 text-right" },
  { id: "span", header: D.table.colSpan, className: "w-32 px-2.5" },
  { id: "suggestion", header: D.table.colSuggestion, className: "w-40 px-2.5" },
  { id: "review", header: D.table.colReview, className: "w-64 px-3.5" },
];

const PILL = "rounded-full border border-border bg-surface px-3 py-1.5";

function Summary({ rows }: { rows: readonly DigestRow[] }) {
  const sum = summarise(rows);
  return (
    <ul className="flex flex-wrap gap-2.5 text-[13px]">
      <li className={PILL}>{D.summary.clusters(sum.clusters)}</li>
      <li className={PILL}>{D.summary.reviewed(sum.reviewed, sum.waiting)}</li>
      <li
        className={`rounded-full border px-3 py-1.5 ${
          sum.disagreements > 0
            ? `border-[#5a3a14] bg-[#2a1a0a] ${AMBER}`
            : "border-border bg-surface"
        }`}
      >
        {D.summary.disagreements(sum.disagreements)}
      </li>
    </ul>
  );
}

function Legend() {
  const swatch = "inline-block h-3.5 w-3.5 shrink-0 rounded-[3px] border";
  return (
    <div className={`flex flex-wrap gap-x-6 gap-y-2 text-[12.5px] ${MUTED}`}>
      <span className="flex items-center gap-2">
        <span aria-hidden="true" className={`${swatch} border-[#5a3a14] bg-[#2a1a0a]`} />
        {D.legend.disagreement}
      </span>
      <span className="flex items-center gap-2">
        <span aria-hidden="true" className={`${swatch} border-border bg-[#10151c]`} />
        {D.legend.reviewed}
      </span>
      <span>{D.legend.wrong}</span>
    </div>
  );
}

/** Nothing to review: no rule is on (and there is no cluster), or the rules are on and that day had none. */
function Empty({ data }: { data: DigestResponse }) {
  if (!data.rules_enabled) {
    return (
      <section className={PANEL}>
        <h2 className="text-[17px] font-semibold">{D.noRules.title}</h2>
        <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">{D.noRules.body}</p>
        <Link
          to="/admin/rules"
          className={`self-start text-sm text-[#7fb0ff] underline-offset-2 hover:underline ${FOCUS}`}
        >
          {D.noRules.link}
        </Link>
      </section>
    );
  }
  return (
    <section className={PANEL}>
      <h2 className="text-[17px] font-semibold">{D.noClusters.title(formatDay(data.day))}</h2>
      <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">{D.noClusters.body}</p>
    </section>
  );
}

const SKELETON = "animate-pulse rounded-lg bg-[#1a222c]";

/** The layout of the page, so nothing jumps when the rows arrive. */
function Skeleton() {
  return (
    <div role="status" aria-busy="true" className="space-y-4">
      <span className="sr-only">{S.common.loading}</span>
      <div aria-hidden="true" className="flex gap-2.5">
        {[0, 1, 2].map((n) => (
          <div key={n} className={`${SKELETON} h-8 w-40`} />
        ))}
      </div>
      <div aria-hidden="true" className={`${SKELETON} h-72`} />
    </div>
  );
}

/** What a failed first read says: the reason's own text for a 503 or a 403, else the status or the connection. */
function loadErrorHint(error: unknown): string {
  const failure = adminErrorOf(error);
  if (failure.kind === "reason" || failure.kind === "field") return adminReasonText(failure);
  return failure.status === 0 ? D.loadErrorOffline : D.loadErrorServer(failure.status);
}

/** The location state `<Navigate>` leaves when it replaced a refused day: the page says so once. */
function fellBack(state: unknown): boolean {
  return typeof state === "object" && state !== null && "badDay" in state && state.badDay === true;
}

// --- the page ----------------------------------------------------------------------------------------------------

export function DigestPage() {
  const client = useQueryClient();
  const location = useLocation();
  const [params, setParams] = useSearchParams();
  // `null`: no day in the URL, so the server's default. An empty `?day=` is a day, and a bad one.
  const dayParam = params.get("day");
  const key = adminKeys.digest(dayParam);
  const query = useQuery({
    queryKey: key,
    queryFn: () => getDigest(dayParam ?? undefined),
  });
  const data = query.data;

  // A day the server refuses: the default day, in the URL too, with the notice. Not when the default day
  // itself is refused (that is a page error below, not a loop).
  if (data === undefined && dayParam !== null && query.isError && isBadDay(query.error)) {
    const rest = new URLSearchParams(params);
    rest.delete("day");
    return (
      <Navigate to={{ pathname: PATH, search: rest.toString() }} replace state={{ badDay: true }} />
    );
  }

  if (data === undefined && query.isError) {
    return (
      <div className="space-y-3">
        <PageError title={S.admin.common.loadError} onRetry={() => void query.refetch()} />
        <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">{loadErrorHint(query.error)}</p>
      </div>
    );
  }

  const recorded = (row: DigestRow) =>
    client.setQueryData<DigestResponse>(key, (old) =>
      old === undefined ? old : withRow(old, row),
    );

  const pickDay = (day: string) => {
    if (day === "") return;
    // A replace, not a push: a date input fires a change on every keystroke of its fields, and Back should
    // leave the page, not walk through each day passed.
    setParams(
      (before) => {
        const next = new URLSearchParams(before);
        next.set("day", day);
        return next;
      },
      { replace: true },
    );
  };

  let body: ReactNode;
  if (data === undefined) {
    body = <Skeleton />;
  } else if (data.rows.length === 0) {
    body = <Empty data={data} />;
  } else {
    body = (
      <>
        <Summary rows={data.rows} />
        <div className="overflow-x-auto rounded-[10px] border border-border bg-surface">
          <table className="w-full border-collapse text-left text-[13px]">
            <caption className="sr-only">{D.table.label}</caption>
            <thead className="bg-[#18202a] text-xs text-muted">
              <tr>
                {COLUMNS.map((column) => (
                  <th
                    key={column.id}
                    scope="col"
                    className={`py-2.5 font-medium ${column.className}`}
                  >
                    {column.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.rows.map((row) => (
                <DigestRowView
                  key={`${data.day}/${row.alert_id}`}
                  row={row}
                  day={data.day}
                  onRecorded={recorded}
                />
              ))}
            </tbody>
          </table>
        </div>
        <Legend />
      </>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-end gap-4">
        <div className="flex-1 space-y-1">
          <h1 className="text-2xl font-semibold">{S.admin.title.digest}</h1>
          <p className={`text-sm ${MUTED}`}>{D.subtitle}</p>
        </div>
        <label className="flex flex-col gap-1.5 text-xs text-muted">
          {D.dayLabel}
          <input
            type="date"
            value={data?.day ?? dayParam ?? ""}
            onChange={(event) => pickDay(event.target.value)}
            className={`h-10 rounded-md border border-[#2e3a48] bg-[#0f141b] px-2.5 text-sm text-text ${FOCUS}`}
          />
        </label>
        <Link
          to={data === undefined ? PATH : `${PATH}?${new URLSearchParams({ day: data.today })}`}
          className={`flex h-10 items-center rounded-md border border-[#2e3a48] px-3.5 text-sm text-[#c9d3df] hover:bg-surface ${FOCUS}`}
        >
          {D.today}
        </Link>
      </div>

      {data !== undefined && fellBack(location.state) && (
        <div
          role="alert"
          className="rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-2.5 text-[13.5px] leading-snug text-[#fcd9a8]"
        >
          {D.badDay(formatDay(data.day))}
        </div>
      )}
      {data !== undefined && query.isError && (
        <div
          role="alert"
          className="flex items-center justify-between gap-3 rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-2.5 text-[13.5px] text-[#fcd9a8]"
        >
          <span>{D.refreshFailed}</span>
          <button
            type="button"
            onClick={() => void query.refetch()}
            className={`rounded border border-[#5a3a14] px-2 py-0.5 text-xs hover:bg-ground ${FOCUS}`}
          >
            {S.common.retry}
          </button>
        </div>
      )}

      {body}
    </div>
  );
}
