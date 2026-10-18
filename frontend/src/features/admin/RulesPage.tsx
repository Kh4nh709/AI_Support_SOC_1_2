// `/admin/rules` (P11-T14, spec §4.4): the six hard blocks that run before every rule, the rules table (the
// conditions as chips, the 7-day width warning, an enable/disable button with a confirmation dialog) and the
// two-step create (`RuleCreate`). TanStack Query owns the one read, `adminKeys.rules`; each write goes through
// `api/admin.ts` with a JSON body and invalidates through `invalidateAfter`. There are no optimistic updates.
//
// Each block fails alone: the hard blocks are static text, the create section does not read the list, and a
// failed list is a PageError with a retry in place of the title while the rest of the page stays.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import {
  adminErrorOf,
  listRules,
  toggleRule,
  HARD_BLOCK_CODES,
  type RuleRow,
} from "../../api/admin";
import { DataTable, type Column } from "../../components/DataTable";
import { PageError } from "../../components/PageError";
import { Toast } from "../../components/Toast";
import { formatTime } from "../../format";
import { S } from "../../strings";
import { ConfirmDialog } from "./ConfirmDialog";
import { RuleCreate } from "./RuleCreate";
import { adminKeys, invalidateAfter } from "./adminKeys";
import { failureText } from "./ruleErrors";
import { formatCondition } from "./ruleFields";

const R = S.admin.rulesPage;

const PANEL = "rounded-[10px] border border-border bg-surface";

/** What the page says above the table: a thing done (a toast), or a rule that was no longer there (an alert). */
type Notice = { kind: "done" | "missing"; text: string };

/** A toggle the admin is being asked to confirm: the rule, and the state it would be given. */
type Target = { rule: RuleRow; enable: boolean };

const fmtPct = (n: number) => n.toLocaleString("vi-VN", { maximumFractionDigits: 1 });

/** The 7-day width of a rule: a warning when it is over the threshold the row carries, else the plain figure. */
function Width({ rule }: { rule: RuleRow }) {
  if (rule.width_pct === null) return <span className="text-[#5e6b7a]">{S.common.missing}</span>;
  if (rule.width_pct > rule.width_threshold_pct) {
    return (
      <span className="font-semibold text-medium">
        {R.table.widthWarning(fmtPct(rule.width_pct), fmtPct(rule.width_threshold_pct))}
      </span>
    );
  }
  return <span className="text-[#aeb9c6]">{fmtPct(rule.width_pct)}%</span>;
}

function Skeleton() {
  return (
    <div role="status" aria-busy="true" className={`${PANEL} space-y-3 p-4`}>
      <span className="sr-only">{S.common.loading}</span>
      <div
        aria-hidden="true"
        className="h-5 w-1/2 animate-pulse rounded bg-[#1f2833] motion-reduce:animate-none"
      />
      {[0, 1, 2].map((i) => (
        <div
          key={i}
          aria-hidden="true"
          className="h-10 animate-pulse rounded bg-[#1a222c] motion-reduce:animate-none"
        />
      ))}
    </div>
  );
}

function HardBlocks() {
  return (
    <section aria-label={R.hardBlocks.label} className={`${PANEL} space-y-3 px-5 py-4`}>
      <div className="flex items-baseline gap-2.5">
        <h2 className="flex-1 text-[15px] font-semibold">{R.hardBlocks.title}</h2>
        <span className="text-xs text-muted">{R.hardBlocks.note}</span>
      </div>
      <ul className="grid grid-cols-3 gap-2">
        {HARD_BLOCK_CODES.map((code) => (
          <li
            key={code}
            className="flex items-center gap-2.5 rounded-lg border border-[#3a2a30] bg-[#1a1418] px-3 py-2 text-[13px]"
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#fda4af"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
              className="shrink-0"
            >
              <circle cx="12" cy="12" r="9" />
              <path d="M5.6 5.6l12.8 12.8" />
            </svg>
            <span>{S.admin.hardBlock[code]}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function RulesPage() {
  const client = useQueryClient();
  const rules = useQuery({ queryKey: adminKeys.rules, queryFn: () => listRules() });
  const nameRef = useRef<HTMLInputElement>(null);
  const [target, setTarget] = useState<Target | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);

  const toggle = useMutation({
    mutationFn: ({ rule, enable }: Target) => toggleRule(rule.rule_id, enable),
    onSuccess: async (_done, { rule, enable }) => {
      await invalidateAfter(client, "toggleRule");
      setTarget(null);
      setNotice({
        kind: "done",
        text: enable ? R.toggle.doneOn(rule.name) : R.toggle.doneOff(rule.name),
      });
    },
    onError: (error) => {
      const read = adminErrorOf(error);
      if (read.kind === "reason" && read.reason === "rule_not_found") {
        // Somebody else removed it, or the list is old: say so, close the dialog and read the list again.
        setTarget(null);
        setNotice({ kind: "missing", text: S.admin.reason.rule_not_found });
        void invalidateAfter(client, "toggleRule");
      }
    },
  });

  function ask(rule: RuleRow) {
    toggle.reset();
    setNotice(null);
    setTarget({ rule, enable: !rule.enabled });
  }

  function cancel() {
    toggle.reset();
    setTarget(null);
  }

  const focusName = () => nameRef.current?.focus();

  const data = rules.data;
  const columns: Column<RuleRow>[] = [
    {
      id: "name",
      header: R.table.nameAndReason,
      cell: (rule) => (
        <div className="space-y-0.5">
          <div className="break-words font-semibold">{rule.name}</div>
          <div className="break-words text-[12.5px] leading-snug text-muted">{rule.reason}</div>
        </div>
      ),
    },
    {
      id: "conditions",
      header: R.table.conditions,
      className: "w-[330px]",
      cell: (rule) =>
        Array.isArray(rule.match) && rule.match.length > 0 ? (
          <ul className="flex flex-wrap gap-1.5">
            {rule.match.map((condition, i) => (
              <li
                key={i}
                className="break-all rounded border border-[#2e3a48] bg-[#1c2530] px-2 py-0.5 font-mono text-xs"
              >
                {formatCondition(condition)}
              </li>
            ))}
          </ul>
        ) : (
          <span className="text-xs text-medium">{R.table.noConditions}</span>
        ),
    },
    {
      id: "width",
      header: R.table.width,
      className: "w-40",
      cell: (rule) => <Width rule={rule} />,
    },
    {
      id: "created",
      header: R.table.created,
      className: "w-28 text-[#aeb9c6]",
      cell: (rule) => formatTime(rule.created_at),
    },
    {
      id: "state",
      header: R.table.state,
      className: "w-24",
      cell: (rule) => (
        <span
          className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${
            rule.enabled ? "bg-[#133528] text-[#9ff0c5]" : "bg-[#1c2530] text-[#8fa0b3]"
          }`}
        >
          {rule.enabled ? R.table.on : R.table.off}
        </span>
      ),
    },
    {
      id: "action",
      header: R.table.action,
      className: "w-24 text-right",
      cell: (rule) => (
        <button
          type="button"
          onClick={() => ask(rule)}
          aria-label={
            rule.enabled ? R.table.turnOffLabel(rule.name) : R.table.turnOnLabel(rule.name)
          }
          className="h-[34px] rounded-md border border-[#2e3a48] px-3 text-[13px] text-[#c9d3df] hover:bg-ground focus-visible:outline-2 focus-visible:outline-text"
        >
          {rule.enabled ? R.table.turnOff : R.table.turnOn}
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-5">
      {rules.isError && data === undefined ? (
        <PageError title={R.loadFailed} onRetry={() => void rules.refetch()} />
      ) : (
        <div className="flex items-end gap-4">
          <div className="flex flex-1 flex-col gap-1">
            <h1 className="text-[26px] font-semibold">{S.admin.title.rules}</h1>
            {data !== undefined ? (
              <p className="text-sm text-[#aeb9c6]">
                {R.subtitle(data.length, data.filter((rule) => rule.enabled).length)}
              </p>
            ) : null}
          </div>
          <button
            type="button"
            onClick={focusName}
            className="h-10 rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white hover:bg-blue-500 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text"
          >
            {R.create}
          </button>
        </div>
      )}

      {notice?.kind === "done" ? (
        <Toast onClose={() => setNotice(null)}>
          <p>{notice.text}</p>
        </Toast>
      ) : null}
      {notice?.kind === "missing" ? (
        <div
          role="alert"
          className="flex items-start justify-between gap-3 rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-3 text-[13.5px] leading-snug text-[#fcd9a8]"
        >
          <p>{notice.text}</p>
          <button
            type="button"
            onClick={() => setNotice(null)}
            className="shrink-0 rounded border border-[#5a3a14] px-2 py-0.5 text-xs hover:bg-ground focus-visible:outline-2 focus-visible:outline-text"
          >
            {S.common.close}
          </button>
        </div>
      ) : null}

      <HardBlocks />

      {rules.isPending ? (
        <Skeleton />
      ) : data !== undefined && data.length === 0 ? (
        <section className={`${PANEL} space-y-3 p-5`}>
          <h2 className="text-[17px] font-semibold">{R.empty.title}</h2>
          <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">{R.empty.body}</p>
          <button
            type="button"
            onClick={focusName}
            className="h-10 rounded-lg bg-blue-600 px-4 text-sm font-semibold text-white hover:bg-blue-500 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text"
          >
            {R.create}
          </button>
        </section>
      ) : data !== undefined ? (
        <div className="space-y-2">
          <DataTable
            label={R.table.label}
            columns={columns}
            rows={data}
            rowKey={(rule) => rule.rule_id}
            busy={rules.isFetching}
          />
          <p className="px-1 text-xs leading-relaxed text-muted">
            {R.table.widthNote(fmtPct(data[0]!.width_threshold_pct))}
          </p>
        </div>
      ) : null}

      <RuleCreate
        nameRef={nameRef}
        onCreated={(name) => setNotice({ kind: "done", text: R.builder.created(name) })}
      />

      {target !== null ? (
        <ConfirmDialog
          title={
            target.enable ? R.toggle.onTitle(target.rule.name) : R.toggle.offTitle(target.rule.name)
          }
          confirmLabel={target.enable ? R.toggle.onConfirm : R.toggle.offConfirm}
          busy={toggle.isPending}
          error={toggle.isError ? failureText(toggle.error, R.toggle.failed) : undefined}
          onConfirm={() => toggle.mutate(target)}
          onCancel={cancel}
        >
          {target.enable ? R.toggle.onBody : R.toggle.offBody}
        </ConfirmDialog>
      ) : null}
    </div>
  );
}
