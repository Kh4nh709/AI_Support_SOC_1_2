// The two-step create of the rules page (spec §4.4): step 1 is a name, a reason and a condition builder whose
// choices come from the server's whitelist (`ruleFields.ts`), step 2 is the preview (`POST
// /api/admin/rules/simulate`, which writes nothing). "Tạo rule" opens only for the exact conditions last
// previewed: the preview is remembered with a key made of the conditions it was sent (`matchKey`), the
// button compares that key with the one the builder makes NOW, and the create sends the previewed
// conditions, never the builder's. Any edit after the preview makes the two differ until the next preview.
//
// A 422 about the conditions (the whitelist's text or FastAPI's list-shaped detail) is shown under the
// conditions, and nothing the admin typed is lost. Any other failure of the preview is shown in the preview
// panel, and of the create under the buttons: each alone, the rest of the page untouched.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState, type ReactNode, type Ref } from "react";
import { Link } from "react-router";
import { createRule, simulateRule, type RuleCondition, type SimulateResult } from "../../api/admin";
import { S, labelOf } from "../../strings";
import { invalidateAfter } from "./adminKeys";
import { conditionProblemOf, failureText } from "./ruleErrors";
import { useSubmitLatch } from "./useSubmitLatch";
import {
  OP_VALUE_KIND,
  RULE_FIELDS,
  formatValue,
  hardBlockedValues,
  matchKey,
  matchOf,
  newDraftRow,
  opsOf,
  toCondition,
  typeOf,
  withField,
  withOp,
  type DraftRow,
  type RuleField,
  type RuleOp,
  type ValueProblem,
} from "./ruleFields";

const R = S.admin.rulesPage;

const PANEL = "rounded-[10px] border border-border bg-surface p-5";
const HEADING = "text-[17px] font-semibold";
const STEP = "text-xs text-muted";
const INPUT =
  "h-10 rounded-md border border-border bg-ground px-3 text-sm text-text focus-visible:outline-2 focus-visible:outline-text";
const CONTROL =
  "h-[38px] min-w-0 rounded-md border bg-ground px-2 font-mono text-[12.5px] text-text focus-visible:outline-2 focus-visible:outline-text";
const GHOST =
  "rounded-md border border-border text-text hover:bg-ground focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-text";
const PRIMARY =
  "h-11 rounded-lg px-5 text-[15px] font-semibold focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-text " +
  "bg-blue-600 text-white hover:bg-blue-500 " +
  "disabled:cursor-not-allowed disabled:border disabled:border-border disabled:bg-transparent disabled:text-muted";

/** The preview of the conditions last sent, with the key of what was sent. */
type Previewed = { key: string; match: RuleCondition[]; result: SimulateResult };

/** The last failure, with the key of the conditions it was about: it is shown only while the builder still holds those. */
type Failure = { step: "preview" | "create"; error: unknown; key: string };

const fmtInt = (n: number) => n.toLocaleString("vi-VN");

// --- one condition of the builder ---------------------------------------------------------------------------

function placeholderOf(row: DraftRow): string {
  const P = R.builder.placeholder;
  const integer = typeOf(row.field) === "integer";
  switch (OP_VALUE_KIND[row.op]) {
    case "list":
      return integer ? P.integerList : P.list;
    case "integer":
      return P.integer;
    case "text":
      return row.op === "cidr" ? P.cidr : P.prefix;
    case "scalar":
      return integer ? P.integer : P.text;
  }
}

function ConditionRow({
  index,
  row,
  problem,
  hint,
  idBase,
  onChange,
  onRemove,
}: {
  index: number;
  row: DraftRow;
  /** Why the value cannot be used, shown only after the admin tried to preview. */
  problem: ValueProblem | null;
  hint: ReactNode;
  idBase: string;
  onChange: (next: DraftRow) => void;
  onRemove: () => void;
}) {
  const valueId = `${idBase}-value`;
  const noteId = `${idBase}-note`;
  const note = problem !== null ? R.builder.problem[problem] : hint;
  const border = problem !== null ? "border-critical" : "border-border";
  return (
    <div role="group" aria-label={R.builder.group(index + 1)} className="space-y-1">
      <div className="grid grid-cols-[150px_84px_minmax(0,1fr)_36px] items-center gap-2">
        <select
          aria-label={R.builder.field}
          value={row.field}
          onChange={(event) => onChange(withField(row, event.target.value as RuleField))}
          className={`${CONTROL} border-border`}
        >
          {RULE_FIELDS.map((field) => (
            <option key={field} value={field}>
              {field}
            </option>
          ))}
        </select>
        <select
          aria-label={R.builder.op}
          value={row.op}
          onChange={(event) => onChange(withOp(row, event.target.value as RuleOp))}
          className={`${CONTROL} border-border`}
        >
          {opsOf(row.field).map((op) => (
            <option key={op} value={op}>
              {op}
            </option>
          ))}
        </select>
        {typeOf(row.field) === "boolean" ? (
          <select
            id={valueId}
            aria-label={R.builder.value}
            value={row.text}
            onChange={(event) => onChange({ ...row, text: event.target.value })}
            aria-invalid={problem !== null || undefined}
            aria-describedby={note ? noteId : undefined}
            className={`${CONTROL} ${border}`}
          >
            <option value="true">true</option>
            <option value="false">false</option>
          </select>
        ) : (
          <input
            id={valueId}
            type="text"
            aria-label={R.builder.value}
            value={row.text}
            placeholder={placeholderOf(row)}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => onChange({ ...row, text: event.target.value })}
            aria-invalid={problem !== null || undefined}
            aria-describedby={note ? noteId : undefined}
            className={`${CONTROL} ${border}`}
          />
        )}
        <button
          type="button"
          aria-label={R.builder.remove}
          onClick={onRemove}
          className={`h-9 w-9 text-muted ${GHOST}`}
        >
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            aria-hidden="true"
            className="mx-auto"
          >
            <path d="M6 6l12 12M18 6L6 18" />
          </svg>
        </button>
      </div>
      {note ? (
        <p id={noteId} className={`text-xs ${problem !== null ? "text-critical" : "text-medium"}`}>
          {note}
        </p>
      ) : null}
    </div>
  );
}

// --- the preview ---------------------------------------------------------------------------------------------

/** Known severities, worst first; a code this page does not know comes after them, in the order it came. */
const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const SEVERITY_TONE: Record<string, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
};

function bySeverity(counts: Record<string, number>): [string, number][] {
  const known = SEVERITY_ORDER.filter((code) => Object.hasOwn(counts, code));
  const rest = Object.keys(counts).filter((code) => !SEVERITY_ORDER.includes(code));
  return [...known, ...rest].map((code) => [code, counts[code]!]);
}

function Split({
  title,
  entries,
  total,
  toneOf,
}: {
  title: string;
  entries: [string, number][];
  total: number;
  toneOf: (code: string) => string;
}) {
  if (entries.length === 0) return null;
  return (
    <div className="space-y-2">
      <h3 className="text-[13px] font-semibold text-[#aeb9c6]">{title}</h3>
      <ul className="space-y-1.5">
        {entries.map(([code, count]) => {
          // A bar is an SVG whose rect has a width ATTRIBUTE: the CSP forbids `style`.
          const pct = total > 0 ? Math.min(100, (count / total) * 100) : 0;
          return (
            <li
              key={code}
              className="grid grid-cols-[84px_minmax(0,1fr)_44px] items-center gap-2 text-xs"
            >
              <span className="break-all font-mono">{code}</span>
              <svg
                viewBox="0 0 100 8"
                preserveAspectRatio="none"
                aria-hidden="true"
                className={`h-2 w-full rounded-full bg-border ${toneOf(code)}`}
              >
                <rect width={pct} height="8" fill="currentColor" />
              </svg>
              <span className="text-right">{fmtInt(count)}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** Why a rule that matches nothing closes nothing: how many clusters its conditions matched, and which block stopped them. */
function Tally({ result }: { result: SimulateResult }) {
  const tally = result.hard_block_tally;
  const matched = tally?.matched ?? 0;
  return (
    <div className="space-y-2 rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-3 text-[13.5px] leading-relaxed text-[#fcd9a8]">
      {tally !== null && matched > 0 ? (
        <>
          <p>{R.preview.tallyMatched(fmtInt(matched))}</p>
          <ul className="list-disc space-y-0.5 pl-5">
            {tally.blocks
              .filter((block) => block.count > 0)
              .map((block) => (
                <li key={block.code}>
                  {labelOf(S.admin.hardBlock, block.code)}: {fmtInt(block.count)}
                </li>
              ))}
          </ul>
        </>
      ) : (
        <p>{R.preview.tallyNone}</p>
      )}
      <p className="text-xs text-text">{R.preview.tallyNote}</p>
    </div>
  );
}

/** The most sample alerts shown (spec §4.4). */
const SAMPLE_LIMIT = 20;

function PreviewResult({ result, stale }: { result: SimulateResult; stale: boolean }) {
  return (
    <div className={stale ? "space-y-4 opacity-60" : "space-y-4"}>
      <dl className="grid grid-cols-2 gap-3">
        <div className="space-y-1 rounded-lg border border-border bg-ground px-4 py-3.5">
          <dt className="text-[12.5px] text-muted">{R.preview.clusters}</dt>
          <dd className="text-[28px] font-bold leading-none">{fmtInt(result.clusters)}</dd>
        </div>
        <div className="space-y-1 rounded-lg border border-border bg-ground px-4 py-3.5">
          <dt className="text-[12.5px] text-muted">{R.preview.alerts}</dt>
          <dd className="text-[28px] font-bold leading-none">{fmtInt(result.alerts)}</dd>
        </div>
      </dl>
      {result.clusters === 0 ? <Tally result={result} /> : null}
      <div className="grid grid-cols-2 gap-4">
        <Split
          title={R.preview.bySeverity}
          entries={bySeverity(result.by_severity)}
          total={result.clusters}
          toneOf={(code) =>
            Object.hasOwn(SEVERITY_TONE, code) ? SEVERITY_TONE[code]! : "text-muted"
          }
        />
        <Split
          title={R.preview.byAsset}
          entries={Object.entries(result.by_asset_criticality)}
          total={result.clusters}
          toneOf={() => "text-[#5b8def]"}
        />
      </div>
      {result.samples.length > 0 ? (
        <div className="space-y-2">
          <h3 className="text-[13px] font-semibold text-[#aeb9c6]">{R.preview.samples}</h3>
          <ul className="grid grid-cols-3 gap-1.5">
            {result.samples.slice(0, SAMPLE_LIMIT).map((id) => (
              <li key={id} className="min-w-0">
                <Link
                  to={`/alerts/${encodeURIComponent(id)}`}
                  className="block break-all rounded-md border border-border bg-ground px-2 py-1.5 font-mono text-xs text-ai-accent underline-offset-2 hover:underline focus-visible:outline-2 focus-visible:outline-text"
                >
                  {id}
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

// --- the create section ---------------------------------------------------------------------------------------

export function RuleCreate({
  nameRef,
  onCreated,
}: {
  /** The name field, so the page's "Tạo rule mới" buttons can move the focus to it. */
  nameRef: Ref<HTMLInputElement>;
  /** The rule is created and the list asked again: the page says so. */
  onCreated: (name: string) => void;
}) {
  const client = useQueryClient();
  const uid = useId();
  const nextId = useRef(2);
  const [name, setName] = useState("");
  const [reason, setReason] = useState("");
  const [rows, setRows] = useState<DraftRow[]>(() => [newDraftRow(1)]);
  // The admin has pressed "Xem trước" at least once: from then on a value box says what is wrong with it.
  const [attempted, setAttempted] = useState(false);
  const [previewed, setPreviewed] = useState<Previewed | null>(null);
  const [failure, setFailure] = useState<Failure | null>(null);

  const preview = useMutation({
    mutationFn: (match: RuleCondition[]) => simulateRule(match),
    onSuccess: (result, match) => setPreviewed({ key: matchKey(match), match, result }),
    onError: (error, match) => setFailure({ step: "preview", error, key: matchKey(match) }),
  });
  const create = useMutation({
    mutationFn: (body: { name: string; reason: string; match: RuleCondition[] }) =>
      createRule(body),
    onSuccess: async (_created, body) => {
      await invalidateAfter(client, "createRule");
      setName("");
      setReason("");
      setRows([newDraftRow(nextId.current++)]);
      setAttempted(false);
      setPreviewed(null);
      setFailure(null);
      onCreated(body.name);
    },
    onError: (error, body) => setFailure({ step: "create", error, key: matchKey(body.match) }),
  });
  // `disabled={isPending}` is one render late (TanStack tells React through a setTimeout(0)): the latch is
  // what keeps two clicks of one tick to one request.
  const runPreview = useSubmitLatch(preview);
  const runCreate = useSubmitLatch(create);

  const parsed = rows.map(toCondition);
  const match = matchOf(rows);
  const currentKey = match === null ? null : matchKey(match);
  const fresh = previewed !== null && currentKey !== null && previewed.key === currentKey;
  const stale = previewed !== null && !fresh;
  const hasText = name.trim() !== "" && reason.trim() !== "";
  const canCreate = fresh && hasText && !create.isPending;

  // A failure belongs to the conditions it was about: edit them and it goes, put them back and it returns.
  const shown = failure !== null && failure.key === currentKey ? failure : null;
  const conditionProblem = shown === null ? null : conditionProblemOf(shown.error);
  const problemId = `${uid}-condition-problem`;
  const hintId = `${uid}-hint`;

  function addRow() {
    const id = nextId.current++;
    setRows((current) => [...current, newDraftRow(id)]);
  }

  function setRow(next: DraftRow) {
    setRows((current) => current.map((row) => (row.id === next.id ? next : row)));
  }

  function onPreview() {
    setAttempted(true);
    if (match === null) {
      // Nothing is sent; the first value box that is wrong takes the focus, and says why.
      const bad = rows.find((row) => !toCondition(row).ok);
      if (bad) document.getElementById(`${uid}-${bad.id}-value`)?.focus();
      return;
    }
    // A second click in the tick of the first finds the latch shut and sends nothing.
    if (!runPreview(match)) return;
    setFailure(null);
    setPreviewed(null);
  }

  function onCreate() {
    if (previewed === null || !canCreate) return;
    if (!runCreate({ name: name.trim(), reason: reason.trim(), match: previewed.match })) return;
    setFailure(null);
  }

  const hint = !fresh
    ? stale
      ? R.builder.hintStale
      : R.builder.hintIdle
    : !hasText
      ? R.builder.hintNeedText
      : R.builder.hintReady;

  const noteFor = (row: DraftRow, parsedRow: ReturnType<typeof toCondition>): ReactNode => {
    if (!parsedRow.ok) return null;
    const blocked = hardBlockedValues(parsedRow.condition);
    if (blocked.length > 0) {
      return R.builder.neverCloses(
        row.field,
        blocked.map((value) => formatValue(value)).join(", "),
      );
    }
    if (typeOf(row.field) === "string") {
      // An `eq` string is trimmed (`parseValue`), a `prefix` is sent as typed.
      if (row.op === "eq" && row.text.trim() === "") return R.builder.emptyEq;
      if (row.op === "prefix" && row.text === "") return R.builder.emptyPrefix;
    }
    return null;
  };

  const generic = shown !== null && conditionProblem === null ? shown : null;

  return (
    <div className="grid grid-cols-2 gap-5">
      <section aria-labelledby={`${uid}-create`} className={`${PANEL} space-y-3.5`}>
        <div className="flex items-baseline gap-2.5">
          <h2 id={`${uid}-create`} className={`${HEADING} flex-1`}>
            {R.create}
          </h2>
          <span className={STEP}>{R.builder.step}</span>
        </div>
        <label className="flex flex-col gap-1.5 text-[13px] text-[#aeb9c6]">
          {R.builder.name}
          <input
            ref={nameRef}
            type="text"
            value={name}
            autoComplete="off"
            onChange={(event) => setName(event.target.value)}
            className={INPUT}
          />
        </label>
        <label className="flex flex-col gap-1.5 text-[13px] text-[#aeb9c6]">
          {R.builder.reason}
          <input
            type="text"
            value={reason}
            autoComplete="off"
            onChange={(event) => setReason(event.target.value)}
            className={INPUT}
          />
        </label>
        <fieldset
          aria-describedby={conditionProblem !== null ? problemId : undefined}
          className="m-0 space-y-2 border-0 p-0"
        >
          <legend className="mb-1.5 text-[13px] text-[#aeb9c6]">{R.builder.conditions}</legend>
          {rows.map((row, index) => {
            const result = parsed[index]!;
            return (
              <ConditionRow
                key={row.id}
                index={index}
                row={row}
                idBase={`${uid}-${row.id}`}
                problem={attempted && !result.ok ? result.problem : null}
                hint={noteFor(row, result)}
                onChange={setRow}
                onRemove={() => setRows((current) => current.filter((r) => r.id !== row.id))}
              />
            );
          })}
          {rows.length === 0 ? (
            <p className="text-xs leading-relaxed text-medium">{R.builder.none}</p>
          ) : null}
          <button
            type="button"
            onClick={addRow}
            className="h-[34px] rounded-md border border-dashed border-border px-3 text-[13px] text-[#aeb9c6] hover:bg-ground focus-visible:outline-2 focus-visible:outline-text"
          >
            {R.builder.add}
          </button>
        </fieldset>
        {conditionProblem !== null ? (
          <div
            id={problemId}
            role="alert"
            className="space-y-1.5 rounded-lg border border-critical/40 bg-critical-bg px-3.5 py-3 text-[13px] leading-snug text-critical"
          >
            <p>{conditionProblem.sentence}</p>
            {conditionProblem.details.map((line, i) => (
              <p key={i} className="break-words font-mono text-xs text-text">
                {line}
              </p>
            ))}
          </div>
        ) : null}
        <p className="text-xs leading-relaxed text-muted">{R.builder.help}</p>
        <div className="flex gap-2.5">
          <button
            type="button"
            onClick={onPreview}
            disabled={preview.isPending || create.isPending}
            className={PRIMARY}
          >
            {preview.isPending ? R.builder.previewing : R.builder.preview}
          </button>
          <button
            type="button"
            onClick={onCreate}
            disabled={!canCreate}
            aria-describedby={hintId}
            className={PRIMARY}
          >
            {create.isPending ? R.builder.submitting : R.builder.submit}
          </button>
        </div>
        <p id={hintId} className="text-xs leading-relaxed text-muted">
          {hint}
        </p>
        {generic !== null && generic.step === "create" ? (
          <p role="alert" className="text-[13px] text-critical">
            {failureText(generic.error, R.builder.createFailed)}
          </p>
        ) : null}
      </section>

      <section
        aria-labelledby={`${uid}-preview`}
        aria-live="polite"
        className={`${PANEL} space-y-4`}
      >
        <div className="flex items-baseline gap-2.5">
          <h2 id={`${uid}-preview`} className={`${HEADING} flex-1`}>
            {R.preview.title}
          </h2>
          <span className={STEP}>{R.preview.step}</span>
        </div>
        {preview.isPending ? (
          <div role="status" className="flex items-center gap-2.5 text-[13.5px] text-text">
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="#7fb0ff"
              strokeWidth="2"
              strokeLinecap="round"
              aria-hidden="true"
              className="animate-spin motion-reduce:animate-none"
            >
              <path d="M12 3a9 9 0 1 0 9 9" />
            </svg>
            <span>{R.preview.running}</span>
          </div>
        ) : previewed !== null ? (
          <>
            {stale ? (
              <p className="rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-2.5 text-[13px] text-[#fcd9a8]">
                {R.preview.stale}
              </p>
            ) : null}
            <PreviewResult result={previewed.result} stale={stale} />
          </>
        ) : generic !== null && generic.step === "preview" ? (
          <p role="alert" className="text-[13px] text-critical">
            {failureText(generic.error, R.builder.previewFailed)}
          </p>
        ) : (
          <p className="text-[13.5px] leading-relaxed text-muted">{R.preview.idle}</p>
        )}
      </section>
    </div>
  );
}
