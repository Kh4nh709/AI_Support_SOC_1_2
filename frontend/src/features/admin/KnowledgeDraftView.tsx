// One knowledge draft (P13-T06, spec §7.5), on two columns.
//
//   Left   the analyst's work, read-only: the alert with the sections of the alert page and ①'s result, or the case
//          with its heads, its timeline, its notes and ②'s result; the decision and who made it; the SOAR block; and,
//          for a draft in conflict, the entry it conflicts with. These are the components of the Tier-1 and Tier-2
//          pages, fed from `source.alert` / `source.case` / `source.investigation`, which the route builds with the
//          functions of those pages' own routes. No decision panel, no note form, no conclusion form.
//   Right  the draft: the six model fields as a form, the tags as a picker over the closed vocabulary, the six closed
//          fields read-only, and the warnings of the job that wrote it.
//
// The writes: Duyệt sends `{}`; Sửa rồi duyệt sends `{edited}` with the model fields that changed, never a closed
// one (`editsOf`); Từ chối sends a required reason. Each asks first (ConfirmDialog). The answers:
//   200            the page is told (`onDone`), after the lists were marked stale;
//   422 {faults}   each fault is shown at the field named after the colon, the ones with no field above the form;
//                  the dialog closes and nothing the admin typed is lost;
//   422 reason     shown at the reason input, in the dialog;
//   409            "bản nháp đã được xử lý": the dialog closes and the draft and the lists are read again;
//   404            the same, "not found";
//   503            `publish_failed`: nothing was stored, the dialog stays and the same button asks again;
//   anything else  a plain sentence in the dialog; nothing the server wrote is shown.
// Text from a model or an analyst (the draft, the notes, the reasons, an entry's Markdown) is React text and nothing
// else: no raw-HTML escape hatch, no Markdown renderer.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import {
  approveKnowledgeDraft,
  getKnowledgeDraft,
  getKnowledgeTags,
  KNOWLEDGE_CLOSED_FIELDS,
  KNOWLEDGE_LIMITS,
  KNOWLEDGE_MODEL_FIELDS,
  knowledgeErrorOf,
  rejectKnowledgeDraft,
  type KnowledgeDraft,
  type KnowledgeDraftDetail,
  type KnowledgeEdit,
  type KnowledgeError,
  type KnowledgeFault,
  type KnowledgeSource,
} from "../../api/admin";
import type { Suggestion } from "../../api/tier1";
import { ApiError } from "../../api/client";
import { formatDateTime, formatTime } from "../../format";
import { S, knowledgeFaultText, knowledgeWarningText, labelOf } from "../../strings";
import { AiColumn, GateLine, GateSteps, Reasons } from "../tier1/AiColumn";
import {
  Accounts,
  Correlation,
  Enrichment,
  EventDetails,
  Playbook,
  RawLog,
  Summary as AlertSummary,
} from "../tier1/AlertSections";
import {
  Heads as CaseHeads,
  Summary as CaseSummary,
  Timeline as CaseTimeline,
} from "../tier2/CasePage";
import { RunResult } from "../tier2/InvestigationColumn";
import { asText } from "../tier2/parts";
import { ConfirmDialog } from "./ConfirmDialog";
import { adminKeys, invalidateAfter } from "./adminKeys";
import {
  changedFields,
  editsOf,
  faultsByField,
  formOf,
  isDirty,
  type DraftForm,
} from "./knowledgeModel";
import {
  BUTTON_DANGER,
  BUTTON_OUTLINE,
  BUTTON_PRIMARY,
  ERROR_CLASS,
  FIELD_CLASS,
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
const D = K.draft;

/** The two reads (the draft, and the tags it can carry) and the screen. */
export function KnowledgeDraftView({
  draftId,
  onBack,
  onDone,
}: {
  draftId: string;
  onBack: () => void;
  /** A write went through: the text of the toast the page shows on the list it goes back to. */
  onDone: (message: string) => void;
}) {
  const query = useQuery({
    queryKey: adminKeys.knowledgeDraft(draftId),
    queryFn: () => getKnowledgeDraft(draftId),
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
            {K.notice.gone}
          </p>
        ) : (
          <ReadError message={D.loadFailed} onRetry={() => void query.refetch()} />
        )}
      </div>
    );
  }
  // Another draft is another screen: what was typed for the last one stays with it.
  return <DraftScreen key={draftId} detail={query.data} onBack={onBack} onDone={onDone} />;
}

// --- the writes ------------------------------------------------------------------------------------------------

type Job = { kind: "approve"; edited?: KnowledgeEdit } | { kind: "reject"; reason: string };
type Asked = "approve" | "editApprove" | "reject";

function DraftScreen({
  detail,
  onBack,
  onDone,
}: {
  detail: KnowledgeDraftDetail;
  onBack: () => void;
  onDone: (message: string) => void;
}) {
  const { draft, source } = detail;
  const client = useQueryClient();
  const pending = draft.status === "pending";
  const hasText = Object.keys(draft.draft).length > 0;
  const stored = formOf(draft.draft);
  // What the admin starts from is the draft as it was when this screen opened; a read made again after a 409 must
  // not take the text from under their hands.
  const [initial] = useState<DraftForm>(stored);
  const [form, setForm] = useState<DraftForm>(initial);
  const [faults, setFaults] = useState<KnowledgeFault[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [asked, setAsked] = useState<Asked | null>(null);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [reasonError, setReasonError] = useState<string | null>(null);
  // The route answered 404: the draft is gone, whatever the page still holds of it.
  const [gone, setGone] = useState(false);
  // A 409 that leaves the draft pending (its source changed, or it cannot be published): only a rejection is left.
  const [rejectOnly, setRejectOnly] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const headingRef = useRef<HTMLHeadingElement>(null);

  // A draft that is not pending shows what is on file, not what was typed before it was handled.
  const shown = pending ? form : stored;
  const dirty = pending && isDirty(initial, form);
  const unsent = dirty && !gone;
  const title =
    draft.draft.title !== undefined && draft.draft.title !== "" ? draft.draft.title : K.noTitle;

  const write = useMutation({
    mutationFn: (job: Job): Promise<unknown> =>
      job.kind === "reject"
        ? rejectKnowledgeDraft(draft.draft_id, job.reason)
        : approveKnowledgeDraft(draft.draft_id, job.edited),
    onSuccess: async (_done, job) => {
      await invalidateAfter(
        client,
        job.kind === "reject" ? "rejectKnowledgeDraft" : "approveKnowledgeDraft",
      );
      if (job.kind === "reject") onDone(K.done.rejected(title));
      else onDone(K.done.approved(job.edited?.title?.trim() || title));
    },
    onError: (error, job) => refused(knowledgeErrorOf(error), job),
  });
  const run = useSubmitLatch(write);

  function refused(error: KnowledgeError, job: Job): void {
    const mutation = job.kind === "reject" ? "rejectKnowledgeDraft" : "approveKnowledgeDraft";
    switch (error.kind) {
      case "faults":
        setFaults(error.faults);
        setNotice(null);
        setAsked(null);
        return;
      case "stale": {
        // `source_changed` and `unpublishable` leave the draft pending, and an approval would meet the same 409
        // again: say that a rejection is all that is left, and take the approvals off.
        const only = error.reason === "source_changed" || error.reason === "unpublishable";
        setNotice(only ? K.notice.rejectOnly : K.notice.handled);
        setRejectOnly(only);
        setFaults([]);
        setAsked(null);
        void invalidateAfter(client, mutation);
        return;
      }
      case "not_found":
        setNotice(K.notice.gone);
        setGone(true);
        setFaults([]);
        setAsked(null);
        void invalidateAfter(client, mutation);
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
          setDialogError(K.notice.editedInvalid);
        }
        return;
      case "other":
        setDialogError(K.notice.failed);
        return;
    }
  }

  function ask(which: Asked): void {
    write.reset();
    setDialogError(null);
    setReasonError(null);
    if (which === "reject") setReason("");
    setAsked(which);
  }

  function cancel(): void {
    write.reset();
    setAsked(null);
  }

  function edit(change: Partial<DraftForm>, field: string): void {
    setForm((was) => ({ ...was, ...change }));
    // What was said about a field is about the text it had.
    setFaults((was) => was.filter((fault) => fault.field !== field));
  }

  const byPlace = faultsByField(faults);
  const hint = rejectOnly
    ? D.action.approveRejectOnly
    : !hasText
      ? D.action.approveNoText
      : dirty
        ? D.action.approveEdited
        : D.action.editApproveClean;
  const hintId = useId();
  const rightHeading = useId();
  const approveOff = !hasText || dirty || rejectOnly;
  const editOff = !dirty || rejectOnly;

  // The title takes the focus when the draft opens, so a keyboard or a screen reader lands on it.
  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  // A reload or a closed tab would lose the text that was not sent. (The app's router is a declarative one, which
  // has no blocker for its own navigation: the button below asks, and a link of the sidebar does not.)
  useEffect(() => {
    if (!unsent) return;
    const guard = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", guard);
    return () => window.removeEventListener("beforeunload", guard);
  }, [unsent]);

  const back = () => (unsent ? setLeaving(true) : onBack());

  return (
    <div className="space-y-4">
      <Header draft={draft} source={source} title={title} onBack={back} headingRef={headingRef} />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <AnalystWork draft={draft} source={source} />
        <section aria-labelledby={rightHeading} className="min-w-0 space-y-4">
          <RightColumn
            headingId={rightHeading}
            draft={draft}
            pending={pending}
            gone={gone}
            hasText={hasText}
            form={shown}
            onEdit={edit}
            notice={notice}
            faults={faults}
            places={byPlace}
          >
            {pending && !gone && (
              <div className="space-y-2">
                <div className="flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => ask("approve")}
                    disabled={approveOff}
                    aria-describedby={approveOff ? hintId : undefined}
                    className={BUTTON_PRIMARY}
                  >
                    {D.action.approve}
                  </button>
                  <button
                    type="button"
                    onClick={() => ask("editApprove")}
                    disabled={editOff}
                    aria-describedby={editOff ? hintId : undefined}
                    className={BUTTON_OUTLINE}
                  >
                    {D.action.editApprove}
                  </button>
                  <button type="button" onClick={() => ask("reject")} className={BUTTON_DANGER}>
                    {D.action.reject}
                  </button>
                </div>
                {(approveOff || editOff) && (
                  <p id={hintId} className="text-xs text-muted">
                    {hint}
                  </p>
                )}
              </div>
            )}
          </RightColumn>
        </section>
      </div>

      {asked === "approve" && (
        <ConfirmDialog
          title={D.action.approveTitle}
          confirmLabel={D.action.approve}
          busy={write.isPending}
          error={dialogError ?? undefined}
          onConfirm={() => void run({ kind: "approve" })}
          onCancel={cancel}
        >
          {D.action.approveBody}
        </ConfirmDialog>
      )}
      {asked === "editApprove" && (
        <ConfirmDialog
          title={D.action.editApproveTitle}
          confirmLabel={D.action.editApprove}
          busy={write.isPending}
          error={dialogError ?? undefined}
          onConfirm={() => void run({ kind: "approve", edited: editsOf(initial, form, !hasText) })}
          onCancel={cancel}
        >
          {D.action.editApproveBody(
            (hasText ? changedFields(initial, form) : [...KNOWLEDGE_MODEL_FIELDS])
              .map((field) => D.right.field[field])
              .join(", "),
          )}
        </ConfirmDialog>
      )}
      {asked === "reject" && (
        <ReasonDialog
          title={D.action.rejectTitle}
          body={D.action.rejectBody}
          confirmLabel={D.action.reject}
          reasonLabel={D.action.reasonLabel}
          reason={reason}
          onReason={(text) => {
            setReason(text);
            setReasonError(null);
          }}
          reasonError={reasonError}
          error={dialogError}
          busy={write.isPending}
          onConfirm={() => void run({ kind: "reject", reason: reason.trim() })}
          onCancel={cancel}
        />
      )}
      {leaving && (
        <ConfirmDialog
          title={D.leave.title}
          confirmLabel={D.leave.confirm}
          cancelLabel={D.leave.stay}
          tone="danger"
          onConfirm={onBack}
          onCancel={() => setLeaving(false)}
        >
          {D.leave.body}
        </ConfirmDialog>
      )}
    </div>
  );
}

// --- the header ------------------------------------------------------------------------------------------------

function Header({
  draft,
  source,
  title,
  onBack,
  headingRef,
}: {
  draft: KnowledgeDraft;
  source: KnowledgeSource;
  title: string;
  onBack: () => void;
  headingRef: React.RefObject<HTMLHeadingElement | null>;
}) {
  const conflicted = draft.conflict_with_entry !== null || source.conflict_entry !== null;
  const retired = source.conflict_entry?.status === "retired";
  const reviewed =
    draft.reviewed_by_name !== null || draft.reviewed_at !== null
      ? K.reviewedBy(
          draft.reviewed_by_name ?? S.common.missing,
          draft.reviewed_at === null ? S.common.missing : formatDateTime(draft.reviewed_at),
        )
      : null;
  const items: [string, ReactNode][] = [
    [D.meta.source, `${labelOf(K.sourceKind, draft.source_kind)} ${draft.source_id}`],
    [D.meta.conclusion, conclusionLabel(draft.conclusion)],
    [D.meta.created, formatDateTime(draft.created_at)],
  ];
  if (reviewed !== null) items.push([D.meta.reviewed, reviewed]);
  if (draft.review_note !== null) items.push([D.meta.note, draft.review_note]);
  if (draft.duplicate_of_entry !== null) items.push([D.meta.mergedInto, draft.duplicate_of_entry]);
  return (
    <section aria-label={D.header} className={`${PANEL} space-y-3 p-4`}>
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
        <Mark>{labelOf(D.status, draft.status)}</Mark>
        {conflicted && (
          <Mark tone="warn">{retired ? K.badge.conflictRetired : K.badge.conflict}</Mark>
        )}
      </div>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2 lg:grid-cols-3">
        {items.map(([label, value]) => (
          <div key={label} className="min-w-0">
            <dt className="text-xs text-muted">{label}</dt>
            <dd className="break-words">{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

// --- the left column: the analyst's work -----------------------------------------------------------------------

function Block({ title, children }: { title: string; children: ReactNode }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className="space-y-2">
      <h3 id={id} className="text-sm font-semibold">
        {title}
      </h3>
      {children}
    </section>
  );
}

const Sentence = ({ children }: { children: ReactNode }) => (
  <p className="text-sm text-muted">{children}</p>
);

function AnalystWork({ draft, source }: { draft: KnowledgeDraft; source: KnowledgeSource }) {
  const heading = useId();
  return (
    <section aria-labelledby={heading} className="min-w-0 space-y-5">
      <div>
        <h2 id={heading} className="text-xs font-semibold tracking-wide text-muted">
          {D.left.heading}
        </h2>
        <p className="text-xs text-muted">{D.left.hint}</p>
      </div>
      <ConflictEntry draft={draft} source={source} />
      <DecisionBlock source={source} />
      {source.kind === "alert" ? <AlertWork source={source} /> : <CaseWork source={source} />}
      <SoarBlock source={source} />
    </section>
  );
}

/**
 * The entry the draft disagrees with, whole, so the admin sees both sides. Its Markdown is shown as text. A draft
 * in conflict whose entry is gone says so; a draft with no conflict shows nothing.
 */
function ConflictEntry({ draft, source }: { draft: KnowledgeDraft; source: KnowledgeSource }) {
  const entry = source.conflict_entry;
  if (entry === null) {
    if (draft.conflict_with_entry === null) return null;
    return (
      <Block title={D.left.conflict.heading.active}>
        <Sentence>{D.left.conflict.noData}</Sentence>
      </Block>
    );
  }
  const heading =
    entry.status === "retired" ? D.left.conflict.heading.retired : D.left.conflict.heading.active;
  return (
    <Block title={heading}>
      <p className="text-xs text-muted">{D.left.conflict.hint}</p>
      <div className={`${PANEL} space-y-2 p-3`}>
        <p className="font-semibold break-words">{entry.title ?? K.noEntryTitle}</p>
        <p className="text-xs text-muted">
          {conclusionLabel(entry.conclusion)} · {entry.category} ·{" "}
          {labelOf(K.entry.status, entry.status)}
        </p>
        <TextBox value={entry.content} label={D.left.conflict.content} />
      </div>
    </Block>
  );
}

function DecisionBlock({ source }: { source: KnowledgeSource }) {
  const decision = source.decision;
  const payload = decision?.payload;
  const entries =
    typeof payload === "object" && payload !== null && !Array.isArray(payload)
      ? Object.entries(payload)
      : null;
  return (
    <Block title={D.left.decision.heading}>
      {decision === null ? (
        <Sentence>{D.left.noData.decision}</Sentence>
      ) : (
        <div className={`${PANEL} space-y-2 p-3 text-sm`}>
          <p>
            <strong>{labelOf(S.admin.eventType, decision.event_type)}</strong>
            <span className="text-muted">
              {" · "}
              {D.left.decision.by(
                decision.actor_name ?? S.common.missing,
                formatDateTime(decision.at),
              )}
            </span>
          </p>
          {entries !== null
            ? entries.length > 0 && (
                <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1">
                  {entries.map(([key, value]) => (
                    <div key={key} className="contents">
                      <dt className="text-muted">{key}</dt>
                      <dd className="break-words whitespace-pre-wrap">{asText(value)}</dd>
                    </div>
                  ))}
                </dl>
              )
            : payload !== undefined && payload !== null && <TextBox value={payload} />}
        </div>
      )}
    </Block>
  );
}

function AlertWork({ source }: { source: KnowledgeSource }) {
  const alert = source.alert;
  if (alert === null) return <Sentence>{D.left.noData.alert}</Sentence>;
  return (
    <div className="space-y-5">
      <h3 className="text-base font-semibold break-words">{alert.description || alert.alert_id}</h3>
      <AlertSummary view={alert} role="admin" />
      <EventDetails view={alert} />
      <RawLog view={alert} />
      <Accounts view={alert} />
      <Enrichment view={alert} />
      <Correlation view={alert} />
      <Playbook view={alert} />
      <AiColumn view={alert} />
      {alert.suggestion != null && <SuggestionDetail suggestion={alert.suggestion} />}
    </div>
  );
}

/**
 * What the column of ① leaves out once an alert is decided: the gate (forced or not, by which rules, its steps and
 * warnings) and ①'s reasons, with their quotes. Spec §7.5; the server sends them to an admin (DEC-206). The pieces are
 * the ones of the alert page, drawn read-only: the text of a reason or a warning is a model's, and is text.
 */
function SuggestionDetail({ suggestion }: { suggestion: Suggestion }) {
  const id = useId();
  const gate = suggestion.gate ?? null;
  const reasons = suggestion.reasons ?? [];
  return (
    <section
      aria-labelledby={id}
      className="space-y-3 rounded border border-ai-border bg-ai-surface p-4"
    >
      <h3 id={id} className="text-sm font-semibold tracking-wide text-ai-accent">
        {D.left.suggestion.heading}
      </h3>
      {gate === null && reasons.length === 0 && <Sentence>{D.left.suggestion.none}</Sentence>}
      {gate !== null && <GateLine gate={gate} forced={gate.forced === true} />}
      {gate !== null && <GateSteps gate={gate} />}
      {reasons.length > 0 && <Reasons reasons={reasons} />}
    </section>
  );
}

function CaseWork({ source }: { source: KnowledgeSource }) {
  const caseView = source.case;
  return (
    <div className="space-y-5">
      {caseView === null ? (
        <Sentence>{D.left.noData.case}</Sentence>
      ) : (
        <>
          <h3 className="text-base font-semibold break-words">{asText(caseView.title)}</h3>
          <CaseSummary data={caseView} />
          <CaseHeads data={caseView} />
          <CaseTimeline data={caseView} />
        </>
      )}
      <Block title={D.left.notes.heading}>
        {source.notes.length === 0 ? (
          <Sentence>{D.left.notes.empty}</Sentence>
        ) : (
          <ul className="space-y-2">
            {source.notes.map((note) => (
              <li key={note.note_id} className={`${PANEL} space-y-1 p-3 text-sm`}>
                <div className="flex items-baseline gap-2">
                  <strong>{note.author_name ?? note.author_id}</strong>
                  <time dateTime={note.created_at} className="text-xs text-muted">
                    {formatTime(note.created_at)}
                  </time>
                </div>
                <p className="break-words whitespace-pre-wrap">{asText(note.body)}</p>
              </li>
            ))}
          </ul>
        )}
      </Block>
      <Block title={D.left.investigation.heading}>
        <Investigation source={source} />
      </Block>
    </div>
  );
}

function Investigation({ source }: { source: KnowledgeSource }) {
  const view = source.investigation;
  if (view === null) return <Sentence>{D.left.noData.investigation}</Sentence>;
  const run = view.run;
  if (run === null) return <Sentence>{D.left.investigation.none}</Sentence>;
  if (run.result === null || run.result === undefined) {
    return <Sentence>{S.ai2.stopped(asText(run.stopped_text))}</Sentence>;
  }
  return (
    <div className="rounded border border-ai-border bg-ai-surface p-4">
      <RunResult run={run} current={view.current} title={null} />
    </div>
  );
}

/** The SOAR block: an alert's own, or each head's of a case. Nothing is drawn for a source that has none. */
function SoarBlock({ source }: { source: KnowledgeSource }) {
  const shown: { label: string | null; value: unknown }[] = [];
  const found = source.enrichment;
  if (source.kind === "alert") {
    if (found !== null && found !== undefined) shown.push({ label: null, value: found });
  } else if (typeof found === "object" && found !== null && !Array.isArray(found)) {
    for (const [head, block] of Object.entries(found)) {
      shown.push({ label: D.left.soar.forHead(head), value: block });
    }
  }
  if (shown.length === 0) return null;
  return (
    <Block title={D.left.soar.heading}>
      <div className="space-y-2">
        {shown.map(({ label, value }, index) => (
          <div key={index} className="space-y-1">
            {label !== null && <p className="text-xs text-muted">{label}</p>}
            <TextBox value={value} />
          </div>
        ))}
      </div>
    </Block>
  );
}

// --- the right column: the draft ------------------------------------------------------------------------------

function RightColumn({
  headingId,
  draft,
  pending,
  gone,
  hasText,
  form,
  onEdit,
  notice,
  faults,
  places,
  children,
}: {
  headingId: string;
  draft: KnowledgeDraft;
  pending: boolean;
  gone: boolean;
  hasText: boolean;
  form: DraftForm;
  onEdit: (change: Partial<DraftForm>, field: string) => void;
  notice: string | null;
  faults: KnowledgeFault[];
  places: ReturnType<typeof faultsByField>;
  children: ReactNode;
}) {
  const readOnly = !pending || gone;
  const fieldFaults = (field: string): string[] =>
    (places.byField[field] ?? []).map((fault) => knowledgeFaultText(fault));
  return (
    <>
      <h2 id={headingId} className="text-xs font-semibold tracking-wide text-muted">
        {D.right.heading}
      </h2>
      {pending && !gone && !hasText && <Sentence>{D.right.noText}</Sentence>}
      {!pending && <Sentence>{D.right.readOnly}</Sentence>}
      {notice !== null && (
        <p
          role="alert"
          className={`${PANEL} border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-3 text-[13.5px] text-[#fcd9a8]`}
        >
          {notice}
        </p>
      )}
      {faults.length > 0 && (
        <div
          role="alert"
          className="space-y-1 rounded-lg border border-[#5a2e36] bg-[#2a1016] px-3.5 py-3"
        >
          <p className="text-[13.5px] font-semibold text-[#fda4af]">
            {K.notice.faults(faults.length)}
          </p>
          {places.general.length > 0 && (
            <ul className="list-disc pl-5">
              {places.general.map((fault, index) => (
                <li key={index} className={ERROR_CLASS}>
                  {knowledgeFaultText(fault)}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <form onSubmit={(event) => event.preventDefault()} className="space-y-4">
        <TextField
          label={D.right.field.title}
          hint={D.right.hint.max(KNOWLEDGE_LIMITS.titleMax)}
          value={form.title}
          readOnly={readOnly}
          faults={fieldFaults("title")}
          onChange={(title) => onEdit({ title }, "title")}
        />
        <TextField
          label={D.right.field.summary}
          hint={D.right.hint.max(KNOWLEDGE_LIMITS.summaryMax)}
          value={form.summary}
          rows={4}
          readOnly={readOnly}
          faults={fieldFaults("summary")}
          onChange={(summary) => onEdit({ summary }, "summary")}
        />
        <TextField
          label={D.right.field.distinguishing_signals}
          hint={D.right.hint.lines(KNOWLEDGE_LIMITS.maxItems, KNOWLEDGE_LIMITS.itemMax)}
          value={form.signals}
          rows={4}
          readOnly={readOnly}
          faults={fieldFaults("distinguishing_signals")}
          onChange={(signals) => onEdit({ signals }, "distinguishing_signals")}
        />
        <TextField
          label={D.right.field.check_next_time}
          hint={D.right.hint.lines(KNOWLEDGE_LIMITS.maxItems, KNOWLEDGE_LIMITS.itemMax)}
          value={form.checks}
          rows={3}
          readOnly={readOnly}
          faults={fieldFaults("check_next_time")}
          onChange={(checks) => onEdit({ checks }, "check_next_time")}
        />
        <TextField
          label={D.right.field.confidence_note}
          hint={D.right.hint.max(KNOWLEDGE_LIMITS.noteMax)}
          value={form.note}
          rows={2}
          readOnly={readOnly}
          faults={fieldFaults("confidence_note")}
          onChange={(note) => onEdit({ note }, "confidence_note")}
        />
        <TagPicker
          picked={form.tags}
          readOnly={readOnly}
          faults={fieldFaults("tags")}
          onChange={(tags) => onEdit({ tags }, "tags")}
        />
      </form>

      <ClosedFields draft={draft} places={places} />
      <Warnings warnings={draft.warnings} />
      {children}
    </>
  );
}

function TextField({
  label,
  hint,
  value,
  rows,
  readOnly,
  faults,
  onChange,
}: {
  label: string;
  hint: string;
  value: string;
  rows?: number;
  readOnly: boolean;
  faults: string[];
  onChange: (value: string) => void;
}) {
  const id = useId();
  const hintId = useId();
  const errorId = useId();
  const describedBy = [hintId, faults.length > 0 ? errorId : null]
    .filter((x) => x !== null)
    .join(" ");
  const common = {
    id,
    value,
    readOnly,
    "aria-invalid": faults.length > 0 ? true : undefined,
    "aria-describedby": describedBy,
    className: FIELD_CLASS,
    onChange: (event: { target: { value: string } }) => onChange(event.target.value),
  };
  return (
    <div className="space-y-1">
      <label htmlFor={id} className="block text-sm font-medium">
        {label}
      </label>
      {rows === undefined ? (
        <input type="text" {...common} />
      ) : (
        <textarea rows={rows} {...common} />
      )}
      <p id={hintId} className="text-xs text-muted">
        {hint}
      </p>
      {faults.length > 0 && (
        <ul id={errorId} className="list-disc pl-5">
          {faults.map((text, index) => (
            <li key={index} className={ERROR_CLASS}>
              {text}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** The tags as a picker over the closed vocabulary. A tag of the draft that is not in it stays ticked, marked. */
function TagPicker({
  picked,
  readOnly,
  faults,
  onChange,
}: {
  picked: readonly string[];
  readOnly: boolean;
  faults: string[];
  onChange: (tags: string[]) => void;
}) {
  const vocabulary = useQuery({
    queryKey: adminKeys.knowledgeTags,
    queryFn: () => getKnowledgeTags(),
    staleTime: 5 * 60_000,
  });
  const errorId = useId();
  // A tag is "outside the list" only once the list is known; until then (or when it could not be read) the draft's
  // own tags are shown as they are, unmarked.
  const known = vocabulary.data?.tags;
  const outside = known === undefined ? [] : picked.filter((tag) => !known.includes(tag));
  const all = known === undefined ? [...picked] : [...known, ...outside];
  const toggle = (tag: string) =>
    onChange(picked.includes(tag) ? picked.filter((t) => t !== tag) : [...picked, tag]);
  return (
    <fieldset className="space-y-2" aria-describedby={faults.length > 0 ? errorId : undefined}>
      <legend className="text-sm font-medium">{D.right.field.tags}</legend>
      {vocabulary.isPending && <Sentence>{D.right.tags.loading}</Sentence>}
      {vocabulary.isError && (
        <div className="flex items-center gap-3">
          <p className={ERROR_CLASS}>{D.right.tags.loadFailed}</p>
          <button
            type="button"
            onClick={() => void vocabulary.refetch()}
            className={BUTTON_OUTLINE}
          >
            {S.common.retry}
          </button>
        </div>
      )}
      {all.length === 0 && !vocabulary.isPending && !vocabulary.isError && (
        <Sentence>{D.right.tags.none}</Sentence>
      )}
      <ul className="grid grid-cols-1 gap-x-4 gap-y-1.5 sm:grid-cols-2">
        {all.map((tag) => {
          const description = vocabulary.data?.descriptions[tag] ?? "";
          const isOutside = outside.includes(tag);
          return (
            <li key={tag} className="min-w-0">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={picked.includes(tag)}
                  disabled={readOnly}
                  onChange={() => toggle(tag)}
                />
                <span className="break-all">
                  {tag}
                  {isOutside && <span className="text-muted"> ({D.right.tags.outside})</span>}
                </span>
              </label>
              {description !== "" && <p className="pl-6 text-xs text-muted">{description}</p>}
            </li>
          );
        })}
      </ul>
      {faults.length > 0 && (
        <ul id={errorId} className="list-disc pl-5">
          {faults.map((text, index) => (
            <li key={index} className={ERROR_CLASS}>
              {text}
            </li>
          ))}
        </ul>
      )}
    </fieldset>
  );
}

/** The six fields the source owns: read-only, with the fault of a field beside it. */
function ClosedFields({
  draft,
  places,
}: {
  draft: KnowledgeDraft;
  places: ReturnType<typeof faultsByField>;
}) {
  const fields = draft.draft;
  const text = (field: (typeof KNOWLEDGE_CLOSED_FIELDS)[number]): string => {
    const value = fields[field];
    if (Array.isArray(value)) return value.length === 0 ? S.common.missing : value.join(", ");
    return typeof value === "string" && value !== "" ? value : S.common.missing;
  };
  return (
    <fieldset className={`${PANEL} space-y-2 p-3`}>
      <legend className="px-1 text-sm font-medium">{D.right.closedHeading}</legend>
      <p className="text-xs text-muted">{D.right.closedHint}</p>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        {KNOWLEDGE_CLOSED_FIELDS.map((field) => (
          <div key={field} className="contents">
            <dt className="text-muted">{D.right.closed[field]}</dt>
            <dd className="min-w-0 break-words">
              {text(field)}
              {(places.byField[field] ?? []).map((fault, index) => (
                <span key={index} className={`block ${ERROR_CLASS}`}>
                  {knowledgeFaultText(fault)}
                </span>
              ))}
            </dd>
          </div>
        ))}
      </dl>
    </fieldset>
  );
}

function Warnings({ warnings }: { warnings: readonly string[] }) {
  const id = useId();
  if (warnings.length === 0) return null;
  return (
    <section
      aria-labelledby={id}
      className="space-y-1 rounded-lg border border-[#5a3a14] bg-[#2a1a0a] px-3.5 py-3"
    >
      <h3 id={id} className="text-sm font-semibold text-[#fcd9a8]">
        {D.right.warnings}
      </h3>
      <ul className="list-disc pl-5 text-[13px] text-[#fcd9a8]">
        {warnings.map((code, index) => (
          <li key={index}>{knowledgeWarningText(code)}</li>
        ))}
      </ul>
    </section>
  );
}
