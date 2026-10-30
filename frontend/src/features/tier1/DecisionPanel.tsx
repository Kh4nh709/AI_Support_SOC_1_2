// The decision panel of the alert page (spec §3.2, ① column's neighbour): acknowledge a queued alert, decide
// or escalate one the signed-in user holds, reopen an auto-closed one, and say what a closed one was decided
// as. Only Tier 1 acts; every other role is shown nothing here. TanStack Query owns the writes: one mutation,
// and on success the queue and the alert are marked stale so the page shows what the server now says.
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useRef, useState, type ReactNode } from "react";
import { ApiError } from "../../api/client";
import {
  postAcknowledge,
  postDecide,
  postEscalate,
  postReopen,
  type AlertView,
  type DecideResult,
  type DecisionResult,
  type EscalateResult,
} from "../../api/tier1";
import type { Session } from "../../auth/session";
import { Toast } from "../../components/Toast";
import { S, labelOf } from "../../strings";
import { DECIDED } from "./aiState";
import { conflictText, grownCountOf, invalidText } from "./conflict";
import {
  BUTTON,
  DecideForm,
  EscalateForm,
  ReopenForm,
  type Action,
  type AdoptedCount,
} from "./DecisionForms";
import { clearDraft } from "./draft";
import { sameUser, useMe } from "./useMe";

type FormName = "decide" | "escalate" | "reopen";

/** What went wrong, and where it is said: at the field the server was talking about, or for the whole panel. */
type Problem = { at: FormName; text: string } | { at: "panel"; text: string };

function send(alertId: string, action: Action): Promise<DecisionResult> {
  switch (action.kind) {
    case "acknowledge":
      return postAcknowledge(alertId);
    case "decide":
      return postDecide(alertId, {
        decision: action.decision,
        reason: action.reason,
        seen_occurrence_count: action.seen,
      });
    case "escalate":
      return postEscalate(alertId, { title: action.title, severity: action.severity });
    case "reopen":
      return postReopen(alertId, { reason: action.reason });
  }
}

const formOf = (action: Action): FormName | null =>
  action.kind === "acknowledge" ? null : action.kind;

/** The case the server opened or used, named and not linked: only Tier 1 sees this panel, and the case pages are Tier 2's. */
function CaseNumber({ id }: { id: number | string }) {
  return <p>{S.decision.caseNumber(id)}</p>;
}

/** What the toast says of what was done. */
function toastOf(action: Action, result: DecisionResult): ReactNode {
  switch (action.kind) {
    case "acknowledge":
      return <p>{S.decision.acknowledged}</p>;
    case "reopen":
      return <p>{S.decision.reopened}</p>;
    case "decide": {
      const { closed_count: closed, case_id: caseId } = result as DecideResult;
      return (
        <>
          <p>{S.decision.recorded}</p>
          {typeof closed === "number" && closed > 0 && (
            <p>{closed === 1 ? S.decision.closedOne : S.decision.closedCluster(closed)}</p>
          )}
          {caseId !== null && caseId !== undefined && <CaseNumber id={caseId} />}
        </>
      );
    }
    case "escalate": {
      const { case_id: caseId } = result as EscalateResult;
      return (
        <>
          <p>{S.decision.caseOpened}</p>
          {caseId !== null && caseId !== undefined && <CaseNumber id={caseId} />}
        </>
      );
    }
  }
}

/** The words for a failed request. A 409 is the server's own account of what it found. */
function problemOf(action: Action, error: unknown): Problem {
  if (!(error instanceof ApiError)) return { at: "panel", text: S.common.unknownError };
  if (error.status === 401) return { at: "panel", text: S.decision.sessionEnded };
  if (error.status === 409) return { at: "panel", text: conflictText(error) };
  if (error.status === 503) return { at: "panel", text: S.decision.timeout };
  const form = formOf(action);
  if (error.status === 422 && form !== null) return { at: form, text: invalidText(error) };
  return { at: "panel", text: S.common.unknownError };
}

/** What a person with the alert in front of them may do about it, by its status and by who holds it. */
function Actions({
  view,
  busy,
  problem,
  adopted,
  run,
}: {
  view: AlertView;
  busy: boolean;
  problem: Problem | null;
  adopted: AdoptedCount | null;
  run: (action: Action) => void;
}) {
  const holds = view.status === "tier1_active";
  // Who the user is, asked only for an alert somebody holds: the page is not told, and it does not guess.
  const who = useMe(holds);
  const fieldError = (form: FormName) => (problem?.at === form ? problem.text : null);

  if (view.status === "queued_tier1") {
    return (
      <button
        type="button"
        disabled={busy}
        onClick={() => run({ kind: "acknowledge" })}
        className={BUTTON}
      >
        {S.decision.acknowledge}
      </button>
    );
  }
  if (view.status === "auto_closed") {
    return (
      <div className="space-y-3">
        <p className="text-sm">{S.decision.autoClosed}</p>
        <ReopenForm busy={busy} error={fieldError("reopen")} onRun={run} />
      </div>
    );
  }
  if (holds) {
    if (who.isError) {
      return (
        <div className="space-y-2">
          <p role="alert" className="text-sm text-critical">
            {S.decision.meFailed}
          </p>
          <button type="button" onClick={() => void who.refetch()} className={BUTTON}>
            {S.common.retry}
          </button>
        </div>
      );
    }
    if (!who.data) {
      return (
        <p role="status" className="text-sm text-muted">
          {S.decision.loadingMe}
        </p>
      );
    }
    if (!sameUser(view.acknowledged_by, who.data.userId)) {
      return (
        <p className="text-sm">
          {view.acknowledged_by_name
            ? S.decision.heldBy(view.acknowledged_by_name)
            : S.decision.heldByOther}
        </p>
      );
    }
    return (
      <div className="space-y-4">
        <DecideForm
          view={view}
          userId={who.data.userId}
          busy={busy}
          error={fieldError("decide")}
          adopted={adopted}
          onRun={run}
        />
        <EscalateForm view={view} busy={busy} error={fieldError("escalate")} onRun={run} />
      </div>
    );
  }
  const label = labelOf(S.status, view.status);
  // DEC-212: the archive of the old queue is not a decision, even for an alert somebody held at the time.
  if (view.status === "archived") {
    return (
      <div className="space-y-1 text-sm">
        <p>{S.decision.archived}</p>
        {view.close_reason && (
          <p className="whitespace-pre-wrap break-words text-muted">{view.close_reason}</p>
        )}
      </div>
    );
  }
  if (DECIDED.has(view.status)) {
    return (
      <div className="space-y-1 text-sm">
        <p>{S.decision.decidedAs(label)}</p>
        {view.close_reason && (
          <p className="whitespace-pre-wrap break-words text-muted">{view.close_reason}</p>
        )}
      </div>
    );
  }
  return <p className="text-sm">{S.decision.notActionable(label)}</p>;
}

export function DecisionPanel({
  view,
  me,
  onDone,
}: {
  view: AlertView;
  me: Session;
  /** Told what the server answered to a decision that went through. */
  onDone?: (result: DecisionResult) => void;
}) {
  // Tier 1 acts; a reader of another role sees no panel, and the page does not ask who they are.
  if (me.role !== "tier1") return null;
  return <Panel view={view} onDone={onDone} />;
}

function Panel({ view, onDone }: { view: AlertView; onDone?: (result: DecisionResult) => void }) {
  const client = useQueryClient();
  const headingId = useId();
  const [toast, setToast] = useState<ReactNode>(null);
  const [problem, setProblem] = useState<Problem | null>(null);
  const [busy, setBusy] = useState(false);
  // The count the server made the analyst read (a `cluster_grew` answer): the decide form holds it (R19).
  const [adopted, setAdopted] = useState<AdoptedCount | null>(null);
  // A second click can arrive before the first one has been drawn as a disabled button: this says so at once.
  const running = useRef(false);

  // Whatever the request did, the page is asked again what the alert now is: the head of a duplicate (the
  // alert the decision is about) and the id that was asked for (the page that is open) alike.
  const refresh = () => {
    const ids = new Set([view.alert_id, view.requested_alert_id ?? view.alert_id]);
    return Promise.all([
      client.invalidateQueries({ queryKey: ["queue"] }),
      ...[...ids].map((id) => client.invalidateQueries({ queryKey: ["alert", id] })),
    ]);
  };

  const mutation = useMutation({
    mutationFn: (action: Action) => send(view.alert_id, action),
    onSuccess: async (result, action) => {
      if (action.kind === "decide" || action.kind === "escalate") clearDraft(view.alert_id);
      setToast(toastOf(action, result));
      onDone?.(result);
      await refresh();
    },
    onError: async (error, action) => {
      setProblem(problemOf(action, error));
      // A 409 says the alert is not what the analyst saw: they are shown what it is before they answer again.
      if (error instanceof ApiError && error.status === 409) {
        await refresh();
        // Only `cluster_grew` moves the count the form sends, and to the count of the view just fetched.
        const reported = grownCountOf(error);
        if (action.kind === "decide" && reported !== null) {
          const fetched = client.getQueryData<AlertView>([
            "alert",
            view.alert_id,
          ])?.occurrence_count;
          setAdopted({ count: typeof fetched === "number" ? fetched : reported });
        }
      }
    },
    onSettled: () => {
      running.current = false;
      setBusy(false);
    },
  });

  function run(action: Action) {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    setToast(null);
    setProblem(null);
    mutation.mutate(action);
  }

  return (
    <section
      aria-labelledby={headingId}
      className="space-y-3 rounded border border-ai-border bg-surface p-3"
    >
      <h3 id={headingId} className="text-sm font-semibold">
        {S.decision.heading}
      </h3>
      {toast !== null && <Toast onClose={() => setToast(null)}>{toast}</Toast>}
      {problem?.at === "panel" && (
        <p role="alert" className="text-sm text-critical">
          {problem.text}
        </p>
      )}
      <Actions view={view} busy={busy} problem={problem} adopted={adopted} run={run} />
    </section>
  );
}
