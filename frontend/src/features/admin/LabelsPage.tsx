// `/admin/labels` (spec §4.6, P11-T16): blind, independent labelling of the gold set.
//
// ONE read owns the page: `GET /api/admin/labels/next?labeler=<self>`. It carries the progress, the cluster to
// label, and the two flags that say which screen it is: `frozen` and `candidates_present`. The writes are
// `POST /api/admin/labels` (a label) and `POST /api/admin/labels/undo`; each invalidates through
// `invalidateAfter`, which reads `labels/next` again. The page makes no other request of any kind while it is
// open (plan Review Focus 5), and renders no field the cluster does not carry by name (LabelClusterView.tsx).
//
// The screen, by what the server says:
//   frozen                       the frozen state (progress only; no form, no undo), and `cluster` is IGNORED:
//                                the server still sends one to an admin who has clusters left (P11-T08 review);
//   no candidates                `candidates_present` false, or a candidate file with no cluster in it;
//   finished                     no cluster left, done == total (with the undo, until the set is frozen);
//   a cluster                    the labelling screen: the cluster, and the form beside it.
//
// The write answers (labels.py):
//   save  201 {cluster_id, done, total, next}  the toast says what was saved and who is next; the next cluster is
//                                              read from `labels/next` (a cluster is only ever sent by it);
//         409 already labelled / frozen, 404 not a candidate   the screen was stale: read again, the refusal said;
//         403, 422, 5xx, the network           nothing changed: the form is kept and the refusal said at it;
//   undo  200 {undone_cluster_id, done, total}; 409 `frozen`, 404 `nothing_to_undo` (in `detail.reason`).
// A read that fails after a write replaces the screen with the page error: the cluster that was just labelled is
// never left on screen to be labelled twice.
//
// Two clicks in one tick: TanStack Query tells React a mutation is pending only on a timer, so a guard on
// `isPending` lets both through. The shared `useSubmitLatch` lets one write through. The save and the undo are
// ONE mutation (`Write`, below), so one latch covers both: a save and an undo of the same tick send one POST.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useRef, useState, type ReactNode, type Ref } from "react";
import {
  adminErrorOf,
  getLabelsNext,
  postLabel,
  undoLabel,
  type AdminError,
  type LabelsNext,
  type NewLabel,
} from "../../api/admin";
import { useAuth } from "../../auth/AuthProvider";
import { PageError } from "../../components/PageError";
import { Toast } from "../../components/Toast";
import { S, adminReasonText } from "../../strings";
import { adminKeys, invalidateAfter } from "./adminKeys";
import { ClusterDetails, ClusterHead } from "./LabelClusterView";
import { LabelForm, type LabelValues } from "./LabelForm";
import { labelerIdOf } from "./labelerId";
import { useSubmitLatch } from "./useSubmitLatch";

const L = S.admin.labelsPage;

/** What the last write said: a confirmation (a toast) or a refusal (an alert). */
type Notice = { tone: "ok" | "error"; text: string };

/**
 * The page's one write, as the variables of one mutation. A save and an undo are two routes but one kind of
 * act on the labeller's own rows, and one latch (`useSubmitLatch`) wraps the mutation: so no two writes of this
 * page are ever out at once, whichever buttons were pressed in the same tick.
 */
type Write = { kind: "save"; body: NewLabel } | { kind: "undo" };
type Answer =
  | { kind: "save"; saved: Awaited<ReturnType<typeof postLabel>> }
  | { kind: "undo"; undone: Awaited<ReturnType<typeof undoLabel>> };

/** The refusals after which the screen on view is out of date, so `labels/next` is read again. */
const STALE_REASONS = new Set<string>([
  "already_labelled",
  "unknown_cluster",
  "frozen",
  "nothing_to_undo",
]);
const isStale = (error: AdminError): boolean =>
  error.kind === "reason" && STALE_REASONS.has(error.reason);

/**
 * What a failed write says. A reason the server names is read from `S.admin.reason`; a 422 of a save is "Nhãn
 * không hợp lệ" (`invalid`); anything else is the status, or the lost connection. Never the server's own text.
 */
function failureText(
  error: AdminError,
  words: { invalid: string | null; offline: string; server: (status: number) => string },
): string {
  if (error.kind === "reason" || error.kind === "field") return adminReasonText(error);
  if (error.status === 422 && words.invalid !== null) return words.invalid;
  return error.status === 0 ? words.offline : words.server(error.status);
}

const SAVE_WORDS = {
  invalid: L.notice.invalid,
  offline: L.notice.saveOffline,
  server: L.notice.saveServer,
};
const UNDO_WORDS = {
  invalid: null,
  offline: L.notice.undoOffline,
  server: L.notice.undoServer,
};

// Whole class names: Tailwind finds a class by reading the source. The two pseudo-elements paint a
// `<progress>` (WebKit and Firefox), since an inline style cannot, and the CSP forbids one.
const BAR =
  "h-2 w-full appearance-none overflow-hidden rounded bg-[#1f2833] [&::-webkit-progress-bar]:bg-[#1f2833] [&::-webkit-progress-value]:bg-[#5b8def] [&::-moz-progress-bar]:bg-[#5b8def]";
const CARD = "flex flex-col gap-3 rounded-[10px] border bg-surface p-5";
const OUTLINE_BUTTON =
  "h-[38px] self-start rounded-lg border border-[#2e3a48] px-3.5 text-sm text-text hover:bg-ground focus-visible:outline-2 focus-visible:outline-text disabled:cursor-not-allowed disabled:opacity-60";

function Progress({ done, total }: { done: number; total: number }) {
  if (total <= 0) return null;
  return (
    <div className="flex w-[300px] flex-col gap-1.5">
      <div className="flex justify-between text-[13px]">
        <span className="text-muted">{L.progress.label}</span>
        <span className="font-semibold">{L.progress.of(done, total)}</span>
      </div>
      <progress
        aria-label={L.progress.bar}
        value={Math.min(done, total)}
        max={total}
        className={BAR}
      />
    </div>
  );
}

function Header({ children }: { children?: ReactNode }) {
  return (
    <div className="flex items-end gap-4">
      <div className="flex flex-1 flex-col gap-1">
        <h1 className="text-[26px] leading-tight font-semibold">{S.admin.title.labels}</h1>
        <p className="text-sm text-[#aeb9c6]">{L.subtitle}</p>
      </div>
      {children}
    </div>
  );
}

function ErrorNote({ children }: { children: ReactNode }) {
  return (
    <div
      role="alert"
      className="rounded-lg border border-[#5a2e36] bg-[#2a1016] px-3 py-2.5 text-[13px] leading-snug text-[#fda4af]"
    >
      {children}
    </div>
  );
}

function Icon({ stroke, children }: { stroke: string; children: ReactNode }) {
  return (
    <svg
      width="30"
      height="30"
      viewBox="0 0 24 24"
      fill="none"
      stroke={stroke}
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

/** The current state of the gold set: frozen, and only the progress to look at. */
function FrozenCard({ done, total }: { done: number; total: number }) {
  const id = useId();
  return (
    <section aria-labelledby={id} className={`${CARD} border-[#3a4757]`}>
      <Icon stroke="#7fb0ff">
        <rect x="5" y="11" width="14" height="10" rx="2" />
        <path d="M8 11V8a4 4 0 0 1 8 0v3" />
      </Icon>
      <h2 id={id} className="text-[17px] font-semibold">
        {L.frozen.title}
      </h2>
      <p className="self-start rounded border border-[#3a4757] px-2 py-0.5 text-xs font-medium text-[#aeb9c6]">
        {L.frozen.badge}
      </p>
      <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">{L.frozen.body(total)}</p>
      {total > 0 && (
        <div className="max-w-[360px]">
          <Progress done={done} total={total} />
        </div>
      )}
    </section>
  );
}

/** The labeller has labelled every cluster. The undo is theirs until the set is frozen. */
function FinishedCard({
  total,
  undo,
  ref,
}: {
  total: number;
  undo: ReactNode;
  ref?: Ref<HTMLHeadingElement>;
}) {
  const id = useId();
  return (
    <section aria-labelledby={id} className={`${CARD} border-border`}>
      <Icon stroke="#9ff0c5">
        <path d="M4 12l5 5L20 6" />
      </Icon>
      <h2
        id={id}
        ref={ref}
        tabIndex={-1}
        className="text-[17px] font-semibold focus-visible:outline-2 focus-visible:outline-text"
      >
        {L.finished.title(total)}
      </h2>
      <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">{L.finished.body}</p>
      {undo}
    </section>
  );
}

function NoCandidatesCard() {
  const id = useId();
  return (
    <section aria-labelledby={id} className={`${CARD} border-border`}>
      <h2 id={id} className="text-[17px] font-semibold">
        {L.noCandidates.title}
      </h2>
      <p className="text-[13.5px] leading-relaxed text-[#c9d3df]">
        {L.noCandidates.before}{" "}
        <span className="font-mono text-[12.5px]">{L.noCandidates.file}</span>.
      </p>
    </section>
  );
}

const SKELETON = "animate-pulse rounded-lg bg-[#1a222c]";

/** The page's title and the labelling layout's blocks, so nothing jumps when the cluster arrives. */
function Skeleton() {
  return (
    <div className="space-y-5">
      <h1 className="text-[26px] leading-tight font-semibold">{S.admin.title.labels}</h1>
      <div role="status" aria-busy="true" className="space-y-4">
        <span className="sr-only">{S.common.loading}</span>
        <div aria-hidden="true" className={`${SKELETON} h-12`} />
        <div aria-hidden="true" className="flex gap-5">
          <div className="flex flex-1 flex-col gap-4">
            <div className={`${SKELETON} h-64`} />
            <div className={`${SKELETON} h-40`} />
          </div>
          <div className={`${SKELETON} h-96 w-[340px]`} />
        </div>
      </div>
    </div>
  );
}

/**
 * The page could not be had: the shared title, why, and a retry where trying again can help. `saved` is what
 * the last write said when it went through (the read after it is what failed): first line, so the page error is
 * not read as if nothing had been written.
 */
function LoadFailure({
  hint,
  onRetry,
  saved,
}: {
  hint: string;
  onRetry?: () => void;
  saved?: string;
}) {
  return (
    <div className="space-y-3">
      <PageError title={S.admin.common.loadError} onRetry={onRetry} />
      {saved !== undefined && <p className="text-[13.5px] leading-relaxed text-low">{saved}</p>}
      <p
        role={onRetry === undefined ? "alert" : undefined}
        className="text-[13.5px] leading-relaxed text-[#c9d3df]"
      >
        {hint}
      </p>
    </div>
  );
}

/** What a failed read says: the reason's own words for a 403, else the status, or the lost connection. */
function loadErrorHint(error: unknown): string {
  const failure = adminErrorOf(error);
  if (failure.kind === "reason" || failure.kind === "field") return adminReasonText(failure);
  return failure.status === 0 ? L.loadErrorOffline : L.loadErrorServer(failure.status);
}

/**
 * Which screen a read shows, as a key. A write asks for the focus, and gets it when the screen is no longer the
 * one the write was made on (the next cluster, the finished card): not before, on the stale one.
 */
function screenOf(data: LabelsNext | undefined): string | null {
  if (data === undefined) return null;
  if (data.frozen) return "frozen";
  if (!data.candidates_present || data.total === 0) return "none";
  return data.cluster_id === null ? "finished" : `cluster:${data.cluster_id}`;
}

export function LabelsPage() {
  const { session } = useAuth();
  const client = useQueryClient();
  const labelerId = session === null ? null : labelerIdOf(session.token);
  const [notice, setNotice] = useState<Notice | null>(null);
  const wantsFocus = useRef(false);
  const screenAtWrite = useRef<string | null>(null);
  const headRef = useRef<HTMLElement>(null);
  const finishedRef = useRef<HTMLHeadingElement>(null);

  const query = useQuery({
    queryKey: adminKeys.labels,
    queryFn: (): Promise<LabelsNext> =>
      labelerId === null ? Promise.reject(new Error("no labeller")) : getLabelsNext(labelerId),
    enabled: labelerId !== null,
    // Read on entry and after this page's own writes, never behind the labeller's back: a cluster they are
    // reading must not change under them.
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });

  const write = useMutation({
    mutationFn: async (w: Write): Promise<Answer> =>
      w.kind === "save"
        ? { kind: "save", saved: await postLabel(w.body) }
        : { kind: "undo", undone: await undoLabel() },
    onSuccess: async (answer) => {
      wantsFocus.current = true;
      if (answer.kind === "save") {
        const { cluster_id, done, total, next } = answer.saved;
        setNotice({ tone: "ok", text: L.notice.saved(cluster_id, done, total, next) });
        await invalidateAfter(client, "postLabel");
      } else {
        const { undone_cluster_id, done, total } = answer.undone;
        setNotice({ tone: "ok", text: L.notice.undone(undone_cluster_id, done, total) });
        await invalidateAfter(client, "undoLabel");
      }
    },
    onError: async (thrown, w) => {
      const error = adminErrorOf(thrown);
      const saving = w.kind === "save";
      setNotice({ tone: "error", text: failureText(error, saving ? SAVE_WORDS : UNDO_WORDS) });
      if (isStale(error)) await invalidateAfter(client, saving ? "postLabel" : "undoLabel");
    },
  });
  const run = useSubmitLatch(write);
  const screenKey = screenOf(query.data);

  /** One write at a time, and one click of it: `run` says whether the call went, and the old notice goes with it. */
  function send(w: Write) {
    if (run(w)) {
      setNotice(null);
      screenAtWrite.current = screenKey;
    }
  }

  // A write brought another screen: the button that had the focus is gone, so the focus goes to the cluster, or
  // to the finished card after the last label. It does not go to the stale screen the write was made on.
  useEffect(() => {
    if (wantsFocus.current && screenKey !== screenAtWrite.current) {
      wantsFocus.current = false;
      (headRef.current ?? finishedRef.current)?.focus();
    }
  });

  if (labelerId === null) return <LoadFailure hint={L.sessionUnreadable} />;
  // A failed read replaces whatever the page showed, the cluster of a label just saved included.
  if (query.isError) {
    const failure = adminErrorOf(query.error);
    const retryable = failure.kind !== "reason" && failure.kind !== "field";
    return (
      <LoadFailure
        hint={loadErrorHint(query.error)}
        saved={notice?.tone === "ok" ? notice.text : undefined}
        onRetry={retryable ? () => void query.refetch() : undefined}
      />
    );
  }
  const data = query.data;
  if (data === undefined) return <Skeleton />;

  const working = write.isPending ? (write.variables?.kind ?? null) : null;
  const toast =
    notice?.tone === "ok" ? <Toast onClose={() => setNotice(null)}>{notice.text}</Toast> : null;
  const refusal = notice?.tone === "error" ? notice.text : null;

  /** The undo of the finished card; the form has its own. */
  const cardUndo = (
    <button
      type="button"
      disabled={working !== null}
      aria-busy={working === "undo"}
      onClick={() => send({ kind: "undo" })}
      className={OUTLINE_BUTTON}
    >
      {working === "undo" ? L.form.undoing : L.form.undo}
    </button>
  );

  // frozen: nothing of `data.cluster` is read past this line.
  if (data.frozen) {
    return (
      <div className="space-y-5">
        <Header />
        {toast}
        {refusal !== null && <ErrorNote>{refusal}</ErrorNote>}
        <FrozenCard done={data.done} total={data.total} />
      </div>
    );
  }

  if (!data.candidates_present || data.total === 0) {
    return (
      <div className="space-y-5">
        <Header />
        {toast}
        {refusal !== null && <ErrorNote>{refusal}</ErrorNote>}
        <NoCandidatesCard />
      </div>
    );
  }

  if (data.cluster_id === null) {
    return (
      <div className="space-y-5">
        <Header>
          <Progress done={data.done} total={data.total} />
        </Header>
        {toast}
        {refusal !== null && <ErrorNote>{refusal}</ErrorNote>}
        <FinishedCard ref={finishedRef} total={data.total} undo={data.done > 0 ? cardUndo : null} />
      </div>
    );
  }

  const cluster = data.cluster;
  if (cluster === null) {
    return <LoadFailure hint={L.clusterMissing} onRetry={() => void query.refetch()} />;
  }

  return (
    <div className="space-y-5">
      <Header>
        <Progress done={data.done} total={data.total} />
      </Header>
      {toast}
      <ClusterHead cluster={cluster} ref={headRef} />
      <div className="flex items-start gap-5">
        <ClusterDetails cluster={cluster} />
        <LabelForm
          key={cluster.gold_cluster_id}
          working={working}
          canUndo={data.done > 0}
          error={refusal}
          onSave={(values: LabelValues) =>
            send({
              kind: "save",
              body: {
                labeler: labelerId,
                cluster_id: cluster.gold_cluster_id,
                label: values.label,
                confidence: values.confidence,
                ...(values.note === "" ? {} : { note: values.note }),
              },
            })
          }
          onUndo={() => send({ kind: "undo" })}
        />
      </div>
    </div>
  );
}
