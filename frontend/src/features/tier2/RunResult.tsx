// The flat result of a ② run: the conclusion, the summary, the narrative, the hypotheses, the evidence and the next
// steps, one under the other. It is what the case column drew of a result until DEC-221 gave the column the scorecard
// (`ResultPanel`: four tiles over five tabs). The admin's knowledge-draft view still draws this one on the left of a
// case: an admin who reviews a draft reads the analyst's whole work at once, and the admin pages are not part of that
// redesign. Nothing about the column's states lives here.
//
// Everything the model wrote (summary, narrative, hypotheses, quotes, next steps) is rendered as text.
import {
  type InvestigationView,
  type EvidenceRow,
  type HypothesisRow,
  type RunView,
} from "../../api/tier2";
import { ragNoteOf, type RagNote } from "../../api/rag";
import { RagNotice } from "../../components/RagNotice";
import { formatDateTime, formatTime } from "../../format";
import { S, labelOf } from "../../strings";
import { HEADING, asText } from "./parts";
import { heldOf } from "./runModel";
import { useId } from "react";

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <h3 className={HEADING}>{title}</h3>
      {children}
    </div>
  );
}

/**
 * What the AI concluded on the case (P14-T03, DEC-213): "AI kết luận: <the label of ②'s conclusion>", and when the
 * system held it as `need_more_data`, "… — hệ thống giữ lại vì: <causes>" (just "… — hệ thống giữ lại" when it
 * knows no cause). The conclusion is the model's own (`model_conclusion`), not the `need_more_data` the system
 * stored in its place; a cause the UI has no label for is shown as its code. All of it is text.
 *
 * P14-T07 (DEC-213, spec 4.3): `rag.pct` is how strongly the case matched approved knowledge (the run's
 * `rag.best_pct`, null when there was no match): "AI kết luận: <label> — trùng 87% với tri thức đã duyệt", before the
 * system's own clause, as on the alert page. DEC-220 (trial): with no match, `rag.belowFloor` takes its place: "—
 * trùng cao nhất 47% với tri thức đã duyệt (dưới mức tối thiểu 50%)".
 */
function ModelConclusion({
  conclusion,
  causes,
  held,
  rag,
}: {
  conclusion: string;
  causes: string[];
  held: boolean;
  rag: RagNote;
}) {
  return (
    <p className="text-base">
      {S.ai2.conclusion}: <strong>{labelOf(S.ai2.suggestedConclusion, conclusion)}</strong>
      {rag.pct !== null && ` ${S.rag.dash} ${S.rag.match(rag.pct)}`}
      {rag.belowFloor !== undefined &&
        ` ${S.rag.dash} ${S.rag.belowFloor(rag.belowFloor.pct, rag.belowFloor.floor)}`}
      {held && ` ${S.ai2.heldLine(causes.map((cause) => labelOf(S.ai2.heldReason, cause)))}`}
    </p>
  );
}

export function RunResult({
  run,
  current,
  title,
}: {
  run: RunView;
  current: InvestigationView["current"];
  title: string | null;
}) {
  const evidenceId = useId();
  // A run from before P14-T02 carries no `model_conclusion`: it keeps the stored label and the overruled text. The
  // causes the server named, and whether the system held the conclusion, are `heldOf`'s (the scorecard reads the same).
  const { modelConclusion, causes, held } = heldOf(run);
  // The percentage and the notice (P14-T07) are the run's own, read through `ragNoteOf`.
  const rag = ragNoteOf(run.rag);
  const hypotheses = run.hypotheses ?? [];
  const evidence = run.evidence ?? [];
  const nextSteps = run.next_steps ?? [];
  return (
    <div className="space-y-4">
      {title !== null && <h3 className="text-sm font-semibold">{title}</h3>}
      <p className="text-xs text-muted">{S.ai2.resultAt(formatDateTime(run.created_at))}</p>

      {run.changed === true && (
        <div className="space-y-1 rounded border border-medium/40 bg-medium-bg p-3 text-sm text-medium">
          <p>{S.ai2.stale}</p>
          {run.snapshot !== null && run.snapshot !== undefined && (
            <p>
              {S.ai2.snapshot(
                run.snapshot.alert_count,
                run.snapshot.total_occurrences,
                run.snapshot.last_seen_at === null ? null : formatTime(run.snapshot.last_seen_at),
              )}
            </p>
          )}
          {current !== null && (
            <p>
              {S.ai2.current(
                current.alert_count,
                current.total_occurrences,
                current.last_seen_at === null ? null : formatTime(current.last_seen_at),
              )}
            </p>
          )}
        </div>
      )}

      <Block title={S.ai2.suggested}>
        {modelConclusion !== null ? (
          <ModelConclusion conclusion={modelConclusion} causes={causes} held={held} rag={rag} />
        ) : (
          <p className="flex flex-wrap items-baseline gap-2">
            <strong className="text-base">{asText(run.conclusion_label)}</strong>
            <code className="text-xs text-muted">{asText(run.conclusion)}</code>
          </p>
        )}
        <p className="text-sm">
          {`${S.ai2.confidence}: ${labelOf(S.ai2.confidenceLevel, run.confidence)}`}
        </p>
        {rag.notApplied !== null && <RagNotice kind={rag.notApplied} subject="case" />}
      </Block>

      {(modelConclusion === null || (held && causes.length === 0)) &&
        run.overruled !== null &&
        run.overruled !== undefined &&
        run.overruled !== "" && (
          <p className="rounded border border-high/40 bg-high-bg p-3 text-sm text-high">
            {run.overruled}
          </p>
        )}

      <Block title={S.ai2.summary}>
        <p className="whitespace-pre-wrap text-sm">{asText(run.summary)}</p>
      </Block>

      <Block title={S.ai2.narrative}>
        <p className="whitespace-pre-wrap text-sm">{asText(run.narrative)}</p>
      </Block>

      {hypotheses.length > 0 && (
        <Block title={S.ai2.hypotheses}>
          <ol className="space-y-3">
            {hypotheses.map((hypothesis, index) => (
              <Hypothesis key={index} hypothesis={hypothesis} />
            ))}
          </ol>
        </Block>
      )}

      <div className="space-y-1">
        <h3 id={evidenceId} className={HEADING}>
          {S.ai2.evidence}
        </h3>
        {evidence.length === 0 ? (
          <p className="text-sm">{S.ai2.noEvidence}</p>
        ) : (
          <ul aria-labelledby={evidenceId} className="space-y-2">
            {evidence.map((row, index) => (
              <EvidenceItem key={index} row={row} />
            ))}
          </ul>
        )}
      </div>

      {nextSteps.length > 0 && (
        <Block title={S.ai2.nextSteps}>
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {nextSteps.map((step, index) => (
              <li key={index}>{asText(step)}</li>
            ))}
          </ul>
        </Block>
      )}

      {run.playbook_used !== null &&
        run.playbook_used !== undefined &&
        run.playbook_used !== "" && (
          <p className="text-xs text-muted">{S.ai2.playbook(asText(run.playbook_used))}</p>
        )}

      <p className="text-xs text-muted">{S.ai2.disclaimer}</p>
    </div>
  );
}

/** One hypothesis, with the evidence for it and against it. One with none against is flagged. */
function Hypothesis({ hypothesis }: { hypothesis: HypothesisRow }) {
  const forId = useId();
  const againstId = useId();
  const supporting = hypothesis.evidence_for ?? [];
  const counter = hypothesis.evidence_against ?? [];
  return (
    <li className="space-y-2 rounded border border-ai-border p-3 text-sm">
      <p className="font-medium">{asText(hypothesis.text)}</p>
      <div>
        <p id={forId} className="text-xs text-muted">
          {S.ai2.supporting}
        </p>
        <ul aria-labelledby={forId} className="list-disc pl-5">
          {supporting.map((line, index) => (
            <li key={index}>{asText(line)}</li>
          ))}
        </ul>
      </div>
      {counter.length === 0 ? (
        <p className="rounded bg-medium-bg p-2 text-xs text-medium">{S.ai2.noCounterEvidence}</p>
      ) : (
        <div>
          <p id={againstId} className="text-xs text-muted">
            {S.ai2.counter}
          </p>
          <ul aria-labelledby={againstId} className="list-disc pl-5">
            {counter.map((line, index) => (
              <li key={index}>{asText(line)}</li>
            ))}
          </ul>
        </div>
      )}
    </li>
  );
}

/** One quote the assistant cited, marked verified only when the server checked it against the log. */
function EvidenceItem({ row }: { row: EvidenceRow }) {
  const verified = row.verified === true;
  return (
    <li className="space-y-1 rounded border border-ai-border p-3 text-sm">
      <div className="flex items-center gap-2">
        <span
          data-verified={verified}
          className={
            verified
              ? "rounded bg-low-bg px-2 py-0.5 text-xs text-low"
              : "rounded bg-medium-bg px-2 py-0.5 text-xs text-medium"
          }
        >
          {verified ? S.ai2.mark.verified : S.ai2.unverified}
        </span>
        <code className="text-xs text-muted">{asText(row.alert_id)}</code>
      </div>
      <p className="whitespace-pre-wrap font-mono text-xs">{`“${asText(row.quote)}”`}</p>
      <p>{asText(row.why)}</p>
      {!verified && <p className="text-xs text-medium">{asText(row.reason_text)}</p>}
    </li>
  );
}
