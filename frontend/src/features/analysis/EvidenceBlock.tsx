// One piece of evidence the model cited: the claim it makes, the quote in a monospace box, and a line saying where the
// quote comes from and whether the server found it in the log. A quote that was found has a check and a solid box; one
// that was not has a warning, a dashed box and its line in the warning colour. The claim and the quote are the model's
// words about untrusted data: they are text, never markup, and a quote keeps its line breaks.
import { S } from "../../strings";
import type { ReactNode } from "react";
import { StatusIcon } from "./StatusIcon";

export function EvidenceBlock({
  claim,
  quote,
  source,
  verified,
}: {
  claim: string;
  /** `null` for a claim that quotes nothing (the box is not drawn). */
  quote: string | null;
  /** "alert 111976 · khớp nguyên văn", or whatever says where the quote is from and what became of it. */
  source: ReactNode;
  verified: boolean;
}) {
  return (
    <div
      data-verified={verified}
      className="flex flex-col gap-1.5 rounded-[10px] border border-border bg-surface px-3.5 py-3"
    >
      <div className="flex items-start gap-2 text-sm">
        <StatusIcon
          kind={verified ? "pass" : "warn"}
          label={verified ? S.analysis.evidence.verified : S.analysis.evidence.unverified}
        />
        <span className="min-w-0 break-words whitespace-pre-wrap">{claim}</span>
      </div>
      {quote !== null && (
        <div
          className={`rounded-md border bg-ground px-2.5 py-2 font-mono text-xs leading-[18px] break-words whitespace-pre-wrap text-text ${
            verified ? "border-border" : "border-dashed border-medium/40"
          }`}
        >
          {quote}
        </div>
      )}
      <div className={`text-xs ${verified ? "text-muted" : "text-medium"}`}>{source}</div>
    </div>
  );
}
