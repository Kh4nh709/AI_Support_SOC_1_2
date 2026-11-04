// The notice beside the AI's conclusion when the RAG was not applied (P14-T07, DEC-213, spec 4.3): "⚠ Không áp
// dụng RAG cho alert này: <where it failed> — AI đã phân tích không có tri thức tham khảo." Shared by the alert page
// (①) and the case page (②), which say "alert" and "case". The reason is one of the six closed failure kinds,
// worded in strings.ts (`S.rag.failureKind`); the provider's own words never reach the page, so there are none to
// show here. A kind with no label is shown as its code, as text.
import { S, labelOf } from "../strings";

export function RagNotice({ kind, subject }: { kind: string; subject: "alert" | "case" }) {
  return (
    <p role="note" className="rounded border border-medium/40 bg-medium-bg p-2 text-sm text-medium">
      {S.rag.notApplied(subject, labelOf(S.rag.failureKind, kind))}
    </p>
  );
}
