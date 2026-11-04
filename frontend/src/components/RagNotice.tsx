// The notice beside the AI's conclusion when the RAG was not applied (P14-T07, DEC-213, spec 4.3): "⚠ Không áp
// dụng RAG cho alert này: <where it failed> — AI đã phân tích không có tri thức tham khảo." Shared by the alert page
// (①) and the case page (②), which say "alert" and "case". The reason is one of the six closed failure kinds,
// worded in strings.ts (`S.rag.failureKind`). A kind this UI has no words for draws nothing, and never its code:
// the server sends only the closed six, and a value it should not send is not something to show.
import { S, failureKindLabel } from "../strings";

export function RagNotice({ kind, subject }: { kind: string; subject: "alert" | "case" }) {
  const reason = failureKindLabel(kind);
  if (reason === null) return null;
  return (
    <p role="note" className="rounded border border-medium/40 bg-medium-bg p-2 text-sm text-medium">
      {S.rag.notApplied(subject, reason)}
    </p>
  );
}
