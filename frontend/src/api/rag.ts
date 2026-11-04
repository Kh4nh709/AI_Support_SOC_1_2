// What the pages say of the RAG beside the AI's conclusion (P14-T07, DEC-213, spec 4.3). The alert view and the
// run of the case view carry `rag: {best_pct, not_applied}` (backend `llm/rag_view.py`): how strongly the alert or
// case matched approved knowledge, as a whole percentage, and the closed kind of the failure that left the RAG out
// of ①'s or ②'s prompt. On the blind arm (DEC-101) the server drops the key until the alert is decided, so a view
// without it says nothing, and so does a value of any other shape: this file is the one place the pair is read.

/** The pair as the server sends it. */
export type RagWire = { best_pct: number | null; not_applied: string | null };

/** The pair as the pages use it: `pct` is a whole number from 0 to 100, `notApplied` a failure kind. */
export type RagNote = { pct: number | null; notApplied: string | null };

/** `rag` as the pages read it: a field that is not what the server sends is nothing to say. */
export function ragNoteOf(raw: unknown): RagNote {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { pct: null, notApplied: null };
  }
  const { best_pct: pct, not_applied: kind } = raw as Record<string, unknown>;
  return {
    pct: typeof pct === "number" && Number.isInteger(pct) && pct >= 0 && pct <= 100 ? pct : null,
    notApplied: typeof kind === "string" && kind !== "" ? kind : null,
  };
}
