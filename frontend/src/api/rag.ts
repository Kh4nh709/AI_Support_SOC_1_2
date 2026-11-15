// What the pages say of the RAG beside the AI's conclusion (P14-T07, DEC-213, spec 4.3). The alert view and the
// run of the case view carry `rag: {best_pct, not_applied}` (backend `llm/rag_view.py`): how strongly the alert or
// case matched approved knowledge, as a whole percentage, and the closed kind of the failure that left the RAG out
// of ①'s or ②'s prompt. On the blind arm (DEC-101) the server drops the key until the alert is decided, so a view
// without it says nothing, and so does a value of any other shape: this file is the one place the pair is read.
// DEC-220 (trial) adds `below_floor_pct` and `floor_pct`: for a lookup that kept no match, the best candidate the
// rerank scored and the floor it was under.

/**
 * The pair as the server sends it. `below_floor_pct` and `floor_pct` (DEC-220) belong to a lookup that kept no match:
 * the best candidate's percentage and the floor it was under; both are null otherwise, and absent from an older
 * server.
 */
export type RagWire = {
  best_pct: number | null;
  not_applied: string | null;
  below_floor_pct?: number | null;
  floor_pct?: number | null;
};

/**
 * The pair as the pages use it: `pct` is a whole number from 0 to 100, `notApplied` a failure kind, and `belowFloor`
 * (DEC-220) the best candidate's percentage and the floor, there only for a run with no match (`pct` null) whose
 * server sent both. The key is absent, not null, when there is nothing to say.
 */
export type RagNote = {
  pct: number | null;
  notApplied: string | null;
  belowFloor?: { pct: number; floor: number };
};

/** A whole percentage from 0 to 100, else null. */
function percentOf(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 100
    ? value
    : null;
}

/** `rag` as the pages read it: a field that is not what the server sends is nothing to say. */
export function ragNoteOf(raw: unknown): RagNote {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { pct: null, notApplied: null };
  }
  const {
    best_pct: best,
    not_applied: kind,
    below_floor_pct: below,
    floor_pct: floor,
  } = raw as Record<string, unknown>;
  const note: RagNote = {
    pct: percentOf(best),
    notApplied: typeof kind === "string" && kind !== "" ? kind : null,
  };
  // A match is what the page says first: the best candidate under the floor is for a run that kept none.
  const belowPct = percentOf(below);
  const floorPct = percentOf(floor);
  if (note.pct === null && belowPct !== null && floorPct !== null) {
    note.belowFloor = { pct: belowPct, floor: floorPct };
  }
  return note;
}
