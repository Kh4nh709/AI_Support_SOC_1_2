// src/api/rag.test.ts — `ragNoteOf`, the one place the `rag` pair of an alert view and of a case run is read
// (P14-T07, DEC-213): the server sends `{best_pct, not_applied}`, and a key that is absent, or a value of another
// shape, is nothing to say.
import { ragNoteOf } from "./rag";

describe("ragNoteOf", () => {
  it("reads the pair the server sends", () => {
    expect(ragNoteOf({ best_pct: 87, not_applied: null })).toEqual({ pct: 87, notApplied: null });
    expect(ragNoteOf({ best_pct: null, not_applied: "auth" })).toEqual({
      pct: null,
      notApplied: "auth",
    });
    expect(ragNoteOf({ best_pct: 100, not_applied: "timeout" })).toEqual({
      pct: 100,
      notApplied: "timeout",
    });
  });

  it("reads 0% as a percentage, not as nothing", () => {
    expect(ragNoteOf({ best_pct: 0, not_applied: null }).pct).toBe(0);
  });

  it.each([undefined, null, "x", 3, true])("says nothing for %j", (raw) => {
    expect(ragNoteOf(raw)).toEqual({ pct: null, notApplied: null });
  });

  it("says nothing for a list", () => {
    expect(ragNoteOf([])).toEqual({ pct: null, notApplied: null });
    expect(ragNoteOf([87, "auth"])).toEqual({ pct: null, notApplied: null });
  });

  it("says nothing for the empty pair", () => {
    expect(ragNoteOf({ best_pct: null, not_applied: null })).toEqual({
      pct: null,
      notApplied: null,
    });
    expect(ragNoteOf({})).toEqual({ pct: null, notApplied: null });
  });

  it.each([-1, 101, 87.5, Number.NaN, Number.POSITIVE_INFINITY, "87", true, {}])(
    "takes %j for no percentage",
    (pct) => {
      expect(ragNoteOf({ best_pct: pct, not_applied: null }).pct).toBeNull();
    },
  );

  it.each([7, true, "", {}])("takes %j for no notice", (kind) => {
    expect(ragNoteOf({ best_pct: null, not_applied: kind }).notApplied).toBeNull();
  });
});
