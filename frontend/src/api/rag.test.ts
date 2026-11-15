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

// DEC-220 (trial): a lookup that kept no match carries the best candidate's percentage and the floor it was under,
// `below_floor_pct` and `floor_pct`. `belowFloor` is there only when both are whole percentages and there is no
// match: a match (`best_pct`) is what the page says first, and a half-pair is nothing to say.
describe("ragNoteOf, the best candidate under the floor (DEC-220)", () => {
  const wire = (over: Record<string, unknown>) => ({
    best_pct: null,
    not_applied: null,
    below_floor_pct: null,
    floor_pct: null,
    ...over,
  });

  it("reads the percentage and the floor the server sends", () => {
    expect(ragNoteOf(wire({ below_floor_pct: 47, floor_pct: 50 }))).toEqual({
      pct: null,
      notApplied: null,
      belowFloor: { pct: 47, floor: 50 },
    });
  });

  it("reads 0% as a percentage, not as nothing", () => {
    expect(ragNoteOf(wire({ below_floor_pct: 0, floor_pct: 50 })).belowFloor).toEqual({
      pct: 0,
      floor: 50,
    });
  });

  it("has no belowFloor when the pair carries none, or the server is older", () => {
    expect(ragNoteOf(wire({})).belowFloor).toBeUndefined();
    expect(ragNoteOf({ best_pct: null, not_applied: null }).belowFloor).toBeUndefined();
    expect(ragNoteOf({ best_pct: 87, not_applied: null }).belowFloor).toBeUndefined();
  });

  it("is not there beside a match: best_pct is what the page says", () => {
    const note = ragNoteOf(wire({ best_pct: 87, below_floor_pct: 47, floor_pct: 50 }));
    expect(note).toEqual({ pct: 87, notApplied: null });
    expect(note.belowFloor).toBeUndefined();
  });

  it("is not there when only one of the two arrives", () => {
    expect(ragNoteOf(wire({ below_floor_pct: 47 })).belowFloor).toBeUndefined();
    expect(ragNoteOf(wire({ floor_pct: 50 })).belowFloor).toBeUndefined();
    expect(ragNoteOf({ below_floor_pct: 47, floor_pct: null }).belowFloor).toBeUndefined();
  });

  it.each([-1, 101, 47.5, Number.NaN, Number.POSITIVE_INFINITY, "47", true, {}])(
    "takes %j for no percentage",
    (value) => {
      expect(ragNoteOf(wire({ below_floor_pct: value, floor_pct: 50 })).belowFloor).toBeUndefined();
      expect(ragNoteOf(wire({ below_floor_pct: 47, floor_pct: value })).belowFloor).toBeUndefined();
    },
  );

  it("leaves the notice and the rest of the pair as they were", () => {
    expect(ragNoteOf(wire({ not_applied: "auth", below_floor_pct: 47, floor_pct: 50 }))).toEqual({
      pct: null,
      notApplied: "auth",
      belowFloor: { pct: 47, floor: 50 },
    });
  });
});
