// src/features/analysis/knowledge.test.ts — what the two AI panels read of a knowledge lookup and say on the Tri thức
// (RAG) tile (DEC-221): one reader and one tile for both tiers. The object is data: a key may be missing, null or of
// another kind, and nothing here throws or invents a number.
import { S } from "../../strings";
import { knowledgeFrom, ragTile, type Knowledge } from "./knowledge";

const known = (over: Record<string, unknown> = {}): Knowledge | null =>
  knowledgeFrom({
    state: "matched",
    failure: null,
    best_pct: 62,
    floor_pct: 50,
    scored: 12,
    candidates: [],
    ...over,
  });

describe("knowledgeFrom", () => {
  it("reads a lookup with its state, its numbers and its candidates, best first, at most three", () => {
    const k = known({
      state: "below_floor",
      best_pct: 47,
      candidates: [
        { pct: 47, title: "a", conclusion: "closed_fp" },
        { pct: 43, title: null, conclusion: null },
        { pct: 41, title: "c", conclusion: "x" },
        { pct: 40, title: "d", conclusion: null },
      ],
    });
    expect(k).toEqual({
      state: "below_floor",
      failure: null,
      best_pct: 47,
      floor_pct: 50,
      scored: 12,
      candidates: [
        { pct: 47, title: "a", conclusion: "closed_fp" },
        { pct: 43, title: null, conclusion: null },
        { pct: 41, title: "c", conclusion: "x" },
      ],
    });
  });

  it("is nothing for what is not an object with a state", () => {
    for (const raw of [null, undefined, "x", 3, [], {}, { state: 5 }]) {
      expect(knowledgeFrom(raw), String(raw)).toBeNull();
    }
  });

  it("skips a candidate with no whole percentage from 0 to 100, and a row that is not an object", () => {
    const k = known({
      candidates: [{ pct: "x" }, { pct: 47.5 }, { pct: 101 }, null, 3, { pct: 40, title: "c" }],
    });
    expect(k?.candidates).toEqual([{ pct: 40, title: "c", conclusion: null }]);
  });

  it("reads a number that is not a percentage, or a count that is not whole, as none", () => {
    const k = known({ best_pct: 62.5, floor_pct: -1, scored: 1.5, failure: "" });
    expect(k).toMatchObject({ best_pct: null, floor_pct: null, scored: null, failure: null });
  });
});

describe("the Tri thức (RAG) tile", () => {
  it("is the number and 'trùng sự cố cũ' for a match", () => {
    expect(ragTile(known({ state: "matched", best_pct: 62 }))).toEqual({
      value: "62%",
      note: "trùng sự cố cũ",
    });
  });

  it("is the number and the floor for a lookup whose candidates all scored under it", () => {
    expect(ragTile(known({ state: "below_floor", best_pct: 47, floor_pct: 50 }))).toEqual({
      value: "47%",
      note: "dưới mức 50%",
    });
    expect(ragTile(known({ state: "below_floor", best_pct: 47, floor_pct: null })).note).toBe(
      "dưới mức tối thiểu",
    );
  });

  it("is a dash and a line for each of the other three states", () => {
    expect(ragTile(known({ state: "no_candidate", best_pct: null }))).toEqual({
      value: "—",
      note: "không có mục nào trùng",
    });
    expect(ragTile(known({ state: "no_lookup", best_pct: null }))).toEqual({
      value: "—",
      note: "không có tra cứu",
    });
    expect(ragTile(known({ state: "failed", failure: "timeout", best_pct: null }))).toEqual({
      value: "—",
      note: "quá thời gian chờ",
    });
  });

  it.each(Object.entries(S.analysis.ragNote.failedKind))(
    "words the failure kind %s",
    (kind, words) => {
      expect(ragTile(known({ state: "failed", failure: kind, best_pct: null })).note).toBe(words);
    },
  );

  it("says only that the lookup failed for a kind it has no words for, and never shows the code", () => {
    expect(ragTile(known({ state: "failed", failure: "cosmic_ray", best_pct: null }))).toEqual({
      value: "—",
      note: "tra cứu bị lỗi",
    });
    expect(ragTile(known({ state: "failed", failure: "constructor", best_pct: null })).note).toBe(
      "tra cứu bị lỗi",
    );
  });

  it("has no data for a number that is not there, a state it does not know, or no lookup", () => {
    const none = { value: "—", note: "chưa có dữ liệu" };
    expect(ragTile(known({ state: "matched", best_pct: null }))).toEqual(none);
    expect(ragTile(known({ state: "below_floor", best_pct: null }))).toEqual(none);
    expect(ragTile(known({ state: "future_state" }))).toEqual(none);
    expect(ragTile(null)).toEqual(none);
  });
});
