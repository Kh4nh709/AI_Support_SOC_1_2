// src/features/tier1/analysisModel.test.ts — what the Tier 1 panel reads out of a view's `analysis` (DEC-221, AP-T4), key
// by key: the tiles in each state, the highlights, the checks, the facts, the lookup, the history. The server's object is
// data; a key may be missing, null or of another kind, and no reader throws or invents a value the run does not carry.
import type { AlertView } from "../../api/tier1";
import { S } from "../../strings";
import { aiStateOfView, type AiState } from "./aiState";
import {
  analysisOf,
  checksTile,
  confidenceTile,
  highlightText,
  verdictTile,
} from "./analysisModel";
import { analysis, olderAnalysis, ragDefaultAnalysis, ragDefaultKeys } from "./analysisFixtures";

const baseView = (over: Partial<AlertView> = {}): AlertView => ({
  alert_id: "a1",
  status: "queued_tier1",
  suggestion_visible: true,
  triage_status: "ready",
  suggestion: {
    run_id: "r1",
    suggested_action: "true_positive",
    confidence: "medium",
    reasons: [],
    gate: { forced: false, forced_by: [], proposed_verdict: "true_positive", warnings: [] },
    correlated_at_analysis: 3,
    created_at: "2026-11-15T11:35:56Z",
  },
  proposed_action: "true_positive",
  held_by: [],
  analysis: analysis(),
  ...over,
});

const stateOf = (
  over: Partial<AlertView> = {},
): Extract<AiState, { kind: "ready" | "decided" }> => {
  const state = aiStateOfView(baseView(over));
  if (state.kind !== "ready" && state.kind !== "decided") throw new Error(`state ${state.kind}`);
  return state;
};

const withAction = (action: string, confidence: string | null = "medium"): Partial<AlertView> => ({
  suggestion: {
    run_id: "r1",
    suggested_action: action,
    confidence,
    gate: { forced: false, forced_by: [], proposed_verdict: action, warnings: [] },
  },
  proposed_action: action,
});

describe("analysisOf", () => {
  it("is nothing for a view with no analysis, a null one, or one that is not an object", () => {
    expect(analysisOf(baseView({ analysis: undefined }))).toBeNull();
    expect(analysisOf(baseView({ analysis: null }))).toBeNull();
    for (const garbled of ["x", 3, true, [], [analysis()]]) {
      expect(analysisOf(baseView({ analysis: garbled as never })), String(garbled)).toBeNull();
    }
  });

  it("reads an object with no key at all as a model with nothing in it, never an error", () => {
    const model = analysisOf(baseView({ analysis: {} as never }));
    expect(model).not.toBeNull();
    expect(model?.summary).toBeNull();
    expect(model?.nextChecks).toEqual([]);
    expect(model?.reasons).toEqual([]);
    expect(model?.facts).toEqual([]);
    expect(model?.checks).toEqual([]);
    expect(model?.highlights).toEqual([]);
    expect(model?.rag).toBeNull();
    expect(model?.history).toBeNull();
    expect(model?.playbook).toBeNull();
  });

  it("survives every key being of the wrong kind", () => {
    const garbled = {
      summary: 5,
      reading_attack: [],
      reading_benign: {},
      would_change: false,
      next_checks: "a, b",
      reasons: "x",
      facts: { a: 1 },
      checks: 7,
      check_totals: "no",
      rag: "no",
      history: [],
      playbook: 3,
      highlights: "no",
      tech: "no",
    };
    const model = analysisOf(baseView({ analysis: garbled as never }));
    expect(model?.summary).toBeNull();
    expect(model?.readingAttack).toBeNull();
    expect(model?.wouldChange).toBeNull();
    expect(model?.nextChecks).toEqual([]);
    expect(model?.reasons).toEqual([]);
    expect(model?.rag).toBeNull();
    expect(model?.tech.mitre).toEqual([]);
    expect(model?.tech.inputTokens).toBeNull();
  });

  it("reads the five texts of a version 4 run, and finds nothing of them in an older run", () => {
    const v4 = analysisOf(baseView());
    expect(v4?.summary).toMatch(/^amsi\.dll bị nạp/);
    expect(v4?.readingAttack).toMatch(/^Mã độc/);
    expect(v4?.nextChecks).toHaveLength(3);
    const older = analysisOf(baseView({ analysis: olderAnalysis() }));
    expect(older?.summary).toBeNull();
    expect(older?.readingAttack).toBeNull();
    expect(older?.readingBenign).toBeNull();
    expect(older?.wouldChange).toBeNull();
    expect(older?.nextChecks).toEqual([]);
    // what the server builds from the gate and the lookup is there either way
    expect(older?.checks).toHaveLength(7);
    expect(older?.highlights).toHaveLength(4);
  });

  it("drops a blank text and a blank next check, and keeps at most three next checks", () => {
    const model = analysisOf(
      baseView({
        analysis: analysis({ summary: "   ", next_checks: ["a", "", "  ", "b", "c", "d", "e"] }),
      }),
    );
    expect(model?.summary).toBeNull();
    expect(model?.nextChecks).toEqual(["a", "b", "c"]);
  });

  it("serves a reason's source in the product's words, and the code itself for a source with no word", () => {
    const model = analysisOf(
      baseView({
        analysis: analysis({
          reasons: [
            { claim: "a", quote: "q", source: "wazuh_raw_log", verified: true, why: null },
            { claim: "b", quote: "q", source: "something_new", verified: true, why: null },
            { claim: "c", quote: null, source: null, verified: false, why: "empty_quote" },
          ],
        }),
      }),
    );
    expect(model?.reasons.map((reason) => reason.source)).toEqual([
      "Log gốc của alert",
      "something_new",
      null,
    ]);
    expect(model?.reasons.map((reason) => reason.why)).toEqual([
      null,
      null,
      "AI diễn giải, không trích nguyên văn",
    ]);
  });

  it("words a reason that was not verified for a why it has no word for as the code, and never drops it", () => {
    const model = analysisOf(
      baseView({
        analysis: analysis({
          reasons: [{ claim: "a", quote: "q", source: null, verified: false, why: "odd" as never }],
        }),
      }),
    );
    expect(model?.reasons).toHaveLength(1);
    expect(model?.reasons[0]?.why).toBe("odd");
    expect(model?.reasons[0]?.verified).toBe(false);
  });

  it("counts the verified reasons over all of them", () => {
    expect(analysisOf(baseView())?.evidence).toEqual({ verified: 2, total: 4 });
  });
});

describe("the Kết luận tile", () => {
  it("is TP in the high-severity orange with 'tấn công thật' under it", () => {
    expect(verdictTile(stateOf())).toEqual({
      label: "TP",
      tone: "high",
      note: "tấn công thật",
      forced: false,
    });
  });

  it("is FP in the calm blue with 'dương tính giả' under it", () => {
    expect(verdictTile(stateOf(withAction("false_positive")))).toEqual({
      label: "FP",
      tone: "low",
      note: "dương tính giả",
      forced: false,
    });
  });

  it("says the verdict is the default below the threshold for a run the RAG default applied to (DEC-219)", () => {
    const tile = verdictTile(
      stateOf({ ...ragDefaultKeys(80, 62), analysis: ragDefaultAnalysis() }),
    );
    expect(tile).toEqual({
      label: "FP",
      tone: "low",
      note: "(dưới 80%: mặc định FP)",
      forced: false,
    });
    expect(tile.note).toBe(S.ai1.ragDefault(80));
  });

  it("carries the flag of a run the gate forced (a version 1 row), and only then", () => {
    const forced = stateOf({
      suggestion: {
        run_id: "r1",
        suggested_action: "true_positive",
        confidence: "high",
        gate: { forced: true, forced_by: ["step4"], proposed_verdict: "true_positive" },
      },
    });
    expect(verdictTile(forced).forced).toBe(true);
    expect(verdictTile(stateOf()).forced).toBe(false);
  });

  it("carries no flag for a run the RAG default applied to, even if the gate's record says forced", () => {
    const stray = stateOf({
      ...ragDefaultKeys(80, 62),
      suggestion: {
        ...ragDefaultKeys(80, 62).suggestion!,
        gate: { ...ragDefaultKeys(80, 62).suggestion!.gate!, forced: true, forced_by: ["step4"] },
      },
    });
    expect(verdictTile(stray).forced).toBe(false);
  });

  it("falls back on the model's own answer for a stored needs_review that still arrives, as the line did", () => {
    const stored = stateOf({
      suggestion: {
        run_id: "r1",
        suggested_action: "needs_review",
        confidence: "low",
        gate: { forced: true, forced_by: ["step4"], proposed_verdict: "true_positive" },
      },
      proposed_action: "true_positive",
    });
    expect(verdictTile(stored).label).toBe("TP");
  });

  it("shows a verdict it has no scale for as it came, neutral, with no line under it", () => {
    const odd = stateOf({
      suggestion: { run_id: "r1", suggested_action: "needs_review", confidence: null },
      proposed_action: null,
    });
    expect(verdictTile(odd)).toEqual({
      label: "Cần xem xét",
      tone: "neutral",
      note: null,
      forced: false,
    });
  });
});

describe("the Độ tin cậy tile", () => {
  it.each([
    ["low", "Thấp"],
    ["medium", "Trung bình"],
    ["high", "Cao"],
  ] as const)("is %s: the word %s over a meter", (level, word) => {
    expect(confidenceTile(stateOf(withAction("true_positive", level)))).toEqual({
      kind: "level",
      level,
      word,
    });
  });

  it("has no confidence for a run the RAG default applied to, and says so rather than naming one", () => {
    const tile = confidenceTile(stateOf({ ...ragDefaultKeys(), analysis: ragDefaultAnalysis() }));
    expect(tile).toEqual({ kind: "none", word: "—", note: "không áp dụng cho kết luận mặc định" });
  });

  it("is a dash with no meter for a run that carries no confidence", () => {
    expect(confidenceTile(stateOf(withAction("true_positive", null)))).toEqual({
      kind: "word",
      word: "—",
    });
  });

  it("shows a level this page has no scale for as it came, with no meter", () => {
    expect(confidenceTile(stateOf(withAction("true_positive", "rất cao")))).toEqual({
      kind: "word",
      word: "rất cao",
    });
  });
});

describe("the Kiểm chứng tile", () => {
  const model = (over: Record<string, unknown>) => {
    const read = analysisOf(baseView({ analysis: analysis(over as never) }));
    if (read === null) throw new Error("no analysis");
    return read;
  };

  it("is the checks passed over the checks that apply, and the warnings in the warning colour", () => {
    expect(checksTile(model({}))).toEqual({ value: "3/5", note: "2 cảnh báo", warn: true });
  });

  it("says there is no warning when there is none", () => {
    expect(checksTile(model({ check_totals: { passed: 6, applicable: 6, warnings: 0 } }))).toEqual({
      value: "6/6",
      note: "không có cảnh báo",
      warn: false,
    });
  });

  it("is a dash when no check applies", () => {
    expect(checksTile(model({ check_totals: { passed: 0, applicable: 0, warnings: 0 } }))).toEqual({
      value: "—",
      note: "chưa có kiểm chứng",
      warn: false,
    });
  });

  it("counts the rows itself when the server sent no totals, and shows nothing for no rows", () => {
    expect(checksTile(model({ check_totals: undefined }))).toEqual({
      value: "3/5",
      note: "2 cảnh báo",
      warn: true,
    });
    expect(checksTile(model({ check_totals: undefined, checks: [] }))).toEqual({
      value: "—",
      note: "chưa có kiểm chứng",
      warn: false,
    });
  });

  it("holds the passed count to the applicable one, whatever the server says", () => {
    expect(
      checksTile(model({ check_totals: { passed: 9, applicable: 5, warnings: 0 } })).value,
    ).toBe("5/5");
  });
});

describe("the highlights", () => {
  it("words each closed code from its params, with the arrow of its direction", () => {
    expect(analysisOf(baseView())?.highlights).toEqual([
      {
        direction: "up",
        text: "Lịch sử: 15 trên 15 alert cùng kịch bản và cùng máy từng là sự cố thật.",
      },
      { direction: "up", text: "Tài khoản liên quan là tài khoản đặc quyền." },
      {
        direction: "warn",
        text: "Không có tri thức đã duyệt nào trùng từ 50% trở lên (cao nhất 47%).",
      },
      { direction: "warn", text: "Bộ kiểm chứng độc lập không đồng ý." },
    ]);
  });

  it("words a matched entry with its conclusion, and a lookup failure with its kind", () => {
    expect(highlightText("rag_matched", { pct: 62, conclusion: "closed_fp" })).toBe(
      "Tri thức đã duyệt trùng 62% (đã đóng FP).",
    );
    expect(highlightText("rag_matched", { pct: 62, conclusion: null })).toBe(
      "Tri thức đã duyệt trùng 62%.",
    );
    expect(highlightText("rag_failed", { failure: "quota" })).toBe(
      "Không tra cứu được tri thức đã duyệt: Voyage hết hạn mức.",
    );
    // a kind the page has no words for is not shown, and never as its code (`failureKindLabel`)
    expect(highlightText("rag_failed", { failure: "cosmic_ray" })).toBe(
      "Không tra cứu được tri thức đã duyệt.",
    );
  });

  // The scope is the history's own key, in the words of the Tri thức tab's line (the mock-up: "alert cùng kịch bản và
  // cùng máy"); no history, no key, or a key this page has no words for says "tương tự".
  it.each([
    ["soar_case", "cùng case SOAR"],
    ["cluster", "cùng cụm (rule, nguồn, đích, máy)"],
    ["scenario_host", "cùng kịch bản và cùng máy"],
    ["rule_host", "cùng rule và cùng máy"],
    ["rule_source", "cùng rule và cùng nguồn hoặc người dùng"],
    ["category_host", "cùng loại alert và cùng máy"],
  ])("words the history highlights with the scope of the key %s: %s", (key, scope) => {
    const model = analysisOf(
      baseView({
        analysis: analysis({
          history: { ...analysis().history, key } as never,
          highlights: [
            { direction: "up", code: "history_incident", params: { count: 9, total: 12 } },
            { direction: "down", code: "history_benign", params: { count: 7, total: 8 } },
          ],
        }),
      }),
    );
    expect(model?.highlights.map((row) => row.text)).toEqual([
      `Lịch sử: 9 trên 12 alert ${scope} từng là sự cố thật.`,
      `Lịch sử: 7 trên 8 alert ${scope} từng được đóng là không phải tấn công.`,
    ]);
  });

  it("says 'tương tự' for a highlight of a run with no history, no key or a key it has no words for", () => {
    const text = (history: unknown) =>
      analysisOf(
        baseView({
          analysis: analysis({
            history: history as never,
            highlights: [
              { direction: "up", code: "history_incident", params: { count: 3, total: 4 } },
            ],
          }),
        }),
      )?.highlights[0]?.text;
    const expected = "Lịch sử: 3 trên 4 alert tương tự từng là sự cố thật.";
    expect(text(null)).toBe(expected);
    expect(text({ ...analysis().history, key: null })).toBe(expected);
    expect(text({ ...analysis().history, key: "future_level" })).toBe(expected);
    expect(text({ ...analysis().history, key: "constructor" })).toBe(expected);
  });

  it("degrades to a plainer sentence when the params are missing or of the wrong kind", () => {
    expect(highlightText("history_incident", {})).toBe(
      "Lịch sử: phần lớn alert tương tự từng là sự cố thật.",
    );
    expect(highlightText("history_benign", { count: "x", total: null })).toBe(
      "Lịch sử: phần lớn alert tương tự từng được đóng là không phải tấn công.",
    );
    expect(highlightText("rag_below_floor", { pct: "x" })).toBe(
      "Không có tri thức đã duyệt nào đạt mức tối thiểu.",
    );
    expect(highlightText("rag_failed", {})).toBe("Không tra cứu được tri thức đã duyệt.");
  });

  it("shows a code it has no words for as the code, never drops it, and reads an odd direction as a warning", () => {
    const model = analysisOf(
      baseView({
        analysis: analysis({
          highlights: [
            { direction: "sideways" as never, code: "brand_new_code" as never, params: {} },
            { direction: "down", code: "asset_high", params: null as never },
          ],
        }),
      }),
    );
    expect(model?.highlights).toEqual([
      { direction: "warn", text: "brand_new_code" },
      { direction: "down", text: "Tài sản liên quan có độ quan trọng cao." },
    ]);
  });

  it("does not answer for a code from the prototype chain", () => {
    expect(highlightText("constructor", {})).toBe("constructor");
    expect(highlightText("__proto__", {})).toBe("__proto__");
  });
});

describe("the checks", () => {
  const lines = (over: Record<string, unknown> = {}) =>
    analysisOf(baseView({ analysis: analysis(over as never) }))?.checks;

  it("words each row with the name of its step and its closed detail, in the order served", () => {
    expect(lines()).toEqual([
      { id: "1", name: "Đúng định dạng", outcome: "pass", text: "hợp lệ ngay lần đầu", notes: [] },
      {
        id: "2",
        name: "Dữ kiện",
        outcome: "warn",
        text: "AI khai mức nghiêm trọng high, hệ thống ghi medium",
        notes: [],
      },
      {
        id: "3",
        name: "Dẫn chứng",
        outcome: "pass",
        text: "2 trên 4 khớp nguyên văn",
        notes: [],
      },
      {
        id: "3r",
        name: "Quy tắc RAG",
        outcome: "na",
        text: "không áp dụng, không có mục nào đạt mức tối thiểu",
        notes: [],
      },
      {
        id: "4",
        name: "Chính sách FP",
        outcome: "na",
        text: "không xét, vì kết luận là TP",
        notes: [],
      },
      { id: "5", name: "Chèn lệnh", outcome: "pass", text: "không phát hiện", notes: [] },
      {
        id: "6",
        name: "Bộ kiểm chứng độc lập",
        outcome: "warn",
        text: "không đồng ý",
        notes: [],
      },
    ]);
  });

  it("lists every field step 2 flagged, joined", () => {
    const facts = analysis().facts.map((fact) =>
      fact.field === "asset_criticality"
        ? { ...fact, system: "low", model: "high", match: false }
        : fact,
    );
    expect(lines({ facts })?.[1]?.text).toBe(
      "AI khai mức nghiêm trọng high, hệ thống ghi medium; AI khai độ quan trọng tài sản high, hệ thống ghi low",
    );
  });

  it("says the closed word alone when no fact is flagged (a run the RAG default applied to has no model column)", () => {
    const model = analysisOf(baseView({ analysis: ragDefaultAnalysis() }));
    expect(model?.checks.map((row) => row.text)).toEqual([
      "hợp lệ ngay lần đầu",
      "dữ kiện AI khai khớp với hệ thống",
      "2 trên 2 khớp nguyên văn",
      "đã áp dụng, kết luận mặc định là FP",
      "đạt",
      "không phát hiện",
    ]);
    expect(model?.checks.some((row) => row.id === "6")).toBe(false);
  });

  it("shows a step and a detail it has no words for as the codes, with the outcome it was given", () => {
    const rows = lines({
      checks: [{ id: "9", outcome: "warn", detail: "brand_new" }],
    });
    expect(rows).toEqual([{ id: "9", name: "9", outcome: "warn", text: "brand_new", notes: [] }]);
  });

  it("reads an outcome it does not know as not applicable, and skips a row that is not an object", () => {
    const rows = lines({
      checks: [{ id: "1", outcome: "maybe", detail: "schema_ok" }, null, 3],
    });
    expect(rows?.map((row) => row.outcome)).toEqual(["na"]);
  });
});

describe("the RAG rule's check says why it did not apply, from the state of the lookup", () => {
  const rule = (rag: Record<string, unknown>, detail = "rag_rule_not_applied") =>
    analysisOf(
      baseView({
        analysis: analysis({
          rag: { ...analysis().rag, ...rag } as never,
          checks: [{ id: "3r", outcome: "na", detail }],
        } as never),
      }),
    )?.checks[0]?.text;

  it.each([
    [{ state: "no_candidate", best_pct: null, candidates: [] }, "không có mục trùng"],
    [{ state: "no_lookup", best_pct: null, candidates: [] }, "không có tra cứu"],
    [{ state: "failed", failure: "auth", best_pct: null, candidates: [] }, "tra cứu bị lỗi"],
    [{ state: "below_floor", best_pct: 47, floor_pct: 50 }, "không có mục nào đạt mức tối thiểu"],
    [{ state: "matched", best_pct: 85, threshold_pct: 80 }, "độ trùng 85% không dưới ngưỡng 80%"],
  ])("for %j: 'không áp dụng, %s'", (rag, why) => {
    expect(rule(rag)).toBe(`không áp dụng, ${why}`);
  });

  it("shows a state it has no words for as the code, and says nothing more of a rule that is off or applied", () => {
    expect(rule({ state: "future_state" })).toBe("không áp dụng, future_state");
    expect(rule({ state: "no_candidate" }, "rag_rule_off")).toBe("quy tắc đang tắt");
    expect(rule({ state: "matched", best_pct: 62 }, "rag_rule_applied")).toBe(
      "đã áp dụng, kết luận mặc định là FP",
    );
  });
});

/**
 * The gate's own account of a run, from the keys of the view the panel used to leave unread (spec G2): `held_by`, the
 * gate's `warnings`, the verifier's verdict and the verdict before and after the gate. Built as the server serves them.
 */
describe("the gate's own account of the run", () => {
  const gated = (
    gate: Record<string, unknown> = {},
    held: unknown = [],
    over: Partial<AlertView> = {},
  ): AlertView =>
    baseView({
      held_by: held as never,
      suggestion: {
        run_id: "r1",
        suggested_action: "true_positive",
        confidence: "medium",
        gate: {
          forced: false,
          forced_by: [],
          proposed_verdict: "true_positive",
          final_verdict: "true_positive",
          warnings: [],
          ...gate,
        } as never,
      },
      ...over,
    });
  const notes = (view: AlertView) => {
    const model = analysisOf(view);
    return Object.fromEntries(model?.checks.map((row) => [row.id, row.notes]) ?? []);
  };

  it("names, under each step, the held reasons that belong to it, in the words of the flat column", () => {
    const view = gated({}, [
      "facts_mismatch",
      "no_verified_quote",
      "fp_policy:severity",
      "fp_policy:ioc_reputation",
      "fp_policy:asset_criticality",
      "fp_policy:identity_privileged",
      "fp_policy:playbook_rule",
      "verifier_disagrees",
    ]);
    expect(notes(view)).toEqual({
      "1": [],
      "2": ["AI khai dữ kiện lệch với hệ thống"],
      "3": ["không có dẫn chứng kiểm chứng được"],
      "3r": [],
      "4": [
        "alert mức critical",
        "IOC độc hại hoặc đáng ngờ",
        "tài sản quan trọng hoặc chưa rõ",
        "tài khoản đặc quyền",
        "không khớp bảng quyết định đã duyệt",
      ],
      "5": [],
      "6": ["bộ kiểm chứng không đồng ý"],
    });
    expect(analysisOf(view)?.gate.held).toEqual([
      "AI khai dữ kiện lệch với hệ thống",
      "không có dẫn chứng kiểm chứng được",
      "alert mức critical",
      "IOC độc hại hoặc đáng ngờ",
      "tài sản quan trọng hoặc chưa rõ",
      "tài khoản đặc quyền",
      "không khớp bảng quyết định đã duyệt",
      "bộ kiểm chứng không đồng ý",
    ]);
  });

  // Every code of `held_by` the page has words for (`S.ai1.heldReason`, held equal to the backend's HELD_REASONS by
  // strings.test.ts) stands under a step of the page: none is left to the loose list.
  it.each(Object.keys(S.ai1.heldReason))("places the held reason %s under a step", (code) => {
    const model = analysisOf(gated({}, [code]));
    expect(model?.gate.loose).toEqual([]);
    expect(model?.checks.flatMap((row) => row.notes)).toEqual([S.ai1.heldReason[code as never]]);
  });

  it("names the playbook failure beside the fact that failed, when both did (the step's line says only the fact)", () => {
    const both = analysis({
      checks: [{ id: "4", outcome: "warn", detail: "fp_policy_facts" }],
      check_totals: { passed: 0, applicable: 1, warnings: 1 },
    });
    const view = gated({}, ["fp_policy:ioc_reputation", "fp_policy:playbook_rule"], {
      analysis: both,
    });
    const row = analysisOf(view)?.checks[0];
    expect(row?.text).toBe("một dữ kiện của alert không cho phép kết luận FP");
    expect(row?.notes).toEqual([
      "IOC độc hại hoặc đáng ngờ",
      "không khớp bảng quyết định đã duyệt",
    ]);
  });

  it("words each reason the rule check wrote into the gate's warnings, under step 4, after the held reasons", () => {
    const view = gated({ warnings: ["no_rule_cited", "rule_is_not_false_positive"] }, [
      "fp_policy:playbook_rule",
    ]);
    expect(notes(view)["4"]).toEqual([
      "không khớp bảng quyết định đã duyệt",
      "AI không dẫn rule nào của bảng quyết định",
      "rule AI dẫn không dẫn tới kết luận FP",
    ]);
  });

  it.each([
    ["no_rule_cited", "AI không dẫn rule nào của bảng quyết định"],
    ["no_table", "loại alert này chưa có bảng quyết định"],
    ["table_unreviewed", "bảng quyết định chưa được ký duyệt"],
    ["unknown_rule", "rule AI dẫn không có trong bảng quyết định"],
    ["rule_does_not_hold", "rule AI dẫn không khớp dữ kiện của alert"],
    ["rule_is_not_false_positive", "rule AI dẫn không dẫn tới kết luận FP"],
  ])("words the warning %s", (code, words) => {
    expect(notes(gated({ warnings: [code] }))["4"]).toEqual([words]);
  });

  it("shows a warning it has no words for as it came, a non-text warning as its text, and drops none", () => {
    expect(notes(gated({ warnings: ["brand_new_warning", { odd: 1 }] }))["4"]).toEqual([
      "brand_new_warning",
      '{"odd":1}',
    ]);
  });

  it("lists a held code that names no step of the page under the tab, shown as the code, and never drops it", () => {
    const view = gated({}, ["brand_new_reason", "facts_mismatch", "fp_policy:brand_new"]);
    const model = analysisOf(view);
    expect(model?.gate.loose).toEqual(["brand_new_reason"]);
    expect(notes(view)["4"]).toEqual(["fp_policy:brand_new"]);
    expect(model?.gate.held).toEqual([
      "brand_new_reason",
      "AI khai dữ kiện lệch với hệ thống",
      "fp_policy:brand_new",
    ]);
  });

  it("lists a reason whose step has no row (a run with no verifier check) under the tab", () => {
    const view = gated({}, ["verifier_invalid", "facts_mismatch"], {
      analysis: analysis({
        checks: [{ id: "2", outcome: "warn", detail: "facts_mismatch" }],
      }),
    });
    const model = analysisOf(view);
    expect(model?.gate.loose).toEqual(["bộ kiểm chứng không trả lời hợp lệ"]);
    expect(model?.checks[0]?.notes).toEqual(["AI khai dữ kiện lệch với hệ thống"]);
  });

  it("reads held_by as the page always did: only its non-empty strings, once each", () => {
    const view = gated({}, ["facts_mismatch", "", 3, null, "facts_mismatch"]);
    expect(analysisOf(view)?.gate.held).toEqual(["AI khai dữ kiện lệch với hệ thống"]);
    expect(analysisOf(gated({}, "facts_mismatch"))?.gate.held).toEqual([]);
    expect(analysisOf(gated({}, undefined))?.gate.held).toEqual([]);
  });

  it("says what the verifier answered beside step 6, in the product's verdict labels", () => {
    const text = (verdict: unknown) =>
      analysisOf(gated({ verifier_verdict: verdict }))?.checks.find((row) => row.id === "6")?.text;
    expect(text("needs_review")).toBe("không đồng ý (trả lời: Cần xem xét)");
    expect(text("false_positive")).toBe("không đồng ý (trả lời: FP)");
    expect(text("true_positive")).toBe("không đồng ý (trả lời: TP)");
    expect(text("something_new")).toBe("không đồng ý (trả lời: something_new)");
    expect(text(null)).toBe("không đồng ý");
    expect(text("")).toBe("không đồng ý");
    expect(text(5)).toBe("không đồng ý");
  });

  it("gives the verdict before and after the gate for a run the gate forced (a version 1 row), and for no other", () => {
    const forced = gated({
      forced: true,
      forced_by: ["step4"],
      proposed_verdict: "true_positive",
      final_verdict: "needs_review",
    });
    expect(analysisOf(forced)?.gate.forced).toEqual({ proposed: "TP", final: "Cần xem xét" });
    expect(
      analysisOf(gated({ forced: true, proposed_verdict: "true_positive", final_verdict: null }))
        ?.gate.forced,
    ).toEqual({ proposed: "TP", final: null });
    expect(
      analysisOf(gated({ forced: false, final_verdict: "needs_review" }))?.gate.forced,
    ).toBeNull();
    expect(analysisOf(baseView())?.gate.forced).toBeNull();
  });

  describe("for a run the RAG default applied to (DEC-219), whatever arrives", () => {
    const applied = (gate: Record<string, unknown>, held: unknown, over: Partial<AlertView> = {}) =>
      gated({ rag_rule: { threshold: 80, best_pct: 62, applied: true }, ...gate }, held, {
        analysis: ragDefaultAnalysis(),
        ...over,
      });

    it("never says what the verifier answered, nor a verdict before and after the gate, even from a stray key", () => {
      const view = applied(
        {
          verifier_verdict: "needs_review",
          forced: true,
          forced_by: ["step4"],
          proposed_verdict: "true_positive",
          final_verdict: "false_positive",
        },
        ["verifier_disagrees"],
        {
          analysis: analysis({
            checks: ragDefaultAnalysis().checks.concat([
              { id: "6", outcome: "warn", detail: "verifier_disagrees" },
            ]),
          }),
        },
      );
      const model = analysisOf(view);
      expect(model?.checks.find((row) => row.id === "6")?.text).toBe("không đồng ý");
      expect(model?.gate.forced).toBeNull();
    });

    it("leaves out the reasons the server leaves out: the verifier's disagreement, the playbook rule and its warnings", () => {
      const view = applied(
        { warnings: ["rule_is_not_false_positive", "no_rule_cited", "brand_new_warning"] },
        [
          "fp_policy:asset_criticality",
          "fp_policy:playbook_rule",
          "verifier_disagrees",
          "verifier_invalid",
        ],
      );
      const model = analysisOf(view);
      expect(model?.gate.held).toEqual([
        "tài sản quan trọng hoặc chưa rõ",
        "bộ kiểm chứng không trả lời hợp lệ",
      ]);
      const byStep = Object.fromEntries(model?.checks.map((row) => [row.id, row.notes]) ?? []);
      expect(byStep["4"]).toEqual(["tài sản quan trọng hoặc chưa rõ", "brand_new_warning"]);
    });
  });
});

describe("the facts", () => {
  it("words the field, the system's value and the value the model declared, and whether they agree", () => {
    const model = analysisOf(baseView());
    expect(model?.showDeclared).toBe(true);
    expect(model?.facts).toEqual([
      { field: "Mức nghiêm trọng", system: "medium", declared: "high", match: false },
      { field: "Danh tiếng IOC", system: "chưa tra", declared: "chưa tra", match: true },
      { field: "Độ quan trọng tài sản", system: "medium", declared: "medium", match: true },
      { field: "Tài khoản đặc quyền", system: "có", declared: "có", match: true },
      { field: "Số lần xuất hiện", system: "2", declared: "2", match: true },
    ]);
  });

  it("has no model column for a run the RAG default applied to: the declared values are null", () => {
    const model = analysisOf(baseView({ analysis: ragDefaultAnalysis() }));
    expect(model?.showDeclared).toBe(false);
    expect(model?.facts.map((fact) => [fact.field, fact.system])).toEqual([
      ["Mức nghiêm trọng", "medium"],
      ["Danh tiếng IOC", "chưa tra"],
      ["Độ quan trọng tài sản", "medium"],
      ["Tài khoản đặc quyền", "không"],
      ["Số lần xuất hiện", "2"],
    ]);
  });

  it("shows a missing value as a dash, an unknown value as it came and an unknown field as its code", () => {
    const model = analysisOf(
      baseView({
        analysis: analysis({
          facts: [
            { field: "severity", system: null, model: "high", match: null },
            {
              field: "identity_privileged",
              system: "perhaps" as never,
              model: "true",
              match: null,
            },
            { field: "new_field" as never, system: "x", model: "y", match: null },
          ],
        }),
      }),
    );
    expect(model?.facts).toEqual([
      { field: "Mức nghiêm trọng", system: "—", declared: "high", match: null },
      { field: "Tài khoản đặc quyền", system: "perhaps", declared: "có", match: null },
      { field: "new_field", system: "x", declared: "y", match: null },
    ]);
  });
});

describe("the lookup, the history, the playbook and the technical figures", () => {
  it("reads the lookup with its candidates, best first, at most three, each with a percentage", () => {
    const rag = analysisOf(baseView())?.rag;
    expect(rag?.state).toBe("below_floor");
    expect(rag?.best_pct).toBe(47);
    expect(rag?.floor_pct).toBe(50);
    expect(rag?.threshold).toBe(80);
    expect(rag?.scored).toBe(23);
    expect(rag?.candidates.map((row) => row.pct)).toEqual([47, 43, 41]);
    const long = analysisOf(
      baseView({
        analysis: analysis({
          rag: {
            ...analysis().rag,
            candidates: [1, 2, 3, 4, 5].map((pct) => ({ pct, title: null, conclusion: null })),
          },
        }),
      }),
    )?.rag;
    expect(long?.candidates).toHaveLength(3);
  });

  it("skips a candidate with no whole percentage", () => {
    const rag = analysisOf(
      baseView({
        analysis: analysis({
          rag: {
            ...analysis().rag,
            candidates: [
              { pct: "x" as never, title: "a", conclusion: null },
              { pct: 47.5 as never, title: "b", conclusion: null },
              { pct: 40, title: "c", conclusion: null },
            ],
          },
        }),
      }),
    )?.rag;
    expect(rag?.candidates.map((row) => row.pct)).toEqual([40]);
  });

  it("words the history of a decision: the scope, the total, the incidents, and the rest by conclusion", () => {
    expect(analysisOf(baseView())?.history).toEqual({
      line: "Cùng kịch bản và cùng máy: 15 quyết định, 15 là sự cố thật · gần nhất 06/11 16:00",
    });
    const mixed = analysisOf(
      baseView({
        analysis: analysis({
          history: {
            key: "rule_host",
            total: 15,
            by_conclusion: {
              tier1_closed_fp: 3,
              tier1_closed_benign: 1,
              escalated_open: 0,
              concluded_fp: 0,
              concluded_policy_violation: 0,
              confirmed_incident: 11,
            },
            last_seen: null,
          },
        }),
      }),
    )?.history;
    expect(mixed?.line).toBe(
      "Cùng rule và cùng máy: 15 quyết định, 11 là sự cố thật; còn lại: 3 đóng FP, 1 đóng lành tính",
    );
  });

  it("calls a history with no key 'Alert tương tự', shows an unknown key as it came, and has none for a total that is not a count", () => {
    const history = (over: Record<string, unknown>) =>
      analysisOf(
        baseView({
          analysis: analysis({ history: { ...analysis().history, ...over } as never }),
        }),
      )?.history;
    expect(history({ key: null, last_seen: null })?.line).toBe(
      "Alert tương tự: 15 quyết định, 15 là sự cố thật",
    );
    expect(history({ key: "future_level", last_seen: null })?.line).toBe(
      "future_level: 15 quyết định, 15 là sự cố thật",
    );
    expect(history({ total: 0 })).toBeNull();
    expect(history({ total: "x" })).toBeNull();
    expect(analysisOf(baseView({ analysis: analysis({ history: null }) }))?.history).toBeNull();
  });

  it("reads the playbook and the rule of the decision table that matched, and whether the table is signed", () => {
    expect(analysisOf(baseView())?.playbook).toEqual({
      name: "ransomware_v1",
      ruleId: "ran-1",
      action: "cần người xem",
      reviewed: true,
    });
    const none = analysisOf(
      baseView({
        analysis: analysis({
          playbook: { name: null, rule_id: null, rule_action: null, rule_table_reviewed: null },
        }),
      }),
    );
    expect(none?.playbook).toBeNull();
    const unsigned = analysisOf(
      baseView({
        analysis: analysis({
          playbook: {
            name: "ssh_v1",
            rule_id: null,
            rule_action: null,
            rule_table_reviewed: false,
          },
        }),
      }),
    )?.playbook;
    expect(unsigned).toEqual({ name: "ssh_v1", ruleId: null, action: null, reviewed: false });
  });

  it("reads the technical figures, and none of them is a model", () => {
    const tech = analysisOf(baseView())?.tech;
    expect(tech).toEqual({
      inputTokens: 13637,
      outputTokens: 981,
      latencyMs: 4200,
      costUsd: 0.0007,
      analysedAt: "2026-11-15T11:35:56Z",
      mitre: ["T1490"],
      correlated: 3,
    });
    expect(Object.keys(tech ?? {}).join(" ")).not.toMatch(/model/i);
  });

  it("keeps the MITRE ids that are strings, and the figures that are numbers", () => {
    const tech = analysisOf(
      baseView({
        analysis: analysis({
          tech: {
            input_tokens: "x" as never,
            output_tokens: null,
            latency_ms: Number.NaN,
            cost_usd: 0.1,
            analysed_at: 5 as never,
            mitre_ids: ["T1", 4, null, "T2"] as never,
            correlated_at_analysis: null,
          },
        }),
      }),
    )?.tech;
    expect(tech).toEqual({
      inputTokens: null,
      outputTokens: null,
      latencyMs: null,
      costUsd: 0.1,
      analysedAt: null,
      mitre: ["T1", "T2"],
      correlated: null,
    });
  });
});
