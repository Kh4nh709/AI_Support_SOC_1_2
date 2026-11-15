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
        text: "Lịch sử: 15 trên 15 alert tương tự từng là sự cố thật.",
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
      { id: "1", name: "Đúng định dạng", outcome: "pass", text: "hợp lệ ngay lần đầu" },
      {
        id: "2",
        name: "Dữ kiện",
        outcome: "warn",
        text: "AI khai mức nghiêm trọng high, hệ thống ghi medium",
      },
      { id: "3", name: "Dẫn chứng", outcome: "pass", text: "2 trên 4 khớp nguyên văn" },
      { id: "3r", name: "Quy tắc RAG", outcome: "na", text: "không áp dụng" },
      { id: "4", name: "Chính sách FP", outcome: "na", text: "không xét, vì kết luận là TP" },
      { id: "5", name: "Chèn lệnh", outcome: "pass", text: "không phát hiện" },
      { id: "6", name: "Bộ kiểm chứng độc lập", outcome: "warn", text: "không đồng ý" },
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
    expect(rows).toEqual([{ id: "9", name: "9", outcome: "warn", text: "brand_new" }]);
  });

  it("reads an outcome it does not know as not applicable, and skips a row that is not an object", () => {
    const rows = lines({
      checks: [{ id: "1", outcome: "maybe", detail: "schema_ok" }, null, 3],
    });
    expect(rows?.map((row) => row.outcome)).toEqual(["na"]);
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

  it("calls a history with no or an unknown key 'alert tương tự', and has none for a total that is not a count", () => {
    const history = (over: Record<string, unknown>) =>
      analysisOf(
        baseView({
          analysis: analysis({ history: { ...analysis().history, ...over } as never }),
        }),
      )?.history;
    expect(history({ key: null, last_seen: null })?.line).toBe(
      "Alert tương tự: 15 quyết định, 15 là sự cố thật",
    );
    expect(history({ key: "future_level", last_seen: null })?.line).toMatch(/^Alert tương tự:/);
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
