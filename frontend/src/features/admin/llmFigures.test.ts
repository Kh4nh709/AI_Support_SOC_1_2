// src/features/admin/llmFigures.test.ts — the pure figures of the LLM page: money and number text, the cost
// state (which is spent >= cap, never `pct`), the sums of the pipeline table, the labels, the link of a
// subject, and the reading of a limit field. The page test (LlmPage.test.tsx) shows them on screen.
import type { LimitsOut, PipelineRoleRow } from "../../api/admin";
import {
  WARN_PCT,
  costState,
  formatCount,
  formatLatency,
  formatPercent,
  formatSeconds,
  formatTokens,
  formatUsd,
  limitChanges,
  parseLimit,
  pipelineLabel,
  shortId,
  stoppedEntries,
  subjectLink,
  summarise,
} from "./llmFigures";

const row = (over: Partial<PipelineRoleRow> = {}): PipelineRoleRow => ({
  pipeline: "triage",
  role: "proposer",
  calls: 10,
  with_result: 9,
  stopped: {},
  input_tokens: 1000,
  output_tokens: 100,
  latency_p50_ms: 2000,
  latency_p95_ms: 4000,
  cost_usd: 0.1,
  ...over,
});

describe("formatUsd", () => {
  it.each([
    [0.51, "$0,51"],
    [0.0024, "$0,0024"],
    [24.6, "$24,60"],
    [0, "$0,00"],
    [1234.5, "$1.234,50"],
    [0.00004, "$0,00"],
  ])("writes %s as %s, two to four decimals", (value, text) => {
    expect(formatUsd(value)).toBe(text);
  });

  it("writes a whole-dollar value (the cap) with no decimals", () => {
    expect(formatUsd(30, true)).toBe("$30");
    expect(formatUsd(1000, true)).toBe("$1.000");
  });
});

describe("the number texts", () => {
  it("groups a count with the Vietnamese point", () => {
    expect(formatCount(1589)).toBe("1.589");
    expect(formatCount(0)).toBe("0");
  });

  it("writes tokens from 100,000 up in millions with at most two decimals, and below that in full", () => {
    expect(formatTokens(2_437_000)).toBe("2,44 tr");
    expect(formatTokens(411_000)).toBe("0,41 tr");
    expect(formatTokens(100_000)).toBe("0,1 tr");
    expect(formatTokens(99_999)).toBe("99.999");
    expect(formatTokens(47_000)).toBe("47.000");
    expect(formatTokens(0)).toBe("0");
  });

  it("writes a percentage with one decimal at most", () => {
    expect(formatPercent(82)).toBe("82%");
    expect(formatPercent(82.4)).toBe("82,4%");
    expect(formatPercent(14.28)).toBe("14,3%");
    expect(formatPercent(0)).toBe("0%");
  });

  it("writes milliseconds as seconds with one decimal, and a missing latency as a dash", () => {
    expect(formatSeconds(2300)).toBe("2,3 s");
    expect(formatSeconds(12500)).toBe("12,5 s");
    expect(formatSeconds(0)).toBe("0 s");
    expect(formatSeconds(null)).toBe("—");
  });

  it("writes p50 / p95, a dash for the one that is missing, and one dash when both are", () => {
    expect(formatLatency(2400, 9800)).toBe("2,4 s / 9,8 s");
    expect(formatLatency(1100, null)).toBe("1,1 s / —");
    expect(formatLatency(null, null)).toBe("—");
  });
});

describe("costState — spent >= cap is the stop, pct is only for the amber", () => {
  const month = (spent_usd: number, cap_usd: number | null, pct: number | null) => ({
    spent_usd,
    cap_usd,
    pct,
    projected_usd: 0,
  });

  it("warns from 80 %", () => {
    expect(WARN_PCT).toBe(80);
    expect(costState(month(24, 30, 80))).toBe("warn");
    expect(costState(month(23.97, 30, 79.9))).toBe("ok");
    expect(costState(month(24.6, 30, 82))).toBe("warn");
  });

  it("stops when spent reaches the cap, and only then", () => {
    expect(costState(month(30, 30, 100))).toBe("stopped");
    expect(costState(month(31.5, 30, 100))).toBe("stopped");
    expect(costState(month(29.9999, 30, 99.9))).toBe("warn");
  });

  it("does not read pct for the stop: a pct of 100 with spent below the cap is not a stop", () => {
    expect(costState(month(29.99, 30, 100))).toBe("warn");
  });

  it("does not read pct for the stop: a pct below 100 with spent at the cap is a stop", () => {
    expect(costState(month(30, 30, 99.9))).toBe("stopped");
  });

  it("has no state to warn about without a cap", () => {
    expect(costState(month(5, null, null))).toBe("ok");
  });
});

describe("summarise", () => {
  const rows = [
    row({
      calls: 855,
      input_tokens: 1_890_000,
      output_tokens: 330_000,
      stopped: { schema: 100, cap: 22 },
    }),
    row({
      role: "verifier",
      calls: 733,
      input_tokens: 500_000,
      output_tokens: 80_000,
      stopped: {},
    }),
    row({
      pipeline: "investigate",
      role: "investigator",
      calls: 1,
      input_tokens: 47_000,
      output_tokens: 1000,
      stopped: { other: 3 },
    }),
  ];

  it("sums the calls and the tokens", () => {
    const sum = summarise(rows);
    expect(sum.calls).toBe(1589);
    expect(sum.inputTokens).toBe(2_437_000);
    expect(sum.outputTokens).toBe(411_000);
  });

  it("counts calls and input tokens per pipeline, ① first, ② second, any other after", () => {
    const sum = summarise([
      row({ pipeline: "chat", role: null, calls: 2, input_tokens: 20 }),
      ...rows,
    ]);
    expect(sum.byPipeline.map((p) => [p.pipeline, p.calls, p.inputTokens])).toEqual([
      ["triage", 1588, 2_390_000],
      ["investigate", 1, 47_000],
      ["chat", 2, 20],
    ]);
  });

  it("counts the stopped runs, and names the code most of them stopped on", () => {
    const sum = summarise(rows);
    expect(sum.stopped).toBe(125);
    expect(sum.mainStopped).toEqual({ code: "schema", count: 100 });
  });

  it("names no code when nothing stopped", () => {
    const sum = summarise([row()]);
    expect(sum.stopped).toBe(0);
    expect(sum.mainStopped).toBeNull();
  });

  it("is all zeros for no rows", () => {
    expect(summarise([])).toEqual({
      calls: 0,
      inputTokens: 0,
      outputTokens: 0,
      byPipeline: [],
      stopped: 0,
      mainStopped: null,
    });
  });
});

describe("stoppedEntries", () => {
  it("lists the largest count first, then by code", () => {
    expect(stoppedEntries({ transient: 2, schema: 5, cap: 2, other: 1 })).toEqual([
      ["schema", 5],
      ["cap", 2],
      ["transient", 2],
      ["other", 1],
    ]);
  });
  it("is empty for none", () => {
    expect(stoppedEntries({})).toEqual([]);
  });
});

describe("pipelineLabel", () => {
  it.each([
    ["triage", "proposer", "① triage · proposer"],
    ["triage", "verifier", "① triage · verifier"],
    ["triage", null, "① triage"],
    ["investigate", "investigator", "② điều tra case"],
    ["investigate", null, "② điều tra case"],
  ])("%s / %s is %s", (pipeline, role, label) => {
    expect(pipelineLabel(pipeline, role)).toBe(label);
  });

  it("shows an unknown pipeline and role as they came", () => {
    expect(pipelineLabel("chat", null)).toBe("chat");
    expect(pipelineLabel("chat", "assistant")).toBe("chat · assistant");
    expect(pipelineLabel("triage", "auditor")).toBe("① triage · auditor");
  });

  it("does not answer from the prototype chain", () => {
    expect(pipelineLabel("constructor", "__proto__")).toBe("constructor · __proto__");
  });
});

describe("subjectLink and shortId", () => {
  it("links an alert and a case to their own pages, the id encoded", () => {
    expect(subjectLink("alert", "1662100")).toBe("/alerts/1662100");
    expect(subjectLink("case", "0b30b853-1c2d-4e5f-8a9b-000000000001")).toBe(
      "/cases/0b30b853-1c2d-4e5f-8a9b-000000000001",
    );
    expect(subjectLink("alert", "a/b?c")).toBe("/alerts/a%2Fb%3Fc");
  });

  it("links nothing it does not know, or has no id for", () => {
    expect(subjectLink("rule", "7")).toBeNull();
    expect(subjectLink(null, "7")).toBeNull();
    expect(subjectLink("alert", null)).toBeNull();
    expect(subjectLink("alert", "")).toBeNull();
    expect(subjectLink("constructor", "7")).toBeNull();
  });

  it("shortens an id of more than twelve characters to its last eight, and leaves a shorter one", () => {
    expect(shortId("1662100")).toBe("1662100");
    expect(shortId("123456789012")).toBe("123456789012");
    expect(shortId("1234567890123")).toBe("…67890123");
    expect(shortId("0b30b853-1c2d-4e5f-8a9b-000000000001")).toBe("…00000001");
    expect(shortId("1759012345.1662100")).toBe("….1662100");
  });
});

describe("parseLimit", () => {
  const bound = { min: 10, max: 120 };

  it("reads an integer inside the bounds", () => {
    expect(parseLimit("90", bound)).toEqual({ ok: true, value: 90 });
    expect(parseLimit(" 90 ", bound)).toEqual({ ok: true, value: 90 });
    expect(parseLimit("10", bound)).toEqual({ ok: true, value: 10 });
    expect(parseLimit("120", bound)).toEqual({ ok: true, value: 120 });
    expect(parseLimit("1e2", bound)).toEqual({ ok: true, value: 100 });
  });

  it("calls a blank field empty", () => {
    expect(parseLimit("", bound)).toEqual({ ok: false, reason: "empty" });
    expect(parseLimit("   ", bound)).toEqual({ ok: false, reason: "empty" });
  });

  it.each(["30.5", "abc", "ba mươi", "0x10", "Infinity", "NaN", "1,5", "--3", "12 3", "1e400"])(
    "calls %j not an integer",
    (text) => {
      expect(parseLimit(text, bound)).toEqual({ ok: false, reason: "not_integer" });
    },
  );

  it("reads 30.0 as the integer 30: it is one", () => {
    expect(parseLimit("30.0", bound)).toEqual({ ok: true, value: 30 });
  });

  it.each(["9", "121", "0", "-5", "5000"])(
    "calls %s out of range, with the bounds it was held to",
    (text) => {
      expect(parseLimit(text, bound)).toEqual({
        ok: false,
        reason: "out_of_range",
        min: 10,
        max: 120,
      });
    },
  );
});

describe("limitChanges", () => {
  const limits: LimitsOut = {
    cap_usd: 30,
    quota_per_24h: 30,
    timeout_s: 120,
    sources: {
      LLM_MONTHLY_USD_CAP: {
        source: "env",
        updated_at: null,
        updated_by_name: null,
        clamped: false,
      },
      ANALYZE_QUOTA_PER_USER_DAY: {
        source: "env",
        updated_at: null,
        updated_by_name: null,
        clamped: false,
      },
      LLM_TIMEOUT_S: { source: "env", updated_at: null, updated_by_name: null, clamped: false },
    },
    bounds: {
      cap_usd: { min: 1, max: 1000 },
      quota_per_24h: { min: 1, max: 200 },
      timeout_s: { min: 10, max: 120 },
    },
  };

  it("has no change for no edit", () => {
    expect(limitChanges(limits, {})).toEqual({ changes: {}, errors: {} });
  });

  it("keeps only the fields whose value differs", () => {
    expect(limitChanges(limits, { cap_usd: "40", quota_per_24h: "30", timeout_s: "90" })).toEqual({
      changes: { cap_usd: 40, timeout_s: 90 },
      errors: {},
    });
  });

  it("treats a differently written equal value as no change", () => {
    expect(limitChanges(limits, { cap_usd: "030", timeout_s: "120.0" })).toEqual({
      changes: {},
      errors: {},
    });
  });

  it("reports a bad field and still reads the good ones", () => {
    const result = limitChanges(limits, { cap_usd: "", quota_per_24h: "20", timeout_s: "500" });
    expect(result.changes).toEqual({ quota_per_24h: 20 });
    expect(result.errors).toEqual({
      cap_usd: { ok: false, reason: "empty" },
      timeout_s: { ok: false, reason: "out_of_range", min: 10, max: 120 },
    });
  });

  it("reads each field against its own bounds from the answer, not constants", () => {
    const tight = { ...limits, bounds: { ...limits.bounds, cap_usd: { min: 5, max: 20 } } };
    expect(limitChanges(tight, { cap_usd: "40" }).errors).toEqual({
      cap_usd: { ok: false, reason: "out_of_range", min: 5, max: 20 },
    });
    expect(limitChanges(tight, { cap_usd: "20" }).changes).toEqual({ cap_usd: 20 });
  });
});
