// src/features/tier2/runModel.test.ts — what the Tier 2 panel reads out of a run, key by key. Every reader takes a run
// as the server serves it, may meet a key that is absent, null or of the wrong kind (an older server, a stored
// document is data), and answers with a value the panel can draw without a crash.
import {
  capList,
  confidenceOf,
  evidenceCounts,
  evidenceTile,
  heldOf,
  hypothesesOf,
  knowledgeOf,
  mitreSteps,
  nextStepsOf,
  overruledShown,
  ragTile,
  scopeOf,
  snapshotOf,
  techOf,
  timelineOf,
  verdictTile,
} from "./runModel";
import {
  asRun,
  evidenceRow,
  knowledgeOf as knowledge,
  runOld,
  runV3,
  runV4,
  timelineRow,
  unverifiedRow,
} from "./runFixtures";

const run = (over: Record<string, unknown> = {}) => asRun(runV4(over));

describe("verdictTile", () => {
  // A: the tile shows one short word per conclusion, as the mock-up does ("Sự cố"); the server's whole label is `label`.
  it.each([
    ["confirmed_incident", "Là sự cố thật", "Sự cố", "critical"],
    ["policy_violation", "Có vi phạm nội quy, không phải tấn công", "Vi phạm nội quy", "high"],
    ["false_positive", "Không phải sự cố", "Không phải sự cố", "low"],
    ["need_more_data", "Cần thêm dữ liệu", "Cần thêm dữ liệu", "medium"],
  ])(
    "says %s as the short word %s over its whole label, in the tone %s, as the assistant's suggestion",
    (code, label, word, tone) => {
      expect(
        verdictTile(run({ conclusion: code, conclusion_label: label, model_conclusion: null })),
      ).toEqual({ label, word, tone, note: "gợi ý của AI" });
    },
  );

  it("says a conclusion the system held back as the system's own, in the caution tone", () => {
    expect(
      verdictTile(
        run({
          conclusion: "need_more_data",
          conclusion_label: "Cần thêm dữ liệu",
          model_conclusion: "confirmed_incident",
          held_by: ["no_verified_evidence"],
        }),
      ),
    ).toEqual({
      label: "Cần thêm dữ liệu",
      word: "Cần thêm dữ liệu",
      tone: "medium",
      note: "hệ thống giữ lại",
    });
  });

  it("says a conclusion an older run had lowered, when it names no model conclusion", () => {
    expect(
      verdictTile(
        run({
          conclusion: "need_more_data",
          conclusion_label: "Cần thêm dữ liệu",
          model_conclusion: null,
          held_by: [],
          overruled:
            "Mô hình đề xuất Là sự cố thật nhưng kết luận đã bị hạ xuống Cần thêm dữ liệu: x.",
        }),
      ),
    ).toEqual({
      label: "Cần thêm dữ liệu",
      word: "Cần thêm dữ liệu",
      tone: "medium",
      note: "đã bị hạ",
    });
  });

  it("holds a stored need_more_data over one of the model's three even when no cause was named", () => {
    const tile = verdictTile(
      run({
        conclusion: "need_more_data",
        conclusion_label: "Cần thêm dữ liệu",
        model_conclusion: "confirmed_incident",
        held_by: [],
      }),
    );
    expect(tile.note).toBe("hệ thống giữ lại");
  });

  it("shows a conclusion it has no words for by the server's label, in the neutral tone", () => {
    expect(
      verdictTile(
        run({ conclusion: "cosmic", conclusion_label: "Nhãn lạ", model_conclusion: null }),
      ),
    ).toEqual({ label: "Nhãn lạ", word: "Nhãn lạ", tone: "neutral", note: "gợi ý của AI" });
  });

  it("shows a run with no conclusion at all as a dash, without a crash", () => {
    expect(
      verdictTile(run({ conclusion: null, conclusion_label: undefined, model_conclusion: null })),
    ).toEqual({ label: "—", word: "—", tone: "neutral", note: "gợi ý của AI" });
  });
});

describe("heldOf and overruledShown", () => {
  it("names the causes the server named, and only text ones", () => {
    const held = heldOf(
      run({
        conclusion: "need_more_data",
        model_conclusion: "confirmed_incident",
        held_by: ["no_verified_evidence", "", 7, null, "high_severity_injection_finding"],
      }),
    );
    expect(held).toEqual({
      modelConclusion: "confirmed_incident",
      causes: ["no_verified_evidence", "high_severity_injection_finding"],
      held: true,
    });
  });

  it("is not held for a conclusion that is the model's own, whatever held_by is missing", () => {
    expect(heldOf(run({ held_by: undefined })).held).toBe(false);
    expect(heldOf(run({ held_by: "no_verified_evidence" })).causes).toEqual([]);
  });

  it("does not call need_more_data held when the model's conclusion is not one of the three", () => {
    expect(
      heldOf(run({ conclusion: "need_more_data", model_conclusion: "need_more_data" })).held,
    ).toBe(false);
  });

  it("shows the server's overrule sentence for an older run, and hides it when the causes are named", () => {
    const sentence = "Mô hình đề xuất A nhưng kết luận đã bị hạ xuống B: x.";
    expect(overruledShown(run({ model_conclusion: null, overruled: sentence }))).toBe(sentence);
    expect(
      overruledShown(
        run({
          conclusion: "need_more_data",
          model_conclusion: "confirmed_incident",
          held_by: ["no_verified_evidence"],
          overruled: sentence,
        }),
      ),
    ).toBeNull();
    expect(
      overruledShown(
        run({
          conclusion: "need_more_data",
          model_conclusion: "confirmed_incident",
          held_by: [],
          overruled: sentence,
        }),
      ),
    ).toBe(sentence);
  });

  it("shows no overrule for a run that has none", () => {
    for (const none of [null, undefined, ""]) {
      expect(overruledShown(run({ model_conclusion: null, overruled: none }))).toBeNull();
    }
  });
});

describe("confidenceOf", () => {
  it.each([
    ["low", "Thấp"],
    ["medium", "Trung bình"],
    ["high", "Cao"],
  ])("says %s as %s with its level", (value, word) => {
    expect(confidenceOf(run({ confidence: value }))).toEqual({ level: value, word });
  });

  it("shows a level it has no words for as it came, with no meter, and a missing one as a dash", () => {
    expect(confidenceOf(run({ confidence: "rất cao" }))).toEqual({ level: null, word: "rất cao" });
    expect(confidenceOf(run({ confidence: null }))).toEqual({ level: null, word: "—" });
    expect(confidenceOf(run({ confidence: undefined }))).toEqual({ level: null, word: "—" });
    expect(confidenceOf(run({ confidence: "constructor" }))).toEqual({
      level: null,
      word: "constructor",
    });
  });
});

describe("ragTile", () => {
  const tile = (k: unknown, rag?: unknown) =>
    ragTile(run({ knowledge: k, ...(rag === undefined ? {} : { rag }) }));

  it("is the best match, as a figure, for a lookup that kept one", () => {
    expect(tile(knowledge("matched", { best_pct: 84 }))).toEqual({
      value: "84%",
      note: "trùng tri thức đã duyệt",
    });
  });

  it("is the best candidate and the floor it was under for a lookup that kept none", () => {
    expect(tile(knowledge("below_floor", { best_pct: 47, floor_pct: 50 }))).toEqual({
      value: "47%",
      note: "dưới mức 50%",
    });
    expect(tile(knowledge("below_floor", { best_pct: 47, floor_pct: null })).note).toBe(
      "dưới mức tối thiểu",
    );
  });

  it("says that no candidate was scored, and that no lookup was made, with no number", () => {
    expect(tile(knowledge("no_candidate"))).toEqual({
      value: "—",
      note: "không có mục nào trùng",
    });
    expect(tile(knowledge("no_lookup"))).toEqual({
      value: "—",
      note: "không có tra cứu",
    });
  });

  it.each([
    ["rate_limit", "vượt giới hạn tốc độ"],
    ["timeout", "quá thời gian chờ"],
    ["auth", "thiếu hoặc sai API key"],
    ["quota", "hết hạn mức"],
    ["provider_error", "lỗi phía nhà cung cấp"],
    ["vectordb_unreachable", "không kết nối được vector DB"],
  ])("says a lookup that failed with %s in a short line", (kind, note) => {
    expect(tile(knowledge("failed", { failure: kind }))).toEqual({
      value: "—",
      note,
    });
  });

  it("says a failure of a kind it has no words for without the kind", () => {
    for (const kind of ["cosmic_ray", "constructor", "<b>x</b>", null]) {
      expect(tile(knowledge("failed", { failure: kind })).note).toBe("tra cứu bị lỗi");
    }
  });

  it("does not draw a percentage that is not a whole number from 0 to 100", () => {
    for (const bad of [null, -1, 101, 84.5, "84", Number.NaN]) {
      expect(tile(knowledge("matched", { best_pct: bad })).value).toBe("—");
    }
  });

  it("reads the rag pair when the server sends no knowledge", () => {
    const rag = (over: Record<string, unknown>) => ({
      best_pct: null,
      not_applied: null,
      below_floor_pct: null,
      floor_pct: null,
      ...over,
    });
    expect(tile(undefined, rag({ best_pct: 87 }))).toEqual({
      value: "87%",
      note: "trùng tri thức đã duyệt",
    });
    expect(tile(undefined, rag({ below_floor_pct: 47, floor_pct: 50 }))).toEqual({
      value: "47%",
      note: "dưới mức 50%",
    });
    expect(tile(undefined, rag({ not_applied: "quota" }))).toEqual({
      value: "—",
      note: "hết hạn mức",
    });
    expect(tile(undefined, rag({}))).toEqual({ value: "—", note: "chưa có dữ liệu" });
    expect(tile(undefined, null).note).toBe("chưa có dữ liệu");
  });

  it("shows a state it does not know as the code", () => {
    expect(tile(knowledge("quantum")).note).toBe("quantum");
    // a `knowledge` that is not an object is ignored, and the rag pair (here empty) is read instead
    const empty = { best_pct: null, not_applied: null, below_floor_pct: null, floor_pct: null };
    expect(tile("matched", empty).note).toBe("chưa có dữ liệu");
  });
});

describe("evidenceCounts and evidenceTile", () => {
  it("reads the server's summary", () => {
    expect(evidenceCounts(run())).toEqual({ cited: 3, verified: 2 });
    expect(evidenceTile(run())).toEqual({
      value: "2/3",
      note: "khớp nguyên văn",
      warn: true,
    });
  });

  it("is calm when every quote was found", () => {
    expect(evidenceTile(run({ evidence_summary: { cited: 5, verified: 5 } }))).toEqual({
      value: "5/5",
      note: "khớp nguyên văn",
      warn: false,
    });
  });

  it("counts the rows itself when the server sends no summary", () => {
    const rows = [evidenceRow(), unverifiedRow(), unverifiedRow({ alert_id: "9" })];
    expect(evidenceCounts(run({ evidence_summary: undefined, evidence: rows }))).toEqual({
      cited: 3,
      verified: 1,
    });
    expect(evidenceCounts(run({ evidence_summary: { cited: "x" }, evidence: rows }))).toEqual({
      cited: 3,
      verified: 1,
    });
  });

  it("says there is none when the assistant cited nothing", () => {
    expect(
      evidenceTile(run({ evidence_summary: { cited: 0, verified: 0 }, evidence: [] })),
    ).toEqual({
      value: "—",
      note: "không có dẫn chứng",
      warn: false,
    });
    expect(evidenceCounts(run({ evidence_summary: undefined, evidence: undefined }))).toEqual({
      cited: 0,
      verified: 0,
    });
  });

  it("never counts more verified than cited", () => {
    expect(evidenceCounts(run({ evidence_summary: { cited: 2, verified: 9 } }))).toEqual({
      cited: 2,
      verified: 2,
    });
  });
});

describe("timelineOf and mitreSteps", () => {
  it("is the server's rows in the server's order", () => {
    expect(timelineOf(run()).map((row) => row.alert_id)).toEqual([
      "112437",
      "112438",
      "111525",
      "111976",
    ]);
  });

  it("is empty for an older run, for no key, for null and for a value that is not a list", () => {
    expect(timelineOf(asRun(runV3()))).toEqual([]);
    for (const bad of [undefined, null, "x", {}, 7]) {
      expect(timelineOf(run({ timeline: bad }))).toEqual([]);
    }
  });

  it("drops a row that names no alert or says nothing, and keeps a row with no time", () => {
    const rows = timelineOf(
      run({
        timeline: [
          null,
          "x",
          timelineRow({ alert_id: null }),
          timelineRow({ what: "" }),
          timelineRow({ what: 7 }),
          timelineRow({ time: null, tactic: null, technique: null }),
        ],
      }),
    );
    expect(rows).toEqual([
      {
        alert_id: "112437",
        time: null,
        what: "amsi.dll được nạp bởi splwow64.exe",
        tactic: null,
        technique: null,
        technique_name: null,
        technique_known: null,
      },
    ]);
  });

  it("reads what the server checked of a technique: MITRE's name as text and the verdict as a boolean only (DEC-223)", () => {
    const rows = timelineOf(
      run({
        timeline: [
          timelineRow({ technique_name: "Password Guessing", technique_known: true }),
          timelineRow({ technique: "T9999", technique_name: null, technique_known: false }),
          timelineRow({ technique_name: "", technique_known: null }),
          timelineRow({ technique_name: 7, technique_known: "true" }),
          { alert_id: "9", what: "older server", tactic: null, technique: "T1110" },
        ],
      }),
    );
    expect(rows.map((row) => [row.technique_name, row.technique_known])).toEqual([
      ["Password Guessing", true],
      [null, false],
      [null, null],
      [null, null],
      [null, null],
    ]);
  });

  it("counts the steps and ends at the last technique, else the last tactic", () => {
    expect(mitreSteps(timelineOf(run()))).toEqual({ count: 4, endsAt: "T1490" });
    expect(
      mitreSteps(
        timelineOf(
          run({
            timeline: [timelineRow(), timelineRow({ technique: null, tactic: "Gây tác động" })],
          }),
        ),
      ),
    ).toEqual({ count: 2, endsAt: "Gây tác động" });
    expect(mitreSteps([])).toEqual({ count: 0, endsAt: null });
  });

  it("counts only the rows that name a tactic or a technique", () => {
    const rows = timelineOf(
      run({
        timeline: [timelineRow(), timelineRow({ tactic: null, technique: null })],
      }),
    );
    expect(mitreSteps(rows)).toEqual({ count: 1, endsAt: "T1562.001" });
  });
});

describe("scopeOf", () => {
  it("sets what the model said beside what the system knows", () => {
    expect(scopeOf(run())).toEqual({
      hosts: { model: ["wazuh-win-01"], system: ["Windows_Endpoint"] },
      accounts: { model: ["Administrator"], system: ["Administrator"] },
    });
  });

  it("has only the system's side for an older run", () => {
    expect(scopeOf(asRun(runV3()))).toEqual({
      hosts: { model: [], system: ["Windows_Endpoint"] },
      accounts: { model: [], system: ["Administrator"] },
    });
  });

  it("is empty on both sides for a server that sends no scope, and keeps only text", () => {
    expect(scopeOf(asRun(runOld()))).toEqual({
      hosts: { model: [], system: [] },
      accounts: { model: [], system: [] },
    });
    expect(
      scopeOf(
        run({
          scope: {
            hosts: ["a", 7, null, ""],
            accounts: "x",
            system: { hosts: [1, "b"], accounts: null },
          },
        }),
      ),
    ).toEqual({
      hosts: { model: ["a"], system: ["b"] },
      accounts: { model: [], system: [] },
    });
  });
});

describe("nextStepsOf", () => {
  it("reads the rows with their priority", () => {
    expect(nextStepsOf(run()).map((row) => [row.priority, row.step])).toEqual([
      ["high", "Cô lập máy Windows_Endpoint khỏi mạng."],
      ["high", "Thu danh sách job BITS và nội dung lệnh PowerShell đã giải mã."],
      ["medium", "Tìm cùng chuỗi hành vi trên các máy khác trong 24 giờ."],
      ["low", "Đặt lại mật khẩu tài khoản Administrator của máy."],
    ]);
  });

  it("has no priority for an older run's rows, and reads the strings of a server that sends no rows", () => {
    expect(nextStepsOf(asRun(runV3())).every((row) => row.priority === null)).toBe(true);
    expect(nextStepsOf(asRun(runOld()))).toEqual([
      { step: "Cô lập máy Windows_Endpoint khỏi mạng.", priority: null },
      { step: "Thu danh sách job BITS và nội dung lệnh PowerShell đã giải mã.", priority: null },
      { step: "Tìm cùng chuỗi hành vi trên các máy khác trong 24 giờ.", priority: null },
      { step: "Đặt lại mật khẩu tài khoản Administrator của máy.", priority: null },
    ]);
  });

  it("drops a row with no text, and a priority that is not one of the three is none", () => {
    expect(
      nextStepsOf(
        run({
          next_steps_rows: [
            { step: "một", priority: "urgent" },
            { step: 7, priority: "high" },
            null,
            { step: "hai", priority: "constructor" },
            { step: "ba", priority: "high" },
          ],
        }),
      ),
    ).toEqual([
      { step: "một", priority: null },
      { step: "hai", priority: null },
      { step: "ba", priority: "high" },
    ]);
  });

  it("is empty for no rows and no steps", () => {
    expect(nextStepsOf(run({ next_steps_rows: undefined, next_steps: undefined }))).toEqual([]);
    expect(nextStepsOf(run({ next_steps_rows: null, next_steps: null }))).toEqual([]);
  });
});

describe("hypothesesOf", () => {
  it("reads the text, the likelihood and the two lists", () => {
    const [first, second] = hypothesesOf(run());
    expect(first).toEqual({
      text: "Chuẩn bị triển khai ransomware",
      likelihood: "high",
      support: ["bốn bước nối tiếp trong 24 phút, cùng tài khoản"],
      counter: ["chưa có alert mã hoá tệp"],
    });
    expect(second?.likelihood).toBe("low");
  });

  it("has no likelihood for an older run, a likelihood outside the three, or a server that sends none", () => {
    expect(hypothesesOf(asRun(runV3())).map((row) => row.likelihood)).toEqual([null, null]);
    expect(
      hypothesesOf(run({ hypotheses: [{ text: "a", likelihood: "certain" }] }))[0]?.likelihood,
    ).toBeNull();
    expect(hypothesesOf(asRun(runOld())).map((row) => row.likelihood)).toEqual([null, null]);
  });

  it("copes with a hypothesis that carries no lists, and drops a row that is not an object", () => {
    expect(
      hypothesesOf(run({ hypotheses: [null, "x", { text: null, evidence_for: null }] })),
    ).toEqual([{ text: null, likelihood: null, support: [], counter: [] }]);
    expect(hypothesesOf(run({ hypotheses: undefined }))).toEqual([]);
  });
});

describe("knowledgeOf", () => {
  it("is the server's lookup, with its candidates", () => {
    const k = knowledgeOf(run());
    expect(k?.state).toBe("matched");
    expect(k?.scored).toBe(23);
    expect(k?.candidates).toHaveLength(3);
  });

  it("is made from the rag pair when the server sends no knowledge, and null when that says nothing", () => {
    expect(
      knowledgeOf(
        run({
          knowledge: undefined,
          rag: { best_pct: 87, not_applied: null, below_floor_pct: null, floor_pct: null },
        }),
      ),
    ).toMatchObject({ state: "matched", best_pct: 87, candidates: [] });
    expect(
      knowledgeOf(
        run({
          knowledge: undefined,
          rag: { best_pct: null, not_applied: null, below_floor_pct: 47, floor_pct: 50 },
        }),
      ),
    ).toMatchObject({ state: "below_floor", best_pct: 47, floor_pct: 50 });
    expect(
      knowledgeOf(
        run({
          knowledge: undefined,
          rag: { best_pct: null, not_applied: "timeout", below_floor_pct: null, floor_pct: null },
        }),
      ),
    ).toMatchObject({ state: "failed", failure: "timeout" });
    expect(
      knowledgeOf(
        run({
          knowledge: undefined,
          rag: { best_pct: null, not_applied: null, below_floor_pct: null, floor_pct: null },
        }),
      ),
    ).toBeNull();
  });

  it("drops a candidate that is not a row with a percentage, and keeps at most three", () => {
    const k = knowledgeOf(
      run({
        knowledge: knowledge("below_floor", {
          candidates: [
            null,
            { pct: "x", title: "a", conclusion: null },
            { pct: 47, title: "b", conclusion: "closed_fp" },
            { pct: 40, title: 7, conclusion: 9 },
            { pct: 30, title: "d", conclusion: null },
            { pct: 20, title: "e", conclusion: null },
          ],
        }),
      }),
    );
    expect(k?.candidates).toEqual([
      { pct: 47, title: "b", conclusion: "closed_fp" },
      { pct: 40, title: null, conclusion: null },
      { pct: 30, title: "d", conclusion: null },
    ]);
  });
});

describe("techOf", () => {
  const current = { alert_count: 4, total_occurrences: 9, last_seen_at: null };

  it("reads the figures of the run", () => {
    expect(techOf(run(), current)).toEqual({
      inputTokens: 21480,
      outputTokens: 1612,
      latencyMs: 9800,
      costUsd: 0.0013,
      analysedAt: "2026-11-15T12:02:11+00:00",
      playbook: "ransomware_v1",
      alertsRead: 4,
      alertsTotal: 4,
    });
  });

  it("has no figure for an older run's tokens, and keeps what the run itself says", () => {
    expect(techOf(asRun(runV3()), null)).toEqual({
      inputTokens: null,
      outputTokens: null,
      latencyMs: null,
      costUsd: null,
      analysedAt: "2026-11-15T12:02:11+00:00",
      playbook: "ransomware_v1",
      alertsRead: null,
      alertsTotal: 4,
    });
  });

  it("falls back on the run's own keys when the server sends no tech", () => {
    expect(techOf(asRun(runOld()), current)).toEqual({
      inputTokens: null,
      outputTokens: null,
      latencyMs: null,
      costUsd: null,
      analysedAt: "2026-11-15T12:02:11+00:00",
      playbook: "ransomware_v1",
      alertsRead: 4,
      alertsTotal: 4,
    });
  });

  it("reads a figure that is not a finite number as none", () => {
    const t = techOf(
      run({
        tech: { input_tokens: "x", output_tokens: null, latency_ms: Number.NaN, cost_usd: {} },
      }),
      null,
    );
    expect([t.inputTokens, t.outputTokens, t.latencyMs, t.costUsd]).toEqual([
      null,
      null,
      null,
      null,
    ]);
  });
});

// D: a list the server can send by the hundred is cut to its first few, and what is left of it is counted.
describe("capList", () => {
  const hosts = (n: number) => Array.from({ length: n }, (_, i) => `h${i + 1}`);

  it("keeps the first five and counts the rest", () => {
    expect(capList(hosts(100))).toEqual({ shown: ["h1", "h2", "h3", "h4", "h5"], rest: 95 });
    expect(capList(hosts(6))).toEqual({ shown: ["h1", "h2", "h3", "h4", "h5"], rest: 1 });
  });

  it("keeps a list of five or fewer whole, with nothing left over", () => {
    expect(capList(hosts(5))).toEqual({ shown: hosts(5), rest: 0 });
    expect(capList(hosts(1))).toEqual({ shown: ["h1"], rest: 0 });
    expect(capList([])).toEqual({ shown: [], rest: 0 });
  });

  it("cuts at the number it is given", () => {
    expect(capList(hosts(4), 2)).toEqual({ shown: ["h1", "h2"], rest: 2 });
  });
});

// E: the numbers of the case at the run and now are read as numbers, or not at all: a notice never says "undefined".
describe("snapshotOf", () => {
  it("reads a snapshot with its two counts, and its last-seen time or null", () => {
    const seen = "2026-09-26T04:12:00+00:00";
    expect(snapshotOf({ alert_count: 3, total_occurrences: 61, last_seen_at: seen })).toEqual({
      alert_count: 3,
      total_occurrences: 61,
      last_seen_at: seen,
    });
    expect(snapshotOf({ alert_count: 0, total_occurrences: 0, last_seen_at: null })).toEqual({
      alert_count: 0,
      total_occurrences: 0,
      last_seen_at: null,
    });
    expect(snapshotOf({ alert_count: 3, total_occurrences: 61 })).toEqual({
      alert_count: 3,
      total_occurrences: 61,
      last_seen_at: null,
    });
    expect(snapshotOf({ alert_count: 3, total_occurrences: 61, last_seen_at: 7 })).toEqual({
      alert_count: 3,
      total_occurrences: 61,
      last_seen_at: null,
    });
  });

  it.each([
    ["nothing", undefined],
    ["null", null],
    ["a string", "snapshot"],
    ["a number", 7],
    ["a list", [3, 61]],
    ["an empty object", {}],
    ["half a snapshot", { alert_count: 3 }],
    ["the other half", { total_occurrences: 61 }],
    ["counts that are text", { alert_count: "3", total_occurrences: "61" }],
    ["a count that is not a whole number", { alert_count: 3.5, total_occurrences: 61 }],
    ["a negative count", { alert_count: -1, total_occurrences: 61 }],
    ["a count that is not a number", { alert_count: Number.NaN, total_occurrences: 61 }],
  ])("is nothing for %s", (_what, value) => {
    expect(snapshotOf(value)).toBeNull();
  });
});
