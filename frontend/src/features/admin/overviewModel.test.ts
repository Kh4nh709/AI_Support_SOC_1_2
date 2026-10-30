// src/features/admin/overviewModel.test.ts — the arithmetic of the overview page (P11-T11): the days the API
// leaves out are filled with zeros, the funnel is read by status, the failing health checks come first, a
// section that failed is told from one that is merely empty, and the numbers are written the Vietnamese way.
import type { AdminError, FailedJob, HealthCheck, OverviewResponse } from "../../api/admin";
import { S } from "../../strings";
import {
  FUNNEL_STEPS,
  dayLabel,
  failedFirst,
  formatCap,
  formatCount,
  formatPct,
  formatSpend,
  funnelCounts,
  lastAttemptAt,
  llmCardState,
  localDay,
  sectionFailure,
  shiftDay,
  writeErrorText,
  zeroFillDays,
  type DayPoint,
} from "./overviewModel";

const at = (iso: string): number => Date.parse(iso);

describe("localDay", () => {
  it("is the calendar day in Asia/Ho_Chi_Minh, not the UTC day", () => {
    expect(localDay(at("2026-09-30T02:40:00Z"))).toBe("2026-09-30");
    expect(localDay(at("2026-09-30T16:59:59Z"))).toBe("2026-09-30");
    expect(localDay(at("2026-09-30T17:00:00Z"))).toBe("2026-10-01");
    expect(localDay(at("2026-12-31T20:00:00Z"))).toBe("2027-01-01");
  });
});

describe("shiftDay", () => {
  it.each([
    ["2026-09-30", 1, "2026-10-01"],
    ["2026-03-01", -1, "2026-02-28"],
    ["2028-03-01", -1, "2028-02-29"],
    ["2026-12-31", 1, "2027-01-01"],
    ["2026-01-01", -1, "2025-12-31"],
    ["2026-09-30", 0, "2026-09-30"],
    ["2026-09-30", -30, "2026-08-31"],
  ])("moves %s by %i days to %s", (day, by, expected) => {
    expect(shiftDay(day, by)).toBe(expected);
  });
});

describe("dayLabel", () => {
  it("writes day/month, the way the canvas does", () => {
    expect(dayLabel("2026-09-30")).toBe("30/09");
    expect(dayLabel("2027-01-02")).toBe("02/01");
  });

  it("shows a day it cannot read as it came", () => {
    expect(dayLabel("not-a-day")).toBe("not-a-day");
    expect(dayLabel("")).toBe("—");
  });
});

const point = (day: string, total: number, heads: number): DayPoint => ({
  day,
  total,
  heads,
  duplicates: total - heads,
});
const zero = (day: string): DayPoint => ({ day, total: 0, heads: 0, duplicates: 0 });

describe("zeroFillDays", () => {
  // 30/09 09:40 in Ho Chi Minh.
  const NOW = at("2026-09-30T02:40:00Z");

  it("gives the two local days a 24 hour window touches, and fills the one with no alert", () => {
    expect(zeroFillDays([point("2026-09-30", 5, 3)], "24h", NOW)).toEqual([
      zero("2026-09-29"),
      point("2026-09-30", 5, 3),
    ]);
  });

  it("gives 8 local days for 7d and 31 for 30d, oldest first, each day once", () => {
    const week = zeroFillDays([], "7d", NOW);
    expect(week).toHaveLength(8);
    expect(week[0]?.day).toBe("2026-09-23");
    expect(week[7]?.day).toBe("2026-09-30");
    const month = zeroFillDays([], "30d", NOW);
    expect(month).toHaveLength(31);
    expect(month[0]?.day).toBe("2026-08-31");
    expect(month[30]?.day).toBe("2026-09-30");
    expect(new Set(month.map((d) => d.day)).size).toBe(31);
  });

  it("keeps the API's days where they are and zeroes the gaps between them", () => {
    const days = zeroFillDays([point("2026-09-24", 10, 4), point("2026-09-27", 7, 7)], "7d", NOW);
    expect(days.map((d) => [d.day, d.total, d.heads, d.duplicates])).toEqual([
      ["2026-09-23", 0, 0, 0],
      ["2026-09-24", 10, 4, 6],
      ["2026-09-25", 0, 0, 0],
      ["2026-09-26", 0, 0, 0],
      ["2026-09-27", 7, 7, 0],
      ["2026-09-28", 0, 0, 0],
      ["2026-09-29", 0, 0, 0],
      ["2026-09-30", 0, 0, 0],
    ]);
  });

  it("turns a range with no alert into a row of zeros, not into nothing", () => {
    const days = zeroFillDays([], "24h", NOW);
    expect(days).toEqual([zero("2026-09-29"), zero("2026-09-30")]);
  });

  it("follows the local day edge: at 00:30 local the window started on the day before", () => {
    // 2026-10-01 00:30 in Ho Chi Minh is 2026-09-30 17:30 UTC.
    const days = zeroFillDays([], "24h", at("2026-09-30T17:30:00Z"));
    expect(days.map((d) => d.day)).toEqual(["2026-09-30", "2026-10-01"]);
  });

  it("never drops a day the API sent, even one outside the window the clock gives", () => {
    const days = zeroFillDays([point("2026-10-02", 9, 2), point("2026-09-20", 1, 1)], "24h", NOW);
    expect(days[0]?.day).toBe("2026-09-20");
    expect(days[days.length - 1]?.day).toBe("2026-10-02");
    expect(days.find((d) => d.day === "2026-10-02")).toEqual(point("2026-10-02", 9, 2));
    expect(days.find((d) => d.day === "2026-09-20")).toEqual(point("2026-09-20", 1, 1));
    expect(days).toHaveLength(13);
  });

  it("sorts the API's days, whatever order they came in", () => {
    const days = zeroFillDays([point("2026-09-30", 2, 1), point("2026-09-29", 3, 3)], "24h", NOW);
    expect(days.map((d) => d.day)).toEqual(["2026-09-29", "2026-09-30"]);
  });

  it("does not build thousands of days when the clock and the data are years apart", () => {
    const days = zeroFillDays([point("2001-01-01", 1, 1)], "24h", NOW);
    expect(days).toEqual([point("2001-01-01", 1, 1)]);
  });

  it("does not change the list it was given", () => {
    const given = [point("2026-09-30", 5, 3)];
    const copy = structuredClone(given);
    zeroFillDays(given, "7d", NOW);
    expect(given).toEqual(copy);
  });
});

describe("funnelCounts", () => {
  type Funnel = NonNullable<OverviewResponse["funnel"]>;
  const triage = { ready: 0, unavailable: 0, pending: 0, none: 0 };

  it("has the five status rows of the canvas, in its order (the sixth row, ① coverage, is ready / heads)", () => {
    expect(FUNNEL_STEPS.map((s) => s.key)).toEqual([
      "auto_closed",
      "waiting",
      "active",
      "closed_by_tier1",
      "escalated",
    ]);
  });

  it("sums the three Tier-1 closings and zero-fills what the API left out", () => {
    const funnel: Funnel = {
      by_status: {
        auto_closed: 41,
        queued_tier1: 848,
        closed_fp: 4,
        closed_benign: 3,
        closed_confirmed: 2,
      },
      triage: { ready: 733, unavailable: 50, pending: 70, none: 2 },
    };
    const counts = funnelCounts(funnel);
    expect(counts.steps).toEqual([
      { key: "auto_closed", count: 41 },
      { key: "waiting", count: 848 },
      { key: "active", count: 0 },
      { key: "closed_by_tier1", count: 9 },
      { key: "escalated", count: 0 },
    ]);
    expect(counts.ready).toBe(733);
    expect(counts.heads).toBe(41 + 848 + 4 + 3 + 2);
  });

  it("counts a head in a status the funnel has no row for among the heads", () => {
    const counts = funnelCounts({
      by_status: { enriching: 5, received: 2, tier1_active: 1 },
      triage: { ...triage, none: 8 },
    });
    expect(counts.heads).toBe(8);
    expect(counts.steps.find((s) => s.key === "active")?.count).toBe(1);
  });

  it("is all zeros for an empty funnel", () => {
    const counts = funnelCounts({ by_status: {}, triage });
    expect(counts.steps.every((s) => s.count === 0)).toBe(true);
    expect(counts.ready).toBe(0);
    expect(counts.heads).toBe(0);
    expect(counts.archived).toBe(0);
  });

  it("keeps archived heads out of 'closed by Tier-1': a bucket of their own (DEC-212)", () => {
    // The archive closed the old queue without review; a person did not close those heads.
    const counts = funnelCounts({
      by_status: { archived: 7084, queued_tier1: 30, closed_fp: 4, closed_benign: 3 },
      triage: { ...triage, ready: 7000 },
    });
    expect(counts.archived).toBe(7084);
    expect(counts.steps.find((s) => s.key === "closed_by_tier1")?.count).toBe(7);
    expect(counts.steps.find((s) => s.key === "waiting")?.count).toBe(30);
    expect(FUNNEL_STEPS.flatMap((s) => s.statuses)).not.toContain("archived");
  });

  it("does not read a status off the prototype", () => {
    const counts = funnelCounts({ by_status: Object.create({ auto_closed: 99 }) as never, triage });
    expect(counts.steps[0]?.count).toBe(0);
  });
});

describe("failedFirst", () => {
  const check = (name: string, ok: boolean): HealthCheck => ({
    name,
    ok,
    value: null,
    threshold: null,
    detail: name,
  });

  it("puts the failing checks first and keeps the server's order inside each group", () => {
    const sorted = failedFirst([
      check("a", true),
      check("b", false),
      check("c", true),
      check("d", false),
      check("e", true),
    ]);
    expect(sorted.map((c) => c.name)).toEqual(["b", "d", "a", "c", "e"]);
  });

  it("does not change the list it was given", () => {
    const given = [check("a", true), check("b", false)];
    failedFirst(given);
    expect(given.map((c) => c.name)).toEqual(["a", "b"]);
  });
});

describe("lastAttemptAt", () => {
  const job = (locked_at: string | null): FailedJob => ({
    job_id: 1,
    job_type: "triage",
    subject_id: "x",
    attempts: 3,
    last_error: null,
    locked_at,
    created_at: "2026-09-30T01:00:00+00:00",
  });

  it("is the last attempt, and the creation time of a job that never ran", () => {
    expect(lastAttemptAt(job("2026-09-30T02:05:00+00:00"))).toBe("2026-09-30T02:05:00+00:00");
    expect(lastAttemptAt(job(null))).toBe("2026-09-30T01:00:00+00:00");
  });
});

describe("sectionFailure", () => {
  const base: OverviewResponse = {
    range: "24h",
    errors: [],
    alerts_by_day: [],
    by_source: { rows: [], rejected: 0 },
    top_agents: [],
    funnel: { by_status: {}, triage: { ready: 0, unavailable: 0, pending: 0, none: 0 } },
    waiting: { count: 0, oldest_received_at: null },
    cases_open: 0,
    health: null,
    failed_jobs: [],
    inventory: { assets: 0, identities: 0, iocs: 0, loaded_at: null },
    llm_month: { spent_usd: 0, cap_usd: 30, pct: 0 },
    knowledge: { pending: 0, conflicts: 0 },
  };

  it("is null for a section that answered, even an empty one or a zero", () => {
    expect(sectionFailure(base, "alerts_by_day")).toBeNull();
    expect(sectionFailure(base, "cases_open")).toBeNull();
    expect(sectionFailure(base, "failed_jobs")).toBeNull();
  });

  it("is the code the server gave for a section that is null with an error", () => {
    const data: OverviewResponse = {
      ...base,
      top_agents: null,
      by_source: null,
      errors: [
        { section: "top_agents", error: "timeout" },
        { section: "by_source", error: "query_failed" },
      ],
    };
    expect(sectionFailure(data, "top_agents")).toBe("timeout");
    expect(sectionFailure(data, "by_source")).toBe("query_failed");
  });

  it("is unknown for a section that is null with no error listed", () => {
    expect(sectionFailure({ ...base, waiting: null }, "waiting")).toBe("unknown");
  });

  it("is unknown for a code it has no text for", () => {
    const data = {
      ...base,
      waiting: null,
      errors: [{ section: "waiting", error: "disk_on_fire" }],
    } as unknown as OverviewResponse;
    expect(sectionFailure(data, "waiting")).toBe("unknown");
  });

  it("trusts the data over the list: a section with data is not failed because it is listed", () => {
    const data: OverviewResponse = { ...base, errors: [{ section: "waiting", error: "timeout" }] };
    expect(sectionFailure(data, "waiting")).toBeNull();
  });

  it("does not call a health row that does not exist yet a failure", () => {
    expect(sectionFailure({ ...base, health: null }, "health")).toBeNull();
    const failed: OverviewResponse = {
      ...base,
      health: null,
      errors: [{ section: "health", error: "timeout" }],
    };
    expect(sectionFailure(failed, "health")).toBe("timeout");
  });

  it("reads the first entry when a section is listed twice", () => {
    const data: OverviewResponse = {
      ...base,
      waiting: null,
      errors: [
        { section: "waiting", error: "timeout" },
        { section: "waiting", error: "query_failed" },
      ],
    };
    expect(sectionFailure(data, "waiting")).toBe("timeout");
  });
});

// The cost card's state (P11-T20 row 50, DEC-203): `stopped` is the adapter's own comparison, spent >= cap, and
// never `pct`, which the route rounds (so it can read 99,9 at the cap, or 100 a cent under it).
describe("llmCardState", () => {
  const month = (spent_usd: number, cap_usd: number | null, pct: number | null) => ({
    spent_usd,
    cap_usd,
    pct,
  });

  it.each([
    ["well under the cap", month(0.51, 30, 1.7), "ok"],
    ["nothing spent", month(0, 30, 0), "ok"],
    ["past 80 % of the cap, which this card does not colour", month(27, 30, 90), "ok"],
    ["a cent under the cap, though pct reads 100", month(29.99, 30, 100), "ok"],
    ["exactly at the cap, though pct reads 99,9", month(30, 30, 99.9), "stopped"],
    ["exactly at the cap, with pct null", month(30, 30, null), "stopped"],
    ["over the cap", month(31.2, 30, 104), "stopped"],
    ["a cap of 0 with nothing spent", month(0, 0, null), "stopped"],
    ["the limits unreadable (no cap, no pct)", month(0.51, null, null), "unknown"],
    ["no cap, a large spend", month(500, null, null), "unknown"],
    ["a cap and no pct, under the cap (not sent by the route)", month(1, 30, null), "unknown"],
  ] as const)("is %s", (_name, data, state) => {
    expect(llmCardState(data)).toBe(state);
  });
});

describe("the numbers", () => {
  it("writes a count with the Vietnamese thousands dot", () => {
    expect(formatCount(7040)).toBe("7.040");
    expect(formatCount(12321)).toBe("12.321");
    expect(formatCount(0)).toBe("0");
    expect(formatCount(999)).toBe("999");
  });

  it("writes the spend with two decimals and a comma, and the cap as a whole number when it is one", () => {
    expect(formatSpend(0.5123)).toBe("$0,51");
    expect(formatSpend(0)).toBe("$0,00");
    expect(formatSpend(1234.5)).toBe("$1.234,50");
    expect(formatCap(30)).toBe("$30");
    expect(formatCap(30.5)).toBe("$30,5");
  });

  it("writes the share of the cap with one decimal", () => {
    expect(formatPct(1.7)).toBe("1,7%");
    expect(formatPct(100)).toBe("100,0%");
    expect(formatPct(0)).toBe("0,0%");
  });
});

describe("writeErrorText", () => {
  it("is the Vietnamese of a reason the client knows", () => {
    const error: AdminError = { kind: "reason", status: 409, reason: "already_queued", extra: {} };
    expect(writeErrorText(error)).toBe(S.admin.reason.already_queued);
  });

  it("puts the server's bounds in the text of a field error", () => {
    const error: AdminError = {
      kind: "field",
      status: 422,
      field: "x",
      reason: "out_of_range",
      min: 1,
      max: 9,
    };
    expect(writeErrorText(error)).toBe("Phải từ 1 đến 9");
  });

  it.each<AdminError>([
    { kind: "other", status: 500 },
    { kind: "other", status: 0 },
    { kind: "message", status: 422, message: "an English sentence" },
    { kind: "messages", status: 422, messages: ["an English sentence"] },
  ])("is the general error for anything else: %j", (error) => {
    expect(writeErrorText(error)).toBe(S.common.unknownError);
  });
});
