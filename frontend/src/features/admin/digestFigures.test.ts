// src/features/admin/digestFigures.test.ts — the pure helpers of the digest page: a day in a sentence, the
// span of a cluster, the tail of an alert id, the summary line's counts, the bad-day check and the row swap.
// The page test (DigestPage.test.tsx) shows them on screen.
import type { DigestResponse, DigestRow } from "../../api/admin";
import { ApiError } from "../../api/client";
import {
  alertTail,
  formatDay,
  isBadDay,
  spanText,
  summarise,
  markReopened,
  withRow,
} from "./digestFigures";

const row = (over: Partial<DigestRow> = {}): DigestRow => ({
  alert_id: "1759012345.1661001",
  rule_id: "5715",
  description: "sshd: authentication success",
  severity: "low",
  category: "suspicious_login",
  agent_name: "srv-db-02",
  occurrence_count: 4,
  first_seen_at: "2026-09-29T01:02:00+00:00",
  last_seen_at: "2026-09-29T10:40:00+00:00",
  autoclose_rule_id: "r-1",
  autoclose_rule_name: "Đăng nhập SSH thành công từ máy quản trị",
  suggested_action: "false_positive",
  disagreement: false,
  reviewed_verdict: null,
  reviewed_by_name: null,
  reviewed_at: null,
  reopened_by_review: false,
  ...over,
});

describe("formatDay", () => {
  it("writes a server day as day/month/year", () => {
    expect(formatDay("2026-09-29")).toBe("29/09/2026");
    expect(formatDay("2031-01-02")).toBe("02/01/2031");
  });

  it("shows anything that is not a day as it came, never blank", () => {
    expect(formatDay("")).toBe("");
    expect(formatDay("hôm qua")).toBe("hôm qua");
    expect(formatDay("2026-9-29")).toBe("2026-9-29");
  });
});

describe("spanText", () => {
  it("shows the clock of both ends when they fall on one day of the display zone", () => {
    expect(spanText("2026-09-29T01:02:00+00:00", "2026-09-29T10:40:00+00:00")).toBe(
      "08:02 – 17:40",
    );
  });

  it("reads the day in the display zone, not in UTC", () => {
    // 19:00Z and 19:30Z on the 28th are 02:00 and 02:30 on the 29th at +07.
    expect(spanText("2026-09-28T19:00:00+00:00", "2026-09-28T19:30:00+00:00")).toBe(
      "02:00 – 02:30",
    );
  });

  it("shows the day too when the cluster crosses midnight", () => {
    // 16:50Z is 23:50 on the 29th, 17:10Z is 00:10 on the 30th.
    expect(spanText("2026-09-29T16:50:00+00:00", "2026-09-29T17:10:00+00:00")).toBe(
      "29/09 23:50 – 30/09 00:10",
    );
  });

  it("shows an unreadable end as it came and a missing one as a dash", () => {
    expect(spanText("2026-09-29T01:02:00+00:00", "")).toBe("29/09 08:02 – —");
    expect(spanText("không rõ", "2026-09-29T01:02:00+00:00")).toBe("không rõ – 29/09 08:02");
  });
});

describe("alertTail", () => {
  it("keeps the part after the last point, behind an ellipsis", () => {
    expect(alertTail("1759012399.1661877")).toBe("…1661877");
  });

  it("shows an id with no point, or one that ends in it, whole", () => {
    expect(alertTail("abc")).toBe("abc");
    expect(alertTail("1759012399.")).toBe("1759012399.");
    expect(alertTail("")).toBe("");
  });
});

describe("summarise", () => {
  it("counts the clusters, the reviewed, the waiting and the disagreements from the rows", () => {
    const rows = [
      row({ alert_id: "a" }),
      row({ alert_id: "b", disagreement: true }),
      row({ alert_id: "c", reviewed_verdict: "correct" }),
      row({
        alert_id: "d",
        reviewed_verdict: "wrong",
        disagreement: true,
        reopened_by_review: true,
      }),
    ];
    expect(summarise(rows)).toEqual({ clusters: 4, reviewed: 2, waiting: 2, disagreements: 2 });
  });

  it("is all zeros with no row", () => {
    expect(summarise([])).toEqual({ clusters: 0, reviewed: 0, waiting: 0, disagreements: 0 });
  });
});

describe("isBadDay", () => {
  it("is true for the 422 bad_day answer, and for nothing else", () => {
    expect(isBadDay(new ApiError(422, { reason: "bad_day" }))).toBe(true);
    expect(isBadDay(new ApiError(422, { field: "verdict", reason: "invalid" }))).toBe(false);
    expect(isBadDay(new ApiError(409, { reason: "bad_day" }))).toBe(false);
    expect(isBadDay(new ApiError(500, "boom"))).toBe(false);
    expect(isBadDay(new ApiError(422, [{ type: "x", loc: [], msg: "y", input: 1 }]))).toBe(false);
    expect(isBadDay(new TypeError("Failed to fetch"))).toBe(false);
    expect(isBadDay(null)).toBe(false);
  });
});

const response = (rows: DigestRow[]): DigestResponse => ({
  day: "2026-09-29",
  today: "2026-09-30",
  rules_enabled: true,
  rows,
});

describe("withRow", () => {
  it("swaps the row with the same alert id and touches nothing else", () => {
    const a = row({ alert_id: "a" });
    const b = row({ alert_id: "b" });
    const recorded = row({ alert_id: "b", reviewed_verdict: "correct" });
    const next = withRow(response([a, b]), recorded);
    expect(next.rows).toEqual([a, recorded]);
    expect(next.rows[0]).toBe(a);
    expect(next.day).toBe("2026-09-29");
    expect(next.today).toBe("2026-09-30");
    expect(next.rules_enabled).toBe(true);
  });

  it("leaves the answer as it is when the row is not on it (another day was read since)", () => {
    const only = response([row({ alert_id: "a" })]);
    expect(withRow(only, row({ alert_id: "zzz" })).rows).toEqual(only.rows);
  });
});

describe("markReopened", () => {
  it("marks a row the server said it reopened, even when the row did not say so itself", () => {
    const recorded = row({ reviewed_verdict: "wrong", reopened_by_review: false });
    expect(markReopened(recorded, true).reopened_by_review).toBe(true);
  });

  it("leaves a row the server did not reopen as the server wrote it", () => {
    const recorded = row({ reviewed_verdict: "correct", reopened_by_review: false });
    expect(markReopened(recorded, false)).toBe(recorded);
    const already = row({ reviewed_verdict: "wrong", reopened_by_review: true });
    expect(markReopened(already, false).reopened_by_review).toBe(true);
  });
});
