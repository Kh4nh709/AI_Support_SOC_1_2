// src/format.test.ts — `npm test` runs Vitest with TZ=UTC, so the +07 conversion is really exercised.
import { DISPLAY_TZ, formatDateTime, formatTime } from "./format";

it("runs under a host zone that is not +07 (otherwise this file proves nothing)", () => {
  expect(new Date("2026-09-30T02:31:00Z").getTimezoneOffset()).toBe(0);
});

it("displays in Asia/Ho_Chi_Minh", () => {
  expect(DISPLAY_TZ).toBe("Asia/Ho_Chi_Minh");
});

it("formats in +07 whatever the host zone", () => {
  expect(formatTime("2026-09-30T02:31:00Z")).toBe("30/09 09:31");
  expect(formatDateTime("2026-09-30T02:31:02Z")).toBe("30/09/2026 09:31:02");
  expect(formatTime(null)).toBe("—");
});

it("shows a dash for a missing or empty time", () => {
  for (const missing of [null, undefined, ""]) {
    expect(formatTime(missing)).toBe("—");
    expect(formatDateTime(missing)).toBe("—");
  }
});

it("rolls over the day and the year with the +07 offset", () => {
  // 17:05Z is 00:05 the next day in +07, never the "24:05" some ICU builds print for hour12: false.
  expect(formatTime("2026-09-30T17:05:00Z")).toBe("01/10 00:05");
  expect(formatDateTime("2026-12-31T17:00:09Z")).toBe("01/01/2027 00:00:09");
});

it("reads an offset in the input (the backend sends +00:00 and Z)", () => {
  expect(formatTime("2026-09-30T02:31:00+00:00")).toBe("30/09 09:31");
  expect(formatTime("2026-09-30T09:31:00+07:00")).toBe("30/09 09:31");
});

it("reads a timestamp with no zone as UTC, not in the host's zone", () => {
  expect(formatTime("2026-09-30T02:31:00")).toBe("30/09 09:31");
  expect(formatDateTime("2026-09-30 02:31:02.123456")).toBe("30/09/2026 09:31:02");
});

it("shows an unparseable value as it came, never throws", () => {
  expect(formatTime("not a time")).toBe("not a time");
  expect(formatDateTime("not a time")).toBe("not a time");
});
