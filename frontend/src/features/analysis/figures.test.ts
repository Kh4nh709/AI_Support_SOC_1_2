// src/features/analysis/figures.test.ts — the three technical figures of an AI run, said as the mock-up of the
// analysis panel says them (Vietnamese grouping and decimal comma), and "—" for a figure the run does not carry.
import { formatCost, formatCount, formatSeconds } from "./figures";

describe("formatCount", () => {
  it("groups the thousands with a dot", () => {
    expect(formatCount(21480)).toBe("21.480");
    expect(formatCount(1612)).toBe("1.612");
    expect(formatCount(1234567)).toBe("1.234.567");
  });

  it("writes a small number as it is, and zero as 0", () => {
    expect(formatCount(981)).toBe("981");
    expect(formatCount(0)).toBe("0");
  });
});

describe("formatSeconds", () => {
  it("says milliseconds as seconds with one decimal and a comma", () => {
    expect(formatSeconds(9800)).toBe("9,8 giây");
    expect(formatSeconds(4200)).toBe("4,2 giây");
    expect(formatSeconds(400)).toBe("0,4 giây");
  });

  it("drops a decimal that is zero, and rounds rather than cuts", () => {
    expect(formatSeconds(61000)).toBe("61 giây");
    expect(formatSeconds(9849)).toBe("9,8 giây");
    expect(formatSeconds(9850)).toBe("9,9 giây");
  });
});

describe("formatCost", () => {
  it("says dollars with four decimals and a comma", () => {
    expect(formatCost(0.0013)).toBe("$0,0013");
    expect(formatCost(0.0007)).toBe("$0,0007");
    expect(formatCost(0)).toBe("$0,0000");
    expect(formatCost(12.5)).toBe("$12,5000");
  });
});

describe("a figure the run does not carry", () => {
  it.each([null, undefined, Number.NaN, Number.POSITIVE_INFINITY])(
    "is a dash for %s",
    (missing) => {
      expect(formatCount(missing)).toBe("—");
      expect(formatSeconds(missing)).toBe("—");
      expect(formatCost(missing)).toBe("—");
    },
  );
});
