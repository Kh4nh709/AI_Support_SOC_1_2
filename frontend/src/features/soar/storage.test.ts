// src/features/soar/storage.test.ts — the two small preferences of the SOAR page that outlive the tab: whether the new-ticket
// signal is on, and which notices were dismissed. The store may be missing, full or blocked: nothing here may throw.
import { afterEach, beforeEach, vi } from "vitest";
import {
  DISMISSED_CAP,
  DISMISSED_KEY,
  SIGNAL_KEY,
  readDismissed,
  readSignalOn,
  writeDismissed,
  writeSignalOn,
} from "./storage";

beforeEach(() => localStorage.clear());
afterEach(() => vi.restoreAllMocks());

describe("the signal switch", () => {
  it("is off until somebody turns it on", () => {
    expect(readSignalOn()).toBe(false);
  });

  it("keeps the choice, on and off", () => {
    writeSignalOn(true);
    expect(readSignalOn()).toBe(true);
    expect(localStorage.getItem(SIGNAL_KEY)).toBe("1");
    writeSignalOn(false);
    expect(readSignalOn()).toBe(false);
  });

  it("reads anything but its own 'on' value as off", () => {
    for (const odd of ["true", "yes", "2", "", "{}"]) {
      localStorage.setItem(SIGNAL_KEY, odd);
      expect(readSignalOn()).toBe(false);
    }
  });

  it("works without storage: reads off, writes nothing, throws nothing", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    expect(readSignalOn()).toBe(false);
    expect(() => writeSignalOn(true)).not.toThrow();
  });
});

describe("the dismissed notices", () => {
  it("are none at first", () => {
    expect(readDismissed()).toEqual([]);
  });

  it("keeps the ids, in order", () => {
    writeDismissed(["N1", "N2"]);
    expect(readDismissed()).toEqual(["N1", "N2"]);
    expect(JSON.parse(localStorage.getItem(DISMISSED_KEY) ?? "null")).toEqual(["N1", "N2"]);
  });

  it("cannot grow without bound: only the newest DISMISSED_CAP ids are written, and read", () => {
    const ids = Array.from({ length: DISMISSED_CAP + 50 }, (_, i) => `N${i}`);
    writeDismissed(ids);
    const stored = JSON.parse(localStorage.getItem(DISMISSED_KEY) ?? "[]") as string[];
    expect(stored).toHaveLength(DISMISSED_CAP);
    expect(stored[0]).toBe("N50");
    expect(stored.at(-1)).toBe(`N${DISMISSED_CAP + 49}`);
    // a store somebody filled by hand is cut on the way in as well
    localStorage.setItem(DISMISSED_KEY, JSON.stringify(ids));
    expect(readDismissed()).toHaveLength(DISMISSED_CAP);
  });

  it("drops what is not a short text, and reads an unreadable store as none", () => {
    localStorage.setItem(
      DISMISSED_KEY,
      JSON.stringify(["N1", 7, null, { a: 1 }, "x".repeat(200), "N2"]),
    );
    expect(readDismissed()).toEqual(["N1", "N2"]);
    for (const odd of ["not json", "{}", "null", '"N1"', "7"]) {
      localStorage.setItem(DISMISSED_KEY, odd);
      expect(readDismissed()).toEqual([]);
    }
  });

  it("repeats no id", () => {
    writeDismissed(["N1", "N2", "N1"]);
    expect(readDismissed()).toEqual(["N2", "N1"]);
  });

  it("works without storage: reads none, writes nothing, throws nothing", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    expect(readDismissed()).toEqual([]);
    expect(() => writeDismissed(["N1"])).not.toThrow();
  });
});
