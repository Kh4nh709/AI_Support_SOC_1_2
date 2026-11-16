// src/features/soar/storage.test.ts — the two preferences of the SOAR page, kept in THIS TAB's session store, as the alert page keeps
// its draft (features/tier1/draft.ts): whether the new-ticket signal was turned on or off in this tab, and which notices were
// dismissed in it. The store may be missing, full, blocked or filled by hand: nothing here may throw, and nothing it holds is
// believed until it has the shape that was written. Nothing is ever written to the store that outlives the tab.
import { afterEach, beforeEach, vi } from "vitest";
import {
  DISMISSED_CAP,
  DISMISSED_KEY,
  NOTICE_ID,
  SIGNAL_KEY,
  readDismissed,
  readSignalChoice,
  writeDismissed,
  writeSignalOn,
} from "./storage";

/** An id of a notice: N and twelve characters (spec section 2). */
const nid = (n: number) => `N${String(n).padStart(12, "0")}`;
const N1 = nid(1);
const N2 = nid(2);

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
});
afterEach(() => {
  // whatever a test did, nothing of it is in the store that outlives the tab
  expect(localStorage.length).toBe(0);
  vi.restoreAllMocks();
});

describe("the keys", () => {
  it("are two, fixed, and in the session store of the tab", () => {
    expect(SIGNAL_KEY).toBe("soc.soar.signal");
    expect(DISMISSED_KEY).toBe("soc.soar.dismissed");
    writeSignalOn(true);
    writeDismissed([N1]);
    expect(sessionStorage.length).toBe(2);
    expect(sessionStorage.getItem(SIGNAL_KEY)).toBe("1");
    expect(sessionStorage.getItem(DISMISSED_KEY)).toBe(JSON.stringify([N1]));
  });
});

describe("the choice of the signal", () => {
  it("is none until somebody has chosen in this tab (the default is the browser's to give, see signal.ts)", () => {
    expect(readSignalChoice()).toBeNull();
  });

  it("keeps a choice, on and off, as 1 and 0 and nothing else", () => {
    writeSignalOn(true);
    expect(readSignalChoice()).toBe(true);
    expect(sessionStorage.getItem(SIGNAL_KEY)).toBe("1");
    writeSignalOn(false);
    expect(readSignalChoice()).toBe(false);
    expect(sessionStorage.getItem(SIGNAL_KEY)).toBe("0");
  });

  it("ignores a value that is neither 1 nor 0, as no choice", () => {
    for (const odd of ["true", "yes", "2", "", "{}", "01", " 1", "1 ", "on", "null"]) {
      sessionStorage.setItem(SIGNAL_KEY, odd);
      expect(readSignalChoice(), JSON.stringify(odd)).toBeNull();
    }
  });

  it("works without the store: reads no choice, writes nothing, throws nothing", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    expect(readSignalChoice()).toBeNull();
    expect(() => writeSignalOn(true)).not.toThrow();
  });
});

describe("the dismissed notices", () => {
  it("are none at first", () => {
    expect(readDismissed()).toEqual([]);
  });

  it("keeps the ids, in order", () => {
    writeDismissed([N1, N2]);
    expect(readDismissed()).toEqual([N1, N2]);
    expect(JSON.parse(sessionStorage.getItem(DISMISSED_KEY) ?? "null")).toEqual([N1, N2]);
  });

  it("cannot grow without bound: only the newest DISMISSED_CAP (200) ids are written, and read", () => {
    expect(DISMISSED_CAP).toBe(200);
    const ids = Array.from({ length: DISMISSED_CAP + 50 }, (_, i) => nid(i));
    writeDismissed(ids);
    const stored = JSON.parse(sessionStorage.getItem(DISMISSED_KEY) ?? "[]") as string[];
    expect(stored).toHaveLength(DISMISSED_CAP);
    expect(stored[0]).toBe(nid(50));
    expect(stored.at(-1)).toBe(nid(DISMISSED_CAP + 49));
    // a store somebody filled by hand is cut on the way in as well
    sessionStorage.setItem(DISMISSED_KEY, JSON.stringify(ids));
    expect(readDismissed()).toHaveLength(DISMISSED_CAP);
  });

  it("keeps only the shape of a notice id (N and twelve letters, digits, _ or -): a token, a path or an object is not one", () => {
    expect(NOTICE_ID.test(N1)).toBe(true);
    expect(NOTICE_ID.test("N_-abcXYZ1234")).toBe(true);
    const odd = [
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbiJ9.c2lnbmF0dXJl", // a JWT
      "K7QM2XHP", // the id of a review, not a notice
      "N1",
      "N0000000000012", // thirteen after the N
      "N00000000001 ",
      "n00000000001",
      "N0000000000/",
      "N<script>alert",
    ];
    writeDismissed([N1, ...odd, N2]);
    expect(JSON.parse(sessionStorage.getItem(DISMISSED_KEY) ?? "[]")).toEqual([N1, N2]);
    sessionStorage.setItem(DISMISSED_KEY, JSON.stringify([N1, ...odd, N2]));
    expect(readDismissed()).toEqual([N1, N2]);
  });

  it("drops what is not a text, and reads an unreadable or poisoned store as none", () => {
    sessionStorage.setItem(DISMISSED_KEY, JSON.stringify([N1, 7, null, { a: 1 }, [N2], N2]));
    expect(readDismissed()).toEqual([N1, N2]);
    for (const odd of [
      "not json",
      "{}",
      "null",
      JSON.stringify(N1),
      "7",
      '{"__proto__":{}}',
      "[[[",
    ]) {
      sessionStorage.setItem(DISMISSED_KEY, odd);
      expect(readDismissed(), odd).toEqual([]);
    }
  });

  it("repeats no id", () => {
    writeDismissed([N1, N2, N1]);
    expect(readDismissed()).toEqual([N2, N1]);
  });

  it("works without the store: reads none, writes nothing, throws nothing", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    expect(readDismissed()).toEqual([]);
    expect(() => writeDismissed([N1])).not.toThrow();
  });
});

describe("the store that outlives the tab", () => {
  it("is not read or written by anything here: even with it blocked, nothing changes", () => {
    const local = vi.spyOn(Storage.prototype, "setItem");
    writeSignalOn(true);
    writeDismissed([N1]);
    // sessionStorage and localStorage share Storage.prototype in jsdom: every write went to the session store of the tab
    expect(local).toHaveBeenCalledTimes(2);
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(2);
  });
});
