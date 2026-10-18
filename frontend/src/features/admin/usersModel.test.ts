// src/features/admin/usersModel.test.ts — the small rules the users page (P11-T12) is built on, away from
// the DOM: which state an account is in, what the search matches, and how long a password is.
import type { UserRow } from "../../api/admin";
import { accountState, codePoints, matchesSearch, passwordProblem } from "./usersModel";

const NOW = Date.parse("2026-09-30T03:00:00Z");

const user = (over: Partial<UserRow> = {}): UserRow => ({
  user_id: "00000000-0000-4000-8000-0000000000a1",
  username: "lan.t1",
  display_name: "Trần Lan",
  role: "tier1",
  is_active: true,
  locked_until: null,
  failed_logins: 0,
  last_login_at: null,
  created_at: "2026-09-01T00:00:00Z",
  ...over,
});

describe("accountState", () => {
  it("is active for an active account with no lock", () => {
    expect(accountState(user(), NOW)).toBe("active");
  });

  it("is locked while locked_until is in the future", () => {
    expect(accountState(user({ locked_until: "2026-09-30T03:00:01Z" }), NOW)).toBe("locked");
  });

  it("is active again at locked_until and after it: the server keeps the stamp, the lock is over", () => {
    expect(accountState(user({ locked_until: "2026-09-30T03:00:00Z" }), NOW)).toBe("active");
    expect(accountState(user({ locked_until: "2026-09-30T02:59:59Z" }), NOW)).toBe("active");
  });

  it("is inactive for a deactivated account, locked or not: reactivating comes first", () => {
    expect(accountState(user({ is_active: false }), NOW)).toBe("inactive");
    expect(
      accountState(user({ is_active: false, locked_until: "2026-09-30T04:00:00Z" }), NOW),
    ).toBe("inactive");
  });

  it("does not call a lock it cannot read a lock: the server decides at login", () => {
    expect(accountState(user({ locked_until: "not a date" }), NOW)).toBe("active");
  });
});

describe("matchesSearch", () => {
  it("matches everything for an empty or blank search", () => {
    expect(matchesSearch(user(), "")).toBe(true);
    expect(matchesSearch(user(), "   ")).toBe(true);
  });

  it("matches a part of the username or of the display name, in any case", () => {
    expect(matchesSearch(user(), "AN.T")).toBe(true);
    expect(matchesSearch(user(), "trần")).toBe(true);
    expect(matchesSearch(user(), "TRẦN LAN")).toBe(true);
    expect(matchesSearch(user(), "quang")).toBe(false);
  });

  it("ignores the blanks around the search", () => {
    expect(matchesSearch(user(), "  lan  ")).toBe(true);
  });

  it("reads a display name that is null as nothing", () => {
    expect(matchesSearch(user({ display_name: null }), "lan")).toBe(true);
    expect(matchesSearch(user({ display_name: null }), "trần")).toBe(false);
  });

  it("takes the search as text, not as a pattern", () => {
    expect(matchesSearch(user({ username: "lan.t1" }), "l.n")).toBe(false);
    expect(matchesSearch(user({ username: "lan.t1" }), ".*")).toBe(false);
    expect(matchesSearch(user({ username: "lan.t1" }), "n.t")).toBe(true);
  });
});

describe("codePoints", () => {
  it("counts a character, not a UTF-16 unit: the server counts characters", () => {
    expect(codePoints("abc")).toBe(3);
    expect(codePoints("😀")).toBe(1);
    expect(codePoints("😀".repeat(12))).toBe(12);
    expect(codePoints("")).toBe(0);
  });
});

describe("passwordProblem", () => {
  it("accepts 12 to 256 characters", () => {
    expect(passwordProblem("a".repeat(12))).toBeNull();
    expect(passwordProblem("a".repeat(256))).toBeNull();
  });

  it("says empty for nothing at all", () => {
    expect(passwordProblem("")).toEqual({ reason: "empty" });
  });

  it("says too short under 12, with how many there are", () => {
    expect(passwordProblem("a".repeat(11))).toEqual({ reason: "too_short", have: 11, min: 12 });
    expect(passwordProblem("12345678")).toEqual({ reason: "too_short", have: 8, min: 12 });
  });

  it("says too long over 256", () => {
    expect(passwordProblem("a".repeat(257))).toEqual({ reason: "too_long", max: 256 });
  });

  it("counts characters, not UTF-16 units, at both ends", () => {
    expect(passwordProblem("😀".repeat(11))).toEqual({ reason: "too_short", have: 11, min: 12 });
    expect(passwordProblem("😀".repeat(12))).toBeNull();
    expect(passwordProblem("😀".repeat(256))).toBeNull();
    expect(passwordProblem("😀".repeat(257))).toEqual({ reason: "too_long", max: 256 });
  });

  it("does not trim: blanks are part of a password", () => {
    expect(passwordProblem(" ".repeat(12))).toBeNull();
  });
});
