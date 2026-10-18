// src/features/admin/adminStrings.test.ts — the admin section of strings.ts (P11-T10): a text for every
// reason code of the admin routes and for every audit event type, and the tables that the backend owns
// (the six hard blocks, the verdict labels, the audit groups, the limits of the forms) kept equal to it.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  ADMIN_LIMITS,
  ADMIN_REASONS,
  AUDIT_GROUPS,
  DIGEST_VERDICTS,
  HARD_BLOCK_CODES,
} from "../../api/admin";
import { S, adminReasonText, labelOf } from "../../strings";

const BACKEND_APP = join("..", "backend", "app");
const py = (...path: string[]): string => readFileSync(join(BACKEND_APP, ...path), "utf8");

const isText = (value: unknown): value is string =>
  typeof value === "string" && value.trim() !== "";

/** `EVENT_TYPES` of `audit/events.py`: the 28 names the database CHECK admits. */
function eventTypes(): string[] {
  const body = /EVENT_TYPES\s*=\s*frozenset\(\s*\{([\s\S]*?)\}\s*\)/.exec(
    py("audit", "events.py"),
  )?.[1];
  if (body === undefined) throw new Error("EVENT_TYPES not found in audit/events.py");
  return [...body.matchAll(/"([a-z0-9_]+\.[a-z0-9_]+)"/g)].map((m) => m[1] as string);
}

/** `GROUPS` of `admin_audit.py`: group key -> its event types. */
function auditGroups(): Record<string, string[]> {
  const body = /GROUPS: dict\[str, tuple\[str, \.\.\.\]\] = \{([\s\S]*?)\n\}\n/.exec(
    py("web", "routers", "admin_audit.py"),
  )?.[1];
  if (body === undefined) throw new Error("GROUPS not found in admin_audit.py");
  const groups: Record<string, string[]> = {};
  for (const m of body.matchAll(/"(\w+)":\s*\(([\s\S]*?)\),/g)) {
    groups[m[1] as string] = [...(m[2] as string).matchAll(/"([a-z0-9_.]+)"/g)].map(
      (n) => n[1] as string,
    );
  }
  return groups;
}

describe("the audit event types", () => {
  const names = eventTypes();

  it("reads the 28 names of the backend", () => {
    expect(names).toHaveLength(28);
    expect(new Set(names).size).toBe(28);
  });

  it.each(names)("has a Vietnamese label for %s", (name) => {
    expect(isText(labelOf(S.admin.eventType, name))).toBe(true);
    expect(labelOf(S.admin.eventType, name)).not.toBe(name);
  });

  it("has no label for a name the backend does not have", () => {
    expect(Object.keys(S.admin.eventType).sort()).toEqual([...names].sort());
  });

  it("gives two event types two different labels", () => {
    const labels = Object.values(S.admin.eventType);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("shows an event type it has no label for as the type itself", () => {
    expect(labelOf(S.admin.eventType, "alert.brand_new")).toBe("alert.brand_new");
  });
});

describe("the audit groups", () => {
  const groups = auditGroups();

  it("are the five of the backend, in the order the client lists them", () => {
    expect(Object.keys(groups)).toEqual([...AUDIT_GROUPS]);
    expect([...AUDIT_GROUPS]).toEqual([
      "users",
      "configuration",
      "alerts_cases",
      "model",
      "system",
    ]);
  });

  it.each(AUDIT_GROUPS)("has a label for %s", (group) => {
    expect(isText(S.admin.auditGroup[group])).toBe(true);
  });

  it("has no label for a group the backend does not have", () => {
    expect(Object.keys(S.admin.auditGroup).sort()).toEqual([...AUDIT_GROUPS].sort());
  });

  it("holds every event type once, so no event is a name without a group", () => {
    const grouped = Object.values(groups).flat();
    expect([...grouped].sort()).toEqual([...eventTypes()].sort());
  });
});

describe("the reason codes", () => {
  it.each(ADMIN_REASONS)("has a Vietnamese text for %s", (reason) => {
    expect(isText(S.admin.reason[reason])).toBe(true);
  });

  it("has no text for a reason that is not in the union", () => {
    expect(Object.keys(S.admin.reason).sort()).toEqual([...ADMIN_REASONS].sort());
  });

  // The routes' own codes, read from their source: a code the admin routes started to use and this client
  // does not know would reach a page as `other`, with no text.
  it("covers every reason the admin routes write", () => {
    const files: [string, string[]][] = [
      ["admin_users.py", ["web", "routers", "admin_users.py"]],
      ["admin_llm.py", ["web", "routers", "admin_llm.py"]],
      ["admin_overview.py", ["web", "routers", "admin_overview.py"]],
      ["admin_digest.py", ["web", "routers", "admin_digest.py"]],
      ["admin_audit.py", ["web", "routers", "admin_audit.py"]],
      ["labels.py", ["web", "routers", "labels.py"]],
    ];
    const found = new Set<string>();
    const patterns = [
      /"reason":\s*"([a-z_]+)"/g, // detail={"reason": "x"}
      /\breason="([a-z_]+)"/g, // _unprocessable(field=..., reason="x")
      /_bad\([^,()]+,\s*"([a-z_]+)"/g, // _bad("field", "x")
      /_refuse\(\s*\d+,\s*"([a-z_]+)"/g, // _refuse(409, "x")
      /UserConflict\("([a-z_]+)"/g, // UserConflict("x")
    ];
    for (const [, path] of files) {
      const text = py(...path);
      for (const pattern of patterns)
        for (const m of text.matchAll(pattern)) found.add(m[1] as string);
    }
    expect(found.size).toBeGreaterThan(15);
    // `actor_no_longer_admin` is the `reason` of an `authz.denied` audit payload in admin_users.py, which no
    // answer carries.
    const notAnAnswer = new Set(["actor_no_longer_admin"]);
    const unknown = [...found].filter(
      (code) => !notAnAnswer.has(code) && !(ADMIN_REASONS as readonly string[]).includes(code),
    );
    expect(unknown).toEqual([]);
  });

  it("lists, beyond the source of the routes, only the codes it reads from legacy text or from P11-T08", () => {
    const text = [
      "admin_users.py",
      "admin_llm.py",
      "admin_overview.py",
      "admin_digest.py",
      "admin_audit.py",
      "labels.py",
    ]
      .map((name) => py("web", "routers", name))
      .join("\n");
    const written = (code: string) => new RegExp(`"${code}"`).test(text);
    const beyond = ADMIN_REASONS.filter((code) => !written(code));
    // The codes of a plain-text `detail` (the rules and labels routes: `rule_not_found`, `unknown_cluster`,
    // `already_labelled`, `labeler_mismatch`) and the two of the undo route of P11-T08, which is built beside
    // this card: until it is merged they are written nowhere, after it `frozen` and `nothing_to_undo` are.
    const readFromElsewhere = new Set([
      "rule_not_found",
      "unknown_cluster",
      "already_labelled",
      "labeler_mismatch",
      "frozen",
      "nothing_to_undo",
    ]);
    expect(beyond.filter((code) => !readFromElsewhere.has(code))).toEqual([]);
    // And the ones the routes of this base do write really are written there: nothing is listed by guess.
    expect(beyond).toContain("rule_not_found");
    expect(ADMIN_REASONS.filter(written).length).toBeGreaterThan(15);
  });
});

describe("adminReasonText", () => {
  it("says the text of the reason when there is nothing to put in it", () => {
    expect(adminReasonText({ reason: "self_change" })).toBe(S.admin.reason.self_change);
    expect(adminReasonText({ reason: "too_short" })).toBe(S.admin.reason.too_short);
  });

  it("puts the bounds of the server in the text", () => {
    expect(adminReasonText({ reason: "too_short", min: 12 })).toBe(S.admin.bounds.tooShort(12));
    expect(adminReasonText({ reason: "too_long", max: 100 })).toBe(S.admin.bounds.tooLong(100));
    expect(adminReasonText({ reason: "out_of_range", min: 10, max: 120 })).toBe(
      S.admin.bounds.outOfRange(10, 120),
    );
    expect(S.admin.bounds.tooShort(12)).toContain("12");
    expect(S.admin.bounds.tooLong(100)).toContain("100");
    expect(S.admin.bounds.outOfRange(10, 120)).toContain("10");
    expect(S.admin.bounds.outOfRange(10, 120)).toContain("120");
  });

  it("falls back to the plain text when one bound is missing", () => {
    expect(adminReasonText({ reason: "out_of_range", min: 10 })).toBe(S.admin.reason.out_of_range);
    expect(adminReasonText({ reason: "out_of_range", max: 120 })).toBe(S.admin.reason.out_of_range);
    expect(adminReasonText({ reason: "too_long", min: 1 })).toBe(S.admin.reason.too_long);
  });

  it("does not put a bound in a reason that has none", () => {
    expect(adminReasonText({ reason: "invalid", min: 1, max: 2 })).toBe(S.admin.reason.invalid);
  });
});

describe("the six hard blocks", () => {
  /** `_HARD_BLOCK_ORDER` of admin_rules.py, as `[code, label]` in its order. */
  function backendBlocks(): [string, string][] {
    const constants = new Map(
      [...py("ingest", "autoclose.py").matchAll(/^(_HARD_BLOCK_[A-Z_]+)\s*=\s*"([^"]+)"/gm)].map(
        (m) => [m[1] as string, m[2] as string] as const,
      ),
    );
    const order = /_HARD_BLOCK_ORDER[^=]*=\s*\(([\s\S]*?)\n\)/.exec(
      py("web", "routers", "admin_rules.py"),
    )?.[1];
    if (order === undefined) throw new Error("_HARD_BLOCK_ORDER not found in admin_rules.py");
    return [...order.matchAll(/\(autoclose\.(_HARD_BLOCK_[A-Z_]+),\s*"([^"]*)"\)/g)].map((m) => {
      const code = constants.get(m[1] as string);
      if (code === undefined) throw new Error(`${m[1]} is not a constant of autoclose.py`);
      return [code, m[2] as string];
    });
  }

  it("are listed by the client in the order of the backend", () => {
    expect(backendBlocks().map(([code]) => code)).toEqual([...HARD_BLOCK_CODES]);
    expect(HARD_BLOCK_CODES).toHaveLength(6);
  });

  it("carry the labels of the backend, word for word, keyed by code", () => {
    expect(Object.fromEntries(backendBlocks())).toEqual(S.admin.hardBlock);
  });
});

describe("the digest verdicts", () => {
  it("carry the labels of admin_digest.py", () => {
    const body = /_VERDICT_LABEL\s*=\s*\{([^}]*)\}/.exec(
      py("web", "routers", "admin_digest.py"),
    )?.[1];
    const backend = Object.fromEntries(
      [...(body ?? "").matchAll(/"(\w+)":\s*"([^"]+)"/g)].map((m) => [m[1], m[2]]),
    );
    expect(backend).toEqual({ correct: "Đúng", wrong: "Sai", unsure: "Không chắc" });
    expect(S.admin.verdict).toEqual(backend);
    expect([...DIGEST_VERDICTS]).toEqual(["correct", "wrong", "unsure"]);
  });
});

describe("the limits of the forms", () => {
  const num = (name: string, file: string[]): number =>
    Number(new RegExp(`^${name}\\s*=\\s*(\\d+)`, "m").exec(py(...file))?.[1]);

  it("equal the constants of the routes they mirror", () => {
    const users = ["web", "routers", "admin_users.py"];
    expect(ADMIN_LIMITS.passwordMin).toBe(num("PASSWORD_MIN_CHARS", users));
    expect(ADMIN_LIMITS.passwordMax).toBe(num("PASSWORD_MAX_CHARS", users));
    expect(ADMIN_LIMITS.displayNameMax).toBe(num("DISPLAY_NAME_MAX_CHARS", users));
    expect(ADMIN_LIMITS.noteMax).toBe(num("NOTE_MAX_CHARS", ["tier1", "labels.py"]));
    const pattern = /^USERNAME_RE\s*=\s*r"([^"]+)"/m.exec(py(...users))?.[1];
    expect(ADMIN_LIMITS.username.source).toBe(pattern);
  });
});

describe("the common words and the page titles", () => {
  it("has the words every dialog and form needs", () => {
    expect(S.admin.common.cancel).toBe("Huỷ");
    expect(S.admin.common.confirm).toBe("Xác nhận");
    expect(S.admin.common.save).toBe("Lưu");
    expect(S.admin.common.saving).toBe("Đang lưu…");
  });

  it("has the titles of the canvas and the labels of its sidebar", () => {
    expect(S.admin.title).toEqual({
      overview: "Tổng quan hệ thống",
      users: "Người dùng và quyền",
      llm: "LLM và hạn mức",
      rules: "Rules tự đóng",
      digest: "Digest hằng ngày",
      labels: "Gán nhãn tập vàng",
      audit: "Nhật ký audit",
    });
    expect(S.admin.nav).toEqual({
      label: "Quản trị",
      overview: "Tổng quan",
      users: "Người dùng & quyền",
      llm: "LLM & hạn mức",
      rules: "Rules tự đóng",
      digest: "Digest hằng ngày",
      labels: "Gán nhãn",
      audit: "Nhật ký audit",
    });
  });

  it("names the three ranges of the overview and the audit, and the month of the usage page", () => {
    expect(S.admin.range).toEqual({
      "24h": "24 giờ qua",
      "7d": "7 ngày qua",
      "30d": "30 ngày qua",
      month: "Tháng này",
    });
  });
});
