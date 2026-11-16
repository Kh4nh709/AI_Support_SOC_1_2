// src/features/admin/adminStrings.test.ts — the admin section of strings.ts (P11-T10): a text for every
// reason code of the admin routes and for every audit event type, and the tables that the backend owns
// (the audit groups, the limits of the forms) kept equal to it. The rules and digest routes (admin_rules.py,
// admin_digest.py) are not read here since DEC-214: the UI no longer calls them.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  ADMIN_LIMITS,
  ADMIN_RANGES,
  ADMIN_REASONS,
  AUDIT_GROUPS,
  KNOWLEDGE_CLOSED_FIELDS,
  KNOWLEDGE_DRAFT_STATUSES,
  KNOWLEDGE_ENTRY_STATUSES,
  KNOWLEDGE_LIMITS,
  KNOWLEDGE_MODEL_FIELDS,
  KNOWLEDGE_REDRAFTABLE_WARNINGS,
  LABEL_CHOICES,
  LABEL_CONFIDENCES,
  LIMIT_FIELDS,
  LIMIT_KEYS,
  LIMIT_KEY_OF_FIELD,
  LLM_RANGES,
  OVERVIEW_SECTIONS,
} from "../../api/admin";
import {
  S,
  adminReasonText,
  knowledgeFaultText,
  knowledgeWarningText,
  labelOf,
} from "../../strings";

const BACKEND_APP = join("..", "backend", "app");
const py = (...path: string[]): string => readFileSync(join(BACKEND_APP, ...path), "utf8");

const isText = (value: unknown): value is string =>
  typeof value === "string" && value.trim() !== "";

/** `EVENT_TYPES` of `audit/events.py`: the 42 names the database CHECK admits. */
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

  it("reads the 42 names of the backend", () => {
    expect(names).toHaveLength(42);
    expect(new Set(names).size).toBe(42);
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
  // DEC-214, ruling 3: each of these was answered by admin_rules.py or admin_digest.py and by no router a page
  // that stays calls (read from `backend/app/web/routers`: admin_users, admin_llm, admin_overview, admin_audit,
  // admin_knowledge, labels, `POST /api/admin/reload-inventory` in main.py). `invalid`, `forbidden` and
  // `not_found`, which the digest route also wrote, are written by those too, and stay.
  const REMOVED_REASONS = [
    "bad_day",
    "not_in_digest",
    "already_reviewed",
    "not_auto_closed",
    "rule_not_found",
  ];

  it("has no reason, and no text, that only the removed rules and digest routes answered with", () => {
    for (const reason of REMOVED_REASONS) {
      expect(ADMIN_REASONS as readonly string[], reason).not.toContain(reason);
      expect(Object.keys(S.admin.reason), reason).not.toContain(reason);
    }
    for (const reason of ["invalid", "forbidden", "not_found"]) {
      expect(ADMIN_REASONS as readonly string[], reason).toContain(reason);
    }
  });

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

  it("lists, beyond the source of the routes, only the codes it reads from legacy text", () => {
    const text = [
      "admin_users.py",
      "admin_llm.py",
      "admin_overview.py",
      "admin_audit.py",
      "labels.py",
    ]
      .map((name) => py("web", "routers", name))
      .join("\n");
    const written = (code: string) => new RegExp(`"${code}"`).test(text);
    const beyond = ADMIN_REASONS.filter((code) => !written(code));
    // The codes of a plain-text `detail` (the labels route: `unknown_cluster`, `already_labelled`,
    // `labeler_mismatch`). `reserved` is no longer one of them: P11-T20 part 1 is merged, and the create route
    // writes it (`_bad("username", "reserved")`). `frozen` and `nothing_to_undo`, the undo route of P11-T08, are
    // written in labels.py and need no entry either. A code only the removed rules and digest routes answered
    // with (DEC-214) is in neither list: no route a page calls writes it, so it has no place here.
    const readFromElsewhere = new Set(["unknown_cluster", "already_labelled", "labeler_mismatch"]);
    expect(beyond.filter((code) => !readFromElsewhere.has(code))).toEqual([]);
    // And the ones the routes of this base do write really are written there: nothing is listed by guess.
    expect(beyond).toContain("unknown_cluster");
    expect(written("reserved")).toBe(true);
    expect(ADMIN_REASONS.filter(written).length).toBeGreaterThan(15);
  });

  it("has a text for the username a create refuses as reserved, naming the two", () => {
    expect(isText(S.admin.reason.reserved)).toBe(true);
    expect(S.admin.reason.reserved).toContain("system");
    expect(S.admin.reason.reserved).toContain("llm");
  });

  // `frozen` is the reason of a refused undo (P11-T08) and also of a refused label save (the labels route's
  // plain "the gold set is frozen"), so its text cannot say only "cannot undo".
  it("words `frozen` for a refused label save as well as for a refused undo", () => {
    expect(S.admin.reason.frozen).toBe(
      "Tập vàng đã đóng băng — không gán thêm hay hoàn tác được nữa.",
    );
    expect(S.admin.reason.frozen).not.toMatch(/^Không hoàn tác được/);
  });

  // `not_found` is read from `{reason: "not_found"}`: a user, a job or a knowledge entry that is gone. The pages
  // of the users and of the failed jobs reload their list; the others do not, so its text must not say that a
  // list was reloaded.
  it("has a text for `not_found` that does not claim a list was reloaded", () => {
    expect(isText(S.admin.reason.not_found)).toBe(true);
    expect(S.admin.reason.not_found).not.toContain("Danh sách đã được tải lại");
  });

  // P11-T20 row 51 (P11-T11 N3): the pages that reload their list on a 404 (the users and the failed jobs) show this
  // text after the list is already read again, so it must not tell the admin to reload the page.
  it("words `not_found` neutrally: it does not tell the admin to reload a page that was reloaded", () => {
    expect(S.admin.reason.not_found).toBe("Không tìm thấy mục này.");
    expect(S.admin.reason.not_found).not.toMatch(/tải lại/);
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

// The audit page still reads an old `autoclose.reviewed` event, and words its verdict with these three labels
// (auditSummary.ts). They were the digest page's; since DEC-214 nothing but the audit page uses them.
describe("the verdict labels of an old digest review", () => {
  it("are the three the audit summary of `autoclose.reviewed` reads, word for word", () => {
    expect(S.admin.verdict).toEqual({ correct: "Đúng", wrong: "Sai", unsure: "Không chắc" });
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

  // `system` and `llm` are the two `actor_role`s of an audit row that is not a person: the audit page's actor
  // filter reads them as roles (`_ROLE_ACTORS`), so a user of that name would be unreachable there (P11-T20).
  it("lists as reserved the two actor names the audit filter reads as roles", () => {
    const actors = /_ROLE_ACTORS\s*=\s*\(([^)]*)\)/.exec(
      py("web", "routers", "admin_audit.py"),
    )?.[1];
    const names = [...(actors ?? "").matchAll(/"(\w+)"/g)].map((m) => m[1]);
    expect(names).toEqual(["system", "llm"]);
    expect([...ADMIN_LIMITS.reservedUsernames]).toEqual(names);
  });
});

describe("the vocabulary of the client equals the one of the routes", () => {
  const router = (name: string): string => py("web", "routers", name);
  const quoted = (text: string | undefined): string[] =>
    [...(text ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1] as string);
  /** `NAME = Literal["a", "b"]`: the values, in order. */
  const literalOf = (source: string, name: string): string[] =>
    quoted(new RegExp(`${name}\\s*=\\s*Literal\\[([^\\]]*)\\]`).exec(source)?.[1]);
  /** The keys of `NAME... = { "k": ..., }`, in order. */
  const keysOf = (source: string, name: string): string[] =>
    [
      ...(new RegExp(`${name}[^=]*=\\s*\\{([^}]*)\\}`).exec(source)?.[1] ?? "").matchAll(
        /^\s*"(\w+)":/gm,
      ),
    ].map((m) => m[1] as string);

  it("OVERVIEW_SECTIONS is the sections of admin_overview.py, in its order", () => {
    const body = /sections = \(([\s\S]*?)\n {4}\)/.exec(router("admin_overview.py"))?.[1];
    const names = [...(body ?? "").matchAll(/\("(\w+)",\s*lambda/g)].map((m) => m[1]);
    expect(names).toHaveLength(11);
    expect([...OVERVIEW_SECTIONS]).toEqual(names);
  });

  it("ADMIN_RANGES is the window list of the overview and of the audit page", () => {
    for (const file of ["admin_overview.py", "admin_audit.py"]) {
      expect(literalOf(router(file), "RangeName"), file).toEqual([...ADMIN_RANGES]);
      expect(keysOf(router(file), "_WINDOWS"), file).toEqual([...ADMIN_RANGES]);
    }
    expect([...ADMIN_RANGES]).toEqual(["24h", "7d", "30d"]);
  });

  it("LLM_RANGES is the range list of admin_llm.py: the three and the calendar month", () => {
    expect(literalOf(router("admin_llm.py"), "RangeName")).toEqual([...LLM_RANGES]);
    expect(keysOf(router("admin_llm.py"), "_SINCE_SQL")).toEqual([...LLM_RANGES]);
    expect([...LLM_RANGES]).toEqual([...ADMIN_RANGES, "month"]);
  });

  it("the three limit settings, their request fields and the map between them are infra/settings.py's", () => {
    const settings = py("infra", "settings.py");
    const keys = quoted(/^KEYS\s*=\s*\(([^)]*)\)/m.exec(settings)?.[1]);
    const map = Object.fromEntries(
      [
        ...(/FIELD_OF_KEY\s*=\s*\{([^}]*)\}/.exec(settings)?.[1] ?? "").matchAll(
          /"(\w+)":\s*"(\w+)"/g,
        ),
      ].map((m) => [m[1], m[2]]),
    );
    expect(keys).toHaveLength(3);
    expect([...LIMIT_KEYS]).toEqual(keys);
    expect(LIMIT_KEY_OF_FIELD).toEqual(
      Object.fromEntries(Object.entries(map).map(([key, field]) => [field, key])),
    );
    expect([...LIMIT_FIELDS]).toEqual(keys.map((key) => map[key]));
  });

  it("LABEL_CHOICES and LABEL_CONFIDENCES are the Literals of LabelIn in labels.py", () => {
    const labels = router("labels.py");
    const label = quoted(/^\s+label: Literal\[([^\]]*)\]/m.exec(labels)?.[1]);
    const confidence = (/^\s+confidence: Literal\[([^\]]*)\]/m.exec(labels)?.[1] ?? "")
      .split(",")
      .map((n) => Number(n.trim()));
    expect([...LABEL_CHOICES]).toEqual(label);
    expect(label).toHaveLength(3);
    expect([...LABEL_CONFIDENCES]).toEqual(confidence);
    expect(confidence).toEqual([1, 2, 3]);
  });

  it("S.admin.range has a text for each range of the usage page, and no other", () => {
    expect(Object.keys(S.admin.range)).toEqual([...LLM_RANGES]);
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
      labels: "Gán nhãn tập vàng",
      knowledge: "Tri thức học được",
      audit: "Nhật ký audit",
    });
    expect(S.admin.nav).toEqual({
      label: "Quản trị",
      overview: "Tổng quan",
      users: "Người dùng & quyền",
      llm: "LLM & hạn mức",
      labels: "Gán nhãn",
      knowledge: "Tri thức",
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

describe("the learned-knowledge words (DEC-210, P13-T06)", () => {
  const K = S.admin.knowledgePage;
  const quoted = (text: string | undefined): string[] =>
    [...(text ?? "").matchAll(/"([^"]+)"/g)].map((m) => m[1] as string);
  const draftPy = (): string => py("rag", "draft.py");
  const number = (source: string, name: string): number =>
    Number(new RegExp(`^${name}\\s*=\\s*(\\d+)`, "m").exec(source)?.[1]);

  it("names the five tabs, and the four actions, in the words of the spec", () => {
    expect(K.tab).toEqual({
      pending: "Chờ duyệt",
      active: "Đã duyệt",
      merged: "Đã gộp",
      rejected: "Từ chối",
      retired: "Đã gỡ",
    });
    expect(K.draft.action.approve).toBe("Duyệt");
    expect(K.draft.action.editApprove).toBe("Sửa rồi duyệt");
    expect(K.draft.action.reject).toBe("Từ chối");
    expect(K.entry.retire).toBe("Gỡ");
    expect(S.admin.nav.knowledge).toBe("Tri thức");
  });

  it("has an empty-state sentence and a table name for each tab", () => {
    for (const tab of Object.keys(K.tab)) {
      expect(isText(K.empty[tab as keyof typeof K.empty]), tab).toBe(true);
      expect(isText(K.tableLabel[tab as keyof typeof K.tableLabel]), tab).toBe(true);
    }
    expect(Object.keys(K.empty).sort()).toEqual(Object.keys(K.tab).sort());
    expect(Object.keys(K.tableLabel).sort()).toEqual(Object.keys(K.tab).sort());
  });

  it("says a part the source no longer has as 'không còn dữ liệu'", () => {
    for (const text of Object.values(K.draft.left.noData))
      expect(text).toContain("không còn dữ liệu");
  });

  it("says a handled draft as 'bản nháp đã được xử lý'", () => {
    expect(K.notice.handled).toContain("bản nháp đã được xử lý");
  });

  describe("the vocabulary of the client is the one of rag/draft.py and rag/publish.py", () => {
    it("KNOWLEDGE_MODEL_FIELDS and KNOWLEDGE_CLOSED_FIELDS", () => {
      expect([...KNOWLEDGE_MODEL_FIELDS]).toEqual(
        quoted(/^MODEL_FIELDS = \(([^)]*)\)/m.exec(draftPy())?.[1]),
      );
      expect([...KNOWLEDGE_CLOSED_FIELDS]).toEqual(
        quoted(/^CLOSED_FIELDS = \(([^)]*)\)/m.exec(draftPy())?.[1]),
      );
      expect(KNOWLEDGE_MODEL_FIELDS).toHaveLength(6);
      expect(KNOWLEDGE_CLOSED_FIELDS).toHaveLength(6);
    });

    it("KNOWLEDGE_REDRAFTABLE_WARNINGS are the warnings of REDRAFTABLE_WARNINGS", () => {
      const draft = draftPy();
      const named = new Map(
        [...draft.matchAll(/^(WARNING_[A-Z]+) = "([a-z_]+)"$/gm)].map((m) => [m[1], m[2]]),
      );
      const body = /^REDRAFTABLE_WARNINGS = frozenset\(\s*\{([^}]*)\}\s*\)/m.exec(draft)?.[1];
      expect(body).toBeDefined();
      const backend = [...(body ?? "").matchAll(/WARNING_[A-Z]+/g)].map((m) => named.get(m[0]));
      expect(backend).toHaveLength(4);
      expect([...KNOWLEDGE_REDRAFTABLE_WARNINGS].sort()).toEqual(backend.sort());
    });

    it("KNOWLEDGE_LIMITS", () => {
      const draft = draftPy();
      expect(KNOWLEDGE_LIMITS.titleMax).toBe(number(draft, "TITLE_MAX"));
      expect(KNOWLEDGE_LIMITS.summaryMax).toBe(number(draft, "SUMMARY_MAX"));
      expect(KNOWLEDGE_LIMITS.itemMax).toBe(number(draft, "ITEM_MAX"));
      expect(KNOWLEDGE_LIMITS.maxItems).toBe(number(draft, "MAX_ITEMS"));
      expect(KNOWLEDGE_LIMITS.noteMax).toBe(number(draft, "NOTE_MAX"));
      expect(KNOWLEDGE_LIMITS.reasonMax).toBe(number(py("rag", "publish.py"), "REASON_MAX"));
      expect(KNOWLEDGE_LIMITS.listDefault).toBe(
        number(py("web", "routers", "admin_knowledge.py"), "DEFAULT_LIMIT"),
      );
    });

    it("KNOWLEDGE_DRAFT_STATUSES and KNOWLEDGE_ENTRY_STATUSES are the Literals of the router", () => {
      const router = py("web", "routers", "admin_knowledge.py");
      const literal = (name: string) =>
        quoted(new RegExp(`^${name} = Literal\\[([^\\]]*)\\]`, "m").exec(router)?.[1]);
      expect([...KNOWLEDGE_DRAFT_STATUSES]).toEqual(literal("DraftStatus"));
      expect([...KNOWLEDGE_ENTRY_STATUSES]).toEqual(literal("EntryStatus"));
      expect(Object.keys(K.draft.status).sort()).toEqual([...KNOWLEDGE_DRAFT_STATUSES].sort());
      expect(Object.keys(K.entry.status).sort()).toEqual([...KNOWLEDGE_ENTRY_STATUSES].sort());
    });
  });

  describe("the faults of V1-V5", () => {
    /** The rule of every name of `FAULT_VOCABULARY`: what is before the colon, `v3_<kind>` for each finding kind. */
    function backendRules(): string[] {
      const body = /def _fault_vocabulary\(\)[\s\S]*?return frozenset\(names\)/.exec(
        draftPy(),
      )?.[0];
      if (body === undefined) throw new Error("_fault_vocabulary not found in rag/draft.py");
      const kinds = quoted(/^FINDING_NAMES = \(([^)]*)\)/m.exec(py("rag", "generalise.py"))?.[1]);
      const rules = new Set<string>();
      for (const m of body.matchAll(/\bv\d_(?:\{kind\}|[a-z]+)/g)) {
        const rule = m[0];
        if (rule.endsWith("{kind}")) for (const kind of kinds) rules.add(`v3_${kind}`);
        else rules.add(rule);
      }
      return [...rules];
    }

    it("reads the rules of the backend (a parse that finds nothing would compare nothing)", () => {
      const rules = backendRules();
      expect(rules).toContain("v1_schema");
      expect(rules).toContain("v3_ipv4");
      expect(rules).toContain("v4_nonce");
      expect(rules).toContain("v5_empty");
      expect(rules.length).toBeGreaterThan(12);
    });

    it("has a Vietnamese text for each rule of FAULT_VOCABULARY, and for no other", () => {
      const rules = backendRules();
      for (const rule of rules)
        expect(isText(K.fault.rule[rule as keyof typeof K.fault.rule]), rule).toBe(true);
      expect(Object.keys(K.fault.rule).sort()).toEqual([...rules].sort());
    });

    it("has its own words for the three names whose part after the colon is not a field, and they are the backend's", () => {
      const body = /def _fault_vocabulary\(\)[\s\S]*?return frozenset\(names\)/.exec(
        draftPy(),
      )?.[0];
      const names = /names = \{([^}]*)\}/.exec(body ?? "")?.[1];
      expect(quoted(names).sort()).toEqual(Object.keys(K.fault.special).sort());
      for (const text of Object.values(K.fault.special)) expect(isText(text)).toBe(true);
    });

    it("words a fault by its rule, and the three special ones in their own words", () => {
      expect(knowledgeFaultText({ rule: "v3_ipv4", field: "summary" })).toBe(K.fault.rule.v3_ipv4);
      expect(knowledgeFaultText({ rule: "v5_length", field: "title" })).toBe(
        K.fault.rule.v5_length,
      );
      expect(knowledgeFaultText({ rule: "v1_schema", field: "root" })).toBe(
        K.fault.special["v1_schema:root"],
      );
      expect(knowledgeFaultText({ rule: "v1_schema", field: "unexpected_key" })).toBe(
        K.fault.special["v1_schema:unexpected_key"],
      );
      expect(knowledgeFaultText({ rule: "v1_tags", field: "unknown_tag" })).toBe(
        K.fault.special["v1_tags:unknown_tag"],
      );
    });

    it("gives an unknown rule a generic sentence that names the rule, and shows nothing else of it", () => {
      expect(knowledgeFaultText({ rule: "v9_brand_new", field: "title" })).toBe(
        K.fault.fallback("v9_brand_new"),
      );
      expect(knowledgeFaultText({ rule: "weird", field: null })).toBe(K.fault.fallback("weird"));
    });

    it("does not answer from the prototype chain", () => {
      expect(knowledgeFaultText({ rule: "constructor", field: null })).toBe(
        K.fault.fallback("constructor"),
      );
      expect(knowledgeFaultText({ rule: "v1_schema", field: "__proto__" })).toBe(
        K.fault.rule.v1_schema,
      );
      expect(knowledgeFaultText({ rule: "toString", field: "root" })).toBe(
        K.fault.fallback("toString"),
      );
    });
  });

  describe("the warnings of a draft", () => {
    it("has a text for each warning the job writes besides the V names, and for no other", () => {
      const draft = draftPy();
      const codes = [...draft.matchAll(/^WARNING_[A-Z]+ = "([a-z_]+)"/gm)].map(
        (m) => m[1] as string,
      );
      expect(codes).toHaveLength(5);
      expect(Object.keys(K.warning).sort()).toEqual([...codes].sort());
    });

    it("words a known code, a V name with its field, and an unknown code as it came", () => {
      expect(knowledgeWarningText("budget")).toBe(K.warning.budget);
      expect(knowledgeWarningText("v3_ipv4:summary")).toBe(
        K.fault.named(K.draft.right.field.summary, K.fault.rule.v3_ipv4),
      );
      expect(knowledgeWarningText("v1_schema:root")).toBe(K.fault.special["v1_schema:root"]);
      expect(knowledgeWarningText("v2_closed:category")).toBe(
        K.fault.named(K.draft.right.closed.category, K.fault.rule.v2_closed),
      );
      expect(knowledgeWarningText("something_new")).toBe("something_new");
      expect(knowledgeWarningText("constructor")).toBe("constructor");
    });
  });
});
