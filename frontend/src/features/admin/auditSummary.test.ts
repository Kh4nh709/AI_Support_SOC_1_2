// src/features/admin/auditSummary.test.ts — what the audit page makes of an event's payload: the one-line
// summary of each of the 28 event types, the link of a subject that is an alert or a case, the payload as
// text, and the escape of the characters a person cannot see. A payload is whatever the writers of the
// events put there, so every function here is also shown to survive a payload of the wrong shape.
import { S } from "../../strings";
import {
  hasInvisible,
  payloadText,
  subjectPathOf,
  summaryOf,
  tooBigSize,
  visible,
} from "./auditSummary";

const TYPES = Object.keys(S.admin.eventType);

const sum = (event_type: string, payload: unknown) => summaryOf({ event_type, payload });

describe("summaryOf, one event type at a time", () => {
  it("covers all 28 event types of the backend, and each has a case below", () => {
    expect(TYPES).toHaveLength(28);
  });

  it.each<[type: string, payload: unknown, summary: string]>([
    ["alert.received", null, "alert vào hệ thống"],
    [
      "alert.duplicate_merged",
      { parent: "1759012345.1662100", occurrence: 12 },
      "gộp vào alert 1759012345.1662100; lần xuất hiện thứ 12",
    ],
    ["alert.duplicate_merged", {}, "gộp vào alert đã có"],
    [
      "alert.auto_closed",
      { rule_id: "r-1", rule_name: "Quét DNS nội bộ", reason: "Quét DNS lặp lại, không rủi ro" },
      "đóng theo rule “Quét DNS nội bộ”; lý do: Quét DNS lặp lại, không rủi ro",
    ],
    ["alert.auto_closed", null, "đóng theo rule tự đóng"],
    [
      "alert.autoclose_blocked_critical",
      { rule_id: "r-2" },
      "mức critical chặn tự đóng; rule r-2 đã khớp",
    ],
    ["alert.autoclose_blocked_critical", null, "mức critical chặn tự đóng"],
    ["alert.enrich_started", null, "bắt đầu làm giàu dữ liệu"],
    [
      "alert.enriched",
      { risk_score: 72, exhausted: false },
      "làm giàu dữ liệu xong; điểm rủi ro 72",
    ],
    [
      "alert.enriched",
      { risk_score: 10, exhausted: true },
      "làm giàu dữ liệu xong; điểm rủi ro 10; hết lượt thử, không có dữ liệu bổ sung",
    ],
    ["alert.enriched", null, "làm giàu dữ liệu xong"],
    ["alert.reopened", { reason: "digest" }, "mở lại về hàng đợi Tier 1; lý do: digest"],
    ["alert.reopened", null, "mở lại về hàng đợi Tier 1"],
    ["alert.acknowledged", null, "Tier 1 nhận alert để xử lý"],
    [
      "tier1.decided",
      { decision: "closed_fp", reason: "Báo động giả", occurrence_count: 3 },
      "quyết định: Đã đóng — dương tính giả; lý do: Báo động giả",
    ],
    [
      "tier1.decided",
      { decision: "closed_benign", reason: "Việc của IT" },
      "quyết định: Đã đóng — lành tính; lý do: Việc của IT",
    ],
    ["tier1.decided", null, "quyết định của Tier 1"],
    [
      "tier1.escalated",
      { case_id: "c-1", alert_ids: ["a", "b", "c"], llm_suggestion: null },
      "chuyển lên Tier 2, case c-1; 3 alert",
    ],
    ["tier1.escalated", null, "chuyển lên Tier 2"],
    [
      "case.opened",
      { trigger_alert_id: "a1", alert_count: 3, correlated_count: 2 },
      "mở từ alert a1; 3 alert, 2 liên quan",
    ],
    ["case.opened", null, "mở case"],
    ["case.truncated", { dropped: 4 }, "cắt 4 cụm vượt giới hạn của case"],
    ["case.truncated", { dropped: ["x", "y"] }, "cắt 2 cụm vượt giới hạn của case"],
    ["case.truncated", null, "case bị cắt bớt cụm"],
    [
      "tier2.concluded",
      { conclusion: "confirmed_incident", reason: "có bằng chứng lateral movement" },
      "kết luận: Xác nhận sự cố; lý do: có bằng chứng lateral movement",
    ],
    ["tier2.concluded", null, "Tier 2 kết luận case"],
    ["case.analyzed", { run_id: "run-1", job_id: 77 }, "chạy phân tích ②; job 77"],
    ["case.analyzed", null, "chạy phân tích ②"],
    [
      "triage.suggested",
      { suggested_action: "escalate", confidence: "high", forced: true, run_id: "x" },
      "đề xuất ①: Chuyển tier 2; độ tin cậy cao; cổng kiểm soát đã ép kết quả",
    ],
    [
      "triage.suggested",
      { suggested_action: "false_positive", confidence: "low", forced: false },
      "đề xuất ①: Dương tính giả; độ tin cậy thấp",
    ],
    ["triage.suggested", null, "đã có đề xuất ①"],
    [
      "llm.gate_forced",
      { proposed: "false_positive", final: "needs_review", forced_by: "critical", missing: [] },
      "cổng kiểm soát ép Dương tính giả → Cần xem xét; do critical",
    ],
    ["llm.gate_forced", null, "cổng kiểm soát ép kết quả ①"],
    ["llm.builder_violation", { violations_count: 2 }, "2 vi phạm khi dựng dữ liệu gửi model"],
    ["llm.builder_violation", null, "dữ liệu gửi model bị chặn"],
    [
      "job.exhausted",
      { reason: "llm_transient", attempts: 3 },
      "hết 3 lần thử; lý do: model không phản hồi",
    ],
    [
      "job.exhausted",
      { reason: "something_new", attempts: 5 },
      "hết 5 lần thử; lý do: something_new",
    ],
    ["job.exhausted", null, "hết số lần thử của worker"],
    [
      "admin.user_created",
      { username: "an.t2", role: "tier2" },
      "tạo tài khoản an.t2; vai trò Tier 2",
    ],
    ["admin.user_created", { username: "an.t2" }, "tạo tài khoản an.t2"],
    ["admin.user_created", null, "tạo tài khoản"],
    [
      "admin.user_updated",
      { username: "an.t2", before: { role: "tier1" }, after: { role: "tier2" } },
      "an.t2: vai trò Tier 1 → Tier 2; phiên cũ bị đăng xuất",
    ],
    [
      "admin.user_updated",
      { username: "an.t2", before: { is_active: true }, after: { is_active: false } },
      "an.t2: vô hiệu hoá tài khoản; phiên cũ bị đăng xuất",
    ],
    [
      "admin.user_updated",
      { username: "an.t2", before: { is_active: false }, after: { is_active: true } },
      "an.t2: kích hoạt lại tài khoản",
    ],
    [
      "admin.user_updated",
      { username: "an.t2", before: { display_name: "A" }, after: { display_name: "B" } },
      "an.t2: đổi tên hiển thị",
    ],
    [
      "admin.user_updated",
      {
        username: "an.t2",
        before: { role: "tier2", display_name: "A" },
        after: { role: "admin", display_name: "B" },
      },
      "an.t2: vai trò Tier 2 → Admin; đổi tên hiển thị; phiên cũ bị đăng xuất",
    ],
    [
      "admin.user_updated",
      { username: "an.t2", action: "password_reset" },
      "an.t2: đặt lại mật khẩu; phiên cũ bị đăng xuất",
    ],
    ["admin.user_updated", { username: "an.t2", action: "unlock" }, "an.t2: mở khoá tài khoản"],
    ["admin.user_updated", { username: "an.t2" }, "an.t2: cập nhật tài khoản"],
    ["admin.user_updated", null, "cập nhật tài khoản"],
    [
      "admin.job_retried",
      {
        job_id: 100412,
        job_type: "triage",
        subject_id: "a",
        attempts_before: 3,
        last_error: "boom",
      },
      "chạy lại job triage #100412; trước đó đã thử 3 lần",
    ],
    ["admin.job_retried", null, "chạy lại job lỗi"],
    [
      "authz.denied",
      { required: ["admin"], role: "tier1", method: "GET" },
      "GET: cần vai trò Admin; tài khoản là Tier 1",
    ],
    [
      "authz.denied",
      {
        required: ["admin"],
        role: "tier1",
        method: "PATCH",
        reason: "actor_no_longer_admin",
      },
      "PATCH: cần vai trò Admin; tài khoản là Tier 1; vai trò đã đổi giữa chừng",
    ],
    ["authz.denied", null, "bị từ chối quyền"],
    [
      "admin.autoclose_rule_toggled",
      { name: "Thử nghiệm: quét DNS", before: true, after: false },
      "“Thử nghiệm: quét DNS”: bật → tắt",
    ],
    [
      "admin.autoclose_rule_toggled",
      { name: "Rule mới", before: false, after: true },
      "“Rule mới”: tắt → bật",
    ],
    ["admin.autoclose_rule_toggled", null, "bật/tắt rule tự đóng"],
    [
      "autoclose.reviewed",
      {
        verdict: "unsure",
        autoclose_rule_id: "r",
        suggested_action: "false_positive",
        run_id: "x",
      },
      "duyệt: Không chắc; đề xuất ①: Dương tính giả",
    ],
    ["autoclose.reviewed", { verdict: "wrong", suggested_action: null }, "duyệt: Sai"],
    ["autoclose.reviewed", null, "duyệt digest"],
    [
      "rule.suspected_wrong",
      { wrong_count: 3, window: "7 days" },
      "3 cụm bị duyệt “Sai” trong 7 ngày",
    ],
    [
      "rule.suspected_wrong",
      { wrong_count: 3, window: "1 day" },
      "3 cụm bị duyệt “Sai” trong 1 ngày",
    ],
    [
      "rule.suspected_wrong",
      { wrong_count: 2, window: "a week" },
      "2 cụm bị duyệt “Sai” trong a week",
    ],
    ["rule.suspected_wrong", { wrong_count: 2 }, "2 cụm bị duyệt “Sai” trong thời gian gần đây"],
    ["rule.suspected_wrong", null, "rule bị nghi đóng nhầm"],
    [
      "label.created",
      {
        alert_id: "a",
        labeler_id: "u",
        label: "false_positive",
        confidence: 2,
        gold_set: "gold_v2",
      },
      "gán nhãn dương tính giả; độ tin cậy 2/3; gold_v2",
    ],
    [
      "label.created",
      {
        alert_id: "a",
        labeler_id: "u",
        label: "false_positive",
        confidence: null,
        gold_set: null,
        source: "digest",
      },
      "gán nhãn dương tính giả; từ duyệt digest",
    ],
    ["label.created", { undo: true, alert_id: "a", labeler_id: "u" }, "hoàn tác nhãn"],
    ["label.created", null, "gán nhãn tập vàng"],
    [
      "admin.settings_changed",
      { changes: [{ key: "LLM_MONTHLY_USD_CAP", old: 30, new: 40 }] },
      "trần chi phí (USD mỗi tháng) 30 → 40",
    ],
    [
      "admin.settings_changed",
      {
        changes: [
          { key: "LLM_TIMEOUT_S", old: 120, new: 90 },
          { key: "ANALYZE_QUOTA_PER_USER_DAY", old: 30, new: 20 },
        ],
      },
      "thời gian chờ mỗi lượt gọi (giây) 120 → 90; hạn mức phân tích ② (lượt mỗi người trong 24 giờ) 30 → 20",
    ],
    [
      "admin.settings_changed",
      { changes: [{ key: "SOMETHING_NEW", old: 1, new: 2 }] },
      "SOMETHING_NEW 1 → 2",
    ],
    ["admin.settings_changed", { changes: [] }, "đổi hạn mức LLM"],
    ["admin.settings_changed", null, "đổi hạn mức LLM"],
    [
      "health.alarm",
      { failing: ["backup_age", "disk_free"], new: ["backup_age"] },
      "mới lỗi: Bản sao lưu gần nhất; đang lỗi: Bản sao lưu gần nhất, Dung lượng đĩa còn trống",
    ],
    [
      "health.alarm",
      { failing: ["a_new_check"], new: ["a_new_check"] },
      "mới lỗi: a_new_check; đang lỗi: a_new_check",
    ],
    ["health.alarm", null, "cảnh báo sức khoẻ"],
  ])("%s %j says %j", (type, payload, summary) => {
    expect(sum(type, payload)).toBe(summary);
  });

  it("has a case for every one of the 28 types", () => {
    // The cases above are the table; this is the other direction: no type of the backend is left without one.
    const covered = new Set(
      [
        "alert.received",
        "alert.duplicate_merged",
        "alert.auto_closed",
        "alert.autoclose_blocked_critical",
        "alert.enrich_started",
        "alert.enriched",
        "alert.reopened",
        "alert.acknowledged",
        "tier1.decided",
        "tier1.escalated",
        "case.opened",
        "case.truncated",
        "tier2.concluded",
        "case.analyzed",
        "triage.suggested",
        "llm.gate_forced",
        "llm.builder_violation",
        "job.exhausted",
        "admin.user_created",
        "admin.user_updated",
        "admin.job_retried",
        "authz.denied",
        "admin.autoclose_rule_toggled",
        "autoclose.reviewed",
        "rule.suspected_wrong",
        "label.created",
        "admin.settings_changed",
        "health.alarm",
      ].sort(),
    );
    expect([...covered]).toEqual([...TYPES].sort());
  });
});

describe("summaryOf, on a payload that is not what the writer would write", () => {
  it("says the payload is too big, whatever the event, when the server cut it", () => {
    for (const type of TYPES) {
      expect(sum(type, { truncated: true, size: 70000 })).toBe(
        "payload quá lớn (70.000 byte), server không gửi nội dung",
      );
    }
  });

  it("does not take a payload that merely has a `truncated` key for the cut one", () => {
    expect(sum("case.truncated", { dropped: 4, truncated: true, size: 3 })).toBe(
      "cắt 4 cụm vượt giới hạn của case",
    );
    expect(sum("case.truncated", { truncated: true })).toBe("case bị cắt bớt cụm");
    expect(sum("case.truncated", { truncated: true, size: "big" })).toBe("case bị cắt bớt cụm");
  });

  it("shows a dash for an event type it has no line for, never a blank", () => {
    expect(sum("alert.brand_new", { a: 1 })).toBe("—");
    expect(sum("", null)).toBe("—");
    expect(sum("constructor", null)).toBe("—");
    expect(sum("__proto__", null)).toBe("—");
    expect(sum("toString", { a: 1 })).toBe("—");
  });

  // Every key a builder reads, set to a value of the wrong kind in turn.
  const KEYS = [
    "parent",
    "occurrence",
    "rule_id",
    "rule_name",
    "reason",
    "risk_score",
    "exhausted",
    "decision",
    "case_id",
    "alert_ids",
    "trigger_alert_id",
    "alert_count",
    "correlated_count",
    "dropped",
    "conclusion",
    "job_id",
    "suggested_action",
    "confidence",
    "forced",
    "proposed",
    "final",
    "forced_by",
    "violations_count",
    "attempts",
    "username",
    "role",
    "before",
    "after",
    "action",
    "job_type",
    "attempts_before",
    "required",
    "method",
    "name",
    "verdict",
    "wrong_count",
    "window",
    "label",
    "gold_set",
    "source",
    "undo",
    "changes",
    "failing",
    "new",
  ];
  const WRONG: [string, unknown][] = [
    ["null", null],
    ["a number", 42],
    ["NaN", Number.NaN],
    ["infinity", Number.POSITIVE_INFINITY],
    ["a string", "text"],
    ["an empty string", ""],
    ["true", true],
    ["an empty list", []],
    ["a list of junk", [1, null, {}, "x", [[]]]],
    ["an empty object", {}],
    ["an object", { role: {}, key: [], old: null }],
    ["a long string", "x".repeat(5000)],
    ["a markup string", "<img src=x onerror=alert(1)>"],
  ];

  it.each(WRONG)("survives every key holding %s, for every event type", (_name, value) => {
    const payload = Object.fromEntries(KEYS.map((key) => [key, value]));
    for (const type of TYPES) {
      const text = sum(type, payload);
      expect(typeof text, type).toBe("string");
      expect(text.length, type).toBeGreaterThan(0);
      expect(text, type).not.toMatch(/undefined|NaN|\[object|null/);
    }
  });

  it.each(WRONG)("survives a payload that is %s itself, for every event type", (_name, payload) => {
    for (const type of TYPES) {
      const text = sum(type, payload);
      expect(typeof text, type).toBe("string");
      expect(text.length, type).toBeGreaterThan(0);
    }
  });

  it("survives a payload with no payload at all, and one nested a hundred levels deep", () => {
    let deep: unknown = "end";
    for (let i = 0; i < 100; i++) deep = { before: deep, after: deep, changes: [deep] };
    for (const type of TYPES) {
      expect(sum(type, undefined).length, type).toBeGreaterThan(0);
      expect(sum(type, deep).length, type).toBeGreaterThan(0);
    }
  });

  it("is not fooled by a `__proto__` or `constructor` key in the payload", () => {
    const hostile = JSON.parse(
      '{"__proto__": {"role": "admin"}, "constructor": "x", "role": "tier1"}',
    );
    expect(sum("admin.user_created", hostile)).toBe("tạo tài khoản; vai trò Tier 1");
    expect(sum("admin.user_created", JSON.parse('{"__proto__": {"role": "admin"}}'))).toBe(
      "tạo tài khoản",
    );
    expect(sum("authz.denied", JSON.parse('{"__proto__": {"required": ["x"]}}'))).toBe(
      "bị từ chối quyền",
    );
  });

  it("cuts a long free text to one short line, and puts a one-line text on one line", () => {
    const long = sum("alert.reopened", { reason: "x".repeat(5000) });
    expect(long.length).toBeLessThan(200);
    expect(long.endsWith("…")).toBe(true);
    const lines = sum("alert.reopened", { reason: "dòng một\n\n  dòng hai\r\n\tdòng ba" });
    expect(lines).toBe("mở lại về hàng đợi Tier 1; lý do: dòng một dòng hai dòng ba");
  });

  it("shows the invisible and bidi characters of a text as their escapes", () => {
    const text = sum("alert.reopened", { reason: "a\u202eb\u200bc\u0001d\u007Fe" });
    expect(text).toContain("a\\u202eb\\u200bc\\u0001d\\u007fe");
    // The escapes are plain characters: nothing in the result is itself a format character.
    expect(hasInvisible(text)).toBe(false);
  });

  it("does not print a number that is not a finite number", () => {
    expect(sum("alert.enriched", { risk_score: Number.NaN })).toBe("làm giàu dữ liệu xong");
    expect(
      sum("alert.duplicate_merged", { parent: "a", occurrence: Number.POSITIVE_INFINITY }),
    ).toBe("gộp vào alert a");
  });
});

describe("subjectPathOf", () => {
  const ALERT_TYPES = [
    "alert.received",
    "alert.duplicate_merged",
    "alert.auto_closed",
    "alert.autoclose_blocked_critical",
    "alert.enrich_started",
    "alert.enriched",
    "alert.reopened",
    "alert.acknowledged",
    "tier1.decided",
    "tier1.escalated",
    "triage.suggested",
    "llm.gate_forced",
    "llm.builder_violation",
    "autoclose.reviewed",
    "label.created",
  ];
  const CASE_TYPES = ["case.opened", "case.truncated", "case.analyzed", "tier2.concluded"];

  it.each(ALERT_TYPES)("links the subject of %s to the alert", (event_type) => {
    expect(subjectPathOf({ event_type, subject_id: "1759012345.1662100" })).toBe(
      "/alerts/1759012345.1662100",
    );
  });

  it.each(CASE_TYPES)("links the subject of %s to the case", (event_type) => {
    expect(subjectPathOf({ event_type, subject_id: "0b30b853-1c2d-4e5f-8a9b-000000000001" })).toBe(
      "/cases/0b30b853-1c2d-4e5f-8a9b-000000000001",
    );
  });

  it("links no other event: a rule, a user, a job, a limit, a path, a check is text", () => {
    const linked = new Set([...ALERT_TYPES, ...CASE_TYPES]);
    const rest = TYPES.filter((type) => !linked.has(type));
    expect(rest.sort()).toEqual([
      "admin.autoclose_rule_toggled",
      "admin.job_retried",
      "admin.settings_changed",
      "admin.user_created",
      "admin.user_updated",
      "authz.denied",
      "health.alarm",
      "job.exhausted",
      "rule.suspected_wrong",
    ]);
    for (const event_type of rest) {
      expect(subjectPathOf({ event_type, subject_id: "abc" }), event_type).toBeNull();
    }
  });

  it("encodes an id, so a slash, a question mark or a space stays inside the one path segment", () => {
    expect(subjectPathOf({ event_type: "alert.received", subject_id: "a/b?c=d e#f" })).toBe(
      "/alerts/a%2Fb%3Fc%3Dd%20e%23f",
    );
    expect(subjectPathOf({ event_type: "case.opened", subject_id: "../x" })).toBe("/cases/..%2Fx");
  });

  it("links nothing for an empty subject, an unknown type, or a type from the prototype", () => {
    expect(subjectPathOf({ event_type: "alert.received", subject_id: "" })).toBeNull();
    expect(subjectPathOf({ event_type: "alert.brand_new", subject_id: "a" })).toBeNull();
    expect(subjectPathOf({ event_type: "constructor", subject_id: "a" })).toBeNull();
    expect(subjectPathOf({ event_type: "__proto__", subject_id: "a" })).toBeNull();
  });
});

describe("payloadText", () => {
  it("pretty-prints a payload as JSON with two spaces", () => {
    expect(payloadText({ a: 1, b: { c: [1, "x"] } })).toBe(
      '{\n  "a": 1,\n  "b": {\n    "c": [\n      1,\n      "x"\n    ]\n  }\n}',
    );
  });

  it("is empty for no payload, and says what a bare value is", () => {
    expect(payloadText(null)).toBe("");
    expect(payloadText(undefined)).toBe("");
    expect(payloadText("text")).toBe('"text"');
    expect(payloadText(42)).toBe("42");
    expect(payloadText([])).toBe("[]");
  });

  it("keeps markup as text, escapes a control character the way JSON does, and a bidi mark as a visible escape", () => {
    const text = payloadText({
      html: "<img src=x onerror=alert(1)></pre><script>window.pwned=1</script>",
      ctl: "a\u0001b\u001b[31m",
      bidi: "a\u202eb",
      del: "a\u007Fb",
    });
    expect(text).toContain("<img src=x onerror=alert(1)></pre><script>window.pwned=1</script>");
    expect(text).toContain("a\\u0001b\\u001b[31m");
    expect(text).toContain("a\\u202eb");
    expect(text).toContain("a\\u007fb");
    expect(hasInvisible(text)).toBe(false);
  });

  it("keeps the redaction marker of the server as it is", () => {
    expect(payloadText({ db: { password: "[đã ẩn]" } })).toContain('"password": "[đã ẩn]"');
  });

  it("returns a string of a megabyte and more without trouble", () => {
    const text = payloadText({ big: "x".repeat(1_000_000) });
    expect(text.length).toBeGreaterThan(1_000_000);
  });

  it("never throws: a cycle or a bigint (not JSON, but a payload is whatever it is) is still text", () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    expect(typeof payloadText(cycle)).toBe("string");
    expect(typeof payloadText(10n)).toBe("string");
    expect(payloadText(10n)).toContain("10");
  });
});

describe("tooBigSize", () => {
  it("reads the marker the server sends for a payload it did not send", () => {
    expect(tooBigSize({ truncated: true, size: 70000 })).toBe(70000);
  });

  it("is null for anything else, a payload that only looks like it included", () => {
    expect(tooBigSize(null)).toBeNull();
    expect(tooBigSize(undefined)).toBeNull();
    expect(tooBigSize({})).toBeNull();
    expect(tooBigSize({ truncated: true })).toBeNull();
    expect(tooBigSize({ truncated: false, size: 3 })).toBeNull();
    expect(tooBigSize({ truncated: true, size: "3" })).toBeNull();
    expect(tooBigSize({ truncated: true, size: -1 })).toBeNull();
    expect(tooBigSize({ truncated: true, size: 3.5 })).toBeNull();
    expect(tooBigSize({ truncated: true, size: 3, dropped: 1 })).toBeNull();
    expect(tooBigSize([{ truncated: true, size: 3 }])).toBeNull();
    expect(tooBigSize("truncated")).toBeNull();
  });
});

describe("hasInvisible", () => {
  it("is true for each character `visible` writes out, and false for text a person can read", () => {
    for (const code of [0x00, 0x08, 0x1b, 0x7f, 0x85, 0xad, 0x200b, 0x202e, 0x2066, 0xfeff]) {
      expect(hasInvisible(`a${String.fromCodePoint(code)}b`), code.toString(16)).toBe(true);
    }
    for (const text of ["", "Nhật ký audit — tiếng Việt", "a\tb\nc\r\nd", "<script>1</script>"]) {
      expect(hasInvisible(text), text).toBe(false);
    }
  });

  it("agrees with `visible`: a text it calls clean is returned by `visible` as it came", () => {
    for (const text of ["x", "tiếng Việt", `a${String.fromCodePoint(0x202e)}b`, "a\u0001b"]) {
      expect(hasInvisible(text) ? visible(text) !== text : visible(text) === text, text).toBe(true);
    }
  });
});

describe("visible", () => {
  it("leaves ordinary text alone, Vietnamese, tabs and line breaks included", () => {
    expect(visible("Nhật ký audit — tiếng Việt\tcó tab\nvà dòng")).toBe(
      "Nhật ký audit — tiếng Việt\tcó tab\nvà dòng",
    );
    expect(visible("")).toBe("");
  });

  it.each([
    ["\u0000", "\\u0000"],
    ["\u0008", "\\u0008"],
    ["\u001b", "\\u001b"],
    ["\u007f", "\\u007f"],
    ["\u0085", "\\u0085"],
    ["\u009f", "\\u009f"],
    ["\u00ad", "\\u00ad"],
    ["\u061c", "\\u061c"],
    ["\u200b", "\\u200b"],
    ["\u200f", "\\u200f"],
    ["\u2028", "\\u2028"],
    ["\u202a", "\\u202a"],
    ["\u202e", "\\u202e"],
    ["\u2066", "\\u2066"],
    ["\u2069", "\\u2069"],
    ["\ufeff", "\\ufeff"],
  ])("writes %j as the characters %j", (raw, shown) => {
    expect(visible(`a${raw}b`)).toBe(`a${shown}b`);
  });
});
