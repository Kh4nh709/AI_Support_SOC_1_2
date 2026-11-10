// src/features/admin/auditSummary.test.ts — what the audit page makes of an event's payload: the one-line
// summary of each of the 40 event types, the link of a subject that is an alert or a case, the payload as
// text, and the escape of the characters a person cannot see. A payload is whatever the writers of the
// events put there, so every function here is also shown to survive a payload of the wrong shape.
import { S } from "../../strings";
import { containsWord } from "../../testing/containsWord";
import {
  REDACTED,
  hasInvisible,
  isAlarmEvent,
  payloadText,
  subjectPathOf,
  summaryOf,
  tooBigSize,
  visible,
} from "./auditSummary";

const TYPES = Object.keys(S.admin.eventType);

const sum = (event_type: string, payload: unknown) => summaryOf({ event_type, payload });

describe("summaryOf, one event type at a time", () => {
  it("covers all 40 event types of the backend, and each has a case below", () => {
    expect(TYPES).toHaveLength(40);
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
    [
      "tier1.escalated",
      { case_id: "c-1", alert_ids: ["a"], llm_suggestion: null },
      "chuyển lên Tier 2, case c-1; 1 alert",
    ],
    ["tier1.escalated", null, "chuyển lên Tier 2"],
    // An event written before T2 (DEC-215) says how many correlated alerts the escalation swept in; one
    // written since says that none was taken along.
    [
      "case.opened",
      { trigger_alert_id: "a1", alert_count: 3, correlated_count: 2 },
      "mở từ alert a1; 3 alert, 2 liên quan",
    ],
    [
      "case.opened",
      { trigger_alert_id: "a1", alert_count: 1, correlated_count: 0 },
      "mở từ alert a1; 1 alert, không kéo theo alert liên quan",
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
    [
      "alert.archived",
      {
        reason: "DEC-212: dọn hàng đợi",
        before: "2026-10-30T20:15:00+07:00",
        from_status: "queued_tier1",
        decision: "DEC-212",
      },
      "lưu trữ khi dọn hàng đợi, không ai quyết định; trạng thái trước đó: Chờ xử lý; lý do: DEC-212: dọn hàng đợi",
    ],
    [
      "alert.archived",
      { from_status: "escalated_tier2", case_id: "c-1" },
      "lưu trữ khi dọn hàng đợi, không ai quyết định; trạng thái trước đó: Đã chuyển tier 2",
    ],
    ["alert.archived", null, "lưu trữ khi dọn hàng đợi, không ai quyết định"],
    [
      "case.archived",
      { reason: "DEC-212: dọn hàng đợi", from_status: "investigating", decision: "DEC-212" },
      "lưu trữ khi dọn hàng đợi, không ai kết luận; trạng thái trước đó: Đang điều tra; lý do: DEC-212: dọn hàng đợi",
    ],
    ["case.archived", null, "lưu trữ khi dọn hàng đợi, không ai kết luận"],
    ["case.analyzed", { run_id: "run-1", job_id: 77 }, "chạy phân tích ②; job 77"],
    ["case.analyzed", null, "chạy phân tích ②"],
    [
      "triage.suggested",
      { suggested_action: "true_positive", confidence: "high", forced: true, run_id: "x" },
      "đề xuất ①: TP; độ tin cậy cao; cổng kiểm soát đã ép kết quả",
    ],
    [
      "triage.suggested",
      { suggested_action: "false_positive", confidence: "low", forced: false },
      "đề xuất ①: FP; độ tin cậy thấp",
    ],
    ["triage.suggested", null, "đã có đề xuất ①"],
    [
      "llm.gate_forced",
      { proposed: "false_positive", final: "needs_review", forced_by: "critical", missing: [] },
      "cổng kiểm soát ép FP → Cần xem xét; do critical",
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
    // A field that is the same before and after is not a change (the canvas's own sample lists is_active twice).
    [
      "admin.user_updated",
      {
        username: "an.t2",
        before: { role: "tier1", is_active: true, display_name: "A" },
        after: { role: "tier2", is_active: true, display_name: "A" },
      },
      "an.t2: vai trò Tier 1 → Tier 2; phiên cũ bị đăng xuất",
    ],
    [
      "admin.user_updated",
      { username: "an.t2", before: { role: "tier2" }, after: { role: "tier2" } },
      "an.t2: cập nhật tài khoản",
    ],
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
      "duyệt: Không chắc; đề xuất ①: FP",
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
    // DEC-204: that someone labelled a cluster or undid it, never what they chose.
    [
      "label.created",
      {
        alert_id: "1759012345.1662100",
        labeler_id: "u",
        label: "false_positive",
        confidence: 2,
        gold_set: "gold_v2",
      },
      "gán nhãn cụm 1759012345.1662100; tập gold_v2",
    ],
    [
      "label.created",
      { alert_id: "a", labeler_id: "u", label: "benign", confidence: 1, gold_set: null },
      "gán nhãn cụm a",
    ],
    ["label.created", { undo: true, alert_id: "a", labeler_id: "u" }, "hoàn tác nhãn cụm a"],
    ["label.created", { undo: true }, "hoàn tác nhãn"],
    ["label.created", { gold_set: "gold_v2" }, "gán nhãn tập vàng; tập gold_v2"],
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
    // P13-T01 (DEC-210): the learned-knowledge events. A line may name the draft or the entry by its id and
    // carry the admin's reason; it never carries what the draft or the entry says (see the describe below).
    [
      "knowledge.drafted",
      { draft_id: "d-1", conclusion: "closed_fp" },
      "model đề xuất một bản nháp tri thức, chờ admin duyệt; bản nháp d-1",
    ],
    ["knowledge.drafted", null, "model đề xuất một bản nháp tri thức, chờ admin duyệt"],
    [
      "knowledge.approved",
      { entry_id: "e-1" },
      "admin duyệt bản nháp thành tri thức; tri thức e-1",
    ],
    ["knowledge.approved", {}, "admin duyệt bản nháp thành tri thức"],
    [
      "knowledge.rejected",
      { draft_id: "d-2", reason: "Quá chung chung, không có căn cứ" },
      "admin từ chối bản nháp; bản nháp d-2; lý do: Quá chung chung, không có căn cứ",
    ],
    ["knowledge.rejected", null, "admin từ chối bản nháp"],
    [
      "knowledge.retired",
      { entry_id: "e-3", reason: "Rule đã đổi" },
      "admin gỡ tri thức khỏi kho; tri thức e-3; lý do: Rule đã đổi",
    ],
    ["knowledge.retired", null, "admin gỡ tri thức khỏi kho"],
    [
      "knowledge.redraft_requested",
      { draft_id: "d-5" },
      "admin yêu cầu soạn lại bản nháp không có nội dung; bản nháp d-5",
    ],
    ["knowledge.redraft_requested", null, "admin yêu cầu soạn lại bản nháp không có nội dung"],
    [
      "knowledge.merged",
      { entry_id: "e-4" },
      "bản nháp gộp vào tri thức đã có, không tạo mục mới; tri thức e-4",
    ],
    ["knowledge.merged", null, "bản nháp gộp vào tri thức đã có, không tạo mục mới"],
    ["rag.lookup_failed", null, "tra cứu tri thức thất bại sau lần thử cuối"],
    ["rag.lookup_failed", { reason: "timeout" }, "tra cứu tri thức thất bại sau lần thử cuối"],
    [
      "rag.integrity_failed",
      { entry_id: "e-5" },
      "tệp tri thức không còn khớp mã băm lúc duyệt, mục bị loại khỏi tra cứu; tri thức e-5",
    ],
    [
      "rag.integrity_failed",
      null,
      "tệp tri thức không còn khớp mã băm lúc duyệt, mục bị loại khỏi tra cứu",
    ],
    [
      "lab.run_created",
      { run_id: "r-1", name: "Lần 1", purpose: "test" },
      "ghi nhận một lần chạy lab; tên: Lần 1; mục đích: để chấm điểm",
    ],
    [
      "lab.run_created",
      { run_id: "r-2", name: "Dựng KB", purpose: "kb" },
      "ghi nhận một lần chạy lab; tên: Dựng KB; mục đích: dựng cơ sở tri thức",
    ],
    ["lab.run_created", null, "ghi nhận một lần chạy lab"],
    [
      "lab.labeled",
      { alert_id: "a1", run_id: "r-1", label: "true_positive" },
      "gán nhãn: tấn công thật (TP)",
    ],
    [
      "lab.labeled",
      { alert_id: "a1", run_id: "r-1", label: "false_positive" },
      "gán nhãn: không phải tấn công (FP)",
    ],
    ["lab.labeled", { alert_id: "a1", run_id: "r-1", label: null }, "xoá nhãn lab"],
    ["lab.labeled", null, "gán nhãn lab"],
    ["lab.labeled", { label: {} }, "gán nhãn lab"],
  ])("%s %j says %j", (type, payload, summary) => {
    expect(sum(type, payload)).toBe(summary);
  });

  it("has a case for every one of the 40 types", () => {
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
        "alert.archived",
        "case.archived",
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
        "knowledge.drafted",
        "knowledge.approved",
        "knowledge.rejected",
        "knowledge.retired",
        "knowledge.merged",
        "knowledge.redraft_requested",
        "lab.run_created",
        "lab.labeled",
        "rag.lookup_failed",
        "rag.integrity_failed",
      ].sort(),
    );
    expect([...covered]).toEqual([...TYPES].sort());
  });
});

// DEC-210: a learned-knowledge event is about a draft or an entry, and a draft is written by a model from an
// analyst's own words. The audit page may say which draft or which entry, and an admin's reason for rejecting
// or retiring one; it must not repeat what the draft or the entry says. The server keeps no such text in these
// payloads, and the line must not depend on that: it reads `draft_id`, `entry_id` and `reason`, nothing else.
describe("the summary of a learned-knowledge event never shows a draft or an entry's content (DEC-210)", () => {
  const SECRET = "TEXT-OF-A-DRAFT-OR-ENTRY";
  const KNOWLEDGE = [
    "knowledge.drafted",
    "knowledge.approved",
    "knowledge.rejected",
    "knowledge.retired",
    "knowledge.merged",
    "knowledge.redraft_requested",
    "rag.lookup_failed",
    "rag.integrity_failed",
  ];
  const CONTENT_KEYS = [
    "draft",
    "content",
    "body",
    "fingerprint",
    "title",
    "summary",
    "text",
    "note",
    "match_notes",
    "matches",
    "history",
    "evidence",
    "warnings",
    "review_note",
    "conclusion",
    "category",
    "error",
  ];

  it.each(KNOWLEDGE)("%s repeats no field but the ids and the reason", (type) => {
    const payload = Object.fromEntries([
      ...CONTENT_KEYS.map((key) => [key, `${SECRET}-${key}`]),
      ["draft", { title: SECRET, body: SECRET }],
      ["entry", { content: SECRET }],
    ]);
    expect(sum(type, payload), type).not.toContain(SECRET);
    // With the ids and a reason added, only those three show, and the content still does not.
    const withIds = sum(type, { ...payload, draft_id: "d-9", entry_id: "e-9", reason: "vì sao" });
    expect(withIds, type).not.toContain(SECRET);
  });

  it("shows the id of a draft and of an entry, and the admin's reason, where the event has them", () => {
    expect(sum("knowledge.rejected", { draft_id: "d-9", reason: "vì sao" })).toContain("d-9");
    expect(sum("knowledge.rejected", { draft_id: "d-9", reason: "vì sao" })).toContain(
      "lý do: vì sao",
    );
    expect(sum("knowledge.retired", { entry_id: "e-9", reason: "vì sao" })).toContain("e-9");
    expect(sum("knowledge.retired", { entry_id: "e-9", reason: "vì sao" })).toContain(
      "lý do: vì sao",
    );
    expect(sum("knowledge.approved", { entry_id: "e-9" })).toContain("e-9");
    expect(sum("knowledge.drafted", { draft_id: "d-9" })).toContain("d-9");
  });

  it("cuts a long reason to one short line, as every other free text is", () => {
    const long = sum("knowledge.rejected", { reason: "x".repeat(5000) });
    expect(long.length).toBeLessThan(200);
    expect(long.endsWith("…")).toBe(true);
  });

  it("shows the invisible characters of an id or a reason as their escapes", () => {
    const text = sum("knowledge.retired", { entry_id: "e\u202e1", reason: "a\u200bb" });
    expect(text).toContain("e\\u202e1");
    expect(text).toContain("a\\u200bb");
    expect(hasInvisible(text)).toBe(false);
  });

  it("gives an audit row of a learned-knowledge event no link: its subject is a draft, an entry or a lookup", () => {
    for (const type of KNOWLEDGE) {
      expect(subjectPathOf({ event_type: type, subject_id: "abc" }), type).toBeNull();
    }
  });

  it("is not an alarm row: a failed lookup is told in the summary, not tinted like a refusal", () => {
    for (const type of KNOWLEDGE) expect(isAlarmEvent(type), type).toBe(false);
  });
});

// DEC-204: labelling is blind between the two labellers, and both are admins who can open this page. The audit
// read hides `label` and `confidence` of a `label.created` event on the server; the line must not depend on
// that. It states that someone labelled a cluster (or undid it), and never what they chose.
describe("the summary of a label.created event never shows a verdict (DEC-204)", () => {
  const LABELS = ["false_positive", "benign", "escalate"] as const;
  const SHOWN = ["dương tính giả", "lành tính", "chuyển tier 2", "độ tin cậy"];
  const base = { alert_id: "1759012345.1662100", labeler_id: "u-1", gold_set: "gold_v2" };
  const bare = "gán nhãn cụm 1759012345.1662100; tập gold_v2";

  it.each(LABELS.flatMap((label) => [1, 2, 3].map((confidence) => [label, confidence] as const)))(
    "says the same for label %s with confidence %s as for a payload that has neither",
    (label, confidence) => {
      const line = sum("label.created", { ...base, label, confidence });
      expect(line).toBe(bare);
      expect(line).toBe(sum("label.created", base));
      expect(line).not.toContain(label);
      expect(line).not.toMatch(new RegExp(`${confidence}\\s*/\\s*3`)); // "2/3", how a confidence was said
      for (const word of SHOWN) expect(line).not.toContain(word);
    },
  );

  it("says the same when the payload is the digest's (source digest labels a false positive)", () => {
    const line = sum("label.created", {
      ...base,
      gold_set: null,
      label: "false_positive",
      confidence: null,
      source: "digest",
    });
    expect(line).toBe("gán nhãn cụm 1759012345.1662100");
    expect(line).not.toMatch(/digest|dương tính giả|false_positive/);
  });

  it("says the same when the server redacted them: the marker is not read, and nothing fails", () => {
    const redacted = { ...base, label: "[đã ẩn]", confidence: "[đã ẩn]" };
    expect(sum("label.created", redacted)).toBe(bare);
    expect(sum("label.created", redacted)).not.toContain("[đã ẩn]");
    expect(sum("label.created", { ...base, label: "[đã ẩn]" })).toBe(bare);
    expect(sum("label.created", { ...base, confidence: "[đã ẩn]" })).toBe(bare);
  });

  it("does not read `label` or `confidence` whatever kind of value they hold", () => {
    const values = [null, 0, 3, "x", "", true, [], {}, { label: "benign" }, ["escalate"]];
    for (const value of values) {
      expect(sum("label.created", { ...base, label: value, confidence: value })).toBe(bare);
    }
  });

  it("says an undo is an undo, with the cluster, and no verdict", () => {
    const line = sum("label.created", {
      undo: true,
      alert_id: "a-1",
      labeler_id: "u-1",
      label: "escalate",
      confidence: 3,
    });
    expect(line).toBe("hoàn tác nhãn cụm a-1");
  });

  it("reads only the cluster, the gold set and the undo flag of the payload", () => {
    // Every other key set to a value that would show if it were read.
    const line = sum("label.created", {
      ...base,
      labeler_id: "LABELER-ID",
      label: "LABEL-VALUE",
      confidence: 99,
      source: "SOURCE-VALUE",
      note: "NOTE-VALUE",
      extra: { label: "NESTED-VALUE" },
    });
    expect(line).toBe(bare);
  });
});

// DEC-101, context pack §6.4: the server leaves ①'s suggestion off an alert that is blind and not yet decided,
// replacing every key that carries it with the marker, for every viewer. The line says it is withheld; it never
// puts the marker where a verdict would be, and never reads what is left of a payload the server cut down.
describe("the summary of an event whose suggestion the server withheld (DEC-101)", () => {
  const H = REDACTED;
  const A = S.admin.auditPage.summary;
  const WORDS = ["Cần xem xét", "độ tin cậy", "đã ép", " ép "];
  // the two labels of a verdict are found as words ("SFTP" in a payload is not a leak)
  const VERDICT_LABELS = ["TP", "FP"];
  const notShown = (line: string) => {
    expect(line).not.toContain(H);
    for (const word of WORDS) expect(line).not.toContain(word);
    for (const label of VERDICT_LABELS) expect(containsWord(line, label), label).toBe(false);
  };

  it("says triage.suggested is withheld, with no marker, no action and no confidence", () => {
    const line = sum("triage.suggested", {
      suggested_action: H,
      confidence: H,
      forced: H,
      run_id: H,
    });
    expect(line).toBe(A.suggestionHidden);
    notShown(line);
  });

  it.each(["suggested_action", "confidence", "forced", "run_id"])(
    "says it is withheld when only %s was withheld, and reads nothing else of the payload",
    (key) => {
      const payload = {
        suggested_action: "true_positive",
        confidence: "high",
        forced: true,
        run_id: "x",
      };
      const line = sum("triage.suggested", { ...payload, [key]: H });
      expect(line).toBe(A.suggestionHidden);
      notShown(line);
    },
  );

  it.each(["proposed", "final", "forced_by", "missing"])(
    "says llm.gate_forced is withheld when only %s was withheld",
    (key) => {
      const payload = { proposed: "false_positive", final: "needs_review", forced_by: ["step4"] };
      const line = sum("llm.gate_forced", { ...payload, [key]: H });
      expect(line).toBe(A.gateForcedHidden);
      notShown(line);
    },
  );

  it("says llm.gate_forced is withheld when the server took every key", () => {
    const line = sum("llm.gate_forced", { proposed: H, final: H, forced_by: H, missing: H });
    expect(line).toBe(A.gateForcedHidden);
    notShown(line);
  });

  it("keeps the verdict of a digest review and says its suggestion is withheld", () => {
    const line = sum("autoclose.reviewed", {
      verdict: "wrong",
      autoclose_rule_id: "r",
      suggested_action: H,
      run_id: H,
    });
    expect(line).toBe(`duyệt: Sai; ${A.suggestionHidden}`);
    notShown(line);
  });

  it("is unchanged when nothing was withheld (a visible head, or a decided one)", () => {
    expect(
      sum("triage.suggested", {
        suggested_action: "true_positive",
        confidence: "high",
        forced: true,
      }),
    ).toBe("đề xuất ①: TP; độ tin cậy cao; cổng kiểm soát đã ép kết quả");
    expect(sum("llm.gate_forced", { proposed: "false_positive", final: "needs_review" })).toBe(
      "cổng kiểm soát ép FP → Cần xem xét",
    );
  });

  it("does not fail on a withheld value of another kind, or on the marker as a whole payload", () => {
    for (const type of ["triage.suggested", "llm.gate_forced", "autoclose.reviewed"]) {
      expect(typeof sum(type, H)).toBe("string");
      expect(typeof sum(type, [H])).toBe("string");
      expect(typeof sum(type, { suggested_action: [H], proposed: { a: H } })).toBe("string");
    }
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
    "draft_id",
    "entry_id",
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
    "alert.archived",
  ];
  const CASE_TYPES = [
    "case.opened",
    "case.truncated",
    "case.analyzed",
    "tier2.concluded",
    "case.archived",
  ];

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
      "knowledge.approved",
      "knowledge.drafted",
      "knowledge.merged",
      "knowledge.redraft_requested",
      "knowledge.rejected",
      "knowledge.retired",
      "lab.labeled",
      "lab.run_created",
      "rag.integrity_failed",
      "rag.lookup_failed",
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

// The second list: characters that draw nothing (fillers, a blank braille cell, the grapheme joiner, the variation
// selectors) and the Tag characters, which spell ASCII text a person cannot see and a model may read. The tags are
// outside the BMP, so each is written as a code point: `\u{e0001}`. Every code point here is written as a number so
// that no source file holds a raw invisible character.
describe("visible, the invisible characters the first list missed", () => {
  const esc = (code: number) =>
    code > 0xffff ? `\\u{${code.toString(16)}}` : `\\u${code.toString(16).padStart(4, "0")}`;
  const span = (from: number, to: number) =>
    Array.from({ length: to - from + 1 }, (_, i) => from + i);
  const char = (code: number) => String.fromCodePoint(code);

  it.each([
    { code: 0x034f, name: "the combining grapheme joiner" },
    { code: 0x115f, name: "the Hangul choseong filler" },
    { code: 0x1160, name: "the Hangul jungseong filler" },
    { code: 0x2800, name: "the blank braille pattern" },
    { code: 0x3164, name: "the Hangul filler" },
    { code: 0xffa0, name: "the halfwidth Hangul filler" },
  ])("writes $name out", ({ code }) => {
    expect(visible(`a${char(code)}b`)).toBe(`a${esc(code)}b`);
    expect(hasInvisible(`a${char(code)}b`)).toBe(true);
  });

  it("writes out each of the sixteen variation selectors, U+FE00 to U+FE0F", () => {
    for (const code of span(0xfe00, 0xfe0f)) {
      expect(visible(`a${char(code)}b`), code.toString(16)).toBe(`a${esc(code)}b`);
      expect(hasInvisible(char(code)), code.toString(16)).toBe(true);
    }
  });

  it("writes out the Tag characters, U+E0001 and U+E0020 to U+E007F, each as one code point", () => {
    for (const code of [0xe0001, ...span(0xe0020, 0xe007f)]) {
      expect(visible(`a${char(code)}b`), code.toString(16)).toBe(`a\\u{${code.toString(16)}}b`);
      expect(hasInvisible(char(code)), code.toString(16)).toBe(true);
    }
    expect(visible(char(0xe0001))).toBe("\\u{e0001}");
    expect(visible(char(0xe007f))).toBe("\\u{e007f}");
  });

  it("leaves nothing of a sentence spelled in Tag characters but its escapes", () => {
    const hidden = [..."ignore previous instructions"]
      .map((c) => char(0xe0000 + c.charCodeAt(0)))
      .join("");
    const shown = visible(`visible text${hidden}`);
    expect(hasInvisible(`visible text${hidden}`)).toBe(true);
    expect(hasInvisible(shown)).toBe(false);
    expect(shown.startsWith("visible text\\u{e0069}\\u{e0067}")).toBe(true); // "i", "g": the escape of each
    expect(shown.match(/\\u\{e00[0-7][0-9a-f]\}/g)).toHaveLength(
      "ignore previous instructions".length,
    );
  });

  it("leaves the characters next to those alone", () => {
    for (const code of [
      0x034e, 0x0350, 0x1161, 0x2801, 0x3165, 0xfdfa, 0xfe10, 0xff9f, 0xffa1, 0xe0000, 0xe001f,
      0xe0080,
    ]) {
      expect(visible(`a${char(code)}b`), code.toString(16)).toBe(`a${char(code)}b`);
      expect(hasInvisible(char(code)), code.toString(16)).toBe(false);
    }
  });

  it("leaves text in other scripts as it is: Vietnamese in NFC and NFD, CJK, Hangul, Arabic, Hebrew, Thai", () => {
    const vietnamese = "Nguyễn Thị Hương, tiếng Việt: ặ ế ự ỡ Ơ Ư";
    for (const text of [
      vietnamese,
      vietnamese.normalize("NFC"),
      vietnamese.normalize("NFD"),
      "日本語の監査ログ 汉字 漢字 한국어 감사 로그",
      "مَرْحَبًا بِالعَالَم نص عربي مع تشكيل",
      "שָׁלוֹם עוֹלָם, יומן ביקורת",
      "ภาษาไทย บันทึกการตรวจสอบ",
      "𠮷野家 😀 𝒜 𐍈",
    ]) {
      expect(visible(text), text).toBe(text);
      expect(hasInvisible(text), text).toBe(false);
    }
    // NFD really is a different string with combining marks: the test is about marks, not about NFC alone.
    expect(vietnamese.normalize("NFD")).not.toBe(vietnamese.normalize("NFC"));
  });

  it("does not split a surrogate pair of an ordinary astral character", () => {
    expect(visible("a𠮷b😀c")).toBe("a𠮷b😀c");
    // A lone surrogate is not a valid character; it is left to JSON to write (`payloadText` does).
    expect(payloadText({ lone: String.fromCharCode(0xd800) })).toContain("\\ud800");
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
