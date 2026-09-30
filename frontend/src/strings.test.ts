import { S, labelOf } from "./strings";

it("names the two Tier-1 closing decisions, escalate and reopen", () => {
  expect(S.decision.falsePositive).toBe("Đóng — dương tính giả");
  expect(S.decision.benign).toBe("Đóng — lành tính");
  expect(S.decision.acknowledge).toBe("Nhận xử lý");
  expect(S.decision.escalate).toBeTruthy();
  expect(S.decision.reopen).toBeTruthy();
});

it("labels the three case conclusions exactly", () => {
  expect(S.conclusion.concluded_fp).toBe("Dương tính giả");
  expect(S.conclusion.concluded_policy_violation).toBe("Vi phạm chính sách");
  expect(S.conclusion.confirmed_incident).toBe("Xác nhận sự cố");
  expect(Object.keys(S.conclusion).sort()).toEqual([
    "concluded_fp",
    "concluded_policy_violation",
    "confirmed_incident",
  ]);
});

it("keeps the scope note of a confirmed incident beside the conclusion", () => {
  expect(S.case.scopeNote).toMatch(/^Kết luận này chỉ ghi nhận sự cố/);
});

it("labels the four risk bands, the column 'Mức' is risk_band and not severity", () => {
  expect(Object.keys(S.band).sort()).toEqual(["critical", "high", "low", "medium"]);
  expect(S.queue.col.band).toBe("Mức");
});

it("labels every alert status the Jinja page labelled", () => {
  expect(S.status).toMatchObject({
    received: "Đã nhận",
    duplicate: "Bản sao",
    enriching: "Đang làm giàu dữ liệu",
    queued_tier1: "Chờ xử lý",
    tier1_active: "Đang xử lý",
    auto_closed: "Tự động đóng",
    escalated_tier2: "Đã chuyển tier 2",
    closed_fp: "Đã đóng — dương tính giả",
    closed_benign: "Đã đóng — lành tính",
    closed_confirmed: "Đã đóng — xác nhận sự cố",
  });
});

it("says 'ẩn — nhánh mù' for the blind arm and 'chưa có' for no result yet", () => {
  expect(S.ai1.hidden).toBe("ẩn — nhánh mù");
  expect(S.ai1.none).toBe("chưa có");
});

it("carries the two column headings and the live indicator", () => {
  expect(S.alert.infoHeading).toBe("THÔNG TIN ALERT");
  expect(S.alert.aiHeading).toBe("PHÂN TÍCH AI ①");
  expect(S.case.aiHeading).toBe("PHÂN TÍCH AI ②");
  expect(S.live.on).toBe("Trực tiếp");
  expect(S.live.off).toBe("Mất kết nối");
});

it("carries the login errors of the spec §3.1", () => {
  expect(S.login.invalid).toBe("Sai tên đăng nhập hoặc mật khẩu");
  expect(S.login.locked("09:45")).toBe("Tài khoản bị khoá đến 09:45");
  expect(S.login.disabled).toBe("Đăng nhập đang tắt");
});

it("carries the 503 copy of a decision and the two ② dead ends", () => {
  expect(S.decision.timeout).toBe("Hết thời gian xử lý, chưa ghi gì — thử lại");
  expect(S.ai2.stalled(5)).toBe("Chưa được xử lý sau 5 phút — kiểm tra worker");
  expect(S.ai2.failed).toBe("Phân tích thất bại — có thể thử lại");
});

it("names the four evidence marks of ②", () => {
  expect(Object.keys(S.ai2.mark).sort()).toEqual([
    "not_in_case",
    "quote_not_found",
    "quote_too_short",
    "verified",
  ]);
});

it("writes no English-only label where a Vietnamese one is named by the spec", () => {
  expect(S.app.name).toBe("AI Support SOC");
  expect(S.nav.adminLegacy).toBe("Quản trị (UI cũ)");
});

describe("labelOf", () => {
  it("returns the label of a known code", () => {
    expect(labelOf(S.status, "queued_tier1")).toBe("Chờ xử lý");
  });

  it("returns the raw code for a code with no label, never a blank", () => {
    expect(labelOf(S.status, "quarantined")).toBe("quarantined");
    expect(labelOf(S.band, "urgent")).toBe("urgent");
  });

  it("does not answer from the prototype chain", () => {
    for (const hostile of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
      expect(labelOf(S.status, hostile)).toBe(hostile);
    }
  });

  it("shows a dash for a missing code", () => {
    for (const missing of [null, undefined, ""]) {
      expect(labelOf(S.status, missing)).toBe("—");
    }
  });
});
