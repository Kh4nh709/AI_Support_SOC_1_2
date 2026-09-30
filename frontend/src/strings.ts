// Every user-facing label of the UI, in Vietnamese (spec §4). Components import `S`; none writes its own copy.
// The tables keyed by a server code (`status`, `band`, `conclusion`, ...) are read through `labelOf`, so a
// code this file has no label for is shown as the code itself.

export const S = {
  app: {
    name: "AI Support SOC",
  },

  nav: {
    queue: "Hàng đợi",
    cases: "Case",
    adminLegacy: "Quản trị (UI cũ)",
    logout: "Đăng xuất",
  },

  live: {
    on: "Trực tiếp",
    off: "Mất kết nối",
  },

  common: {
    missing: "—",
    loading: "Đang tải…",
    retry: "Thử lại",
    copy: "Sao chép",
    copied: "Đã sao chép",
    prev: "« trang trước",
    next: "trang sau »",
    none: "Không có",
    unknownError: "Có lỗi xảy ra",
  },

  login: {
    title: "Đăng nhập",
    username: "Tên đăng nhập",
    password: "Mật khẩu",
    submit: "Đăng nhập",
    invalid: "Sai tên đăng nhập hoặc mật khẩu",
    locked: (until: string) => `Tài khoản bị khoá đến ${until}`,
    disabled: "Đăng nhập đang tắt",
  },

  // Risk bands: the "Mức" of the queue is `risk_band`, never the alert's `severity`.
  band: {
    critical: "Nghiêm trọng",
    high: "Cao",
    medium: "Trung bình",
    low: "Thấp",
  },

  // `alerts.status`, as the Jinja page labelled them (alerts_pages.STATUS_LABELS).
  status: {
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
  },

  queue: {
    title: "Hàng đợi Tier-1",
    count: (n: number) => `${n} cụm đang chờ`,
    empty: "Không có cụm nào đang chờ.",
    col: {
      band: "Mức",
      description: "Mô tả",
      category: "Category",
      agent: "Agent",
      occurrences: "Số lần",
      lastSeen: "Lần cuối",
      ai: "①",
    },
    filter: {
      band: "Mức",
      category: "Category",
      agent: "Agent",
      status: "Trạng thái",
      all: "Tất cả",
      waiting: "Chờ xử lý",
      mine: "Của tôi",
    },
  },

  // The ① cell of the queue and the ① column of the alert page.
  ai1: {
    heading: "Gợi ý ①",
    hidden: "ẩn — nhánh mù",
    none: "chưa có",
    forced: "⚑",
    pending: "Đang phân tích…",
    unavailable: "Không có gợi ý ①",
    decidedMine: "Quyết định của bạn",
    decidedAi: "Gợi ý ①",
    verdict: "Đề xuất",
    confidence: "Độ tin cậy",
    gate: "Cổng kiểm soát",
    verifier: "Bộ kiểm chứng",
    reasons: "Lý do",
    gateSteps: "Các bước của cổng",
    facts: "Dữ kiện đã dùng",
    quote: "Trích dẫn",
    source: "Nguồn",
  },

  alert: {
    infoHeading: "THÔNG TIN ALERT",
    aiHeading: "PHÂN TÍCH AI ①",
    notFound: "Không tìm thấy alert",
    summary: {
      severity: "Mức độ",
      category: "Category",
      status: "Trạng thái",
      rule: "Rule",
      level: "Level",
      agent: "Agent",
      occurrences: "Số lần xuất hiện",
      firstSeen: "Thấy lần đầu",
      lastSeen: "Gần nhất",
      acknowledgedBy: "Người tiếp nhận",
      case: "Case",
    },
    eventDetails: "Chi tiết sự kiện",
    rawLog: "Log gốc",
    rawLogTruncated: "[đã cắt]",
    accounts: "Tài khoản bị nhắm",
    noAccounts: "Không có tài khoản nào trong cụm.",
    correlation: "Tương quan ±2 giờ",
    noCorrelation: "Không có cụm tương quan trong ±2 giờ.",
    enrichment: "Ngữ cảnh làm giàu dữ liệu",
    asset: "Tài sản",
    identity: "Danh tính",
    ioc: "IOC",
    lookupStatus: "Trạng thái tra cứu",
    playbook: "Playbook",
    noPlaybook: "Không có playbook cho category này.",
  },

  decision: {
    heading: "Quyết định",
    acknowledge: "Nhận xử lý",
    falsePositive: "Đóng — dương tính giả",
    benign: "Đóng — lành tính",
    escalate: "Chuyển tier 2",
    reopen: "Mở lại",
    reason: "Lý do",
    reopenReason: "Lý do mở lại",
    caseTitle: "Tiêu đề case",
    severity: "Mức độ nghiêm trọng",
    submit: "Ghi quyết định",
    heldBy: (name: string) => `Đang được ${name} xử lý`,
    readOnly: "Chỉ Tier 1 thao tác được",
    autoClosed: "Alert này đã được tự động đóng.",
    fannedOut: (n: number) => `Đã đóng thêm ${n} alert tương quan`,
    caseOpened: "Đã mở case",
    goToCase: "Xem case",
    timeout: "Hết thời gian xử lý, chưa ghi gì — thử lại",
  },

  case: {
    listTitle: "Danh sách case",
    empty: "Chưa có case nào.",
    col: {
      title: "Tiêu đề",
      status: "Trạng thái",
      severity: "Mức độ",
      clusters: "Số cụm",
      alerts: "Số alert (gồm bản sao)",
      created: "Tạo lúc",
      lastAnalysed: "Phân tích gần nhất",
    },
    infoHeading: "THÔNG TIN CASE",
    aiHeading: "PHÂN TÍCH AI ②",
    ongoing: "Còn tiếp diễn",
    ongoingHint: (lastSeen: string) =>
      `Có alert mới đến lúc ${lastSeen} sau lần phân tích gần nhất — hãy chạy lại ②.`,
    heads: "Cụm cảnh báo",
    noHeads: "Case chưa có cảnh báo nào.",
    headCol: {
      description: "Mô tả",
      band: "Mức rủi ro",
      status: "Trạng thái",
      lastSeen: "Lần cuối thấy",
      rawLog: "Log gốc",
    },
    truncated: "đã cắt",
    timeline: "Diễn biến",
    notes: "Ghi chú",
    noNotes: "Chưa có ghi chú.",
    addNote: "Thêm ghi chú",
    saveNote: "Lưu ghi chú",
    conclusionHeading: "Kết luận case",
    // CONFIRMED_INCIDENT_SCOPE_NOTE (cases_pages.py), shown beside the "Xác nhận sự cố" choice.
    scopeNote:
      "Kết luận này chỉ ghi nhận sự cố — hệ thống dừng lại ở đây, không có bước cách ly, ứng cứu hay " +
      "khắc phục nào (hệ thống phát hiện và phân loại, không ứng cứu).",
    reasonRequired: "Lý do (bắt buộc)",
    concludeSubmit: "Kết luận",
    concludedBy: (name: string, when: string) => `Đã được ${name} kết luận lúc ${when}`,
  },

  // `cases.status`: the case is investigating, or concluded with one of the three conclusions.
  caseStatus: {
    investigating: "Đang điều tra",
    concluded_fp: "Dương tính giả",
    concluded_policy_violation: "Vi phạm chính sách",
    confirmed_incident: "Xác nhận sự cố",
  },

  // The three conclusions of `POST /api/tier2/cases/{id}/conclude`.
  conclusion: {
    concluded_fp: "Dương tính giả",
    concluded_policy_violation: "Vi phạm chính sách",
    confirmed_incident: "Xác nhận sự cố",
  },

  // A head's own `alerts.status` while it belongs to a case (cases_pages.HEAD_STATUS_LABELS).
  headStatus: {
    escalated_tier2: "Đang xử lý Tier 2",
    closed_fp: "Đã đóng — không phải sự cố",
    closed_benign: "Đã đóng — vi phạm nội quy",
    closed_confirmed: "Đã đóng — sự cố xác nhận",
  },

  ai2: {
    heading: "Trợ lý điều tra ②",
    disclaimer: "Đây chỉ là gợi ý của trợ lý — kết luận do Tier 2 quyết định.",
    analyze: "Phân tích",
    running: "Đang phân tích…",
    loading: "Đang tải phân tích…",
    stalled: (minutes: number) => `Chưa được xử lý sau ${minutes} phút — kiểm tra worker`,
    recheck: "Kiểm tra lại",
    failed: "Phân tích thất bại — có thể thử lại",
    lastResult: "Kết quả của lượt phân tích trước",
    stale: "Dữ liệu của case đã thay đổi kể từ lượt phân tích này.",
    suggested: "Kết luận gợi ý",
    confidence: "Độ tin cậy",
    summary: "Tóm tắt",
    narrative: "Diễn biến",
    hypotheses: "Giả thuyết",
    supporting: "Bằng chứng ủng hộ",
    counter: "Bằng chứng phản bác",
    noEvidence: "Trợ lý không đưa ra bằng chứng nào.",
    noCounterEvidence:
      "Mô hình không nêu bằng chứng phản bác nào cho giả thuyết này — kết quả không đúng định dạng " +
      "yêu cầu (mỗi giả thuyết phải có ít nhất một bằng chứng phản bác), hãy đọc giả thuyết này thận trọng.",
    nextSteps: "Bước tiếp theo",
    injection: "Cảnh báo tiêm lệnh (prompt injection)",
    quotaExhausted: (n: number) => `Đã dùng hết ${n} lượt phân tích hôm nay`,
    alreadyRunning: "Đang có một lượt phân tích chạy cho case này",
    concluded: "Case đã kết luận — không thể phân tích thêm",
    // Evidence marks (`evidence_check`): verified, or the reason the quote was rejected.
    mark: {
      verified: "Đã kiểm chứng",
      quote_not_found: "Trích dẫn không có trong log hay mô tả của alert",
      not_in_case: "Alert này không thuộc case",
      quote_too_short: "Trích dẫn quá ngắn nên không kiểm chứng được",
    },
    // `investigate_v2.suggested_conclusion`.
    suggestedConclusion: {
      false_positive: "Dương tính giả",
      policy_violation: "Vi phạm chính sách",
      confirmed_incident: "Xác nhận sự cố",
      need_more_data: "Cần thêm dữ liệu",
    },
    // `llm_runs.stopped_by` of a run with no result.
    stoppedBy: {
      cap: "đã chạm hạn mức chi phí LLM",
      permanent: "mô hình từ chối yêu cầu, lỗi không thể thử lại",
      linter: "dữ liệu của case không qua bộ kiểm tra an toàn trước khi gửi cho mô hình",
      schema: "mô hình trả lời sai định dạng, kể cả sau một lần sửa",
      transient: "mô hình không phản hồi sau nhiều lần thử",
    },
  },
} as const;

type Labels = Readonly<Record<string, unknown>>;

/**
 * The label of a server code, or the code itself when there is none: an unknown status, category,
 * `stopped_by` or conclusion is shown raw, never blank and never a crash. Only the table's own
 * string entries answer, so a hostile code such as `constructor` or `__proto__` is shown as text.
 */
export function labelOf(labels: Labels, code: string | null | undefined): string {
  if (code === null || code === undefined || code === "") return S.common.missing;
  const label = Object.hasOwn(labels, code) ? labels[code] : undefined;
  return typeof label === "string" ? label : code;
}
