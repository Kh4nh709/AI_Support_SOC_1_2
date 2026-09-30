// Every user-facing label of the UI, in Vietnamese (spec §4). Components import `S`; none writes its own copy.
// The tables keyed by a server code (`status`, `band`, `conclusion`, ...) are read through `labelOf`, so a
// code this file has no label for is shown as the code itself.

/** The shortest quote ② may cite, in characters (`MIN_QUOTE_CHARS` of backend/app/tier2/investigate.py). */
export const MIN_QUOTE_CHARS = 8;

/**
 * The four risk bands: the code, and the label the server sends in `risk_band` (`tier1.queue.risk_band`,
 * `tier2.case_view.head_band`). This is the only place the two are paired.
 */
const BANDS = {
  critical: "Rất cao",
  high: "Cao",
  medium: "Vừa",
  low: "Thấp",
} as const;

export type BandCode = keyof typeof BANDS;

export const S = {
  app: {
    name: "AI Support SOC",
  },

  nav: {
    label: "Điều hướng chính",
    queue: "Hàng đợi",
    cases: "Case",
    adminLegacy: "Quản trị (UI cũ)",
    logout: "Đăng xuất",
  },

  // The chip beside the user name in the header, by `role`.
  role: {
    tier1: "Tier 1",
    tier2: "Tier 2",
    admin: "Admin",
  },

  // Shown on the queue after a route was refused to the signed-in role (RequireRole).
  forbidden: "Bạn không có quyền vào trang đó",

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

  // Risk bands: the "Mức" of the queue is `risk_band`, never the alert's `severity`. One table, by code;
  // the server sends the label, and `bandCodeOf` reads it back to the code the colours are keyed by.
  band: BANDS,

  // `severity` of a case and of an alert. It is a different word from the risk band, so it has its own table.
  severity: {
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
    model: "Mô hình",
    latency: "Thời gian",
    cost: "Chi phí",
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
    truncated: "[đã cắt]",
    showLog: "Xem log",
    hideLog: "Ẩn log",
    rawLogOf: (alertId: string) => `Log gốc — ${alertId}`,
    notFound: "Không tìm thấy case",
    summaryLabel: "Tóm tắt case",
    neverAnalysed: "chưa phân tích",
    clusterCount: (n: number) => `${n} cụm`,
    timeline: "Diễn biến",
    // What the case detail itself records: its creation, each note, the last run of ② and the conclusion.
    timelineCreated: "Case được tạo",
    timelineNote: (who: string) => `${who} thêm ghi chú`,
    timelineAnalysed: "Chạy phân tích AI ②",
    timelineConcluded: (who: string, conclusion: string) => `${who} kết luận: ${conclusion}`,
    notes: "Ghi chú",
    noNotes: "Chưa có ghi chú.",
    addNote: "Thêm ghi chú",
    saveNote: "Lưu ghi chú",
    noteInvalid: "Không lưu được ghi chú — nội dung trống hoặc quá dài",
    conclusionHeading: "Kết luận case",
    pickConclusion: "Chọn kết luận",
    // A 409 of the conclude: someone concluded the case first. `concludedBy` then says who and when.
    conflict: "Case đã được kết luận trước đó — kết luận của bạn chưa được ghi.",
    concludeInvalid: "Không ghi được kết luận — thiếu lý do hoặc lý do không hợp lệ",
    reasonOfConclusion: "Lý do",
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
    model: "Mô hình",
    tokens: "Token",
    cost: "Chi phí",
    // The 429 of `POST .../analyze` carries no count, so the sentence gives none.
    quotaExhausted: "Đã dùng hết lượt phân tích hôm nay",
    alreadyRunning: "Đang có một lượt phân tích chạy cho case này",
    concluded: "Case đã kết luận — không thể phân tích thêm",
    idle: "Chưa có phân tích nào cho case này.",
    idleClosed: "Case đã kết luận và chưa có phân tích nào.",
    reanalyze: "Phân tích lại",
    failedClosed: "Phân tích thất bại",
    stopped: (why: string) => `Phân tích không có kết quả: ${why}`,
    retryable: "có thể thử lại",
    resultAt: (when: string) => `Kết quả lúc ${when}`,
    snapshot: (alerts: number, occurrences: number, lastSeen: string | null) =>
      `Lúc phân tích: ${alerts} alert, ${occurrences} lần xuất hiện` +
      (lastSeen === null ? "." : `, alert mới nhất ${lastSeen}.`),
    current: (alerts: number, occurrences: number, lastSeen: string | null) =>
      `Hiện tại: ${alerts} alert, ${occurrences} lần xuất hiện` +
      (lastSeen === null ? "." : `, alert mới nhất ${lastSeen}.`),
    // `investigate_v2.confidence`; an unknown value is shown as it came.
    confidenceLevel: {
      low: "thấp",
      medium: "trung bình",
      high: "cao",
    },
    // Evidence marks (`evidence_check`): verified, or the reason the quote was rejected.
    unverified: "Chưa kiểm chứng",
    mark: {
      verified: "Đã kiểm chứng",
      quote_not_found: "Trích dẫn không có trong log hay mô tả của alert",
      not_in_case: "Alert này không thuộc case",
      quote_too_short: `Trích dẫn ngắn hơn ${MIN_QUOTE_CHARS} ký tự nên không kiểm chứng được`,
    },
    // `investigate_v2.suggested_conclusion`: the words of the backend's CONCLUSION_LABELS
    // (case_analyze_pages.py), which the Jinja page used; strings.test.ts compares the two. They are
    // not the three case-conclusion labels of `S.conclusion`, which name what Tier 2 decided.
    suggestedConclusion: {
      false_positive: "Không phải sự cố",
      policy_violation: "Có vi phạm nội quy, không phải tấn công",
      confirmed_incident: "Là sự cố thật",
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

/**
 * The band code of the label the server sent (`risk_band`: "Thấp", "Vừa", "Cao" or "Rất cao"), or `null`
 * for anything else: a label this UI does not know, `null` or a number. The caller shows such a label as
 * the text it is, in a neutral style, and never guesses a colour for it.
 */
export function bandCodeOf(label: unknown): BandCode | null {
  if (typeof label !== "string") return null;
  const codes = Object.keys(BANDS) as BandCode[];
  return codes.find((code) => BANDS[code] === label) ?? null;
}
