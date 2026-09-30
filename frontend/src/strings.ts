// Every user-facing label of the UI, in Vietnamese (spec §4). Components import `S`; none writes its own copy.
// The tables keyed by a server code (`status`, `band`, `conclusion`, ...) are read through `labelOf`, so a
// code this file has no label for is shown as the code itself.

import { BAND_CODES, type BandCode } from "./api/types";

/** The shortest quote ② may cite, in characters (`MIN_QUOTE_CHARS` of backend/app/tier2/investigate.py). */
export const MIN_QUOTE_CHARS = 8;

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
    close: "Đóng",
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

  // Risk bands, the one label <-> code table (rulings R8 and R13), used by the queue and by the case pages.
  // The label is the text of the server's `risk_band` (queue.risk_band: Thấp/Vừa/Cao/Rất cao), which the
  // Jinja page and the canvas show; the code is what the queue's `band` filter and `counts_by_band` speak,
  // and what the colours are keyed by. Read a code through `labelOf`, and a row's label through
  // `bandCodeOfLabel`. The "Mức" of the queue is `risk_band`, never the alert's `severity`.
  band: {
    critical: "Rất cao",
    high: "Cao",
    medium: "Vừa",
    low: "Thấp",
  } satisfies Record<BandCode, string>,

  // `severity` of a case and of an alert. It is a different word from the risk band, so it has its own table.
  severity: {
    critical: "Nghiêm trọng",
    high: "Cao",
    medium: "Trung bình",
    low: "Thấp",
  },

  // `confidence` of ① (`low|medium|high`), read through `labelOf`.
  confidence: {
    low: "thấp",
    medium: "trung bình",
    high: "cao",
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
    countMine: (n: number) => `${n} cụm bạn đang xử lý`,
    emptyMine: "Bạn chưa nhận xử lý cụm nào.",
    tableLabel: "Các cụm alert đang chờ",
    loadError: "Không tải được hàng đợi",
    retriage: "Số lần xuất hiện đã tăng mạnh — cần phân tích lại",
    /** The sign beside a row that needs a new triage; its words are `retriage`. */
    retriageMark: "⟳",
    rule: (id: string) => `rule ${id}`,
    bandCounts: "Số cụm theo mức",
    bandChip: (label: string, n: number) => `${label} ${n}`,
    filtersLabel: "Bộ lọc hàng đợi",
    pagination: "Phân trang",
    range: (from: number, to: number, total: number) => `Hiển thị ${from}–${to} trên ${total}`,
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
      apply: "Lọc",
      clear: "Xoá bộ lọc",
    },
    noMatch: "Không có cụm nào khớp bộ lọc.",
    pageEmpty: "Trang này không có cụm nào.",
    page: (n: number) => `Trang ${n}`,
  },

  // The ① cell of the queue and the ① column of the alert page.
  ai1: {
    heading: "Gợi ý ①",
    hidden: "ẩn — nhánh mù",
    none: "chưa có",
    forced: "⚑",
    forcedLabel: "Cổng kiểm soát đã ép kết quả",
    // `suggested_action` of ① (output_guard.SUGGESTED_ACTIONS), read through `labelOf`.
    action: {
      false_positive: "Dương tính giả",
      needs_review: "Cần xem xét",
      escalate: "Chuyển tier 2",
    },
    pending: "Đang phân tích…",
    unavailable: "Không có gợi ý ①",
    unavailableBody: "① đã chạy nhưng không có đề xuất. Hãy quyết định dựa trên thông tin alert.",
    // `llm_runs.stopped_by` of a ① run with no result (backend/app/llm, tier1/triage_job.py), read through
    // `labelOf`: a code with no label here is shown as the code.
    stoppedBy: {
      linter: "dữ liệu alert không qua bộ kiểm tra an toàn trước khi gửi cho mô hình",
      cap: "đã chạm hạn mức chi phí LLM",
      schema: "mô hình trả lời sai định dạng, kể cả sau các lần thử lại",
      transient: "mô hình không phản hồi sau nhiều lần thử",
      disabled: "gợi ý ① đang tắt",
      permanent: "mô hình từ chối yêu cầu, lỗi không thể thử lại",
    },
    stoppedByLabel: "Lý do dừng",
    hiddenBody:
      "Alert này thuộc nhánh mù của pilot: bạn quyết định mà không thấy gợi ý ①. Gợi ý sẽ hiện sau khi bạn gửi quyết định.",
    pendingBody:
      "Alert đã vào hàng chờ phân tích. Trang tự cập nhật khi có kết quả; bạn vẫn có thể quyết định ngay.",
    decidedHeading: "Đã quyết — so sánh",
    decidedAi: "Gợi ý ①",
    // Whether ① and the person who decided agree (the pilot report's mapping, see agreement.ts).
    match: "Khớp",
    matchAgree: "có",
    matchDisagree: "không",
    matchNoVerdict: "không có đề xuất để so",
    // An alert closed by the system or by a Tier 2 conclusion: no Tier 1 person decided it, so there is
    // nobody to name and nothing to compare ① with.
    notTier1Decision: "Không phải quyết định của Tier 1 — không so với gợi ý ①",
    // What Tier 2 concluded on an alert Tier 1 escalated: context beside the escalation, never the decision
    // of the person who held the alert.
    tier2Concluded: (label: string) => `Tier 2 đã kết luận: ${label}`,
    verdict: "Đề xuất",
    confidence: "Độ tin cậy",
    gate: "Cổng kiểm soát",
    gateForced: "Bị ép",
    gateNotForced: "Không bị ép",
    gateForcedBy: "Ép bởi",
    gateProposed: "Đề xuất gốc",
    gateFinal: "Kết luận sau cổng",
    gateWarnings: "Cảnh báo của cổng",
    verifier: "Bộ kiểm chứng",
    analysedAt: "Phân tích lúc",
    correlatedThen: "Cụm tương quan lúc phân tích",
    correlatedChanged: (then: number, now: number) =>
      `gợi ý dựa trên ${then} cụm liên quan tại thời điểm phân tích; hiện có ${now}`,
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
    loadFailed: "Không tải được alert",
    duplicateOf: (headId: string) => `bản sao của ${headId}`,
    infoHint: "dữ liệu gốc từ Wazuh và phần làm giàu",
    aiHint: "gợi ý tham khảo — bạn là người quyết",
    summaryLabel: "Tóm tắt alert",
    summary: {
      rule: "Rule",
      level: "Level",
      agent: "Agent",
      occurrences: "Số lần xuất hiện",
      firstSeen: "Thấy lần đầu",
      lastSeen: "Gần nhất",
      acknowledgedBy: "Người tiếp nhận",
      acknowledgedAt: "Tiếp nhận lúc",
      closedAt: "Đóng lúc",
      closeReason: "Lý do đóng",
      case: "Case",
    },
    eventDetails: "Chi tiết sự kiện",
    field: {
      srcip: "IP nguồn (srcip)",
      dstip: "IP đích (dstip)",
      srcPort: "Cổng nguồn",
      dstPort: "Cổng đích",
      user: "Tài khoản đích",
      decoder: "Decoder",
      ruleGroups: "Nhóm rule",
      mitre: "MITRE ATT&CK",
      source: "Nguồn nạp",
      originHost: "Máy phát sinh",
      alertTime: "Thời điểm alert",
      eventTime: "Thời điểm sự kiện",
    },
    rawLog: "Log gốc",
    rawLogTruncated: "[đã cắt]",
    accounts: "Tài khoản bị nhắm",
    correlation: "Tương quan ±2 giờ",
    noCorrelation: "Không có cụm tương quan trong ±2 giờ.",
    correlationHint: (n: number) => `cùng agent hoặc cùng IP nguồn · ${n} cụm`,
    correlationColumns: {
      rule: "Rule",
      category: "Category",
      status: "Trạng thái",
      alerts: "Alert",
      span: "Đầu → cuối",
      srcIps: "Src IP",
    },
    correlationSamples: "Mẫu trong cửa sổ",
    enrichment: "Ngữ cảnh làm giàu dữ liệu",
    assetCriticality: "Mức quan trọng tài sản",
    assetOwner: "Chủ tài sản",
    assetRole: "Vai trò tài sản",
    identityPrivileged: "Danh tính đặc quyền",
    iocReputation: "Uy tín IP nguồn (IOC)",
    lookupStatus: "Trạng thái tra cứu",
    // `lookup_status` values of an enrichment source, read through `labelOf`.
    lookup: {
      found: "có",
      not_found: "không thấy",
      skipped: "bỏ qua",
    },
    yes: "có",
    no: "không",
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
    choose: "Chọn quyết định",
    reason: "Lý do",
    reasonHint: "Bắt buộc, tối đa 500 ký tự",
    reopenReason: "Lý do mở lại",
    caseTitle: "Tiêu đề case",
    severity: "Mức độ nghiêm trọng",
    submit: "Ghi quyết định",
    seenHint: (n: number) =>
      `Bạn đang xem ${n} lần xuất hiện — nếu số này đổi, hệ thống sẽ yêu cầu xem lại`,
    // Beside the count the form holds, when the alert now has more: the analyst is told, and the count is not changed.
    seenChanged: (held: number, now: number) =>
      `${held} → ${now}: cụm đã tăng khi bạn đọc — khi bạn gửi, hệ thống sẽ yêu cầu xem lại`,
    heldBy: (name: string) => `Đang được ${name} xử lý`,
    heldByOther: "Đang được người khác xử lý",
    decidedAs: (label: string) => `Đã quyết: ${label}`,
    notActionable: (label: string) => `Trạng thái: ${label} — chưa thể quyết định`,
    acknowledged: "Đã nhận xử lý",
    recorded: "Đã ghi quyết định",
    reopened: "Đã mở lại alert",
    loadingMe: "Đang xác định tài khoản của bạn…",
    meFailed: "Không xác định được tài khoản của bạn",
    sessionEnded:
      "Phiên đã hết hạn — đăng nhập lại để gửi. Lý do bạn đã nhập được giữ lại trong tab này.",
    invalid: "Dữ liệu chưa hợp lệ",
    // The 409 of a decision, worded as the Jinja page does (alerts_pages._conflict_text).
    conflict: {
      clusterGrew: (seen: number, now: number, delta: number, tolerance: number) =>
        `Cụm đã tăng từ ${seen} lên ${now} bản sao trong lúc bạn đọc (chênh ${delta} > ${tolerance}) — xem lại rồi xác nhận`,
      alreadyDecided: (by: string, what: string, when: string) =>
        `Đã được ${by} quyết ${what} lúc ${when}`,
      system: "hệ thống",
      alreadyInCase: "Alert đã thuộc một case khác — không thể chuyển tier 2 lại",
      notReopenable: "Alert không ở trạng thái tự động đóng nên không mở lại được",
      notActive: "Alert không còn ở trạng thái có thể thao tác — trang đã được tải lại",
    },
    autoClosed: "Alert này đã được tự động đóng.",
    fannedOut: (n: number) => `Đã đóng thêm ${n} alert tương quan`,
    caseOpened: "Đã mở case",
    goToCase: "Xem case",
    // For a reader who cannot open the case pages (Tier 1): the case is named, not linked.
    caseNumber: (id: number | string) => `case #${id}`,
    timeout: "Hết thời gian xử lý, chưa ghi gì — thử lại",
  },

  case: {
    listTitle: "Danh sách case",
    empty: "Chưa có case nào.",
    // A page after the first with no row on it: the list is not empty, the reader went past its end.
    pastEnd: "Không còn case ở trang này.",
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
    evidence: "Bằng chứng",
    noEvidence: "Trợ lý không đưa ra bằng chứng nào.",
    noCounterEvidence:
      "Mô hình không nêu bằng chứng phản bác nào cho giả thuyết này — kết quả không đúng định dạng " +
      "yêu cầu (mỗi giả thuyết phải có ít nhất một bằng chứng phản bác), hãy đọc giả thuyết này thận trọng.",
    nextSteps: "Bước tiếp theo",
    playbook: (name: string) => `Playbook: ${name}`,
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

/** The code of a risk-band label (`Rất cao` is `critical`), or null for a label this table does not have. */
export function bandCodeOfLabel(label: string | null | undefined): BandCode | null {
  if (label === null || label === undefined) return null;
  return BAND_CODES.find((code) => S.band[code] === label) ?? null;
}
