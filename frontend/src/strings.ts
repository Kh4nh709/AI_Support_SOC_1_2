// Every user-facing label of the UI, in Vietnamese (spec §4). Components import `S`; none writes its own copy.
// The tables keyed by a server code (`status`, `band`, `conclusion`, ...) are read through `labelOf`, so a
// code this file has no label for is shown as the code itself.

import type {
  AdminReason,
  AuditGroup,
  DigestVerdict,
  HardBlockCode,
  KnowledgeFault,
  LlmRange,
} from "./api/admin";
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
    // The in-app link to the admin console (P11-T10), admin only; it replaced the link to the old console.
    admin: "Quản trị",
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
  // The label is the text of the server's `risk_band` (queue.risk_band: Thấp/Vừa/Cao/Rất cao); the code is
  // what the queue's `band` filter and `counts_by_band` speak, and what the colours are keyed by. Read a
  // code through `labelOf`, and a row's label through `bandCodeOfLabel`. The "Mức" of the queue is
  // `risk_band`, never the alert's `severity`.
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

  // `alerts.status`, one label for each status the queue and the alert page can show.
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
      user: "User",
      srcip: "IP nguồn",
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
    /** The sort of the queue (P10-T14, DEC-164): the arrows of the sorted header and the way back to the risk order. */
    sort: {
      asc: "▲",
      desc: "▼",
      byRisk: "Sắp theo mức rủi ro",
    },
    noMatch: "Không có cụm nào khớp bộ lọc.",
    pageEmpty: "Trang này không có cụm nào.",
    page: (n: number) => `Trang ${n}`,
  },

  // The ① cell of the queue and the ① column of the alert page.
  ai1: {
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
    source: "Nguồn",
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
      `Bạn đang xem ${n} lần xuất hiện — nếu số này đổi, hệ thống có thể yêu cầu xem lại`,
    // Beside the count the form holds, when the alert now has more: the analyst is told, and the count is not changed.
    // "có thể", not "sẽ": the server asks for a review only past a tolerance (REVIEW_DELTA_TOLERANCE), and that
    // number is not shown here.
    seenChanged: (held: number, now: number) =>
      `${held} → ${now}: cụm đã tăng khi bạn đọc — khi bạn gửi, hệ thống có thể yêu cầu xem lại`,
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
    // The 409 of a decision (`decide.DecisionConflict`), one sentence for each kind: see conflict.ts.
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
    // `closed_count` counts the head itself with its duplicates: 1 is the alert alone, never "1 more".
    closedOne: "Đã đóng alert",
    closedCluster: (n: number) => `Đã đóng cụm (${n} alert)`,
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
    // What a "confirmed incident" conclusion does and does not mean, shown beside the "Xác nhận sự cố" choice.
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

  // A head's own `alerts.status` while it belongs to a case.
  headStatus: {
    escalated_tier2: "Đang xử lý Tier 2",
    closed_fp: "Đã đóng — không phải sự cố",
    closed_benign: "Đã đóng — vi phạm nội quy",
    closed_confirmed: "Đã đóng — sự cố xác nhận",
  },

  ai2: {
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
    // The 429 of `POST .../analyze` carries no count, so the sentence gives none.
    quotaExhausted: "Đã dùng hết lượt phân tích trong 24 giờ gần nhất",
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
    // (backend/app/tier2/investigation_view.py); strings.test.ts compares the two. They are
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

  // The admin console (P11-T10, spec §3): the sidebar, the page titles, the words every dialog shares, and
  // a text for each code the admin routes answer with. The page tasks add their own page's words under their
  // own key (`S.admin.users`, ...); what two pages share lives here.
  admin: {
    // The sidebar: the label of the navigation, then the seven links in the order of the canvas.
    nav: {
      label: "Quản trị",
      overview: "Tổng quan",
      users: "Người dùng & quyền",
      llm: "LLM & hạn mức",
      rules: "Rules tự đóng",
      digest: "Digest hằng ngày",
      labels: "Gán nhãn",
      knowledge: "Tri thức",
      audit: "Nhật ký audit",
    },
    // The h1 of each page (the canvas's own). The sidebar says it shorter.
    title: {
      overview: "Tổng quan hệ thống",
      users: "Người dùng và quyền",
      llm: "LLM và hạn mức",
      rules: "Rules tự đóng",
      digest: "Digest hằng ngày",
      labels: "Gán nhãn tập vàng",
      knowledge: "Tri thức học được",
      audit: "Nhật ký audit",
    },

    // The overview page (P11-T11, spec §4.1): the canvas's `AdminOverview` and the Tổng quan section of
    // `AdminStates`, in its words. A function takes what the server sent, already formatted by the page.
    overviewPage: {
      updated: (time: string) => `Cập nhật ${time}`,
      // A refresh that failed while an earlier answer is still on screen: the page says whose data it shows.
      refreshFailed: (time: string) => `Không làm mới được. Đang hiện dữ liệu lúc ${time}.`,
      rangeLabel: "Khoảng thời gian",

      // The range holds no alert: the cards say 0 and the chart is empty (AdminStates, "không có dữ liệu").
      emptyRange: (range: string) => `Không có alert nào trong ${range}`,
      emptyRangeHint:
        'Các ô số hiện 0, biểu đồ để trống. Nếu chờ đợi có alert, xem dòng "Lần kéo alert gần nhất" ở khối Sức khoẻ.',

      // A block or a card whose own section failed (`errors[]`); the others are served.
      blockFailed: "Không tải được khối này",
      tileFailed: "Không tải được",
      sectionError: {
        timeout: "Truy vấn quá thời gian cho phép.",
        query_failed: "Truy vấn thất bại.",
        unknown: "Máy chủ không trả khối này.",
      },

      kpi: {
        received: "Alert nhận vào",
        receivedSub: (range: string, heads: string) => `${range} · ${heads} head sau gộp`,
        waiting: "Cụm chờ Tier-1",
        waitingOldest: (time: string) => `cũ nhất: ${time}`,
        waitingNone: "không có cụm nào chờ",
        casesOpen: "Case đang mở",
        casesOpenSub: "đang được điều tra",
        llmCost: "Chi phí LLM tháng này",
        llmCap: (cap: string, pct: string) => `trần ${cap} · ${pct}`,
        llmCapUnknown: "không đọc được hạn mức",
        // P11-T20 row 50: the month's spend has reached the cap (`spent_usd >= cap_usd`); the share is left out,
        // because the route rounds it. The same fact as the LLM page's red cost tile, in one line.
        llmStopped: (cap: string) => `trần ${cap} · đã chạm trần, model dừng gọi`,
      },

      byDay: {
        title: "Alert nhận vào theo ngày",
        legend: "cột đậm: head mới · cột nhạt: bản sao gộp lại",
        chart: "Biểu đồ cột: alert nhận vào theo ngày",
        day: "Ngày",
        total: "Tổng",
        heads: "Head",
        duplicates: "Bản sao",
        bar: (label: string, total: string, heads: string, duplicates: string) =>
          `${label}: ${total} alert, ${heads} head, ${duplicates} bản sao`,
      },

      funnel: {
        title: "Tình trạng xử lý",
        auto_closed: "Tự động đóng (rules)",
        waiting: "Chờ Tier-1",
        active: "Tier-1 đang xử lý",
        closed_by_tier1: "Đã đóng bởi Tier-1",
        escalated: "Chuyển Tier-2",
        coverage: "Có gợi ý AI ① sẵn",
        ofHeads: (ready: string, heads: string) => `${ready} / ${heads}`,
      },

      bySource: {
        title: "Theo nguồn",
        source: "Nguồn",
        alerts: "Alert",
        heads: "Head",
        rejected: "bị từ chối khi nạp",
      },

      topAgents: {
        title: "Agent nhiều alert nhất",
        agent: "Agent",
        alerts: "Alert",
        empty: "Chưa có alert nào.",
      },

      health: {
        title: "Sức khoẻ hệ thống",
        okOfTotal: (ok: number, total: number) => `${ok}/${total} ổn`,
        none: "Chưa có lần kiểm tra sức khoẻ nào.",
        checkedAt: (time: string) =>
          `Lấy từ lần kiểm tra mới nhất (system_health), ${time}. Check lỗi đứng đầu danh sách.`,
        ok: "Ổn",
        failing: "Lỗi",
        // The thirteen checks of `infra/health.py` (the last three are DEC-210's), in the canvas's words; a name
        // with no label is shown as it is.
        check: {
          heartbeat: "Lần kéo alert gần nhất",
          intake_backlog: "Alert chờ nạp",
          job_backlog: "Job đang chờ trong worker",
          llm_null_ratio: "Lượt gọi model không có kết quả",
          triage_unavailable: "Gợi ý AI ① không khả dụng",
          monthly_cost: "Chi phí LLM so với trần",
          backup_age: "Bản sao lưu gần nhất",
          inventory_empty: "Kiểm kê tài sản",
          digest_unreviewed: "Digest hôm qua chưa duyệt",
          disk_free: "Dung lượng đĩa còn trống",
          knowledge_queue: "Hàng đợi tri thức chờ duyệt",
          knowledge_integrity: "Tệp tri thức khớp bản gốc",
          rag_budget: "Hạn mức chi phí RAG",
        },
      },

      jobs: {
        title: "Job lỗi",
        count: (n: number) => `${n} job`,
        // The server sends at most 50, the newest attempt first.
        countCapped: (n: number) => `${n} job gần nhất`,
        table: "Các job lỗi",
        job: "Job",
        type: "Loại",
        subject: "Đối tượng",
        attempts: "Đã thử",
        lastError: "Lỗi cuối",
        at: "Lúc",
        // The header of the column of buttons, read by a screen reader only.
        actions: "Thao tác",
        retry: "Chạy lại",
        retryJob: (id: number) => `Chạy lại job ${id}`,
        note: "Job đã hết số lần thử của worker. Chạy lại đặt job về hàng chờ và ghi audit.",
        empty: "Không có job lỗi nào.",
        dialogTitle: (id: number) => `Chạy lại job ${id}?`,
        times: (n: number) => `${n} lần`,
        dialogNote: "Job về lại hàng chờ của worker. Thao tác được ghi audit.",
        done: (id: number) => `Đã đặt job ${id} về hàng chờ.`,
      },

      // The learned knowledge (DEC-210, P13-T05): the queue of drafts, counts only. The review page is P13-T06's.
      knowledge: {
        title: "Tri thức",
        pending: "Bản nháp chờ duyệt",
        conflicts: "Trong đó mâu thuẫn với tri thức đã duyệt",
        open: "Mở trang duyệt",
      },

      inventory: {
        title: "Kiểm kê tài sản",
        assets: "Asset đang dùng",
        identities: "Identity",
        iocs: "IoC",
        loadedAt: "Nạp lần cuối",
        neverLoaded: "chưa nạp lần nào",
        reload: "Nạp lại kiểm kê",
        hint: "Đọc lại tệp kiểm kê trên máy chủ. Asset không có trong kiểm kê bị chặn cứng, không rule nào tự đóng được.",
        dialogTitle: "Nạp lại kiểm kê?",
        dialogRead: "Đọc lại",
        dialogAnd: "và",
        dialogRest:
          ", rồi cập nhật cơ sở dữ liệu. Mục không còn trong tệp bị vô hiệu hoá. Alert đã nạp trước đó không được tính lại.",
        confirm: "Nạp lại",
        loaded: (assets: number, identities: number, iocs: number, deactivated: number) =>
          `Đã nạp: ${assets} asset · ${identities} identity · ${iocs} IoC · ${deactivated} mục bị vô hiệu hoá`,
        warnings: (n: number) => `${n} cảnh báo`,
        refused: "Không nạp được — tệp kiểm kê không hợp lệ. Cơ sở dữ liệu không thay đổi.",
      },
    },

    common: {
      cancel: "Huỷ",
      confirm: "Xác nhận",
      save: "Lưu",
      saving: "Đang lưu…",
      // The confirm button of a dialog while its write is in flight, whatever the write is.
      working: "Đang xử lý…",
      loadError: "Không tải được trang",
      renderError: "Trang này gặp lỗi khi hiển thị.",
    },

    // `?range=` of the overview, the LLM usage and the audit page.
    range: {
      "24h": "24 giờ qua",
      "7d": "7 ngày qua",
      "30d": "30 ngày qua",
      month: "Tháng này",
    } satisfies Record<LlmRange, string>,

    // One text for each code of `ADMIN_REASONS` (api/admin.ts), in the words of the canvas's AdminStates
    // where it has one. Read a reason through `adminReasonText`, which puts the server's bounds in the text.
    reason: {
      username_taken: "Tên đăng nhập đã tồn tại",
      last_active_admin:
        "Không thể hạ quyền hoặc vô hiệu hoá admin hoạt động cuối cùng. Tạo hoặc kích hoạt một admin khác trước.",
      self_change:
        "Bạn không thể tự hạ quyền hoặc tự vô hiệu hoá tài khoản của mình. Nhờ một admin khác làm việc này.",
      not_found: "Không tìm thấy mục này.",
      empty: "Không được để trống",
      invalid: "Giá trị không hợp lệ",
      too_short: "Quá ngắn",
      too_long: "Quá dài",
      reserved: "Tên đăng nhập này được dành riêng cho hệ thống (system, llm)",
      unknown: "Trường này không được hỗ trợ",
      not_integer: "Phải là số nguyên",
      out_of_range: "Ngoài khoảng cho phép",
      limits_unavailable:
        "Không đọc được hạn mức đã lưu. Model đang dừng gọi để không vượt trần; chưa lưu được hạn mức.",
      timeout: "Truy vấn quá thời gian cho phép. Thu hẹp khoảng thời gian hoặc thêm bộ lọc.",
      query_failed: "Truy vấn thất bại. Thử lại sau ít phút.",
      not_failed:
        "Job không còn ở trạng thái lỗi — đã được chạy lại hoặc đã xong. Danh sách đã được tải lại.",
      already_queued:
        "Đã có một job cùng loại và cùng đối tượng đang chờ hoặc đang chạy, nên chưa chạy lại được.",
      bad_day: "Ngày không hợp lệ",
      not_in_digest: "Cụm này không có trong digest của ngày đã chọn.",
      already_reviewed:
        "Cụm này đã được duyệt trước đó. Dòng đã được cập nhật theo kết quả đã ghi.",
      not_auto_closed:
        "Cụm không còn ở trạng thái tự đóng (đã được mở lại), nên không duyệt được nữa.",
      // The reason of a refused undo and of a refused label save alike: it names neither.
      frozen: "Tập vàng đã đóng băng — không gán thêm hay hoàn tác được nữa.",
      nothing_to_undo: "Bạn chưa có nhãn nào để hoàn tác.",
      forbidden:
        "Bạn không còn quyền làm việc này. Vai trò của tài khoản có thể đã đổi — đăng nhập lại.",
      rule_not_found: "Không tìm thấy rule này. Danh sách đã được tải lại.",
      unknown_cluster: "Cụm này không nằm trong danh sách ứng viên",
      already_labelled: "Bạn đã gán nhãn cụm này rồi",
      labeler_mismatch: "Người gán nhãn phải là tài khoản đang đăng nhập",
    } satisfies Record<AdminReason, string>,
    // The same reasons with the server's bounds in them (`{field, reason, min?, max?}`).
    bounds: {
      tooShort: (min: number) => `Cần tối thiểu ${min} ký tự`,
      tooLong: (max: number) => `Tối đa ${max} ký tự`,
      outOfRange: (min: number, max: number) => `Phải từ ${min} đến ${max}`,
    },

    // The users page (P11-T12, spec §4.2), in the words of the canvas's AdminUsers and of the
    // "NGƯỜI DÙNG & QUYỀN" cards of AdminStates. The reasons the routes answer with are in `reason` above.
    usersPage: {
      // Under the h1: how many accounts there are.
      count: (n: number) => `${n} tài khoản · quyền cấp theo vai trò`,
      tableLabel: "Danh sách tài khoản",
      search: { label: "Tìm", placeholder: "username, tên…" },
      // The search found nothing (AdminStates "TÌM KHÔNG THẤY"), and the list that has no account at all.
      noMatch: {
        title: (query: string) => `Không có tài khoản khớp “${query}”`,
        hint: "Tìm theo tên đăng nhập hoặc tên hiển thị.",
        clear: "Xoá tìm kiếm",
      },
      empty: "Chưa có tài khoản nào.",
      col: {
        account: "Tài khoản",
        role: "Vai trò",
        status: "Trạng thái",
        lastLogin: "Đăng nhập cuối",
        actions: "Thao tác",
      },
      // The chip on the caller's own row.
      you: "bạn",
      neverLoggedIn: "chưa đăng nhập",
      status: {
        active: "Hoạt động",
        locked: (until: string) => `Bị khoá đến ${until}`,
        inactive: "Vô hiệu",
      },
      roleSelect: (username: string) => `Vai trò của ${username}`,
      // The buttons of a row. Each is named with its account (`rowAction`), the visible text first.
      action: {
        reset: "Đặt lại mật khẩu",
        unlock: "Mở khoá",
        reactivate: "Kích hoạt lại",
        deactivate: "Vô hiệu hoá",
      },
      rowAction: (action: string, username: string) => `${action} ${username}`,
      // The button of a row that holds its less common actions (a row menu).
      moreActions: (username: string) => `Thêm thao tác cho ${username}`,
      // What a write failed with when the server said nothing a person can read: the connection, or a 5xx.
      writeFailed: {
        network: "Không lưu được: mất kết nối máy chủ. Thử lại.",
        server: "Không lưu được: máy chủ trả lỗi. Thử lại sau ít phút.",
      },
      // The words a password form shares: the create form and the reset dialog.
      password: {
        short: (min: number, have: number) => `Cần tối thiểu ${min} ký tự, đang có ${have}`,
        mismatch: "Không khớp với mật khẩu",
        invalid: "Mật khẩu chứa ký tự không hợp lệ",
      },
      // The four dialogs (AdminStates). A refusal keeps the title and the alert and only the button "Đóng".
      dialog: {
        role: {
          title: (username: string) => `Đổi vai trò của ${username}?`,
          change: (from: string, to: string) => `${from} → ${to}`,
          body: (username: string) =>
            `Quyền đổi ngay. Mọi phiên đang mở của ${username} bị đăng xuất; lần đăng nhập sau sẽ có quyền mới.`,
          confirm: "Đổi vai trò",
        },
        deactivate: {
          title: (username: string) => `Vô hiệu hoá ${username}?`,
          body: (name: string) =>
            `${name} bị đăng xuất ngay và không đăng nhập được nữa. Các quyết định đã ghi vẫn giữ nguyên. Có thể kích hoạt lại sau.`,
          confirm: "Vô hiệu hoá",
        },
        // A light confirmation: it restores login with the old password, admin rights included.
        reactivate: {
          title: (username: string) => `Kích hoạt lại ${username}?`,
          body: "Tài khoản đăng nhập được ngay bằng mật khẩu hiện tại.",
          confirm: "Kích hoạt lại",
        },
        reset: {
          title: (username: string) => `Đặt lại mật khẩu cho ${username}`,
          password: "Mật khẩu tạm",
          repeat: "Nhập lại",
          hint: (min: number) =>
            `Tối thiểu ${min} ký tự. Báo mật khẩu tạm cho người dùng qua kênh riêng; trang không hiển thị lại.`,
          sessions: (username: string) => `Mọi phiên đang mở của ${username} bị đăng xuất.`,
          own: "Đây là tài khoản của bạn: đặt lại mật khẩu cũng đăng xuất mọi phiên của bạn, kể cả phiên này. Bạn sẽ phải đăng nhập lại.",
          confirm: "Đặt lại",
        },
        unlock: {
          title: (username: string) => `Mở khoá ${username}?`,
          body: (until: string, failed: number) =>
            `Tài khoản bị khoá đến ${until} sau ${failed} lần nhập sai mật khẩu. Mở khoá xoá số lần sai và cho đăng nhập ngay.`,
          confirm: "Mở khoá",
        },
      },
      // The note after a write (the toast).
      done: {
        role: (username: string, from: string, to: string) =>
          `Đã đổi vai trò của ${username} từ ${from} sang ${to}. Phiên cũ của người đó đã bị đăng xuất.`,
        deactivate: (username: string) => `Đã vô hiệu hoá ${username}. Người đó đã bị đăng xuất.`,
        reactivate: (username: string) => `Đã kích hoạt lại ${username}.`,
        reset: (username: string) =>
          `Đã đặt lại mật khẩu của ${username}. Báo mật khẩu tạm qua kênh riêng; trang không hiển thị lại.`,
        unlock: (username: string) => `Đã mở khoá ${username}.`,
        create: (username: string, role: string) =>
          `Đã tạo tài khoản ${username} (${role}). Báo mật khẩu tạm qua kênh riêng; trang không hiển thị lại.`,
      },
      // The create panel (the canvas's "Tạo người dùng").
      create: {
        title: "Tạo người dùng",
        username: "Tên đăng nhập",
        usernamePlaceholder: "vd. an.t1",
        displayName: "Tên hiển thị",
        role: "Vai trò",
        // The one line under each role (the canvas's).
        roleHelp: {
          tier1: "xử lý hàng đợi, quyết alert",
          tier2: "điều tra case, chạy ②, hỏi AI",
          admin: "mọi quyền, gồm quản trị người dùng và hạn mức",
        },
        password: "Mật khẩu tạm",
        repeat: "Nhập lại mật khẩu",
        hint: (min: number) =>
          `Tối thiểu ${min} ký tự. Mật khẩu chỉ lưu dạng băm argon2id, không hiển thị lại.`,
        submit: "Tạo tài khoản",
        // What the form can say before it posts, and the plainer words for the server's `invalid`.
        roleMissing: "Chưa chọn vai trò",
        usernameInvalid:
          "Chỉ dùng chữ thường a–z, số, dấu chấm, gạch dưới, gạch ngang; dài 3 đến 32 ký tự",
        displayNameInvalid: "Tên hiển thị không được chứa ký tự điều khiển hay ký tự vô hình",
      },
      // The read-only matrix of role to function (the canvas's nine rows), static text.
      matrix: {
        title: "Quyền theo vai trò",
        note: "đổi vai trò là đổi quyền; phiên cũ của người đó bị đăng xuất",
        feature: "Chức năng",
        yes: "có",
        no: "—",
        // What a screen reader says for the "—".
        noSpoken: "không",
        // [label, tier1, tier2, admin]
        rows: [
          ["Xem hàng đợi và chi tiết alert", true, true, true],
          ["Quyết định alert (đóng, chuyển Tier-2)", true, false, false],
          ["Xem và kết luận case", false, true, true],
          ["Chạy phân tích ② và hỏi AI", false, true, true],
          ["Quản trị rules tự đóng, digest", false, false, true],
          ["Gán nhãn đánh giá", false, false, true],
          ["Quản lý người dùng", false, false, true],
          ["Xem và chỉnh hạn mức LLM", false, false, true],
          ["Xem nhật ký audit, chạy lại job lỗi, nạp lại kiểm kê", false, false, true],
        ] satisfies readonly (readonly [string, boolean, boolean, boolean])[],
      },
    },

    // The LLM and limits page (P11-T13, spec §4.3): `/admin/llm`. Its words are here and nowhere else.
    llmPage: {
      subtitle: "Mọi lượt gọi model đều ghi vào llm_runs kèm token, thời gian và chi phí",
      rangeLabel: "Khoảng thời gian",
      // A background read failed while the page still shows the one before it.
      refreshFailed: "Không làm mới được dữ liệu — đang hiển thị lần tải trước.",
      loadErrorOffline:
        "Mất kết nối tới máy chủ. Thử lại sau ít phút; nếu lặp lại, xem Tổng quan → Sức khoẻ hệ thống.",
      loadErrorServer: (status: number) =>
        `Máy chủ trả lỗi ${status}. Thử lại sau ít phút; nếu lặp lại, xem Tổng quan → Sức khoẻ hệ thống.`,

      // The four tiles.
      cost: {
        title: "Chi phí tháng này",
        barLabel: "Chi phí tháng này so với trần",
        left: (usd: string) => `còn ${usd}`,
        projected: (usd: string) => `dự báo tuyến tính cuối tháng ${usd}`,
        // `warn` is at 80 % of the cap and below it; `stopped` is spent >= cap, whatever `pct` says.
        warn: (pct: string) =>
          `${pct} · sắp chạm trần. Khi chạm trần, mọi lượt gọi model dừng cho tới khi tăng trần hoặc sang tháng mới.`,
        stopped:
          "Model đã dừng gọi. Alert mới không có đề xuất ① (stopped_by = cap); ② báo hết hạn mức. Tăng trần ở khối Hạn mức hoặc chờ sang tháng.",
        noCap: "Không có trần để so sánh: không đọc được hạn mức.",
        // The canvas has no such note. `spent_usd` is the calendar month whatever the range says, and the
        // month begins at the midnight of the database session's time zone (`date_trunc('month', now())`).
        monthNote:
          "Tính cả tháng dương lịch, dù khoảng thời gian đang chọn là gì. Tháng bắt đầu lúc 0 giờ ngày 1, theo múi giờ của phiên cơ sở dữ liệu.",
      },
      calls: { title: "Lượt gọi model" },
      // The unit words after a figure (`llmFigures.ts`): millions of tokens ("2,44 tr") and seconds ("2,3 s").
      units: {
        million: (amount: string) => `${amount} tr`,
        seconds: (amount: string) => `${amount} s`,
      },
      tokens: {
        title: "Token vào / ra",
        average: (parts: string) => `trung bình ${parts}`,
        averageOf: (pipeline: string, tokens: string) => `${pipeline} ${tokens} vào`,
      },
      stoppedTile: {
        title: "Lượt dừng không có kết quả",
        none: "không có lượt nào dừng",
        // Over the runs of ① and ②, the verifier's calls left out: one failed alert is one stop.
        detail: (stopped: string, runs: string, main: string) =>
          `${stopped} / ${runs} lượt (không tính lượt verifier) · nhiều nhất: ${main}`,
      },

      // The pipelines of `llm_runs.pipeline` and, for ①, its two roles. There is no chat row: the column's
      // CHECK admits `triage`, `investigate` and, since migration 020 (DEC-210), `rag_lookup` and
      // `knowledge_draft`. Anything else is shown as it came.
      pipeline: {
        triage: "①",
        investigate: "②",
        triageRole: {
          proposer: "① triage · proposer",
          verifier: "① triage · verifier",
        },
        triageNoRole: "① triage",
        investigateRow: "② điều tra case",
        // DEC-210: the lookup of similar knowledge (role `retriever`) and the draft of a new entry (role `drafter`).
        // These are the labels of the runs that spend on the RAG sub-cap. A ① or ② run that READ a lookup is not
        // labelled here: it names the lookup (`llm_runs.rag_lookup_id`) only when the learned section reached its
        // prompt. When the token budget cut the section whole, the run's warnings name the cut
        // (`learned_entries_dropped`, `learned_history_dropped`, `learned_dropped`) and it has no lookup id.
        ragLookup: "Tra cứu tri thức",
        ragLookupRole: { retriever: "Tra cứu tri thức · retriever" },
        knowledgeDraft: "Soạn tri thức",
        knowledgeDraftRole: { drafter: "Soạn tri thức · drafter" },
      },
      // The short words of `llm_runs.stopped_by` for a table cell. `other` is the server's bucket for a reason
      // longer than a short code. A code with no word here is shown as the code (`labelOf`).
      stopped: {
        cap: "chạm trần chi phí",
        permanent: "bị từ chối, không thử lại",
        linter: "không qua kiểm tra an toàn",
        schema: "sai định dạng (schema)",
        transient: "mô hình không phản hồi",
        disabled: "① đang tắt",
        other: "lý do khác",
      },

      byPipeline: {
        title: "Theo pipeline",
        label: "Lượt gọi theo pipeline và vai trò",
        colPipeline: "Pipeline",
        colCalls: "Lượt",
        colWithResult: "Có kết quả",
        colStopped: "Dừng vì",
        colLatency: "Trễ p50 / p95",
        colCost: "Chi phí",
        // The server's tool-call count is always 0; the sentence is decision 4's.
        toolCalls: (count: number) =>
          count === 0 ? "Tool call: 0 — mô hình không gọi công cụ nào." : `Tool call: ${count}`,
      },
      noCalls: {
        title: (range: string) => `Chưa có lượt gọi model nào trong ${range}`,
        body: "Bảng theo pipeline để trống. Chọn khoảng thời gian dài hơn để xem.",
      },

      limits: {
        title: "Hạn mức",
        // The label of each editable field, and the shorter name the confirmation lists it by.
        field: {
          cap_usd: "Trần chi phí mỗi tháng (USD)",
          quota_per_24h: "Lượt ② mỗi người trong 24 giờ",
          timeout_s: "Thời gian chờ mỗi lượt gọi (giây)",
        },
        changeName: {
          cap_usd: "Trần chi phí mỗi tháng",
          quota_per_24h: "Lượt ② mỗi người trong 24 giờ",
          timeout_s: "Thời gian chờ mỗi lượt",
        },
        rangeHint: (min: number, max: number) => `Từ ${min} đến ${max}`,
        sourceEnv: "từ .env",
        sourceWeb: (by: string | null, at: string) =>
          by === null ? `sửa trên web lúc ${at}` : `sửa trên web bởi ${by} lúc ${at}`,
        clamped:
          "Giá trị đã lưu vượt mức tối đa hiện tại nên đang được giữ ở mức tối đa; lưu lại để ghi đúng giá trị.",
        save: "Lưu hạn mức",
        note: "Thay đổi có hiệu lực ngay và được ghi audit (người sửa, giá trị cũ → mới). Nếu không đọc được hạn mức đã lưu, model dừng gọi chứ không bỏ trần.",
        saved: "Đã lưu hạn mức. Có hiệu lực ngay.",
        // The two ways a save fails that no field or reason explains.
        saveOffline: "Không lưu được: mất kết nối máy chủ. Thử lại.",
        saveServer: "Không lưu được: máy chủ trả lỗi. Thử lại.",
      },
      confirm: {
        title: "Lưu hạn mức mới?",
        confirm: "Lưu",
        confirmAnyway: "Vẫn lưu",
        colLimit: "Hạn mức",
        colOld: "Cũ",
        colNew: "Mới",
        tableLabel: "Giá trị thay đổi",
        seconds: (value: number) => `${value} s`,
        // Spent >= the new cap is when the adapter stops: it compares `spent >= cap`.
        belowSpent: (cap: string, spent: string) =>
          `Trần mới ${cap} không cao hơn chi phí tháng này ${spent}. Model sẽ dừng gọi ngay sau khi lưu.`,
        note: "Chỉ liệt kê giá trị thay đổi. Có hiệu lực ngay cho lượt gọi tiếp theo và được ghi audit (người sửa, cũ → mới).",
      },
      // The read-only panel that replaces the form when the stored limits cannot be read (fail closed).
      failClosed: {
        title: "Không đọc được hạn mức đã lưu",
        body: "Model đang dừng gọi để không vượt trần, chứ không phải được gọi mà không có trần. Khối Hạn mức chỉ đọc cho tới khi đọc lại được. Kiểm tra cơ sở dữ liệu ở Tổng quan → Sức khoẻ hệ thống.",
      },

      quota: {
        title: "Dùng hạn mức ② · 24 giờ gần nhất",
        label: "Lượt ② của từng người trong 24 giờ gần nhất",
        limit: (count: number) => `Giới hạn ${count} lượt mỗi người`,
        limitUnknown: "Không đọc được giới hạn",
        colUser: "Người dùng",
        colUsed: "Lượt ②",
        colLeft: "Còn",
        exhausted: "0 · hết lượt",
        empty: "Chưa ai chạy ② trong 24 giờ gần nhất.",
        note: "Đếm trên 24 giờ gần nhất, không theo ngày lịch. Người hết lượt không chạy thêm được ② cho tới khi lượt cũ nhất quá 24 giờ.",
      },

      recent: {
        title: "Lượt gọi gần nhất",
        note: "20 lượt mới nhất, không phụ thuộc khoảng thời gian đang chọn",
        label: "Các lượt gọi model gần nhất",
        colAt: "Lúc",
        colPipeline: "Pipeline",
        colSubject: "Đối tượng",
        colTokens: "Token vào / ra",
        colLatency: "Trễ",
        colOutcome: "Kết quả",
        colCost: "Chi phí",
        empty: "Chưa có lượt gọi nào.",
        subject: (type: string, id: string) => `${type} ${id}`,
        // A run on an alert that is blind and not yet decided: the server sends no subject and no outcome
        // (DEC-101, context pack §6.4), and the cell says so, not "missing".
        hidden: "đã ẩn: alert chưa có quyết định",
        // `outcome` is `stopped:<stopped_by>` for a run with no verdict.
        stopped: (reason: string) => `dừng · ${reason}`,
        // A verifier's `outcome` is its own `structured_only_verdict` (from the facts and the decision
        // table alone), not whether it agreed with the proposer: the cell says so.
        verifier: (verdict: string) => `kết luận riêng: ${verdict}`,
      },
    },

    // The groups of the audit page's filter (`GROUPS` of admin_audit.py), in the canvas's words.
    auditGroup: {
      users: "Người dùng và quyền",
      configuration: "Rules, digest, hạn mức",
      alerts_cases: "Alert và case",
      model: "Model và cổng kiểm soát",
      system: "Hệ thống và job",
    } satisfies Record<AuditGroup, string>,

    // One label for each of the 35 names of `audit/events.py`'s EVENT_TYPES, read through `labelOf`. The
    // canvas gives nine; the rest follow its wording. An event with more than one use says the common part
    // (`admin.user_updated` is a role change, a deactivation, a reset and an unlock): the summary line of the
    // audit page says which.
    eventType: {
      "alert.received": "Alert được nhận",
      "alert.duplicate_merged": "Alert trùng được gộp",
      "alert.auto_closed": "Alert tự động đóng",
      "alert.autoclose_blocked_critical": "Chặn tự đóng alert nghiêm trọng",
      "alert.enrich_started": "Bắt đầu làm giàu dữ liệu",
      "alert.enriched": "Làm giàu dữ liệu xong",
      "alert.reopened": "Alert được mở lại",
      "job.exhausted": "Job hết số lần thử",
      "triage.suggested": "Model đưa đề xuất ①",
      "alert.acknowledged": "Tier 1 nhận xử lý",
      "tier1.decided": "Tier 1 quyết định",
      "tier1.escalated": "Tier 1 chuyển lên Tier 2",
      "case.opened": "Mở case",
      "case.truncated": "Case bị cắt bớt cụm",
      "case.analyzed": "Model phân tích case ②",
      "tier2.concluded": "Tier 2 kết luận case",
      "authz.denied": "Bị từ chối quyền",
      "admin.user_created": "Tạo người dùng",
      "admin.user_updated": "Cập nhật người dùng",
      "admin.job_retried": "Chạy lại job lỗi",
      "admin.autoclose_rule_toggled": "Bật/tắt rule tự đóng",
      "autoclose.reviewed": "Duyệt digest",
      "rule.suspected_wrong": "Rule bị nghi đóng nhầm",
      "llm.gate_forced": "Cổng kiểm soát ép kết quả ①",
      "llm.builder_violation": "Bộ kiểm tra an toàn chặn dữ liệu gửi model",
      "health.alarm": "Cảnh báo sức khoẻ",
      "label.created": "Gán nhãn tập vàng",
      "admin.settings_changed": "Sửa hạn mức LLM",
      "knowledge.drafted": "Model đề xuất tri thức",
      "knowledge.approved": "Duyệt tri thức",
      "knowledge.rejected": "Từ chối bản nháp tri thức",
      "knowledge.retired": "Gỡ tri thức",
      "knowledge.redraft_requested": "Yêu cầu soạn lại bản nháp tri thức",
      "knowledge.merged": "Gộp bản nháp vào tri thức",
      "rag.lookup_failed": "Tra cứu tri thức lỗi",
      "rag.integrity_failed": "Tệp tri thức không khớp bản gốc",
    },

    // The audit page (P11-T17, spec §4.7): `/admin/audit`, the canvas's `AdminAudit` and the "AUDIT" cards of
    // `AdminStates`. The texts of a 503 and a 403 it shows are `reason.timeout`, `reason.query_failed` and
    // `reason.forbidden` above; the label of an event is `eventType`, of a group `auditGroup`.
    auditPage: {
      subtitle: "Chỉ đọc · mọi thao tác ghi của người, hệ thống và model đều có một dòng ở đây",

      // The filter form: four filters, then the two buttons.
      filtersLabel: "Lọc nhật ký",
      rangeLabel: "Khoảng thời gian",
      groupLabel: "Nhóm sự kiện",
      groupAll: "Tất cả",
      actorLabel: "Người thực hiện",
      actorPlaceholder: "username, system, llm",
      subjectLabel: "Đối tượng",
      subjectPlaceholder: "mã alert, case, rule, user",
      apply: "Lọc",
      clear: "Xoá lọc",
      // A 422 that names a filter, said under that filter; and the line above the table, which also stands for
      // a 422 that names none of the four.
      fieldFault: (label: string) => `“${label}” không hợp lệ. Sửa lại rồi bấm Lọc.`,
      badFilter: "Bộ lọc không hợp lệ nên chưa có kết quả. Sửa bộ lọc, hoặc bấm Xoá lọc.",

      // The table.
      table: "Nhật ký audit",
      colToggle: "Chi tiết",
      colAt: "Thời điểm",
      colEvent: "Sự kiện",
      colActor: "Người thực hiện",
      colSubject: "Đối tượng",
      colSummary: "Tóm tắt",
      show: (event: string, at: string) => `Xem payload: ${event}, ${at}`,
      hide: (event: string, at: string) => `Ẩn payload: ${event}, ${at}`,
      payload: "payload",
      payloadNote:
        "giá trị của khoá nhạy cảm (mật khẩu, token, DSN, key) đã được server thay bằng “[đã ẩn]”",
      payloadLabel: (id: number) => `Payload của sự kiện ${id}`,
      noPayload: "Sự kiện này không ghi payload.",
      payloadTooBig: (bytes: string) =>
        `Payload quá lớn (${bytes} byte) nên server không gửi nội dung của nó.`,
      // The "Trước / Sau" of the cursor, and what is on screen: `from–to`, of `total` when the server counted.
      pager: "Phân trang nhật ký",
      prev: "Trước",
      next: "Sau",
      shown: (from: string, to: string) => `${from}–${to} · mới nhất trước`,
      shownOf: (from: string, to: string, total: string) =>
        `${from}–${to} trong ${total} sự kiện · mới nhất trước`,

      // The states.
      noMatchTitle: "Không có sự kiện khớp bộ lọc",
      noMatchBody: (filters: string) => `Bộ lọc đang dùng: ${filters}.`,
      filterGroup: (label: string) => `nhóm “${label}”`,
      filterActor: (value: string) => `người thực hiện “${value}”`,
      filterSubject: (value: string) => `đối tượng “${value}”`,
      emptyTitle: "Nhật ký chưa có sự kiện nào",
      emptyBody: (range: string) =>
        `Không có sự kiện nào trong ${range}. Mọi thao tác ghi sẽ hiện ở đây.`,
      // A page after the last one (the page before it was full, and nothing is older).
      endOfLog: "Không còn sự kiện nào cũ hơn.",
      timeoutNote:
        "Mọi truy vấn của trang chạy chỉ đọc, có giới hạn thời gian; trang không tự thử lại.",
      refreshFailed: "Không làm mới được nhật ký — đang hiển thị lần tải trước.",
      loadErrorOffline:
        "Mất kết nối tới máy chủ. Thử lại sau ít phút; nếu lặp lại, xem Tổng quan → Sức khoẻ hệ thống.",
      loadErrorServer: (status: number) =>
        `Máy chủ trả lỗi ${status}. Thử lại sau ít phút; nếu lặp lại, xem Tổng quan → Sức khoẻ hệ thống.`,
      // A 403 says `reason.forbidden` (one text for every admin page); only the way back is this page's.
      forbiddenBack: "Về hàng đợi",

      // The one-line summary of an event, built from its payload (`auditSummary.ts`). Each is a clause with
      // no capital and no full stop: a fact the payload holds. The summary joins the clauses with "; ".
      summary: {
        tooBig: (bytes: string) => `payload quá lớn (${bytes} byte), server không gửi nội dung`,
        received: "alert vào hệ thống",
        mergedInto: (parent: string) => `gộp vào alert ${parent}`,
        mergedUnknown: "gộp vào alert đã có",
        occurrence: (n: number) => `lần xuất hiện thứ ${n}`,
        autoClosedBy: (rule: string) => `đóng theo rule “${rule}”`,
        autoClosed: "đóng theo rule tự đóng",
        blockedCritical: "mức critical chặn tự đóng",
        blockedRule: (rule: string) => `rule ${rule} đã khớp`,
        enrichStarted: "bắt đầu làm giàu dữ liệu",
        enriched: "làm giàu dữ liệu xong",
        riskScore: (score: number) => `điểm rủi ro ${score}`,
        enrichExhausted: "hết lượt thử, không có dữ liệu bổ sung",
        reopened: "mở lại về hàng đợi Tier 1",
        reason: (text: string) => `lý do: ${text}`,
        acknowledged: "Tier 1 nhận alert để xử lý",
        decided: (status: string) => `quyết định: ${status}`,
        decidedUnknown: "quyết định của Tier 1",
        escalated: (caseId: string) => `chuyển lên Tier 2, case ${caseId}`,
        escalatedUnknown: "chuyển lên Tier 2",
        alertCount: (n: number) => `${n} alert`,
        caseOpened: (alert: string) => `mở từ alert ${alert}`,
        caseOpenedUnknown: "mở case",
        caseSize: (alerts: number, correlated: number) =>
          `${alerts} alert, ${correlated} liên quan`,
        truncated: (n: number) => `cắt ${n} cụm vượt giới hạn của case`,
        truncatedUnknown: "case bị cắt bớt cụm",
        concluded: (conclusion: string) => `kết luận: ${conclusion}`,
        concludedUnknown: "Tier 2 kết luận case",
        analyzed: "chạy phân tích ②",
        job: (id: number) => `job ${id}`,
        suggested: (action: string) => `đề xuất ①: ${action}`,
        suggestedUnknown: "đã có đề xuất ①",
        // The server withholds ①'s verdict of an alert that is blind and not yet decided (DEC-101, context
        // pack §6.4): a person's `autoclose.reviewed` is listed, its verdict is the marker, and the line says so
        // instead of a verdict. (`triage.suggested` and `llm.gate_forced` of such an alert are not listed at all,
        // DEC-206; their branches stay for a row an older server masked.)
        suggestionHidden: "đề xuất ① đã ẩn: alert chưa có quyết định",
        confidence: (level: string) => `độ tin cậy ${level}`,
        gateForced: "cổng kiểm soát đã ép kết quả",
        gateForcedBy: (proposed: string, final: string) =>
          `cổng kiểm soát ép ${proposed} → ${final}`,
        gateForcedUnknown: "cổng kiểm soát ép kết quả ①",
        gateForcedHidden: "kết quả của cổng kiểm soát ① đã ẩn: alert chưa có quyết định",
        forcedBy: (who: string) => `do ${who}`,
        builderViolation: (n: number) => `${n} vi phạm khi dựng dữ liệu gửi model`,
        builderViolationUnknown: "dữ liệu gửi model bị chặn",
        exhausted: (attempts: number) => `hết ${attempts} lần thử`,
        exhaustedUnknown: "hết số lần thử của worker",
        // `job.exhausted` reasons the system writes, by code; a code not here is shown as it came.
        exhaustedReason: { llm_transient: "model không phản hồi" } as Readonly<
          Record<string, string>
        >,
        userCreated: (username: string) => `tạo tài khoản ${username}`,
        userCreatedUnknown: "tạo tài khoản",
        roleIs: (role: string) => `vai trò ${role}`,
        userRole: (before: string, after: string) => `vai trò ${before} → ${after}`,
        userActivated: "kích hoạt lại tài khoản",
        userDeactivated: "vô hiệu hoá tài khoản",
        userRenamed: "đổi tên hiển thị",
        userPassword: "đặt lại mật khẩu",
        userUnlock: "mở khoá tài khoản",
        userSessionsEnded: "phiên cũ bị đăng xuất",
        userUpdatedUnknown: "cập nhật tài khoản",
        jobRetried: (type: string, id: string) => `chạy lại job ${type} #${id}`,
        jobRetriedUnknown: "chạy lại job lỗi",
        attemptsBefore: (n: number) => `trước đó đã thử ${n} lần`,
        denied: (role: string) => `tài khoản là ${role}`,
        deniedNeeds: (roles: string) => `cần vai trò ${roles}`,
        deniedRoleChanged: "vai trò đã đổi giữa chừng",
        deniedUnknown: "bị từ chối quyền",
        ruleToggled: (name: string, before: string, after: string) =>
          `“${name}”: ${before} → ${after}`,
        ruleToggledUnknown: "bật/tắt rule tự đóng",
        on: "bật",
        off: "tắt",
        reviewed: (verdict: string) => `duyệt: ${verdict}`,
        reviewedUnknown: "duyệt digest",
        suspectedWrong: (count: number, window: string) =>
          `${count} cụm bị duyệt “Sai” trong ${window}`,
        suspectedUnknown: "rule bị nghi đóng nhầm",
        window: (days: number) => `${days} ngày`,
        recently: "thời gian gần đây",
        // `label.created` says only that someone labelled a cluster, or undid it, and which one: never what
        // they chose. The verdict is not for the other labeller to read (DEC-204), so these words have no
        // place for a label or a confidence.
        labelled: (cluster: string) => `gán nhãn cụm ${cluster}`,
        labelledUnknown: "gán nhãn tập vàng",
        labelUndone: (cluster: string) => `hoàn tác nhãn cụm ${cluster}`,
        labelUndoneUnknown: "hoàn tác nhãn",
        goldSet: (name: string) => `tập ${name}`,
        limitChange: (name: string, from: string, to: string) => `${name} ${from} → ${to}`,
        limitUnknown: "đổi hạn mức LLM",
        // The three limits, with the unit each is counted in.
        limitName: {
          LLM_MONTHLY_USD_CAP: "trần chi phí (USD mỗi tháng)",
          ANALYZE_QUOTA_PER_USER_DAY: "hạn mức phân tích ② (lượt mỗi người trong 24 giờ)",
          LLM_TIMEOUT_S: "thời gian chờ mỗi lượt gọi (giây)",
        } as Readonly<Record<string, string>>,
        alarmNew: (names: string) => `mới lỗi: ${names}`,
        alarmFailing: (names: string) => `đang lỗi: ${names}`,
        alarmUnknown: "cảnh báo sức khoẻ",
        // The learned-knowledge events (DEC-210) name a draft or an entry by its id and carry an admin's
        // reason, and say nothing of what a draft or an entry contains: that text comes from an analyst's
        // own words, and the audit page is not where it is read.
        knowledgeDrafted: "model đề xuất một bản nháp tri thức, chờ admin duyệt",
        knowledgeApproved: "admin duyệt bản nháp thành tri thức",
        knowledgeRejected: "admin từ chối bản nháp",
        knowledgeRetired: "admin gỡ tri thức khỏi kho",
        knowledgeRedraft: "admin yêu cầu soạn lại bản nháp không có nội dung",
        knowledgeMerged: "bản nháp gộp vào tri thức đã có, không tạo mục mới",
        lookupFailed: "tra cứu tri thức thất bại sau lần thử cuối",
        integrityFailed: "tệp tri thức không còn khớp mã băm lúc duyệt, mục bị loại khỏi tra cứu",
        draftId: (id: string) => `bản nháp ${id}`,
        entryId: (id: string) => `tri thức ${id}`,
      },
    },

    // The six hard blocks (`_HARD_BLOCK_ORDER` of admin_rules.py), word for word, keyed by code. The order is
    // `HARD_BLOCK_CODES` of api/admin.ts. A test keeps both equal to the backend.
    hardBlock: {
      critical: "Mức độ nghiêm trọng = critical",
      never_autoclose_agent: "Agent nằm trong NEVER_AUTOCLOSE_AGENTS",
      asset_high: "Asset trọng yếu (asset.criticality = high)",
      asset_not_in_inventory: "Asset không có trong kiểm kê (inventory)",
      identity_privileged: "Danh tính đặc quyền (identity_privileged)",
      ioc_bad: "IoC malicious hoặc suspicious",
    } satisfies Record<HardBlockCode, string>,

    // `/admin/rules` (P11-T14, spec §4.4): the words of the rules page. The six hard-block texts above are
    // reused as they are; the reasons of a failed write come from `S.admin.reason` (`rule_not_found`,
    // `forbidden`) and the rest from here.
    rulesPage: {
      subtitle: (total: number, enabled: number) =>
        `Rule chỉ đóng cụm đã qua sáu chặn cứng · ${total} rule, ${enabled} đang bật`,
      create: "Tạo rule mới",
      loadFailed: "Không tải được danh sách rule",
      hardBlocks: {
        label: "Sáu chặn cứng",
        title: "Sáu chặn cứng (G8′) — luôn chạy trước mọi rule",
        note: "Một cụm dính bất kỳ chặn nào thì không rule nào đóng được nó, kể cả rule khớp mọi thứ",
      },
      empty: {
        title: "Chưa có rule tự đóng nào",
        body: "Mọi cụm đều vào hàng đợi Tier 1. Khối sáu chặn cứng vẫn hiện ở đầu trang.",
      },
      table: {
        label: "Các rule tự đóng",
        nameAndReason: "Tên và lý do",
        conditions: "Điều kiện",
        width: "Độ rộng 7 ngày",
        created: "Tạo lúc",
        state: "Trạng thái",
        action: "Thao tác",
        on: "bật",
        off: "tắt",
        turnOn: "Bật",
        turnOff: "Tắt",
        turnOnLabel: (name: string) => `Bật rule ${name}`,
        turnOffLabel: (name: string) => `Tắt rule ${name}`,
        noConditions: "Không có điều kiện: khớp mọi cụm",
        widthWarning: (pct: string, threshold: string) => `⚠ ${pct}% > ${threshold}%`,
        widthNote: (threshold: string) =>
          `Độ rộng = tỉ lệ alert của 7 ngày qua (tính cả bản sao) mà rule đã đóng. Vượt ${threshold}% (AUTOCLOSE_RULE_WIDTH_PCT) thì cảnh báo: rule có thể đang đóng cả alert thật.`,
      },
      toggle: {
        offTitle: (name: string) => `Tắt rule “${name}”?`,
        offBody:
          "Từ giờ các cụm khớp rule này vào hàng đợi Tier 1. Cụm đã bị đóng trước đó không tự mở lại. Thao tác được ghi audit.",
        offConfirm: "Tắt rule",
        onTitle: (name: string) => `Bật rule “${name}”?`,
        onBody:
          "Từ giờ các cụm khớp rule này, sau khi qua sáu chặn cứng, sẽ được tự đóng và không vào hàng đợi Tier 1. Thao tác được ghi audit.",
        onConfirm: "Bật rule",
        doneOff: (name: string) => `Đã tắt rule “${name}”.`,
        doneOn: (name: string) => `Đã bật rule “${name}”.`,
        failed: "Chưa đổi được trạng thái rule. Thử lại sau ít phút.",
      },
      builder: {
        step: "Bước 1/2 · nhập điều kiện",
        name: "Tên",
        reason: "Lý do",
        conditions: "Điều kiện — mọi điều kiện đều phải khớp",
        group: (n: number) => `Điều kiện ${n}`,
        field: "Trường",
        op: "Phép so",
        value: "Giá trị",
        remove: "Xoá điều kiện",
        add: "+ Thêm điều kiện",
        none: "Chưa có điều kiện nào: rule này khớp mọi cụm đã qua sáu chặn cứng. Xem trước để biết nó sẽ đóng bao nhiêu cụm.",
        help: "Chỉ các trường và phép so mà bộ máy cho phép mới chọn được. Phép in nhận nhiều giá trị, cách nhau bằng dấu phẩy.",
        placeholder: {
          text: "giá trị",
          integer: "số nguyên, ví dụ 443",
          list: "a, b, c",
          integerList: "22, 443",
          cidr: "10.0.0.0/8",
          prefix: "tiền tố",
        },
        problem: {
          not_integer: "Phải là số nguyên, ví dụ 443",
          list_empty: "Nhập ít nhất một giá trị",
          list_blank_item: "Danh sách có một giá trị rỗng giữa hai dấu phẩy",
          not_boolean: "Chọn true hoặc false",
        },
        emptyEq: "Giá trị đang để trống: điều kiện này chỉ khớp chuỗi rỗng.",
        emptyPrefix: "Tiền tố rỗng khớp mọi giá trị chuỗi.",
        neverCloses: (field: string, values: string) =>
          `Chặn cứng chạy trước mọi rule: cụm có ${field} = ${values} không bao giờ bị rule đóng.`,
        preview: "Xem trước",
        previewing: "Đang xem trước…",
        submit: "Tạo rule",
        submitting: "Đang tạo rule…",
        hintIdle:
          "Nút “Tạo rule” chỉ mở sau khi đã xem trước đúng bộ điều kiện đang nhập. Sửa điều kiện thì phải xem trước lại.",
        hintStale:
          "Điều kiện đã đổi sau lần xem trước gần nhất. Xem trước lại để mở nút “Tạo rule”.",
        hintNeedText: "Nhập tên và lý do của rule.",
        hintReady:
          "Rule được tạo ở trạng thái bật và áp dụng ngay cho các alert nhận từ giờ. Xem trước đã tính cả sáu chặn cứng.",
        created: (name: string) => `Đã tạo rule “${name}”. Rule đang bật.`,
        conditionRejected:
          "Máy chủ từ chối điều kiện: có trường hoặc phép so ngoài danh sách cho phép, hoặc giá trị sai dạng. Chưa tạo rule nào; phần đã nhập vẫn còn nguyên.",
        conditionMalformed:
          "Máy chủ không đọc được điều kiện vì sai dạng. Chưa tạo rule nào; phần đã nhập vẫn còn nguyên.",
        previewFailed: "Chưa xem trước được. Điều kiện vẫn còn nguyên — thử lại sau ít phút.",
        createFailed: "Chưa tạo được rule. Điều kiện vẫn còn nguyên — thử lại sau ít phút.",
      },
      preview: {
        title: "Kết quả xem trước",
        step: "Bước 2/2 · 30 ngày qua, đã tính sáu chặn cứng",
        idle: "Chưa có kết quả. Bấm “Xem trước” để chạy thử các điều kiện trên 30 ngày dữ liệu; chưa có gì được ghi.",
        running: "Đang chạy thử trên 30 ngày dữ liệu…",
        stale:
          "Kết quả bên dưới là của bộ điều kiện trước khi sửa. Xem trước lại để có kết quả mới.",
        clusters: "Cụm sẽ bị đóng",
        alerts: "Alert, gồm bản sao",
        bySeverity: "Theo mức độ",
        byAsset: "Theo asset criticality",
        samples: "Alert mẫu (tối đa 20) — mở trong trang alert",
        tallyMatched: (n: string) => `Rule khớp ${n} cụm nhưng cả ${n} bị chặn cứng:`,
        tallyNone: "Rule không khớp cụm nào trong 30 ngày qua.",
        tallyNote:
          "Bạn vẫn tạo được rule này, nhưng với dữ liệu hiện tại nó sẽ không đóng được cụm nào.",
      },
    },

    // The daily digest page (P11-T15, spec §4.5): `/admin/digest`. Its words are here and nowhere else; the
    // texts of its refusals are the shared `S.admin.reason` ones, except the two the canvas words for a row.
    digestPage: {
      subtitle: "Duyệt từng cụm mà rule đã tự đóng trong ngày",
      dayLabel: "Ngày",
      today: "Hôm nay (đến giờ)",
      // The day the server fell back to, `dd/mm/yyyy` (`formatDay`), after a day the server refused.
      badDay: (day: string) => `Ngày không hợp lệ — đang hiển thị ${day}.`,
      // A read after a review failed while the page still shows the list it had.
      refreshFailed: "Không làm mới được danh sách — đang hiển thị lần tải trước.",
      loadErrorOffline: "Không kết nối được máy chủ. Kiểm tra mạng rồi thử lại.",
      loadErrorServer: (status: number) =>
        `Máy chủ trả lỗi ${status}. Thử lại sau ít phút; nếu lặp lại, xem Tổng quan → Sức khoẻ hệ thống.`,
      summary: {
        clusters: (n: number) => `${n} cụm tự đóng`,
        reviewed: (done: number, waiting: number) => `${done} đã duyệt · ${waiting} chờ duyệt`,
        disagreements: (n: number) => `${n} cụm ① không đề xuất đóng`,
      },
      table: {
        label: "Các cụm đã tự đóng trong ngày",
        colRule: "Rule tự đóng",
        colRuleDesc: "Rule · mô tả",
        colSeverity: "Mức độ",
        colAgent: "Agent",
        colCount: "Số lần",
        colSpan: "Khoảng thời gian",
        colSuggestion: "Đề xuất ①",
        colReview: "Duyệt",
      },
      // ① has no suggestion for the cluster yet.
      noSuggestion: "(chưa có kết quả ①)",
      // A row a "Sai" review reopened is blind again while it is undecided (A17, DEC-101): the server leaves
      // ①'s verdict off it, and "no result" would be a wrong thing to say.
      reopenedNoSuggestion: "(không hiện sau khi mở lại về hàng đợi Tier 1)",
      disagreement: "⚠ ① không đề xuất đóng",
      // The name of the group of the three buttons of a row (the buttons themselves are `S.admin.verdict`).
      group: (ruleId: string, agent: string) => `Duyệt cụm ${ruleId} · ${agent}`,
      reviewed: (verdict: string) => `Đã duyệt: ${verdict}`,
      reopened: "đã mở lại về hàng đợi Tier 1",
      // A refused review, said in the row it was for.
      invalidVerdict: "Đánh giá không hợp lệ. Dòng giữ nguyên, chưa ghi gì.",
      notAutoClosed: (cluster: string) =>
        `Cụm ${cluster} không còn ở trạng thái tự đóng (đã được mở lại), nên không duyệt được nữa.`,
      // A write that failed with no word of its own (a 5xx, the network): `status` 0 is no answer at all.
      saveFailed: (status: number) =>
        status === 0
          ? "Không lưu được: mất kết nối máy chủ. Thử lại."
          : `Không lưu được: máy chủ trả lỗi ${status}. Thử lại.`,
      noRules: {
        title: "Không có gì để duyệt",
        body: "Chưa có rule tự đóng nào đang bật, nên không có cụm nào bị tự đóng.",
        link: "Đến Rules tự đóng",
      },
      noClusters: {
        title: (day: string) => `Không có cụm nào bị tự đóng ngày ${day}`,
        body: "Chọn ngày khác hoặc xem hôm nay.",
      },
      legend: {
        disagreement: "① không đồng ý với việc tự đóng: nên xem trước",
        reviewed: "Đã duyệt (mờ đi)",
        wrong: '"Sai" mở lại cụm về hàng đợi Tier 1 và đánh dấu rule có thể sai.',
      },
    },

    // The verdicts of a digest review (`_VERDICT_LABEL` of admin_digest.py).
    verdict: {
      correct: "Đúng",
      wrong: "Sai",
      unsure: "Không chắc",
    } satisfies Record<DigestVerdict, string>,

    // The blind labelling page (P11-T16, spec §4.6): `/admin/labels`. Its words are here and nowhere else.
    // Nothing on it names the model, a suggestion, an alert page or a case: the page is blind (DEC-019, DEC-101).
    labelsPage: {
      subtitle:
        "Gán nhãn mù và độc lập: trang chỉ hiện dữ kiện của alert, mỗi người một thứ tự riêng",
      progress: {
        label: "Đã gán",
        bar: "Tiến độ gán nhãn",
        of: (done: number, total: number) => `${done} / ${total}`,
      },
      // Why the page could not be read, under the shared title `S.admin.common.loadError`.
      loadErrorOffline: "Mất kết nối tới máy chủ. Thử lại sau ít phút.",
      loadErrorServer: (status: number) => `Máy chủ trả lỗi ${status}. Thử lại sau ít phút.`,
      // The token holds no user id the page can read: it asks the server for nothing else, so it stops here.
      sessionUnreadable:
        "Không đọc được phiên đăng nhập của bạn. Đăng nhập lại rồi mở lại trang này.",
      // The server says a cluster is next but sends none: never guessed, the page asks again.
      clusterMissing: "Máy chủ báo còn cụm để gán nhưng không gửi nội dung cụm. Thử lại.",

      // The current state of the gold set (`eval/gold_v1.sha256` exists): progress only.
      frozen: {
        title: "Tập vàng gold_v1 đã đóng băng",
        badge: "Đã đóng băng — chỉ xem tiến độ",
        body: (total: number) =>
          `${total} cụm, đã ghi mã sha256. Không gán thêm hay hoàn tác được nữa. Nhãn mới chỉ vào một bộ mới (gold_v2), không ghi đè gold_v1.`,
      },
      finished: {
        title: (total: number) => `Bạn đã gán nhãn toàn bộ ${total} cụm`,
        body: "Nhãn của người gán còn lại không hiện ở đây. Đối chiếu bất đồng làm sau khi cả hai xong.",
      },
      noCandidates: {
        title: "Chưa có cụm nào để gán nhãn",
        before: "Chưa dựng tệp ứng viên",
        file: "eval/gold_candidates.csv",
      },

      // The cluster on screen: only the fields `labels/next` sends (`VIEW_KEYS` of tier1/labels.py).
      cluster: {
        label: "Cụm đang gán nhãn",
        rule: "rule",
        level: (level: string) => `(level ${level})`,
        clusterId: "cụm",
        alertTitle: "Alert đại diện",
        time: "Thời điểm",
        agent: "Agent",
        user: "User",
        route: "Src → Dst",
        description: "Mô tả",
        rawLog: "raw_log",
        rawLogCut: "raw_log dài hơn 32 KB: đã cắt ở 32 KB khi hiển thị.",
        seen: (count: number, first: string, last: string) =>
          `Xuất hiện ${count} lần · từ ${first} đến ${last}`,
        playbook: "Playbook",
      },
      correlation: {
        title: "Tương quan ±2 giờ",
        table: "Cụm tương quan trong ±2 giờ",
        colRule: "Rule",
        colCategory: "Loại",
        colClusters: "Số cụm",
        colAlerts: "Số alert",
        colFirst: "Đầu",
        colLast: "Cuối",
        empty: "Không có cụm tương quan trong ±2 giờ.",
        samples: "Mẫu raw_log của các cụm tương quan",
        sample: (rule: string, category: string, severity: string, count: number, time: string) =>
          `${rule} · ${category} · ${severity} · ×${count} · ${time}`,
      },

      // The form. The three labels are `LABEL_CHOICES` of api/admin.ts and the three confidences
      // `LABEL_CONFIDENCES`; a test keeps the keys equal.
      form: {
        title: "Nhãn cho cụm này",
        label: "Nhãn",
        choices: {
          false_positive: "Báo động giả",
          benign: "Thật nhưng vô hại",
          escalate: "Cần chuyển Tier 2",
        },
        confidence: "Độ chắc chắn",
        confidences: { 1: "1 thấp", 2: "2 vừa", 3: "3 cao" },
        note: "Ghi chú (một dòng)",
        noteCount: (used: number, max: number) => `${used} / ${max}`,
        save: "Lưu nhãn và sang cụm tiếp",
        undo: "Hoàn tác nhãn vừa gán",
        undoing: "Đang hoàn tác…",
        hint: "Chỉ hoàn tác được khi tập vàng chưa đóng băng. Nhãn của bạn không hiện với người gán nhãn còn lại.",
        noLabel: "Chọn một nhãn trước khi lưu.",
      },

      // What the writes say. A refusal the server names (`frozen`, `already_labelled`, ...) is read from
      // `S.admin.reason`; these are the ones it does not name.
      notice: {
        saved: (clusterId: string, done: number, total: number, next: string | null) =>
          `Đã lưu nhãn cụm ${clusterId}. Đã gán ${done} / ${total}. ${
            next === null ? "Bạn đã xong phần của mình." : `Cụm tiếp: ${next}.`
          }`,
        undone: (clusterId: string, done: number, total: number) =>
          `Đã hoàn tác nhãn cụm ${clusterId}. Đã gán ${done} / ${total}.`,
        // A refusal that makes the page read again is said beside the NEXT cluster's form: it names the cluster it
        // was about, so it is not read as about the one on screen.
        aboutCluster: (clusterId: string, text: string) => `Cụm ${clusterId}: ${text}`,
        invalid: "Nhãn không hợp lệ. Kiểm tra lại nhãn, độ chắc chắn và ghi chú.",
        saveServer: (status: number) =>
          `Máy chủ trả lỗi ${status}. Nhãn chưa được lưu — thử lại sau ít phút.`,
        saveOffline: "Mất kết nối tới máy chủ. Nhãn chưa được lưu — thử lại khi có mạng.",
        undoServer: (status: number) =>
          `Máy chủ trả lỗi ${status}. Chưa hoàn tác được — thử lại sau ít phút.`,
        undoOffline: "Mất kết nối tới máy chủ. Chưa hoàn tác được — thử lại khi có mạng.",
      },
    },

    // The learned-knowledge page (DEC-210, P13-T06, spec §7.5): the drafts the model wrote from the analysts'
    // conclusions, for an admin to edit and approve, or reject; and the entries approved, to retire. The `409` and
    // `503` of its writes are worded here (`notice`), the V1-V5 faults of a `422` in `fault`; the page never shows a
    // server text. The words an admin needs to find are the spec's own: Duyệt, Sửa rồi duyệt, Từ chối, Gỡ.
    knowledgePage: {
      subtitle:
        "Bản nháp do mô hình viết từ kết luận của analyst. Chỉ mục được admin duyệt mới được ① và ② tra cứu.",
      tabsLabel: "Bản nháp và mục tri thức",
      // The five tabs, in the order of the spec. The first, third and fourth list drafts, the others entries.
      tab: {
        pending: "Chờ duyệt",
        active: "Đã duyệt",
        merged: "Đã gộp",
        rejected: "Từ chối",
        retired: "Đã gỡ",
      },
      tableLabel: {
        pending: "Bản nháp chờ duyệt",
        active: "Mục tri thức đã duyệt",
        merged: "Bản nháp đã gộp",
        rejected: "Bản nháp bị từ chối",
        retired: "Mục tri thức đã gỡ",
      },
      // A tab with nothing in it is not an error: it says what the tab is for.
      empty: {
        pending:
          "Không có bản nháp nào chờ duyệt. Bản nháp mới đến sau khi analyst đóng alert hoặc kết luận case.",
        active:
          "Chưa có mục tri thức nào được duyệt. Duyệt một bản nháp để ① và ② bắt đầu tra cứu.",
        merged:
          "Chưa có bản nháp nào được gộp. Bản nháp giống một mục đã duyệt được gộp vào mục đó, không cần duyệt.",
        rejected: "Chưa có bản nháp nào bị từ chối.",
        retired: "Chưa có mục nào bị gỡ.",
      },
      loadFailed: "Không tải được danh sách",
      // The route sends 200 rows at most.
      listLimited: (n: number) => `Chỉ hiện ${n} mục đầu tiên của danh sách.`,
      pendingCount: (total: number, conflicts: number) =>
        conflicts === 0
          ? `${total} bản nháp chờ duyệt`
          : `${total} bản nháp chờ duyệt, ${conflicts} mâu thuẫn với tri thức đã duyệt (xếp lên đầu)`,
      col: {
        title: "Tiêu đề",
        source: "Nguồn",
        conclusion: "Kết luận",
        created: "Tạo lúc",
        flags: "Dấu hiệu",
        reviewed: "Xử lý",
        reason: "Lý do",
        mergedInto: "Gộp vào mục",
        category: "Danh mục",
        tags: "Thẻ",
        approvedBy: "Duyệt bởi",
        evidence: "Bằng chứng",
        action: "Thao tác",
      },
      sourceKind: { alert: "Alert", case: "Case" },
      evidenceCount: (n: number) => `${n} nguồn`,
      open: "Mở",
      openDraft: (title: string) => `Mở bản nháp ${title}`,
      openEntry: (title: string) => `Mở mục ${title}`,
      noTitle: "Bản nháp chưa có nội dung",
      noEntryTitle: "Mục không có tiêu đề",
      badge: {
        conflict: "Mâu thuẫn",
        conflictHint: "Kết luận khác với một mục đã duyệt",
        // The entry the draft conflicts with was retired after the draft was made: the detail view knows it (the list does not).
        conflictRetired: "Mâu thuẫn với mục đã gỡ",
        noText: "Chưa có nội dung",
        warnings: (n: number) => `${n} cảnh báo`,
      },
      reviewedBy: (name: string, time: string) => `${name} · ${time}`,
      back: "← Danh sách",
      // A toast after a write that went through.
      done: {
        approved: (title: string) => `Đã duyệt: ${title}`,
        rejected: (title: string) => `Đã từ chối: ${title}`,
        redrafted: (title: string) => `Đã yêu cầu soạn lại: ${title}`,
        retired: (title: string) => `Đã gỡ: ${title}`,
      },

      // What the writes say when the server refuses or fails. A 409 is one sentence whatever its reason.
      notice: {
        handled: "Không xử lý được: bản nháp đã được xử lý. Danh sách đã được tải lại.",
        entryHandled:
          "Không gỡ được: mục tri thức đã được gỡ hoặc không còn hoạt động. Danh sách đã được tải lại.",
        publishFailed:
          "Không ghi được tệp tri thức, nên chưa lưu gì. Bấm lại để thử lần nữa; nếu vẫn lỗi, báo người vận hành.",
        gone: "Không tìm thấy bản nháp này nữa.",
        notRedraftable:
          "Không soạn lại được: bản nháp đã có nội dung hoặc đã được xử lý. Danh sách đã được tải lại.",
        draftsDisabled:
          "Không soạn lại được: việc soạn bản nháp đang tắt (KNOWLEDGE_DRAFT_ENABLED).",
        entryGone: "Không tìm thấy mục này nữa.",
        failed: "Chưa lưu được. Thử lại sau ít phút.",
        reasonRequired: "Cần nhập lý do.",
        reasonInvalid: (max: number) => `Lý do không hợp lệ: cần từ 1 đến ${max} ký tự.`,
        editedInvalid: "Nội dung sửa không hợp lệ.",
        // A 409 that leaves the draft pending (`source_changed`, `unpublishable`): an approval would meet it again.
        rejectOnly:
          "Không duyệt được: bản nháp đã được xử lý hoặc nguồn của nó đã đổi, nên chỉ có thể từ chối bản nháp này. Danh sách đã được tải lại.",
        faults: (n: number) => `Không duyệt được: còn ${n} lỗi cần sửa trong bản nháp.`,
      },

      // The draft on screen: two columns, the analyst's work and the draft.
      draft: {
        header: "Bản nháp",
        loadFailed: "Không tải được bản nháp",
        status: {
          pending: "Chờ duyệt",
          approved: "Đã duyệt",
          merged: "Đã gộp",
          rejected: "Từ chối",
        },
        meta: {
          source: "Nguồn",
          conclusion: "Kết luận",
          created: "Tạo lúc",
          reviewed: "Xử lý bởi",
          note: "Lý do từ chối",
          mergedInto: "Gộp vào mục",
        },
        left: {
          heading: "Công việc của analyst",
          hint: "Chỉ đọc: đúng những gì analyst đã thấy, không có nút thao tác nào.",
          // A part the source no longer has (the row is gone) is a sentence, not an error.
          noData: {
            alert: "Alert không còn dữ liệu.",
            case: "Case không còn dữ liệu.",
            investigation: "Kết quả điều tra ② không còn dữ liệu.",
            decision: "Quyết định của analyst không còn dữ liệu.",
          },
          decision: {
            heading: "Quyết định của analyst",
            by: (name: string, time: string) => `${name} · ${time}`,
            payload: "Chi tiết ghi lại",
          },
          notes: { heading: "Ghi chú của case", empty: "Case không có ghi chú." },
          soar: {
            heading: "Ngữ cảnh SOAR",
            forHead: (id: string) => `Cụm ${id}`,
          },
          investigation: {
            heading: "Kết quả điều tra ②",
            none: "Case chưa có kết quả phân tích ②.",
          },
          suggestion: {
            heading: "Cổng kiểm soát và lý do của ①",
            none: "① không ghi cổng kiểm soát hay lý do nào cho alert này.",
          },
          conflict: {
            heading: {
              active: "Mâu thuẫn với mục đã duyệt",
              retired: "Mâu thuẫn với mục đã gỡ",
            },
            hint: "Bản nháp kết luận khác mục này. Đối chiếu hai bên trước khi duyệt.",
            noData: "Mục mâu thuẫn không còn dữ liệu.",
            content: "Nội dung mục (Markdown)",
          },
        },
        right: {
          heading: "Bản nháp tri thức",
          noText:
            "Job không soạn được nội dung cho bản nháp này. Bạn có thể tự viết rồi chọn Sửa rồi duyệt, hoặc từ chối.",
          readOnly: "Bản nháp đã được xử lý nên không sửa được nữa.",
          field: {
            title: "Tiêu đề",
            summary: "Tóm tắt",
            distinguishing_signals: "Dấu hiệu phân biệt",
            check_next_time: "Cần kiểm tra lần sau",
            confidence_note: "Ghi chú về độ tin cậy",
            tags: "Thẻ",
          },
          hint: {
            max: (n: number) => `Tối đa ${n} ký tự.`,
            lines: (items: number, chars: number) =>
              `Mỗi dòng một mục, tối đa ${items} mục, mỗi mục tối đa ${chars} ký tự.`,
          },
          tags: {
            loading: "Đang tải danh sách thẻ…",
            loadFailed: "Không tải được danh sách thẻ.",
            outside: "ngoài danh sách",
            none: "Chưa chọn thẻ nào.",
          },
          closedHeading: "Trường cố định",
          closedHint: "Lấy từ nguồn, không sửa được.",
          closed: {
            conclusion: "Kết luận",
            category: "Danh mục",
            mitre_ids: "MITRE",
            soar_scenario: "Kịch bản SOAR",
            rule_ids: "Rule",
            log_source: "Nguồn log",
          },
          warnings: "Cảnh báo của job soạn thảo",
        },
        // Leaving a draft with text that was not sent.
        leave: {
          title: "Bỏ các chỉnh sửa chưa gửi?",
          body: "Bản nháp có chỉnh sửa chưa gửi đi. Rời khỏi bản nháp này sẽ làm mất chúng.",
          stay: "Ở lại",
          confirm: "Bỏ chỉnh sửa",
        },
        action: {
          approve: "Duyệt",
          editApprove: "Sửa rồi duyệt",
          reject: "Từ chối",
          // For a draft the model could not be asked for (the budget, a refusal, a timeout): make it again.
          redraft: "Soạn lại",
          redraftTitle: "Soạn lại bản nháp này?",
          redraftBody:
            "Bản nháp trống này bị xoá và hệ thống soạn lại từ đầu bằng một lần gọi model, tính vào hạn mức tri thức. Bản mới xuất hiện trong danh sách chờ duyệt sau ít phút.",
          // Why a button cannot be pressed now.
          approveEdited: "Bạn đã sửa nội dung: dùng Sửa rồi duyệt để gửi bản đã sửa.",
          approveRejectOnly: "Chỉ có thể từ chối bản nháp này.",
          editApproveClean: "Chưa sửa gì. Sửa nội dung rồi bấm Sửa rồi duyệt.",
          approveNoText: "Bản nháp chưa có nội dung: hãy viết nội dung rồi chọn Sửa rồi duyệt.",
          approveTitle: "Duyệt bản nháp này?",
          approveBody:
            "Mục được ghi vào kho tri thức và tệp được xuất bản. ① và ② có thể tra cứu nó ngay.",
          editApproveTitle: "Duyệt bản đã sửa?",
          editApproveBody: (fields: string) =>
            `Các trường đã sửa: ${fields}. Hệ thống kiểm tra lại toàn bộ nội dung trước khi ghi.`,
          rejectTitle: "Từ chối bản nháp này?",
          rejectBody: "Bản nháp không được xuất bản. Lý do được ghi lại.",
          reasonLabel: "Lý do (bắt buộc)",
          reasonCount: (used: number, max: number) => `${used} / ${max}`,
        },
      },

      // One approved (or retired) entry.
      entry: {
        header: "Mục tri thức",
        loadFailed: "Không tải được mục tri thức",
        status: { active: "Đang dùng", retired: "Đã gỡ" },
        field: {
          version: "Phiên bản",
          conclusion: "Kết luận",
          category: "Danh mục",
          mitre_ids: "MITRE",
          tags: "Thẻ",
          soar_scenario: "Kịch bản SOAR",
          rule_ids: "Rule",
          log_source: "Nguồn log",
          file_path: "Tệp",
          content_sha256: "SHA-256",
          approved: "Duyệt bởi",
          supersedes: "Thay thế mục",
          sources: "Từ alert và case",
        },
        integrity: {
          heading: "Toàn vẹn",
          ok: "Nội dung và tệp khớp bản gốc",
          contentBad: "Nội dung trong cơ sở dữ liệu không khớp mã băm của nó",
          fileBad: "Tệp đã xuất bản không khớp bản gốc",
        },
        evidence: { heading: "Bằng chứng", empty: "Chưa ghi nguồn nào." },
        content: "Nội dung (Markdown)",
        retire: "Gỡ",
        retireTitle: "Gỡ mục tri thức này?",
        retireBody:
          "Mục không còn được ① và ② tra cứu và tệp được chuyển sang thư mục đã gỡ. Lý do được ghi lại.",
        reasonLabel: "Lý do (bắt buộc)",
      },

      // The faults of V1-V5 (spec §7.7), by the rule before the colon: the field they belong to is already the
      // place they are shown. A rule this table has no word for gets `fallback`; a test reads the backend's list.
      fault: {
        rule: {
          v1_schema: "Sai định dạng: thiếu, sai kiểu, hoặc có ký tự điều khiển hay ký tự ẩn.",
          v1_tags: "Có thẻ không nằm trong danh sách cho phép.",
          v2_closed: "Trường cố định không khớp với nguồn.",
          v3_ipv4: "Có địa chỉ IPv4 cụ thể. Hãy viết tổng quát.",
          v3_ipv6: "Có địa chỉ IPv6 cụ thể. Hãy viết tổng quát.",
          v3_email: "Có địa chỉ email cụ thể. Hãy viết tổng quát.",
          v3_account: "Có tên tài khoản cụ thể. Hãy viết tổng quát.",
          v3_hostname: "Có tên máy cụ thể. Hãy viết tổng quát.",
          v3_alert_id: "Có mã alert cụ thể. Hãy viết tổng quát.",
          v3_hash: "Có mã băm cụ thể. Hãy viết tổng quát.",
          v4_detector: "Nội dung giống một câu lệnh chèn vào mô hình (prompt injection).",
          v4_delimiter: "Có dấu phân cách dữ liệu không tin cậy, không được dùng.",
          v4_nonce: "Có chuỗi giống mã nonce (16 ký tự thập lục phân).",
          v4_structure:
            "Có dòng mở đầu như một dòng cấu trúc của hệ thống: số trong ngoặc vuông như [1], hoặc khóa như level:, total:, examples:. Hãy viết lại.",
          v5_length: "Độ dài ngoài giới hạn.",
          v5_count: "Số mục ngoài giới hạn.",
          v5_empty: "Không được để trống.",
        },
        // A fault whose part after the colon is not a field: it is shown above the form, in its own words.
        special: {
          "v1_schema:root": "Bản nháp không đúng cấu trúc.",
          "v1_schema:unexpected_key": "Có trường không được phép sửa.",
          "v1_tags:unknown_tag": "Có thẻ không nằm trong danh sách cho phép.",
        },
        fallback: (rule: string) => `Không qua kiểm tra: ${rule}`,
        // Above the form, a fault names its field when it has one the page knows.
        named: (field: string, text: string) => `${field}: ${text}`,
      },
      // The `warnings` of a draft that are not V names.
      warning: {
        budget: "Hết ngân sách tra cứu và soạn tri thức của tháng nên chưa soạn được.",
        llm_transient: "Mô hình không phản hồi kịp và job đã hết số lần thử.",
        llm_permanent: "Mô hình từ chối yêu cầu, không thử lại.",
        linter: "Lời nhắc không qua kiểm tra an toàn nên không được gửi đi.",
        rank_unavailable: "Không xếp hạng được các mục tương tự nên chưa tìm mục trùng.",
      },
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

/**
 * The text of a failed admin call's reason (`AdminError` of kind `reason` or `field`). The server's own
 * bounds go in the text when it sent them (`too_short` with `min`, `too_long` with `max`, `out_of_range`
 * with both); otherwise the plain text of the reason.
 */
export function adminReasonText(error: {
  reason: AdminReason;
  min?: number;
  max?: number;
}): string {
  const { reason, min, max } = error;
  if (reason === "too_short" && min !== undefined) return S.admin.bounds.tooShort(min);
  if (reason === "too_long" && max !== undefined) return S.admin.bounds.tooLong(max);
  if (reason === "out_of_range" && min !== undefined && max !== undefined) {
    return S.admin.bounds.outOfRange(min, max);
  }
  return S.admin.reason[reason];
}

/** Whether `table` holds `key` itself (a hostile name such as `constructor` is not an answer). */
const own = (table: object, key: string): boolean => Object.hasOwn(table, key);

/**
 * The text of one fault of V1-V5 (`KnowledgeFault`): the three names whose part after the colon is not a field
 * have their own words, any other is worded by its rule, and a rule this file has no word for gets a generic
 * sentence that names it. Never a value: the server sends none.
 */
export function knowledgeFaultText(fault: KnowledgeFault): string {
  const words = S.admin.knowledgePage.fault;
  const full = `${fault.rule}:${fault.field ?? ""}`;
  if (fault.field !== null && own(words.special, full)) {
    return words.special[full as keyof typeof words.special];
  }
  return own(words.rule, fault.rule)
    ? words.rule[fault.rule as keyof typeof words.rule]
    : words.fallback(fault.rule);
}

/** The label of a field of the draft, model's or source's, or null for a name that is no field. */
export function knowledgeFieldLabel(field: string): string | null {
  const right = S.admin.knowledgePage.draft.right;
  if (own(right.field, field)) return right.field[field as keyof typeof right.field];
  if (own(right.closed, field)) return right.closed[field as keyof typeof right.closed];
  return null;
}

/**
 * The text of one `warnings` entry of a draft: a code the job writes besides the V names, or a V name
 * (`rule:field`) worded with the label of its field. A code this file does not know is shown as it came.
 */
export function knowledgeWarningText(code: string): string {
  const words = S.admin.knowledgePage;
  if (own(words.warning, code)) return words.warning[code as keyof typeof words.warning];
  const colon = code.indexOf(":");
  if (colon === -1) return code;
  const fault: KnowledgeFault = { rule: code.slice(0, colon), field: code.slice(colon + 1) };
  const text = knowledgeFaultText(fault);
  const label = fault.field === null ? null : knowledgeFieldLabel(fault.field);
  return label === null ? text : words.fault.named(label, text);
}
