// Every user-facing label of the UI, in Vietnamese (spec §4). Components import `S`; none writes its own copy.
// The tables keyed by a server code (`status`, `band`, `conclusion`, ...) are read through `labelOf`, so a
// code this file has no label for is shown as the code itself.

import type { AdminReason, AuditGroup, DigestVerdict, HardBlockCode, LlmRange } from "./api/admin";
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
      audit: "Nhật ký audit",
    },
    // What a page that is not built yet says (the page tasks replace these pages).
    building: "Trang này đang xây dựng.",

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
        // The ten checks of `infra/health.py`, in the canvas's words; a name with no label is shown as it is.
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
      not_found: "Không tìm thấy mục này. Có thể nó đã bị xoá hoặc đã đổi — hãy tải lại trang.",
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
      tokens: {
        title: "Token vào / ra",
        average: (parts: string) => `trung bình ${parts}`,
        averageOf: (pipeline: string, tokens: string) => `${pipeline} ${tokens} vào`,
      },
      stoppedTile: {
        title: "Lượt dừng không có kết quả",
        none: "không có lượt nào dừng",
        detail: (stopped: string, calls: string, main: string) =>
          `${stopped} / ${calls} lượt · nhiều nhất: ${main}`,
      },

      // The pipelines of `llm_runs.pipeline` and, for ①, its two roles. There is no chat row: the column's
      // CHECK admits `triage` and `investigate` only (spec decision 5). Anything else is shown as it came.
      pipeline: {
        triage: "①",
        investigate: "②",
        triageRole: {
          proposer: "① triage · proposer",
          verifier: "① triage · verifier",
        },
        triageNoRole: "① triage",
        investigateRow: "② điều tra case",
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

    // One label for each of the 28 names of `audit/events.py`'s EVENT_TYPES, read through `labelOf`. The
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
