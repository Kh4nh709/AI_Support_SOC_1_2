// Every user-facing label of the UI, in Vietnamese (spec §4). Components import `S`; none writes its own copy.
// The tables keyed by a server code (`status`, `band`, `conclusion`, ...) are read through `labelOf`, so a
// code this file has no label for is shown as the code itself.

import type { AdminReason, AuditGroup, KnowledgeFault, LlmRange } from "./api/admin";
import { BAND_CODES, type BandCode } from "./api/types";

/** The shortest quote ② may cite, in characters (`MIN_QUOTE_CHARS` of backend/app/tier2/investigate.py). */
export const MIN_QUOTE_CHARS = 8;

/**
 * The line under the "Tri thức (RAG)" tile, for each state of the lookup and each failure kind
 * (`rag.failures.FAILURE_KINDS`; strings.test.ts holds the keys equal to the backend's). One table for both tiers' tiles
 * (DEC-221): `S.analysis.ragNote` and `S.ai2.tile.ragNote` are this object.
 */
const RAG_TILE_NOTE = {
  matched: "trùng sự cố cũ",
  belowFloor: (floor: number | null) => (floor === null ? "dưới mức tối thiểu" : `dưới mức ${floor}%`),
  noCandidate: "không có mục nào trùng",
  noLookup: "không có tra cứu",
  noData: "chưa có dữ liệu",
  failed: "tra cứu bị lỗi",
  failedKind: {
    rate_limit: "vượt giới hạn tốc độ",
    timeout: "quá thời gian chờ",
    auth: "thiếu hoặc sai API key",
    quota: "hết hạn mức",
    provider_error: "lỗi phía nhà cung cấp",
    vectordb_unreachable: "không kết nối được vector DB",
  },
} as const;

/**
 * What a highlight of the Tier 1 panel's "Điều nổi bật" says: the server's params, read into numbers and words by
 * `analysisModel.ts` (`null` when the server sent none), so a sentence below degrades to a plainer one instead of
 * printing a hole.
 */
export type HighlightWords = {
  count: number | null;
  total: number | null;
  pct: number | null;
  floor: number | null;
  /** The label of the entry's conclusion, or null. */
  conclusion: string | null;
  /** The words of the failure kind, or null. */
  reason: string | null;
};

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

  // `alerts.category`: every category the backend's mapper can emit (`PRIORITY` of ingest/category.py; a test
  // reads the tuple, so a category added there without a label here goes red). Read through `labelOf`; a
  // category with no label is shown as its code. The page keeps the code beside the label.
  category: {
    ransomware: "Mã độc tống tiền",
    impact: "Phá hoại, gây gián đoạn",
    malware: "Mã độc",
    c2_beacon: "Kết nối điều khiển C2",
    data_exfiltration: "Rò rỉ dữ liệu",
    collection: "Thu thập dữ liệu",
    lateral_movement: "Di chuyển ngang",
    privilege_escalation: "Leo thang đặc quyền",
    credential_access: "Đánh cắp thông tin xác thực",
    persistence: "Duy trì truy cập",
    defense_evasion: "Né tránh phòng thủ",
    execution: "Thực thi mã",
    ssh_brute_force: "Dò mật khẩu SSH",
    brute_force: "Dò mật khẩu",
    web_attack: "Tấn công ứng dụng web",
    initial_access: "Truy cập ban đầu",
    suspicious_login: "Đăng nhập đáng ngờ",
    recon: "Do thám",
    resource_development: "Chuẩn bị hạ tầng tấn công",
    policy_violation: "Vi phạm chính sách",
    unknown: "Chưa phân loại",
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
    // INT-T03 / DEC-212: the old queue closed out without review. Not "đóng": nobody closed it.
    archived: "Đã lưu trữ",
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
    // The flag of a gate that forced the verdict: only a version 1 row (before DEC-217) carries it; a new run
    // never does, because the gate's checks are warnings beside the verdict.
    forced: "⚑",
    forcedLabel: "Cổng kiểm soát đã ép kết quả",
    // `suggested_action` of ① (`llm.verdicts.STORED_ACTIONS`, read through `labelOf`; strings.test.ts compares the
    // keys). P14-T03 (DEC-213): ① concludes `false_positive` or `true_positive` (it was `escalate`) and says them as
    // FP and TP. DEC-217: ① never ends `needs_review` any more, so the alert page and the queue say FP or TP; the
    // label is kept for a row stored before it, which the admin LLM page shows as it is.
    action: {
      false_positive: "FP",
      needs_review: "Cần xem xét",
      true_positive: "TP",
    },
    // The alert page's line: "AI kết luận: TP (độ tin cậy cao)", and when the gate's checks raised warnings, "… — có
    // cảnh báo kiểm chứng: <reasons>" (P14-T03, spec 4.3; DEC-217 section 8). The verdict is the model's own and the
    // warnings sit beside it: nothing is held back for a person. The phrase `held` is bold on the page, so it is a
    // string of its own: the dash, the phrase, and the ": …" that follows it directly when a reason is known.
    conclusion: "AI kết luận",
    confidenceNote: (level: string) => `(độ tin cậy ${level})`,
    heldDash: "—",
    held: "có cảnh báo kiểm chứng",
    heldBecause: (reasons: string[]) => (reasons.length === 0 ? "" : `: ${reasons.join(", ")}`),
    // DEC-219 (trial, amended by the Owner): below the RAG threshold `false_positive` is ①'s default answer, whether
    // the model had said it itself or not. The line says so in a parenthesis after the percentage clause and prints
    // no confidence note (it is the model's, in its own answer), and never names the model's answer: "AI kết luận: FP
    // — trùng 62% với tri thức đã duyệt (dưới 80%: mặc định FP) — có cảnh báo kiểm chứng: …". The verdict it names is
    // always `false_positive`, worded as `action.false_positive` (strings.test.ts compares the two).
    ragDefault: (threshold: number) => `(dưới ${threshold}%: mặc định FP)`,
    // `llm.verdicts.HELD_REASONS`: the checks of the gate that raised a warning, in the gate's step order (the codes
    // kept their names from before DEC-217, when a failed check held the verdict). The keys are compared with the
    // backend's tuple in strings.test.ts; a code with no label is shown as the code.
    heldReason: {
      facts_mismatch: "AI khai dữ kiện lệch với hệ thống",
      no_verified_quote: "không có dẫn chứng kiểm chứng được",
      "fp_policy:severity": "alert mức critical",
      "fp_policy:ioc_reputation": "IOC độc hại hoặc đáng ngờ",
      "fp_policy:asset_criticality": "tài sản quan trọng hoặc chưa rõ",
      "fp_policy:identity_privileged": "tài khoản đặc quyền",
      "fp_policy:playbook_rule": "không khớp bảng quyết định đã duyệt",
      verifier_disagrees: "bộ kiểm tra không đồng ý",
      verifier_invalid: "bộ kiểm tra không trả lời hợp lệ",
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
      unavailable: "nhà cung cấp LLM từ chối (hết số dư / hạn mức, 402)",
    },
    stoppedByLabel: "Lý do dừng",
    hiddenBody:
      "Alert này thuộc nhánh mù của pilot: bạn quyết định mà không thấy gợi ý ①. Gợi ý sẽ hiện sau khi bạn gửi quyết định.",
    pendingBody:
      "Alert đã vào hàng chờ phân tích. Trang tự cập nhật khi có kết quả; bạn vẫn có thể quyết định ngay.",
    // An archived alert (DEC-212) whose ① had not answered: no answer will come.
    noneBody: "Alert đã được lưu trữ khi ① chưa phân tích xong, nên sẽ không có gợi ý ①.",
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

    // ── The Tier 1 panel (DEC-221): four tiles, five tabs ───────────────────────────────────────────────────────
    // The heading and the advisory line at its right are `S.alert.aiHeading` and `S.alert.aiHint`. Every closed code of
    // the server's `analysis` object has a word here; the keys are compared with the backend's tuples in
    // strings.test.ts, and a code with no word is shown as the code. The panel names no model (G5).
    panel: {
      // The tablist's name for a screen reader.
      tabsLabel: "Chi tiết phân tích AI Tier 1",
      tile: {
        verdict: "Kết luận",
        confidence: "Độ tin cậy",
        rag: "Tri thức (RAG)",
        checks: "Kiểm chứng",
        // The line under the conclusion: what the verdict means.
        verdictNote: { true_positive: "tấn công thật", false_positive: "dương tính giả" },
        // The confidence is the model's, in its own answer, so a verdict the RAG default decided (DEC-219) has none
        // to show: the tile says it does not apply, and never what the model had answered.
        confidenceNone: "không áp dụng cho kết luận mặc định",
        // Checks passed over checks that apply, and under it the warnings (in the warning colour) or the calm line.
        checksNote: {
          clean: "không có cảnh báo",
          none: "chưa có kiểm chứng",
          warnings: (count: number) => `${count} cảnh báo`,
        },
      },
      tabs: {
        overview: "Tổng quan",
        evidence: "Bằng chứng",
        knowledge: "Tri thức",
        checks: "Kiểm chứng",
        tech: "Kỹ thuật",
      },

      // Tổng quan.
      overview: {
        highlights: "Điều nổi bật",
        attack: "Nếu là tấn công",
        benign: "Nếu lành tính",
        wouldChange: "Điều sẽ làm đổi kết luận:",
        nextChecks: "Nên kiểm tra tiếp",
        // An older run, or one with nothing to say: no empty headings, one plain line.
        none: "Lượt phân tích này không có phần tóm tắt.",
      },
      // `analysis.highlights[].code`, in the order the server serves them (`HIGHLIGHT_CODES`). The server builds each one
      // from system facts, never from a text the model wrote.
      highlight: {
        history_incident: ({ count, total }: HighlightWords) =>
          count !== null && total !== null
            ? `Lịch sử: ${count} trên ${total} alert tương tự từng là sự cố thật.`
            : "Lịch sử: phần lớn alert tương tự từng là sự cố thật.",
        history_benign: ({ count, total }: HighlightWords) =>
          count !== null && total !== null
            ? `Lịch sử: ${count} trên ${total} alert tương tự từng được đóng là không phải tấn công.`
            : "Lịch sử: phần lớn alert tương tự từng được đóng là không phải tấn công.",
        identity_privileged: () => "Tài khoản liên quan là tài khoản đặc quyền.",
        asset_high: () => "Tài sản liên quan có độ quan trọng cao.",
        asset_unknown: () => "Độ quan trọng của tài sản liên quan chưa rõ.",
        severity_critical: () => "Alert ở mức nghiêm trọng critical.",
        rag_matched: ({ pct, conclusion }: HighlightWords) =>
          pct === null
            ? "Có tri thức đã duyệt trùng với alert này."
            : `Tri thức đã duyệt trùng ${pct}%${conclusion === null ? "" : ` (${conclusion})`}.`,
        rag_below_floor: ({ pct, floor }: HighlightWords) =>
          floor === null
            ? "Không có tri thức đã duyệt nào đạt mức tối thiểu."
            : pct === null
              ? `Không có tri thức đã duyệt nào trùng từ ${floor}% trở lên.`
              : `Không có tri thức đã duyệt nào trùng từ ${floor}% trở lên (cao nhất ${pct}%).`,
        rag_failed: ({ reason }: HighlightWords) =>
          reason === null
            ? "Không tra cứu được tri thức đã duyệt."
            : `Không tra cứu được tri thức đã duyệt: ${reason}.`,
        warning_facts_mismatch: () => "AI khai dữ kiện lệch với hệ thống.",
        warning_no_verified_quote: () => "Không có dẫn chứng nào khớp nguyên văn với dữ liệu alert.",
        warning_fp_policy_facts: () => "Một dữ kiện của alert không cho phép kết luận FP.",
        warning_fp_policy_playbook: () => "Kết luận FP không khớp bảng quyết định đã duyệt.",
        warning_injection_findings: () => "Dữ liệu alert có dấu hiệu chèn lệnh.",
        warning_verifier_disagrees: () => "Bộ kiểm chứng độc lập không đồng ý.",
        warning_verifier_invalid: () => "Bộ kiểm chứng độc lập không trả lời hợp lệ.",
      },

      // Bằng chứng: every reason of the model's answer, the quote, where it is from and whether the server found it.
      evidence: {
        summary: (verified: number, total: number) =>
          `${verified} trên ${total} dẫn chứng khớp nguyên văn với dữ liệu alert.`,
        none: "AI không nêu dẫn chứng nào.",
        matched: "khớp nguyên văn",
        // `reasons[].source`: the six sources a reason may cite (`security/output_guard.REASON_SOURCES`).
        source: {
          wazuh_raw_log: "Log gốc của alert",
          rule_description: "Mô tả rule",
          correlation_samples: "Mẫu tương quan",
          kb_playbook: "Playbook",
          context: "Ngữ cảnh tài khoản và tài sản",
          siem_context: "Ngữ cảnh SIEM",
        },
        // `reasons[].why`: why the server did not verify a quote (`REASON_WHY`).
        why: {
          not_substring: "AI ghép hoặc diễn giải, không tìm thấy nguyên văn",
          unknown_source: "nguồn trích dẫn không nằm trong dữ liệu AI được đưa",
          empty_quote: "AI diễn giải, không trích nguyên văn",
        },
      },

      // Tri thức: the lookup, the decision history, the playbook and the decision table.
      knowledge: {
        // The card's one sentence for each state of the lookup (`rag.state`, `STATES`).
        state: {
          matched: (best: number | null, floor: number | null) =>
            best === null
              ? "Có tri thức đã duyệt trùng với alert này, nên AI được cung cấp tri thức tham khảo."
              : floor === null
                ? `Mục trùng cao nhất đạt ${best}%, nên AI được cung cấp tri thức tham khảo.`
                : `Mục trùng cao nhất đạt ${best}%, qua mức tối thiểu ${floor}%, nên AI được cung cấp tri thức tham khảo.`,
          below_floor: (floor: number | null) =>
            floor === null
              ? "Không mục nào đạt mức tối thiểu, nên AI không được cung cấp tri thức tham khảo."
              : `Không mục nào đạt mức tối thiểu ${floor}%, nên AI không được cung cấp tri thức tham khảo.`,
          no_candidate: () => "Không có mục tri thức đã duyệt nào được chấm điểm cho alert này.",
          failed: (reason: string | null) =>
            reason === null
              ? "Không tra cứu được tri thức đã duyệt."
              : `Không tra cứu được tri thức đã duyệt: ${reason}.`,
          no_lookup: () => "Lượt phân tích này không tra cứu tri thức đã duyệt.",
        },
        // The rule of DEC-219: below the threshold `false_positive` is the default answer. The sentence says whether it
        // applied and never what the model had answered.
        rule: {
          applied: (threshold: number) =>
            `Quy tắc "dưới ${threshold}% → mặc định FP" đã áp dụng: kết luận mặc định là FP.`,
          notApplied: (threshold: number) =>
            `Quy tắc "dưới ${threshold}% → mặc định FP" không áp dụng.`,
          off: 'Quy tắc "dưới ngưỡng → mặc định FP" đang tắt.',
        },
      },
      history: {
        heading: "Lịch sử quyết định",
        none: "Chưa có quyết định nào trước đây cho alert tương tự.",
        // Which alerts the history counts (`rag.history.LEVELS`, by name).
        scope: {
          soar_case: "Cùng case SOAR",
          cluster: "Cùng cụm (rule, nguồn, đích, máy)",
          scenario_host: "Cùng kịch bản và cùng máy",
          rule_host: "Cùng rule và cùng máy",
          rule_source: "Cùng rule và cùng nguồn hoặc người dùng",
          category_host: "Cùng loại alert và cùng máy",
        },
        generic: "Alert tương tự",
        // `rag.history.CONCLUSIONS`: what the earlier alerts came to.
        conclusion: {
          tier1_closed_fp: "đóng FP",
          tier1_closed_benign: "đóng lành tính",
          escalated_open: "đang điều tra ở Tier 2",
          concluded_fp: "Tier 2 kết luận dương tính giả",
          concluded_policy_violation: "vi phạm chính sách",
          confirmed_incident: "sự cố thật",
        },
        // "Cùng kịch bản và cùng máy: 15 quyết định, 15 là sự cố thật · gần nhất 06/11."
        line: (scope: string, total: number, incidents: number) =>
          `${scope}: ${total} quyết định, ${incidents} là sự cố thật`,
        rest: (parts: string) => `; còn lại: ${parts}`,
        lastSeen: (when: string) => ` · gần nhất ${when}`,
      },
      playbook: {
        heading: "Playbook và bảng quyết định",
        playbook: "Playbook",
        ruleHead: "Theo bảng quyết định, rule",
        ruleMatches: (action: string) => `khớp: ${action}.`,
        // `analysis.playbook.rule_action`.
        action: {
          false_positive: "cho phép kết luận FP",
          needs_review: "cần người xem",
          true_positive: "kết luận TP",
        },
        ruleNone: "Theo bảng quyết định, không có rule nào khớp.",
        unsigned: "Bảng quyết định này chưa được ký duyệt.",
        none: "Không có playbook hay bảng quyết định cho loại alert này.",
      },

      // Kiểm chứng: one line per gate step, then the facts the system recorded beside what the model declared.
      checks: {
        // `analysis.checks[].id` (`CHECK_IDS`): the name of the gate step.
        step: {
          "1": "Đúng định dạng",
          "2": "Dữ kiện",
          "3": "Dẫn chứng",
          "3r": "Quy tắc RAG",
          "4": "Chính sách FP",
          "5": "Chèn lệnh",
          "6": "Bộ kiểm chứng độc lập",
        },
        // `analysis.checks[].detail` (`CHECK_DETAILS`): the closed explanation of the outcome.
        detail: {
          schema_ok: "hợp lệ ngay lần đầu",
          schema_repaired: "hợp lệ sau một lần sửa lại",
          facts_match: "dữ kiện AI khai khớp với hệ thống",
          facts_mismatch: "AI khai dữ kiện lệch với hệ thống",
          quotes_verified: "mọi dẫn chứng khớp nguyên văn",
          quotes_some_dropped: "một số dẫn chứng không khớp nguyên văn",
          no_verified_quote: "không có dẫn chứng nào khớp nguyên văn",
          rag_rule_applied: "đã áp dụng, kết luận mặc định là FP",
          rag_rule_not_applied: "không áp dụng",
          rag_rule_off: "quy tắc đang tắt",
          fp_policy_ok: "đạt",
          fp_policy_facts: "một dữ kiện của alert không cho phép kết luận FP",
          fp_policy_playbook: "không khớp bảng quyết định đã duyệt",
          not_false_positive: "không xét, vì kết luận là TP",
          no_injection_findings: "không phát hiện",
          injection_findings: "phát hiện dấu hiệu chèn lệnh",
          verifier_agrees: "đồng ý với kết luận",
          verifier_disagrees: "không đồng ý",
          verifier_invalid: "không trả lời hợp lệ",
          not_run: "không có ghi nhận",
        },
        // The dash between a step's name and its explanation.
        dash: "—",
        // `quotes_verified` and `quotes_some_dropped` with the counts the reasons give: "2 trên 4 khớp nguyên văn".
        quotes: (verified: number, total: number) => `${verified} trên ${total} khớp nguyên văn`,
        // `facts_mismatch` with the fields step 2 flagged: "AI khai mức nghiêm trọng high, hệ thống ghi medium".
        mismatch: (field: string, declared: string, system: string) =>
          `AI khai ${field.toLowerCase()} ${declared}, hệ thống ghi ${system}`,
        mismatchJoin: "; ",
      },
      facts: {
        label: "Dữ kiện đã dùng",
        // `analysis.facts[].field` (`FACT_FIELDS`).
        field: {
          severity: "Mức nghiêm trọng",
          ioc_reputation: "Danh tiếng IOC",
          asset_criticality: "Độ quan trọng tài sản",
          identity_privileged: "Tài khoản đặc quyền",
          occurrence_count: "Số lần xuất hiện",
        },
        // The columns: the fact, what the system recorded, what the model declared (the value, not a model's name), and
        // whether they agree. A run the RAG default decided has the first two only.
        column: { fact: "Dữ kiện", system: "Hệ thống", declared: "AI khai", match: "Khớp" },
        match: { yes: "khớp", no: "lệch" },
        // The words of a few closed values; any other value is shown as it came.
        value: {
          identity_privileged: { true: "có", false: "không", unknown: "chưa rõ" },
          ioc_reputation: {
            malicious: "độc hại",
            suspicious: "đáng ngờ",
            clean: "sạch",
            not_found: "không thấy",
            skipped: "chưa tra",
          },
        },
      },

      // Kỹ thuật: tokens, time, cost and when are `S.analysis.tech`'s; there is no model, no verifier and no answer
      // format among the rows (the Owner's change, G5).
      tech: {
        mitre: "Nhãn MITRE của alert",
        correlated: "Cụm tương quan lúc phân tích",
      },
    },
  },

  // P14-T07 (DEC-213, spec 4.3): what the alert page and the case page say of the RAG beside the AI's conclusion.
  // The percentage follows the conclusion line ("AI kết luận: TP (độ tin cậy cao) — trùng 87% với tri thức đã
  // duyệt"); the notice is a sentence of its own, in the words of the alert or of the case. `failureKind` is
  // `rag.failures.FAILURE_KINDS` (strings.test.ts compares the keys): each label names where the failure was,
  // because a `vectordb` failure is not Voyage's. A kind with no label is not shown at all, and never as its code
  // (`failureKindLabel`): the server sends only the closed six, never the provider's words.
  rag: {
    dash: "—",
    match: (pct: number) => `trùng ${pct}% với tri thức đã duyệt`,
    // DEC-220 (trial): a lookup that kept no match still scored candidates; the line says the best one's percentage
    // and the floor it was under, in the place of `match`: "— trùng cao nhất 47% với tri thức đã duyệt (dưới mức tối
    // thiểu 50%)". The rule of DEC-219 does not apply to such a run, so no "mặc định FP" follows.
    belowFloor: (pct: number, floor: number) =>
      `trùng cao nhất ${pct}% với tri thức đã duyệt (dưới mức tối thiểu ${floor}%)`,
    notApplied: (subject: "alert" | "case", reason: string) =>
      `⚠ Không áp dụng RAG cho ${subject} này: ${reason} — AI đã phân tích không có tri thức tham khảo.`,
    failureKind: {
      rate_limit: "Voyage vượt giới hạn tốc độ",
      timeout: "Voyage quá thời gian chờ",
      auth: "thiếu hoặc sai API key Voyage",
      quota: "Voyage hết hạn mức",
      provider_error: "lỗi phía Voyage",
      vectordb_unreachable: "không kết nối được vector DB",
    },
  },

  alert: {
    infoHeading: "THÔNG TIN ALERT",
    aiHeading: "PHÂN TÍCH AI · TIER 1",
    notFound: "Không tìm thấy alert",
    loadFailed: "Không tải được alert",
    duplicateOf: (headId: string) => `bản sao của ${headId}`,
    infoHint: "dữ liệu gốc từ Wazuh và phần làm giàu",
    aiHint: "Gợi ý tham khảo — bạn là người quyết định",
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
    // The SOAR enrichment of the SIEM (S3, `view.soar`). All of it is the SIEM's own text and numbers, shown as
    // they came: the page reads none of it into a decision.
    soar: {
      caseTitle: "Case TheHive",
      caseNumber: (number: number | string) => `Case TheHive: #${number}`,
      noCase: "chưa tạo case (điểm thấp)",
      dedupKey: "Khoá gộp (dedup)",
      thehiveAlertId: "Alert TheHive",
      actionTitle: "Hành động SOAR dự kiến",
      // "block_ip → 79.79.78.202 (auto, act_first)": what is missing is left out with its punctuation.
      action: (type: string, target: string, detail: string) => {
        const head = [type, target].filter((part) => part !== "").join(" → ");
        return detail === "" ? head : `${head} (${detail})`;
      },
      scenarioTitle: "Kịch bản và điểm SOAR",
      scenario: "Kịch bản",
      // "SC03 — External port scan (pfSense)"
      scenarioName: (id: string, name: string) =>
        [id, name].filter((part) => part !== "").join(" — "),
      score: "Điểm triage của SIEM",
      scoreHint:
        "Điểm và tín hiệu do SIEM tính — chỉ để tham khảo, không dùng để quyết định thay bạn.",
      signal: "Tín hiệu",
      signalCodes: "Mã tín hiệu",
      historyTitle: "Lịch sử 7 ngày",
      ruleTotal7d: "Số lần rule này xuất hiện (7 ngày)",
      ruleHost7d: "Số lần trên máy này (7 ngày)",
      ruleHosts7d: "Số máy có rule này (7 ngày)",
      firstSeenHost: "Lần đầu rule này xuất hiện trên máy",
      lastSeen: "Lần cuối thấy rule",
      yes: "Có",
      no: "Không",
      geoTitle: "Địa lý nguồn (GEO01)",
      country: "Quốc gia",
      countrySimulated: "Quốc gia mô phỏng",
      simulated: "mô phỏng",
      countryWithMark: (country: string) => `${country} (mô phỏng)`,
      srcIpType: "Loại IP nguồn",
      firstSeenCountry30d: "Lần đầu thấy quốc gia này (30 ngày)",
      seenCount30d: "Số lần thấy trong 30 ngày",
      priorFailures30m: "Số lần thất bại trước đó (30 phút)",
      impossibleTravel: "Di chuyển bất khả thi",
      offHours: "Ngoài giờ làm việc",
      scanTitle: "Quét cổng (SC03)",
      sampledPackets: "Số gói lấy mẫu",
      distinctPorts: "Số cổng đích khác nhau (trong mẫu)",
      portsSample: "Mẫu cổng đích",
      morePorts: (n: number) => `+${n} cổng khác`,
      dstIps: "IP đích",
      scanActions: "Hành động của tường lửa",
      previousOutput: "Log tường lửa gốc (previous_output)",
      previousOutputLines: (total: number) =>
        `Log tường lửa gốc (previous_output) — ${total} dòng, chỉ hiển thị phần đầu`,
      tiTitle: "Tra cứu TI của SOAR",
      ti: (type: string, value: string, verdict: string) =>
        [type, value, verdict].filter((part) => part !== "").join(" · "),
    },
  },

  decision: {
    heading: "Quyết định",
    acknowledge: "Nhận xử lý",
    falsePositive: "Đóng — dương tính giả",
    benign: "Đóng — lành tính",
    escalate: "Chuyển tier 2",
    // Beside the escalate form (T2, DEC-215, the Owner 11/11): what goes into the case. Only this alert and its
    // own copies; the alerts correlated with it stay in the queue as they are, to be decided one by one. It used to
    // be the other way round (the correlated open alerts were swept into the case and closed with it).
    escalateScope:
      "Chỉ alert này (cùng các bản sao của nó) được chuyển vào case. Các alert tương quan trong ±2 giờ vẫn ở hàng đợi Tier 1 với trạng thái hiện tại, để quyết định từng alert.",
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
    // INT-T03 / DEC-212: set aside by the archive of the old queue; nobody decided it, and nobody can now.
    archived: "Alert đã được lưu trữ khi dọn hàng đợi — không ai quyết định và không thể xử lý.",
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
    // DEC-221: the heading of the Tier 2 panel, as the approved mock-up has it.
    aiHeading: "PHÂN TÍCH AI · TIER 2",
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
    // The newest ② run ended without a result (INT-T02): its time, a dash, then this (lastAnalysed.ts).
    noResult: "không có kết quả",
    clusterCount: (n: number) => `${n} cụm`,
    timeline: "Diễn biến",
    // What the case detail itself records: its creation, each note, the last run of ② and the conclusion.
    timelineCreated: "Case được tạo",
    timelineNote: (who: string) => `${who} thêm ghi chú`,
    timelineAnalysed: "Chạy phân tích AI ②",
    timelineConcluded: (who: string, conclusion: string) => `${who} kết luận: ${conclusion}`,
    // DEC-212: the archive is the system's, not a person's conclusion.
    timelineArchived: "Case được lưu trữ (dọn hàng đợi)",
    archivedAt: (when: string) => `Đã lưu trữ lúc ${when} — không ai kết luận`,
    conflictArchived: "Case đã được lưu trữ — không thể kết luận nữa.",
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

  // `cases.status`: the case is investigating, concluded with one of the three conclusions, or archived
  // (DEC-212: the old queue closed out without review, concluded by nobody).
  caseStatus: {
    investigating: "Đang điều tra",
    concluded_fp: "Dương tính giả",
    concluded_policy_violation: "Vi phạm chính sách",
    confirmed_incident: "Xác nhận sự cố",
    archived: "Đã lưu trữ",
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
    archived: "Đã lưu trữ",
  },

  // What the two AI panels share (DEC-221, spec 2026-11-15): the score tiles, the tab strip, the evidence block, the
  // knowledge candidates and the technical figures. Nothing here names a tier, and nothing names a model (G5): the
  // technical tab shows tokens, time and cost, never which model spent them.
  analysis: {
    // The middle dot between the parts of one line: "Né tránh phòng thủ · T1562.001 · alert 112437".
    separator: " · ",
    // The confidence tile's word, from the model's `low`, `medium` or `high`.
    level: { low: "Thấp", medium: "Trung bình", high: "Cao" },
    // The three-segment meter, said to a screen reader.
    meter: (filled: number) => `${filled} trên 3`,
    // StatusIcon: the spoken name of a mark that has no text beside it. `up` and `down` are the arrows of a highlight
    // (Tier 1): towards an attack, towards a benign reading.
    status: {
      pass: "Đạt",
      warn: "Cảnh báo",
      na: "Không áp dụng",
      up: "Nghiêng về tấn công",
      down: "Nghiêng về lành tính",
    },
    // The line under the RAG tile of both tiers (see `RAG_TILE_NOTE`).
    ragNote: RAG_TILE_NOTE,
    // The mark of a quoted piece of evidence: the server checked the quote against the log, or could not.
    evidence: { verified: "Đã kiểm chứng", unverified: "Không kiểm chứng được" },
    knowledge: {
      heading: "Tri thức đã duyệt",
      scored: (count: number) => `${count} mục được chấm điểm`,
      // An entry the server could not read a title for (it is gone, or has no heading).
      untitled: "Mục không có tiêu đề",
      // `knowledge_entries.conclusion`: the closing of the alert or the case the entry was learned from.
      conclusion: {
        confirmed_incident: "sự cố thật",
        concluded_policy_violation: "vi phạm chính sách",
        concluded_fp: "dương tính giả",
        closed_fp: "đã đóng FP",
        closed_benign: "lành tính",
      },
    },
    tech: {
      tokens: "Token vào → ra",
      tokenLine: (input: string, output: string) => `${input} → ${output}`,
      time: "Thời gian",
      seconds: (value: string) => `${value} giây`,
      cost: "Chi phí",
      analysedAt: "Phân tích lúc",
    },
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
    // The case page's line: "AI kết luận: <label>", and when the system held it as `need_more_data`,
    // "… — hệ thống giữ lại vì: <causes>" (P14-T03, spec 4.3). The causes are `tier2.investigate.HELD_BY`.
    conclusion: "AI kết luận",
    heldLine: (causes: string[]) =>
      causes.length === 0 ? "— hệ thống giữ lại" : `— hệ thống giữ lại vì: ${causes.join(", ")}`,
    heldReason: {
      no_verified_evidence: "không có bằng chứng kiểm chứng được",
      high_severity_injection_finding: "phát hiện dấu hiệu chèn lệnh mức cao",
    },
    // `investigate_v3.suggested_conclusion`: the words of the backend's CONCLUSION_LABELS
    // (backend/app/tier2/investigation_view.py); strings.test.ts compares the two. They are
    // not the three case-conclusion labels of `S.conclusion`, which name what Tier 2 decided.
    suggestedConclusion: {
      false_positive: "Không phải sự cố",
      policy_violation: "Có vi phạm nội quy, không phải tấn công",
      confirmed_incident: "Là sự cố thật",
      need_more_data: "Cần thêm dữ liệu",
    },
    // `llm_runs.stopped_by` of a run with no result. `permanent` is the provider's refusal (a 402 since R4) as
    // well as the model's, and says both (INT-T02); strings.test.ts holds this table equal to the backend's.
    stoppedBy: {
      cap: "đã chạm hạn mức chi phí LLM",
      permanent: "nhà cung cấp hoặc mô hình từ chối yêu cầu (ví dụ hết số dư, 402), không thử lại",
      linter: "dữ liệu của case không qua bộ kiểm tra an toàn trước khi gửi cho mô hình",
      schema: "mô hình trả lời sai định dạng, kể cả sau một lần sửa",
      transient: "mô hình không phản hồi sau nhiều lần thử",
    },

    // ── The Tier 2 panel (DEC-221): four tiles, five tabs ─────────────────────────────────────────────────────
    // The line at the right of the panel's heading: the case, its clusters and the agents they came from.
    caseLine: (id: string, clusters: number, agents: readonly string[]) =>
      [`Case ${id}`, `${clusters} cụm`, ...(agents.length > 0 ? [agents.join(", ")] : [])].join(
        " · ",
      ),
    tile: {
      verdict: "Kết luận",
      confidence: "Độ tin cậy",
      rag: "Tri thức (RAG)",
      evidence: "Dẫn chứng",
      // The line under the conclusion: whose word it is. The system's own `need_more_data` (a conclusion it held back,
      // or an older run's lowered one) says so; every other conclusion is the assistant's suggestion.
      verdictNote: { plain: "gợi ý của AI", held: "hệ thống giữ lại", overruled: "đã bị hạ" },
      // The line under the RAG tile, one for each state of the lookup and for each failure kind
      // (`rag.failures.FAILURE_KINDS`; strings.test.ts holds the keys equal to the backend's).
      ragNote: RAG_TILE_NOTE,
      evidenceNote: "khớp nguyên văn",
      evidenceNone: "không có dẫn chứng",
    },
    tabs: {
      label: "Chi tiết phân tích AI Tier 2",
      overview: "Tổng quan",
      timeline: "Diễn biến",
      hypotheses: "Giả thuyết",
      evidence: "Bằng chứng",
      tech: "Kỹ thuật",
    },
    // Tổng quan: the scope sets what the model said beside what the system knows of the case's alerts.
    overview: {
      scope: {
        label: "Phạm vi",
        hosts: "Máy",
        accounts: "Tài khoản",
        tactics: "Chiến thuật",
        model: (list: string) => `AI nêu: ${list}`,
        modelNone: "AI không nêu",
        system: (list: string) => `Hệ thống ghi: ${list}`,
        systemNone: "Hệ thống chưa ghi",
        steps: (count: number) => `${count} bước MITRE`,
        endsAt: (what: string) => `kết thúc ở ${what}`,
        noSteps: "chưa có dòng thời gian",
      },
      nextSteps: "Việc nên làm tiếp",
      priority: { high: "ưu tiên cao", medium: "trung bình", low: "thấp" },
      attention: "Cần lưu ý",
      unverified: (count: number, total: number) =>
        `${count} trên ${total} dẫn chứng chưa kiểm chứng được — cần xác minh trước khi tin (xem tab Bằng chứng).`,
    },
    // Diễn biến: the narrative the model wrote, then the timeline the server built from the alerts' own times.
    timeline: {
      label: "Dòng thời gian",
      none: "Lượt phân tích này không có dòng thời gian.",
      alert: "alert",
    },
    // Giả thuyết: each hypothesis, then what the knowledge base had (the same card as the alert page's).
    hypothesesTab: {
      likelihood: {
        high: "khả dĩ cao",
        medium: "khả dĩ trung bình",
        low: "khả dĩ thấp",
      },
      for: "Ủng hộ:",
      against: "Chống lại:",
      none: "Lượt phân tích này không nêu giả thuyết nào.",
      knowledgeBelowFloor: (floor: number | null) =>
        floor === null
          ? "Không mục nào đạt mức tối thiểu, nên không có tri thức tham khảo nào được đưa cho AI."
          : `Không mục nào đạt mức tối thiểu ${floor}%, nên không có tri thức tham khảo nào được đưa cho AI.`,
      knowledgeNoCandidate: "Không có mục tri thức đã duyệt nào được chấm điểm cho case này.",
      knowledgeNoLookup: "Lượt phân tích này không tra cứu tri thức đã duyệt.",
      knowledgeFailed: (reason: string | null) =>
        reason === null
          ? "Không tra cứu được tri thức đã duyệt."
          : `Không tra cứu được tri thức đã duyệt: ${reason}.`,
    },
    // Bằng chứng: the quotes the assistant cited and whether the server found each in the log.
    evidenceTab: {
      summary: (verified: number, cited: number) =>
        `${verified} trên ${cited} dẫn chứng khớp nguyên văn với log của alert trong case.`,
      matched: "khớp nguyên văn",
      alert: "alert",
    },
    // Kỹ thuật: the figures of the run. Tokens, time, cost and when are `S.analysis.tech`'s.
    tech: {
      playbook: "Playbook",
      alertsRead: "Alert AI đã đọc",
      alertsReadOf: (read: number, total: number) => `${read} trên ${total}`,
    },
  },

  // The admin console (P11-T10, spec §3): the sidebar, the page titles, the words every dialog shares, and
  // a text for each code the admin routes answer with. The page tasks add their own page's words under their
  // own key (`S.admin.users`, ...); what two pages share lives here.
  admin: {
    // The sidebar: the label of the navigation, then the six links in the order of the canvas.
    nav: {
      label: "Quản trị",
      overview: "Tổng quan",
      users: "Người dùng & quyền",
      llm: "LLM & hạn mức",
      labels: "Gán nhãn",
      knowledge: "Tri thức",
      audit: "Nhật ký audit",
    },
    // The h1 of each page (the canvas's own). The sidebar says it shorter.
    title: {
      overview: "Tổng quan hệ thống",
      users: "Người dùng và quyền",
      llm: "LLM và hạn mức",
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
        'Các ô số hiện 0, biểu đồ để trống. Nếu chờ đợi có alert, xem dòng "Tín hiệu gần nhất từ nguồn" ở khối Sức khoẻ.',

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
        waiting: "Chờ Tier-1",
        active: "Tier-1 đang xử lý",
        closed_by_tier1: "Đã đóng bởi Tier-1",
        escalated: "Chuyển Tier-2",
        // INT-T03 / DEC-212: shown only while something is archived; never part of "closed by Tier-1".
        archived: "Đã lưu trữ (dọn hàng đợi)",
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
        // The fourteen checks of `infra/health.py` (the last four are DEC-210's and P14-T06's), in the canvas's words; a name
        // with no label is shown as it is.
        check: {
          // True in both modes on purpose (INT-T02): with the pull on (the default) the check reads the last
          // pull that succeeded, alert or not; with it off, the last alert the webhook took. Neither "pull"
          // nor "alert" is in the words.
          heartbeat: "Tín hiệu gần nhất từ nguồn",
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
          rag_lookup_failures: "Tra cứu RAG thất bại liên tục",
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
      // The reason of a refused undo and of a refused label save alike: it names neither.
      frozen: "Tập vàng đã đóng băng — không gán thêm hay hoàn tác được nữa.",
      nothing_to_undo: "Bạn chưa có nhãn nào để hoàn tác.",
      forbidden:
        "Bạn không còn quyền làm việc này. Vai trò của tài khoản có thể đã đổi — đăng nhập lại.",
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
      // The read-only matrix of role to function (the canvas's rows, less the auto-close one that went with DEC-214), static text.
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
        unavailable: "nhà cung cấp LLM từ chối (hết số dư / hạn mức, 402)",
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

    // One label for each of the 40 names of `audit/events.py`'s EVENT_TYPES, read through `labelOf`. The
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
      "alert.archived": "Lưu trữ alert (dọn hàng đợi)",
      "case.archived": "Lưu trữ case (dọn hàng đợi)",
      "lab.run_created": "Tạo lần chạy lab",
      "lab.labeled": "Gán nhãn lab",
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
        // Since T2 (DEC-215) a case is the trigger alone and `correlated` is 0; the events written before it say
        // how many correlated alerts that escalation swept in, and still read as they were.
        caseSize: (alerts: number, correlated: number) =>
          correlated === 0
            ? `${alerts} alert, không kéo theo alert liên quan`
            : `${alerts} alert, ${correlated} liên quan`,
        truncated: (n: number) => `cắt ${n} cụm vượt giới hạn của case`,
        truncatedUnknown: "case bị cắt bớt cụm",
        concluded: (conclusion: string) => `kết luận: ${conclusion}`,
        concludedUnknown: "Tier 2 kết luận case",
        archived: "lưu trữ khi dọn hàng đợi, không ai quyết định",
        caseArchived: "lưu trữ khi dọn hàng đợi, không ai kết luận",
        archivedFrom: (status: string) => `trạng thái trước đó: ${status}`,
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
        // The lab events (DEC-213, P14-T09): a run recorded, an alert labelled by hand. The summary names the
        // run and what it is for, or the label; it says nothing of the alert, and the subject is not linked
        // (the alert's page shows ①'s answer, and labelling is blind to it).
        labRunCreated: "ghi nhận một lần chạy lab",
        labRunName: (name: string) => `tên: ${name}`,
        labPurpose: (purpose: string) => `mục đích: ${purpose}`,
        labPurposes: {
          kb: "dựng cơ sở tri thức",
          test: "để chấm điểm",
        } as Readonly<Record<string, string>>,
        labLabeled: (label: string) => `gán nhãn: ${label}`,
        labLabelCleared: "xoá nhãn lab",
        labLabelUnknown: "gán nhãn lab",
        labLabels: {
          true_positive: "tấn công thật (TP)",
          false_positive: "không phải tấn công (FP)",
        } as Readonly<Record<string, string>>,
      },
    },

    // The verdicts a digest review recorded, as the audit page words an `autoclose.reviewed` event (auditSummary.ts).
    // The digest page that wrote them was removed with DEC-214; an old event still reads correctly.
    verdict: {
      correct: "Đúng",
      wrong: "Sai",
      unsure: "Không chắc",
    } satisfies Record<"correct" | "wrong" | "unsure", string>,

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

    // The lab labelling pages (DEC-213, P14-T10, spec §6): the lab runs the measurement is made on, and the hand
    // labels (TP, FP) that are its ground truth. This block holds its own sidebar link and titles too, so the
    // sidebar reads `lab.nav` (a test pins both). The run page is BLIND: its words name the alert's own fields and
    // the two labels, nothing of ① or ② (LabRunPage.test.tsx reads this block and its page for that). A refusal
    // is worded here, by the field the server names or by the kind `labErrorOf` reads: the page never shows a code.
    lab: {
      nav: "Gán nhãn lab",
      title: { runs: "Gán nhãn lab", run: "Lần chạy lab" },
      // `PURPOSES` of lab/runs.py; a test keeps the keys equal.
      purpose: { kb: "Xây kho", test: "Chấm điểm" },
      // The state of an alert's label: `LABELS` of lab/labels.py, and none.
      label: { true_positive: "TP", false_positive: "FP", none: "chưa gán" },
      progress: (labelled: number, total: number) => `Đã gán ${labelled}/${total}`,
      // The window of a run: the time it starts, an arrow, the time it ends.
      window: (starts: string, ends: string) => `${starts} → ${ends}`,

      // The words of a 422 beside its field, by reason; a few depend on the field (`labFieldText`).
      fieldReason: {
        required: "Phải điền trường này",
        requiredPurpose: "Chọn một mục đích",
        empty: "Không được để trống",
        tooLong: (max: number) => `Quá dài: tối đa ${max} ký tự`,
        invalidName: "Tên có ký tự không được dùng (ký tự điều khiển hoặc ký tự vô hình)",
        invalidPurpose: "Chọn Xây kho hoặc Chấm điểm",
        invalidTime: (yearMin: number, yearMax: number) =>
          `Thời điểm không hợp lệ. Chỉ nhận các năm từ ${yearMin} đến ${yearMax} (theo giờ UTC).`,
        invalidLabel: "Nhãn không hợp lệ",
        taken: "Tên này đã được dùng cho lần chạy khác",
        not_after_starts: "Giờ kết thúc phải sau giờ bắt đầu",
      },

      // `/admin/lab`: the runs, and the form that makes one.
      runsPage: {
        subtitle:
          "Mỗi lần chạy lab là một khung giờ. Alert nhận vào trong khung giờ đó thuộc lần chạy; bạn gán TP hoặc FP cho từng alert để làm đáp án của phép đo.",
        count: (n: number) => `${n} lần chạy`,
        tableLabel: "Các lần chạy lab",
        col: { name: "Tên", purpose: "Mục đích", window: "Khung giờ", labelled: "Tiến độ gán" },
        empty: "Chưa có lần chạy nào. Tạo lần chạy đầu tiên ở khung bên cạnh.",
        create: {
          title: "Tạo lần chạy",
          name: "Tên lần chạy",
          namePlaceholder: "Ví dụ: Lần chạy chấm điểm 1",
          nameHint: (max: number) => `Tối đa ${max} ký tự, không trùng tên lần chạy khác.`,
          purpose: "Mục đích",
          purposeHelp: {
            kb: "Alert của lần chạy này dùng để xây kho tri thức.",
            test: "Alert của lần chạy này được chấm điểm.",
          },
          starts: "Bắt đầu",
          ends: "Kết thúc",
          timeHint:
            "Giờ Việt Nam (UTC+7). Alert nhận vào từ giờ bắt đầu đến trước giờ kết thúc thuộc lần chạy. Hai lần chạy không được trùng khung giờ; lần sau có thể bắt đầu đúng lúc lần trước kết thúc.",
          overlap: "Khung giờ trùng với lần chạy khác",
          submit: "Tạo lần chạy",
          done: (name: string) => `Đã tạo lần chạy “${name}”.`,
        },
      },

      // `/admin/lab/:runId`: the alerts of one run, oldest first, and the buttons that label them.
      runPage: {
        back: "← Các lần chạy lab",
        subtitle:
          "Gán nhãn mù: trang chỉ hiện dữ kiện của alert, không hiện kết quả phân tích nào. Gán TP nếu là tấn công thật, FP nếu không phải.",
        windowLabel: "Khung giờ",
        listLabel: "Các alert của lần chạy",
        alertLabel: (id: string) => `Alert ${id}`,
        received: "Nhận lúc",
        rule: "rule",
        level: (level: number) => `(level ${level})`,
        agent: "Máy",
        details: "Chi tiết",
        detail: {
          alertTime: "Giờ SIEM phát hiện",
          user: "User",
          category: "Loại",
          mitre: "MITRE",
          count: "Số lần gặp",
          rawLog: "raw_log",
          rawLogCut: "raw_log dài hơn 32 KB: đã cắt ở 32 KB khi hiển thị.",
        },
        action: {
          true_positive: "TP — tấn công thật",
          false_positive: "FP — không phải tấn công",
          clear: "Bỏ nhãn",
        },
        actionsLabel: "Nhãn của alert này",
        empty: "Chưa có alert nào nhận vào trong khung giờ này.",
        shown: (n: number) => `Đang hiện ${n} alert`,
        loadMore: "Tải thêm",
        loadingMore: "Đang tải…",
        loadMoreFailed: "Không tải thêm được. Thử lại.",
        // The run is not there (a 404, or an id in the address that is no uuid): not an error to retry.
        notFound: "Không tìm thấy lần chạy này",
        backToRuns: "Về danh sách lần chạy",
        // What a label that was refused says, on the row.
        rowError: {
          not_a_queue_head:
            "Alert này là bản sao của một alert khác nên không gán nhãn được. Gán nhãn cho alert gốc.",
          outside_every_run: "Alert này nằm ngoài mọi lần chạy nên không gán nhãn được.",
          not_found: "Không tìm thấy alert này nữa.",
        },
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
          // P14-T07 (DEC-213): the newest lookup of the source - every candidate the Voyage rerank scored, as a
          // percentage (where the P13 agent's reasons used to be), or why a failed lookup failed (S.rag.failureKind).
          // `status` is `rag_results.status`, read through `labelOf`.
          lookup: {
            heading: "Tra cứu tri thức",
            hint: "Lần tra cứu mới nhất của nguồn này: các mục tri thức đã duyệt được chấm điểm giống với nguồn.",
            status: {
              ok: "Đã tra cứu",
              empty: "Chưa có tri thức nào để so",
              failed: "Tra cứu thất bại",
              budget: "Hết hạn mức RAG, không tra cứu",
            },
            at: (time: string) => `Lúc ${time}`,
            reason: (label: string) => `Lý do: ${label}`,
            ranked: "Điểm giống của từng mục tri thức",
            rankedNone: "Không có mục tri thức nào được chấm điểm.",
            percent: (pct: number) => `${pct}%`,
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
        // The provider's refusal (a 402, R4) as well as the model's (INT-T02).
        llm_permanent:
          "Nhà cung cấp hoặc mô hình từ chối yêu cầu (ví dụ hết số dư, 402), không thử lại.",
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

/**
 * The words for a RAG failure kind (`S.rag.failureKind`, P14-T07), or null when the table has none: unlike
 * `labelOf` it never falls back on the code. The pages draw a notice for a kind they can word and nothing for any
 * other, so a value the server should never send (or a name from the prototype chain) is not shown as it came.
 */
export function failureKindLabel(kind: string | null | undefined): string | null {
  if (kind === null || kind === undefined || !Object.hasOwn(S.rag.failureKind, kind)) return null;
  const label: unknown = (S.rag.failureKind as Record<string, unknown>)[kind];
  return typeof label === "string" ? label : null;
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
