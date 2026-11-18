// What the server serves as `analysis` (DEC-221, AP-T2: `backend/app/tier1/analysis.py`), as fixtures for the tests of
// the Tier 1 panel. The default is the run of the approved mock-up (a TP with a medium confidence, the best knowledge
// candidate at 47% under the 50% floor, two warnings); the variants are the three shapes a run can have: a version 4 run
// (this one), an older run (stored before version 4: none of the model's five texts) and a run the RAG default of
// DEC-219 applied to (nothing of the model's own answer). Test support only: nothing in the product imports it.
import type { Analysis, AlertView } from "../../api/tier1";

export const analysis = (over: Partial<Analysis> = {}): Analysis => ({
  summary:
    "amsi.dll bị nạp bởi splwow64.exe dưới tài khoản Administrator, lặp lại hai lần trong một giờ, ngay sau một alert BITS Jobs trên cùng máy.",
  reading_attack: "Mã độc nạp amsi.dll để dò hoặc vô hiệu hoá AMSI trước khi chạy PowerShell.",
  reading_benign:
    "splwow64.exe là trình in của Windows; phiên in từ ứng dụng có macro nạp amsi.dll hợp lệ.",
  would_change:
    "tiến trình cha là ứng dụng văn phòng đang in, không có lệnh PowerShell nào theo sau.",
  next_checks: [
    "Xem tiến trình cha và dòng lệnh của splwow64.exe (PID 728).",
    "Tìm lệnh PowerShell hoặc kết nối ra ngoài trong 30 phút sau đó.",
    "Đối chiếu job BITS của alert 112438: tải gì, từ đâu.",
  ],
  reasons: [
    {
      claim: "amsi.dll được nạp bởi tiến trình bất thường splwow64.exe.",
      quote: "Image: C:\\Windows\\splwow64.exe · ImageLoaded: C:\\Windows\\System32\\amsi.dll",
      source: "wazuh_raw_log",
      verified: true,
      why: null,
    },
    {
      claim: "Tài khoản thực thi là tài khoản đặc quyền.",
      quote: "identity: username=Administrator",
      source: "context",
      verified: true,
      why: null,
    },
    {
      claim: "Alert tương tự lặp lại trên cùng máy trong khoảng một giờ, kèm alert BITS Jobs.",
      quote: "rule 112437 lần 2, PID 728 cùng ProcessGuid … rule 112438 BITS Jobs",
      source: "correlation_samples",
      verified: false,
      why: "not_substring",
    },
    {
      claim: "15 trên 15 case cùng kịch bản và cùng máy đã được xác nhận là sự cố thật.",
      quote: null,
      source: null,
      verified: false,
      why: "empty_quote",
    },
  ],
  facts: [
    { field: "severity", system: "medium", model: "high", match: false },
    { field: "ioc_reputation", system: "skipped", model: "skipped", match: true },
    { field: "asset_criticality", system: "medium", model: "medium", match: true },
    { field: "identity_privileged", system: "true", model: "true", match: true },
    { field: "occurrence_count", system: 2, model: 2, match: true },
  ],
  checks: [
    { id: "1", outcome: "pass", detail: "schema_ok" },
    { id: "2", outcome: "warn", detail: "facts_mismatch" },
    { id: "3", outcome: "pass", detail: "quotes_some_dropped" },
    { id: "4", outcome: "na", detail: "not_false_positive" },
    { id: "5", outcome: "pass", detail: "no_injection_findings" },
    { id: "6", outcome: "warn", detail: "verifier_disagrees" },
  ],
  check_totals: { passed: 3, applicable: 5, warnings: 2 },
  rag: {
    state: "below_floor",
    failure: null,
    best_pct: 47,
    floor_pct: 50,
    scored: 23,
    candidates: [
      {
        pct: 47,
        title: "PowerShell mã hoá Base64 từ wazuh-agent",
        conclusion: "confirmed_incident",
      },
      { pct: 43, title: "Shell quyền SYSTEM do agent giám sát sinh ra", conclusion: "closed_fp" },
      { pct: 41, title: "Tác vụ cập nhật định kỳ của Windows", conclusion: "closed_benign" },
    ],
  },
  history: {
    key: "scenario_host",
    total: 15,
    by_conclusion: {
      tier1_closed_fp: 0,
      tier1_closed_benign: 0,
      escalated_open: 0,
      concluded_fp: 0,
      concluded_policy_violation: 0,
      confirmed_incident: 15,
    },
    last_seen: "2026-11-06T09:00:00Z",
  },
  playbook: {
    name: "ransomware_v1",
    rule_id: "ran-1",
    rule_action: "needs_review",
    rule_table_reviewed: true,
  },
  highlights: [
    { direction: "up", code: "history_incident", params: { count: 15, total: 15 } },
    { direction: "up", code: "identity_privileged", params: {} },
    { direction: "warn", code: "rag_below_floor", params: { pct: 47, floor_pct: 50 } },
    { direction: "warn", code: "warning_verifier_disagrees", params: {} },
  ],
  tech: {
    input_tokens: 13637,
    output_tokens: 981,
    latency_ms: 4200,
    cost_usd: 0.0007,
    analysed_at: "2026-11-15T11:35:56Z",
    mitre_ids: ["T1490"],
    correlated_at_analysis: 3,
  },
  ...over,
});

/**
 * A run stored before version 4: the five texts the model writes are not there (`null`, and `[]` for the list); the
 * rest of the object is what the server builds from the gate and the lookup, and is there.
 */
export const olderAnalysis = (over: Partial<Analysis> = {}): Analysis =>
  analysis({
    summary: null,
    reading_attack: null,
    reading_benign: null,
    would_change: null,
    next_checks: [],
    ...over,
  });

/**
 * A run the RAG rule decided (DEC-219, DEC-225): the page is not told, but the server withholds what would give the
 * model's answer away. What it then does not send is `null` or left out: the two readings and `would_change`, the
 * model's column of the facts and `match`, and the verifier's check (row 6), and step 4 is told from the system facts
 * only. The lookup matched (62%).
 */
export const ruleDecidedAnalysis = (over: Partial<Analysis> = {}): Analysis =>
  analysis({
    reading_attack: null,
    reading_benign: null,
    would_change: null,
    reasons: analysis().reasons.slice(0, 2),
    facts: [
      { field: "severity", system: "medium", model: null, match: null },
      { field: "ioc_reputation", system: "skipped", model: null, match: null },
      { field: "asset_criticality", system: "medium", model: null, match: null },
      { field: "identity_privileged", system: "false", model: null, match: null },
      { field: "occurrence_count", system: 2, model: null, match: null },
    ],
    checks: [
      { id: "1", outcome: "pass", detail: "schema_ok" },
      { id: "2", outcome: "pass", detail: "facts_match" },
      { id: "3", outcome: "pass", detail: "quotes_verified" },
      { id: "4", outcome: "pass", detail: "fp_policy_ok" },
      { id: "5", outcome: "pass", detail: "no_injection_findings" },
    ],
    check_totals: { passed: 5, applicable: 5, warnings: 0 },
    rag: {
      state: "matched",
      failure: null,
      best_pct: 62,
      floor_pct: 50,
      scored: 12,
      candidates: [
        { pct: 62, title: "Quét cổng từ máy trong mạng nội bộ", conclusion: "closed_fp" },
        {
          pct: 55,
          title: "Đăng nhập thất bại lặp lại từ máy quản trị",
          conclusion: "concluded_fp",
        },
      ],
    },
    highlights: [
      { direction: "down", code: "rag_matched", params: { pct: 62, conclusion: "closed_fp" } },
    ],
    ...over,
  });

/**
 * The `suggestion` and the keys beside it that go with a run the RAG rule decided, as the server serves them (DEC-219,
 * DEC-225): the verdict ① ended with, no confidence, no verifier verdict, and no `rag_rule`.
 */
export const ruleDecidedKeys = (best = 62): Partial<AlertView> => ({
  suggestion: {
    run_id: "r1",
    suggested_action: "false_positive",
    confidence: null,
    reasons: [],
    gate: {
      forced: false,
      forced_by: [],
      proposed_verdict: "false_positive",
      final_verdict: "false_positive",
      verifier_verdict: null,
      warnings: [],
    },
    correlated_at_analysis: 3,
    created_at: "2026-11-15T11:35:56Z",
  },
  proposed_action: "false_positive",
  held_by: [],
  rag: { best_pct: best, not_applied: null },
});
