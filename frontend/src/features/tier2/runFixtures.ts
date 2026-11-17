// Runs of ② as `investigation_view.present_run` serves them, for the tests of the Tier 2 panel: a version 4 run with
// every key (DEC-221), an older run with none of the new ones, and a stopped run. The wording is the approved
// mock-up's; the shapes are the server contract's (backend/tests/test_panel_t2_pure.py). Nothing here is shown to a
// person: it stands for what the server sends.
import type { RunView } from "../../api/tier2";

export const RUN_ID = "6f1c7a52-98d4-5c0e-b3a1-2d4e6f8a0b1c";

type Over = Record<string, unknown>;

export const evidenceRow = (over: Over = {}) => ({
  alert_id: "111976",
  quote: "CommandLine: vssadmin delete shadows /all /quiet",
  why: "Lệnh xoá toàn bộ shadow copy, không hỏi lại.",
  verified: true,
  reason_text: null,
  ...over,
});

export const unverifiedRow = (over: Over = {}) =>
  evidenceRow({
    alert_id: "112438",
    quote: "RemoteName: hxxp://… /update.bin",
    why: "Job BITS tải tệp từ một máy chủ bên ngoài.",
    verified: false,
    reason_text: "trích dẫn không có trong log hay mô tả của alert",
    ...over,
  });

export const timelineRow = (over: Over = {}) => ({
  alert_id: "112437",
  // 18:28 in +07
  time: "2026-11-15T11:28:00+00:00",
  what: "amsi.dll được nạp bởi splwow64.exe",
  tactic: "Né tránh phòng thủ",
  technique: "T1562.001",
  // DEC-223: what the server made of `technique` against the local ATT&CK document. null, null is the server with no
  // such document (and a technique that is not an id): the row reads as it did before; the tests of the check set both.
  technique_name: null,
  technique_known: null,
  ...over,
});

export const TIMELINE = [
  timelineRow(),
  timelineRow({
    alert_id: "112438",
    time: "2026-11-15T11:31:00+00:00",
    what: "Job BITS được tạo bởi tiến trình không thường dùng BITS",
    tactic: "Duy trì hiện diện",
    technique: "T1197",
  }),
  timelineRow({
    alert_id: "111525",
    time: "2026-11-15T11:40:00+00:00",
    what: "PowerShell chạy với tham số mã hoá Base64",
    tactic: "Thực thi",
    technique: "T1059.001",
  }),
  timelineRow({
    alert_id: "111976",
    time: "2026-11-15T11:52:00+00:00",
    what: "Shadow copy bị xoá bằng vssadmin",
    tactic: "Gây tác động",
    technique: "T1490",
  }),
];

export const HYPOTHESES = [
  {
    text: "Chuẩn bị triển khai ransomware",
    evidence_for: ["bốn bước nối tiếp trong 24 phút, cùng tài khoản"],
    evidence_against: ["chưa có alert mã hoá tệp"],
    likelihood: "high",
  },
  {
    text: "Quản trị viên bảo trì máy",
    evidence_for: ["tài khoản Administrator, trong giờ làm việc"],
    evidence_against: ["lệnh PowerShell bị mã hoá", "máy thuộc phòng nhân sự"],
    likelihood: "low",
  },
];

export const CANDIDATES = [
  { pct: 84, title: "PowerShell mã hoá kèm xoá shadow copy", conclusion: "confirmed_incident" },
  { pct: 71, title: "Job BITS tải công cụ từ máy chủ ngoài", conclusion: "confirmed_incident" },
  { pct: 58, title: "Quản trị viên dọn shadow copy theo lịch", conclusion: "closed_benign" },
];

export const NEXT_STEPS = [
  { step: "Cô lập máy Windows_Endpoint khỏi mạng.", priority: "high" },
  { step: "Thu danh sách job BITS và nội dung lệnh PowerShell đã giải mã.", priority: "high" },
  { step: "Tìm cùng chuỗi hành vi trên các máy khác trong 24 giờ.", priority: "medium" },
  { step: "Đặt lại mật khẩu tài khoản Administrator của máy.", priority: "low" },
];

/** A version 4 run with a result: every key of the contract, a conclusion the system did not touch. */
export const runV4 = (over: Over = {}) => ({
  run_id: RUN_ID,
  // 19:02:11 in +07
  created_at: "2026-11-15T12:02:11+00:00",
  rag: { best_pct: 84, not_applied: null, below_floor_pct: null, floor_pct: 50 },
  result: { suggested_conclusion: "confirmed_incident", timeline: [] },
  conclusion: "confirmed_incident",
  conclusion_label: "Là sự cố thật",
  confidence: "medium",
  summary:
    "Trong 24 phút, tài khoản Administrator trên một máy trạm đã nạp amsi.dll từ trình in, tạo job BITS, chạy PowerShell mã hoá và xoá shadow copy.",
  narrative: "18:28 amsi.dll được nạp\n18:52 shadow copy bị xoá",
  hypotheses: HYPOTHESES,
  evidence: [
    evidenceRow(),
    evidenceRow({
      alert_id: "111525",
      quote: "CommandLine: powershell.exe -NoP -W Hidden -Enc SQBFAFgA…",
      why: "PowerShell chạy ẩn với nội dung mã hoá.",
    }),
    unverifiedRow(),
  ],
  evidence_summary: { cited: 3, verified: 2 },
  timeline: TIMELINE,
  scope: {
    hosts: ["wazuh-win-01"],
    accounts: ["Administrator"],
    system: { hosts: ["Windows_Endpoint"], accounts: ["Administrator"], alert_count: 4 },
  },
  next_steps: NEXT_STEPS.map((row) => row.step),
  next_steps_rows: NEXT_STEPS,
  playbook_used: "ransomware_v1",
  overruled: null,
  model_conclusion: "confirmed_incident",
  held_by: [],
  snapshot: { alert_count: 4, total_occurrences: 9, last_seen_at: "2026-11-15T11:52:00+00:00" },
  changed: false,
  tech: {
    input_tokens: 21480,
    output_tokens: 1612,
    latency_ms: 9800,
    cost_usd: 0.0013,
    analysed_at: "2026-11-15T12:02:11+00:00",
    playbook: "ransomware_v1",
    alerts_read: 4,
  },
  knowledge: {
    state: "matched",
    failure: null,
    best_pct: 84,
    floor_pct: 50,
    threshold_pct: 0,
    scored: 23,
    candidates: CANDIDATES,
  },
  ...over,
});

/**
 * A run stored before version 4 (`investigate_v3`): the new keys are there but empty, as the server serves them for such
 * a run: no timeline, nothing the model said of the scope, no likelihood, no priority, no figures but the system's.
 */
export const runV3 = (over: Over = {}) =>
  runV4({
    result: { suggested_conclusion: "confirmed_incident" },
    hypotheses: HYPOTHESES.map((row) => ({ ...row, likelihood: null })),
    timeline: [],
    scope: {
      hosts: [],
      accounts: [],
      system: { hosts: ["Windows_Endpoint"], accounts: ["Administrator"], alert_count: 4 },
    },
    next_steps_rows: NEXT_STEPS.map((row) => ({ step: row.step, priority: null })),
    tech: {
      input_tokens: null,
      output_tokens: null,
      latency_ms: null,
      cost_usd: null,
      analysed_at: "2026-11-15T12:02:11+00:00",
      playbook: "ransomware_v1",
      alerts_read: null,
    },
    ...over,
  });

/**
 * A run from a server that serves none of the new keys at all (the shape this UI read before DEC-221): the panel
 * must still draw its frame from the old keys alone.
 */
export const runOld = (over: Over = {}): Record<string, unknown> => {
  const {
    evidence_summary: _summary,
    timeline: _timeline,
    scope: _scope,
    next_steps_rows: _rows,
    tech: _tech,
    knowledge: _knowledge,
    ...rest
  } = runV3();
  void [_summary, _timeline, _scope, _rows, _tech, _knowledge];
  return {
    ...rest,
    hypotheses: HYPOTHESES.map(({ text, evidence_for, evidence_against }) => ({
      text,
      evidence_for,
      evidence_against,
    })),
    ...over,
  };
};

/** A run that stopped with no result (`present_run`: `result: null` and the stop reason only). */
export const stoppedRun = (text: string, over: Over = {}) => ({
  run_id: RUN_ID,
  created_at: "2026-11-15T12:02:11+00:00",
  rag: { best_pct: null, not_applied: null, below_floor_pct: null, floor_pct: null },
  result: null,
  stopped_text: text,
  ...over,
});

/** The `knowledge` of a run, for the states the lookup can end in. */
export const knowledgeOf = (state: string, over: Over = {}) => ({
  state,
  failure: null,
  best_pct: null,
  floor_pct: 50,
  threshold_pct: 0,
  scored: 0,
  candidates: [],
  ...over,
});

export const asRun = (value: unknown): RunView => value as RunView;
