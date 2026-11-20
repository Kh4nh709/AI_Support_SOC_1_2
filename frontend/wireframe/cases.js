import { S } from "../src/strings";
import { runV4, RUN_ID } from "../src/features/tier2/runFixtures";
import { alerts, alertData, escalations } from "./queue";
import { caseId, empty, me, now, json, scenario } from "./data";

function makeCase(id, title, status, row) {
  const open = status === "investigating",
    archived = status === "archived";
  const headStatus = {
    investigating: "escalated_tier2",
    concluded_fp: "closed_fp",
    concluded_policy_violation: "closed_benign",
    confirmed_incident: "closed_confirmed",
    archived: "archived",
  }[status];
  return {
    case_id: id,
    title,
    status,
    severity: row.severity,
    created_by: "minh.nguyen",
    created_at: "2026-11-19T02:10:00Z",
    last_analyzed_at: "2026-11-20T01:31:00Z",
    last_run: { created_at: "2026-11-20T01:31:00Z", has_result: true },
    ongoing: open,
    ongoing_last_seen: open ? now : null,
    cluster_count: 1,
    occurrence_count: row.occurrence_count,
    concluded_at: open ? null : now,
    concluded_by_name: open || archived ? null : "linh.tran",
    conclusion_reason: open ? null : "Đã đối chiếu bằng chứng và lịch vận hành.",
    heads: [{ ...alertData(row), status: headStatus }],
    notes: [],
  };
}
const cases = Object.keys(S.caseStatus).map((status, i) =>
  makeCase(
    i ? caseId.slice(0, -1) + (i + 1) : caseId,
    [
      "Điều tra tiến trình nạp AMSI",
      "Đăng nhập theo lịch bảo trì",
      "Kiểm tra tuân thủ trên máy biên",
      "Sự cố đã xác nhận",
      "Hồ sơ lưu trữ",
    ][i],
    status,
    alerts[i],
  ),
);
// Case evidence has its own heads. Following a head link must open the same
// record, with the case status, instead of reopening an unrelated queue item.
const baseline = runV4();
const ruleTitles = [
  "Unusual AMSI library load",
  "Background transfer job created",
  "Encoded PowerShell detected",
  "Shadow copy deletion detected",
];
for (const [index, item] of cases.entries()) {
  const count = index === 0 ? baseline.timeline.length : 1;
  item.heads = Array.from({ length: count }, (_, n) => {
    const base = alerts[index];
    const event = baseline.timeline[n];
    const id = base.alert_id.slice(0, -4) + (0xa100 + index * 8 + n).toString(16);
    const record = {
      ...base,
      alert_id: id,
      case_id: item.case_id,
      status: item.heads[0].status,
      description: index === 0 ? ruleTitles[n] : base.description,
      rule_id: index === 0 ? event.alert_id : base.rule_id,
      occurrence_count: n === 0 ? base.occurrence_count : 1,
    };
    alerts.push(record);
    return alertData(record);
  });
  item.cluster_count = count;
  item.occurrence_count = item.heads.reduce((sum, h) => sum + h.occurrence_count, 0);
}
function presentRun(item, snapshot) {
  const headFor = (id) =>
    item.heads[baseline.timeline.findIndex((e) => e.alert_id === id)] ?? item.heads[0];
  const evidence = baseline.evidence.map((e) => ({ ...e, alert_id: headFor(e.alert_id).alert_id }));
  const timeline = baseline.timeline
    .slice(0, item.heads.length)
    .map((e) => ({ ...e, alert_id: headFor(e.alert_id).alert_id }));
  return runV4({
    snapshot,
    changed: item.ongoing,
    created_at: item.last_analyzed_at,
    evidence,
    timeline,
    scope: {
      ...baseline.scope,
      hosts: [item.heads[0].agent_name],
      system: {
        hosts: [item.heads[0].agent_name],
        accounts: ["Administrator"],
        alert_count: item.heads.length,
      },
    },
    tech: { ...baseline.tech, analysed_at: item.last_analyzed_at, alerts_read: item.heads.length },
  });
}
const states = new Map();
export function caseApi(path, q, body) {
  if (!path.startsWith("/tier2/cases")) return;
  if (me.role === "tier1") return json({}, 403);
  for (const entry of escalations) {
    if (!cases.some((c) => c.case_id === entry.case_id))
      cases.unshift(makeCase(entry.case_id, entry.title, "investigating", entry.alert));
  }
  if (path === "/tier2/cases") {
    const start = Number(q.get("offset"));
    return empty ? [] : cases.slice(start, start + Number(q.get("limit") || 50));
  }
  const [, , , id, action] = path.split("/");
  const item = cases.find((c) => c.case_id === id);
  if (!item || empty) return json({}, 404);
  if (!action) return item;
  if (action === "notes") {
    const note = {
      note_id: item.notes.length + 1,
      case_id: id,
      body: body.body,
      author_id: me.user_id,
      author_name: me.username,
      created_at: new Date().toISOString(),
    };
    item.notes.push(note);
    return note;
  }
  if (action === "conclude") {
    Object.assign(item, {
      status: body.conclusion,
      concluded_by: me.user_id,
      concluded_by_name: me.username,
      concluded_at: new Date().toISOString(),
      conclusion_reason: body.reason,
      ongoing: false,
    });
    item.heads.forEach(
      (h) =>
        (h.status = {
          concluded_fp: "closed_fp",
          concluded_policy_violation: "closed_benign",
          confirmed_incident: "closed_confirmed",
        }[body.conclusion]),
    );
    for (const head of item.heads) {
      const alert = alerts.find((row) => row.alert_id === head.alert_id);
      if (alert) alert.status = head.status;
    }
    return item;
  }
  if (action === "analyze") {
    if (scenario === "quota") return json({ detail: "quota exhausted" }, 429);
    states.set(id, "running");
    setTimeout(() => {
      states.set(id, "done");
      item.ongoing = false;
      item.last_analyzed_at = new Date().toISOString();
      item.last_run = { created_at: item.last_analyzed_at, has_result: true };
    }, 1600);
    return { run_id: RUN_ID, job_id: 41 };
  }
  if (action === "investigation") {
    const state =
      states.get(id) ||
      (["idle", "running", "stalled", "failed"].includes(scenario)
        ? scenario
        : scenario === "quota"
          ? "idle"
          : "done");
    const current = {
      alert_count: item.heads.length,
      total_occurrences: item.occurrence_count,
      last_seen_at: now,
    };
    const snapshot = item.ongoing
      ? {
          ...current,
          total_occurrences: Math.max(1, current.total_occurrences - 1),
          last_seen_at: item.last_analyzed_at,
        }
      : current;
    return {
      state,
      run_id: state === "idle" ? null : RUN_ID,
      minutes: state === "stalled" ? 12 : null,
      case_open: item.status === "investigating",
      current,
      run: state === "done" ? presentRun(item, snapshot) : null,
    };
  }
}
