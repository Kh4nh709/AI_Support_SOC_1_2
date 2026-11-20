import sample from "./admin-samples.json";
import { empty, labId, alertId, now, json, scenario } from "./data";
const clusters = empty ? [] : sample.clusters;
clusters.forEach((c, i) => {
  c.alert_id = c.gold_cluster_id = alertId.slice(0, -2) + (40 + i);
  c.correlation.samples.forEach((s) => (s.alert_id = alertId.slice(0, -2) + "48"));
});
const labels = [];
const sourceAlerts = clusters.map((c, i) => ({
  alert_id: c.alert_id,
  received_at: now,
  alert_time: now,
  rule_id: c.rule_id,
  rule_level: c.rule_level,
  severity: c.severity,
  description: c.description,
  agent_name: c.agent_name,
  alert_user: c.alert_user,
  srcip: c.srcip,
  dstip: c.dstip,
  category: c.category,
  mitre_ids: ["T1110"],
  occurrence_count: c.occurrence_count,
  raw_log: c.raw_log,
  raw_log_truncated_for_display: false,
  label: i === 0 ? "true_positive" : null,
}));
const runs = empty
  ? []
  : [
      {
        run_id: labId,
        name: "Kiểm tra xác thực trên máy lab",
        purpose: "test",
        starts_at: "2026-11-20T02:00:00Z",
        ends_at: "2026-11-20T03:00:00Z",
        alerts: sourceAlerts,
      },
    ];
const info = ({ alerts, ...run }) => ({
  ...run,
  total: alerts.length,
  labelled: alerts.filter((a) => a.label !== null).length,
});
function gold(path, body) {
  const done = labels.length,
    total = clusters.length,
    cluster = clusters[done] ?? null;
  if (path.endsWith("/next"))
    return {
      cluster_id: cluster?.gold_cluster_id ?? null,
      done,
      total,
      cluster,
      frozen: scenario === "frozen",
      candidates_present: total > 0,
    };
  if (path.endsWith("/undo")) {
    const last = labels.pop();
    return last
      ? { undone_cluster_id: last.cluster_id, done: labels.length, total }
      : json({ detail: { reason: "nothing_to_undo" } }, 404);
  }
  if (cluster?.gold_cluster_id !== body.cluster_id)
    return json({ detail: { reason: "unknown_cluster" } }, 404);
  labels.push(body);
  return {
    cluster_id: body.cluster_id,
    done: labels.length,
    total,
    next: clusters[labels.length]?.gold_cluster_id ?? null,
  };
}
export function labellingApi(path, q, body, method) {
  if (path.startsWith("/admin/labels")) return gold(path, body);
  if (path === "/admin/lab/runs") {
    if (method === "GET") return { runs: runs.map(info) };
    if (
      runs.some(
        (r) =>
          Date.parse(r.ends_at) > Date.parse(body.starts_at) &&
          Date.parse(r.starts_at) < Date.parse(body.ends_at),
      )
    )
      return json({ detail: { reason: "overlap" } }, 409);
    const item = { ...body, run_id: crypto.randomUUID(), alerts: [] };
    runs.unshift(item);
    return info(item);
  }
  if (path.startsWith("/admin/lab/labels/")) {
    const id = path.split("/").pop(),
      r = runs.find((r) => r.alerts.some((a) => a.alert_id === id));
    if (!r) return json({}, 404);
    const a = r.alerts.find((a) => a.alert_id === id);
    a.label = method === "DELETE" ? null : body.label;
    return a.label
      ? { alert_id: id, run_id: r.run_id, label: a.label }
      : new Response(null, { status: 204 });
  }
  const item = runs.find((r) => r.run_id === path.split("/")[4]);
  return item ? { run: info(item), alerts: item.alerts, next_after: null } : json({}, 404);
}
