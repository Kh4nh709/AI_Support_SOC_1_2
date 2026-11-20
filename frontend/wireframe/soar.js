import { review, notice, detailOf } from "../src/features/soar/fixtures";
import { alerts } from "./queue";
import { empty, json, me, page } from "./data";

const moment = Date.now();
const iso = (minutes) => new Date(moment + minutes * 60000).toISOString();
const tickets = Array.from({ length: 57 }, (_, i) => {
  const critical = i % 5 === 0,
    host = critical ? "ad-server.home.arpa" : "fw-edge-01";
  const type = critical ? "isolate_host" : "block_ip",
    target = critical ? host : "192.0.2." + (20 + i);
  const status =
    i === 2
      ? "processing"
      : i < 53
        ? "open"
        : ["kept", "undone", "false_positive", "expired"][i - 53];
  return review({
    id: "RV" + (885310 + i),
    status,
    simulated: true,
    host,
    action_type: type,
    action_target: target,
    action_via: critical ? "wazuh" : "pfsense",
    action_text: critical ? "Cách ly máy " + host : "Chặn IP " + target,
    src_ip: critical ? null : target,
    scenario_id: critical ? "MW03" : "SC03",
    scenario_name: critical ? "Microsoft Defender malware detection" : "External port scan",
    case_number: 65 + i,
    case_id: "~" + (4096 + i),
    score: critical ? 85 : 50,
    host_critical: critical,
    strong_warning: critical,
    created_at: iso(-i - 1),
    received_at: iso(-i - 1),
    updated_at: iso(-i),
    auto_expire_at: critical ? null : iso(47 - i),
    remind_every_minutes: critical ? 15 : 0,
    next_remind_at: critical ? iso(i ? -1 : 6) : null,
    note: "DRY_RUN · " + target,
    locked_by: status === "processing" ? "linh.tran" : null,
    buttons: [
      { decision: "keep", label: critical ? "Giữ cách ly" : "Giữ chặn" },
      { decision: "undo", label: critical ? "Gỡ cách ly" : "Gỡ chặn IP" },
      { decision: "fp", label: "Dương tính giả" },
    ],
  });
});
const notices = [
  notice({
    title: "DRY_RUN",
    note: "SOAR mô phỏng quyết định trên máy mẫu.",
    simulated: true,
    host: "ad-server.home.arpa",
    received_at: iso(-2),
  }),
];
const history = new Map();
function served(row) {
  const available =
    row.status === "open"
      ? row.buttons.map((b) => b.decision)
      : row.status === "kept"
        ? ["undo"]
        : [];
  return {
    ...row,
    allowed_decisions: available.filter((action) => action !== "undo" || me.role !== "tier1"),
  };
}
export function soarApi(path, q, body) {
  if (!path.startsWith("/soar/reviews")) return;
  if (path.endsWith("/count")) {
    const open = empty ? [] : tickets.filter((row) => row.status === "open");
    return { count: open.length, latest_received_at: open[0]?.received_at || null };
  }
  if (path === "/soar/reviews") {
    const statuses = q.getAll("status"),
      needle = (q.get("q") || "").toLowerCase();
    const records = q.get("kind") === "notice" ? notices : tickets;
    return page(
      empty
        ? []
        : records
            .filter(
              (r) =>
                (!statuses.length || statuses.includes(r.status)) &&
                (/^[0-9]{1,18}$/.test(needle)
                  ? r.case_number === Number(needle)
                  : [r.src_ip, r.host, r.action_target, r.user_name, r.domain].some((value) =>
                      String(value ?? "")
                        .toLowerCase()
                        .includes(needle),
                    )),
            )
            .map(served),
      q,
    );
  }
  const [, , , id, action] = path.split("/"),
    row = [...tickets, ...notices].find((r) => r.id === id);
  if (!row || empty) return json({}, 404);
  if (action === "decision") {
    if (!served(row).allowed_decisions.includes(body.decision)) return json({}, 403);
    row.status = "processing";
    row.locked_by = me.username;
    // Keep the action pending long enough to display its in-flight state.
    const status = { keep: "kept", undo: "undone", fp: "false_positive" }[body.decision];
    return new Promise((resolve) =>
      setTimeout(() => {
        Object.assign(row, {
          status,
          locked_by: null,
          decided_by: me.username,
          decided_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          result: "DRY_RUN",
        });
        history.set(id, [
          ...(history.get(id) || []),
          {
            at: row.updated_at,
            event: "soar.review_decided",
            actor: me.username,
            actor_role: me.role,
            payload: { decision: body.decision, note: body.note, status },
          },
        ]);
        resolve({ outcome: "ok", message: null, review: served(row) });
      }, 450),
    );
  }
  const detail = detailOf(served(row));
  return {
    ...detail,
    raw: { id, kind: row.kind, status: row.status, simulated: true },
    related_alerts: [alerts[0]],
    related_total: 1,
    history: [...detail.history, ...(history.get(id) || [])],
  };
}
