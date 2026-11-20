import sample from "./admin-samples.json";
import { json, empty, me, now, alertId, caseId } from "./data";
import { labellingApi } from "./labelling";
import { knowledgeApi } from "./knowledge";

const { overview, usage, users } = sample;
users.find((u) => u.username === "hoa.admin").username = "an.pham";
overview.failed_jobs[0].subject_id = alertId;
overview.failed_jobs[1].subject_id = caseId;
usage.recent.forEach((r) => (r.subject_id = r.subject_type === "alert" ? alertId : caseId));
if (empty) {
  users.length = 0;
  overview.failed_jobs = [];
  usage.recent = [];
  usage.by_pipeline_role = [];
  usage.quota.users = [];
}
const ageOfRange = { "24h": 1, "7d": 7, "30d": 30, month: 20 };
const days = Array.from({ length: 30 }, (_, i) => {
  const day = new Date(Date.parse(now) - (29 - i) * 86400000).toISOString().slice(0, 10),
    heads = 34 + (i % 8),
    duplicates = 12 + i * 2;
  return { day, total: heads + duplicates, heads, duplicates };
});
function overviewFor(range) {
  const rows = empty ? [] : days.slice(-ageOfRange[range]);
  const counts = rows.reduce((s, d) => ({ total: s.total + d.total, heads: s.heads + d.heads }), {
    total: 0,
    heads: 0,
  });
  return {
    ...overview,
    range,
    alerts_by_day: rows,
    by_source: {
      rows: rows.length ? [{ source: "wazuh", alerts: counts.total, heads: counts.heads }] : [],
      rejected: 0,
    },
    top_agents: empty ? [] : [{ agent_name: "win-fin-17", alerts: counts.total }],
    waiting: { count: empty ? 0 : 56, oldest_received_at: empty ? null : now },
    cases_open: empty ? 0 : 1,
    funnel: {
      by_status: {
        queued_tier1: empty ? 0 : 56,
        tier1_active: empty ? 0 : 1,
        closed_fp: Math.max(0, counts.heads - 57),
      },
      triage: { ready: counts.heads },
    },
    llm_month: usage.month,
    health: { ...overview.health, checked_at: now },
    knowledge: {
      pending: empty
        ? 0
        : sample.knowledge.drafts.filter((d) => d.draft.status === "pending").length,
      conflicts: 0,
    },
  };
}
const auditGroups = {
  users: ["admin.user_updated", "authz.denied"],
  configuration: ["admin.settings_changed", "admin.autoclose_rule_toggled", "autoclose.reviewed"],
  alerts_cases: ["tier1.decided", "case.opened"],
  model: ["triage.suggested"],
  system: ["admin.job_retried", "health.alarm"],
};
const events = Array.from({ length: 90 }, (_, i) => {
  const seed = sample.events[i % sample.events.length];
  return {
    ...seed,
    audit_id: 1000 - i,
    created_at: new Date(Date.now() - (i < 60 ? i * 60000 : (i - 59) * 86400000)).toISOString(),
    subject_id:
      seed.event_type === "case.opened"
        ? caseId
        : ["tier1.decided", "triage.suggested"].includes(seed.event_type)
          ? alertId
          : seed.subject_id,
  };
});
function audit(q) {
  const cutoff = Date.now() - (ageOfRange[q.get("range")] || 1) * 86400000;
  const all = (empty ? [] : events).filter(
    (e) =>
      Date.parse(e.created_at) >= cutoff &&
      (!q.get("group") || auditGroups[q.get("group")]?.includes(e.event_type)) &&
      (!q.get("actor") || q.get("actor") === (e.actor_username ?? e.actor_role)) &&
      (!q.get("subject") || q.get("subject") === e.subject_id),
  );
  const size = Number(q.get("limit") || 50),
    remaining = all.filter((e) => !q.get("cursor") || e.audit_id < Number(q.get("cursor")));
  const rows = remaining.slice(0, size);
  return {
    events: rows,
    total: all.length,
    next_cursor: remaining.length > size ? rows.at(-1).audit_id : null,
  };
}
function accounts(path, body, method) {
  if (path === "/admin/users") {
    if (method === "GET") return { users };
    if (users.some((u) => u.username === body.username))
      return json({ detail: { reason: "username_taken" } }, 409);
    const user = {
      user_id: crypto.randomUUID(),
      username: body.username,
      display_name: body.display_name,
      role: body.role,
      is_active: true,
      failed_logins: 0,
      last_login_at: null,
      locked_until: null,
      created_at: now,
    };
    users.push(user);
    return { user_id: user.user_id };
  }
  const [, , , id, action] = path.split("/"),
    u = users.find((u) => u.user_id === id);
  if (!u) return json({}, 404);
  if (action === "unlock") {
    u.locked_until = null;
    u.failed_logins = 0;
  }
  if (method === "PATCH") {
    Object.assign(u, body);
    return u;
  }
  return new Response(null, { status: 204 });
}
export function adminApi(path, q, body, method) {
  if (!path.startsWith("/admin/")) return;
  if (me.role !== "admin") return json({}, 403);
  if (path.startsWith("/admin/users")) return accounts(path, body, method);
  if (path.startsWith("/admin/lab")) return labellingApi(path, q, body, method);
  if (path.startsWith("/admin/knowledge")) return knowledgeApi(path, q, body);
  if (path === "/admin/audit") return audit(q);
  if (path === "/admin/overview") return overviewFor(q.get("range") || "24h");
  if (path === "/admin/reload-inventory") {
    overview.inventory.loaded_at = new Date().toISOString();
    return { ...overview.inventory, deactivated: 0, warnings: [] };
  }
  if (path.startsWith("/admin/jobs/")) {
    const id = Number(path.split("/")[3]);
    overview.failed_jobs = overview.failed_jobs.filter((j) => j.job_id !== id);
    return { job_id: id, status: "pending" };
  }
  if (path === "/admin/llm/limits") {
    Object.assign(usage.limits, body);
    for (const [key, field] of Object.entries({
      LLM_MONTHLY_USD_CAP: "cap_usd",
      ANALYZE_QUOTA_PER_USER_DAY: "quota_per_24h",
      LLM_TIMEOUT_S: "timeout_s",
    })) {
      if (Object.hasOwn(body, field))
        usage.limits.sources[key] = {
          source: "db",
          updated_at: now,
          updated_by_name: me.username,
          clamped: false,
        };
    }
    usage.month.cap_usd = usage.limits.cap_usd;
    usage.month.pct = (usage.month.spent_usd * 100) / usage.month.cap_usd;
    usage.quota.limit = usage.limits.quota_per_24h;
    usage.quota.users.forEach((u) => (u.remaining = Math.max(0, usage.quota.limit - u.used)));
    return { limits: usage.limits };
  }
  if (path === "/admin/llm/usage") {
    const range = q.get("range") || "month",
      factor = (ageOfRange[range] || 20) / 30;
    return {
      ...usage,
      range,
      by_pipeline_role: usage.by_pipeline_role.map((r) => ({
        ...r,
        calls: Math.ceil(r.calls * factor),
        with_result: Math.ceil(r.with_result * factor),
        cost_usd: r.cost_usd * factor,
        input_tokens: Math.round(r.input_tokens * factor),
        output_tokens: Math.round(r.output_tokens * factor),
      })),
    };
  }
}
