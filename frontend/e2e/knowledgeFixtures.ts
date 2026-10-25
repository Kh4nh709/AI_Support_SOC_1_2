// Test-only seeds of the knowledge page's end-to-end suite (P13-T06, admin-knowledge.spec.ts).
//
// The stack runs no `rag-worker` and leaves RAG_ENABLED and KNOWLEDGE_DRAFT_ENABLED off (scripts/ui_e2e_stack.sh), so
// nothing drafts an entry by itself: a pending draft is a row this file inserts, with the SQL helper of fixtures.ts
// (psql against the scratch database, credentials by PG* variables, never in an argument). Its source is a REAL
// alert, posted through the webhook and closed by Tier 1 through the API, so the left column of the page, the
// approval's re-check of the closed fields (`source_record`) and the audit trail all run on real rows.
//
// The model's six fields below pass V1-V5 for the alert: no address, no host name, no account, no hash; tags from
// `rag/tags.yaml`. The closed six are copied from the alert row (an approval takes them from the source again).
import { expect, type APIRequestContext } from "@playwright/test";
import { apiLogin, apiPost, postAlert, sql, waitForStatus, type Posted } from "./fixtures";

/** The six fields a model writes (`knowledge_draft_v1`), as the draft job stores them. */
export type ModelFields = {
  title: string;
  tags: string[];
  summary: string;
  distinguishing_signals: string[];
  check_next_time: string[];
  confidence_note: string;
};

/** A draft that passes V1-V5; `title` says which test it is for. */
export function modelFields(title: string): ModelFields {
  return {
    title,
    tags: ["port_scan", "firewall"],
    summary:
      "Một máy giám sát quét cổng định kỳ vào máy chủ nội bộ; đây là hoạt động đã biết, không phải tấn công.",
    distinguishing_signals: ["Nguồn thuộc dải máy giám sát", "Lặp lại đều đặn theo giờ"],
    check_next_time: ["Xác nhận lịch quét với đội hạ tầng"],
    confidence_note: "Chỉ dựa trên một quyết định của analyst.",
  };
}

const ALERT_ID = /^\d+\.\d+$/;

/** A SQL string literal; the inputs here are the suite's own constants, and quotes are doubled all the same. */
const literal = (text: string): string => `'${text.replace(/'/g, "''")}'`;

/**
 * An alert posted through the webhook and closed as a false positive by Tier 1, through the API, with a reason:
 * the decision a draft is made from. It returns the head, whose `description` and `agent` the page shows.
 */
export async function closedAlert(request: APIRequestContext, tag: string): Promise<Posted> {
  const head = await postAlert(request, { tag, arm: "visible" });
  await waitForStatus(head.id, "queued_tier1");
  const token = await apiLogin(request, "t1");
  const held = await apiPost(request, `/api/tier1/alerts/${head.id}/acknowledge`, {
    token,
    data: {},
  });
  expect(held.status, "Tier 1 takes the alert").toBe(200);
  const decided = await apiPost(request, `/api/tier1/alerts/${head.id}/decide`, {
    token,
    data: {
      decision: "false_positive",
      reason: `Routine scan of the monitoring host (${tag}), confirmed with its owner.`,
      seen_occurrence_count: 1,
    },
  });
  expect(decided.status, "Tier 1 closes the alert").toBe(200);
  return head;
}

/**
 * Inserts the pending draft of `alertId` (or puts the one that is there back to pending with this text) and returns
 * its id. The closed fields come from the alert row.
 */
export function seedPendingDraft(alertId: string, fields: ModelFields): string {
  if (!ALERT_ID.test(alertId)) throw new Error(`not an alert id: ${alertId}`);
  const model = literal(JSON.stringify(fields));
  const draft = `${model}::jsonb || jsonb_build_object('conclusion', a.status, 'category', a.category, 'mitre_ids', to_jsonb(a.mitre_ids), 'soar_scenario', NULL, 'rule_ids', jsonb_build_array(a.rule_id), 'log_source', NULL)`;
  const id = sql(
    `INSERT INTO knowledge_drafts (source_kind, source_id, conclusion, status, draft, warnings)` +
      ` SELECT 'alert', a.alert_id, a.status, 'pending', ${draft}, '[]'::jsonb FROM alerts a` +
      ` WHERE a.alert_id = ${literal(alertId)}` +
      ` ON CONFLICT (source_kind, source_id) DO UPDATE SET status = 'pending', draft = EXCLUDED.draft,` +
      ` warnings = '[]'::jsonb, conflict_with_entry = NULL, reviewed_by = NULL, reviewed_at = NULL` +
      ` RETURNING draft_id`,
  );
  // psql prints the id and a status line ("INSERT 0 1"); the id is the first line.
  const first = id.split("\n")[0]?.trim() ?? "";
  expect(first, "the draft was inserted").toMatch(/^[0-9a-f-]{36}$/);
  return first;
}
