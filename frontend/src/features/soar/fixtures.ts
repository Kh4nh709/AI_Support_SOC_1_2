// The review objects the SOAR tests serve: every key of the served object (spec section 4), as the API sends them.
import type {
  SoarCountResponse,
  SoarListResponse,
  SoarReview,
  SoarReviewDetail,
} from "../../api/soar";

/** An open `block_ip` review, the way the API serves it to a role that may keep and undo. */
export function review(over: Partial<SoarReview> = {}): SoarReview {
  return {
    id: "K7QM2XHP",
    kind: "review",
    status: "open",
    severity: "warning",
    title: "ĐÃ TỰ XỬ LÝ",
    simulated: false,
    case_id: "~4096",
    case_number: 65,
    action_type: "block_ip",
    action_text: "Chặn IP 79.79.78.202 trên pfSense",
    action_target: "79.79.78.202",
    action_via: "pfsense",
    action_agent: null,
    host: "pfSense.home.arpa",
    agent_id: "003",
    user_name: null,
    src_ip: "79.79.78.202",
    domain: null,
    scenario_id: "SC03",
    scenario_name: "Quét cổng từ bên ngoài",
    score: 50,
    note: "Đã chặn 79.79.78.202 trên pfSense, tự gỡ 22:40",
    buttons: [
      { decision: "keep", label: "✅ Giữ chặn" },
      { decision: "undo", label: "↩️ Gỡ chặn IP" },
    ],
    created_at: "2026-11-13T14:40:03+00:00",
    auto_expire_at: "2026-11-13T15:40:03+00:00",
    remind_every_minutes: 0,
    next_remind_at: null,
    decided_by: null,
    decided_at: null,
    result: null,
    last_error: null,
    locked_by: null,
    locked_at: null,
    last_sent_at: "2026-11-13T14:40:05+00:00",
    received_at: "2026-11-13T14:40:05+00:00",
    updated_at: "2026-11-13T14:40:05+00:00",
    allowed_decisions: ["keep", "undo"],
    strong_warning: false,
    host_critical: false,
    ...over,
  };
}

/** A notice: status `info`, no buttons, no decision to make. */
export function notice(over: Partial<SoarReview> = {}): SoarReview {
  return review({
    id: "N0123456789AB",
    kind: "notice",
    status: "info",
    severity: "info",
    title: "Đã gỡ chặn IP 79.79.78.202",
    case_id: null,
    case_number: null,
    action_type: null,
    action_text: null,
    action_target: null,
    action_via: null,
    scenario_id: null,
    scenario_name: null,
    score: null,
    note: "Hết hạn chặn, SOAR đã tự gỡ",
    buttons: [],
    auto_expire_at: null,
    allowed_decisions: [],
    ...over,
  });
}

export function listOf(rows: SoarReview[], over: Partial<SoarListResponse> = {}): SoarListResponse {
  return { rows, total: rows.length, page: 1, page_size: 50, ...over };
}

export function countOf(count: number, latest: string | null = null): SoarCountResponse {
  return { count, latest_received_at: latest };
}

/** The review beside the history, the alerts of its case and the last body n8n sent. */
export function detailOf(over: Partial<SoarReviewDetail> = {}): SoarReviewDetail {
  return {
    ...review(),
    raw: { schema_version: "1.0", id: "K7QM2XHP", kind: "review", status: "open" },
    history: [
      {
        at: "2026-11-13T14:40:05+00:00",
        event: "soar.review_received",
        // as the backend serves a push of n8n: no person, the role is the word "system"
        actor: null,
        actor_role: "system",
        payload: {
          event: "created",
          kind: "review",
          outcome: "created",
          reason: null,
          status: "open",
        },
      },
    ],
    related_alerts: [],
    related_total: 0,
    ...over,
  };
}
