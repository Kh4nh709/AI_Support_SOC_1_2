// Test support of the knowledge page (P13-T06): the shapes admin_knowledge.py answers with, built by hand, and a fake
// of its eight routes for MSW that remembers what it was sent. Nothing in the app imports this file.
//
// `source.alert`, `source.case` and `source.investigation` are the JSON of the Tier-1 and Tier-2 routes, so the
// builders below make exactly those types (`AlertView`, `CaseDetail`, `InvestigationView`).
import { http, HttpResponse } from "msw";
import type { SetupServer } from "msw/node";
import type {
  KnowledgeDraft,
  KnowledgeDraftDetail,
  KnowledgeDraftFields,
  KnowledgeDraftRow,
  KnowledgeDraftStatus,
  KnowledgeEntry,
  KnowledgeEntryRow,
  KnowledgeEntryStatus,
  KnowledgeSource,
  KnowledgeTags,
} from "../../api/admin";
import type { AlertView, Suggestion } from "../../api/tier1";
import type { CaseDetail, InvestigationView } from "../../api/tier2";

export const BASE = "/api/admin/knowledge";

const uuid = (kind: number, n: number) =>
  `${String(kind).padStart(8, "0")}-0000-4000-8000-${String(n).padStart(12, "0")}`;
export const draftId = (n: number) => uuid(1, n);
export const entryId = (n: number) => uuid(2, n);
export const CASE_ID = uuid(3, 1);
export const ALERT_ID = "1727401201.662100";

export const TAGS: KnowledgeTags = {
  tags: ["brute_force", "firewall", "malware", "port_scan"],
  descriptions: {
    brute_force: "Dò mật khẩu",
    firewall: "Sự kiện tường lửa",
    malware: "Mã độc",
    port_scan: "Quét cổng",
  },
};

export const GOOD_FIELDS: KnowledgeDraftFields = {
  title: "Quét cổng định kỳ từ máy giám sát nội bộ",
  conclusion: "closed_benign",
  category: "recon",
  mitre_ids: ["T1046"],
  soar_scenario: "SC03",
  rule_ids: ["100190"],
  log_source: "wazuh",
  tags: ["port_scan", "firewall"],
  summary:
    "Máy giám sát quét cổng định kỳ vào <HOST>; đây là hoạt động đã biết, không phải tấn công.",
  distinguishing_signals: ["Nguồn là <IP_NOI_BO> thuộc dải giám sát", "Lặp lại đều theo giờ"],
  check_next_time: [
    "Xác nhận lịch quét với đội hạ tầng",
    "So sánh nguồn với danh sách máy giám sát",
  ],
  confidence_note: "Chỉ dựa trên một quyết định của analyst.",
};

export function alertView(over: Partial<AlertView> = {}): AlertView {
  return {
    alert_id: ALERT_ID,
    status: "closed_benign",
    suggestion_visible: true,
    suggestion: { suggested_action: "close_fp", confidence: "high", reasons: [], gate: null },
    rule_id: "100190",
    rule_level: 7,
    description: "Phát hiện quét cổng từ máy trong mạng nội bộ",
    category: "recon",
    severity: "medium",
    risk_band: "Vừa",
    agent_name: "fw-edge-01",
    srcip: "10.10.5.7",
    dstip: "10.10.8.20",
    alert_time: "2026-10-25T01:02:03+00:00",
    raw_log: "Oct 25 01:02:03 fw-edge-01 kernel: SCAN SRC=10.10.5.7 DST=10.10.8.20",
    raw_log_truncated: false,
    occurrence_count: 3,
    acknowledged_by_name: "an.t1",
    closed_at: "2026-10-25T01:10:00+00:00",
    close_reason: "đã xác minh với đội hạ tầng",
    targeted_accounts: ["svc-monitor"],
    mitre_ids: ["T1046"],
    playbook: "Xác nhận nguồn quét với đội hạ tầng.",
    ...over,
  };
}

/**
 * ①'s result with everything the gate and the reasons can carry: a forced gate with the rules that forced it, its
 * steps and warnings, and reasons whose text is hostile (a script, a `javascript:` link, an image with a handler).
 */
export function forcedSuggestion(over: Partial<Suggestion> = {}): Suggestion {
  return {
    suggested_action: "false_positive",
    confidence: "high",
    gate: {
      forced: true,
      forced_by: ["asset_high", "ioc_bad"],
      proposed_verdict: "false_positive",
      final_verdict: "needs_review",
      verifier_verdict: "disagree",
      warnings: ["<script>alert('gate')</script>"],
    },
    reasons: [
      {
        claim: "<script>alert(1)</script> máy này quét cổng đều đặn",
        quote: "[bấm vào đây](javascript:alert(1))",
        source: "<img src=x onerror=alert(2)>",
      },
      { claim: "Nguồn thuộc dải máy giám sát" },
    ],
    ...over,
  };
}

export function caseView(over: Partial<CaseDetail> = {}): CaseDetail {
  return {
    case_id: CASE_ID,
    title: "Chuỗi quét cổng và đăng nhập lặp lại",
    status: "concluded_fp",
    severity: "medium",
    created_by: "u-1",
    created_at: "2026-10-25T01:00:00+00:00",
    last_analyzed_at: "2026-10-25T01:30:00+00:00",
    last_run: { created_at: "2026-10-25T01:30:00+00:00", has_result: true },
    concluded_by: "u-2",
    concluded_at: "2026-10-25T02:00:00+00:00",
    conclusion_reason: "Hoạt động đã biết của đội giám sát",
    concluded_by_name: "binh.t2",
    ongoing: false,
    ongoing_last_seen: null,
    heads: [
      {
        alert_id: "1727401201.662100",
        rule_id: "100190",
        severity: "medium",
        description: "Phát hiện quét cổng từ máy trong mạng nội bộ",
        agent_name: "fw-edge-01",
        alert_time: "2026-10-25T01:02:03+00:00",
        srcip: "10.10.5.7",
        category: "recon",
        occurrence_count: 3,
        status: "escalated_tier2",
        raw_log: "SCAN SRC=10.10.5.7",
        raw_log_truncated: false,
        risk_band: "Vừa",
        last_seen_at: "2026-10-25T01:05:00+00:00",
      },
    ],
    notes: [
      {
        note_id: 1,
        case_id: CASE_ID,
        author_id: "u-2",
        author_name: "binh.t2",
        body: "Đã hỏi đội hạ tầng, lịch quét có thật.",
        created_at: "2026-10-25T01:45:00+00:00",
      },
    ],
    ...over,
  };
}

export function investigationView(over: Partial<InvestigationView> = {}): InvestigationView {
  return {
    state: "done",
    run_id: null,
    minutes: null,
    case_open: false,
    current: null,
    run: {
      run_id: "run-1",
      created_at: "2026-10-25T01:30:00+00:00",
      result: { conclusion: "concluded_fp" },
      conclusion: "concluded_fp",
      conclusion_label: "Dương tính giả",
      confidence: "high",
      summary: "Các cụm là một đợt quét định kỳ của máy giám sát.",
      narrative: "Máy giám sát quét cổng theo giờ; không có đăng nhập thành công sau đó.",
      hypotheses: [],
      evidence: [
        {
          alert_id: "1727401201.662100",
          quote: "SCAN SRC=10.10.5.7",
          why: "Nguồn thuộc dải giám sát",
          verified: true,
          reason_text: null,
        },
      ],
      next_steps: [],
      playbook_used: null,
      overruled: null,
      snapshot: null,
      changed: false,
    },
    ...over,
  };
}

export function draftRow(n: number, over: Partial<KnowledgeDraftRow> = {}): KnowledgeDraftRow {
  return {
    draft_id: draftId(n),
    source_kind: "alert",
    source_id: `17274012${String(n).padStart(2, "0")}.662100`,
    conclusion: "closed_benign",
    status: "pending",
    title: `Bản nháp số ${n}`,
    has_text: true,
    warnings: [],
    conflict_with_entry: null,
    duplicate_of_entry: null,
    created_at: "2026-10-25T03:00:00+00:00",
    reviewed_by: null,
    reviewed_by_name: null,
    reviewed_at: null,
    review_note: null,
    ...over,
  };
}

export function draftDetail(
  n = 1,
  over: {
    draft?: Partial<KnowledgeDraft>;
    source?: Partial<KnowledgeSource>;
  } = {},
): KnowledgeDraftDetail {
  const kind = over.draft?.source_kind ?? "alert";
  const sourceId = over.draft?.source_id ?? (kind === "alert" ? ALERT_ID : CASE_ID);
  const draft: KnowledgeDraft = {
    draft_id: draftId(n),
    source_kind: kind,
    source_id: sourceId,
    conclusion: "closed_benign",
    status: "pending",
    draft: { ...GOOD_FIELDS },
    warnings: [],
    llm_run_id: null,
    duplicate_of_entry: null,
    conflict_with_entry: null,
    created_at: "2026-10-25T03:00:00+00:00",
    reviewed_by: null,
    reviewed_by_name: null,
    reviewed_at: null,
    review_note: null,
    ...over.draft,
  };
  const source: KnowledgeSource =
    kind === "alert"
      ? {
          kind,
          id: sourceId,
          alert: alertView(),
          case: null,
          investigation: null,
          decision: {
            event_type: "tier1.decided",
            actor_id: "u-1",
            actor_name: "an.t1",
            at: "2026-10-25T01:10:00+00:00",
            payload: { decision: "benign", reason: "đã xác minh với đội hạ tầng" },
          },
          notes: [],
          enrichment: { asset: { host: "fw-edge-01", criticality: "high" } },
          conflict_entry: null,
          ...over.source,
        }
      : {
          kind,
          id: sourceId,
          alert: null,
          case: caseView(),
          investigation: investigationView(),
          decision: {
            event_type: "tier2.concluded",
            actor_id: "u-2",
            actor_name: "binh.t2",
            at: "2026-10-25T02:00:00+00:00",
            payload: { conclusion: "concluded_fp", reason: "Hoạt động đã biết của đội giám sát" },
          },
          notes: caseView().notes,
          enrichment: {},
          conflict_entry: null,
          ...over.source,
        };
  return { draft, source };
}

export function entryRow(n: number, over: Partial<KnowledgeEntryRow> = {}): KnowledgeEntryRow {
  return {
    entry_id: entryId(n),
    version: 1,
    status: "active",
    title: `Mục tri thức số ${n}`,
    conclusion: "closed_benign",
    category: "recon",
    mitre_ids: ["T1046"],
    tags: ["port_scan"],
    soar_scenario: "SC03",
    rule_ids: ["100190"],
    log_source: "wazuh",
    file_path: `entries/recon/${entryId(n)}.md`,
    content_sha256: "a".repeat(64),
    evidence_count: 2,
    approved_by: "u-9",
    approved_by_name: "e2e-admin",
    approved_at: "2026-10-25T04:00:00+00:00",
    ...over,
  };
}

export function entryFull(n = 1, over: Partial<KnowledgeEntry> = {}): KnowledgeEntry {
  const row = entryRow(n);
  return {
    entry_id: row.entry_id,
    version: row.version,
    status: row.status,
    title: row.title,
    conclusion: row.conclusion,
    category: row.category,
    mitre_ids: row.mitre_ids,
    tags: row.tags,
    soar_scenario: row.soar_scenario,
    rule_ids: row.rule_ids,
    log_source: row.log_source,
    fingerprint: "recon 100190 sc03",
    content: `---\nentry_id: ${row.entry_id}\nversion: 1\n---\n\n# ${row.title}\n\nTóm tắt của mục.\n`,
    content_sha256: row.content_sha256,
    file_path: row.file_path,
    source_alert_ids: [ALERT_ID],
    source_case_ids: [],
    evidence: [{ subject: `alert:${ALERT_ID}`, at: "2026-10-25T04:00:00+00:00" }],
    approved_by: row.approved_by,
    approved_by_name: row.approved_by_name,
    approved_at: row.approved_at,
    supersedes_entry: null,
    integrity: { content_ok: true, file_ok: true },
    ...over,
  };
}

// --- the fake of the eight routes ----------------------------------------------------------------------------------

export type Answer = (body: unknown) => Response | Promise<Response>;

export type Fake = {
  /** The lists by status; a write moves a row out of its list. */
  drafts: Record<KnowledgeDraftStatus, KnowledgeDraftRow[]>;
  entries: Record<KnowledgeEntryStatus, KnowledgeEntryRow[]>;
  details: Map<string, KnowledgeDraftDetail>;
  entryDetails: Map<string, KnowledgeEntry>;
  /** How many times each read was made. */
  reads: {
    drafts: Record<string, number>;
    entries: Record<string, number>;
    draft: Record<string, number>;
    entry: Record<string, number>;
    tags: number;
  };
  /** What each write was sent: its path id, its body and its Content-Type. */
  approves: { id: string; body: unknown; contentType: string | null }[];
  rejects: { id: string; body: unknown; contentType: string | null }[];
  redrafts: { id: string; body: unknown; contentType: string | null }[];
  retires: { id: string; body: unknown; contentType: string | null }[];
};

export type FakeInit = {
  drafts?: Partial<Record<KnowledgeDraftStatus, KnowledgeDraftRow[]>>;
  entries?: Partial<Record<KnowledgeEntryStatus, KnowledgeEntryRow[]>>;
  details?: KnowledgeDraftDetail[];
  entryDetails?: KnowledgeEntry[];
  tags?: KnowledgeTags;
  /** An answer to replace the default of a route (`null` for a write the test never expects). */
  list?: (kind: "drafts" | "entries", status: string) => Response | Promise<Response>;
  tagsAnswer?: () => Response | Promise<Response>;
  draftAnswer?: (id: string) => Response | Promise<Response>;
  entryAnswer?: (id: string) => Response | Promise<Response>;
  approve?: Answer;
  reject?: Answer;
  redraft?: Answer;
  retire?: Answer;
};

export const detail = (body: unknown, status: number) =>
  HttpResponse.json({ detail: body }, { status });

/**
 * Installs the routes on `server`. A list answers with the rows it holds; an approval, a rejection or a
 * retirement answers like the route does and takes the row out of the list it was in (so the refetch a page makes
 * after the write shows the new state), unless the test gives its own answer.
 */
export function knowledgeBackend(server: SetupServer, init: FakeInit = {}): Fake {
  const fake: Fake = {
    drafts: { pending: [], approved: [], merged: [], rejected: [], ...copyLists(init.drafts) },
    entries: { active: [], retired: [], ...copyLists(init.entries) },
    details: new Map((init.details ?? []).map((d) => [d.draft.draft_id, structuredClone(d)])),
    entryDetails: new Map((init.entryDetails ?? []).map((e) => [e.entry_id, structuredClone(e)])),
    reads: { drafts: {}, entries: {}, draft: {}, entry: {}, tags: 0 },
    approves: [],
    rejects: [],
    redrafts: [],
    retires: [],
  };
  const bump = (table: Record<string, number>, key: string) => {
    table[key] = (table[key] ?? 0) + 1;
  };
  const recordWrite = async (request: Request, id: string) => {
    const text = await request.text();
    return {
      id,
      body: text === "" ? undefined : (JSON.parse(text) as unknown),
      contentType: request.headers.get("content-type"),
    };
  };

  server.use(
    http.get(`${BASE}/drafts`, ({ request }) => {
      const status = new URL(request.url).searchParams.get("status") ?? "pending";
      bump(fake.reads.drafts, status);
      if (init.list) return init.list("drafts", status);
      return HttpResponse.json(fake.drafts[status as KnowledgeDraftStatus] ?? []);
    }),
    http.get(`${BASE}/drafts/:id`, ({ params }) => {
      const id = String(params.id);
      bump(fake.reads.draft, id);
      if (init.draftAnswer) return init.draftAnswer(id);
      const found = fake.details.get(id);
      return found ? HttpResponse.json(found) : detail({ reason: "not_found" }, 404);
    }),
    http.post(`${BASE}/drafts/:id/approve`, async ({ request, params }) => {
      const sent = await recordWrite(request, String(params.id));
      fake.approves.push(sent);
      if (init.approve) return init.approve(sent.body);
      take(fake.drafts.pending, sent.id);
      const found = fake.details.get(sent.id);
      if (found) found.draft.status = "approved";
      return HttpResponse.json({ entry_id: entryId(99) });
    }),
    http.post(`${BASE}/drafts/:id/reject`, async ({ request, params }) => {
      const sent = await recordWrite(request, String(params.id));
      fake.rejects.push(sent);
      if (init.reject) return init.reject(sent.body);
      take(fake.drafts.pending, sent.id);
      const found = fake.details.get(sent.id);
      if (found) found.draft.status = "rejected";
      return HttpResponse.json({ draft_id: sent.id, status: "rejected" });
    }),
    http.post(`${BASE}/drafts/:id/redraft`, async ({ request, params }) => {
      const sent = await recordWrite(request, String(params.id));
      fake.redrafts.push(sent);
      if (init.redraft) return init.redraft(sent.body);
      take(fake.drafts.pending, sent.id);
      fake.details.delete(sent.id);
      return HttpResponse.json({ draft_id: sent.id, queued: true });
    }),
    http.get(`${BASE}/entries`, ({ request }) => {
      const status = new URL(request.url).searchParams.get("status") ?? "active";
      bump(fake.reads.entries, status);
      if (init.list) return init.list("entries", status);
      return HttpResponse.json(fake.entries[status as KnowledgeEntryStatus] ?? []);
    }),
    http.get(`${BASE}/entries/:id`, ({ params }) => {
      const id = String(params.id);
      bump(fake.reads.entry, id);
      if (init.entryAnswer) return init.entryAnswer(id);
      const found = fake.entryDetails.get(id);
      return found ? HttpResponse.json(found) : detail({ reason: "not_found" }, 404);
    }),
    http.post(`${BASE}/entries/:id/retire`, async ({ request, params }) => {
      const sent = await recordWrite(request, String(params.id));
      fake.retires.push(sent);
      if (init.retire) return init.retire(sent.body);
      const moved = take(fake.entries.active, sent.id);
      if (moved) fake.entries.retired.unshift({ ...moved, status: "retired" });
      const found = fake.entryDetails.get(sent.id);
      if (found) found.status = "retired";
      return HttpResponse.json({ entry_id: sent.id, status: "retired" });
    }),
    http.get(`${BASE}/tags`, () => {
      fake.reads.tags += 1;
      if (init.tagsAnswer) return init.tagsAnswer();
      return HttpResponse.json(init.tags ?? TAGS);
    }),
  );
  return fake;
}

function copyLists<T>(lists: Partial<Record<string, T[]>> | undefined): Record<string, T[]> {
  return Object.fromEntries(
    Object.entries(lists ?? {}).map(([status, rows]) => [
      status,
      (rows ?? []).map((r) => ({ ...r })),
    ]),
  );
}

/** Takes the row out of the list and returns it. */
function take<T extends { draft_id?: string; entry_id?: string }>(rows: T[], id: string): T | null {
  const at = rows.findIndex((row) => row.draft_id === id || row.entry_id === id);
  if (at === -1) return null;
  return rows.splice(at, 1)[0] ?? null;
}
