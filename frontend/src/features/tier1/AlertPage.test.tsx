// src/features/tier1/AlertPage.test.tsx — the alert page (/alerts/:alertId): the summary, the two columns, the
// sections that show only when the view carries their data, a duplicate, the case link, hostile log text,
// the live refetch, and the ① column as the page hands it the state of the view.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter, Route, Routes } from "react-router";
import type { AlertView, Suggestion } from "../../api/tier1";
import { setTokenSource } from "../../api/client";
import { AuthContext, type AuthState } from "../../auth/AuthProvider";
import type { Session } from "../../auth/session";
import { LiveProvider } from "../../live/LiveProvider";
import type { LiveOptions } from "../../live/socket";
import { S } from "../../strings";
import { AlertPage } from "./AlertPage";
import { GEO, MW03, SC03 } from "./soarFixtures";

// The socket is faked: the test is the server, and calls what the client handed to connectLive.
const fake = vi.hoisted(() => ({ opened: [] as unknown[] }));
vi.mock("../../live/socket", () => ({
  connectLive: (opts: LiveOptions) => {
    fake.opened.push(opts);
    return () => {};
  },
}));
const live = (): LiveOptions => {
  const opts = fake.opened.at(-1) as LiveOptions | undefined;
  if (!opts) throw new Error("the page opened no socket");
  return opts;
};

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterAll(() => server.close());

const ME_ID = "6f0c3a52-0d3e-4b8e-9d55-2f1a5f0e7c11";

const sessionOf = (role: Session["role"]): Session => ({
  token: "tok-1",
  role,
  username: "an",
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
});

const suggestion = (over: Partial<Suggestion> = {}): Suggestion => ({
  run_id: "r1",
  suggested_action: "true_positive",
  confidence: "medium",
  reasons: [
    {
      claim: "37 lần xác thực thất bại từ cùng một IP ngoài",
      quote: "Failed password for invalid user admin from 203.0.113.45 port 51522 ssh2",
      source: "wazuh_raw_log",
    },
  ],
  gate: {
    forced: false,
    proposed_verdict: "true_positive",
    final_verdict: "true_positive",
    verifier_verdict: "agree",
  },
  correlated_at_analysis: 4,
  created_at: "2026-09-30T02:31:02Z",
  ...over,
});

/** A visible-arm view with every key the server sends. */
const full = (over: Partial<AlertView> = {}): AlertView => ({
  alert_id: "a1",
  requested_alert_id: "a1",
  status: "queued_tier1",
  suggestion_visible: true,
  triage_status: "ready",
  suggestion: suggestion(),
  proposed_action: "true_positive",
  held_by: [],
  rule_id: "5760",
  rule_level: 5,
  description: "sshd: authentication failed",
  category: "ssh_brute_force",
  severity: "high",
  risk_band: "Cao",
  agent_name: "lab-ubuntu-01",
  origin_host: "lab-ubuntu-01",
  alert_time: "2026-09-30T02:31:02Z",
  event_time: "2026-09-30T02:31:00Z",
  alert_user: "admin",
  srcip: "203.0.113.45",
  dstip: "192.0.2.10",
  src_port: 51522,
  dst_port: 22,
  decoder: "sshd",
  mitre_ids: ["T1110.001"],
  rule_groups: ["syslog", "sshd", "authentication_failed"],
  raw_log: "Sep 30 09:31:02 lab-ubuntu-01 sshd[2231]: Failed password for invalid user admin",
  raw_log_truncated: false,
  source: "wazuh_pull",
  occurrence_count: 37,
  first_seen_at: "2026-09-30T02:12:44Z",
  last_seen_at: "2026-09-30T02:31:02Z",
  acknowledged_at: null,
  acknowledged_by: null,
  acknowledged_by_name: null,
  closed_at: null,
  close_reason: null,
  case_id: null,
  asset_context: { present: true, criticality: "medium", owner: "[CHỦ TÀI SẢN]", role: "server" },
  identity_context: { privileged: null },
  ioc_context: { reputation: null },
  lookup_status: { asset: "found", identity: "found", ioc: "skipped" },
  targeted_accounts: ["admin", "root", "ubuntu"],
  correlation: {
    rows: [
      {
        rule_id: "5710",
        category: "ssh_invalid_user",
        status: "queued_tier1",
        cluster_count: 1,
        alert_count: 12,
        first_seen: "2026-09-30T02:12:00Z",
        last_seen: "2026-09-30T02:30:00Z",
        src_ip_count: 1,
      },
    ],
    samples: [
      {
        alert_id: "s1",
        rule_id: "5710",
        category: "ssh_invalid_user",
        severity: "medium",
        status: "queued_tier1",
        occurrence_count: 12,
        alert_time: "2026-09-30T02:12:00Z",
        description: "sshd: attempt to login using a non-existent user",
      },
    ],
  },
  correlated_now: 4,
  playbook: "1. Xác định IP nguồn là nội bộ hay bên ngoài.\n2. Đối chiếu tài khoản bị nhắm.",
  ...over,
});

/** The least the server sends: the keys every view carries. */
const sparse = (over: Partial<AlertView> = {}): AlertView => ({
  alert_id: "a1",
  status: "queued_tier1",
  suggestion_visible: true,
  suggestion: null,
  triage_status: "pending",
  ...over,
});

/** What the server sends for a blind, undecided head: no `suggestion`, no `triage_status`, no `run_id`. */
function blind(over: Partial<AlertView> = {}): AlertView {
  const stripped = full({ suggestion_visible: false });
  delete stripped.suggestion;
  delete stripped.triage_status;
  delete stripped.proposed_action; // P14-T03: the model's answer and why it was held go with the suggestion
  delete stripped.held_by;
  return { ...stripped, ...over };
}

let views: Record<string, AlertView | { status: number; body?: unknown }> = {};
let requests: string[] = [];
let meCalls = 0;
beforeEach(() => {
  views = { a1: full() };
  requests = [];
  meCalls = 0;
  fake.opened = [];
  sessionStorage.clear();
  server.use(
    http.get("/api/tier1/alerts/:id", ({ params }) => {
      const id = String(params.id);
      requests.push(id);
      const answer = views[id];
      if (answer === undefined) return HttpResponse.json({ detail: "not found" }, { status: 404 });
      // An error answer has a numeric status; a view's status is a code.
      if (typeof answer.status === "number") {
        const failure = answer as { status: number; body?: unknown };
        return HttpResponse.json(failure.body ?? { detail: "boom" }, { status: failure.status });
      }
      return HttpResponse.json(answer);
    }),
    http.get("/api/auth/me", () => {
      meCalls += 1;
      return HttpResponse.json({ user_id: ME_ID, username: "an", role: "tier1" });
    }),
  );
  setTokenSource(
    () => "tok-1",
    () => {},
  );
});
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
  vi.restoreAllMocks();
  sessionStorage.clear();
  setTokenSource(
    () => null,
    () => {},
  );
});

function renderPage(entry = "/alerts/a1", role: Session["role"] = "tier1", client?: QueryClient) {
  const auth: AuthState = {
    session: sessionOf(role),
    ready: true,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
  };
  const queryClient = client ?? new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={[entry]}>
          <LiveProvider>
            <main>
              <Routes>
                <Route path="/alerts/:alertId" element={<AlertPage />} />
                <Route path="/cases/:caseId" element={<p>trang case</p>} />
                <Route path="/queue" element={<p>hàng đợi</p>} />
              </Routes>
            </main>
          </LiveProvider>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

const summary = () => screen.getByRole("region", { name: S.alert.summaryLabel });
const aiColumn = () => screen.getByRole("region", { name: S.alert.aiHeading });
const heading3 = (name: string) => screen.queryByRole("heading", { level: 3, name });
/** The value of a labelled row of a description list, wherever it is on the page. */
const valueOf = (label: string) => screen.getByText(label, { selector: "dt" }).nextElementSibling;
const loaded = () => screen.findByRole("heading", { level: 1 });

describe("the page", () => {
  it("shows the summary of the alert: band, category, status, description, rule, agent, count and times", async () => {
    renderPage();
    expect(await loaded()).toHaveTextContent("sshd: authentication failed");
    const top = within(summary());
    expect(top.getByText("Cao")).toBeInTheDocument();
    expect(top.getByText("ssh_brute_force")).toBeInTheDocument();
    expect(top.getByText(S.status.queued_tier1)).toBeInTheDocument();
    expect(valueOf(S.alert.summary.rule)).toHaveTextContent("5760");
    expect(valueOf(S.alert.summary.level)).toHaveTextContent("5");
    expect(valueOf(S.alert.summary.agent)).toHaveTextContent("lab-ubuntu-01");
    expect(valueOf(S.alert.summary.occurrences)).toHaveTextContent("37");
    // 02:12:44Z and 02:31:02Z, in Asia/Ho_Chi_Minh, whatever the zone of the machine
    expect(valueOf(S.alert.summary.firstSeen)).toHaveTextContent("30/09 09:12");
    expect(valueOf(S.alert.summary.lastSeen)).toHaveTextContent("30/09 09:31");
  });

  it("puts the left column and the right column side by side, each under its heading", async () => {
    renderPage();
    await loaded();
    const left = screen.getByRole("heading", { level: 2, name: S.alert.infoHeading });
    const right = screen.getByRole("heading", { level: 2, name: S.alert.aiHeading });
    expect(left).toBeInTheDocument();
    expect(right).toBeInTheDocument();
    expect(within(aiColumn()).getByRole("heading", { level: 2, name: S.alert.aiHeading })).toBe(
      right,
    );
    // the left column comes first in the reading order
    expect(left.compareDocumentPosition(right) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText(S.alert.infoHint)).toBeInTheDocument();
    expect(screen.getByText(S.alert.aiHint)).toBeInTheDocument();
  });

  it("links back to the queue, and names the alert", async () => {
    renderPage();
    await loaded();
    expect(screen.getByRole("link", { name: S.nav.queue })).toHaveAttribute("href", "/queue");
    expect(screen.getByText("a1", { selector: "span" })).toBeInTheDocument();
  });

  it("says it is loading, and then shows the alert", async () => {
    renderPage();
    expect(screen.getByRole("status")).toHaveTextContent(S.common.loading);
    await loaded();
    expect(screen.queryByText(S.common.loading)).not.toBeInTheDocument();
  });

  it("says the alert was not found for a 404, without a retry", async () => {
    renderPage("/alerts/nope");
    expect(await screen.findByRole("heading", { name: S.alert.notFound })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.common.retry })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: S.nav.queue })).toBeInTheDocument();
  });

  it("says it failed for a 500 and asks again on 'Thử lại'", async () => {
    views = { a1: { status: 500 } };
    renderPage();
    expect(await screen.findByRole("alert")).toHaveTextContent(S.alert.loadFailed);
    views = { a1: full() };
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: S.common.retry }));
    expect(await loaded()).toHaveTextContent("sshd: authentication failed");
  });

  it("asks for the alert of the URL, encoded", async () => {
    views = { "a b/1": full({ alert_id: "a b/1" }) };
    renderPage("/alerts/a%20b%2F1");
    await loaded();
    expect(requests).toEqual(["a b/1"]);
  });

  it("unknown enum renders raw code: a status, a category and a band with no label", async () => {
    views = {
      a1: full({
        status: "quantum_pending",
        category: "new_thing",
        risk_band: "Nghiêm trọng",
        suggestion: null,
      }),
    };
    renderPage();
    await loaded();
    const top = within(summary());
    expect(top.getByText("quantum_pending")).toBeInTheDocument();
    expect(top.getByText("new_thing")).toBeInTheDocument();
    expect(top.getByText("Nghiêm trọng")).toBeInTheDocument();
  });
});

describe("sections", () => {
  it("shows a section for each part of the view that has data", async () => {
    renderPage();
    await loaded();
    expect(heading3(S.alert.eventDetails)).toBeInTheDocument();
    expect(heading3(S.alert.rawLog)).toBeInTheDocument();
    expect(heading3(S.alert.accounts)).toBeInTheDocument();
    expect(heading3(S.alert.enrichment)).toBeInTheDocument();
    expect(heading3(S.alert.correlation)).toBeInTheDocument();
    expect(heading3(S.alert.playbook)).toBeInTheDocument();
    expect(valueOf(S.alert.field.srcip)).toHaveTextContent("203.0.113.45");
    expect(valueOf(S.alert.field.dstip)).toHaveTextContent("192.0.2.10");
    expect(valueOf(S.alert.field.srcPort)).toHaveTextContent("51522");
    expect(valueOf(S.alert.field.dstPort)).toHaveTextContent("22");
    expect(valueOf(S.alert.field.user)).toHaveTextContent("admin");
    expect(valueOf(S.alert.field.decoder)).toHaveTextContent("sshd");
    expect(valueOf(S.alert.field.ruleGroups)).toHaveTextContent(
      "syslog, sshd, authentication_failed",
    );
    expect(valueOf(S.alert.field.mitre)).toHaveTextContent("T1110.001");
    expect(valueOf(S.alert.field.source)).toHaveTextContent("wazuh_pull");
    expect(valueOf(S.alert.field.alertTime)).toHaveTextContent("30/09/2026 09:31:02");
    expect(valueOf(S.alert.field.eventTime)).toHaveTextContent("30/09/2026 09:31:00");
  });

  it("shows no MITRE block when mitre_ids is empty, and no other section for data the view lacks", async () => {
    views = { a1: sparse({ mitre_ids: [], srcip: "203.0.113.45", description: "d" }) };
    renderPage();
    await loaded();
    expect(screen.getByText(S.alert.field.srcip, { selector: "dt" })).toBeInTheDocument();
    expect(screen.queryByText(S.alert.field.mitre, { selector: "dt" })).not.toBeInTheDocument();
    expect(
      screen.queryByText(S.alert.field.ruleGroups, { selector: "dt" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(S.alert.field.dstip, { selector: "dt" })).not.toBeInTheDocument();
    for (const name of [
      S.alert.rawLog,
      S.alert.accounts,
      S.alert.enrichment,
      S.alert.correlation,
      S.alert.playbook,
    ]) {
      expect(heading3(name), name).not.toBeInTheDocument();
    }
  });

  it("shows no event-details block at all when it has none of its fields", async () => {
    views = {
      a1: sparse({ description: "d", mitre_ids: [], rule_groups: [], targeted_accounts: [] }),
    };
    renderPage();
    await loaded();
    expect(heading3(S.alert.eventDetails)).not.toBeInTheDocument();
    expect(heading3(S.alert.accounts)).not.toBeInTheDocument();
  });

  it("names the alert by its id when the view carries no description", async () => {
    views = { a1: sparse() };
    renderPage();
    expect(await loaded()).toHaveTextContent("a1");
  });

  it("lists the targeted accounts, the correlation rows and the samples, the playbook as text", async () => {
    renderPage();
    await loaded();
    const accounts = within(heading3(S.alert.accounts)!.closest("section")!);
    expect(accounts.getAllByRole("listitem").map((li) => li.textContent)).toEqual([
      "admin",
      "root",
      "ubuntu",
    ]);

    const correlation = within(heading3(S.alert.correlation)!.closest("section")!);
    expect(correlation.getByText(S.alert.correlationHint(4))).toBeInTheDocument();
    const row = correlation.getByRole("row", { name: /5710/ });
    expect(row).toHaveTextContent("ssh_invalid_user");
    expect(row).toHaveTextContent(S.status.queued_tier1);
    expect(row).toHaveTextContent("12");
    expect(row).toHaveTextContent("30/09 09:12 → 30/09 09:30");
    expect(correlation.getByText(S.alert.correlationSamples)).toBeInTheDocument();
    expect(
      correlation.getByRole("link", { name: /sshd: attempt to login using a non-existent user/ }),
    ).toHaveAttribute("href", "/alerts/s1");

    const playbook = within(heading3(S.alert.playbook)!.closest("section")!);
    expect(playbook.getByText(/Xác định IP nguồn là nội bộ hay bên ngoài/)).toBeInTheDocument();
  });

  it("says so when the window holds no cluster, and when the category has no playbook", async () => {
    views = {
      a1: full({ correlation: { rows: [], samples: [] }, correlated_now: 0, playbook: null }),
    };
    renderPage();
    await loaded();
    expect(screen.getByText(S.alert.noCorrelation)).toBeInTheDocument();
    expect(screen.getByText(S.alert.noPlaybook)).toBeInTheDocument();
  });

  it("shows what the enrichment says, and 'not known' for what it has not", async () => {
    renderPage();
    await loaded();
    const enrichment = heading3(S.alert.enrichment)!.closest("section")!;
    expect(
      within(enrichment).getByText(S.alert.assetCriticality).nextElementSibling,
    ).toHaveTextContent("medium");
    expect(within(enrichment).getByText(S.alert.assetOwner).nextElementSibling).toHaveTextContent(
      "[CHỦ TÀI SẢN]",
    );
    expect(within(enrichment).getByText(S.alert.assetRole).nextElementSibling).toHaveTextContent(
      "server",
    );
    expect(
      within(enrichment).getByText(S.alert.identityPrivileged).nextElementSibling,
    ).toHaveTextContent(S.common.missing);
    expect(
      within(enrichment).getByText(S.alert.iocReputation).nextElementSibling,
    ).toHaveTextContent(S.common.missing);
    const lookups = within(enrichment).getByText(S.alert.lookupStatus).nextElementSibling!;
    expect(lookups).toHaveTextContent(`asset: ${S.alert.lookup.found}`);
    expect(lookups).toHaveTextContent(`ioc: ${S.alert.lookup.skipped}`);
  });

  it("unknown enum renders raw code: a lookup status and an asset criticality with no label", async () => {
    views = {
      a1: full({
        lookup_status: { asset: "exploded" },
        asset_context: { present: true, criticality: "ultra" },
      }),
    };
    renderPage();
    await loaded();
    const enrichment = heading3(S.alert.enrichment)!.closest("section")!;
    expect(enrichment).toHaveTextContent("asset: exploded");
    expect(enrichment).toHaveTextContent("ultra");
  });
});

describe("a duplicate, and the case", () => {
  it("says the alert is a copy of its head, and shows the head", async () => {
    views = {
      dup9: full({ alert_id: "head1", requested_alert_id: "dup9" }),
      head1: full({ alert_id: "head1" }),
    };
    renderPage("/alerts/dup9");
    await loaded();
    expect(screen.getByText(S.alert.duplicateOf("head1"))).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "head1" })).toHaveAttribute("href", "/alerts/head1");
  });

  it("says nothing of a copy when the alert asked for is the head", async () => {
    renderPage();
    await loaded();
    expect(screen.queryByText(/bản sao của/)).not.toBeInTheDocument();
  });

  it.each(["tier2", "admin"] as const)(
    "links an escalated alert to its case for %s, who can open it",
    async (role) => {
      views = { a1: full({ status: "escalated_tier2", case_id: 9 }) };
      renderPage("/alerts/a1", role);
      await loaded();
      const link = within(summary()).getByRole("link", { name: `${S.decision.goToCase} #9` });
      expect(link).toHaveAttribute("href", "/cases/9");
    },
  );

  it("names the case in plain text for tier 1, who has no case pages to be sent to", async () => {
    views = { a1: full({ status: "escalated_tier2", case_id: 9 }) };
    renderPage("/alerts/a1", "tier1");
    await loaded();
    expect(within(summary()).getByText(S.decision.caseNumber(9))).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /case/i })).not.toBeInTheDocument();
  });

  it.each(["tier1", "tier2", "admin"] as const)(
    "shows no case, link or text, for an alert with none (%s)",
    async (role) => {
      renderPage("/alerts/a1", role);
      await loaded();
      expect(
        screen.queryByRole("link", { name: new RegExp(S.decision.goToCase) }),
      ).not.toBeInTheDocument();
      expect(summary().textContent).not.toMatch(/case #/);
    },
  );

  it("shows when it was acknowledged and by whom, and why and when it was closed", async () => {
    views = {
      a1: full({
        status: "closed_benign",
        acknowledged_by: ME_ID,
        acknowledged_by_name: "An",
        acknowledged_at: "2026-09-30T02:40:00Z",
        closed_at: "2026-09-30T02:50:00Z",
        close_reason: "máy quét nội bộ đã đăng ký",
      }),
    };
    renderPage();
    await loaded();
    expect(valueOf(S.alert.summary.acknowledgedBy)).toHaveTextContent("An");
    expect(valueOf(S.alert.summary.acknowledgedAt)).toHaveTextContent("30/09 09:40");
    expect(valueOf(S.alert.summary.closedAt)).toHaveTextContent("30/09 09:50");
    expect(valueOf(S.alert.summary.closeReason)).toHaveTextContent("máy quét nội bộ đã đăng ký");
  });
});

describe("the ① column, from the state of the view", () => {
  it("says 'gợi ý dựa trên N cụm … hiện có M' when the clusters changed since ① ran", async () => {
    views = { a1: full({ correlated_now: 6 }) };
    renderPage();
    await loaded();
    expect(within(aiColumn()).getByText(S.ai1.correlatedChanged(4, 6))).toBeInTheDocument();
  });

  it("says nothing of it when the count is the same", async () => {
    renderPage();
    await loaded();
    expect(screen.queryByText(/gợi ý dựa trên/)).not.toBeInTheDocument();
  });

  it("shows ① for the visible arm", async () => {
    renderPage();
    await loaded();
    expect(within(aiColumn()).getByText(/AI kết luận/)).toHaveTextContent(
      "AI kết luận: TP (độ tin cậy trung bình)",
    );
  });

  it("says the verdict and which checks warned (DEC-217), from the view's own keys", async () => {
    views = {
      a1: full({
        suggestion: suggestion({
          suggested_action: "false_positive",
          gate: { forced: false, forced_by: [], proposed_verdict: "false_positive" },
        }),
        proposed_action: "false_positive",
        held_by: ["fp_policy:asset_criticality", "fp_policy:playbook_rule"],
      }),
    };
    renderPage();
    await loaded();
    expect(within(aiColumn()).getByText(/AI kết luận/)).toHaveTextContent(
      "AI kết luận: FP (độ tin cậy trung bình) — có cảnh báo kiểm chứng: " +
        "tài sản quan trọng hoặc chưa rõ, không khớp bảng quyết định đã duyệt",
    );
    expect(aiColumn().textContent).not.toContain("Cần xem xét");
  });

  it("still flags a version 1 row the gate forced (gate_forced true), with the model's own verdict", async () => {
    views = {
      a1: full({
        suggestion: suggestion({
          suggested_action: "false_positive",
          gate: { forced: true, forced_by: ["step4"], proposed_verdict: "false_positive" },
        }),
        proposed_action: "false_positive",
        held_by: ["fp_policy:playbook_rule"],
      }),
    };
    renderPage();
    await loaded();
    expect(within(aiColumn()).getByRole("img", { name: S.ai1.forcedLabel })).toBeInTheDocument();
    expect(within(aiColumn()).getByText(S.ai1.gateForced)).toBeInTheDocument();
  });

  // DEC-219: the page hands the column the view as it is, and the line says the RAG rule made the verdict.
  it("says the RAG rule made the verdict, with the flag, from the view's own gate (DEC-219)", async () => {
    views = {
      a1: full({
        suggestion: suggestion({
          suggested_action: "false_positive",
          confidence: "high",
          gate: {
            forced: true,
            forced_by: ["rag_rule"],
            proposed_verdict: "true_positive",
            final_verdict: "false_positive",
            verifier_verdict: "true_positive",
            rag_rule: { threshold: 80, best_pct: 62, applied: true, changed: true },
          },
        }),
        proposed_action: "true_positive",
        held_by: ["fp_policy:playbook_rule"],
        rag: { best_pct: 62, not_applied: null },
      }),
    };
    renderPage();
    await loaded();
    expect(within(aiColumn()).getByText(/AI kết luận/).textContent).toBe(
      "AI kết luận: FP — trùng 62% với tri thức đã duyệt — theo quy tắc RAG: trùng dưới 80% (model kết luận TP) — " +
        "có cảnh báo kiểm chứng: không khớp bảng quyết định đã duyệt⚑",
    );
    expect(within(aiColumn()).getByRole("img", { name: S.ai1.forcedLabel })).toBeInTheDocument();
    expect(within(aiColumn()).getByText("quy tắc RAG")).toBeInTheDocument();
  });

  it("shows the hidden state for a blind view, names no verdict, and still lets the analyst act", async () => {
    views = {
      a1: blind({ status: "tier1_active", acknowledged_by: ME_ID, acknowledged_by_name: "An" }),
    };
    renderPage();
    await loaded();
    const col = aiColumn();
    expect(within(col).getByText(S.ai1.hidden)).toBeInTheDocument();
    for (const word of [
      "TP",
      "true_positive",
      "AI kết luận",
      "cảnh báo kiểm chứng",
      "quy tắc RAG",
      "model kết luận",
      "trung bình",
      "Failed password for invalid user admin from",
    ]) {
      expect(col.textContent, word).not.toContain(word);
    }
    for (const said of [S.ai1.pending, S.ai1.unavailable, S.ai1.none]) {
      expect(col.textContent, said).not.toContain(said);
    }
    expect(
      await screen.findByRole("radio", { name: S.decision.falsePositive }),
    ).toBeInTheDocument();
  });

  it("shows nothing of ① on the page itself for a blind view, the ⟳ and the counters included", async () => {
    views = { a1: blind() };
    renderPage();
    await loaded();
    expect(screen.queryByText(S.ai1.action.true_positive)).not.toBeInTheDocument();
    expect(screen.queryByText(/AI kết luận/)).not.toBeInTheDocument();
    expect(screen.queryByText(S.queue.retriageMark)).not.toBeInTheDocument();
  });

  it("shows the pending state from the server's word, and polls until ① has answered", async () => {
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"],
      shouldAdvanceTime: true,
    });
    views = { a1: sparse({ description: "d" }) };
    renderPage();
    await loaded();
    expect(within(aiColumn()).getByText(S.ai1.pending)).toBeInTheDocument();
    expect(requests).toHaveLength(1);
    views = { a1: full({ description: "d" }) };
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    await waitFor(() =>
      expect(within(aiColumn()).getByText(/AI kết luận/)).toHaveTextContent(
        `AI kết luận: ${S.ai1.action.true_positive}`,
      ),
    );
    expect(requests).toHaveLength(2);
    // ① has answered: no more polling while the socket is (faked) live
    act(() => live().onStatus("live"));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(requests.length).toBeLessThanOrEqual(4); // at most the resync of the socket coming up
  });

  it("does not poll a blind, undecided view: no answer to wait for, and the socket is live", async () => {
    // A blind view has no `suggestion` and no `triage_status`, as a pending one has none. Only the server's
    // word "pending" makes the page ask again every 10 s (R12); a blind view must never be taken for one.
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"],
      shouldAdvanceTime: true,
    });
    views = { a1: blind({ description: "d" }) };
    renderPage();
    await loaded();
    expect(within(aiColumn()).getByText(S.ai1.hidden)).toBeInTheDocument();
    act(() => live().onStatus("live")); // one resync of the socket coming up, then no clock
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    const afterResync = requests.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(65_000);
    });
    expect(requests).toHaveLength(afterResync);
  });

  it("shows the unavailable state when ① gave up", async () => {
    views = { a1: sparse({ triage_status: "unavailable", description: "d" }) };
    renderPage();
    await loaded();
    expect(within(aiColumn()).getByText(S.ai1.unavailable)).toBeInTheDocument();
    expect(within(aiColumn()).queryByText(S.ai1.stoppedByLabel)).not.toBeInTheDocument();
  });

  it("says why ① gave up when the view carries it: a provider 402 reads as the F6 label (INT-T02)", async () => {
    views = {
      a1: sparse({
        triage_status: "unavailable",
        llm_stopped_by: "unavailable",
        description: "d",
      }),
    };
    renderPage();
    await loaded();
    const column = within(aiColumn());
    expect(column.getByText(S.ai1.unavailable)).toBeInTheDocument();
    expect(column.getByText(S.ai1.stoppedByLabel)).toBeInTheDocument();
    expect(
      column.getByText("nhà cung cấp LLM từ chối (hết số dư / hạn mức, 402)"),
    ).toBeInTheDocument();
  });

  it("says nothing of why on the blind arm, whatever a view carries (INT-T02, DEC-101)", async () => {
    views = {
      a1: blind({
        triage_status: "unavailable",
        llm_stopped_by: "unavailable",
        description: "d",
      }),
    };
    renderPage();
    await loaded();
    const column = within(aiColumn());
    expect(column.getByText(S.ai1.hidden)).toBeInTheDocument();
    expect(column.queryByText(S.ai1.unavailable)).not.toBeInTheDocument();
    expect(column.queryByText(S.ai1.stoppedByLabel)).not.toBeInTheDocument();
    expect(aiColumn().textContent).not.toContain("402");
  });

  it("shows the comparison once the alert is decided", async () => {
    views = {
      a1: full({ status: "closed_fp", acknowledged_by: ME_ID, acknowledged_by_name: "An" }),
    };
    renderPage();
    await loaded();
    expect(within(aiColumn()).getByText(S.ai1.decidedHeading)).toBeInTheDocument();
  });

  it("goes from hidden to the comparison when the decision is made, from the view it fetches again", async () => {
    views = {
      a1: blind({ status: "tier1_active", acknowledged_by: ME_ID, acknowledged_by_name: "An" }),
    };
    server.use(
      http.post("/api/tier1/alerts/:id/decide", () => {
        // The decision is recorded: from now on the server shows the suggestion, and the status is closed.
        views = {
          a1: full({
            status: "closed_fp",
            acknowledged_by: ME_ID,
            acknowledged_by_name: "An",
            close_reason: "không có dấu hiệu tấn công",
          }),
        };
        return HttpResponse.json({
          alert_id: "a1",
          status: "closed_fp",
          closed_count: 1,
          case_id: null,
        });
      }),
    );
    renderPage();
    await loaded();
    expect(within(aiColumn()).getByText(S.ai1.hidden)).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("radio", { name: S.decision.falsePositive }));
    await user.type(screen.getByLabelText(S.decision.reason), "không có dấu hiệu tấn công");
    await user.click(screen.getByRole("button", { name: S.decision.submit }));
    expect(await within(aiColumn()).findByText(S.ai1.decidedHeading)).toBeInTheDocument();
    expect(within(aiColumn()).getByText(S.ai1.decidedAi).closest("div")).toHaveTextContent(
      S.ai1.action.true_positive,
    );
    expect(within(aiColumn()).queryByText(S.ai1.hidden)).not.toBeInTheDocument();
    expect(screen.getByText(S.decision.decidedAs(S.status.closed_fp))).toBeInTheDocument();
  });
});

describe("the decision panel on the page", () => {
  it("is there for tier1, and asks for the user once", async () => {
    views = {
      a1: full({ status: "tier1_active", acknowledged_by: ME_ID, acknowledged_by_name: "An" }),
    };
    renderPage();
    await loaded();
    expect(await screen.findByRole("radio", { name: S.decision.benign })).toBeInTheDocument();
    expect(meCalls).toBe(1);
  });

  it.each(["tier2", "admin"] as const)("is not there for %s, who reads the page", async (role) => {
    views = {
      a1: full({ status: "tier1_active", acknowledged_by: ME_ID, acknowledged_by_name: "An" }),
    };
    renderPage("/alerts/a1", role);
    await loaded();
    expect(screen.queryByRole("button", { name: S.decision.acknowledge })).not.toBeInTheDocument();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: S.decision.heading })).not.toBeInTheDocument();
    expect(meCalls).toBe(0);
  });

  it("acknowledges, and the page shows the alert as active and held by the analyst", async () => {
    views = { a1: full() };
    server.use(
      http.post("/api/tier1/alerts/:id/acknowledge", () => {
        views = {
          a1: full({ status: "tier1_active", acknowledged_by: ME_ID, acknowledged_by_name: "An" }),
        };
        return HttpResponse.json({
          alert_id: "a1",
          status: "tier1_active",
          acknowledged_by: ME_ID,
        });
      }),
    );
    renderPage();
    await loaded();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: S.decision.acknowledge }));
    expect(
      await screen.findByRole("radio", { name: S.decision.falsePositive }),
    ).toBeInTheDocument();
    expect(within(summary()).getByText(S.status.tier1_active)).toBeInTheDocument();
  });
});

describe("the count a decision is made on, across a live refetch (ruling R19)", () => {
  it("sends the count read when the form was drawn, then the count the 409 showed", async () => {
    views = {
      a1: full({ status: "tier1_active", acknowledged_by: ME_ID, acknowledged_by_name: "An" }),
    };
    const seen: number[] = [];
    server.use(
      http.post("/api/tier1/alerts/:id/decide", async ({ request }) => {
        const body = (await request.json()) as { seen_occurrence_count: number };
        seen.push(body.seen_occurrence_count);
        if (seen.length === 1) {
          return HttpResponse.json(
            {
              kind: "cluster_grew",
              occurrence_count: 120,
              seen_occurrence_count: body.seen_occurrence_count,
              delta: 83,
              tolerance: 2,
              status: "tier1_active",
              decided_by: null,
              decision: null,
              decided_at: null,
              acknowledged_by: ME_ID,
            },
            { status: 409 },
          );
        }
        return HttpResponse.json({
          alert_id: "a1",
          status: "closed_fp",
          closed_count: 1,
          case_id: null,
        });
      }),
    );
    renderPage();
    await loaded();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("radio", { name: S.decision.falsePositive }));
    await user.type(
      screen.getByRole("textbox", { name: S.decision.reason }),
      "không có dấu hiệu tấn công",
    );
    // the alert is refetched by the socket while the analyst types: the page shows 120, the form still holds 37
    views = {
      a1: full({
        status: "tier1_active",
        acknowledged_by: ME_ID,
        acknowledged_by_name: "An",
        occurrence_count: 120,
      }),
    };
    act(() => live().onChange(["a1"]));
    await waitFor(() => expect(valueOf(S.alert.summary.occurrences)).toHaveTextContent("120"));
    expect(screen.getByText(S.decision.seenChanged(37, 120))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: S.decision.submit }));
    expect(await screen.findByText(S.decision.seenHint(120))).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: S.decision.submit }));
    await waitFor(() => expect(seen).toHaveLength(2));
    expect(seen).toEqual([37, 120]);
  });
});

describe("the SOAR enrichment (S3)", () => {
  const SOAR_TITLES = [
    S.alert.soar.caseTitle,
    S.alert.soar.actionTitle,
    S.alert.soar.scenarioTitle,
    S.alert.soar.historyTitle,
    S.alert.soar.geoTitle,
    S.alert.soar.scanTitle,
    S.alert.soar.tiTitle,
  ];
  const left = () => screen.getByRole("region", { name: S.alert.infoHeading });

  it("shows the case, the action, the scenario, the history, the scan and the TI in the left column", async () => {
    views = { a1: full({ soar: SC03 }) };
    renderPage();
    await loaded();
    const column = within(left());
    for (const title of [
      S.alert.soar.caseTitle,
      S.alert.soar.actionTitle,
      S.alert.soar.scenarioTitle,
      S.alert.soar.historyTitle,
      S.alert.soar.scanTitle,
      S.alert.soar.tiTitle,
    ]) {
      expect(column.getByRole("heading", { level: 3, name: title })).toBeInTheDocument();
    }
    expect(column.getByText("Case TheHive: #55")).toBeInTheDocument();
    expect(column.getByText("block_ip → 79.79.78.202 (auto, act_first)")).toBeInTheDocument();
    expect(column.getByText(SC03.triage!.signal_text!)).toBeInTheDocument();
    expect(heading3(S.alert.soar.geoTitle)).toBeNull(); // SC03 has no geo
    // none of it is in the ① column
    expect(within(aiColumn()).queryByText("Case TheHive: #55")).toBeNull();
  });

  it("shows the GEO01 block when the view carries one", async () => {
    views = { a1: full({ soar: { ...MW03, ...GEO } }) };
    renderPage();
    await loaded();
    expect(heading3(S.alert.soar.geoTitle)).toBeInTheDocument();
    expect(valueOf(S.alert.soar.country)).toHaveTextContent("VN (mô phỏng)");
  });

  it.each([
    ["no soar key", full()],
    ["soar null", full({ soar: null })],
    ["soar empty", full({ soar: {} })],
  ])("shows none of the SOAR sections for an alert with %s", async (_name, answer) => {
    views = { a1: answer };
    renderPage();
    await loaded();
    for (const title of SOAR_TITLES) expect(heading3(title)).toBeNull();
    // and the rest of the page is as it was
    expect(heading3(S.alert.eventDetails)).toBeInTheDocument();
  });

  it("keeps them on the blind arm, where nothing of ① is shown", async () => {
    views = { a1: blind({ soar: SC03 }) };
    renderPage();
    await loaded();
    expect(heading3(S.alert.soar.caseTitle)).toBeInTheDocument();
    expect(screen.getByText("Case TheHive: #55")).toBeInTheDocument();
    const column = aiColumn();
    expect(within(column).queryByText("Case TheHive: #55")).toBeNull();
    expect(within(column).getByText(S.ai1.hidden)).toBeInTheDocument();
  });

  it("shows the event time beside the alert time, in +07", async () => {
    views = { a1: full({ soar: MW03 }) };
    renderPage();
    await loaded();
    expect(valueOf(S.alert.field.alertTime)).toHaveTextContent("30/09/2026 09:31:02");
    expect(valueOf(S.alert.field.eventTime)).toHaveTextContent("30/09/2026 09:31:00");
  });

  it("renders a hostile SOAR value as text on the page", async () => {
    const hostile = '<img src=x onerror="window.__s3p=1"></script><script>window.__s3p=2</script>';
    views = {
      a1: full({
        soar: {
          ...SC03,
          case: { case_number: 9, dedup_key: hostile },
          triage: { score: 1, signal_text: hostile },
          scan: { ports_sampled: [hostile], previous_output: hostile },
        },
      }),
    };
    renderPage();
    await loaded();
    expect(document.body.querySelector("img")).toBeNull();
    expect(document.body.querySelector("script")).toBeNull();
    expect((window as unknown as { __s3p?: number }).__s3p).toBeUndefined();
    expect(valueOf(S.alert.soar.dedupKey)).toHaveTextContent(hostile);
    expect(screen.getByText(hostile, { selector: "pre" })).toBeInTheDocument();
  });
});

describe("the category in Vietnamese (S1 follow-up)", () => {
  it("shows credential_access by its Vietnamese label and keeps the code beside it", async () => {
    views = { a1: full({ category: "credential_access" }) };
    renderPage();
    await loaded();
    const top = within(summary());
    expect(S.category.credential_access).toBeTruthy();
    expect(top.getByText(S.category.credential_access)).toBeInTheDocument();
    expect(top.getByText("credential_access")).toBeInTheDocument();
  });
});

describe("hostile text (Review Focus 1)", () => {
  it("renders hostile raw_log as text", async () => {
    const hostile = '<img src=x onerror="window.__x=1">';
    views = { a1: full({ raw_log: hostile }) };
    renderPage();
    await loaded();
    const page = document.body;
    expect(page.querySelector("img")).toBeNull();
    expect(screen.getByText(hostile, { selector: "pre" })).toBeInTheDocument();
    expect((window as unknown as { __x?: number }).__x).toBeUndefined();
  });

  it("renders </script>, a right-to-left override and ANSI escapes as they are", async () => {
    const hostile = "</script><script>window.__y=1</script> ‮txet \u001b[31mred\u001b[0m";
    views = {
      a1: full({
        raw_log: hostile,
        description: hostile,
        alert_user: hostile,
        rule_groups: [hostile],
        targeted_accounts: [hostile],
        playbook: hostile,
        suggestion: suggestion({ reasons: [{ claim: hostile, quote: hostile, source: hostile }] }),
      }),
    };
    renderPage();
    await loaded();
    expect(document.body.querySelector("script")).toBeNull();
    expect((window as unknown as { __y?: number }).__y).toBeUndefined();
    expect(screen.getByText(hostile, { selector: "pre" })).toBeInTheDocument();
  });

  it("renders a 200 KB raw_log without a new element", async () => {
    const line = "Failed password for invalid user admin from 203.0.113.45 port 51522 ssh2\n";
    const big = line.repeat(Math.ceil(200_000 / line.length) + 1);
    expect(big.length).toBeGreaterThanOrEqual(200_000);

    views = { a1: full({ raw_log: "short" }) };
    const small = renderPage();
    await loaded();
    // counted inside the page's own container: an unmounted render leaves its empty container in the body
    const elementsWithShort = small.container.querySelectorAll("*").length;
    small.unmount();

    views = { a1: full({ raw_log: big }) };
    const large = renderPage();
    await loaded();
    const logs = document.body.querySelectorAll("pre");
    expect(logs).toHaveLength(1);
    const pre = logs[0]!;
    expect(pre.textContent!.length).toBeGreaterThanOrEqual(200_000);
    expect(pre.childNodes).toHaveLength(1); // one text node: the log is not split into elements
    expect(pre.className).toContain("max-h-96");
    expect(pre.className).toContain("overflow-auto");
    expect(large.container.querySelectorAll("*").length).toBe(elementsWithShort);
  });

  it("notes that the log was cut only when the server says so", async () => {
    views = { a1: full({ raw_log_truncated: true }) };
    const first = renderPage();
    await loaded();
    expect(screen.getByText(S.alert.rawLogTruncated)).toBeInTheDocument();
    first.unmount();
    views = { a1: full({ raw_log_truncated: false }) };
    renderPage();
    await loaded();
    expect(screen.queryByText(S.alert.rawLogTruncated)).not.toBeInTheDocument();
  });

  it("copies the log to the clipboard, and says so", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(screen.getByRole("button", { name: S.common.copy }));
    expect(await navigator.clipboard.readText()).toBe(full().raw_log);
    expect(await screen.findByText(S.common.copied)).toBeInTheDocument();
  });

  it("does not fail when the clipboard is refused", async () => {
    const user = userEvent.setup();
    renderPage();
    await loaded();
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("denied"));
    await user.click(screen.getByRole("button", { name: S.common.copy }));
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalled());
    expect(screen.queryByText(S.common.copied)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: S.common.copy })).toBeEnabled();
  });
});

describe("live", () => {
  it("fetches the alert again when alerts.changed names its id", async () => {
    renderPage();
    await loaded();
    expect(valueOf(S.alert.summary.occurrences)).toHaveTextContent("37");
    expect(requests).toHaveLength(1);
    views = { a1: full({ occurrence_count: 41 }) };
    act(() => live().onChange(["a1"]));
    await waitFor(() => expect(valueOf(S.alert.summary.occurrences)).toHaveTextContent("41"));
    expect(requests).toHaveLength(2);
  });

  it("does not fetch it again for a change to another alert", async () => {
    renderPage();
    await loaded();
    act(() => live().onChange(["zzz"]));
    await new Promise((r) => setTimeout(r, 80));
    expect(requests).toHaveLength(1);
  });

  it("fetches it again when the server folds a burst into 'many'", async () => {
    renderPage();
    await loaded();
    views = { a1: full({ occurrence_count: 50 }) };
    act(() => live().onChange("many"));
    await waitFor(() => expect(valueOf(S.alert.summary.occurrences)).toHaveTextContent("50"));
  });

  it("follows the head of a duplicate: a change to the head refreshes what the page shows", async () => {
    views = {
      dup9: full({ alert_id: "head1", requested_alert_id: "dup9" }),
      head1: full({ alert_id: "head1" }),
    };
    renderPage("/alerts/dup9");
    await loaded();
    expect(valueOf(S.alert.summary.occurrences)).toHaveTextContent("37");
    views = {
      dup9: full({ alert_id: "head1", requested_alert_id: "dup9", occurrence_count: 44 }),
      head1: full({ alert_id: "head1", occurrence_count: 44 }),
    };
    act(() => live().onChange(["head1"]));
    await waitFor(() => expect(valueOf(S.alert.summary.occurrences)).toHaveTextContent("44"));
    expect(screen.getByText(S.alert.duplicateOf("head1"))).toBeInTheDocument();
  });

  it("polls every 30 s while the socket is down, and stops when it is live", async () => {
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"],
      shouldAdvanceTime: true,
    });
    renderPage();
    await loaded();
    expect(requests).toHaveLength(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(29_000);
    });
    expect(requests).toHaveLength(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2_000);
    });
    await waitFor(() => expect(requests).toHaveLength(2));
    act(() => live().onStatus("live")); // one resync of the socket coming up, then no clock
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    const afterResync = requests.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(120_000);
    });
    expect(requests).toHaveLength(afterResync);
  });
});

describe("accessibility", () => {
  const violations = async (container: HTMLElement) => {
    // jsdom computes no colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`);
  };
  const held = { status: "tier1_active", acknowledged_by: ME_ID, acknowledged_by_name: "An" };

  const cases: [string, Record<string, AlertView | { status: number }>, Session["role"]][] = [
    ["ready, queued", { a1: full() }, "tier1"],
    ["ready, held by the analyst", { a1: full(held) }, "tier1"],
    [
      "ready, forced",
      {
        a1: full({
          suggestion: suggestion({ gate: { forced: true, forced_by: ["x"], warnings: ["w"] } }),
          correlated_now: 9,
        }),
      },
      "tier1",
    ],
    ["hidden", { a1: blind() }, "tier1"],
    ["pending", { a1: sparse({ description: "d" }) }, "tier1"],
    ["unavailable", { a1: sparse({ triage_status: "unavailable", description: "d" }) }, "tier1"],
    [
      "decided",
      { a1: full({ status: "closed_benign", close_reason: "lý do", acknowledged_by_name: "An" }) },
      "tier1",
    ],
    ["escalated, with its case", { a1: full({ status: "escalated_tier2", case_id: 9 }) }, "tier1"],
    ["a duplicate", { a1: full({ alert_id: "head1", requested_alert_id: "a1" }) }, "tier1"],
    ["read by tier2", { a1: full(held) }, "tier2"],
    ["with none of the optional data", { a1: sparse() }, "tier1"],
    ["with the SOAR sections of an MW03 alert", { a1: full({ soar: MW03 }) }, "tier1"],
    ["with the SOAR sections of an SC03 alert", { a1: full({ soar: SC03 }) }, "tier1"],
    [
      "with the SOAR sections and a GEO01 block",
      { a1: full({ soar: { ...SC03, ...GEO } }) },
      "tier1",
    ],
    ["blind, with the SOAR sections", { a1: blind({ soar: SC03 }) }, "tier1"],
  ];

  it.each(cases)("has no axe violation: %s", async (_name, answers, role) => {
    views = answers;
    renderPage("/alerts/a1", role);
    await loaded();
    // the form of a held alert appears once /me has said whose it is
    if (role === "tier1" && answers.a1?.status === "tier1_active") {
      await screen.findByRole("radio", { name: S.decision.benign });
    }
    expect(await violations(document.body)).toEqual([]);
  });

  it("has none while loading, not found, or failed", async () => {
    const loading = renderPage();
    expect(await violations(document.body)).toEqual([]);
    await loaded();
    loading.unmount();
    renderPage("/alerts/nope");
    await screen.findByRole("heading", { name: S.alert.notFound });
    expect(await violations(document.body)).toEqual([]);
  });
});
