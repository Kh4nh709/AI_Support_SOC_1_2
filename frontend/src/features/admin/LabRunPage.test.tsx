// src/features/admin/LabRunPage.test.tsx — `/admin/lab/:runId` (P14-T10, DEC-213, spec §6): the alerts of one lab run,
// oldest first, and the buttons that label them TP or FP. A small in-memory backend stands in for the three routes
// (MSW) and records every call.
//
// BLIND (DEC-101): the page shows the alert's own fields and its label, nothing of ① or ②. The server filters what it
// sends (`tier1.visibility.strip(..., mode="labeling")`); the page is the second wall: it renders each field by name,
// calls no tier1, tier2 or knowledge route, and links to no alert page. The tests plant the keys the server must never
// send and read the source of the page for the ways one could get through.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { delay, http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter, Route, Routes } from "react-router";
import ts from "typescript";
import type { LabAlert, LabAlertsResponse, LabLabel, LabRun } from "../../api/admin";
import { S } from "../../strings";
import { LabRunPage } from "./LabRunPage";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// --- the fixture --------------------------------------------------------------------------------------------------

const RUN_ID = "5f1c0a2e-3b4d-4e5f-8a9b-0123456789ab";

const alert = (n: number, over: Partial<LabAlert> = {}): LabAlert => ({
  alert_id: `1766000000.${n}`,
  // 09:0n:00 in Asia/Ho_Chi_Minh
  received_at: `2026-11-04T02:0${n}:00Z`,
  alert_time: `2026-11-04T01:5${n}:30Z`,
  rule_id: `9900${n}`,
  rule_level: 3 + n,
  severity: "medium",
  description: `Mô tả của alert số ${n}`,
  agent_name: `host-${n}.lab`,
  alert_user: `user${n}`,
  srcip: `203.0.113.${n}`,
  dstip: `10.9.0.${n}`,
  category: `loai-${n}`,
  mitre_ids: [`T10${n}`],
  occurrence_count: n,
  raw_log: `raw log of alert ${n}`,
  raw_log_truncated_for_display: false,
  label: null,
  ...over,
});

/** Three alerts, the first already carrying a TP label. */
const THREE = () => [alert(1, { label: "true_positive" }), alert(2), alert(3)];
const FIVE = () => [
  alert(1, { label: "true_positive" }),
  alert(2),
  alert(3),
  alert(4),
  alert(5, { label: "false_positive" }),
];

const runOf = (alerts: LabAlert[], over: Partial<LabRun> = {}): LabRun => ({
  run_id: RUN_ID,
  name: "Chạy chấm điểm 1",
  purpose: "test",
  starts_at: "2026-11-04T02:00:00Z", // 09:00
  ends_at: "2026-11-04T04:00:00Z", // 11:00
  total: alerts.length,
  labelled: alerts.filter((a) => a.label !== null).length,
  ...over,
});

/**
 * What a server that LEAKS would add to an alert: every key `LABELING_DENYLIST` of tier1/visibility.py drops, with a
 * value that is easy to find. The real server never sends them; the page must show none of them if it did.
 */
const MARK = "LEAKMARK-7be41c";
const LEAK = {
  suggestion: `suggestion-${MARK}`,
  suggested_action: `escalate-${MARK}`,
  confidence: `high-${MARK}`,
  gate_forced: `forced-${MARK}`,
  gate_result: `gate-${MARK}`,
  verifier_result: `verifier-${MARK}`,
  triage_status: `ready-${MARK}`,
  risk_score: `93-${MARK}`,
  risk_band: `critical-${MARK}`,
  status: `escalated_tier2-${MARK}`,
  source: `wazuh-${MARK}`,
  soar: `soar-${MARK}`,
  case_id: `case-${MARK}`,
  llm_run_id: `run-${MARK}`,
  run_id: `run-${MARK}`,
  rag_notice: `rag-${MARK}`,
};

// --- the backend --------------------------------------------------------------------------------------------------

type Call = {
  method: string;
  path: string;
  search: string;
  body: unknown;
  contentType: string | null;
};

const refuse = (status: number, detail: unknown) => HttpResponse.json({ detail }, { status });

function backend(
  opts: {
    alerts?: LabAlert[];
    /** The size of a page; the route's own default is 100. */
    pageSize?: number;
    list?: (after: string | null) => Response | Promise<Response>;
    put?: (alertId: string) => Response | Promise<Response> | undefined;
    del?: (alertId: string) => Response | Promise<Response> | undefined;
    leak?: boolean;
  } = {},
) {
  const alerts = (opts.alerts ?? THREE()).map((a) => ({ ...a }));
  const pageSize = opts.pageSize ?? 100;
  const calls: Call[] = [];
  const note = async (request: Request) => {
    const url = new URL(request.url);
    const text = await request.clone().text();
    calls.push({
      method: request.method,
      path: url.pathname,
      search: url.search,
      body: text === "" ? null : (JSON.parse(text) as unknown),
      contentType: request.headers.get("content-type"),
    });
  };
  const view = (a: LabAlert) => (opts.leak ? { ...a, ...LEAK } : a);
  server.use(
    http.get("/api/admin/lab/runs/:runId/alerts", async ({ request }) => {
      await note(request);
      const after = new URL(request.url).searchParams.get("after");
      if (opts.list) return opts.list(after);
      const from = after === null ? 0 : alerts.findIndex((a) => a.alert_id === after) + 1;
      const page = alerts.slice(from, from + pageSize);
      const body = {
        run: opts.leak ? { ...runOf(alerts), ...LEAK } : runOf(alerts),
        alerts: page.map(view),
        next_after: page.length === pageSize ? (page[page.length - 1]?.alert_id ?? null) : null,
      } satisfies LabAlertsResponse;
      return HttpResponse.json(body);
    }),
    http.put("/api/admin/lab/labels/:alertId", async ({ request, params }) => {
      await note(request);
      const id = String(params.alertId);
      const refused = opts.put?.(id);
      if (refused !== undefined) return refused;
      const body = (await request.json()) as { label: LabLabel };
      const found = alerts.find((a) => a.alert_id === id);
      if (found) found.label = body.label;
      return HttpResponse.json(
        opts.leak
          ? { ...LEAK, alert_id: id, run_id: RUN_ID, label: body.label }
          : { alert_id: id, run_id: RUN_ID, label: body.label },
      );
    }),
    http.delete("/api/admin/lab/labels/:alertId", async ({ request, params }) => {
      await note(request);
      const id = String(params.alertId);
      const refused = opts.del?.(id);
      if (refused !== undefined) return refused;
      const found = alerts.find((a) => a.alert_id === id);
      if (found) found.label = null;
      return new HttpResponse(null, { status: 204 });
    }),
  );
  return {
    calls,
    alertsNow: () => alerts,
    gets: () => calls.filter((c) => c.method === "GET"),
    writes: () => calls.filter((c) => c.method !== "GET"),
  };
}

// --- the page -----------------------------------------------------------------------------------------------------

function renderPage(path = `/admin/lab/${RUN_ID}`) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <main>
          <Routes>
            <Route path="/admin/lab/:runId" element={<LabRunPage />} />
            <Route path="/admin/lab" element={<p>danh sách lần chạy</p>} />
          </Routes>
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...view, client };
}

const list = () => screen.findByRole("list", { name: "Các alert của lần chạy" });
/** The row of one alert, once the list is on screen. */
async function rowOf(n: number) {
  await list();
  return within(await screen.findByRole("listitem", { name: `Alert 1766000000.${n}` }));
}
const counter = (text: string) => screen.findByText(text);
/** The chip that says what an alert's label is: `TP`, `FP` or `chưa gán`, and nothing longer (a button's text is). */
const state = (row: ReturnType<typeof within>) => row.getByText(/^(TP|FP|chưa gán)$/);

const TP = "TP — tấn công thật";
const FP = "FP — không phải tấn công";
const CLEAR = "Bỏ nhãn";

// ====================================================================================================================
// the page
// ====================================================================================================================

describe("the run", () => {
  it("is named by its h1, with its purpose and its window as `start → end` in the console's zone", async () => {
    backend();
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 1, name: "Chạy chấm điểm 1" }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(screen.getByText("Chấm điểm")).toBeInTheDocument();
    expect(screen.getByText("04/11/2026 09:00:00 → 04/11/2026 11:00:00")).toBeInTheDocument();
  });

  it("shows `Đã gán x/y` from the run's labelled and total", async () => {
    backend();
    renderPage();
    expect(await counter("Đã gán 1/3")).toBeInTheDocument();
  });

  it("links back to the runs, and to nothing else", async () => {
    backend();
    const { container } = renderPage();
    await list();
    const links = within(container).getAllByRole("link");
    expect(links.map((a) => [a.textContent, a.getAttribute("href")])).toEqual([
      ["← Các lần chạy lab", "/admin/lab"],
    ]);
    expect(container.querySelectorAll("[href]")).toHaveLength(1);
  });

  it("reads the first page of the run's alerts, and only that, from GET /api/admin/lab/runs/{id}/alerts", async () => {
    const b = backend();
    renderPage();
    await list();
    expect(b.calls).toHaveLength(1);
    expect(b.calls[0]).toMatchObject({
      method: "GET",
      path: `/api/admin/lab/runs/${RUN_ID}/alerts`,
      search: "",
    });
  });

  it("lists the alerts in the order the server sent, oldest first, one item each", async () => {
    backend();
    renderPage();
    const items = within(await list()).getAllByRole("listitem");
    expect(items.map((li) => li.getAttribute("aria-label"))).toEqual([
      "Alert 1766000000.1",
      "Alert 1766000000.2",
      "Alert 1766000000.3",
    ]);
  });

  it("shows the alert's time, rule, level, description and host fields on its row", async () => {
    backend();
    renderPage();
    const row = await rowOf(2);
    // the time it was received, in the console's zone
    expect(row.getByText("04/11/2026 09:02:00")).toBeInTheDocument();
    expect(row.getByText("99002")).toBeInTheDocument();
    expect(row.getByText("(level 5)")).toBeInTheDocument();
    expect(row.getByText("Mô tả của alert số 2")).toBeInTheDocument();
    expect(row.getByText("host-2.lab")).toBeInTheDocument();
    expect(row.getByText("203.0.113.2 → 10.9.0.2")).toBeInTheDocument();
    expect(row.getByText("1766000000.2")).toBeInTheDocument();
  });

  it("shows a dash for a host field that came empty, never the word null", async () => {
    backend({ alerts: [alert(1, { srcip: "", dstip: "", agent_name: "" })] });
    const { container } = renderPage();
    const row = await rowOf(1);
    expect(row.getByText("— → —")).toBeInTheDocument();
    expect(container).not.toHaveTextContent(/null|undefined/);
  });

  it("shows the label of each alert: TP, FP or chưa gán", async () => {
    backend({ alerts: FIVE() });
    renderPage();
    const chip = async (n: number) => state(await rowOf(n));
    expect(await chip(1)).toHaveTextContent("TP");
    expect(await chip(2)).toHaveTextContent("chưa gán");
    expect(await chip(5)).toHaveTextContent("FP");
  });

  it("renders every text of the alert as text, never as markup", async () => {
    backend({
      alerts: [
        alert(1, {
          description: '<img src=x onerror="alert(1)"> <b>đậm</b>',
          agent_name: "<script>alert(1)</script>",
          raw_log: "</pre><script>alert(2)</script>",
        }),
      ],
    });
    const { container } = renderPage();
    const row = await rowOf(1);
    expect(row.getByText('<img src=x onerror="alert(1)"> <b>đậm</b>')).toBeInTheDocument();
    expect(row.getByText("<script>alert(1)</script>")).toBeInTheDocument();
    await userEvent.click(row.getByText("Chi tiết"));
    expect(await row.findByText("</pre><script>alert(2)</script>")).toBeInTheDocument();
    expect(container.querySelector("img, script, b")).toBeNull();
  });

  describe("the details of an alert", () => {
    it("are closed until asked for, then show the rest of the blind view: user, category, MITRE, count, the SIEM's time and the raw log", async () => {
      backend({ alerts: [alert(2, { raw_log_truncated_for_display: true })] });
      const user = userEvent.setup();
      renderPage();
      const row = await rowOf(2);
      expect(row.queryByText("raw log of alert 2")).not.toBeInTheDocument();
      await user.click(row.getByText("Chi tiết"));
      expect(await row.findByText("raw log of alert 2")).toBeInTheDocument();
      expect(row.getByText("user2")).toBeInTheDocument();
      expect(row.getByText("loai-2")).toBeInTheDocument();
      expect(row.getByText("T102")).toBeInTheDocument();
      expect(row.getByText("2")).toBeInTheDocument(); // the count of sightings
      expect(row.getByText("04/11/2026 08:52:30")).toBeInTheDocument(); // alert_time, +07
      expect(
        row.getByText("raw_log dài hơn 32 KB: đã cắt ở 32 KB khi hiển thị."),
      ).toBeInTheDocument();
    });

    it("show a dash for a user that is null", async () => {
      backend({ alerts: [alert(1, { alert_user: null, mitre_ids: [] })] });
      const user = userEvent.setup();
      renderPage();
      const row = await rowOf(1);
      await user.click(row.getByText("Chi tiết"));
      const dt = await row.findByText("User");
      expect(dt.nextElementSibling).toHaveTextContent("—");
    });
  });

  it("has the three buttons of the brief on every row, the current label pressed", async () => {
    backend();
    renderPage();
    const one = await rowOf(1);
    expect(one.getByRole("button", { name: TP })).toHaveAttribute("aria-pressed", "true");
    expect(one.getByRole("button", { name: FP })).toHaveAttribute("aria-pressed", "false");
    expect(one.getByRole("button", { name: CLEAR })).not.toHaveAttribute("aria-disabled", "true");
    const two = await rowOf(2);
    expect(two.getByRole("button", { name: TP })).toHaveAttribute("aria-pressed", "false");
    expect(two.getByRole("button", { name: FP })).toHaveAttribute("aria-pressed", "false");
    // an alert with no label has nothing to take off
    expect(two.getByRole("button", { name: CLEAR })).toHaveAttribute("aria-disabled", "true");
  });

  // Fix round 1, M1: the code says what the comment of LabAlertRow says.
  it("makes the button of the label the alert already has, and only it, aria-disabled; it is not dimmed", async () => {
    backend();
    renderPage();
    const one = await rowOf(1);
    expect(one.getByRole("button", { name: TP })).toHaveAttribute("aria-disabled", "true");
    expect(one.getByRole("button", { name: FP })).toHaveAttribute("aria-disabled", "false");
    expect(one.getByRole("button", { name: CLEAR })).toHaveAttribute("aria-disabled", "false");
    // the pressed label is the one that stands out, not the one that fades
    expect(one.getByRole("button", { name: TP }).className).not.toMatch(/\bopacity-50\b/);
    const two = await rowOf(2);
    for (const name of [TP, FP]) {
      expect(two.getByRole("button", { name })).toHaveAttribute("aria-disabled", "false");
    }
  });

  it("moves the aria-disabled with the label: after a TP, TP is the one that does nothing", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    const two = await rowOf(2);
    await user.click(two.getByRole("button", { name: TP }));
    await counter("Đã gán 2/3");
    await waitFor(() =>
      expect(two.getByRole("button", { name: TP })).toHaveAttribute("aria-disabled", "true"),
    );
    expect(two.getByRole("button", { name: FP })).toHaveAttribute("aria-disabled", "false");
    expect(two.getByRole("button", { name: CLEAR })).toHaveAttribute("aria-disabled", "false");
  });

  // Fix round 1, M4: the details of a row hold no heading (an h3 under the h1 skipped a level).
  it("leaves no heading in a row, details open or not: the page has an h1 and no h2 to put one under", async () => {
    backend({ alerts: [alert(1), alert(2, { raw_log_truncated_for_display: true })] });
    const user = userEvent.setup();
    const { container } = renderPage();
    const one = await rowOf(1);
    await user.click(one.getByText("Chi tiết"));
    await one.findByText("raw log of alert 1");
    expect(within(await list()).queryAllByRole("heading")).toEqual([]);
    expect(container.querySelectorAll("h2, h3, h4")).toHaveLength(0);
    // "raw_log" still names what the box is
    expect(one.getByText("raw_log")).toBeInTheDocument();
  });

  it("has no axe violation with the details of a row open, heading order included", async () => {
    backend();
    const user = userEvent.setup();
    const { container } = renderPage();
    const one = await rowOf(1);
    await user.click(one.getByText("Chi tiết"));
    await one.findByText("raw log of alert 1");
    const result = await axe.run(container, {
      rules: { "color-contrast": { enabled: false } },
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "best-practice"] },
    });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });

  it("says there is no alert, and offers no more to load, for a run with none", async () => {
    backend({ alerts: [] });
    renderPage();
    expect(
      await screen.findByText("Chưa có alert nào nhận vào trong khung giờ này."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Tải thêm" })).not.toBeInTheDocument();
    expect(await counter("Đã gán 0/0")).toBeInTheDocument();
  });

  it("has no axe violation, with alerts on screen and with a refusal on a row", async () => {
    backend({ put: () => refuse(409, { reason: "not_a_queue_head" }) });
    const user = userEvent.setup();
    const { container } = renderPage();
    const row = await rowOf(2);
    await user.click(row.getByRole("button", { name: TP }));
    await row.findByRole("alert");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

// ====================================================================================================================
// labelling
// ====================================================================================================================

describe("labelling an alert", () => {
  it("PUTs the label on a click of TP, shows it on the row, and moves the counter by one", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await counter("Đã gán 1/3");
    const row = await rowOf(2);
    await user.click(row.getByRole("button", { name: TP }));
    expect(await counter("Đã gán 2/3")).toBeInTheDocument();
    expect(state(row)).toHaveTextContent("TP");
    expect(row.getByRole("button", { name: TP })).toHaveAttribute("aria-pressed", "true");
    expect(row.getByRole("button", { name: CLEAR })).not.toHaveAttribute("aria-disabled", "true");
    expect(b.writes()).toEqual([
      expect.objectContaining({
        method: "PUT",
        path: "/api/admin/lab/labels/1766000000.2",
        body: { label: "true_positive" },
      }),
    ]);
    expect(b.writes()[0]?.contentType).toMatch(/^application\/json/);
  });

  it("PUTs false_positive on a click of FP", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    const row = await rowOf(3);
    await user.click(row.getByRole("button", { name: FP }));
    await counter("Đã gán 2/3");
    expect(state(row)).toHaveTextContent("FP");
    expect(b.writes()[0]).toMatchObject({
      path: "/api/admin/lab/labels/1766000000.3",
      body: { label: "false_positive" },
    });
  });

  it("does not read the alerts again: a label updates the counter in place, without reloading the page", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await counter("Đã gán 1/3");
    await user.click((await rowOf(2)).getByRole("button", { name: TP }));
    await counter("Đã gán 2/3");
    await user.click((await rowOf(3)).getByRole("button", { name: FP }));
    await counter("Đã gán 3/3");
    expect(b.gets()).toHaveLength(1);
    // and no skeleton or waiting line came back over the list
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("keeps the counter when a label is changed to the other one, and changes the row", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await counter("Đã gán 1/3");
    const row = await rowOf(1);
    await user.click(row.getByRole("button", { name: FP }));
    await waitFor(() => expect(state(row)).toHaveTextContent("FP"));
    expect(screen.getByText("Đã gán 1/3")).toBeInTheDocument();
    expect(b.writes()[0]).toMatchObject({ method: "PUT", body: { label: "false_positive" } });
  });

  it("clears the label on `Bỏ nhãn`: a DELETE with the JSON content type, the counter one less, the row `chưa gán`", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await counter("Đã gán 1/3");
    const row = await rowOf(1);
    await user.click(row.getByRole("button", { name: CLEAR }));
    expect(await counter("Đã gán 0/3")).toBeInTheDocument();
    expect(state(row)).toHaveTextContent("chưa gán");
    expect(row.getByRole("button", { name: CLEAR })).toHaveAttribute("aria-disabled", "true");
    expect(row.getByRole("button", { name: TP })).toHaveAttribute("aria-pressed", "false");
    expect(b.writes()).toEqual([
      expect.objectContaining({
        method: "DELETE",
        path: "/api/admin/lab/labels/1766000000.1",
        contentType: "application/json",
      }),
    ]);
    expect(b.gets()).toHaveLength(1);
  });

  it("sends nothing for a click on the label an alert already has, or on `Bỏ nhãn` of an alert with none", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await counter("Đã gán 1/3");
    await user.click((await rowOf(1)).getByRole("button", { name: TP }));
    await user.click((await rowOf(2)).getByRole("button", { name: CLEAR }));
    expect(b.writes()).toEqual([]);
    expect(screen.getByText("Đã gán 1/3")).toBeInTheDocument();
  });

  it("keeps the focus on the button that was pressed", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    const row = await rowOf(2);
    const button = row.getByRole("button", { name: TP });
    await user.click(button);
    await counter("Đã gán 2/3");
    expect(button).toHaveFocus();
    const clear = row.getByRole("button", { name: CLEAR });
    await user.click(clear);
    await counter("Đã gán 1/3");
    expect(clear).toHaveFocus();
  });

  it("sends one write when a button is pressed twice, or two buttons of a row at once, and leaves another row free", async () => {
    const b = backend({
      put: () => undefined,
    });
    server.use(
      http.put("/api/admin/lab/labels/:alertId", async ({ request, params }) => {
        const body = (await request.json()) as { label: LabLabel };
        b.calls.push({
          method: "PUT",
          path: `/api/admin/lab/labels/${String(params.alertId)}`,
          search: "",
          body,
          contentType: null,
        });
        await delay(60);
        return HttpResponse.json({ alert_id: params.alertId, run_id: RUN_ID, label: body.label });
      }),
    );
    renderPage();
    await counter("Đã gán 1/3");
    const two = await rowOf(2);
    const three = await rowOf(3);
    const tp = two.getByRole("button", { name: TP });
    fireEvent.click(tp);
    fireEvent.click(tp);
    fireEvent.click(two.getByRole("button", { name: FP }));
    fireEvent.click(three.getByRole("button", { name: FP }));
    await counter("Đã gán 3/3");
    expect(b.writes().map((w) => [w.path, (w.body as { label: string }).label])).toEqual([
      ["/api/admin/lab/labels/1766000000.2", "true_positive"],
      ["/api/admin/lab/labels/1766000000.3", "false_positive"],
    ]);
  });

  it("marks the row busy while its write is out", async () => {
    backend();
    server.use(
      http.put("/api/admin/lab/labels/:alertId", async ({ params }) => {
        await delay(80);
        return HttpResponse.json({
          alert_id: params.alertId,
          run_id: RUN_ID,
          label: "true_positive",
        });
      }),
    );
    const user = userEvent.setup();
    renderPage();
    const li = await screen.findByRole("listitem", { name: "Alert 1766000000.2" });
    await user.click(within(li).getByRole("button", { name: TP }));
    await waitFor(() => expect(li).toHaveAttribute("aria-busy", "true"));
    await waitFor(() => expect(li).not.toHaveAttribute("aria-busy"));
  });

  // Fix round 1, M2: a click the latch drops is seen not to have been taken.
  it("dims the three buttons of a row and makes them aria-disabled while its write is out, and a click on one sends nothing", async () => {
    const b = backend();
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    server.use(
      http.put("/api/admin/lab/labels/:alertId", async ({ request, params }) => {
        const { label } = (await request.json()) as { label: LabLabel };
        b.calls.push({
          method: "PUT",
          path: `/api/admin/lab/labels/${String(params.alertId)}`,
          search: "",
          body: { label },
          contentType: null,
        });
        await held;
        return HttpResponse.json({ alert_id: params.alertId, run_id: RUN_ID, label });
      }),
    );
    const user = userEvent.setup();
    renderPage();
    await counter("Đã gán 1/3");
    const two = await rowOf(2);
    // before: nothing is dimmed but the `Bỏ nhãn` of an alert with no label
    for (const name of [TP, FP]) {
      expect(two.getByRole("button", { name }).className).not.toMatch(/\bopacity-50\b/);
    }
    await user.click(two.getByRole("button", { name: TP }));
    await waitFor(() =>
      expect(two.getByRole("button", { name: FP })).toHaveAttribute("aria-disabled", "true"),
    );
    for (const name of [TP, FP, CLEAR]) {
      const button = two.getByRole("button", { name });
      expect(button, name).toHaveAttribute("aria-disabled", "true");
      expect(button.className, name).toMatch(/\bopacity-50\b/);
    }
    // the click that is dropped sends nothing
    await user.click(two.getByRole("button", { name: FP }));
    await user.click(two.getByRole("button", { name: CLEAR }));
    expect(b.writes()).toHaveLength(1);
    // another row is not held by this one's write
    expect((await rowOf(3)).getByRole("button", { name: TP }).className).not.toMatch(
      /\bopacity-50\b/,
    );

    release();
    await counter("Đã gán 2/3");
    // after: TP is what the row holds (aria-disabled, but standing out), FP and `Bỏ nhãn` are free and bright again
    await waitFor(() =>
      expect(two.getByRole("button", { name: FP })).toHaveAttribute("aria-disabled", "false"),
    );
    expect(two.getByRole("button", { name: CLEAR })).toHaveAttribute("aria-disabled", "false");
    expect(two.getByRole("button", { name: TP })).toHaveAttribute("aria-disabled", "true");
    for (const name of [TP, FP, CLEAR]) {
      expect(two.getByRole("button", { name }).className, name).not.toMatch(/\bopacity-50\b/);
    }
    expect(b.writes()).toHaveLength(1);
  });

  it("lets the FP that was dropped be pressed again once the TP has landed", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await counter("Đã gán 1/3");
    const two = await rowOf(2);
    fireEvent.click(two.getByRole("button", { name: TP }));
    fireEvent.click(two.getByRole("button", { name: FP }));
    await counter("Đã gán 2/3");
    await waitFor(() =>
      expect(two.getByRole("button", { name: FP })).toHaveAttribute("aria-disabled", "false"),
    );
    await user.click(two.getByRole("button", { name: FP }));
    await waitFor(() => expect(state(two)).toHaveTextContent("FP"));
    expect(b.writes().map((w) => (w.body as { label: string }).label)).toEqual([
      "true_positive",
      "false_positive",
    ]);
  });

  describe("when the server refuses", () => {
    const REFUSALS: [string, () => Response, string][] = [
      [
        "409 not_a_queue_head",
        () => refuse(409, { reason: "not_a_queue_head" }),
        "Alert này là bản sao của một alert khác nên không gán nhãn được. Gán nhãn cho alert gốc.",
      ],
      [
        "409 outside_every_run",
        () => refuse(409, { reason: "outside_every_run" }),
        "Alert này nằm ngoài mọi lần chạy nên không gán nhãn được.",
      ],
      [
        "404 not_found",
        () => refuse(404, { reason: "not_found" }),
        "Không tìm thấy alert này nữa.",
      ],
      [
        "a 422 on the label",
        () => refuse(422, { field: "label", reason: "invalid" }),
        "Nhãn không hợp lệ",
      ],
      ["a 409 it does not know", () => refuse(409, { reason: "something_new" }), "Có lỗi xảy ra"],
      ["a 500", () => refuse(500, "boom"), "Có lỗi xảy ra"],
      ["a 403", () => refuse(403, "forbidden"), "Có lỗi xảy ra"],
      ["a network failure", () => HttpResponse.error(), "Có lỗi xảy ra"],
    ];

    it.each(REFUSALS)(
      "%s says its words on the row, and changes neither the row nor the counter",
      async (_name, reply, text) => {
        backend({ put: () => reply() });
        const user = userEvent.setup();
        const { container } = renderPage();
        await counter("Đã gán 1/3");
        const row = await rowOf(2);
        await user.click(row.getByRole("button", { name: FP }));
        expect(await row.findByRole("alert")).toHaveTextContent(text);
        expect(state(row)).toHaveTextContent("chưa gán");
        expect(screen.getByText("Đã gán 1/3")).toBeInTheDocument();
        // no other row says anything, and no code is on the page
        expect(screen.getAllByRole("alert")).toHaveLength(1);
        expect(container).not.toHaveTextContent(
          /not_a_queue_head|outside_every_run|not_found|something_new|boom|forbidden/,
        );
      },
    );

    it("says the same for a DELETE that is refused", async () => {
      backend({ del: () => refuse(404, { reason: "not_found" }) });
      const user = userEvent.setup();
      renderPage();
      const row = await rowOf(1);
      await user.click(row.getByRole("button", { name: CLEAR }));
      expect(await row.findByRole("alert")).toHaveTextContent("Không tìm thấy alert này nữa.");
      expect(screen.getByText("Đã gán 1/3")).toBeInTheDocument();
    });

    it("drops the message when the admin tries again and it works", async () => {
      let first = true;
      backend({
        put: () => {
          if (first) {
            first = false;
            return refuse(409, { reason: "outside_every_run" });
          }
          return undefined;
        },
      });
      const user = userEvent.setup();
      renderPage();
      const row = await rowOf(2);
      await user.click(row.getByRole("button", { name: TP }));
      await row.findByRole("alert");
      await user.click(row.getByRole("button", { name: TP }));
      await counter("Đã gán 2/3");
      expect(row.queryByRole("alert")).not.toBeInTheDocument();
    });
  });
});

// ====================================================================================================================
// the pages of alerts
// ====================================================================================================================

describe("more alerts", () => {
  it("offers `Tải thêm` while the server has a next page, and loads it after the last alert seen, below the first", async () => {
    const b = backend({ alerts: FIVE(), pageSize: 2 });
    const user = userEvent.setup();
    renderPage();
    await rowOf(2);
    expect(within(await list()).getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByText("Đang hiện 2 alert")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Tải thêm" }));
    await screen.findByRole("listitem", { name: "Alert 1766000000.4" });
    expect(
      within(await list())
        .getAllByRole("listitem")
        .map((li) => li.getAttribute("aria-label")),
    ).toEqual([
      "Alert 1766000000.1",
      "Alert 1766000000.2",
      "Alert 1766000000.3",
      "Alert 1766000000.4",
    ]);
    expect(b.gets().map((g) => g.search)).toEqual(["", "?after=1766000000.2"]);
    // the third page is the last one (a page that is not full)
    await user.click(screen.getByRole("button", { name: "Tải thêm" }));
    await screen.findByRole("listitem", { name: "Alert 1766000000.5" });
    expect(b.gets().map((g) => g.search)).toEqual([
      "",
      "?after=1766000000.2",
      "?after=1766000000.4",
    ]);
    expect(screen.queryByRole("button", { name: "Tải thêm" })).not.toBeInTheDocument();
    expect(screen.getByText("Đang hiện 5 alert")).toBeInTheDocument();
  });

  it("stops offering it when the page that came was the last", async () => {
    backend({ alerts: THREE(), pageSize: 2 });
    const user = userEvent.setup();
    renderPage();
    await rowOf(2);
    await user.click(screen.getByRole("button", { name: "Tải thêm" }));
    await screen.findByRole("listitem", { name: "Alert 1766000000.3" });
    expect(screen.queryByRole("button", { name: "Tải thêm" })).not.toBeInTheDocument();
  });

  it("does not offer it when the first page was the only one", async () => {
    backend({ alerts: THREE() });
    renderPage();
    await rowOf(3);
    expect(screen.queryByRole("button", { name: "Tải thêm" })).not.toBeInTheDocument();
  });

  it("labels an alert of a later page, and the counter, which belongs to the run, moves", async () => {
    const b = backend({ alerts: FIVE(), pageSize: 2 });
    const user = userEvent.setup();
    renderPage();
    await counter("Đã gán 2/5");
    await user.click(await screen.findByRole("button", { name: "Tải thêm" }));
    const four = await rowOf(4);
    await user.click(four.getByRole("button", { name: TP }));
    expect(await counter("Đã gán 3/5")).toBeInTheDocument();
    expect(state(four)).toHaveTextContent("TP");
    expect(b.gets()).toHaveLength(2);
  });

  it("sends one request for two presses of `Tải thêm`", async () => {
    const b = backend({ alerts: FIVE(), pageSize: 2 });
    renderPage();
    const button = await screen.findByRole("button", { name: "Tải thêm" });
    fireEvent.click(button);
    fireEvent.click(button);
    await screen.findByRole("listitem", { name: "Alert 1766000000.3" });
    expect(b.gets()).toHaveLength(2);
  });

  it("says the next page could not be loaded, keeps the rows, and loads it on the next press", async () => {
    let fail = true;
    const alerts = FIVE();
    backend({
      alerts,
      pageSize: 2,
      list: (after) => {
        if (after === null) {
          return HttpResponse.json({
            run: runOf(alerts),
            alerts: alerts.slice(0, 2),
            next_after: alerts[1]?.alert_id ?? null,
          });
        }
        if (fail) return refuse(500, "boom");
        return HttpResponse.json({
          run: runOf(alerts),
          alerts: alerts.slice(2, 4),
          next_after: alerts[3]?.alert_id ?? null,
        });
      },
    });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Tải thêm" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Không tải thêm được. Thử lại.");
    expect(within(await list()).getAllByRole("listitem")).toHaveLength(2);
    fail = false;
    await user.click(screen.getByRole("button", { name: "Tải thêm" }));
    await screen.findByRole("listitem", { name: "Alert 1766000000.4" });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

// ====================================================================================================================
// a run that cannot be shown
// ====================================================================================================================

describe("a page error", () => {
  it.each([
    ["404 not_found", () => refuse(404, { reason: "not_found" })],
    [
      "a 422, an id that is no uuid",
      () => refuse(422, [{ type: "uuid_parsing", loc: ["path"], msg: "x" }]),
    ],
  ])("says the run is not there, with the way back and no retry, for %s", async (_name, reply) => {
    backend({ list: () => reply() });
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 1, name: "Không tìm thấy lần chạy này" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Về danh sách lần chạy" })).toHaveAttribute(
      "href",
      "/admin/lab",
    );
    expect(screen.queryByRole("button", { name: "Thử lại" })).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says the page could not load, with a retry that reads again, on a 500", async () => {
    let fail = true;
    const b = backend({
      list: () =>
        fail
          ? refuse(500, "boom")
          : HttpResponse.json({ run: runOf(THREE()), alerts: THREE(), next_after: null }),
    });
    const user = userEvent.setup();
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(
      within(alert).getByRole("heading", { name: "Không tải được trang" }),
    ).toBeInTheDocument();
    fail = false;
    await user.click(within(alert).getByRole("button", { name: "Thử lại" }));
    await list();
    expect(b.gets()).toHaveLength(2);
  });

  it("says the role is gone, with no retry, on a 403", async () => {
    backend({ list: () => refuse(403, "forbidden") });
    renderPage();
    expect(
      await screen.findByRole("heading", { name: S.admin.reason.forbidden }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Thử lại" })).not.toBeInTheDocument();
  });

  it("shows a waiting line while the first page comes", async () => {
    server.use(
      http.get("/api/admin/lab/runs/:runId/alerts", async () => {
        await delay("infinite");
        return HttpResponse.json({});
      }),
    );
    const { container } = renderPage();
    expect(await screen.findByRole("status")).toHaveTextContent("Đang tải…");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

// ====================================================================================================================
// BLIND
// ====================================================================================================================

describe("the page is blind: nothing of ① or ②", () => {
  it("shows no key the server must never send, as text or in any attribute, though a leaking server sends them", async () => {
    backend({ alerts: THREE(), leak: true });
    const user = userEvent.setup();
    const { container } = renderPage();
    const one = await rowOf(1);
    await user.click(one.getByText("Chi tiết"));
    await one.findByText("raw log of alert 1");
    await user.click((await rowOf(2)).getByRole("button", { name: TP }));
    await counter("Đã gán 2/3");
    const html = container.innerHTML;
    expect(html).not.toContain(MARK);
    for (const key of Object.keys(LEAK)) expect(html, key).not.toContain(key);
    expect(document.body.textContent).not.toContain(MARK);
  });

  it("calls no route but the three lab routes: no tier1, no tier2, no knowledge", async () => {
    const b = backend({ alerts: FIVE(), pageSize: 3 });
    const user = userEvent.setup();
    renderPage();
    await user.click((await rowOf(2)).getByRole("button", { name: TP }));
    await counter("Đã gán 3/5");
    await user.click(await screen.findByRole("button", { name: "Tải thêm" }));
    await rowOf(5);
    await user.click((await rowOf(1)).getByRole("button", { name: CLEAR }));
    await counter("Đã gán 2/5");
    expect(b.calls.map((c) => c.method)).toEqual(["GET", "PUT", "GET", "DELETE"]);
    for (const call of b.calls) {
      expect(call.path, `${call.method} ${call.path}`).toMatch(
        /^\/api\/admin\/lab\/(runs|labels)\//,
      );
    }
  });

  it("links to no alert page, case page or the queue: nothing that would show what was decided", async () => {
    backend({ alerts: FIVE(), pageSize: 3 });
    const { container } = renderPage();
    await rowOf(2);
    const hrefs = [...container.querySelectorAll("[href]")].map((el) => el.getAttribute("href"));
    expect(hrefs).toEqual(["/admin/lab"]);
  });

  it("names no model, suggestion, AI, risk or verdict anywhere on the page, in any state", async () => {
    const FORBIDDEN =
      /\bAI\b|\bLLM\b|①|②|\bRAG\b|model|mô hình|gợi ý|đề xuất|kết luận|suggest|verifier|proposer|risk|điểm rủi ro|độ tin cậy|confidence|\d\s*%|%/i;
    backend({ alerts: FIVE(), pageSize: 3, leak: true });
    const user = userEvent.setup();
    const { container } = renderPage();
    await rowOf(2);
    expect(container.textContent).not.toMatch(FORBIDDEN);
    await user.click(await screen.findByRole("button", { name: "Tải thêm" }));
    await rowOf(5);
    await user.click((await rowOf(2)).getByRole("button", { name: FP }));
    await counter("Đã gán 3/5");
    expect(container.textContent).not.toMatch(FORBIDDEN);
    expect(container.innerHTML).not.toMatch(/\bAI kết luận\b/);
  });

  it("has no word of ① or ② in the strings of the lab pages", () => {
    const FORBIDDEN =
      /\bAI\b|\bLLM\b|①|②|\bRAG\b|model|mô hình|gợi ý|đề xuất|kết luận|suggest|verifier|proposer|risk/i;
    const texts: string[] = [];
    const collect = (value: unknown): void => {
      if (typeof value === "string") texts.push(value);
      else if (typeof value === "function") texts.push(String(value));
      else if (typeof value === "object" && value !== null) Object.values(value).forEach(collect);
    };
    collect(S.admin.lab);
    expect(texts.length).toBeGreaterThan(40);
    expect(texts.filter((text) => FORBIDDEN.test(text))).toEqual([]);
  });

  describe("the source of the page", () => {
    const SRC = join("src", "features", "admin");
    const FILES = ["LabRunPage.tsx", "LabAlertRow.tsx"];
    const read = (name: string) => readFileSync(join(SRC, name), "utf8");

    /** Where the source of the lab pages could let a key through, or reach for ① or ②: what the page must not do. */
    function violations(text: string, name: string, importsOnly = false): string[] {
      const file = ts.createSourceFile(name, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
      const found: string[] = [];
      const visit = (node: ts.Node): void => {
        if (!importsOnly && (ts.isJsxSpreadAttribute(node) || ts.isSpreadAssignment(node))) {
          found.push("a spread of an object");
        }
        if (
          !importsOnly &&
          ts.isObjectBindingPattern(node) &&
          node.elements.some((e) => e.dotDotDotToken)
        ) {
          found.push("an object rest");
        }
        if (ts.isCallExpression(node)) {
          const callee = node.expression.getText(file);
          if (
            !importsOnly &&
            /^(Object\.(entries|values|keys|assign|fromEntries|getOwnPropertyNames)|Reflect\.ownKeys|JSON\.stringify|structuredClone)$/.test(
              callee,
            )
          ) {
            found.push(callee);
          }
          if (node.expression.kind === ts.SyntaxKind.ImportKeyword) found.push("a dynamic import");
        }
        if (!importsOnly && ts.isForInStatement(node)) found.push("a for…in loop");
        if (
          !importsOnly &&
          ts.isJsxAttribute(node) &&
          node.name.getText(file) === "dangerouslySetInnerHTML"
        ) {
          found.push("dangerouslySetInnerHTML");
        }
        if (
          (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
          node.moduleSpecifier !== undefined &&
          ts.isStringLiteral(node.moduleSpecifier)
        ) {
          const from = node.moduleSpecifier.text;
          if (/tier1|tier2|[Kk]nowledge|\/api\/(?!admin$|types$)/.test(from))
            found.push(`the module ${from}`);
        }
        ts.forEachChild(node, visit);
      };
      visit(file);
      return found;
    }

    function importedFromAdminApi(text: string): string[] {
      const file = ts.createSourceFile(
        "scratch.tsx",
        text,
        ts.ScriptTarget.Latest,
        true,
        ts.ScriptKind.TSX,
      );
      const names: string[] = [];
      for (const statement of file.statements) {
        if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier))
          continue;
        if (!/\/api\/admin$/.test(statement.moduleSpecifier.text)) continue;
        const bindings = statement.importClause?.namedBindings;
        if (bindings !== undefined && ts.isNamedImports(bindings)) {
          for (const element of bindings.elements) names.push(element.name.text);
        }
      }
      return names;
    }

    it.each(FILES)(
      "%s dumps no object, spreads none, and reaches for no tier1, tier2 or knowledge module",
      (name) => {
        expect(violations(read(name), name)).toEqual([]);
      },
    );

    it("the files exist and are the ones that render an alert (a guard over no files would pass for nothing)", () => {
      for (const name of FILES) expect(read(name).length).toBeGreaterThan(500);
      expect(read("LabAlertRow.tsx")).toContain("alert.description");
    });

    it("calls the three lab routes of api/admin.ts and no other function of it", () => {
      const imported = FILES.flatMap((name) => importedFromAdminApi(read(name)))
        .filter((name) => /^[a-z]/.test(name))
        .sort();
      expect([...new Set(imported)]).toEqual(
        ["deleteLabLabel", "getLabRunAlerts", "labErrorOf", "putLabLabel"].sort(),
      );
      // labModel.ts and the page's own helpers take part too: they import nothing of tier1 or tier2
      // (labModel.ts spreads the data it copies, so only its imports are held to the rule)
      expect(violations(read("labModel.ts"), "labModel.ts", true)).toEqual([]);
    });

    // The checker is itself checked, on scratch copies in strings: the real source has none, the copy has one.
    describe("the checker", () => {
      const real = read("LabAlertRow.tsx");

      it("finds nothing in the real source it is given the scratch copies of", () => {
        expect(violations(real, "LabAlertRow.tsx")).toEqual([]);
      });

      it.each([
        ["JSON.stringify of the alert", "void JSON.stringify(alert);"],
        ["Object.entries of the alert", "void Object.entries(alert);"],
        ["Object.values of the alert", "void Object.values(alert);"],
        ["a spread of the alert", "void { ...alert };"],
        ["a spread of the alert in JSX", "void (<div {...alert} />);"],
        [
          "an object rest of the alert",
          "const { rule_id, ...others } = alert; void [rule_id, others];",
        ],
        ["a for…in loop", "for (const key in alert) { void key; }"],
        [
          "dangerouslySetInnerHTML",
          "void (<div dangerouslySetInnerHTML={{ __html: alert.raw_log }} />);",
        ],
        ["an import of a tier1 module", 'import { x } from "../tier1/AlertPage"; void x;'],
        ["an import of the tier1 API", 'import { x } from "../../api/tier1"; void x;'],
        ["an import of a knowledge module", 'import { x } from "./KnowledgePage"; void x;'],
        ["a dynamic import", 'void import("../tier2/CasePage");'],
      ])("finds %s", (_what, code) => {
        expect(violations(`${real}\n${code}\n`, "scratch.tsx").length).toBeGreaterThan(0);
      });
    });
  });
});
