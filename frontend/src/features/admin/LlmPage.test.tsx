// src/features/admin/LlmPage.test.tsx — `/admin/llm` (spec §4.3, P11-T13): the usage of the model against the
// month's cap, the table by pipeline and role, the ② quota of the last 24 hours, the last 20 calls, and the
// form of the three limits with its confirmation. MSW answers the two routes; nothing is mocked above `fetch`.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import type { LimitsOut, LlmUsage, PipelineRoleRow, RecentRun } from "../../api/admin";
import { S } from "../../strings";
import { adminKeys } from "./adminKeys";
import { LlmPage } from "./LlmPage";

const USAGE_URL = "/api/admin/llm/usage";
const LIMITS_URL = "/api/admin/llm/limits";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const L = S.admin.llmPage;

// --- the data -----------------------------------------------------------------------------------------------

const ENV = { source: "env", updated_at: null, updated_by_name: null, clamped: false } as const;
/** 12/10/2026 14:05:00 in the console's +07. */
const SAVED_AT = "2026-10-12T07:05:00+00:00";

function limits(over: Partial<LimitsOut> = {}): LimitsOut {
  return {
    cap_usd: 30,
    quota_per_24h: 30,
    timeout_s: 120,
    sources: {
      LLM_MONTHLY_USD_CAP: ENV,
      ANALYZE_QUOTA_PER_USER_DAY: ENV,
      LLM_TIMEOUT_S: ENV,
    },
    bounds: {
      cap_usd: { min: 1, max: 1000 },
      quota_per_24h: { min: 1, max: 200 },
      timeout_s: { min: 10, max: 120 },
    },
    ...over,
  };
}

const pipelineRows = (): PipelineRoleRow[] => [
  {
    pipeline: "triage",
    role: "proposer",
    calls: 855,
    with_result: 733,
    stopped: { schema: 122 },
    input_tokens: 1_890_000,
    output_tokens: 330_000,
    latency_p50_ms: 2400,
    latency_p95_ms: 9800,
    cost_usd: 0.33,
  },
  {
    pipeline: "triage",
    role: "verifier",
    calls: 733,
    with_result: 733,
    stopped: {},
    input_tokens: 500_000,
    output_tokens: 80_000,
    latency_p50_ms: 1100,
    latency_p95_ms: 3600,
    cost_usd: 0.18,
  },
  {
    pipeline: "investigate",
    role: "investigator",
    calls: 1,
    with_result: 1,
    stopped: {},
    input_tokens: 47_000,
    output_tokens: 1000,
    latency_p50_ms: 12500,
    latency_p95_ms: 12500,
    cost_usd: 0.0024,
  },
];

const ALERT_ID = "1759012345.1662100";
const CASE_ID = "0b30b853-1c2d-4e5f-8a9b-000000000001";

const recentRows = (): RecentRun[] => [
  {
    run_id: "r1",
    created_at: "2026-09-30T02:31:00+00:00",
    pipeline: "triage",
    role: "proposer",
    subject_type: "alert",
    subject_id: ALERT_ID,
    input_tokens: 2214,
    output_tokens: 190,
    latency_ms: 2300,
    outcome: "escalate",
    cost_usd: 0.0004,
  },
  {
    run_id: "r2",
    created_at: "2026-09-30T02:31:00+00:00",
    pipeline: "triage",
    role: "verifier",
    subject_type: "alert",
    subject_id: ALERT_ID,
    input_tokens: 1380,
    output_tokens: 60,
    latency_ms: 1000,
    outcome: "escalate",
    cost_usd: 0.0002,
  },
  {
    run_id: "r3",
    created_at: "2026-09-30T02:05:00+00:00",
    pipeline: "triage",
    role: "proposer",
    subject_type: "alert",
    subject_id: "1759012399.1661877",
    input_tokens: 2190,
    output_tokens: 0,
    latency_ms: 9700,
    outcome: "stopped:schema",
    cost_usd: 0.0004,
  },
  {
    run_id: "r4",
    created_at: "2026-09-30T01:19:00+00:00",
    pipeline: "investigate",
    role: "investigator",
    subject_type: "case",
    subject_id: CASE_ID,
    input_tokens: 49_701,
    output_tokens: 800,
    latency_ms: 12_500,
    outcome: "false_positive",
    cost_usd: 0.0024,
  },
  {
    run_id: "r5",
    created_at: "2026-09-30T01:05:00+00:00",
    pipeline: "triage",
    role: "proposer",
    subject_type: "alert",
    subject_id: "1759012400.1661650",
    input_tokens: 2205,
    output_tokens: 150,
    latency_ms: 2600,
    outcome: "needs_review",
    cost_usd: 0.0004,
  },
];

type Month = LlmUsage["month"];
const month = (over: Partial<Month> = {}): Month => ({
  spent_usd: 0.51,
  cap_usd: 30,
  pct: 1.7,
  projected_usd: 0.74,
  ...over,
});

function usage(over: Partial<LlmUsage> = {}): LlmUsage {
  return {
    range: "month",
    month: month(),
    by_pipeline_role: pipelineRows(),
    quota: {
      limit: 30,
      window: "24h",
      users: [
        { username: "minh.t2", display_name: "Minh Tier2", used: 4, remaining: 26 },
        { username: "hoa.admin", display_name: null, used: 1, remaining: 29 },
      ],
    },
    recent: recentRows(),
    limits: limits(),
    limits_error: null,
    tool_calls: 0,
    ...over,
  };
}

/** What the page shows when the stored limits cannot be read: the rest is still served. */
const failClosed = (over: Partial<LlmUsage> = {}) =>
  usage({
    month: month({ spent_usd: 5.2, cap_usd: null, pct: null, projected_usd: 7 }),
    quota: {
      limit: null,
      window: "24h",
      users: [{ username: "minh.t2", display_name: null, used: 4, remaining: null }],
    },
    limits: null,
    limits_error: "limits_unavailable",
    ...over,
  });

// --- the server -----------------------------------------------------------------------------------------------

type Answer = LlmUsage | (() => Response | Promise<Response>);

/** Serves `answers` one per GET (the last one for every GET after), and records the `range` each GET carried. */
function serveUsage(...answers: Answer[]) {
  const ranges: string[] = [];
  server.use(
    http.get(USAGE_URL, ({ request }) => {
      ranges.push(new URL(request.url).searchParams.get("range") ?? "");
      const answer = answers[Math.min(ranges.length - 1, answers.length - 1)];
      if (answer === undefined) throw new Error("serveUsage needs an answer");
      return typeof answer === "function" ? answer() : HttpResponse.json(answer);
    }),
  );
  return ranges;
}

/** Answers every PUT with `answer(body, n)`, and records each body as the server read it. */
function servePut(answer: (body: unknown, n: number) => Response | Promise<Response>) {
  const bodies: unknown[] = [];
  server.use(
    http.put(LIMITS_URL, async ({ request }) => {
      const body: unknown = await request.json();
      bodies.push(body);
      return answer(body, bodies.length);
    }),
  );
  return bodies;
}

const saved = (over: Partial<LimitsOut> = {}) => HttpResponse.json({ limits: limits(over) });
const refuse = (status: number, detail: unknown) => HttpResponse.json({ detail }, { status });

/** A promise held shut until `release()`, to look at the page while a request is out. */
function gate() {
  let release: () => void = () => {};
  const opened = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { opened, release: () => release() };
}

function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function renderPage(client = newClient()) {
  const view = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/admin/llm"]}>
        <main>
          <LlmPage />
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { client, ...view };
}

// --- finding things -----------------------------------------------------------------------------------

const region = (name: string) => screen.findByRole("region", { name });
const costTile = () => region(L.cost.title);
const limitsPanel = () => region(L.limits.title);
const byPipeline = () => region(L.byPipeline.title);
const quotaPanel = () => region(L.quota.title);
const recentPanel = () => region(L.recent.title);

const field = (name: string) => screen.getByRole("spinbutton", { name });
const capField = () => field(L.limits.field.cap_usd);
const quotaField = () => field(L.limits.field.quota_per_24h);
const timeoutField = () => field(L.limits.field.timeout_s);
const saveButton = () => screen.getByRole("button", { name: L.limits.save });
const dialog = () => screen.getByRole("dialog", { name: L.confirm.title });

/** The texts of the cells of each body row of a table. */
function rowsOf(table: HTMLElement): string[][] {
  const [, ...body] = within(table).getAllByRole("row");
  return body.map((r) =>
    within(r)
      .getAllByRole("cell")
      .map((c) => c.textContent ?? ""),
  );
}

/** Types `value` into a number field, replacing what it held. */
async function setField(
  user: ReturnType<typeof userEvent.setup>,
  input: HTMLElement,
  value: string,
) {
  await user.clear(input);
  if (value !== "") await user.type(input, value);
}

/** Loads the page, edits the fields named, presses "Lưu hạn mức" and waits for the confirmation. */
async function openConfirm(edits: { cap?: string; quota?: string; timeout?: string }) {
  const user = userEvent.setup();
  const view = renderPage();
  await limitsPanel();
  if (edits.cap !== undefined) await setField(user, capField(), edits.cap);
  if (edits.quota !== undefined) await setField(user, quotaField(), edits.quota);
  if (edits.timeout !== undefined) await setField(user, timeoutField(), edits.timeout);
  await user.click(saveButton());
  return { user, ...view };
}

const confirmButton = (name: string) => within(dialog()).getByRole("button", { name });

// --- the first read ------------------------------------------------------------------------------------

describe("the first read", () => {
  it("titles the page, and reads the calendar month first", async () => {
    const ranges = serveUsage(usage());
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 1, name: S.admin.title.llm }),
    ).toBeInTheDocument();
    await costTile();
    expect(ranges).toEqual(["month"]);
    expect(screen.getByText(L.subtitle)).toBeInTheDocument();
  });

  it("asks for the page again every 60 seconds", async () => {
    serveUsage(usage());
    const { client } = renderPage();
    await costTile();
    const query = client.getQueryCache().find({ queryKey: adminKeys.llmUsage("month") });
    expect(query?.observers[0]?.options.refetchInterval).toBe(60_000);
  });
});

// --- the four tiles ---------------------------------------------------------------------------------

describe("the tiles", () => {
  it("shows the cost against the cap, with a bar, what is left and the projection", async () => {
    serveUsage(usage());
    renderPage();
    const tile = within(await costTile());
    expect(tile.getByText("$0,51")).toBeInTheDocument();
    expect(tile.getByText("/ $30")).toBeInTheDocument();
    const bar = tile.getByRole("progressbar", { name: L.cost.barLabel });
    expect(bar).toHaveAttribute("value", "0.51");
    expect(bar).toHaveAttribute("max", "30");
    expect(tile.getByText(/còn \$29,49/)).toBeInTheDocument();
    expect(tile.getByText(/dự báo tuyến tính cuối tháng \$0,74/)).toBeInTheDocument();
  });

  it("shows the projection as the server gave it, not worked out again", async () => {
    serveUsage(usage({ month: month({ spent_usd: 0.3, pct: 1, projected_usd: 9.3 }) }));
    renderPage();
    const tile = within(await costTile());
    expect(tile.getByText(/dự báo tuyến tính cuối tháng \$9,30/)).toBeInTheDocument();
  });

  it("says the month is the calendar one and starts at the database session's midnight", async () => {
    serveUsage(usage());
    renderPage();
    const tile = within(await costTile());
    expect(tile.getByText(L.cost.monthNote)).toBeInTheDocument();
    expect(L.cost.monthNote).toMatch(/0 giờ ngày 1/);
    expect(L.cost.monthNote).toMatch(/múi giờ của phiên cơ sở dữ liệu/);
  });

  it("counts the calls of both pipelines, with no chat row", async () => {
    serveUsage(usage());
    renderPage();
    await costTile();
    const tile = within(await region(L.calls.title));
    expect(tile.getByText("1.589")).toBeInTheDocument();
    expect(tile.getByText("① 1.588 · ② 1")).toBeInTheDocument();
    expect(screen.queryByText(/chat/i)).not.toBeInTheDocument();
  });

  it("sums the tokens in and out, with the average of each pipeline", async () => {
    serveUsage(usage());
    renderPage();
    await costTile();
    const tile = within(await region(S.admin.llmPage.tokens.title));
    expect(tile.getByText("2,44 tr")).toBeInTheDocument();
    expect(tile.getByText("/ 0,41 tr")).toBeInTheDocument();
    expect(tile.getByText("trung bình ① 1.505 vào · ② 47.000 vào")).toBeInTheDocument();
  });

  it("counts the runs that stopped without a result, with the reason most of them stopped on", async () => {
    serveUsage(usage());
    renderPage();
    await costTile();
    const tile = within(await region(L.stoppedTile.title));
    expect(tile.getByText("7,7%")).toBeInTheDocument();
    expect(
      tile.getByText("122 / 1.589 lượt · nhiều nhất: sai định dạng (schema)"),
    ).toBeInTheDocument();
  });

  it("says nothing stopped when nothing did", async () => {
    serveUsage(usage({ by_pipeline_role: pipelineRows().map((r) => ({ ...r, stopped: {} })) }));
    renderPage();
    await costTile();
    const tile = within(await region(L.stoppedTile.title));
    expect(tile.getByText("0%")).toBeInTheDocument();
    expect(tile.getByText(L.stoppedTile.none)).toBeInTheDocument();
  });
});

// --- the cost tile: amber from 80 %, red at the cap, and what drives each ---------------------------

describe("the cost tile states", () => {
  type Case = {
    name: string;
    month: Partial<Month>;
    state: "ok" | "warn" | "stopped";
    barValue?: string;
  };
  const cases: Case[] = [
    { name: "below 80 %", month: { spent_usd: 23.97, pct: 79.9 }, state: "ok" },
    { name: "at 80 %", month: { spent_usd: 24, pct: 80 }, state: "warn" },
    { name: "at 82 %", month: { spent_usd: 24.6, pct: 82 }, state: "warn" },
    { name: "at the cap", month: { spent_usd: 30, pct: 100 }, state: "stopped" },
    {
      name: "over the cap (it was lowered under the spend)",
      month: { spent_usd: 31.5, pct: 100 },
      state: "stopped",
      barValue: "30",
    },
    {
      name: "at the cap although pct says 99.9: the stop is spent >= cap, never pct",
      month: { spent_usd: 30, pct: 99.9 },
      state: "stopped",
    },
    {
      name: "below the cap although pct says 100: not stopped, only amber",
      month: { spent_usd: 29.99, pct: 100 },
      state: "warn",
    },
  ];

  it.each(cases)("$name is $state", async ({ month: over, state, barValue }) => {
    serveUsage(usage({ month: month(over) }));
    renderPage();
    const tile = await costTile();
    expect(tile).toHaveAttribute("data-cost", state);
    const inside = within(tile);
    expect(inside.queryByRole("alert") !== null).toBe(state === "stopped");
    expect(inside.queryByText(/sắp chạm trần/) !== null).toBe(state === "warn");
    if (barValue !== undefined) {
      expect(inside.getByRole("progressbar")).toHaveAttribute("value", barValue);
    }
  });

  it("words the amber state with the percentage and what the cap does", async () => {
    serveUsage(usage({ month: month({ spent_usd: 24.6, pct: 82 }) }));
    renderPage();
    const tile = within(await costTile());
    expect(
      tile.getByText(
        "82% · sắp chạm trần. Khi chạm trần, mọi lượt gọi model dừng cho tới khi tăng trần hoặc sang tháng mới.",
      ),
    ).toBeInTheDocument();
  });

  it("words the red notice: no ① suggestion, ② out of limit, raise the cap or wait for the month", async () => {
    serveUsage(usage({ month: month({ spent_usd: 30, pct: 100 }) }));
    renderPage();
    const alert = within(await costTile()).getByRole("alert");
    expect(alert).toHaveTextContent(
      "Model đã dừng gọi. Alert mới không có đề xuất ① (stopped_by = cap); ② báo hết hạn mức. Tăng trần ở khối Hạn mức hoặc chờ sang tháng.",
    );
  });

  it("shows no stopped notice, and no bar, without a cap to compare with", async () => {
    serveUsage(failClosed());
    renderPage();
    const tile = within(await costTile());
    expect(tile.getByText("$5,20")).toBeInTheDocument();
    expect(tile.getByText("/ —")).toBeInTheDocument();
    expect(tile.getByText(L.cost.noCap)).toBeInTheDocument();
    expect(tile.queryByRole("alert")).not.toBeInTheDocument();
    expect(tile.queryByRole("progressbar")).not.toBeInTheDocument();
  });
});

// --- by pipeline and role ------------------------------------------------------------------------------

describe("by pipeline and role", () => {
  const table = async () =>
    within(await byPipeline()).getByRole("table", { name: L.byPipeline.label });

  it("heads the table with the six columns of the canvas", async () => {
    serveUsage(usage());
    renderPage();
    await table();
    expect(
      within(await byPipeline())
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual([
      L.byPipeline.colPipeline,
      L.byPipeline.colCalls,
      L.byPipeline.colWithResult,
      L.byPipeline.colStopped,
      L.byPipeline.colLatency,
      L.byPipeline.colCost,
    ]);
  });

  it("has a row for ① proposer, ① verifier and ②, and none for chat", async () => {
    serveUsage(usage());
    renderPage();
    expect(rowsOf(await table())).toEqual([
      ["① triage · proposer", "855", "733", "sai định dạng (schema) 122", "2,4 s / 9,8 s", "$0,33"],
      ["① triage · verifier", "733", "733", "—", "1,1 s / 3,6 s", "$0,18"],
      ["② điều tra case", "1", "1", "—", "12,5 s / 12,5 s", "$0,0024"],
    ]);
  });

  it("labels the server's `other` stop bucket, ordering the reasons by count", async () => {
    serveUsage(
      usage({
        by_pipeline_role: [{ ...pipelineRows()[0]!, stopped: { cap: 1, other: 4, transient: 2 } }],
      }),
    );
    renderPage();
    const [row] = rowsOf(await table());
    expect(row?.[3]).toBe("lý do khác 4 · mô hình không phản hồi 2 · chạm trần chi phí 1");
  });

  it("shows a stop reason it has no word for as the code, as text", async () => {
    const hostile = '<img src=x onerror="alert(1)">';
    serveUsage(
      usage({
        by_pipeline_role: [{ ...pipelineRows()[0]!, stopped: { new_reason: 2, [hostile]: 1 } }],
      }),
    );
    const { container } = renderPage();
    const [row] = rowsOf(await table());
    expect(row?.[3]).toBe(`new_reason 2 · ${hostile} 1`);
    expect(container.querySelector("img")).toBeNull();
  });

  it("writes a missing latency as a dash, and a row with no role by its pipeline", async () => {
    serveUsage(
      usage({
        by_pipeline_role: [
          {
            ...pipelineRows()[0]!,
            role: null,
            latency_p50_ms: null,
            latency_p95_ms: null,
            stopped: {},
          },
        ],
      }),
    );
    renderPage();
    const [row] = rowsOf(await table());
    expect(row?.[0]).toBe("① triage");
    expect(row?.[4]).toBe("—");
  });

  it("shows a pipeline and a role it does not know as they came", async () => {
    serveUsage(
      usage({
        by_pipeline_role: [{ ...pipelineRows()[0]!, pipeline: "chat", role: "assistant" }],
      }),
    );
    renderPage();
    const [row] = rowsOf(await table());
    expect(row?.[0]).toBe("chat · assistant");
  });

  it("says the model makes no tool call, for the 0 the server always sends", async () => {
    serveUsage(usage());
    renderPage();
    await table();
    expect(
      within(await byPipeline()).getByText("Tool call: 0 — mô hình không gọi công cụ nào."),
    ).toBeInTheDocument();
  });

  it("gives only the number for a tool-call count above 0", async () => {
    serveUsage(usage({ tool_calls: 3 }));
    renderPage();
    await table();
    expect(within(await byPipeline()).getByText("Tool call: 3")).toBeInTheDocument();
  });
});

// --- the ② quota ---------------------------------------------------------------------------------------

describe("the quota of ②", () => {
  const table = async () => within(await quotaPanel()).getByRole("table", { name: L.quota.label });

  it("is the last 24 hours, said so, and never the calendar day", async () => {
    serveUsage(usage());
    renderPage();
    const panel = await quotaPanel();
    expect(within(panel).getByRole("heading", { name: /24 giờ gần nhất/ })).toBeInTheDocument();
    expect(within(panel).getByText(L.quota.note)).toBeInTheDocument();
    expect(panel.textContent).not.toMatch(/nửa đêm|0 giờ|hôm nay|reset/i);
    expect(L.quota.note).toMatch(/không theo ngày lịch/);
  });

  it("lists each user's runs and what is left, against the limit", async () => {
    serveUsage(usage());
    renderPage();
    expect(await screen.findByText("Giới hạn 30 lượt mỗi người")).toBeInTheDocument();
    const rows = rowsOf(await table());
    expect(rows).toEqual([
      ["minh.t2Minh Tier2", "4", "26"],
      ["hoa.admin", "1", "29"],
    ]);
  });

  it("shows a user who has used it all as out of runs, in an alert colour of its own", async () => {
    serveUsage(
      usage({
        quota: {
          limit: 30,
          window: "24h",
          users: [
            { username: "minh.t2", display_name: null, used: 30, remaining: 0 },
            { username: "hoa.admin", display_name: null, used: 1, remaining: 29 },
          ],
        },
      }),
    );
    renderPage();
    const rows = rowsOf(await table());
    expect(rows[0]).toEqual(["minh.t2", "30", "0 · hết lượt"]);
    expect(rows[1]).toEqual(["hoa.admin", "1", "29"]);
  });

  it("shows a user over the limit (it was lowered) as out of runs too", async () => {
    serveUsage(
      usage({
        quota: {
          limit: 10,
          window: "24h",
          users: [{ username: "minh.t2", display_name: null, used: 30, remaining: 0 }],
        },
      }),
    );
    renderPage();
    expect(rowsOf(await table())[0]).toEqual(["minh.t2", "30", "0 · hết lượt"]);
  });

  it("says nobody has run ② when no one has", async () => {
    serveUsage(usage({ quota: { limit: 30, window: "24h", users: [] } }));
    renderPage();
    expect(within(await quotaPanel()).getByText(L.quota.empty)).toBeInTheDocument();
  });

  it("writes an unreadable limit and its `remaining` as dashes", async () => {
    serveUsage(failClosed());
    renderPage();
    const panel = await quotaPanel();
    expect(within(panel).getByText(L.quota.limitUnknown)).toBeInTheDocument();
    expect(rowsOf(await table())).toEqual([["minh.t2", "4", "—"]]);
  });
});

// --- recent calls -------------------------------------------------------------------------------------

describe("recent calls", () => {
  const table = async () =>
    within(await recentPanel()).getByRole("table", { name: L.recent.label });

  it("heads the table with the seven columns of the canvas", async () => {
    serveUsage(usage());
    renderPage();
    await table();
    expect(
      within(await recentPanel())
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual([
      L.recent.colAt,
      L.recent.colPipeline,
      L.recent.colSubject,
      L.recent.colTokens,
      L.recent.colLatency,
      L.recent.colOutcome,
      L.recent.colCost,
    ]);
  });

  it("shows the time, pipeline and role, subject, tokens in and out, latency, outcome and cost of each call", async () => {
    serveUsage(usage());
    renderPage();
    expect(rowsOf(await table())).toEqual([
      [
        "30/09 09:31",
        "① triage · proposer",
        "alert ….1662100",
        "2.214 / 190",
        "2,3 s",
        "Chuyển tier 2",
        "$0,0004",
      ],
      [
        "30/09 09:31",
        "① triage · verifier",
        "alert ….1662100",
        "1.380 / 60",
        "1,0 s",
        "kết luận riêng: Chuyển tier 2",
        "$0,0002",
      ],
      [
        "30/09 09:05",
        "① triage · proposer",
        "alert ….1661877",
        "2.190 / 0",
        "9,7 s",
        "dừng · sai định dạng (schema)",
        "$0,0004",
      ],
      [
        "30/09 08:19",
        "② điều tra case",
        "case …00000001",
        "49.701 / 800",
        "12,5 s",
        "Không phải sự cố",
        "$0,0024",
      ],
      [
        "30/09 08:05",
        "① triage · proposer",
        "alert ….1661650",
        "2.205 / 150",
        "2,6 s",
        "Cần xem xét",
        "$0,0004",
      ],
    ]);
  });

  it("links an alert to /alerts/:id and a case to /cases/:id, with the whole id in the address", async () => {
    serveUsage(usage());
    renderPage();
    const panel = within(await recentPanel());
    const alerts = panel.getAllByRole("link", { name: "alert ….1662100" });
    expect(alerts).toHaveLength(2);
    for (const link of alerts) expect(link).toHaveAttribute("href", `/alerts/${ALERT_ID}`);
    expect(alerts[0]).toHaveAttribute("title", ALERT_ID);
    expect(panel.getByRole("link", { name: "case …00000001" })).toHaveAttribute(
      "href",
      `/cases/${CASE_ID}`,
    );
  });

  it("gives a verifier row the verifier's own verdict, not an agreement with the proposer", async () => {
    serveUsage(usage());
    renderPage();
    const rows = rowsOf(await table());
    const verifier = rows[1] ?? [];
    expect(verifier[1]).toBe("① triage · verifier");
    expect(verifier[5]).toBe(L.recent.verifier("Chuyển tier 2"));
    expect(verifier[5]).not.toMatch(/đồng ý|không đồng ý|agree/i);
  });

  it("shows a verdict it has no word for as it came, a stop reason it does not know, and none as a dash", async () => {
    const runs = recentRows();
    serveUsage(
      usage({
        recent: [
          { ...runs[0]!, run_id: "a", outcome: "weird_verdict" },
          { ...runs[0]!, run_id: "b", outcome: "stopped:new_reason" },
          { ...runs[0]!, run_id: "c", outcome: null },
          { ...runs[3]!, run_id: "d", outcome: "need_more_data" },
        ],
      }),
    );
    renderPage();
    const outcomes = rowsOf(await table()).map((r) => r[5]);
    expect(outcomes).toEqual([
      "weird_verdict",
      "dừng · new_reason",
      "—",
      S.ai2.suggestedConclusion.need_more_data,
    ]);
  });

  it("writes a missing token, latency and cost as dashes", async () => {
    serveUsage(
      usage({
        recent: [
          {
            ...recentRows()[0]!,
            input_tokens: null,
            output_tokens: null,
            latency_ms: null,
            cost_usd: null,
          },
        ],
      }),
    );
    renderPage();
    const [row] = rowsOf(await table());
    expect(row?.[3]).toBe("— / —");
    expect(row?.[4]).toBe("—");
    expect(row?.[6]).toBe("—");
  });

  it("links nothing for a subject it has no page for, or has no id for", async () => {
    const run = recentRows()[0]!;
    serveUsage(
      usage({
        recent: [
          { ...run, run_id: "a", subject_type: "rule", subject_id: "7" },
          { ...run, run_id: "b", subject_type: null, subject_id: null },
          { ...run, run_id: "c", subject_type: "alert", subject_id: null },
        ],
      }),
    );
    renderPage();
    const panel = within(await recentPanel());
    const cells = rowsOf(await table()).map((r) => r[2]);
    expect(cells).toEqual(["rule 7", "—", "—"]);
    expect(panel.queryByRole("link")).not.toBeInTheDocument();
  });

  it("renders what a hostile id, outcome and name say as text, never as markup", async () => {
    const markup = '<img src=x onerror="alert(1)"><b>đậm</b>';
    const run = recentRows()[0]!;
    serveUsage(
      usage({
        recent: [
          { ...run, run_id: "a", subject_type: "rule", subject_id: markup, outcome: markup },
        ],
        quota: {
          limit: 30,
          window: "24h",
          users: [{ username: markup, display_name: markup, used: 1, remaining: 29 }],
        },
      }),
    );
    const { container } = renderPage();
    await recentPanel();
    expect(container.querySelector("img, b")).toBeNull();
    expect(screen.getAllByText(markup, { exact: false }).length).toBeGreaterThan(0);
  });

  it("says there is no call yet when there is none", async () => {
    serveUsage(usage({ recent: [] }));
    renderPage();
    expect(within(await recentPanel()).getByText(L.recent.empty)).toBeInTheDocument();
  });

  it("says its twenty calls are the newest, whatever the range", async () => {
    serveUsage(usage());
    renderPage();
    expect(within(await recentPanel()).getByText(L.recent.note)).toBeInTheDocument();
  });
});

// --- no calls -------------------------------------------------------------------------------------------

describe("no calls in the range", () => {
  const empty = (range: LlmUsage["range"]) =>
    usage({
      range,
      by_pipeline_role: [],
      recent: [],
      month: month({ spent_usd: 0, pct: 0, projected_usd: 0 }),
    });

  it.each([
    ["24h", "Chưa có lượt gọi model nào trong 24 giờ qua"],
    ["7d", "Chưa có lượt gọi model nào trong 7 ngày qua"],
    ["30d", "Chưa có lượt gọi model nào trong 30 ngày qua"],
    ["month", "Chưa có lượt gọi model nào trong tháng này"],
  ] as const)("says so for %s, in place of the table", async (range, title) => {
    serveUsage(empty(range));
    renderPage();
    const panel = within(await byPipeline());
    expect(panel.getByRole("heading", { name: title })).toBeInTheDocument();
    expect(panel.getByText(L.noCalls.body)).toBeInTheDocument();
    expect(panel.queryByRole("table")).not.toBeInTheDocument();
  });

  it("keeps the other blocks: the tiles read zero, the form is there", async () => {
    serveUsage(empty("24h"));
    renderPage();
    await byPipeline();
    const calls = within(await region(L.calls.title));
    expect(calls.getByText("0")).toBeInTheDocument();
    expect(within(await region(L.stoppedTile.title)).getByText("—")).toBeInTheDocument();
    expect(capField()).toHaveValue(30);
  });

  it("still serves the twenty newest calls when the range has none of its own", async () => {
    serveUsage(usage({ range: "24h", by_pipeline_role: [] }));
    renderPage();
    await byPipeline();
    expect(rowsOf(await within(await recentPanel()).findByRole("table")).length).toBe(5);
  });
});

// --- the range select ---------------------------------------------------------------------------------------

describe("the range", () => {
  it("offers the four ranges of the route, the month first, under 'Khoảng thời gian'", async () => {
    serveUsage(usage());
    renderPage();
    await costTile();
    const select = screen.getByRole("combobox", { name: L.rangeLabel });
    expect(select).toHaveValue("month");
    expect(
      within(select)
        .getAllByRole("option")
        .map((o) => [o.getAttribute("value"), o.textContent]),
    ).toEqual([
      ["month", "Tháng này"],
      ["24h", "24 giờ qua"],
      ["7d", "7 ngày qua"],
      ["30d", "30 ngày qua"],
    ]);
  });

  it("reads the range chosen, and shows what it answers", async () => {
    const week = usage({
      range: "7d",
      by_pipeline_role: [{ ...pipelineRows()[0]!, calls: 7, with_result: 7, stopped: {} }],
    });
    const ranges = serveUsage(usage(), week);
    renderPage();
    const user = userEvent.setup();
    await costTile();
    await user.selectOptions(screen.getByRole("combobox", { name: L.rangeLabel }), "7d");
    await waitFor(() => expect(ranges).toEqual(["month", "7d"]));
    await waitFor(() =>
      expect(
        rowsOf(within(screen.getByRole("region", { name: L.byPipeline.title })).getByRole("table"))
          .length,
      ).toBe(1),
    );
  });

  it("keeps the page it has, and the form's edits, while the next range loads", async () => {
    const held = gate();
    serveUsage(usage(), async () => {
      await held.opened;
      return HttpResponse.json(usage({ range: "24h" }));
    });
    renderPage();
    const user = userEvent.setup();
    await limitsPanel();
    await setField(user, capField(), "45");
    await user.selectOptions(screen.getByRole("combobox", { name: L.rangeLabel }), "24h");
    expect(screen.getByRole("region", { name: L.cost.title })).toBeInTheDocument();
    expect(capField()).toHaveValue(45);
    held.release();
    await waitFor(() =>
      expect(screen.getByRole("combobox", { name: L.rangeLabel })).toHaveValue("24h"),
    );
    expect(capField()).toHaveValue(45);
  });
});

// --- the limits form ----------------------------------------------------------------------------------------

describe("the limits form", () => {
  it("has the three fields with their effective values, and the audit note", async () => {
    serveUsage(usage({ limits: limits({ cap_usd: 30, quota_per_24h: 25, timeout_s: 90 }) }));
    renderPage();
    const panel = within(await limitsPanel());
    expect(capField()).toHaveValue(30);
    expect(quotaField()).toHaveValue(25);
    expect(timeoutField()).toHaveValue(90);
    expect(panel.getByText(L.limits.note)).toBeInTheDocument();
    expect(panel.getAllByRole("spinbutton")).toHaveLength(3);
  });

  it("offers no model or thinking line: the route does not send one", async () => {
    serveUsage(usage());
    renderPage();
    const panel = await limitsPanel();
    expect(panel.textContent).not.toMatch(/deepseek|thinking/i);
  });

  it("takes each field's min and max from limits.bounds, and holds none of its own", async () => {
    serveUsage(
      usage({
        limits: limits({
          bounds: {
            cap_usd: { min: 2, max: 500 },
            quota_per_24h: { min: 3, max: 77 },
            timeout_s: { min: 15, max: 90 },
          },
        }),
      }),
    );
    renderPage();
    await limitsPanel();
    expect(capField()).toHaveAttribute("min", "2");
    expect(capField()).toHaveAttribute("max", "500");
    expect(quotaField()).toHaveAttribute("min", "3");
    expect(quotaField()).toHaveAttribute("max", "77");
    expect(timeoutField()).toHaveAttribute("min", "15");
    expect(timeoutField()).toHaveAttribute("max", "90");
    expect(capField()).toHaveAccessibleDescription(/Từ 2 đến 500/);
    expect(quotaField()).toHaveAccessibleDescription(/Từ 3 đến 77/);
    expect(timeoutField()).toHaveAccessibleDescription(/Từ 15 đến 90/);
  });

  it("refuses a timeout above the answer's own max (the job lock's ceiling), not above 600", async () => {
    serveUsage(
      usage({
        limits: limits({
          bounds: {
            cap_usd: { min: 1, max: 1000 },
            quota_per_24h: { min: 1, max: 200 },
            timeout_s: { min: 10, max: 90 },
          },
        }),
      }),
    );
    const bodies = servePut(() => saved());
    renderPage();
    const user = userEvent.setup();
    await limitsPanel();
    await setField(user, timeoutField(), "100");
    await user.click(saveButton());
    expect(timeoutField()).toHaveAccessibleDescription(/Phải từ 10 đến 90/);
    expect(timeoutField()).toHaveAttribute("aria-invalid", "true");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(bodies).toEqual([]);
  });

  describe("where each limit came from", () => {
    it("says `từ .env` for a limit that is the .env's", async () => {
      serveUsage(usage());
      renderPage();
      await limitsPanel();
      for (const input of [capField(), quotaField(), timeoutField()]) {
        expect(input).toHaveAccessibleDescription(/từ \.env/);
      }
    });

    it("says who changed it on the web and when, in the console's time, for that field only", async () => {
      serveUsage(
        usage({
          limits: limits({
            sources: {
              LLM_MONTHLY_USD_CAP: {
                source: "web",
                updated_at: SAVED_AT,
                updated_by_name: "Hoa Admin",
                clamped: false,
              },
              ANALYZE_QUOTA_PER_USER_DAY: ENV,
              LLM_TIMEOUT_S: ENV,
            },
          }),
        }),
      );
      renderPage();
      await limitsPanel();
      expect(capField()).toHaveAccessibleDescription(
        /sửa trên web bởi Hoa Admin lúc 12\/10\/2026 14:05:00/,
      );
      expect(quotaField()).toHaveAccessibleDescription(/từ \.env/);
      expect(timeoutField()).toHaveAccessibleDescription(/từ \.env/);
      expect(capField()).not.toHaveAccessibleDescription(/từ \.env/);
    });

    it("reads each field's own setting: the quota's source is the quota's, the timeout's the timeout's", async () => {
      serveUsage(
        usage({
          limits: limits({
            sources: {
              LLM_MONTHLY_USD_CAP: ENV,
              ANALYZE_QUOTA_PER_USER_DAY: {
                source: "web",
                updated_at: SAVED_AT,
                updated_by_name: "Quota Người",
                clamped: false,
              },
              LLM_TIMEOUT_S: {
                source: "web",
                updated_at: "2026-10-13T01:00:00+00:00",
                updated_by_name: "Timeout Người",
                clamped: false,
              },
            },
          }),
        }),
      );
      renderPage();
      await limitsPanel();
      expect(capField()).toHaveAccessibleDescription(/từ \.env/);
      expect(quotaField()).toHaveAccessibleDescription(/bởi Quota Người lúc 12\/10\/2026 14:05:00/);
      expect(timeoutField()).toHaveAccessibleDescription(
        /bởi Timeout Người lúc 13\/10\/2026 08:00:00/,
      );
    });

    it("leaves the name out when the user is gone", async () => {
      serveUsage(
        usage({
          limits: limits({
            sources: {
              LLM_MONTHLY_USD_CAP: {
                source: "web",
                updated_at: SAVED_AT,
                updated_by_name: null,
                clamped: false,
              },
              ANALYZE_QUOTA_PER_USER_DAY: ENV,
              LLM_TIMEOUT_S: ENV,
            },
          }),
        }),
      );
      renderPage();
      await limitsPanel();
      expect(capField()).toHaveAccessibleDescription(/sửa trên web lúc 12\/10\/2026 14:05:00/);
      expect(capField()).not.toHaveAccessibleDescription(/bởi/);
    });

    it("says a stored timeout was held to its ceiling, on the timeout only", async () => {
      serveUsage(
        usage({
          limits: limits({
            timeout_s: 120,
            sources: {
              LLM_MONTHLY_USD_CAP: ENV,
              ANALYZE_QUOTA_PER_USER_DAY: ENV,
              LLM_TIMEOUT_S: {
                source: "web",
                updated_at: SAVED_AT,
                updated_by_name: "Hoa Admin",
                clamped: true,
              },
            },
          }),
        }),
      );
      renderPage();
      await limitsPanel();
      expect(timeoutField()).toHaveValue(120);
      expect(timeoutField()).toHaveAccessibleDescription(new RegExp(L.limits.clamped));
      expect(capField()).not.toHaveAccessibleDescription(new RegExp(L.limits.clamped));
      expect(quotaField()).not.toHaveAccessibleDescription(new RegExp(L.limits.clamped));
    });
  });

  describe("the Save button", () => {
    it("is disabled until a field differs from the effective value", async () => {
      serveUsage(usage());
      renderPage();
      const user = userEvent.setup();
      await limitsPanel();
      expect(saveButton()).toBeDisabled();
      await setField(user, capField(), "40");
      expect(saveButton()).toBeEnabled();
      await setField(user, capField(), "30");
      expect(saveButton()).toBeDisabled();
    });

    it("is not enabled by the same value written another way", async () => {
      serveUsage(usage());
      renderPage();
      const user = userEvent.setup();
      await limitsPanel();
      await setField(user, capField(), "030");
      expect(saveButton()).toBeDisabled();
    });
  });

  describe("a value that cannot be sent", () => {
    it("says a blank field is empty, at the field, and opens nothing", async () => {
      const bodies = servePut(() => saved());
      serveUsage(usage());
      renderPage();
      const user = userEvent.setup();
      await limitsPanel();
      await setField(user, quotaField(), "");
      await user.click(saveButton());
      expect(quotaField()).toHaveAccessibleDescription(/Không được để trống/);
      expect(quotaField()).toHaveAttribute("aria-invalid", "true");
      expect(quotaField()).toHaveFocus();
      expect(capField()).not.toHaveAttribute("aria-invalid", "true");
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(bodies).toEqual([]);
    });

    it("says a decimal is not an integer, at the field", async () => {
      const bodies = servePut(() => saved());
      serveUsage(usage());
      renderPage();
      const user = userEvent.setup();
      await limitsPanel();
      await setField(user, capField(), "12.5");
      await user.click(saveButton());
      expect(capField()).toHaveAccessibleDescription(/Phải là số nguyên/);
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(bodies).toEqual([]);
    });

    it.each([
      ["0", "cap_usd", "Phải từ 1 đến 1000"],
      ["1001", "cap_usd", "Phải từ 1 đến 1000"],
      ["201", "quota_per_24h", "Phải từ 1 đến 200"],
      ["9", "timeout_s", "Phải từ 10 đến 120"],
      ["121", "timeout_s", "Phải từ 10 đến 120"],
    ])("says %s is out of range for %s, with the bounds", async (typed, which, text) => {
      const bodies = servePut(() => saved());
      serveUsage(usage());
      renderPage();
      const user = userEvent.setup();
      await limitsPanel();
      const input =
        which === "cap_usd"
          ? capField()
          : which === "quota_per_24h"
            ? quotaField()
            : timeoutField();
      await setField(user, input, typed);
      await user.click(saveButton());
      expect(input).toHaveAccessibleDescription(new RegExp(text));
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(bodies).toEqual([]);
    });

    it("flags every bad field at once, and focuses the first", async () => {
      serveUsage(usage());
      renderPage();
      const user = userEvent.setup();
      await limitsPanel();
      await setField(user, capField(), "");
      await setField(user, timeoutField(), "5");
      await user.click(saveButton());
      expect(capField()).toHaveAttribute("aria-invalid", "true");
      expect(timeoutField()).toHaveAttribute("aria-invalid", "true");
      expect(quotaField()).not.toHaveAttribute("aria-invalid", "true");
      expect(capField()).toHaveFocus();
    });

    it("takes a field's error away when it is edited again", async () => {
      serveUsage(usage());
      renderPage();
      const user = userEvent.setup();
      await limitsPanel();
      await setField(user, capField(), "");
      await user.click(saveButton());
      expect(capField()).toHaveAttribute("aria-invalid", "true");
      await user.type(capField(), "40");
      expect(capField()).not.toHaveAttribute("aria-invalid", "true");
      expect(capField()).not.toHaveAccessibleDescription(/Không được để trống/);
    });
  });
});

// --- the confirmation ----------------------------------------------------------------------------------------

describe("the confirmation", () => {
  it("lists only the fields that changed, old and new, with their units", async () => {
    serveUsage(usage());
    await openConfirm({ cap: "40", timeout: "90" });
    const table = within(dialog()).getByRole("table", { name: L.confirm.tableLabel });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual([L.confirm.colLimit, L.confirm.colOld, L.confirm.colNew]);
    expect(rowsOf(table)).toEqual([
      ["Trần chi phí mỗi tháng", "$30", "$40"],
      ["Thời gian chờ mỗi lượt", "120 s", "90 s"],
    ]);
    expect(within(dialog()).getByText(L.confirm.note)).toBeInTheDocument();
  });

  it("lists the quota as a plain number, and a lone change as one row", async () => {
    serveUsage(usage());
    await openConfirm({ quota: "20" });
    expect(rowsOf(within(dialog()).getByRole("table"))).toEqual([
      [L.limits.changeName.quota_per_24h, "30", "20"],
    ]);
  });

  it("leaves a field that was typed over with the same value out of the list", async () => {
    serveUsage(usage());
    await openConfirm({ cap: "40", quota: "30" });
    expect(rowsOf(within(dialog()).getByRole("table"))).toEqual([
      ["Trần chi phí mỗi tháng", "$30", "$40"],
    ]);
  });

  it("is titled 'Lưu hạn mức mới?', with Lưu as the confirm and no warning", async () => {
    serveUsage(usage());
    await openConfirm({ cap: "40" });
    expect(within(dialog()).queryByRole("alert")).not.toBeInTheDocument();
    expect(confirmButton("Lưu")).toBeEnabled();
  });

  it("closes on Huỷ, sends nothing, and keeps what was typed", async () => {
    const bodies = servePut(() => saved());
    serveUsage(usage());
    const { user } = await openConfirm({ cap: "40" });
    await user.click(within(dialog()).getByRole("button", { name: S.admin.common.cancel }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(bodies).toEqual([]);
    expect(capField()).toHaveValue(40);
    expect(saveButton()).toBeEnabled();
  });

  it("closes on Esc, sends nothing, and keeps what was typed", async () => {
    const bodies = servePut(() => saved());
    serveUsage(usage());
    const { user } = await openConfirm({ timeout: "90" });
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(bodies).toEqual([]);
    expect(timeoutField()).toHaveValue(90);
  });

  describe("the warning when the new cap is not above what has been spent this month", () => {
    const spent = (spent_usd: number) => usage({ month: month({ spent_usd, pct: 40 }) });
    const WARNING = (cap: string, spentText: string) =>
      `Trần mới ${cap} không cao hơn chi phí tháng này ${spentText}. Model sẽ dừng gọi ngay sau khi lưu.`;

    it("warns when the new cap is below it, and the confirm becomes 'Vẫn lưu'", async () => {
      serveUsage(spent(12.5));
      await openConfirm({ cap: "10" });
      expect(within(dialog()).getByRole("alert")).toHaveTextContent(WARNING("$10", "$12,50"));
      expect(confirmButton("Vẫn lưu")).toBeEnabled();
      expect(within(dialog()).queryByRole("button", { name: "Lưu" })).not.toBeInTheDocument();
    });

    it("warns when the new cap equals it: the adapter stops at spent >= cap", async () => {
      serveUsage(spent(12));
      await openConfirm({ cap: "12" });
      expect(within(dialog()).getByRole("alert")).toHaveTextContent(WARNING("$12", "$12,00"));
    });

    it("does not warn when the new cap is above it", async () => {
      serveUsage(spent(12.5));
      await openConfirm({ cap: "13" });
      expect(within(dialog()).queryByRole("alert")).not.toBeInTheDocument();
      expect(confirmButton("Lưu")).toBeEnabled();
    });

    it("warns when a raised cap is still below the spend", async () => {
      serveUsage(usage({ month: month({ spent_usd: 35, cap_usd: 30, pct: 100 }) }));
      await openConfirm({ cap: "32" });
      expect(within(dialog()).getByRole("alert")).toHaveTextContent(WARNING("$32", "$35,00"));
    });

    it("does not warn about the cap when the cap is not what changes", async () => {
      serveUsage(usage({ month: month({ spent_usd: 35, cap_usd: 30, pct: 100 }) }));
      await openConfirm({ timeout: "90" });
      expect(within(dialog()).queryByRole("alert")).not.toBeInTheDocument();
      expect(confirmButton("Lưu")).toBeEnabled();
    });

    it("still sends the save when 'Vẫn lưu' is pressed", async () => {
      serveUsage(spent(12.5));
      const bodies = servePut(() => saved({ cap_usd: 10 }));
      const { user } = await openConfirm({ cap: "10" });
      await user.click(confirmButton("Vẫn lưu"));
      await waitFor(() => expect(bodies).toEqual([{ cap_usd: 10 }]));
    });
  });
});

// --- saving: success ----------------------------------------------------------------------------------------

describe("a saved limit", () => {
  it("sends only the changed fields, as a JSON object of integers", async () => {
    serveUsage(usage());
    const bodies = servePut(() => saved({ cap_usd: 40, timeout_s: 90 }));
    const { user } = await openConfirm({ cap: "40", quota: "30", timeout: "90" });
    await user.click(confirmButton("Lưu"));
    await waitFor(() => expect(bodies).toEqual([{ cap_usd: 40, timeout_s: 90 }]));
  });

  it("closes the dialog and says it is saved, and in force now", async () => {
    serveUsage(usage());
    servePut(() => saved({ cap_usd: 40 }));
    const { user } = await openConfirm({ cap: "40" });
    await user.click(confirmButton("Lưu"));
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Đã lưu hạn mức. Có hiệu lực ngay.",
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: S.common.close }));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows what the PUT answered, at once and before the page is read again, not what was typed", async () => {
    const held = gate();
    // The server holds the cap at 41 although 40 was asked (the answer is what is in force).
    const web = {
      source: "web",
      updated_at: SAVED_AT,
      updated_by_name: "Hoa Admin",
      clamped: false,
    } as const;
    serveUsage(usage(), async () => {
      await held.opened;
      return HttpResponse.json(usage());
    });
    servePut(() =>
      saved({
        cap_usd: 41,
        sources: {
          LLM_MONTHLY_USD_CAP: web,
          ANALYZE_QUOTA_PER_USER_DAY: ENV,
          LLM_TIMEOUT_S: ENV,
        },
      }),
    );
    const { user } = await openConfirm({ cap: "40" });
    await user.click(confirmButton("Lưu"));
    await waitFor(() => expect(capField()).toHaveValue(41));
    expect(capField()).toHaveAccessibleDescription(
      /sửa trên web bởi Hoa Admin lúc 12\/10\/2026 14:05:00/,
    );
    expect(saveButton()).toBeDisabled();
    held.release();
  });

  it("then reads the page again, and marks what the write touched stale (invalidateAfter)", async () => {
    const ranges = serveUsage(usage());
    servePut(() => saved({ cap_usd: 40 }));
    const client = newClient();
    client.setQueryData(adminKeys.overview("24h"), { seeded: true });
    client.setQueryData(adminKeys.audit({ range: "24h" }), { seeded: true });
    client.setQueryData(adminKeys.llmUsage("7d"), { seeded: true });
    client.setQueryData(adminKeys.users, { seeded: true });
    const user = userEvent.setup();
    renderPage(client);
    await limitsPanel();
    await setField(user, capField(), "40");
    await user.click(saveButton());
    await user.click(confirmButton("Lưu"));
    await waitFor(() => expect(ranges.length).toBe(2));
    const stale = (key: readonly unknown[]) => client.getQueryState(key)?.isInvalidated;
    expect(stale(adminKeys.overview("24h"))).toBe(true);
    expect(stale(adminKeys.audit({ range: "24h" }))).toBe(true);
    expect(stale(adminKeys.llmUsage("7d"))).toBe(true);
    expect(stale(adminKeys.users)).toBe(false);
  });

  it("sends one request for two quick presses of the confirm button", async () => {
    serveUsage(usage());
    const held = gate();
    const bodies = servePut(async () => {
      await held.opened;
      return saved({ cap_usd: 40 });
    });
    const { user } = await openConfirm({ cap: "40" });
    const button = confirmButton("Lưu");
    await user.dblClick(button);
    expect(bodies.length).toBeLessThanOrEqual(1);
    held.release();
    await waitFor(() => expect(bodies).toHaveLength(1));
  });

  it("is busy while the save is out: both buttons are disabled and Esc does not cancel", async () => {
    serveUsage(usage());
    const held = gate();
    servePut(async () => {
      await held.opened;
      return saved({ cap_usd: 40 });
    });
    const { user } = await openConfirm({ cap: "40" });
    await user.click(confirmButton("Lưu"));
    const busy = await within(dialog()).findByRole("button", { name: S.admin.common.working });
    expect(busy).toBeDisabled();
    expect(within(dialog()).getByRole("button", { name: S.admin.common.cancel })).toBeDisabled();
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    held.release();
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });
});

// --- saving: what the server refuses ------------------------------------------------------------------------

describe("a refused save", () => {
  it.each([
    ["not_integer", {}, "Phải là số nguyên"],
    ["unknown", {}, "Trường này không được hỗ trợ"],
    ["empty", {}, "Không được để trống"],
    ["out_of_range", { min: 10, max: 90 }, "Phải từ 10 đến 90"],
  ])("shows the 422 %s at the field it names, closing the dialog", async (reason, extra, text) => {
    serveUsage(usage());
    servePut(() => refuse(422, { field: "timeout_s", reason, ...extra }));
    const { user } = await openConfirm({ cap: "40", timeout: "100" });
    await user.click(confirmButton("Lưu"));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(timeoutField()).toHaveAttribute("aria-invalid", "true");
    expect(timeoutField()).toHaveAccessibleDescription(new RegExp(text));
    expect(timeoutField()).toHaveFocus();
    expect(capField()).not.toHaveAttribute("aria-invalid", "true");
    expect(quotaField()).not.toHaveAttribute("aria-invalid", "true");
  });

  it("reads the page again after a 422 out_of_range, so the bounds on screen are the server's now", async () => {
    const narrower = usage({
      limits: limits({
        bounds: {
          cap_usd: { min: 1, max: 1000 },
          quota_per_24h: { min: 1, max: 200 },
          timeout_s: { min: 10, max: 90 },
        },
      }),
    });
    const ranges = serveUsage(usage(), narrower);
    servePut(() => refuse(422, { field: "timeout_s", reason: "out_of_range", min: 10, max: 90 }));
    const { user } = await openConfirm({ timeout: "100" });
    await user.click(confirmButton("Lưu"));
    await waitFor(() => expect(ranges.length).toBe(2));
    await waitFor(() => expect(timeoutField()).toHaveAttribute("max", "90"));
    expect(timeoutField()).toHaveAccessibleDescription(/Từ 10 đến 90/);
    expect(timeoutField()).toHaveAccessibleDescription(/Phải từ 10 đến 90/);
    expect(timeoutField()).toHaveValue(100);
  });

  it("keeps what was typed, so the admin corrects it instead of retyping", async () => {
    serveUsage(usage());
    servePut(() => refuse(422, { field: "timeout_s", reason: "out_of_range", min: 10, max: 90 }));
    const { user } = await openConfirm({ cap: "40", timeout: "100" });
    await user.click(confirmButton("Lưu"));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(capField()).toHaveValue(40);
    expect(timeoutField()).toHaveValue(100);
    expect(saveButton()).toBeEnabled();
  });

  it("shows a 422 about a field this form has not got inside the dialog", async () => {
    serveUsage(usage());
    servePut(() => refuse(422, { field: "zzz", reason: "unknown" }));
    const { user } = await openConfirm({ cap: "40" });
    await user.click(confirmButton("Lưu"));
    expect(await within(dialog()).findByRole("alert")).toHaveTextContent(S.admin.reason.unknown);
  });

  it("answers 503 limits_unavailable inside the dialog, which stays open, and reads the page again", async () => {
    const ranges = serveUsage(usage());
    servePut(() => refuse(503, { reason: "limits_unavailable" }));
    const { user } = await openConfirm({ cap: "40" });
    await user.click(confirmButton("Lưu"));
    expect(await within(dialog()).findByRole("alert")).toHaveTextContent(
      S.admin.reason.limits_unavailable,
    );
    expect(confirmButton("Lưu")).toBeEnabled();
    await waitFor(() => expect(ranges.length).toBe(2));
  });

  it("swaps the form for the fail-closed panel, and drops the dialog, when the page then reads no limits", async () => {
    serveUsage(usage(), failClosed());
    servePut(() => refuse(503, { reason: "limits_unavailable" }));
    const { user } = await openConfirm({ cap: "40" });
    await user.click(confirmButton("Lưu"));
    expect(await screen.findByText(L.failClosed.title)).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByRole("spinbutton")).not.toBeInTheDocument();
  });

  it("answers a stale 403 inside the dialog with the reason's text", async () => {
    serveUsage(usage());
    servePut(() => refuse(403, "forbidden"));
    const { user } = await openConfirm({ cap: "40" });
    await user.click(confirmButton("Lưu"));
    expect(await within(dialog()).findByRole("alert")).toHaveTextContent(S.admin.reason.forbidden);
  });

  it("says the server failed, inside the dialog, for a 500", async () => {
    serveUsage(usage());
    servePut(() => refuse(500, "boom"));
    const { user } = await openConfirm({ cap: "40" });
    await user.click(confirmButton("Lưu"));
    expect(await within(dialog()).findByRole("alert")).toHaveTextContent(L.limits.saveServer);
  });

  it.each([
    [404, "Not Found", L.limits.saveServer],
    [409, { reason: "already_queued" }, S.admin.reason.already_queued],
  ])(
    "reads a %s the route never sends: its reason's text if it has one, else 'the server failed'",
    async (status, detail, text) => {
      serveUsage(usage());
      servePut(() => refuse(status, detail));
      const { user } = await openConfirm({ cap: "40" });
      await user.click(confirmButton("Lưu"));
      expect(await within(dialog()).findByRole("alert")).toHaveTextContent(text);
    },
  );

  it("says the connection failed, inside the dialog, when there was no answer", async () => {
    serveUsage(usage());
    servePut(() => HttpResponse.error());
    const { user } = await openConfirm({ cap: "40" });
    await user.click(confirmButton("Lưu"));
    expect(await within(dialog()).findByRole("alert")).toHaveTextContent(L.limits.saveOffline);
  });

  it("lets the confirm be pressed again after a failure, and then saves", async () => {
    serveUsage(usage());
    const bodies = servePut((_body, n) => (n === 1 ? refuse(500, "boom") : saved({ cap_usd: 40 })));
    const { user } = await openConfirm({ cap: "40" });
    await user.click(confirmButton("Lưu"));
    await within(dialog()).findByRole("alert");
    await user.click(confirmButton("Lưu"));
    expect(await screen.findByRole("status")).toHaveTextContent("Đã lưu hạn mức");
    expect(bodies).toHaveLength(2);
  });
});

// --- fail closed ------------------------------------------------------------------------------------------

describe("when the stored limits cannot be read", () => {
  it("replaces the form with a read-only panel that says the model is stopped, not let through", async () => {
    serveUsage(failClosed());
    renderPage();
    const panel = within(await limitsPanel());
    expect(panel.getByRole("heading", { name: L.failClosed.title })).toBeInTheDocument();
    expect(panel.getByText(L.failClosed.body)).toBeInTheDocument();
    expect(L.failClosed.body).toMatch(/dừng gọi/);
    expect(L.failClosed.body).toMatch(/chứ không phải được gọi mà không có trần/);
    expect(panel.queryByRole("spinbutton")).not.toBeInTheDocument();
    expect(panel.queryByRole("button")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: L.limits.save })).not.toBeInTheDocument();
  });

  it("fails closed on limits_error alone, whatever else came with it", async () => {
    serveUsage(usage({ limits_error: "limits_unavailable" }));
    renderPage();
    const panel = within(await limitsPanel());
    expect(panel.getByText(L.failClosed.title)).toBeInTheDocument();
    expect(panel.queryByRole("spinbutton")).not.toBeInTheDocument();
  });

  it("is a block failing alone: the tiles, the tables and the recent calls still render", async () => {
    serveUsage(failClosed());
    renderPage();
    await limitsPanel();
    expect(within(await costTile()).getByText("$5,20")).toBeInTheDocument();
    expect(within(await region(L.calls.title)).getByText("1.589")).toBeInTheDocument();
    expect(rowsOf(within(await byPipeline()).getByRole("table")).length).toBe(3);
    expect(rowsOf(within(await quotaPanel()).getByRole("table")).length).toBe(1);
    expect(rowsOf(within(await recentPanel()).getByRole("table")).length).toBe(5);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

// --- loading and errors ----------------------------------------------------------------------------------

describe("loading", () => {
  it("shows a skeleton under the page's own title until the first answer", async () => {
    const held = gate();
    serveUsage(async () => {
      await held.opened;
      return HttpResponse.json(usage());
    });
    renderPage();
    expect(screen.getByRole("heading", { level: 1, name: S.admin.title.llm })).toBeInTheDocument();
    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("aria-busy", "true");
    expect(status).toHaveTextContent(S.common.loading);
    expect(screen.queryByRole("region")).not.toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByRole("spinbutton")).not.toBeInTheDocument();
    held.release();
    await costTile();
    expect(screen.queryByText(S.common.loading)).not.toBeInTheDocument();
  });
});

describe("a failed read", () => {
  it("shows the page error for a 500, and reads again when Thử lại is pressed", async () => {
    let calls = 0;
    server.use(
      http.get(USAGE_URL, () => {
        calls += 1;
        return calls === 1 ? refuse(500, "boom") : HttpResponse.json(usage());
      }),
    );
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(S.admin.common.loadError);
    expect(screen.getByText(L.loadErrorServer(500))).toBeInTheDocument();
    expect(screen.getByRole("link", { name: S.nav.queue })).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: S.common.retry }));
    await costTile();
    expect(calls).toBe(2);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it.each([
    ["timeout", S.admin.reason.timeout],
    ["query_failed", S.admin.reason.query_failed],
  ])("says what a 503 %s means, in the reason's own text", async (reason, text) => {
    serveUsage(() => refuse(503, { reason }));
    renderPage();
    await screen.findByRole("alert");
    expect(screen.getByText(text)).toBeInTheDocument();
  });

  it("says the connection failed when there was no answer", async () => {
    serveUsage(() => HttpResponse.error());
    renderPage();
    await screen.findByRole("alert");
    expect(screen.getByText(L.loadErrorOffline)).toBeInTheDocument();
  });

  it("says a 403 in the reason's text", async () => {
    serveUsage(() => refuse(403, "forbidden"));
    renderPage();
    await screen.findByRole("alert");
    expect(screen.getByText(S.admin.reason.forbidden)).toBeInTheDocument();
  });

  it("keeps the page it has, and says so, when a later read fails", async () => {
    const ranges = serveUsage(usage(), () => refuse(500, "boom"), usage());
    const { client } = renderPage();
    await costTile();
    await client.refetchQueries({ queryKey: adminKeys.llmAll });
    expect(await screen.findByRole("alert")).toHaveTextContent(L.refreshFailed);
    expect(screen.getByRole("region", { name: L.cost.title })).toBeInTheDocument();
    expect(screen.queryByText(S.admin.common.loadError)).not.toBeInTheDocument();
    await client.refetchQueries({ queryKey: adminKeys.llmAll });
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    expect(ranges).toHaveLength(3);
  });
});

// --- markup and accessibility -----------------------------------------------------------------------

describe("markup", () => {
  it("sets no style attribute anywhere (the CSP forbids one): the bar is a <progress>", async () => {
    serveUsage(usage());
    const { container } = renderPage();
    await limitsPanel();
    expect(container.querySelector("[style]")).toBeNull();
    expect(container.querySelector("progress")).not.toBeNull();
  });

  it("sets no style attribute in the confirmation either", async () => {
    serveUsage(usage({ month: month({ spent_usd: 35, cap_usd: 30, pct: 100 }) }));
    const { container } = await openConfirm({ cap: "32" });
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("renders a name that a save recorded as text", async () => {
    const markup = '<img src=x onerror="alert(1)"><b>đậm</b>';
    serveUsage(
      usage({
        limits: limits({
          sources: {
            LLM_MONTHLY_USD_CAP: {
              source: "web",
              updated_at: SAVED_AT,
              updated_by_name: markup,
              clamped: false,
            },
            ANALYZE_QUOTA_PER_USER_DAY: ENV,
            LLM_TIMEOUT_S: ENV,
          },
        }),
      }),
    );
    const { container } = renderPage();
    await limitsPanel();
    expect(container.querySelector("img, b")).toBeNull();
    expect(capField()).toHaveAccessibleDescription(new RegExp("bởi <img src=x"));
  });
});

describe("accessibility", () => {
  // jsdom computes no colours, so the contrast rule is off; the colours are the canvas's.
  const clean = async (container: HTMLElement) => {
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
  };

  it("has no axe violation in the normal state", async () => {
    serveUsage(usage());
    const { container } = renderPage();
    await limitsPanel();
    await clean(container);
  });

  it("has none in the amber state", async () => {
    serveUsage(usage({ month: month({ spent_usd: 24.6, pct: 82 }) }));
    const { container } = renderPage();
    await limitsPanel();
    await clean(container);
  });

  it("has none in the stopped state, with a user out of runs", async () => {
    serveUsage(
      usage({
        month: month({ spent_usd: 30, pct: 100 }),
        quota: {
          limit: 30,
          window: "24h",
          users: [{ username: "minh.t2", display_name: null, used: 30, remaining: 0 }],
        },
      }),
    );
    const { container } = renderPage();
    await limitsPanel();
    await clean(container);
  });

  it("has none in the fail-closed state", async () => {
    serveUsage(failClosed());
    const { container } = renderPage();
    await limitsPanel();
    await clean(container);
  });

  it("has none with no calls", async () => {
    serveUsage(usage({ by_pipeline_role: [], recent: [] }));
    const { container } = renderPage();
    await limitsPanel();
    await clean(container);
  });

  it("has none with the errors at the fields", async () => {
    serveUsage(usage());
    const { container } = renderPage();
    const user = userEvent.setup();
    await limitsPanel();
    await setField(user, capField(), "");
    await setField(user, timeoutField(), "500");
    await user.click(saveButton());
    expect(capField()).toHaveAttribute("aria-invalid", "true");
    await clean(container);
  });

  it("has none with the confirmation open, warning included", async () => {
    serveUsage(usage({ month: month({ spent_usd: 12.5, pct: 41 }) }));
    const { container } = await openConfirm({ cap: "10", timeout: "90" });
    expect(within(dialog()).getByRole("alert")).toBeInTheDocument();
    await clean(container);
  });

  it("has none while loading", async () => {
    const held = gate();
    serveUsage(async () => {
      await held.opened;
      return HttpResponse.json(usage());
    });
    const { container } = renderPage();
    await clean(container);
    held.release();
    await costTile();
  });

  it("has none in the page error", async () => {
    serveUsage(() => refuse(500, "boom"));
    const { container } = renderPage();
    await screen.findByRole("alert");
    await clean(container);
  });
});
