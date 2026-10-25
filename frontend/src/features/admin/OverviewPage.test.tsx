// src/features/admin/OverviewPage.test.tsx — `/admin/overview` (P11-T11, spec §4.1): the canvas's AdminOverview
// and the Tổng quan section of AdminStates, over MSW. The page is read with the clock fixed at 30/09 09:40
// (Ho Chi Minh) so the days the API leaves out can be zero-filled, and every answer the two write routes and
// the read can give is shown where the spec puts it: in the dialog, in the block, or as the page's error.
// The cost card is the overview's own tenth section, `llm_month` (DEC-203, P11-T20 row 50): the page makes no
// second read, and `serve()` keeps a handler on `llm/usage` only so that a test can say nobody called it.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import {
  ADMIN_RANGES,
  OVERVIEW_SECTIONS,
  type FailedJob,
  type HealthCheck,
  type LoadReport,
  type OverviewResponse,
  type OverviewSection,
} from "../../api/admin";
import { S } from "../../strings";
import { adminKeys, invalidateAfter } from "./adminKeys";
import { OverviewPage } from "./OverviewPage";
import { FAILED_JOBS_CAP, WINDOW_DAYS } from "./overviewModel";

const P = S.admin.overviewPage;

const OVERVIEW_URL = "/api/admin/overview";
const LLM_URL = "/api/admin/llm/usage";
const RELOAD_URL = "/api/admin/reload-inventory";
const RETRY_URL = "/api/admin/jobs/:id/retry";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// 30/09 09:40 in Ho Chi Minh. Only `Date` is frozen: the timers stay real, so MSW and waitFor run as usual.
const NOW = "2026-09-30T02:40:00Z";
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date(NOW));
});
afterEach(() => {
  vi.useRealTimers();
});

// --- fixtures: the canvas's numbers, made consistent with each other ----------------------------------------

const CHECK_NAMES = [
  "heartbeat",
  "intake_backlog",
  "job_backlog",
  "llm_null_ratio",
  "triage_unavailable",
  "monthly_cost",
  "backup_age",
  "inventory_empty",
  "digest_unreviewed",
  "disk_free",
] as const;

const check = (name: string, ok = true, detail?: string): HealthCheck => ({
  name,
  ok,
  value: ok ? 1 : 99,
  threshold: 50,
  detail: detail ?? (ok ? `${name} is fine` : `${name} is over its limit`),
});

const job = (job_id: number, over: Partial<FailedJob> = {}): FailedJob => ({
  job_id,
  job_type: "triage",
  subject_id: `alert-${job_id}`,
  attempts: 3,
  last_error: "timeout after 120s",
  locked_at: "2026-09-30T02:05:00+00:00",
  created_at: "2026-09-30T01:00:00+00:00",
  ...over,
});

const JOBS: FailedJob[] = [
  job(100412, { subject_id: "alert-1661877" }),
  job(100398, {
    job_type: "investigate",
    subject_id: "case-0b30b853",
    last_error: "schema invalid after repair",
    locked_at: "2026-09-30T01:47:00+00:00",
  }),
  job(100377, {
    job_type: "digest",
    subject_id: "2026-09-29",
    last_error: "statement timeout",
    locked_at: "2026-09-30T01:00:00+00:00",
  }),
];

function overview(over: Partial<OverviewResponse> = {}): OverviewResponse {
  return {
    range: "24h",
    errors: [],
    alerts_by_day: [
      { day: "2026-09-29", total: 3200, heads: 400, duplicates: 2800 },
      { day: "2026-09-30", total: 3840, heads: 503, duplicates: 3337 },
    ],
    by_source: {
      rows: [
        { source: "wazuh", alerts: 6304, heads: 725 },
        { source: "lab", alerts: 736, heads: 178 },
      ],
      rejected: 19,
    },
    top_agents: [
      { agent_name: "win-endpoint-01", alerts: 3412 },
      { agent_name: "lab-ubuntu-01", alerts: 2980 },
      { agent_name: "fw-edge", alerts: 665 },
    ],
    funnel: {
      by_status: {
        auto_closed: 41,
        queued_tier1: 848,
        tier1_active: 2,
        closed_fp: 5,
        closed_benign: 3,
        closed_confirmed: 1,
        escalated_tier2: 3,
      },
      triage: { ready: 733, unavailable: 90, pending: 78, none: 2 },
    },
    waiting: { count: 848, oldest_received_at: "2026-09-26T01:26:00+00:00" },
    cases_open: 3,
    health: {
      checked_at: "2026-09-30T02:40:00+00:00",
      ok: true,
      checks: CHECK_NAMES.map((name) => check(name)),
    },
    failed_jobs: JOBS,
    inventory: { assets: 6, identities: 3, iocs: 0, loaded_at: "2026-09-29T07:20:00+00:00" },
    llm_month: llmMonth(),
    knowledge: { pending: 4, conflicts: 1 },
    ...over,
  };
}

/** The sections as `null`, each with its entry in `errors[]`, as the handler answers a section that failed. */
function failing(
  sections: readonly OverviewSection[],
  error: "timeout" | "query_failed" = "timeout",
): OverviewResponse {
  const nulls = Object.fromEntries(sections.map((s) => [s, null])) as Partial<OverviewResponse>;
  return overview({ ...nulls, errors: sections.map((section) => ({ section, error })) });
}

/** The `llm_month` section as the route serves it; `over` changes what the test is about. */
const llmMonth = (
  over: Partial<NonNullable<OverviewResponse["llm_month"]>> = {},
): NonNullable<OverviewResponse["llm_month"]> => ({
  spent_usd: 0.5123,
  cap_usd: 30,
  pct: 1.7,
  ...over,
});

// --- the server -----------------------------------------------------------------------------------------------

type Answer = JsonBodyType | (() => Response | Promise<Response>);
const respond = (answer: Answer) =>
  typeof answer === "function" ? answer() : HttpResponse.json(answer);
const status =
  (code: number, body: JsonBodyType = null) =>
  () =>
    HttpResponse.json(body, { status: code });
const reason = (code: number, why: string) => status(code, { detail: { reason: why } });
const networkError = () => HttpResponse.error();

type Post = { path: string; body: unknown; contentType: string | null };
type Served = {
  overview: URLSearchParams[];
  llm: URLSearchParams[];
  posts: Post[];
};

/** Each list is served one answer per request, the last one for every request after it. */
function serve(
  options: { overviews?: Answer[]; retry?: Answer[]; reload?: Answer[] } = {},
): Served {
  const { overviews = [overview()], retry, reload } = options;
  const log: Served = { overview: [], llm: [], posts: [] };
  const nth = (list: Answer[], n: number): Answer => list[Math.min(n, list.length - 1)] as Answer;
  server.use(
    http.get(OVERVIEW_URL, ({ request }) => {
      log.overview.push(new URL(request.url).searchParams);
      return respond(nth(overviews, log.overview.length - 1));
    }),
    // The overview does not read this any more (the cost card is `llm_month`): a call is recorded, and refused.
    http.get(LLM_URL, ({ request }) => {
      log.llm.push(new URL(request.url).searchParams);
      return HttpResponse.json({ detail: "the overview does not read llm/usage" }, { status: 500 });
    }),
  );
  const write = (path: string, list: Answer[]) => {
    let sent = 0;
    return http.post(path, async ({ request }) => {
      log.posts.push({
        path: new URL(request.url).pathname,
        body: await request.json(),
        contentType: request.headers.get("content-type"),
      });
      return respond(nth(list, sent++));
    });
  };
  if (retry !== undefined) server.use(write(RETRY_URL, retry));
  if (reload !== undefined) server.use(write(RELOAD_URL, reload));
  return log;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}

/**
 * Two clicks in ONE tick: both inside a single `act`, so React renders nothing between them and the second lands
 * on the same enabled button as the first. (TanStack Query 5 tells React a write is pending only through a
 * `setTimeout(0)`, so `disabled={mutation.isPending}` cannot stop the second by itself; `userEvent`, which
 * awaits between clicks, never reproduces it.)
 */
function clickTwiceInOneTick(button: HTMLElement) {
  act(() => {
    fireEvent.click(button);
    fireEvent.click(button);
  });
}

// --- rendering ------------------------------------------------------------------------------------------------

const newClient = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });

function renderPage(client: QueryClient = newClient()) {
  const view = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/admin/overview"]}>
        <header>
          <span>AI Support SOC</span>
        </header>
        <main>
          <OverviewPage />
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { client, ...view };
}

const updated = () => screen.findByText(/^Cập nhật \d\d\/\d\d \d\d:\d\d$/);

/** The page, once the overview is in (the month's LLM cost is one of its sections). */
async function renderLoaded(options: Parameters<typeof serve>[0] = {}) {
  const log = serve(options);
  const view = renderPage();
  await updated();
  return { log, ...view };
}

const block = (name: string) => screen.getByRole("region", { name });
const tile = (label: string): HTMLElement => {
  const box = screen.getByText(label).closest("div");
  if (box === null) throw new Error(`no tile ${label}`);
  return box;
};
/** The `dd` that goes with a `dt` of this text, inside `scope`. */
const valueOf = (scope: HTMLElement, label: string): string | undefined =>
  within(scope).getByText(label).closest("div")?.querySelector("dd")?.textContent ?? undefined;
const rowsOf = (table: HTMLElement) =>
  within(table)
    .getAllByRole("row")
    .slice(1)
    .map((row) =>
      within(row)
        .getAllByRole("cell")
        .map((cell) => cell.textContent),
    );

async function axeViolations(container: HTMLElement): Promise<string[]> {
  // jsdom computes no layout or colour, so the contrast rule cannot run here.
  const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  return result.violations.map((v) => v.id);
}

// ==============================================================================================================
describe("the normal render", () => {
  it("shows the title, one h1, and when the data was read, in Ho Chi Minh time", async () => {
    await renderLoaded();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(
      screen.getByRole("heading", { level: 1, name: "Tổng quan hệ thống" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Cập nhật 30/09 09:40")).toBeInTheDocument();
  });

  it("reads the overview of 24h once, and never `llm/usage`: the cost card is the overview's `llm_month`", async () => {
    const { log } = await renderLoaded();
    expect(log.overview.map((p) => p.get("range"))).toEqual(["24h"]);
    expect(log.llm).toEqual([]);
  });

  it("shows the four cards of the canvas", async () => {
    await renderLoaded();
    const received = tile("Alert nhận vào");
    expect(valueOf(received, "Alert nhận vào")).toBe("7.040");
    expect(received).toHaveTextContent("24 giờ qua · 903 head sau gộp");
    const waiting = tile("Cụm chờ Tier-1");
    expect(valueOf(waiting, "Cụm chờ Tier-1")).toBe("848");
    expect(waiting).toHaveTextContent("cũ nhất: 26/09 08:26");
    const cases = tile("Case đang mở");
    expect(valueOf(cases, "Case đang mở")).toBe("3");
    const cost = tile("Chi phí LLM tháng này");
    expect(valueOf(cost, "Chi phí LLM tháng này")).toBe("$0,51");
    expect(cost).toHaveTextContent("trần $30 · 1,7%");
  });

  it("reads the waiting card from `waiting`, not from the funnel", async () => {
    // The funnel's queued_tier1 is bounded by the range and the card's count is not: they may differ.
    await renderLoaded({
      overviews: [
        overview({
          waiting: { count: 17, oldest_received_at: "2026-09-29T20:00:00+00:00" },
        }),
      ],
    });
    const waiting = tile("Cụm chờ Tier-1");
    expect(valueOf(waiting, "Cụm chờ Tier-1")).toBe("17");
    expect(waiting).toHaveTextContent("cũ nhất: 30/09 03:00");
    expect(valueOf(block("Tình trạng xử lý"), "Chờ Tier-1")).toBe("848");
  });

  it("says nothing waits when no cluster does, and shows 0", async () => {
    await renderLoaded({
      overviews: [overview({ waiting: { count: 0, oldest_received_at: null } })],
    });
    const waiting = tile("Cụm chờ Tier-1");
    expect(valueOf(waiting, "Cụm chờ Tier-1")).toBe("0");
    expect(waiting).toHaveTextContent("không có cụm nào chờ");
    expect(waiting).not.toHaveTextContent("cũ nhất");
  });

  it("shows 0 open cases as 0, not as a missing value", async () => {
    await renderLoaded({ overviews: [overview({ cases_open: 0 })] });
    expect(valueOf(tile("Case đang mở"), "Case đang mở")).toBe("0");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("draws the days as bars with the numbers of each day in a table for a screen reader", async () => {
    await renderLoaded();
    const days = block("Alert nhận vào theo ngày");
    expect(within(days).getByRole("img", { name: P.byDay.chart })).toBeInTheDocument();
    expect(within(days).getByText(P.byDay.legend)).toBeInTheDocument();
    const table = within(days).getByRole("table", { name: "Alert nhận vào theo ngày" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual(["Ngày", "Tổng", "Head", "Bản sao"]);
    expect(rowsOf(table)).toEqual([
      ["29/09", "3.200", "400", "2.800"],
      ["30/09", "3.840", "503", "3.337"],
    ]);
  });

  it("gives each bar a title with its numbers", async () => {
    const { container } = await renderLoaded();
    const titles = [...container.querySelectorAll("svg title")].map((t) => t.textContent);
    expect(titles).toEqual([
      "29/09: 3.200 alert, 400 head, 2.800 bản sao",
      "30/09: 3.840 alert, 503 head, 3.337 bản sao",
    ]);
  });

  it("scales the bars to the biggest day, heads under the copies, and draws a day with no alert at zero", async () => {
    const { container } = await renderLoaded({
      overviews: [
        overview({
          alerts_by_day: [{ day: "2026-09-30", total: 3840, heads: 503, duplicates: 3337 }],
        }),
      ],
    });
    const part = (g: Element, name: string) =>
      Number(g.querySelector(`rect[data-part="${name}"]`)?.getAttribute("height"));
    const [empty, full] = [...container.querySelectorAll("svg g[data-day]")];
    expect(empty?.getAttribute("data-day")).toBe("2026-09-29");
    expect(part(empty as Element, "heads")).toBe(0);
    expect(part(empty as Element, "duplicates")).toBe(0);
    expect(full?.getAttribute("data-day")).toBe("2026-09-30");
    const heads = part(full as Element, "heads");
    const copies = part(full as Element, "duplicates");
    expect(heads).toBeGreaterThan(0);
    expect(copies).toBeGreaterThan(heads);
    expect(heads / (heads + copies)).toBeCloseTo(503 / 3840, 2);
  });

  it("draws the second day higher than the first in the proportion of their totals", async () => {
    const { container } = await renderLoaded();
    const total = (g: Element) =>
      [...g.querySelectorAll("rect")].reduce((sum, r) => sum + Number(r.getAttribute("height")), 0);
    const [first, second] = [...container.querySelectorAll("svg g[data-day]")];
    expect(total(second as Element) / total(first as Element)).toBeCloseTo(3840 / 3200, 1);
  });

  it("shows the funnel: auto-closed, waiting, active, closed by Tier 1, escalated and ① coverage", async () => {
    await renderLoaded();
    const funnel = block("Tình trạng xử lý");
    expect(
      within(funnel)
        .getAllByRole("term")
        .map((t) => [t.textContent, valueOf(funnel, t.textContent ?? "")]),
    ).toEqual([
      ["Tự động đóng (rules)", "41"],
      ["Chờ Tier-1", "848"],
      ["Tier-1 đang xử lý", "2"],
      ["Đã đóng bởi Tier-1", "9"],
      ["Chuyển Tier-2", "3"],
      ["Có gợi ý AI ① sẵn", "733 / 903"],
    ]);
  });

  it("shows the sources with their heads, and the intake the server refused", async () => {
    await renderLoaded();
    const table = within(block("Theo nguồn")).getByRole("table", { name: "Theo nguồn" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual(["Nguồn", "Alert", "Head"]);
    expect(rowsOf(table)).toEqual([
      ["wazuh", "6.304", "725"],
      ["lab", "736", "178"],
      ["bị từ chối khi nạp", "19", "—"],
    ]);
  });

  it("shows the five busiest agents' alerts as the server counted them", async () => {
    await renderLoaded();
    const table = within(block("Agent nhiều alert nhất")).getByRole("table");
    expect(rowsOf(table)).toEqual([
      ["win-endpoint-01", "3.412"],
      ["lab-ubuntu-01", "2.980"],
      ["fw-edge", "665"],
    ]);
  });

  it("says there is no agent when none sent an alert", async () => {
    await renderLoaded({ overviews: [overview({ top_agents: [] })] });
    expect(
      within(block("Agent nhiều alert nhất")).getByText("Chưa có alert nào."),
    ).toBeInTheDocument();
  });

  it("shows the inventory counts and when it was loaded last", async () => {
    await renderLoaded();
    const inventory = block("Kiểm kê tài sản");
    expect(valueOf(inventory, "Asset đang dùng")).toBe("6");
    expect(valueOf(inventory, "Identity")).toBe("3");
    expect(valueOf(inventory, "IoC")).toBe("0");
    expect(valueOf(inventory, "Nạp lần cuối")).toBe("29/09 14:20");
    expect(within(inventory).getByRole("button", { name: "Nạp lại kiểm kê" })).toBeInTheDocument();
    expect(
      within(inventory).getByText(/Asset không có trong kiểm kê bị chặn cứng/),
    ).toBeInTheDocument();
  });

  it("shows the learned-knowledge queue: the drafts waiting and those in conflict (DEC-210)", async () => {
    await renderLoaded();
    const knowledge = block("Tri thức");
    expect(valueOf(knowledge, "Bản nháp chờ duyệt")).toBe("4");
    expect(valueOf(knowledge, "Trong đó mâu thuẫn với tri thức đã duyệt")).toBe("1");
    // the counts, and the way to the page that reviews them (P13-T06): one link, and no button
    expect(within(knowledge).queryByRole("button")).not.toBeInTheDocument();
    const link = within(knowledge).getByRole("link", { name: "Mở trang duyệt" });
    expect(link).toHaveAttribute("href", "/admin/knowledge");
    expect(within(knowledge).getAllByRole("link")).toHaveLength(1);
  });

  it("shows an empty queue as two zeros, not as an error", async () => {
    await renderLoaded({ overviews: [overview({ knowledge: { pending: 0, conflicts: 0 } })] });
    const knowledge = block("Tri thức");
    expect(valueOf(knowledge, "Bản nháp chờ duyệt")).toBe("0");
    expect(valueOf(knowledge, "Trong đó mâu thuẫn với tri thức đã duyệt")).toBe("0");
    expect(within(knowledge).queryByRole("alert")).not.toBeInTheDocument();
    // the link is there with nothing waiting: the approved entries are on the same page
    expect(within(knowledge).getByRole("link", { name: "Mở trang duyệt" })).toBeInTheDocument();
  });

  it("writes the queue with the thousands dot", async () => {
    await renderLoaded({
      overviews: [overview({ knowledge: { pending: 1234, conflicts: 56 } })],
    });
    expect(valueOf(block("Tri thức"), "Bản nháp chờ duyệt")).toBe("1.234");
  });

  it("says an inventory that was never loaded has not been", async () => {
    await renderLoaded({
      overviews: [overview({ inventory: { assets: 0, identities: 0, iocs: 0, loaded_at: null } })],
    });
    expect(valueOf(block("Kiểm kê tài sản"), "Nạp lần cuối")).toBe("chưa nạp lần nào");
  });

  it("writes every number with the Vietnamese thousands dot", async () => {
    await renderLoaded({
      overviews: [
        overview({
          alerts_by_day: [{ day: "2026-09-30", total: 1234567, heads: 8901, duplicates: 1225666 }],
          cases_open: 12345,
        }),
      ],
    });
    expect(valueOf(tile("Alert nhận vào"), "Alert nhận vào")).toBe("1.234.567");
    expect(valueOf(tile("Case đang mở"), "Case đang mở")).toBe("12.345");
  });
});

// ==============================================================================================================
describe("zero-filling what the API leaves out", () => {
  it("shows the day with no alert as a row of zeros, between and around the days that have some", async () => {
    await renderLoaded({
      overviews: [
        overview({
          range: "7d",
          alerts_by_day: [
            { day: "2026-09-25", total: 10, heads: 4, duplicates: 6 },
            { day: "2026-09-28", total: 7, heads: 7, duplicates: 0 },
          ],
        }),
      ],
    });
    // The page asked for 24h; the answer's own `range` is not what the series is drawn over.
    const table = within(block("Alert nhận vào theo ngày")).getByRole("table");
    expect(rowsOf(table).map((r) => r[0])).toEqual([
      "25/09",
      "26/09",
      "27/09",
      "28/09",
      "29/09",
      "30/09",
    ]);
    expect(rowsOf(table)[1]).toEqual(["26/09", "0", "0", "0"]);
    expect(rowsOf(table)[5]).toEqual(["30/09", "0", "0", "0"]);
  });

  it("shows a status the API has no head in as 0 in the funnel, and 0 / 0 for ① coverage", async () => {
    await renderLoaded({
      overviews: [
        overview({
          funnel: {
            by_status: { queued_tier1: 5 },
            triage: { ready: 0, unavailable: 0, pending: 5, none: 0 },
          },
        }),
      ],
    });
    const funnel = block("Tình trạng xử lý");
    expect(valueOf(funnel, "Tự động đóng (rules)")).toBe("0");
    expect(valueOf(funnel, "Chờ Tier-1")).toBe("5");
    expect(valueOf(funnel, "Tier-1 đang xử lý")).toBe("0");
    expect(valueOf(funnel, "Đã đóng bởi Tier-1")).toBe("0");
    expect(valueOf(funnel, "Chuyển Tier-2")).toBe("0");
    expect(valueOf(funnel, "Có gợi ý AI ① sẵn")).toBe("0 / 5");
  });

  it("shows an empty funnel as zeros", async () => {
    await renderLoaded({
      overviews: [
        overview({
          funnel: { by_status: {}, triage: { ready: 0, unavailable: 0, pending: 0, none: 0 } },
        }),
      ],
    });
    const funnel = block("Tình trạng xử lý");
    expect(valueOf(funnel, "Tự động đóng (rules)")).toBe("0");
    expect(valueOf(funnel, "Có gợi ý AI ① sẵn")).toBe("0 / 0");
  });
});

// ==============================================================================================================
describe("the range", () => {
  const select = () => screen.getByRole("combobox", { name: "Khoảng thời gian" });

  it("offers the three ranges of the API in the canvas's words, 24 giờ qua first and chosen", async () => {
    await renderLoaded();
    const options = within(select()).getAllByRole("option");
    expect(options.map((o) => [o.getAttribute("value"), o.textContent])).toEqual([
      ["24h", "24 giờ qua"],
      ["7d", "7 ngày qua"],
      ["30d", "30 ngày qua"],
    ]);
    expect(options.map((o) => o.getAttribute("value"))).toEqual([...ADMIN_RANGES]);
    expect(select()).toHaveValue("24h");
  });

  it("reads the overview again for the range picked, shows the new range's days and keeps the select", async () => {
    const user = userEvent.setup();
    const week = [23, 24, 25, 26, 27, 28, 29, 30].slice(1).map((d) => ({
      day: `2026-09-${d}`,
      total: d,
      heads: 1,
      duplicates: d - 1,
    }));
    const { log } = await renderLoaded({
      overviews: [overview(), overview({ range: "7d", alerts_by_day: week })],
    });
    await user.selectOptions(select(), "7d");
    await waitFor(() => expect(log.overview.map((p) => p.get("range"))).toEqual(["24h", "7d"]));
    const days = () => rowsOf(within(block("Alert nhận vào theo ngày")).getByRole("table"));
    await waitFor(() => expect(days()).toHaveLength(8));
    expect(days()[0]).toEqual(["23/09", "0", "0", "0"]);
    expect(days()[7]).toEqual(["30/09", "30", "1", "29"]);
    expect(select()).toHaveValue("7d");
    expect(tile("Alert nhận vào")).toHaveTextContent("7 ngày qua · 7 head sau gộp");
  });

  it("keeps the month's LLM cost the month's whatever the range, and reads no `llm/usage` for it", async () => {
    const user = userEvent.setup();
    const { log } = await renderLoaded({
      overviews: [overview(), overview({ range: "30d", llm_month: llmMonth({ spent_usd: 7 }) })],
    });
    expect(valueOf(tile("Chi phí LLM tháng này"), "Chi phí LLM tháng này")).toBe("$0,51");
    await user.selectOptions(select(), "30d");
    await waitFor(() => expect(log.overview).toHaveLength(2));
    // the card comes with every answer of the overview, so it follows the answer, not a read of its own
    await waitFor(() =>
      expect(valueOf(tile("Chi phí LLM tháng này"), "Chi phí LLM tháng này")).toBe("$7,00"),
    );
    expect(log.llm).toEqual([]);
  });

  it("shows 31 days for 30d", async () => {
    const user = userEvent.setup();
    await renderLoaded({ overviews: [overview(), overview({ range: "30d", alerts_by_day: [] })] });
    await user.selectOptions(select(), "30d");
    await waitFor(() =>
      expect(rowsOf(within(block("Alert nhận vào theo ngày")).getByRole("table"))).toHaveLength(31),
    );
  });

  it("labels every day of a short range, and, for 31 days, only every fourth, counted back from the last one", async () => {
    const user = userEvent.setup();
    const { container } = await renderLoaded({
      overviews: [overview(), overview({ range: "30d", alerts_by_day: [] })],
    });
    const labels = () =>
      [...container.querySelectorAll("svg text")]
        .map((t) => t.textContent ?? "")
        .filter((text) => /^\d\d\/\d\d$/.test(text));
    expect(labels()).toEqual(["29/09", "30/09"]);
    await user.selectOptions(select(), "30d");
    await waitFor(() => expect(labels().length).toBeGreaterThan(2));
    const shown = labels();
    expect(shown).toHaveLength(8);
    expect(shown[shown.length - 1]).toBe("30/09");
    expect(shown[shown.length - 2]).toBe("26/09");
    expect(shown[0]).toBe("02/09");
    // no total is written over the bars when there are too many of them
    expect(
      [...container.querySelectorAll("svg text")].filter((t) =>
        /^[\d.]+$/.test(t.textContent ?? ""),
      ),
    ).toHaveLength(0);
  });

  it("shows the loading skeleton, not the last range's numbers, while the new range is read", async () => {
    const user = userEvent.setup();
    const gate = deferred<Response>();
    serve({ overviews: [overview(), () => gate.promise] });
    renderPage();
    await updated();
    await user.selectOptions(select(), "7d");
    expect(await screen.findByRole("status")).toHaveTextContent("Đang tải…");
    expect(screen.queryByText("7.040")).not.toBeInTheDocument();
    expect(select()).toHaveValue("7d");
    gate.resolve(HttpResponse.json(overview({ range: "7d" })));
    await updated();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("is a labelled field of its own: the label is the canvas's", async () => {
    await renderLoaded();
    expect(screen.getByLabelText("Khoảng thời gian")).toBe(select());
  });
});

// ==============================================================================================================
describe("a range with no alert (AdminStates)", () => {
  const empty = () =>
    overview({
      alerts_by_day: [],
      by_source: { rows: [], rejected: 0 },
      top_agents: [],
      funnel: { by_status: {}, triage: { ready: 0, unavailable: 0, pending: 0, none: 0 } },
    });

  it("says so, says what the cards and the chart show, and points at the health block", async () => {
    await renderLoaded({ overviews: [empty()] });
    expect(
      screen.getByRole("heading", { name: "Không có alert nào trong 24 giờ qua" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        'Các ô số hiện 0, biểu đồ để trống. Nếu chờ đợi có alert, xem dòng "Lần kéo alert gần nhất" ở khối Sức khoẻ.',
      ),
    ).toBeInTheDocument();
  });

  it("shows 0 on the cards and an empty chart: the days are there, all zero", async () => {
    await renderLoaded({ overviews: [empty()] });
    expect(valueOf(tile("Alert nhận vào"), "Alert nhận vào")).toBe("0");
    expect(tile("Alert nhận vào")).toHaveTextContent("24 giờ qua · 0 head sau gộp");
    const table = within(block("Alert nhận vào theo ngày")).getByRole("table");
    expect(rowsOf(table)).toEqual([
      ["29/09", "0", "0", "0"],
      ["30/09", "0", "0", "0"],
    ]);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("names the range that is empty", async () => {
    const user = userEvent.setup();
    await renderLoaded({ overviews: [empty(), overview({ ...empty(), range: "7d" })] });
    await user.selectOptions(screen.getByRole("combobox", { name: "Khoảng thời gian" }), "7d");
    expect(
      await screen.findByRole("heading", { name: "Không có alert nào trong 7 ngày qua" }),
    ).toBeInTheDocument();
  });

  it("is not shown while alerts are there", async () => {
    await renderLoaded();
    expect(screen.queryByText(/Không có alert nào trong/)).not.toBeInTheDocument();
  });

  it("is not shown when the day series failed: it cannot say the range is empty", async () => {
    await renderLoaded({ overviews: [failing(["alerts_by_day"])] });
    expect(screen.queryByText(/Không có alert nào trong/)).not.toBeInTheDocument();
  });

  it("goes away when alerts come in", async () => {
    const user = userEvent.setup();
    await renderLoaded({ overviews: [empty(), overview()] });
    expect(screen.getByText(/Không có alert nào trong/)).toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Khoảng thời gian" }), "7d");
    await waitFor(() =>
      expect(screen.queryByText(/Không có alert nào trong/)).not.toBeInTheDocument(),
    );
  });
});

// ==============================================================================================================
describe("loading", () => {
  it("shows the title, the range and a skeleton with a status, and none of the numbers", async () => {
    const gate = deferred<Response>();
    serve({ overviews: [() => gate.promise] });
    renderPage();
    expect(
      screen.getByRole("heading", { level: 1, name: "Tổng quan hệ thống" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Khoảng thời gian" })).toBeInTheDocument();
    const loading = screen.getByRole("status");
    expect(loading).toHaveTextContent("Đang tải…");
    expect(loading).toHaveAttribute("aria-busy", "true");
    expect(screen.queryByText(/^Cập nhật /)).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    gate.resolve(HttpResponse.json(overview()));
    await updated();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("keeps the layout of the page: four card places, and the blocks", async () => {
    const gate = deferred<Response>();
    serve({ overviews: [() => gate.promise] });
    const { container } = renderPage();
    expect(container.querySelectorAll("[data-skeleton]").length).toBeGreaterThanOrEqual(4);
    gate.resolve(HttpResponse.json(overview()));
    await updated();
    expect(container.querySelectorAll("[data-skeleton]")).toHaveLength(0);
  });

  it("draws the cost card with the other three, from the same answer: no card waits for a second read", async () => {
    const gate = deferred<Response>();
    const log = serve({ overviews: [() => gate.promise] });
    renderPage();
    expect(screen.queryByText("Chi phí LLM tháng này")).not.toBeInTheDocument();
    gate.resolve(HttpResponse.json(overview()));
    await updated();
    expect(valueOf(tile("Alert nhận vào"), "Alert nhận vào")).toBe("7.040");
    expect(valueOf(tile("Chi phí LLM tháng này"), "Chi phí LLM tháng này")).toBe("$0,51");
    expect(tile("Chi phí LLM tháng này")).not.toHaveTextContent("Đang tải…");
    expect(log.llm).toEqual([]);
  });
});

// ==============================================================================================================
describe("the page cannot be read", () => {
  it.each([
    ["500", status(500, { detail: "Internal Server Error" })],
    ["503", status(503, { detail: "auth disabled: JWT_SECRET unset" })],
    ["403", status(403, { detail: "forbidden" })],
    [
      "422",
      status(422, { detail: [{ type: "literal_error", loc: ["query", "range"], msg: "bad" }] }),
    ],
    ["a network failure", networkError],
  ])("shows the error of the page, with a retry, on %s", async (_name, answer) => {
    serve({ overviews: [answer] });
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(
      within(alert).getByRole("heading", { level: 1, name: "Không tải được trang" }),
    ).toBeInTheDocument();
    expect(within(alert).getByRole("button", { name: "Thử lại" })).toBeInTheDocument();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(screen.queryByText("Internal Server Error")).not.toBeInTheDocument();
    expect(screen.queryByText(/auth disabled/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^Cập nhật /)).not.toBeInTheDocument();
  });

  it("asks again on Thử lại and shows the page when the answer is good", async () => {
    const user = userEvent.setup();
    const log = serve({ overviews: [status(500), overview()] });
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Thử lại" }));
    await updated();
    expect(log.overview).toHaveLength(2);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 1, name: "Tổng quan hệ thống" }),
    ).toBeInTheDocument();
  });

  it("keeps the range select so another range can be tried", async () => {
    const user = userEvent.setup();
    const log = serve({ overviews: [status(500), overview({ range: "30d" })] });
    renderPage();
    await screen.findByRole("alert");
    await user.selectOptions(screen.getByRole("combobox", { name: "Khoảng thời gian" }), "30d");
    await updated();
    expect(log.overview.map((p) => p.get("range"))).toEqual(["24h", "30d"]);
  });

  it("shows no page error when only the month's LLM cost cannot be read", async () => {
    serve({ overviews: [failing(["llm_month"], "timeout")] });
    renderPage();
    await updated();
    expect(screen.queryByRole("heading", { name: "Không tải được trang" })).not.toBeInTheDocument();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
  });
});

describe("a refresh that fails while the page is on screen", () => {
  it("keeps the numbers it has, says whose data they are, and offers a retry", async () => {
    const user = userEvent.setup();
    const { client, log } = await renderLoaded({
      overviews: [overview(), status(500), overview()],
    });
    await act(() => client.invalidateQueries({ queryKey: adminKeys.overviewAll }));
    const notice = await screen.findByText(
      "Không làm mới được. Đang hiện dữ liệu lúc 30/09 09:40.",
    );
    expect(valueOf(tile("Alert nhận vào"), "Alert nhận vào")).toBe("7.040");
    expect(screen.queryByRole("heading", { name: "Không tải được trang" })).not.toBeInTheDocument();
    await user.click(
      within(notice.closest("div") as HTMLElement).getByRole("button", { name: "Thử lại" }),
    );
    await waitFor(() => expect(log.overview).toHaveLength(3));
    await waitFor(() => expect(screen.queryByText(/Không làm mới được/)).not.toBeInTheDocument());
  });
});

// ==============================================================================================================
describe("one block failing alone (AdminStates)", () => {
  // For each section: where its failure is drawn, and a value of the blocks around it that must still be there.
  const WHERE: Record<OverviewSection, string[]> = {
    alerts_by_day: ["Alert nhận vào theo ngày", "Alert nhận vào"],
    by_source: ["Theo nguồn"],
    top_agents: ["Agent nhiều alert nhất"],
    funnel: ["Tình trạng xử lý"],
    waiting: ["Cụm chờ Tier-1"],
    cases_open: ["Case đang mở"],
    health: ["Sức khoẻ hệ thống"],
    failed_jobs: ["Job lỗi"],
    inventory: ["Kiểm kê tài sản"],
    // The cost card reads `llm_month` (DEC-203, P11-T20 row 50): its failure is drawn in the card.
    llm_month: ["Chi phí LLM tháng này"],
    // The learned-knowledge queue (DEC-210, P13-T05) is a block of its own in the last row.
    knowledge: ["Tri thức"],
  };
  const TILES = new Set([
    "Alert nhận vào",
    "Cụm chờ Tier-1",
    "Case đang mở",
    "Chi phí LLM tháng này",
  ]);
  const container = (name: string): HTMLElement => (TILES.has(name) ? tile(name) : block(name));

  /** What each section shows when it is served: the check that the others around a failure are drawn. */
  const PROBE: Record<OverviewSection, () => void> = {
    alerts_by_day: () => expect(valueOf(tile("Alert nhận vào"), "Alert nhận vào")).toBe("7.040"),
    by_source: () => expect(screen.getByText("wazuh")).toBeInTheDocument(),
    top_agents: () => expect(screen.getByText("win-endpoint-01")).toBeInTheDocument(),
    funnel: () => expect(valueOf(block("Tình trạng xử lý"), "Tự động đóng (rules)")).toBe("41"),
    waiting: () => expect(valueOf(tile("Cụm chờ Tier-1"), "Cụm chờ Tier-1")).toBe("848"),
    cases_open: () => expect(valueOf(tile("Case đang mở"), "Case đang mở")).toBe("3"),
    health: () => expect(screen.getByText("10/10 ổn")).toBeInTheDocument(),
    failed_jobs: () => expect(screen.getByText("100412")).toBeInTheDocument(),
    inventory: () => expect(valueOf(block("Kiểm kê tài sản"), "Asset đang dùng")).toBe("6"),
    llm_month: () =>
      expect(valueOf(tile("Chi phí LLM tháng này"), "Chi phí LLM tháng này")).toBe("$0,51"),
    knowledge: () => expect(valueOf(block("Tri thức"), "Bản nháp chờ duyệt")).toBe("4"),
  };

  it("has a place for each of the eleven sections of the API", () => {
    expect(Object.keys(WHERE).sort()).toEqual([...OVERVIEW_SECTIONS].sort());
    expect(Object.keys(PROBE).sort()).toEqual([...OVERVIEW_SECTIONS].sort());
  });

  const cases = OVERVIEW_SECTIONS.flatMap((section) =>
    (["timeout", "query_failed"] as const).map((error) => [section, error] as const),
  );

  it.each(cases)(
    "shows %s that failed (%s) as an error where it belongs, and the rest as it is",
    async (section, error) => {
      await renderLoaded({ overviews: [failing([section], error)] });
      const alerts = screen.getAllByRole("alert");
      expect(alerts).toHaveLength(WHERE[section].length);
      const text = error === "timeout" ? "Truy vấn quá thời gian cho phép." : "Truy vấn thất bại.";
      for (const place of WHERE[section]) {
        const alert = within(container(place)).getByRole("alert");
        expect(alert).toHaveTextContent(text);
        expect(alert).toHaveTextContent(
          TILES.has(place) ? "Không tải được" : "Không tải được khối này",
        );
      }
      for (const other of OVERVIEW_SECTIONS) if (other !== section) PROBE[other]();
      // One h1, whichever section failed: a failed block never takes the page's title with it.
      expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
      expect(
        screen.getByRole("heading", { level: 1, name: "Tổng quan hệ thống" }),
      ).toBeInTheDocument();
      expect(
        screen.queryByRole("heading", { name: "Không tải được trang" }),
      ).not.toBeInTheDocument();
    },
  );

  it("shows every block's own error when all eleven failed, under the title and the range", async () => {
    await renderLoaded({ overviews: [failing(OVERVIEW_SECTIONS, "query_failed")] });
    // 4 cards + 8 blocks (the day chart is both a card's and a block's section)
    expect(screen.getAllByRole("alert")).toHaveLength(12);
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(
      screen.getByRole("heading", { level: 1, name: "Tổng quan hệ thống" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Khoảng thời gian" })).toBeInTheDocument();
    expect(screen.queryByText(/Không có alert nào trong/)).not.toBeInTheDocument();
  });

  it("shows two failed blocks each with its own code", async () => {
    const data = overview({
      top_agents: null,
      by_source: null,
      errors: [
        { section: "top_agents", error: "timeout" },
        { section: "by_source", error: "query_failed" },
      ],
    });
    await renderLoaded({ overviews: [data] });
    expect(within(block("Agent nhiều alert nhất")).getByRole("alert")).toHaveTextContent(
      "quá thời gian",
    );
    expect(within(block("Theo nguồn")).getByRole("alert")).toHaveTextContent("Truy vấn thất bại.");
  });

  it("asks the server again from a block's Thử lại, and draws the block when it answers", async () => {
    const user = userEvent.setup();
    const { log } = await renderLoaded({ overviews: [failing(["top_agents"]), overview()] });
    await user.click(
      within(block("Agent nhiều alert nhất")).getByRole("button", { name: "Thử lại" }),
    );
    await waitFor(() => expect(log.overview).toHaveLength(2));
    expect(await screen.findByText("win-endpoint-01")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says the server did not send a section when it is null with no error listed", async () => {
    await renderLoaded({ overviews: [overview({ top_agents: null })] });
    expect(within(block("Agent nhiều alert nhất")).getByRole("alert")).toHaveTextContent(
      "Máy chủ không trả khối này.",
    );
  });

  it("shows a section that has data even when `errors` lists it", async () => {
    await renderLoaded({
      overviews: [overview({ errors: [{ section: "top_agents", error: "timeout" }] })],
    });
    expect(screen.getByText("win-endpoint-01")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("ignores an entry of `errors` for a section it does not know", async () => {
    await renderLoaded({
      overviews: [overview({ errors: [{ section: "disk_on_fire", error: "timeout" } as never] })],
    });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("keeps the reload button when the inventory could not be read: the button does not need the counts", async () => {
    await renderLoaded({ overviews: [failing(["inventory"])] });
    expect(
      within(block("Kiểm kê tài sản")).getByRole("button", { name: "Nạp lại kiểm kê" }),
    ).toBeInTheDocument();
  });

  // The cost card is the tenth section, `llm_month` (DEC-203): it fails alone, in the card, like the other nine.
  describe("the cost card", () => {
    const costCard = () => tile("Chi phí LLM tháng này");

    it.each(["timeout", "query_failed"] as const)(
      "shows its own error (%s), the other nine sections, and the page's single h1, when llm_month fails",
      async (error) => {
        await renderLoaded({ overviews: [failing(["llm_month"], error)] });
        const alert = within(costCard()).getByRole("alert");
        expect(alert).toHaveTextContent("Không tải được");
        expect(alert).toHaveTextContent(
          error === "timeout" ? "Truy vấn quá thời gian cho phép." : "Truy vấn thất bại.",
        );
        for (const other of OVERVIEW_SECTIONS) if (other !== "llm_month") PROBE[other]();
        expect(screen.getAllByRole("alert")).toHaveLength(1);
        expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
        expect(
          screen.getByRole("heading", { level: 1, name: "Tổng quan hệ thống" }),
        ).toBeInTheDocument();
        expect(screen.getByRole("combobox", { name: "Khoảng thời gian" })).toBeInTheDocument();
      },
    );

    it("says the server did not send llm_month when it is null with no error listed", async () => {
      await renderLoaded({ overviews: [overview({ llm_month: null })] });
      expect(within(costCard()).getByRole("alert")).toHaveTextContent(
        "Máy chủ không trả khối này.",
      );
      expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    });

    it("asks the overview again, not llm/usage, on the card's Thử lại, and draws the card when it answers", async () => {
      const user = userEvent.setup();
      const { log } = await renderLoaded({
        overviews: [failing(["llm_month"]), overview({ llm_month: llmMonth({ spent_usd: 2 }) })],
      });
      await user.click(within(costCard()).getByRole("button", { name: "Thử lại" }));
      await waitFor(() => expect(log.overview).toHaveLength(2));
      expect(await within(costCard()).findByText("$2,00")).toBeInTheDocument();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
      expect(log.llm).toEqual([]);
    });

    it("shows the spend and the cap with the share the server computed", async () => {
      await renderLoaded({
        overviews: [overview({ llm_month: llmMonth({ spent_usd: 24.6, cap_usd: 30, pct: 82 }) })],
      });
      expect(valueOf(costCard(), "Chi phí LLM tháng này")).toBe("$24,60");
      expect(costCard()).toHaveTextContent("trần $30 · 82,0%");
      expect(costCard()).not.toHaveTextContent("dừng gọi");
    });

    it("says the cap cannot be read when the limits are unreadable, read-only, and still shows the spend", async () => {
      await renderLoaded({
        overviews: [overview({ llm_month: llmMonth({ cap_usd: null, pct: null }) })],
      });
      expect(valueOf(costCard(), "Chi phí LLM tháng này")).toBe("$0,51");
      expect(costCard()).toHaveTextContent("không đọc được hạn mức");
      expect(costCard()).not.toHaveTextContent("dừng gọi");
      expect(within(costCard()).queryByRole("alert")).not.toBeInTheDocument();
      expect(within(costCard()).queryByRole("button")).not.toBeInTheDocument();
    });

    it("is stopped when the spend has reached the cap, whatever `pct` says", async () => {
      // `pct` is rounded to one decimal by the route today, so it can still read 99,9 at the cap.
      await renderLoaded({
        overviews: [overview({ llm_month: llmMonth({ spent_usd: 30, cap_usd: 30, pct: 99.9 }) })],
      });
      expect(valueOf(costCard(), "Chi phí LLM tháng này")).toBe("$30,00");
      expect(costCard()).toHaveTextContent("trần $30 · đã chạm trần, model dừng gọi");
      expect(costCard()).not.toHaveTextContent("99,9%");
    });

    it("is stopped above the cap too", async () => {
      await renderLoaded({
        overviews: [overview({ llm_month: llmMonth({ spent_usd: 31.2, cap_usd: 30, pct: 104 }) })],
      });
      expect(costCard()).toHaveTextContent("đã chạm trần, model dừng gọi");
    });

    it("is not stopped under the cap even when `pct` reads 100", async () => {
      await renderLoaded({
        overviews: [overview({ llm_month: llmMonth({ spent_usd: 29.99, cap_usd: 30, pct: 100 }) })],
      });
      expect(costCard()).toHaveTextContent("trần $30 · 100,0%");
      expect(costCard()).not.toHaveTextContent("dừng gọi");
    });

    it("is not stopped with nothing spent", async () => {
      await renderLoaded({
        overviews: [overview({ llm_month: llmMonth({ spent_usd: 0, cap_usd: 30, pct: 0 }) })],
      });
      expect(valueOf(costCard(), "Chi phí LLM tháng này")).toBe("$0,00");
      expect(costCard()).toHaveTextContent("trần $30 · 0,0%");
      expect(costCard()).not.toHaveTextContent("dừng gọi");
    });

    it("is refreshed by a limit change: `putLlmLimits` makes the overview stale, and the card follows", async () => {
      const { client, log } = await renderLoaded({
        overviews: [
          overview(),
          overview({ llm_month: llmMonth({ spent_usd: 0.5123, cap_usd: 50, pct: 1 }) }),
        ],
      });
      expect(costCard()).toHaveTextContent("trần $30 · 1,7%");
      await act(() => invalidateAfter(client, "putLlmLimits"));
      await waitFor(() => expect(costCard()).toHaveTextContent("trần $50 · 1,0%"));
      expect(log.overview).toHaveLength(2);
      expect(log.llm).toEqual([]);
    });
  });
});

// ==============================================================================================================
describe("system health", () => {
  const withHealth = (
    checks: HealthCheck[],
    over: Partial<NonNullable<OverviewResponse["health"]>> = {},
  ) =>
    overview({
      health: {
        checked_at: "2026-09-30T02:40:00+00:00",
        ok: checks.every((c) => c.ok),
        checks,
        ...over,
      },
    });

  it("says how many checks are fine, with the time of the check", async () => {
    await renderLoaded();
    const health = block("Sức khoẻ hệ thống");
    expect(within(health).getByText("10/10 ổn")).toBeInTheDocument();
    expect(health).toHaveTextContent("Lấy từ lần kiểm tra mới nhất (system_health), 30/09 09:40.");
  });

  it("lists the failing checks first, then the rest in the server's order", async () => {
    const checks = CHECK_NAMES.map((name) =>
      check(name, name !== "backup_age" && name !== "disk_free"),
    );
    await renderLoaded({ overviews: [withHealth(checks)] });
    const health = block("Sức khoẻ hệ thống");
    expect(within(health).getByText("8/10 ổn")).toBeInTheDocument();
    const labels = within(health)
      .getAllByRole("term")
      .map((t) => t.textContent ?? "");
    const label = (name: (typeof CHECK_NAMES)[number]) => S.admin.overviewPage.health.check[name];
    const expected = [
      label("backup_age"),
      label("disk_free"),
      // the other eight keep the order they came in
      ...CHECK_NAMES.filter((n) => n !== "backup_age" && n !== "disk_free").map(label),
    ];
    expect(labels).toHaveLength(10);
    labels.forEach((text, i) => expect(text).toContain(expected[i]));
    expect(labels[0]).toContain(S.admin.overviewPage.health.failing);
    expect(labels[2]).toContain(S.admin.overviewPage.health.ok);
  });

  it("shows each check's detail as the server wrote it, and marks a failing check in words, not only in colour", async () => {
    const checks = [
      check("heartbeat", true, "last heartbeat 0.4 min ago"),
      check("backup_age", false, "last backup 31.0 hours ago, over 36"),
    ];
    await renderLoaded({ overviews: [withHealth(checks)] });
    const health = block("Sức khoẻ hệ thống");
    expect(valueOf(health, "Bản sao lưu gần nhất")).toBe("last backup 31.0 hours ago, over 36");
    expect(within(health).getAllByText(S.admin.overviewPage.health.failing)).toHaveLength(1);
    expect(within(health).getAllByText(S.admin.overviewPage.health.ok)).toHaveLength(1);
  });

  it("shows the name of a failing check beside its label, the one health.alarm carries, and not that of a check that is fine", async () => {
    const checks = [check("heartbeat", true), check("backup_age", false)];
    await renderLoaded({ overviews: [withHealth(checks)] });
    const health = block("Sức khoẻ hệ thống");
    expect(within(health).getByText("backup_age")).toBeInTheDocument();
    expect(within(health).queryByText("heartbeat")).not.toBeInTheDocument();
  });

  it("names every check of the backend in Vietnamese, and shows a name it does not know as it is", async () => {
    const checks = [
      ...CHECK_NAMES.map((n) => check(n)),
      check("brand_new_check", false, "something"),
    ];
    await renderLoaded({ overviews: [withHealth(checks)] });
    const health = block("Sức khoẻ hệ thống");
    expect(within(health).getByText("10/11 ổn")).toBeInTheDocument();
    for (const name of CHECK_NAMES) {
      expect(within(health).getByText(S.admin.overviewPage.health.check[name])).toBeInTheDocument();
    }
    expect(within(health).getByText("brand_new_check")).toBeInTheDocument();
  });

  it("says no check has run when there is no health row yet, and that is not an error", async () => {
    await renderLoaded({ overviews: [overview({ health: null })] });
    const health = block("Sức khoẻ hệ thống");
    expect(within(health).getByText("Chưa có lần kiểm tra sức khoẻ nào.")).toBeInTheDocument();
    expect(within(health).queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says no check has run for a row that has no check in it", async () => {
    await renderLoaded({ overviews: [withHealth([])] });
    expect(
      within(block("Sức khoẻ hệ thống")).getByText("Chưa có lần kiểm tra sức khoẻ nào."),
    ).toBeInTheDocument();
    expect(screen.queryByText("0/0 ổn")).not.toBeInTheDocument();
  });
});

// ==============================================================================================================
describe("failed jobs", () => {
  const jobsBlock = () => block("Job lỗi");

  it("lists the job, its type, its subject, the attempts, the last error and the time of the last attempt", async () => {
    await renderLoaded();
    const table = within(jobsBlock()).getByRole("table", { name: "Các job lỗi" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual(["Job", "Loại", "Đối tượng", "Đã thử", "Lỗi cuối", "Lúc", "Thao tác"]);
    expect(rowsOf(table)).toEqual([
      ["100412", "triage", "alert-1661877", "3", "timeout after 120s", "30/09 09:05", "Chạy lại"],
      [
        "100398",
        "investigate",
        "case-0b30b853",
        "3",
        "schema invalid after repair",
        "30/09 08:47",
        "Chạy lại",
      ],
      ["100377", "digest", "2026-09-29", "3", "statement timeout", "30/09 08:00", "Chạy lại"],
    ]);
    expect(within(jobsBlock()).getByText("3 job")).toBeInTheDocument();
    expect(within(jobsBlock()).getByText(/Job đã hết số lần thử của worker/)).toBeInTheDocument();
  });

  it("names each Chạy lại button by its job", async () => {
    await renderLoaded();
    for (const j of JOBS) {
      expect(
        within(jobsBlock()).getByRole("button", { name: `Chạy lại job ${j.job_id}` }),
      ).toBeInTheDocument();
    }
  });

  it("shows the time a job was created when it never ran, and a dash for an error it never recorded", async () => {
    await renderLoaded({
      overviews: [overview({ failed_jobs: [job(7, { locked_at: null, last_error: null })] })],
    });
    const [row] = rowsOf(within(jobsBlock()).getByRole("table"));
    expect(row?.[4]).toBe("—");
    expect(row?.[5]).toBe("30/09 08:00");
  });

  it("shows no job: the green line, no table and no count", async () => {
    await renderLoaded({ overviews: [overview({ failed_jobs: [] })] });
    expect(within(jobsBlock()).getByText("Không có job lỗi nào.")).toBeInTheDocument();
    expect(within(jobsBlock()).queryByRole("table")).not.toBeInTheDocument();
    expect(within(jobsBlock()).queryByText(/^\d+ job/)).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says the list is the newest 50 when the server sent as many as it ever sends", async () => {
    const many = Array.from({ length: FAILED_JOBS_CAP }, (_, i) => job(1000 + i));
    await renderLoaded({ overviews: [overview({ failed_jobs: many })] });
    expect(within(jobsBlock()).getByText("50 job gần nhất")).toBeInTheDocument();
    expect(within(jobsBlock()).getAllByRole("button", { name: /^Chạy lại job/ })).toHaveLength(50);
  });

  describe("the retry dialog", () => {
    const open = async (user: ReturnType<typeof userEvent.setup>, id = 100412) => {
      await user.click(screen.getByRole("button", { name: `Chạy lại job ${id}` }));
      return screen.getByRole("dialog", { name: `Chạy lại job ${id}?` });
    };

    it("asks first, saying what the job is and what retrying does", async () => {
      const user = userEvent.setup();
      const log = serve({ retry: [{ job_id: 100412, status: "pending" }] });
      renderPage();
      await updated();
      const dialog = await open(user);
      expect(valueOf(dialog, "Loại")).toBe("triage");
      expect(valueOf(dialog, "Đối tượng")).toBe("alert-1661877");
      expect(valueOf(dialog, "Đã thử")).toBe("3 lần");
      expect(valueOf(dialog, "Lỗi cuối")).toBe("timeout after 120s");
      expect(dialog).toHaveTextContent("Job về lại hàng chờ của worker. Thao tác được ghi audit.");
      expect(within(dialog).getByRole("button", { name: "Huỷ" })).toBeInTheDocument();
      expect(within(dialog).getByRole("button", { name: "Chạy lại" })).toHaveFocus();
      expect(log.posts).toEqual([]);
    });

    it("sends nothing on Huỷ, closes, and gives the focus back to the button that opened it", async () => {
      const user = userEvent.setup();
      const log = serve({ retry: [{ job_id: 100412, status: "pending" }] });
      renderPage();
      await updated();
      const dialog = await open(user);
      await user.click(within(dialog).getByRole("button", { name: "Huỷ" }));
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Chạy lại job 100412" })).toHaveFocus();
      expect(log.posts).toEqual([]);
      expect(log.overview).toHaveLength(1);
    });

    it("sends nothing on Esc", async () => {
      const user = userEvent.setup();
      const log = serve({ retry: [{ job_id: 100412, status: "pending" }] });
      renderPage();
      await updated();
      await open(user);
      await user.keyboard("{Escape}");
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(log.posts).toEqual([]);
    });

    it("posts the job's id with a JSON body, once, on Chạy lại", async () => {
      const user = userEvent.setup();
      const log = serve({ retry: [{ job_id: 100398, status: "pending" }] });
      renderPage();
      await updated();
      const dialog = await open(user, 100398);
      await user.click(within(dialog).getByRole("button", { name: "Chạy lại" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
      expect(log.posts).toEqual([
        { path: "/api/admin/jobs/100398/retry", body: {}, contentType: "application/json" },
      ]);
    });

    it("is busy while the write is in flight: both buttons off, Esc does nothing, one post only", async () => {
      const user = userEvent.setup();
      const gate = deferred<Response>();
      const log = serve({ retry: [() => gate.promise] });
      renderPage();
      await updated();
      const dialog = await open(user);
      await user.click(within(dialog).getByRole("button", { name: "Chạy lại" }));
      const confirm = await within(dialog).findByRole("button", { name: "Đang xử lý…" });
      expect(confirm).toBeDisabled();
      expect(confirm).toHaveAttribute("aria-busy", "true");
      expect(within(dialog).getByRole("button", { name: "Huỷ" })).toBeDisabled();
      await user.keyboard("{Escape}");
      expect(screen.getByRole("dialog")).toBeInTheDocument();
      await user.click(confirm);
      expect(log.posts).toHaveLength(1);
      gate.resolve(HttpResponse.json({ job_id: 100412, status: "pending" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    });

    // Row 46: the shared latch. The confirm button is `disabled` one render late (TanStack Query tells React
    // a write is pending only through a `setTimeout(0)`), so two clicks of one tick both reach `mutate`.
    it("sends one POST for two clicks of Chạy lại in the same tick, before the dialog is busy", async () => {
      const user = userEvent.setup();
      const gate = deferred<Response>();
      const log = serve({ retry: [() => gate.promise] });
      renderPage();
      await updated();
      const dialog = await open(user);
      clickTwiceInOneTick(within(dialog).getByRole("button", { name: "Chạy lại" }));
      await within(dialog).findByRole("button", { name: "Đang xử lý…" });
      expect(log.posts).toHaveLength(1);
      gate.resolve(HttpResponse.json({ job_id: 100412, status: "pending" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
      expect(log.posts).toHaveLength(1);
    });

    it("can retry another job once the first write has settled: the latch is released", async () => {
      const user = userEvent.setup();
      const log = serve({
        retry: [
          { job_id: 100412, status: "pending" },
          { job_id: 100398, status: "pending" },
        ],
      });
      renderPage();
      await updated();
      await user.click(within(await open(user)).getByRole("button", { name: "Chạy lại" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
      await user.click(within(await open(user, 100398)).getByRole("button", { name: "Chạy lại" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
      expect(log.posts.map((p) => p.path)).toEqual([
        "/api/admin/jobs/100412/retry",
        "/api/admin/jobs/100398/retry",
      ]);
    });

    // Row 48: the write has committed, so the dialog and the toast do not wait for the overview to be read
    // again (nine sections, up to about 30 s in the worst case).
    it("closes the dialog and shows the toast at once, before the overview is read again", async () => {
      const user = userEvent.setup();
      const refetch = deferred<Response>();
      const log = serve({
        overviews: [overview(), () => refetch.promise],
        retry: [{ job_id: 100412, status: "pending" }],
      });
      renderPage();
      await updated();
      await user.click(within(await open(user)).getByRole("button", { name: "Chạy lại" }));
      await waitFor(() => expect(log.overview).toHaveLength(2));
      // the second read is out and held: the write is done and the page says so
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(within(jobsBlock()).getByRole("status")).toHaveTextContent(
        "Đã đặt job 100412 về hàng chờ.",
      );
      expect(
        within(jobsBlock()).getByRole("button", { name: "Chạy lại job 100412" }),
      ).toBeInTheDocument();
      refetch.resolve(HttpResponse.json(overview({ failed_jobs: JOBS.slice(1) })));
      await waitFor(() =>
        expect(
          within(jobsBlock()).queryByRole("button", { name: "Chạy lại job 100412" }),
        ).not.toBeInTheDocument(),
      );
      expect(within(jobsBlock()).getByText("2 job")).toBeInTheDocument();
    });

    it("is free for another job while the overview is still being read: that dialog is not busy and sends", async () => {
      const user = userEvent.setup();
      // Two reads are held by one gate (each builds its own Response: a body can be read only once).
      const gate = deferred<OverviewResponse>();
      const held = () => gate.promise.then((body) => HttpResponse.json(body));
      const log = serve({
        overviews: [overview(), held],
        retry: [
          { job_id: 100412, status: "pending" },
          { job_id: 100398, status: "pending" },
        ],
      });
      renderPage();
      await updated();
      await user.click(within(await open(user)).getByRole("button", { name: "Chạy lại" }));
      await waitFor(() => expect(log.overview).toHaveLength(2));
      const second = await open(user, 100398);
      const confirm = within(second).getByRole("button", { name: "Chạy lại" });
      expect(confirm).toBeEnabled();
      await user.click(confirm);
      await waitFor(() => expect(log.posts).toHaveLength(2));
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
      gate.resolve(overview({ failed_jobs: JOBS.slice(2) }));
      await waitFor(() => expect(within(jobsBlock()).getByText("1 job")).toBeInTheDocument());
    });

    // Row 51 (P11-T11 N4): the toast is in the block's own flow, as LlmPage's is in its page's, not a box
    // floating over the page.
    it("shows the toast inside the Job lỗi block, not floating over the page", async () => {
      const user = userEvent.setup();
      serve({ retry: [{ job_id: 100412, status: "pending" }] });
      const { container } = renderPage();
      await updated();
      await user.click(within(await open(user)).getByRole("button", { name: "Chạy lại" }));
      const toast = await within(jobsBlock()).findByRole("status");
      expect(toast).toHaveTextContent("Đã đặt job 100412 về hàng chờ.");
      expect(container.querySelector(".fixed")).toBeNull();
    });

    // Row 47: the row that opened the dialog leaves the list, so the focus the dialog gives back is lost.
    it("moves the focus to the Job lỗi heading after a successful retry, when the row that opened the dialog is gone", async () => {
      const user = userEvent.setup();
      const log = serve({
        overviews: [overview(), overview({ failed_jobs: JOBS.slice(1) })],
        retry: [{ job_id: 100412, status: "pending" }],
      });
      renderPage();
      await updated();
      await user.click(within(await open(user)).getByRole("button", { name: "Chạy lại" }));
      await waitFor(() => expect(log.overview).toHaveLength(2));
      await waitFor(() =>
        expect(
          within(jobsBlock()).queryByRole("button", { name: "Chạy lại job 100412" }),
        ).not.toBeInTheDocument(),
      );
      const heading = within(jobsBlock()).getByRole("heading", { name: "Job lỗi" });
      expect(heading).toHaveFocus();
      expect(heading).toHaveAttribute("tabindex", "-1");
    });

    it("does not take the focus to the heading when the retry is refused inside the dialog", async () => {
      const user = userEvent.setup();
      serve({ retry: [reason(409, "already_queued")] });
      renderPage();
      await updated();
      const dialog = await open(user);
      await user.click(within(dialog).getByRole("button", { name: "Chạy lại" }));
      await within(dialog).findByRole("alert");
      expect(screen.getByRole("dialog")).toBeInTheDocument();
      expect(within(jobsBlock()).getByRole("heading", { name: "Job lỗi" })).not.toHaveFocus();
    });

    it("reads the overview again, so the retried job leaves the list, and says it was done", async () => {
      const user = userEvent.setup();
      const log = serve({
        overviews: [overview(), overview({ failed_jobs: JOBS.slice(1) })],
        retry: [{ job_id: 100412, status: "pending" }],
      });
      renderPage();
      await updated();
      await user.click(
        within(await screen.findByRole("region", { name: "Job lỗi" })).getByRole("button", {
          name: "Chạy lại job 100412",
        }),
      );
      await user.click(
        within(screen.getByRole("dialog")).getByRole("button", { name: "Chạy lại" }),
      );
      await waitFor(() => expect(log.overview).toHaveLength(2));
      await waitFor(() =>
        expect(
          within(jobsBlock()).queryByRole("button", { name: "Chạy lại job 100412" }),
        ).not.toBeInTheDocument(),
      );
      expect(within(jobsBlock()).getByText("2 job")).toBeInTheDocument();
      const toast = screen.getByRole("status");
      expect(toast).toHaveTextContent("Đã đặt job 100412 về hàng chờ.");
      await user.click(within(toast).getByRole("button", { name: "Đóng" }));
      expect(screen.queryByRole("status")).not.toBeInTheDocument();
    });

    it("invalidates through the table of writes: the overview and the audit log, and nothing else", async () => {
      const user = userEvent.setup();
      serve({ retry: [{ job_id: 100412, status: "pending" }] });
      const client = newClient();
      const audit = ["admin", "audit", { range: "24h" }];
      const users = ["admin", "users"];
      client.setQueryData(audit, { events: [] });
      client.setQueryData(users, { users: [] });
      renderPage(client);
      await updated();
      await open(user);
      await user.click(
        within(screen.getByRole("dialog")).getByRole("button", { name: "Chạy lại" }),
      );
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
      expect(client.getQueryState(audit)?.isInvalidated).toBe(true);
      expect(client.getQueryState(users)?.isInvalidated).toBe(false);
    });

    describe("an answer that says no", () => {
      /** 409 not_failed and 404: the list on screen is stale, so the dialog closes, the list is read again, and the page says why. */
      it.each([
        ["409 not_failed", reason(409, "not_failed"), S.admin.reason.not_failed],
        ["404 not_found", reason(404, "not_found"), S.admin.reason.not_found],
      ])(
        "on %s closes the dialog, reloads the list and says why in the block",
        async (_name, answer, text) => {
          const user = userEvent.setup();
          const log = serve({
            overviews: [overview(), overview({ failed_jobs: JOBS.slice(1) })],
            retry: [answer],
          });
          renderPage();
          await updated();
          await open(user);
          await user.click(
            within(screen.getByRole("dialog")).getByRole("button", { name: "Chạy lại" }),
          );
          await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
          const alert = within(jobsBlock()).getByRole("alert");
          expect(alert).toHaveTextContent(text);
          await waitFor(() => expect(log.overview).toHaveLength(2));
          await waitFor(() =>
            expect(
              within(jobsBlock()).queryByRole("button", { name: "Chạy lại job 100412" }),
            ).not.toBeInTheDocument(),
          );
          expect(within(jobsBlock()).getByRole("alert")).toHaveTextContent(text);
          expect(screen.queryByRole("status")).not.toBeInTheDocument();
        },
      );

      // Row 48 for the two answers that reload the list: the dialog closes and the notice shows at once.
      it.each([
        ["409 not_failed", reason(409, "not_failed"), S.admin.reason.not_failed],
        ["404 not_found", reason(404, "not_found"), S.admin.reason.not_found],
      ])(
        "on %s closes the dialog and shows the notice before the overview is read again",
        async (_name, answer, text) => {
          const user = userEvent.setup();
          const refetch = deferred<Response>();
          const log = serve({
            overviews: [overview(), () => refetch.promise],
            retry: [answer],
          });
          renderPage();
          await updated();
          await open(user);
          await user.click(
            within(screen.getByRole("dialog")).getByRole("button", { name: "Chạy lại" }),
          );
          await waitFor(() => expect(log.overview).toHaveLength(2));
          expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
          expect(within(jobsBlock()).getByRole("alert")).toHaveTextContent(text);
          refetch.resolve(HttpResponse.json(overview({ failed_jobs: JOBS.slice(1) })));
          await waitFor(() =>
            expect(
              within(jobsBlock()).queryByRole("button", { name: "Chạy lại job 100412" }),
            ).not.toBeInTheDocument(),
          );
        },
      );

      // Row 47 for the same two answers: the notice is on screen, and the row that opened the dialog is gone.
      it.each([
        ["409 not_failed", reason(409, "not_failed")],
        ["404 not_found", reason(404, "not_found")],
      ])("on %s moves the focus to the Job lỗi heading", async (_name, answer) => {
        const user = userEvent.setup();
        const log = serve({
          overviews: [overview(), overview({ failed_jobs: JOBS.slice(1) })],
          retry: [answer],
        });
        renderPage();
        await updated();
        await open(user);
        await user.click(
          within(screen.getByRole("dialog")).getByRole("button", { name: "Chạy lại" }),
        );
        await waitFor(() => expect(log.overview).toHaveLength(2));
        await waitFor(() =>
          expect(
            within(jobsBlock()).queryByRole("button", { name: "Chạy lại job 100412" }),
          ).not.toBeInTheDocument(),
        );
        expect(within(jobsBlock()).getByRole("alert")).toBeInTheDocument();
        expect(within(jobsBlock()).getByRole("heading", { name: "Job lỗi" })).toHaveFocus();
      });

      it("says the 409 not_failed in the canvas's words", () => {
        expect(S.admin.reason.not_failed).toBe(
          "Job không còn ở trạng thái lỗi — đã được chạy lại hoặc đã xong. Danh sách đã được tải lại.",
        );
      });

      it("lets the admin dismiss that notice, and drops it when the next dialog opens", async () => {
        const user = userEvent.setup();
        serve({ retry: [reason(409, "not_failed")] });
        renderPage();
        await updated();
        await open(user);
        await user.click(
          within(screen.getByRole("dialog")).getByRole("button", { name: "Chạy lại" }),
        );
        const alert = await within(jobsBlock()).findByRole("alert");
        await user.click(within(alert).getByRole("button", { name: "Đóng" }));
        expect(within(jobsBlock()).queryByRole("alert")).not.toBeInTheDocument();
        // and again: the notice is dropped by opening another dialog
        await open(user);
        await user.click(
          within(screen.getByRole("dialog")).getByRole("button", { name: "Chạy lại" }),
        );
        await within(jobsBlock()).findByRole("alert");
        await open(user, 100398);
        expect(within(jobsBlock()).queryByRole("alert")).not.toBeInTheDocument();
      });

      it("on 409 already_queued keeps the dialog open and says why inside it, the list untouched", async () => {
        const user = userEvent.setup();
        const log = serve({ retry: [reason(409, "already_queued")] });
        renderPage();
        await updated();
        const dialog = await open(user);
        await user.click(within(dialog).getByRole("button", { name: "Chạy lại" }));
        const alert = await within(dialog).findByRole("alert");
        expect(alert).toHaveTextContent(S.admin.reason.already_queued);
        expect(S.admin.reason.already_queued).toBe(
          "Đã có một job cùng loại và cùng đối tượng đang chờ hoặc đang chạy, nên chưa chạy lại được.",
        );
        expect(screen.getByRole("dialog")).toBeInTheDocument();
        expect(within(dialog).getByRole("button", { name: "Chạy lại" })).toBeEnabled();
        expect(within(jobsBlock()).queryByRole("alert")).not.toBeInTheDocument();
        expect(log.overview).toHaveLength(1);
        expect(screen.queryByRole("status")).not.toBeInTheDocument();
      });

      it("lets the admin press Chạy lại again after already_queued, and the second answer closes the dialog", async () => {
        const user = userEvent.setup();
        const log = serve({
          retry: [reason(409, "already_queued"), { job_id: 100412, status: "pending" }],
        });
        renderPage();
        await updated();
        const dialog = await open(user);
        await user.click(within(dialog).getByRole("button", { name: "Chạy lại" }));
        await within(dialog).findByRole("alert");
        await user.click(within(dialog).getByRole("button", { name: "Chạy lại" }));
        await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
        expect(log.posts).toHaveLength(2);
        expect(screen.getByRole("status")).toHaveTextContent("Đã đặt job 100412 về hàng chờ.");
      });

      it("clears the dialog's error when the dialog is cancelled and opened again", async () => {
        const user = userEvent.setup();
        serve({ retry: [reason(409, "already_queued")] });
        renderPage();
        await updated();
        const dialog = await open(user);
        await user.click(within(dialog).getByRole("button", { name: "Chạy lại" }));
        await within(dialog).findByRole("alert");
        await user.click(within(dialog).getByRole("button", { name: "Huỷ" }));
        const again = await open(user);
        expect(within(again).queryByRole("alert")).not.toBeInTheDocument();
      });

      it.each([
        [
          "403 forbidden (the role changed)",
          status(403, { detail: "forbidden" }),
          S.admin.reason.forbidden,
        ],
        ["500", status(500, { detail: "Internal Server Error" }), S.common.unknownError],
        ["503", status(503, { detail: "auth disabled: JWT_SECRET unset" }), S.common.unknownError],
        [
          "422 in FastAPI's own shape",
          status(422, {
            detail: [{ type: "int_parsing", loc: ["path", "job_id"], msg: "bad", input: "x" }],
          }),
          S.common.unknownError,
        ],
        [
          "a 409 with a reason this page does not know",
          reason(409, "brand_new"),
          S.common.unknownError,
        ],
        ["a network failure", networkError, S.common.unknownError],
      ])(
        "on %s shows the text inside the dialog and leaves it open",
        async (_name, answer, text) => {
          const user = userEvent.setup();
          const log = serve({ retry: [answer] });
          renderPage();
          await updated();
          const dialog = await open(user);
          await user.click(within(dialog).getByRole("button", { name: "Chạy lại" }));
          expect(await within(dialog).findByRole("alert")).toHaveTextContent(text);
          expect(screen.queryByText("Internal Server Error")).not.toBeInTheDocument();
          expect(screen.queryByText(/auth disabled/)).not.toBeInTheDocument();
          expect(screen.getByRole("dialog")).toBeInTheDocument();
          expect(within(jobsBlock()).queryByRole("alert")).not.toBeInTheDocument();
          expect(log.overview).toHaveLength(1);
        },
      );
    });
  });

  it("shows a hostile last error and subject as text", async () => {
    const hostile = '<img src=x onerror="window.pwned=1"> </script><script>window.pwned=1</script>';
    const { container } = await renderLoaded({
      overviews: [
        overview({ failed_jobs: [job(5, { last_error: hostile, subject_id: hostile })] }),
      ],
    });
    expect(container.querySelector("img, script")).toBeNull();
    expect(within(jobsBlock()).getAllByText(hostile).length).toBeGreaterThanOrEqual(1);
  });
});

// ==============================================================================================================
describe("the inventory", () => {
  const inventory = () => block("Kiểm kê tài sản");
  const report = (over: Partial<LoadReport> = {}): LoadReport => ({
    assets: 6,
    identities: 3,
    iocs: 0,
    deactivated: 1,
    warnings: [],
    ...over,
  });
  const openReload = async (user: ReturnType<typeof userEvent.setup>) => {
    await user.click(within(inventory()).getByRole("button", { name: "Nạp lại kiểm kê" }));
    return screen.getByRole("dialog", { name: "Nạp lại kiểm kê?" });
  };

  it("asks first, naming the three files and what the reload does", async () => {
    const user = userEvent.setup();
    const log = serve({ reload: [report()] });
    renderPage();
    await updated();
    const dialog = await openReload(user);
    expect(dialog).toHaveTextContent(
      "Đọc lại inventory.yaml, identities.yaml và iocs.csv, rồi cập nhật cơ sở dữ liệu. Mục không còn trong tệp bị vô hiệu hoá. Alert đã nạp trước đó không được tính lại.",
    );
    expect(within(dialog).getByRole("button", { name: "Nạp lại" })).toHaveFocus();
    expect(log.posts).toEqual([]);
  });

  it("sends nothing on Huỷ and gives the focus back to the button", async () => {
    const user = userEvent.setup();
    const log = serve({ reload: [report()] });
    renderPage();
    await updated();
    const dialog = await openReload(user);
    await user.click(within(dialog).getByRole("button", { name: "Huỷ" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(within(inventory()).getByRole("button", { name: "Nạp lại kiểm kê" })).toHaveFocus();
    expect(log.posts).toEqual([]);
  });

  it("posts a JSON body once on Nạp lại, and is busy meanwhile", async () => {
    const user = userEvent.setup();
    const gate = deferred<Response>();
    const log = serve({ reload: [() => gate.promise] });
    renderPage();
    await updated();
    const dialog = await openReload(user);
    await user.click(within(dialog).getByRole("button", { name: "Nạp lại" }));
    const busy = await within(dialog).findByRole("button", { name: "Đang xử lý…" });
    expect(busy).toBeDisabled();
    await user.click(busy);
    expect(log.posts).toEqual([{ path: RELOAD_URL, body: {}, contentType: "application/json" }]);
    gate.resolve(HttpResponse.json(report()));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  // Row 46: the shared latch (see the retry dialog's test for why `disabled` is not enough).
  it("posts once for two clicks of Nạp lại in the same tick, before the dialog is busy", async () => {
    const user = userEvent.setup();
    const gate = deferred<Response>();
    const log = serve({ reload: [() => gate.promise] });
    renderPage();
    await updated();
    const dialog = await openReload(user);
    clickTwiceInOneTick(within(dialog).getByRole("button", { name: "Nạp lại" }));
    await within(dialog).findByRole("button", { name: "Đang xử lý…" });
    expect(log.posts).toEqual([{ path: RELOAD_URL, body: {}, contentType: "application/json" }]);
    gate.resolve(HttpResponse.json(report()));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(log.posts).toHaveLength(1);
  });

  it("can reload again once the first write has settled, after a failure too: the latch is released", async () => {
    const user = userEvent.setup();
    const log = serve({ reload: [status(500, { detail: "boom" }), report()] });
    renderPage();
    await updated();
    const dialog = await openReload(user);
    await user.click(within(dialog).getByRole("button", { name: "Nạp lại" }));
    await within(dialog).findByRole("alert");
    await user.click(within(dialog).getByRole("button", { name: "Nạp lại" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(log.posts).toHaveLength(2);
  });

  // Row 48: the files are loaded, so the dialog closes and the result shows before the overview is read again.
  it("closes the dialog and shows the result at once, before the overview is read again", async () => {
    const user = userEvent.setup();
    const refetch = deferred<Response>();
    const log = serve({
      overviews: [overview(), () => refetch.promise],
      reload: [report({ assets: 7, iocs: 2, deactivated: 1 })],
    });
    renderPage();
    await updated();
    await user.click(within(await openReload(user)).getByRole("button", { name: "Nạp lại" }));
    await waitFor(() => expect(log.overview).toHaveLength(2));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(within(inventory()).getByRole("status")).toHaveTextContent(
      "Đã nạp: 7 asset · 3 identity · 2 IoC · 1 mục bị vô hiệu hoá",
    );
    expect(valueOf(inventory(), "Asset đang dùng")).toBe("6");
    refetch.resolve(
      HttpResponse.json(
        overview({
          inventory: { assets: 7, identities: 3, iocs: 2, loaded_at: "2026-09-30T02:41:00+00:00" },
        }),
      ),
    );
    await waitFor(() => expect(valueOf(inventory(), "Asset đang dùng")).toBe("7"));
    expect(within(inventory()).getByRole("button", { name: "Nạp lại kiểm kê" })).toHaveFocus();
  });

  it("can reload again while the overview is still being read: the next dialog is not busy and sends", async () => {
    const user = userEvent.setup();
    // Two reads are held by one gate (each builds its own Response: a body can be read only once).
    const gate = deferred<OverviewResponse>();
    const held = () => gate.promise.then((body) => HttpResponse.json(body));
    const log = serve({ overviews: [overview(), held], reload: [report(), report({ assets: 8 })] });
    renderPage();
    await updated();
    await user.click(within(await openReload(user)).getByRole("button", { name: "Nạp lại" }));
    await waitFor(() => expect(log.overview).toHaveLength(2));
    const confirm = within(await openReload(user)).getByRole("button", { name: "Nạp lại" });
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    await waitFor(() => expect(log.posts).toHaveLength(2));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    gate.resolve(overview());
    await waitFor(() => expect(log.overview).toHaveLength(3));
  });

  it("shows the counts of what was loaded in the block, closes the dialog, and reads the overview again", async () => {
    const user = userEvent.setup();
    const log = serve({
      overviews: [
        overview(),
        overview({
          inventory: { assets: 7, identities: 3, iocs: 2, loaded_at: "2026-09-30T02:41:00+00:00" },
        }),
      ],
      reload: [report({ assets: 7, iocs: 2, deactivated: 1 })],
    });
    renderPage();
    await updated();
    const dialog = await openReload(user);
    await user.click(within(dialog).getByRole("button", { name: "Nạp lại" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    const result = await within(inventory()).findByRole("status");
    expect(result).toHaveTextContent("Đã nạp: 7 asset · 3 identity · 2 IoC · 1 mục bị vô hiệu hoá");
    await waitFor(() => expect(valueOf(inventory(), "Asset đang dùng")).toBe("7"));
    expect(log.overview).toHaveLength(2);
    expect(within(inventory()).queryByText(/cảnh báo/)).not.toBeInTheDocument();
    expect(within(inventory()).getByRole("button", { name: "Nạp lại kiểm kê" })).toHaveFocus();
  });

  it("invalidates the overview only: a reload is not in the audit log's table of writes", async () => {
    const user = userEvent.setup();
    serve({ reload: [report()] });
    const client = newClient();
    const audit = ["admin", "audit", { range: "24h" }];
    client.setQueryData(audit, { events: [] });
    renderPage(client);
    await updated();
    await user.click(within(await openReload(user)).getByRole("button", { name: "Nạp lại" }));
    await within(inventory()).findByRole("status");
    expect(client.getQueryState(audit)?.isInvalidated).toBe(false);
  });

  it("shows the warnings of the report with their count, without the 'warning: ' prefix the loader adds", async () => {
    const user = userEvent.setup();
    serve({
      reload: [
        report({
          deactivated: 0,
          warnings: [
            "warning: iocs.csv:3: expires_at 2026-01-01 is already in the past",
            'inventory.yaml: host "old-db" không còn trong tệp, đã vô hiệu hoá',
          ],
        }),
      ],
    });
    renderPage();
    await updated();
    await user.click(within(await openReload(user)).getByRole("button", { name: "Nạp lại" }));
    const result = await within(inventory()).findByRole("status");
    expect(within(result).getByText("2 cảnh báo")).toBeInTheDocument();
    expect(
      within(result)
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual([
      "iocs.csv:3: expires_at 2026-01-01 is already in the past",
      'inventory.yaml: host "old-db" không còn trong tệp, đã vô hiệu hoá',
    ]);
  });

  it("lets the admin dismiss the result", async () => {
    const user = userEvent.setup();
    serve({ reload: [report({ warnings: ["warning: x"] })] });
    renderPage();
    await updated();
    await user.click(within(await openReload(user)).getByRole("button", { name: "Nạp lại" }));
    const result = await within(inventory()).findByRole("status");
    await user.click(within(result).getByRole("button", { name: "Đóng" }));
    expect(within(inventory()).queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows the file errors of a 422 as a list, says the database did not change, and reads nothing again", async () => {
    const user = userEvent.setup();
    const log = serve({
      reload: [
        status(422, {
          detail: [
            'inventory.yaml:14: criticality "critical" không thuộc high | medium | low | unknown',
            "iocs.csv:2: reputation is empty",
          ],
        }),
      ],
    });
    renderPage();
    await updated();
    await user.click(within(await openReload(user)).getByRole("button", { name: "Nạp lại" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    const alert = await within(inventory()).findByRole("alert");
    expect(alert).toHaveTextContent(
      "Không nạp được — tệp kiểm kê không hợp lệ. Cơ sở dữ liệu không thay đổi.",
    );
    expect(
      within(alert)
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual([
      'inventory.yaml:14: criticality "critical" không thuộc high | medium | low | unknown',
      "iocs.csv:2: reputation is empty",
    ]);
    expect(log.overview).toHaveLength(1);
    expect(within(inventory()).queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows a single-text 422 the same way, as a list of one", async () => {
    const user = userEvent.setup();
    serve({ reload: [status(422, { detail: "inventory.yaml: empty file" })] });
    renderPage();
    await updated();
    await user.click(within(await openReload(user)).getByRole("button", { name: "Nạp lại" }));
    const alert = await within(inventory()).findByRole("alert");
    expect(
      within(alert)
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual(["inventory.yaml: empty file"]);
  });

  it("replaces a refusal with the result of the next reload, and the result with the next refusal", async () => {
    const user = userEvent.setup();
    serve({
      reload: [status(422, { detail: ["x: bad"] }), report(), status(422, { detail: ["y: bad"] })],
    });
    renderPage();
    await updated();
    for (const expectedRole of ["alert", "status", "alert"] as const) {
      await user.click(within(await openReload(user)).getByRole("button", { name: "Nạp lại" }));
      await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
      expect(await within(inventory()).findByRole(expectedRole)).toBeInTheDocument();
      expect(
        within(inventory()).queryByRole(expectedRole === "alert" ? "status" : "alert"),
      ).not.toBeInTheDocument();
    }
  });

  it.each([
    ["403 forbidden", status(403, { detail: "forbidden" }), S.admin.reason.forbidden],
    ["500", status(500, { detail: "Internal Server Error" }), S.common.unknownError],
    ["503", status(503, { detail: "auth disabled: JWT_SECRET unset" }), S.common.unknownError],
    ["a network failure", networkError, S.common.unknownError],
  ])(
    "on %s shows the text inside the dialog, leaves it open and shows no result",
    async (_name, answer, text) => {
      const user = userEvent.setup();
      serve({ reload: [answer] });
      renderPage();
      await updated();
      const dialog = await openReload(user);
      await user.click(within(dialog).getByRole("button", { name: "Nạp lại" }));
      expect(await within(dialog).findByRole("alert")).toHaveTextContent(text);
      expect(screen.queryByText("Internal Server Error")).not.toBeInTheDocument();
      expect(within(inventory()).queryByRole("status")).not.toBeInTheDocument();
      expect(screen.getByRole("dialog")).toBeInTheDocument();
    },
  );

  it("shows hostile warnings and file errors as text", async () => {
    const user = userEvent.setup();
    const hostile = '<img src=x onerror="window.pwned=1"><script>window.pwned=1</script>';
    serve({
      reload: [report({ warnings: [`warning: ${hostile}`] }), status(422, { detail: [hostile] })],
    });
    const { container } = renderPage();
    await updated();
    await user.click(within(await openReload(user)).getByRole("button", { name: "Nạp lại" }));
    await within(inventory()).findByRole("status");
    expect(container.querySelector("img, script")).toBeNull();
    expect(within(inventory()).getByText(hostile)).toBeInTheDocument();
    await user.click(within(await openReload(user)).getByRole("button", { name: "Nạp lại" }));
    await within(inventory()).findByRole("alert");
    expect(container.querySelector("img, script")).toBeNull();
    expect(within(inventory()).getByText(hostile)).toBeInTheDocument();
  });
});

// ==============================================================================================================
describe("the page renders nothing the server sent as markup", () => {
  it("shows a hostile source, agent, check and range name as plain text", async () => {
    const hostile = '<img src=x onerror="window.pwned=1"><script>window.pwned=1</script>';
    const { container } = await renderLoaded({
      overviews: [
        overview({
          by_source: { rows: [{ source: hostile, alerts: 1, heads: 1 }], rejected: 0 },
          top_agents: [{ agent_name: hostile, alerts: 1 }],
          health: {
            checked_at: "2026-09-30T02:40:00+00:00",
            ok: false,
            checks: [check(hostile, false, hostile)],
          },
        }),
      ],
    });
    expect(container.querySelector("img, script")).toBeNull();
    expect(within(block("Theo nguồn")).getByText(hostile)).toBeInTheDocument();
    expect(within(block("Agent nhiều alert nhất")).getByText(hostile)).toBeInTheDocument();
    expect(within(block("Sức khoẻ hệ thống")).getAllByText(hostile).length).toBeGreaterThanOrEqual(
      1,
    );
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
  });

  it("shows a hostile name that is a property of Object.prototype as text", async () => {
    await renderLoaded({
      overviews: [
        overview({
          top_agents: [{ agent_name: "__proto__", alerts: 4 }],
          funnel: {
            by_status: { constructor: 3 } as never,
            triage: { ready: 0, unavailable: 0, pending: 0, none: 0 },
          },
        }),
      ],
    });
    expect(within(block("Agent nhiều alert nhất")).getByText("__proto__")).toBeInTheDocument();
  });
});

// ==============================================================================================================
describe("the refresh", () => {
  it("reads the overview again every 60 seconds, and not before; the cost card is read with it", async () => {
    vi.useRealTimers();
    vi.useFakeTimers({
      toFake: ["Date", "setInterval", "clearInterval", "setTimeout", "clearTimeout"],
      shouldAdvanceTime: true,
    });
    vi.setSystemTime(new Date(NOW));
    const log = serve();
    renderPage();
    await updated();
    expect(log.overview).toHaveLength(1);
    await act(() => vi.advanceTimersByTimeAsync(50_000));
    expect(log.overview).toHaveLength(1);
    await act(() => vi.advanceTimersByTimeAsync(11_000));
    await waitFor(() => expect(log.overview).toHaveLength(2));
    await act(() => vi.advanceTimersByTimeAsync(60_000));
    await waitFor(() => expect(log.overview).toHaveLength(3));
    // there is no second read, with its own timer, behind the cost card
    expect(log.llm).toEqual([]);
  });

  it("is set to 60 s on the one read, and not in the background (the tab must be visible)", async () => {
    serve();
    const { client } = renderPage();
    await updated();
    const options = client
      .getQueryCache()
      .findAll()
      .map((q) => [
        q.queryKey,
        q.observers[0]?.options.refetchInterval,
        q.observers[0]?.options.refetchIntervalInBackground === true,
      ]);
    expect(options).toEqual([[adminKeys.overview("24h"), 60_000, false]]);
    expect(client.getQueryCache().findAll({ queryKey: adminKeys.llmAll })).toEqual([]);
  });
});

// ==============================================================================================================
describe("what the page reads and writes", () => {
  it("makes no request but the one read, and only the two writes a dialog confirms", async () => {
    const user = userEvent.setup();
    const log = serve({
      retry: [{ job_id: 100412, status: "pending" }],
      reload: [{ assets: 1, identities: 1, iocs: 1, deactivated: 0, warnings: [] }],
    });
    renderPage();
    await updated();
    await user.click(screen.getByRole("button", { name: "Chạy lại job 100412" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Chạy lại" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await user.click(screen.getByRole("button", { name: "Nạp lại kiểm kê" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Nạp lại" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(log.posts.map((p) => [p.path, p.contentType, p.body])).toEqual([
      ["/api/admin/jobs/100412/retry", "application/json", {}],
      [RELOAD_URL, "application/json", {}],
    ]);
    expect(log.llm).toEqual([]);
  });
});

// ==============================================================================================================
describe("what the page keeps equal to the backend", () => {
  const BACKEND = join("..", "backend", "app");
  const read = (...path: string[]) => readFileSync(join(BACKEND, ...path), "utf8");

  it("knows how many failed jobs the server sends at most", () => {
    const limit = /_FAILED_JOBS_LIMIT\s*=\s*(\d+)/.exec(
      read("web", "routers", "admin_overview.py"),
    )?.[1];
    expect(Number(limit)).toBe(FAILED_JOBS_CAP);
  });

  it("knows how many days each range covers", () => {
    const body = /_WINDOWS: dict\[str, timedelta\] = \{([\s\S]*?)\}/.exec(
      read("web", "routers", "admin_overview.py"),
    )?.[1];
    const windows = Object.fromEntries(
      [...(body ?? "").matchAll(/"(\w+)":\s*timedelta\((hours|days)=(\d+)\)/g)].map((m) => [
        m[1],
        m[2] === "hours" ? Number(m[3]) / 24 : Number(m[3]),
      ]),
    );
    expect(windows).toEqual(WINDOW_DAYS);
    expect(Object.keys(windows)).toEqual([...ADMIN_RANGES]);
  });

  it("has a Vietnamese label for each of the thirteen health checks of the backend, and no other", () => {
    const names = new Set(
      [...read("infra", "health.py").matchAll(/CheckResult\(\s*"([a-z_]+)"/g)].map((m) => m[1]),
    );
    expect(names.size).toBe(13);
    expect(Object.keys(S.admin.overviewPage.health.check).sort()).toEqual([...names].sort());
  });

  it("reads the alert statuses the schema has: the funnel's rows are real statuses", () => {
    const schema = readFileSync(join("..", "docs", "Schema", "schema.sql"), "utf8");
    const list =
      /CONSTRAINT ck_alerts_status CHECK \(status IN \(([\s\S]*?)\)\)/.exec(schema)?.[1] ?? "";
    const statuses = [...list.matchAll(/'([a-z_0-9]+)'/g)].map((m) => m[1]);
    for (const status of [
      "auto_closed",
      "queued_tier1",
      "tier1_active",
      "closed_fp",
      "closed_benign",
      "closed_confirmed",
      "escalated_tier2",
    ]) {
      expect(statuses).toContain(status);
    }
  });

  it("strips the same 'warning: ' prefix the inventory loader writes", () => {
    expect(/^WARNING = "(.*)"$/m.exec(read("enrichment", "inventory.py"))?.[1]).toBe("warning: ");
  });
});

// ==============================================================================================================
describe("accessibility", () => {
  it("has no axe violation on the loaded page", async () => {
    const { container } = await renderLoaded();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has none while loading", async () => {
    serve({ overviews: [() => new Promise<Response>(() => {})] });
    const { container } = renderPage();
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has none on a range with no alert", async () => {
    const { container } = await renderLoaded({
      overviews: [
        overview({
          alerts_by_day: [],
          top_agents: [],
          by_source: { rows: [], rejected: 0 },
          failed_jobs: [],
          health: null,
        }),
      ],
    });
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has none with every block failed", async () => {
    const { container } = await renderLoaded({ overviews: [failing(OVERVIEW_SECTIONS)] });
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has none with failing health checks", async () => {
    const checks = CHECK_NAMES.map((name) => check(name, name !== "disk_free"));
    const { container } = await renderLoaded({
      overviews: [
        overview({ health: { checked_at: "2026-09-30T02:40:00+00:00", ok: false, checks } }),
      ],
    });
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has none on the page error", async () => {
    serve({ overviews: [status(500)] });
    const { container } = renderPage();
    await screen.findByRole("alert");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has none with the retry dialog open, and with its error", async () => {
    const user = userEvent.setup();
    serve({ retry: [reason(409, "already_queued")] });
    const { container } = renderPage();
    await updated();
    await user.click(screen.getByRole("button", { name: "Chạy lại job 100412" }));
    expect(await axeViolations(container)).toEqual([]);
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Chạy lại" }));
    await within(screen.getByRole("dialog")).findByRole("alert");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has none with the reload dialog open, with the result and warnings, and with a refusal", async () => {
    const user = userEvent.setup();
    serve({
      reload: [
        { assets: 6, identities: 3, iocs: 0, deactivated: 1, warnings: ["warning: x"] },
        status(422, { detail: ["inventory.yaml:14: bad"] }),
      ],
    });
    const { container } = renderPage();
    await updated();
    await user.click(screen.getByRole("button", { name: "Nạp lại kiểm kê" }));
    expect(await axeViolations(container)).toEqual([]);
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Nạp lại" }));
    await within(block("Kiểm kê tài sản")).findByRole("status");
    expect(await axeViolations(container)).toEqual([]);
    await user.click(screen.getByRole("button", { name: "Nạp lại kiểm kê" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Nạp lại" }));
    await within(block("Kiểm kê tài sản")).findByRole("alert");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("has none with the not-failed notice and the toast on screen", async () => {
    const user = userEvent.setup();
    serve({ retry: [reason(409, "not_failed"), { job_id: 100398, status: "pending" }] });
    const { container } = renderPage();
    await updated();
    await user.click(screen.getByRole("button", { name: "Chạy lại job 100412" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Chạy lại" }));
    await within(block("Job lỗi")).findByRole("alert");
    expect(await axeViolations(container)).toEqual([]);
    await user.click(screen.getByRole("button", { name: "Chạy lại job 100398" }));
    await user.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Chạy lại" }));
    await screen.findByRole("status");
    expect(await axeViolations(container)).toEqual([]);
  });
});
