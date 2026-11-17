// src/features/ti/TiPage.test.tsx — the page "Threat Intel" top to bottom: the status bar and its stale banner, the four KPI cards, the two
// charts, the table's states, and what each section says when its own read is busy, refused or fails.
import { QueryClient } from "@tanstack/react-query";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { shouldRetry } from "../../api/queryClient";
import { S } from "../../strings";
import { tiFixture } from "./fixtures";
import { busy, fake, renderTi, serve } from "./testkit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const table = () => screen.findByRole("table", { name: S.ti.tableLabel });
const group = (name: string) => screen.getByRole("group", { name });

describe("the layout", () => {
  it("has the title, then the status bar, the KPI cards, the charts and the table, in that order", async () => {
    serve(server, fake());
    renderTi();
    const tbl = await table();
    const title = screen.getByRole("heading", { level: 1, name: S.ti.title });
    const status = await screen.findByRole("region", { name: S.ti.status.label });
    const kpi = await screen.findByRole("region", { name: S.ti.kpi.label });
    const charts = await screen.findByRole("region", { name: S.ti.charts.label });
    const filters = screen.getByRole("search", { name: S.ti.filters.label });
    const order = [title, status, kpi, charts, filters, tbl];
    for (let i = 1; i < order.length; i += 1) {
      const before = order[i - 1] as Element;
      const after = order[i] as Element;
      expect(
        before.compareDocumentPosition(after) & Node.DOCUMENT_POSITION_FOLLOWING,
        String(i),
      ).toBeTruthy();
    }
  });

  it("says how many IOCs the list has", async () => {
    serve(server, fake({ total: 4321 }));
    renderTi();
    expect(await screen.findByText(S.ti.count(4321))).toBeInTheDocument();
  });

  it("has no 'Tìm trong log' button and nothing for log matching or AI summaries (section 6 is not built)", async () => {
    serve(server, fake());
    renderTi({ role: "admin" });
    await table();
    expect(screen.queryByText(/tìm trong log/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/tóm tắt|giải thích AI|AI summary/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /log/i })).not.toBeInTheDocument();
  });
});

describe("the status bar", () => {
  it("says when the last import finished, in GMT+7, and how many IOCs were new", async () => {
    // 2026-11-17T00:10:05Z is 07:10:05 in GMT+7
    serve(server, fake());
    renderTi();
    const bar = await screen.findByRole("region", { name: S.ti.status.label });
    expect(await within(bar).findByText(S.ti.status.at("17/11/2026 07:10:05"))).toBeInTheDocument();
    expect(within(bar).getByText(S.ti.status.newCount(37))).toBeInTheDocument();
    expect(within(bar).getByText(S.ti.status.updatedCount(163))).toBeInTheDocument();
    expect(within(bar).getByText(S.ti.status.errorCount(0))).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("shows a red banner when the data is stale, and says for how long", async () => {
    serve(
      server,
      fake({
        status: tiFixture.status({
          stale: true,
          latest_success: tiFixture.log({ finished_at: "2026-11-15T00:10:05.000000+00:00" }),
        }),
      }),
    );
    renderTi();
    const banner = await screen.findByRole("alert");
    expect(banner).toHaveTextContent(S.ti.status.stale(26));
    // red: the critical tokens, as the web's own error lines have
    expect(banner.className).toMatch(/border-critical/);
    expect(banner.className).toMatch(/text-critical/);
  });

  it("is stale and says there never was an import when there is none", async () => {
    serve(
      server,
      fake({
        status: tiFixture.status({ stale: true, latest: null, latest_success: null }),
      }),
    );
    renderTi();
    expect(await screen.findByRole("alert")).toHaveTextContent(S.ti.status.staleNever);
    expect(screen.getByText(S.ti.status.never)).toBeInTheDocument();
  });

  it("says so when the newest run failed, and still shows the last good import", async () => {
    const good = tiFixture.log({ id: 7 });
    const failed = tiFixture.log({
      id: 8,
      status: "failed",
      rows_new: 0,
      finished_at: "2026-11-17T01:00:00.000000+00:00",
      message: "no_file",
    });
    serve(server, fake({ status: tiFixture.status({ latest: failed, latest_success: good }) }));
    renderTi();
    const bar = await screen.findByRole("region", { name: S.ti.status.label });
    expect(
      await within(bar).findByText(S.ti.status.failedLast("17/11/2026 08:00:00")),
    ).toBeInTheDocument();
    expect(within(bar).getByText(S.ti.status.newCount(37))).toBeInTheDocument();
  });
});

describe("the KPI cards", () => {
  it("shows new today, confidence at or above 75, the top three malware with counts, and matched in logs", async () => {
    serve(server, fake());
    renderTi();
    await screen.findByRole("region", { name: S.ti.kpi.label });
    expect(group(S.ti.kpi.today)).toHaveTextContent("200");
    expect(group(S.ti.kpi.high(75))).toHaveTextContent("57");
    expect(group(S.ti.kpi.matched)).toHaveTextContent("0");
    const top = group(S.ti.kpi.top);
    expect(
      within(top)
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual([
      S.ti.kpi.topItem("Example.Rat", 42),
      S.ti.kpi.topItem("Example.Loader", 31),
      S.ti.kpi.topItem("Example.Dropper", 18),
    ]);
  });

  it("takes the top three from top_malware and never from newest_malware", async () => {
    serve(server, fake());
    renderTi();
    await screen.findByRole("region", { name: S.ti.kpi.label });
    expect(group(S.ti.kpi.top)).not.toHaveTextContent("Example.Newest");
    expect(group(S.ti.kpi.top)).not.toHaveTextContent("Example.Stealer");
  });

  it("says there is none when no malware is named, and shows a plain zero as 0", async () => {
    serve(
      server,
      fake({ stats: tiFixture.stats({ top_malware: [], imported_today: 0, high_confidence: 0 }) }),
    );
    renderTi();
    await screen.findByRole("region", { name: S.ti.kpi.label });
    expect(group(S.ti.kpi.top)).toHaveTextContent(S.ti.kpi.topEmpty);
    expect(group(S.ti.kpi.today)).toHaveTextContent(/^.*0$/);
  });

  it("asks for the thirty days, and carries no filter of the list", async () => {
    const state = fake();
    serve(server, state);
    renderTi({ entry: "/threat-intel?source=urlhaus&q=abc&min_confidence=75" });
    await screen.findByRole("region", { name: S.ti.kpi.label });
    expect(state.statsRequests.map((u) => u.search)).toEqual(["?days=30"]);
  });
});

describe("the charts", () => {
  it("draws the thirty days of the series and the top ten malware from the stats", async () => {
    serve(server, fake());
    const view = renderTi();
    const charts = await screen.findByRole("region", { name: S.ti.charts.label });
    expect(
      within(charts).getByRole("heading", { name: S.ti.charts.perDay.title(30) }),
    ).toBeInTheDocument();
    expect(
      within(charts).getByRole("heading", { name: S.ti.charts.topMalware.title }),
    ).toBeInTheDocument();
    expect(view.container.querySelectorAll("g[data-day]")).toHaveLength(30);
    expect(view.container.querySelectorAll("g[data-row]")).toHaveLength(5);
    expect(view.container.querySelectorAll("rect[data-source]").length).toBeGreaterThan(30);
  });
});

describe("the table's states", () => {
  it("is a loading line until the first list arrives", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const state = fake();
    state.list = async () => {
      await gate;
      return undefined;
    };
    serve(server, state);
    renderTi();
    expect(screen.getAllByText(S.common.loading).length).toBeGreaterThan(0);
    expect(screen.queryByRole("table", { name: S.ti.tableLabel })).not.toBeInTheDocument();
    release();
    await table();
  });

  it("says there is no IOC when there is none, and says nothing matches when a filter is set", async () => {
    serve(server, fake({ rows: [], total: 0 }));
    const view = renderTi();
    await table();
    expect(screen.getByText(S.ti.empty)).toBeInTheDocument();
    view.unmount();
    serve(server, fake({ rows: [], total: 0 }));
    renderTi({ entry: "/threat-intel?source=urlhaus" });
    await table();
    expect(screen.getByText(S.ti.emptyFiltered)).toBeInTheDocument();
  });
});

describe("a read that is busy, refused or failing", () => {
  it("says 'busy, try again' for a 503 timeout on the list, in the page's words, and retries", async () => {
    const state = fake();
    let first = true;
    state.list = () => {
      if (first) {
        first = false;
        return busy();
      }
      return undefined;
    };
    serve(server, state);
    const user = userEvent.setup();
    renderTi();
    const note = await screen.findByText(S.ti.busy);
    expect(note.closest("[role]")).toHaveAttribute("role", "status");
    expect(screen.queryByText(S.ti.loadError.list)).not.toBeInTheDocument();
    await user.click(
      within(note.closest("[role]") as HTMLElement).getByRole("button", { name: S.common.retry }),
    );
    await table();
    expect(screen.queryByText(S.ti.busy)).not.toBeInTheDocument();
    expect(state.lists).toHaveLength(2);
  });

  it("says busy for the stats and for the status as well, each in its own place, and the table still shows", async () => {
    const state = fake();
    state.statsAnswer = busy;
    state.statusAnswer = busy;
    serve(server, state);
    renderTi();
    await table();
    const notes = await screen.findAllByText(S.ti.busy);
    expect(notes).toHaveLength(2);
    expect(screen.getByRole("region", { name: S.ti.status.label })).toContainElement(
      notes[0] as HTMLElement,
    );
    expect(screen.getByText("203.0.113[.]7:443")).toBeInTheDocument();
  });

  it("is an error line with a retry for any other failure, and the generic words, never the busy ones", async () => {
    const state = fake();
    state.list = () => HttpResponse.json({ detail: "boom" }, { status: 500 });
    serve(server, state);
    renderTi();
    const line = await screen.findByText(S.ti.loadError.list);
    expect(line.closest("[role]")).toHaveAttribute("role", "alert");
    expect(screen.queryByText(S.ti.busy)).not.toBeInTheDocument();
  });

  it("does not take another 503 for 'busy'", async () => {
    const state = fake();
    state.list = () => HttpResponse.json({ detail: "service down" }, { status: 503 });
    serve(server, state);
    renderTi();
    expect(await screen.findByText(S.ti.loadError.list)).toBeInTheDocument();
    expect(screen.queryByText(S.ti.busy)).not.toBeInTheDocument();
  });

  it("follows the other pages for a 403: the web's own refusal text, not an error line", async () => {
    const state = fake();
    state.list = () => HttpResponse.json({ detail: "forbidden" }, { status: 403 });
    serve(server, state);
    renderTi();
    expect(await screen.findByText(S.forbidden)).toBeInTheDocument();
    expect(screen.queryByText(S.ti.loadError.list)).not.toBeInTheDocument();
  });

  it("hands a 401 to the session, as every page does, and shows neither 'busy' nor a refusal", async () => {
    const state = fake();
    state.list = () => HttpResponse.json({ detail: "no" }, { status: 401 });
    serve(server, state);
    const onUnauthorized = vi.fn();
    renderTi({ onUnauthorized });
    await waitFor(() => expect(onUnauthorized).toHaveBeenCalled());
    expect(screen.queryByText(S.ti.busy)).not.toBeInTheDocument();
    expect(screen.queryByText(S.forbidden)).not.toBeInTheDocument();
  });
});

// TI12 M3: the app's query client retries a 5xx twice, which on a database that is already too busy to answer in time runs the same
// statement three times before the page says it is busy. A 503 `timeout` is not retried; any other failure keeps the app's own rule.
describe("a busy read is asked once", () => {
  const appClient = () =>
    new QueryClient({ defaultOptions: { queries: { retry: shouldRetry, retryDelay: 0 } } });
  const quiet = () => new Promise((resolve) => setTimeout(resolve, 150));

  it("asks the list once when it is busy, the stats once, the status once", async () => {
    const state = fake();
    state.list = busy;
    state.statsAnswer = busy;
    state.statusAnswer = busy;
    serve(server, state);
    renderTi({ client: appClient() });
    expect(await screen.findAllByText(S.ti.busy)).toHaveLength(3);
    await quiet();
    expect(state.lists).toHaveLength(1);
    expect(state.statsRequests).toHaveLength(1);
    expect(state.statusRequests).toBe(1);
  });

  it("keeps the app's rule for another failure: asked three times (two retries) before the error line", async () => {
    const state = fake();
    state.list = () => HttpResponse.json({ detail: "boom" }, { status: 500 });
    state.statsAnswer = () => HttpResponse.json({ detail: "boom" }, { status: 502 });
    state.statusAnswer = () => HttpResponse.json({ detail: "boom" }, { status: 500 });
    serve(server, state);
    renderTi({ client: appClient() });
    expect(await screen.findByText(S.ti.loadError.list)).toBeInTheDocument();
    expect(await screen.findByText(S.ti.loadError.stats)).toBeInTheDocument();
    expect(await screen.findByText(S.ti.loadError.status)).toBeInTheDocument();
    expect(state.lists).toHaveLength(3);
    expect(state.statsRequests).toHaveLength(3);
    expect(state.statusRequests).toBe(3);
  });

  it("does not retry a 503 that is not the timeout either way round: only {reason: timeout} is busy", async () => {
    const state = fake();
    state.list = () => HttpResponse.json({ detail: "service down" }, { status: 503 });
    serve(server, state);
    renderTi({ client: appClient() });
    expect(await screen.findByText(S.ti.loadError.list)).toBeInTheDocument();
    expect(state.lists).toHaveLength(3);
  });

  it("uses what the client says for the rest: a client that never retries asks once", async () => {
    const state = fake();
    state.list = () => HttpResponse.json({ detail: "boom" }, { status: 500 });
    serve(server, state);
    renderTi();
    expect(await screen.findByText(S.ti.loadError.list)).toBeInTheDocument();
    await quiet();
    expect(state.lists).toHaveLength(1);
  });
});
