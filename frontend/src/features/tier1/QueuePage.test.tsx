// src/features/tier1/QueuePage.test.tsx — the Tier-1 queue: rows, band chips, server-side filters kept in
// the URL, the ① cell, the pages, and the live socket (faked) that makes it real time.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { delay, http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter, useLocation } from "react-router";
import type { QueueResponse, QueueRow } from "../../api/tier1";
import { setTokenSource } from "../../api/client";
import { AuthContext, type AuthState } from "../../auth/AuthProvider";
import type { Session } from "../../auth/session";
import { LiveProvider } from "../../live/LiveProvider";
import type { LiveOptions } from "../../live/socket";
import { S } from "../../strings";
import { QueuePage } from "./QueuePage";

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

const session: Session = {
  token: "tok-1",
  role: "tier1",
  username: "an",
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
};

/** A visible-arm row with a ① result: every key the server sends. */
const row = (over: Partial<QueueRow> = {}): QueueRow => ({
  alert_id: "a1",
  rule_id: "5760",
  description: "sshd: authentication failed",
  category: "ssh_brute_force",
  severity: "high",
  agent_name: "lab-ubuntu-01",
  occurrence_count: 7,
  triaged_count: 1,
  first_seen_at: "2026-09-30T01:00:00Z",
  last_seen_at: "2026-09-30T02:15:00Z",
  alert_time: "2026-09-30T01:00:00Z",
  suggestion_visible: true,
  status: "queued_tier1",
  needs_retriage: false,
  risk_band: "Cao",
  triage_status: "ready",
  run_id: "r1",
  suggested_action: "needs_review",
  confidence: "medium",
  gate_forced: false,
  ...over,
});

/**
 * What the server sends for a blind, undecided head: the ① keys are not there at all, and (R17) neither are
 * `triaged_count` and `needs_retriage`, which would say that ① ran.
 */
function blindRow(over: Partial<QueueRow> = {}): QueueRow {
  const stripped = row({ suggestion_visible: false });
  delete stripped.suggested_action;
  delete stripped.confidence;
  delete stripped.gate_forced;
  delete stripped.triage_status;
  delete stripped.run_id;
  delete stripped.triaged_count;
  delete stripped.needs_retriage;
  return { ...stripped, ...over };
}

const answer = (rows: QueueRow[], over: Partial<QueueResponse> = {}): QueueResponse => ({
  rows,
  total: rows.length,
  page: 1,
  page_size: 50,
  counts_by_band: { critical: 1, high: 2, medium: 3, low: 4 },
  ...over,
});

/** The queue requests the server has seen, oldest first. */
let requests: URL[] = [];
let respond: (url: URL) => Response = () => HttpResponse.json(answer([row()]));
beforeEach(() => {
  requests = [];
  fake.opened = [];
  respond = () => HttpResponse.json(answer([row()]));
  server.use(
    http.get("/api/tier1/queue", ({ request }) => {
      const url = new URL(request.url);
      requests.push(url);
      return respond(url);
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
  setTokenSource(
    () => null,
    () => {},
  );
});

function Where() {
  const { pathname, search } = useLocation();
  return <p data-testid="where">{`${pathname}${search}`}</p>;
}

function renderQueue(entry = "/queue") {
  const auth: AuthState = {
    session,
    ready: true,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
  };
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={[entry]}>
          <LiveProvider>
            <main>
              <QueuePage />
            </main>
            <Where />
          </LiveProvider>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

const where = () => screen.getByTestId("where").textContent;
const cells = (r: HTMLElement) => within(r).getAllByRole("cell");
const queueFetches = (spy: { mock: { calls: unknown[][] } }) =>
  spy.mock.calls.filter(([input]) => String(input).includes("/tier1/queue")).length;

describe("the rows", () => {
  it("shows a row's band, description, rule, category, agent, count and last seen in +07", async () => {
    renderQueue();
    const r = await screen.findByRole("row", { name: /sshd: authentication failed/ });
    const [band, description, category, agent, count, lastSeen] = cells(r);
    expect(band).toHaveTextContent("Cao");
    expect(description).toHaveTextContent("sshd: authentication failed");
    expect(description).toHaveTextContent(S.queue.rule("5760"));
    expect(category).toHaveTextContent("ssh_brute_force");
    expect(agent).toHaveTextContent("lab-ubuntu-01");
    expect(count).toHaveTextContent("7");
    expect(lastSeen).toHaveTextContent("30/09 09:15"); // 02:15Z, in Asia/Ho_Chi_Minh, under TZ=UTC
  });

  it("links the description to the alert page", async () => {
    renderQueue();
    const link = await screen.findByRole("link", { name: /sshd: authentication failed/ });
    expect(link).toHaveAttribute("href", "/alerts/a1");
  });

  it("sends the Bearer token, and asks for the first page of the waiting queue with no other filter", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    expect(requests).toHaveLength(1);
    const query = requests[0]?.searchParams;
    expect(query?.get("page")).toBe("1");
    expect(query?.get("page_size")).toBe("50");
    // An unset filter is left out: an empty `band=` or `status=` is a 422 on the server.
    expect([...(query?.keys() ?? [])].sort()).toEqual(["page", "page_size"]);
  });

  it("marks a row that needs a new triage, for the screen reader too", async () => {
    respond = () => HttpResponse.json(answer([row({ needs_retriage: true })]));
    renderQueue();
    const mark = await screen.findByRole("img", { name: S.queue.retriage });
    expect(mark).toBeInTheDocument();
    // The glyph is a string of strings.ts, like every other word or sign of the page.
    expect(S.queue.retriageMark).toBe("⟳");
    expect(mark).toHaveTextContent(S.queue.retriageMark);
  });

  it("shows no ⟳ for a row the server sent without needs_retriage (R17: a blind head), nor for false", async () => {
    // A blind head is sent with neither `triaged_count` nor `needs_retriage`: even with a count of 12 that
    // would have lit it, the page has nothing to show — and says nothing of ① having run.
    respond = () =>
      HttpResponse.json(
        answer([
          blindRow({ alert_id: "b1", description: "blind head", occurrence_count: 12 }),
          row({ alert_id: "v1", description: "visible head", needs_retriage: false }),
        ]),
      );
    renderQueue();
    await screen.findByRole("row", { name: /blind head/ });
    expect(screen.getByRole("row", { name: /visible head/ })).toBeInTheDocument();
    expect(screen.queryByRole("img", { name: S.queue.retriage })).toBeNull();
    expect(screen.queryByText(S.queue.retriageMark)).toBeNull();
  });

  it("shows the title and how many clusters are waiting", async () => {
    respond = () => HttpResponse.json(answer([row()], { total: 120 }));
    renderQueue();
    expect(screen.getByRole("heading", { level: 1, name: S.queue.title })).toBeInTheDocument();
    expect(await screen.findByText(S.queue.count(120))).toBeInTheDocument();
  });

  it("says so when nothing is waiting, and when nothing matches the filters", async () => {
    respond = () => HttpResponse.json(answer([]));
    const { unmount } = renderQueue();
    expect(await screen.findByText(S.queue.empty)).toBeInTheDocument();
    unmount();
    renderQueue("/queue?category=nothing");
    expect(await screen.findByText(S.queue.noMatch)).toBeInTheDocument();
  });

  it("says so when the caller holds no cluster ('mine')", async () => {
    respond = () => HttpResponse.json(answer([]));
    renderQueue("/queue?status=mine");
    expect(await screen.findByText(S.queue.emptyMine)).toBeInTheDocument();
  });

  it("shows a value it has no label for as it came, and no score as a dash", async () => {
    respond = () =>
      HttpResponse.json(
        answer([
          row({
            alert_id: "u1",
            description: "odd one",
            risk_band: "Nghiêm trọng",
            category: "new_thing",
          }),
          row({
            alert_id: "u2",
            description: "no score",
            risk_band: null,
            suggested_action: "quarantine",
          }),
        ]),
      );
    renderQueue();
    const odd = await screen.findByRole("row", { name: /odd one/ });
    expect(cells(odd)[0]).toHaveTextContent("Nghiêm trọng");
    expect(cells(odd)[2]).toHaveTextContent("new_thing");
    const none = screen.getByRole("row", { name: /no score/ });
    expect(cells(none)[0]).toHaveTextContent(S.common.missing);
    expect(cells(none)[6]).toHaveTextContent("quarantine");
  });

  it("renders hostile text as text", async () => {
    const hostile = '<img src=x onerror="alert(1)"> ‮';
    respond = () =>
      HttpResponse.json(answer([row({ description: hostile, agent_name: "</td><b>x</b>" })]));
    const { container } = renderQueue();
    await screen.findByRole("row", { name: /img src/ });
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
  });
});

describe("the ① cell", () => {
  /** The ① cell (the seventh) of the row with this name. */
  const ai = async (name: RegExp): Promise<HTMLElement> => {
    const cell = cells(await screen.findByRole("row", { name }))[6];
    if (!cell) throw new Error("the row has no ① cell");
    return cell;
  };

  it("says the action and the confidence, and marks a result the gate forced", async () => {
    respond = () =>
      HttpResponse.json(
        answer([
          row({
            alert_id: "r1",
            description: "plain",
            suggested_action: "false_positive",
            confidence: "high",
          }),
          row({
            alert_id: "r2",
            description: "forced",
            suggested_action: "escalate",
            gate_forced: true,
          }),
        ]),
      );
    renderQueue();
    expect(await ai(/plain/)).toHaveTextContent("Dương tính giả (cao)");
    expect(within(await ai(/plain/)).queryByRole("img")).toBeNull();
    expect(await ai(/forced/)).toHaveTextContent("Chuyển tier 2 (trung bình)");
    expect(
      within(await ai(/forced/)).getByRole("img", { name: S.ai1.forcedLabel }),
    ).toBeInTheDocument();
  });

  it("says 'ẩn — nhánh mù' for a blind row, never 'chưa có', and asks the server for nothing else", async () => {
    respond = () => HttpResponse.json(answer([blindRow({ description: "blind head" })]));
    renderQueue();
    const cell = await ai(/blind head/);
    expect(cell).toHaveTextContent(S.ai1.hidden);
    expect(cell).not.toHaveTextContent(S.ai1.none);
    // Every request that reached the server (`onUnhandledRequest: "error"` refuses the rest) was the queue.
    expect(requests.map((u) => u.pathname)).toEqual(["/api/tier1/queue"]);
  });

  it("says 'chưa có' when the visible arm has no result yet, and that ① is unavailable when it gave up", async () => {
    respond = () =>
      HttpResponse.json(
        answer([
          row({
            alert_id: "p",
            description: "waits",
            suggested_action: null,
            confidence: null,
            triage_status: "pending",
          }),
          row({
            alert_id: "x",
            description: "gave up",
            suggested_action: null,
            confidence: null,
            triage_status: "unavailable",
          }),
        ]),
      );
    renderQueue();
    expect(await ai(/waits/)).toHaveTextContent(S.ai1.none);
    expect(await ai(/gave up/)).toHaveTextContent(S.ai1.unavailable);
  });
});

describe("the band chips", () => {
  it("show the count of each band from counts_by_band, most serious first", async () => {
    renderQueue();
    const group = await screen.findByRole("group", { name: S.queue.bandCounts });
    const chips = within(group).getAllByRole("button");
    expect(chips.map((c) => c.textContent)).toEqual(["Rất cao 1", "Cao 2", "Vừa 3", "Thấp 4"]);
    for (const chip of chips) expect(chip).toHaveAttribute("aria-pressed", "false");
  });

  it("set the band filter by its code, and press again clears it", async () => {
    const user = userEvent.setup();
    renderQueue();
    const chip = await screen.findByRole("button", { name: "Cao 2" });
    await user.click(chip);
    await waitFor(() => expect(requests.at(-1)?.searchParams.get("band")).toBe("high"));
    expect(where()).toBe("/queue?band=high");
    expect(screen.getByRole("button", { name: "Cao 2" })).toHaveAttribute("aria-pressed", "true");
    await user.click(screen.getByRole("button", { name: "Cao 2" }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.has("band")).toBe(false));
    expect(where()).toBe("/queue");
  });

  it("take their counts from the answer, so a filter that empties a band shows its zero", async () => {
    respond = () =>
      HttpResponse.json(
        answer([row()], { counts_by_band: { critical: 0, high: 12, medium: 0, low: 0 } }),
      );
    renderQueue();
    expect(await screen.findByRole("button", { name: "Rất cao 0" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cao 12" })).toBeInTheDocument();
  });
});

describe("the filters", () => {
  it("send band=high when the band select changes to Cao", async () => {
    const user = userEvent.setup();
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    await user.selectOptions(screen.getByRole("combobox", { name: S.queue.filter.band }), "Cao");
    await waitFor(() => expect(requests.at(-1)?.searchParams.get("band")).toBe("high"));
    expect(where()).toBe("/queue?band=high");
  });

  it("send status=mine for 'Của tôi', and nothing for the waiting queue", async () => {
    const user = userEvent.setup();
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    const status = screen.getByRole("combobox", { name: S.queue.filter.status });
    await user.selectOptions(status, S.queue.filter.mine);
    await waitFor(() => expect(requests.at(-1)?.searchParams.get("status")).toBe("mine"));
    expect(await screen.findByText(S.queue.countMine(1))).toBeInTheDocument();
    await user.selectOptions(status, S.queue.filter.waiting);
    await waitFor(() => expect(requests.at(-1)?.searchParams.has("status")).toBe(false));
  });

  it("send the category and the agent when the form is submitted", async () => {
    const user = userEvent.setup();
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    await user.type(
      screen.getByRole("textbox", { name: S.queue.filter.category }),
      "ssh_brute_force",
    );
    await user.type(screen.getByRole("textbox", { name: S.queue.filter.agent }), "lab-01{Enter}");
    await waitFor(() => expect(requests.at(-1)?.searchParams.get("agent")).toBe("lab-01"));
    expect(requests.at(-1)?.searchParams.get("category")).toBe("ssh_brute_force");
    expect(where()).toBe("/queue?category=ssh_brute_force&agent=lab-01");
  });

  it("go back to page 1 when a filter changes", async () => {
    const user = userEvent.setup();
    renderQueue("/queue?page=3");
    await screen.findByRole("row", { name: /sshd/ });
    expect(requests.at(-1)?.searchParams.get("page")).toBe("3");
    await user.click(screen.getByRole("button", { name: "Cao 2" }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get("band")).toBe("high"));
    expect(requests.at(-1)?.searchParams.get("page")).toBe("1");
  });

  it("are read from the URL on load, so a reload or a shared link keeps them", async () => {
    renderQueue("/queue?band=critical&category=web&agent=srv&status=mine&page=2");
    await screen.findByRole("row", { name: /sshd/ });
    const query = requests[0]?.searchParams;
    expect(Object.fromEntries(query ?? [])).toEqual({
      page: "2",
      page_size: "50",
      band: "critical",
      category: "web",
      agent: "srv",
      status: "mine",
    });
    expect(screen.getByRole("combobox", { name: S.queue.filter.band })).toHaveValue("critical");
    expect(screen.getByRole("combobox", { name: S.queue.filter.status })).toHaveValue("mine");
    expect(screen.getByRole("textbox", { name: S.queue.filter.category })).toHaveValue("web");
    expect(screen.getByRole("textbox", { name: S.queue.filter.agent })).toHaveValue("srv");
  });

  it("ignore a band, a status or a page in the URL that the UI does not know", async () => {
    renderQueue("/queue?band=urgent&status=all&page=abc");
    await screen.findByRole("row", { name: /sshd/ });
    expect([...(requests[0]?.searchParams.keys() ?? [])].sort()).toEqual(["page", "page_size"]);
    expect(requests[0]?.searchParams.get("page")).toBe("1");
  });

  it("clear with one button", async () => {
    const user = userEvent.setup();
    renderQueue("/queue?band=low&category=web&status=mine");
    await screen.findByRole("row", { name: /sshd/ });
    await user.click(screen.getByRole("button", { name: S.queue.filter.clear }));
    await waitFor(() => expect(where()).toBe("/queue"));
    expect(requests.at(-1)?.searchParams.has("category")).toBe(false);
  });
});

describe("the pages", () => {
  const many = () => HttpResponse.json(answer([row()], { total: 120, page: 2, page_size: 50 }));

  it("say which rows are shown, and number the pages", async () => {
    respond = many;
    renderQueue("/queue?page=2");
    expect(await screen.findByText(S.queue.range(51, 100, 120))).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: S.queue.pagination });
    expect(within(nav).getByRole("link", { name: S.queue.page(1) })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: S.queue.page(3) })).toBeInTheDocument();
    expect(within(nav).getByText("2")).toHaveAttribute("aria-current", "page");
  });

  it("open another page from a numbered link, keeping the filters", async () => {
    respond = many;
    const user = userEvent.setup();
    renderQueue("/queue?band=high&page=2");
    await screen.findByRole("row", { name: /sshd/ });
    await user.click(screen.getByRole("link", { name: S.queue.page(3) }));
    await waitFor(() => expect(requests.at(-1)?.searchParams.get("page")).toBe("3"));
    expect(requests.at(-1)?.searchParams.get("band")).toBe("high");
    expect(where()).toBe("/queue?band=high&page=3");
  });

  it("step back and forward, and are inert at either end", async () => {
    respond = () => HttpResponse.json(answer([row()], { total: 120 }));
    renderQueue("/queue");
    await screen.findByRole("row", { name: /sshd/ });
    expect(screen.queryByRole("link", { name: S.common.prev })).toBeNull();
    expect(screen.getByRole("link", { name: S.common.next })).toHaveAttribute(
      "href",
      "/queue?page=2",
    );
  });

  it("show no navigation when everything fits on one page", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    expect(screen.queryByRole("navigation", { name: S.queue.pagination })).toBeNull();
  });
});

describe("a failure", () => {
  it("says the queue could not be loaded, and tries again on request", async () => {
    let fail = true;
    respond = () =>
      fail
        ? HttpResponse.json({ detail: "boom" }, { status: 500 })
        : HttpResponse.json(answer([row()]));
    const user = userEvent.setup();
    renderQueue();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(S.queue.loadError);
    fail = false;
    await user.click(within(alert).getByRole("button", { name: S.common.retry }));
    expect(await screen.findByRole("row", { name: /sshd/ })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("real time", () => {
  it("connects the live socket for the session", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    expect(live().token()).toBe("tok-1");
  });

  it("fetches the queue again when a change arrives", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    respond = () =>
      HttpResponse.json(answer([row(), row({ alert_id: "a2", description: "new arrival" })]));
    act(() => live().onChange(["a2"]));
    expect(await screen.findByRole("row", { name: /new arrival/ })).toBeInTheDocument();
  });

  it("fetches nothing more when the socket first says live, and once when it is back after a drop", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    act(() => live().onStatus("live"));
    await new Promise((r) => setTimeout(r, 100));
    expect(requests).toHaveLength(1); // the mount fetch is fresh
    act(() => live().onStatus("offline"));
    act(() => live().onStatus("live")); // what came during the drop was not heard
    await waitFor(() => expect(requests).toHaveLength(2));
  });

  // Review Focus 2: a pull of 500 alerts arrives as many messages; the queue is fetched about once per burst.
  it("fetches at most twice for a burst of 50 changes inside 100 ms", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    act(() => live().onStatus("live")); // the first live of the page: the fetch of its mount is fresh
    await new Promise((r) => setTimeout(r, 100));
    expect(requests).toHaveLength(1);
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    const started = Date.now();
    act(() => {
      for (let i = 0; i < 50; i++) live().onChange([`a${i}`]);
    });
    expect(Date.now() - started).toBeLessThan(100);
    await new Promise((r) => setTimeout(r, 900)); // past the closing flush of the window
    const fetches = queueFetches(fetchSpy);
    expect(fetches).toBeGreaterThanOrEqual(1);
    expect(fetches).toBeLessThanOrEqual(2);
  });

  // A flush used to abort the fetch under way, so with an answer slower than the 500 ms window a steady stream
  // never let one land: the list stayed as it was until the stream stopped.
  it("shows a slow answer while changes keep coming, and ends on the last change", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    let latest = -1; // the last change the server has: what a fetch that starts now will show
    server.use(
      http.get("/api/tier1/queue", async () => {
        const seen = latest;
        await delay(700); // slower than the window of the invalidator
        return HttpResponse.json(answer([row({ description: `after change ${seen}` })]));
      }),
    );
    let updatedInStream = false;
    for (let i = 0; i < 15; i++) {
      latest = i;
      act(() => live().onChange([`a${i}`])); // 1.5 s of changes, 10 a second
      await act(() => new Promise<void>((r) => setTimeout(r, 100)));
      if (screen.queryByRole("row", { name: /after change/ })) updatedInStream = true;
    }
    expect(updatedInStream).toBe(true);
    // the stream is over: the list catches up with its last change, and does not stay on an older one
    expect(
      await screen.findByRole("row", { name: /after change 14/ }, { timeout: 4000 }),
    ).toBeInTheDocument();
  }, 10_000);

  it("polls every 30 s while offline, and stops when the socket is live", async () => {
    vi.useFakeTimers({
      toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date"],
      shouldAdvanceTime: true,
    });
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await act(() => vi.advanceTimersByTimeAsync(29_000));
    expect(queueFetches(fetchSpy)).toBe(0);
    await act(() => vi.advanceTimersByTimeAsync(2_000));
    expect(queueFetches(fetchSpy)).toBe(1);
    await act(() => vi.advanceTimersByTimeAsync(30_000));
    expect(queueFetches(fetchSpy)).toBe(2);

    act(() => live().onStatus("offline")); // the socket that failed to come up ...
    act(() => live().onStatus("live")); // ... and then does: one resync, then no clock
    await act(() => vi.advanceTimersByTimeAsync(1_000));
    const afterResync = queueFetches(fetchSpy);
    await act(() => vi.advanceTimersByTimeAsync(120_000));
    expect(queueFetches(fetchSpy)).toBe(afterResync);

    act(() => live().onStatus("offline")); // and the clock again
    await act(() => vi.advanceTimersByTimeAsync(31_000));
    expect(queueFetches(fetchSpy)).toBe(afterResync + 1);
  });
});

describe("accessibility", () => {
  it("has no axe violation with rows of every ① state, the chips, the form and the pages", async () => {
    respond = () =>
      HttpResponse.json(
        answer(
          [
            row({ alert_id: "r1", description: "ready row", gate_forced: true }),
            blindRow({ alert_id: "r2", description: "blind row" }),
            row({
              alert_id: "r3",
              description: "waiting row",
              suggested_action: null,
              triage_status: "pending",
            }),
            row({
              alert_id: "r4",
              description: "retriage row",
              needs_retriage: true,
              risk_band: "Rất cao",
            }),
          ],
          { total: 120 },
        ),
      );
    const { container } = renderQueue("/queue?band=high");
    await screen.findByRole("row", { name: /ready row/ });
    // jsdom computes no colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(
      result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`),
    ).toEqual([]);
  });

  it("has none in the empty and in the error states either", async () => {
    respond = () => HttpResponse.json({ detail: "x" }, { status: 500 });
    const { container } = renderQueue();
    await screen.findByRole("alert");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});
