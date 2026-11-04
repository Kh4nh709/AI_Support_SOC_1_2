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
  alert_user: "alice",
  srcip: "203.0.113.9",
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
  it("shows a row's band, description, rule, category, agent, user, source IP, count and last seen in +07", async () => {
    renderQueue();
    const r = await screen.findByRole("row", { name: /sshd: authentication failed/ });
    const [band, description, category, agent, user, srcip, count, lastSeen] = cells(r);
    expect(band).toHaveTextContent("Cao");
    expect(description).toHaveTextContent("sshd: authentication failed");
    expect(description).toHaveTextContent(S.queue.rule("5760"));
    expect(category).toHaveTextContent("ssh_brute_force");
    expect(agent).toHaveTextContent("lab-ubuntu-01");
    expect(user).toHaveTextContent("alice");
    expect(srcip).toHaveTextContent("203.0.113.9");
    expect(count).toHaveTextContent("7");
    expect(lastSeen).toHaveTextContent("30/09 09:15"); // 02:15Z, in Asia/Ho_Chi_Minh, under TZ=UTC
  });

  // P10-T15 (DEC-165): with grouping off every alert is its own row, so the row says whose alert it is and
  // where it came from. The two columns sit right after Agent; neither is sortable; ① stays the last.
  it("has the User and IP nguồn columns right after Agent, in Vietnamese, with no sort button", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    expect(S.queue.col.user).toBe("User");
    expect(S.queue.col.srcip).toBe("IP nguồn");
    const headers = screen.getAllByRole("columnheader").map((th) => th.textContent ?? "");
    const at = (label: string) => headers.findIndex((text) => text.startsWith(label));
    expect(at(S.queue.col.user)).toBe(at(S.queue.col.agent) + 1);
    expect(at(S.queue.col.srcip)).toBe(at(S.queue.col.agent) + 2);
    expect(at(S.queue.col.ai)).toBe(headers.length - 1);
    for (const name of [S.queue.col.user, S.queue.col.srcip]) {
      const th = screen.getByRole("columnheader", { name });
      expect(within(th).queryByRole("button")).toBeNull();
      expect(th).not.toHaveAttribute("aria-sort");
    }
  });

  it("shows a dash for a null user and for a missing or empty source IP, on a visible and a blind row", async () => {
    // `alert_user` is nullable and `srcip` is TEXT NOT NULL DEFAULT '' in the schema: the server sends both raw.
    respond = () =>
      HttpResponse.json(
        answer([
          row({
            alert_id: "n1",
            description: "null user",
            alert_user: null,
            srcip: "198.51.100.4",
          }),
          row({ alert_id: "n2", description: "empty ip", alert_user: "bob", srcip: "" }),
          blindRow({ alert_id: "n3", description: "blind null", alert_user: null, srcip: "" }),
          blindRow({ alert_id: "n4", description: "blind has both", alert_user: "eve" }),
        ]),
      );
    renderQueue();
    const userAndIp = async (name: RegExp) => {
      const r = await screen.findByRole("row", { name });
      return [cells(r)[4]?.textContent, cells(r)[5]?.textContent];
    };
    expect(await userAndIp(/null user/)).toEqual([S.common.missing, "198.51.100.4"]);
    expect(await userAndIp(/empty ip/)).toEqual(["bob", S.common.missing]);
    expect(await userAndIp(/blind null/)).toEqual([S.common.missing, S.common.missing]);
    // A blind head keeps both: neither is derived from ① (DEC-101, R12).
    expect(await userAndIp(/blind has both/)).toEqual(["eve", "203.0.113.9"]);
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
    expect(cells(none)[8]).toHaveTextContent("quarantine");
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
  /** The ① cell (the ninth, after User and IP nguồn) of the row with this name. */
  const ai = async (name: RegExp): Promise<HTMLElement> => {
    const cell = cells(await screen.findByRole("row", { name }))[8];
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
            suggested_action: "true_positive",
            gate_forced: true,
          }),
        ]),
      );
    renderQueue();
    expect(await ai(/plain/)).toHaveTextContent("FP (cao)");
    expect(within(await ai(/plain/)).queryByRole("img")).toBeNull();
    expect(await ai(/forced/)).toHaveTextContent("TP (trung bình)");
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

// P10-T14 (DEC-164): the queue sorts on the server by last seen, occurrences or agent. The three headers are
// buttons; the sort is in the URL (`sort`, `dir`), and the default risk order is the absence of both.
describe("the sort", () => {
  const header = (name: string) => screen.getByRole("columnheader", { name });
  const sortButton = (name: string) => screen.getByRole("button", { name });
  /** Whether "Sắp theo mức rủi ro" is a control the reader can use now. It is never `aria-pressed`. */
  const riskOrderOffered = () => {
    const byRisk = sortButton(S.queue.sort.byRisk);
    expect(byRisk).not.toHaveAttribute("aria-pressed");
    return byRisk.getAttribute("aria-disabled") !== "true";
  };
  const sortedHeaders = () =>
    screen
      .getAllByRole("columnheader")
      .filter((th) => th.hasAttribute("aria-sort"))
      .map((th) => [th.textContent, th.getAttribute("aria-sort")]);
  const lastQuery = () => requests.at(-1)?.searchParams;

  it("has a button in the header of last seen, occurrences and agent, and in no other", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    for (const name of [S.queue.col.lastSeen, S.queue.col.occurrences, S.queue.col.agent]) {
      expect(within(header(name)).getByRole("button", { name })).toBeInTheDocument();
    }
    for (const name of [S.queue.col.band, S.queue.col.description, S.queue.col.category]) {
      expect(within(header(name)).queryByRole("button")).toBeNull();
    }
    // The ① column is not a sort key: nothing derived from it can be sorted on (R17).
    expect(within(header(S.queue.col.ai)).queryByRole("button")).toBeNull();
  });

  it("starts in the risk order: no sort or dir on the request, no aria-sort on any header", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    expect(lastQuery()?.has("sort")).toBe(false);
    expect(lastQuery()?.has("dir")).toBe(false);
    expect(sortedHeaders()).toEqual([]);
    expect(within(screen.getByRole("table")).queryByText(S.queue.sort.asc)).toBeNull();
    expect(within(screen.getByRole("table")).queryByText(S.queue.sort.desc)).toBeNull();
    expect(riskOrderOffered()).toBe(false); // it is the order in use: nothing to switch to, so it is announced unavailable
  });

  it("spells the two arrows in strings.ts", () => {
    expect(S.queue.sort.asc).toBe("▲");
    expect(S.queue.sort.desc).toBe("▼");
    expect(S.queue.sort.byRisk).toBe("Sắp theo mức rủi ro");
  });

  it("sorts by last seen, newest first, on the first click: in the URL and on the request", async () => {
    const user = userEvent.setup();
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    await user.click(sortButton(S.queue.col.lastSeen));
    await waitFor(() => expect(lastQuery()?.get("sort")).toBe("time"));
    expect(lastQuery()?.get("dir")).toBe("desc");
    expect(where()).toBe("/queue?sort=time&dir=desc");
    await waitFor(() =>
      expect(header(S.queue.col.lastSeen)).toHaveAttribute("aria-sort", "descending"),
    );
    expect(header(S.queue.col.lastSeen)).toHaveTextContent(S.queue.sort.desc);
    expect(sortedHeaders()).toEqual([
      [`${S.queue.col.lastSeen}${S.queue.sort.desc}`, "descending"],
    ]);
  });

  it("sorts by occurrences, most first, and by agent, A to Z, on the first click", async () => {
    const user = userEvent.setup();
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    await user.click(sortButton(S.queue.col.occurrences));
    await waitFor(() => expect(lastQuery()?.get("sort")).toBe("occurrences"));
    expect(lastQuery()?.get("dir")).toBe("desc");
    expect(where()).toBe("/queue?sort=occurrences&dir=desc");
    await user.click(sortButton(S.queue.col.agent));
    await waitFor(() => expect(lastQuery()?.get("sort")).toBe("agent"));
    expect(lastQuery()?.get("dir")).toBe("asc");
    expect(where()).toBe("/queue?sort=agent&dir=asc");
    await waitFor(() =>
      expect(header(S.queue.col.agent)).toHaveAttribute("aria-sort", "ascending"),
    );
    expect(header(S.queue.col.agent)).toHaveTextContent(S.queue.sort.asc);
  });

  it("reverses the direction on a second click on the same header, and back on a third", async () => {
    const user = userEvent.setup();
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    await user.click(sortButton(S.queue.col.lastSeen));
    await waitFor(() => expect(lastQuery()?.get("dir")).toBe("desc"));
    await user.click(sortButton(S.queue.col.lastSeen));
    await waitFor(() => expect(lastQuery()?.get("dir")).toBe("asc"));
    expect(lastQuery()?.get("sort")).toBe("time");
    expect(where()).toBe("/queue?sort=time&dir=asc");
    await waitFor(() =>
      expect(header(S.queue.col.lastSeen)).toHaveAttribute("aria-sort", "ascending"),
    );
    expect(header(S.queue.col.lastSeen)).toHaveTextContent(S.queue.sort.asc);
    await user.click(sortButton(S.queue.col.lastSeen));
    await waitFor(() => expect(lastQuery()?.get("dir")).toBe("desc"));
    expect(where()).toBe("/queue?sort=time&dir=desc");
  });

  it("marks one header at a time: another header takes the mark, in its own default direction", async () => {
    const user = userEvent.setup();
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    await user.click(sortButton(S.queue.col.lastSeen));
    await user.click(sortButton(S.queue.col.lastSeen)); // ascending
    await waitFor(() => expect(lastQuery()?.get("dir")).toBe("asc"));
    await user.click(sortButton(S.queue.col.occurrences));
    await waitFor(() => expect(lastQuery()?.get("sort")).toBe("occurrences"));
    expect(lastQuery()?.get("dir")).toBe("desc"); // not the ascending of the header before
    await waitFor(() =>
      expect(sortedHeaders()).toEqual([
        [`${S.queue.col.occurrences}${S.queue.sort.desc}`, "descending"],
      ]),
    );
    expect(header(S.queue.col.lastSeen)).not.toHaveAttribute("aria-sort");
  });

  it("sorts from the keyboard: the header is a real button", async () => {
    const user = userEvent.setup();
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    sortButton(S.queue.col.agent).focus();
    await user.keyboard("{Enter}");
    await waitFor(() => expect(lastQuery()?.get("sort")).toBe("agent"));
    await user.keyboard(" ");
    await waitFor(() => expect(lastQuery()?.get("dir")).toBe("desc"));
  });

  it("goes back to page 1 when the sort changes", async () => {
    const user = userEvent.setup();
    renderQueue("/queue?page=3");
    await screen.findByRole("row", { name: /sshd/ });
    expect(lastQuery()?.get("page")).toBe("3");
    await user.click(sortButton(S.queue.col.lastSeen));
    await waitFor(() => expect(lastQuery()?.get("sort")).toBe("time"));
    expect(lastQuery()?.get("page")).toBe("1");
    expect(where()).toBe("/queue?sort=time&dir=desc");
  });

  it("goes back to page 1 when the direction is reversed", async () => {
    const user = userEvent.setup();
    renderQueue("/queue?sort=agent&dir=asc&page=4");
    await screen.findByRole("row", { name: /sshd/ });
    expect(lastQuery()?.get("page")).toBe("4");
    await user.click(sortButton(S.queue.col.agent));
    await waitFor(() => expect(lastQuery()?.get("dir")).toBe("desc"));
    expect(lastQuery()?.get("page")).toBe("1");
    expect(where()).toBe("/queue?sort=agent&dir=desc");
  });

  it("is read from the URL on load, with the filters and the page, and the header shows it", async () => {
    renderQueue("/queue?band=critical&agent=srv&status=mine&sort=occurrences&dir=asc&page=2");
    await screen.findByRole("row", { name: /sshd/ });
    expect(Object.fromEntries(requests[0]?.searchParams ?? [])).toEqual({
      page: "2",
      page_size: "50",
      band: "critical",
      agent: "srv",
      status: "mine",
      sort: "occurrences",
      dir: "asc",
    });
    expect(header(S.queue.col.occurrences)).toHaveAttribute("aria-sort", "ascending");
    expect(riskOrderOffered()).toBe(true);
  });

  it("takes a key with no direction as its default direction", async () => {
    renderQueue("/queue?sort=time");
    await screen.findByRole("row", { name: /sshd/ });
    expect(requests[0]?.searchParams.get("sort")).toBe("time");
    expect(requests[0]?.searchParams.get("dir")).toBe("desc");
    expect(header(S.queue.col.lastSeen)).toHaveAttribute("aria-sort", "descending");
  });

  it("ignores a sort or a direction in the URL that the UI does not know: the server would say 422", async () => {
    for (const search of [
      "sort=risk_score&dir=up",
      "sort=risk&dir=asc",
      "sort=triaged_count",
      "sort=&dir=",
      "dir=asc",
    ]) {
      const { unmount } = renderQueue(`/queue?${search}`);
      await screen.findByRole("row", { name: /sshd/ });
      expect([...(requests.at(-1)?.searchParams.keys() ?? [])].sort()).toEqual([
        "page",
        "page_size",
      ]);
      expect(sortedHeaders()).toEqual([]);
      unmount();
    }
  });

  it("keeps the sort when a filter changes, and starts that filter from page 1", async () => {
    const user = userEvent.setup();
    renderQueue("/queue?sort=agent&dir=desc&page=3");
    await screen.findByRole("row", { name: /sshd/ });
    await user.click(screen.getByRole("button", { name: "Cao 2" }));
    await waitFor(() => expect(lastQuery()?.get("band")).toBe("high"));
    expect(lastQuery()?.get("sort")).toBe("agent");
    expect(lastQuery()?.get("dir")).toBe("desc");
    expect(lastQuery()?.get("page")).toBe("1");
    expect(where()).toBe("/queue?band=high&sort=agent&dir=desc");
    await user.click(screen.getByRole("button", { name: S.queue.filter.clear }));
    await waitFor(() => expect(lastQuery()?.has("band")).toBe(false));
    expect(where()).toBe("/queue?sort=agent&dir=desc"); // 'Xoá bộ lọc' clears filters, not the order
  });

  it("keeps the filters when the sort changes", async () => {
    const user = userEvent.setup();
    renderQueue("/queue?band=high&category=web&status=mine");
    await screen.findByRole("row", { name: /sshd/ });
    await user.click(sortButton(S.queue.col.lastSeen));
    await waitFor(() => expect(lastQuery()?.get("sort")).toBe("time"));
    expect(lastQuery()?.get("band")).toBe("high");
    expect(lastQuery()?.get("category")).toBe("web");
    expect(lastQuery()?.get("status")).toBe("mine");
    expect(where()).toBe("/queue?band=high&category=web&status=mine&sort=time&dir=desc");
  });

  it("keeps the sort in the links of the pages", async () => {
    respond = () => HttpResponse.json(answer([row()], { total: 120 }));
    renderQueue("/queue?band=high&sort=time&dir=asc");
    await screen.findByRole("row", { name: /sshd/ });
    const nav = screen.getByRole("navigation", { name: S.queue.pagination });
    expect(within(nav).getByRole("link", { name: S.common.next })).toHaveAttribute(
      "href",
      "/queue?band=high&sort=time&dir=asc&page=2",
    );
    expect(within(nav).getByRole("link", { name: S.queue.page(3) })).toHaveAttribute(
      "href",
      "/queue?band=high&sort=time&dir=asc&page=3",
    );
  });

  it("goes back to the risk order from 'Sắp theo mức rủi ro': neither sort nor dir, page 1", async () => {
    const user = userEvent.setup();
    renderQueue("/queue?band=high&sort=agent&dir=desc&page=2");
    await screen.findByRole("row", { name: /sshd/ });
    expect(riskOrderOffered()).toBe(true);
    await user.click(sortButton(S.queue.sort.byRisk));
    await waitFor(() => expect(lastQuery()?.has("sort")).toBe(false));
    expect(lastQuery()?.has("dir")).toBe(false);
    expect(lastQuery()?.get("band")).toBe("high"); // the filters stay
    expect(lastQuery()?.get("page")).toBe("1");
    expect(where()).toBe("/queue?band=high");
    await waitFor(() => expect(sortedHeaders()).toEqual([]));
    expect(riskOrderOffered()).toBe(false);
  });

  // It is not a toggle: "pressed" would say the reader can un-press it, and a click does nothing. While the
  // risk order is in use it is announced as unavailable (aria-disabled, which keeps it focusable and in
  // the reading order), and it is never `aria-pressed`.
  it("announces 'Sắp theo mức rủi ro' as unavailable in the risk order, never as a pressed toggle", async () => {
    const user = userEvent.setup();
    renderQueue("/queue?page=2&sort=agent&dir=asc");
    await screen.findByRole("row", { name: /sshd/ });
    const byRisk = sortButton(S.queue.sort.byRisk);
    expect(byRisk).not.toHaveAttribute("aria-pressed");
    expect(byRisk).not.toHaveAttribute("aria-disabled", "true");
    await user.click(byRisk);
    await waitFor(() => expect(where()).toBe("/queue"));
    const now = sortButton(S.queue.sort.byRisk);
    expect(now).toHaveAttribute("aria-disabled", "true");
    expect(now).not.toHaveAttribute("aria-pressed");
    expect(now).toBeEnabled(); // aria-disabled, not `disabled`: it stays focusable
  });

  it("does nothing when 'Sắp theo mức rủi ro' is pressed in the risk order", async () => {
    const user = userEvent.setup();
    renderQueue("/queue?page=3");
    await screen.findByRole("row", { name: /sshd/ });
    const before = requests.length;
    await user.click(sortButton(S.queue.sort.byRisk));
    expect(where()).toBe("/queue?page=3");
    expect(requests).toHaveLength(before);
  });

  // The query key holds the sort, so the live layer's invalidation of ["queue"] fetches the sorted page again.
  it("keeps the sort when a change arrives and the queue is fetched again", async () => {
    const user = userEvent.setup();
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    await user.click(sortButton(S.queue.col.lastSeen));
    await waitFor(() => expect(lastQuery()?.get("sort")).toBe("time"));
    const before = requests.length;
    respond = () =>
      HttpResponse.json(answer([row(), row({ alert_id: "a2", description: "new arrival" })]));
    act(() => live().onChange(["a2"]));
    expect(await screen.findByRole("row", { name: /new arrival/ })).toBeInTheDocument();
    expect(requests.length).toBeGreaterThan(before);
    for (const url of requests.slice(before)) {
      expect(url.searchParams.get("sort")).toBe("time");
      expect(url.searchParams.get("dir")).toBe("desc");
    }
    expect(where()).toBe("/queue?sort=time&dir=desc");
    expect(header(S.queue.col.lastSeen)).toHaveAttribute("aria-sort", "descending");
  });

  it("keeps the sort in the resync of a socket that comes up", async () => {
    const user = userEvent.setup();
    renderQueue("/queue?sort=occurrences&dir=asc");
    await screen.findByRole("row", { name: /sshd/ });
    const before = requests.length;
    act(() => live().onStatus("live"));
    await waitFor(() => expect(requests.length).toBeGreaterThan(before));
    for (const url of requests.slice(before)) {
      expect(url.searchParams.get("sort")).toBe("occurrences");
      expect(url.searchParams.get("dir")).toBe("asc");
    }
    // and a header click after a live refetch still reverses from what the URL says
    await user.click(sortButton(S.queue.col.occurrences));
    await waitFor(() => expect(lastQuery()?.get("dir")).toBe("desc"));
    expect(where()).toBe("/queue?sort=occurrences&dir=desc");
  });

  it("shows the rows in the order the server sent them: the page does not sort them itself", async () => {
    respond = (url) =>
      HttpResponse.json(
        answer(
          url.searchParams.get("sort") === "agent"
            ? [
                row({ alert_id: "z", description: "second by risk", agent_name: "alpha" }),
                row({ alert_id: "y", description: "first by risk", agent_name: "beta" }),
              ]
            : [
                row({ alert_id: "y", description: "first by risk", agent_name: "beta" }),
                row({ alert_id: "z", description: "second by risk", agent_name: "alpha" }),
              ],
        ),
      );
    const user = userEvent.setup();
    renderQueue();
    await screen.findByRole("row", { name: /first by risk/ });
    const order = () =>
      screen
        .getAllByRole("row")
        .slice(1)
        .map((r) => cells(r)[3]?.textContent);
    expect(order()).toEqual(["beta", "alpha"]);
    await user.click(sortButton(S.queue.col.agent));
    // the page does not sort the rows itself: what the server sent is the order
    await waitFor(() => expect(order()).toEqual(["alpha", "beta"]));
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

  // The fetch of the page starts before the socket does (child effects run before the parent's), and the server
  // subscribes only after the auth frame and a check in the database (live_ws.py). An alert committed between
  // the snapshot of the queue and the subscription is in neither the rows nor any message, and while the
  // socket is live nothing polls: it would stay off the screen until some other alert changed.
  it("shows an alert committed before the server subscribed once the socket is live, with no message", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    expect(screen.queryByRole("row", { name: /before the subscription/ })).toBeNull();
    respond = () =>
      HttpResponse.json(
        answer([row(), row({ alert_id: "a2", description: "before the subscription" })]),
      );
    act(() => live().onStatus("live")); // ready: no alerts.changed was ever sent for a2
    expect(await screen.findByRole("row", { name: /before the subscription/ })).toBeInTheDocument();
  });

  it("fetches once when the socket first says live, and once more when it is back after a drop", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    expect(requests).toHaveLength(1);
    act(() => live().onStatus("live"));
    await waitFor(() => expect(requests).toHaveLength(2)); // the first live reads it all again
    await new Promise((r) => setTimeout(r, 600)); // its window has closed
    expect(requests).toHaveLength(2); // and once, not twice
    act(() => live().onStatus("offline"));
    act(() => live().onStatus("live")); // what came during the drop was not heard
    await waitFor(() => expect(requests).toHaveLength(3));
  });

  // Review Focus 2: a pull of 500 alerts arrives as many messages; the queue is fetched about once per burst.
  it("fetches at most twice for a burst of 50 changes inside 100 ms", async () => {
    renderQueue();
    await screen.findByRole("row", { name: /sshd/ });
    act(() => live().onStatus("live")); // the resync of a socket that just came up
    await waitFor(() => expect(requests).toHaveLength(2));
    await new Promise((r) => setTimeout(r, 600)); // its window has closed
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

    act(() => live().onStatus("live")); // one resync, then no clock
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

  /** What axe finds in `container`, as text; jsdom computes no colour, so the contrast rule cannot run here. */
  const violationsIn = async (container: HTMLElement): Promise<string[]> => {
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`);
  };

  it("has none in the empty state, the waiting queue and the 'mine' one", async () => {
    respond = () =>
      HttpResponse.json(
        answer([], { counts_by_band: { critical: 0, high: 0, medium: 0, low: 0 } }),
      );
    const first = renderQueue();
    expect(await screen.findByText(S.queue.empty)).toBeInTheDocument();
    expect(await violationsIn(first.container)).toEqual([]);
    first.unmount();
    const mine = renderQueue("/queue?status=mine");
    expect(await screen.findByText(S.queue.emptyMine)).toBeInTheDocument();
    expect(await violationsIn(mine.container)).toEqual([]);
    mine.unmount();
    const narrowed = renderQueue("/queue?category=nothing");
    expect(await screen.findByText(S.queue.noMatch)).toBeInTheDocument();
    expect(await violationsIn(narrowed.container)).toEqual([]);
  });

  it("has none with a sort on: the header buttons, the mark, aria-sort and 'Sắp theo mức rủi ro'", async () => {
    const user = userEvent.setup();
    const { container } = renderQueue("/queue?sort=agent&dir=asc");
    await screen.findByRole("row", { name: /sshd/ });
    expect(await violationsIn(container)).toEqual([]);
    await user.click(screen.getByRole("button", { name: S.queue.col.agent })); // now descending
    await waitFor(() =>
      expect(screen.getByRole("columnheader", { name: S.queue.col.agent })).toHaveAttribute(
        "aria-sort",
        "descending",
      ),
    );
    expect(await violationsIn(container)).toEqual([]);
    await user.click(screen.getByRole("button", { name: S.queue.sort.byRisk }));
    await waitFor(() => expect(where()).toBe("/queue"));
    expect(await violationsIn(container)).toEqual([]);
  });

  it("has none in the error state", async () => {
    respond = () => HttpResponse.json({ detail: "x" }, { status: 500 });
    const { container } = renderQueue();
    await screen.findByRole("alert");
    expect(await violationsIn(container)).toEqual([]);
  });
});
