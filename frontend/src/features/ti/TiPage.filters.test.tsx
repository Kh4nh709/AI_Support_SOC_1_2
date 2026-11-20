// src/features/ti/TiPage.filters.test.tsx — the filters, the search and the pagination: the query each makes, and the URL that holds
// them (a reload, or a link to another tab, keeps the view). A value that comes from the URL is checked before it reaches the API.
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setupServer } from "msw/node";
import { S } from "../../strings";
import { fake, renderTi, serve } from "./testkit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const where = () => screen.getByTestId("where").textContent;
const lastList = (state: ReturnType<typeof fake>) => {
  const url = state.lists.at(-1);
  if (url === undefined) throw new Error("no list request");
  return url;
};
const form = () => screen.getByRole("search", { name: S.ti.filters.label });
const field = (label: string) => within(form()).getByLabelText(label);
const apply = (user: ReturnType<typeof userEvent.setup>) =>
  user.click(within(form()).getByRole("button", { name: S.ti.filters.apply }));
const ready = () => screen.findByRole("table", { name: S.ti.tableLabel });

describe("the first request", () => {
  it("is page 1 of fifty, sorted by the server, with no filter parameter at all", async () => {
    const state = fake();
    serve(server, state);
    renderTi();
    await ready();
    expect(state.lists).toHaveLength(1);
    expect(Object.fromEntries(lastList(state).searchParams)).toEqual({
      page: "1",
      page_size: "50",
    });
    expect(where()).toBe("/threat-intel");
  });

  it("offers the three sources, and any, in the source filter", async () => {
    serve(server, fake());
    renderTi();
    await ready();
    const select = field(S.ti.filters.source) as HTMLSelectElement;
    expect([...select.options].map((o) => o.textContent)).toEqual([
      S.ti.filters.sourceAny,
      S.ti.source.threatfox,
      S.ti.source.urlhaus,
      S.ti.source.malwarebazaar,
    ]);
    expect(select.value).toBe("");
  });
});

describe("each filter", () => {
  it("source: sent as the closed code, kept in the URL, page back to 1", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi({ entry: "/threat-intel?page=3" });
    await ready();
    await user.selectOptions(field(S.ti.filters.source), S.ti.source.urlhaus);
    await apply(user);
    await waitFor(() => expect(where()).toBe("/threat-intel?source=urlhaus"));
    await waitFor(() => expect(lastList(state).searchParams.get("source")).toBe("urlhaus"));
    expect(lastList(state).searchParams.get("page")).toBe("1");
  });

  it("type and malware: typed, sent, kept", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.type(field(S.ti.filters.type), "Domain");
    await user.type(field(S.ti.filters.malware), "Example.Rat");
    await apply(user);
    await waitFor(() =>
      expect(Object.fromEntries(lastList(state).searchParams)).toMatchObject({
        type: "domain",
        malware: "Example.Rat",
      }),
    );
    expect(where()).toBe("/threat-intel?type=domain&malware=Example.Rat");
  });

  it("date range: dates only, as YYYY-MM-DD, never a time", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi();
    await ready();
    const from = field(S.ti.filters.from) as HTMLInputElement;
    expect(from.type).toBe("date");
    expect((field(S.ti.filters.to) as HTMLInputElement).type).toBe("date");
    fireEvent.change(from, { target: { value: "2026-11-01" } });
    fireEvent.change(field(S.ti.filters.to), { target: { value: "2026-11-17" } });
    await apply(user);
    await waitFor(() => expect(lastList(state).searchParams.get("from")).toBe("2026-11-01"));
    expect(lastList(state).searchParams.get("to")).toBe("2026-11-17");
    expect(lastList(state).search).not.toMatch(/T\d\d|%3A/);
  });

  it("minimum confidence: a number from 1 to 100, sent as min_confidence", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi();
    await ready();
    const box = field(S.ti.filters.confidence) as HTMLInputElement;
    expect(box.type).toBe("number");
    // 0 is the bottom of the box (the arrows reach it) and means "any": the page never sends it
    expect(box.min).toBe("0");
    expect(box.max).toBe("100");
    await user.type(box, "75");
    await apply(user);
    await waitFor(() => expect(lastList(state).searchParams.get("min_confidence")).toBe("75"));
    expect(where()).toBe("/threat-intel?min_confidence=75");
  });

  it("any confidence (left empty, or 0) sends NO min_confidence: 0 would drop every IOC with no confidence", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi({ entry: "/threat-intel?min_confidence=75" });
    await ready();
    expect(lastList(state).searchParams.get("min_confidence")).toBe("75");
    const box = field(S.ti.filters.confidence) as HTMLInputElement;
    expect(box.value).toBe("75");
    await user.clear(box);
    await apply(user);
    await waitFor(() => expect(lastList(state).searchParams.has("min_confidence")).toBe(false));
    expect(where()).toBe("/threat-intel");

    await user.type(box, "0");
    await apply(user);
    // nothing changes (the view is the empty one again), and nothing is asked: give a request that would go out time to come
    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(where()).toBe("/threat-intel");
    expect(state.lists.some((u) => u.searchParams.has("min_confidence"))).toBe(true);
    expect(state.lists.some((u) => u.searchParams.get("min_confidence") === "0")).toBe(false);
    expect(state.lists.at(-1)?.searchParams.has("min_confidence")).toBe(false);
  });

  it("says what the confidence filter does with an IOC that has none", async () => {
    serve(server, fake());
    renderTi();
    await ready();
    expect(within(form()).getByText(S.ti.filters.confidenceHint)).toBeInTheDocument();
  });
});

describe("the search box", () => {
  it("can clear a draft before sending the search", async () => {
    serve(server, fake());
    renderTi();
    const box = await screen.findByRole("searchbox", { name: S.ti.filters.search });
    await userEvent.type(box, "draft");
    await userEvent.click(screen.getByRole("button", { name: S.ti.filters.clear }));
    expect(box).toHaveValue("");
    expect(box).toHaveFocus();
  });

  it("sends q as typed, as one parameter, and keeps it in the URL", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.type(field(S.ti.filters.search), "evil&page_size=200");
    await apply(user);
    await waitFor(() => expect(lastList(state).searchParams.get("q")).toBe("evil&page_size=200"));
    expect(lastList(state).searchParams.get("page_size")).toBe("50");
  });

  it("is a literal search: %, _, a quote and SQL words go as they are", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.type(field(S.ti.filters.search), "%_'; drop table ti_ioc--");
    await apply(user);
    await waitFor(() =>
      expect(lastList(state).searchParams.get("q")).toBe("%_'; drop table ti_ioc--"),
    );
  });

  it("takes at most 128 characters, in the box and from the URL", async () => {
    const state = fake();
    serve(server, state);
    renderTi({ entry: `/threat-intel?q=${"a".repeat(300)}` });
    await ready();
    expect(lastList(state).searchParams.get("q")).toBe("a".repeat(128));
    expect((field(S.ti.filters.search) as HTMLInputElement).maxLength).toBe(128);
    expect((field(S.ti.filters.search) as HTMLInputElement).value).toBe("a".repeat(128));
  });

  it("acts when the form is sent, not on every key", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    renderTi();
    await ready();
    await user.type(field(S.ti.filters.search), "abc");
    expect(state.lists).toHaveLength(1);
    await user.keyboard("{Enter}");
    await waitFor(() => expect(lastList(state).searchParams.get("q")).toBe("abc"));
  });
});

describe("a value that comes from the URL", () => {
  it("is checked before it reaches the API: a bad source, confidence, date, type and page are dropped", async () => {
    const state = fake();
    serve(server, state);
    renderTi({
      entry:
        "/threat-intel?source=evil&min_confidence=999&from=2026-02-30&to=2026-11-17T10:00&type=a%20b&page=-4&expired=true&page_size=500",
    });
    await ready();
    expect(Object.fromEntries(lastList(state).searchParams)).toEqual({
      page: "1",
      page_size: "50",
    });
  });

  it("keeps what is valid beside what is not", async () => {
    const state = fake();
    serve(server, state);
    renderTi({
      entry: "/threat-intel?source=malwarebazaar&min_confidence=0&from=2026-11-01&to=nope&page=2",
    });
    await ready();
    expect(Object.fromEntries(lastList(state).searchParams)).toEqual({
      source: "malwarebazaar",
      from: "2026-11-01",
      page: "2",
      page_size: "50",
    });
  });

  it("fills the boxes with the valid values", async () => {
    serve(server, fake());
    renderTi({
      entry:
        "/threat-intel?source=urlhaus&type=url&malware=Example.Dropper&from=2026-11-01&to=2026-11-17&min_confidence=50&q=abc",
    });
    await ready();
    expect((field(S.ti.filters.source) as HTMLSelectElement).value).toBe("urlhaus");
    expect((field(S.ti.filters.type) as HTMLInputElement).value).toBe("url");
    expect((field(S.ti.filters.malware) as HTMLInputElement).value).toBe("Example.Dropper");
    expect((field(S.ti.filters.from) as HTMLInputElement).value).toBe("2026-11-01");
    expect((field(S.ti.filters.to) as HTMLInputElement).value).toBe("2026-11-17");
    expect((field(S.ti.filters.confidence) as HTMLInputElement).value).toBe("50");
    expect((field(S.ti.filters.search) as HTMLInputElement).value).toBe("abc");
  });
});

describe("clearing", () => {
  it("is offered only when a filter is set, and empties the URL", async () => {
    const state = fake();
    serve(server, state);
    const user = userEvent.setup();
    const view = renderTi();
    await ready();
    expect(
      within(form()).queryByRole("button", { name: S.ti.filters.clear }),
    ).not.toBeInTheDocument();
    view.unmount();
    serve(server, state);
    renderTi({ entry: "/threat-intel?source=urlhaus&q=abc&page=2" });
    await ready();
    await user.click(within(form()).getByRole("button", { name: S.ti.filters.clear }));
    await waitFor(() => expect(where()).toBe("/threat-intel"));
    await waitFor(() =>
      expect(Object.fromEntries(lastList(state).searchParams)).toEqual({
        page: "1",
        page_size: "50",
      }),
    );
  });
});

describe("the pagination", () => {
  const rows = fake().rows;

  it("says which rows are on screen and links the pages, keeping the filters", async () => {
    serve(server, fake({ rows, total: 120 }));
    renderTi({ entry: "/threat-intel?source=threatfox" });
    await ready();
    const nav = await screen.findByRole("navigation", { name: S.ti.pagination });
    expect(within(nav).getByText(S.ti.range(1, 50, 120))).toBeInTheDocument();
    const next = within(nav).getByRole("link", { name: S.common.next });
    expect(next).toHaveAttribute("href", "/threat-intel?source=threatfox&page=2");
    expect(within(nav).getByRole("link", { name: S.ti.page(3) })).toHaveAttribute(
      "href",
      "/threat-intel?source=threatfox&page=3",
    );
    expect(within(nav).queryByRole("link", { name: S.common.prev })).not.toBeInTheDocument();
  });

  it("asks the server for the page that was pressed, and the URL follows", async () => {
    const state = fake({ rows, total: 120 });
    serve(server, state);
    const user = userEvent.setup();
    renderTi();
    await ready();
    const nav = await screen.findByRole("navigation", { name: S.ti.pagination });
    await user.click(within(nav).getByRole("link", { name: S.ti.page(3) }));
    await waitFor(() => expect(where()).toBe("/threat-intel?page=3"));
    await waitFor(() => expect(lastList(state).searchParams.get("page")).toBe("3"));
    expect(lastList(state).searchParams.get("page_size")).toBe("50");
  });

  it("has no pagination for one page", async () => {
    serve(server, fake({ rows, total: 4 }));
    renderTi();
    await ready();
    expect(screen.queryByRole("navigation", { name: S.ti.pagination })).not.toBeInTheDocument();
  });

  it("says a page past the end is empty, and still offers the way back", async () => {
    serve(server, fake({ rows: [], total: 120 }));
    renderTi({ entry: "/threat-intel?page=9" });
    await ready();
    expect(screen.getByText(S.ti.pageEmpty)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: S.common.prev })).toBeInTheDocument();
  });
});
