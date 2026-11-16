// src/features/soar/SoarPage.filters.test.tsx — the four filters, the search and the pagination: the query each builds,
// and the URL that holds them (a reload, or a link to another tab, keeps the view).
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setupServer } from "msw/node";
import { afterEach } from "vitest";
import { S } from "../../strings";
import { listOf, review } from "./fixtures";
import { fake, renderSoar, serve } from "./testkit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const where = () => screen.getByTestId("where").textContent;
/** The last request of the table itself: a review tab's (it has `status`), or the notices' (`kind=notice`, nothing else). */
const lastList = (state: ReturnType<typeof fake>, notices = false) => {
  const urls = state.lists.filter((url) =>
    notices ? url.searchParams.get("kind") === "notice" : url.searchParams.has("status"),
  );
  const url = urls.at(-1);
  if (url === undefined) throw new Error("no list request");
  return url;
};
const nav = () => screen.getByRole("navigation", { name: S.soar.tabs.label });

describe("the filters", () => {
  it("has the four, in order, with Đang mở current at first", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(
      within(nav())
        .getAllByRole("link")
        .map((a) => a.textContent),
    ).toEqual(["Đang mở", "Đã xử lý", "Hết hạn", "Thông báo"]);
    expect(within(nav()).getByRole("link", { name: "Đang mở" })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(within(nav()).getByRole("link", { name: "Đã xử lý" })).not.toHaveAttribute(
      "aria-current",
    );
  });

  it("Đang mở asks for open and processing, the first page of fifty", async () => {
    const state = fake({ rows: [review()] });
    serve(server, state);
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    const url = lastList(state);
    expect(url.searchParams.getAll("status")).toEqual(["open", "processing"]);
    expect(url.searchParams.get("page")).toBe("1");
    expect(url.searchParams.get("page_size")).toBe("50");
    expect(url.searchParams.has("kind")).toBe(false);
  });

  it("Đã xử lý asks for kept, undone and false_positive, and puts tab=done in the URL", async () => {
    const state = fake({ rows: [review()] });
    serve(server, state);
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    await userEvent.click(within(nav()).getByRole("link", { name: "Đã xử lý" }));
    expect(where()).toBe("/soar?tab=done");
    await waitFor(() =>
      expect(
        state.lists.some(
          (u) => u.searchParams.getAll("status").join() === "kept,undone,false_positive",
        ),
      ).toBe(true),
    );
    expect(within(nav()).getByRole("link", { name: "Đã xử lý" })).toHaveAttribute(
      "aria-current",
      "page",
    );
  });

  it("Hết hạn asks for expired", async () => {
    const state = fake({ rows: [review()] });
    serve(server, state);
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    await userEvent.click(within(nav()).getByRole("link", { name: "Hết hạn" }));
    expect(where()).toBe("/soar?tab=expired");
    await waitFor(() =>
      expect(state.lists.some((u) => u.searchParams.getAll("status").join() === "expired")).toBe(
        true,
      ),
    );
  });

  it("Thông báo asks for kind=notice and no status", async () => {
    const state = fake({ rows: [review()] });
    serve(server, state);
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    await userEvent.click(within(nav()).getByRole("link", { name: "Thông báo" }));
    expect(where()).toBe("/soar?tab=notice");
    await waitFor(() => expect(lastList(state, true).searchParams.get("kind")).toBe("notice"));
    expect(lastList(state, true).searchParams.has("status")).toBe(false);
  });

  it("starts where the URL says: tab, search and page", async () => {
    const state = fake({ rows: [review()] });
    state.list = () => listOf([review()], { total: 120, page: 3 });
    serve(server, state);
    renderSoar({ entry: "/soar?tab=done&q=10.0.0.5&page=3" });
    await screen.findByRole("table", { name: S.soar.tableLabel });
    const url = lastList(state);
    expect(url.searchParams.getAll("status")).toEqual(["kept", "undone", "false_positive"]);
    expect(url.searchParams.get("q")).toBe("10.0.0.5");
    expect(url.searchParams.get("page")).toBe("3");
    expect(screen.getByRole("searchbox", { name: S.soar.search.label })).toHaveValue("10.0.0.5");
  });

  it("falls back to Đang mở for a tab it does not know", async () => {
    const state = fake({ rows: [review()] });
    serve(server, state);
    renderSoar({ entry: "/soar?tab=everything" });
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(lastList(state).searchParams.getAll("status")).toEqual(["open", "processing"]);
  });

  it("says how many tickets match", async () => {
    const state = fake({ rows: [review()] });
    state.list = () => listOf([review()], { total: 120 });
    serve(server, state);
    renderSoar();
    expect(await screen.findByText("120 phiếu")).toBeInTheDocument();
  });
});

describe("the search", () => {
  it("is a labelled box for case number, IP or host, at most 100 characters", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    const box = await screen.findByRole("searchbox", { name: "Tìm theo case, IP hoặc máy" });
    expect(box).toHaveAttribute("maxlength", "100");
  });

  it("sends q when the form is sent, goes back to the first page, and puts q in the URL", async () => {
    const state = fake({ rows: [review()] });
    state.list = () => listOf([review()], { total: 120 });
    serve(server, state);
    renderSoar({ entry: "/soar?page=2" });
    const box = await screen.findByRole("searchbox", { name: S.soar.search.label });
    await userEvent.type(box, "AD-server{Enter}");
    expect(where()).toBe("/soar?q=AD-server");
    await waitFor(() => expect(lastList(state).searchParams.get("q")).toBe("AD-server"));
    expect(lastList(state).searchParams.get("page")).toBe("1");
  });

  it("does not ask for every half-typed word", async () => {
    const state = fake({ rows: [review()] });
    serve(server, state);
    renderSoar();
    const box = await screen.findByRole("searchbox", { name: S.soar.search.label });
    const before = state.lists.length;
    await userEvent.type(box, "10.0");
    expect(state.lists.length).toBe(before);
    expect(where()).toBe("/soar");
  });

  it("keeps the search when the tab changes, and clears it with its own button", async () => {
    const state = fake({ rows: [review()] });
    serve(server, state);
    renderSoar({ entry: "/soar?q=79.79" });
    await screen.findByRole("table", { name: S.soar.tableLabel });
    await userEvent.click(within(nav()).getByRole("link", { name: "Đã xử lý" }));
    expect(where()).toBe("/soar?tab=done&q=79.79");
    await userEvent.click(screen.getByRole("button", { name: S.soar.search.clear }));
    expect(where()).toBe("/soar?tab=done");
    expect(screen.getByRole("searchbox", { name: S.soar.search.label })).toHaveValue("");
  });

  it("offers no clear button while there is no search", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(screen.queryByRole("button", { name: S.soar.search.clear })).not.toBeInTheDocument();
  });

  it("trims the search, and sends nothing for a box of spaces", async () => {
    const state = fake({ rows: [review()] });
    serve(server, state);
    renderSoar();
    const box = await screen.findByRole("searchbox", { name: S.soar.search.label });
    await userEvent.type(box, "   {Enter}");
    expect(where()).toBe("/soar");
    await userEvent.type(box, "  host-1  {Enter}");
    expect(where()).toBe("/soar?q=host-1");
  });
});

describe("the pagination", () => {
  const big = () => {
    const state = fake({ rows: [review()] });
    state.list = (url) =>
      listOf([review()], { total: 120, page: Number(url.searchParams.get("page")) });
    return state;
  };

  it("shows the range, the pages and next, and none of it for one page", async () => {
    serve(server, big());
    renderSoar();
    const pages = await screen.findByRole("navigation", { name: S.soar.pagination });
    expect(within(pages).getByText("Hiển thị 1–50 trên 120")).toBeInTheDocument();
    expect(within(pages).getByRole("link", { name: "Trang 2" })).toBeInTheDocument();
    expect(within(pages).getByRole("link", { name: S.common.next })).toBeInTheDocument();
    expect(within(pages).queryByRole("link", { name: S.common.prev })).not.toBeInTheDocument();
  });

  it("is not there when everything fits on one page", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(screen.queryByRole("navigation", { name: S.soar.pagination })).not.toBeInTheDocument();
  });

  it("opens page 2 with a link, which keeps the tab and the search, and asks for page 2", async () => {
    const state = big();
    serve(server, state);
    renderSoar({ entry: "/soar?tab=done&q=79.79" });
    const pages = await screen.findByRole("navigation", { name: S.soar.pagination });
    const link = within(pages).getByRole("link", { name: "Trang 2" });
    expect(link).toHaveAttribute("href", "/soar?tab=done&q=79.79&page=2");
    await userEvent.click(link);
    expect(where()).toBe("/soar?tab=done&q=79.79&page=2");
    await waitFor(() => expect(lastList(state).searchParams.get("page")).toBe("2"));
    expect(await screen.findByText("Hiển thị 51–100 trên 120")).toBeInTheDocument();
  });

  it("marks the page it is on, and offers previous from the second page", async () => {
    serve(server, big());
    renderSoar({ entry: "/soar?page=2" });
    const pages = await screen.findByRole("navigation", { name: S.soar.pagination });
    expect(within(pages).getByText("2")).toHaveAttribute("aria-current", "page");
    expect(within(pages).getByRole("link", { name: S.common.prev })).toHaveAttribute(
      "href",
      "/soar",
    );
  });

  it("says a page past the end is empty, and still offers the way back", async () => {
    const state = fake();
    state.list = () => listOf([], { total: 60, page: 9 });
    serve(server, state);
    renderSoar({ entry: "/soar?page=9" });
    expect(await screen.findByText(S.soar.pageEmpty)).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: S.soar.pagination })).toBeInTheDocument();
  });
});
