// src/features/tier2/CasesPage.test.tsx — the case list (spec §4): the rows the server sends, in the order
// it sends them, paged by offset, and a code this UI has no label for shown as the code.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import { S } from "../../strings";
import { CasesPage } from "./CasesPage";

const LIST_URL = "/api/tier2/cases";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const row = (n: number, over: Record<string, unknown> = {}) => ({
  case_id: `0b30b853-1c2d-4e5f-8a9b-${String(n).padStart(12, "0")}`,
  title: `Brute force vào máy chủ ${n}`,
  status: "investigating",
  severity: "high",
  created_at: "2026-09-26T04:14:00+00:00",
  last_analyzed_at: "2026-09-30T01:19:00+00:00",
  last_run: { created_at: "2026-09-30T01:19:00+00:00", has_result: true },
  cluster_count: 2,
  occurrence_count: 61,
  ...over,
});

/** Serves `pages` one per GET (the last for every GET after) and records the query each GET carried. */
function serve(...pages: JsonBodyType[]) {
  const queries: { offset: string | null; limit: string | null }[] = [];
  server.use(
    http.get(LIST_URL, ({ request }) => {
      const params = new URL(request.url).searchParams;
      queries.push({ offset: params.get("offset"), limit: params.get("limit") });
      return HttpResponse.json(pages[Math.min(queries.length - 1, pages.length - 1)]);
    }),
  );
  return queries;
}

// A fresh client per render, so no test reads what another one cached; `retry: false` so a failed read
// shows at once (T09's tests do the same). `gcTime: 0` is a client that keeps no page it has left.
function renderList(options: { gcTime?: number } = {}) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, ...options } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/cases"]}>
        <main>
          <CasesPage />
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const table = () => screen.findByRole("table", { name: S.case.listTitle });

describe("the rows", () => {
  it("shows the title, the status, the severity, the counts and the two times of each case", async () => {
    serve([row(1)]);
    renderList();
    const [, first] = within(await table()).getAllByRole("row");
    const cells = within(first as HTMLElement);
    expect(cells.getByRole("link", { name: "Brute force vào máy chủ 1" })).toHaveAttribute(
      "href",
      "/cases/0b30b853-1c2d-4e5f-8a9b-000000000001",
    );
    expect(cells.getByText(S.caseStatus.investigating)).toBeInTheDocument();
    expect(cells.getByText(S.severity.high)).toBeInTheDocument();
    expect(cells.getByText("2")).toBeInTheDocument();
    expect(cells.getByText("61")).toBeInTheDocument();
    expect(cells.getByText("26/09 11:14")).toBeInTheDocument();
    expect(cells.getByText("30/09 08:19")).toBeInTheDocument();
  });

  it("heads the table with the seven columns of the Jinja page", async () => {
    serve([row(1)]);
    renderList();
    await table();
    const heads = screen.getAllByRole("columnheader").map((h) => h.textContent);
    expect(heads).toEqual([
      S.case.col.title,
      S.case.col.status,
      S.case.col.severity,
      S.case.col.clusters,
      S.case.col.alerts,
      S.case.col.created,
      S.case.col.lastAnalysed,
    ]);
  });

  it("keeps the order the server sent: investigating first, then newest first", async () => {
    serve([row(3), row(2, { status: "concluded_fp" }), row(1, { status: "confirmed_incident" })]);
    renderList();
    await table();
    const links = screen.getAllByRole("link").map((a) => a.textContent);
    expect(links).toEqual([
      "Brute force vào máy chủ 3",
      "Brute force vào máy chủ 2",
      "Brute force vào máy chủ 1",
    ]);
  });

  it("labels a concluded case's status with its conclusion", async () => {
    serve([
      row(1, { status: "concluded_fp" }),
      row(2, { status: "concluded_policy_violation" }),
      row(3, { status: "confirmed_incident" }),
    ]);
    renderList();
    await table();
    expect(screen.getByText("Dương tính giả")).toBeInTheDocument();
    expect(screen.getByText("Vi phạm chính sách")).toBeInTheDocument();
    expect(screen.getByText("Xác nhận sự cố")).toBeInTheDocument();
  });

  it("labels an archived case 'Đã lưu trữ' - closed by the archive, not concluded by anyone (DEC-212)", async () => {
    serve([row(2), row(1, { status: "archived", last_analyzed_at: null, last_run: null })]);
    renderList();
    await table();
    const archivedRow = screen.getByText("Brute force vào máy chủ 1").closest("tr") as HTMLElement;
    expect(within(archivedRow).getByText("Đã lưu trữ")).toBeInTheDocument();
    expect(within(archivedRow).queryByText("Đang điều tra")).not.toBeInTheDocument();
    const openRow = screen.getByText("Brute force vào máy chủ 2").closest("tr") as HTMLElement;
    expect(within(openRow).getByText("Đang điều tra")).toBeInTheDocument();
    expect(screen.queryByText("Dương tính giả")).not.toBeInTheDocument();
  });

  it("says a case never analysed is so, not a blank or a dash", async () => {
    serve([row(1, { last_analyzed_at: null, last_run: null })]);
    renderList();
    await table();
    expect(screen.getByText(S.case.neverAnalysed)).toBeInTheDocument();
  });

  // INT-T02 fix round 1 (N4): "Phân tích gần nhất" follows the newest ② run here as on the case page,
  // so one column title does not mean two things (`last_analyzed_at` moves only for a run WITH a result).
  describe("Phân tích gần nhất follows the newest ② run (last_run)", () => {
    it("shows the time of a run that stopped, with 'không có kết quả', not 'chưa phân tích'", async () => {
      serve([
        row(1, {
          last_analyzed_at: null,
          last_run: { created_at: "2026-09-30T01:19:00+00:00", has_result: false },
        }),
      ]);
      renderList();
      await table();
      expect(screen.getByText("30/09 08:19 — không có kết quả")).toBeInTheDocument();
      expect(screen.queryByText(S.case.neverAnalysed)).not.toBeInTheDocument();
    });

    it("shows the time alone for a run with a result, and the newest run over an older good one", async () => {
      serve([
        row(1),
        row(2, {
          last_analyzed_at: "2026-09-29T01:19:00+00:00",
          last_run: { created_at: "2026-09-30T03:30:00+00:00", has_result: false },
        }),
      ]);
      renderList();
      await table();
      expect(screen.getByText("30/09 08:19")).toBeInTheDocument();
      expect(screen.getByText("30/09 10:30 — không có kết quả")).toBeInTheDocument();
      expect(screen.queryByText("29/09 08:19")).not.toBeInTheDocument();
    });

    it("reads an answer with no last_run as last_analyzed_at was read", async () => {
      const old = row(1);
      delete (old as Record<string, unknown>).last_run;
      serve([old, row(2, { last_analyzed_at: null, last_run: undefined })]);
      renderList();
      await table();
      expect(screen.getByText("30/09 08:19")).toBeInTheDocument();
      expect(screen.getByText(S.case.neverAnalysed)).toBeInTheDocument();
    });
  });

  it("shows a status and a severity it has no label for as the codes, and a missing one as a dash", async () => {
    serve([
      row(1, { status: "reopened_by_magic", severity: "catastrophic" }),
      row(2, { status: "constructor", severity: null }),
    ]);
    renderList();
    await table();
    expect(screen.getByText("reopened_by_magic")).toBeInTheDocument();
    expect(screen.getByText("catastrophic")).toBeInTheDocument();
    expect(screen.getByText("constructor")).toBeInTheDocument();
    expect(screen.getAllByText(S.common.missing).length).toBeGreaterThan(0);
  });

  it("renders a title as text, never as markup", async () => {
    const markup = '<img src=x onerror="alert(1)"><b>đậm</b>';
    serve([row(1, { title: markup })]);
    const { container } = renderList();
    await table();
    expect(container.querySelector("img, b")).toBeNull();
    expect(screen.getByRole("link", { name: markup })).toBeInTheDocument();
  });
});

describe("the states", () => {
  it("says 'Đang tải…' until the first answer", async () => {
    serve([row(1)]);
    renderList();
    expect(screen.getByText(S.common.loading)).toBeInTheDocument();
    await table();
    expect(screen.queryByText(S.common.loading)).not.toBeInTheDocument();
  });

  it("says there is no case for an empty list, and has no page to go to", async () => {
    serve([]);
    renderList();
    expect(await screen.findByText(S.case.empty)).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: S.common.next })).toBeDisabled();
    expect(screen.getByRole("button", { name: S.common.prev })).toBeDisabled();
  });

  it("shows an error, and loads again when Thử lại is pressed", async () => {
    let calls = 0;
    server.use(
      http.get(LIST_URL, () => {
        calls += 1;
        return calls === 1
          ? HttpResponse.json({ detail: "boom" }, { status: 500 })
          : HttpResponse.json([row(1)]);
      }),
    );
    renderList();
    expect(await screen.findByRole("alert")).toHaveTextContent(S.common.unknownError);
    await userEvent.setup().click(screen.getByRole("button", { name: S.common.retry }));
    await table();
    expect(calls).toBe(2);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("titles the page", async () => {
    serve([row(1)]);
    renderList();
    expect(
      await screen.findByRole("heading", { level: 1, name: S.case.listTitle }),
    ).toBeInTheDocument();
  });
});

describe("paging", () => {
  const full = () => Array.from({ length: 50 }, (_, i) => row(i + 1));

  it("asks for the first 50, offset 0, and offers no previous page there", async () => {
    const queries = serve(full());
    renderList();
    await table();
    expect(queries).toEqual([{ offset: "0", limit: "50" }]);
    expect(screen.getByRole("button", { name: S.common.prev })).toBeDisabled();
    expect(screen.getByRole("button", { name: S.common.next })).toBeEnabled();
  });

  it("goes to the next 50 and back", async () => {
    const second = Array.from({ length: 3 }, (_, i) => row(i + 51));
    const queries = serve(full(), second, full());
    renderList();
    const user = userEvent.setup();
    await table();
    await user.click(screen.getByRole("button", { name: S.common.next }));
    expect(
      await screen.findByRole("link", { name: "Brute force vào máy chủ 51" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("link", { name: "Brute force vào máy chủ 1" }),
    ).not.toBeInTheDocument();
    expect(queries[1]).toEqual({ offset: "50", limit: "50" });
    // A short page is the last: there is nothing after it.
    expect(screen.getByRole("button", { name: S.common.next })).toBeDisabled();
    expect(screen.getByRole("button", { name: S.common.prev })).toBeEnabled();

    await user.click(screen.getByRole("button", { name: S.common.prev }));
    expect(
      await screen.findByRole("link", { name: "Brute force vào máy chủ 1" }),
    ).toBeInTheDocument();
    expect(queries[2]).toEqual({ offset: "0", limit: "50" });
  });

  it("offers no paging for a short first page", async () => {
    serve([row(1)]);
    renderList();
    await table();
    expect(screen.getByRole("button", { name: S.common.next })).toBeDisabled();
    expect(screen.getByRole("button", { name: S.common.prev })).toBeDisabled();
  });

  it("says there is no case left on this page, not that there is none, when paging past the end", async () => {
    const queries = serve(full(), []);
    renderList();
    const user = userEvent.setup();
    await table();
    await user.click(screen.getByRole("button", { name: S.common.next }));
    expect(await screen.findByText(S.case.pastEnd)).toBeInTheDocument();
    expect(screen.queryByText(S.case.empty)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: S.common.prev })).toBeEnabled();
    expect(screen.getByRole("button", { name: S.common.next })).toBeDisabled();
    expect(queries[1]).toEqual({ offset: "50", limit: "50" });
  });

  it("says neither empty nor past the end while it goes back from a page past the end", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let calls = 0;
    server.use(
      http.get(LIST_URL, async () => {
        calls += 1;
        if (calls === 1) return HttpResponse.json(full());
        if (calls === 2) return HttpResponse.json([]);
        await gate;
        return HttpResponse.json(full());
      }),
    );
    // No cache of the page just left, so the page asked for has nothing of its own to show yet.
    renderList({ gcTime: 0 });
    const user = userEvent.setup();
    await table();
    await user.click(screen.getByRole("button", { name: S.common.next }));
    await screen.findByText(S.case.pastEnd);
    await user.click(screen.getByRole("button", { name: S.common.prev }));

    // The empty page still in hand belongs to offset 50; the page asked for is not here yet.
    expect(screen.getByText(S.common.loading)).toBeInTheDocument();
    expect(screen.queryByText(S.case.empty)).not.toBeInTheDocument();
    expect(screen.queryByText(S.case.pastEnd)).not.toBeInTheDocument();
    release();
    await table();
  });

  it("shows a page it has read before as its own rows, busy, while it reads it again", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let calls = 0;
    server.use(
      http.get(LIST_URL, async () => {
        calls += 1;
        if (calls === 1) return HttpResponse.json(full());
        if (calls === 2) return HttpResponse.json([]);
        await gate;
        return HttpResponse.json(full());
      }),
    );
    renderList();
    const user = userEvent.setup();
    await table();
    await user.click(screen.getByRole("button", { name: S.common.next }));
    await screen.findByText(S.case.pastEnd);
    await user.click(screen.getByRole("button", { name: S.common.prev }));

    // Offset 0 is in the cache, so its rows are there at once; nothing says the list is empty or over.
    expect(await table()).toHaveAttribute("aria-busy", "true");
    expect(screen.queryByText(S.case.empty)).not.toBeInTheDocument();
    expect(screen.queryByText(S.case.pastEnd)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: S.common.next })).toBeDisabled();
    release();
    await waitFor(() => expect(screen.getByRole("table")).toHaveAttribute("aria-busy", "false"));
  });

  it("goes back from a page past the end to the last page", async () => {
    const queries = serve(full(), [], full());
    renderList();
    const user = userEvent.setup();
    await table();
    await user.click(screen.getByRole("button", { name: S.common.next }));
    await screen.findByText(S.case.pastEnd);
    await user.click(screen.getByRole("button", { name: S.common.prev }));
    await table();
    expect(queries[2]).toEqual({ offset: "0", limit: "50" });
    expect(screen.queryByText(S.case.pastEnd)).not.toBeInTheDocument();
  });
});

describe("accessibility", () => {
  it("has no axe violation", async () => {
    serve([row(1), row(2, { status: "concluded_fp", last_analyzed_at: null, last_run: null })]);
    const { container } = renderList();
    await table();
    // jsdom computes no layout or colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(
      result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(" ")}`),
    ).toEqual([]);
  });
});
