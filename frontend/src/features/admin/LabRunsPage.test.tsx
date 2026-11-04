// src/features/admin/LabRunsPage.test.tsx — `/admin/lab` (P14-T10, DEC-213): the lab runs in a table, and the form that
// makes one. A small in-memory backend stands in for the two routes (MSW) and records every call, so a test can say
// what was sent. The refusals are asserted in words: a code is never on the page.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { delay, http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import type { LabRun } from "../../api/admin";
import { S } from "../../strings";
import { LabRunsPage } from "./LabRunsPage";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// --- the fixture --------------------------------------------------------------------------------------------------

const ID = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;

const run = (n: number, over: Partial<LabRun> = {}): LabRun => ({
  run_id: ID(n),
  name: `Lần chạy ${n}`,
  purpose: "test",
  starts_at: "2026-11-04T02:00:00Z", // 09:00 in Asia/Ho_Chi_Minh
  ends_at: "2026-11-04T04:00:00Z", // 11:00
  total: 12,
  labelled: 5,
  ...over,
});

const SCORED = run(2, { name: "Chạy chấm điểm 1" });
const BUILD = run(1, {
  name: "Xây kho 1",
  purpose: "kb",
  starts_at: "2026-11-03T02:00:00Z",
  ends_at: "2026-11-03T03:30:00Z",
  total: 40,
  labelled: 40,
});
/** Latest window first, as the route sends them. */
const RUNS = [SCORED, BUILD];

// --- the backend --------------------------------------------------------------------------------------------------

type Call = { method: string; path: string; body: unknown; contentType: string | null };
type Reply = () => Response | Promise<Response>;

const refuse = (status: number, detail: unknown) => HttpResponse.json({ detail }, { status });

function backend(opts: { runs?: LabRun[]; list?: Reply; create?: Reply } = {}) {
  let runs = [...(opts.runs ?? RUNS)];
  const calls: Call[] = [];
  const note = async (request: Request) => {
    const text = await request.clone().text();
    calls.push({
      method: request.method,
      path: new URL(request.url).pathname,
      body: text === "" ? null : (JSON.parse(text) as unknown),
      contentType: request.headers.get("content-type"),
    });
  };
  server.use(
    http.get("/api/admin/lab/runs", async ({ request }) => {
      await note(request);
      return opts.list ? opts.list() : HttpResponse.json({ runs });
    }),
    http.post("/api/admin/lab/runs", async ({ request }) => {
      await note(request);
      if (opts.create) return opts.create();
      const body = (await request.json()) as Record<string, string>;
      const made = run(50 + runs.length, {
        name: body.name,
        purpose: body.purpose as LabRun["purpose"],
        starts_at: body.starts_at,
        ends_at: body.ends_at,
        total: 0,
        labelled: 0,
      });
      runs = [made, ...runs];
      return HttpResponse.json(made, { status: 201 });
    }),
  );
  return {
    calls,
    gets: () => calls.filter((c) => c.method === "GET").length,
    posts: () => calls.filter((c) => c.method === "POST"),
  };
}

// --- the page -----------------------------------------------------------------------------------------------------

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/admin/lab"]}>
        <main>
          <LabRunsPage />
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const TABLE = "Các lần chạy lab";
const table = () => screen.findByRole("table", { name: TABLE });
const form = () => within(screen.getByRole("region", { name: "Tạo lần chạy" }));

/** Fills the form the way a person does; `datetime-local` takes the value, not keystrokes. */
async function fill(
  user: ReturnType<typeof userEvent.setup>,
  over: { name?: string; purpose?: "kb" | "test" | null; starts?: string; ends?: string } = {},
) {
  const f = form();
  const values = {
    name: "Lần chạy mới",
    purpose: "test",
    starts: "2026-11-05T09:00",
    ends: "2026-11-05T11:30",
    ...over,
  };
  if (values.name !== "") await user.type(f.getByLabelText("Tên lần chạy"), values.name);
  if (values.purpose === "test") await user.click(f.getByRole("radio", { name: /^Chấm điểm/ }));
  if (values.purpose === "kb") await user.click(f.getByRole("radio", { name: /^Xây kho/ }));
  if (values.starts !== "")
    fireEvent.change(f.getByLabelText("Bắt đầu"), { target: { value: values.starts } });
  if (values.ends !== "")
    fireEvent.change(f.getByLabelText("Kết thúc"), { target: { value: values.ends } });
}
const submit = (user: ReturnType<typeof userEvent.setup>) =>
  user.click(form().getByRole("button", { name: "Tạo lần chạy" }));

// ====================================================================================================================
// the table
// ====================================================================================================================

describe("the page", () => {
  it("has the title of the page, once, and counts the runs", async () => {
    backend();
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 1, name: "Gán nhãn lab" }),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(await screen.findByText("2 lần chạy")).toBeInTheDocument();
  });

  it("reads the runs once, from GET /api/admin/lab/runs", async () => {
    const b = backend();
    renderPage();
    await table();
    expect(b.gets()).toBe(1);
    expect(b.calls[0]).toMatchObject({ method: "GET", path: "/api/admin/lab/runs" });
  });

  it("heads the table: name, purpose, window, progress", async () => {
    backend();
    renderPage();
    const heads = within(await table()).getAllByRole("columnheader");
    expect(heads.map((h) => h.textContent)).toEqual([
      "Tên",
      "Mục đích",
      "Khung giờ",
      "Tiến độ gán",
    ]);
  });

  it("lists the runs in the order the server sent, with the purpose in words, the window as `start → end` and `Đã gán x/y`", async () => {
    backend();
    renderPage();
    const rows = within(await table()).getAllByRole("row");
    expect(rows).toHaveLength(3);
    const cells = (row: HTMLElement) =>
      within(row)
        .getAllByRole("cell")
        .map((c) => c.textContent);
    expect(cells(rows[1] as HTMLElement)).toEqual([
      "Chạy chấm điểm 1",
      "Chấm điểm",
      "04/11/2026 09:00:00 → 04/11/2026 11:00:00",
      "Đã gán 5/12",
    ]);
    expect(cells(rows[2] as HTMLElement)).toEqual([
      "Xây kho 1",
      "Xây kho",
      "03/11/2026 09:00:00 → 03/11/2026 10:30:00",
      "Đã gán 40/40",
    ]);
  });

  it("shows the times in the console's zone, +07, whatever the zone the data came in", async () => {
    backend({
      runs: [
        run(3, { starts_at: "2026-11-04T19:30:00+00:00", ends_at: "2026-11-04T21:00:00+00:00" }),
      ],
    });
    renderPage();
    const row = within(await table()).getAllByRole("row")[1] as HTMLElement;
    expect(within(row).getAllByRole("cell")[2]).toHaveTextContent(
      "05/11/2026 02:30:00 → 05/11/2026 04:00:00",
    );
  });

  it("links each run to its own page, by the name", async () => {
    backend();
    renderPage();
    const link = within(await table()).getByRole("link", { name: "Chạy chấm điểm 1" });
    expect(link).toHaveAttribute("href", `/admin/lab/${ID(2)}`);
    expect(within(await table()).getByRole("link", { name: "Xây kho 1" })).toHaveAttribute(
      "href",
      `/admin/lab/${ID(1)}`,
    );
  });

  it("renders a name that looks like markup as text", async () => {
    backend({ runs: [run(4, { name: '<img src=x onerror="alert(1)"> & <b>đậm</b>' })] });
    const { container } = renderPage();
    const link = await within(await table()).findByRole("link", {
      name: '<img src=x onerror="alert(1)"> & <b>đậm</b>',
    });
    expect(link).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    // (the create form has a <b> of its own for each purpose: the table has none)
    expect(container.querySelector("table b")).toBeNull();
  });

  it("says there is no run, and the form is still there to make one", async () => {
    backend({ runs: [] });
    renderPage();
    expect(
      await screen.findByText("Chưa có lần chạy nào. Tạo lần chạy đầu tiên ở khung bên cạnh."),
    ).toBeInTheDocument();
    expect(form().getByRole("button", { name: "Tạo lần chạy" })).toBeInTheDocument();
  });

  it("shows a skeleton while the runs load, and no axe violation", async () => {
    server.use(
      http.get("/api/admin/lab/runs", async () => {
        await delay("infinite");
        return HttpResponse.json({ runs: [] });
      }),
    );
    const { container } = renderPage();
    await screen.findByRole("status");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });

  it("has no axe violation with the runs on screen", async () => {
    backend();
    const { container } = renderPage();
    await table();
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("a page error", () => {
  it("says the page could not load, with a retry, when the server fails, and reads again on the retry", async () => {
    let fail = true;
    const b = backend({
      list: () => (fail ? refuse(500, "boom") : HttpResponse.json({ runs: RUNS })),
    });
    const user = userEvent.setup();
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(
      within(alert).getByRole("heading", { name: "Không tải được trang" }),
    ).toBeInTheDocument();
    fail = false;
    await user.click(within(alert).getByRole("button", { name: "Thử lại" }));
    await table();
    expect(b.gets()).toBe(2);
  });

  it("says the role is gone, with no retry, on a 403", async () => {
    backend({ list: () => refuse(403, "forbidden") });
    renderPage();
    expect(
      await screen.findByRole("heading", { name: S.admin.reason.forbidden }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Thử lại" })).not.toBeInTheDocument();
  });
});

// ====================================================================================================================
// the create form
// ====================================================================================================================

describe("the create form", () => {
  it("has the four inputs of the brief, with the purpose chosen by the admin and not by default", async () => {
    backend();
    renderPage();
    await table();
    const f = form();
    expect(f.getByLabelText("Tên lần chạy")).toHaveValue("");
    const radios = f.getAllByRole("radio");
    expect(radios.map((r) => (r as HTMLInputElement).checked)).toEqual([false, false]);
    expect(f.getByRole("radio", { name: /^Xây kho/ })).toBeInTheDocument();
    expect(f.getByRole("radio", { name: /^Chấm điểm/ })).toBeInTheDocument();
    expect(f.getByLabelText("Bắt đầu")).toHaveAttribute("type", "datetime-local");
    expect(f.getByLabelText("Kết thúc")).toHaveAttribute("type", "datetime-local");
  });

  it("says the times are entered in Vietnam time, beside both times", async () => {
    backend();
    renderPage();
    await table();
    const f = form();
    for (const input of [f.getByLabelText("Bắt đầu"), f.getByLabelText("Kết thúc")]) {
      expect(input).toHaveAccessibleDescription(/Giờ Việt Nam \(UTC\+7\)/);
    }
  });

  it("posts the name, the purpose and the two times as ISO 8601 with the +07:00 offset, as JSON", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, { name: "  Lần chạy mới  ", purpose: "test" });
    await submit(user);
    await waitFor(() => expect(b.posts()).toHaveLength(1));
    expect(b.posts()[0]).toMatchObject({
      path: "/api/admin/lab/runs",
      body: {
        name: "Lần chạy mới",
        purpose: "test",
        starts_at: "2026-11-05T09:00:00+07:00",
        ends_at: "2026-11-05T11:30:00+07:00",
      },
    });
    expect(b.posts()[0]?.contentType).toMatch(/^application\/json/);
  });

  it("sends a time that has seconds with its seconds", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, { purpose: "kb", starts: "2026-11-05T09:00:15", ends: "2026-11-05T09:05:45" });
    await submit(user);
    await waitFor(() => expect(b.posts()).toHaveLength(1));
    // jsdom's input also gives the milliseconds of a time that has seconds ("09:00:15.000"); a browser does not
    expect(b.posts()[0]?.body).toMatchObject({
      purpose: "kb",
      starts_at: expect.stringMatching(/^2026-11-05T09:00:15(\.000)?\+07:00$/) as string,
      ends_at: expect.stringMatching(/^2026-11-05T09:05:45(\.000)?\+07:00$/) as string,
    });
  });

  it("clears the form, says the run was made, and shows it in the table, read again from the server", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, { name: "Lần chạy mới" });
    await submit(user);
    expect(await screen.findByText("Đã tạo lần chạy “Lần chạy mới”.")).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "Lần chạy mới" })).toBeInTheDocument();
    expect(b.gets()).toBe(2);
    const f = form();
    expect(f.getByLabelText("Tên lần chạy")).toHaveValue("");
    expect(f.getByLabelText("Bắt đầu")).toHaveValue("");
    expect(f.getByLabelText("Kết thúc")).toHaveValue("");
    expect((f.getAllByRole("radio") as HTMLInputElement[]).map((r) => r.checked)).toEqual([
      false,
      false,
    ]);
    expect(screen.getByText("3 lần chạy")).toBeInTheDocument();
  });

  it("closes the note with its button", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user);
    await submit(user);
    const note = await screen.findByText("Đã tạo lần chạy “Lần chạy mới”.");
    await user.click(
      within(note.closest("[role=status]") as HTMLElement).getByRole("button", { name: "Đóng" }),
    );
    expect(screen.queryByText("Đã tạo lần chạy “Lần chạy mới”.")).not.toBeInTheDocument();
  });

  it("sends one write when the button is pressed twice in the same tick", async () => {
    const b = backend({
      create: async () => {
        await delay(50);
        return HttpResponse.json(run(60), { status: 201 });
      },
    });
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user);
    const button = form().getByRole("button", { name: "Tạo lần chạy" });
    fireEvent.click(button);
    fireEvent.click(button);
    await screen.findByText(/Đã tạo lần chạy/);
    expect(b.posts()).toHaveLength(1);
  });

  describe("before it posts", () => {
    it("asks for every input, beside it, in words, and sends nothing", async () => {
      const b = backend();
      const user = userEvent.setup();
      renderPage();
      await table();
      await submit(user);
      const f = form();
      expect(f.getByText("Không được để trống")).toBeInTheDocument(); // the name
      expect(f.getByText("Chọn một mục đích")).toBeInTheDocument();
      expect(f.getAllByText("Phải điền trường này")).toHaveLength(2); // the two times
      expect(f.getByLabelText("Tên lần chạy")).toHaveAttribute("aria-invalid", "true");
      expect(f.getByLabelText("Bắt đầu")).toHaveAttribute("aria-invalid", "true");
      expect(f.getByLabelText("Kết thúc")).toHaveAttribute("aria-invalid", "true");
      expect(b.posts()).toHaveLength(0);
    });

    it("puts the focus on the first input that is wrong", async () => {
      backend();
      const user = userEvent.setup();
      renderPage();
      await table();
      await submit(user);
      expect(form().getByLabelText("Tên lần chạy")).toHaveFocus();
    });

    it("drops the message of an input once it is edited", async () => {
      backend();
      const user = userEvent.setup();
      renderPage();
      await table();
      await submit(user);
      await user.type(form().getByLabelText("Tên lần chạy"), "x");
      expect(form().queryByText("Không được để trống")).not.toBeInTheDocument();
      expect(form().getByLabelText("Tên lần chạy")).not.toHaveAttribute("aria-invalid");
    });

    it("refuses a name longer than 80 characters, with the limit in the words", async () => {
      const b = backend();
      const user = userEvent.setup();
      renderPage();
      await table();
      await fill(user, { name: "a".repeat(81) });
      await submit(user);
      expect(form().getByText("Quá dài: tối đa 80 ký tự")).toBeInTheDocument();
      expect(b.posts()).toHaveLength(0);
    });
  });

  describe("when the server refuses", () => {
    it("says 'Khung giờ trùng với lần chạy khác' on a 409 overlap, keeps what was typed, and shows no code", async () => {
      const b = backend({ create: () => refuse(409, { reason: "overlap" }) });
      const user = userEvent.setup();
      const { container } = renderPage();
      await table();
      await fill(user);
      await submit(user);
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent("Khung giờ trùng với lần chạy khác");
      expect(container).not.toHaveTextContent(/overlap/i);
      expect(b.posts()).toHaveLength(1);
      // nothing is lost: the admin only moves the window
      const f = form();
      expect(f.getByLabelText("Tên lần chạy")).toHaveValue("Lần chạy mới");
      expect(f.getByLabelText("Bắt đầu")).toHaveValue("2026-11-05T09:00");
      expect(f.getByLabelText("Kết thúc")).toHaveValue("2026-11-05T11:30");
      expect(screen.queryByText(/Đã tạo lần chạy/)).not.toBeInTheDocument();
      // and the message belongs to both times
      expect(f.getByLabelText("Bắt đầu")).toHaveAccessibleDescription(
        /Khung giờ trùng với lần chạy khác/,
      );
      expect(f.getByLabelText("Kết thúc")).toHaveAccessibleDescription(
        /Khung giờ trùng với lần chạy khác/,
      );
    });

    it("drops the overlap message once a time is moved", async () => {
      backend({ create: () => refuse(409, { reason: "overlap" }) });
      const user = userEvent.setup();
      renderPage();
      await table();
      await fill(user);
      await submit(user);
      await screen.findByText("Khung giờ trùng với lần chạy khác");
      fireEvent.change(form().getByLabelText("Kết thúc"), {
        target: { value: "2026-11-05T11:00" },
      });
      expect(screen.queryByText("Khung giờ trùng với lần chạy khác")).not.toBeInTheDocument();
    });

    it.each([
      ["name", "taken", "Tên lần chạy", "Tên này đã được dùng cho lần chạy khác"],
      ["name", "empty", "Tên lần chạy", "Không được để trống"],
      ["name", "too_long", "Tên lần chạy", "Quá dài: tối đa 80 ký tự"],
      [
        "name",
        "invalid",
        "Tên lần chạy",
        "Tên có ký tự không được dùng (ký tự điều khiển hoặc ký tự vô hình)",
      ],
      ["ends_at", "not_after_starts", "Kết thúc", "Giờ kết thúc phải sau giờ bắt đầu"],
      [
        "starts_at",
        "invalid",
        "Bắt đầu",
        "Thời điểm không hợp lệ. Chỉ nhận các năm từ 2000 đến 2099 (theo giờ UTC).",
      ],
      [
        "ends_at",
        "invalid",
        "Kết thúc",
        "Thời điểm không hợp lệ. Chỉ nhận các năm từ 2000 đến 2099 (theo giờ UTC).",
      ],
      ["starts_at", "required", "Bắt đầu", "Phải điền trường này"],
    ])(
      "shows the 422 of %s / %s beside the input it names, in words",
      async (field, reason, label, text) => {
        backend({ create: () => refuse(422, { field, reason }) });
        const user = userEvent.setup();
        const { container } = renderPage();
        await table();
        await fill(user);
        await submit(user);
        const input = form().getByLabelText(label);
        await waitFor(() => expect(input).toHaveAttribute("aria-invalid", "true"));
        expect(input).toHaveAccessibleDescription(new RegExp(text.replace(/[()]/g, "\\$&")));
        expect(form().getByText(text)).toBeInTheDocument();
        expect(container).not.toHaveTextContent(new RegExp(`\\b${reason}\\b`));
        expect(container).not.toHaveTextContent(new RegExp(`\\b${field}\\b`));
      },
    );

    it("shows the 422 of the purpose beside the purpose", async () => {
      backend({ create: () => refuse(422, { field: "purpose", reason: "invalid" }) });
      const user = userEvent.setup();
      renderPage();
      await table();
      await fill(user);
      await submit(user);
      expect(await screen.findByText("Chọn Xây kho hoặc Chấm điểm")).toBeInTheDocument();
      expect(form().getByRole("radiogroup")).toHaveAttribute("aria-invalid", "true");
    });

    it.each([
      ["a 422 whose field is the body", () => refuse(422, { field: "body", reason: "invalid" })],
      [
        "a 422 with a reason it does not know",
        () => refuse(422, { field: "name", reason: "poetic" }),
      ],
      [
        "FastAPI's own list-shaped 422",
        () => refuse(422, [{ type: "missing", loc: ["body"], msg: "x" }]),
      ],
      ["a 409 with a reason it does not know", () => refuse(409, { reason: "something_new" })],
      ["a 500", () => refuse(500, "boom")],
      ["a 403", () => refuse(403, "forbidden")],
      ["a network failure", () => HttpResponse.error()],
    ])("says the console's generic text for %s, and never the code", async (_name, reply) => {
      backend({ create: reply });
      const user = userEvent.setup();
      const { container } = renderPage();
      await table();
      await fill(user);
      await submit(user);
      expect(await screen.findByRole("alert")).toHaveTextContent("Có lỗi xảy ra");
      expect(container).not.toHaveTextContent(/something_new|poetic|boom|forbidden|missing/);
    });

    it("lets the admin press the button again after a refusal", async () => {
      let first = true;
      const b = backend({
        create: () => {
          if (first) {
            first = false;
            return refuse(409, { reason: "overlap" });
          }
          return HttpResponse.json(run(70), { status: 201 });
        },
      });
      const user = userEvent.setup();
      renderPage();
      await table();
      await fill(user);
      await submit(user);
      await screen.findByText("Khung giờ trùng với lần chạy khác");
      await submit(user);
      expect(await screen.findByText(/Đã tạo lần chạy/)).toBeInTheDocument();
      expect(b.posts()).toHaveLength(2);
      expect(screen.queryByText("Khung giờ trùng với lần chạy khác")).not.toBeInTheDocument();
    });
  });

  it("has no axe violation, with the messages on screen", async () => {
    backend();
    const user = userEvent.setup();
    const { container } = renderPage();
    await table();
    await submit(user);
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});
