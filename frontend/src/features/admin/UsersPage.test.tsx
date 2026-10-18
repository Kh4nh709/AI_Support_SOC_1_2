// src/features/admin/UsersPage.test.tsx — the users page of the admin console (P11-T12, spec §4.2): the table
// with the actions each state allows, the four dialogs, the create form, the role matrix, and every answer
// the five user routes can give, each shown where the canvas's AdminStates puts it. A small in-memory
// backend stands in for the routes (MSW); it records every call so a test can say what was sent.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { delay, http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import type { UserRow } from "../../api/admin";
import { AuthContext, type AuthState } from "../../auth/AuthProvider";
import { S } from "../../strings";
import { AdminLayout } from "./AdminLayout";
import { UsersPage } from "./UsersPage";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// --- the fixture: the six accounts of the canvas ------------------------------------------------------------

const ID = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
/** A lock that has not ended, and a lock that has: the page reads the clock, so one is far ahead. */
const LOCKED_UNTIL = "2099-01-01T02:55:00+00:00"; // 09:55 in Asia/Ho_Chi_Minh
const LOCK_OVER = "2020-01-01T02:55:00+00:00";

const account = (n: number, over: Partial<UserRow> = {}): UserRow => ({
  user_id: ID(n),
  username: `user${n}`,
  display_name: `Người ${n}`,
  role: "tier1",
  is_active: true,
  locked_until: null,
  failed_logins: 0,
  last_login_at: "2026-09-30T02:12:00+00:00", // 30/09 09:12
  created_at: "2026-09-01T00:00:00+00:00",
  ...over,
});

const LAN = account(1, { username: "lan.t1", display_name: "Trần Lan" });
const TUAN = account(2, {
  username: "tuan.t1",
  display_name: "Lê Tuấn",
  locked_until: LOCKED_UNTIL,
  failed_logins: 5,
  last_login_at: "2026-09-30T02:38:00+00:00", // 09:38
});
const MINH = account(3, {
  username: "minh.t2",
  display_name: "Phạm Minh",
  role: "tier2",
  last_login_at: "2026-09-30T01:20:00+00:00", // 08:20
});
const HOA = account(4, { username: "hoa.admin", display_name: "Đỗ Hoa", role: "admin" });
const AN = account(5, {
  username: "an.t2",
  display_name: "Võ An",
  role: "tier2",
  is_active: false,
  last_login_at: "2026-09-21T10:02:00+00:00", // 21/09 17:02
});
const BINH = account(6, { username: "binh.t1", display_name: "Ngô Bình", last_login_at: null });
const USERS = [LAN, TUAN, MINH, HOA, AN, BINH];
/** The page is open as this account: it is the caller's own row. */
const ME = "hoa.admin";

// --- the backend ----------------------------------------------------------------------------------------------

type Call = { method: string; path: string; body: unknown; contentType: string | null };
type Reply = () => Response | Promise<Response>;

/** `{detail}` as FastAPI's HTTPException answers. */
const refuse = (status: number, detail: unknown) => HttpResponse.json({ detail }, { status });
const noContent = () => new HttpResponse(null, { status: 204 });

/**
 * Serves the five routes from `users`, and records what each call carried. A write that is given a reply
 * answers that and changes nothing; otherwise it behaves as the real route does, on the in-memory list.
 */
function backend(
  opts: {
    users?: UserRow[];
    list?: Reply;
    patch?: Reply;
    create?: Reply;
    password?: Reply;
    unlock?: Reply;
  } = {},
) {
  let users = (opts.users ?? USERS).map((u) => ({ ...u }));
  const calls: Call[] = [];
  const note = async (request: Request, path: string) => {
    const text = await request.clone().text();
    calls.push({
      method: request.method,
      path,
      body: text === "" ? null : (JSON.parse(text) as unknown),
      contentType: request.headers.get("content-type"),
    });
  };
  server.use(
    http.get("/api/admin/users", async ({ request }) => {
      await note(request, "/api/admin/users");
      return opts.list ? opts.list() : HttpResponse.json({ users });
    }),
    http.post("/api/admin/users", async ({ request }) => {
      await note(request, "/api/admin/users");
      if (opts.create) return opts.create();
      const body = (await request.json()) as Record<string, string>;
      users = [
        ...users,
        account(90 + users.length, {
          username: body.username,
          display_name: body.display_name,
          role: body.role as UserRow["role"],
          last_login_at: null,
        }),
      ];
      return HttpResponse.json({ user_id: ID(99) }, { status: 201 });
    }),
    http.patch("/api/admin/users/:id", async ({ request, params }) => {
      await note(request, `/api/admin/users/${String(params.id)}`);
      if (opts.patch) return opts.patch();
      const changes = (await request.json()) as Partial<UserRow>;
      users = users.map((u) => (u.user_id === params.id ? { ...u, ...changes } : u));
      return HttpResponse.json(users.find((u) => u.user_id === params.id));
    }),
    http.post("/api/admin/users/:id/password", async ({ request, params }) => {
      await note(request, `/api/admin/users/${String(params.id)}/password`);
      return opts.password ? opts.password() : noContent();
    }),
    http.post("/api/admin/users/:id/unlock", async ({ request, params }) => {
      await note(request, `/api/admin/users/${String(params.id)}/unlock`);
      if (opts.unlock) return opts.unlock();
      users = users.map((u) =>
        u.user_id === params.id ? { ...u, locked_until: null, failed_logins: 0 } : u,
      );
      return noContent();
    }),
  );
  return {
    calls,
    gets: () => calls.filter((c) => c.method === "GET").length,
    writes: () => calls.filter((c) => c.method !== "GET"),
  };
}

// --- the page ---------------------------------------------------------------------------------------------------

/** Opens the page as the caller `username`: under the app's header and main landmark and the console's sidebar. */
function renderPage(username: string = ME) {
  const auth: AuthState = {
    session: {
      token: "t",
      role: "admin",
      username,
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    },
    ready: true,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
  };
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={["/admin/users"]}>
          <header>
            <span>AI Support SOC</span>
          </header>
          <main>
            <AdminLayout>
              <UsersPage />
            </AdminLayout>
          </main>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
  return { ...view, client };
}

/** Does anything TanStack's mutation cache holds (variables, answer, context) contain `secret`? */
function mutationCacheHolds(client: QueryClient, secret: string): boolean {
  const held = client
    .getMutationCache()
    .getAll()
    .map((m) => ({ variables: m.state.variables, data: m.state.data, context: m.state.context }));
  return JSON.stringify(held).includes(secret);
}

const TABLE = "Danh sách tài khoản";
const table = () => screen.findByRole("table", { name: TABLE });

/** The row of one account, once the table is on screen. */
async function rowOf(username: string) {
  const rows = within(await table()).getAllByRole("row");
  const row = rows.find((r) => within(r).queryByText(username, { exact: true }) !== null);
  if (row === undefined) throw new Error(`no row for ${username}`);
  return { row, q: within(row) };
}

const dialog = (name: string | RegExp) => screen.findByRole("dialog", { name });

/** Opens the row's "more" button and chooses "Vô hiệu hoá" there: that opens the dialog. */
async function chooseDeactivate(user: ReturnType<typeof userEvent.setup>, username: string) {
  const { q } = await rowOf(username);
  await user.click(q.getByRole("button", { name: `Thêm thao tác cho ${username}` }));
  await user.click(q.getByRole("button", { name: `Vô hiệu hoá ${username}` }));
}
const create = () => within(screen.getByRole("region", { name: "Tạo người dùng" }));
const GOOD = "correct-horse-battery";

// ============================================================================================================
// the normal render
// ============================================================================================================

describe("the page", () => {
  it("has the h1 of the canvas and counts the accounts", async () => {
    backend();
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 1, name: "Người dùng và quyền" }),
    ).toBeInTheDocument();
    expect(await screen.findByText(/6 tài khoản/)).toBeInTheDocument();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
  });

  it("reads the list once, from GET /api/admin/users", async () => {
    const b = backend();
    renderPage();
    await table();
    expect(b.gets()).toBe(1);
    expect(b.calls[0]).toMatchObject({ method: "GET", path: "/api/admin/users" });
  });

  it("heads the table with the five columns of the canvas", async () => {
    backend();
    renderPage();
    const heads = within(await table()).getAllByRole("columnheader");
    expect(heads.map((h) => h.textContent)).toEqual([
      "Tài khoản",
      "Vai trò",
      "Trạng thái",
      "Đăng nhập cuối",
      "Thao tác",
    ]);
  });

  it("lists the accounts in the order the server sent, one row each", async () => {
    backend();
    renderPage();
    const rows = within(await table()).getAllByRole("row");
    expect(rows).toHaveLength(1 + USERS.length);
    const names = rows.slice(1).map((r) => within(r).getAllByRole("cell")[0]?.textContent);
    expect(names).toEqual([
      "lan.t1Trần Lan",
      "tuan.t1Lê Tuấn",
      "minh.t2Phạm Minh",
      "hoa.adminbạnĐỗ Hoa",
      "an.t2Võ An",
      "binh.t1Ngô Bình",
    ]);
  });

  it("shows each account's role in a select that holds the three roles", async () => {
    backend();
    renderPage();
    const { q } = await rowOf("minh.t2");
    const select = q.getByRole("combobox", { name: "Vai trò của minh.t2" });
    expect(select).toHaveValue("tier2");
    expect(
      within(select)
        .getAllByRole("option")
        .map((o) => o.textContent),
    ).toEqual(["tier1", "tier2", "admin"]);
  });

  it("says when each account last logged in, and 'chưa đăng nhập' for one that never has", async () => {
    backend();
    renderPage();
    expect((await rowOf("lan.t1")).q.getByText("30/09 09:12")).toBeInTheDocument();
    expect((await rowOf("minh.t2")).q.getByText("30/09 08:20")).toBeInTheDocument();
    expect((await rowOf("an.t2")).q.getByText("21/09 17:02")).toBeInTheDocument();
    expect((await rowOf("binh.t1")).q.getByText("chưa đăng nhập")).toBeInTheDocument();
    expect(screen.getAllByText("chưa đăng nhập")).toHaveLength(1);
  });

  it("says active, locked until the clock time, or inactive", async () => {
    backend();
    renderPage();
    expect((await rowOf("lan.t1")).q.getByText("Hoạt động")).toBeInTheDocument();
    expect((await rowOf("tuan.t1")).q.getByText("Bị khoá đến 09:55")).toBeInTheDocument();
    expect((await rowOf("an.t2")).q.getByText("Vô hiệu")).toBeInTheDocument();
  });

  it("shows an account whose lock has ended as active", async () => {
    backend({ users: [LAN, account(7, { username: "old.lock", locked_until: LOCK_OVER })] });
    renderPage();
    const { q } = await rowOf("old.lock");
    expect(q.getByText("Hoạt động")).toBeInTheDocument();
    expect(q.queryByText(/khoá đến/)).not.toBeInTheDocument();
    expect(q.getByRole("button", { name: /Đặt lại mật khẩu/ })).toBeInTheDocument();
    expect(q.queryByRole("button", { name: /Mở khoá/ })).not.toBeInTheDocument();
  });

  it("shows an inactive account as inactive even when it is also locked", async () => {
    backend({
      users: [HOA, account(7, { username: "both", is_active: false, locked_until: LOCKED_UNTIL })],
    });
    renderPage();
    const { q } = await rowOf("both");
    expect(q.getByText("Vô hiệu")).toBeInTheDocument();
    expect(q.queryByText(/khoá đến/)).not.toBeInTheDocument();
    expect(q.getByRole("button", { name: /Kích hoạt lại/ })).toBeInTheDocument();
  });

  it("shows no hash, password or token anywhere, whatever the server sends", async () => {
    backend({
      list: () =>
        HttpResponse.json({
          users: [{ ...LAN, password_hash: "$argon2id$secret", token: "tok-secret" }, HOA],
        }),
    });
    renderPage();
    await table();
    expect(document.body.textContent).not.toContain("$argon2id$secret");
    expect(document.body.textContent).not.toContain("tok-secret");
  });
});

// ============================================================================================================
// the actions each state allows
// ============================================================================================================

describe("the actions of a row", () => {
  it("offers reset password for an active account, and deactivate behind the row's more button", async () => {
    backend();
    renderPage();
    const { q } = await rowOf("lan.t1");
    expect(q.getByRole("button", { name: /^Đặt lại mật khẩu/ })).toBeEnabled();
    const more = q.getByRole("button", { name: "Thêm thao tác cho lan.t1" });
    expect(more).toBeEnabled();
    expect(more).toHaveAttribute("aria-expanded", "false");
    expect(q.queryByRole("button", { name: /Vô hiệu hoá/ })).not.toBeInTheDocument();
    expect(q.queryByRole("button", { name: /Mở khoá/ })).not.toBeInTheDocument();
    expect(q.queryByRole("button", { name: /Kích hoạt lại/ })).not.toBeInTheDocument();
    await userEvent.setup().click(more);
    expect(q.getByRole("button", { name: /^Vô hiệu hoá/ })).toBeEnabled();
  });

  it("offers unlock for a locked account, and deactivate behind the more button", async () => {
    backend();
    renderPage();
    const { q } = await rowOf("tuan.t1");
    expect(q.getByRole("button", { name: /^Mở khoá/ })).toBeEnabled();
    expect(q.getByRole("button", { name: "Thêm thao tác cho tuan.t1" })).toBeEnabled();
    expect(q.queryByRole("button", { name: /Đặt lại mật khẩu/ })).not.toBeInTheDocument();
    expect(q.queryByRole("button", { name: /Vô hiệu hoá/ })).not.toBeInTheDocument();
  });

  it("offers only reactivate for an inactive account, and no more button", async () => {
    backend();
    renderPage();
    const { q } = await rowOf("an.t2");
    expect(q.getByRole("button", { name: /^Kích hoạt lại/ })).toBeEnabled();
    expect(q.queryByRole("button", { name: /Thêm thao tác/ })).not.toBeInTheDocument();
    expect(q.queryByRole("button", { name: /Vô hiệu hoá/ })).not.toBeInTheDocument();
    expect(q.queryByRole("button", { name: /Đặt lại mật khẩu/ })).not.toBeInTheDocument();
    expect(q.queryByRole("button", { name: /Mở khoá/ })).not.toBeInTheDocument();
  });

  it("names each button with the account it acts on", async () => {
    backend();
    renderPage();
    const { q } = await rowOf("minh.t2");
    expect(q.getByRole("button", { name: "Đặt lại mật khẩu minh.t2" })).toBeInTheDocument();
    await userEvent.setup().click(q.getByRole("button", { name: "Thêm thao tác cho minh.t2" }));
    expect(q.getByRole("button", { name: "Vô hiệu hoá minh.t2" })).toBeInTheDocument();
  });

  it("closes the more button's list on Escape, and when another action is pressed", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.click(q.getByRole("button", { name: "Thêm thao tác cho lan.t1" }));
    await user.keyboard("{Escape}");
    expect(q.queryByRole("button", { name: /Vô hiệu hoá/ })).not.toBeInTheDocument();
    expect(q.getByRole("button", { name: "Thêm thao tác cho lan.t1" })).toHaveFocus();
    await user.click(q.getByRole("button", { name: "Thêm thao tác cho lan.t1" }));
    await user.click(q.getByRole("button", { name: /^Đặt lại mật khẩu/ }));
    expect(q.queryByRole("button", { name: /^Vô hiệu hoá/ })).not.toBeInTheDocument();
    expect(await dialog("Đặt lại mật khẩu cho lan.t1")).toBeInTheDocument();
  });
});

describe("the caller's own row", () => {
  it("is marked as the caller's", async () => {
    backend();
    renderPage();
    expect((await rowOf("hoa.admin")).q.getByText("bạn")).toBeInTheDocument();
    expect(screen.getAllByText("bạn")).toHaveLength(1);
  });

  it("locks the role select and the deactivate control, and leaves reset password open", async () => {
    backend();
    renderPage();
    const { q } = await rowOf("hoa.admin");
    expect(q.getByRole("combobox", { name: "Vai trò của hoa.admin" })).toBeDisabled();
    expect(q.getByRole("button", { name: "Thêm thao tác cho hoa.admin" })).toBeDisabled();
    expect(q.getByRole("button", { name: /^Đặt lại mật khẩu/ })).toBeEnabled();
  });

  it("says why they are locked, for the screen reader and the pointer alike", async () => {
    backend();
    renderPage();
    const { q } = await rowOf("hoa.admin");
    const hint =
      "Bạn không thể tự hạ quyền hoặc tự vô hiệu hoá tài khoản của mình. Nhờ một admin khác làm việc này.";
    expect(q.getByRole("combobox", { name: "Vai trò của hoa.admin" })).toHaveAttribute(
      "title",
      hint,
    );
    expect(q.getByRole("button", { name: "Thêm thao tác cho hoa.admin" })).toHaveAttribute(
      "title",
      hint,
    );
  });

  it("leaves every other row's controls open", async () => {
    backend();
    renderPage();
    const { q } = await rowOf("lan.t1");
    expect(q.getByRole("combobox", { name: "Vai trò của lan.t1" })).toBeEnabled();
    expect(q.getByRole("button", { name: "Thêm thao tác cho lan.t1" })).toBeEnabled();
    expect(q.queryByText("bạn")).not.toBeInTheDocument();
  });

  it("opens nothing when the disabled more button is clicked", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("hoa.admin");
    await user.click(q.getByRole("button", { name: "Thêm thao tác cho hoa.admin" }));
    expect(q.queryByRole("button", { name: /Vô hiệu hoá/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("is told apart by the session's username, so no row is the caller's for another name", async () => {
    backend();
    renderPage("someone.else");
    const { q } = await rowOf("hoa.admin");
    expect(q.queryByText("bạn")).not.toBeInTheDocument();
    expect(q.getByRole("combobox", { name: "Vai trò của hoa.admin" })).toBeEnabled();
    expect(q.getByRole("button", { name: "Thêm thao tác cho hoa.admin" })).toBeEnabled();
  });
});

// ============================================================================================================
// loading, a page error, a missing list
// ============================================================================================================

describe("loading", () => {
  it("shows the h1 and a skeleton that says it is loading, and no table yet", async () => {
    server.use(
      http.get("/api/admin/users", async () => {
        await delay("infinite");
        return HttpResponse.json({ users: [] });
      }),
    );
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 1, name: "Người dùng và quyền" }),
    ).toBeInTheDocument();
    const status = screen.getByRole("status");
    expect(status).toHaveTextContent("Đang tải…");
    expect(status).toHaveAttribute("aria-busy", "true");
    expect(screen.queryByRole("table", { name: TABLE })).not.toBeInTheDocument();
  });

  it("keeps the create form and the matrix on screen, which need no list", async () => {
    server.use(
      http.get("/api/admin/users", async () => {
        await delay("infinite");
        return HttpResponse.json({ users: [] });
      }),
    );
    renderPage();
    await screen.findByRole("status");
    expect(screen.getByRole("region", { name: "Tạo người dùng" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Quyền theo vai trò" })).toBeInTheDocument();
  });

  it("has no axe violation while it loads", async () => {
    server.use(
      http.get("/api/admin/users", async () => {
        await delay("infinite");
        return HttpResponse.json({ users: [] });
      }),
    );
    const { container } = renderPage();
    await screen.findByRole("status");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("a page error", () => {
  it("says the page could not load, with a retry, when the server fails", async () => {
    backend({ list: () => refuse(500, "boom") });
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(
      within(alert).getByRole("heading", { name: "Không tải được trang" }),
    ).toBeInTheDocument();
    expect(within(alert).getByRole("button", { name: "Thử lại" })).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: TABLE })).not.toBeInTheDocument();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
  });

  it("loads the list when the retry is pressed and the server has recovered", async () => {
    let fail = true;
    backend({ list: () => (fail ? refuse(500, "boom") : HttpResponse.json({ users: USERS })) });
    const user = userEvent.setup();
    renderPage();
    const retry = await screen.findByRole("button", { name: "Thử lại" });
    fail = false;
    await user.click(retry);
    expect(await table()).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says the page could not load when the network is down", async () => {
    server.use(http.get("/api/admin/users", () => HttpResponse.error()));
    renderPage();
    expect(
      await screen.findByRole("heading", { name: "Không tải được trang" }),
    ).toBeInTheDocument();
  });

  it("says the role is gone, and offers no retry, on a 403 (the stale actor)", async () => {
    backend({ list: () => refuse(403, "forbidden") });
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 1, name: S.admin.reason.forbidden }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Thử lại" })).not.toBeInTheDocument();
    expect(screen.queryByRole("table", { name: TABLE })).not.toBeInTheDocument();
  });

  it("has no axe violation on the error", async () => {
    backend({ list: () => refuse(500, "boom") });
    const { container } = renderPage();
    await screen.findByRole("alert");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

// ============================================================================================================
// the search
// ============================================================================================================

describe("the search", () => {
  it("is a labelled search box that starts empty", async () => {
    backend();
    renderPage();
    await table();
    const box = screen.getByRole("searchbox", { name: "Tìm" });
    expect(box).toHaveValue("");
    expect(box).toHaveAttribute("placeholder", "username, tên…");
  });

  it("keeps the rows whose username or display name holds what was typed, in any case", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await user.type(screen.getByRole("searchbox", { name: "Tìm" }), "T1");
    const rows = within(await table())
      .getAllByRole("row")
      .slice(1);
    expect(rows.map((r) => within(r).getAllByRole("cell")[0]?.textContent)).toEqual([
      "lan.t1Trần Lan",
      "tuan.t1Lê Tuấn",
      "binh.t1Ngô Bình",
    ]);
    await user.clear(screen.getByRole("searchbox", { name: "Tìm" }));
    await user.type(screen.getByRole("searchbox", { name: "Tìm" }), "tuấn");
    const left = within(await table())
      .getAllByRole("row")
      .slice(1);
    expect(left).toHaveLength(1);
    expect(within(left[0] as HTMLElement).getByText("tuan.t1")).toBeInTheDocument();
  });

  it("makes no request: it filters the list it has", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await user.type(screen.getByRole("searchbox", { name: "Tìm" }), "lan");
    expect(b.calls).toHaveLength(1);
  });

  it("says nothing matched, with the words typed, and a button that clears the search", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await user.type(screen.getByRole("searchbox", { name: "Tìm" }), "quang");
    expect(await screen.findByText("Không có tài khoản khớp “quang”")).toBeInTheDocument();
    expect(screen.getByText("Tìm theo tên đăng nhập hoặc tên hiển thị.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Xoá tìm kiếm" }));
    expect(screen.getByRole("searchbox", { name: "Tìm" })).toHaveValue("");
    expect(within(await table()).getAllByRole("row")).toHaveLength(1 + USERS.length);
    expect(screen.queryByText(/Không có tài khoản khớp/)).not.toBeInTheDocument();
  });

  it("shows hostile search text as text, never as markup", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await user.type(screen.getByRole("searchbox", { name: "Tìm" }), "<img src=x onerror=alert(1)>");
    expect(
      await screen.findByText("Không có tài khoản khớp “<img src=x onerror=alert(1)>”"),
    ).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  it("has no axe violation on the empty result", async () => {
    backend();
    const user = userEvent.setup();
    const { container } = renderPage();
    await table();
    await user.type(screen.getByRole("searchbox", { name: "Tìm" }), "quang");
    await screen.findByText("Không có tài khoản khớp “quang”");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

// ============================================================================================================
// the role matrix (static text of the canvas)
// ============================================================================================================

describe("the role to function matrix", () => {
  const ROWS: [string, string, string, string][] = [
    ["Xem hàng đợi và chi tiết alert", "có", "có", "có"],
    ["Quyết định alert (đóng, chuyển Tier-2)", "có", "—", "—"],
    ["Xem và kết luận case", "—", "có", "có"],
    ["Chạy phân tích ② và hỏi AI", "—", "có", "có"],
    ["Quản trị rules tự đóng, digest", "—", "—", "có"],
    ["Gán nhãn đánh giá", "—", "—", "có"],
    ["Quản lý người dùng", "—", "—", "có"],
    ["Xem và chỉnh hạn mức LLM", "—", "—", "có"],
    ["Xem nhật ký audit, chạy lại job lỗi, nạp lại kiểm kê", "—", "—", "có"],
  ];

  it("has the nine rows and the three role columns of the canvas, under its own heading", async () => {
    backend();
    renderPage();
    await table();
    expect(
      screen.getByRole("heading", { level: 2, name: "Quyền theo vai trò" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("đổi vai trò là đổi quyền; phiên cũ của người đó bị đăng xuất"),
    ).toBeInTheDocument();
    const matrix = screen.getByRole("table", { name: "Quyền theo vai trò" });
    expect(
      within(matrix)
        .getAllByRole("columnheader")
        .map((h) => h.textContent),
    ).toEqual(["Chức năng", "tier1", "tier2", "admin"]);
    const body = within(matrix).getAllByRole("row").slice(1);
    expect(body.map((r) => within(r).getAllByRole("cell")[0]?.textContent)).toEqual(
      ROWS.map(([label]) => label),
    );
  });

  it("says 'có' or '—' in each cell, and the '—' is read out as 'không'", async () => {
    backend();
    renderPage();
    const matrix = within(await screen.findByRole("table", { name: "Quyền theo vai trò" }));
    const body = matrix.getAllByRole("row").slice(1);
    ROWS.forEach(([, a, b, c], i) => {
      const cells = within(body[i] as HTMLElement)
        .getAllByRole("cell")
        .slice(1);
      [a, b, c].forEach((want, j) => {
        const cell = cells[j] as HTMLElement;
        if (want === "có") expect(cell).toHaveTextContent(/^có$/);
        else {
          expect(cell).toHaveTextContent(/^—không$/);
          expect(within(cell).getByText("—")).toHaveAttribute("aria-hidden", "true");
        }
      });
    });
  });
});

// ============================================================================================================
// the role change dialog
// ============================================================================================================

describe("changing a role", () => {
  it("opens a dialog that says what changes, and who is signed out, and changes nothing yet", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "tier2");
    const box = within(await dialog("Đổi vai trò của lan.t1?"));
    expect(box.getByText("tier1 → tier2")).toBeInTheDocument();
    expect(
      box.getByText(
        "Quyền đổi ngay. Mọi phiên đang mở của lan.t1 bị đăng xuất; lần đăng nhập sau sẽ có quyền mới.",
      ),
    ).toBeInTheDocument();
    expect(box.getByRole("button", { name: "Huỷ" })).toBeInTheDocument();
    expect(box.getByRole("button", { name: "Đổi vai trò" })).toBeInTheDocument();
    expect(b.writes()).toEqual([]);
    // the select shows what the server has until the change is made
    expect(q.getByRole("combobox", { name: "Vai trò của lan.t1" })).toHaveValue("tier1");
  });

  it("sends PATCH {role} as JSON when confirmed, says so, and shows the new role", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "tier2");
    await user.click(
      within(await dialog("Đổi vai trò của lan.t1?")).getByRole("button", { name: "Đổi vai trò" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toEqual([
      {
        method: "PATCH",
        path: `/api/admin/users/${ID(1)}`,
        body: { role: "tier2" },
        contentType: "application/json",
      },
    ]);
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Đã đổi vai trò của lan.t1 từ tier1 sang tier2. Phiên cũ của người đó đã bị đăng xuất.",
    );
    // the list was read again, and now says tier2
    expect(b.gets()).toBe(2);
    await waitFor(async () =>
      expect(
        (await rowOf("lan.t1")).q.getByRole("combobox", { name: "Vai trò của lan.t1" }),
      ).toHaveValue("tier2"),
    );
  });

  it("sends nothing and leaves the select as it was when cancelled", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "admin");
    await user.click(
      within(await dialog("Đổi vai trò của lan.t1?")).getByRole("button", { name: "Huỷ" }),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(b.writes()).toEqual([]);
    expect(q.getByRole("combobox", { name: "Vai trò của lan.t1" })).toHaveValue("tier1");
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("is cancelled by Escape too", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("minh.t2");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của minh.t2" }), "tier1");
    await dialog("Đổi vai trò của minh.t2?");
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(b.writes()).toEqual([]);
  });

  it("sends one request, however often the confirm button is pressed", async () => {
    const b = backend({
      patch: async () => {
        await delay(50);
        return HttpResponse.json({ ...LAN, role: "tier2" });
      },
    });
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "tier2");
    const confirm = within(await dialog("Đổi vai trò của lan.t1?")).getByRole("button", {
      name: "Đổi vai trò",
    });
    await user.dblClick(confirm);
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toHaveLength(1);
  });

  it("says why on a 409 last_active_admin, with only 'Đóng', and changes nothing", async () => {
    const b = backend({ patch: () => refuse(409, { reason: "last_active_admin" }) });
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "admin");
    await user.click(
      within(await dialog("Đổi vai trò của lan.t1?")).getByRole("button", { name: "Đổi vai trò" }),
    );
    const box = within(await dialog("Đổi vai trò của lan.t1?"));
    expect(await box.findByRole("alert")).toHaveTextContent(
      "Không thể hạ quyền hoặc vô hiệu hoá admin hoạt động cuối cùng. Tạo hoặc kích hoạt một admin khác trước.",
    );
    expect(box.getByRole("button", { name: "Đóng" })).toBeInTheDocument();
    expect(box.queryByRole("button", { name: "Đổi vai trò" })).not.toBeInTheDocument();
    expect(box.queryByRole("button", { name: "Huỷ" })).not.toBeInTheDocument();
    expect(box.queryByText(/Mọi phiên đang mở/)).not.toBeInTheDocument();
    await user.click(box.getByRole("button", { name: "Đóng" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(q.getByRole("combobox", { name: "Vai trò của lan.t1" })).toHaveValue("tier1");
    expect(b.writes()).toHaveLength(1);
  });

  it("says why on a 409 self_change, with only 'Đóng'", async () => {
    backend({ patch: () => refuse(409, { reason: "self_change" }) });
    const user = userEvent.setup();
    // the page believes this is not the caller's row (it is: the server is the authority)
    renderPage("someone.else");
    const { q } = await rowOf("hoa.admin");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của hoa.admin" }), "tier2");
    await user.click(
      within(await dialog("Đổi vai trò của hoa.admin?")).getByRole("button", {
        name: "Đổi vai trò",
      }),
    );
    const box = within(await dialog("Đổi vai trò của hoa.admin?"));
    expect(await box.findByRole("alert")).toHaveTextContent(
      "Bạn không thể tự hạ quyền hoặc tự vô hiệu hoá tài khoản của mình. Nhờ một admin khác làm việc này.",
    );
    expect(box.getByRole("button", { name: "Đóng" })).toBeInTheDocument();
    expect(box.queryByRole("button", { name: "Đổi vai trò" })).not.toBeInTheDocument();
  });

  it("says the role is gone on a 403 forbidden (the stale actor), with only 'Đóng'", async () => {
    backend({ patch: () => refuse(403, "forbidden") });
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "tier2");
    await user.click(
      within(await dialog("Đổi vai trò của lan.t1?")).getByRole("button", { name: "Đổi vai trò" }),
    );
    const box = within(await dialog("Đổi vai trò của lan.t1?"));
    expect(await box.findByRole("alert")).toHaveTextContent(S.admin.reason.forbidden);
    expect(box.queryByRole("button", { name: "Đổi vai trò" })).not.toBeInTheDocument();
    expect(box.getByRole("button", { name: "Đóng" })).toBeInTheDocument();
  });

  it("says the account is gone on a 404, with only 'Đóng', and reads the list again", async () => {
    const b = backend({ patch: () => refuse(404, { reason: "not_found" }) });
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "tier2");
    await user.click(
      within(await dialog("Đổi vai trò của lan.t1?")).getByRole("button", { name: "Đổi vai trò" }),
    );
    const box = within(await dialog("Đổi vai trò của lan.t1?"));
    expect(await box.findByRole("alert")).toHaveTextContent(S.admin.reason.not_found);
    expect(box.queryByRole("button", { name: "Đổi vai trò" })).not.toBeInTheDocument();
    await waitFor(() => expect(b.gets()).toBe(2));
  });

  it("shows the field's own text on a 422, in the dialog, and lets the admin close it", async () => {
    backend({ patch: () => refuse(422, { field: "role", reason: "invalid" }) });
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "tier2");
    await user.click(
      within(await dialog("Đổi vai trò của lan.t1?")).getByRole("button", { name: "Đổi vai trò" }),
    );
    const box = within(await dialog("Đổi vai trò của lan.t1?"));
    expect(await box.findByRole("alert")).toHaveTextContent(S.admin.reason.invalid);
    await user.click(box.getByRole("button", { name: "Huỷ" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("says the save failed on a 500, and lets the admin press the button again", async () => {
    let fail = true;
    const b = backend({
      patch: () => (fail ? refuse(500, "boom") : HttpResponse.json({ ...LAN, role: "tier2" })),
    });
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "tier2");
    await user.click(
      within(await dialog("Đổi vai trò của lan.t1?")).getByRole("button", { name: "Đổi vai trò" }),
    );
    const box = within(await dialog("Đổi vai trò của lan.t1?"));
    expect(await box.findByRole("alert")).toHaveTextContent(
      "Không lưu được: máy chủ trả lỗi. Thử lại sau ít phút.",
    );
    fail = false;
    await user.click(box.getByRole("button", { name: "Đổi vai trò" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toHaveLength(2);
  });

  it("says the connection is lost when the network fails", async () => {
    backend({ patch: () => HttpResponse.error() });
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "tier2");
    await user.click(
      within(await dialog("Đổi vai trò của lan.t1?")).getByRole("button", { name: "Đổi vai trò" }),
    );
    expect(
      await within(await dialog("Đổi vai trò của lan.t1?")).findByRole("alert"),
    ).toHaveTextContent("Không lưu được: mất kết nối máy chủ. Thử lại.");
  });

  it("has no axe violation with the dialog open", async () => {
    backend();
    const user = userEvent.setup();
    const { container } = renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "tier2");
    await dialog("Đổi vai trò của lan.t1?");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

// ============================================================================================================
// deactivate, and reactivate
// ============================================================================================================

describe("deactivating", () => {
  it("opens the canvas's dialog, danger-toned, with the focus on 'Huỷ'", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await chooseDeactivate(user, "tuan.t1");
    const box = within(await dialog("Vô hiệu hoá tuan.t1?"));
    expect(
      box.getByText(
        "Lê Tuấn bị đăng xuất ngay và không đăng nhập được nữa. Các quyết định đã ghi vẫn giữ nguyên. Có thể kích hoạt lại sau.",
      ),
    ).toBeInTheDocument();
    expect(box.getByRole("button", { name: "Huỷ" })).toHaveFocus();
    expect(box.getByRole("button", { name: "Vô hiệu hoá" })).toBeInTheDocument();
    expect(b.writes()).toEqual([]);
  });

  it("sends PATCH {is_active: false} as JSON when confirmed, and says so", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await chooseDeactivate(user, "lan.t1");
    await user.click(
      within(await dialog("Vô hiệu hoá lan.t1?")).getByRole("button", { name: "Vô hiệu hoá" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toEqual([
      {
        method: "PATCH",
        path: `/api/admin/users/${ID(1)}`,
        body: { is_active: false },
        contentType: "application/json",
      },
    ]);
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Đã vô hiệu hoá lan.t1. Người đó đã bị đăng xuất.",
    );
    // the row is now an inactive one, which offers reactivation
    await waitFor(async () =>
      expect((await rowOf("lan.t1")).q.getByText("Vô hiệu")).toBeInTheDocument(),
    );
  });

  it("names the account by its username when it has no display name", async () => {
    backend({ users: [HOA, account(7, { username: "no.name", display_name: null })] });
    const user = userEvent.setup();
    renderPage();
    await chooseDeactivate(user, "no.name");
    expect(
      within(await dialog("Vô hiệu hoá no.name?")).getByText(/^no\.name bị đăng xuất ngay/),
    ).toBeInTheDocument();
  });

  it("sends nothing when cancelled", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await chooseDeactivate(user, "lan.t1");
    await user.click(
      within(await dialog("Vô hiệu hoá lan.t1?")).getByRole("button", { name: "Huỷ" }),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(b.writes()).toEqual([]);
    // the focus is back on the row's more button, where the dialog was opened from
    expect(
      (await rowOf("lan.t1")).q.getByRole("button", { name: "Thêm thao tác cho lan.t1" }),
    ).toHaveFocus();
  });

  it("answers 409 last_active_admin with the refusal card: its text and only 'Đóng'", async () => {
    const b = backend({ patch: () => refuse(409, { reason: "last_active_admin" }) });
    const user = userEvent.setup();
    renderPage();
    await chooseDeactivate(user, "minh.t2");
    await user.click(
      within(await dialog("Vô hiệu hoá minh.t2?")).getByRole("button", { name: "Vô hiệu hoá" }),
    );
    const box = within(await dialog("Vô hiệu hoá minh.t2?"));
    expect(await box.findByRole("alert")).toHaveTextContent(S.admin.reason.last_active_admin);
    expect(box.queryByRole("button", { name: "Vô hiệu hoá" })).not.toBeInTheDocument();
    await user.click(box.getByRole("button", { name: "Đóng" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(b.writes()).toHaveLength(1);
  });

  it("answers 409 self_change and 403 forbidden with their texts and only 'Đóng'", async () => {
    for (const [reply, text] of [
      [() => refuse(409, { reason: "self_change" }), S.admin.reason.self_change],
      [() => refuse(403, "forbidden"), S.admin.reason.forbidden],
    ] as const) {
      backend({ patch: reply });
      const user = userEvent.setup();
      const { unmount } = renderPage("someone.else");
      await chooseDeactivate(user, "hoa.admin");
      await user.click(
        within(await dialog("Vô hiệu hoá hoa.admin?")).getByRole("button", { name: "Vô hiệu hoá" }),
      );
      const box = within(await dialog("Vô hiệu hoá hoa.admin?"));
      expect(await box.findByRole("alert")).toHaveTextContent(text);
      expect(box.queryByRole("button", { name: "Vô hiệu hoá" })).not.toBeInTheDocument();
      expect(box.getByRole("button", { name: "Đóng" })).toBeInTheDocument();
      unmount();
      server.resetHandlers();
    }
  });

  it("answers a 404 with its text, and a 500 with a failed save the admin can retry", async () => {
    backend({ patch: () => refuse(404, { reason: "not_found" }) });
    const user = userEvent.setup();
    const first = renderPage();
    await chooseDeactivate(user, "lan.t1");
    await user.click(
      within(await dialog("Vô hiệu hoá lan.t1?")).getByRole("button", { name: "Vô hiệu hoá" }),
    );
    expect(await within(await dialog("Vô hiệu hoá lan.t1?")).findByRole("alert")).toHaveTextContent(
      S.admin.reason.not_found,
    );
    first.unmount();
    server.resetHandlers();

    backend({ patch: () => refuse(500, "boom") });
    renderPage();
    await chooseDeactivate(user, "lan.t1");
    const box = within(await dialog("Vô hiệu hoá lan.t1?"));
    await user.click(box.getByRole("button", { name: "Vô hiệu hoá" }));
    expect(await box.findByRole("alert")).toHaveTextContent("Không lưu được: máy chủ trả lỗi");
    expect(box.getByRole("button", { name: "Vô hiệu hoá" })).toBeEnabled();
  });

  it("has no axe violation with the dialog open", async () => {
    backend();
    const user = userEvent.setup();
    const { container } = renderPage();
    await chooseDeactivate(user, "lan.t1");
    await dialog("Vô hiệu hoá lan.t1?");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("reactivating", () => {
  // It restores login with the old password, admin rights included: a light confirmation (a primary-tone
  // dialog), not the red one of deactivating.
  const open = async (username: string) => {
    const user = userEvent.setup();
    const { q } = await rowOf(username);
    await user.click(q.getByRole("button", { name: /^Kích hoạt lại/ }));
    const box = within(await dialog(`Kích hoạt lại ${username}?`));
    return { user, box };
  };

  it("opens a confirmation that says what it restores, and sends nothing yet", async () => {
    const b = backend();
    renderPage();
    const { box } = await open("an.t2");
    expect(
      box.getByText("Tài khoản đăng nhập được ngay bằng mật khẩu hiện tại."),
    ).toBeInTheDocument();
    expect(box.getByRole("button", { name: "Huỷ" })).toBeInTheDocument();
    // primary tone: the focus opens on the confirm button
    expect(box.getByRole("button", { name: "Kích hoạt lại" })).toHaveFocus();
    expect(b.writes()).toEqual([]);
  });

  it("sends PATCH {is_active: true} as JSON when confirmed, says so, and shows the account active", async () => {
    const b = backend();
    renderPage();
    const { user, box } = await open("an.t2");
    await user.click(box.getByRole("button", { name: "Kích hoạt lại" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(await screen.findByRole("status")).toHaveTextContent("Đã kích hoạt lại an.t2.");
    expect(b.writes()).toEqual([
      {
        method: "PATCH",
        path: `/api/admin/users/${ID(5)}`,
        body: { is_active: true },
        contentType: "application/json",
      },
    ]);
    await waitFor(async () =>
      expect((await rowOf("an.t2")).q.getByText("Hoạt động")).toBeInTheDocument(),
    );
    expect(b.gets()).toBe(2);
  });

  it("sends nothing when cancelled, with Huỷ or Escape", async () => {
    const b = backend();
    renderPage();
    const first = await open("an.t2");
    await first.user.click(first.box.getByRole("button", { name: "Huỷ" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    const second = await open("an.t2");
    await second.user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(b.writes()).toEqual([]);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("answers 403 forbidden and 404 with their texts and only 'Đóng', inside the dialog", async () => {
    for (const [reply, text] of [
      [() => refuse(403, "forbidden"), S.admin.reason.forbidden],
      [() => refuse(404, { reason: "not_found" }), S.admin.reason.not_found],
    ] as const) {
      backend({ patch: reply });
      const view = renderPage();
      const { user, box } = await open("an.t2");
      await user.click(box.getByRole("button", { name: "Kích hoạt lại" }));
      expect(await box.findByRole("alert")).toHaveTextContent(text);
      expect(box.queryByRole("button", { name: "Kích hoạt lại" })).not.toBeInTheDocument();
      await user.click(box.getByRole("button", { name: "Đóng" }));
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      view.unmount();
      server.resetHandlers();
    }
  });

  it("answers a 422, a 500 and a lost connection with a text in the dialog, which can be retried", async () => {
    for (const [reply, text] of [
      [() => refuse(422, { field: "is_active", reason: "invalid" }), S.admin.reason.invalid],
      [() => refuse(500, "boom"), "Không lưu được: máy chủ trả lỗi. Thử lại sau ít phút."],
      [() => HttpResponse.error(), "Không lưu được: mất kết nối máy chủ. Thử lại."],
    ] as const) {
      backend({ patch: reply });
      const view = renderPage();
      const { user, box } = await open("an.t2");
      await user.click(box.getByRole("button", { name: "Kích hoạt lại" }));
      expect(await box.findByRole("alert")).toHaveTextContent(text);
      expect(box.getByRole("button", { name: "Kích hoạt lại" })).toBeEnabled();
      view.unmount();
      server.resetHandlers();
    }
  });

  it("sends one request when the confirm button is pressed twice with a pause between", async () => {
    const b = backend({
      patch: async () => {
        await delay(50);
        return HttpResponse.json({ ...AN, is_active: true });
      },
    });
    renderPage();
    const { user, box } = await open("an.t2");
    await user.dblClick(box.getByRole("button", { name: "Kích hoạt lại" }));
    await screen.findByRole("status");
    expect(b.writes()).toHaveLength(1);
  });

  it("has no axe violation with the dialog open", async () => {
    backend();
    const { container } = renderPage();
    await open("an.t2");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

// ============================================================================================================
// reset password
// ============================================================================================================

describe("resetting a password", () => {
  const open = async (username: string) => {
    const user = userEvent.setup();
    const { q } = await rowOf(username);
    await user.click(q.getByRole("button", { name: /^Đặt lại mật khẩu/ }));
    const box = within(await dialog(`Đặt lại mật khẩu cho ${username}`));
    return { user, box };
  };

  it("opens the canvas's dialog: two password fields, the hint, and a confirm that waits", async () => {
    const b = backend();
    renderPage();
    const { box } = await open("minh.t2");
    expect(box.getByLabelText("Mật khẩu tạm")).toHaveAttribute("type", "password");
    expect(box.getByLabelText("Mật khẩu tạm")).toHaveAttribute("autocomplete", "new-password");
    expect(box.getByLabelText("Nhập lại")).toHaveAttribute("type", "password");
    expect(box.getByLabelText("Nhập lại")).toHaveAttribute("autocomplete", "new-password");
    expect(
      box.getByText(
        "Tối thiểu 12 ký tự. Báo mật khẩu tạm cho người dùng qua kênh riêng; trang không hiển thị lại.",
      ),
    ).toBeInTheDocument();
    expect(box.getByRole("button", { name: "Đặt lại" })).toBeDisabled();
    expect(box.getByLabelText("Mật khẩu tạm")).toHaveFocus();
    expect(b.writes()).toEqual([]);
  });

  it("says who is signed out by a reset", async () => {
    backend();
    renderPage();
    const { box } = await open("minh.t2");
    expect(box.getByText(/Mọi phiên đang mở của minh\.t2 bị đăng xuất/)).toBeInTheDocument();
  });

  it("warns on the caller's own account that it ends their own sessions, and on no other", async () => {
    backend();
    const first = renderPage();
    const { box } = await open("hoa.admin");
    expect(
      box.getByText(
        "Đây là tài khoản của bạn: đặt lại mật khẩu cũng đăng xuất mọi phiên của bạn, kể cả phiên này. Bạn sẽ phải đăng nhập lại.",
      ),
    ).toBeInTheDocument();
    first.unmount();
    server.resetHandlers();
    backend();
    renderPage();
    const other = await open("minh.t2");
    expect(other.box.queryByText(/Đây là tài khoản của bạn/)).not.toBeInTheDocument();
  });

  it("says how many characters are missing as the password is typed", async () => {
    backend();
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), "12345678");
    expect(box.getByText("Cần tối thiểu 12 ký tự, đang có 8")).toBeInTheDocument();
    expect(box.getByLabelText("Mật khẩu tạm")).toHaveAttribute("aria-invalid", "true");
    expect(box.getByRole("button", { name: "Đặt lại" })).toBeDisabled();
    await user.type(box.getByLabelText("Mật khẩu tạm"), "9abc");
    expect(box.queryByText(/Cần tối thiểu/)).not.toBeInTheDocument();
    expect(box.getByLabelText("Mật khẩu tạm")).not.toHaveAttribute("aria-invalid", "true");
  });

  it("counts characters, not UTF-16 units: eleven emoji are too short", async () => {
    backend();
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.click(box.getByLabelText("Mật khẩu tạm"));
    await user.paste("😀".repeat(11));
    expect(box.getByText("Cần tối thiểu 12 ký tự, đang có 11")).toBeInTheDocument();
  });

  it("says the two passwords differ, and keeps the confirm button down until they match", async () => {
    backend();
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(box.getByLabelText("Nhập lại"), `${GOOD.slice(0, -1)}!`);
    expect(box.getByText("Không khớp với mật khẩu")).toBeInTheDocument();
    expect(box.getByLabelText("Nhập lại")).toHaveAttribute("aria-invalid", "true");
    expect(box.getByRole("button", { name: "Đặt lại" })).toBeDisabled();
    await user.clear(box.getByLabelText("Nhập lại"));
    await user.type(box.getByLabelText("Nhập lại"), GOOD);
    expect(box.queryByText("Không khớp với mật khẩu")).not.toBeInTheDocument();
    expect(box.getByRole("button", { name: "Đặt lại" })).toBeEnabled();
  });

  it("sends POST {password} as JSON when confirmed, says so, and never shows the password", async () => {
    const b = backend();
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(box.getByLabelText("Nhập lại"), GOOD);
    await user.click(box.getByRole("button", { name: "Đặt lại" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toEqual([
      {
        method: "POST",
        path: `/api/admin/users/${ID(3)}/password`,
        body: { password: GOOD },
        contentType: "application/json",
      },
    ]);
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Đã đặt lại mật khẩu của minh.t2. Báo mật khẩu tạm qua kênh riêng; trang không hiển thị lại.",
    );
    expect(document.body.textContent).not.toContain(GOOD);
    expect(b.gets()).toBe(2);
  });

  it("sends nothing when cancelled, and a reopened dialog holds nothing typed before", async () => {
    const b = backend();
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.click(box.getByRole("button", { name: "Huỷ" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(b.writes()).toEqual([]);
    const again = await open("minh.t2");
    expect(again.box.getByLabelText("Mật khẩu tạm")).toHaveValue("");
    expect(again.box.getByLabelText("Nhập lại")).toHaveValue("");
  });

  it("shows a 422 too_short at the password field, with the server's number", async () => {
    backend({ password: () => refuse(422, { field: "password", reason: "too_short", min: 12 }) });
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(box.getByLabelText("Nhập lại"), GOOD);
    await user.click(box.getByRole("button", { name: "Đặt lại" }));
    expect(await box.findByText("Cần tối thiểu 12 ký tự")).toBeInTheDocument();
    expect(box.getByLabelText("Mật khẩu tạm")).toHaveAttribute("aria-invalid", "true");
    expect(box.getByRole("button", { name: "Huỷ" })).toBeEnabled();
  });

  it("shows a 422 too_long and a 422 invalid at the password field", async () => {
    backend({ password: () => refuse(422, { field: "password", reason: "too_long", max: 256 }) });
    const first = renderPage();
    const one = await open("minh.t2");
    await one.user.type(one.box.getByLabelText("Mật khẩu tạm"), GOOD);
    await one.user.type(one.box.getByLabelText("Nhập lại"), GOOD);
    await one.user.click(one.box.getByRole("button", { name: "Đặt lại" }));
    expect(await one.box.findByText("Tối đa 256 ký tự")).toBeInTheDocument();
    first.unmount();
    server.resetHandlers();

    backend({ password: () => refuse(422, { field: "password", reason: "invalid" }) });
    renderPage();
    const two = await open("minh.t2");
    await two.user.type(two.box.getByLabelText("Mật khẩu tạm"), GOOD);
    await two.user.type(two.box.getByLabelText("Nhập lại"), GOOD);
    await two.user.click(two.box.getByRole("button", { name: "Đặt lại" }));
    expect(await two.box.findByText("Mật khẩu chứa ký tự không hợp lệ")).toBeInTheDocument();
  });

  it("clears the server's text when the password is edited", async () => {
    backend({ password: () => refuse(422, { field: "password", reason: "too_short", min: 12 }) });
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(box.getByLabelText("Nhập lại"), GOOD);
    await user.click(box.getByRole("button", { name: "Đặt lại" }));
    await box.findByText("Cần tối thiểu 12 ký tự");
    await user.type(box.getByLabelText("Mật khẩu tạm"), "x");
    expect(box.queryByText("Cần tối thiểu 12 ký tự")).not.toBeInTheDocument();
  });

  it("answers a 404 with its text and only 'Đóng'", async () => {
    backend({ password: () => refuse(404, { reason: "not_found" }) });
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(box.getByLabelText("Nhập lại"), GOOD);
    await user.click(box.getByRole("button", { name: "Đặt lại" }));
    expect(await box.findByRole("alert")).toHaveTextContent(S.admin.reason.not_found);
    expect(box.queryByRole("button", { name: "Đặt lại" })).not.toBeInTheDocument();
    expect(box.getByRole("button", { name: "Đóng" })).toBeInTheDocument();
  });

  it("answers a 403 forbidden with its text and only 'Đóng'", async () => {
    backend({ password: () => refuse(403, "forbidden") });
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(box.getByLabelText("Nhập lại"), GOOD);
    await user.click(box.getByRole("button", { name: "Đặt lại" }));
    expect(await box.findByRole("alert")).toHaveTextContent(S.admin.reason.forbidden);
    expect(box.queryByRole("button", { name: "Đặt lại" })).not.toBeInTheDocument();
  });

  it("answers a 500 and a lost connection with a failed save, and keeps what was typed", async () => {
    backend({ password: () => refuse(500, "boom") });
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(box.getByLabelText("Nhập lại"), GOOD);
    await user.click(box.getByRole("button", { name: "Đặt lại" }));
    expect(await box.findByRole("alert")).toHaveTextContent("Không lưu được: máy chủ trả lỗi");
    expect(box.getByLabelText("Mật khẩu tạm")).toHaveValue(GOOD);
    expect(box.getByRole("button", { name: "Đặt lại" })).toBeEnabled();
  });

  it("has no axe violation with the dialog open, with a hint showing", async () => {
    backend();
    const { container } = renderPage();
    const { user, box } = await open("hoa.admin");
    await user.type(box.getByLabelText("Mật khẩu tạm"), "1234");
    await box.findByText("Cần tối thiểu 12 ký tự, đang có 4");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

// ============================================================================================================
// unlock
// ============================================================================================================

describe("unlocking", () => {
  const open = async () => {
    const user = userEvent.setup();
    const { q } = await rowOf("tuan.t1");
    await user.click(q.getByRole("button", { name: /^Mở khoá/ }));
    const box = within(await dialog("Mở khoá tuan.t1?"));
    return { user, box };
  };

  it("opens the canvas's dialog, naming the time and the failed attempts", async () => {
    const b = backend();
    renderPage();
    const { box } = await open();
    expect(
      box.getByText(
        "Tài khoản bị khoá đến 09:55 sau 5 lần nhập sai mật khẩu. Mở khoá xoá số lần sai và cho đăng nhập ngay.",
      ),
    ).toBeInTheDocument();
    expect(box.getByRole("button", { name: "Huỷ" })).toBeInTheDocument();
    expect(box.getByRole("button", { name: "Mở khoá" })).toBeInTheDocument();
    expect(b.writes()).toEqual([]);
  });

  it("sends POST with the JSON body {} when confirmed, says so, and shows the account unlocked", async () => {
    const b = backend();
    renderPage();
    const { user, box } = await open();
    await user.click(box.getByRole("button", { name: "Mở khoá" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toEqual([
      {
        method: "POST",
        path: `/api/admin/users/${ID(2)}/unlock`,
        body: {},
        contentType: "application/json",
      },
    ]);
    expect(await screen.findByRole("status")).toHaveTextContent("Đã mở khoá tuan.t1.");
    await waitFor(async () =>
      expect((await rowOf("tuan.t1")).q.getByText("Hoạt động")).toBeInTheDocument(),
    );
    expect(b.gets()).toBe(2);
  });

  it("sends nothing when cancelled", async () => {
    const b = backend();
    renderPage();
    const { user, box } = await open();
    await user.click(box.getByRole("button", { name: "Huỷ" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(b.writes()).toEqual([]);
  });

  it("answers a 404 with its text and only 'Đóng'", async () => {
    const b = backend({ unlock: () => refuse(404, { reason: "not_found" }) });
    renderPage();
    const { user, box } = await open();
    await user.click(box.getByRole("button", { name: "Mở khoá" }));
    expect(await box.findByRole("alert")).toHaveTextContent(S.admin.reason.not_found);
    expect(box.queryByRole("button", { name: "Mở khoá" })).not.toBeInTheDocument();
    await waitFor(() => expect(b.gets()).toBe(2));
  });

  it("answers a 403 with its text, a 422 with the server's text, and a 500 with a failed save", async () => {
    backend({ unlock: () => refuse(403, "forbidden") });
    const first = renderPage();
    const one = await open();
    await one.user.click(one.box.getByRole("button", { name: "Mở khoá" }));
    expect(await one.box.findByRole("alert")).toHaveTextContent(S.admin.reason.forbidden);
    expect(one.box.queryByRole("button", { name: "Mở khoá" })).not.toBeInTheDocument();
    first.unmount();
    server.resetHandlers();

    backend({ unlock: () => refuse(422, { field: "body", reason: "invalid" }) });
    const second = renderPage();
    const two = await open();
    await two.user.click(two.box.getByRole("button", { name: "Mở khoá" }));
    expect(await two.box.findByRole("alert")).toHaveTextContent(S.admin.reason.invalid);
    second.unmount();
    server.resetHandlers();

    backend({ unlock: () => refuse(500, "boom") });
    renderPage();
    const three = await open();
    await three.user.click(three.box.getByRole("button", { name: "Mở khoá" }));
    expect(await three.box.findByRole("alert")).toHaveTextContent(
      "Không lưu được: máy chủ trả lỗi",
    );
    expect(three.box.getByRole("button", { name: "Mở khoá" })).toBeEnabled();
  });

  it("has no axe violation with the dialog open", async () => {
    backend();
    const { container } = renderPage();
    await open();
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

// ============================================================================================================
// the create form
// ============================================================================================================

describe("the create form", () => {
  const fill = async (
    user: ReturnType<typeof userEvent.setup>,
    v: { username?: string; name?: string; role?: string; password?: string; repeat?: string },
  ) => {
    const form = create();
    if (v.username !== undefined) await user.type(form.getByLabelText("Tên đăng nhập"), v.username);
    if (v.name !== undefined) await user.type(form.getByLabelText("Tên hiển thị"), v.name);
    if (v.role !== undefined)
      await user.click(form.getByRole("radio", { name: new RegExp(`^${v.role}`) }));
    if (v.password !== undefined) await user.type(form.getByLabelText("Mật khẩu tạm"), v.password);
    if (v.repeat !== undefined) await user.type(form.getByLabelText("Nhập lại mật khẩu"), v.repeat);
  };
  const submit = (user: ReturnType<typeof userEvent.setup>) =>
    user.click(create().getByRole("button", { name: "Tạo tài khoản" }));
  const VALID = {
    username: "an.t1",
    name: "An Nguyễn",
    role: "tier1",
    password: GOOD,
    repeat: GOOD,
  };

  it("has the fields of the canvas, the three roles with their descriptions, and the hint", async () => {
    backend();
    renderPage();
    await table();
    const form = create();
    expect(form.getByRole("heading", { level: 2, name: "Tạo người dùng" })).toBeInTheDocument();
    expect(form.getByLabelText("Tên đăng nhập")).toHaveAttribute("placeholder", "vd. an.t1");
    expect(form.getByLabelText("Tên hiển thị")).toBeInTheDocument();
    expect(form.getByLabelText("Mật khẩu tạm")).toHaveAttribute("type", "password");
    expect(form.getByLabelText("Mật khẩu tạm")).toHaveAttribute("autocomplete", "new-password");
    expect(form.getByLabelText("Nhập lại mật khẩu")).toHaveAttribute("type", "password");
    const group = within(form.getByRole("radiogroup", { name: "Vai trò" }));
    expect(group.getAllByRole("radio")).toHaveLength(3);
    expect(
      group.getByRole("radio", { name: /^tier1\s*xử lý hàng đợi, quyết alert/ }),
    ).not.toBeChecked();
    expect(
      group.getByRole("radio", { name: /^tier2\s*điều tra case, chạy ②, hỏi AI/ }),
    ).not.toBeChecked();
    expect(
      group.getByRole("radio", { name: /^admin\s*mọi quyền, gồm quản trị người dùng và hạn mức/ }),
    ).not.toBeChecked();
    expect(
      form.getByText("Tối thiểu 12 ký tự. Mật khẩu chỉ lưu dạng băm argon2id, không hiển thị lại."),
    ).toBeInTheDocument();
    expect(form.getByRole("button", { name: "Tạo tài khoản" })).toBeEnabled();
  });

  it("shows a field's error where the field is, marks it invalid, and sends nothing: empty form", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await submit(user);
    const form = create();
    expect(form.getByLabelText("Tên đăng nhập")).toHaveAttribute("aria-invalid", "true");
    expect(form.getByLabelText("Tên hiển thị")).toHaveAttribute("aria-invalid", "true");
    expect(form.getByLabelText("Mật khẩu tạm")).toHaveAttribute("aria-invalid", "true");
    expect(form.getByText("Chưa chọn vai trò")).toBeInTheDocument();
    expect(form.getAllByText("Không được để trống").length).toBeGreaterThanOrEqual(3);
    expect(b.writes()).toEqual([]);
  });

  it("says 'Cần tối thiểu 12 ký tự, đang có 8' and 'Không khớp với mật khẩu' as the canvas does", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, { ...VALID, password: "12345678", repeat: "1234567" });
    await submit(user);
    const form = create();
    expect(form.getByText("Cần tối thiểu 12 ký tự, đang có 8")).toBeInTheDocument();
    expect(form.getByText("Không khớp với mật khẩu")).toBeInTheDocument();
    expect(form.getByLabelText("Mật khẩu tạm")).toHaveAttribute("aria-invalid", "true");
    expect(form.getByLabelText("Nhập lại mật khẩu")).toHaveAttribute("aria-invalid", "true");
    expect(b.writes()).toEqual([]);
  });

  it("counts the password in characters, not UTF-16 units, before it posts", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, { ...VALID, password: undefined, repeat: undefined });
    for (const label of ["Mật khẩu tạm", "Nhập lại mật khẩu"]) {
      await user.click(create().getByLabelText(label));
      await user.paste("😀".repeat(11));
    }
    await submit(user);
    expect(create().getByText("Cần tối thiểu 12 ký tự, đang có 11")).toBeInTheDocument();
    expect(b.writes()).toEqual([]);
  });

  it("refuses a username the server's pattern refuses, before it posts", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, { name: "An", role: "tier1", password: GOOD, repeat: GOOD });
    for (const bad of ["ab", "An.T1", "an t1", "a".repeat(33), "an@t1"]) {
      const field = create().getByLabelText("Tên đăng nhập");
      await user.clear(field);
      await user.click(field);
      await user.paste(bad);
      await submit(user);
      expect(
        create().getByText(/Chỉ dùng chữ thường a–z, số, dấu chấm, gạch dưới, gạch ngang/),
      ).toBeInTheDocument();
      expect(field).toHaveAttribute("aria-invalid", "true");
    }
    expect(b.writes()).toEqual([]);
  });

  it.each(["system", "llm"])(
    "refuses the reserved username %s before it posts, with the server's text",
    async (name) => {
      const b = backend();
      const user = userEvent.setup();
      renderPage();
      await table();
      await fill(user, { ...VALID, username: name });
      await submit(user);
      expect(create().getByText(S.admin.reason.reserved)).toBeInTheDocument();
      expect(create().getByLabelText("Tên đăng nhập")).toHaveAttribute("aria-invalid", "true");
      expect(b.writes()).toEqual([]);
    },
  );

  it("refuses a display name that is only blanks, or over 100 characters, before it posts", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, { ...VALID, name: "   " });
    await submit(user);
    expect(create().getByText("Không được để trống")).toBeInTheDocument();
    const field = create().getByLabelText("Tên hiển thị");
    await user.clear(field);
    await user.click(field);
    await user.paste("n".repeat(101));
    await submit(user);
    expect(create().getByText("Tối đa 100 ký tự")).toBeInTheDocument();
    expect(b.writes()).toEqual([]);
  });

  it("clears a field's error when that field is edited", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await submit(user);
    expect(create().getByText("Chưa chọn vai trò")).toBeInTheDocument();
    await user.click(create().getByRole("radio", { name: /^admin/ }));
    expect(create().queryByText("Chưa chọn vai trò")).not.toBeInTheDocument();
    expect(create().getByLabelText("Tên đăng nhập")).toHaveAttribute("aria-invalid", "true");
    await user.type(create().getByLabelText("Tên đăng nhập"), "an.t1");
    expect(create().getByLabelText("Tên đăng nhập")).not.toHaveAttribute("aria-invalid", "true");
  });

  it("posts the four fields as JSON, nothing else, and says the account was made", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, VALID);
    await submit(user);
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Đã tạo tài khoản an.t1 (tier1). Báo mật khẩu tạm qua kênh riêng; trang không hiển thị lại.",
    );
    expect(b.writes()).toEqual([
      {
        method: "POST",
        path: "/api/admin/users",
        body: { username: "an.t1", display_name: "An Nguyễn", role: "tier1", password: GOOD },
        contentType: "application/json",
      },
    ]);
  });

  it("empties the form after it succeeds, the password with it, and shows the new account", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, VALID);
    await submit(user);
    await screen.findByRole("status");
    const form = create();
    expect(form.getByLabelText("Tên đăng nhập")).toHaveValue("");
    expect(form.getByLabelText("Tên hiển thị")).toHaveValue("");
    expect(form.getByLabelText("Mật khẩu tạm")).toHaveValue("");
    expect(form.getByLabelText("Nhập lại mật khẩu")).toHaveValue("");
    for (const radio of form.getAllByRole("radio")) expect(radio).not.toBeChecked();
    expect(document.body.textContent).not.toContain(GOOD);
    expect(b.gets()).toBe(2);
    expect((await rowOf("an.t1")).q.getByText("chưa đăng nhập")).toBeInTheDocument();
  });

  it("submits with Enter in a field, as a form does", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, { ...VALID, repeat: undefined });
    await user.type(create().getByLabelText("Nhập lại mật khẩu"), `${GOOD}{Enter}`);
    await screen.findByRole("status");
    expect(b.writes()).toHaveLength(1);
  });

  it("holds the button while the request is out, so it is sent once", async () => {
    const b = backend({
      create: async () => {
        await delay(50);
        return HttpResponse.json({ user_id: ID(99) }, { status: 201 });
      },
    });
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, VALID);
    await user.dblClick(create().getByRole("button", { name: "Tạo tài khoản" }));
    await screen.findByRole("status");
    expect(b.writes()).toHaveLength(1);
  });

  it("shows a 409 username_taken at the username field, and keeps what was typed", async () => {
    backend({ create: () => refuse(409, { reason: "username_taken" }) });
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, { ...VALID, username: "an.t2" });
    await submit(user);
    const form = create();
    expect(await form.findByText("Tên đăng nhập đã tồn tại")).toBeInTheDocument();
    expect(form.getByLabelText("Tên đăng nhập")).toHaveAttribute("aria-invalid", "true");
    expect(form.getByLabelText("Tên đăng nhập")).toHaveValue("an.t2");
    expect(form.getByLabelText("Mật khẩu tạm")).toHaveValue(GOOD);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it.each<[field: string, label: string, body: Record<string, unknown>, text: string]>([
    ["username", "Tên đăng nhập", { reason: "reserved" }, S.admin.reason.reserved],
    [
      "username",
      "Tên đăng nhập",
      { reason: "invalid" },
      "Chỉ dùng chữ thường a–z, số, dấu chấm, gạch dưới, gạch ngang; dài 3 đến 32 ký tự",
    ],
    ["username", "Tên đăng nhập", { reason: "empty" }, "Không được để trống"],
    [
      "display_name",
      "Tên hiển thị",
      { reason: "invalid" },
      "Tên hiển thị không được chứa ký tự điều khiển hay ký tự vô hình",
    ],
    ["display_name", "Tên hiển thị", { reason: "too_long", max: 100 }, "Tối đa 100 ký tự"],
    ["display_name", "Tên hiển thị", { reason: "empty" }, "Không được để trống"],
    ["password", "Mật khẩu tạm", { reason: "too_short", min: 12 }, "Cần tối thiểu 12 ký tự"],
    ["password", "Mật khẩu tạm", { reason: "too_long", max: 256 }, "Tối đa 256 ký tự"],
    ["password", "Mật khẩu tạm", { reason: "invalid" }, "Mật khẩu chứa ký tự không hợp lệ"],
  ])("shows a 422 on %s %j at that field", async (field, label, extra, text) => {
    backend({ create: () => refuse(422, { field, ...extra }) });
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, VALID);
    await submit(user);
    const form = create();
    expect(await form.findByText(text)).toBeInTheDocument();
    expect(form.getByLabelText(label)).toHaveAttribute("aria-invalid", "true");
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows a 422 on the role at the role group", async () => {
    backend({ create: () => refuse(422, { field: "role", reason: "invalid" }) });
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, VALID);
    await submit(user);
    expect(await create().findByText(S.admin.reason.invalid)).toBeInTheDocument();
    expect(create().getByRole("radiogroup", { name: "Vai trò" })).toHaveAttribute(
      "aria-invalid",
      "true",
    );
  });

  it("refuses a display name with a format character at the server, and shows the 422 at the field", async () => {
    // The page does not guess at Cf/Zl/Zp (the server's Unicode tables are the rule): it posts, and the 422 shows.
    const b = backend({
      create: () => refuse(422, { field: "display_name", reason: "invalid" }),
    });
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, { ...VALID, name: "An​Nguyễn" });
    await submit(user);
    expect(
      await create().findByText("Tên hiển thị không được chứa ký tự điều khiển hay ký tự vô hình"),
    ).toBeInTheDocument();
    expect(b.writes()).toHaveLength(1);
    expect(b.writes()[0]?.body).toMatchObject({ display_name: "An​Nguyễn" });
  });

  it("shows a 403 forbidden and a failed save as an alert in the form", async () => {
    backend({ create: () => refuse(403, "forbidden") });
    const user = userEvent.setup();
    const first = renderPage();
    await table();
    await fill(user, VALID);
    await submit(user);
    expect(await create().findByRole("alert")).toHaveTextContent(S.admin.reason.forbidden);
    first.unmount();
    server.resetHandlers();

    backend({ create: () => refuse(500, "boom") });
    renderPage();
    await table();
    await fill(user, VALID);
    await submit(user);
    expect(await create().findByRole("alert")).toHaveTextContent(
      "Không lưu được: máy chủ trả lỗi. Thử lại sau ít phút.",
    );
  });

  it("shows a lost connection as an alert in the form", async () => {
    backend({ create: () => HttpResponse.error() });
    const user = userEvent.setup();
    renderPage();
    await table();
    await fill(user, VALID);
    await submit(user);
    expect(await create().findByRole("alert")).toHaveTextContent(
      "Không lưu được: mất kết nối máy chủ. Thử lại.",
    );
  });

  it("has no axe violation with errors showing", async () => {
    backend();
    const user = userEvent.setup();
    const { container } = renderPage();
    await table();
    await fill(user, { ...VALID, password: "12345678", repeat: "1234567", role: undefined });
    await submit(user);
    await create().findByText("Cần tối thiểu 12 ký tự, đang có 8");
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

// ============================================================================================================
// the whole page
// ============================================================================================================

// ============================================================================================================
// a password is never kept (fix round 1, I1)
// ============================================================================================================

describe("no password stays in the mutation cache", () => {
  // TanStack Query keeps a mutation's variables while a component observes it and for `gcTime` after that
  // (5 minutes by default). A password is in the variables of a create and of a reset, so neither may be
  // there once the write has settled: not after it succeeded, and not after it failed.
  const SECRET = "tr0ub4dor-and-3-horses";
  type User = ReturnType<typeof userEvent.setup>;

  async function submitCreate(user: User) {
    await user.type(create().getByLabelText("Tên đăng nhập"), "an.t1");
    await user.type(create().getByLabelText("Tên hiển thị"), "An");
    await user.click(create().getByRole("radio", { name: /^tier1/ }));
    await user.type(create().getByLabelText("Mật khẩu tạm"), SECRET);
    await user.type(create().getByLabelText("Nhập lại mật khẩu"), SECRET);
    await user.click(create().getByRole("button", { name: "Tạo tài khoản" }));
  }

  async function submitReset(user: User) {
    await user.click((await rowOf("minh.t2")).q.getByRole("button", { name: /^Đặt lại mật khẩu/ }));
    const box = within(await dialog("Đặt lại mật khẩu cho minh.t2"));
    await user.type(box.getByLabelText("Mật khẩu tạm"), SECRET);
    await user.type(box.getByLabelText("Nhập lại"), SECRET);
    await user.click(box.getByRole("button", { name: "Đặt lại" }));
    return box;
  }

  it("after an account is made", async () => {
    backend();
    const user = userEvent.setup();
    const { client } = renderPage();
    await table();
    await submitCreate(user);
    await screen.findByRole("status");
    await waitFor(() => expect(mutationCacheHolds(client, SECRET)).toBe(false));
  });

  it.each<[string, () => Response]>([
    ["a 409 username_taken", () => refuse(409, { reason: "username_taken" })],
    ["a 422 at the password", () => refuse(422, { field: "password", reason: "invalid" })],
    ["a 500", () => refuse(500, "boom")],
  ])("after a create the server refused with %s", async (_name, reply) => {
    backend({ create: reply });
    const user = userEvent.setup();
    const { client } = renderPage();
    await table();
    await submitCreate(user);
    await create().findByText(/./, { selector: "[role=alert]" });
    await waitFor(() => expect(mutationCacheHolds(client, SECRET)).toBe(false));
  });

  it("after a password is reset, and the dialog has closed", async () => {
    backend();
    const user = userEvent.setup();
    const { client } = renderPage();
    await submitReset(user);
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await waitFor(() => expect(mutationCacheHolds(client, SECRET)).toBe(false));
  });

  it.each<[string, () => Response]>([
    [
      "a 422 at the password",
      () => refuse(422, { field: "password", reason: "too_short", min: 12 }),
    ],
    ["a 404", () => refuse(404, { reason: "not_found" })],
    ["a 500", () => refuse(500, "boom")],
  ])(
    "after a reset the server refused with %s, with the dialog still open",
    async (_name, reply) => {
      backend({ password: reply });
      const user = userEvent.setup();
      const { client } = renderPage();
      const box = await submitReset(user);
      await box.findByText(/./, { selector: "[role=alert]" });
      expect(screen.getByRole("dialog")).toBeInTheDocument();
      await waitFor(() => expect(mutationCacheHolds(client, SECRET)).toBe(false));
    },
  );

  it("holds nothing when a typed reset is cancelled before it is sent", async () => {
    backend();
    const user = userEvent.setup();
    const { client } = renderPage();
    await user.click((await rowOf("minh.t2")).q.getByRole("button", { name: /^Đặt lại mật khẩu/ }));
    const box = within(await dialog("Đặt lại mật khẩu cho minh.t2"));
    await user.type(box.getByLabelText("Mật khẩu tạm"), SECRET);
    await user.click(box.getByRole("button", { name: "Huỷ" }));
    expect(mutationCacheHolds(client, SECRET)).toBe(false);
    expect(client.getMutationCache().getAll()).toHaveLength(0);
  });
});

// ============================================================================================================
// the focus when a row changes state (fix round 1, m1)
// ============================================================================================================

describe("the focus after a row changes state", () => {
  it("goes to the row's new main button after Vô hiệu hoá (the old controls are gone)", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    await chooseDeactivate(user, "lan.t1");
    await user.click(
      within(await dialog("Vô hiệu hoá lan.t1?")).getByRole("button", { name: "Vô hiệu hoá" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await waitFor(async () =>
      expect(
        (await rowOf("lan.t1")).q.getByRole("button", { name: "Kích hoạt lại lan.t1" }),
      ).toHaveFocus(),
    );
  });

  it("goes to the row's new main button after Kích hoạt lại", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    await user.click((await rowOf("an.t2")).q.getByRole("button", { name: /^Kích hoạt lại/ }));
    await user.click(
      within(await dialog("Kích hoạt lại an.t2?")).getByRole("button", { name: "Kích hoạt lại" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    await waitFor(async () =>
      expect(
        (await rowOf("an.t2")).q.getByRole("button", { name: "Đặt lại mật khẩu an.t2" }),
      ).toHaveFocus(),
    );
  });

  it("goes to the table when the row is gone from the list that was read again", async () => {
    let reads = 0;
    backend({
      list: () => {
        reads += 1;
        return HttpResponse.json({
          users: reads === 1 ? USERS : USERS.filter((u) => u.user_id !== LAN.user_id),
        });
      },
    });
    const user = userEvent.setup();
    renderPage();
    await chooseDeactivate(user, "lan.t1");
    await user.click(
      within(await dialog("Vô hiệu hoá lan.t1?")).getByRole("button", { name: "Vô hiệu hoá" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    const box = (await table()).closest('[tabindex="-1"]');
    expect(box).not.toBeNull();
    await waitFor(() => expect(box).toHaveFocus());
  });

  it("is left alone by a write that leaves the row as it was (the dialog gives it back to its opener)", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    await user.click((await rowOf("minh.t2")).q.getByRole("button", { name: /^Đặt lại mật khẩu/ }));
    const box = within(await dialog("Đặt lại mật khẩu cho minh.t2"));
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(box.getByLabelText("Nhập lại"), GOOD);
    await user.click(box.getByRole("button", { name: "Đặt lại" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(
      (await rowOf("minh.t2")).q.getByRole("button", { name: "Đặt lại mật khẩu minh.t2" }),
    ).toHaveFocus();
  });
});

// ============================================================================================================
// the reset dialog's live hints (fix round 1, m2)
// ============================================================================================================

describe("the reset dialog's live hints", () => {
  const open = async (username: string) => {
    const user = userEvent.setup();
    await user.click((await rowOf(username)).q.getByRole("button", { name: /^Đặt lại mật khẩu/ }));
    return { user, box: within(await dialog(`Đặt lại mật khẩu cho ${username}`)) };
  };

  it("are polite descriptions of the field, not alerts that speak on every key", async () => {
    backend();
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), "1234");
    const hint = box.getByText("Cần tối thiểu 12 ký tự, đang có 4");
    expect(hint).not.toHaveAttribute("role", "alert");
    expect(hint).toHaveAttribute("aria-live", "polite");
    expect(box.getByLabelText("Mật khẩu tạm")).toHaveAccessibleDescription(
      "Cần tối thiểu 12 ký tự, đang có 4",
    );
    expect(box.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("describe the repeat field the same way when the two differ", async () => {
    backend();
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(box.getByLabelText("Nhập lại"), "x");
    const hint = box.getByText("Không khớp với mật khẩu");
    expect(hint).not.toHaveAttribute("role", "alert");
    expect(hint).toHaveAttribute("aria-live", "polite");
    expect(box.getByLabelText("Nhập lại")).toHaveAccessibleDescription("Không khớp với mật khẩu");
    expect(box.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("keep their live region on the page when they are empty, so a change is announced", async () => {
    backend();
    renderPage();
    const { box } = await open("minh.t2");
    expect(
      document.querySelectorAll('[role="dialog"] [aria-live="polite"]').length,
    ).toBeGreaterThanOrEqual(2);
    expect(box.getByLabelText("Mật khẩu tạm")).not.toHaveAttribute("aria-invalid", "true");
  });

  it("leave role=alert to the server's answer about the password", async () => {
    backend({ password: () => refuse(422, { field: "password", reason: "too_short", min: 12 }) });
    renderPage();
    const { user, box } = await open("minh.t2");
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(box.getByLabelText("Nhập lại"), GOOD);
    await user.click(box.getByRole("button", { name: "Đặt lại" }));
    const alert = await box.findByRole("alert");
    expect(alert).toHaveTextContent("Cần tối thiểu 12 ký tự");
    expect(box.getByLabelText("Mật khẩu tạm")).toHaveAccessibleDescription(
      "Cần tối thiểu 12 ký tự",
    );
  });
});

// ============================================================================================================
// a second press in the same tick (the console's ruling for every write)
// ============================================================================================================

describe("a second press in the same tick", () => {
  // TanStack Query 5 tells React that a mutation is pending only on a `setTimeout(0)`, so two presses before
  // it fires both find the button enabled and `isPending` false. `fireEvent` with nothing awaited between
  // the two is that case (`userEvent` waits between them, which hides it). A ref latches each write.
  const twice = (element: HTMLElement) => {
    fireEvent.click(element);
    fireEvent.click(element);
  };

  it("sends one role change", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "tier2");
    twice(
      within(await dialog("Đổi vai trò của lan.t1?")).getByRole("button", { name: "Đổi vai trò" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toHaveLength(1);
  });

  it("sends one deactivation", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await chooseDeactivate(user, "lan.t1");
    twice(within(await dialog("Vô hiệu hoá lan.t1?")).getByRole("button", { name: "Vô hiệu hoá" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toHaveLength(1);
  });

  it("sends one reactivation", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await user.click((await rowOf("an.t2")).q.getByRole("button", { name: /^Kích hoạt lại/ }));
    twice(
      within(await dialog("Kích hoạt lại an.t2?")).getByRole("button", { name: "Kích hoạt lại" }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toHaveLength(1);
  });

  it("sends one password reset", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await user.click((await rowOf("minh.t2")).q.getByRole("button", { name: /^Đặt lại mật khẩu/ }));
    const box = within(await dialog("Đặt lại mật khẩu cho minh.t2"));
    await user.type(box.getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(box.getByLabelText("Nhập lại"), GOOD);
    twice(box.getByRole("button", { name: "Đặt lại" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toHaveLength(1);
  });

  it("sends one unlock", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await user.click((await rowOf("tuan.t1")).q.getByRole("button", { name: /^Mở khoá/ }));
    twice(within(await dialog("Mở khoá tuan.t1?")).getByRole("button", { name: "Mở khoá" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toHaveLength(1);
  });

  it("sends one create", async () => {
    const b = backend();
    const user = userEvent.setup();
    renderPage();
    await table();
    await user.type(create().getByLabelText("Tên đăng nhập"), "an.t1");
    await user.type(create().getByLabelText("Tên hiển thị"), "An");
    await user.click(create().getByRole("radio", { name: /^tier1/ }));
    await user.type(create().getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(create().getByLabelText("Nhập lại mật khẩu"), GOOD);
    twice(create().getByRole("button", { name: "Tạo tài khoản" }));
    await screen.findByRole("status");
    expect(b.writes()).toHaveLength(1);
  });

  it("lets the button be pressed again after the write failed", async () => {
    let fail = true;
    const b = backend({
      patch: () => (fail ? refuse(500, "boom") : HttpResponse.json({ ...LAN, role: "tier2" })),
    });
    const user = userEvent.setup();
    renderPage();
    const { q } = await rowOf("lan.t1");
    await user.selectOptions(q.getByRole("combobox", { name: "Vai trò của lan.t1" }), "tier2");
    const box = within(await dialog("Đổi vai trò của lan.t1?"));
    twice(box.getByRole("button", { name: "Đổi vai trò" }));
    await box.findByRole("alert");
    expect(b.writes()).toHaveLength(1);
    fail = false;
    await user.click(box.getByRole("button", { name: "Đổi vai trò" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(b.writes()).toHaveLength(2);
  });
});

describe("the whole page", () => {
  it("has no axe violation in its normal state", async () => {
    backend();
    const { container } = renderPage();
    await table();
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });

  it("sets no inline style on anything it draws: the CSP forbids the attribute", async () => {
    backend();
    const { container } = renderPage();
    await table();
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("leaves the rest of the page standing when one block's write fails: each block fails alone", async () => {
    backend({ create: () => refuse(500, "boom"), patch: () => refuse(500, "boom") });
    const user = userEvent.setup();
    renderPage();
    await table();
    // the create form fails ...
    await user.type(create().getByLabelText("Tên đăng nhập"), "an.t1");
    await user.type(create().getByLabelText("Tên hiển thị"), "An");
    await user.click(create().getByRole("radio", { name: /^tier1/ }));
    await user.type(create().getByLabelText("Mật khẩu tạm"), GOOD);
    await user.type(create().getByLabelText("Nhập lại mật khẩu"), GOOD);
    await user.click(create().getByRole("button", { name: "Tạo tài khoản" }));
    expect(await create().findByRole("alert")).toHaveTextContent("Không lưu được");
    // ... and a row's reactivation fails ...
    await user.click((await rowOf("an.t2")).q.getByRole("button", { name: /^Kích hoạt lại/ }));
    await user.click(
      within(await dialog("Kích hoạt lại an.t2?")).getByRole("button", { name: "Kích hoạt lại" }),
    );
    await waitFor(() => expect(screen.getAllByRole("alert").length).toBeGreaterThanOrEqual(2));
    // ... and the list, the matrix and both messages are all still on the page.
    expect(within(await table()).getAllByRole("row")).toHaveLength(1 + USERS.length);
    expect(screen.getByRole("table", { name: "Quyền theo vai trò" })).toBeInTheDocument();
    expect(create().getByLabelText("Tên đăng nhập")).toHaveValue("an.t1");
  });

  it("dismisses the toast with its button", async () => {
    backend();
    const user = userEvent.setup();
    renderPage();
    await user.click((await rowOf("an.t2")).q.getByRole("button", { name: /^Kích hoạt lại/ }));
    await user.click(
      within(await dialog("Kích hoạt lại an.t2?")).getByRole("button", { name: "Kích hoạt lại" }),
    );
    const toast = await screen.findByRole("status");
    await user.click(within(toast).getByRole("button", { name: "Đóng" }));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows the text of an account as text: a hostile display name is not markup", async () => {
    backend({
      users: [
        HOA,
        account(7, { username: "evil", display_name: "<img src=x onerror=alert(1)><b>x</b>" }),
      ],
    });
    renderPage();
    expect(
      (await rowOf("evil")).q.getByText("<img src=x onerror=alert(1)><b>x</b>"),
    ).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect((await table()).querySelector("b")).toBeNull();
  });
});
