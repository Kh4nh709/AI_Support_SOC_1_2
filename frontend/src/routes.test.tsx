// src/routes.test.tsx — the route table of the spec §3.1, for each role.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { StrictMode } from "react";
import { MemoryRouter, useLocation } from "react-router";
import { api } from "./api/client";
import { AuthContext, AuthProvider, type AuthState } from "./auth/AuthProvider";
import type { Session } from "./auth/session";
import { AppRoutes } from "./routes";
import { S } from "./strings";

// The queue page needs a query cache and an API; this file tests which route opens for which role, not the
// page (QueuePage.test.tsx does). Its heading is all the route test looks for.
vi.mock("./features/tier1/QueuePage", () => ({
  QueuePage: () => <h1>{S.queue.title}</h1>,
}));
// The same for the alert page (AlertPage.test.tsx tests it): the route test looks for its place, not its content.
vi.mock("./features/tier1/AlertPage", () => ({
  AlertPage: () => <h1>{S.alert.infoHeading}</h1>,
}));

// The users page of the console reads the backend and its own file tests it (UsersPage.test.tsx); here only
// its place in the route table matters.
vi.mock("./features/admin/UsersPage", () => ({
  UsersPage: () => <h1>{S.admin.title.users}</h1>,
}));

// The case pages are real and read the backend; these tests are about the route table, so the backend
// says "no cases" and "no case 3". A request nobody handled fails the test.
const server = setupServer(
  http.get("/api/tier2/cases", () => HttpResponse.json([])),
  http.get("/api/tier2/cases/3", () =>
    HttpResponse.json({ detail: "case not found" }, { status: 404 }),
  ),
);
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const session = (role: Session["role"]): Session => ({
  token: "t",
  role,
  username: "an",
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
});

// The case pages read through TanStack Query, as they do under the app's provider; a fresh client per
// render so no test reads what another cached, and `retry: false` so a failed read shows at once.
const newClient = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });

function Where() {
  const { pathname } = useLocation();
  return <p data-testid="where">{pathname}</p>;
}

function renderAt(path: string, s: Session | null, ready = true) {
  const auth: AuthState = {
    session: s,
    ready,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
  };
  return render(
    <QueryClientProvider client={newClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={[path]}>
          <AppRoutes />
          <Where />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

const where = () => screen.getByTestId("where").textContent;

describe("the route table", () => {
  it.each<[Session["role"], string]>([
    ["tier1", "/queue"],
    ["tier2", "/cases"],
    ["admin", "/admin/overview"],
  ])("sends %s from / to %s", (role, home) => {
    renderAt("/", session(role));
    expect(where()).toBe(home);
  });

  it("sends a visitor with no session from / to /login", () => {
    renderAt("/", null);
    expect(where()).toBe("/login");
    expect(screen.getByRole("heading", { name: S.login.title })).toBeInTheDocument();
  });

  it.each<Session["role"]>(["tier1", "tier2", "admin"])(
    "lets %s read /queue and an alert",
    (role) => {
      renderAt("/queue", session(role));
      expect(where()).toBe("/queue");
      expect(screen.getByRole("heading", { name: S.queue.title })).toBeInTheDocument();
    },
  );

  it.each<Session["role"]>(["tier1", "tier2", "admin"])("lets %s open /alerts/:alertId", (role) => {
    renderAt("/alerts/12", session(role));
    expect(where()).toBe("/alerts/12");
  });

  it.each<Session["role"]>(["tier2", "admin"])(
    "lets %s open /cases and /cases/:caseId",
    async (role) => {
      const cases = renderAt("/cases", session(role));
      expect(where()).toBe("/cases");
      expect(await screen.findByText(S.case.empty)).toBeInTheDocument();
      cases.unmount();
      renderAt("/cases/3", session(role));
      expect(where()).toBe("/cases/3");
      expect(await screen.findByText(S.case.notFound)).toBeInTheDocument();
    },
  );

  it.each(["/cases", "/cases/3"])(
    "turns tier1 away from %s to /queue, saying S.forbidden",
    (path) => {
      renderAt(path, session("tier1"));
      expect(where()).toBe("/queue");
      expect(screen.getByRole("alert")).toHaveTextContent(S.forbidden);
    },
  );

  it.each(["/queue", "/alerts/12", "/cases", "/cases/3"])(
    "sends a visitor with no session from %s to /login",
    (path) => {
      renderAt(path, null);
      expect(where()).toBe("/login");
    },
  );

  it("waits, and redirects nobody, while the session is being restored", () => {
    renderAt("/cases/3", null, false);
    expect(where()).toBe("/cases/3");
    expect(screen.getByRole("status")).toHaveTextContent(S.common.loading);
  });

  it("sends a signed-in visitor of /login to their home", async () => {
    renderAt("/login", session("tier2"));
    expect(where()).toBe("/cases");
    expect(await screen.findByText(S.case.empty)).toBeInTheDocument();
  });

  it("sends an unknown path to /", () => {
    renderAt("/nowhere/at/all", session("tier1"));
    expect(where()).toBe("/queue");
  });
});

const ADMIN_PAGES: [path: string, title: string][] = [
  ["/admin/overview", S.admin.title.overview],
  ["/admin/users", S.admin.title.users],
  ["/admin/llm", S.admin.title.llm],
  ["/admin/rules", S.admin.title.rules],
  ["/admin/digest", S.admin.title.digest],
  ["/admin/labels", S.admin.title.labels],
  ["/admin/audit", S.admin.title.audit],
];

describe("the admin console (spec §3)", () => {
  it.each(ADMIN_PAGES)("lets admin open %s, under the sidebar", (path, title) => {
    renderAt(path, session("admin"));
    expect(where()).toBe(path);
    expect(screen.getByRole("navigation", { name: S.admin.nav.label })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: title })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("sends admin from /admin to /admin/overview", () => {
    renderAt("/admin", session("admin"));
    expect(where()).toBe("/admin/overview");
    expect(
      screen.getByRole("heading", { level: 1, name: S.admin.title.overview }),
    ).toBeInTheDocument();
  });

  it("sends an admin who opens / to /admin/overview", () => {
    renderAt("/", session("admin"));
    expect(where()).toBe("/admin/overview");
    expect(
      screen.getByRole("heading", { level: 1, name: S.admin.title.overview }),
    ).toBeInTheDocument();
  });

  it.each<Session["role"]>(["tier1", "tier2"])(
    "turns %s away from /admin/users to /queue, saying S.forbidden",
    (role) => {
      renderAt("/admin/users", session(role));
      expect(where()).toBe("/queue");
      expect(screen.getByRole("alert")).toHaveTextContent(S.forbidden);
      expect(screen.queryByRole("navigation", { name: S.admin.nav.label })).not.toBeInTheDocument();
    },
  );

  it.each<[Session["role"], string]>(
    ADMIN_PAGES.flatMap(([path]) => [
      ["tier1", path] as [Session["role"], string],
      ["tier2", path] as [Session["role"], string],
    ]),
  )("turns %s away from %s", (role, path) => {
    renderAt(path, session(role));
    expect(where()).toBe("/queue");
    expect(screen.getByRole("alert")).toHaveTextContent(S.forbidden);
  });

  it.each<Session["role"]>(["tier1", "tier2"])("turns %s away from /admin too", (role) => {
    renderAt("/admin", session(role));
    expect(where()).toBe("/queue");
    expect(screen.getByRole("alert")).toHaveTextContent(S.forbidden);
  });

  it.each(["/admin", ...ADMIN_PAGES.map(([path]) => path)])(
    "sends a visitor with no session from %s to /login",
    (path) => {
      renderAt(path, null);
      expect(where()).toBe("/login");
    },
  );

  it("waits, and redirects nobody, while the session is being restored", () => {
    renderAt("/admin/users", null, false);
    expect(where()).toBe("/admin/users");
    expect(screen.getByRole("status")).toHaveTextContent(S.common.loading);
  });

  it("has one main landmark on an admin page, and the header above it", () => {
    renderAt("/admin/rules", session("admin"));
    expect(screen.getAllByRole("main")).toHaveLength(1);
    expect(screen.getByRole("banner")).toHaveTextContent(S.app.name);
    expect(screen.getByRole("navigation", { name: S.nav.label })).toBeInTheDocument();
  });

  it("keeps the header link and the sidebar apart: two navigations, two names", () => {
    renderAt("/admin/audit", session("admin"));
    const names = screen.getAllByRole("navigation").map((n) => n.getAttribute("aria-label"));
    expect(names).toEqual([S.nav.label, S.admin.nav.label]);
  });
});

describe("the layout", () => {
  it("has the header with the navigation on a signed-in page, and one main landmark", () => {
    renderAt("/queue", session("tier2"));
    expect(screen.getByRole("banner")).toHaveTextContent(S.app.name);
    expect(screen.getByRole("navigation", { name: S.nav.label })).toBeInTheDocument();
    expect(screen.getAllByRole("main")).toHaveLength(1);
  });

  it("has the banner and the main landmark on the login page, with no navigation", () => {
    renderAt("/login", null);
    expect(screen.getByRole("banner")).toHaveTextContent(S.app.name);
    expect(screen.getAllByRole("main")).toHaveLength(1);
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  });

  it("has the banner and the main landmark while the session is being restored", () => {
    renderAt("/queue", null, false);
    expect(screen.getByRole("banner")).toHaveTextContent(S.app.name);
    expect(screen.getByRole("main")).toBeInTheDocument();
  });
});

describe("with the real AuthProvider", () => {
  afterEach(() => {
    sessionStorage.clear();
  });

  const later = (ms: number) => new Date(Date.now() + ms).toISOString();

  function renderApp(path: string) {
    return render(
      <StrictMode>
        <QueryClientProvider client={newClient()}>
          <MemoryRouter initialEntries={[path]}>
            <AuthProvider>
              <AppRoutes />
              <Where />
            </AuthProvider>
          </MemoryRouter>
        </QueryClientProvider>
      </StrictMode>,
    );
  }

  const signedIn = () => {
    sessionStorage.setItem(
      "soc.session",
      JSON.stringify({
        token: "tok-1",
        role: "tier1",
        username: "an",
        expiresAt: later(3_600_000),
      }),
    );
    server.use(
      http.get("/api/auth/me", () =>
        HttpResponse.json({
          user_id: 4,
          username: "an",
          display_name: "An",
          role: "tier1",
          expires_at: later(3_600_000),
        }),
      ),
    );
  };

  it("restores a stored session on a deep link and stays on the page", async () => {
    signedIn();
    renderApp("/alerts/5");
    expect(await screen.findByRole("button", { name: S.nav.logout })).toBeInTheDocument();
    expect(where()).toBe("/alerts/5");
  });

  it("sends a deep link with no session to /login, and returns to it after the login", async () => {
    server.use(
      http.post("/api/auth/login", () =>
        HttpResponse.json({
          token: "tok-2",
          role: "tier1",
          user_id: 4,
          expires_at: later(3_600_000),
        }),
      ),
    );
    renderApp("/alerts/5");
    await waitFor(() => expect(where()).toBe("/login"), { timeout: 2000 });
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(S.login.username), "an");
    await user.type(screen.getByLabelText(S.login.password), "pw");
    await user.click(screen.getByRole("button", { name: S.login.submit }));
    await waitFor(() => expect(where()).toBe("/alerts/5"));
  });

  it("after Đăng xuất, the next login lands on the role home, not on the page just left", async () => {
    signedIn();
    server.use(
      http.post("/api/auth/logout", () => new HttpResponse(null, { status: 204 })),
      http.post("/api/auth/login", () =>
        HttpResponse.json({
          token: "tok-2",
          role: "tier1",
          user_id: 4,
          expires_at: later(3_600_000),
        }),
      ),
    );
    renderApp("/alerts/5");
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: S.nav.logout }));
    await waitFor(() => expect(where()).toBe("/login"));
    expect(sessionStorage.getItem("soc.session")).toBeNull();
    await user.type(screen.getByLabelText(S.login.username), "an");
    await user.type(screen.getByLabelText(S.login.password), "pw");
    await user.click(screen.getByRole("button", { name: S.login.submit }));
    await waitFor(() => expect(where()).toBe("/queue"));
  });

  it("goes to /login when the session is lost in the middle of a page, and returns on the next login", async () => {
    signedIn();
    server.use(
      http.get("/api/ping", () => HttpResponse.json({ detail: "expired" }, { status: 401 })),
      http.post("/api/auth/login", () =>
        HttpResponse.json({
          token: "tok-2",
          role: "tier1",
          user_id: 4,
          expires_at: later(3_600_000),
        }),
      ),
    );
    renderApp("/alerts/5");
    await screen.findByRole("button", { name: S.nav.logout });
    await api("/ping").catch(() => {});
    await waitFor(() => expect(where()).toBe("/login"));
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(S.login.username), "an");
    await user.type(screen.getByLabelText(S.login.password), "pw");
    await user.click(screen.getByRole("button", { name: S.login.submit }));
    await waitFor(() => expect(where()).toBe("/alerts/5"));
  });
});
