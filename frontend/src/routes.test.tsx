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
// The page of the SOAR tickets (SR-T2) reads the API (features/soar/SoarPage.*.test.tsx test it); here only its place matters.
vi.mock("./features/soar/SoarPage", () => ({
  SoarPage: () => <h1>{S.soar.title}</h1>,
}));
// The page Threat Intel (DEC-224) reads the API (features/ti/TiPage.*.test.tsx test it); here only its place matters.
vi.mock("./features/ti/TiPage", () => ({
  TiPage: () => <h1>{S.ti.title}</h1>,
}));
// The labelling page reads the label routes with the labeller named in the session's token (LabelsPage.test.tsx
// tests it); this file looks for its place and its title.
vi.mock("./features/admin/LabelsPage", () => ({
  LabelsPage: () => <h1>{S.admin.title.labels}</h1>,
}));

// The users page of the console reads the backend and its own file tests it (UsersPage.test.tsx); here only
// its place in the route table matters.
vi.mock("./features/admin/UsersPage", () => ({
  UsersPage: () => <h1>{S.admin.title.users}</h1>,
}));
// The two lab pages (P14-T10) read the API (LabRunsPage.test.tsx, LabRunPage.test.tsx test them); here only their places matter.
vi.mock("./features/admin/LabRunsPage", () => ({
  LabRunsPage: () => <h1>{S.admin.lab.title.runs}</h1>,
}));
vi.mock("./features/admin/LabRunPage", () => ({
  LabRunPage: () => <h1>{S.admin.lab.title.run}</h1>,
}));
// The knowledge page (P13-T06) reads the API too (KnowledgePage.test.tsx tests it); here only its place matters.
vi.mock("./features/admin/KnowledgePage", () => ({
  KnowledgePage: () => <h1>{S.admin.title.knowledge}</h1>,
}));
// The overview page reads the API (OverviewPage.test.tsx tests it); this file looks for its place and its title.
vi.mock("./features/admin/OverviewPage", () => ({
  OverviewPage: () => <h1>{S.admin.title.overview}</h1>,
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
  const { pathname, search } = useLocation();
  return (
    <>
      <p data-testid="where">{pathname}</p>
      <p data-testid="where-search">{search}</p>
    </>
  );
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
const whereSearch = () => screen.getByTestId("where-search").textContent;

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

// The audit page reads the API (AuditPage.test.tsx tests it); here only its place in the route table matters.
vi.mock("./features/admin/AuditPage", () => ({
  AuditPage: () => <h1>{S.admin.title.audit}</h1>,
}));

// The LLM page reads the API as well (LlmPage.test.tsx tests it). The admin pages are fetched with `import()` when their
// route opens (P11-T20 row 56), so a page that is not a stub would be transformed from source inside the test, and
// `findBy` would wait for that: here too only the place matters.
vi.mock("./features/admin/LlmPage", () => ({
  LlmPage: () => <h1>{S.admin.title.llm}</h1>,
}));

const ADMIN_PAGES: [path: string, title: string][] = [
  ["/admin/overview", S.admin.title.overview],
  ["/admin/users", S.admin.title.users],
  ["/admin/llm", S.admin.title.llm],
  ["/admin/labels", S.admin.title.labels],
  ["/admin/lab", S.admin.lab.title.runs],
  ["/admin/lab/5f1c0a2e-3b4d-4e5f-8a9b-0123456789ab", S.admin.lab.title.run],
  ["/admin/knowledge", S.admin.title.knowledge],
  ["/admin/audit", S.admin.title.audit],
];

describe("the admin console (spec §3)", () => {
  it.each(ADMIN_PAGES)("lets admin open %s, under the sidebar", async (path, title) => {
    renderAt(path, session("admin"));
    expect(where()).toBe(path);
    expect(screen.getByRole("navigation", { name: S.admin.nav.label })).toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 1, name: title })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("sends admin from /admin to /admin/overview", async () => {
    renderAt("/admin", session("admin"));
    expect(where()).toBe("/admin/overview");
    expect(
      await screen.findByRole("heading", { level: 1, name: S.admin.title.overview }),
    ).toBeInTheDocument();
  });

  it("sends an admin who opens / to /admin/overview", async () => {
    renderAt("/", session("admin"));
    expect(where()).toBe("/admin/overview");
    expect(
      await screen.findByRole("heading", { level: 1, name: S.admin.title.overview }),
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

  it("has one main landmark on an admin page, and the header above it", async () => {
    renderAt("/admin/llm", session("admin"));
    await screen.findByRole("heading", { level: 1, name: S.admin.title.llm });
    expect(screen.getAllByRole("main")).toHaveLength(1);
    expect(screen.getByRole("banner")).toHaveTextContent(S.app.name);
    expect(screen.getByRole("navigation", { name: S.nav.label })).toBeInTheDocument();
  });

  it("keeps the header link and the sidebar apart: two navigations, two names", async () => {
    renderAt("/admin/audit", session("admin"));
    await screen.findByRole("heading", { level: 1, name: S.admin.title.audit });
    const names = screen.getAllByRole("navigation").map((n) => n.getAttribute("aria-label"));
    expect(names).toEqual([S.nav.label, S.admin.nav.label]);
  });
});

// DEC-214: the pages "Rules tự đóng" and "Digest hằng ngày" are gone, and so are their routes. A bookmark or an old
// link to one lands where every unknown path lands: no redirect of its own, no notice, no page.
describe("a removed admin page is an unknown path (DEC-214)", () => {
  const REMOVED = [
    "/admin/rules",
    "/admin/rules/anything",
    "/admin/digest",
    "/admin/digest?day=2026-11-03",
  ];
  /** The h1 the two removed pages had. Literals: the strings are gone with the pages. */
  const REMOVED_TITLES = ["Rules tự đóng", "Digest hằng ngày"];

  it("sends an unknown admin path to the admin's home", async () => {
    renderAt("/admin/no-such-page", session("admin"));
    expect(where()).toBe("/admin/overview");
    expect(
      await screen.findByRole("heading", { level: 1, name: S.admin.title.overview }),
    ).toBeInTheDocument();
  });

  it.each(REMOVED)(
    "ends %s where /admin/no-such-page ends, and shows nothing of the page",
    async (path) => {
      const unknown = renderAt("/admin/no-such-page", session("admin"));
      await screen.findByRole("heading", { level: 1, name: S.admin.title.overview });
      const expected = [where(), whereSearch()];
      unknown.unmount();

      renderAt(path, session("admin"));
      expect(
        await screen.findByRole("heading", { level: 1, name: S.admin.title.overview }),
      ).toBeInTheDocument();
      expect([where(), whereSearch()]).toEqual(expected);
      expect(where()).toBe("/admin/overview");
      expect(whereSearch()).toBe("");
      for (const title of REMOVED_TITLES) {
        expect(screen.queryByRole("heading", { name: title })).not.toBeInTheDocument();
      }
      // no notice, no error boundary: the overview under the sidebar, nothing else
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
      expect(screen.queryByText(/rules? tự đóng|digest/i)).not.toBeInTheDocument();
    },
  );
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

// SR-T2: the page "Phản hồi SOAR" is every role's, and its link in the header carries the count of open tickets, asked of
// the API only while somebody is signed in.
describe("the SOAR page (SR-T2)", () => {
  const count = (n: number) =>
    http.get("/api/soar/reviews/count", () =>
      HttpResponse.json({ count: n, latest_received_at: "2026-11-16T01:00:00+00:00" }),
    );

  it.each<Session["role"]>(["tier1", "tier2", "admin"])("lets %s open /soar", async (role) => {
    server.use(count(0));
    renderAt("/soar", session(role));
    expect(where()).toBe("/soar");
    expect(
      await screen.findByRole("heading", { level: 1, name: S.soar.title }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("sends a visitor with no session from /soar to /login, and asks the API for no count", async () => {
    let asked = 0;
    server.use(
      http.get("/api/soar/reviews/count", () => {
        asked += 1;
        return HttpResponse.json({ count: 1, latest_received_at: null });
      }),
    );
    renderAt("/soar", null);
    expect(where()).toBe("/login");
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(asked).toBe(0);
  });

  it("shows the count of open tickets in the link of the header, on any page", async () => {
    server.use(count(4));
    renderAt("/queue", session("tier1"));
    const link = await screen.findByRole("link", { name: `${S.nav.soar} ${S.soar.badge.sr(4)}` });
    expect(link).toHaveAttribute("href", "/soar");
  });

  it("leaves the link and the whole header as they are when the count fails", async () => {
    server.use(
      http.get("/api/soar/reviews/count", () =>
        HttpResponse.json({ detail: "x" }, { status: 500 }),
      ),
    );
    renderAt("/queue", session("tier1"));
    expect(await screen.findByRole("link", { name: S.nav.soar })).toBeInTheDocument();
    expect(screen.getByRole("banner")).toHaveTextContent(S.app.name);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

// DEC-224: the page "Threat Intel" is every role's, like the queue and the SOAR page; the export on it is the admin's alone, which the
// page itself decides (features/ti/TiPage.export.test.tsx), and the API enforces.
describe("the Threat Intel page (DEC-224)", () => {
  it.each<Session["role"]>(["tier1", "tier2", "admin"])(
    "lets %s open /threat-intel",
    async (role) => {
      server.use(
        http.get("/api/soar/reviews/count", () =>
          HttpResponse.json({ count: 0, latest_received_at: null }),
        ),
      );
      renderAt("/threat-intel", session(role));
      expect(where()).toBe("/threat-intel");
      expect(
        await screen.findByRole("heading", { level: 1, name: S.ti.title }),
      ).toBeInTheDocument();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    },
  );

  it("keeps the filters of the URL when it opens", async () => {
    server.use(
      http.get("/api/soar/reviews/count", () =>
        HttpResponse.json({ count: 0, latest_received_at: null }),
      ),
    );
    renderAt("/threat-intel?source=urlhaus&page=2", session("tier1"));
    await screen.findByRole("heading", { level: 1, name: S.ti.title });
    expect(where()).toBe("/threat-intel");
    expect(whereSearch()).toBe("?source=urlhaus&page=2");
  });

  it("sends a visitor with no session from /threat-intel to /login, and the login remembers where they were going", () => {
    renderAt("/threat-intel", null);
    expect(where()).toBe("/login");
  });

  it("is a link in the header on every page, and it goes to the page", async () => {
    server.use(
      http.get("/api/soar/reviews/count", () =>
        HttpResponse.json({ count: 0, latest_received_at: null }),
      ),
    );
    renderAt("/queue", session("tier2"));
    const link = await screen.findByRole("link", { name: S.nav.ti });
    expect(link).toHaveAttribute("href", "/threat-intel");
    await userEvent.setup().click(link);
    expect(where()).toBe("/threat-intel");
    expect(await screen.findByRole("heading", { level: 1, name: S.ti.title })).toBeInTheDocument();
  });
});
