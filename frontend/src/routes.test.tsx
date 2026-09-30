// src/routes.test.tsx — the route table of the spec §3.1, for each role.
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

const session = (role: Session["role"]): Session => ({
  token: "t",
  role,
  username: "an",
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
});

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
    <AuthContext.Provider value={auth}>
      <MemoryRouter initialEntries={[path]}>
        <AppRoutes />
        <Where />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

const where = () => screen.getByTestId("where").textContent;

describe("the route table", () => {
  it.each<[Session["role"], string]>([
    ["tier1", "/queue"],
    ["tier2", "/cases"],
    ["admin", "/cases"],
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

  it.each<Session["role"]>(["tier2", "admin"])("lets %s open /cases and /cases/:caseId", (role) => {
    renderAt("/cases/3", session(role));
    expect(where()).toBe("/cases/3");
  });

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

  it("sends a signed-in visitor of /login to their home", () => {
    renderAt("/login", session("tier2"));
    expect(where()).toBe("/cases");
  });

  it("sends an unknown path to /", () => {
    renderAt("/nowhere/at/all", session("tier1"));
    expect(where()).toBe("/queue");
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
  const server = setupServer();
  beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
  afterEach(() => {
    server.resetHandlers();
    sessionStorage.clear();
  });
  afterAll(() => server.close());

  const later = (ms: number) => new Date(Date.now() + ms).toISOString();

  function renderApp(path: string) {
    return render(
      <StrictMode>
        <MemoryRouter initialEntries={[path]}>
          <AuthProvider>
            <AppRoutes />
            <Where />
          </AuthProvider>
        </MemoryRouter>
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
