// src/auth/RequireRole.test.tsx — the route guard, against a fixed auth state (no network, no timers).
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";
import { S } from "../strings";
import { AuthContext, type AuthState } from "./AuthProvider";
import { ForbiddenNotice, RequireRole } from "./RequireRole";
import type { Session } from "./session";

const session = (role: Session["role"]): Session => ({
  token: "t",
  role,
  username: "an",
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
});

const state = (s: Session | null, ready = true, signedOut = false): AuthState => ({
  session: s,
  ready,
  signedOut,
  login: async () => {},
  logout: async () => {},
});

function LoginProbe() {
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from;
  return <p data-testid="login">{`login page, from ${from ?? "nowhere"}`}</p>;
}

function renderAt(path: string, auth: AuthState) {
  return render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/login" element={<LoginProbe />} />
          <Route
            path="/queue"
            element={
              <>
                <ForbiddenNotice />
                <p>queue page</p>
              </>
            }
          />
          <Route
            path="/cases/:id"
            element={
              <RequireRole roles={["tier2", "admin"]}>
                <p>case page</p>
              </RequireRole>
            }
          />
        </Routes>
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

it("redirects tier1 from a tier2 route to /queue, saying S.forbidden", () => {
  renderAt("/cases/7", state(session("tier1")));
  expect(screen.getByText("queue page")).toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent(S.forbidden);
  expect(screen.queryByText("case page")).not.toBeInTheDocument();
});

it("sends a visitor with no session to /login, remembering where they were going", () => {
  renderAt("/cases/7", state(null));
  expect(screen.getByTestId("login")).toHaveTextContent("login page, from /cases/7");
  expect(screen.queryByText("case page")).not.toBeInTheDocument();
});

it("remembers no page after an Đăng xuất: the next login starts at the role's home", () => {
  renderAt("/cases/7", state(null, true, true));
  expect(screen.getByTestId("login")).toHaveTextContent("login page, from nowhere");
});

it("remembers the query string of the page too", () => {
  renderAt("/cases/7?tab=notes", state(null));
  expect(screen.getByTestId("login")).toHaveTextContent("from /cases/7?tab=notes");
});

it.each<Session["role"]>(["tier2", "admin"])("lets %s in", (role) => {
  renderAt("/cases/7", state(session(role)));
  expect(screen.getByText("case page")).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("shows nothing forbidden and does not redirect while the session is still being restored", () => {
  renderAt("/cases/7", state(null, false));
  expect(screen.getByRole("status")).toHaveTextContent(S.common.loading);
  expect(screen.queryByTestId("login")).not.toBeInTheDocument();
  expect(screen.queryByText("case page")).not.toBeInTheDocument();
});

it("shows no forbidden notice on /queue when nobody was turned away", () => {
  renderAt("/queue", state(session("tier1")));
  expect(screen.getByText("queue page")).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});
