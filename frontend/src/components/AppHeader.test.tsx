// src/components/AppHeader.test.tsx — the header: navigation by role, the user, the role chip, logout.
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { AuthContext, type AuthState } from "../auth/AuthProvider";
import type { Session } from "../auth/session";
import { S } from "../strings";
import { AppHeader } from "./AppHeader";

const session = (role: Session["role"], username = "an"): Session => ({
  token: "t",
  role,
  username,
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
});

function renderHeader(s: Session | null, over: Partial<AuthState> = {}, live?: React.ReactNode) {
  const auth: AuthState = {
    session: s,
    ready: true,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
    ...over,
  };
  return render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter initialEntries={["/queue"]}>
        <AppHeader live={live} />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

it("shows the app name as a banner, and nothing else when nobody is signed in", () => {
  renderHeader(null);
  expect(screen.getByRole("banner")).toHaveTextContent(S.app.name);
  expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: S.nav.logout })).not.toBeInTheDocument();
});

it("gives tier1 the queue and no Case link, no legacy link", () => {
  renderHeader(session("tier1"));
  const nav = screen.getByRole("navigation", { name: S.nav.label });
  expect(nav).toHaveTextContent(S.nav.queue);
  expect(screen.getByRole("link", { name: S.nav.queue })).toHaveAttribute("href", "/queue");
  expect(screen.queryByRole("link", { name: S.nav.cases })).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: S.nav.adminLegacy })).not.toBeInTheDocument();
});

it("gives tier2 the queue and Case, no legacy link", () => {
  renderHeader(session("tier2"));
  expect(screen.getByRole("link", { name: S.nav.queue })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: S.nav.cases })).toHaveAttribute("href", "/cases");
  expect(screen.queryByRole("link", { name: S.nav.adminLegacy })).not.toBeInTheDocument();
});

it("gives admin the queue, Case and the legacy console on port 8000 of this host", () => {
  renderHeader(session("admin"));
  expect(screen.getByRole("link", { name: S.nav.queue })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: S.nav.cases })).toBeInTheDocument();
  const legacy = screen.getByRole("link", { name: S.nav.adminLegacy });
  expect(legacy).toHaveAttribute("href", `http://${window.location.hostname}:8000/admin/rules`);
  expect(legacy).toHaveAttribute("rel", expect.stringContaining("noopener"));
});

it("marks the page you are on", () => {
  renderHeader(session("tier2"));
  expect(screen.getByRole("link", { name: S.nav.queue })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("link", { name: S.nav.cases })).not.toHaveAttribute("aria-current");
});

it("shows the username and the role as a chip", () => {
  renderHeader(session("tier2", "bo"));
  expect(screen.getByText("bo")).toBeInTheDocument();
  expect(screen.getByText("Tier 2")).toBeInTheDocument();
});

it("shows a role it has no label for as its raw code", () => {
  renderHeader({ ...session("tier1"), role: "auditor" as Session["role"] });
  expect(screen.getByText("auditor")).toBeInTheDocument();
});

it("renders the username as text, whatever it holds", () => {
  renderHeader(session("tier1", "<img src=x onerror=alert(1)>"));
  expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
  expect(document.querySelector("img")).toBeNull();
});

it("has a slot for the live indicator", () => {
  renderHeader(session("tier1"), {}, <span>indicator here</span>);
  expect(screen.getByText("indicator here")).toBeInTheDocument();
});

it("calls logout when Đăng xuất is pressed", async () => {
  const logout = vi.fn(async () => {});
  renderHeader(session("tier1"), { logout });
  await userEvent.setup().click(screen.getByRole("button", { name: S.nav.logout }));
  expect(logout).toHaveBeenCalledTimes(1);
});
