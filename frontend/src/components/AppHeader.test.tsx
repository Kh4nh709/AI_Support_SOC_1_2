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

function renderHeader(
  s: Session | null,
  over: Partial<AuthState> = {},
  live?: React.ReactNode,
  at = "/queue",
) {
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
      <MemoryRouter initialEntries={[at]}>
        <AppHeader live={live} />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
}

it("remembers the chosen appearance after returning to the console", async () => {
  const first = renderHeader(null);
  try {
    const light = screen.getByRole("radio", { name: "Sáng" });
    await userEvent.click(light);
    expect(light).toBeChecked();
    expect(document.documentElement.dataset.theme).toBe("light");
    first.unmount();
    renderHeader(session("tier2"));
    expect(screen.getByRole("radio", { name: "Sáng" })).toBeChecked();
    await userEvent.click(screen.getByRole("radio", { name: "Tối" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
  } finally {
    localStorage.removeItem("soc.theme");
    delete document.documentElement.dataset.theme;
  }
});

it("shows the brand and appearance picker when signed out", () => {
  renderHeader(null);
  expect(screen.getByRole("banner")).toHaveTextContent(S.app.name);
  expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: S.nav.logout })).not.toBeInTheDocument();
});

it("gives tier1 the queue and no Case link, no Quản trị link", () => {
  renderHeader(session("tier1"));
  const nav = screen.getByRole("navigation", { name: S.nav.label });
  expect(nav).toHaveTextContent(S.nav.queue);
  expect(screen.getByRole("link", { name: S.nav.queue })).toHaveAttribute("href", "/queue");
  expect(screen.queryByRole("link", { name: S.nav.cases })).not.toBeInTheDocument();
  expect(screen.queryByRole("link", { name: S.nav.admin })).not.toBeInTheDocument();
});

it("gives tier2 the queue and Case, no Quản trị link", () => {
  renderHeader(session("tier2"));
  expect(screen.getByRole("link", { name: S.nav.queue })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: S.nav.cases })).toHaveAttribute("href", "/cases");
  expect(screen.queryByRole("link", { name: S.nav.admin })).not.toBeInTheDocument();
});

it("gives admin the queue, Case and an in-app Quản trị link to /admin", () => {
  renderHeader(session("admin"));
  expect(screen.getByRole("link", { name: S.nav.queue })).toBeInTheDocument();
  expect(screen.getByRole("link", { name: S.nav.cases })).toBeInTheDocument();
  const admin = screen.getByRole("link", { name: "Quản trị" });
  expect(admin).toHaveTextContent("Quản trị");
  expect(S.nav.admin).toBe("Quản trị");
  expect(admin).toHaveAttribute("href", "/admin");
  // In-app: no new tab, no other port or host.
  expect(admin).not.toHaveAttribute("target");
  expect(admin.getAttribute("href")).not.toMatch(/^[a-z]+:/i);
});

it("shows Quản trị to nobody who is not an admin, and to nobody signed out", () => {
  for (const s of [session("tier1"), session("tier2"), null]) {
    const view = renderHeader(s);
    expect(screen.queryByRole("link", { name: "Quản trị" })).not.toBeInTheDocument();
    view.unmount();
  }
});

it("has no link to another port of this host, and no legacy console link, for any role", () => {
  for (const role of ["tier1", "tier2", "admin"] as const) {
    const view = renderHeader(session(role));
    for (const a of screen.getAllByRole("link")) {
      expect(a.getAttribute("href")).not.toContain(":8000");
      expect(a).not.toHaveAttribute("target", "_blank");
    }
    expect(screen.queryByText(/UI cũ/)).not.toBeInTheDocument();
    view.unmount();
  }
});

it("marks Quản trị as the current page below /admin", () => {
  renderHeader(session("admin"), {}, undefined, "/admin/users");
  expect(screen.getByRole("link", { name: "Quản trị" })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("link", { name: S.nav.queue })).not.toHaveAttribute("aria-current");
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

// SR-T2: the page "Phản hồi SOAR" is every role's, so its link is in every role's navigation, after the pages that are
// some roles' own and before the console.
it.each(["tier1", "tier2", "admin"] as const)("gives %s the link to /soar", (role) => {
  renderHeader(session(role));
  const link = screen.getByRole("link", { name: S.nav.soar });
  expect(S.nav.soar).toBe("Phản hồi SOAR");
  expect(link).toHaveAttribute("href", "/soar");
  expect(link).not.toHaveAttribute("target");
});

const NAV = [S.nav.queue, S.nav.cases, S.nav.soar, S.nav.ti, S.nav.admin];

it("puts the SOAR link after Case and before Quản trị", () => {
  renderHeader(session("admin"));
  const names = screen
    .getAllByRole("link")
    .map((a) => a.textContent)
    .filter((text) => (NAV as readonly string[]).includes(text ?? ""));
  expect(names).toEqual(NAV);
});

// DEC-224: the page "Threat Intel" is every role's too (the export on it is the admin's alone, and the page decides that), so its link
// is in every role's navigation, after the SOAR link and before the console.
it.each(["tier1", "tier2", "admin"] as const)("gives %s the link to /threat-intel", (role) => {
  renderHeader(session(role));
  const link = screen.getByRole("link", { name: S.nav.ti });
  expect(S.nav.ti).toBe("Threat Intel");
  expect(link).toHaveAttribute("href", "/threat-intel");
  expect(link).not.toHaveAttribute("target");
  expect(link.getAttribute("href")).not.toMatch(/^[a-z]+:/i);
});

it("puts the Threat Intel link after the SOAR link and before Quản trị, and marks it as the current page on /threat-intel", () => {
  renderHeader(session("admin"), {}, undefined, "/threat-intel");
  const names = screen.getAllByRole("link").map((a) => a.textContent);
  expect(names.indexOf(S.nav.ti)).toBe(names.indexOf(S.nav.soar) + 1);
  expect(names.indexOf(S.nav.admin)).toBe(names.indexOf(S.nav.ti) + 1);
  expect(screen.getByRole("link", { name: S.nav.ti })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("link", { name: S.nav.soar })).not.toHaveAttribute("aria-current");
});

it("shows no Threat Intel link to nobody signed in", () => {
  renderHeader(null);
  expect(screen.queryByRole("link", { name: S.nav.ti })).not.toBeInTheDocument();
});

it("marks the SOAR link as the current page on /soar", () => {
  renderHeader(session("tier1"), {}, undefined, "/soar");
  expect(screen.getByRole("link", { name: S.nav.soar })).toHaveAttribute("aria-current", "page");
  expect(screen.getByRole("link", { name: S.nav.queue })).not.toHaveAttribute("aria-current");
});

it("shows the SOAR link with no slot given, and the slot's content inside the link when it is", () => {
  const view = renderHeader(session("tier1"));
  expect(screen.getByRole("link", { name: S.nav.soar })).toHaveTextContent(/^Phản hồi SOAR$/);
  view.unmount();
  const auth: AuthState = {
    session: session("tier1"),
    ready: true,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
  };
  render(
    <AuthContext.Provider value={auth}>
      <MemoryRouter>
        <AppHeader soarBadge={<span>badge here</span>} />
      </MemoryRouter>
    </AuthContext.Provider>,
  );
  expect(screen.getByRole("link", { name: /Phản hồi SOAR/ })).toHaveTextContent("badge here");
});

it("shows no SOAR link, and so mounts no badge, to nobody signed in", () => {
  renderHeader(null);
  expect(screen.queryByRole("link", { name: S.nav.soar })).not.toBeInTheDocument();
});
