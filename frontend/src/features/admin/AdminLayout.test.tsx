// src/features/admin/AdminLayout.test.tsx — the sidebar of the admin console (spec §3): seven links in the
// canvas order, the current one marked, and the placeholder pages the page tasks replace.
import { render, screen, within } from "@testing-library/react";
import axe from "axe-core";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router";
import { S } from "../../strings";
import { AdminLayout } from "./AdminLayout";
import { AuditPage } from "./AuditPage";
import { DigestPage } from "./DigestPage";
import { LabelsPage } from "./LabelsPage";
import { LlmPage } from "./LlmPage";
import { OverviewPage } from "./OverviewPage";
import { UsersPage } from "./UsersPage";

/** The sidebar, in the order and with the words of the canvas, and where each link goes. */
const SIDEBAR: [label: string, href: string][] = [
  ["Tổng quan", "/admin/overview"],
  ["Người dùng & quyền", "/admin/users"],
  ["LLM & hạn mức", "/admin/llm"],
  ["Rules tự đóng", "/admin/rules"],
  ["Digest hằng ngày", "/admin/digest"],
  ["Gán nhãn", "/admin/labels"],
  ["Nhật ký audit", "/admin/audit"],
];

function renderAt(path: string, page: ReactNode = <p>nội dung trang</p>) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AdminLayout>{page}</AdminLayout>
    </MemoryRouter>,
  );
}

const sidebar = () => screen.getByRole("navigation", { name: "Quản trị" });

describe("the sidebar", () => {
  it("is a navigation named Quản trị", () => {
    renderAt("/admin/overview");
    expect(sidebar()).toBeInTheDocument();
    expect(S.admin.nav.label).toBe("Quản trị");
  });

  it("has seven links, in the canvas order, with the canvas words, to the seven paths", () => {
    renderAt("/admin/overview");
    const links = within(sidebar()).getAllByRole("link");
    expect(links.map((a) => [a.textContent, a.getAttribute("href")])).toEqual(SIDEBAR);
  });

  it("takes its words from strings.ts", () => {
    renderAt("/admin/overview");
    const links = within(sidebar()).getAllByRole("link");
    expect(links.map((a) => a.textContent)).toEqual([
      S.admin.nav.overview,
      S.admin.nav.users,
      S.admin.nav.llm,
      S.admin.nav.rules,
      S.admin.nav.digest,
      S.admin.nav.labels,
      S.admin.nav.audit,
    ]);
  });

  it.each(SIDEBAR)(
    "marks %s as the current page on its own path, and no other link",
    (label, href) => {
      renderAt(href);
      const links = within(sidebar()).getAllByRole("link");
      const current = links.filter((a) => a.getAttribute("aria-current") === "page");
      expect(current.map((a) => a.textContent)).toEqual([label]);
      for (const link of links) {
        if (link.textContent !== label) expect(link).not.toHaveAttribute("aria-current");
      }
    },
  );

  it("marks nothing as current on a path that is not one of the seven", () => {
    renderAt("/admin");
    for (const link of within(sidebar()).getAllByRole("link")) {
      expect(link).not.toHaveAttribute("aria-current");
    }
  });

  it("is beside the page it is given, which it renders as it came", () => {
    renderAt("/admin/users", <h1>Người dùng và quyền</h1>);
    expect(screen.getByRole("heading", { name: "Người dùng và quyền" })).toBeInTheDocument();
  });

  it("adds no landmark of its own but the navigation: the app shell owns the main", () => {
    renderAt("/admin/users");
    expect(screen.queryByRole("main")).not.toBeInTheDocument();
    expect(screen.queryByRole("banner")).not.toBeInTheDocument();
    expect(screen.getAllByRole("navigation")).toHaveLength(1);
  });
});

// RulesPage (P11-T14) is built: RulesPage.test.tsx covers it, and it needs a query client these renders lack.
const PAGES: [name: string, Page: () => ReactNode, title: string][] = [
  ["OverviewPage", OverviewPage, "Tổng quan hệ thống"],
  ["UsersPage", UsersPage, "Người dùng và quyền"],
  ["LlmPage", LlmPage, "LLM và hạn mức"],
  ["DigestPage", DigestPage, "Digest hằng ngày"],
  ["LabelsPage", LabelsPage, "Gán nhãn tập vàng"],
  ["AuditPage", AuditPage, "Nhật ký audit"],
];

describe("the placeholder pages", () => {
  it.each(PAGES)("%s shows its title and says it is being built", (_name, Page, title) => {
    render(<Page />);
    expect(screen.getByRole("heading", { level: 1, name: title })).toBeInTheDocument();
    expect(screen.getByText(/đang xây dựng/i)).toBeInTheDocument();
  });

  it("take their titles from strings.ts", () => {
    expect(PAGES.map(([, , title]) => title)).toEqual([
      S.admin.title.overview,
      S.admin.title.users,
      S.admin.title.llm,
      S.admin.title.digest,
      S.admin.title.labels,
      S.admin.title.audit,
    ]);
  });
});

describe("accessibility", () => {
  it.each(PAGES)("has no axe violation around %s", async (_name, Page) => {
    // The app shell gives the page its main landmark and the header its banner; both are here so the
    // landmark rules judge what the real page looks like.
    const { container } = render(
      <MemoryRouter initialEntries={["/admin/users"]}>
        <header>
          <span>AI Support SOC</span>
        </header>
        <main>
          <AdminLayout>
            <Page />
          </AdminLayout>
        </main>
      </MemoryRouter>,
    );
    // jsdom computes no layout or colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});
