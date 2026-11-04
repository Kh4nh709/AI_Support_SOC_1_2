// src/features/admin/AdminLayout.test.tsx — the sidebar of the admin console (spec §3): nine links in the
// canvas order (the knowledge page of DEC-210 before the audit log, and the lab labelling of P14-T10 after the
// gold-set labelling), the current one marked, and the page titles (all eight pages with a title of their own are built).
import { render, screen, within } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router";
import { S } from "../../strings";
import { AdminLayout } from "./AdminLayout";
import { AuditPage } from "./AuditPage";
import { DigestPage } from "./DigestPage";
import { KnowledgePage } from "./KnowledgePage";
import { LabelsPage } from "./LabelsPage";
import { LlmPage } from "./LlmPage";
import { OverviewPage } from "./OverviewPage";
import { RulesPage } from "./RulesPage";
import { UsersPage } from "./UsersPage";

/** The sidebar, in the order and with the words of the canvas (and DEC-210's "Tri thức"), and where each link goes. */
const SIDEBAR: [label: string, href: string][] = [
  ["Tổng quan", "/admin/overview"],
  ["Người dùng & quyền", "/admin/users"],
  ["LLM & hạn mức", "/admin/llm"],
  ["Rules tự đóng", "/admin/rules"],
  ["Digest hằng ngày", "/admin/digest"],
  ["Gán nhãn", "/admin/labels"],
  ["Gán nhãn lab", "/admin/lab"],
  ["Tri thức", "/admin/knowledge"],
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

  it("has nine links, in the canvas order, with the canvas words, to the nine paths", () => {
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
      S.admin.lab.nav,
      S.admin.nav.knowledge,
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

  it("keeps Gán nhãn lab current on the page of one run, and Gán nhãn is not", () => {
    renderAt("/admin/lab/5f1c0a2e-3b4d-4e5f-8a9b-0123456789ab");
    const current = within(sidebar())
      .getAllByRole("link")
      .filter((a) => a.getAttribute("aria-current") === "page");
    expect(current.map((a) => a.textContent)).toEqual(["Gán nhãn lab"]);
  });

  it("puts Gán nhãn lab straight after Gán nhãn, the gold-set labelling it is not", () => {
    renderAt("/admin/overview");
    const names = within(sidebar())
      .getAllByRole("link")
      .map((a) => a.textContent);
    expect(names.indexOf("Gán nhãn lab")).toBe(names.indexOf("Gán nhãn") + 1);
  });

  it("marks nothing as current on a path that is not one of the nine", () => {
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

const PAGES: [name: string, Page: () => ReactNode, title: string][] = [
  ["OverviewPage", OverviewPage, "Tổng quan hệ thống"],
  ["UsersPage", UsersPage, "Người dùng và quyền"],
  ["LlmPage", LlmPage, "LLM và hạn mức"],
  ["RulesPage", RulesPage, "Rules tự đóng"],
  ["DigestPage", DigestPage, "Digest hằng ngày"],
  ["LabelsPage", LabelsPage, "Gán nhãn tập vàng"],
  ["KnowledgePage", KnowledgePage, "Tri thức học được"],
  ["AuditPage", AuditPage, "Nhật ký audit"],
];

// All eight pages are built (P11-T11 to T17, and the knowledge page of P13-T06): each has its own test file, which needs a query client, a session
// and an API this file does not give, and covers its page, axe included. No placeholder is left to test here.
describe("the pages", () => {
  it("leave no placeholder text in strings.ts: no admin text says a page is being built", () => {
    const texts: string[] = [];
    const collect = (value: unknown): void => {
      if (typeof value === "string") texts.push(value);
      else if (typeof value === "object" && value !== null) Object.values(value).forEach(collect);
    };
    collect(S.admin);
    expect(texts.length).toBeGreaterThan(100);
    expect(texts.filter((text) => /đang xây dựng/i.test(text))).toEqual([]);
  });

  it("take their titles from strings.ts", () => {
    expect(PAGES.map(([, , title]) => title)).toEqual([
      S.admin.title.overview,
      S.admin.title.users,
      S.admin.title.llm,
      S.admin.title.rules,
      S.admin.title.digest,
      S.admin.title.labels,
      S.admin.title.knowledge,
      S.admin.title.audit,
    ]);
  });
});
