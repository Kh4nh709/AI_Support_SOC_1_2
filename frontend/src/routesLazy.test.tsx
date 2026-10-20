// src/routesLazy.test.tsx — the seven admin pages are fetched when their route opens, and only for an admin
// (P11-T20 row 56: the main bundle carried every page of the console, for tier1 and tier2 as well).
//
// routes.test.tsx tests which route opens for which role, with the pages as stubs that are ready at once. This file
// holds the pages back, so it can see what routes.tsx does while a page is on its way: a page's module is only
// asked for (its mock factory only runs) when the route renders it, and a route that turns the visitor away never does.
// The file has an order, because a module that has been fetched stays fetched: the test that expects no fetch is first.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { readFileSync } from "node:fs";
import { MemoryRouter, useLocation } from "react-router";
import { AuthContext, type AuthState } from "./auth/AuthProvider";
import type { Session } from "./auth/session";
import { AppRoutes } from "./routes";
import { S } from "./strings";

/**
 * What the mocked pages record, and the gate that can hold them. The gate is open until a test calls `hold()`, so a
 * routes.tsx that imports the pages at once fails the tests below and does not hang them.
 */
const gate = vi.hoisted(() => {
  let release: () => void = () => {};
  let held: Promise<void> | null = null;
  return {
    /** The page modules asked for (a factory runs when its module is first imported), and the pages rendered. */
    loads: [] as string[],
    rendered: [] as string[],
    failAudit: false,
    /** From now on a page's module is not ready until `open()`. */
    hold() {
      held = new Promise<void>((resolve) => {
        release = resolve;
      });
    },
    open() {
      release();
      held = null;
    },
    /** What a mock factory awaits. */
    ready: (): Promise<void> => held ?? Promise.resolve(),
  };
});

vi.mock("./features/admin/OverviewPage", async () => {
  gate.loads.push("OverviewPage");
  await gate.ready();
  return {
    OverviewPage: () => {
      gate.rendered.push("OverviewPage");
      return <h1>{S.admin.title.overview}</h1>;
    },
  };
});
vi.mock("./features/admin/UsersPage", async () => {
  gate.loads.push("UsersPage");
  await gate.ready();
  return {
    UsersPage: () => {
      gate.rendered.push("UsersPage");
      return <h1>{S.admin.title.users}</h1>;
    },
  };
});
vi.mock("./features/admin/LlmPage", async () => {
  gate.loads.push("LlmPage");
  await gate.ready();
  return {
    LlmPage: () => {
      gate.rendered.push("LlmPage");
      return <h1>{S.admin.title.llm}</h1>;
    },
  };
});
vi.mock("./features/admin/RulesPage", async () => {
  gate.loads.push("RulesPage");
  await gate.ready();
  return {
    RulesPage: () => {
      gate.rendered.push("RulesPage");
      return <h1>{S.admin.title.rules}</h1>;
    },
  };
});
vi.mock("./features/admin/DigestPage", async () => {
  gate.loads.push("DigestPage");
  await gate.ready();
  return {
    DigestPage: () => {
      gate.rendered.push("DigestPage");
      return <h1>{S.admin.title.digest}</h1>;
    },
  };
});
vi.mock("./features/admin/LabelsPage", async () => {
  gate.loads.push("LabelsPage");
  await gate.ready();
  return {
    LabelsPage: () => {
      gate.rendered.push("LabelsPage");
      return <h1>{S.admin.title.labels}</h1>;
    },
  };
});
vi.mock("./features/admin/AuditPage", async () => {
  gate.loads.push("AuditPage");
  // A chunk that cannot be fetched: the network, or a deploy that replaced the file this tab knows the name of.
  if (gate.failAudit) throw new Error("Failed to fetch dynamically imported module");
  await gate.ready();
  return {
    AuditPage: () => {
      gate.rendered.push("AuditPage");
      return <h1>{S.admin.title.audit}</h1>;
    },
  };
});

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

function renderAt(path: string, s: Session | null) {
  const auth: AuthState = {
    session: s,
    ready: true,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
  };
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
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
/** The page area: the header has a `status` of its own (the live indicator), which is not the waiting line. */
const inMain = () => within(screen.getByRole("main"));

const ADMIN_PATHS = [
  "/admin",
  "/admin/overview",
  "/admin/users",
  "/admin/llm",
  "/admin/rules",
  "/admin/digest",
  "/admin/labels",
  "/admin/audit",
];

/** Nothing asked for a page module, and no page rendered: said after the imports that a render started have settled. */
async function expectNoPageFetched(): Promise<void> {
  await vi.dynamicImportSettled();
  expect(gate.loads).toEqual([]);
  expect(gate.rendered).toEqual([]);
}

describe("who fetches an admin page", () => {
  // A mock factory runs when its module is first imported, so what a test reads is what that test caused.
  beforeEach(() => {
    gate.loads.length = 0;
    gate.rendered.length = 0;
  });

  it.each(["tier1", "tier2"] as const)(
    "never asks for one when %s is turned away, whichever page it was",
    async (role) => {
      for (const path of ADMIN_PATHS) {
        const view = renderAt(path, session(role));
        expect(where(), path).toBe("/queue");
        expect(screen.getByRole("alert")).toHaveTextContent(S.forbidden);
        view.unmount();
      }
      await expectNoPageFetched();
    },
  );

  it("never asks for one when nobody is signed in", async () => {
    for (const path of ADMIN_PATHS) {
      const view = renderAt(path, null);
      expect(where(), path).toBe("/login");
      view.unmount();
    }
    await expectNoPageFetched();
  });

  it("asks for the page of the route, and only that one, when an admin opens it", async () => {
    gate.hold();
    try {
      renderAt("/admin/users", session("admin"));
      // Holding the page back shows the waiting line: the sidebar is there already, and no page is.
      expect(screen.getByRole("navigation", { name: S.admin.nav.label })).toBeInTheDocument();
      expect(await inMain().findByRole("status")).toHaveTextContent(S.common.loading);
      expect(screen.queryByRole("heading", { level: 1 })).not.toBeInTheDocument();
      expect(gate.loads).toEqual(["UsersPage"]);
    } finally {
      gate.open();
    }
    expect(
      await screen.findByRole("heading", { level: 1, name: S.admin.title.users }),
    ).toBeInTheDocument();
    expect(inMain().queryByRole("status")).not.toBeInTheDocument();
    expect(gate.loads).toEqual(["UsersPage"]);
  });

  it("sends /admin to the overview and fetches that page", async () => {
    renderAt("/admin", session("admin"));
    expect(
      await screen.findByRole("heading", { level: 1, name: S.admin.title.overview }),
    ).toBeInTheDocument();
    expect(where()).toBe("/admin/overview");
    expect(gate.loads).toEqual(["OverviewPage"]);
  });
});

describe("a page that cannot be fetched", () => {
  it("says so in place of the page, under the sidebar, and the other pages still open", async () => {
    gate.failAudit = true;
    // React logs the error it hands to the boundary, which is the point of the test and not noise to keep.
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      renderAt("/admin/audit", session("admin"));
      expect(await screen.findByRole("alert")).toHaveTextContent(S.admin.common.loadError);
      expect(screen.getByRole("button", { name: S.common.retry })).toBeInTheDocument();
      expect(screen.getByRole("navigation", { name: S.admin.nav.label })).toBeInTheDocument();
      expect(inMain().queryByRole("status")).not.toBeInTheDocument();

      // The sidebar still works: the users page is in hand, so the next route shows it, not the failure.
      const user = userEvent.setup();
      await user.click(screen.getByRole("link", { name: S.admin.nav.users }));
      expect(where()).toBe("/admin/users");
      expect(
        await screen.findByRole("heading", { level: 1, name: S.admin.title.users }),
      ).toBeInTheDocument();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    } finally {
      logged.mockRestore();
      gate.failAudit = false;
    }
  });
});

describe("the route table in source", () => {
  const source = readFileSync("src/routes.tsx", "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");

  it.each(["Overview", "Users", "Llm", "Rules", "Digest", "Labels", "Audit"])(
    "has %sPage in a dynamic import() and in no static import, so the page stays out of the main bundle",
    (name) => {
      const path = `./features/admin/${name}Page`;
      expect(source).not.toMatch(new RegExp(`^import\\b[^;]*from "${path}"`, "m"));
      expect(source).toContain(`import("${path}")`);
    },
  );
});
