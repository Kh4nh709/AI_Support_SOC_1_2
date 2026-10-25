// src/features/admin/KnowledgePage.test.tsx — `/admin/knowledge` (P13-T06, spec §7.5): the five tabs, what each
// lists, the conflicts first, an empty store, and the way into a draft or an entry and back. The backend is MSW
// (knowledgeFixtures.ts); the page, the draft view and the entry view are the real ones. The writes themselves are
// tested in KnowledgeDraftView.test.tsx and KnowledgeEntryView.test.tsx; here only what the page does with an answer.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import { S } from "../../strings";
import { KnowledgePage } from "./KnowledgePage";
import {
  detail,
  draftDetail,
  draftRow,
  entryFull,
  entryId,
  entryRow,
  knowledgeBackend,
  type FakeInit,
} from "./knowledgeFixtures";

const K = S.admin.knowledgePage;
const TABS = ["pending", "active", "merged", "rejected", "retired"] as const;
type Tab = (typeof TABS)[number];

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/admin/knowledge"]}>
        <main>
          <KnowledgePage />
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const tab = (name: Tab) => screen.getByRole("tab", { name: K.tab[name] });
const tableOf = (name: Tab) => screen.findByRole("table", { name: K.tableLabel[name] });
const rowsOf = async (name: Tab) =>
  within(await tableOf(name))
    .getAllByRole("row")
    .slice(1);

async function start(init: FakeInit = {}) {
  const fake = knowledgeBackend(server, init);
  const user = userEvent.setup();
  const view = renderPage();
  return { fake, user, view };
}

/** The toast that holds a text: the one `status` element around it. */
const toastOf = (text: HTMLElement) => text.closest('[role="status"]') as HTMLElement;

const SOME: FakeInit = {
  drafts: {
    pending: [draftRow(1), draftRow(2)],
    merged: [draftRow(3, { status: "merged", duplicate_of_entry: entryId(1) })],
    rejected: [
      draftRow(4, {
        status: "rejected",
        reviewed_by_name: "e2e-admin",
        reviewed_at: "2026-10-25T05:00:00+00:00",
        review_note: "Trùng với mục khác",
      }),
    ],
  },
  entries: { active: [entryRow(1), entryRow(2)], retired: [entryRow(3, { status: "retired" })] },
  details: [draftDetail(1), draftDetail(2)],
  entryDetails: [entryFull(1), entryFull(3, { status: "retired" })],
};

describe("the page", () => {
  it("has its title, the five tabs in the order of the spec, and the first one selected", async () => {
    await start(SOME);
    expect(
      screen.getByRole("heading", { level: 1, name: S.admin.title.knowledge }),
    ).toBeInTheDocument();
    const tabs = within(screen.getByRole("tablist", { name: K.tabsLabel })).getAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual([
      "Chờ duyệt",
      "Đã duyệt",
      "Đã gộp",
      "Từ chối",
      "Đã gỡ",
    ]);
    expect(tabs.map((t) => t.getAttribute("aria-selected"))).toEqual([
      "true",
      "false",
      "false",
      "false",
      "false",
    ]);
    expect(await tableOf("pending")).toBeInTheDocument();
  });

  it("reads only the list of the tab on screen", async () => {
    const { fake, user } = await start(SOME);
    await tableOf("pending");
    expect(fake.reads.drafts).toEqual({ pending: 1 });
    expect(fake.reads.entries).toEqual({});
    await user.click(tab("active"));
    await tableOf("active");
    expect(fake.reads.drafts).toEqual({ pending: 1 });
    expect(fake.reads.entries).toEqual({ active: 1 });
  });

  it("names the tab panel after its tab", async () => {
    await start(SOME);
    await tableOf("pending");
    expect(screen.getByRole("tabpanel", { name: K.tab.pending })).toBeInTheDocument();
    expect(tab("pending")).toHaveAttribute("aria-controls", screen.getByRole("tabpanel").id);
  });

  it("moves between the tabs with the arrow keys, Home and End", async () => {
    const { user } = await start(SOME);
    await tableOf("pending");
    tab("pending").focus();
    await user.keyboard("{ArrowRight}");
    expect(tab("active")).toHaveFocus();
    expect(tab("active")).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{End}");
    expect(tab("retired")).toHaveFocus();
    await user.keyboard("{ArrowRight}");
    expect(tab("pending")).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(tab("retired")).toHaveFocus();
    await user.keyboard("{Home}");
    expect(tab("pending")).toHaveFocus();
    expect(tab("pending")).toHaveAttribute("aria-selected", "true");
  });
});

describe("each tab lists what it is for", () => {
  it("Chờ duyệt lists the pending drafts with their source, conclusion and time", async () => {
    await start(SOME);
    const rows = await rowsOf("pending");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("Bản nháp số 1");
    expect(rows[0]).toHaveTextContent(K.sourceKind.alert);
    expect(rows[0]).toHaveTextContent("1727401201.662100");
    expect(rows[0]).toHaveTextContent(S.status.closed_benign);
    expect(rows[1]).toHaveTextContent("Bản nháp số 2");
  });

  it("Đã duyệt lists the active entries", async () => {
    const { fake, user } = await start(SOME);
    await user.click(tab("active"));
    const rows = await rowsOf("active");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("Mục tri thức số 1");
    expect(rows[0]).toHaveTextContent("recon");
    expect(rows[0]).toHaveTextContent("port_scan");
    expect(rows[0]).toHaveTextContent("e2e-admin");
    expect(rows[0]).toHaveTextContent(K.evidenceCount(2));
    expect(fake.reads.entries).toEqual({ active: 1 });
  });

  it("Đã gộp lists the merged drafts and the entry each went into", async () => {
    const { fake, user } = await start(SOME);
    await user.click(tab("merged"));
    const rows = await rowsOf("merged");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("Bản nháp số 3");
    expect(rows[0]).toHaveTextContent(entryId(1));
    expect(fake.reads.drafts).toEqual({ pending: 1, merged: 1 });
  });

  it("Từ chối lists the rejected drafts with who, when and why", async () => {
    const { fake, user } = await start(SOME);
    await user.click(tab("rejected"));
    const rows = await rowsOf("rejected");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("Bản nháp số 4");
    expect(rows[0]).toHaveTextContent("e2e-admin");
    expect(rows[0]).toHaveTextContent("Trùng với mục khác");
    expect(fake.reads.drafts).toEqual({ pending: 1, rejected: 1 });
  });

  it("Đã gỡ lists the retired entries", async () => {
    const { fake, user } = await start(SOME);
    await user.click(tab("retired"));
    const rows = await rowsOf("retired");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("Mục tri thức số 3");
    expect(fake.reads.entries).toEqual({ retired: 1 });
  });

  it("goes back to a tab it listed already without a flash of nothing", async () => {
    const { user } = await start(SOME);
    await tableOf("pending");
    await user.click(tab("active"));
    await tableOf("active");
    await user.click(tab("pending"));
    expect(await rowsOf("pending")).toHaveLength(2);
  });
});

describe("the conflicts come first", () => {
  const ordered: FakeInit = {
    drafts: {
      // the order the route sends: the drafts in conflict, then the oldest
      pending: [
        draftRow(7, { conflict_with_entry: entryId(1), title: "Mâu thuẫn A" }),
        draftRow(8, { conflict_with_entry: entryId(2), title: "Mâu thuẫn B" }),
        draftRow(1, { title: "Cũ nhất" }),
        draftRow(2, { title: "Mới hơn" }),
      ],
    },
  };

  it("lists the drafts in the order the route sent them", async () => {
    await start(ordered);
    const rows = await rowsOf("pending");
    expect(rows.map((r) => within(r).getAllByRole("cell")[0]?.textContent)).toEqual([
      "Mâu thuẫn A",
      "Mâu thuẫn B",
      "Cũ nhất",
      "Mới hơn",
    ]);
  });

  it("marks each draft in conflict with a badge, and only those", async () => {
    await start(ordered);
    const rows = await rowsOf("pending");
    const badged = rows.map((r) => within(r).queryByText(K.badge.conflict) !== null);
    expect(badged).toEqual([true, true, false, false]);
  });

  it("says how many wait and how many are in conflict", async () => {
    await start(ordered);
    await tableOf("pending");
    expect(screen.getByText(K.pendingCount(4, 2))).toBeInTheDocument();
  });

  it("says only how many wait when none is in conflict", async () => {
    await start(SOME);
    await tableOf("pending");
    expect(screen.getByText(K.pendingCount(2, 0))).toBeInTheDocument();
    expect(screen.queryByText(K.badge.conflict)).not.toBeInTheDocument();
  });
});

describe("a draft the job could not write, and one it warned about", () => {
  it("is named by the sentence for a draft with no text, and marked", async () => {
    await start({
      drafts: {
        pending: [
          draftRow(1, { title: null, has_text: false, warnings: ["llm_permanent", "budget"] }),
        ],
      },
    });
    const [row] = await rowsOf("pending");
    expect(row).toHaveTextContent(K.noTitle);
    expect(row).toHaveTextContent(K.badge.noText);
    expect(row).toHaveTextContent(K.badge.warnings(2));
  });
});

describe("an empty store", () => {
  it.each(TABS)("shows the empty state of %s, with no error", async (name) => {
    const { fake, user } = await start();
    if (name !== "pending") await user.click(tab(name));
    expect(await screen.findByText(K.empty[name])).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByText(K.loadFailed)).not.toBeInTheDocument();
    expect(fake.reads.tags).toBe(0);
  });

  it("walks every tab of an empty store without a single error", async () => {
    const { user } = await start();
    for (const name of TABS) {
      await user.click(tab(name));
      expect(await screen.findByText(K.empty[name])).toBeInTheDocument();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    }
  });
});

describe("a list that cannot be read", () => {
  it.each(TABS)("says so on %s, keeps the tabs, and reads again on Thử lại", async (name) => {
    let fail = true;
    const { fake, user } = await start({
      ...SOME,
      list: (kind, status) => {
        if (fail) return HttpResponse.json({}, { status: 500 });
        const rows = kind === "drafts" ? fake.drafts : fake.entries;
        return HttpResponse.json((rows as Record<string, object[]>)[status] ?? []);
      },
    });
    if (name !== "pending") await user.click(tab(name));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(K.loadFailed);
    expect(screen.getAllByRole("tab")).toHaveLength(5);
    fail = false;
    await user.click(within(alert).getByRole("button", { name: S.common.retry }));
    await tableOf(name);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("does not show what the server wrote", async () => {
    await start({
      list: () =>
        HttpResponse.json({ detail: "Traceback (most recent call last)" }, { status: 500 }),
    });
    const alert = await screen.findByRole("alert");
    expect(alert).not.toHaveTextContent("Traceback");
  });
});

describe("a long list", () => {
  it("says the route sends 200 rows at most when it sent 200", async () => {
    const rows = Array.from({ length: 200 }, (_, i) => draftRow(i + 1));
    await start({ drafts: { pending: rows } });
    await tableOf("pending");
    expect(screen.getByText(K.listLimited(200))).toBeInTheDocument();
  });

  it("does not say it for a list that ended", async () => {
    await start(SOME);
    await tableOf("pending");
    expect(screen.queryByText(K.listLimited(200))).not.toBeInTheDocument();
  });
});

describe("text in the lists is text", () => {
  it("shows a hostile title, source, reason and name as literal characters", async () => {
    const HOSTILE = '<img src=x onerror="alert(1)"><script>alert(1)</script>';
    const view = (
      await start({
        drafts: {
          pending: [draftRow(1, { title: HOSTILE, source_id: HOSTILE })],
          rejected: [
            draftRow(2, { status: "rejected", review_note: HOSTILE, reviewed_by_name: HOSTILE }),
          ],
        },
      })
    ).view;
    const [row] = await rowsOf("pending");
    expect(row).toHaveTextContent(HOSTILE);
    await userEvent.setup().click(tab("rejected"));
    const [rejected] = await rowsOf("rejected");
    expect(rejected).toHaveTextContent(HOSTILE);
    expect(view.container.querySelector("script")).toBeNull();
    expect(view.container.querySelector("img")).toBeNull();
    expect(view.container.querySelector("[onerror]")).toBeNull();
  });
});

describe("into a draft and back", () => {
  const openFirst = async (user: ReturnType<typeof userEvent.setup>) => {
    await tableOf("pending");
    await user.click(screen.getByRole("button", { name: K.openDraft("Bản nháp số 1") }));
    return screen.findByRole("region", { name: K.draft.right.heading });
  };

  it("opens the draft in place of the list, with two columns, and goes back to the same tab", async () => {
    const { user } = await start(SOME);
    await openFirst(user);
    expect(screen.getByRole("region", { name: K.draft.left.heading })).toBeInTheDocument();
    // the list and its tabs wait behind the draft
    expect(screen.queryByRole("tablist")).not.toBeInTheDocument();
  });

  it("goes back to the list it came from", async () => {
    const { user } = await start(SOME);
    await user.click(tab("rejected"));
    await tableOf("rejected");
    await user.click(tab("pending"));
    await openFirst(user);
    await user.click(screen.getByRole("button", { name: K.back }));
    expect(await tableOf("pending")).toBeInTheDocument();
    expect(tab("pending")).toHaveAttribute("aria-selected", "true");
    expect(screen.queryByRole("region", { name: K.draft.right.heading })).not.toBeInTheDocument();
  });

  it("after Duyệt: back on the list, the draft gone from it, a toast that says what was done", async () => {
    const { fake, user } = await start(SOME);
    await openFirst(user);
    await user.click(screen.getByRole("button", { name: K.draft.action.approve }));
    const dialog = screen.getByRole("dialog", { name: K.draft.action.approveTitle });
    await user.click(within(dialog).getByRole("button", { name: K.draft.action.approve }));
    const toast = toastOf(
      await screen.findByText(K.done.approved("Quét cổng định kỳ từ máy giám sát nội bộ")),
    );
    const rows = await rowsOf("pending");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("Bản nháp số 2");
    expect(fake.approves).toHaveLength(1);
    // the list was read again behind the write, not guessed
    await waitFor(() => expect(fake.reads.drafts.pending).toBeGreaterThanOrEqual(2));
    await user.click(within(toast).getByRole("button", { name: S.common.close }));
    expect(
      screen.queryByText(K.done.approved("Quét cổng định kỳ từ máy giám sát nội bộ")),
    ).not.toBeInTheDocument();
  });

  it("after Từ chối: back on the list with the draft gone, and it is in the Từ chối tab", async () => {
    const { fake, user } = await start(SOME);
    await openFirst(user);
    await user.click(screen.getByRole("button", { name: K.draft.action.reject }));
    const dialog = screen.getByRole("dialog", { name: K.draft.action.rejectTitle });
    await user.type(within(dialog).getByLabelText(K.draft.action.reasonLabel), "lý do");
    await user.click(within(dialog).getByRole("button", { name: K.draft.action.reject }));
    expect(
      await screen.findByText(K.done.rejected("Quét cổng định kỳ từ máy giám sát nội bộ")),
    ).toBeInTheDocument();
    expect(fake.rejects).toHaveLength(1);
    expect(await rowsOf("pending")).toHaveLength(1);
  });

  it("after a 409: the draft stays open, the list behind it is read again", async () => {
    const { fake, user } = await start({
      ...SOME,
      approve: () => detail({ reason: "not_pending" }, 409),
    });
    await openFirst(user);
    await user.click(screen.getByRole("button", { name: K.draft.action.approve }));
    const dialog = screen.getByRole("dialog", { name: K.draft.action.approveTitle });
    await user.click(within(dialog).getByRole("button", { name: K.draft.action.approve }));
    expect(await screen.findByRole("alert")).toHaveTextContent("bản nháp đã được xử lý");
    await waitFor(() => expect(fake.reads.drafts.pending).toBeGreaterThanOrEqual(2));
    // the draft is still the screen
    expect(screen.getByRole("region", { name: K.draft.right.heading })).toBeInTheDocument();
  });

  it("opens a merged draft read-only, and the entry it was merged into", async () => {
    const { user } = await start({
      ...SOME,
      details: [draftDetail(3, { draft: { status: "merged", duplicate_of_entry: entryId(1) } })],
    });
    await user.click(tab("merged"));
    await tableOf("merged");
    await user.click(screen.getByRole("button", { name: K.openDraft("Bản nháp số 3") }));
    await screen.findByRole("region", { name: K.draft.right.heading });
    expect(screen.queryByRole("button", { name: K.draft.action.approve })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: K.back }));
    await tableOf("merged");
    await user.click(screen.getByRole("button", { name: K.openEntry(entryId(1)) }));
    expect(await screen.findByRole("region", { name: K.entry.header })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: K.back }));
    expect(await tableOf("merged")).toBeInTheDocument();
  });
});

describe("into an entry and back", () => {
  it("opens an entry of Đã duyệt, and Gỡ brings the page back to Đã duyệt without it", async () => {
    const { fake, user } = await start(SOME);
    await user.click(tab("active"));
    await tableOf("active");
    await user.click(screen.getByRole("button", { name: K.openEntry("Mục tri thức số 1") }));
    await screen.findByRole("region", { name: K.entry.header });
    await user.click(screen.getByRole("button", { name: K.entry.retire }));
    const dialog = screen.getByRole("dialog", { name: K.entry.retireTitle });
    await user.type(within(dialog).getByLabelText(K.entry.reasonLabel), "không còn đúng");
    await user.click(within(dialog).getByRole("button", { name: K.entry.retire }));
    expect(await screen.findByText(K.done.retired("Mục tri thức số 1"))).toBeInTheDocument();
    expect(tab("active")).toHaveAttribute("aria-selected", "true");
    const rows = await rowsOf("active");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent("Mục tri thức số 2");
    expect(fake.retires).toHaveLength(1);
    // and the entry is now in the other tab
    await user.click(tab("retired"));
    expect(await rowsOf("retired")).toHaveLength(2);
  });

  it("opens an entry of Đã gỡ without a Gỡ button", async () => {
    const { user } = await start(SOME);
    await user.click(tab("retired"));
    await tableOf("retired");
    await user.click(screen.getByRole("button", { name: K.openEntry("Mục tri thức số 3") }));
    await screen.findByRole("region", { name: K.entry.header });
    expect(screen.queryByRole("button", { name: K.entry.retire })).not.toBeInTheDocument();
  });
});

describe("accessibility", () => {
  const axeOf = async (container: HTMLElement) => {
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(" ")}`);
  };

  it.each(TABS)("has no axe violation: %s with rows", async (name) => {
    const { user, view } = await start(SOME);
    if (name !== "pending") await user.click(tab(name));
    await tableOf(name);
    expect(await axeOf(view.container)).toEqual([]);
  });

  it.each(TABS)("has no axe violation: %s, empty", async (name) => {
    const { user, view } = await start();
    if (name !== "pending") await user.click(tab(name));
    await screen.findByText(K.empty[name]);
    expect(await axeOf(view.container)).toEqual([]);
  });

  it("has no axe violation: a failed list, a toast", async () => {
    const { view } = await start({ list: () => HttpResponse.json({}, { status: 500 }) });
    await screen.findByRole("alert");
    expect(await axeOf(view.container)).toEqual([]);
  });
});
