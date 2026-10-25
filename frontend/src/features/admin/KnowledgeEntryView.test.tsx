// src/features/admin/KnowledgeEntryView.test.tsx — one approved (or retired) knowledge entry (P13-T06): its
// fields, its integrity, its Markdown as text, and Gỡ. The backend is MSW (knowledgeFixtures.ts).
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import { S } from "../../strings";
import { KnowledgeEntryView } from "./KnowledgeEntryView";
import {
  ALERT_ID,
  CASE_ID,
  detail,
  entryFull,
  entryId,
  knowledgeBackend,
  type FakeInit,
} from "./knowledgeFixtures";

const K = S.admin.knowledgePage;
const E = K.entry;

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderView(id = entryId(1)) {
  const onBack = vi.fn();
  const onDone = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const utils = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/admin/knowledge"]}>
        <main>
          <KnowledgeEntryView entryId={id} onBack={onBack} onDone={onDone} />
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...utils, onBack, onDone };
}

const head = () => screen.findByRole("region", { name: E.header });
const retireButton = () => screen.getByRole("button", { name: E.retire });
const dialog = () => screen.getByRole("dialog", { name: E.retireTitle });
const reasonBox = () => within(dialog()).getByLabelText(E.reasonLabel);
const confirm = () => within(dialog()).getByRole("button", { name: E.retire });

async function open(entry = entryFull(), init: FakeInit = {}) {
  const fake = knowledgeBackend(server, { entryDetails: [entry], ...init });
  const user = userEvent.setup();
  const view = renderView(entry.entry_id);
  await head();
  return { fake, user, view };
}

function clickTwiceInOneTick(button: HTMLElement) {
  act(() => {
    fireEvent.click(button);
    fireEvent.click(button);
  });
}

describe("the entry", () => {
  it("shows its title, its status and every field of the entry", async () => {
    await open(entryFull(1, { supersedes_entry: entryId(7) }));
    const region = await head();
    expect(within(region).getByRole("heading", { name: "Mục tri thức số 1" })).toBeInTheDocument();
    expect(region).toHaveTextContent(E.status.active);
    expect(region).toHaveTextContent(E.field.version);
    expect(region).toHaveTextContent(S.status.closed_benign);
    expect(region).toHaveTextContent("recon");
    expect(region).toHaveTextContent("T1046");
    expect(region).toHaveTextContent("port_scan");
    expect(region).toHaveTextContent("SC03");
    expect(region).toHaveTextContent("100190");
    expect(region).toHaveTextContent("wazuh");
    expect(region).toHaveTextContent(`entries/recon/${entryId(1)}.md`);
    expect(region).toHaveTextContent("a".repeat(64));
    expect(region).toHaveTextContent("e2e-admin");
    expect(region).toHaveTextContent(entryId(7));
  });

  it("lists the evidence and links the alerts and cases it came from", async () => {
    await open(
      entryFull(1, {
        source_alert_ids: [ALERT_ID],
        source_case_ids: [CASE_ID],
        evidence: [
          { subject: `alert:${ALERT_ID}`, at: "2026-10-25T04:00:00+00:00" },
          { subject: `case:${CASE_ID}`, at: "2026-10-26T04:00:00+00:00" },
          { subject: "something:else", at: "2026-10-27T04:00:00+00:00" },
        ],
      }),
    );
    const evidence = screen.getByRole("region", { name: E.evidence.heading });
    expect(within(evidence).getAllByRole("listitem")).toHaveLength(3);
    expect(within(evidence).getByText("something:else")).toBeInTheDocument();
    const links = within(screen.getByRole("main"))
      .getAllByRole("link")
      .map((a) => a.getAttribute("href"));
    expect(links).toContain(`/alerts/${encodeURIComponent(ALERT_ID)}`);
    expect(links).toContain(`/cases/${encodeURIComponent(CASE_ID)}`);
  });

  it("says an entry with no evidence in a sentence", async () => {
    await open(entryFull(1, { evidence: [] }));
    expect(screen.getByText(E.evidence.empty)).toBeInTheDocument();
  });

  it("shows the Markdown as text, in a box that scrolls", async () => {
    await open();
    const content = screen.getByRole("region", { name: E.content });
    expect(content).toHaveTextContent("# Mục tri thức số 1");
    expect(content).toHaveTextContent("entry_id:");
    expect(content).toHaveTextContent("Tóm tắt của mục.");
    expect(content).toHaveAttribute("tabindex", "0");
  });

  it("goes back to the list", async () => {
    const { user, view } = await open();
    await user.click(screen.getByRole("button", { name: K.back }));
    expect(view.onBack).toHaveBeenCalledTimes(1);
  });
});

describe("approved Markdown is text, never markup", () => {
  const MARKDOWN = [
    "# Mục",
    "",
    "<script>alert(1)</script>",
    "",
    "[bấm vào đây](javascript:alert(1))",
    "",
    '<a href="javascript:alert(2)" onclick="alert(3)">x</a>',
    "",
    "<img src=x onerror=alert(4)>",
  ].join("\n");

  it("renders an entry whose content holds a script and a javascript: link as literal text", async () => {
    const { view } = await open(entryFull(1, { content: MARKDOWN, title: "<b>đậm</b>" }));
    const content = screen.getByRole("region", { name: E.content });
    expect(content).toHaveTextContent("<script>alert(1)</script>");
    expect(content).toHaveTextContent("[bấm vào đây](javascript:alert(1))");
    expect(content).toHaveTextContent('<a href="javascript:alert(2)" onclick="alert(3)">x</a>');
    expect(view.container.querySelector("script")).toBeNull();
    expect(view.container.querySelector('a[href^="javascript"]')).toBeNull();
    expect(view.container.querySelector("img")).toBeNull();
    expect(view.container.querySelector("b")).toBeNull();
    expect(view.container.querySelector("[onclick], [onerror]")).toBeNull();
    // the only links are the ones the page makes itself, to the page of an alert
    for (const a of view.container.querySelectorAll("a")) {
      expect(a.getAttribute("href")).toMatch(/^\/(alerts|cases)\//);
    }
    expect(screen.getByRole("heading", { name: "<b>đậm</b>" })).toBeInTheDocument();
  });

  it("renders a hostile subject of the evidence as text, and makes no link of it", async () => {
    const { view } = await open(
      entryFull(1, {
        evidence: [
          { subject: "alert:<img src=x onerror=alert(1)>", at: "2026-10-25T04:00:00+00:00" },
        ],
        source_alert_ids: [],
      }),
    );
    expect(view.container.querySelector("img")).toBeNull();
    const evidence = screen.getByRole("region", { name: E.evidence.heading });
    expect(evidence).toHaveTextContent("alert:<img src=x onerror=alert(1)>");
    expect(view.container.querySelector('a[href*="onerror"]')).toBeNull();
  });
});

describe("integrity (both an active and a retired entry)", () => {
  it.each(["active", "retired"] as const)("says an intact %s entry is intact", async (status) => {
    await open(entryFull(1, { status }));
    const integrity = screen.getByRole("region", { name: E.integrity.heading });
    expect(integrity).toHaveTextContent(E.integrity.ok);
    expect(integrity).not.toHaveTextContent(E.integrity.contentBad);
    expect(integrity).not.toHaveTextContent(E.integrity.fileBad);
  });

  it.each(["active", "retired"] as const)(
    "says a %s entry whose file differs from the database",
    async (status) => {
      await open(entryFull(1, { status, integrity: { content_ok: true, file_ok: false } }));
      const integrity = screen.getByRole("region", { name: E.integrity.heading });
      expect(integrity).toHaveTextContent(E.integrity.fileBad);
      expect(integrity).not.toHaveTextContent(E.integrity.contentBad);
      expect(integrity).not.toHaveTextContent(E.integrity.ok);
    },
  );

  it.each(["active", "retired"] as const)(
    "says a %s entry whose content does not hash to its hash",
    async (status) => {
      await open(entryFull(1, { status, integrity: { content_ok: false, file_ok: true } }));
      const integrity = screen.getByRole("region", { name: E.integrity.heading });
      expect(integrity).toHaveTextContent(E.integrity.contentBad);
      expect(integrity).not.toHaveTextContent(E.integrity.fileBad);
    },
  );

  it("says both when both are wrong", async () => {
    await open(entryFull(1, { integrity: { content_ok: false, file_ok: false } }));
    const integrity = screen.getByRole("region", { name: E.integrity.heading });
    expect(integrity).toHaveTextContent(E.integrity.contentBad);
    expect(integrity).toHaveTextContent(E.integrity.fileBad);
  });
});

describe("Gỡ", () => {
  it("is offered on an active entry and not on a retired one", async () => {
    await open(entryFull(1, { status: "retired" }));
    expect(screen.queryByRole("button", { name: E.retire })).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: E.header })).toHaveTextContent(E.status.retired);
  });

  it("asks for a reason first, and cannot be confirmed without one", async () => {
    const { fake, user } = await open();
    await user.click(retireButton());
    expect(dialog()).toHaveTextContent(E.retireBody);
    expect(reasonBox()).toHaveFocus();
    expect(confirm()).toBeDisabled();
    await user.type(reasonBox(), "   ");
    expect(confirm()).toBeDisabled();
    expect(fake.retires).toEqual([]);
  });

  it("sends the reason, trimmed, with a JSON Content-Type, then says it is done", async () => {
    const { fake, user, view } = await open();
    await user.click(retireButton());
    await user.type(reasonBox(), "  không còn đúng sau khi đổi quy trình  ");
    await user.click(confirm());
    await waitFor(() => expect(view.onDone).toHaveBeenCalledTimes(1));
    expect(fake.retires).toHaveLength(1);
    expect(fake.retires[0]?.id).toBe(entryId(1));
    expect(fake.retires[0]?.body).toEqual({ reason: "không còn đúng sau khi đổi quy trình" });
    expect(fake.retires[0]?.contentType).toMatch(/^application\/json/);
    expect(view.onDone).toHaveBeenCalledWith(K.done.retired("Mục tri thức số 1"));
  });

  it("sends one POST for two clicks of the same tick", async () => {
    const { fake, user } = await open();
    await user.click(retireButton());
    await user.type(reasonBox(), "một lý do");
    clickTwiceInOneTick(confirm());
    await waitFor(() => expect(fake.retires).toHaveLength(1));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(fake.retires).toHaveLength(1);
  });

  it("sends nothing when the admin cancels", async () => {
    const { fake, user } = await open();
    await user.click(retireButton());
    await user.type(reasonBox(), "dở dang");
    await user.click(within(dialog()).getByRole("button", { name: S.admin.common.cancel }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(fake.retires).toEqual([]);
  });

  it("counts the characters and cannot be confirmed past 500", async () => {
    const { user } = await open();
    await user.click(retireButton());
    fireEvent.change(reasonBox(), { target: { value: "a".repeat(501) } });
    expect(dialog()).toHaveTextContent(S.admin.knowledgePage.draft.action.reasonCount(501, 500));
    expect(confirm()).toBeDisabled();
  });

  it("says a 409 not_active as the entry's own sentence, closes the dialog and reads again", async () => {
    const { fake, user, view } = await open(entryFull(), {
      retire: () => detail({ reason: "not_active" }, 409),
    });
    await user.click(retireButton());
    await user.type(reasonBox(), "lý do");
    await user.click(confirm());
    expect(await screen.findByRole("alert")).toHaveTextContent(K.notice.entryHandled);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await waitFor(() => expect(fake.reads.entry[entryId(1)]).toBe(2));
    expect(view.onDone).not.toHaveBeenCalled();
  });

  it("shows an entry retired meanwhile as retired once it is read again, with no Gỡ", async () => {
    const { fake, user } = await open(entryFull(), {
      retire: () => detail({ reason: "not_active" }, 409),
    });
    const stored = fake.entryDetails.get(entryId(1));
    if (stored) stored.status = "retired";
    await user.click(retireButton());
    await user.type(reasonBox(), "lý do");
    await user.click(confirm());
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: E.retire })).not.toBeInTheDocument(),
    );
    expect(screen.getByRole("region", { name: E.header })).toHaveTextContent(E.status.retired);
  });

  it("keeps the dialog open on a 503 publish_failed, and the same button asks again", async () => {
    let attempts = 0;
    const { fake, user, view } = await open(entryFull(), {
      retire: () => {
        attempts += 1;
        return attempts === 1
          ? detail({ reason: "publish_failed" }, 503)
          : HttpResponse.json({ entry_id: entryId(1), status: "retired" });
      },
    });
    await user.click(retireButton());
    await user.type(reasonBox(), "lý do");
    await user.click(confirm());
    expect(await within(dialog()).findByRole("alert")).toHaveTextContent(K.notice.publishFailed);
    expect(confirm()).toBeEnabled();
    await user.click(confirm());
    await waitFor(() => expect(view.onDone).toHaveBeenCalledTimes(1));
    expect(fake.retires).toHaveLength(2);
  });

  it("shows a 422 about the reason at the reason input", async () => {
    const { user } = await open(entryFull(), {
      retire: () => detail({ field: "reason", reason: "invalid" }, 422),
    });
    await user.click(retireButton());
    await user.type(reasonBox(), "lý do");
    await user.click(confirm());
    await waitFor(() => expect(reasonBox()).toBeInvalid());
    expect(reasonBox()).toHaveAccessibleDescription(new RegExp(K.notice.reasonInvalid(500)));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("says any other failure in a plain sentence in the dialog", async () => {
    const { user } = await open(entryFull(), {
      retire: () => HttpResponse.json({ detail: "boom" }, { status: 500 }),
    });
    await user.click(retireButton());
    await user.type(reasonBox(), "lý do");
    await user.click(confirm());
    const alert = await within(dialog()).findByRole("alert");
    expect(alert).toHaveTextContent(K.notice.failed);
    expect(alert).not.toHaveTextContent("boom");
  });
});

describe("loading and failing", () => {
  it("shows a waiting line, then the entry", async () => {
    knowledgeBackend(server, { entryDetails: [entryFull()] });
    renderView();
    expect(screen.getByRole("status")).toHaveTextContent(S.common.loading);
    await head();
  });

  it("says an entry that does not exist, with the way back and no retry", async () => {
    knowledgeBackend(server);
    const view = renderView(entryId(9));
    expect(await screen.findByText(K.notice.entryGone)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.common.retry })).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: K.back }));
    expect(view.onBack).toHaveBeenCalled();
  });

  it("says a failed read, and reads again on Thử lại", async () => {
    let fail = true;
    const fake = knowledgeBackend(server, {
      entryDetails: [entryFull()],
      entryAnswer: (id) =>
        fail
          ? HttpResponse.json({}, { status: 500 })
          : HttpResponse.json(fake.entryDetails.get(id)),
    });
    renderView();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(E.loadFailed);
    fail = false;
    await userEvent.setup().click(within(alert).getByRole("button", { name: S.common.retry }));
    await head();
    expect(fake.reads.entry[entryId(1)]).toBe(2);
  });
});

describe("accessibility", () => {
  const axeOf = async (container: HTMLElement) => {
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(" ")}`);
  };

  it("has no axe violation: an active entry, a broken one, a retired one, the dialog", async () => {
    const { view, user } = await open(
      entryFull(1, { integrity: { content_ok: false, file_ok: false } }),
    );
    expect(await axeOf(view.container)).toEqual([]);
    await user.click(retireButton());
    expect(await axeOf(view.container)).toEqual([]);
  });

  it("has no axe violation: a retired entry", async () => {
    const { view } = await open(entryFull(1, { status: "retired" }));
    expect(await axeOf(view.container)).toEqual([]);
  });
});

// --- fix round 1 of the review (task-6-review-r1.md) -------------------------------------------------------------

describe("source ids that are not safe to link are still shown (M6)", () => {
  it("shows an id that fails the link pattern as plain text, and links the others", async () => {
    const odd = "<img src=x onerror=alert(1)>";
    const spaced = "id with spaces";
    const { view } = await open(
      entryFull(1, { source_alert_ids: [odd, ALERT_ID, spaced], source_case_ids: [CASE_ID] }),
    );
    const evidence = screen.getByRole("region", { name: E.evidence.heading });
    expect(evidence).toHaveTextContent(odd);
    expect(evidence).toHaveTextContent(spaced);
    expect(evidence).toHaveTextContent(ALERT_ID);
    expect(view.container.querySelector("img")).toBeNull();
    expect(view.container.querySelector("[onerror]")).toBeNull();
    const links = within(evidence)
      .getAllByRole("link")
      .map((a) => a.getAttribute("href"));
    expect(links).toContain(`/alerts/${encodeURIComponent(ALERT_ID)}`);
    expect(links).toContain(`/cases/${encodeURIComponent(CASE_ID)}`);
    expect(links.some((href) => /onerror|%20/.test(href ?? ""))).toBe(false);
  });
});

describe("a 404 leaves no action on stale data (M3)", () => {
  it("hides Gỡ after a 404 on the retirement, and says the entry is gone", async () => {
    const { user, view } = await open(entryFull(), {
      retire: () => detail({ reason: "not_found" }, 404),
    });
    await user.click(retireButton());
    await user.type(reasonBox(), "lý do");
    await user.click(confirm());
    expect(await screen.findByRole("alert")).toHaveTextContent(K.notice.entryGone);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: E.retire })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: K.back }));
    expect(view.onBack).toHaveBeenCalled();
  });
});

describe("focus (M4)", () => {
  it("moves to the title of the entry when it opens", async () => {
    await open();
    const title = screen.getByRole("heading", { name: "Mục tri thức số 1" });
    expect(title).toHaveFocus();
    expect(title).toHaveAttribute("tabindex", "-1");
  });
});

describe("the reason counts characters, as the backend does (nit)", () => {
  it("counts 500 emoji as 500, and 501 as too long", async () => {
    const { user } = await open();
    await user.click(retireButton());
    fireEvent.change(reasonBox(), { target: { value: "😀".repeat(500) } });
    expect(dialog()).toHaveTextContent(S.admin.knowledgePage.draft.action.reasonCount(500, 500));
    expect(confirm()).toBeEnabled();
    fireEvent.change(reasonBox(), { target: { value: "😀".repeat(501) } });
    expect(confirm()).toBeDisabled();
  });
});
