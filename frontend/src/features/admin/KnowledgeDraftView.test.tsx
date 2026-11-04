// src/features/admin/KnowledgeDraftView.test.tsx — one knowledge draft (P13-T06, spec §7.5): the analyst's work
// read-only on the left, the draft form on the right, and the four writes. The backend is MSW (a fake of
// admin_knowledge.py's routes, knowledgeFixtures.ts); the view is the real one.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import { KNOWLEDGE_CLOSED_FIELDS, KNOWLEDGE_MODEL_FIELDS } from "../../api/admin";
import type { Suggestion } from "../../api/tier1";
import { S } from "../../strings";
import { KnowledgeDraftView } from "./KnowledgeDraftView";
import {
  CASE_ID,
  GOOD_FIELDS,
  TAGS,
  alertView,
  detail,
  draftDetail,
  draftId,
  entryFull,
  entryId,
  forcedSuggestion,
  knowledgeBackend,
  type FakeInit,
} from "./knowledgeFixtures";

const K = S.admin.knowledgePage;
const D = K.draft;

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// --- rendering and small helpers --------------------------------------------------------------------------

function renderView(id = draftId(1), client?: QueryClient) {
  const onBack = vi.fn();
  const onDone = vi.fn();
  const queryClient = client ?? new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const utils = render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/admin/knowledge"]}>
        <main>
          <KnowledgeDraftView draftId={id} onBack={onBack} onDone={onDone} />
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...utils, onBack, onDone, queryClient };
}

const left = () => screen.getByRole("region", { name: D.left.heading });
const right = () => screen.getByRole("region", { name: D.right.heading });
const box = (name: string) => within(right()).getByLabelText(name) as HTMLInputElement;
const approveButton = () => within(right()).getByRole("button", { name: D.action.approve });
const editApproveButton = () => within(right()).getByRole("button", { name: D.action.editApprove });
const rejectButton = () => within(right()).getByRole("button", { name: D.action.reject });
const dialog = (name: string) => screen.getByRole("dialog", { name });
const loaded = () => screen.findByRole("region", { name: D.right.heading });

type User = ReturnType<typeof userEvent.setup>;

async function open(init: FakeInit = {}, n = 1) {
  const fake = knowledgeBackend(server, { details: [draftDetail(n)], ...init });
  const user = userEvent.setup();
  const view = renderView(draftId(n));
  await loaded();
  return { fake, user, view };
}

async function replace(user: User, field: HTMLElement, text: string) {
  await user.clear(field);
  if (text !== "") await user.type(field, text);
}

function clickTwiceInOneTick(button: HTMLElement) {
  act(() => {
    fireEvent.click(button);
    fireEvent.click(button);
  });
}

// --- the re-draft (P13 fix wave, item 20: the model could not be asked) ---------------------------------------

const redraftButton = () => within(right()).queryByRole("button", { name: D.action.redraft });
const textless = (warnings: string[], status: "pending" | "approved" = "pending") =>
  draftDetail(1, { draft: { draft: {}, warnings, status } });

describe("Soạn lại, for a draft the model could not be asked for", () => {
  it.each([
    ["the budget", ["budget"]],
    ["a timeout", ["llm_transient"]],
    ["a refusal", ["llm_permanent"]],
    ["a ranking that gave no answer", ["rank_unavailable", "llm_permanent"]],
  ])("is offered for a text-less draft whose warning is %s", async (_label, warnings) => {
    await open({ details: [textless(warnings)] });
    expect(redraftButton()).toBeEnabled();
  });

  it.each([
    ["a draft with text", draftDetail(1, { draft: { warnings: ["budget"] } })],
    ["no warning at all", textless([])],
    ["a rule the model broke", textless(["v3_ipv4:summary"])],
    ["one warning that is not the absence of the model", textless(["budget", "v4_nonce:title"])],
    ["our own prompt failing the linter", textless(["linter"])],
    ["a word nobody here knows", textless(["something_new"])],
    ["a draft already handled", textless(["budget"], "approved")],
  ])("is not offered for %s", async (_label, one) => {
    await open({ details: [one] });
    expect(redraftButton()).not.toBeInTheDocument();
  });

  it("asks first, then sends one body-less POST and leaves the screen with a toast", async () => {
    const { fake, user, view } = await open({ details: [textless(["budget"])] });
    await user.click(redraftButton()!);
    expect(fake.redrafts).toHaveLength(0); // the click only asks
    await user.click(
      within(dialog(D.action.redraftTitle)).getByRole("button", { name: D.action.redraft }),
    );
    await waitFor(() => expect(view.onDone).toHaveBeenCalledTimes(1));
    expect(fake.redrafts).toEqual([
      { id: draftId(1), body: {}, contentType: expect.stringContaining("application/json") },
    ]);
    expect(view.onDone).toHaveBeenCalledWith(K.done.redrafted(K.noTitle));
  });

  it("sends nothing when the dialog is cancelled", async () => {
    const { fake, user } = await open({ details: [textless(["budget"])] });
    await user.click(redraftButton()!);
    await user.click(
      within(dialog(D.action.redraftTitle)).getByRole("button", { name: S.admin.common.cancel }),
    );
    expect(fake.redrafts).toHaveLength(0);
  });

  it("says the draft cannot be made again when the route answers 409 not_redraftable", async () => {
    const { user } = await open({
      details: [textless(["budget"])],
      redraft: () => detail({ reason: "not_redraftable" }, 409),
    });
    await user.click(redraftButton()!);
    await user.click(
      within(dialog(D.action.redraftTitle)).getByRole("button", { name: D.action.redraft }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(K.notice.notRedraftable);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("says the drafts are switched off when the route answers 409 drafts_disabled", async () => {
    const { user, view } = await open({
      details: [textless(["budget"])],
      redraft: () => detail({ reason: "drafts_disabled" }, 409),
    });
    await user.click(redraftButton()!);
    await user.click(
      within(dialog(D.action.redraftTitle)).getByRole("button", { name: D.action.redraft }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(K.notice.draftsDisabled);
    expect(view.onDone).not.toHaveBeenCalled();
  });

  it("is not offered once the draft is gone (404)", async () => {
    const { user } = await open({
      details: [textless(["budget"])],
      redraft: () => detail({ reason: "not_found" }, 404),
    });
    await user.click(redraftButton()!);
    await user.click(
      within(dialog(D.action.redraftTitle)).getByRole("button", { name: D.action.redraft }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(K.notice.gone);
    expect(redraftButton()).not.toBeInTheDocument();
  });

  it("still lets the admin reject or write it by hand", async () => {
    await open({ details: [textless(["budget"])] });
    expect(rejectButton()).toBeEnabled();
    expect(approveButton()).toBeDisabled(); // no text yet: Sửa rồi duyệt is the way, as before
  });
});

// --- the left column ----------------------------------------------------------------------------------------

describe("the analyst's work, on the left, of an alert", () => {
  it("shows the alert with the sections of the alert page, and ①'s result", async () => {
    await open();
    const col = within(left());
    // the title of the alert page, which the sections below it do not carry
    expect(
      col.getByRole("heading", { name: "Phát hiện quét cổng từ máy trong mạng nội bộ" }),
    ).toBeInTheDocument();
    // the same sections the Tier-1 page draws from the same JSON
    expect(col.getByRole("region", { name: S.alert.summaryLabel })).toHaveTextContent("100190");
    expect(col.getByText("10.10.5.7")).toBeInTheDocument(); // the event details
    expect(col.getByRole("region", { name: S.alert.rawLog })).toHaveTextContent(
      "SCAN SRC=10.10.5.7",
    );
    expect(col.getByText("svc-monitor")).toBeInTheDocument(); // the targeted accounts
    expect(col.getByText("Xác nhận nguồn quét với đội hạ tầng.")).toBeInTheDocument(); // the playbook
    expect(col.getByRole("heading", { name: S.alert.aiHeading })).toBeInTheDocument(); // ① (decided: DEC-206)
  });

  it("shows the decision: who, when, and what was recorded", async () => {
    await open();
    const decision = within(left()).getByRole("region", { name: D.left.decision.heading });
    expect(decision).toHaveTextContent(S.admin.eventType["tier1.decided"]);
    expect(decision).toHaveTextContent("an.t1");
    expect(decision).toHaveTextContent("benign");
    expect(decision).toHaveTextContent("đã xác minh với đội hạ tầng");
  });

  it("shows the SOAR block, as text", async () => {
    await open();
    const soar = within(left()).getByRole("region", { name: D.left.soar.heading });
    expect(soar).toHaveTextContent("fw-edge-01");
    expect(soar).toHaveTextContent("criticality");
    expect(soar).toHaveTextContent("high");
  });

  it("leaves the SOAR block out when the alert has none", async () => {
    await open({ details: [draftDetail(1, { source: { enrichment: null } })] });
    expect(
      within(left()).queryByRole("region", { name: D.left.soar.heading }),
    ).not.toBeInTheDocument();
  });

  it("has no action of the analyst: no button but the copy button of the log", async () => {
    await open();
    for (const button of within(left()).queryAllByRole("button")) {
      expect(button.textContent).toBe(S.common.copy);
    }
    for (const name of [
      D.action.approve,
      D.action.reject,
      S.decision.heading,
      S.decision.goToCase,
    ]) {
      expect(within(left()).queryByRole("button", { name })).not.toBeInTheDocument();
    }
    expect(within(left()).queryByRole("textbox")).not.toBeInTheDocument();
    expect(within(left()).queryByRole("form")).not.toBeInTheDocument();
  });

  it("says a missing alert as a sentence, not as an error", async () => {
    await open({ details: [draftDetail(1, { source: { alert: null } })] });
    expect(within(left()).getByText(D.left.noData.alert)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    // the form still works
    expect(approveButton()).toBeEnabled();
  });

  it("says a missing decision as a sentence too", async () => {
    await open({ details: [draftDetail(1, { source: { decision: null } })] });
    expect(within(left()).getByText(D.left.noData.decision)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("the analyst's work, on the left, of a case", () => {
  const caseDraft = (source: Parameters<typeof draftDetail>[1] = {}) =>
    draftDetail(1, {
      ...source,
      draft: {
        source_kind: "case",
        source_id: CASE_ID,
        conclusion: "concluded_fp",
        ...source.draft,
      },
    });

  it("shows the case, its heads, its timeline, its notes and ②'s result with the evidence", async () => {
    await open({ details: [caseDraft()] });
    const col = within(left());
    // the title of the case page, which the sections below it do not carry
    expect(
      col.getByRole("heading", { name: "Chuỗi quét cổng và đăng nhập lặp lại" }),
    ).toBeInTheDocument();
    expect(col.getByRole("region", { name: S.case.summaryLabel })).toHaveTextContent(
      S.caseStatus.concluded_fp,
    );
    expect(col.getByRole("heading", { name: S.case.heads })).toBeInTheDocument();
    expect(col.getByRole("link", { name: /Phát hiện quét cổng/ })).toHaveAttribute(
      "href",
      "/alerts/1727401201.662100",
    );
    expect(col.getByRole("list", { name: S.case.timeline })).toBeInTheDocument();
    const notes = col.getByRole("region", { name: D.left.notes.heading });
    expect(notes).toHaveTextContent("binh.t2");
    expect(notes).toHaveTextContent("Đã hỏi đội hạ tầng, lịch quét có thật.");
    // ②: the summary and the quote it cited, marked as checked against the log
    expect(col.getByText("Các cụm là một đợt quét định kỳ của máy giám sát.")).toBeInTheDocument();
    expect(col.getByText(/SCAN SRC=10\.10\.5\.7/, { selector: "p" })).toBeInTheDocument();
    expect(col.getByText(S.ai2.mark.verified)).toBeInTheDocument();
  });

  it("shows the decision of Tier 2", async () => {
    await open({ details: [caseDraft()] });
    const decision = within(left()).getByRole("region", { name: D.left.decision.heading });
    expect(decision).toHaveTextContent(S.admin.eventType["tier2.concluded"]);
    expect(decision).toHaveTextContent("binh.t2");
  });

  it("shows the SOAR block of each head that has one", async () => {
    const enrichment = { "1727401201.662100": { asset: { host: "fw-edge-01" } } };
    await open({ details: [caseDraft({ source: { enrichment } })] });
    const soar = within(left()).getByRole("region", { name: D.left.soar.heading });
    expect(soar).toHaveTextContent(D.left.soar.forHead("1727401201.662100"));
    expect(soar).toHaveTextContent("fw-edge-01");
  });

  it("has no note form, no conclusion form and no analyse button", async () => {
    await open({ details: [caseDraft()] });
    expect(within(left()).queryByRole("textbox")).not.toBeInTheDocument();
    expect(within(left()).queryByRole("radio")).not.toBeInTheDocument();
    expect(within(left()).queryByRole("button", { name: S.ai2.analyze })).not.toBeInTheDocument();
    expect(within(left()).queryByRole("button", { name: S.ai2.reanalyze })).not.toBeInTheDocument();
    expect(
      within(left()).queryByRole("button", { name: S.case.concludeSubmit }),
    ).not.toBeInTheDocument();
    for (const button of within(left()).queryAllByRole("button")) {
      expect([S.case.showLog, S.case.hideLog, S.common.copy]).toContain(button.textContent);
    }
  });

  it("says a case that is gone, and its investigation that is gone, as sentences", async () => {
    await open({
      details: [caseDraft({ source: { case: null, investigation: null, notes: [] } })],
    });
    expect(within(left()).getByText(D.left.noData.case)).toBeInTheDocument();
    expect(within(left()).getByText(D.left.noData.investigation)).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says a case with no result of ② as a sentence", async () => {
    await open({
      details: [
        caseDraft({
          source: {
            investigation: {
              state: "idle",
              run_id: null,
              minutes: null,
              run: null,
              current: null,
              case_open: false,
            },
          },
        }),
      ],
    });
    expect(within(left()).getByText(D.left.investigation.none)).toBeInTheDocument();
  });
});

describe("a draft that conflicts with an entry", () => {
  const conflicting = (status: "active" | "retired") =>
    draftDetail(1, {
      draft: { conflict_with_entry: entryId(5) },
      source: {
        conflict_entry: entryFull(5, {
          status,
          title: "Mục cũ: quét cổng là hoạt động đáng ngờ",
          conclusion: "confirmed_incident",
        }),
      },
    });

  it("shows the conflicting entry beside the draft, with its Markdown as text", async () => {
    await open({ details: [conflicting("active")] });
    const panel = within(left()).getByRole("region", { name: D.left.conflict.heading.active });
    expect(panel).toHaveTextContent("Mục cũ: quét cổng là hoạt động đáng ngờ");
    expect(panel).toHaveTextContent(S.caseStatus.confirmed_incident);
    expect(panel).toHaveTextContent("Tóm tắt của mục.");
    expect(panel).toHaveTextContent("entry_id:");
  });

  it("marks the draft as in conflict in its header, with the plain badge for an active entry", async () => {
    await open({ details: [conflicting("active")] });
    const head = screen.getByRole("region", { name: D.header });
    expect(within(head).getByText(K.badge.conflict)).toBeInTheDocument();
    expect(within(head).queryByText(K.badge.conflictRetired)).not.toBeInTheDocument();
  });

  it("names a conflicting entry that has been retired since: the badge says 'mâu thuẫn với mục đã gỡ'", async () => {
    await open({ details: [conflicting("retired")] });
    const head = screen.getByRole("region", { name: D.header });
    expect(within(head).getByText(K.badge.conflictRetired)).toBeInTheDocument();
    expect(within(head).queryByText(K.badge.conflict)).not.toBeInTheDocument();
    expect(K.badge.conflictRetired).toMatch(/mâu thuẫn với mục đã gỡ/i);
    expect(
      within(left()).getByRole("region", { name: D.left.conflict.heading.retired }),
    ).toBeInTheDocument();
  });

  it("says a conflicting entry that is gone as a sentence", async () => {
    await open({
      details: [
        draftDetail(1, {
          draft: { conflict_with_entry: entryId(5) },
          source: { conflict_entry: null },
        }),
      ],
    });
    expect(within(left()).getByText(D.left.conflict.noData)).toBeInTheDocument();
  });

  it("shows no conflict panel for a draft with none", async () => {
    await open();
    expect(
      within(left()).queryByRole("region", { name: D.left.conflict.heading.active }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(K.badge.conflict)).not.toBeInTheDocument();
  });
});

// --- the right column ---------------------------------------------------------------------------------------

describe("the draft form, on the right", () => {
  it("fills the six model fields with the draft", async () => {
    await open();
    expect(box(D.right.field.title).value).toBe(GOOD_FIELDS.title);
    expect(box(D.right.field.summary).value).toBe(GOOD_FIELDS.summary);
    expect(box(D.right.field.distinguishing_signals).value).toBe(
      GOOD_FIELDS.distinguishing_signals.join("\n"),
    );
    expect(box(D.right.field.check_next_time).value).toBe(GOOD_FIELDS.check_next_time.join("\n"));
    expect(box(D.right.field.confidence_note).value).toBe(GOOD_FIELDS.confidence_note);
  });

  it("shows the six closed fields read-only, with their values and no input", async () => {
    await open();
    const closed = within(right()).getByRole("group", { name: D.right.closedHeading });
    expect(closed).toHaveTextContent(D.right.closedHint);
    for (const field of KNOWLEDGE_CLOSED_FIELDS) {
      expect(closed).toHaveTextContent(D.right.closed[field]);
    }
    expect(closed).toHaveTextContent("recon");
    expect(closed).toHaveTextContent("T1046");
    expect(closed).toHaveTextContent("SC03");
    expect(closed).toHaveTextContent("100190");
    expect(closed).toHaveTextContent("wazuh");
    expect(within(closed).queryByRole("textbox")).not.toBeInTheDocument();
    expect(within(closed).queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("offers the tags as a picker over the closed vocabulary, the draft's tags ticked", async () => {
    const { fake } = await open();
    const tags = await within(right()).findByRole("group", { name: D.right.field.tags });
    await waitFor(() =>
      expect(within(tags).getAllByRole("checkbox")).toHaveLength(TAGS.tags.length),
    );
    for (const tag of TAGS.tags) {
      const input = within(tags).getByRole("checkbox", { name: tag });
      if (GOOD_FIELDS.tags.includes(tag)) expect(input).toBeChecked();
      else expect(input).not.toBeChecked();
    }
    expect(within(tags).getByText(TAGS.descriptions.port_scan as string)).toBeInTheDocument();
    expect(fake.reads.tags).toBe(1);
  });

  it("keeps a tag of the draft that is not in the vocabulary ticked, marked, and removable", async () => {
    const user = userEvent.setup();
    knowledgeBackend(server, {
      details: [
        draftDetail(1, { draft: { draft: { ...GOOD_FIELDS, tags: ["port_scan", "old_tag"] } } }),
      ],
    });
    renderView();
    const tags = await within(await loaded()).findByRole("group", { name: D.right.field.tags });
    await waitFor(() => expect(within(tags).getAllByRole("checkbox").length).toBeGreaterThan(2));
    const old = within(tags).getByRole("checkbox", { name: /old_tag/ });
    expect(old).toBeChecked();
    expect(tags).toHaveTextContent(D.right.tags.outside);
    await user.click(old);
    expect(old).not.toBeChecked();
  });

  it("says when the tag list cannot be read, and leaves the rest of the form usable", async () => {
    await open({ tagsAnswer: () => HttpResponse.json({}, { status: 500 }) });
    const tags = await within(right()).findByRole("group", { name: D.right.field.tags });
    expect(await within(tags).findByText(D.right.tags.loadFailed)).toBeInTheDocument();
    expect(box(D.right.field.title)).toBeEnabled();
  });

  it("lists the warnings of the job in words", async () => {
    await open({
      details: [
        draftDetail(1, {
          draft: { warnings: ["rank_unavailable", "v3_ipv4:summary", "something_new"] },
        }),
      ],
    });
    const warnings = within(right()).getByRole("region", { name: D.right.warnings });
    expect(warnings).toHaveTextContent(K.warning.rank_unavailable);
    expect(warnings).toHaveTextContent(K.fault.rule.v3_ipv4);
    expect(warnings).toHaveTextContent("something_new");
  });

  it("shows no warnings block when there is none", async () => {
    await open();
    expect(
      within(right()).queryByRole("region", { name: D.right.warnings }),
    ).not.toBeInTheDocument();
  });

  it("states the limits in the hints of the fields", async () => {
    await open();
    expect(box(D.right.field.title)).toHaveAccessibleDescription(/120/);
    expect(box(D.right.field.summary)).toHaveAccessibleDescription(/600/);
    expect(box(D.right.field.distinguishing_signals)).toHaveAccessibleDescription(/6.*160/);
    expect(box(D.right.field.confidence_note)).toHaveAccessibleDescription(/200/);
  });
});

describe("a draft that has no text", () => {
  const noText = () => draftDetail(1, { draft: { draft: {}, warnings: ["llm_permanent"] } });

  it("words the refusal as the provider's or the model's, a 402 included (INT-T02)", async () => {
    await open({ details: [noText()] });
    const warnings = within(right()).getByRole("region", { name: D.right.warnings });
    expect(warnings).toHaveTextContent(K.warning.llm_permanent);
    expect(warnings).toHaveTextContent(/nhà cung cấp hoặc mô hình từ chối yêu cầu/i);
    expect(warnings).toHaveTextContent(/hết số dư, 402/);
  });

  it("says so, offers an empty form, and does not offer Duyệt", async () => {
    await open({ details: [noText()] });
    expect(within(right()).getByText(D.right.noText)).toBeInTheDocument();
    expect(box(D.right.field.title).value).toBe("");
    expect(approveButton()).toBeDisabled();
    expect(approveButton()).toHaveAccessibleDescription(D.action.approveNoText);
    expect(rejectButton()).toBeEnabled();
  });

  it("sends all six fields when the admin writes the draft and chooses Sửa rồi duyệt", async () => {
    const { fake, user } = await open({ details: [noText()] });
    await user.type(box(D.right.field.title), "Tự viết");
    await user.click(editApproveButton());
    await user.click(
      within(dialog(D.action.editApproveTitle)).getByRole("button", { name: D.action.editApprove }),
    );
    await waitFor(() => expect(fake.approves).toHaveLength(1));
    expect(fake.approves[0]?.body).toEqual({
      edited: {
        title: "Tự viết",
        tags: [],
        summary: "",
        distinguishing_signals: [],
        check_next_time: [],
        confidence_note: "",
      },
    });
  });
});

describe("a draft that is not pending", () => {
  it.each([
    [
      "rejected",
      {
        status: "rejected",
        reviewed_by_name: "e2e-admin",
        reviewed_at: "2026-10-25T05:00:00+00:00",
        review_note: "Trùng với mục khác",
      },
    ],
    ["merged", { status: "merged", duplicate_of_entry: entryId(3) }],
    [
      "approved",
      {
        status: "approved",
        reviewed_by_name: "e2e-admin",
        reviewed_at: "2026-10-25T05:00:00+00:00",
      },
    ],
  ] as const)("is read-only when %s: no action, no editable field", async (_name, change) => {
    await open({ details: [draftDetail(1, { draft: { ...change } })] });
    expect(
      within(right()).queryByRole("button", { name: D.action.approve }),
    ).not.toBeInTheDocument();
    expect(
      within(right()).queryByRole("button", { name: D.action.editApprove }),
    ).not.toBeInTheDocument();
    expect(
      within(right()).queryByRole("button", { name: D.action.reject }),
    ).not.toBeInTheDocument();
    expect(box(D.right.field.title).readOnly).toBe(true);
    expect(box(D.right.field.summary).readOnly).toBe(true);
    expect(within(right()).getByText(D.right.readOnly)).toBeInTheDocument();
    for (const tag of within(right()).getAllByRole("checkbox")) expect(tag).toBeDisabled();
  });

  it("shows who handled it, and the reason of a rejection", async () => {
    await open({
      details: [
        draftDetail(1, {
          draft: {
            status: "rejected",
            reviewed_by_name: "e2e-admin",
            reviewed_at: "2026-10-25T05:00:00+00:00",
            review_note: "Trùng với mục khác",
          },
        }),
      ],
    });
    const head = screen.getByRole("region", { name: D.header });
    expect(head).toHaveTextContent(D.status.rejected);
    expect(head).toHaveTextContent("e2e-admin");
    expect(head).toHaveTextContent("Trùng với mục khác");
  });
});

// --- the header ---------------------------------------------------------------------------------------------

describe("the header", () => {
  it("names the draft, its status, its source and its conclusion, and goes back", async () => {
    const { user, view } = await open();
    const head = screen.getByRole("region", { name: D.header });
    expect(within(head).getByRole("heading", { name: GOOD_FIELDS.title })).toBeInTheDocument();
    expect(head).toHaveTextContent(D.status.pending);
    expect(head).toHaveTextContent(K.sourceKind.alert);
    expect(head).toHaveTextContent("1727401201.662100");
    expect(head).toHaveTextContent(S.status.closed_benign);
    await user.click(within(head).getByRole("button", { name: K.back }));
    expect(view.onBack).toHaveBeenCalledTimes(1);
  });

  it("names a draft with no text by the sentence for it", async () => {
    await open({ details: [draftDetail(1, { draft: { draft: {} } })] });
    expect(screen.getByRole("heading", { name: K.noTitle })).toBeInTheDocument();
  });
});

describe("loading and failing", () => {
  it("shows a waiting line, then the draft", async () => {
    knowledgeBackend(server, { details: [draftDetail()] });
    renderView();
    expect(screen.getByRole("status")).toHaveTextContent(S.common.loading);
    await loaded();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("says a draft that does not exist, with the way back and no retry", async () => {
    knowledgeBackend(server);
    const view = renderView(draftId(9));
    expect(await screen.findByText(K.notice.gone)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.common.retry })).not.toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: K.back }));
    expect(view.onBack).toHaveBeenCalled();
  });

  it("says a failed read, and reads again on Thử lại", async () => {
    let fail = true;
    const fake = knowledgeBackend(server, {
      details: [draftDetail()],
      draftAnswer: (id) =>
        fail ? HttpResponse.json({}, { status: 500 }) : HttpResponse.json(fake.details.get(id)),
    });
    renderView();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(D.loadFailed);
    fail = false;
    await userEvent.setup().click(within(alert).getByRole("button", { name: S.common.retry }));
    await loaded();
    expect(fake.reads.draft[draftId(1)]).toBe(2);
  });
});

// --- Duyệt ---------------------------------------------------------------------------------------------------

describe("Duyệt", () => {
  it("asks first, and sends nothing when the admin cancels", async () => {
    const { fake, user, view } = await open();
    await user.click(approveButton());
    const box_ = dialog(D.action.approveTitle);
    expect(box_).toHaveTextContent(D.action.approveBody);
    await user.click(within(box_).getByRole("button", { name: S.admin.common.cancel }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(fake.approves).toEqual([]);
    expect(view.onDone).not.toHaveBeenCalled();
  });

  it("sends {} with a JSON Content-Type, then says it is done", async () => {
    const { fake, user, view } = await open();
    await user.click(approveButton());
    await user.click(
      within(dialog(D.action.approveTitle)).getByRole("button", { name: D.action.approve }),
    );
    await waitFor(() => expect(view.onDone).toHaveBeenCalledTimes(1));
    expect(fake.approves).toHaveLength(1);
    expect(fake.approves[0]?.id).toBe(draftId(1));
    expect(fake.approves[0]?.body).toEqual({});
    expect(fake.approves[0]?.contentType).toMatch(/^application\/json/);
    expect(view.onDone).toHaveBeenCalledWith(K.done.approved(GOOD_FIELDS.title));
  });

  it("sends one POST for two clicks of the same tick", async () => {
    const { fake, user } = await open();
    await user.click(approveButton());
    clickTwiceInOneTick(
      within(dialog(D.action.approveTitle)).getByRole("button", { name: D.action.approve }),
    );
    await waitFor(() => expect(fake.approves).toHaveLength(1));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(fake.approves).toHaveLength(1);
  });

  it("is not offered while the form is edited: the edit would be lost", async () => {
    const { user } = await open();
    await user.type(box(D.right.field.title), " bổ sung");
    expect(approveButton()).toBeDisabled();
    expect(approveButton()).toHaveAccessibleDescription(D.action.approveEdited);
    expect(editApproveButton()).toBeEnabled();
  });

  it("is the only one offered while the form is as it came", async () => {
    await open();
    expect(approveButton()).toBeEnabled();
    expect(editApproveButton()).toBeDisabled();
    expect(editApproveButton()).toHaveAccessibleDescription(D.action.editApproveClean);
  });
});

// --- Sửa rồi duyệt -------------------------------------------------------------------------------------------

describe("Sửa rồi duyệt", () => {
  async function confirmEdit(user: User) {
    await user.click(editApproveButton());
    await user.click(
      within(dialog(D.action.editApproveTitle)).getByRole("button", { name: D.action.editApprove }),
    );
  }

  it("sends only the field that changed", async () => {
    const { fake, user, view } = await open();
    await replace(user, box(D.right.field.title), "Quét cổng định kỳ của máy giám sát");
    await confirmEdit(user);
    await waitFor(() => expect(view.onDone).toHaveBeenCalledTimes(1));
    expect(fake.approves[0]?.body).toEqual({
      edited: { title: "Quét cổng định kỳ của máy giám sát" },
    });
  });

  it("sends a list field as its lines, a blank line dropped", async () => {
    const { fake, user } = await open();
    await replace(
      user,
      box(D.right.field.distinguishing_signals),
      "Một dấu hiệu{Enter}{Enter}Hai dấu hiệu",
    );
    await confirmEdit(user);
    await waitFor(() => expect(fake.approves).toHaveLength(1));
    expect(fake.approves[0]?.body).toEqual({
      edited: { distinguishing_signals: ["Một dấu hiệu", "Hai dấu hiệu"] },
    });
  });

  it("sends the tags as picked", async () => {
    const { fake, user } = await open();
    const tags = await within(right()).findByRole("group", { name: D.right.field.tags });
    await waitFor(() => expect(within(tags).getAllByRole("checkbox")).toHaveLength(4));
    await user.click(within(tags).getByRole("checkbox", { name: "firewall" }));
    await user.click(within(tags).getByRole("checkbox", { name: "malware" }));
    await confirmEdit(user);
    await waitFor(() => expect(fake.approves).toHaveLength(1));
    const edited = (fake.approves[0]?.body as { edited: { tags: string[] } }).edited;
    expect([...edited.tags].sort()).toEqual(["malware", "port_scan"]);
  });

  it("never sends a closed field, whatever was changed", async () => {
    const { fake, user } = await open();
    await replace(user, box(D.right.field.title), "A");
    await replace(user, box(D.right.field.summary), "B");
    await replace(user, box(D.right.field.distinguishing_signals), "C");
    await replace(user, box(D.right.field.check_next_time), "D");
    await replace(user, box(D.right.field.confidence_note), "E");
    await confirmEdit(user);
    await waitFor(() => expect(fake.approves).toHaveLength(1));
    const sent = (fake.approves[0]?.body as { edited: Record<string, unknown> }).edited;
    expect(Object.keys(sent).sort()).toEqual(
      [...KNOWLEDGE_MODEL_FIELDS].filter((f) => f !== "tags").sort(),
    );
    for (const closed of KNOWLEDGE_CLOSED_FIELDS) expect(sent).not.toHaveProperty(closed);
    expect(Object.keys(fake.approves[0]?.body as object)).toEqual(["edited"]);
  });

  it("names the fields it is about to send in the dialog", async () => {
    const { user } = await open();
    await replace(user, box(D.right.field.title), "Tiêu đề khác");
    await user.click(editApproveButton());
    expect(dialog(D.action.editApproveTitle)).toHaveTextContent(D.right.field.title);
  });
});

// --- the faults of V1-V5 -------------------------------------------------------------------------------------

describe("a 422 with faults", () => {
  const faults =
    (...names: string[]) =>
    () =>
      HttpResponse.json({ faults: names }, { status: 422 });

  async function approveWith(user: User, ...names: string[]) {
    const fake = knowledgeBackend(server, { details: [draftDetail()], approve: faults(...names) });
    renderView();
    await loaded();
    await user.type(box(D.right.field.summary), " thêm");
    await user.click(editApproveButton());
    await user.click(
      within(dialog(D.action.editApproveTitle)).getByRole("button", { name: D.action.editApprove }),
    );
    await waitFor(() => expect(fake.approves).toHaveLength(1));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    return fake;
  }

  it("shows each fault next to the field named after the colon, and keeps what was typed", async () => {
    const user = userEvent.setup();
    await approveWith(user, "v3_ipv4:summary", "v5_length:summary", "v5_empty:title");
    expect(box(D.right.field.summary)).toHaveAccessibleDescription(
      new RegExp(K.fault.rule.v3_ipv4),
    );
    expect(box(D.right.field.summary)).toHaveAccessibleDescription(
      new RegExp(K.fault.rule.v5_length),
    );
    expect(box(D.right.field.title)).toHaveAccessibleDescription(new RegExp(K.fault.rule.v5_empty));
    expect(box(D.right.field.summary)).toBeInvalid();
    expect(box(D.right.field.title)).toBeInvalid();
    expect(box(D.right.field.check_next_time)).not.toBeInvalid();
    expect(box(D.right.field.summary).value).toBe(`${GOOD_FIELDS.summary} thêm`);
  });

  it("shows a fault of a closed field next to that field", async () => {
    const user = userEvent.setup();
    await approveWith(user, "v2_closed:category");
    const closed = within(right()).getByRole("group", { name: D.right.closedHeading });
    expect(closed).toHaveTextContent(K.fault.rule.v2_closed);
  });

  it("shows a fault with no field of the draft above the form", async () => {
    const user = userEvent.setup();
    await approveWith(user, "v1_schema:root", "v1_tags:unknown_tag", "v5_length:title");
    const above = within(right()).getByRole("alert");
    expect(above).toHaveTextContent(K.notice.faults(3));
    expect(above).toHaveTextContent(K.fault.special["v1_schema:root"]);
    expect(above).toHaveTextContent(K.fault.special["v1_tags:unknown_tag"]);
    // the one that has a field is at its field, and not repeated above
    expect(above).not.toHaveTextContent(K.fault.rule.v5_length);
    expect(box(D.right.field.title)).toHaveAccessibleDescription(
      new RegExp(K.fault.rule.v5_length),
    );
  });

  it("words a rule it does not know with the generic sentence", async () => {
    const user = userEvent.setup();
    await approveWith(user, "v9_brand_new:summary");
    expect(box(D.right.field.summary)).toHaveAccessibleDescription(
      new RegExp(K.fault.fallback("v9_brand_new")),
    );
  });

  it("forgets a field's faults when that field is edited, and the rest when asked again", async () => {
    const user = userEvent.setup();
    await approveWith(user, "v3_ipv4:summary", "v5_empty:title");
    await user.type(box(D.right.field.summary), "x");
    expect(box(D.right.field.summary)).not.toBeInvalid();
    expect(box(D.right.field.title)).toBeInvalid();
  });

  it("leaves the draft as it was: the form is still editable and the buttons are back", async () => {
    const user = userEvent.setup();
    await approveWith(user, "v3_ipv4:summary");
    expect(editApproveButton()).toBeEnabled();
    expect(rejectButton()).toBeEnabled();
  });

  it("does not call the page's done", async () => {
    const user = userEvent.setup();
    const fake = knowledgeBackend(server, {
      details: [draftDetail()],
      approve: faults("v1_schema:root"),
    });
    const view = renderView();
    await loaded();
    await user.click(approveButton());
    await user.click(
      within(dialog(D.action.approveTitle)).getByRole("button", { name: D.action.approve }),
    );
    await waitFor(() => expect(fake.approves).toHaveLength(1));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(view.onDone).not.toHaveBeenCalled();
  });
});

// --- 409, 404, 503 ------------------------------------------------------------------------------------------

describe("a write that is refused or fails", () => {
  async function approveAndFail(answer: () => Response, init: FakeInit = {}) {
    const fake = knowledgeBackend(server, { details: [draftDetail()], approve: answer, ...init });
    const user = userEvent.setup();
    const view = renderView();
    await loaded();
    await user.click(approveButton());
    await user.click(
      within(dialog(D.action.approveTitle)).getByRole("button", { name: D.action.approve }),
    );
    await waitFor(() => expect(fake.approves).toHaveLength(1));
    return { fake, user, view };
  }

  it.each(["not_pending", "source_changed", "unpublishable", "anything_else"])(
    "says 'bản nháp đã được xử lý' for a 409 %s, closes the dialog and reads the draft again",
    async (reason) => {
      const { fake, view } = await approveAndFail(() => detail({ reason }, 409));
      expect(await screen.findByRole("alert")).toHaveTextContent("bản nháp đã được xử lý");
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      await waitFor(() => expect(fake.reads.draft[draftId(1)]).toBe(2));
      expect(view.onDone).not.toHaveBeenCalled();
    },
  );

  it("shows a draft that was handled meanwhile as read-only once it is read again", async () => {
    const answer = () => detail({ reason: "not_pending" }, 409);
    const fake = knowledgeBackend(server, { details: [draftDetail()], approve: answer });
    const user = userEvent.setup();
    renderView();
    await loaded();
    // another admin rejected it meanwhile
    const stored = fake.details.get(draftId(1));
    if (stored) stored.draft.status = "rejected";
    await user.click(approveButton());
    await user.click(
      within(dialog(D.action.approveTitle)).getByRole("button", { name: D.action.approve }),
    );
    await waitFor(() => expect(box(D.right.field.title).readOnly).toBe(true));
    expect(
      within(right()).queryByRole("button", { name: D.action.approve }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("bản nháp đã được xử lý");
  });

  it("says a 404 as 'not found', closes the dialog and reads again", async () => {
    await approveAndFail(() => detail({ reason: "not_found" }, 404));
    expect(await screen.findByRole("alert")).toHaveTextContent(K.notice.gone);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("keeps the dialog open on a 503 publish_failed, says it is worth another try, and succeeds on it", async () => {
    let attempts = 0;
    const { fake, user, view } = await approveAndFail(() => {
      attempts += 1;
      return attempts === 1
        ? detail({ reason: "publish_failed" }, 503)
        : HttpResponse.json({ entry_id: entryId(99) });
    });
    const box_ = dialog(D.action.approveTitle);
    expect(await within(box_).findByRole("alert")).toHaveTextContent(K.notice.publishFailed);
    expect(view.onDone).not.toHaveBeenCalled();
    const confirm = within(box_).getByRole("button", { name: D.action.approve });
    expect(confirm).toBeEnabled();
    await user.click(confirm);
    await waitFor(() => expect(view.onDone).toHaveBeenCalledTimes(1));
    expect(fake.approves).toHaveLength(2);
  });

  it("keeps the dialog open on any other failure, with a plain sentence and no server text", async () => {
    await approveAndFail(() =>
      HttpResponse.json({ detail: "Traceback (most recent call last)" }, { status: 500 }),
    );
    const box_ = dialog(D.action.approveTitle);
    expect(await within(box_).findByRole("alert")).toHaveTextContent(K.notice.failed);
    expect(box_).not.toHaveTextContent("Traceback");
  });

  it("keeps the dialog open when the network fails", async () => {
    await approveAndFail(() => HttpResponse.error());
    expect(await within(dialog(D.action.approveTitle)).findByRole("alert")).toHaveTextContent(
      K.notice.failed,
    );
  });

  it("treats a 422 about the request itself as a plain failure", async () => {
    await approveAndFail(() => detail({ field: "edited", reason: "invalid" }, 422));
    expect(await within(dialog(D.action.approveTitle)).findByRole("alert")).toHaveTextContent(
      K.notice.editedInvalid,
    );
  });
});

// --- Từ chối -------------------------------------------------------------------------------------------------

describe("Từ chối", () => {
  const reasonBox = () => within(dialog(D.action.rejectTitle)).getByLabelText(D.action.reasonLabel);
  const confirm = () =>
    within(dialog(D.action.rejectTitle)).getByRole("button", { name: D.action.reject });

  it("asks for a reason, and cannot be confirmed without one", async () => {
    const { fake, user } = await open();
    await user.click(rejectButton());
    expect(reasonBox()).toHaveFocus();
    expect(confirm()).toBeDisabled();
    await user.type(reasonBox(), "   ");
    expect(confirm()).toBeDisabled();
    expect(fake.rejects).toEqual([]);
  });

  it("sends the reason, trimmed, with a JSON Content-Type, then says it is done", async () => {
    const { fake, user, view } = await open();
    await user.click(rejectButton());
    await user.type(reasonBox(), "  Trùng với mục khác  ");
    await user.click(confirm());
    await waitFor(() => expect(view.onDone).toHaveBeenCalledTimes(1));
    expect(fake.rejects).toHaveLength(1);
    expect(fake.rejects[0]?.id).toBe(draftId(1));
    expect(fake.rejects[0]?.body).toEqual({ reason: "Trùng với mục khác" });
    expect(fake.rejects[0]?.contentType).toMatch(/^application\/json/);
    expect(view.onDone).toHaveBeenCalledWith(K.done.rejected(GOOD_FIELDS.title));
  });

  it("counts the characters and cannot be confirmed past 500", async () => {
    const { user } = await open();
    await user.click(rejectButton());
    fireEvent.change(reasonBox(), { target: { value: "a".repeat(500) } });
    expect(dialog(D.action.rejectTitle)).toHaveTextContent(D.action.reasonCount(500, 500));
    expect(confirm()).toBeEnabled();
    fireEvent.change(reasonBox(), { target: { value: "a".repeat(501) } });
    expect(confirm()).toBeDisabled();
  });

  it("sends one POST for two clicks of the same tick", async () => {
    const { fake, user } = await open();
    await user.click(rejectButton());
    await user.type(reasonBox(), "một lý do");
    clickTwiceInOneTick(confirm());
    await waitFor(() => expect(fake.rejects).toHaveLength(1));
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(fake.rejects).toHaveLength(1);
  });

  it.each([
    ["required", K.notice.reasonRequired],
    ["invalid", K.notice.reasonInvalid(500)],
  ])("shows a 422 %s on the reason input", async (reason, text) => {
    const { user } = await open({
      reject: () => detail({ field: "reason", reason }, 422),
    });
    await user.click(rejectButton());
    await user.type(reasonBox(), "lý do");
    await user.click(confirm());
    await waitFor(() => expect(reasonBox()).toBeInvalid());
    expect(reasonBox()).toHaveAccessibleDescription(new RegExp(text));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("says 'bản nháp đã được xử lý' for a 409 and reads again", async () => {
    const { fake, user } = await open({ reject: () => detail({ reason: "not_pending" }, 409) });
    await user.click(rejectButton());
    await user.type(reasonBox(), "lý do");
    await user.click(confirm());
    expect(await screen.findByRole("alert")).toHaveTextContent("bản nháp đã được xử lý");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await waitFor(() => expect(fake.reads.draft[draftId(1)]).toBe(2));
  });

  it("forgets the reason when the dialog is closed", async () => {
    const { user } = await open();
    await user.click(rejectButton());
    await user.type(reasonBox(), "dở dang");
    await user.click(
      within(dialog(D.action.rejectTitle)).getByRole("button", { name: S.admin.common.cancel }),
    );
    await user.click(rejectButton());
    expect((reasonBox() as HTMLTextAreaElement).value).toBe("");
  });
});

// --- text is text --------------------------------------------------------------------------------------------

describe("everything a model or an analyst wrote is text", () => {
  const HOSTILE = '<img src=x onerror="alert(1)"><script>alert(1)</script>';

  it("renders the draft, the notes, the decision, the SOAR block and the warnings as literal text", async () => {
    const hostile = draftDetail(1, {
      draft: {
        draft: { ...GOOD_FIELDS, title: `T ${HOSTILE}`, summary: `S ${HOSTILE}` },
        warnings: [HOSTILE],
        review_note: HOSTILE,
      },
      source: {
        decision: {
          event_type: "tier1.decided",
          actor_id: "u",
          actor_name: HOSTILE,
          at: "2026-10-25T01:10:00+00:00",
          payload: { reason: HOSTILE },
        },
        enrichment: { note: HOSTILE },
      },
    });
    knowledgeBackend(server, { details: [hostile] });
    const view = renderView();
    await loaded();
    expect(view.container.querySelector("script")).toBeNull();
    expect(view.container.querySelector("img")).toBeNull();
    expect(view.container.querySelector("[onerror]")).toBeNull();
    expect(screen.getByRole("heading", { name: `T ${HOSTILE}` })).toBeInTheDocument();
    expect(box(D.right.field.summary).value).toBe(`S ${HOSTILE}`);
    expect(within(left()).getByRole("region", { name: D.left.decision.heading })).toHaveTextContent(
      HOSTILE,
    );
    // the SOAR block is JSON, where a quote is escaped: the same characters, as text
    expect(within(left()).getByRole("region", { name: D.left.soar.heading })).toHaveTextContent(
      JSON.stringify(HOSTILE).slice(1, -1),
    );
  });

  it("renders the Markdown of a conflicting entry as literal text, with no link and no script", async () => {
    const markdown =
      '# Mục\n\n<script>alert(1)</script>\n\n[bấm vào đây](javascript:alert(1))\n\n<a href="javascript:alert(2)">x</a>';
    knowledgeBackend(server, {
      details: [
        draftDetail(1, {
          draft: { conflict_with_entry: entryId(5) },
          source: { conflict_entry: entryFull(5, { content: markdown }) },
        }),
      ],
    });
    const view = renderView();
    await loaded();
    const panel = within(left()).getByRole("region", { name: D.left.conflict.heading.active });
    expect(panel).toHaveTextContent("<script>alert(1)</script>");
    expect(panel).toHaveTextContent("[bấm vào đây](javascript:alert(1))");
    expect(view.container.querySelector("script")).toBeNull();
    expect(view.container.querySelector('a[href^="javascript"]')).toBeNull();
    expect(panel.querySelector("a")).toBeNull();
  });
});

// --- accessibility -------------------------------------------------------------------------------------------

describe("accessibility", () => {
  const axeOf = async (container: HTMLElement) => {
    // jsdom computes no layout or colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(" ")}`);
  };

  it("has no axe violation: an alert draft", async () => {
    const { view } = await open();
    await within(right()).findByRole("group", { name: D.right.field.tags });
    await waitFor(() => expect(within(right()).getAllByRole("checkbox")).toHaveLength(4));
    expect(await axeOf(view.container)).toEqual([]);
  });

  it("has no axe violation: a case draft with a conflict", async () => {
    knowledgeBackend(server, {
      details: [
        draftDetail(1, {
          draft: { source_kind: "case", source_id: CASE_ID, conflict_with_entry: entryId(5) },
          source: { conflict_entry: entryFull(5) },
        }),
      ],
    });
    const view = renderView();
    await loaded();
    expect(await axeOf(view.container)).toEqual([]);
  });

  it("has no axe violation: a draft with faults at its fields", async () => {
    const user = userEvent.setup();
    knowledgeBackend(server, {
      details: [draftDetail()],
      approve: () =>
        HttpResponse.json({ faults: ["v3_ipv4:summary", "v1_schema:root"] }, { status: 422 }),
    });
    const view = renderView();
    await loaded();
    await user.click(approveButton());
    await user.click(
      within(dialog(D.action.approveTitle)).getByRole("button", { name: D.action.approve }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(await axeOf(view.container)).toEqual([]);
  });

  it("has no axe violation: the reject dialog", async () => {
    const { user, view } = await open();
    await user.click(rejectButton());
    expect(await axeOf(view.container)).toEqual([]);
  });

  it("has no axe violation: a draft with no text, and a draft already handled", async () => {
    knowledgeBackend(server, {
      details: [
        draftDetail(1, { draft: { draft: {} } }),
        draftDetail(2, { draft: { status: "rejected", review_note: "trùng" } }),
      ],
    });
    const first = renderView(draftId(1));
    await loaded();
    expect(await axeOf(first.container)).toEqual([]);
    first.unmount();
    const second = renderView(draftId(2));
    await loaded();
    expect(await axeOf(second.container)).toEqual([]);
  });
});

// --- fix round 1 of the review (task-6-review-r1.md) -------------------------------------------------------------

describe("①'s suggestion: its gate and its reasons, beside what ① decided (spec §7.5, I1)", () => {
  const withSuggestion = (suggestion: Suggestion | null) =>
    draftDetail(1, { source: { alert: alertView({ suggestion }) } });
  const box = () => within(left()).getByRole("region", { name: D.left.suggestion.heading });

  it("shows a forced gate: that it forced, by which rules, its steps and its warnings", async () => {
    await open({ details: [withSuggestion(forcedSuggestion())] });
    const gate = box();
    expect(gate).toHaveTextContent(S.ai1.gate);
    expect(gate).toHaveTextContent(S.ai1.gateForced);
    expect(gate).toHaveTextContent(S.ai1.gateForcedBy);
    expect(gate).toHaveTextContent("asset_high, ioc_bad");
    // the steps: what ① proposed, what the gate ended with, what the verifier said
    expect(gate).toHaveTextContent(S.ai1.gateSteps);
    expect(gate).toHaveTextContent(S.ai1.gateProposed);
    expect(gate).toHaveTextContent(S.ai1.action.false_positive);
    expect(gate).toHaveTextContent(S.ai1.gateFinal);
    expect(gate).toHaveTextContent(S.ai1.action.needs_review);
    expect(gate).toHaveTextContent(S.ai1.verifier);
    expect(gate).toHaveTextContent("disagree");
    expect(gate).toHaveTextContent(S.ai1.gateWarnings);
  });

  it("shows the reasons of ①, with the quote and the source of each", async () => {
    await open({ details: [withSuggestion(forcedSuggestion())] });
    const gate = box();
    expect(gate).toHaveTextContent(S.ai1.reasons);
    expect(gate).toHaveTextContent("Nguồn thuộc dải máy giám sát");
    expect(gate).toHaveTextContent(S.ai1.source);
    expect(within(gate).getAllByRole("listitem").length).toBeGreaterThanOrEqual(2);
  });

  it("is still the column of ① above it: the decision and the agreement are kept", async () => {
    await open({ details: [withSuggestion(forcedSuggestion())] });
    expect(within(left()).getByRole("heading", { name: S.alert.aiHeading })).toBeInTheDocument();
    expect(within(left()).getByText(S.ai1.decidedHeading)).toBeInTheDocument();
  });

  it("renders hostile text in a claim, a quote, a source and a warning as literal characters", async () => {
    const { view } = await open({ details: [withSuggestion(forcedSuggestion())] });
    const gate = box();
    expect(gate).toHaveTextContent("<script>alert(1)</script> máy này quét cổng đều đặn");
    expect(gate).toHaveTextContent("[bấm vào đây](javascript:alert(1))");
    expect(gate).toHaveTextContent("<img src=x onerror=alert(2)>");
    expect(gate).toHaveTextContent("<script>alert('gate')</script>");
    expect(view.container.querySelector("script")).toBeNull();
    expect(view.container.querySelector("img")).toBeNull();
    expect(view.container.querySelector("[onerror]")).toBeNull();
    expect(view.container.querySelector('a[href^="javascript"]')).toBeNull();
    expect(gate.querySelector("a")).toBeNull();
  });

  it("says a gate that did not force the verdict as such", async () => {
    const calm = forcedSuggestion({
      gate: {
        forced: false,
        forced_by: [],
        proposed_verdict: "false_positive",
        final_verdict: "false_positive",
      },
      reasons: [],
    });
    await open({ details: [withSuggestion(calm)] });
    expect(box()).toHaveTextContent(S.ai1.gateNotForced);
    expect(box()).not.toHaveTextContent(S.ai1.gateForcedBy);
    expect(box()).not.toHaveTextContent(S.ai1.reasons);
  });

  it("says in a sentence that ① left neither a gate nor reasons", async () => {
    await open();
    expect(box()).toHaveTextContent(D.left.suggestion.none);
  });

  it("shows no section for an alert that carries no suggestion", async () => {
    await open({ details: [withSuggestion(null)] });
    expect(
      within(left()).queryByRole("region", { name: D.left.suggestion.heading }),
    ).not.toBeInTheDocument();
  });

  it("has no button and no field in it", async () => {
    await open({ details: [withSuggestion(forcedSuggestion())] });
    expect(within(box()).queryByRole("button")).not.toBeInTheDocument();
    expect(within(box()).queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("has no axe violation", async () => {
    const { view } = await open({ details: [withSuggestion(forcedSuggestion())] });
    const result = await axe.run(view.container, {
      rules: { "color-contrast": { enabled: false } },
    });
    expect(result.violations.map((v) => v.id)).toEqual([]);
  });
});

describe("the tag picker marks 'ngoài danh sách' only once it knows the vocabulary (M1)", () => {
  const drafted = () =>
    draftDetail(1, { draft: { draft: { ...GOOD_FIELDS, tags: ["port_scan", "old_tag"] } } });

  it("marks no tag while the vocabulary is loading, and marks the stranger once it is there", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    knowledgeBackend(server, {
      details: [drafted()],
      tagsAnswer: async () => {
        await gate;
        return HttpResponse.json(TAGS);
      },
    });
    renderView();
    const tags = await within(await loaded()).findByRole("group", { name: D.right.field.tags });
    // loading: the draft's own tags are there, ticked, and none is called a stranger
    expect(within(tags).getByRole("checkbox", { name: "port_scan" })).toBeChecked();
    expect(within(tags).getByRole("checkbox", { name: "old_tag" })).toBeChecked();
    expect(tags).not.toHaveTextContent(D.right.tags.outside);
    release();
    await waitFor(() => expect(tags).toHaveTextContent(D.right.tags.outside));
    expect(within(tags).getByRole("checkbox", { name: "port_scan" })).toBeChecked();
    expect(within(tags).getByRole("checkbox", { name: /old_tag/ })).toBeChecked();
    expect(within(tags).getByText(D.right.tags.outside, { exact: false })).toBeInTheDocument();
    // only the one that is outside is marked
    expect(within(tags).getByRole("checkbox", { name: "port_scan" })).toBeInTheDocument();
  });

  it("marks no tag when the vocabulary could not be read", async () => {
    knowledgeBackend(server, {
      details: [drafted()],
      tagsAnswer: () => HttpResponse.json({}, { status: 500 }),
    });
    renderView();
    const tags = await within(await loaded()).findByRole("group", { name: D.right.field.tags });
    expect(await within(tags).findByText(D.right.tags.loadFailed)).toBeInTheDocument();
    expect(within(tags).getByRole("checkbox", { name: "old_tag" })).toBeChecked();
    expect(within(tags).getByRole("checkbox", { name: "port_scan" })).toBeChecked();
    expect(tags).not.toHaveTextContent(D.right.tags.outside);
  });
});

describe("a 409 that leaves the draft pending says it can only be rejected now (M2)", () => {
  async function approveFailing(reason: string) {
    const fake = knowledgeBackend(server, {
      details: [draftDetail()],
      approve: () => detail({ reason }, 409),
    });
    const user = userEvent.setup();
    const view = renderView();
    await loaded();
    await user.click(approveButton());
    await user.click(
      within(dialog(D.action.approveTitle)).getByRole("button", { name: D.action.approve }),
    );
    await waitFor(() => expect(fake.approves).toHaveLength(1));
    return { fake, user, view };
  }

  it.each(["source_changed", "unpublishable"])(
    "keeps 'bản nháp đã được xử lý' and adds that only a rejection is left, after %s",
    async (reason) => {
      await approveFailing(reason);
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent("bản nháp đã được xử lý");
      expect(alert).toHaveTextContent("chỉ có thể từ chối");
      expect(alert).toHaveTextContent(K.notice.rejectOnly);
    },
  );

  it("leaves Duyệt and Sửa rồi duyệt off, whatever is typed, and Từ chối on and working", async () => {
    const { fake, user, view } = await approveFailing("source_changed");
    await screen.findByRole("alert");
    expect(approveButton()).toBeDisabled();
    expect(editApproveButton()).toBeDisabled();
    await user.type(box(D.right.field.title), "x");
    expect(editApproveButton()).toBeDisabled();
    expect(rejectButton()).toBeEnabled();
    await user.click(rejectButton());
    await user.type(
      within(dialog(D.action.rejectTitle)).getByLabelText(D.action.reasonLabel),
      "nguồn đã đổi",
    );
    await user.click(
      within(dialog(D.action.rejectTitle)).getByRole("button", { name: D.action.reject }),
    );
    await waitFor(() => expect(view.onDone).toHaveBeenCalledTimes(1));
    expect(fake.rejects).toHaveLength(1);
  });

  it("does not say it for a draft that was handled (not_pending)", async () => {
    await approveFailing("not_pending");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("bản nháp đã được xử lý");
    expect(alert).not.toHaveTextContent("chỉ có thể từ chối");
  });
});

describe("a 404 leaves no action on stale data (M3)", () => {
  async function failWith404(which: "approve" | "reject") {
    const answer = () => detail({ reason: "not_found" }, 404);
    const fake = knowledgeBackend(server, {
      details: [draftDetail()],
      ...(which === "approve" ? { approve: answer } : { reject: answer }),
    });
    const user = userEvent.setup();
    const view = renderView();
    await loaded();
    if (which === "approve") {
      await user.click(approveButton());
      await user.click(
        within(dialog(D.action.approveTitle)).getByRole("button", { name: D.action.approve }),
      );
    } else {
      await user.click(rejectButton());
      await user.type(
        within(dialog(D.action.rejectTitle)).getByLabelText(D.action.reasonLabel),
        "lý do",
      );
      await user.click(
        within(dialog(D.action.rejectTitle)).getByRole("button", { name: D.action.reject }),
      );
    }
    await waitFor(() => expect(fake.approves.length + fake.rejects.length).toBe(1));
    return { fake, user, view };
  }

  it.each(["approve", "reject"] as const)(
    "after a 404 on %s: says it is gone, hides all three actions and makes the form read-only",
    async (which) => {
      await failWith404(which);
      expect(await screen.findByRole("alert")).toHaveTextContent(K.notice.gone);
      expect(
        within(right()).queryByRole("button", { name: D.action.approve }),
      ).not.toBeInTheDocument();
      expect(
        within(right()).queryByRole("button", { name: D.action.editApprove }),
      ).not.toBeInTheDocument();
      expect(
        within(right()).queryByRole("button", { name: D.action.reject }),
      ).not.toBeInTheDocument();
      expect(box(D.right.field.title).readOnly).toBe(true);
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    },
  );

  it("still offers the way back", async () => {
    const { user, view } = await failWith404("approve");
    await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: K.back }));
    expect(view.onBack).toHaveBeenCalled();
  });
});

describe("focus (M4)", () => {
  it("moves to the title of the draft when it opens", async () => {
    await open();
    expect(screen.getByRole("heading", { name: GOOD_FIELDS.title })).toHaveFocus();
    expect(screen.getByRole("heading", { name: GOOD_FIELDS.title })).toHaveAttribute(
      "tabindex",
      "-1",
    );
  });
});

describe("edits that were not sent are not lost by accident (M5)", () => {
  const leaveDialog = () => screen.getByRole("dialog", { name: D.leave.title });

  it("asks before '← Danh sách' when the form is edited, and a confirm dialog is not window.confirm", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    try {
      const { user, view } = await open();
      await user.type(box(D.right.field.title), " bổ sung");
      await user.click(screen.getByRole("button", { name: K.back }));
      expect(leaveDialog()).toHaveTextContent(D.leave.body);
      expect(view.onBack).not.toHaveBeenCalled();
      // staying keeps the view and what was typed
      await user.click(within(leaveDialog()).getByRole("button", { name: D.leave.stay }));
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
      expect(view.onBack).not.toHaveBeenCalled();
      expect(box(D.right.field.title).value).toBe(`${GOOD_FIELDS.title} bổ sung`);
      // leaving goes back
      await user.click(screen.getByRole("button", { name: K.back }));
      await user.click(within(leaveDialog()).getByRole("button", { name: D.leave.confirm }));
      expect(view.onBack).toHaveBeenCalledTimes(1);
      expect(confirm).not.toHaveBeenCalled();
    } finally {
      confirm.mockRestore();
    }
  });

  it("does not ask when nothing was edited", async () => {
    const { user, view } = await open();
    await user.click(screen.getByRole("button", { name: K.back }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(view.onBack).toHaveBeenCalledTimes(1);
  });

  it("does not ask for a form that was edited and put back as it was", async () => {
    const { user, view } = await open();
    await user.type(box(D.right.field.title), "x");
    await user.type(box(D.right.field.title), "{Backspace}");
    await user.click(screen.getByRole("button", { name: K.back }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(view.onBack).toHaveBeenCalledTimes(1);
  });

  it("guards a reload or a closed tab while the form is edited, and only then", async () => {
    const attempt = () => {
      const event = new Event("beforeunload", { cancelable: true });
      window.dispatchEvent(event);
      return event.defaultPrevented;
    };
    const { user, view } = await open();
    expect(attempt()).toBe(false);
    await user.type(box(D.right.field.title), " bổ sung");
    expect(attempt()).toBe(true);
    await replace(user, box(D.right.field.title), GOOD_FIELDS.title);
    expect(attempt()).toBe(false);
    await user.type(box(D.right.field.title), "!");
    expect(attempt()).toBe(true);
    view.unmount();
    expect(attempt()).toBe(false);
  });

  it("does not ask once the write went through", async () => {
    const { user, view, fake } = await open();
    await user.type(box(D.right.field.title), " bổ sung");
    await user.click(editApproveButton());
    await user.click(
      within(dialog(D.action.editApproveTitle)).getByRole("button", { name: D.action.editApprove }),
    );
    await waitFor(() => expect(view.onDone).toHaveBeenCalledTimes(1));
    expect(fake.approves).toHaveLength(1);
    expect(screen.queryByRole("dialog", { name: D.leave.title })).not.toBeInTheDocument();
  });
});

describe("the reason counts characters, as the backend does (nit)", () => {
  it("counts 500 emoji as 500, and 501 as too long", async () => {
    const { user } = await open();
    await user.click(rejectButton());
    const reasonBox = () =>
      within(dialog(D.action.rejectTitle)).getByLabelText(D.action.reasonLabel);
    const confirm = () =>
      within(dialog(D.action.rejectTitle)).getByRole("button", { name: D.action.reject });
    fireEvent.change(reasonBox(), { target: { value: "😀".repeat(500) } });
    expect(dialog(D.action.rejectTitle)).toHaveTextContent(D.action.reasonCount(500, 500));
    expect(confirm()).toBeEnabled();
    fireEvent.change(reasonBox(), { target: { value: "😀".repeat(501) } });
    expect(dialog(D.action.rejectTitle)).toHaveTextContent(D.action.reasonCount(501, 500));
    expect(confirm()).toBeDisabled();
  });
});
