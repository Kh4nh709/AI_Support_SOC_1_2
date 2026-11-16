// src/features/soar/SoarPage.decision.test.tsx — pressing a button: keep at once; undo and false positive through a dialog
// with a note (and a stronger warning for an isolated or domain-controller host); "Đang xử lý…" while the request runs (up
// to 45 s); then each outcome, the local 409, the 403, the 503 and a network failure, on the row.
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterEach, vi } from "vitest";
import type { SoarDecisionAnswer, SoarReview } from "../../api/soar";
import { S } from "../../strings";
import { listOf, review } from "./fixtures";
import { NOTE_MAX } from "./model";
import { SOAR_LIST_POLL_MS } from "./soarQueries";
import { fake, renderSoar, serve, type Fake } from "./testkit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
});
afterAll(() => server.close());

const rowOf = async (id = "K7QM2XHP") => {
  const button = await screen.findByRole("button", { name: S.soar.detail.open(id) });
  const row = button.closest("tr");
  if (row === null) throw new Error("no row");
  return row;
};
const press = async (label: string, id?: string) => {
  const row = await rowOf(id);
  await userEvent.click(within(row).getByRole("button", { name: label }));
};
const KEEP = "✅ Giữ chặn";
const UNDO = "↩️ Gỡ chặn IP";

/** What the server serves for a decided ticket, and what the answer carries. */
const decided = (over: Partial<SoarReview> = {}) =>
  review({
    status: "kept",
    decided_by: "an",
    decided_at: "2026-11-13T14:41:10+00:00",
    updated_at: "2026-11-13T14:41:10+00:00",
    allowed_decisions: ["undo"],
    ...over,
  });
const answer = (over: Partial<SoarDecisionAnswer> = {}): SoarDecisionAnswer => ({
  outcome: "ok",
  message: null,
  review: decided(),
  ...over,
});

/** A server whose answer to a decision is `make(state)`, and which holds the row as the answer left it. */
function serveDecision(make: (state: Fake) => SoarDecisionAnswer | Response, rows = [review()]) {
  const state = fake({ rows });
  state.decision = () => {
    const out = make(state);
    if (!(out instanceof Response))
      state.rows = state.rows.map((r) => (r.id === out.review.id ? out.review : r));
    return out;
  };
  serve(server, state);
  return state;
}

describe("keep", () => {
  it("sends at once, with no dialog and no note", async () => {
    const state = serveDecision(() => answer());
    renderSoar();
    await press(KEEP);
    await waitFor(() =>
      expect(state.decisions).toEqual([{ id: "K7QM2XHP", body: { decision: "keep" } }]),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("the dialog of undo and false positive", () => {
  it("opens for undo, named by its title, with the ticket, what follows, and an optional note counted to 500", async () => {
    const state = serveDecision(() => answer());
    renderSoar();
    await press(UNDO);
    const dialog = await screen.findByRole("dialog", { name: S.soar.dialog.title.undo });
    expect(S.soar.dialog.title.undo).toBe("Gỡ biện pháp đã áp dụng?");
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(
      within(dialog).getByText("Phiếu K7QM2XHP: Chặn IP 79.79.78.202 trên pfSense"),
    ).toBeInTheDocument();
    expect(within(dialog).getByText(S.soar.dialog.after.undo)).toBeInTheDocument();
    const note = within(dialog).getByRole("textbox", { name: S.soar.dialog.note });
    expect(note).toHaveFocus();
    expect(note).toHaveAttribute("maxlength", String(NOTE_MAX));
    expect(within(dialog).getByText("0/500")).toBeInTheDocument();
    await userEvent.type(note, "máy sạch");
    expect(within(dialog).getByText("8/500")).toBeInTheDocument();
    expect(state.decisions).toEqual([]);
    expect(within(dialog).queryByRole("checkbox")).not.toBeInTheDocument();
  });

  it("sends undo with the note when confirmed, and closes", async () => {
    const state = serveDecision(() =>
      answer({ review: decided({ status: "undone", allowed_decisions: [] }) }),
    );
    renderSoar();
    await press(UNDO);
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByRole("textbox"), "  máy sạch  ");
    await userEvent.click(within(dialog).getByRole("button", { name: S.soar.dialog.confirm.undo }));
    await waitFor(() =>
      expect(state.decisions).toEqual([
        { id: "K7QM2XHP", body: { decision: "undo", note: "máy sạch" } },
      ]),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("sends no note at all when the box is empty or only spaces", async () => {
    const state = serveDecision(() => answer());
    renderSoar();
    await press(UNDO);
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByRole("textbox"), "   ");
    await userEvent.click(within(dialog).getByRole("button", { name: S.soar.dialog.confirm.undo }));
    await waitFor(() =>
      expect(state.decisions).toEqual([{ id: "K7QM2XHP", body: { decision: "undo" } }]),
    );
  });

  it("opens for a false positive, with its own title and confirm button, and sends fp", async () => {
    const row = review({
      action_type: "kill_process",
      buttons: [
        { decision: "keep", label: "✅ Giữ dừng" },
        { decision: "fp", label: "🚫 Dương tính giả" },
      ],
      allowed_decisions: ["keep", "fp"],
    });
    const state = serveDecision(
      () =>
        answer({ review: decided({ ...row, status: "false_positive", allowed_decisions: [] }) }),
      [row],
    );
    renderSoar();
    await press("🚫 Dương tính giả");
    const dialog = await screen.findByRole("dialog", { name: S.soar.dialog.title.fp });
    expect(within(dialog).getByText(S.soar.dialog.after.fp)).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: S.soar.dialog.confirm.fp }));
    await waitFor(() =>
      expect(state.decisions).toEqual([{ id: "K7QM2XHP", body: { decision: "fp" } }]),
    );
  });

  it("cancels with the button: nothing is sent, the buttons are as they were and the focus returns", async () => {
    const state = serveDecision(() => answer());
    renderSoar();
    await press(UNDO);
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Huỷ" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(state.decisions).toEqual([]);
    const row = await rowOf();
    expect(within(row).getByRole("button", { name: UNDO })).toBeEnabled();
    expect(within(row).getByRole("button", { name: UNDO })).toHaveFocus();
  });

  it("cancels with Escape", async () => {
    const state = serveDecision(() => answer());
    renderSoar();
    await press(UNDO);
    await screen.findByRole("dialog");
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(state.decisions).toEqual([]);
  });

  it("holds Tab inside the dialog", async () => {
    serveDecision(() => answer());
    renderSoar();
    await press(UNDO);
    const dialog = await screen.findByRole("dialog");
    for (let i = 0; i < 6; i++) {
      await userEvent.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
  });

  it("stops the note at 500 characters and says so in its count", async () => {
    serveDecision(() => answer());
    renderSoar();
    await press(UNDO);
    const dialog = await screen.findByRole("dialog");
    const note = within(dialog).getByRole("textbox") as HTMLTextAreaElement;
    await userEvent.click(note);
    await userEvent.paste("x".repeat(600));
    expect(note.value).toHaveLength(500);
    expect(within(dialog).getByText("500/500")).toBeInTheDocument();
  });

  it("is not closed, nor its note wiped, by the list asking again", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const state = serveDecision(() => answer());
    renderSoar();
    await press(UNDO);
    const dialog = await screen.findByRole("dialog");
    await userEvent.type(within(dialog).getByRole("textbox"), "đang gõ dở", { delay: null });
    const before = state.lists.length;
    state.rows = [review({ updated_at: "2026-11-13T14:41:00+00:00", note: "đã đổi" })];
    await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
    await waitFor(() => expect(state.lists.length).toBeGreaterThan(before));
    expect(screen.getByRole("dialog")).toBe(dialog);
    expect(within(dialog).getByRole("textbox")).toHaveValue("đang gõ dở");
  });

  it("is not closed by the ticket leaving the list under it, and still names the ticket", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const state = serveDecision(() => answer());
    renderSoar();
    await press(UNDO);
    await screen.findByRole("dialog");
    state.rows = [];
    await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
    await screen.findByText(S.soar.empty.open);
    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByText("Phiếu K7QM2XHP: Chặn IP 79.79.78.202 trên pfSense"),
    ).toBeInTheDocument();
  });
});

describe("the strong warning", () => {
  const isolated = () =>
    review({
      action_type: "isolate_host",
      action_text: "Cách ly AD-server khỏi mạng",
      host: "AD-server",
      buttons: [
        { decision: "keep", label: "✅ Giữ cách ly" },
        { decision: "undo", label: "↩️ Gỡ cách ly" },
      ],
      allowed_decisions: ["keep", "undo"],
      strong_warning: true,
    });

  it("is in the dialog of undo when strong_warning is true: stronger title, the warning, what follows", async () => {
    serveDecision(() => answer(), [isolated()]);
    renderSoar();
    await press("↩️ Gỡ cách ly");
    const dialog = await screen.findByRole("dialog", { name: S.soar.dialog.title.undoStrong });
    expect(S.soar.dialog.title.undoStrong).not.toBe(S.soar.dialog.title.undo);
    const warning = within(dialog).getByText(
      "Gỡ cách ly AD-server sẽ nối lại máy với mạng ngay. Đây là máy đang bị cách ly hoặc máy mà SOAR đánh dấu quan trọng (ví dụ máy chủ AD). Nếu máy vẫn bị xâm nhập, kẻ tấn công có thể tiếp tục hoạt động và lây lan.",
    );
    expect(warning.textContent).toMatch(/^Gỡ cách ly AD-server/);
    expect(within(dialog).getByText(S.soar.dialog.after.undo)).toBeInTheDocument();
  });

  it("asks for a deliberate confirm: the button waits for the box to be ticked, and the focus is not on it", async () => {
    const state = serveDecision(() => answer(), [isolated()]);
    renderSoar();
    await press("↩️ Gỡ cách ly");
    const dialog = await screen.findByRole("dialog");
    const confirm = within(dialog).getByRole("button", { name: S.soar.dialog.confirm.undo });
    expect(confirm).toBeDisabled();
    expect(confirm).not.toHaveFocus();
    await userEvent.click(confirm);
    expect(state.decisions).toEqual([]);
    await userEvent.click(within(dialog).getByRole("checkbox", { name: S.soar.dialog.understand }));
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);
    await waitFor(() =>
      expect(state.decisions).toEqual([{ id: "K7QM2XHP", body: { decision: "undo" } }]),
    );
  });

  it("is in the dialog of a false positive on a domain controller too, worded for that decision", async () => {
    const row = review({
      host: "AD-server",
      action_type: "kill_process",
      buttons: [{ decision: "fp", label: "🚫 Dương tính giả" }],
      allowed_decisions: ["fp"],
      strong_warning: true,
    });
    serveDecision(() => answer(), [row]);
    renderSoar();
    await press("🚫 Dương tính giả");
    const dialog = await screen.findByRole("dialog", { name: S.soar.dialog.title.fpStrong });
    expect(
      within(dialog).getByText(
        "Tiến trình đã bị dừng trên AD-server, một máy mà SOAR đánh dấu quan trọng. Nếu đây là tấn công thật, đánh dấu dương tính giả sẽ đóng phiếu và không còn nhắc nữa.",
      ),
    ).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: S.soar.dialog.confirm.fp })).toBeDisabled();
  });

  it("is not there for an ordinary ticket", async () => {
    serveDecision(() => answer());
    renderSoar();
    await press(UNDO);
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByText(/^Gỡ cách ly máy chủ AD/)).not.toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: S.soar.dialog.confirm.undo })).toBeEnabled();
  });

  it("words the warning by the action being undone: unblocking an IP on the domain controller is not described as an isolation", async () => {
    const row = review({
      host: "AD-server",
      action_type: "block_ip",
      action_target: "79.79.78.202",
      strong_warning: true,
    });
    serveDecision(() => answer(), [row]);
    renderSoar();
    await press(UNDO);
    const dialog = await screen.findByRole("dialog", { name: S.soar.dialog.title.undoStrong });
    expect(
      within(dialog).getByText(
        "Gỡ chặn 79.79.78.202: lưu lượng từ địa chỉ này được phép đi qua trở lại. AD-server là máy mà SOAR đánh dấu quan trọng; hãy chắc chắn địa chỉ này không còn nguy hiểm.",
      ),
    ).toBeInTheDocument();
    expect(dialog).not.toHaveTextContent("Gỡ cách ly");
    expect(dialog).not.toHaveTextContent("nối lại máy với mạng");
  });
});

describe("while the request runs", () => {
  it("says Đang xử lý… on the row and disables its buttons, and does not send twice", async () => {
    let release: () => void = () => {};
    const wait = new Promise<void>((resolve) => (release = resolve));
    const state = fake({ rows: [review()] });
    state.decision = async () => {
      await wait;
      return answer();
    };
    serve(server, state);
    renderSoar();
    const row = await rowOf();
    const keep = within(row).getByRole("button", { name: KEEP });
    await userEvent.dblClick(keep);
    expect(await within(row).findByText(S.soar.working)).toBeInTheDocument();
    expect(S.soar.working).toBe("Đang xử lý…");
    expect(within(row).getByRole("button", { name: KEEP })).toBeDisabled();
    expect(within(row).getByRole("button", { name: UNDO })).toBeDisabled();
    expect(state.decisions).toHaveLength(1);
    await act(async () => release());
    await waitFor(() => expect(within(row).queryByText(S.soar.working)).not.toBeInTheDocument());
  });

  it("is not overwritten by a poll that was already on its way when the answer came", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let releaseDecision: () => void = () => {};
    const decisionGate = new Promise<void>((resolve) => (releaseDecision = resolve));
    let releaseList: () => void = () => {};
    const listGate = new Promise<void>((resolve) => (releaseList = resolve));
    let hold = false;
    const state = fake({ rows: [review()] });
    state.decision = async () => {
      await decisionGate;
      state.rows = [decided()];
      return answer();
    };
    // the poll that is on its way saw the ticket as held, and says so after the answer has landed
    state.list = async (url) => {
      if (!hold || !url.searchParams.has("status")) return undefined;
      await listGate;
      return listOf([
        review({
          status: "processing",
          locked_by: "an",
          allowed_decisions: [],
          updated_at: "2026-11-13T14:41:07+00:00",
        }),
      ]);
    };
    serve(server, state);
    renderSoar();
    await press(KEEP);
    hold = true;
    await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
    await act(async () => releaseDecision());
    const row = await rowOf();
    await waitFor(() => expect(within(row).getAllByRole("cell")[8]).toHaveTextContent("Đã giữ"));
    await act(async () => releaseList());
    await act(() => vi.advanceTimersByTimeAsync(200));
    expect(within(await rowOf()).getAllByRole("cell")[8]).toHaveTextContent("Đã giữ");
    expect(within(await rowOf()).queryByText("Đang xử lý (an)")).not.toBeInTheDocument();
  });

  it("shows a row that is processing for ME as Đang xử lý… with no buttons, as after leaving the page during a request", async () => {
    serve(
      server,
      fake({
        rows: [
          review({ id: "MINE0001", status: "processing", locked_by: "an", allowed_decisions: [] }),
          review({
            id: "THEIRS01",
            status: "processing",
            locked_by: "binh",
            allowed_decisions: [],
          }),
        ],
      }),
    );
    renderSoar({ username: "an" });
    const mine = await rowOf("MINE0001");
    expect(within(mine).getByText(S.soar.working)).toBeInTheDocument();
    expect(within(mine).getAllByRole("cell")[8]).toHaveTextContent("Đang xử lý (an)");
    expect(within(mine).queryByRole("button", { name: KEEP })).not.toBeInTheDocument();
    // somebody else's row only says who holds it
    const theirs = await rowOf("THEIRS01");
    expect(within(theirs).queryByText(S.soar.working)).not.toBeInTheDocument();
    expect(within(theirs).getAllByRole("cell")[8]).toHaveTextContent("Đang xử lý (binh)");
  });

  it("does not take a row held by someone else for mine, nor a row of mine that is not processing", async () => {
    serve(
      server,
      fake({
        rows: [review({ locked_by: "an", status: "open" })],
      }),
    );
    renderSoar({ username: "an" });
    expect(within(await rowOf()).queryByText(S.soar.working)).not.toBeInTheDocument();
  });

  it("moves the focus to the row's group when a decision starts, so it never falls to the page: after the dialog is confirmed", async () => {
    let release: () => void = () => {};
    const wait = new Promise<void>((resolve) => (release = resolve));
    const state = fake({ rows: [review()] });
    state.decision = async () => {
      await wait;
      return answer();
    };
    serve(server, state);
    renderSoar();
    await press(UNDO);
    const dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: S.soar.dialog.confirm.undo }));
    const group = await screen.findByRole("group", { name: S.soar.buttonsLabel("K7QM2XHP") });
    await waitFor(() => expect(group).toHaveFocus());
    expect(document.body).not.toHaveFocus();
    await act(async () => release());
    // it stays there when the result comes, and is not taken away
    await waitFor(() => expect(screen.queryByText(S.soar.working)).not.toBeInTheDocument());
    expect(group).toHaveFocus();
  });

  it("moves the focus to the row's group when keep is pressed (its button is disabled the moment the request starts)", async () => {
    let release: () => void = () => {};
    const wait = new Promise<void>((resolve) => (release = resolve));
    const state = fake({ rows: [review()] });
    state.decision = async () => {
      await wait;
      return answer();
    };
    serve(server, state);
    renderSoar();
    await press(KEEP);
    const group = await screen.findByRole("group", { name: S.soar.buttonsLabel("K7QM2XHP") });
    await waitFor(() => expect(group).toHaveFocus());
    expect(group).toHaveAttribute("tabindex", "-1");
    await act(async () => release());
  });

  it("does not take the focus for a request that fails to start with the focus elsewhere, nor on a list refetch", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const state = fake({ rows: [review(), review({ id: "B2C3D4E5" })] });
    serve(server, state);
    renderSoar();
    const other = within(await rowOf("B2C3D4E5")).getByRole("button", { name: KEEP });
    other.focus();
    await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
    expect(other).toHaveFocus();
  });

  it("leaves another row's buttons alone", async () => {
    let release: () => void = () => {};
    const wait = new Promise<void>((resolve) => (release = resolve));
    const state = fake({ rows: [review(), review({ id: "B2C3D4E5" })] });
    state.decision = async () => {
      await wait;
      return answer();
    };
    serve(server, state);
    renderSoar();
    await press(KEEP);
    const other = await rowOf("B2C3D4E5");
    expect(within(other).getByRole("button", { name: KEEP })).toBeEnabled();
    expect(within(other).queryByText(S.soar.working)).not.toBeInTheDocument();
    await act(async () => release());
  });

  it("keeps saying it through a refetch that serves the row as held (processing)", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let release: () => void = () => {};
    const wait = new Promise<void>((resolve) => (release = resolve));
    const state = fake({ rows: [review()] });
    state.decision = async () => {
      await wait;
      return answer();
    };
    serve(server, state);
    renderSoar({ username: "an" });
    await press(KEEP);
    state.rows = [review({ status: "processing", locked_by: "an", allowed_decisions: [] })];
    await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
    const row = await rowOf();
    await waitFor(() => expect(within(row).getByText("Đang xử lý (an)")).toBeInTheDocument());
    expect(within(row).getByText(S.soar.working)).toBeInTheDocument();
    await act(async () => release());
  });
});

describe("the outcomes", () => {
  it("ok: shows the new status on the row, a line that says so, and a note that stays when the row leaves the tab", async () => {
    serveDecision(() => answer({ message: "Đã giữ chặn 79.79.78.202" }));
    renderSoar();
    await press(KEEP);
    const row = await rowOf();
    await waitFor(() => expect(within(row).getAllByRole("cell")[8]).toHaveTextContent("Đã giữ"));
    expect(within(row).getByText("Đã cập nhật: Đã giữ")).toBeInTheDocument();
    expect(within(row).getByText("Đã giữ chặn 79.79.78.202")).toBeInTheDocument();
    expect(screen.getAllByText("Phiếu K7QM2XHP: Đã giữ").length).toBeGreaterThan(0);
    // the buttons are the new state's: undo is still there, keep is not
    expect(within(row).queryByRole("button", { name: KEEP })).not.toBeInTheDocument();
    expect(within(row).getByRole("button", { name: UNDO })).toBeEnabled();
  });

  it("failed: shows the server's message in an error line on the row, and the buttons again", async () => {
    serveDecision(() =>
      answer({
        outcome: "failed",
        message: "GỠ THẤT BẠI: pfSense không phản hồi",
        review: review({
          last_error: "GỠ THẤT BẠI: pfSense không phản hồi",
          updated_at: "2026-11-13T14:41:10+00:00",
        }),
      }),
    );
    renderSoar();
    await press(KEEP);
    const row = await rowOf();
    const line = await within(row).findByText("GỠ THẤT BẠI: pfSense không phản hồi");
    expect(line).toHaveAttribute("role", "alert");
    expect(within(row).getByRole("button", { name: KEEP })).toBeEnabled();
    expect(within(row).getByRole("button", { name: UNDO })).toBeEnabled();
    expect(within(row).getAllByRole("cell")[8]).toHaveTextContent("Đang mở");
    // the stored last_error says the same thing, and is said once
    expect(within(row).getAllByText(/GỠ THẤT BẠI/)).toHaveLength(1);
  });

  it("unavailable: shows the message, or a fixed sentence when there is none, and the buttons again", async () => {
    serveDecision(() =>
      answer({
        outcome: "unavailable",
        message: null,
        review: review({ updated_at: "2026-11-13T14:41:10+00:00" }),
      }),
    );
    renderSoar();
    await press(KEEP);
    const row = await rowOf();
    expect(await within(row).findByText(S.soar.result.unavailableNoMessage)).toHaveAttribute(
      "role",
      "alert",
    );
    expect(within(row).getByRole("button", { name: KEEP })).toBeEnabled();
  });

  it("failed with no message still says it failed", async () => {
    serveDecision(() =>
      answer({
        outcome: "failed",
        message: null,
        review: review({ updated_at: "2026-11-13T14:41:10+00:00" }),
      }),
    );
    renderSoar();
    await press(KEEP);
    expect(await screen.findByText(S.soar.result.failedNoMessage)).toBeInTheDocument();
  });

  it("keeps the error line through a refetch that leaves the row as it was, and drops it when the row has changed", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const state = serveDecision(() =>
      answer({
        outcome: "failed",
        message: "GỠ THẤT BẠI: hết giờ",
        review: review({ last_error: null, updated_at: "2026-11-13T14:41:10+00:00" }),
      }),
    );
    renderSoar();
    await press(KEEP);
    await screen.findByText("GỠ THẤT BẠI: hết giờ");
    await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
    expect(screen.getByText("GỠ THẤT BẠI: hết giờ")).toBeInTheDocument();
    // n8n changed the ticket in the meantime: the line is about the old row, so it goes
    state.rows = [review({ updated_at: "2026-11-13T14:42:00+00:00", note: "n8n đã sửa" })];
    await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
    await waitFor(() => expect(screen.queryByText("GỠ THẤT BẠI: hết giờ")).not.toBeInTheDocument());
  });

  it.each([
    ["a new status", { status: "undone", allowed_decisions: [] } as Partial<SoarReview>],
    ["a new decided_at", { decided_at: "2026-11-13T14:50:00+00:00", decided_by: "binh" }],
  ])(
    "drops my error line when a poll brings %s, even when updated_at has not moved: a later decision of someone else never sits beside my failure",
    async (_name, changed) => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const state = serveDecision(() =>
        answer({
          outcome: "failed",
          message: "GỠ THẤT BẠI: hết giờ",
          review: review({ last_error: null, updated_at: "2026-11-13T14:41:10+00:00" }),
        }),
      );
      renderSoar();
      await press(KEEP);
      await screen.findByText("GỠ THẤT BẠI: hết giờ");
      // the poll that brings what somebody else decided: the same updated_at, another status or another decision time
      state.rows = [
        review({ updated_at: "2026-11-13T14:41:10+00:00", last_error: null, ...changed }),
      ];
      await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
      await waitFor(() =>
        expect(screen.queryByText("GỠ THẤT BẠI: hết giờ")).not.toBeInTheDocument(),
      );
    },
  );

  it("conflict: shows the status n8n gave and says it was handled elsewhere", async () => {
    serveDecision(() =>
      answer({
        outcome: "conflict",
        message: "Đã xử lý trên Telegram",
        review: review({
          status: "undone",
          allowed_decisions: [],
          updated_at: "2026-11-13T14:41:10+00:00",
        }),
      }),
    );
    renderSoar();
    await press(KEEP);
    const row = await rowOf();
    await waitFor(() => expect(within(row).getAllByRole("cell")[8]).toHaveTextContent("Đã gỡ"));
    expect(within(row).getByText("Phiếu đã được xử lý ở nơi khác: Đã gỡ")).toBeInTheDocument();
    expect(within(row).getByText("Đã xử lý trên Telegram")).toBeInTheDocument();
  });

  it.each([
    ["invalid_state", S.soar.result.invalidState, decided()],
    [
      "locked",
      S.soar.result.locked,
      review({
        status: "processing",
        locked_by: "binh",
        allowed_decisions: [],
        updated_at: "2026-11-13T14:41:10+00:00",
      }),
    ],
  ] as const)(
    "a local 409 (%s): refreshes the row from detail.review and explains in short",
    async (reason, text, current) => {
      serveDecision(
        () =>
          HttpResponse.json(
            { detail: { reason, review: current } },
            { status: 409 },
          ) as unknown as Response,
      );
      renderSoar();
      await press(KEEP);
      const row = await rowOf();
      expect(await within(row).findByText(text)).toBeInTheDocument();
      const status = reason === "locked" ? "Đang xử lý (binh)" : "Đã giữ";
      expect(within(row).getAllByRole("cell")[8]).toHaveTextContent(status);
    },
  );

  it("words a locked row without saying it is someone else's: it may be the person's own request", () => {
    expect(S.soar.result.locked).toBe("Phiếu đang được xử lý; đã làm mới.");
  });

  it("a local 409 with no usable review still explains, and asks the list again", async () => {
    const state = serveDecision(
      () =>
        HttpResponse.json({ detail: { reason: "locked" } }, { status: 409 }) as unknown as Response,
    );
    renderSoar();
    await rowOf();
    const before = state.lists.length;
    await press(KEEP);
    expect(await screen.findByText(S.soar.result.locked)).toBeInTheDocument();
    await waitFor(() => expect(state.lists.length).toBeGreaterThan(before));
  });

  it("403: says there is no right, and the buttons are back", async () => {
    serveDecision(
      () => HttpResponse.json({ detail: "forbidden" }, { status: 403 }) as unknown as Response,
    );
    renderSoar();
    await press(KEEP);
    const row = await rowOf();
    expect(
      await within(row).findByText("Bạn không có quyền thực hiện thao tác này"),
    ).toHaveAttribute("role", "alert");
    expect(within(row).getByRole("button", { name: KEEP })).toBeEnabled();
  });

  it("503: says the approval link is not configured, and the buttons are back", async () => {
    serveDecision(
      () =>
        HttpResponse.json(
          { detail: "soar approval not configured" },
          { status: 503 },
        ) as unknown as Response,
    );
    renderSoar();
    await press(KEEP);
    const row = await rowOf();
    expect(await within(row).findByText(S.soar.result.notConfigured)).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: KEEP })).toBeEnabled();
  });

  it("404: says the ticket was not found", async () => {
    serveDecision(
      () => HttpResponse.json({ detail: "not found" }, { status: 404 }) as unknown as Response,
    );
    renderSoar();
    await press(KEEP);
    expect(await screen.findByText(S.soar.result.notFound)).toBeInTheDocument();
  });

  it("a network failure: says the request did not go, and the buttons are back", async () => {
    serveDecision(() => HttpResponse.error() as unknown as Response);
    renderSoar();
    await press(KEEP);
    const row = await rowOf();
    expect(await within(row).findByText(S.soar.result.network)).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: KEEP })).toBeEnabled();
  });

  it("a 500 or an outcome it does not know: says something went wrong, and nothing crashes", async () => {
    serveDecision(
      () => HttpResponse.json({ detail: "boom" }, { status: 500 }) as unknown as Response,
    );
    const view = renderSoar();
    await press(KEEP);
    expect(await screen.findByText(S.common.unknownError)).toBeInTheDocument();
    view.unmount();
    serveDecision(() =>
      answer({
        outcome: "weird" as never,
        review: review({ updated_at: "2026-11-13T14:41:10+00:00" }),
      }),
    );
    renderSoar();
    await press(KEEP);
    expect(await screen.findByText(S.common.unknownError)).toBeInTheDocument();
  });

  it("shows the stored last_error of a row, the way it came", async () => {
    serve(server, fake({ rows: [review({ last_error: "Hết thời gian chờ n8n" })] }));
    renderSoar();
    const row = await rowOf();
    expect(within(row).getByText("Lỗi gần nhất: Hết thời gian chờ n8n")).toBeInTheDocument();
    expect(S.soar.lastError("x")).toBe("Lỗi gần nhất: x");
  });
});
