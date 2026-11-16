// src/features/soar/SoarPage.liveDialog.test.tsx — the dialog of undo and false positive follows the LIVE row (it was a snapshot):
// when the ticket changes while it is open the dialog says so and asks again; when the decision is no longer allowed it says
// why and offers no confirm; when the row has left the list it says so and offers no confirm either (the simpler of the two
// ways: the person closes it and looks at the ticket again, since the page has no second source of truth for the row).
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setupServer } from "msw/node";
import { afterEach, vi } from "vitest";
import type { SoarReview } from "../../api/soar";
import { S } from "../../strings";
import { review } from "./fixtures";
import { SOAR_LIST_POLL_MS } from "./soarQueries";
import { fake, renderSoar, serve } from "./testkit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
});
afterAll(() => server.close());

const UNDO = "↩️ Gỡ chặn IP";
const rowOf = async (id = "K7QM2XHP") => {
  const button = await screen.findByRole("button", { name: S.soar.detail.open(id) });
  return button.closest("tr") as HTMLElement;
};
const poll = () => act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));

/** Opens the dialog of undo on the fixture's ticket, with the clock under the test's hand. */
async function openUndo(over: Partial<SoarReview> = {}, rows?: SoarReview[]) {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  const state = fake({ rows: rows ?? [review(over)] });
  serve(server, state);
  renderSoar();
  await userEvent.click(within(await rowOf()).getByRole("button", { name: UNDO }));
  const dialog = await screen.findByRole("dialog");
  return { state, dialog };
}
const confirm = (dialog: HTMLElement) =>
  within(dialog).queryByRole("button", { name: S.soar.dialog.confirm.undo });

/** The ticket as someone else has just decided it: kept, by binh, with undo still allowed. */
const keptByBinh = (over: Partial<SoarReview> = {}) =>
  review({
    status: "kept",
    decided_by: "binh",
    decided_at: "2026-11-13T14:41:30+00:00",
    updated_at: "2026-11-13T14:41:30+00:00",
    allowed_decisions: ["undo"],
    ...over,
  });

describe("a dialog whose ticket has not changed", () => {
  it("says nothing of change, and its confirm works at once", async () => {
    const { state, dialog } = await openUndo();
    await poll();
    expect(within(dialog).queryByText(/Phiếu vừa thay đổi/)).not.toBeInTheDocument();
    expect(within(dialog).queryByRole("checkbox")).not.toBeInTheDocument();
    expect(confirm(dialog)).toBeEnabled();
    expect(state.decisions).toEqual([]);
  });
});

describe("a ticket that changes while the dialog is open", () => {
  it("says what it is now and by whom, whole, and asks for a deliberate confirm", async () => {
    const { state, dialog } = await openUndo();
    await userEvent.type(within(dialog).getByRole("textbox"), "ghi chú dở", { delay: null });
    state.rows = [keptByBinh()];
    await poll();
    const notice = await within(dialog).findByText("Phiếu vừa thay đổi: Đã giữ (binh)");
    expect(notice).toHaveAttribute("role", "alert");
    expect(S.soar.dialog.changed("Đã giữ", "binh")).toBe("Phiếu vừa thay đổi: Đã giữ (binh)");
    // the dialog is the same one, and the note being typed is still there
    expect(screen.getByRole("dialog")).toBe(dialog);
    expect(within(dialog).getByRole("textbox")).toHaveValue("ghi chú dở");
    // the confirm is shut until the person says they have seen it
    expect(confirm(dialog)).toBeDisabled();
    await userEvent.click(confirm(dialog) as HTMLElement);
    expect(state.decisions).toEqual([]);
    await userEvent.click(
      within(dialog).getByRole("checkbox", { name: S.soar.dialog.acknowledgeChange }),
    );
    expect(confirm(dialog)).toBeEnabled();
    await userEvent.click(confirm(dialog) as HTMLElement);
    await waitFor(() =>
      expect(state.decisions).toEqual([
        { id: "K7QM2XHP", body: { decision: "undo", note: "ghi chú dở" } },
      ]),
    );
    expect(S.soar.dialog.acknowledgeChange).toBe("Tôi đã xem thay đổi và vẫn muốn tiếp tục");
  });

  it("says the status alone when nobody is named, for a change that moved only updated_at or the allowed decisions", async () => {
    const { state, dialog } = await openUndo();
    state.rows = [review({ updated_at: "2026-11-13T14:50:00+00:00", note: "n8n đã sửa ghi chú" })];
    await poll();
    expect(await within(dialog).findByText("Phiếu vừa thay đổi: Đang mở")).toBeInTheDocument();
    expect(confirm(dialog)).toBeDisabled();
    expect(S.soar.dialog.changed("Đang mở", null)).toBe("Phiếu vừa thay đổi: Đang mở");
  });

  it("hints which box to tick when the shut confirm is waiting for the change to be seen", async () => {
    const { state, dialog } = await openUndo();
    state.rows = [keptByBinh()];
    await poll();
    expect(
      await within(dialog).findByText(
        "Tích ô “Tôi đã xem thay đổi và vẫn muốn tiếp tục” để bật nút xác nhận.",
      ),
    ).toBeInTheDocument();
  });

  it("asks again when it changes a second time after the person has acknowledged the first", async () => {
    const { state, dialog } = await openUndo();
    state.rows = [keptByBinh()];
    await poll();
    await userEvent.click(
      await within(dialog).findByRole("checkbox", { name: S.soar.dialog.acknowledgeChange }),
    );
    expect(confirm(dialog)).toBeEnabled();
    state.rows = [keptByBinh({ updated_at: "2026-11-13T14:42:00+00:00", result: "đã giữ lại" })];
    await poll();
    await waitFor(() => expect(confirm(dialog)).toBeDisabled());
    expect(
      within(dialog).getByRole("checkbox", { name: S.soar.dialog.acknowledgeChange }),
    ).not.toBeChecked();
  });

  it("needs both boxes on a strong warning: the risk first, then the change", async () => {
    const { state, dialog } = await openUndo({ strong_warning: true });
    await userEvent.click(within(dialog).getByRole("checkbox", { name: S.soar.dialog.understand }));
    expect(confirm(dialog)).toBeEnabled();
    state.rows = [keptByBinh({ strong_warning: true })];
    await poll();
    await waitFor(() => expect(confirm(dialog)).toBeDisabled());
    await userEvent.click(
      within(dialog).getByRole("checkbox", { name: S.soar.dialog.acknowledgeChange }),
    );
    expect(confirm(dialog)).toBeEnabled();
    await userEvent.click(within(dialog).getByRole("checkbox", { name: S.soar.dialog.understand }));
    expect(confirm(dialog)).toBeDisabled();
  });

  it("sends the decision for the ticket as it now is, so the answer is written against the live row", async () => {
    const { state, dialog } = await openUndo();
    state.rows = [keptByBinh()];
    await poll();
    await userEvent.click(
      await within(dialog).findByRole("checkbox", { name: S.soar.dialog.acknowledgeChange }),
    );
    await userEvent.click(confirm(dialog) as HTMLElement);
    await waitFor(() => expect(state.decisions).toHaveLength(1));
  });
});

describe("a decision that is no longer allowed", () => {
  it("says why, offers no confirm, and only closes", async () => {
    const { state, dialog } = await openUndo();
    state.rows = [keptByBinh({ status: "undone", allowed_decisions: [], decided_by: "binh" })];
    await poll();
    const why = await within(dialog).findByText(
      "Thao tác này không còn được phép với phiếu (đang ở trạng thái “Đã gỡ”). Hãy đóng hộp thoại.",
    );
    expect(why).toHaveAttribute("role", "alert");
    expect(S.soar.dialog.notAllowed("Đã gỡ")).toBe(
      "Thao tác này không còn được phép với phiếu (đang ở trạng thái “Đã gỡ”). Hãy đóng hộp thoại.",
    );
    expect(confirm(dialog)).toBeNull();
    expect(within(dialog).queryByRole("checkbox")).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: S.common.close }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(state.decisions).toEqual([]);
  });

  it("holds when the role lost the right and the status is the same", async () => {
    const { state, dialog } = await openUndo();
    state.rows = [review({ allowed_decisions: ["keep"], updated_at: "2026-11-13T14:45:00+00:00" })];
    await poll();
    expect(
      await within(dialog).findByText(S.soar.dialog.notAllowed("Đang mở")),
    ).toBeInTheDocument();
    expect(confirm(dialog)).toBeNull();
  });
});

describe("a ticket that has left the list", () => {
  it("says it is no longer in this view, keeps the dialog open, and offers no confirm", async () => {
    const { state, dialog } = await openUndo();
    await userEvent.type(within(dialog).getByRole("textbox"), "đang gõ", { delay: null });
    state.rows = [];
    await poll();
    const gone = await within(dialog).findByText(
      "Phiếu không còn trong danh sách này (đã đổi trạng thái hoặc sang trang khác). Hãy đóng hộp thoại và xem lại phiếu.",
    );
    expect(gone).toHaveAttribute("role", "alert");
    expect(screen.getByRole("dialog")).toBe(dialog);
    expect(confirm(dialog)).toBeNull();
    expect(
      within(dialog).getByText("Phiếu K7QM2XHP: Chặn IP 79.79.78.202 trên pfSense"),
    ).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: S.common.close }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(state.decisions).toEqual([]);
  });
});
