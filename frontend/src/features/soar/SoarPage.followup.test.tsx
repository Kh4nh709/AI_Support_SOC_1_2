// src/features/soar/SoarPage.followup.test.tsx — the minors of the second review: a focus request that is used and gone; a dialog
// that cannot follow its ticket (the list is another view, or failed); the change notice at the top of the dialog; the search
// that keeps its focus; the history that says it was cut.
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterEach, vi } from "vitest";
import { S } from "../../strings";
import { detailOf, listOf, review } from "./fixtures";
import { SOAR_LIST_POLL_MS } from "./soarQueries";
import { fake, nav, renderSoar, serve } from "./testkit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
});
afterAll(() => server.close());

const KEEP = "✅ Giữ chặn";
const UNDO = "↩️ Gỡ chặn IP";
const rowOf = async (id = "K7QM2XHP") =>
  (await screen.findByRole("button", { name: S.soar.detail.open(id) })).closest(
    "tr",
  ) as HTMLElement;
const tab = (name: string) =>
  within(screen.getByRole("navigation", { name: S.soar.tabs.label })).getByRole("link", { name });

describe("the focus request of a decision is used once", () => {
  it("does not pull the focus from the tab link into the row when the person goes to Thông báo and back", async () => {
    const state = fake({ rows: [review()], notices: [] });
    state.decision = () => ({
      outcome: "ok",
      message: null,
      review: review({
        status: "kept",
        allowed_decisions: ["undo"],
        updated_at: "2026-11-13T14:41:10+00:00",
      }),
    });
    serve(server, state);
    renderSoar();
    await userEvent.click(within(await rowOf()).getByRole("button", { name: KEEP }));
    const group = await screen.findByRole("group", { name: S.soar.buttonsLabel("K7QM2XHP") });
    await waitFor(() => expect(group).toHaveFocus());
    await userEvent.click(tab("Thông báo"));
    await screen.findByRole("table", { name: S.soar.noticeTableLabel });
    await userEvent.click(tab("Đang mở"));
    await rowOf();
    // the link the person pressed has the focus, and no row has taken it
    expect(tab("Đang mở")).toHaveFocus();
    expect(
      screen.queryByRole("group", { name: S.soar.buttonsLabel("K7QM2XHP") }),
    ).not.toHaveFocus();
  });
});

describe("a dialog that cannot follow its ticket", () => {
  /** Opens undo on the open tab with the list of the Đã xử lý tab under the hand of the test. */
  async function openWithSlowDone(done: () => Promise<Response | undefined>) {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const state = fake({ rows: [review()] });
    state.list = async (url) => {
      if (url.searchParams.getAll("status").includes("kept")) return (await done()) as never;
      return undefined;
    };
    serve(server, state);
    renderSoar();
    await userEvent.click(within(await rowOf()).getByRole("button", { name: UNDO }));
    const dialog = await screen.findByRole("dialog");
    return { state, dialog };
  }
  const confirm = (dialog: HTMLElement) =>
    within(dialog).queryByRole("button", { name: S.soar.dialog.confirm.undo });

  it("shuts the confirm and says so while the list of another view is loading (the rows on screen are the old view's)", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const { dialog } = await openWithSlowDone(async () => {
      await gate;
      return undefined;
    });
    expect(confirm(dialog)).toBeEnabled();
    act(() => nav.go("/soar?tab=done"));
    const why = await within(dialog).findByText(S.soar.dialog.cannotFollow);
    expect(why).toHaveAttribute("role", "alert");
    expect(S.soar.dialog.cannotFollow).toBe(
      "Không theo dõi được phiếu lúc này: danh sách đang tải hoặc không tải được. Hãy đóng hộp thoại và xem lại phiếu.",
    );
    expect(confirm(dialog)).toBeNull();
    expect(within(dialog).getByRole("button", { name: S.common.close })).toBeInTheDocument();
    await act(async () => release());
  });

  it("keeps it shut when that list then fails: the snapshot is not enough to decide on", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const { state, dialog } = await openWithSlowDone(async () => {
      await gate;
      return HttpResponse.json({ detail: "boom" }, { status: 500 }) as unknown as Response;
    });
    act(() => nav.go("/soar?tab=done"));
    await within(dialog).findByText(S.soar.dialog.cannotFollow);
    await act(async () => release());
    await waitFor(() => expect(screen.getByText(S.soar.loadError)).toBeInTheDocument());
    expect(within(dialog).getByText(S.soar.dialog.cannotFollow)).toBeInTheDocument();
    expect(confirm(dialog)).toBeNull();
    expect(state.decisions).toEqual([]);
  });

  it("says the ticket is not in the view when the new list has loaded and does not hold it", async () => {
    const { dialog } = await openWithSlowDone(async () => listOf([]) as never);
    act(() => nav.go("/soar?tab=done"));
    expect(await within(dialog).findByText(S.soar.dialog.gone)).toBeInTheDocument();
    expect(confirm(dialog)).toBeNull();
  });

  it("is followed again when the view comes back with the ticket in it", async () => {
    const { dialog } = await openWithSlowDone(async () => listOf([]) as never);
    act(() => nav.go("/soar?tab=done"));
    await within(dialog).findByText(S.soar.dialog.gone);
    act(() => nav.go("/soar"));
    await waitFor(() => expect(confirm(dialog)).toBeEnabled());
    expect(within(dialog).queryByText(S.soar.dialog.gone)).not.toBeInTheDocument();
    await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
    expect(confirm(dialog)).toBeEnabled();
  });
});

describe("the notice of a change is at the top of the dialog", () => {
  it("comes before the ticket, the boxes and the note, so it is the first thing read", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const state = fake({ rows: [review({ strong_warning: true, host_critical: true })] });
    serve(server, state);
    renderSoar();
    await userEvent.click(within(await rowOf()).getByRole("button", { name: UNDO }));
    const dialog = await screen.findByRole("dialog");
    state.rows = [
      review({
        strong_warning: true,
        host_critical: true,
        status: "kept",
        decided_by: "binh",
        allowed_decisions: ["undo"],
        updated_at: "2026-11-13T14:50:00+00:00",
      }),
    ];
    await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
    const notice = await within(dialog).findByText("Phiếu vừa thay đổi: Đã giữ (binh)");
    const after = (node: Element) =>
      Boolean(notice.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_FOLLOWING);
    expect(
      after(within(dialog).getByText("Phiếu K7QM2XHP: Chặn IP 79.79.78.202 trên pfSense")),
    ).toBe(true);
    expect(after(within(dialog).getByRole("checkbox", { name: S.soar.dialog.understand }))).toBe(
      true,
    );
    expect(
      after(within(dialog).getByRole("checkbox", { name: S.soar.dialog.acknowledgeChange })),
    ).toBe(true);
    expect(after(within(dialog).getByRole("textbox"))).toBe(true);
    // and it is the first element of the body of the dialog
    const body = notice.closest("[id]") as HTMLElement;
    expect(body.firstElementChild).toBe(notice);
  });
});

describe("the search keeps the focus", () => {
  it("stays in the search field after it is sent, and after it is cleared", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    const box = await screen.findByRole("searchbox", { name: S.soar.search.label });
    await userEvent.type(box, "AD-server{Enter}");
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("/soar?q=AD-server"));
    expect(screen.getByRole("searchbox", { name: S.soar.search.label })).toHaveFocus();
    expect(screen.getByRole("searchbox", { name: S.soar.search.label })).toBe(box);
    await userEvent.click(screen.getByRole("button", { name: S.soar.search.clear }));
    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent(/^\/soar$/));
    expect(screen.getByRole("searchbox", { name: S.soar.search.label })).toHaveFocus();
    expect(screen.getByRole("searchbox", { name: S.soar.search.label })).toHaveValue("");
  });

  it("follows the URL when it changes under a draft (the back button), without losing a draft being typed", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar({ entry: "/soar?q=79.79" });
    const box = await screen.findByRole("searchbox", { name: S.soar.search.label });
    expect(box).toHaveValue("79.79");
    await userEvent.type(box, "x");
    expect(box).toHaveValue("79.79x");
    act(() => nav.go("/soar?q=abc"));
    await waitFor(() => expect(box).toHaveValue("abc"));
  });
});

describe("a history that was cut", () => {
  it("says only the newest 200 events are shown, above the history, when the server says it left some out", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () => detailOf({ history_truncated: true });
    serve(server, state);
    renderSoar();
    await userEvent.click(
      await screen.findByRole("button", { name: S.soar.detail.open("K7QM2XHP") }),
    );
    const panel = await screen.findByRole("region", { name: S.soar.detail.title("K7QM2XHP") });
    const note = await within(panel).findByText("Chỉ hiện 200 sự kiện mới nhất.");
    expect(S.soar.detail.history.truncated).toBe("Chỉ hiện 200 sự kiện mới nhất.");
    const table = within(panel).getByRole("table", { name: S.soar.detail.history.label });
    expect(Boolean(note.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING)).toBe(
      true,
    );
  });

  it("says nothing when it is false or absent", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () => detailOf({ history_truncated: false });
    serve(server, state);
    const view = renderSoar();
    await userEvent.click(
      await screen.findByRole("button", { name: S.soar.detail.open("K7QM2XHP") }),
    );
    const panel = await screen.findByRole("region", { name: S.soar.detail.title("K7QM2XHP") });
    await within(panel).findByRole("table", { name: S.soar.detail.history.label });
    expect(within(panel).queryByText(/Chỉ hiện 200/)).not.toBeInTheDocument();
    view.unmount();
    state.detail = () => detailOf();
    renderSoar();
    await userEvent.click(
      await screen.findByRole("button", { name: S.soar.detail.open("K7QM2XHP") }),
    );
    const again = await screen.findByRole("region", { name: S.soar.detail.title("K7QM2XHP") });
    await within(again).findByRole("table", { name: S.soar.detail.history.label });
    expect(within(again).queryByText(/Chỉ hiện 200/)).not.toBeInTheDocument();
  });
});
