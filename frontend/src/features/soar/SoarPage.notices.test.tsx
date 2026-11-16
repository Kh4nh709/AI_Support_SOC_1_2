// src/features/soar/SoarPage.notices.test.tsx — the notices above the table (coloured by severity, with its word, each
// dismissible and remembered in sessionStorage), the filter "Thông báo", and the switch that turns the new-ticket signal on.
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { setupServer } from "msw/node";
import { afterEach, beforeEach, vi } from "vitest";
import { S } from "../../strings";
import { notice, review } from "./fixtures";
import { closeSignalAudio } from "./signal";
import { DISMISSED_CAP, DISMISSED_KEY, SIGNAL_KEY } from "./storage";
import { fake, renderSoar, serve } from "./testkit";

/** An id of a notice: N and twelve characters (spec section 2); the store keeps nothing of another shape. */
const nid = (n: number) => `N${String(n).padStart(12, "0")}`;
const [N1, N2, N3, N5, N9] = [1, 2, 3, 5, 9].map(nid) as [string, string, string, string, string];

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
});
afterEach(() => {
  // nothing of these flows is ever written to the store that outlives the tab
  expect(localStorage.length).toBe(0);
  server.resetHandlers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
afterAll(() => server.close());

const errorNotice = notice({
  id: N1,
  severity: "error",
  title: "Không gỡ được chặn IP",
  note: "pfSense từ chối",
});
const warningNotice = notice({
  id: N2,
  severity: "warning",
  title: "Sắp hết hạn chặn",
  note: null,
});
const infoNotice = notice({
  id: N3,
  severity: "info",
  title: "Đã gỡ chặn IP 79.79.78.202",
  note: null,
});
const stripOf = () => screen.getByRole("region", { name: S.soar.notice.heading });

describe("the notices above the table", () => {
  it("shows a line for each, with the word of its severity, above the table", async () => {
    serve(server, fake({ rows: [review()], notices: [errorNotice, warningNotice, infoNotice] }));
    renderSoar();
    const strip = await waitFor(() => stripOf());
    const items = within(strip).getAllByRole("listitem");
    expect(items).toHaveLength(3);
    expect(items[0]).toHaveTextContent("Lỗi");
    expect(items[0]).toHaveTextContent("Không gỡ được chặn IP");
    expect(items[0]).toHaveTextContent("pfSense từ chối");
    expect(items[1]).toHaveTextContent("Cảnh báo");
    expect(items[2]).toHaveTextContent("Thông tin");
    expect(S.soar.severity).toEqual({ error: "Lỗi", warning: "Cảnh báo", info: "Thông tin" });
    const table = await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(strip.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("says a dismissal is for this session: a hint line, and a title on each button", async () => {
    serve(server, fake({ rows: [review()], notices: [errorNotice, warningNotice] }));
    renderSoar();
    const strip = await waitFor(() => stripOf());
    expect(
      within(strip).getByText("Thông báo đã ẩn sẽ hiện lại khi mở tab mới."),
    ).toBeInTheDocument();
    for (const id of [N1, N2]) {
      const button = within(strip).getByRole("button", { name: S.soar.notice.dismissLabel(id) });
      expect(button).toHaveAttribute("title", "Ẩn trong phiên này");
    }
    expect(S.soar.notice.sessionOnly).toBe("Ẩn trong phiên này");
    expect(S.soar.notice.sessionHint).toBe("Thông báo đã ẩn sẽ hiện lại khi mở tab mới.");
  });

  it("colours a line by its severity: error red, warning orange, info grey, always with the word", async () => {
    serve(server, fake({ rows: [review()], notices: [errorNotice, warningNotice, infoNotice] }));
    renderSoar();
    const strip = await waitFor(() => stripOf());
    const [error, warning, info] = within(strip).getAllByRole("listitem");
    expect(error?.className).toContain("border-critical");
    expect(within(error as HTMLElement).getByText("Lỗi").className).toContain("text-critical");
    expect(warning?.className).toContain("border-high");
    expect(within(warning as HTMLElement).getByText("Cảnh báo").className).toContain("text-high");
    expect(info?.className).toContain("border-border");
    expect(within(info as HTMLElement).getByText("Thông tin").className).toContain("text-muted");
  });

  it("shows a severity it does not know as its code, in the grey of info, and does not crash", async () => {
    serve(
      server,
      fake({ rows: [], notices: [notice({ id: N9, severity: "fatal" as never, title: "Lạ" })] }),
    );
    renderSoar();
    const strip = await waitFor(() => stripOf());
    expect(within(strip).getByText("fatal")).toBeInTheDocument();
    expect(within(strip).getByRole("listitem").className).toContain("border-border");
  });

  it("draws no region at all when there are no notices", async () => {
    const state = fake({ rows: [review()], notices: [] });
    serve(server, state);
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    await waitFor(() =>
      expect(state.lists.some((url) => url.searchParams.get("kind") === "notice")).toBe(true),
    );
    await act(async () => {});
    expect(screen.queryByRole("region", { name: S.soar.notice.heading })).not.toBeInTheDocument();
  });

  it("dismisses one with its button, remembers it for the tab (the session store), and does not show it again after the page is opened again", async () => {
    serve(server, fake({ rows: [review()], notices: [errorNotice, warningNotice] }));
    const first = renderSoar();
    const strip = await waitFor(() => stripOf());
    await userEvent.click(
      within(strip).getByRole("button", { name: S.soar.notice.dismissLabel(N1) }),
    );
    expect(screen.queryByText("Không gỡ được chặn IP")).not.toBeInTheDocument();
    expect(screen.getByText("Sắp hết hạn chặn")).toBeInTheDocument();
    expect(JSON.parse(sessionStorage.getItem(DISMISSED_KEY) ?? "[]")).toEqual([N1]);
    first.unmount();
    renderSoar();
    await screen.findByText("Sắp hết hạn chặn");
    expect(screen.queryByText("Không gỡ được chặn IP")).not.toBeInTheDocument();
  });

  it("takes the region away when the last line is dismissed", async () => {
    serve(server, fake({ rows: [review()], notices: [infoNotice] }));
    renderSoar();
    const strip = await waitFor(() => stripOf());
    await userEvent.click(
      within(strip).getByRole("button", { name: S.soar.notice.dismissLabel(N3) }),
    );
    expect(screen.queryByRole("region", { name: S.soar.notice.heading })).not.toBeInTheDocument();
  });

  it("starts without the ids already dismissed", async () => {
    sessionStorage.setItem(DISMISSED_KEY, JSON.stringify([N1, N2]));
    serve(server, fake({ rows: [review()], notices: [errorNotice, warningNotice, infoNotice] }));
    renderSoar();
    const strip = await waitFor(() => stripOf());
    expect(within(strip).getAllByRole("listitem")).toHaveLength(1);
    expect(within(strip).getByText("Đã gỡ chặn IP 79.79.78.202")).toBeInTheDocument();
  });

  it("caps what it remembers: the newest DISMISSED_CAP ids", async () => {
    const seeded = Array.from({ length: DISMISSED_CAP }, (_, i) => nid(1000 + i));
    sessionStorage.setItem(DISMISSED_KEY, JSON.stringify(seeded));
    serve(server, fake({ rows: [review()], notices: [infoNotice] }));
    renderSoar();
    const strip = await waitFor(() => stripOf());
    await userEvent.click(
      within(strip).getByRole("button", { name: S.soar.notice.dismissLabel(N3) }),
    );
    const stored = JSON.parse(sessionStorage.getItem(DISMISSED_KEY) ?? "[]") as string[];
    expect(stored).toHaveLength(DISMISSED_CAP);
    expect(stored.at(-1)).toBe(N3);
    expect(stored).not.toContain(nid(1000));
  });

  it("works with the store blocked: a dismissal holds for the visit", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    serve(server, fake({ rows: [review()], notices: [errorNotice] }));
    renderSoar();
    const strip = await waitFor(() => stripOf());
    await userEvent.click(
      within(strip).getByRole("button", { name: S.soar.notice.dismissLabel(N1) }),
    );
    expect(screen.queryByText("Không gỡ được chặn IP")).not.toBeInTheDocument();
  });

  it("shows the first 20 and says how many more there are, and where to find them", async () => {
    const many = Array.from({ length: 23 }, (_, i) =>
      notice({ id: nid(100 + i), title: `Thông báo ${i}` }),
    );
    serve(server, fake({ rows: [review()], notices: many }));
    renderSoar();
    const strip = await waitFor(() => stripOf());
    expect(within(strip).getAllByRole("listitem")).toHaveLength(20);
    expect(
      within(strip).getByText("Còn 3 thông báo khác, xem ở mục “Thông báo”."),
    ).toBeInTheDocument();
  });

  it("asks for notices with kind=notice", async () => {
    const state = fake({ rows: [review()], notices: [infoNotice] });
    serve(server, state);
    renderSoar();
    await waitFor(() => stripOf());
    expect(state.lists.some((url) => url.searchParams.get("kind") === "notice")).toBe(true);
  });
});

describe("the filter Thông báo", () => {
  it("lists them all, dismissed or not, in a table of their own, and the strip is not drawn twice", async () => {
    sessionStorage.setItem(DISMISSED_KEY, JSON.stringify([N1]));
    serve(server, fake({ rows: [review()], notices: [errorNotice, warningNotice] }));
    renderSoar({ entry: "/soar?tab=notice" });
    const table = await screen.findByRole("table", { name: S.soar.noticeTableLabel });
    expect(within(table).getByText("Không gỡ được chặn IP")).toBeInTheDocument();
    expect(within(table).getByText("Sắp hết hạn chặn")).toBeInTheDocument();
    expect(screen.getAllByText("Không gỡ được chặn IP")).toHaveLength(1);
    expect(screen.queryByRole("region", { name: S.soar.notice.heading })).not.toBeInTheDocument();
  });

  it("marks a dismissed one as such, and still lets the others be dismissed", async () => {
    sessionStorage.setItem(DISMISSED_KEY, JSON.stringify([N1]));
    serve(server, fake({ notices: [errorNotice, warningNotice] }));
    renderSoar({ entry: "/soar?tab=notice" });
    const table = await screen.findByRole("table", { name: S.soar.noticeTableLabel });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows[0]).toHaveTextContent(S.soar.notice.dismissed);
    expect(
      within(rows[0] as HTMLElement).queryByRole("button", { name: /^Ẩn/ }),
    ).not.toBeInTheDocument();
    await userEvent.click(
      within(rows[1] as HTMLElement).getByRole("button", {
        name: S.soar.notice.dismissLabel(N2),
      }),
    );
    expect(rows[1]).toHaveTextContent(S.soar.notice.dismissed);
    expect(JSON.parse(sessionStorage.getItem(DISMISSED_KEY) ?? "[]")).toEqual([N1, N2]);
  });

  it("shows the time, the severity word, the title, the note, the host and the case of a notice", async () => {
    serve(
      server,
      fake({
        notices: [
          notice({
            id: N5,
            severity: "warning",
            title: "Tiêu đề",
            note: "Nội dung",
            host: "AD-server",
            case_number: 7,
          }),
        ],
      }),
    );
    renderSoar({ entry: "/soar?tab=notice" });
    const table = await screen.findByRole("table", { name: S.soar.noticeTableLabel });
    const [, row] = within(table).getAllByRole("row");
    const cells = within(row as HTMLElement).getAllByRole("cell");
    expect(cells[0]).toHaveTextContent("13/11 21:40");
    expect(cells[1]).toHaveTextContent("Cảnh báo");
    expect(cells[2]).toHaveTextContent("Tiêu đề");
    expect(cells[3]).toHaveTextContent("Nội dung");
    expect(cells[4]).toHaveTextContent("AD-server");
    expect(cells[5]).toHaveTextContent("#7");
  });
});

describe("the switch of the signal", () => {
  class Notify {
    static permission = "default";
    static requestPermission = vi.fn(async () => "granted");
  }
  const mine = () => screen.getByRole("switch", { name: S.soar.signal.label });

  beforeEach(() => {
    Notify.permission = "default";
    Notify.requestPermission = vi.fn(async () => "granted");
    vi.stubGlobal("Notification", Notify);
  });

  it("is off at first when the browser has not granted the permission, labelled, and asks for nothing on load", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(mine()).not.toBeChecked();
    expect(Notify.requestPermission).not.toHaveBeenCalled();
    expect(screen.getByText(S.soar.signal.hint)).toBeInTheDocument();
  });

  it("says the choice is the tab's own and that the browser remembers the permission", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(
      screen.getByText(
        "Lựa chọn chỉ áp dụng cho tab này; trình duyệt tự nhớ quyền hiện thông báo.",
      ),
    ).toBeInTheDocument();
    expect(S.soar.signal.perTab).toBe(
      "Lựa chọn chỉ áp dụng cho tab này; trình duyệt tự nhớ quyền hiện thông báo.",
    );
  });

  // A new tab is not silently mute: with no choice stored in the tab, the signal is on when the browser already holds the
  // permission to notify (it remembers that itself), and off otherwise.
  it.each([
    ["granted", true],
    ["default", false],
    ["denied", false],
  ] as const)(
    "a tab with no choice and the permission %s opens with the switch %s",
    async (permission, on) => {
      Notify.permission = permission;
      serve(server, fake({ rows: [review()] }));
      renderSoar();
      await screen.findByRole("table", { name: S.soar.tableLabel });
      if (on) expect(mine()).toBeChecked();
      else expect(mine()).not.toBeChecked();
      // looking at the page chooses nothing and asks for nothing
      expect(sessionStorage.getItem(SIGNAL_KEY)).toBeNull();
      expect(Notify.requestPermission).not.toHaveBeenCalled();
    },
  );

  it("a tab with no choice and no Notification API opens with the switch off", async () => {
    vi.stubGlobal("Notification", undefined);
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(mine()).not.toBeChecked();
  });

  it("the choice of the tab wins over the default: off with the permission granted, on with it denied", async () => {
    Notify.permission = "granted";
    sessionStorage.setItem(SIGNAL_KEY, "0");
    serve(server, fake({ rows: [review()] }));
    const first = renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(mine()).not.toBeChecked();
    first.unmount();
    Notify.permission = "denied";
    sessionStorage.setItem(SIGNAL_KEY, "1");
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(mine()).toBeChecked();
  });

  it("turns on with a click: keeps the choice for the tab and asks Notification permission once, on that click", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    await userEvent.click(mine());
    expect(mine()).toBeChecked();
    expect(sessionStorage.getItem(SIGNAL_KEY)).toBe("1");
    expect(Notify.requestPermission).toHaveBeenCalledTimes(1);
  });

  it("turns off with a click, keeps that for the tab, and does not ask again; a default-on tab turned off stays off", async () => {
    sessionStorage.setItem(SIGNAL_KEY, "1");
    serve(server, fake({ rows: [review()] }));
    const first = renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(mine()).toBeChecked();
    await userEvent.click(mine());
    expect(mine()).not.toBeChecked();
    expect(sessionStorage.getItem(SIGNAL_KEY)).toBe("0");
    expect(Notify.requestPermission).not.toHaveBeenCalled();
    first.unmount();
    sessionStorage.clear();
    Notify.permission = "granted";
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(mine()).toBeChecked();
    await userEvent.click(mine());
    expect(sessionStorage.getItem(SIGNAL_KEY)).toBe("0");
    expect(mine()).not.toBeChecked();
  });

  it("is where the choice was left when the page is opened again in the same tab", async () => {
    serve(server, fake({ rows: [review()] }));
    const first = renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    await userEvent.click(mine());
    first.unmount();
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(mine()).toBeChecked();
  });

  it("says the tone is all there is when the browser denied notifications, or has none", async () => {
    serve(server, fake({ rows: [review()] }));
    Notify.permission = "denied";
    const denied = renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(screen.getByText(S.soar.signal.toneOnly)).toBeInTheDocument();
    denied.unmount();
    vi.stubGlobal("Notification", undefined);
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    expect(screen.getByText(S.soar.signal.toneOnly)).toBeInTheDocument();
    await userEvent.click(mine());
    expect(mine()).toBeChecked();
  });

  it("works with the store blocked: the switch moves for this visit", async () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("blocked", "SecurityError");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("full", "QuotaExceededError");
    });
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    await screen.findByRole("table", { name: S.soar.tableLabel });
    await userEvent.click(mine());
    expect(mine()).toBeChecked();
  });
});

// The tone needs a gesture. A tab on which the signal is on by default has had none: its notification goes alone, and the audio
// context is made at the first gesture the page already handles (a press, a dismissal, a detail opened, a search, the switch).
// No listener is added for this: the handlers call `primeAudio`.
describe("the gestures of the page prime the tone", () => {
  const made = { count: 0 };
  class Audio {
    state = "running";
    currentTime = 0;
    destination = {};
    constructor() {
      made.count += 1;
    }
    resume = async () => {};
    close = async () => {};
    createGain() {
      return {
        gain: { setValueAtTime: () => {}, exponentialRampToValueAtTime: () => {} },
        connect: () => {},
      };
    }
    createOscillator() {
      return {
        type: "",
        frequency: { value: 0 },
        connect: () => {},
        start: () => {},
        stop: () => {},
      };
    }
  }
  class Granted {
    static permission = "granted";
    static requestPermission = vi.fn(async () => "granted");
  }

  beforeEach(() => {
    made.count = 0;
    Granted.permission = "granted";
    vi.stubGlobal("AudioContext", Audio);
    vi.stubGlobal("Notification", Granted);
  });
  afterEach(() => closeSignalAudio());

  it("makes no audio context on load, and one at the first press, whatever the number of gestures after", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    const row = (
      await screen.findByRole("button", { name: S.soar.detail.open("K7QM2XHP") })
    ).closest("tr") as HTMLElement;
    expect(made.count).toBe(0);
    await userEvent.click(within(row).getByRole("button", { name: "✅ Giữ chặn" }));
    await waitFor(() => expect(made.count).toBe(1));
    await userEvent.click(screen.getByRole("button", { name: S.soar.detail.open("K7QM2XHP") }));
    expect(made.count).toBe(1);
  });

  it("makes one at a dismissal of a notice", async () => {
    serve(server, fake({ rows: [review()], notices: [notice({ id: N1 })] }));
    renderSoar();
    const strip = await waitFor(() => stripOf());
    expect(made.count).toBe(0);
    await userEvent.click(
      within(strip).getByRole("button", { name: S.soar.notice.dismissLabel(N1) }),
    );
    expect(made.count).toBe(1);
  });

  it("makes one when a detail panel is opened", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    await userEvent.click(
      await screen.findByRole("button", { name: S.soar.detail.open("K7QM2XHP") }),
    );
    expect(made.count).toBe(1);
  });

  it("makes one when the search is sent", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    const box = await screen.findByRole("searchbox", { name: S.soar.search.label });
    expect(made.count).toBe(0);
    await userEvent.type(box, "x{Enter}");
    expect(made.count).toBe(1);
  });

  it("makes none while the signal is off for the tab", async () => {
    sessionStorage.setItem(SIGNAL_KEY, "0");
    serve(server, fake({ rows: [review()], notices: [notice({ id: N1 })] }));
    renderSoar();
    const strip = await waitFor(() => stripOf());
    await userEvent.click(
      within(strip).getByRole("button", { name: S.soar.notice.dismissLabel(N1) }),
    );
    await userEvent.click(screen.getByRole("button", { name: S.soar.detail.open("K7QM2XHP") }));
    expect(made.count).toBe(0);
  });
});
