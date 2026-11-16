// src/features/soar/SoarPage.rows.test.tsx — the table of the page "Phản hồi SOAR": its columns, the score's colour, the
// status words, the tag of a simulated ticket, the buttons by state and by `allowed_decisions`, the timers at fixed clocks.
import { act, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterEach, vi } from "vitest";
import { S } from "../../strings";
import { review } from "./fixtures";
import { SOAR_LIST_POLL_MS } from "./soarQueries";
import { NOW, fake, renderSoar, serve } from "./testkit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
});
afterAll(() => server.close());

/** The row of a ticket, found through its "xem chi tiết" button. */
const rowOf = async (id: string) => {
  const button = await screen.findByRole("button", { name: S.soar.detail.open(id) });
  const row = button.closest("tr");
  if (row === null) throw new Error("no row");
  return row;
};
const cellsOf = (row: HTMLElement) => within(row).getAllByRole("cell");

describe("the table", () => {
  it("has the columns of the card, in order, in Vietnamese", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    await rowOf("K7QM2XHP");
    expect(screen.getAllByRole("columnheader").map((th) => th.textContent)).toEqual([
      S.soar.col.id,
      S.soar.col.time,
      S.soar.col.case,
      S.soar.col.scenario,
      S.soar.col.host,
      S.soar.col.target,
      S.soar.col.action,
      S.soar.col.score,
      S.soar.col.status,
      S.soar.col.actions,
    ]);
    expect([S.soar.col.time, S.soar.col.case, S.soar.col.scenario, S.soar.col.host]).toEqual([
      "Thời gian",
      "Case",
      "Kịch bản",
      "Máy",
    ]);
  });

  it("shows time in +07, case, scenario, host, target, action, score and status of a row", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    const [id, time, caseNo, scenario, host, target, action, score, status] = cellsOf(
      await rowOf("K7QM2XHP"),
    );
    expect(id).toHaveTextContent("K7QM2XHP");
    expect(time).toHaveTextContent("13/11 21:40"); // 14:40:03Z in Asia/Ho_Chi_Minh
    expect(caseNo).toHaveTextContent("#65");
    expect(scenario).toHaveTextContent("Quét cổng từ bên ngoài");
    expect(host).toHaveTextContent("pfSense.home.arpa");
    expect(target).toHaveTextContent("79.79.78.202");
    expect(action).toHaveTextContent("Chặn IP 79.79.78.202 trên pfSense");
    expect(score).toHaveTextContent("50");
    expect(status).toHaveTextContent("Đang mở");
  });

  it("falls back to the Vietnamese word of the action type when n8n sent no text for it", async () => {
    serve(server, fake({ rows: [review({ action_text: null, action_type: "isolate_host" })] }));
    renderSoar();
    expect(cellsOf(await rowOf("K7QM2XHP"))[6]).toHaveTextContent(/^Cách ly máy/);
  });

  it("shows a dash for what a row does not have, and never a blank cell", async () => {
    serve(
      server,
      fake({
        rows: [
          review({
            case_number: null,
            scenario_name: null,
            scenario_id: null,
            host: null,
            action_target: null,
            score: null,
          }),
        ],
      }),
    );
    renderSoar();
    const cells = cellsOf(await rowOf("K7QM2XHP"));
    for (const at of [2, 3, 4, 5, 7])
      expect(cells[at], String(at)).toHaveTextContent(S.common.missing);
  });

  it("tags a simulated ticket GIẢ LẬP, and no other", async () => {
    serve(
      server,
      fake({ rows: [review({ simulated: true }), review({ id: "B2", simulated: false })] }),
    );
    renderSoar();
    expect(await within(await rowOf("K7QM2XHP")).findByText("GIẢ LẬP")).toBeInTheDocument();
    expect(S.soar.simulated).toBe("GIẢ LẬP");
    expect(within(await rowOf("B2")).queryByText("GIẢ LẬP")).not.toBeInTheDocument();
  });

  it.each([
    [85, "text-critical"],
    [70, "text-critical"],
    [69, "text-high"],
    [40, "text-high"],
    [39, "text-medium"],
    [0, "text-medium"],
  ])(
    "prints a score of %i and colours it with %s (red from 70, orange from 40, yellow below)",
    async (score, tone) => {
      serve(server, fake({ rows: [review({ score })] }));
      renderSoar();
      const cell = cellsOf(await rowOf("K7QM2XHP"))[7];
      const number = within(cell as HTMLElement).getByText(String(score));
      expect(number.className).toContain(tone);
      // never colour alone: the number is the text, whatever the colour
      expect(number).toHaveTextContent(new RegExp(`^${score}$`));
    },
  );

  it.each([
    ["open", "Đang mở"],
    ["kept", "Đã giữ"],
    ["undone", "Đã gỡ"],
    ["false_positive", "Dương tính giả"],
    ["expired", "Hết hạn"],
  ] as const)("words the status %s as %s", async (status, word) => {
    serve(server, fake({ rows: [review({ status, allowed_decisions: [] })] }));
    renderSoar({ entry: "/soar?tab=done" });
    expect(cellsOf(await rowOf("K7QM2XHP"))[8]).toHaveTextContent(word);
  });

  it("words a row another person is processing, with who holds it", async () => {
    serve(
      server,
      fake({
        rows: [review({ status: "processing", locked_by: "binh", allowed_decisions: [] })],
      }),
    );
    renderSoar();
    expect(cellsOf(await rowOf("K7QM2XHP"))[8]).toHaveTextContent("Đang xử lý (binh)");
  });

  it("shows a status and an action type it has no word for as their codes, and does not crash", async () => {
    serve(
      server,
      fake({
        rows: [
          review({
            status: "paused" as never,
            action_text: null,
            action_type: "make_coffee" as never,
            allowed_decisions: [],
          }),
        ],
      }),
    );
    renderSoar();
    const cells = cellsOf(await rowOf("K7QM2XHP"));
    expect(cells[8]).toHaveTextContent("paused");
    expect(cells[6]).toHaveTextContent("make_coffee");
  });

  it("says each tab's own empty line, and the search's", async () => {
    serve(server, fake());
    const first = renderSoar();
    expect(await screen.findByText(S.soar.empty.open)).toBeInTheDocument();
    first.unmount();
    for (const [tab, line] of [
      ["done", S.soar.empty.done],
      ["expired", S.soar.empty.expired],
      ["notice", S.soar.empty.notice],
    ] as const) {
      const view = renderSoar({ entry: `/soar?tab=${tab}` });
      expect(await screen.findByText(line), tab).toBeInTheDocument();
      view.unmount();
    }
    renderSoar({ entry: "/soar?q=zzz" });
    expect(await screen.findByText(S.soar.empty.search)).toBeInTheDocument();
  });

  it("says the list could not be loaded, with a retry that asks again", async () => {
    let fail = true;
    const state = fake({ rows: [review()] });
    state.list = () =>
      fail ? new Response(JSON.stringify({ detail: "x" }), { status: 500 }) : undefined;
    serve(server, state);
    const { container } = renderSoar();
    expect(await screen.findByRole("alert")).toHaveTextContent(S.soar.loadError);
    fail = false;
    await act(async () => screen.getByRole("button", { name: S.common.retry }).click());
    await rowOf("K7QM2XHP");
    expect(container.querySelector('[role="alert"]')).toBeNull();
  });

  it("asks again every 20 s", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const state = fake({ rows: [review()] });
    serve(server, state);
    renderSoar();
    await rowOf("K7QM2XHP");
    const before = state.lists.length;
    expect(SOAR_LIST_POLL_MS).toBe(20_000);
    state.rows = [review(), review({ id: "B2C3D4E5" })];
    await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
    await rowOf("B2C3D4E5");
    expect(state.lists.length).toBeGreaterThan(before);
  });
});

describe("the buttons", () => {
  const buttonNames = (row: HTMLElement) =>
    within(row)
      .queryAllByRole("button")
      .filter((b) => !b.getAttribute("aria-label")?.startsWith("Xem chi tiết"))
      .map((b) => b.textContent);

  // m6: the word of the WEB for each decision is always there: a description of the button for a screen reader, and a small
  // muted tag for the eye when the label n8n wrote does not already carry the word.
  describe("the word of the web for each decision", () => {
    const WORDS = { keep: "Giữ", undo: "Gỡ", fp: "Dương tính giả" } as const;
    const tagOf = (button: HTMLElement) => {
      const id = button.getAttribute("aria-describedby");
      const tag = id === null ? null : document.getElementById(id);
      if (tag === null) throw new Error("no description");
      return tag;
    };

    it("describes every button by the word of its decision, keep included, and says it in the table's own words", async () => {
      serve(server, fake({ rows: [review()] }));
      renderSoar();
      const row = await rowOf("K7QM2XHP");
      expect(within(row).getByRole("button", { name: "✅ Giữ chặn" })).toHaveAccessibleDescription(
        "Giữ",
      );
      expect(
        within(row).getByRole("button", { name: "↩️ Gỡ chặn IP" }),
      ).toHaveAccessibleDescription("Gỡ");
      expect(S.soar.decision).toEqual(WORDS);
    });

    it("shows no tag when the label already has the word, in any case", async () => {
      serve(
        server,
        fake({
          rows: [
            review({
              buttons: [
                { decision: "keep", label: "GIỮ LẠI" },
                { decision: "undo", label: "gỡ bỏ" },
              ],
            }),
          ],
        }),
      );
      renderSoar();
      const row = await rowOf("K7QM2XHP");
      for (const name of ["GIỮ LẠI", "gỡ bỏ"]) {
        const tag = tagOf(within(row).getByRole("button", { name }));
        expect(tag.className).toContain("sr-only");
      }
    });

    it("shows a small muted tag with the web's word when the label does not have it, for every decision", async () => {
      serve(
        server,
        fake({
          rows: [
            review({
              action_type: "kill_process",
              buttons: [
                { decision: "keep", label: "OK" },
                { decision: "undo", label: "Hoàn tác" },
                { decision: "fp", label: "Not a threat" },
              ],
              allowed_decisions: ["keep", "undo", "fp"],
            }),
          ],
        }),
      );
      renderSoar();
      const row = await rowOf("K7QM2XHP");
      for (const [label, word] of [
        ["OK", "Giữ"],
        ["Hoàn tác", "Gỡ"],
        ["Not a threat", "Dương tính giả"],
      ] as const) {
        const button = within(row).getByRole("button", { name: label });
        const tag = tagOf(button);
        expect(tag).toHaveTextContent(new RegExp(`^${word}$`));
        expect(tag.className).not.toContain("sr-only");
        expect(tag.className).toContain("text-muted");
        expect(button).toHaveAccessibleDescription(word);
        // beside the button, not inside it: the name of the button stays n8n's label alone
        expect(button).toHaveAccessibleName(label);
        expect(button.contains(tag)).toBe(false);
      }
    });
  });

  it("shows one button per entry of buttons, with n8n's label as text, on an open ticket", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    const row = await rowOf("K7QM2XHP");
    expect(within(row).getByRole("button", { name: "✅ Giữ chặn" })).toBeEnabled();
    expect(within(row).getByRole("button", { name: "↩️ Gỡ chặn IP" })).toBeEnabled();
    expect(buttonNames(row)).toEqual(["✅ Giữ chặn", "↩️ Gỡ chặn IP"]);
  });

  it("keeps the undo button after Giữ: a kept ticket offers undo and nothing else", async () => {
    serve(server, fake({ rows: [review({ status: "kept", allowed_decisions: ["undo"] })] }));
    renderSoar({ entry: "/soar?tab=done" });
    const row = await rowOf("K7QM2XHP");
    expect(buttonNames(row)).toEqual(["↩️ Gỡ chặn IP"]);
  });

  it("offers keep and false positive for a killed process, and nothing once it is kept", async () => {
    const open = review({
      id: "P1",
      action_type: "kill_process",
      buttons: [
        { decision: "keep", label: "✅ Giữ dừng" },
        { decision: "fp", label: "🚫 Dương tính giả" },
      ],
      allowed_decisions: ["keep", "fp"],
    });
    const kept = review({ ...open, id: "P2", status: "kept", allowed_decisions: [] });
    serve(server, fake({ rows: [open, kept] }));
    renderSoar();
    expect(buttonNames(await rowOf("P1"))).toEqual(["✅ Giữ dừng", "🚫 Dương tính giả"]);
    expect(buttonNames(await rowOf("P2"))).toEqual([]);
  });

  it("shows only the buttons the caller's role may press, whatever n8n sent", async () => {
    serve(server, fake({ rows: [review({ allowed_decisions: ["keep"] })] }));
    renderSoar({ role: "tier1" });
    expect(buttonNames(await rowOf("K7QM2XHP"))).toEqual(["✅ Giữ chặn"]);
  });

  it("shows no button when allowed_decisions is empty, and none for a notice", async () => {
    serve(server, fake({ rows: [review({ allowed_decisions: [] })] }));
    const view = renderSoar();
    expect(buttonNames(await rowOf("K7QM2XHP"))).toEqual([]);
    view.unmount();
    serve(
      server,
      fake({
        notices: [
          review({
            id: "N1",
            kind: "notice",
            status: "info",
            title: "Thông báo thử",
            buttons: [{ decision: "keep", label: "Giữ" }],
            allowed_decisions: [],
          }),
        ],
      }),
    );
    renderSoar({ entry: "/soar?tab=notice" });
    expect(await screen.findByText("Thông báo thử")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Giữ" })).not.toBeInTheDocument();
  });

  it("names the group of a row's buttons by its ticket, so a screen reader can tell them apart", async () => {
    serve(server, fake({ rows: [review(), review({ id: "B2C3D4E5" })] }));
    renderSoar();
    await rowOf("K7QM2XHP");
    expect(
      screen.getByRole("group", { name: S.soar.buttonsLabel("K7QM2XHP") }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("group", { name: S.soar.buttonsLabel("B2C3D4E5") }),
    ).toBeInTheDocument();
  });

  it("renders n8n's label as text and nothing else", async () => {
    serve(
      server,
      fake({
        rows: [
          review({
            buttons: [{ decision: "keep", label: "<b>đậm</b><img src=x onerror=alert(1)>" }],
            allowed_decisions: ["keep"],
          }),
        ],
      }),
    );
    const { container } = renderSoar();
    const row = await rowOf("K7QM2XHP");
    expect(
      within(row).getByRole("button", { name: "<b>đậm</b><img src=x onerror=alert(1)>" }),
    ).toBeInTheDocument();
    expect(container.querySelector("img, b")).toBeNull();
  });
});

describe("the timers at fixed clocks", () => {
  // NOW is 14:41:05Z; the ticket expires at 15:40:03Z (22:40 in +07): 58 minutes 58 seconds ahead.
  it("says when it undoes itself, with the countdown, before the time", async () => {
    serve(server, fake({ rows: [review({ auto_expire_at: "2026-11-13T15:40:03+00:00" })] }));
    renderSoar();
    const row = await rowOf("K7QM2XHP");
    expect(within(row).getByText("Tự gỡ lúc 22:40 · còn 58:58")).toBeInTheDocument();
    expect(S.soar.timer.autoUndo("22:40", "58:58")).toBe("Tự gỡ lúc 22:40 · còn 58:58");
    expect(within(row).queryByText(S.soar.timer.waitingClose)).not.toBeInTheDocument();
  });

  it("says the SOAR has yet to close the ticket once the time is past and it is still open", async () => {
    serve(server, fake({ rows: [review({ auto_expire_at: "2026-11-13T14:00:00+00:00" })] }));
    renderSoar();
    const row = await rowOf("K7QM2XHP");
    expect(within(row).getByText("Chờ SOAR đóng phiếu")).toBeInTheDocument();
    expect(within(row).queryByText(/Tự gỡ lúc/)).not.toBeInTheDocument();
    // the web never changes a status itself: it is still Đang mở, with its buttons
    expect(cellsOf(row)[8]).toHaveTextContent("Đang mở");
    expect(within(row).getByRole("button", { name: "✅ Giữ chặn" })).toBeEnabled();
  });

  it("counts down for a kept ticket while its time is ahead, and says nothing once it is past (it is not open)", async () => {
    serve(
      server,
      fake({
        rows: [
          review({
            status: "kept",
            allowed_decisions: ["undo"],
            auto_expire_at: "2026-11-13T15:40:03+00:00",
          }),
          review({
            id: "B2",
            status: "kept",
            allowed_decisions: ["undo"],
            auto_expire_at: "2026-11-13T14:00:00+00:00",
          }),
        ],
      }),
    );
    renderSoar({ entry: "/soar?tab=done" });
    const ahead = await rowOf("K7QM2XHP");
    expect(within(ahead).getByText("Tự gỡ lúc 22:40 · còn 58:58")).toBeInTheDocument();
    const past = await rowOf("B2");
    expect(within(past).queryByText(/Tự gỡ lúc|Chờ SOAR đóng phiếu/)).not.toBeInTheDocument();
  });

  it("says an isolation is held, with the interval, and does not highlight it before the reminder is due", async () => {
    serve(
      server,
      fake({
        rows: [
          review({
            action_type: "isolate_host",
            remind_every_minutes: 30,
            next_remind_at: "2026-11-13T15:00:00+00:00",
            auto_expire_at: null,
          }),
        ],
      }),
    );
    renderSoar();
    const row = await rowOf("K7QM2XHP");
    expect(within(row).getByText("Đang giữ · nhắc mỗi 30 phút")).toBeInTheDocument();
    expect(S.soar.timer.holding(30)).toBe("Đang giữ · nhắc mỗi 30 phút");
    expect(within(row).queryByText(S.soar.timer.remindDue)).not.toBeInTheDocument();
  });

  it("highlights the reminder, in words and not in colour alone, once next_remind_at is past", async () => {
    serve(
      server,
      fake({
        rows: [
          review({
            action_type: "disable_user",
            remind_every_minutes: 15,
            next_remind_at: "2026-11-13T14:30:00+00:00",
            auto_expire_at: null,
          }),
        ],
      }),
    );
    renderSoar();
    const row = await rowOf("K7QM2XHP");
    expect(within(row).getByText("Đang giữ · nhắc mỗi 15 phút")).toBeInTheDocument();
    const due = within(row).getByText(S.soar.timer.remindDue);
    expect(due.className).toContain("text-high");
  });

  it("has no hold line for another action, or an interval of 0", async () => {
    serve(
      server,
      fake({
        rows: [
          review({ remind_every_minutes: 30, auto_expire_at: null }),
          review({
            id: "B2",
            action_type: "isolate_host",
            remind_every_minutes: 0,
            auto_expire_at: null,
          }),
        ],
      }),
    );
    renderSoar();
    for (const id of ["K7QM2XHP", "B2"]) {
      expect(within(await rowOf(id)).queryByText(/Đang giữ/)).not.toBeInTheDocument();
    }
  });

  it("counts down live, once a second, without a live region that would read it out", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.setSystemTime(NOW);
    serve(server, fake({ rows: [review({ auto_expire_at: "2026-11-13T15:40:03+00:00" })] }));
    renderSoar({ now: () => Date.now() });
    const first = await screen.findByText("Tự gỡ lúc 22:40 · còn 58:58");
    await act(() => vi.advanceTimersByTimeAsync(3000));
    const later = await screen.findByText(/^Tự gỡ lúc 22:40 · còn 58:5[0-9]$/);
    expect(later.textContent).not.toBe("Tự gỡ lúc 22:40 · còn 58:58");
    void first;
    expect(
      later.closest('[aria-live], [role="status"], [role="alert"], [role="timer"], [role="log"]'),
    ).toBeNull();
    await waitFor(() => expect(later).toBeInTheDocument());
  });
});

describe("the page itself", () => {
  it("has a heading and a table named for a screen reader, for every role", async () => {
    serve(server, fake({ rows: [review()] }));
    for (const role of ["tier1", "tier2", "admin"] as const) {
      const view = renderSoar({ role });
      expect(
        await screen.findByRole("heading", { level: 1, name: S.soar.title }),
      ).toBeInTheDocument();
      expect(await screen.findByRole("table", { name: S.soar.tableLabel })).toBeInTheDocument();
      view.unmount();
    }
  });

  it("never asks for a status of the closed set it does not know, and is not broken by an empty answer body", async () => {
    server.use(
      http.get("/api/soar/reviews/count", () =>
        HttpResponse.json({ count: 0, latest_received_at: null }),
      ),
      http.get("/api/soar/reviews", () =>
        HttpResponse.json({ rows: [], total: 0, page: 1, page_size: 50 }),
      ),
    );
    renderSoar();
    expect(await screen.findByText(S.soar.empty.open)).toBeInTheDocument();
    expect(NOW).toBeGreaterThan(0);
  });
});
