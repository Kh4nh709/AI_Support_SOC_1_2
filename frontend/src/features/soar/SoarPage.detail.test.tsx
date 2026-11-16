// src/features/soar/SoarPage.detail.test.tsx — the detail panel (it reads GET /api/soar/reviews/{id}): every field, the
// history, who decided and when, the result and the last error, the body n8n sent in a collapsed block, and the links to
// the alerts of the same case.
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterEach, vi } from "vitest";
import { S } from "../../strings";
import { detailOf, review } from "./fixtures";
import { SOAR_LIST_POLL_MS } from "./soarQueries";
import { fake, renderSoar, serve } from "./testkit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
});
afterAll(() => server.close());

const open = async (id = "K7QM2XHP") => {
  await userEvent.click(await screen.findByRole("button", { name: S.soar.detail.open(id) }));
  return screen.findByRole("region", { name: S.soar.detail.title(id) });
};
/** The value of a labelled field of the panel. */
const field = (panel: HTMLElement, label: string) => {
  const term = within(panel).getByText(label, { selector: "dt" });
  return term.nextElementSibling as HTMLElement;
};

describe("opening and closing", () => {
  it("opens from a row, reads the review by its id, and is named by its title", async () => {
    const state = fake({ rows: [review()] });
    serve(server, state);
    renderSoar();
    const panel = await open();
    expect(panel).toHaveTextContent("Chi tiết phiếu K7QM2XHP");
    expect(state.details).toContain("K7QM2XHP");
  });

  it("says it is loading, then shows", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    await userEvent.click(
      await screen.findByRole("button", { name: S.soar.detail.open("K7QM2XHP") }),
    );
    expect(
      screen.getByRole("region", { name: S.soar.detail.title("K7QM2XHP") }),
    ).toBeInTheDocument();
    await screen.findByText("Mã phiếu", { selector: "dt" });
  });

  it("closes with its button and gives the focus back to the row's button, and with Escape", async () => {
    serve(server, fake({ rows: [review()] }));
    renderSoar();
    const panel = await open();
    await userEvent.click(within(panel).getByRole("button", { name: S.soar.detail.close }));
    expect(
      screen.queryByRole("region", { name: S.soar.detail.title("K7QM2XHP") }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: S.soar.detail.open("K7QM2XHP") })).toHaveFocus();
    await open();
    await userEvent.keyboard("{Escape}");
    expect(
      screen.queryByRole("region", { name: S.soar.detail.title("K7QM2XHP") }),
    ).not.toBeInTheDocument();
  });

  it("moves to another ticket when its button is pressed", async () => {
    serve(server, fake({ rows: [review(), review({ id: "B2C3D4E5" })] }));
    renderSoar();
    await open("K7QM2XHP");
    await userEvent.click(screen.getByRole("button", { name: S.soar.detail.open("B2C3D4E5") }));
    expect(
      await screen.findByRole("region", { name: S.soar.detail.title("B2C3D4E5") }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("region", { name: S.soar.detail.title("K7QM2XHP") }),
    ).not.toBeInTheDocument();
  });

  it("stays open, with what it shows, when the list asks again", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const state = fake({ rows: [review()] });
    serve(server, state);
    renderSoar();
    const panel = await open();
    const before = state.lists.length;
    state.rows = [review({ note: "đã đổi", updated_at: "2026-11-13T14:50:00+00:00" })];
    await act(() => vi.advanceTimersByTimeAsync(SOAR_LIST_POLL_MS + 100));
    await waitFor(() => expect(state.lists.length).toBeGreaterThan(before));
    expect(screen.getByRole("region", { name: S.soar.detail.title("K7QM2XHP") })).toBe(panel);
    expect(field(panel, S.soar.detail.field.id)).toHaveTextContent("K7QM2XHP");
  });

  it("says the ticket is not there for a 404, and could not be loaded for a 500, with a retry", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () => HttpResponse.json({ detail: "not found" }, { status: 404 });
    serve(server, state);
    const view = renderSoar();
    const gone = await open();
    expect(await within(gone).findByText(S.soar.detail.notFound)).toBeInTheDocument();
    view.unmount();
    let fail = true;
    const broken = fake({ rows: [review()] });
    broken.detail = () => (fail ? HttpResponse.json({ detail: "x" }, { status: 500 }) : undefined);
    serve(server, broken);
    renderSoar();
    const panel = await open();
    expect(await within(panel).findByRole("alert")).toHaveTextContent(S.soar.detail.loadError);
    fail = false;
    await userEvent.click(within(panel).getByRole("button", { name: S.common.retry }));
    expect(await within(panel).findByText("Mã phiếu", { selector: "dt" })).toBeInTheDocument();
  });
});

describe("the fields", () => {
  const full = review({
    kind: "review",
    status: "undone",
    severity: "warning",
    title: "ĐÃ TỰ XỬ LÝ",
    simulated: true,
    case_id: "~4096",
    case_number: 65,
    action_agent: "wazuh-agent-3",
    host: "AD-server",
    agent_id: "003",
    user_name: "administrator",
    src_ip: "79.79.78.202",
    domain: "evil.example",
    remind_every_minutes: 30,
    next_remind_at: "2026-11-13T15:10:00+00:00",
    decided_by: "an",
    decided_at: "2026-11-13T14:50:10+00:00",
    result: "Đã gỡ chặn",
    last_error: "Lần trước hết giờ",
    locked_by: null,
    allowed_decisions: [],
    strong_warning: true,
  });

  it("shows every field of the review, the way the product shows times (+07)", async () => {
    serve(server, fake({ rows: [full] }));
    renderSoar({ entry: "/soar?tab=done" });
    const panel = await open();
    const F = S.soar.detail.field;
    const expected: [string, string][] = [
      [F.id, "K7QM2XHP"],
      [F.kind, "Phiếu duyệt"],
      [F.status, "Đã gỡ"],
      [F.severity, "Cảnh báo"],
      [F.title, "ĐÃ TỰ XỬ LÝ"],
      [F.simulated, "GIẢ LẬP"],
      [F.case, "#65"],
      [F.caseId, "~4096"],
      [F.action, "Chặn IP 79.79.78.202 trên pfSense"],
      [F.actionType, "Chặn IP"],
      [F.target, "79.79.78.202"],
      [F.via, "pfSense"],
      [F.actionAgent, "wazuh-agent-3"],
      [F.host, "AD-server"],
      [F.agentId, "003"],
      [F.user, "administrator"],
      [F.srcIp, "79.79.78.202"],
      [F.domain, "evil.example"],
      [F.scenario, "SC03 Quét cổng từ bên ngoài"],
      [F.score, "50"],
      [F.note, "Đã chặn 79.79.78.202 trên pfSense, tự gỡ 22:40"],
      [F.createdAt, "13/11/2026 21:40:03"],
      [F.autoExpireAt, "13/11/2026 22:40:03"],
      [F.remind, "mỗi 30 phút"],
      [F.nextRemindAt, "13/11/2026 22:10:00"],
      [F.decidedBy, "an"],
      [F.decidedAt, "13/11/2026 21:50:10"],
      [F.result, "Đã gỡ chặn"],
      [F.lastError, "Lần trước hết giờ"],
      [F.lastSentAt, "13/11/2026 21:40:05"],
      [F.receivedAt, "13/11/2026 21:40:05"],
      [F.updatedAt, "13/11/2026 21:40:05"],
      [F.buttons, "✅ Giữ chặn, ↩️ Gỡ chặn IP"],
      [F.strong, S.soar.detail.yes],
    ];
    expect(F.receivedAt).toBe("Web nhận lúc");
    for (const [label, value] of expected) {
      expect(field(panel, label), label).toHaveTextContent(value);
    }
  });

  it("shows who holds a ticket that is being processed, and leaves out what has no value", async () => {
    serve(
      server,
      fake({
        rows: [
          review({
            status: "processing",
            locked_by: "binh",
            locked_at: "2026-11-13T14:40:50+00:00",
            allowed_decisions: [],
            decided_by: null,
            result: null,
            last_error: null,
            domain: null,
          }),
        ],
      }),
    );
    renderSoar();
    const panel = await open();
    expect(field(panel, S.soar.detail.field.lockedBy)).toHaveTextContent("binh");
    expect(field(panel, S.soar.detail.field.lockedAt)).toHaveTextContent("13/11/2026 21:40:50");
    for (const label of [
      S.soar.detail.field.decidedBy,
      S.soar.detail.field.result,
      S.soar.detail.field.lastError,
      S.soar.detail.field.domain,
    ]) {
      expect(within(panel).queryByText(label, { selector: "dt" })).not.toBeInTheDocument();
    }
  });
});

describe("the history", () => {
  const history = [
    {
      at: "2026-11-13T14:40:05+00:00",
      event: "soar.review_received",
      actor: "system",
      actor_role: null,
      payload: {
        event: "created",
        kind: "review",
        outcome: "created",
        reason: null,
        status: "open",
      },
    },
    {
      at: "2026-11-13T14:45:00+00:00",
      event: "soar.review_decided",
      actor: "an",
      actor_role: "tier2",
      payload: {
        decision: "undo",
        note: "máy sạch",
        outcome: "ok",
        status_before: "open",
        status_after: "undone",
        message: "Đã gỡ chặn",
      },
    },
    {
      at: "2026-11-13T14:46:00+00:00",
      event: "soar.review_received",
      actor: "system",
      actor_role: null,
      payload: {
        event: "updated",
        kind: "review",
        outcome: "ignored",
        reason: "stale",
        status: "open",
      },
    },
  ];

  it("lists each event with its time, the event in Vietnamese, who, and the outcome", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () => detailOf({ history });
    serve(server, state);
    renderSoar();
    const panel = await open();
    const table = within(panel).getByRole("table", { name: S.soar.detail.history.label });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((th) => th.textContent),
    ).toEqual(["Thời gian", "Sự kiện", "Ai", "Kết quả", "Chi tiết"]);
    const rows = within(table).getAllByRole("row").slice(1);
    const cells = (row: HTMLElement) =>
      within(row)
        .getAllByRole("cell")
        .map((c) => c.textContent);
    expect(cells(rows[0] as HTMLElement).slice(0, 4)).toEqual([
      "13/11/2026 21:40:05",
      "Nhận phiếu từ SOAR",
      "Hệ thống",
      "Tạo mới",
    ]);
    expect(cells(rows[1] as HTMLElement).slice(0, 4)).toEqual([
      "13/11/2026 21:45:00",
      "Quyết định trên web",
      "an (Tier 2)",
      "Thành công",
    ]);
    expect(cells(rows[2] as HTMLElement).slice(0, 4)).toEqual([
      "13/11/2026 21:46:00",
      "Nhận phiếu từ SOAR",
      "Hệ thống",
      "Bỏ qua",
    ]);
  });

  // The backend serves `actor` as the username of a person (null for the system) and `actor_role` as tier1, tier2, admin or system.
  it("says Hệ thống for an event of the system, as the backend serves it (no actor, the role system)", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () =>
      detailOf({
        history: [
          {
            at: "2026-11-13T14:40:05+00:00",
            event: "soar.review_received",
            actor: null,
            actor_role: "system",
            payload: { event: "created", outcome: "created", status: "open" },
          },
          {
            at: "2026-11-13T14:41:05+00:00",
            event: "soar.review_decided",
            actor: "an",
            actor_role: "tier2",
            payload: { decision: "keep", outcome: "ok" },
          },
          {
            at: "2026-11-13T14:42:05+00:00",
            event: "soar.review_decided",
            actor: null,
            actor_role: "analyst",
            payload: { decision: "keep", outcome: "ok" },
          },
          {
            at: "2026-11-13T14:43:05+00:00",
            event: "soar.review_received",
            actor: null,
            actor_role: null,
            payload: null,
          },
          {
            at: "2026-11-13T14:44:05+00:00",
            event: "soar.review_received",
            actor: "system",
            actor_role: null,
            payload: null,
          },
        ],
      });
    serve(server, state);
    renderSoar();
    const panel = await open();
    const table = await within(panel).findByRole("table", { name: S.soar.detail.history.label });
    const who = within(table)
      .getAllByRole("row")
      .slice(1)
      .map((row) => within(row).getAllByRole("cell")[2]?.textContent);
    expect(who).toEqual(["Hệ thống", "an (Tier 2)", "analyst", "—", "Hệ thống"]);
  });

  it("says in the detail column what was decided, the note, the change of status and n8n's message", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () => detailOf({ history });
    serve(server, state);
    renderSoar();
    const panel = await open();
    const table = within(panel).getByRole("table", { name: S.soar.detail.history.label });
    const [, , decided, ignored] = within(table).getAllByRole("row");
    expect(within(decided as HTMLElement).getByText("Quyết định: Gỡ")).toBeInTheDocument();
    expect(within(decided as HTMLElement).getByText("Ghi chú: máy sạch")).toBeInTheDocument();
    expect(within(decided as HTMLElement).getByText("Đang mở → Đã gỡ")).toBeInTheDocument();
    expect(within(decided as HTMLElement).getByText("Đã gỡ chặn")).toBeInTheDocument();
    expect(
      within(ignored as HTMLElement).getByText("Lý do: bản cũ hơn bản đã lưu"),
    ).toBeInTheDocument();
  });

  it("shows an event, an outcome and an actor it has no word for as they came, and survives a payload that is not an object", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () =>
      detailOf({
        history: [
          {
            at: "2026-11-13T14:40:05+00:00",
            event: "soar.something_new",
            actor: "robot",
            actor_role: "bot",
            payload: { outcome: "exploded" },
          },
          {
            at: "2026-11-13T14:41:05+00:00",
            event: "soar.review_decided",
            actor: null,
            actor_role: null,
            payload: null,
          },
          {
            at: "not a time",
            event: "soar.review_received",
            actor: "system",
            actor_role: null,
            payload: "x" as never,
          },
        ],
      });
    serve(server, state);
    renderSoar();
    const panel = await open();
    const table = within(panel).getByRole("table", { name: S.soar.detail.history.label });
    const rows = within(table).getAllByRole("row").slice(1);
    const first = within(rows[0] as HTMLElement).getAllByRole("cell");
    expect(first[1]).toHaveTextContent("soar.something_new");
    expect(first[2]).toHaveTextContent("robot (bot)");
    expect(first[3]).toHaveTextContent("exploded");
    expect(within(rows[2] as HTMLElement).getAllByRole("cell")[0]).toHaveTextContent("not a time");
  });

  it("says when there is no history", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () => detailOf({ history: [] });
    serve(server, state);
    renderSoar();
    const panel = await open();
    expect(await within(panel).findByText(S.soar.detail.history.empty)).toBeInTheDocument();
  });
});

describe("the body n8n sent", () => {
  it("is in a block that is closed until opened, and is text", async () => {
    const raw = { schema_version: "1.0", id: "K7QM2XHP", title: "<b>x</b>", nested: { a: [1, 2] } };
    const state = fake({ rows: [review()] });
    state.detail = () => detailOf({ raw });
    serve(server, state);
    renderSoar();
    const panel = await open();
    const block = (await within(panel).findByText(S.soar.detail.raw.summary)).closest(
      "details",
    ) as HTMLDetailsElement;
    expect(block).not.toHaveAttribute("open");
    const text = block.querySelector("pre");
    expect(text?.textContent).toBe(JSON.stringify(raw, null, 2));
    expect(block.querySelector("b")).toBeNull();
    expect(text?.className).toContain("whitespace-pre-wrap");
  });

  it("shows a body that is a string as it is, and says when there is none", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () => detailOf({ raw: "chuỗi gốc <i>không phải HTML</i>" });
    serve(server, state);
    const view = renderSoar();
    const panel = await open();
    expect(
      (await within(panel).findByText(S.soar.detail.raw.summary))
        .closest("details")
        ?.querySelector("pre")?.textContent,
    ).toBe("chuỗi gốc <i>không phải HTML</i>");
    view.unmount();
    const none = fake({ rows: [review()] });
    none.detail = () => detailOf({ raw: null });
    serve(server, none);
    renderSoar();
    const empty = await open();
    expect(await within(empty).findByText(S.soar.detail.raw.empty)).toBeInTheDocument();
  });
});

describe("the alerts of the same case", () => {
  const alert = (n: number, over = {}) => ({
    alert_id: `alert-${n}`,
    alert_time: "2026-11-13T14:30:00+00:00",
    agent_name: `agent-${n}`,
    description: `Mô tả ${n}`,
    severity: "high",
    status: "queued_tier1",
    occurrence_count: 2,
    ...over,
  });

  it("links each to /alerts/<id>, with its time, host, description and status", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () =>
      detailOf({ related_alerts: [alert(1), alert(2, { status: "closed_fp" })], related_total: 2 });
    serve(server, state);
    renderSoar();
    const panel = await open();
    const list = await within(panel).findByRole("list", { name: S.soar.detail.related.label });
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    const link = within(items[0] as HTMLElement).getByRole("link", { name: "Mô tả 1" });
    expect(link).toHaveAttribute("href", "/alerts/alert-1");
    expect(items[0]).toHaveTextContent("13/11 21:30");
    expect(items[0]).toHaveTextContent("agent-1");
    expect(items[0]).toHaveTextContent("Chờ xử lý");
    // m9: the severity and the number of occurrences, in the product's words
    expect(within(items[0] as HTMLElement).getByText("Mức Cao")).toBeInTheDocument();
    expect(within(items[0] as HTMLElement).getByText("2 lần xuất hiện")).toBeInTheDocument();
    expect(S.soar.detail.related.severity("Cao")).toBe("Mức Cao");
    expect(S.soar.detail.related.occurrences(2)).toBe("2 lần xuất hiện");
    expect(items[1]).toHaveTextContent("Đã đóng — dương tính giả");
  });

  it("encodes the alert id in the link, so no id can change the path", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () =>
      detailOf({
        related_alerts: [alert(1, { alert_id: "a/b c?d#e", description: "Lạ" })],
        related_total: 1,
      });
    serve(server, state);
    renderSoar();
    const panel = await open();
    expect(await within(panel).findByRole("link", { name: "Lạ" })).toHaveAttribute(
      "href",
      `/alerts/${encodeURIComponent("a/b c?d#e")}`,
    );
  });

  it("says +N when the case has more alerts than the list carries", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () => detailOf({ related_alerts: [alert(1), alert(2)], related_total: 5 });
    serve(server, state);
    renderSoar();
    const panel = await open();
    const more = await within(panel).findByText("+3 alert khác");
    // plain text: it leads nowhere, so it is neither a link nor a button, and nothing in it can be pressed
    expect(more.tagName).toBe("P");
    expect(more.closest("a, button, [role=link], [role=button]")).toBeNull();
    expect(S.soar.detail.related.more(3)).toBe("+3 alert khác");
  });

  it("says no more when the list is all of them, and that there are none when there are none", async () => {
    const state = fake({ rows: [review()] });
    state.detail = () => detailOf({ related_alerts: [alert(1)], related_total: 1 });
    serve(server, state);
    const view = renderSoar();
    const panel = await open();
    await within(panel).findByRole("link", { name: "Mô tả 1" });
    expect(within(panel).queryByText(/^\+\d+ alert khác$/)).not.toBeInTheDocument();
    view.unmount();
    const none = fake({ rows: [review()] });
    none.detail = () => detailOf({ related_alerts: [], related_total: 0 });
    serve(server, none);
    renderSoar();
    const empty = await open();
    expect(await within(empty).findByText(S.soar.detail.related.empty)).toBeInTheDocument();
  });
});
