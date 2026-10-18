// src/features/admin/AuditPage.test.tsx — `/admin/audit` (P11-T17, spec §4.7): the canvas's AdminAudit and the
// AUDIT cards of AdminStates, over MSW. The page is read-only, so the only request it may make is
// `GET /api/admin/audit`, and a test says so. The filters live in the URL: a `Where` probe shows it. Every
// answer the route can give is shown where the spec puts it (a field, the region above the table, or the
// page), and the payload of a hostile event is shown as text and executes nothing (Review Focus 3).
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router";
import type { AuditEvent, AuditResponse } from "../../api/admin";
import { createQueryClient } from "../../api/queryClient";
import { S } from "../../strings";
import { adminKeys, invalidateAfter } from "./adminKeys";
import { AdminLayout } from "./AdminLayout";
import { AuditPage } from "./AuditPage";
import { hasInvisible } from "./auditSummary";

const P = S.admin.auditPage;
const URL_AUDIT = "/api/admin/audit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// --- the data: the canvas's events, made consistent with each other ----------------------------------------

const ALERT = "1759012345.1662100";
const ALERT_2 = "1759012345.1661502";
const CASE = "0b30b853-1c2d-4e5f-8a9b-000000000001";
const USER = "5f1c9a02-7b3d-4c10-9a55-0000000000a2";
const RULE = "7c1d0e44-52a1-4f0e-8b11-000000000042";

const ev = (audit_id: number, over: Partial<AuditEvent> = {}): AuditEvent => ({
  audit_id,
  created_at: "2026-09-30T02:41:00+00:00", // 30/09 09:41 in Asia/Ho_Chi_Minh
  event_type: "alert.received",
  actor_role: "system",
  actor_username: null,
  subject_id: `1759012345.${1_662_000 + audit_id}`,
  payload: null,
  ...over,
});

/** The nine rows of the canvas and a case, newest first. */
const CANVAS: AuditEvent[] = [
  ev(10, {
    event_type: "admin.user_updated",
    actor_role: "admin",
    actor_username: "hoa.admin",
    subject_id: USER,
    payload: {
      username: "an.t2",
      before: { role: "tier1", is_active: true },
      after: { role: "tier2", is_active: true },
    },
  }),
  ev(9, {
    created_at: "2026-09-30T02:38:00+00:00",
    event_type: "admin.settings_changed",
    actor_role: "admin",
    actor_username: "hoa.admin",
    subject_id: "llm_limits",
    payload: { changes: [{ key: "LLM_MONTHLY_USD_CAP", old: 30, new: 40 }] },
  }),
  ev(8, {
    created_at: "2026-09-30T02:31:00+00:00",
    event_type: "tier1.decided",
    actor_role: "analyst",
    actor_username: "lan.t1",
    subject_id: ALERT,
    payload: { decision: "closed_fp", reason: "Báo động giả", occurrence_count: 3 },
  }),
  ev(7, {
    created_at: "2026-09-30T02:31:00+00:00",
    event_type: "triage.suggested",
    actor_role: "llm",
    subject_id: ALERT,
    payload: { suggested_action: "false_positive", confidence: "high", forced: false, run_id: "r" },
  }),
  ev(6, {
    created_at: "2026-09-30T02:12:00+00:00",
    event_type: "admin.autoclose_rule_toggled",
    actor_role: "admin",
    actor_username: "hoa.admin",
    subject_id: RULE,
    payload: { name: "Thử nghiệm: quét DNS", before: true, after: false },
  }),
  ev(5, {
    created_at: "2026-09-30T01:15:00+00:00",
    event_type: "autoclose.reviewed",
    actor_role: "admin",
    actor_username: "khanh-admin",
    subject_id: ALERT_2,
    payload: { verdict: "unsure", autoclose_rule_id: RULE, suggested_action: null, run_id: null },
  }),
  ev(4, {
    created_at: "2026-09-30T01:05:00+00:00",
    event_type: "admin.job_retried",
    actor_role: "admin",
    actor_username: "hoa.admin",
    subject_id: "100412",
    payload: {
      job_id: 100412,
      job_type: "triage",
      subject_id: ALERT,
      attempts_before: 3,
      last_error: "timeout after 120s",
    },
  }),
  ev(3, {
    created_at: "2026-09-30T00:58:00+00:00",
    event_type: "authz.denied",
    actor_role: "analyst",
    actor_username: "lan.t1",
    subject_id: "/api/admin/users",
    payload: { required: ["admin"], role: "tier1", method: "GET" },
  }),
  ev(2, {
    created_at: "2026-09-30T00:40:00+00:00",
    event_type: "health.alarm",
    actor_role: "system",
    subject_id: "system",
    payload: { failing: ["backup_age"], new: ["backup_age"] },
  }),
  ev(1, {
    created_at: "2026-09-30T00:30:00+00:00",
    event_type: "case.opened",
    actor_role: "analyst",
    actor_username: "minh.t2",
    subject_id: CASE,
    payload: { trigger_alert_id: ALERT, alert_count: 3, correlated_count: 2 },
  }),
];

/** `n` events, newest first, ids `n` down to 1, for the tests of the cursor. */
const MANY = (n: number): AuditEvent[] => Array.from({ length: n }, (_, i) => ev(n - i));

/** The answer of the route to a cursor and a limit over a list, as the handler pages it. */
function pageOf(
  events: AuditEvent[],
  query: URLSearchParams,
  total: number | null = events.length,
): AuditResponse {
  const limit = Number(query.get("limit") ?? 50);
  const cursor = query.get("cursor");
  const older = cursor === null ? events : events.filter((e) => e.audit_id < Number(cursor));
  const page = older.slice(0, limit);
  return {
    events: page,
    next_cursor: page.length === limit ? (page[page.length - 1]?.audit_id ?? null) : null,
    total,
  };
}

// --- the server ----------------------------------------------------------------------------------------------

/** What a test answers with: a body (sent as JSON), a response, or a function that makes one. */
type Answer = JsonBodyType | Response | (() => Response | Promise<Response>);
const respond = (answer: Answer): Response | Promise<Response> =>
  answer instanceof Response
    ? answer
    : typeof answer === "function"
      ? answer()
      : HttpResponse.json(answer);
const status =
  (code: number, body: JsonBodyType = null) =>
  () =>
    HttpResponse.json(body, { status: code });
const reason = (code: number, why: string) => status(code, { detail: { reason: why } });
const networkError = () => HttpResponse.error();
/** FastAPI's own 422: a list of `{type, loc, msg, input}`. */
const invalid = (name: string | null) =>
  status(422, {
    detail: [
      {
        type: "value_error",
        loc: name === null ? ["query"] : ["query", name],
        msg: "Value error, must not contain a NUL byte",
        input: "x",
      },
    ],
  });

type Served = {
  /** The query string of every GET of the route, in order. */
  gets: URLSearchParams[];
  /** Every other request that reached `/api/`: there must be none. */
  others: string[];
};

/** Serves the route with `answer(query, n)` (n counts from 0); anything else under `/api/` is logged and refused. */
function serve(answer: (query: URLSearchParams, n: number) => Answer | Promise<Answer>): Served {
  const log: Served = { gets: [], others: [] };
  server.use(
    http.get(URL_AUDIT, async ({ request }) => {
      const query = new URL(request.url).searchParams;
      log.gets.push(query);
      return respond(await answer(query, log.gets.length - 1));
    }),
    http.all("/api/*", ({ request }) => {
      log.others.push(`${request.method} ${new URL(request.url).pathname}`);
      return HttpResponse.json(null, { status: 599 });
    }),
  );
  return log;
}

/** The common case: a list served with the cursor and the limit the page sends. */
const serveList = (events: AuditEvent[], total?: number | null) =>
  serve((query) => pageOf(events, query, total));

// --- the page --------------------------------------------------------------------------------------------------

function Where() {
  const location = useLocation();
  return <p data-testid="where">{`${location.pathname}${location.search}`}</p>;
}

function Back() {
  const navigate = useNavigate();
  return (
    <button type="button" onClick={() => void navigate(-1)}>
      back
    </button>
  );
}

const testClient = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });

function renderPage(
  path = "/admin/audit",
  client: QueryClient = testClient(),
  options: { layout?: boolean } = {},
) {
  const page = <AuditPage />;
  const result = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Back />
        <Where />
        <Routes>
          <Route
            path="/admin/audit"
            element={
              options.layout ? (
                <>
                  <header>
                    <span>AI Support SOC</span>
                  </header>
                  <main>
                    <AdminLayout>{page}</AdminLayout>
                  </main>
                </>
              ) : (
                page
              )
            }
          />
          <Route path="*" element={<p>elsewhere</p>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { client, ...result };
}

const where = () => screen.getByTestId("where").textContent;
const form = () => screen.getByRole("form", { name: P.filtersLabel });
const rangeSelect = () => within(form()).getByLabelText(P.rangeLabel) as HTMLSelectElement;
const groupSelect = () => within(form()).getByLabelText(P.groupLabel) as HTMLSelectElement;
const actorInput = () => within(form()).getByLabelText(P.actorLabel) as HTMLInputElement;
const subjectInput = () => within(form()).getByLabelText(P.subjectLabel) as HTMLInputElement;
const table = () => screen.getByRole("table", { name: P.table });
const row = (auditId: number) => {
  const element = table().querySelector(`tr[data-audit-id="${auditId}"]`);
  if (!(element instanceof HTMLTableRowElement)) throw new Error(`no row for event ${auditId}`);
  return element;
};
const rowCount = () => table().querySelectorAll("tr[data-audit-id]").length;
/** The columns of a row, by position: the toggle, the time, the event, the actor, the subject, the summary. */
const ACTOR = 3;
const SUBJECT = 4;
const SUMMARY = 5;
const cellOf = (auditId: number, column: number) =>
  row(auditId).querySelectorAll("td")[column] as HTMLElement;
const pager = () => screen.getByRole("navigation", { name: P.pager });
const prevButton = () => within(pager()).getByRole("button", { name: P.prev });
const nextButton = () => within(pager()).getByRole("button", { name: P.next });
const toggleOf = (auditId: number) =>
  within(row(auditId)).getByRole("button", { name: /payload/i });

/** The first read has answered: the table is on screen. */
const loaded = () => screen.findByRole("table", { name: P.table });

describe("the page", () => {
  it("shows the heading, the read-only sentence, and the filter form with its four filters and two buttons", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    expect(screen.getByRole("heading", { level: 1, name: "Nhật ký audit" })).toBeInTheDocument();
    expect(S.admin.title.audit).toBe("Nhật ký audit");
    expect(screen.getByText(P.subtitle)).toBeInTheDocument();
    expect(form()).toBeInTheDocument();
    expect(rangeSelect().value).toBe("7d");
    expect(
      within(rangeSelect())
        .getAllByRole("option")
        .map((o) => o.textContent),
    ).toEqual(["24 giờ qua", "7 ngày qua", "30 ngày qua"]);
    expect(groupSelect().value).toBe("");
    expect(
      within(groupSelect())
        .getAllByRole("option")
        .map((o) => o.textContent),
    ).toEqual([
      "Tất cả",
      "Người dùng và quyền",
      "Rules, digest, hạn mức",
      "Alert và case",
      "Model và cổng kiểm soát",
      "Hệ thống và job",
    ]);
    expect(actorInput().value).toBe("");
    expect(actorInput()).toHaveAttribute("placeholder", "username, system, llm");
    expect(subjectInput().value).toBe("");
    expect(subjectInput()).toHaveAttribute("placeholder", "mã alert, case, rule, user");
    expect(within(form()).getByRole("button", { name: "Lọc" })).toHaveAttribute("type", "submit");
    expect(within(form()).getByRole("button", { name: "Xoá lọc" })).toBeInTheDocument();
  });

  it("asks for seven days and fifty rows, with no other filter, and writes nothing in the URL", async () => {
    const served = serveList(CANVAS);
    renderPage();
    await loaded();
    expect(served.gets).toHaveLength(1);
    expect(Object.fromEntries(served.gets[0] ?? [])).toEqual({ range: "7d", limit: "50" });
    expect(where()).toBe("/admin/audit");
  });

  it("has the columns of the canvas, and one row for each event, newest first", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    const headers = within(table())
      .getAllByRole("columnheader")
      .map((h) => h.textContent);
    expect(headers).toEqual([
      P.colToggle,
      "Thời điểm",
      "Sự kiện",
      "Người thực hiện",
      "Đối tượng",
      "Tóm tắt",
    ]);
    const ids = [...table().querySelectorAll("tr[data-audit-id]")].map((tr) =>
      tr.getAttribute("data-audit-id"),
    );
    expect(ids).toEqual(["10", "9", "8", "7", "6", "5", "4", "3", "2", "1"]);
  });

  it("shows the time in Ho Chi Minh, with the whole date and time in its title", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    const time = within(row(10)).getByText("30/09 09:41");
    expect(time.tagName).toBe("TIME");
    expect(time).toHaveAttribute("title", "30/09/2026 09:41:00");
    expect(time).toHaveAttribute("datetime", "2026-09-30T02:41:00+00:00");
    expect(within(row(5)).getByText("30/09 08:15")).toBeInTheDocument();
  });

  it("names the event in Vietnamese, with the raw event type under it", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    const cell = within(row(10));
    expect(cell.getByText("Cập nhật người dùng")).toBeInTheDocument();
    expect(cell.getByText("admin.user_updated")).toBeInTheDocument();
    expect(within(row(9)).getByText("Sửa hạn mức LLM")).toBeInTheDocument();
    expect(within(row(3)).getByText("Bị từ chối quyền")).toBeInTheDocument();
    expect(within(row(3)).getByText("authz.denied")).toBeInTheDocument();
  });

  it("shows an event type it has no label for as the code, and does not crash", async () => {
    serveList([ev(2, { event_type: "alert.brand_new" }), ev(1, { event_type: "constructor" })]);
    renderPage();
    await loaded();
    expect(within(row(2)).getAllByText("alert.brand_new")).toHaveLength(2); // the label is the code, and the code under it
    expect(within(row(1)).getAllByText("constructor")).toHaveLength(2);
    expect(within(row(2)).getByText("—")).toBeInTheDocument(); // no summary for it
  });

  it("shows the actor: the username when there is one, and a role badge for system, llm, analyst and admin", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    const admin = within(row(10));
    expect(admin.getByText("hoa.admin")).toBeInTheDocument();
    expect(admin.getByText("admin")).toBeInTheDocument();
    const analyst = within(row(8));
    expect(analyst.getByText("lan.t1")).toBeInTheDocument();
    expect(analyst.getByText("analyst")).toBeInTheDocument();
    const model = within(row(7));
    expect(model.getByText("llm")).toBeInTheDocument();
    expect(within(cellOf(2, ACTOR)).getByText("system")).toBeInTheDocument();
  });

  it("shows no username for system and llm: the badge alone is the actor", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    expect(cellOf(7, ACTOR).textContent).toBe("llm");
    expect(cellOf(2, ACTOR).textContent).toBe("system");
    expect(cellOf(10, ACTOR).textContent).toBe("hoa.admin admin");
  });

  it("shows a person's row with no username (their account is gone) with the role badge alone", async () => {
    serveList([ev(1, { actor_role: "analyst", actor_username: null })]);
    renderPage();
    await loaded();
    expect(cellOf(1, ACTOR).textContent).toBe("analyst");
  });

  it("links the subject of an alert event to the alert and of a case event to the case", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    expect(within(row(8)).getByRole("link", { name: ALERT })).toHaveAttribute(
      "href",
      `/alerts/${ALERT}`,
    );
    expect(within(row(7)).getByRole("link", { name: ALERT })).toHaveAttribute(
      "href",
      `/alerts/${ALERT}`,
    );
    expect(within(row(5)).getByRole("link", { name: ALERT_2 })).toHaveAttribute(
      "href",
      `/alerts/${ALERT_2}`,
    );
    expect(within(row(1)).getByRole("link", { name: CASE })).toHaveAttribute(
      "href",
      `/cases/${CASE}`,
    );
  });

  it("shows any other subject, a rule, a user, a job, a limit, a path, a check, as text and no link", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    for (const [id, subject] of [
      [10, USER],
      [9, "llm_limits"],
      [6, RULE],
      [4, "100412"],
      [3, "/api/admin/users"],
      [2, "system"],
    ] as const) {
      expect(within(cellOf(id, SUBJECT)).getByText(subject)).toBeInTheDocument();
      expect(within(row(id)).queryByRole("link")).not.toBeInTheDocument();
    }
  });

  it("encodes a subject id in the link, so a slash or a question mark cannot leave its segment", async () => {
    serveList([ev(1, { subject_id: "a/b?c#d e" })]);
    renderPage();
    await loaded();
    expect(within(row(1)).getByRole("link", { name: "a/b?c#d e" })).toHaveAttribute(
      "href",
      "/alerts/a%2Fb%3Fc%23d%20e",
    );
  });

  it("gives each event the one-line summary of its type, built from its payload", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    expect(
      within(row(10)).getByText("an.t2: vai trò Tier 1 → Tier 2; phiên cũ bị đăng xuất"),
    ).toBeInTheDocument();
    expect(within(row(9)).getByText("trần chi phí (USD mỗi tháng) 30 → 40")).toBeInTheDocument();
    expect(
      within(row(8)).getByText("quyết định: Đã đóng — dương tính giả; lý do: Báo động giả"),
    ).toBeInTheDocument();
    expect(
      within(row(7)).getByText("đề xuất ①: Dương tính giả; độ tin cậy cao"),
    ).toBeInTheDocument();
    expect(within(row(6)).getByText("“Thử nghiệm: quét DNS”: bật → tắt")).toBeInTheDocument();
    expect(within(row(5)).getByText("duyệt: Không chắc")).toBeInTheDocument();
    expect(
      within(row(4)).getByText("chạy lại job triage #100412; trước đó đã thử 3 lần"),
    ).toBeInTheDocument();
    expect(
      within(row(3)).getByText("GET: cần vai trò Admin; tài khoản là Tier 1"),
    ).toBeInTheDocument();
    expect(
      within(row(2)).getByText("mới lỗi: Bản sao lưu gần nhất; đang lỗi: Bản sao lưu gần nhất"),
    ).toBeInTheDocument();
    expect(
      within(row(1)).getByText("mở từ alert 1759012345.1662100; 3 alert, 2 liên quan"),
    ).toBeInTheDocument();
  });

  it("marks the denied and the alarm rows, which the canvas tints", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    expect(row(3)).toHaveAttribute("data-alarm", "true");
    expect(row(2)).toHaveAttribute("data-alarm", "true");
    for (const id of [10, 9, 8, 7, 6, 5, 4, 1]) expect(row(id)).not.toHaveAttribute("data-alarm");
  });

  it("makes no request but the one read: it is read-only", async () => {
    const served = serveList(CANVAS);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(toggleOf(10));
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    await user.click(within(form()).getByRole("button", { name: P.clear }));
    expect(served.others).toEqual([]);
  });
});

describe("the payload of an event", () => {
  it("is not shown until the row is opened, and the toggle says what it does", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    const toggle = toggleOf(10);
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveAccessibleName("Xem payload: Cập nhật người dùng, 30/09 09:41");
    expect(toggle).not.toHaveAttribute("aria-controls");
    expect(screen.queryByRole("region", { name: P.payloadLabel(10) })).not.toBeInTheDocument();
  });

  it("opens in a LogBlock as pretty-printed JSON text, and closes again", async () => {
    serveList(CANVAS);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(toggleOf(10));
    const region = screen.getByRole("region", { name: P.payloadLabel(10) });
    expect(region.tagName).toBe("PRE");
    expect(region.textContent).toBe(JSON.stringify(CANVAS[0]?.payload, null, 2));
    const toggle = toggleOf(10);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(toggle).toHaveAccessibleName("Ẩn payload: Cập nhật người dùng, 30/09 09:41");
    const controlled = document.getElementById(toggle.getAttribute("aria-controls") ?? "");
    expect(controlled).not.toBeNull();
    expect(controlled).toContainElement(region);
    expect(screen.getByText(P.payloadNote)).toBeInTheDocument();
    // The copy button is named after the payload it copies (two may be open at once).
    expect(
      within(controlled as HTMLElement).getByRole("button", {
        name: `${S.common.copy}: ${P.payloadLabel(10)}`,
      }),
    ).toBeInTheDocument();

    await user.click(toggleOf(10));
    expect(screen.queryByRole("region", { name: P.payloadLabel(10) })).not.toBeInTheDocument();
    expect(toggleOf(10)).toHaveAttribute("aria-expanded", "false");
  });

  it("opens two rows at once, each with its own region, and the payload row follows its event", async () => {
    serveList(CANVAS);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(toggleOf(10));
    await user.click(toggleOf(8));
    expect(screen.getByRole("region", { name: P.payloadLabel(10) })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: P.payloadLabel(8) })).toBeInTheDocument();
    expect(row(10).nextElementSibling?.querySelector("pre")).not.toBeNull();
    expect(row(8).nextElementSibling?.querySelector("pre")).not.toBeNull();
    expect(row(9).nextElementSibling).toBe(row(8));
    // Each region has a copy button of its own, and the two are told apart by name.
    expect(
      screen.getByRole("button", { name: `${S.common.copy}: ${P.payloadLabel(10)}` }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: `${S.common.copy}: ${P.payloadLabel(8)}` }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.common.copy })).not.toBeInTheDocument();
  });

  it("says an event with no payload has none, and shows no block for it", async () => {
    serveList([ev(1, { payload: null })]);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(toggleOf(1));
    expect(screen.getByText(P.noPayload)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: P.payloadLabel(1) })).not.toBeInTheDocument();
  });

  it("says a payload the server cut was too big, with its size, and shows what it sent", async () => {
    serveList([ev(1, { event_type: "case.opened", payload: { truncated: true, size: 70000 } })]);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    expect(
      within(row(1)).getByText("payload quá lớn (70.000 byte), server không gửi nội dung"),
    ).toBeInTheDocument();
    await user.click(toggleOf(1));
    expect(screen.getByText(P.payloadTooBig("70.000"))).toBeInTheDocument();
    expect(screen.getByRole("region", { name: P.payloadLabel(1) }).textContent).toBe(
      '{\n  "truncated": true,\n  "size": 70000\n}',
    );
  });

  it("shows the server's redaction marker where it put it, at any depth", async () => {
    const payload = {
      db: { password: "[đã ẩn]" },
      list: [{ api_key: "[đã ẩn]", name: "visible" }],
      access_token: "[đã ẩn]",
    };
    serveList([ev(1, { payload })]);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(toggleOf(1));
    const text = screen.getByRole("region", { name: P.payloadLabel(1) }).textContent ?? "";
    expect(text).toContain('"password": "[đã ẩn]"');
    expect(text).toContain('"api_key": "[đã ẩn]"');
    expect(text).toContain('"access_token": "[đã ẩn]"');
    expect(text).toContain('"name": "visible"');
  });

  it("keeps a row open when the list is read again", async () => {
    serveList(CANVAS);
    const user = userEvent.setup();
    const { client } = renderPage();
    await loaded();
    await user.click(toggleOf(10));
    await act(async () => {
      await client.invalidateQueries({ queryKey: adminKeys.auditAll });
    });
    expect(screen.getByRole("region", { name: P.payloadLabel(10) })).toBeInTheDocument();
  });
});

// DEC-204: both labellers are admins and can open this page, and labelling is blind between them. The server
// redacts `label` and `confidence` of a `label.created` payload; the page must not depend on it. The line says
// that someone labelled a cluster, and the payload, opened, is whatever the server sent, as text.
describe("a label.created event (DEC-204)", () => {
  const labelled = (id: number, payload: unknown) =>
    ev(id, {
      event_type: "label.created",
      actor_role: "admin",
      actor_username: "khanh-admin",
      subject_id: ALERT,
      payload,
    });
  const BASE = { alert_id: ALERT, labeler_id: "u-1", gold_set: "gold_v2" };
  const LINE = `gán nhãn cụm ${ALERT}; tập gold_v2`;
  const VERDICT =
    /escalate|benign|false_positive|chuyển tier 2|lành tính|dương tính giả|độ tin cậy/;

  it("says that a cluster was labelled, and never the verdict, though the payload still carries it", async () => {
    serveList([
      labelled(2, { ...BASE, label: "escalate", confidence: 3 }),
      labelled(1, { ...BASE, label: "benign", confidence: 1 }),
    ]);
    renderPage();
    await loaded();
    for (const id of [2, 1]) {
      expect(cellOf(id, SUMMARY).textContent).toBe(LINE);
      expect(row(id).textContent).not.toMatch(VERDICT);
    }
    expect(within(row(2)).getByRole("link", { name: ALERT })).toHaveAttribute(
      "href",
      `/alerts/${ALERT}`,
    );
  });

  it("shows the payload as the server sent it, as text, when the row is opened", async () => {
    const payload = { ...BASE, label: "escalate", confidence: 3 };
    serveList([labelled(1, payload)]);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(toggleOf(1));
    expect(screen.getByRole("region", { name: P.payloadLabel(1) }).textContent).toBe(
      JSON.stringify(payload, null, 2),
    );
    // The line above it still says no verdict.
    expect(cellOf(1, SUMMARY).textContent).toBe(LINE);
  });

  it("renders an event whose payload the server redacted, with the marker in the payload and the same line", async () => {
    const payload = { ...BASE, label: "[đã ẩn]", confidence: "[đã ẩn]" };
    serveList([labelled(1, payload)]);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    expect(cellOf(1, SUMMARY).textContent).toBe(LINE);
    expect(row(1).textContent).not.toContain("[đã ẩn]");
    await user.click(toggleOf(1));
    const text = screen.getByRole("region", { name: P.payloadLabel(1) }).textContent ?? "";
    expect(text).toContain('"label": "[đã ẩn]"');
    expect(text).toContain('"confidence": "[đã ẩn]"');
    expect(text).toContain('"gold_set": "gold_v2"');
  });

  it("renders an undo, and an event with no payload at all, without a word of verdict", async () => {
    serveList([
      labelled(3, { undo: true, alert_id: ALERT, labeler_id: "u-1", label: "escalate" }),
      labelled(2, null),
      labelled(1, { undo: true }),
    ]);
    renderPage();
    await loaded();
    expect(cellOf(3, SUMMARY).textContent).toBe(`hoàn tác nhãn cụm ${ALERT}`);
    expect(cellOf(2, SUMMARY).textContent).toBe("gán nhãn tập vàng");
    expect(cellOf(1, SUMMARY).textContent).toBe("hoàn tác nhãn");
    expect(table().textContent).not.toMatch(VERDICT);
  });
});

describe("hostile text in an event (Review Focus 3)", () => {
  const BIG = "x".repeat(1_000_000);
  const HOSTILE: AuditEvent = ev(1, {
    event_type: "<b>case.opened</b>",
    actor_role: "analyst",
    actor_username: "<i>lan</i>",
    subject_id: "<img src=x onerror=window.__pwned=1>",
    payload: {
      markup: '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>',
      close: "</pre></div></td></tr></table><h1>HACKED</h1><button>x</button>",
      control: "a\u0001b\u001b[31mred\u007fz",
      bidi: "gnp.exe\u202etxt.",
      invisible: "a\u200bb\ufeffc",
      big: BIG,
      nested: { deep: [{ password: "[đã ẩn]", db_password: "[đã ẩn]", note: "ok" }] },
      ["__proto__"]: { polluted: true },
    },
  });

  beforeEach(() => {
    delete (window as unknown as Record<string, unknown>).__pwned;
  });

  it("renders every one of them as text in one text node, and executes nothing", async () => {
    serveList([HOSTILE]);
    const user = userEvent.setup();
    const { container } = renderPage();
    await loaded();
    await user.click(toggleOf(1));
    const region = screen.getByRole("region", { name: P.payloadLabel(1) });

    // One text node in one <pre>: a megabyte is the same few elements as a line.
    expect(region.childNodes).toHaveLength(1);
    expect(region.firstChild?.nodeType).toBe(Node.TEXT_NODE);
    const text = region.textContent ?? "";
    expect(text.length).toBeGreaterThan(1_000_000);

    // The markup is in it as characters, whole.
    expect(text).toContain(
      '<img src=x onerror=\\"window.__pwned=1\\"><script>window.__pwned=2</script>',
    );
    expect(text).toContain("</pre></div></td></tr></table><h1>HACKED</h1><button>x</button>");
    // A control character is written as its escape; an invisible or bidi one too.
    expect(text).toContain("a\\u0001b\\u001b[31mred\\u007fz");
    expect(text).toContain("gnp.exe\\u202etxt.");
    expect(text).toContain("a\\u200bb\\ufeffc");
    expect(hasInvisible(text)).toBe(false);
    // The server's marker is shown, at depth, and it is all the page shows of a secret.
    expect(text).toContain('"password": "[đã ẩn]"');
    expect(text).toContain('"db_password": "[đã ẩn]"');
    expect(text).toContain('"note": "ok"');

    // And nothing in the page became an element, an attribute or a script.
    expect(
      container.querySelector("img, script, iframe, object, embed, button > button"),
    ).toBeNull();
    expect(container.querySelectorAll("h1")).toHaveLength(1);
    expect(container.querySelector("h1")?.textContent).toBe("Nhật ký audit");
    expect(container.querySelector("[onerror], [onclick], [onload]")).toBeNull();
    expect(container.querySelector("b, i")).toBeNull();
    expect((window as unknown as Record<string, unknown>).__pwned).toBeUndefined();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("renders the hostile event type, actor and subject as text too", async () => {
    serveList([HOSTILE]);
    renderPage();
    await loaded();
    const cells = within(row(1));
    expect(cells.getAllByText("<b>case.opened</b>").length).toBeGreaterThan(0);
    expect(cells.getByText("<i>lan</i>")).toBeInTheDocument();
    // The subject of an unknown type is no link: the text is shown as text.
    expect(cells.getByText("<img src=x onerror=window.__pwned=1>")).toBeInTheDocument();
    expect(cells.queryByRole("link")).not.toBeInTheDocument();
    expect((window as unknown as Record<string, unknown>).__pwned).toBeUndefined();
  });

  it("shows an invisible or bidi character of a subject, an actor or a summary as its escape", async () => {
    serveList([
      ev(2, {
        event_type: "authz.denied",
        subject_id: "/api/admin/\u202eexe.txt",
        actor_role: "analyst",
        actor_username: "lan\u200bt1",
        payload: { required: ["admin"], role: "tier1", method: "GET\u202e" },
      }),
      ev(1, { event_type: "alert.reopened", payload: { reason: "ok\u202egnp" } }),
    ]);
    renderPage();
    await loaded();
    expect(within(row(2)).getByText("/api/admin/\\u202eexe.txt")).toBeInTheDocument();
    expect(within(row(2)).getByText("lan\\u200bt1")).toBeInTheDocument();
    expect(within(row(2)).getByText(/^GET\\u202e: cần vai trò Admin/)).toBeInTheDocument();
    expect(within(row(1)).getByText(/lý do: ok\\u202egnp$/)).toBeInTheDocument();
  });

  it("renders a link to an alert whose id is hostile with the id as text and encoded in the href", async () => {
    serveList([ev(1, { event_type: "alert.received", subject_id: "<script>x</script>/../y" })]);
    renderPage();
    await loaded();
    const link = within(row(1)).getByRole("link", { name: "<script>x</script>/../y" });
    expect(link).toHaveAttribute("href", "/alerts/%3Cscript%3Ex%3C%2Fscript%3E%2F..%2Fy");
  });
});

describe("the pages of the log (the cursor)", () => {
  it("says what is on screen and out of how many, when the server counted", async () => {
    serveList(MANY(120), 1284);
    renderPage();
    await loaded();
    expect(rowCount()).toBe(50);
    const range = within(pager()).getByText("1–50 trong 1.284 sự kiện · mới nhất trước");
    expect(range).toBeInTheDocument();
    // A screen reader hears the new range when a page is read.
    expect(range).toHaveAttribute("aria-live", "polite");
  });

  it("shows no total, and no 'trong', when the server did not count", async () => {
    serveList(MANY(120), null);
    renderPage();
    await loaded();
    expect(within(pager()).getByText("1–50 · mới nhất trước")).toBeInTheDocument();
    expect(within(pager()).queryByText(/trong/)).not.toBeInTheDocument();
  });

  it("opens on the first page: Trước is off, Sau is on", async () => {
    serveList(MANY(120), 120);
    renderPage();
    await loaded();
    expect(prevButton()).toBeDisabled();
    expect(nextButton()).toBeEnabled();
  });

  it("goes on with the server's cursor, the same filters and the same size, and shows 51–100", async () => {
    const served = serveList(MANY(120), 120);
    const user = userEvent.setup();
    renderPage("/admin/audit?group=model&actor=llm");
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(within(pager()).getByText(/^51–100 trong 120/)).toBeInTheDocument());
    expect(served.gets).toHaveLength(2);
    expect(Object.fromEntries(served.gets[1] ?? [])).toEqual({
      range: "7d",
      group: "model",
      actor: "llm",
      limit: "50",
      cursor: "71",
    });
    expect(row(70)).toBeInTheDocument();
    expect(table().querySelector('tr[data-audit-id="71"]')).toBeNull();
    expect(prevButton()).toBeEnabled();
    expect(nextButton()).toBeEnabled();
  });

  it("goes back with Trước to the page before, which keeps its rows and its range", async () => {
    serveList(MANY(120), 120);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(within(pager()).getByText(/^51–100/)).toBeInTheDocument());
    await user.click(prevButton());
    await waitFor(() => expect(within(pager()).getByText(/^1–50/)).toBeInTheDocument());
    expect(row(120)).toBeInTheDocument();
    expect(prevButton()).toBeDisabled();
  });

  it("walks to the last page: its range is short, and Sau is off because the server says none is left", async () => {
    serveList(MANY(120), null);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(within(pager()).getByText(/^51–100/)).toBeInTheDocument());
    await user.click(nextButton());
    await waitFor(() =>
      expect(within(pager()).getByText("101–120 · mới nhất trước")).toBeInTheDocument(),
    );
    expect(rowCount()).toBe(20);
    expect(nextButton()).toBeDisabled();
    expect(prevButton()).toBeEnabled();
  });

  it("turns Sau off on a full last page when the total says it is the last", async () => {
    serve(() => ({ events: MANY(50), next_cursor: 1, total: 50 }));
    renderPage();
    await loaded();
    expect(within(pager()).getByText("1–50 trong 50 sự kiện · mới nhất trước")).toBeInTheDocument();
    expect(nextButton()).toBeDisabled();
  });

  it("says nothing is older on a page with no event after a full one, and keeps Trước", async () => {
    // The page before was full and the total was not counted: the cursor leads to nothing.
    serve((query) =>
      query.get("cursor") === null
        ? { events: MANY(50), next_cursor: 1, total: null }
        : { events: [], next_cursor: null, total: null },
    );
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(nextButton());
    expect(await screen.findByText(P.endOfLog)).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: P.table })).not.toBeInTheDocument();
    expect(screen.queryByText(P.noMatchTitle)).not.toBeInTheDocument();
    expect(screen.queryByText(P.emptyTitle)).not.toBeInTheDocument();
    expect(nextButton()).toBeDisabled();
    expect(prevButton()).toBeEnabled();
    await user.click(prevButton());
    expect(await screen.findByRole("table", { name: P.table })).toBeInTheDocument();
    expect(rowCount()).toBe(50);
  });

  it("starts again at the first page when a filter changes, with no cursor", async () => {
    const served = serveList(MANY(120), 120);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(within(pager()).getByText(/^51–100/)).toBeInTheDocument());
    await user.selectOptions(groupSelect(), "users");
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    await waitFor(() => expect(served.gets).toHaveLength(3));
    expect(Object.fromEntries(served.gets[2] ?? [])).toEqual({
      range: "7d",
      group: "users",
      limit: "50",
    });
    await waitFor(() => expect(within(pager()).getByText(/^1–50/)).toBeInTheDocument());
    expect(prevButton()).toBeDisabled();
  });

  // The cursors belong to the view that made them: a view that comes back is read from its first page, by the
  // form, by Back, and by "Xoá lọc" (which can leave the URL as it was).
  it("starts again at the first page when the same filters come back, typed in the form", async () => {
    const served = serveList(MANY(120), 120);
    const user = userEvent.setup();
    renderPage("/admin/audit?group=model");
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(within(pager()).getByText(/^51–100/)).toBeInTheDocument());

    await user.selectOptions(groupSelect(), "users");
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    await waitFor(() => expect(where()).toBe("/admin/audit?group=users"));
    await waitFor(() => expect(within(pager()).getByText(/^1–50/)).toBeInTheDocument());

    await user.selectOptions(groupSelect(), "model");
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    await waitFor(() => expect(where()).toBe("/admin/audit?group=model"));
    await waitFor(() => expect(within(pager()).getByText(/^1–50 trong 120/)).toBeInTheDocument());
    expect(prevButton()).toBeDisabled();
    expect(served.gets[served.gets.length - 1]?.has("cursor")).toBe(false);
  });

  it("starts again at the first page when the same filters come back with the Back button", async () => {
    const served = serveList(MANY(120), 120);
    const user = userEvent.setup();
    renderPage("/admin/audit?group=model");
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(within(pager()).getByText(/^51–100/)).toBeInTheDocument());
    await user.selectOptions(groupSelect(), "users");
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    await waitFor(() => expect(where()).toBe("/admin/audit?group=users"));
    await user.click(screen.getByRole("button", { name: "back" }));
    await waitFor(() => expect(where()).toBe("/admin/audit?group=model"));
    await waitFor(() => expect(within(pager()).getByText(/^1–50 trong 120/)).toBeInTheDocument());
    expect(prevButton()).toBeDisabled();
    expect(served.gets[served.gets.length - 1]?.has("cursor")).toBe(false);
  });

  it("goes to the first page on Xoá lọc, whether or not the URL has a filter to lose", async () => {
    const served = serveList(MANY(120), 120);
    const user = userEvent.setup();
    // No filter: the URL is the same before and after, and the page must still go back.
    const bare = renderPage("/admin/audit");
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(within(pager()).getByText(/^51–100/)).toBeInTheDocument());
    await user.click(within(form()).getByRole("button", { name: P.clear }));
    await waitFor(() => expect(within(pager()).getByText(/^1–50/)).toBeInTheDocument());
    expect(prevButton()).toBeDisabled();
    expect(where()).toBe("/admin/audit");
    expect(served.gets[served.gets.length - 1]?.has("cursor")).toBe(false);
    bare.unmount();

    // With a filter: the URL changes, and the page goes back as well.
    renderPage("/admin/audit?actor=llm");
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(within(pager()).getByText(/^51–100/)).toBeInTheDocument());
    await user.click(within(form()).getByRole("button", { name: P.clear }));
    await waitFor(() => expect(where()).toBe("/admin/audit"));
    await waitFor(() => expect(within(pager()).getByText(/^1–50/)).toBeInTheDocument());
    expect(served.gets[served.gets.length - 1]?.has("cursor")).toBe(false);
  });

  it("goes to the first page when the form is sent with the filters it already has", async () => {
    const served = serveList(MANY(120), 120);
    const user = userEvent.setup();
    renderPage("/admin/audit?group=users");
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(within(pager()).getByText(/^51–100/)).toBeInTheDocument());
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    await waitFor(() => expect(within(pager()).getByText(/^1–50/)).toBeInTheDocument());
    expect(prevButton()).toBeDisabled();
    expect(served.gets[served.gets.length - 1]?.has("cursor")).toBe(false);
  });

  it("keeps the page it is on when the form is sent with the filters it has and the page is the first", async () => {
    const served = serveList(MANY(120), 120);
    const user = userEvent.setup();
    renderPage("/admin/audit?group=users");
    await loaded();
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    await waitFor(() => expect(served.gets).toHaveLength(2));
    expect(within(pager()).getByText(/^1–50/)).toBeInTheDocument();
  });

  it("keeps Trước in the error of a later page, so the admin can go back", async () => {
    const served = serve((query) =>
      query.has("cursor") ? reason(503, "timeout") : pageOf(MANY(120), query, 120),
    );
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(nextButton());
    expect(await screen.findByRole("alert")).toHaveTextContent(S.admin.reason.timeout);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(prevButton()).toBeEnabled();
    expect(nextButton()).toBeDisabled();
    await user.click(prevButton());
    expect(await loaded()).toBeInTheDocument();
    expect(within(pager()).getByText(/^1–50 trong 120/)).toBeInTheDocument();
    expect(prevButton()).toBeDisabled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(served.gets.some((query) => query.has("cursor"))).toBe(true);
  });

  it("shows no pager in the error of the first page: there is no page to go back to", async () => {
    serve(() => reason(503, "timeout"));
    renderPage();
    await screen.findByRole("alert");
    expect(screen.queryByRole("navigation", { name: P.pager })).not.toBeInTheDocument();
  });

  it("keeps the rows on screen while the next page is read, and the two buttons off", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    serve(async (query) => {
      if (query.get("cursor") !== null) await gate;
      return pageOf(MANY(120), query, 120);
    });
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(table()).toHaveAttribute("aria-busy", "true"));
    expect(row(120)).toBeInTheDocument();
    // What is said is about the rows on screen, which are still the first page's.
    expect(
      within(pager()).getByText("1–50 trong 120 sự kiện · mới nhất trước"),
    ).toBeInTheDocument();
    expect(prevButton()).toBeDisabled();
    expect(nextButton()).toBeDisabled();
    release();
    await waitFor(() => expect(within(pager()).getByText(/^51–100/)).toBeInTheDocument());
    expect(table()).toHaveAttribute("aria-busy", "false");
  });

  it("leaves the focus on the button it pressed", async () => {
    serveList(MANY(120), 120);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(within(pager()).getByText(/^51–100/)).toBeInTheDocument());
    expect(nextButton()).toHaveFocus();
  });

  it("shows no pager for an empty log", async () => {
    serveList([], 0);
    renderPage();
    expect(await screen.findByText(P.emptyTitle)).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: P.pager })).not.toBeInTheDocument();
  });
});

describe("the filters, kept in the URL", () => {
  it("reads all four from the URL, shows them in the form, and sends them", async () => {
    const served = serveList(CANVAS);
    renderPage(`/admin/audit?range=30d&group=users&actor=lan.t1&subject=${ALERT}`);
    await loaded();
    expect(rangeSelect().value).toBe("30d");
    expect(groupSelect().value).toBe("users");
    expect(actorInput().value).toBe("lan.t1");
    expect(subjectInput().value).toBe(ALERT);
    expect(Object.fromEntries(served.gets[0] ?? [])).toEqual({
      range: "30d",
      group: "users",
      actor: "lan.t1",
      subject: ALERT,
      limit: "50",
    });
  });

  it("writes the filters to the URL when the form is sent, and reads again", async () => {
    const served = serveList(CANVAS);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.selectOptions(rangeSelect(), "24h");
    await user.selectOptions(groupSelect(), "model");
    await user.type(actorInput(), "llm");
    await user.type(subjectInput(), "1759012345.1662100");
    expect(where()).toBe("/admin/audit"); // nothing is sent until the form is
    expect(served.gets).toHaveLength(1);
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    expect(where()).toBe("/admin/audit?range=24h&group=model&actor=llm&subject=1759012345.1662100");
    await waitFor(() => expect(served.gets).toHaveLength(2));
    expect(Object.fromEntries(served.gets[1] ?? [])).toEqual({
      range: "24h",
      group: "model",
      actor: "llm",
      subject: "1759012345.1662100",
      limit: "50",
    });
  });

  it("sends the form with the Enter key in a text filter", async () => {
    const served = serveList(CANVAS);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.type(actorInput(), "lan.t1{Enter}");
    expect(where()).toBe("/admin/audit?actor=lan.t1");
    await waitFor(() => expect(served.gets).toHaveLength(2));
  });

  it("does not write the default range", async () => {
    serveList(CANVAS);
    const user = userEvent.setup();
    renderPage("/admin/audit?range=24h");
    await loaded();
    await user.selectOptions(rangeSelect(), "7d");
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    expect(where()).toBe("/admin/audit");
  });

  it("never sends or writes an empty filter text, and trims a spaced one", async () => {
    const served = serveList(CANVAS);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.type(actorInput(), "   ");
    await user.type(subjectInput(), "  abc  ");
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    expect(where()).toBe("/admin/audit?subject=abc");
    await waitFor(() => expect(served.gets).toHaveLength(2));
    expect(Object.fromEntries(served.gets[1] ?? [])).toEqual({
      range: "7d",
      subject: "abc",
      limit: "50",
    });
    for (const query of served.gets) expect(query.has("actor")).toBe(false);
  });

  it("does not send an empty text from the URL either", async () => {
    const served = serveList(CANVAS);
    renderPage("/admin/audit?actor=&subject=%20&group=");
    await loaded();
    expect(Object.fromEntries(served.gets[0] ?? [])).toEqual({ range: "7d", limit: "50" });
  });

  it("falls back to the default for a range or a group the server does not know, and does not send it", async () => {
    const served = serveList(CANVAS);
    renderPage("/admin/audit?range=1y&group=nope");
    await loaded();
    expect(rangeSelect().value).toBe("7d");
    expect(groupSelect().value).toBe("");
    expect(Object.fromEntries(served.gets[0] ?? [])).toEqual({ range: "7d", limit: "50" });
  });

  it("clears the filters with Xoá lọc: the URL, the form and the next read", async () => {
    const served = serveList(CANVAS);
    const user = userEvent.setup();
    renderPage("/admin/audit?range=30d&group=users&actor=lan.t1&subject=abc");
    await loaded();
    await user.click(within(form()).getByRole("button", { name: P.clear }));
    expect(where()).toBe("/admin/audit");
    expect(rangeSelect().value).toBe("7d");
    expect(groupSelect().value).toBe("");
    expect(actorInput().value).toBe("");
    expect(subjectInput().value).toBe("");
    await waitFor(() => expect(served.gets).toHaveLength(2));
    expect(Object.fromEntries(served.gets[1] ?? [])).toEqual({ range: "7d", limit: "50" });
  });

  it("clears what was typed and not yet sent, too", async () => {
    serveList(CANVAS);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.type(actorInput(), "half-typed");
    await user.selectOptions(groupSelect(), "system");
    await user.click(within(form()).getByRole("button", { name: P.clear }));
    expect(actorInput().value).toBe("");
    expect(groupSelect().value).toBe("");
    expect(where()).toBe("/admin/audit");
  });

  it("keeps the filters on a reload: the same URL gives the same form and the same read", async () => {
    const served = serveList(CANVAS);
    const user = userEvent.setup();
    const first = renderPage();
    await loaded();
    await user.selectOptions(groupSelect(), "configuration");
    await user.type(actorInput(), "hoa.admin");
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    const url = where() ?? "";
    expect(url).toBe("/admin/audit?group=configuration&actor=hoa.admin");
    first.unmount();

    renderPage(url);
    await loaded();
    expect(groupSelect().value).toBe("configuration");
    expect(actorInput().value).toBe("hoa.admin");
    expect(Object.fromEntries(served.gets[served.gets.length - 1] ?? [])).toEqual({
      range: "7d",
      group: "configuration",
      actor: "hoa.admin",
      limit: "50",
    });
  });

  it("follows the browser's Back button: the earlier filters come back, in the form and in the read", async () => {
    const served = serveList(CANVAS);
    const user = userEvent.setup();
    renderPage("/admin/audit?actor=lan.t1");
    await loaded();
    await user.clear(actorInput());
    await user.type(actorInput(), "hoa.admin");
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    await waitFor(() => expect(actorInput().value).toBe("hoa.admin"));
    await user.click(screen.getByRole("button", { name: "back" }));
    await waitFor(() => expect(where()).toBe("/admin/audit?actor=lan.t1"));
    await waitFor(() => expect(actorInput().value).toBe("lan.t1"));
    await waitFor(() => expect(served.gets[served.gets.length - 1]?.get("actor")).toBe("lan.t1"));
  });

  it("asks again when the form is sent with the filters it already has", async () => {
    const served = serveList(CANVAS);
    const user = userEvent.setup();
    renderPage("/admin/audit?group=users");
    await loaded();
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    await waitFor(() => expect(served.gets).toHaveLength(2));
    expect(where()).toBe("/admin/audit?group=users");
  });

  it("is read again when another page's write makes the log stale", async () => {
    const served = serveList(CANVAS);
    const { client } = renderPage();
    await loaded();
    await act(async () => {
      await invalidateAfter(client, "retryJob");
    });
    await waitFor(() => expect(served.gets).toHaveLength(2));
  });
});

describe("the states", () => {
  it("shows a skeleton while the first read is on its way, with the form already there", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    serve(async (query) => {
      await gate;
      return pageOf(CANVAS, query);
    });
    renderPage();
    const status = await screen.findByRole("status");
    expect(status).toHaveAttribute("aria-busy", "true");
    expect(status).toHaveTextContent(S.common.loading);
    expect(form()).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "Nhật ký audit" })).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    release();
    expect(await loaded()).toBeInTheDocument();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("does not show the rows of the filters just left under the filters just chosen", async () => {
    // The page being left stays on screen while the next page of the SAME filters is read, and never across
    // filters: here the answer for the new group is held back, and the old group's rows must be gone.
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    serve(async (query) => {
      if (query.get("group") === "users") {
        await gate;
        return pageOf(MANY(3), query, 3);
      }
      return pageOf(CANVAS, query);
    });
    const user = userEvent.setup();
    renderPage();
    await loaded();
    expect(rowCount()).toBe(10);
    await user.selectOptions(groupSelect(), "users");
    await user.click(within(form()).getByRole("button", { name: P.apply }));
    expect(await screen.findByRole("status")).toHaveTextContent(S.common.loading);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(document.querySelector("tr[data-audit-id]")).toBeNull();
    expect(screen.queryByRole("navigation", { name: P.pager })).not.toBeInTheDocument();
    release();
    expect(await loaded()).toBeInTheDocument();
    expect(rowCount()).toBe(3);
    expect(table().querySelector('tr[data-audit-id="10"]')).toBeNull();
  });

  describe("no match", () => {
    it("says which filters were on, and clears them with the button", async () => {
      const served = serve((query) =>
        query.get("group") === null
          ? pageOf(CANVAS, query)
          : { events: [], next_cursor: null, total: 0 },
      );
      const user = userEvent.setup();
      renderPage("/admin/audit?group=users&actor=quang");
      expect(await screen.findByRole("heading", { name: P.noMatchTitle })).toBeInTheDocument();
      expect(
        screen.getByText(
          "Bộ lọc đang dùng: nhóm “Người dùng và quyền”, người thực hiện “quang”, 7 ngày qua.",
        ),
      ).toBeInTheDocument();
      expect(screen.queryByRole("table")).not.toBeInTheDocument();
      expect(screen.queryByText(P.emptyTitle)).not.toBeInTheDocument();
      // The form and the card each have the button; the card's is the one under the message.
      const card = screen.getByRole("heading", { name: P.noMatchTitle })
        .parentElement as HTMLElement;
      await user.click(within(card).getByRole("button", { name: P.clear }));
      expect(where()).toBe("/admin/audit");
      expect(await loaded()).toBeInTheDocument();
      expect(Object.fromEntries(served.gets[served.gets.length - 1] ?? [])).toEqual({
        range: "7d",
        limit: "50",
      });
    });

    it("names every filter that is on: the group, the actor, the subject and the range", async () => {
      serve(() => ({ events: [], next_cursor: null, total: 0 }));
      renderPage("/admin/audit?range=24h&group=model&actor=llm&subject=abc");
      expect(
        await screen.findByText(
          "Bộ lọc đang dùng: nhóm “Model và cổng kiểm soát”, người thực hiện “llm”, đối tượng “abc”, 24 giờ qua.",
        ),
      ).toBeInTheDocument();
    });

    it("is also the answer for a range other than the default with nothing else on", async () => {
      serve(() => ({ events: [], next_cursor: null, total: 0 }));
      renderPage("/admin/audit?range=24h");
      expect(await screen.findByRole("heading", { name: P.noMatchTitle })).toBeInTheDocument();
      expect(screen.getByText("Bộ lọc đang dùng: 24 giờ qua.")).toBeInTheDocument();
    });

    it("shows a hostile filter text as text", async () => {
      serve(() => ({ events: [], next_cursor: null, total: 0 }));
      const { container } = renderPage(
        `/admin/audit?actor=${encodeURIComponent("<img src=x onerror=window.__pwned=1>")}`,
      );
      expect(await screen.findByRole("heading", { name: P.noMatchTitle })).toBeInTheDocument();
      expect(container.querySelector("img")).toBeNull();
      expect(
        screen.getByText(/người thực hiện “<img src=x onerror=window.__pwned=1>”/),
      ).toBeInTheDocument();
    });
  });

  describe("an empty log", () => {
    it("says so, for the default view, with no button to clear a filter that is not there", async () => {
      serve(() => ({ events: [], next_cursor: null, total: 0 }));
      renderPage();
      expect(await screen.findByRole("heading", { name: P.emptyTitle })).toBeInTheDocument();
      expect(screen.getByText(P.emptyBody("7 ngày qua"))).toBeInTheDocument();
      expect(screen.queryByRole("heading", { name: P.noMatchTitle })).not.toBeInTheDocument();
      const card = screen.getByRole("heading", { name: P.emptyTitle }).parentElement as HTMLElement;
      expect(within(card).queryByRole("button")).not.toBeInTheDocument();
      expect(screen.queryByRole("table")).not.toBeInTheDocument();
    });
  });

  describe("503", () => {
    it("says a query that ran out of time in its own words, with the note and a way to ask again", async () => {
      const served = serve((_, n) =>
        n === 0 ? reason(503, "timeout") : pageOf(CANVAS, new URLSearchParams()),
      );
      const user = userEvent.setup();
      renderPage();
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(S.admin.reason.timeout);
      expect(alert).toHaveTextContent("Thu hẹp khoảng thời gian hoặc thêm bộ lọc");
      expect(screen.getByText(P.timeoutNote)).toBeInTheDocument();
      expect(form()).toBeInTheDocument();
      expect(screen.queryByRole("table")).not.toBeInTheDocument();
      await user.click(
        within(alert.parentElement as HTMLElement).getByRole("button", { name: S.common.retry }),
      );
      expect(await loaded()).toBeInTheDocument();
      expect(served.gets).toHaveLength(2);
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });

    it("does not ask again by itself, whatever the app's own retry rule says", async () => {
      const served = serve(() => reason(503, "timeout"));
      renderPage("/admin/audit", createQueryClient());
      // The app's client would retry a 503 after a second, twice: the error would show only after ~3 s.
      expect(await screen.findByRole("alert", {}, { timeout: 900 })).toHaveTextContent(
        S.admin.reason.timeout,
      );
      expect(served.gets).toHaveLength(1);
    });

    it("lets the admin narrow the filter from there: a new filter is read at once", async () => {
      const served = serve((query) =>
        query.get("range") === "30d" ? reason(503, "timeout") : pageOf(CANVAS, query),
      );
      const user = userEvent.setup();
      renderPage("/admin/audit?range=30d");
      expect(await screen.findByRole("alert")).toHaveTextContent(S.admin.reason.timeout);
      await user.selectOptions(rangeSelect(), "24h");
      await user.click(within(form()).getByRole("button", { name: P.apply }));
      expect(await loaded()).toBeInTheDocument();
      expect(Object.fromEntries(served.gets[served.gets.length - 1] ?? [])).toEqual({
        range: "24h",
        limit: "50",
      });
    });

    // This route never sends `query_failed` (admin_audit.py answers 503 only for `timeout`; any other database
    // error is a 500, the page's own error below). The code is in the shell's reason table, so the page has a
    // text for it, and this test keeps that text from going unseen.
    it("says a failed query in its own words too", async () => {
      serve(() => reason(503, "query_failed"));
      renderPage();
      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(S.admin.reason.query_failed);
      expect(alert).not.toHaveTextContent(S.admin.reason.timeout);
      expect(
        within(alert.parentElement as HTMLElement).getByRole("button", { name: S.common.retry }),
      ).toBeInTheDocument();
      expect(form()).toBeInTheDocument();
    });
  });

  describe("422, a filter the server refuses", () => {
    it.each([
      ["actor", "actor=%00", () => actorInput(), P.actorLabel],
      ["subject", "subject=%00", () => subjectInput(), P.subjectLabel],
      ["range", "range=7d", () => rangeSelect(), P.rangeLabel],
      ["group", "group=users", () => groupSelect(), P.groupLabel],
    ] as const)(
      "says at the %s filter that it is not valid, and marks the filter",
      async (name, query, control, label) => {
        serve(() => invalid(name));
        renderPage(`/admin/audit?${query}`);
        const alert = await screen.findByRole("alert");
        expect(alert).toHaveTextContent(P.badFilter);
        const fault = P.fieldFault(label);
        expect(within(form()).getByText(fault)).toBeInTheDocument();
        expect(control()).toHaveAttribute("aria-invalid", "true");
        const described = control().getAttribute("aria-describedby") ?? "";
        expect(document.getElementById(described)).toHaveTextContent(fault);
        // Only that filter is marked.
        for (const other of [actorInput(), subjectInput(), rangeSelect(), groupSelect()]) {
          if (other !== control()) expect(other).not.toHaveAttribute("aria-invalid");
        }
        expect(screen.queryByRole("table")).not.toBeInTheDocument();
      },
    );

    it("clears the fault when the filter is sent again and the server accepts it", async () => {
      serve((query) =>
        query.get("actor") === "\u0000" ? invalid("actor") : pageOf(CANVAS, query),
      );
      const user = userEvent.setup();
      renderPage("/admin/audit?actor=%00");
      expect(await screen.findByRole("alert")).toHaveTextContent(P.badFilter);
      await user.clear(actorInput());
      await user.type(actorInput(), "lan.t1");
      await user.click(within(form()).getByRole("button", { name: P.apply }));
      expect(await loaded()).toBeInTheDocument();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
      expect(actorInput()).not.toHaveAttribute("aria-invalid");
      expect(within(form()).queryByText(P.fieldFault(P.actorLabel))).not.toBeInTheDocument();
    });

    it("says only the line above the table when the 422 names none of the filters", async () => {
      serve(() => invalid("limit"));
      renderPage();
      expect(await screen.findByRole("alert")).toHaveTextContent(P.badFilter);
      for (const control of [actorInput(), subjectInput(), rangeSelect(), groupSelect()]) {
        expect(control).not.toHaveAttribute("aria-invalid");
      }
    });

    it("clears everything with Xoá lọc from there", async () => {
      const served = serve((query) =>
        query.has("actor") ? invalid("actor") : pageOf(CANVAS, query),
      );
      const user = userEvent.setup();
      renderPage("/admin/audit?actor=%00");
      expect(await screen.findByRole("alert")).toHaveTextContent(P.badFilter);
      await user.click(within(form()).getByRole("button", { name: P.clear }));
      expect(await loaded()).toBeInTheDocument();
      expect(Object.fromEntries(served.gets[served.gets.length - 1] ?? [])).toEqual({
        range: "7d",
        limit: "50",
      });
    });
  });

  describe("403", () => {
    it("shows the card of a role that is not admin any more, with a way back, and no form", async () => {
      serve(status(403, { detail: "forbidden" }));
      renderPage();
      expect(
        await screen.findByRole("heading", { level: 1, name: P.forbiddenTitle }),
      ).toBeInTheDocument();
      expect(screen.getByText(P.forbiddenBody)).toBeInTheDocument();
      expect(screen.getByRole("link", { name: P.forbiddenBack })).toHaveAttribute("href", "/queue");
      expect(screen.queryByRole("form")).not.toBeInTheDocument();
      expect(screen.queryByRole("table")).not.toBeInTheDocument();
      expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    });

    it("offers no retry: asking again says the same", async () => {
      serve(status(403, { detail: "forbidden" }));
      renderPage();
      await screen.findByRole("heading", { level: 1, name: P.forbiddenTitle });
      expect(screen.queryByRole("button", { name: S.common.retry })).not.toBeInTheDocument();
    });
  });

  describe("the page's own error", () => {
    it("shows PageError for a 500, with the status, the form, and one h1, and reads again on retry", async () => {
      const served = serve((query, n) => (n === 0 ? status(500, "boom")() : pageOf(CANVAS, query)));
      const user = userEvent.setup();
      renderPage();
      expect(
        await screen.findByRole("heading", { level: 1, name: S.admin.common.loadError }),
      ).toBeInTheDocument();
      expect(screen.getByText(P.loadErrorServer(500))).toBeInTheDocument();
      expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
      expect(form()).toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: S.common.retry }));
      expect(await loaded()).toBeInTheDocument();
      expect(served.gets).toHaveLength(2);
      expect(screen.getByRole("heading", { level: 1, name: "Nhật ký audit" })).toBeInTheDocument();
    });

    it("says the connection was lost when there was no answer", async () => {
      serve(networkError);
      renderPage();
      expect(
        await screen.findByRole("heading", { level: 1, name: S.admin.common.loadError }),
      ).toBeInTheDocument();
      expect(screen.getByText(P.loadErrorOffline)).toBeInTheDocument();
      expect(screen.getByRole("button", { name: S.common.retry })).toBeInTheDocument();
    });

    it("shows PageError for a 503 that is not one of the two reasons (the English of a server)", async () => {
      serve(status(503, { detail: "auth disabled: JWT_SECRET unset" }));
      renderPage();
      expect(
        await screen.findByRole("heading", { level: 1, name: S.admin.common.loadError }),
      ).toBeInTheDocument();
      expect(screen.getByText(P.loadErrorServer(503))).toBeInTheDocument();
      expect(screen.queryByText(/JWT_SECRET/)).not.toBeInTheDocument();
    });

    it("keeps the rows on screen, with a note and a retry, when a new read of them fails", async () => {
      const served = serve((query, n) => (n === 0 ? pageOf(CANVAS, query) : status(500, "boom")()));
      const user = userEvent.setup();
      const { client } = renderPage();
      await loaded();
      await act(async () => {
        await client.invalidateQueries({ queryKey: adminKeys.auditAll });
      });
      expect(await screen.findByText(P.refreshFailed)).toBeInTheDocument();
      expect(rowCount()).toBe(10);
      expect(screen.queryByText(P.loadErrorServer(500))).not.toBeInTheDocument();
      expect(served.gets).toHaveLength(2);
      await user.click(screen.getByRole("button", { name: S.common.retry }));
      await waitFor(() => expect(served.gets).toHaveLength(3));
    });
  });
});

// axe runs over a whole page, and several of these render the page three times: more than the default 5 s on a
// busy machine, so each test here gets 15 s.
describe("accessibility", { timeout: 15_000 }, () => {
  /** jsdom computes no layout or colour, so the contrast rule cannot run here. */
  const axeOf = async (container: HTMLElement) =>
    (await axe.run(container, { rules: { "color-contrast": { enabled: false } } })).violations.map(
      (v) => v.id,
    );

  it("has no axe violation on the table, with the sidebar and the header around it", async () => {
    serveList(CANVAS, 1284);
    const { container } = renderPage("/admin/audit", testClient(), { layout: true });
    await loaded();
    expect(await axeOf(container)).toEqual([]);
  });

  it("has none with two payloads open, one of them the hostile one", async () => {
    serveList([
      ev(11, { payload: { markup: "<script>1</script>", password: "[đã ẩn]" } }),
      ...CANVAS,
    ]);
    const user = userEvent.setup();
    const { container } = renderPage("/admin/audit", testClient(), { layout: true });
    await loaded();
    await user.click(toggleOf(11));
    await user.click(toggleOf(10));
    expect(await axeOf(container)).toEqual([]);
  });

  it("has none with a filter set and the table on a later page", async () => {
    serveList(MANY(120), 120);
    const user = userEvent.setup();
    const { container } = renderPage("/admin/audit?group=model&actor=llm", testClient(), {
      layout: true,
    });
    await loaded();
    await user.click(nextButton());
    await waitFor(() => expect(within(pager()).getByText(/^51–100/)).toBeInTheDocument());
    expect(await axeOf(container)).toEqual([]);
  });

  it("has none while it is loading", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    serve(async (query) => {
      await gate;
      return pageOf(CANVAS, query);
    });
    const { container } = renderPage("/admin/audit", testClient(), { layout: true });
    await screen.findByRole("status");
    expect(await axeOf(container)).toEqual([]);
    release();
    await loaded();
  });

  it("has none for no match, for an empty log, and for the end of the log", async () => {
    serve(() => ({ events: [], next_cursor: null, total: 0 }));
    const noMatch = renderPage("/admin/audit?actor=quang", testClient(), { layout: true });
    await screen.findByRole("heading", { name: P.noMatchTitle });
    expect(await axeOf(noMatch.container)).toEqual([]);
    noMatch.unmount();

    const empty = renderPage("/admin/audit", testClient(), { layout: true });
    await screen.findByRole("heading", { name: P.emptyTitle });
    expect(await axeOf(empty.container)).toEqual([]);
  });

  it("has none for the timeout, the failed query, and a 422 with its field marked", async () => {
    serve(() => reason(503, "timeout"));
    const timeout = renderPage("/admin/audit", testClient(), { layout: true });
    await screen.findByRole("alert");
    expect(await axeOf(timeout.container)).toEqual([]);
    timeout.unmount();

    serve(() => reason(503, "query_failed"));
    const failed = renderPage("/admin/audit", testClient(), { layout: true });
    await screen.findByRole("alert");
    expect(await axeOf(failed.container)).toEqual([]);
    failed.unmount();

    serve(() => invalid("actor"));
    const fault = renderPage("/admin/audit?actor=%00", testClient(), { layout: true });
    await screen.findByRole("alert");
    expect(await axeOf(fault.container)).toEqual([]);
  });

  it("has none for the 403 card and for the page's error", async () => {
    serve(status(403, { detail: "forbidden" }));
    const forbidden = renderPage("/admin/audit", testClient(), { layout: true });
    await screen.findByRole("heading", { level: 1, name: P.forbiddenTitle });
    expect(await axeOf(forbidden.container)).toEqual([]);
    forbidden.unmount();

    serve(status(500, "boom"));
    const broken = renderPage("/admin/audit", testClient(), { layout: true });
    await screen.findByRole("heading", { level: 1, name: S.admin.common.loadError });
    expect(await axeOf(broken.container)).toEqual([]);
  });

  it("reaches every control with the keyboard, in the reading order", async () => {
    serveList(CANVAS, 10);
    const user = userEvent.setup();
    renderPage();
    await loaded();
    rangeSelect().focus();
    await user.tab();
    expect(groupSelect()).toHaveFocus();
    await user.tab();
    expect(actorInput()).toHaveFocus();
    await user.tab();
    expect(subjectInput()).toHaveFocus();
    await user.tab();
    expect(within(form()).getByRole("button", { name: P.apply })).toHaveFocus();
    await user.tab();
    expect(within(form()).getByRole("button", { name: P.clear })).toHaveFocus();
    await user.tab();
    expect(toggleOf(10)).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("region", { name: P.payloadLabel(10) })).toBeInTheDocument();
    expect(toggleOf(10)).toHaveFocus();
  });
});

describe("the form is a form", () => {
  it("does not submit the page: the browser's own submit is prevented", async () => {
    serveList(CANVAS);
    renderPage();
    await loaded();
    const event = new Event("submit", { bubbles: true, cancelable: true });
    form().dispatchEvent(event);
    expect(event.defaultPrevented).toBe(true);
    fireEvent.submit(form());
  });
});
