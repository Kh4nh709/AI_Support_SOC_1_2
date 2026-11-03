// src/features/admin/DigestPage.test.tsx — `/admin/digest` (spec §4.5, P11-T15): the clusters a rule auto-closed
// on one day, each with ①'s suggestion and the three verdict buttons. MSW answers the two routes; nothing is
// mocked above `fetch`. The day lives in the URL, and the page shows the day and "today" the server answered.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter, useLocation, useNavigate } from "react-router";
import type { DigestResponse, DigestRow } from "../../api/admin";
import { S } from "../../strings";
import { ADMIN_INVALIDATES } from "./adminKeys";
import { DigestPage } from "./DigestPage";

const DIGEST_URL = "/api/admin/digest";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const D = S.admin.digestPage;

// --- the data -----------------------------------------------------------------------------------------------

const DAY = "2026-09-29";
const TODAY = "2026-09-30";

/** The six clusters of the canvas (AdminDigest): times are +07 there, so the ISO strings are seven hours back. */
const IDS = {
  open: "1759012345.1661001",
  disagree: "1759012346.1661002",
  noSuggestion: "1759012347.1661003",
  correct: "1759012348.1661004",
  wrong: "1759012349.1661005",
  unsure: "1759012350.1661006",
} as const;

const RULE_SSH = "Đăng nhập SSH thành công từ máy quản trị";
const RULE_DISK = "Cảnh báo dung lượng đĩa máy lab";

function digestRow(over: Partial<DigestRow> = {}): DigestRow {
  return {
    alert_id: IDS.open,
    rule_id: "5715",
    description: "sshd: authentication success",
    severity: "low",
    category: "suspicious_login",
    agent_name: "srv-db-02",
    occurrence_count: 42,
    first_seen_at: "2026-09-29T01:02:00+00:00",
    last_seen_at: "2026-09-29T10:40:00+00:00",
    autoclose_rule_id: "11111111-1111-4111-8111-111111111111",
    autoclose_rule_name: RULE_SSH,
    suggested_action: "false_positive",
    disagreement: false,
    reviewed_verdict: null,
    reviewed_by_name: null,
    reviewed_at: null,
    reopened_by_review: false,
    ...over,
  };
}

const rows = (): DigestRow[] => [
  digestRow(),
  digestRow({
    alert_id: IDS.disagree,
    agent_name: "srv-web-01",
    occurrence_count: 9,
    first_seen_at: "2026-09-29T14:15:00+00:00",
    last_seen_at: "2026-09-29T14:16:00+00:00",
    suggested_action: "true_positive",
    disagreement: true,
  }),
  digestRow({
    alert_id: IDS.noSuggestion,
    rule_id: "531",
    category: "unknown",
    description: "Partition usage reached 90%",
    severity: "medium",
    agent_name: "lab-ubuntu-01",
    occurrence_count: 3,
    first_seen_at: "2026-09-28T19:00:00+00:00",
    last_seen_at: "2026-09-28T19:30:00+00:00",
    autoclose_rule_name: RULE_DISK,
    suggested_action: null,
  }),
  digestRow({
    alert_id: IDS.correct,
    agent_name: "srv-db-01",
    occurrence_count: 17,
    first_seen_at: "2026-09-29T00:55:00+00:00",
    last_seen_at: "2026-09-29T09:20:00+00:00",
    reviewed_verdict: "correct",
    reviewed_by_name: "nguyen-admin",
    reviewed_at: "2026-09-30T01:12:00+00:00",
  }),
  digestRow({
    alert_id: IDS.wrong,
    rule_id: "531",
    category: "unknown",
    description: "Partition usage reached 90%",
    severity: "medium",
    agent_name: "lab-ubuntu-02",
    occurrence_count: 2,
    first_seen_at: "2026-09-28T19:00:00+00:00",
    last_seen_at: "2026-09-28T19:10:00+00:00",
    autoclose_rule_name: RULE_DISK,
    suggested_action: "needs_review",
    disagreement: true,
    reviewed_verdict: "wrong",
    reviewed_by_name: "khanh-admin",
    reviewed_at: "2026-09-30T01:14:00+00:00",
    reopened_by_review: true,
  }),
  digestRow({
    alert_id: IDS.unsure,
    agent_name: "srv-app-03",
    occurrence_count: 5,
    first_seen_at: "2026-09-29T03:00:00+00:00",
    last_seen_at: "2026-09-29T03:04:00+00:00",
    reviewed_verdict: "unsure",
    reviewed_by_name: "khanh-admin",
    reviewed_at: "2026-09-30T01:15:00+00:00",
  }),
];

function digest(over: Partial<DigestResponse> = {}): DigestResponse {
  return { day: DAY, today: TODAY, rules_enabled: true, rows: rows(), ...over };
}

/** A row as the server records it after `verdict`. */
const recorded = (
  id: string,
  verdict: DigestRow["reviewed_verdict"],
  over: Partial<DigestRow> = {},
) =>
  digestRow({
    ...(rows().find((r) => r.alert_id === id) ?? { alert_id: id }),
    reviewed_verdict: verdict,
    reviewed_by_name: "hoa.admin",
    reviewed_at: "2026-09-30T02:00:00+00:00",
    ...over,
  });

/** The day's list as the server gives it once `changed` rows are on file: the list a refresh reads after a review. */
const listWith = (...changed: DigestRow[]) =>
  digest({ rows: rows().map((r) => changed.find((c) => c.alert_id === r.alert_id) ?? r) });

// --- the server -----------------------------------------------------------------------------------------------

type Answer = DigestResponse | ((day: string | null) => Response | Promise<Response>);

/**
 * Serves `answers` one per GET (the last one for every GET after), and records the `day` each GET carried
 * (`null` when it carried none: the server's own default).
 */
function serveDigest(...answers: Answer[]) {
  const days: (string | null)[] = [];
  server.use(
    http.get(DIGEST_URL, ({ request }) => {
      const day = new URL(request.url).searchParams.get("day");
      days.push(day);
      const answer = answers[Math.min(days.length - 1, answers.length - 1)];
      if (answer === undefined) throw new Error("serveDigest needs an answer");
      return typeof answer === "function" ? answer(day) : HttpResponse.json(answer);
    }),
  );
  return days;
}

type Posted = { alertId: string; body: unknown };

/** Answers every POST of a review with `answer(posted, n)`, and records each as the server read it. */
function serveReview(answer: (posted: Posted, n: number) => Response | Promise<Response>) {
  const posts: Posted[] = [];
  server.use(
    http.post(`${DIGEST_URL}/:alertId/review`, async ({ request, params }) => {
      const body: unknown = await request.json();
      const posted = { alertId: String(params.alertId), body };
      posts.push(posted);
      return answer(posted, posts.length);
    }),
  );
  return posts;
}

const ok = (row: DigestRow, reopened = false) => HttpResponse.json({ row, reopened });
const refuse = (status: number, detail: unknown) => HttpResponse.json({ detail }, { status });

/** A promise held shut until `release()`, to look at the page while a request is out. */
function gate() {
  let release: () => void = () => {};
  const opened = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { opened, release: () => release() };
}

function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}

function Where() {
  const { pathname, search } = useLocation();
  return <p data-testid="where">{`${pathname}${search}`}</p>;
}
const where = () => screen.getByTestId("where").textContent;

/** The state of the current history entry, as JSON ("null" for none): what a reload would find there. */
function HistoryState() {
  return <p data-testid="history-state">{JSON.stringify(useLocation().state ?? null)}</p>;
}
const historyState = () => screen.getByTestId("history-state").textContent;

type Entry = string | { pathname: string; search?: string; state?: unknown };

function renderPage(entry: Entry = "/admin/digest", client = newClient()) {
  const view = render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <main>
          <DigestPage />
          <Where />
          <HistoryState />
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { client, ...view };
}

// --- finding things -----------------------------------------------------------------------------------

/** The row of a cluster, by the agent it came from (each agent appears once). */
const rowOf = (agent: string) => screen.getByRole("row", { name: new RegExp(agent) });
const rowById = (id: string) => {
  const found = document.querySelector(`tr[data-alert-id="${id}"]`);
  if (!(found instanceof HTMLElement)) throw new Error(`no row for ${id}`);
  return found;
};
const verdictButton = (row: HTMLElement, verdict: keyof typeof S.admin.verdict) =>
  within(row).getByRole("button", { name: S.admin.verdict[verdict] });
const picker = () => screen.getByLabelText(D.dayLabel);
const loaded = () => screen.findByRole("table", { name: D.table.label });

/** The texts of the cells of one row. */
const cellsOf = (row: HTMLElement) =>
  within(row)
    .getAllByRole("cell")
    .map((c) => c.textContent ?? "");

// --- the first read and the URL --------------------------------------------------------------------------

describe("the first read", () => {
  it("titles the page and asks the server for its default day when the URL has none", async () => {
    const days = serveDigest(digest());
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 1, name: S.admin.title.digest }),
    ).toBeInTheDocument();
    await loaded();
    expect(days).toEqual([null]);
    expect(screen.getByText(D.subtitle)).toBeInTheDocument();
  });

  it("shows the day the server answered, not the browser's", async () => {
    // The browser's date is nowhere near 2031: the day in the picker and the link are the server's.
    serveDigest(digest({ day: "2031-01-01", today: "2031-01-02" }));
    renderPage();
    await loaded();
    expect(picker()).toHaveValue("2031-01-01");
    expect(screen.getByRole("link", { name: D.today })).toHaveAttribute(
      "href",
      "/admin/digest?day=2031-01-02",
    );
  });

  it("reads the day in the URL, so a reload or a shared link keeps it", async () => {
    const days = serveDigest(digest({ day: "2026-09-28" }));
    renderPage("/admin/digest?day=2026-09-28");
    await loaded();
    expect(days).toEqual(["2026-09-28"]);
    expect(picker()).toHaveValue("2026-09-28");
    expect(where()).toBe("/admin/digest?day=2026-09-28");
  });

  it("puts a day picked in the picker into the URL and reads that day", async () => {
    const days = serveDigest((day) =>
      HttpResponse.json(digest({ day: day ?? DAY, rows: day === null ? rows() : [] })),
    );
    renderPage();
    await loaded();
    fireEvent.change(picker(), { target: { value: "2026-09-27" } });
    await waitFor(() => expect(days).toEqual([null, "2026-09-27"]));
    expect(where()).toBe("/admin/digest?day=2026-09-27");
    expect(await screen.findByText(D.noClusters.title("27/09/2026"))).toBeInTheDocument();
    expect(picker()).toHaveValue("2026-09-27");
  });

  it("replaces the history entry when a day is picked, so Back leaves the page and does not walk the days", async () => {
    serveDigest((day) => HttpResponse.json(digest({ day: day ?? DAY, rows: [] })));
    function Back() {
      const navigate = useNavigate();
      return (
        <button type="button" onClick={() => void navigate(-1)}>
          back
        </button>
      );
    }
    render(
      <QueryClientProvider client={newClient()}>
        <MemoryRouter initialEntries={["/elsewhere", "/admin/digest"]} initialIndex={1}>
          <main>
            <DigestPage />
            <Where />
            <Back />
          </main>
        </MemoryRouter>
      </QueryClientProvider>,
    );
    await screen.findByText(D.noClusters.title("29/09/2026"));
    fireEvent.change(picker(), { target: { value: "2026-09-27" } });
    await screen.findByText(D.noClusters.title("27/09/2026"));
    fireEvent.change(picker(), { target: { value: "2026-09-26" } });
    await screen.findByText(D.noClusters.title("26/09/2026"));
    expect(where()).toBe("/admin/digest?day=2026-09-26");
    fireEvent.click(screen.getByRole("button", { name: "back" }));
    expect(where()).toBe("/elsewhere");
  });

  it("does not move when the picker is cleared", async () => {
    const days = serveDigest(digest());
    renderPage();
    await loaded();
    fireEvent.change(picker(), { target: { value: "" } });
    expect(where()).toBe("/admin/digest");
    expect(days).toEqual([null]);
  });

  it("offers 'hôm nay (đến giờ)', which goes to the server's today", async () => {
    const days = serveDigest((day) => HttpResponse.json(digest({ day: day ?? DAY, rows: [] })));
    const user = userEvent.setup();
    renderPage("/admin/digest?day=2026-09-01");
    await screen.findByText(D.noClusters.title("01/09/2026"));
    await user.click(screen.getByRole("link", { name: D.today }));
    expect(where()).toBe(`/admin/digest?day=${TODAY}`);
    await screen.findByText(D.noClusters.title("30/09/2026"));
    expect(days).toEqual(["2026-09-01", TODAY]);
  });

  it("has the link before the first answer, going to the default day", () => {
    const held = gate();
    serveDigest(async () => {
      await held.opened;
      return HttpResponse.json(digest());
    });
    renderPage();
    expect(screen.getByRole("link", { name: D.today })).toHaveAttribute("href", "/admin/digest");
    held.release();
  });
});

// --- the summary and the rows ---------------------------------------------------------------------------------

describe("the summary", () => {
  it("counts the clusters, the reviewed, the waiting and the ① disagreements from the rows", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    expect(screen.getByText(D.summary.clusters(6))).toBeInTheDocument();
    expect(screen.getByText(D.summary.reviewed(3, 3))).toBeInTheDocument();
    expect(screen.getByText(D.summary.disagreements(2))).toBeInTheDocument();
    expect(D.summary.clusters(6)).toBe("6 cụm tự đóng");
    expect(D.summary.reviewed(3, 3)).toBe("3 đã duyệt · 3 chờ duyệt");
    expect(D.summary.disagreements(2)).toBe("2 cụm ① không đề xuất đóng");
  });

  it("counts a cluster reopened by a 'Sai' review as reviewed", async () => {
    serveDigest(digest({ rows: [rows()[4]!] }));
    renderPage();
    await loaded();
    expect(screen.getByText(D.summary.clusters(1))).toBeInTheDocument();
    expect(screen.getByText(D.summary.reviewed(1, 0))).toBeInTheDocument();
  });

  it("is not shown with no cluster", async () => {
    serveDigest(digest({ rows: [] }));
    renderPage();
    await screen.findByText(D.noClusters.title("29/09/2026"));
    expect(screen.queryByText(D.summary.clusters(0))).not.toBeInTheDocument();
  });
});

describe("the rows", () => {
  it("has a caption and the eight columns of the canvas", async () => {
    serveDigest(digest());
    renderPage();
    const table = await loaded();
    const headers = within(table)
      .getAllByRole("columnheader")
      .map((h) => h.textContent);
    expect(headers).toEqual([
      "Rule tự đóng",
      "Rule · mô tả",
      "Mức độ",
      "Agent",
      "Số lần",
      "Khoảng thời gian",
      "Đề xuất ①",
      "Duyệt",
    ]);
    expect(within(table).getAllByRole("row")).toHaveLength(7);
  });

  it("shows the rule, its id and category, the description, severity, agent, count and span of a row", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    const cells = cellsOf(rowOf("srv-db-02"));
    expect(cells[0]).toBe(RULE_SSH);
    expect(cells[1]).toBe("5715 · suspicious_loginsshd: authentication success");
    expect(cells[2]).toBe(S.severity.low);
    expect(cells[3]).toBe("srv-db-02");
    expect(cells[4]).toBe("42");
    expect(cells[5]).toBe("08:02 – 17:40");
    expect(cells[6]).toBe(S.ai1.action.false_positive);
    expect(cells[6]).toBe("FP");
  });

  it("shows a true_positive ① suggestion as TP (it was `escalate` before P14-T01, DEC-213)", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    // ① would not have closed it, and the cell says so beside the verdict
    expect(cellsOf(rowOf("srv-web-01"))[6]).toMatch(/^TP/);
    expect(S.ai1.action).not.toHaveProperty("escalate");
  });

  it("shows a span in the display zone, whatever the browser's", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    // 19:00Z on the 28th is 02:00 on the 29th at +07.
    expect(cellsOf(rowOf("lab-ubuntu-01"))[5]).toBe("02:00 – 02:30");
  });

  it("gives the day of each end when a cluster crosses midnight", async () => {
    serveDigest(
      digest({
        rows: [
          digestRow({
            first_seen_at: "2026-09-29T16:50:00+00:00",
            last_seen_at: "2026-09-29T17:10:00+00:00",
          }),
        ],
      }),
    );
    renderPage();
    await loaded();
    expect(cellsOf(rowOf("srv-db-02"))[5]).toBe("29/09 23:50 – 30/09 00:10");
  });

  it("marks the clusters ① did not suggest closing, and only those", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    for (const agent of ["srv-web-01", "lab-ubuntu-02"]) {
      const row = rowOf(agent);
      expect(within(row).getByText(D.disagreement)).toBeInTheDocument();
      expect(row).toHaveAttribute("data-disagreement", "true");
    }
    for (const agent of ["srv-db-02", "lab-ubuntu-01", "srv-db-01", "srv-app-03"]) {
      const row = rowOf(agent);
      expect(within(row).queryByText(D.disagreement)).not.toBeInTheDocument();
      expect(row).toHaveAttribute("data-disagreement", "false");
    }
    expect(screen.getAllByText(D.disagreement)).toHaveLength(2);
    expect(D.disagreement).toBe("⚠ ① không đề xuất đóng");
  });

  it("says ① has no result when there is no suggestion", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    expect(cellsOf(rowOf("lab-ubuntu-01"))[6]).toBe(D.noSuggestion);
    expect(D.noSuggestion).toBe("(chưa có kết quả ①)");
  });

  // DEC-101: a row a "Sai" review reopened is blind again while it is undecided, and the server leaves ①'s
  // verdict off it (no suggestion, no disagreement). "No result" would be a wrong thing to say of it.
  it("does not say ① has no result on a reopened row that carries no suggestion", async () => {
    const withheld = digestRow({
      alert_id: IDS.wrong,
      agent_name: "lab-ubuntu-02",
      suggested_action: null,
      disagreement: false,
      reviewed_verdict: "wrong",
      reviewed_by_name: "khanh-admin",
      reviewed_at: "2026-09-30T01:14:00+00:00",
      reopened_by_review: true,
    });
    serveDigest(digest({ rows: [withheld] }));
    renderPage();
    await loaded();
    const row = rowOf("lab-ubuntu-02");
    expect(cellsOf(row)[6]).toBe(D.reopenedNoSuggestion);
    expect(within(row).queryByText(D.noSuggestion)).not.toBeInTheDocument();
    expect(within(row).queryByText(D.disagreement)).not.toBeInTheDocument();
    expect(row).toHaveAttribute("data-disagreement", "false");
    expect(within(row).getByText(D.reopened)).toBeInTheDocument();
  });

  it("shows a suggestion this page has no label for as the server wrote it", async () => {
    serveDigest(digest({ rows: [digestRow({ suggested_action: "mới_lạ" })] }));
    renderPage();
    await loaded();
    expect(cellsOf(rowOf("srv-db-02"))[6]).toBe("mới_lạ");
  });

  it("shows a missing rule name as a dash", async () => {
    serveDigest(digest({ rows: [digestRow({ autoclose_rule_name: null })] }));
    renderPage();
    await loaded();
    expect(cellsOf(rowOf("srv-db-02"))[0]).toBe(S.common.missing);
  });

  it("shows a severity this page has no label for as it came", async () => {
    serveDigest(digest({ rows: [digestRow({ severity: "informational" })] }));
    renderPage();
    await loaded();
    expect(cellsOf(rowOf("srv-db-02"))[2]).toBe("informational");
  });

  it("gives each row its alert id, for a link or a test to find it by", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    expect(rowById(IDS.disagree)).toBe(rowOf("srv-web-01"));
  });

  it("shows hostile text as text", async () => {
    const markup = '<img src=x onerror="alert(1)"><b>đậm</b>';
    serveDigest(
      digest({
        rows: [
          digestRow({
            description: markup,
            agent_name: markup,
            autoclose_rule_name: markup,
            reviewed_verdict: "correct",
            reviewed_by_name: markup,
            reviewed_at: "2026-09-30T01:12:00+00:00",
          }),
        ],
      }),
    );
    const { container } = renderPage();
    await loaded();
    expect(container.querySelector("img, b")).toBeNull();
    expect(screen.getAllByText(markup, { exact: false }).length).toBeGreaterThan(0);
  });

  it("sets no style attribute anywhere (the CSP forbids one)", async () => {
    serveDigest(digest());
    const { container } = renderPage();
    await loaded();
    expect(container.querySelector("[style]")).toBeNull();
  });

  it("explains the three marks of the table below it", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    expect(screen.getByText(D.legend.disagreement)).toBeInTheDocument();
    expect(screen.getByText(D.legend.reviewed)).toBeInTheDocument();
    expect(screen.getByText(D.legend.wrong)).toBeInTheDocument();
  });
});

describe("a row that is waiting", () => {
  it("has the three verdict buttons, in the order Đúng, Sai, Không chắc, in a labelled group", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    const row = rowOf("srv-db-02");
    const group = within(row).getByRole("group", { name: D.group("5715", "srv-db-02") });
    expect(
      within(group)
        .getAllByRole("button")
        .map((b) => b.textContent),
    ).toEqual(["Đúng", "Sai", "Không chắc"]);
    expect(row).toHaveAttribute("data-state", "open");
  });
});

describe("a row that was reviewed", () => {
  it("is dimmed, shows the verdict, who reviewed it and when, and has no button", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    const row = rowOf("srv-db-01");
    expect(row).toHaveAttribute("data-state", "reviewed");
    expect(within(row).getByText(D.reviewed("Đúng"))).toBeInTheDocument();
    expect(within(row).getByText("nguyen-admin · 30/09 08:12")).toBeInTheDocument();
    expect(within(row).queryByRole("button")).not.toBeInTheDocument();
    expect(within(row).queryByText(D.reopened)).not.toBeInTheDocument();
    expect(D.reviewed("Đúng")).toBe("Đã duyệt: Đúng");
  });

  it("says Không chắc for an unsure one", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    const row = rowOf("srv-app-03");
    expect(within(row).getByText(D.reviewed("Không chắc"))).toBeInTheDocument();
    expect(within(row).getByText("khanh-admin · 30/09 08:15")).toBeInTheDocument();
  });

  it("says a row was reopened to the Tier 1 queue only when the server says it reopened it", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    const reopened = rowOf("lab-ubuntu-02");
    expect(within(reopened).getByText(D.reviewed("Sai"))).toBeInTheDocument();
    expect(within(reopened).getByText(D.reopened)).toBeInTheDocument();
    expect(within(reopened).getByText("khanh-admin · 30/09 08:14")).toBeInTheDocument();
    expect(D.reopened).toBe("đã mở lại về hàng đợi Tier 1");
    expect(screen.getAllByText(D.reopened)).toHaveLength(1);
  });

  it("does not say reopened for a stale 'Sai' of a cluster that auto-closed again", async () => {
    serveDigest(
      digest({
        rows: [
          digestRow({
            reviewed_verdict: "wrong",
            reviewed_by_name: "a",
            reopened_by_review: false,
          }),
        ],
      }),
    );
    renderPage();
    await loaded();
    expect(screen.queryByText(D.reopened)).not.toBeInTheDocument();
  });

  it("shows a verdict this page has no label for as it came, and a missing reviewer as a dash", async () => {
    serveDigest(
      digest({
        rows: [
          digestRow({
            reviewed_verdict: "mới_lạ" as DigestRow["reviewed_verdict"],
            reviewed_by_name: null,
            reviewed_at: null,
          }),
        ],
      }),
    );
    renderPage();
    await loaded();
    const row = rowOf("srv-db-02");
    expect(within(row).getByText(D.reviewed("mới_lạ"))).toBeInTheDocument();
    expect(within(row).getByText(`${S.common.missing} · ${S.common.missing}`)).toBeInTheDocument();
  });
});

// --- the empty states --------------------------------------------------------------------------------------

describe("the empty states", () => {
  it("says no rule is enabled, with a way to the rules, when there is no rule and no row", async () => {
    serveDigest(digest({ rules_enabled: false, rows: [] }));
    renderPage();
    expect(await screen.findByRole("heading", { name: D.noRules.title })).toBeInTheDocument();
    expect(screen.getByText(D.noRules.body)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: D.noRules.link })).toHaveAttribute(
      "href",
      "/admin/rules",
    );
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByText(D.noClusters.body)).not.toBeInTheDocument();
    expect(D.noRules.title).toBe("Không có gì để duyệt");
    expect(D.noRules.body).toBe(
      "Chưa có rule tự đóng nào đang bật, nên không có cụm nào bị tự đóng.",
    );
  });

  it("says no cluster was auto-closed that day, naming the day, when rules are on", async () => {
    serveDigest(digest({ day: "2026-09-28", rows: [] }));
    renderPage("/admin/digest?day=2026-09-28");
    expect(
      await screen.findByRole("heading", { name: D.noClusters.title("28/09/2026") }),
    ).toBeInTheDocument();
    expect(screen.getByText(D.noClusters.body)).toBeInTheDocument();
    expect(screen.queryByText(D.noRules.title)).not.toBeInTheDocument();
    expect(D.noClusters.title("28/09/2026")).toBe("Không có cụm nào bị tự đóng ngày 28/09/2026");
    expect(D.noClusters.body).toBe("Chọn ngày khác hoặc xem hôm nay.");
  });

  it("still shows the rows of a day when the rules have all been switched off since", async () => {
    serveDigest(digest({ rules_enabled: false }));
    renderPage();
    await loaded();
    expect(screen.queryByText(D.noRules.title)).not.toBeInTheDocument();
    expect(screen.getAllByRole("row")).toHaveLength(7);
  });
});

// --- a bad day ---------------------------------------------------------------------------------------------

describe("a bad day", () => {
  /** The server's own rule: a day is `YYYY-MM-DD` of the calendar, and anything else is a 422. */
  const strict = (day: string | null) => {
    if (day === null) return HttpResponse.json(digest());
    const valid = /^\d{4}-\d{2}-\d{2}$/.test(day) && !Number.isNaN(Date.parse(`${day}T00:00:00Z`));
    const real = valid && new Date(`${day}T00:00:00Z`).toISOString().startsWith(day);
    return real ? HttpResponse.json(digest({ day })) : refuse(422, { reason: "bad_day" });
  };

  it.each([
    ["an impossible day", "2026-02-30"],
    ["a month 13", "2026-13-01"],
    ["another ISO spelling", "20260930"],
    ["text", "hôm-qua"],
    ["an empty day", ""],
  ])(
    "falls back to the default day for %s, with a notice, and corrects the URL",
    async (_name, bad) => {
      const days = serveDigest(strict);
      renderPage(`/admin/digest?day=${encodeURIComponent(bad)}`);
      const notice = await screen.findByRole("alert");
      expect(notice).toHaveTextContent(D.badDay("29/09/2026"));
      expect(D.badDay("29/09/2026")).toBe("Ngày không hợp lệ — đang hiển thị 29/09/2026.");
      expect(days).toEqual([bad, null]);
      expect(where()).toBe("/admin/digest");
      expect(await loaded()).toBeInTheDocument();
      // It is a notice and not a page error: the page, its title and its rows are all there.
      expect(screen.queryByText(S.admin.common.loadError)).not.toBeInTheDocument();
      expect(
        screen.getByRole("heading", { level: 1, name: S.admin.title.digest }),
      ).toBeInTheDocument();
      expect(picker()).toHaveValue(DAY);
    },
  );

  it("names the day the server fell back to, not the browser's", async () => {
    serveDigest((day) =>
      day === null
        ? HttpResponse.json(digest({ day: "2031-01-02", today: "2031-01-02" }))
        : refuse(422, { reason: "bad_day" }),
    );
    renderPage("/admin/digest?day=2026-02-30");
    expect(await screen.findByRole("alert")).toHaveTextContent(D.badDay("02/01/2031"));
  });

  it("shows a skeleton, and no page error, while the fallback day loads; the notice comes with the day", async () => {
    const held = gate();
    serveDigest((day) =>
      day === null
        ? held.opened.then(() => HttpResponse.json(digest()))
        : refuse(422, { reason: "bad_day" }),
    );
    renderPage("/admin/digest?day=2026-02-30");
    await waitFor(() => expect(where()).toBe("/admin/digest"));
    expect(screen.getByRole("status")).toHaveTextContent(S.common.loading);
    expect(screen.queryByText(S.admin.common.loadError)).not.toBeInTheDocument();
    held.release();
    expect(await screen.findByRole("alert")).toHaveTextContent(D.badDay("29/09/2026"));
  });

  it("drops the notice when the admin picks a day", async () => {
    serveDigest(strict);
    renderPage("/admin/digest?day=2026-02-30");
    await screen.findByRole("alert");
    fireEvent.change(picker(), { target: { value: "2026-09-27" } });
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
    expect(where()).toBe("/admin/digest?day=2026-09-27");
  });

  it("drops the notice when the admin goes to today", async () => {
    serveDigest(strict);
    const user = userEvent.setup();
    renderPage("/admin/digest?day=2026-02-30");
    await screen.findByRole("alert");
    await user.click(screen.getByRole("link", { name: D.today }));
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
  });

  // The fallback carries its notice in the history entry (`<Navigate state>`), and a reload keeps an entry's
  // state, so the notice would come back after every reload. The page copies the flag into its own state and
  // clears the entry (P11-T15 review nit, P11-T20 row 52).
  describe("is shown once", () => {
    it("clears the flag from the history entry, and keeps the notice on screen", async () => {
      serveDigest(strict);
      renderPage("/admin/digest?day=2026-02-30");
      const notice = await screen.findByRole("alert");
      await waitFor(() => expect(historyState()).toBe("null"));
      expect(notice).toHaveTextContent(D.badDay("29/09/2026"));
      expect(screen.getByRole("alert")).toBe(notice);
      expect(where()).toBe("/admin/digest");
    });

    it("keeps the other parameters of the URL when it clears the flag", async () => {
      serveDigest(strict);
      renderPage("/admin/digest?day=2026-02-30&keep=1");
      await screen.findByRole("alert");
      await waitFor(() => expect(historyState()).toBe("null"));
      expect(where()).toBe("/admin/digest?keep=1");
    });

    it("does not show it again when the page is mounted on the entry it left (a reload)", async () => {
      serveDigest(strict);
      const first = renderPage("/admin/digest?day=2026-02-30");
      await screen.findByRole("alert");
      await waitFor(() => expect(historyState()).toBe("null"));
      const left = {
        pathname: "/admin/digest",
        state: JSON.parse(historyState() ?? "null") as unknown,
      };
      first.unmount();
      serveDigest(strict);
      renderPage(left);
      await loaded();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });

    it("shows it on a mount whose entry still carries the flag, then clears the entry", async () => {
      // What a reload finds if the page did not clear it: the notice is shown this once, and not again.
      serveDigest(strict);
      renderPage({ pathname: "/admin/digest", state: { badDay: true } });
      expect(await screen.findByRole("alert")).toHaveTextContent(D.badDay("29/09/2026"));
      await waitFor(() => expect(historyState()).toBe("null"));
      expect(screen.getByRole("alert")).toHaveTextContent(D.badDay("29/09/2026"));
    });

    it("clears nothing, and moves nowhere, on a page that had no flag", async () => {
      serveDigest(strict);
      renderPage("/admin/digest?day=2026-09-28");
      await loaded();
      expect(historyState()).toBe("null");
      expect(where()).toBe("/admin/digest?day=2026-09-28");
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    });

    it("still drops the notice when a day is picked after the entry was cleared", async () => {
      serveDigest(strict);
      renderPage("/admin/digest?day=2026-02-30");
      await screen.findByRole("alert");
      await waitFor(() => expect(historyState()).toBe("null"));
      fireEvent.change(picker(), { target: { value: "2026-09-27" } });
      await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
      expect(where()).toBe("/admin/digest?day=2026-09-27");
    });
  });

  it("is a page error, not a loop, if the default day is itself refused", async () => {
    const days = serveDigest(() => refuse(422, { reason: "bad_day" }));
    renderPage("/admin/digest?day=2026-02-30");
    expect(await screen.findByText(S.admin.common.loadError)).toBeInTheDocument();
    expect(days).toEqual(["2026-02-30", null]);
  });
});

// --- reviewing -----------------------------------------------------------------------------------------------

describe("a review", () => {
  it.each([
    ["Đúng", "correct"],
    ["Sai", "wrong"],
    ["Không chắc", "unsure"],
  ] as const)(
    "%s posts %s with the server's day, as JSON, to the alert's own route",
    async (_label, verdict) => {
      serveDigest(digest());
      const posts = serveReview(({ alertId }) =>
        ok(recorded(alertId, verdict), verdict === "wrong"),
      );
      const user = userEvent.setup();
      renderPage();
      await loaded();
      await user.click(verdictButton(rowOf("srv-db-02"), verdict));
      await waitFor(() => expect(posts).toHaveLength(1));
      expect(posts[0]).toEqual({ alertId: IDS.open, body: { day: DAY, verdict } });
    },
  );

  it("posts the day of the page, which is the URL's day", async () => {
    serveDigest(digest({ day: "2026-09-28" }));
    const posts = serveReview(({ alertId }) => ok(recorded(alertId, "correct")));
    const user = userEvent.setup();
    renderPage("/admin/digest?day=2026-09-28");
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]?.body).toEqual({ day: "2026-09-28", verdict: "correct" });
  });

  it("shows the recorded verdict, the reviewer and the time, and updates the summary", async () => {
    serveDigest(digest(), listWith(recorded(IDS.open, "correct")));
    serveReview(({ alertId }) => ok(recorded(alertId, "correct")));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    const row = rowOf("srv-db-02");
    expect(await within(row).findByText(D.reviewed("Đúng"))).toBeInTheDocument();
    expect(within(row).getByText("hoa.admin · 30/09 09:00")).toBeInTheDocument();
    expect(within(row).queryByRole("button")).not.toBeInTheDocument();
    expect(row).toHaveAttribute("data-state", "reviewed");
    expect(screen.getByText(D.summary.reviewed(4, 2))).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("adds the reopened sentence after 'Sai'", async () => {
    const wrong = recorded(IDS.open, "wrong", { reopened_by_review: true });
    serveDigest(digest(), listWith(wrong));
    serveReview(() => ok(wrong, true));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "wrong"));
    const row = rowOf("srv-db-02");
    expect(await within(row).findByText(D.reopened)).toBeInTheDocument();
    expect(within(row).getByText(D.reviewed("Sai"))).toBeInTheDocument();
  });

  it("says reopened when the answer says `reopened` even if its row does not carry the flag", async () => {
    // The read after the review is held, so what is on screen is the answer of the review itself.
    const held = gate();
    serveDigest(digest(), async () => {
      await held.opened;
      return HttpResponse.json(listWith(recorded(IDS.open, "wrong", { reopened_by_review: true })));
    });
    serveReview(({ alertId }) =>
      ok(recorded(alertId, "wrong", { reopened_by_review: false }), true),
    );
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "wrong"));
    expect(await within(rowOf("srv-db-02")).findByText(D.reopened)).toBeInTheDocument();
    held.release();
  });

  it("does not say reopened after Đúng or Không chắc", async () => {
    serveDigest(digest(), listWith(recorded(IDS.open, "unsure")));
    serveReview(({ alertId }) => ok(recorded(alertId, "unsure"), false));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "unsure"));
    await within(rowOf("srv-db-02")).findByText(D.reviewed("Không chắc"));
    expect(screen.getAllByText(D.reopened)).toHaveLength(1); // the canvas's own reopened row
  });

  it("leaves the other rows as they were", async () => {
    serveDigest(digest(), listWith(recorded(IDS.open, "correct")));
    serveReview(({ alertId }) => ok(recorded(alertId, "correct")));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    await within(rowOf("srv-db-02")).findByText(D.reviewed("Đúng"));
    for (const agent of ["srv-web-01", "lab-ubuntu-01"]) {
      expect(within(rowOf(agent)).getAllByRole("button")).toHaveLength(3);
    }
  });

  it("reads the day again, through invalidateAfter(reviewDigest): the digests, the overview and the audit", async () => {
    const days = serveDigest(digest());
    serveReview(({ alertId }) => ok(recorded(alertId, "correct")));
    const user = userEvent.setup();
    const { client } = renderPage();
    await loaded();
    const invalidate = vi.spyOn(client, "invalidateQueries");
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    await waitFor(() => expect(days).toHaveLength(2));
    expect(invalidate.mock.calls.map(([filters]) => filters?.queryKey)).toEqual([
      ...ADMIN_INVALIDATES.reviewDigest,
    ]);
  });

  it("shows the server's list after the refresh, whatever the answer said", async () => {
    // The refresh brings another admin's review of a second row, and the row just reviewed as the list has it.
    const fresh = rows();
    fresh[0] = recorded(IDS.open, "correct");
    fresh[1] = recorded(IDS.disagree, "unsure", {
      disagreement: true,
      suggested_action: "true_positive",
    });
    serveDigest(digest(), digest({ rows: fresh }));
    serveReview(({ alertId }) => ok(recorded(alertId, "correct")));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    await waitFor(() =>
      expect(within(rowOf("srv-web-01")).getByText(D.reviewed("Không chắc"))).toBeInTheDocument(),
    );
    expect(screen.getByText(D.summary.reviewed(5, 1))).toBeInTheDocument();
  });

  it("disables the row's buttons while the request is out", async () => {
    serveDigest(digest(), listWith(recorded(IDS.open, "correct")));
    const held = gate();
    serveReview(async ({ alertId }) => {
      await held.opened;
      return ok(recorded(alertId, "correct"));
    });
    const user = userEvent.setup();
    renderPage();
    await loaded();
    const row = rowOf("srv-db-02");
    await user.click(verdictButton(row, "correct"));
    await waitFor(() => expect(verdictButton(row, "correct")).toBeDisabled());
    expect(verdictButton(row, "wrong")).toBeDisabled();
    expect(verdictButton(row, "unsure")).toBeDisabled();
    expect(row).toHaveAttribute("aria-busy", "true");
    // Another row is not held up by it.
    expect(verdictButton(rowOf("srv-web-01"), "correct")).toBeEnabled();
    held.release();
    await within(row).findByText(D.reviewed("Đúng"));
  });

  it("posts once for two clicks in the same tick (the latch, not the disabled button, stops the second)", async () => {
    serveDigest(digest(), listWith(recorded(IDS.open, "correct")));
    const held = gate();
    const posts = serveReview(async ({ alertId }) => {
      await held.opened;
      return ok(recorded(alertId, "correct"));
    });
    renderPage();
    await loaded();
    const button = verdictButton(rowOf("srv-db-02"), "correct");
    // No await between the two: React has not re-rendered the button as disabled yet.
    fireEvent.click(button);
    fireEvent.click(button);
    held.release();
    await within(rowOf("srv-db-02")).findByText(D.reviewed("Đúng"));
    expect(posts).toHaveLength(1);
  });

  it("posts once for a Đúng and a Sai fired in the same tick on one row", async () => {
    serveDigest(digest(), listWith(recorded(IDS.open, "correct")));
    const held = gate();
    const posts = serveReview(async ({ alertId }) => {
      await held.opened;
      return ok(recorded(alertId, "correct"));
    });
    renderPage();
    await loaded();
    const row = rowOf("srv-db-02");
    fireEvent.click(verdictButton(row, "correct"));
    fireEvent.click(verdictButton(row, "wrong"));
    held.release();
    await within(row).findByText(D.reviewed("Đúng"));
    expect(posts).toHaveLength(1);
    expect(posts[0]?.body).toEqual({ day: DAY, verdict: "correct" });
  });

  it("lets the same row be tried again after a refusal that left its buttons", async () => {
    serveDigest(digest(), listWith(recorded(IDS.open, "correct")));
    const posts = serveReview(({ alertId }, n) =>
      n === 1 ? refuse(503, "auth disabled: x") : ok(recorded(alertId, "correct")),
    );
    const user = userEvent.setup();
    renderPage();
    await loaded();
    const row = rowOf("srv-db-02");
    await user.click(verdictButton(row, "correct"));
    await within(row).findByRole("alert");
    await user.click(verdictButton(row, "correct"));
    await within(row).findByText(D.reviewed("Đúng"));
    expect(posts).toHaveLength(2);
    expect(within(row).queryByRole("alert")).not.toBeInTheDocument();
  });
});

// --- what a review can answer instead ----------------------------------------------------------------------

describe("409 already_reviewed", () => {
  const already = () =>
    refuse(409, {
      reason: "already_reviewed",
      row: recorded(IDS.open, "correct", {
        reviewed_by_name: "nguyen-admin",
        reviewed_at: "2026-09-30T01:12:00+00:00",
      }),
    });

  it("replaces the row by the recorded verdict, in place, with the text beside it", async () => {
    const days = serveDigest(digest());
    serveReview(() => already());
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "wrong"));
    const row = rowOf("srv-db-02");
    expect(await within(row).findByRole("alert")).toHaveTextContent(
      S.admin.reason.already_reviewed,
    );
    expect(S.admin.reason.already_reviewed).toBe(
      "Cụm này đã được duyệt trước đó. Dòng đã được cập nhật theo kết quả đã ghi.",
    );
    expect(within(row).getByText(D.reviewed("Đúng"))).toBeInTheDocument();
    expect(within(row).getByText("nguyen-admin · 30/09 08:12")).toBeInTheDocument();
    expect(within(row).queryByRole("button")).not.toBeInTheDocument();
    expect(row).toHaveAttribute("data-state", "reviewed");
    // The row is the server's own, so nothing was read again and the rest of the list is as it was.
    expect(days).toHaveLength(1);
    expect(screen.getByText(D.summary.reviewed(4, 2))).toBeInTheDocument();
    expect(screen.getAllByRole("row")).toHaveLength(7);
  });

  it("has no alert on the other rows", async () => {
    serveDigest(digest());
    serveReview(() => already());
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "wrong"));
    await within(rowOf("srv-db-02")).findByRole("alert");
    expect(screen.getAllByRole("alert")).toHaveLength(1);
  });

  it("reads the list again, and keeps the text, when the answer carries no usable row", async () => {
    const fresh = rows();
    fresh[0] = recorded(IDS.open, "unsure", { reviewed_by_name: "lan.admin" });
    const days = serveDigest(digest(), digest({ rows: fresh }));
    serveReview(() => refuse(409, { reason: "already_reviewed" }));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "wrong"));
    const row = rowOf("srv-db-02");
    await waitFor(() =>
      expect(within(row).getByText(D.reviewed("Không chắc"))).toBeInTheDocument(),
    );
    expect(days).toHaveLength(2);
    expect(within(row).getByRole("alert")).toHaveTextContent(S.admin.reason.already_reviewed);
  });
});

describe("409 not_auto_closed", () => {
  it("replaces the buttons of that row by the sentence, naming the cluster", async () => {
    const days = serveDigest(digest());
    serveReview(() => refuse(409, { reason: "not_auto_closed" }));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "wrong"));
    const row = rowOf("srv-db-02");
    const alert = await within(row).findByRole("alert");
    expect(alert).toHaveTextContent(D.notAutoClosed("…1661001"));
    expect(D.notAutoClosed("…1661001")).toBe(
      "Cụm …1661001 không còn ở trạng thái tự đóng (đã được mở lại), nên không duyệt được nữa.",
    );
    expect(within(row).queryByRole("button")).not.toBeInTheDocument();
    // The row stays, with its sentence: it is not read away, and the other rows keep their buttons.
    expect(days).toHaveLength(1);
    expect(within(rowOf("srv-web-01")).getAllByRole("button")).toHaveLength(3);
    expect(screen.getAllByRole("alert")).toHaveLength(1);
  });
});

describe("404", () => {
  it("says not_in_digest in the row and takes its buttons away", async () => {
    serveDigest(digest());
    serveReview(() => refuse(404, { reason: "not_in_digest" }));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    const row = rowOf("srv-db-02");
    expect(await within(row).findByRole("alert")).toHaveTextContent(S.admin.reason.not_in_digest);
    expect(within(row).queryByRole("button")).not.toBeInTheDocument();
  });

  it("says not_found, for an alert id the route could not read, in the row", async () => {
    serveDigest(digest());
    serveReview(() => refuse(404, "not found"));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    const row = rowOf("srv-db-02");
    expect(await within(row).findByRole("alert")).toHaveTextContent(S.admin.reason.not_found);
    expect(within(row).queryByRole("button")).not.toBeInTheDocument();
  });
});

describe("422", () => {
  it("says the verdict is invalid in the row, which stays as it was, with its buttons", async () => {
    const days = serveDigest(digest());
    serveReview(() => refuse(422, { field: "verdict", reason: "invalid" }));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    const row = rowOf("srv-db-02");
    expect(await within(row).findByRole("alert")).toHaveTextContent(D.invalidVerdict);
    expect(D.invalidVerdict).toBe("Đánh giá không hợp lệ. Dòng giữ nguyên, chưa ghi gì.");
    expect(within(row).getAllByRole("button")).toHaveLength(3);
    expect(row).toHaveAttribute("data-state", "open");
    expect(days).toHaveLength(1);
    expect(screen.getByText(D.summary.reviewed(3, 3))).toBeInTheDocument();
  });

  it("says a bad day in the row, which keeps its buttons", async () => {
    serveDigest(digest());
    serveReview(() => refuse(422, { reason: "bad_day" }));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    const row = rowOf("srv-db-02");
    expect(await within(row).findByRole("alert")).toHaveTextContent(S.admin.reason.bad_day);
    expect(within(row).getAllByRole("button")).toHaveLength(3);
  });

  it("does not show FastAPI's own list of errors, but says the save failed", async () => {
    serveDigest(digest());
    serveReview(() =>
      refuse(422, [{ type: "x", loc: ["body"], msg: "Field required", input: null }]),
    );
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    const alert = await within(rowOf("srv-db-02")).findByRole("alert");
    expect(alert).toHaveTextContent(D.saveFailed(422));
    expect(alert).not.toHaveTextContent("Field required");
  });
});

describe("a write that fails for another reason", () => {
  it("says a 503 in Vietnamese, not the server's English, and leaves the buttons", async () => {
    serveDigest(digest());
    serveReview(() => refuse(503, "auth disabled: no key"));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    const row = rowOf("srv-db-02");
    const alert = await within(row).findByRole("alert");
    expect(alert).toHaveTextContent(D.saveFailed(503));
    expect(alert).not.toHaveTextContent("auth disabled");
    expect(D.saveFailed(503)).toBe("Không lưu được: máy chủ trả lỗi 503. Thử lại.");
    expect(within(row).getAllByRole("button")).toHaveLength(3);
  });

  it("says the connection failed when there was no answer", async () => {
    serveDigest(digest());
    serveReview(() => HttpResponse.error());
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    const row = rowOf("srv-db-02");
    expect(await within(row).findByRole("alert")).toHaveTextContent(D.saveFailed(0));
    expect(D.saveFailed(0)).toBe("Không lưu được: mất kết nối máy chủ. Thử lại.");
    expect(within(row).getAllByRole("button")).toHaveLength(3);
  });

  it("says a 403 in the reason's text: the account may have lost its role", async () => {
    serveDigest(digest());
    serveReview(() => refuse(403, "forbidden"));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    expect(await within(rowOf("srv-db-02")).findByRole("alert")).toHaveTextContent(
      S.admin.reason.forbidden,
    );
  });

  it("does not read the digest again after a refusal that wrote nothing", async () => {
    const days = serveDigest(digest());
    serveReview(() => refuse(503, "x"));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    await within(rowOf("srv-db-02")).findByRole("alert");
    expect(days).toHaveLength(1);
  });
});

// --- the focus ------------------------------------------------------------------------------------------------

describe("the focus", () => {
  /** The element of a row that holds its answer (the verdict, or the sentence): it takes the focus. */
  const answerOf = (row: HTMLElement) => {
    const found = row.querySelector("[tabindex='-1']");
    if (!(found instanceof HTMLElement)) throw new Error("the row has no answer to focus");
    return found;
  };

  it("goes to the answer of a row whose buttons the review took away", async () => {
    serveDigest(digest(), listWith(recorded(IDS.open, "correct")));
    serveReview(({ alertId }) => ok(recorded(alertId, "correct")));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    await within(rowOf("srv-db-02")).findByText(D.reviewed("Đúng"));
    await waitFor(() => expect(answerOf(rowOf("srv-db-02"))).toHaveFocus());
  });

  it("goes to the sentence that replaced the buttons", async () => {
    serveDigest(digest());
    serveReview(() => refuse(409, { reason: "not_auto_closed" }));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    await within(rowOf("srv-db-02")).findByRole("alert");
    await waitFor(() => expect(answerOf(rowOf("srv-db-02"))).toHaveFocus());
  });

  it("does not move for a row that was never pressed", async () => {
    serveDigest(digest());
    renderPage();
    await loaded();
    expect(document.body).toHaveFocus();
  });

  it("is not taken by a later read that shows the row reviewed after a refused write", async () => {
    serveDigest(digest(), listWith(recorded(IDS.open, "correct")));
    serveReview(() => refuse(503, "x"));
    const user = userEvent.setup();
    const { client } = renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    await within(rowOf("srv-db-02")).findByRole("alert");
    await client.invalidateQueries({ queryKey: ["admin", "digest"] });
    await within(rowOf("srv-db-02")).findByText(D.reviewed("Đúng"));
    expect(answerOf(rowOf("srv-db-02"))).not.toHaveFocus();
  });
});

// --- loading and failing -------------------------------------------------------------------------------------

describe("loading", () => {
  it("shows the title, the day controls and a skeleton, announced once, until the answer comes", async () => {
    const held = gate();
    serveDigest(async () => {
      await held.opened;
      return HttpResponse.json(digest());
    });
    renderPage("/admin/digest?day=2026-09-28");
    expect(
      screen.getByRole("heading", { level: 1, name: S.admin.title.digest }),
    ).toBeInTheDocument();
    expect(picker()).toHaveValue("2026-09-28");
    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("aria-busy", "true");
    expect(status).toHaveTextContent(S.common.loading);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    held.release();
    await loaded();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows no stale day's rows while another day loads", async () => {
    const held = gate();
    serveDigest(digest(), async () => {
      await held.opened;
      return HttpResponse.json(digest({ day: "2026-09-27", rows: [] }));
    });
    renderPage();
    await loaded();
    fireEvent.change(picker(), { target: { value: "2026-09-27" } });
    await waitFor(() => expect(screen.queryByRole("table")).not.toBeInTheDocument());
    expect(screen.getByRole("status")).toBeInTheDocument();
    held.release();
    await screen.findByText(D.noClusters.title("27/09/2026"));
  });
});

describe("a failed read", () => {
  it("is a page error with a retry, and the server's code is said in Vietnamese", async () => {
    const days = serveDigest(() => refuse(500, "boom"), digest());
    const user = userEvent.setup();
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(
      within(alert).getByRole("heading", { name: S.admin.common.loadError }),
    ).toBeInTheDocument();
    expect(screen.getByText(D.loadErrorServer(500))).toBeInTheDocument();
    expect(screen.queryByText("boom")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: S.common.retry }));
    await loaded();
    expect(days).toHaveLength(2);
    expect(screen.queryByText(S.admin.common.loadError)).not.toBeInTheDocument();
  });

  it("says a 503 in Vietnamese, not the server's English (the one the route can send: auth disabled)", async () => {
    // `deps.py`: with no JWT secret the guard answers 503 with a plain English text; the digest routes send no
    // reason of their own on a read.
    serveDigest(() => refuse(503, "auth disabled: JWT_SECRET unset"));
    renderPage();
    await screen.findByRole("alert");
    expect(screen.getByText(D.loadErrorServer(503))).toBeInTheDocument();
    expect(screen.queryByText(/auth disabled/)).not.toBeInTheDocument();
    expect(screen.queryByText(/JWT_SECRET/)).not.toBeInTheDocument();
  });

  it("says the connection failed when there was no answer", async () => {
    serveDigest(() => HttpResponse.error());
    renderPage();
    await screen.findByRole("alert");
    expect(screen.getByText(D.loadErrorOffline)).toBeInTheDocument();
  });

  it("says a 403 in the reason's text", async () => {
    serveDigest(() => refuse(403, "forbidden"));
    renderPage();
    await screen.findByRole("alert");
    expect(screen.getByText(S.admin.reason.forbidden)).toBeInTheDocument();
  });

  it("keeps the page it has, and says so, when the read after a review fails", async () => {
    const days = serveDigest(digest(), () => refuse(500, "boom"), digest());
    serveReview(({ alertId }) => ok(recorded(alertId, "correct")));
    const user = userEvent.setup();
    renderPage();
    await loaded();
    await user.click(verdictButton(rowOf("srv-db-02"), "correct"));
    const notice = await screen.findByText(D.refreshFailed);
    expect(notice.closest("[role=alert]")).not.toBeNull();
    // The review is on the page, the title is, and the page error is not.
    expect(within(rowOf("srv-db-02")).getByText(D.reviewed("Đúng"))).toBeInTheDocument();
    expect(screen.queryByText(S.admin.common.loadError)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: S.common.retry }));
    await waitFor(() => expect(screen.queryByText(D.refreshFailed)).not.toBeInTheDocument());
    expect(days).toHaveLength(3);
  });
});

// --- accessibility ---------------------------------------------------------------------------------------------

describe("accessibility", () => {
  // jsdom computes no colours, so the contrast rule is off; the colours are the canvas's.
  const clean = async (container: HTMLElement) => {
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
  };

  it("has no axe violation in the normal state", async () => {
    serveDigest(digest());
    const { container } = renderPage();
    await loaded();
    await clean(container);
  });

  it("has none with no rule enabled", async () => {
    serveDigest(digest({ rules_enabled: false, rows: [] }));
    const { container } = renderPage();
    await screen.findByRole("heading", { name: D.noRules.title });
    await clean(container);
  });

  it("has none with no cluster that day", async () => {
    serveDigest(digest({ rows: [] }));
    const { container } = renderPage();
    await screen.findByText(D.noClusters.body);
    await clean(container);
  });

  it("has none while loading", async () => {
    const held = gate();
    serveDigest(async () => {
      await held.opened;
      return HttpResponse.json(digest());
    });
    const { container } = renderPage();
    await clean(container);
    held.release();
    await loaded();
  });

  it("has none in the page error", async () => {
    serveDigest(() => refuse(500, "boom"));
    const { container } = renderPage();
    await screen.findByRole("alert");
    await clean(container);
  });

  it("has none with the bad-day notice", async () => {
    serveDigest((day) =>
      day === null ? HttpResponse.json(digest()) : refuse(422, { reason: "bad_day" }),
    );
    const { container } = renderPage("/admin/digest?day=2026-02-30");
    await screen.findByRole("alert");
    await loaded();
    await clean(container);
  });

  it("has none with an alert in each of three rows", async () => {
    serveDigest(digest());
    const answers: Record<string, () => Response> = {
      [IDS.open]: () => refuse(409, { reason: "not_auto_closed" }),
      [IDS.disagree]: () => refuse(422, { field: "verdict", reason: "invalid" }),
      [IDS.noSuggestion]: () =>
        refuse(409, { reason: "already_reviewed", row: recorded(IDS.noSuggestion, "correct") }),
    };
    serveReview(({ alertId }) => answers[alertId]?.() ?? ok(recorded(alertId, "correct")));
    const user = userEvent.setup();
    const { container } = renderPage();
    await loaded();
    for (const agent of ["srv-db-02", "srv-web-01", "lab-ubuntu-01"]) {
      await user.click(verdictButton(rowOf(agent), "correct"));
      await within(rowOf(agent)).findByRole("alert");
    }
    expect(screen.getAllByRole("alert")).toHaveLength(3);
    await clean(container);
  });
});
