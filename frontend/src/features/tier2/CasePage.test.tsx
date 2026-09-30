// src/features/tier2/CasePage.test.tsx — the case page of the spec §4 (`Case` artboard): the left column
// (heads, notes, conclusion) against a mocked backend. The ② column has its own file.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { setupServer } from "msw/node";
import { Link, MemoryRouter, Route, Routes } from "react-router";
import { S } from "../../strings";
import { CasePage } from "./CasePage";

const CASE = "0b30b853-1c2d-4e5f-8a9b-0c1d2e3f4a5b";
const CASE_URL = `/api/tier2/cases/${CASE}`;

const server = setupServer(
  // The ② column reads its own state; these tests are about the left column, so it is idle.
  http.get(`${CASE_URL}/investigation`, () =>
    HttpResponse.json({
      state: "idle",
      run_id: null,
      minutes: null,
      run: null,
      current: null,
      case_open: true,
    }),
  ),
);
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const head = (over: Record<string, unknown> = {}) => ({
  alert_id: "a-1",
  rule_id: "5712",
  severity: "high",
  description: "sshd: brute force trying to get access",
  agent_name: "lab-ubuntu-01",
  alert_time: "2026-09-26T01:00:00+00:00",
  srcip: "127.0.0.1",
  category: "authentication",
  occurrence_count: 6,
  status: "escalated_tier2",
  raw_log: "Sep 26 08:00:01 lab sshd[123]: Failed password for root from 127.0.0.1",
  raw_log_truncated: false,
  risk_band: "Cao",
  last_seen_at: "2026-09-26T04:12:00+00:00",
  ...over,
});

const note = (over: Record<string, unknown> = {}) => ({
  note_id: 1,
  case_id: CASE,
  author_id: "u-2",
  author_name: "nguyen",
  body: "Nguồn là 127.0.0.x trên chính máy lab.",
  created_at: "2026-09-30T01:12:00+00:00",
  ...over,
});

const detail = (over: Record<string, unknown> = {}) => ({
  case_id: CASE,
  title: "SSH brute force vào lab-ubuntu-01",
  status: "investigating",
  severity: "high",
  created_by: "u-1",
  created_at: "2026-09-26T04:14:00+00:00",
  last_analyzed_at: "2026-09-30T01:19:00+00:00",
  concluded_by: null,
  concluded_at: null,
  conclusion_reason: null,
  concluded_by_name: null,
  ongoing: false,
  ongoing_last_seen: null,
  heads: [head()],
  notes: [note()],
  ...over,
});

const concluded = (over: Record<string, unknown> = {}) =>
  detail({
    status: "concluded_fp",
    concluded_by: "u-9",
    concluded_by_name: "Lan",
    concluded_at: "2026-09-30T02:00:00+00:00",
    conclusion_reason: "Script kiểm thử của nhóm hạ tầng",
    ...over,
  });

const serve = (body: JsonBodyType, status = 200) =>
  server.use(http.get(CASE_URL, () => HttpResponse.json(body, { status })));

// A fresh client per render, so no test reads what another one cached; `retry: false` so a failed read
// shows at once (T09's tests do the same).
const newClient = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });

function renderCase(client: QueryClient = newClient()) {
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/cases/${CASE}`]}>
        <main>
          <Routes>
            <Route path="/cases/:caseId" element={<CasePage />} />
          </Routes>
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

async function page() {
  return screen.findByRole("heading", { level: 1, name: "SSH brute force vào lab-ubuntu-01" });
}

describe("the summary", () => {
  it("shows the title, the status label, the severity, the counts and the dates in +07", async () => {
    serve(detail());
    renderCase();
    await page();
    const summary = screen.getByRole("region", { name: S.case.summaryLabel });
    expect(within(summary).getByText("Đang điều tra")).toBeInTheDocument();
    expect(within(summary).getByText(/Cao/)).toBeInTheDocument();
    expect(within(summary).getByText("26/09/2026 11:14:00")).toBeInTheDocument();
    expect(within(summary).getByText("30/09/2026 08:19:00")).toBeInTheDocument();
    expect(within(summary).getByText(S.case.clusterCount(1))).toBeInTheDocument();
  });

  it("says 'chưa phân tích' for a case ② has not run on", async () => {
    serve(detail({ last_analyzed_at: null }));
    renderCase();
    await page();
    expect(screen.getByText(S.case.neverAnalysed)).toBeInTheDocument();
  });

  it("says 'Không tìm thấy case' for a 404, with no retry, since a retry cannot succeed", async () => {
    serve({ detail: "case not found" }, 404);
    renderCase();
    expect(await screen.findByText(S.case.notFound)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.common.retry })).not.toBeInTheDocument();
  });

  it("says 'Không tìm thấy case' for a case id the server cannot read (422), with no retry", async () => {
    serve({ detail: [{ msg: "Input should be a valid UUID" }] }, 422);
    renderCase();
    expect(await screen.findByText(S.case.notFound)).toBeInTheDocument();
    expect(screen.queryByText(S.common.unknownError)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.common.retry })).not.toBeInTheDocument();
  });

  it("offers a retry after any other failure, and loads again when it is pressed", async () => {
    let calls = 0;
    server.use(
      http.get(CASE_URL, () => {
        calls += 1;
        return calls === 1
          ? HttpResponse.json({ detail: "boom" }, { status: 500 })
          : HttpResponse.json(detail());
      }),
    );
    renderCase();
    expect(await screen.findByText(S.common.unknownError)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: S.common.retry }));
    await page();
    expect(calls).toBe(2);
  });
});

describe("the heads", () => {
  it("shows a head's risk band, status label, last seen and description with a link to its alert", async () => {
    serve(detail());
    renderCase();
    await page();
    const row = screen.getByRole("row", { name: /sshd: brute force/ });
    expect(within(row).getByText("Cao")).toHaveAttribute("data-band", "high");
    expect(within(row).getByText("Đang xử lý Tier 2")).toBeInTheDocument();
    expect(within(row).getByText("26/09 11:12")).toBeInTheDocument();
    expect(within(row).getByText("5712")).toBeInTheDocument();
    expect(within(row).getByRole("link", { name: /sshd: brute force/ })).toHaveAttribute(
      "href",
      "/alerts/a-1",
    );
  });

  it("colours a band by its code: the label Rất cao is critical", async () => {
    serve(
      detail({
        heads: [
          head({ alert_id: "a-1", risk_band: "Rất cao" }),
          head({ alert_id: "a-2", description: "second", risk_band: "Thấp" }),
        ],
      }),
    );
    renderCase();
    await page();
    expect(screen.getByText("Rất cao")).toHaveAttribute("data-band", "critical");
    expect(screen.getByText("Thấp")).toHaveAttribute("data-band", "low");
  });

  it("shows a band label it does not know as the text it is, in a neutral style", async () => {
    serve(detail({ heads: [head({ risk_band: "Khẩn cấp" })] }));
    renderCase();
    await page();
    expect(screen.getByText("Khẩn cấp")).toHaveAttribute("data-band", "unknown");
  });

  it("shows a dash for a head with no band", async () => {
    serve(detail({ heads: [head({ risk_band: null })] }));
    renderCase();
    await page();
    const row = screen.getByRole("row", { name: /sshd: brute force/ });
    expect(within(row).getByText(S.common.missing)).toHaveAttribute("data-band", "unknown");
  });

  it("keeps each raw log collapsed until asked, then shows it as text in a pre", async () => {
    serve(detail());
    renderCase();
    await page();
    const log = "Failed password for root from 127.0.0.1";
    expect(screen.queryByText(new RegExp(log))).not.toBeInTheDocument();
    const toggle = screen.getByRole("button", { name: S.case.showLog });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveAccessibleDescription(S.case.rawLogOf("a-1"));
    await userEvent.setup().click(toggle);
    const pre = screen.getByText(new RegExp(log));
    expect(pre.tagName).toBe("PRE");
    expect(screen.getByRole("button", { name: S.case.hideLog })).toHaveAttribute(
      "aria-expanded",
      "true",
    );
  });

  it("marks a truncated raw log, before it is opened and after", async () => {
    serve(detail({ heads: [head({ raw_log_truncated: true })] }));
    renderCase();
    await page();
    expect(screen.getByText(S.case.truncated)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: S.case.showLog }));
    expect(screen.getByText(S.case.truncated)).toBeInTheDocument();
  });

  it("marks no truncation on a whole raw log", async () => {
    serve(detail());
    renderCase();
    await page();
    expect(screen.queryByText(S.case.truncated)).not.toBeInTheDocument();
  });

  it("renders a hostile raw log as text and makes no element of it", async () => {
    const hostile = "<img src=x onerror=alert(1)> </script> ‮ <b>bold</b> \u001b[31mred";
    serve(detail({ heads: [head({ raw_log: hostile })] }));
    const { container } = renderCase();
    await page();
    await userEvent.setup().click(screen.getByRole("button", { name: S.case.showLog }));
    const pre = container.querySelector("pre");
    expect(pre?.textContent).toBe(hostile);
    expect(container.querySelector("img, b, script")).toBeNull();
  });

  it("renders a raw log of 1000 KB in one pre and no other element", async () => {
    const big = "x".repeat(1_000_000);
    serve(detail({ heads: [head({ raw_log: big, raw_log_truncated: true })] }));
    const { container } = renderCase();
    await page();
    // The ② column loads by itself; count only once it has settled.
    await screen.findByRole("button", { name: S.ai2.analyze });
    const before = container.querySelectorAll("*").length;
    await userEvent.setup().click(screen.getByRole("button", { name: S.case.showLog }));
    expect(container.querySelector("pre")?.textContent).toHaveLength(1_000_000);
    expect(container.querySelectorAll("*").length).toBe(before + 1);
  });

  it("says so when the case has no head", async () => {
    serve(detail({ heads: [] }));
    renderCase();
    await page();
    expect(screen.getByText(S.case.noHeads)).toBeInTheDocument();
  });
});

describe("the attack is still going on", () => {
  it("shows 'Còn tiếp diễn' with the last time seen and the hint to run ② again", async () => {
    serve(detail({ ongoing: true, ongoing_last_seen: "2026-09-30T02:30:00+00:00" }));
    renderCase();
    await page();
    expect(screen.getByText(S.case.ongoing)).toBeInTheDocument();
    expect(screen.getByText(S.case.ongoingHint("30/09 09:30"))).toBeInTheDocument();
  });

  it("shows nothing about it when the case is not ongoing", async () => {
    serve(detail({ ongoing: false }));
    renderCase();
    await page();
    expect(screen.queryByText(S.case.ongoing)).not.toBeInTheDocument();
  });
});

describe("the timeline", () => {
  it("lists what the case detail records, oldest first, with the note author's name", async () => {
    serve(detail());
    renderCase();
    await page();
    const items = within(screen.getByRole("list", { name: S.case.timeline })).getAllByRole(
      "listitem",
    );
    expect(items.map((li) => li.textContent)).toEqual([
      `26/09 11:14${S.case.timelineCreated}`,
      `30/09 08:12${S.case.timelineNote("nguyen")}`,
      `30/09 08:19${S.case.timelineAnalysed}`,
    ]);
  });
});

describe("the notes", () => {
  it("shows each note with the author's name, and the id when the server knows no name", async () => {
    serve(
      detail({
        notes: [
          note(),
          note({ note_id: 2, author_id: "u-77", author_name: null, body: "second note" }),
        ],
      }),
    );
    renderCase();
    await page();
    const list = screen.getByRole("list", { name: S.case.notes });
    expect(within(list).getByText("nguyen")).toBeInTheDocument();
    expect(within(list).getByText("Nguồn là 127.0.0.x trên chính máy lab.")).toBeInTheDocument();
    expect(within(list).getByText("u-77")).toBeInTheDocument();
    // Both notes were written at the same minute.
    expect(within(list).getAllByText("30/09 08:12", { exact: false })).toHaveLength(2);
  });

  it("says so when there is no note", async () => {
    serve(detail({ notes: [] }));
    renderCase();
    await page();
    expect(screen.getByText(S.case.noNotes)).toBeInTheDocument();
  });

  it("posts a note, then loads the case again and shows it", async () => {
    let gets = 0;
    let posted: unknown = null;
    const notes = [note()];
    server.use(
      http.get(CASE_URL, () => {
        gets += 1;
        return HttpResponse.json(detail({ notes: [...notes] }));
      }),
      http.post(`${CASE_URL}/notes`, async ({ request }) => {
        posted = await request.json();
        const added = note({ note_id: 2, author_name: "an", body: "Đã hỏi nhóm hạ tầng" });
        notes.push(added);
        return HttpResponse.json(added, { status: 201 });
      }),
    );
    renderCase();
    await page();
    expect(gets).toBe(1);
    const user = userEvent.setup();
    const box = screen.getByLabelText(S.case.addNote);
    await user.type(box, "Đã hỏi nhóm hạ tầng");
    await user.click(screen.getByRole("button", { name: S.case.saveNote }));
    expect(await screen.findByText("Đã hỏi nhóm hạ tầng", { selector: "p" })).toBeInTheDocument();
    expect(posted).toEqual({ body: "Đã hỏi nhóm hạ tầng" });
    expect(gets).toBe(2);
    expect(box).toHaveValue("");
  });

  it("makes the case list stale after a note, so the next look at it reads it again", async () => {
    server.use(
      http.get(CASE_URL, () => HttpResponse.json(detail())),
      http.post(`${CASE_URL}/notes`, () =>
        HttpResponse.json(note({ note_id: 2 }), { status: 201 }),
      ),
    );
    const client = newClient();
    // A page of the list, read earlier and no longer on screen.
    client.setQueryData(["cases", 0], []);
    renderCase(client);
    await page();
    expect(client.getQueryState(["cases", 0])?.isInvalidated).toBe(false);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(S.case.addNote), "ghi chú mới");
    await user.click(screen.getByRole("button", { name: S.case.saveNote }));
    await waitFor(() => expect(client.getQueryState(["cases", 0])?.isInvalidated).toBe(true));
  });

  it("does not post an empty note", async () => {
    serve(detail());
    renderCase();
    await page();
    const user = userEvent.setup();
    expect(screen.getByRole("button", { name: S.case.saveNote })).toBeDisabled();
    await user.type(screen.getByLabelText(S.case.addNote), "   ");
    expect(screen.getByRole("button", { name: S.case.saveNote })).toBeDisabled();
  });

  it("keeps the typed note and says why when the server refuses it", async () => {
    server.use(
      http.get(CASE_URL, () => HttpResponse.json(detail())),
      http.post(`${CASE_URL}/notes`, () =>
        HttpResponse.json({ detail: "body: too long" }, { status: 422 }),
      ),
    );
    renderCase();
    await page();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(S.case.addNote), "a note");
    await user.click(screen.getByRole("button", { name: S.case.saveNote }));
    expect(await screen.findByRole("alert")).toHaveTextContent(S.case.noteInvalid);
    expect(screen.getByLabelText(S.case.addNote)).toHaveValue("a note");
  });
});

describe("the conclusion", () => {
  it("offers exactly the three conclusions, in their Vietnamese labels", async () => {
    serve(detail());
    renderCase();
    await page();
    const group = screen.getByRole("group", { name: S.case.pickConclusion });
    const radios = within(group).getAllByRole("radio");
    expect(radios.map((r) => r.getAttribute("value")).sort()).toEqual([
      "concluded_fp",
      "concluded_policy_violation",
      "confirmed_incident",
    ]);
    expect(within(group).getByRole("radio", { name: "Dương tính giả" })).toHaveAttribute(
      "value",
      "concluded_fp",
    );
    expect(within(group).getByRole("radio", { name: "Vi phạm chính sách" })).toHaveAttribute(
      "value",
      "concluded_policy_violation",
    );
    expect(within(group).getByRole("radio", { name: "Xác nhận sự cố" })).toHaveAttribute(
      "value",
      "confirmed_incident",
    );
  });

  it("puts the scope note beside 'Xác nhận sự cố' and beside no other choice", async () => {
    serve(detail());
    renderCase();
    await page();
    const incident = screen.getByRole("radio", { name: "Xác nhận sự cố" });
    expect(incident).toHaveAccessibleDescription(S.case.scopeNote);
    expect(incident.closest("[data-conclusion]")).toHaveTextContent(S.case.scopeNote);
    for (const name of ["Dương tính giả", "Vi phạm chính sách"]) {
      const radio = screen.getByRole("radio", { name });
      expect(radio).not.toHaveAccessibleDescription(S.case.scopeNote);
      expect(radio.closest("[data-conclusion]")).not.toHaveTextContent(S.case.scopeNote);
    }
  });

  it("sends the choice and the reason only when both are given, then shows the conclusion", async () => {
    let posted: unknown = null;
    // What the server holds: it is the answer of the POST once the POST has been made.
    let held = detail();
    server.use(
      http.get(CASE_URL, () => HttpResponse.json(held)),
      http.post(`${CASE_URL}/conclude`, async ({ request }) => {
        posted = await request.json();
        held = concluded({
          status: "concluded_policy_violation",
          conclusion_reason: "Vi phạm nội quy",
        });
        return HttpResponse.json(held);
      }),
    );
    renderCase();
    await page();
    const user = userEvent.setup();
    const submit = screen.getByRole("button", { name: S.case.concludeSubmit });
    expect(submit).toBeDisabled();
    await user.click(screen.getByRole("radio", { name: "Vi phạm chính sách" }));
    expect(submit).toBeDisabled();
    await user.type(screen.getByLabelText(S.case.reasonRequired), "Vi phạm nội quy");
    expect(submit).toBeEnabled();
    await user.click(submit);
    await screen.findByText("Vi phạm nội quy");
    expect(posted).toEqual({ conclusion: "concluded_policy_violation", reason: "Vi phạm nội quy" });
    expect(screen.queryByRole("button", { name: S.case.concludeSubmit })).not.toBeInTheDocument();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
  });

  it("reads the case again and makes the case list stale once it is concluded", async () => {
    let gets = 0;
    let held = detail();
    server.use(
      http.get(CASE_URL, () => {
        gets += 1;
        return HttpResponse.json(held);
      }),
      http.post(`${CASE_URL}/conclude`, () => {
        held = concluded();
        return HttpResponse.json(held);
      }),
    );
    const client = newClient();
    client.setQueryData(["cases", 0], []);
    renderCase(client);
    await page();
    expect(gets).toBe(1);
    const user = userEvent.setup();
    await user.click(screen.getByRole("radio", { name: "Dương tính giả" }));
    await user.type(screen.getByLabelText(S.case.reasonRequired), "lý do");
    await user.click(screen.getByRole("button", { name: S.case.concludeSubmit }));
    await screen.findByText("Script kiểm thử của nhóm hạ tầng");
    await waitFor(() => expect(gets).toBe(2));
    expect(client.getQueryState(["cases", 0])?.isInvalidated).toBe(true);
    // The read behind the answer says what the answer said.
    expect(screen.getByText("Script kiểm thử của nhóm hạ tầng")).toBeInTheDocument();
  });

  it("names who concluded it first, by name, when the server answers 409", async () => {
    let gets = 0;
    server.use(
      http.get(CASE_URL, () => {
        gets += 1;
        return HttpResponse.json(gets === 1 ? detail() : concluded());
      }),
      http.post(`${CASE_URL}/conclude`, () =>
        HttpResponse.json(
          {
            detail: {
              status: "concluded_fp",
              concluded_by: "u-9",
              concluded_at: "2026-09-30T02:00:00+00:00",
            },
          },
          { status: 409 },
        ),
      ),
    );
    renderCase();
    await page();
    const user = userEvent.setup();
    await user.click(screen.getByRole("radio", { name: "Xác nhận sự cố" }));
    await user.type(screen.getByLabelText(S.case.reasonRequired), "chắc chắn");
    await user.click(screen.getByRole("button", { name: S.case.concludeSubmit }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(S.case.conflict);
    expect(alert).toHaveTextContent(S.case.concludedBy("Lan", "30/09/2026 09:00:00"));
    // The page now shows what was concluded, and offers no second attempt.
    await waitFor(() => expect(screen.queryByRole("radio")).not.toBeInTheDocument());
  });

  it("names who concluded it by the returned id when the case has no name for them", async () => {
    let gets = 0;
    server.use(
      http.get(CASE_URL, () => {
        gets += 1;
        return HttpResponse.json(gets === 1 ? detail() : concluded({ concluded_by_name: null }));
      }),
      http.post(`${CASE_URL}/conclude`, () =>
        HttpResponse.json(
          {
            detail: {
              status: "concluded_fp",
              concluded_by: "u-9",
              concluded_at: "2026-09-30T02:00:00+00:00",
            },
          },
          { status: 409 },
        ),
      ),
    );
    renderCase();
    await page();
    const user = userEvent.setup();
    await user.click(screen.getByRole("radio", { name: "Dương tính giả" }));
    await user.type(screen.getByLabelText(S.case.reasonRequired), "lý do");
    await user.click(screen.getByRole("button", { name: S.case.concludeSubmit }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(S.case.concludedBy("u-9", "30/09/2026 09:00:00"));
  });

  it("says the wait was too long on a 503 and keeps what was typed", async () => {
    server.use(
      http.get(CASE_URL, () => HttpResponse.json(detail())),
      http.post(`${CASE_URL}/conclude`, () =>
        HttpResponse.json({ detail: "conclude: statement timeout" }, { status: 503 }),
      ),
    );
    renderCase();
    await page();
    const user = userEvent.setup();
    await user.click(screen.getByRole("radio", { name: "Dương tính giả" }));
    await user.type(screen.getByLabelText(S.case.reasonRequired), "lý do");
    await user.click(screen.getByRole("button", { name: S.case.concludeSubmit }));
    expect(await screen.findByRole("alert")).toHaveTextContent(S.decision.timeout);
    expect(screen.getByLabelText(S.case.reasonRequired)).toHaveValue("lý do");
    expect(screen.getByRole("radio", { name: "Dương tính giả" })).toBeChecked();
  });

  it("shows a concluded case its conclusion, the reason, who and when, and no form", async () => {
    serve(concluded());
    renderCase();
    await page();
    const section = screen.getByRole("region", { name: S.case.conclusionHeading });
    expect(within(section).getByText("Dương tính giả")).toBeInTheDocument();
    expect(within(section).getByText("Script kiểm thử của nhóm hạ tầng")).toBeInTheDocument();
    expect(
      within(section).getByText(S.case.concludedBy("Lan", "30/09/2026 09:00:00")),
    ).toBeInTheDocument();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.case.concludeSubmit })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.case.saveNote })).not.toBeInTheDocument();
    // What was written before stays readable.
    expect(screen.getByText("Nguồn là 127.0.0.x trên chính máy lab.")).toBeInTheDocument();
  });

  it("repeats the scope note under a concluded confirmed incident", async () => {
    serve(concluded({ status: "confirmed_incident" }));
    renderCase();
    await page();
    expect(screen.getByText("Xác nhận sự cố", { selector: "strong" })).toBeInTheDocument();
    expect(screen.getByText(S.case.scopeNote)).toBeInTheDocument();
  });

  it("falls back to the id, then to a dash, for a concluder with no name", async () => {
    serve(concluded({ concluded_by_name: null }));
    const { unmount } = renderCase();
    await page();
    expect(screen.getByText(S.case.concludedBy("u-9", "30/09/2026 09:00:00"))).toBeInTheDocument();
    unmount();
    serve(concluded({ concluded_by_name: null, concluded_by: null }));
    renderCase();
    await page();
    expect(
      screen.getByText(S.case.concludedBy(S.common.missing, "30/09/2026 09:00:00")),
    ).toBeInTheDocument();
  });
});

describe("codes the UI has no label for", () => {
  it("unknown enum renders raw code", async () => {
    serve(
      detail({
        status: "reopened_by_magic",
        severity: "catastrophic",
        heads: [head({ status: "quarantined", risk_band: "Khẩn cấp" })],
      }),
    );
    renderCase();
    await page();
    const summary = screen.getByRole("region", { name: S.case.summaryLabel });
    expect(within(summary).getByText("reopened_by_magic")).toBeInTheDocument();
    expect(within(summary).getByText("catastrophic")).toBeInTheDocument();
    const row = screen.getByRole("row", { name: /sshd: brute force/ });
    expect(within(row).getByText("quarantined")).toBeInTheDocument();
    expect(within(row).getByText("Khẩn cấp")).toBeInTheDocument();
  });

  it("shows a hostile code as text, never from the prototype chain", async () => {
    serve(detail({ heads: [head({ status: "constructor" })] }));
    renderCase();
    await page();
    const row = screen.getByRole("row", { name: /sshd: brute force/ });
    expect(within(row).getByText("constructor")).toBeInTheDocument();
  });
});

// Going from one case to another (a link, the back button) while an answer for the first is still on the
// way: the second page must never show a word of the first, for the case and for the ② column alike.
describe("going from one case to another", () => {
  const OTHER = "5c4d3e2f-1a0b-4c9d-8e7f-6a5b4c3d2e1f";
  const OTHER_URL = `/api/tier2/cases/${OTHER}`;
  const FIRST_TITLE = "SSH brute force vào lab-ubuntu-01";
  const SECOND_TITLE = "Quét cổng vào máy chủ web";
  const NEXT = "Sang case thứ hai";
  const IDLE = {
    state: "idle",
    run_id: null,
    minutes: null,
    run: null,
    current: null,
    case_open: true,
  };
  const analysis = (summary: string) => ({
    state: "done",
    run_id: null,
    minutes: null,
    run: {
      run_id: "6f1c7a52-98d4-5c0e-b3a1-2d4e6f8a0b1c",
      created_at: "2026-09-30T01:19:00+00:00",
      result: { suggested_conclusion: "false_positive" },
      conclusion: "false_positive",
      conclusion_label: "Không phải sự cố",
      confidence: "medium",
      summary,
      narrative: "-",
      hypotheses: [],
      evidence: [],
      next_steps: [],
      playbook_used: null,
      overruled: null,
      snapshot: null,
      changed: false,
    },
    current: null,
    case_open: true,
  });

  // The second case shares nothing with the first: its own title, head and notes.
  const second = () =>
    detail({
      case_id: OTHER,
      title: SECOND_TITLE,
      heads: [head({ alert_id: "b-1", description: "Quét cổng từ 10.0.0.9" })],
      notes: [],
    });

  /** A promise the test settles when it decides the answer of a read should arrive. */
  function gate() {
    let open: () => void = () => {};
    const opened = new Promise<void>((resolve) => {
      open = resolve;
    });
    return { opened, open };
  }

  // Real time: the wait is for an answer already released to travel through the network layer.
  const settle = () =>
    act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

  function renderBoth() {
    return render(
      <QueryClientProvider client={newClient()}>
        <MemoryRouter initialEntries={[`/cases/${CASE}`]}>
          <nav>
            <Link to={`/cases/${OTHER}`}>{NEXT}</Link>
          </nav>
          <main>
            <Routes>
              <Route path="/cases/:caseId" element={<CasePage />} />
            </Routes>
          </main>
        </MemoryRouter>
      </QueryClientProvider>,
    );
  }

  const secondTitle = () => screen.findByRole("heading", { level: 1, name: SECOND_TITLE });

  it("never shows the first case's detail when its answer arrives after the second's", async () => {
    const late = gate();
    server.use(
      http.get(CASE_URL, async () => {
        await late.opened;
        return HttpResponse.json(detail());
      }),
      http.get(OTHER_URL, () => HttpResponse.json(second())),
      http.get(`${OTHER_URL}/investigation`, () => HttpResponse.json(IDLE)),
    );
    renderBoth();
    await userEvent.setup().click(screen.getByRole("link", { name: NEXT }));
    await secondTitle();

    late.open();
    await settle();
    expect(screen.getByRole("heading", { level: 1, name: SECOND_TITLE })).toBeInTheDocument();
    expect(screen.queryByText(FIRST_TITLE)).not.toBeInTheDocument();
    expect(screen.getByText("Quét cổng từ 10.0.0.9")).toBeInTheDocument();
    expect(screen.queryByText("sshd: brute force trying to get access")).not.toBeInTheDocument();
  });

  it("never shows the first case's failure when it arrives after the second case is on screen", async () => {
    const late = gate();
    server.use(
      http.get(CASE_URL, async () => {
        await late.opened;
        return HttpResponse.json({ detail: "boom" }, { status: 500 });
      }),
      http.get(OTHER_URL, () => HttpResponse.json(second())),
      http.get(`${OTHER_URL}/investigation`, () => HttpResponse.json(IDLE)),
    );
    renderBoth();
    await userEvent.setup().click(screen.getByRole("link", { name: NEXT }));
    await secondTitle();

    late.open();
    await settle();
    expect(screen.getByRole("heading", { level: 1, name: SECOND_TITLE })).toBeInTheDocument();
    expect(screen.queryByText(S.common.unknownError)).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("never shows the first case's analysis when its answer arrives after the second's", async () => {
    const late = gate();
    serve(detail());
    server.use(
      http.get(`${CASE_URL}/investigation`, async () => {
        await late.opened;
        return HttpResponse.json(analysis("tóm tắt của case thứ nhất"));
      }),
      http.get(OTHER_URL, () => HttpResponse.json(second())),
      http.get(`${OTHER_URL}/investigation`, () => HttpResponse.json(IDLE)),
    );
    renderBoth();
    await page();
    await userEvent.setup().click(screen.getByRole("link", { name: NEXT }));
    await secondTitle();
    expect(await screen.findByRole("button", { name: S.ai2.analyze })).toBeInTheDocument();

    late.open();
    await settle();
    expect(screen.queryByText("tóm tắt của case thứ nhất")).not.toBeInTheDocument();
    expect(screen.getByText(S.ai2.idle)).toBeInTheDocument();
  });

  it("shows nothing of the first case while the second is still loading", async () => {
    const late = gate();
    serve(detail());
    server.use(
      http.get(`${CASE_URL}/investigation`, () =>
        HttpResponse.json(analysis("tóm tắt của case thứ nhất")),
      ),
      http.get(OTHER_URL, async () => {
        await late.opened;
        return HttpResponse.json(second());
      }),
      http.get(`${OTHER_URL}/investigation`, async () => {
        await late.opened;
        return HttpResponse.json(IDLE);
      }),
    );
    renderBoth();
    await page();
    expect(await screen.findByText("tóm tắt của case thứ nhất")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("link", { name: NEXT }));

    expect(screen.getByText(S.common.loading)).toBeInTheDocument();
    expect(screen.queryByText(FIRST_TITLE)).not.toBeInTheDocument();
    expect(screen.queryByText("tóm tắt của case thứ nhất")).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();

    late.open();
    await secondTitle();
    expect(await screen.findByText(S.ai2.idle)).toBeInTheDocument();
    expect(screen.queryByText("tóm tắt của case thứ nhất")).not.toBeInTheDocument();
  });
});

// Two reads of one case that answer out of order: only the newest counts, and an answer the page was handed
// by a POST is not overwritten by a read that began before it. (These were the guarantees of `useLoad`.)
describe("reads of one case that answer out of order", () => {
  const NEWER = "Bản đọc mới";
  const OLDER = "Bản đọc cũ";
  const CONCLUDED_REASON = "Script kiểm thử của nhóm hạ tầng";

  function gate() {
    let open: () => void = () => {};
    const opened = new Promise<void>((resolve) => {
      open = resolve;
    });
    return { opened, open };
  }

  // Real time: the wait is for an answer already released to travel through the network layer.
  const settle = () =>
    act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

  it("keeps the newer of two reads of the case when the older one answers last", async () => {
    const older = gate();
    let gets = 0;
    server.use(
      http.get(CASE_URL, async () => {
        gets += 1;
        if (gets === 1) return HttpResponse.json(detail());
        if (gets === 2) {
          await older.opened;
          return HttpResponse.json(detail({ title: OLDER }));
        }
        return HttpResponse.json(detail({ title: NEWER }));
      }),
    );
    const client = newClient();
    renderCase(client);
    await page();
    // The case is read again (a window focus) and the answer is slow; then it is read again (a note) and
    // that one answers first.
    act(() => {
      void client.invalidateQueries({ queryKey: ["case", CASE] });
    });
    await waitFor(() => expect(gets).toBe(2));
    await act(async () => {
      await client.invalidateQueries({ queryKey: ["case", CASE] });
    });
    expect(await screen.findByRole("heading", { level: 1, name: NEWER })).toBeInTheDocument();

    older.open();
    await settle();
    expect(screen.getByRole("heading", { level: 1, name: NEWER })).toBeInTheDocument();
    expect(screen.queryByText(OLDER)).not.toBeInTheDocument();
  });

  it("keeps the conclusion a POST answered when a read that began before it answers after", async () => {
    const slow = gate();
    let gets = 0;
    let held = detail();
    server.use(
      http.get(CASE_URL, async () => {
        gets += 1;
        // The second read begins before the conclusion and is slow: it carries the case still open.
        if (gets === 2) {
          await slow.opened;
          return HttpResponse.json(detail());
        }
        return HttpResponse.json(held);
      }),
      http.post(`${CASE_URL}/conclude`, () => {
        held = concluded();
        return HttpResponse.json(held);
      }),
    );
    const client = newClient();
    renderCase(client);
    await page();
    act(() => {
      void client.invalidateQueries({ queryKey: ["case", CASE] });
    });
    await waitFor(() => expect(gets).toBe(2));
    const user = userEvent.setup();
    await user.click(screen.getByRole("radio", { name: "Dương tính giả" }));
    await user.type(screen.getByLabelText(S.case.reasonRequired), "lý do");
    await user.click(screen.getByRole("button", { name: S.case.concludeSubmit }));
    await screen.findByText(CONCLUDED_REASON);

    slow.open();
    await settle();
    expect(screen.getByText(CONCLUDED_REASON)).toBeInTheDocument();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
  });
});

describe("the page and the ② column", () => {
  it("gives the ② column the case id and tells it the case is open", async () => {
    serve(detail());
    renderCase();
    await page();
    expect(await screen.findByRole("button", { name: S.ai2.analyze })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: S.case.aiHeading })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: S.case.infoHeading })).toBeInTheDocument();
  });

  it("tells the ② column a concluded case is closed", async () => {
    serve(concluded());
    server.use(
      http.get(`${CASE_URL}/investigation`, () =>
        HttpResponse.json({
          state: "idle",
          run_id: null,
          minutes: null,
          run: null,
          current: null,
          case_open: false,
        }),
      ),
    );
    renderCase();
    await page();
    expect(await screen.findByText(S.ai2.idleClosed)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.ai2.analyze })).not.toBeInTheDocument();
  });
});

describe("accessibility", () => {
  const scan = async (container: HTMLElement) => {
    // jsdom computes no layout or colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(" ")}`);
  };

  it("has no axe violation on an open case", async () => {
    serve(detail({ ongoing: true, ongoing_last_seen: "2026-09-30T02:30:00+00:00" }));
    const { container } = renderCase();
    await page();
    await screen.findByRole("button", { name: S.ai2.analyze });
    expect(await scan(container)).toEqual([]);
  });

  it("has no axe violation on a concluded case with an opened log", async () => {
    serve(concluded({ status: "confirmed_incident" }));
    const { container } = renderCase();
    await page();
    await userEvent.setup().click(screen.getByRole("button", { name: S.case.showLog }));
    expect(await scan(container)).toEqual([]);
  });
});
