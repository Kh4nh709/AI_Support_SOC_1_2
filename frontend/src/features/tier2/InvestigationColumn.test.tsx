// src/features/tier2/InvestigationColumn.test.tsx — the ② column of the case page (spec §4): its five
// states, the poll after an analyze and every refusal of the analyze route, and (DEC-221) the scorecard frame they
// are drawn in. What the scorecard says of a result is ResultPanel.test.tsx's.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import { S } from "../../strings";
import { modelNamesIn } from "../../testing/modelName";
import { InvestigationColumn } from "./InvestigationColumn";
import {
  evidenceRow,
  knowledgeOf,
  runOld,
  runV3,
  runV4,
  stoppedRun,
  timelineRow,
} from "./runFixtures";

const CASE = "0b30b853-1c2d-4e5f-8a9b-0c1d2e3f4a5b";
const RUN = "6f1c7a52-98d4-5c0e-b3a1-2d4e6f8a0b1c";
const VIEW_URL = `/api/tier2/cases/${CASE}/investigation`;
const ANALYZE_URL = `/api/tier2/cases/${CASE}/analyze`;
const OTHER = "5c4d3e2f-1a0b-4c9d-8e7f-6a5b4c3d2e1f";
const OTHER_VIEW_URL = `/api/tier2/cases/${OTHER}/investigation`;

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});
afterAll(() => server.close());

// ── what the investigation route answers ────────────────────────────────────────────────────────

const evidenceItem = (over: Record<string, unknown> = {}) => ({
  alert_id: "a-1",
  quote: "Failed password for root",
  why: "37 lần sai mật khẩu vào root",
  verified: true,
  reason_text: null,
  ...over,
});

const run = (over: Record<string, unknown> = {}) => ({
  run_id: RUN,
  created_at: "2026-09-30T01:19:00+00:00",
  result: { suggested_conclusion: "false_positive" },
  conclusion: "false_positive",
  conclusion_label: "Không phải sự cố",
  confidence: "medium",
  summary: "Chuỗi đăng nhập thất bại đến từ chính máy lab.",
  narrative: "08:00 script bắt đầu\n08:12 script dừng",
  hypotheses: [
    {
      text: "Script kiểm thử của nhóm hạ tầng",
      evidence_for: ["Nguồn là 127.0.0.1"],
      evidence_against: ["Không có ticket kiểm thử"],
    },
  ],
  evidence: [
    evidenceItem(),
    evidenceItem({
      alert_id: "a-2",
      quote: "session opened for user root",
      why: "phiên root mở thành công",
      verified: false,
      reason_text: "trích dẫn không có trong log hay mô tả của alert",
    }),
  ],
  next_steps: ["Hỏi nhóm hạ tầng về lịch chạy script"],
  playbook_used: null,
  overruled: null,
  snapshot: { alert_count: 3, total_occurrences: 61, last_seen_at: "2026-09-26T04:12:00+00:00" },
  changed: false,
  ...over,
});

const view = (over: Record<string, unknown> = {}) => ({
  state: "idle",
  run_id: null,
  minutes: null,
  run: null,
  current: null,
  case_open: true,
  ...over,
});

const idle = () => view();
const running = (id = RUN) => view({ state: "running", run_id: id });
const done = (r: Record<string, unknown> = run(), over: Record<string, unknown> = {}) =>
  view({
    state: "done",
    run: r,
    current: { alert_count: 3, total_occurrences: 61, last_seen_at: "2026-09-26T04:12:00+00:00" },
    ...over,
  });

/** Serves `views` one per GET, the last one for every GET after; records the `run_id` each GET carried. */
function serveViews(...views: JsonBodyType[]) {
  const seen: (string | null)[] = [];
  server.use(
    http.get(VIEW_URL, ({ request }) => {
      seen.push(new URL(request.url).searchParams.get("run_id"));
      const next = views[Math.min(seen.length - 1, views.length - 1)];
      return HttpResponse.json(next);
    }),
  );
  return seen;
}

const accept = () =>
  server.use(
    http.post(ANALYZE_URL, () => HttpResponse.json({ run_id: RUN, job_id: 41 }, { status: 202 })),
  );

const refuse = (status: number, detail: unknown) =>
  server.use(http.post(ANALYZE_URL, () => HttpResponse.json({ detail }, { status })));

// A fresh client per render, so no test reads what another one cached; `retry: false` so a failed read
// shows at once (T09's tests do the same).
const newClient = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });

/** The column of `caseId` inside the app's provider, so a `rerender` can hand it another case. */
const columnOf = (client: QueryClient, caseId: string, caseOpen = true, caseLine?: string) => (
  <QueryClientProvider client={client}>
    <MemoryRouter>
      <main>
        <InvestigationColumn caseId={caseId} caseOpen={caseOpen} caseLine={caseLine} />
      </main>
    </MemoryRouter>
  </QueryClientProvider>
);

function renderColumn(caseOpen = true, caseLine?: string) {
  return render(columnOf(newClient(), CASE, caseOpen, caseLine));
}

const analyzeButton = () => screen.findByRole("button", { name: S.ai2.analyze });

// ── the states ──────────────────────────────────────────────────────────────────────────────────

describe("idle", () => {
  it("shows the Phân tích button, and says there is no analysis yet", async () => {
    serveViews(idle());
    renderColumn();
    expect(await analyzeButton()).toBeEnabled();
    expect(screen.getByText(S.ai2.idle)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: S.case.aiHeading })).toBeInTheDocument();
  });

  it("says 'Đang tải phân tích…' until the first answer", async () => {
    serveViews(idle());
    renderColumn();
    expect(screen.getByText(S.ai2.loading)).toBeInTheDocument();
    await analyzeButton();
    expect(screen.queryByText(S.ai2.loading)).not.toBeInTheDocument();
  });

  it("is 560 px wide", async () => {
    serveViews(idle());
    const { container } = renderColumn();
    await analyzeButton();
    expect(container.querySelector("section")).toHaveClass("w-[560px]");
  });

  it("offers no button on a concluded case with no analysis, and says why", async () => {
    serveViews(view({ case_open: false }));
    renderColumn(false);
    expect(await screen.findByText(S.ai2.idleClosed)).toBeInTheDocument();
    expect(screen.queryAllByRole("button")).toEqual([]);
  });
});

describe("the state read from the server", () => {
  it("shows a job still running that another tab or an earlier visit started, and polls it by its run_id", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("jest", { advanceTimersByTime: (ms: number) => vi.advanceTimersByTime(ms) });
    const seen = serveViews(running(), done());
    renderColumn();
    expect(await screen.findByText(S.ai2.running)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.ai2.analyze })).not.toBeInTheDocument();
    await act(() => vi.advanceTimersByTimeAsync(3000));
    expect(await screen.findByText("Không phải sự cố")).toBeInTheDocument();
    expect(seen).toEqual([null, RUN]);
  });

  it("shows a stalled job with the minutes it has waited and 'Kiểm tra lại', and does not poll it", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("jest", { advanceTimersByTime: (ms: number) => vi.advanceTimersByTime(ms) });
    const seen = serveViews(view({ state: "stalled", run_id: RUN, minutes: 7 }), done());
    renderColumn();
    expect(await screen.findByText(S.ai2.stalled(7))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: S.ai2.recheck })).toBeInTheDocument();
    // A second click of Phân tích would only meet the single-flight 409, so it is not offered.
    expect(screen.queryByRole("button", { name: S.ai2.analyze })).not.toBeInTheDocument();
    await act(() => vi.advanceTimersByTimeAsync(30_000));
    expect(seen).toEqual([null]);

    await userEvent
      .setup({ delay: null })
      .click(screen.getByRole("button", { name: S.ai2.recheck }));
    expect(await screen.findByText("Không phải sự cố")).toBeInTheDocument();
    expect(seen).toEqual([null, RUN]);
  });

  it("shows S.ai2.failed for a job that failed, and offers the button again", async () => {
    serveViews(view({ state: "failed" }));
    renderColumn();
    expect(await screen.findByText(S.ai2.failed)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: S.ai2.analyze })).toBeInTheDocument();
  });

  it("shows the previous result under a failed run, headed as the previous one", async () => {
    serveViews(view({ state: "failed", run: run() }));
    renderColumn();
    expect(await screen.findByText(S.ai2.failed)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: S.ai2.lastResult })).toBeInTheDocument();
    expect(screen.getByText("Không phải sự cố")).toBeInTheDocument();
  });

  // A run with no result carries `result: null` and `stopped_text` only (`present_run`).
  const stoppedRun = (text: string) => ({
    run_id: RUN,
    created_at: "2026-09-30T01:19:00+00:00",
    result: null,
    stopped_text: text,
  });

  it("shows why the earlier run stopped, under a failed run, when that run has no result", async () => {
    // `STOPPED_TEXT["cap"]`: the earlier run hit the LLM cost cap.
    serveViews(view({ state: "failed", run: stoppedRun("đã chạm hạn mức chi phí LLM") }));
    renderColumn();
    expect(await screen.findByText(S.ai2.failed)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: S.ai2.lastResult })).toBeInTheDocument();
    expect(screen.getByText(/Phân tích không có kết quả/)).toHaveTextContent(
      `${S.ai2.stopped("đã chạm hạn mức chi phí LLM")} — ${S.ai2.retryable}`,
    );
    expect(screen.getByRole("button", { name: S.ai2.analyze })).toBeInTheDocument();
  });

  it("gives no retry with the stop reason of a failed run on a concluded case", async () => {
    serveViews(
      view({
        state: "failed",
        case_open: false,
        run: stoppedRun("đã chạm hạn mức chi phí LLM"),
      }),
    );
    renderColumn(false);
    expect(await screen.findByText(S.ai2.failedClosed)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: S.ai2.lastResult })).toBeInTheDocument();
    expect(screen.getByText(/Phân tích không có kết quả/)).toHaveTextContent(
      S.ai2.stopped("đã chạm hạn mức chi phí LLM"),
    );
    expect(screen.getByText(/Phân tích không có kết quả/)).not.toHaveTextContent(S.ai2.retryable);
  });

  it("says why a finished run has no result, and that it can be retried while the case is open", async () => {
    serveViews(
      done(
        run({ result: null, stopped_text: "mô hình trả lời sai định dạng, kể cả sau một lần sửa" }),
      ),
    );
    renderColumn();
    const line = await screen.findByText(/Phân tích không có kết quả/);
    expect(line).toHaveTextContent(
      `${S.ai2.stopped("mô hình trả lời sai định dạng, kể cả sau một lần sửa")} — ${S.ai2.retryable}`,
    );
  });

  it("says a failed run of a concluded case failed, with no retry", async () => {
    serveViews(view({ state: "failed", case_open: false }));
    renderColumn(false);
    expect(await screen.findByText(S.ai2.failedClosed)).toBeInTheDocument();
    expect(screen.queryAllByRole("button")).toEqual([]);
  });

  it("shows an error, and loads again when Thử lại is pressed", async () => {
    let calls = 0;
    server.use(
      http.get(VIEW_URL, () => {
        calls += 1;
        return calls === 1
          ? HttpResponse.json({ detail: "boom" }, { status: 500 })
          : HttpResponse.json(idle());
      }),
    );
    renderColumn();
    expect(await screen.findByText(S.common.unknownError)).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: S.common.retry }));
    await analyzeButton();
    expect(calls).toBe(2);
  });

  it("says the case was not found for a 404", async () => {
    server.use(
      http.get(VIEW_URL, () => HttpResponse.json({ detail: "case not found" }, { status: 404 })),
    );
    renderColumn();
    expect(await screen.findByText(S.case.notFound)).toBeInTheDocument();
  });
});

// ── the analyze and the poll ────────────────────────────────────────────────────────────────────

describe("analyze and the poll", () => {
  const fake = () => {
    vi.useFakeTimers();
    // Testing Library waits with fake timers only when it finds a `jest` with advanceTimersByTime.
    vi.stubGlobal("jest", { advanceTimersByTime: (ms: number) => vi.advanceTimersByTime(ms) });
    return userEvent.setup({ delay: null });
  };
  const wait = (ms: number) => act(() => vi.advanceTimersByTimeAsync(ms));

  it("moves to running on a 202, polls every 3 s with the run_id, reaches done and stops polling", async () => {
    const user = fake();
    const seen = serveViews(idle(), running(), running(), done());
    accept();
    renderColumn();
    await user.click(await analyzeButton());
    expect(await screen.findByText(S.ai2.running)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.ai2.analyze })).not.toBeInTheDocument();
    expect(seen).toEqual([null]);

    await wait(2900);
    expect(seen).toEqual([null]);
    await wait(100);
    await screen.findByText(S.ai2.running);
    expect(seen).toEqual([null, RUN]);
    await wait(3000);
    expect(seen).toEqual([null, RUN, RUN]);
    expect(screen.getByText(S.ai2.running)).toBeInTheDocument();

    await wait(3000);
    expect(await screen.findByText("Không phải sự cố")).toBeInTheDocument();
    expect(seen).toEqual([null, RUN, RUN, RUN]);
    expect(screen.queryByText(S.ai2.running)).not.toBeInTheDocument();

    // Done: nothing is asked again, however long the page stays open.
    await wait(60_000);
    expect(seen).toEqual([null, RUN, RUN, RUN]);
  });

  it("keeps the run_id of the 202 and sends it on every poll, though a done state carries none", async () => {
    const user = fake();
    const seen = serveViews(idle(), view({ state: "running", run_id: RUN }), done());
    accept();
    renderColumn();
    await user.click(await analyzeButton());
    await screen.findByText(S.ai2.running);
    await wait(3000);
    await wait(3000);
    await screen.findByText("Không phải sự cố");
    expect(seen.slice(1)).toEqual([RUN, RUN]);
  });

  it("stops polling on failed, and offers the button again", async () => {
    const user = fake();
    const seen = serveViews(idle(), view({ state: "failed" }));
    accept();
    renderColumn();
    await user.click(await analyzeButton());
    await screen.findByText(S.ai2.running);
    await wait(3000);
    expect(await screen.findByText(S.ai2.failed)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: S.ai2.analyze })).toBeInTheDocument();
    await wait(30_000);
    expect(seen).toEqual([null, RUN]);
  });

  it("stops polling on stalled, and 'Kiểm tra lại' asks once more", async () => {
    const user = fake();
    const seen = serveViews(idle(), view({ state: "stalled", run_id: RUN, minutes: 6 }), running());
    accept();
    renderColumn();
    await user.click(await analyzeButton());
    await screen.findByText(S.ai2.running);
    await wait(3000);
    expect(await screen.findByText(S.ai2.stalled(6))).toBeInTheDocument();
    await wait(30_000);
    expect(seen).toEqual([null, RUN]);
    await user.click(screen.getByRole("button", { name: S.ai2.recheck }));
    expect(await screen.findByText(S.ai2.running)).toBeInTheDocument();
    expect(seen).toEqual([null, RUN, RUN]);
  });

  it("shows an error and stops polling when the server refuses the run_id (422)", async () => {
    const user = fake();
    let polls = 0;
    server.use(
      http.get(VIEW_URL, ({ request }) => {
        if (new URL(request.url).searchParams.has("run_id")) {
          polls += 1;
          return HttpResponse.json({ detail: [{ msg: "not a valid UUID" }] }, { status: 422 });
        }
        return HttpResponse.json(idle());
      }),
    );
    accept();
    renderColumn();
    await user.click(await analyzeButton());
    await screen.findByText(S.ai2.running);
    await wait(3000);
    expect(await screen.findByText(S.common.unknownError)).toBeInTheDocument();
    await wait(30_000);
    expect(polls).toBe(1);
    expect(screen.getByRole("button", { name: S.common.retry })).toBeInTheDocument();
  });

  // The server, as `derive_view` has it: a poll with a run_id that finds nothing behind it is `failed`,
  // and a read with no run_id finds `idle`. The first poll of the run breaks with a 500.
  function pollBreaksOnce(afterwards: JsonBodyType) {
    const seen: (string | null)[] = [];
    let polls = 0;
    server.use(
      http.get(VIEW_URL, ({ request }) => {
        const id = new URL(request.url).searchParams.get("run_id");
        seen.push(id);
        if (id === null) return HttpResponse.json(idle());
        polls += 1;
        return polls === 1
          ? HttpResponse.json({ detail: "boom" }, { status: 500 })
          : HttpResponse.json(afterwards);
      }),
    );
    return seen;
  }

  it("says the error, not 'Đang phân tích…', while nothing polls after a poll failed", async () => {
    const user = fake();
    const seen = pollBreaksOnce(running());
    accept();
    renderColumn();
    await user.click(await analyzeButton());
    await screen.findByText(S.ai2.running);
    await wait(3000);
    expect(await screen.findByText(S.common.unknownError)).toBeInTheDocument();
    expect(screen.queryByText(S.ai2.running)).not.toBeInTheDocument();
    // Nothing is asked while the error stands.
    await wait(30_000);
    expect(seen).toEqual([null, RUN]);
    expect(screen.queryByText(S.ai2.running)).not.toBeInTheDocument();
  });

  it("resumes polling the same run when Thử lại follows a failed poll", async () => {
    const user = fake();
    const seen = pollBreaksOnce(running());
    accept();
    renderColumn();
    await user.click(await analyzeButton());
    await screen.findByText(S.ai2.running);
    await wait(3000);
    await screen.findByText(S.common.unknownError);

    await user.click(screen.getByRole("button", { name: S.common.retry }));
    expect(await screen.findByText(S.ai2.running)).toBeInTheDocument();
    expect(screen.queryByText(S.common.unknownError)).not.toBeInTheDocument();
    expect(seen).toEqual([null, RUN, RUN]);
    // And the poll runs again every 3 s, on the same run.
    await wait(3000);
    expect(seen).toEqual([null, RUN, RUN, RUN]);
  });

  it("shows a job with nothing behind it as failed, not idle, when Thử lại follows a failed poll", async () => {
    const user = fake();
    const seen = pollBreaksOnce(view({ state: "failed" }));
    accept();
    renderColumn();
    await user.click(await analyzeButton());
    await screen.findByText(S.ai2.running);
    await wait(3000);
    await screen.findByText(S.common.unknownError);

    await user.click(screen.getByRole("button", { name: S.common.retry }));
    expect(await screen.findByText(S.ai2.failed)).toBeInTheDocument();
    expect(screen.queryByText(S.ai2.idle)).not.toBeInTheDocument();
    expect(seen).toEqual([null, RUN, RUN]);
  });

  it("stops polling when the column goes away", async () => {
    const user = fake();
    const seen = serveViews(idle(), running());
    accept();
    const { unmount } = renderColumn();
    await user.click(await analyzeButton());
    await screen.findByText(S.ai2.running);
    unmount();
    await wait(30_000);
    expect(seen).toEqual([null]);
  });

  it("does not ask again while the last poll is still unanswered", async () => {
    const user = fake();
    let polls = 0;
    let release: () => void = () => {};
    server.use(
      http.get(VIEW_URL, async ({ request }) => {
        if (!new URL(request.url).searchParams.has("run_id")) return HttpResponse.json(idle());
        polls += 1;
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        return HttpResponse.json(running());
      }),
    );
    accept();
    renderColumn();
    await user.click(await analyzeButton());
    await screen.findByText(S.ai2.running);
    await wait(3000);
    await wait(9000);
    expect(polls).toBe(1);
    release();
  });
});

describe("the refusals of Phân tích", () => {
  it("shows the quota message for a 429, and keeps the button", async () => {
    serveViews(idle());
    refuse(429, "analyze quota exceeded for today");
    renderColumn();
    await userEvent.setup().click(await analyzeButton());
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(S.ai2.quotaExhausted);
    // The quota is a rolling 24 hours (decision 8), never the calendar day.
    expect(alert).toHaveTextContent("24 giờ gần nhất");
    expect(alert).not.toHaveTextContent("hôm nay");
    expect(screen.getByRole("button", { name: S.ai2.analyze })).toBeEnabled();
  });

  it("shows the server's message for a 409, and reads the state again", async () => {
    // The run that is already going is the one to follow: the state read again carries its run_id.
    const seen = serveViews(idle(), running());
    refuse(409, "an investigation is already running for this case");
    renderColumn();
    await userEvent.setup().click(await analyzeButton());
    expect(await screen.findByRole("alert")).toHaveTextContent(S.ai2.alreadyRunning);
    expect(await screen.findByText(S.ai2.running)).toBeInTheDocument();
    expect(seen).toEqual([null, null]);
  });

  it("says the case is concluded for the 409 of a concluded case", async () => {
    serveViews(idle());
    refuse(409, "case đã kết luận");
    renderColumn();
    await userEvent.setup().click(await analyzeButton());
    expect(await screen.findByRole("alert")).toHaveTextContent(S.ai2.concluded);
  });

  it("shows the server's own text for a 409 it has no words of its own for", async () => {
    serveViews(idle());
    refuse(409, "một lý do khác");
    renderColumn();
    await userEvent.setup().click(await analyzeButton());
    expect(await screen.findByRole("alert")).toHaveTextContent("một lý do khác");
  });

  it("says something went wrong for any other refusal", async () => {
    serveViews(idle());
    refuse(500, "boom");
    renderColumn();
    await userEvent.setup().click(await analyzeButton());
    expect(await screen.findByRole("alert")).toHaveTextContent(S.common.unknownError);
  });

  it("clears the message when the next attempt is made", async () => {
    serveViews(idle());
    refuse(429, "x");
    renderColumn();
    const user = userEvent.setup();
    await user.click(await analyzeButton());
    await screen.findByRole("alert");
    accept();
    await user.click(screen.getByRole("button", { name: S.ai2.analyze }));
    await screen.findByText(S.ai2.running);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("posts once for a double click", async () => {
    serveViews(idle());
    let posts = 0;
    server.use(
      http.post(ANALYZE_URL, () => {
        posts += 1;
        return HttpResponse.json({ run_id: RUN, job_id: 41 }, { status: 202 });
      }),
    );
    renderColumn();
    await userEvent.setup().dblClick(await analyzeButton());
    await screen.findByText(S.ai2.running);
    expect(posts).toBe(1);
  });
});

// ── another case ────────────────────────────────────────────────────────────────────────────────

describe("another case", () => {
  // Real time: the wait is for an answer already released to travel through the network layer.
  const settle = () =>
    act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

  it("drops the answer of the case it showed when it is given another while that read is pending", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    server.use(
      http.get(VIEW_URL, async () => {
        await gate;
        return HttpResponse.json(done(run({ summary: "tóm tắt của case thứ nhất" })));
      }),
      http.get(OTHER_VIEW_URL, () => HttpResponse.json(idle())),
    );
    const client = newClient();
    const { rerender } = render(columnOf(client, CASE));
    rerender(columnOf(client, OTHER));
    expect(await screen.findByText(S.ai2.idle)).toBeInTheDocument();

    release();
    await settle();
    expect(screen.queryByText("tóm tắt của case thứ nhất")).not.toBeInTheDocument();
    expect(screen.getByText(S.ai2.idle)).toBeInTheDocument();
  });

  it("drops the failure of the case it showed the same way", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    server.use(
      http.get(VIEW_URL, async () => {
        await gate;
        return HttpResponse.json({ detail: "boom" }, { status: 500 });
      }),
      http.get(OTHER_VIEW_URL, () => HttpResponse.json(idle())),
    );
    const client = newClient();
    const { rerender } = render(columnOf(client, CASE));
    rerender(columnOf(client, OTHER));
    expect(await screen.findByText(S.ai2.idle)).toBeInTheDocument();

    release();
    await settle();
    expect(screen.queryByText(S.common.unknownError)).not.toBeInTheDocument();
  });
});

// ── a finished analysis ─────────────────────────────────────────────────────────────────────────
// What the scorecard draws of a result (four tiles over five tabs) is `ResultPanel.test.tsx`'s; the flat result the
// admin's draft view still draws is `RunResult.test.tsx`'s. These are the column's: what surrounds the result.

describe("done", () => {
  it("draws the scorecard under the heading: four tiles and five tabs", async () => {
    serveViews(done(runV4()));
    renderColumn();
    expect(await screen.findByRole("tablist", { name: S.ai2.tabs.label })).toBeInTheDocument();
    for (const name of [
      S.ai2.tile.verdict,
      S.ai2.tile.confidence,
      S.ai2.tile.rag,
      S.ai2.tile.evidence,
    ]) {
      expect(screen.getByRole("group", { name })).toBeInTheDocument();
    }
    expect(screen.getAllByRole("tab")).toHaveLength(5);
    expect(screen.getByRole("heading", { name: S.case.aiHeading })).toHaveTextContent(
      "PHÂN TÍCH AI · TIER 2",
    );
  });

  it("is a region named by its heading, so every state of the column is found in the same place", async () => {
    serveViews(done(runV4()));
    renderColumn();
    await screen.findByRole("tablist");
    const region = screen.getByRole("region", { name: S.case.aiHeading });
    expect(within(region).getByRole("tablist")).toBeInTheDocument();
    expect(region).toHaveClass("w-[560px]");
  });

  it("says the case at the right of the heading when the page gives its line", async () => {
    serveViews(done(runV4()));
    renderColumn(true, S.ai2.caseLine("0b30b853", 3, ["lab-win-02"]));
    expect(await screen.findByText("Case 0b30b853 · 3 cụm · lab-win-02")).toBeInTheDocument();
  });

  it("says nothing at the right of the heading when it has no line", async () => {
    serveViews(done(runV4()));
    const { container } = renderColumn();
    await screen.findByRole("tablist");
    expect(container.textContent).not.toMatch(/Case 0b30/);
  });

  it("shows a result of the old server's shape: the frame is drawn from the old keys alone", async () => {
    serveViews(done(run()));
    renderColumn();
    expect(await screen.findByRole("tablist", { name: S.ai2.tabs.label })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: S.ai2.tile.verdict }).textContent).toBe(
      "Kết luậnKhông phải sự cốgợi ý của AI",
    );
    expect(screen.getByText("Chuỗi đăng nhập thất bại đến từ chính máy lab.")).toBeInTheDocument();
  });

  it("offers Phân tích lại on an open case, above the tiles", async () => {
    serveViews(done(runV4()));
    renderColumn();
    const button = await screen.findByRole("button", { name: S.ai2.reanalyze });
    expect(button).toBeEnabled();
    const tiles = screen.getByRole("group", { name: S.ai2.tile.verdict });
    expect(button.compareDocumentPosition(tiles) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("shows a concluded case's result and no button of its own", async () => {
    serveViews(done(runV4(), { case_open: false }));
    renderColumn(false);
    expect(await screen.findByRole("tablist")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.ai2.reanalyze })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.ai2.analyze })).not.toBeInTheDocument();
    // the only buttons are the tabs
    expect(screen.queryAllByRole("button")).toEqual([]);
  });

  it("closes the column when the page says the case is concluded, though the server's answer is open", async () => {
    serveViews(done(runV4(), { case_open: true }));
    renderColumn(false);
    await screen.findByRole("tablist");
    expect(screen.queryByRole("button", { name: S.ai2.reanalyze })).not.toBeInTheDocument();
  });

  it("keeps the notices of the run inside the frame: the case changed, and the RAG not applied", async () => {
    serveViews(
      done(
        runV4({
          changed: true,
          rag: { best_pct: null, not_applied: "quota", below_floor_pct: null, floor_pct: null },
          knowledge: knowledgeOf("failed", { failure: "quota" }),
        }),
        { current: { alert_count: 5, total_occurrences: 80, last_seen_at: null } },
      ),
    );
    renderColumn();
    await screen.findByText(S.ai2.stale);
    const region = screen.getByRole("region", { name: S.case.aiHeading });
    expect(within(region).getByText(S.ai2.stale)).toBeInTheDocument();
    expect(within(region).getByText(S.ai2.current(5, 80, null))).toBeInTheDocument();
    expect(within(region).getByRole("note")).toHaveTextContent(
      "⚠ Không áp dụng RAG cho case này: Voyage hết hạn mức — AI đã phân tích không có tri thức tham khảo.",
    );
  });

  it("links a timeline step to its alert inside the page's router", async () => {
    serveViews(done(runV4()));
    renderColumn();
    await userEvent.setup().click(await screen.findByRole("tab", { name: S.ai2.tabs.timeline }));
    expect(screen.getByRole("link", { name: "112437" })).toHaveAttribute("href", "/alerts/112437");
  });

  it("renders text the model wrote as text: no element is made of it", async () => {
    const markup = '<b>đậm</b> <img src=x onerror="alert(1)"> </script> ‮';
    serveViews(
      done(
        runV4({
          summary: markup,
          narrative: markup,
          hypotheses: [
            {
              text: markup,
              evidence_for: [markup],
              evidence_against: [markup],
              likelihood: "high",
            },
          ],
          evidence: [evidenceRow({ quote: markup, why: markup, alert_id: markup })],
          next_steps_rows: [{ step: markup, priority: "high" }],
          overruled: markup,
          model_conclusion: null,
          playbook_used: markup,
          timeline: [timelineRow({ what: markup, tactic: markup, technique: markup })],
        }),
      ),
    );
    const { container } = renderColumn();
    const user = userEvent.setup();
    await screen.findByRole("tablist");
    for (const name of Object.values(S.ai2.tabs).slice(1)) {
      await user.click(screen.getByRole("tab", { name }));
      expect(container.querySelector("b, img, script")).toBeNull();
    }
    await user.click(screen.getByRole("tab", { name: S.ai2.tabs.evidence }));
    expect(screen.getAllByText(markup, { exact: false }).length).toBeGreaterThan(1);
  });
});

describe("the open tab", () => {
  const fake = () => {
    vi.useFakeTimers();
    vi.stubGlobal("jest", { advanceTimersByTime: (ms: number) => vi.advanceTimersByTime(ms) });
    return userEvent.setup({ delay: null });
  };

  it("is not kept when the page is loaded again", async () => {
    serveViews(done(runV4()));
    const first = renderColumn();
    await userEvent.setup().click(await screen.findByRole("tab", { name: S.ai2.tabs.tech }));
    expect(screen.getByRole("tab", { name: S.ai2.tabs.tech })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    first.unmount();
    renderColumn();
    expect(await screen.findByRole("tab", { name: S.ai2.tabs.overview })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });

  it("starts on the first tab again when a new run takes the place of the shown one", async () => {
    const user = fake();
    const NEXT = "7a2d8b63-09e5-4d1f-8c2b-3e5f7a9b1c2d";
    serveViews(done(runV4()), done(runV4({ run_id: NEXT, summary: "Lượt phân tích mới." })));
    server.use(
      http.post(ANALYZE_URL, () =>
        HttpResponse.json({ run_id: NEXT, job_id: 42 }, { status: 202 }),
      ),
    );
    renderColumn();
    await user.click(await screen.findByRole("tab", { name: S.ai2.tabs.evidence }));
    await user.click(screen.getByRole("button", { name: S.ai2.reanalyze }));
    expect(await screen.findByText(S.ai2.running)).toBeInTheDocument();
    await act(() => vi.advanceTimersByTimeAsync(3000));
    expect(await screen.findByText("Lượt phân tích mới.")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: S.ai2.tabs.overview })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });
});

// ── what the column keeps of every state, inside the new frame ──────────────────────────────────

describe("every state of the column is drawn inside the frame", () => {
  const frame = () => screen.getByRole("region", { name: S.case.aiHeading });

  it("loading: 'Đang tải phân tích…' under the heading", async () => {
    serveViews(idle());
    renderColumn();
    expect(within(frame()).getByText(S.ai2.loading)).toBeInTheDocument();
    await analyzeButton();
  });

  it("idle: the sentence and the button that starts a run", async () => {
    serveViews(idle());
    renderColumn();
    await analyzeButton();
    expect(within(frame()).getByText(S.ai2.idle)).toBeInTheDocument();
    expect(within(frame()).getByRole("button", { name: S.ai2.analyze })).toBeInTheDocument();
  });

  it("idle on a closed case: the sentence and no button", async () => {
    serveViews(view({ case_open: false }));
    renderColumn(false);
    expect(await within(frame()).findByText(S.ai2.idleClosed)).toBeInTheDocument();
    expect(within(frame()).queryAllByRole("button")).toEqual([]);
  });

  it("running: 'Đang phân tích…' and no button", async () => {
    serveViews(running());
    renderColumn();
    expect(await within(frame()).findByText(S.ai2.running)).toBeInTheDocument();
    expect(within(frame()).queryAllByRole("button")).toEqual([]);
  });

  it("stalled: the minutes it has waited and 'Kiểm tra lại'", async () => {
    serveViews(view({ state: "stalled", run_id: RUN, minutes: 7 }));
    renderColumn();
    expect(await within(frame()).findByText(S.ai2.stalled(7))).toBeInTheDocument();
    expect(within(frame()).getByRole("button", { name: S.ai2.recheck })).toBeInTheDocument();
  });

  it("failed with nothing before it: the failure and the button", async () => {
    serveViews(view({ state: "failed" }));
    renderColumn();
    expect(await within(frame()).findByText(S.ai2.failed)).toBeInTheDocument();
    expect(within(frame()).getByRole("button", { name: S.ai2.analyze })).toBeInTheDocument();
  });

  it("failed with the earlier result under it: the result is the scorecard, headed as the earlier one", async () => {
    serveViews(view({ state: "failed", run: runV4() }));
    renderColumn();
    expect(await within(frame()).findByText(S.ai2.failed)).toBeInTheDocument();
    expect(within(frame()).getByRole("heading", { name: S.ai2.lastResult })).toBeInTheDocument();
    expect(within(frame()).getByRole("tablist")).toBeInTheDocument();
    expect(within(frame()).getByRole("group", { name: S.ai2.tile.verdict })).toBeInTheDocument();
    // a result is there to be analysed again
    expect(within(frame()).getByRole("button", { name: S.ai2.reanalyze })).toBeInTheDocument();
  });

  it("failed on a closed case with the earlier result: no button, the result stays", async () => {
    serveViews(view({ state: "failed", case_open: false, run: runV4() }));
    renderColumn(false);
    expect(await within(frame()).findByText(S.ai2.failedClosed)).toBeInTheDocument();
    expect(within(frame()).getByRole("tablist")).toBeInTheDocument();
    expect(within(frame()).queryByRole("button", { name: S.ai2.analyze })).not.toBeInTheDocument();
  });

  it("a run that stopped with no result: the reason in the server's words, and that it can be retried", async () => {
    serveViews(done(stoppedRun("đã chạm hạn mức chi phí LLM")));
    renderColumn();
    expect(await within(frame()).findByText(/Phân tích không có kết quả/)).toHaveTextContent(
      `${S.ai2.stopped("đã chạm hạn mức chi phí LLM")} — ${S.ai2.retryable}`,
    );
    expect(within(frame()).queryByRole("tablist")).not.toBeInTheDocument();
    expect(within(frame()).getByRole("button", { name: S.ai2.analyze })).toBeInTheDocument();
  });

  it("a run that stopped, on a closed case: the reason and no retry", async () => {
    serveViews(done(stoppedRun("đã chạm hạn mức chi phí LLM"), { case_open: false }));
    renderColumn(false);
    const line = await within(frame()).findByText(/Phân tích không có kết quả/);
    expect(line).toHaveTextContent(S.ai2.stopped("đã chạm hạn mức chi phí LLM"));
    expect(line).not.toHaveTextContent(S.ai2.retryable);
  });

  it("a run that stopped does not say the RAG was not applied: nothing was analysed", async () => {
    serveViews(
      done(
        stoppedRun("đã chạm hạn mức chi phí LLM", {
          rag: { best_pct: null, not_applied: "auth", below_floor_pct: null, floor_pct: null },
        }),
      ),
    );
    renderColumn();
    await within(frame()).findByText(/Phân tích không có kết quả/);
    expect(screen.queryByRole("note")).not.toBeInTheDocument();
    expect(screen.queryByText(/Không áp dụng RAG/)).not.toBeInTheDocument();
  });

  it("the earlier result under a failed run says the conclusion the system held, as on the overview", async () => {
    serveViews(
      view({
        state: "failed",
        run: runV4({
          conclusion: "need_more_data",
          conclusion_label: "Cần thêm dữ liệu",
          model_conclusion: "false_positive",
          held_by: ["no_verified_evidence"],
        }),
      }),
    );
    renderColumn();
    expect(
      await screen.findByText(
        "AI kết luận: Không phải sự cố — hệ thống giữ lại vì: không có bằng chứng kiểm chứng được",
      ),
    ).toBeInTheDocument();
  });

  it("the earlier result under a failed run draws the RAG notice too", async () => {
    serveViews(
      view({
        state: "failed",
        run: runV4({
          rag: { best_pct: null, not_applied: "timeout", below_floor_pct: null, floor_pct: null },
        }),
      }),
    );
    renderColumn();
    expect(await screen.findByRole("note")).toHaveTextContent("Voyage quá thời gian chờ");
  });

  it("the earlier result under a failed run names its playbook on the technical tab", async () => {
    serveViews(view({ state: "failed", run: runOld({ playbook_used: "ssh_brute_force" }) }));
    renderColumn();
    await userEvent.setup().click(await screen.findByRole("tab", { name: S.ai2.tabs.tech }));
    expect(screen.getByText("ssh_brute_force")).toBeInTheDocument();
  });

  it("an error of the read: the notice and 'Thử lại', in the frame", async () => {
    server.use(http.get(VIEW_URL, () => HttpResponse.json({ detail: "boom" }, { status: 500 })));
    renderColumn();
    expect(await within(frame()).findByText(S.common.unknownError)).toBeInTheDocument();
    expect(within(frame()).getByRole("button", { name: S.common.retry })).toBeInTheDocument();
  });
});

// ── G5: the model's name is nowhere on the page ─────────────────────────────────────────────────

describe("G5: the model's name is on no state of the Tier 2 column", () => {
  const STOPPED = Object.values(S.ai2.stoppedBy);
  const STATES: [string, unknown][] = [
    ["idle", idle()],
    ["idle on a closed case", view({ case_open: false })],
    ["running", running()],
    ["stalled", view({ state: "stalled", run_id: RUN, minutes: 7 })],
    ["failed", view({ state: "failed" })],
    ["failed, with the earlier result", view({ state: "failed", run: runV4() })],
    ["a version 4 result", done(runV4())],
    ["an older result", done(runV3())],
    ["a result of the old server's shape", done(runOld())],
    [
      "a held conclusion",
      done(
        runV4({
          conclusion: "need_more_data",
          model_conclusion: "confirmed_incident",
          held_by: ["no_verified_evidence"],
        }),
      ),
    ],
    [
      "a lookup under the floor",
      done(runV4({ knowledge: knowledgeOf("below_floor", { best_pct: 47 }) })),
    ],
    [
      "a lookup that failed",
      done(
        runV4({
          rag: { best_pct: null, not_applied: "quota", below_floor_pct: null, floor_pct: null },
          knowledge: knowledgeOf("failed", { failure: "quota" }),
        }),
      ),
    ],
    ["a changed case", done(runV4({ changed: true }))],
    ["a closed case", done(runV4(), { case_open: false })],
    ...STOPPED.map((text): [string, unknown] => [
      `a run that stopped: ${text}`,
      done(stoppedRun(text)),
    ]),
  ];

  it.each(STATES)(
    "names no model in %s, on any tab, in any text or attribute",
    async (_name, shown) => {
      serveViews(shown as JsonBodyType);
      const { container } = renderColumn();
      await waitFor(() => expect(screen.queryByText(S.ai2.loading)).not.toBeInTheDocument());
      expect(modelNamesIn(container)).toEqual([]);
      const user = userEvent.setup();
      for (const tab of screen.queryAllByRole("tab")) {
        await user.click(tab);
        expect(modelNamesIn(container)).toEqual([]);
      }
    },
  );

  it("labels the technical tab with exactly the six rows of the mock-up, whatever the run carries", async () => {
    for (const shown of [
      done(runV4()),
      done(runV3()),
      done(runOld()),
      done(runV4({ model: "GLM-5.3", tech: { ...runV4().tech, model: "GLM-5.3" } })),
    ]) {
      serveViews(shown);
      const { unmount } = renderColumn();
      await userEvent.setup().click(await screen.findByRole("tab", { name: S.ai2.tabs.tech }));
      expect(
        [...screen.getByRole("tabpanel").querySelectorAll("dt")].map((dt) => dt.textContent),
      ).toEqual([
        "Token vào → ra",
        "Thời gian",
        "Chi phí",
        "Phân tích lúc",
        "Playbook",
        "Alert AI đã đọc",
      ]);
      expect(modelNamesIn(screen.getByRole("tabpanel"))).toEqual([]);
      unmount();
    }
  });

  it("holds the pattern against the names it must catch (the guard itself)", () => {
    for (const name of ["GLM 5.3", "glm-5.3", "GPT-4", "DeepSeek", "Claude Opus", "model: x"]) {
      const probe = document.createElement("p");
      probe.textContent = name;
      expect(modelNamesIn(probe), name).toHaveLength(1);
    }
    const word = document.createElement("p");
    word.textContent = "mô hình trả lời sai định dạng";
    expect(modelNamesIn(word)).toEqual([]);
    const tooltip = document.createElement("p");
    tooltip.setAttribute("title", "GLM 5.3");
    expect(modelNamesIn(tooltip)).toHaveLength(1);
  });
});

// ── accessibility ───────────────────────────────────────────────────────────────────────────────

describe("accessibility", () => {
  const scan = async (container: HTMLElement) => {
    // jsdom computes no layout or colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(" ")}`);
  };

  it("has no axe violation when idle", async () => {
    serveViews(idle());
    const { container } = renderColumn();
    await analyzeButton();
    expect(await scan(container)).toEqual([]);
  });

  it("has no axe violation while an analysis is running", async () => {
    serveViews(running());
    const { container } = renderColumn();
    await screen.findByText(S.ai2.running);
    expect(await scan(container)).toEqual([]);
  });

  it.each(Object.values(S.ai2.tabs).slice(1))(
    "has no axe violation with a full result on the tab %s",
    async (tab) => {
      serveViews(
        done(
          runV4({
            changed: true,
            overruled: "đã bị hạ xuống",
            rag: { best_pct: null, not_applied: "auth", below_floor_pct: null, floor_pct: null },
          }),
        ),
      );
      const { container } = renderColumn(true, S.ai2.caseLine("0b30b853", 3, ["lab-win-02"]));
      await userEvent.setup().click(await screen.findByRole("tab", { name: tab }));
      expect(await scan(container)).toEqual([]);
    },
  );

  it.each(Object.values(S.ai2.tabs).slice(1))(
    "has no axe violation with an older result, the conclusion held, on the tab %s",
    async (tab) => {
      serveViews(
        done(
          runV3({
            conclusion: "need_more_data",
            conclusion_label: "Cần thêm dữ liệu",
            model_conclusion: "false_positive",
            held_by: ["no_verified_evidence", "high_severity_injection_finding"],
          }),
        ),
      );
      const { container } = renderColumn();
      await userEvent.setup().click(await screen.findByRole("tab", { name: tab }));
      expect(await scan(container)).toEqual([]);
    },
  );

  it("has no axe violation when stalled, failed, failed over a result, or stopped", async () => {
    for (const [shown, ready] of [
      [view({ state: "stalled", run_id: RUN, minutes: 9 }), S.ai2.stalled(9)],
      [view({ state: "failed" }), S.ai2.failed],
      [view({ state: "failed", run: runV4() }), S.ai2.failed],
      [done(stoppedRun("đã chạm hạn mức chi phí LLM")), /Phân tích không có kết quả/],
    ] as const) {
      serveViews(shown);
      const { container, unmount } = renderColumn();
      await screen.findByText(ready);
      expect(await scan(container)).toEqual([]);
      unmount();
    }
  });
});
