// src/features/tier2/InvestigationColumn.test.tsx — the ② column of the case page (spec §4): its five
// states, the poll after an analyze, the marks on the evidence, and every refusal of the analyze route.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { http, HttpResponse, type JsonBodyType } from "msw";
import { setupServer } from "msw/node";
import { S } from "../../strings";
import { InvestigationColumn } from "./InvestigationColumn";

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
const columnOf = (client: QueryClient, caseId: string, caseOpen = true) => (
  <QueryClientProvider client={client}>
    <main>
      <InvestigationColumn caseId={caseId} caseOpen={caseOpen} />
    </main>
  </QueryClientProvider>
);

function renderColumn(caseOpen = true) {
  return render(columnOf(newClient(), CASE, caseOpen));
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

describe("done", () => {
  it("shows the suggested conclusion by the server's label and code, the confidence and the summary", async () => {
    serveViews(done());
    renderColumn();
    expect(await screen.findByText("Không phải sự cố")).toBeInTheDocument();
    expect(screen.getByText("false_positive")).toBeInTheDocument();
    expect(
      screen.getByText(`${S.ai2.confidence}: ${S.ai2.confidenceLevel.medium}`),
    ).toBeInTheDocument();
    expect(screen.getByText("Chuỗi đăng nhập thất bại đến từ chính máy lab.")).toBeInTheDocument();
    expect(screen.getByText(S.ai2.disclaimer)).toBeInTheDocument();
    expect(screen.getByText(S.ai2.resultAt("30/09/2026 08:19:00"))).toBeInTheDocument();
  });

  it("shows a conclusion label and a confidence it has no words for as they came", async () => {
    serveViews(
      done(
        run({
          conclusion: "other_thing",
          conclusion_label: "Chưa rõ kết luận",
          confidence: "certain",
        }),
      ),
    );
    renderColumn();
    expect(await screen.findByText("Chưa rõ kết luận")).toBeInTheDocument();
    expect(screen.getByText("other_thing")).toBeInTheDocument();
    expect(screen.getByText(`${S.ai2.confidence}: certain`)).toBeInTheDocument();
  });

  it("shows the narrative with its line breaks, the hypotheses and the next steps", async () => {
    serveViews(done());
    renderColumn();
    const narrative = await screen.findByText(/08:00 script bắt đầu/);
    expect(narrative).toHaveTextContent("08:00 script bắt đầu 08:12 script dừng");
    expect(narrative).toHaveClass("whitespace-pre-wrap");
    expect(screen.getByText("Script kiểm thử của nhóm hạ tầng")).toBeInTheDocument();
    expect(screen.getByText("Hỏi nhóm hạ tầng về lịch chạy script")).toBeInTheDocument();
  });

  it("keeps a hypothesis's supporting and counter-evidence in two labelled lists", async () => {
    serveViews(done());
    renderColumn();
    const hypothesis = (await screen.findByText("Script kiểm thử của nhóm hạ tầng")).closest("li");
    expect(hypothesis).not.toBeNull();
    const inside = within(hypothesis as HTMLElement);
    const support = inside.getByRole("list", { name: S.ai2.supporting });
    const counter = inside.getByRole("list", { name: S.ai2.counter });
    expect(within(support).getByText("Nguồn là 127.0.0.1")).toBeInTheDocument();
    expect(within(counter).getByText("Không có ticket kiểm thử")).toBeInTheDocument();
    expect(within(support).queryByText("Không có ticket kiểm thử")).not.toBeInTheDocument();
  });

  it("warns when a hypothesis has no counter-evidence, and only then", async () => {
    serveViews(
      done(
        run({
          hypotheses: [
            { text: "giả thuyết một", evidence_for: ["a"], evidence_against: [] },
            { text: "giả thuyết hai", evidence_for: ["b"], evidence_against: ["c"] },
          ],
        }),
      ),
    );
    renderColumn();
    const one = (await screen.findByText("giả thuyết một")).closest("li") as HTMLElement;
    const two = screen.getByText("giả thuyết hai").closest("li") as HTMLElement;
    expect(within(one).getByText(S.ai2.noCounterEvidence)).toBeInTheDocument();
    expect(within(two).queryByText(S.ai2.noCounterEvidence)).not.toBeInTheDocument();
  });

  it("marks each evidence item verified or not, with the reason the quote was refused", async () => {
    serveViews(done());
    renderColumn();
    const list = await screen.findByRole("list", { name: S.ai2.evidence });
    const [first, second] = within(list).getAllByRole("listitem");
    expect(within(first as HTMLElement).getByText(S.ai2.mark.verified)).toBeInTheDocument();
    expect(within(first as HTMLElement).queryByText(S.ai2.unverified)).not.toBeInTheDocument();
    expect(within(first as HTMLElement).getByText("a-1")).toBeInTheDocument();
    expect(within(first as HTMLElement).getByText(/Failed password for root/)).toBeInTheDocument();
    expect(
      within(first as HTMLElement).getByText("37 lần sai mật khẩu vào root"),
    ).toBeInTheDocument();
    const other = within(second as HTMLElement);
    expect(other.getByText(S.ai2.unverified)).toBeInTheDocument();
    expect(other.queryByText(S.ai2.mark.verified)).not.toBeInTheDocument();
    expect(other.getByText(/trích dẫn không có trong log hay mô tả của alert/)).toBeInTheDocument();
    expect(other.getByText("a-2")).toBeInTheDocument();
  });

  it("marks every item of a longer list by its own verdict, not by the first", async () => {
    serveViews(
      done(
        run({
          evidence: [
            evidenceItem({ verified: false, reason_text: "alert này không thuộc case" }),
            evidenceItem({ alert_id: "a-2" }),
            evidenceItem({ alert_id: "a-3", verified: false, reason_text: "trích dẫn ngắn" }),
          ],
        }),
      ),
    );
    renderColumn();
    await screen.findByRole("list", { name: S.ai2.evidence });
    expect(screen.getAllByText(S.ai2.mark.verified)).toHaveLength(1);
    expect(screen.getAllByText(S.ai2.unverified)).toHaveLength(2);
    expect(screen.getByText(/alert này không thuộc case/)).toBeInTheDocument();
    expect(screen.getByText(/trích dẫn ngắn/)).toBeInTheDocument();
  });

  it("says so when the assistant gave no evidence", async () => {
    serveViews(done(run({ evidence: [] })));
    renderColumn();
    expect(await screen.findByText(S.ai2.noEvidence)).toBeInTheDocument();
  });

  it("names the playbook the run used, as the Jinja page does", async () => {
    serveViews(done(run({ playbook_used: "ssh_brute_force" })));
    renderColumn();
    expect(await screen.findByText(S.ai2.playbook("ssh_brute_force"))).toBeInTheDocument();
  });

  it("names no playbook for a run that used none", async () => {
    serveViews(done(run({ playbook_used: null })));
    renderColumn();
    await screen.findByText("Không phải sự cố");
    expect(screen.queryByText(/Playbook/)).not.toBeInTheDocument();
  });

  it("names the playbook of the earlier run under a failed one too", async () => {
    serveViews(view({ state: "failed", run: run({ playbook_used: "ssh_brute_force" }) }));
    renderColumn();
    expect(await screen.findByText(S.ai2.playbook("ssh_brute_force"))).toBeInTheDocument();
  });

  it("says the model was overruled, in the server's sentence", async () => {
    const sentence =
      "Mô hình đề xuất Không phải sự cố (false_positive) nhưng kết luận đã bị hạ xuống Cần thêm dữ liệu (need_more_data): không có bằng chứng nào kiểm chứng được với log của case.";
    serveViews(done(run({ overruled: sentence })));
    renderColumn();
    expect(await screen.findByText(sentence)).toBeInTheDocument();
  });

  it("says nothing of an overrule when the model was not overruled", async () => {
    serveViews(done(run({ overruled: null })));
    renderColumn();
    await screen.findByText("Không phải sự cố");
    expect(screen.queryByText(/đã bị hạ xuống/)).not.toBeInTheDocument();
  });

  it("says the case has changed since the run, beside the numbers then and now", async () => {
    serveViews(
      done(run({ changed: true }), {
        current: {
          alert_count: 4,
          total_occurrences: 75,
          last_seen_at: "2026-09-30T02:30:00+00:00",
        },
      }),
    );
    renderColumn();
    expect(await screen.findByText(S.ai2.stale)).toBeInTheDocument();
    expect(screen.getByText(S.ai2.snapshot(3, 61, "26/09 11:12"))).toBeInTheDocument();
    expect(screen.getByText(S.ai2.current(4, 75, "30/09 09:30"))).toBeInTheDocument();
  });

  it("says nothing of a change when the case is as it was", async () => {
    serveViews(done());
    renderColumn();
    await screen.findByText("Không phải sự cố");
    expect(screen.queryByText(S.ai2.stale)).not.toBeInTheDocument();
  });

  it("offers Phân tích lại on an open case", async () => {
    serveViews(done());
    renderColumn();
    expect(await screen.findByRole("button", { name: S.ai2.reanalyze })).toBeEnabled();
  });

  it("shows a concluded case's result and no button", async () => {
    serveViews(done(run(), { case_open: false }));
    renderColumn(false);
    expect(await screen.findByText("Không phải sự cố")).toBeInTheDocument();
    expect(screen.queryAllByRole("button")).toEqual([]);
  });

  it("renders text the model wrote as text: no element is made of it", async () => {
    const markup = '<b>đậm</b> <img src=x onerror="alert(1)"> </script> ‮';
    serveViews(
      done(
        run({
          summary: markup,
          narrative: markup,
          hypotheses: [{ text: markup, evidence_for: [markup], evidence_against: [markup] }],
          evidence: [evidenceItem({ quote: markup, why: markup, alert_id: markup })],
          next_steps: [markup],
          overruled: markup,
          playbook_used: markup,
        }),
      ),
    );
    const { container } = renderColumn();
    await screen.findByRole("list", { name: S.ai2.evidence });
    expect(container.querySelector("b, img, script")).toBeNull();
    expect(screen.getAllByText(markup, { exact: false }).length).toBeGreaterThan(5);
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

  it("has no axe violation with a full result", async () => {
    serveViews(
      done(
        run({
          changed: true,
          overruled: "đã bị hạ xuống",
          hypotheses: [
            { text: "một", evidence_for: ["a"], evidence_against: [] },
            { text: "hai", evidence_for: ["b"], evidence_against: ["c"] },
          ],
        }),
      ),
    );
    const { container } = renderColumn();
    await screen.findByRole("list", { name: S.ai2.evidence });
    expect(await scan(container)).toEqual([]);
  });

  it("has no axe violation when stalled or failed", async () => {
    serveViews(view({ state: "stalled", run_id: RUN, minutes: 9 }));
    const stalled = renderColumn();
    await screen.findByText(S.ai2.stalled(9));
    expect(await scan(stalled.container)).toEqual([]);
    stalled.unmount();

    serveViews(view({ state: "failed" }));
    const failed = renderColumn();
    await screen.findByText(S.ai2.failed);
    expect(await scan(failed.container)).toEqual([]);
  });
});
