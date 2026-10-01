// src/features/tier1/DecisionPanel.test.tsx — the decision panel of the alert page: acknowledge, decide,
// escalate, reopen; who may act; the errors of a decision (409, 422, 503, 401); and the reason draft that
// survives a lost session (Review Focus 4).
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { delay, http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import { fetchAlertView, type AlertView } from "../../api/tier1";
import { setTokenSource } from "../../api/client";
import type { Session } from "../../auth/session";
import { formatDateTime } from "../../format";
import { S } from "../../strings";
import { DecisionPanel } from "./DecisionPanel";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterAll(() => server.close());

const ME_ID = "6f0c3a52-0d3e-4b8e-9d55-2f1a5f0e7c11";

const session = (role: Session["role"] = "tier1"): Session => ({
  token: "tok-1",
  role,
  username: "an",
  expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
});

/** A `tier1_active` alert held by the signed-in user. */
const mine = (over: Partial<AlertView> = {}): AlertView => ({
  alert_id: "a1",
  status: "tier1_active",
  suggestion_visible: true,
  category: "ssh_brute_force",
  agent_name: "lab-ubuntu-01",
  severity: "high",
  occurrence_count: 37,
  acknowledged_by: ME_ID,
  acknowledged_by_name: "An",
  ...over,
});

let calls: { path: string; body: unknown }[] = [];
const posts = (suffix: string) => calls.filter((c) => c.path.endsWith(suffix));
let meCalls = 0;
let unauthorized = vi.fn();

const record = (path: string, body: unknown) => calls.push({ path, body });

beforeEach(() => {
  calls = [];
  meCalls = 0;
  unauthorized = vi.fn();
  sessionStorage.clear();
  server.use(
    http.get("/api/auth/me", () => {
      meCalls += 1;
      return HttpResponse.json({
        user_id: ME_ID,
        username: "an",
        display_name: "An",
        role: "tier1",
        expires_at: new Date(Date.now() + 3_600_000).toISOString(),
      });
    }),
  );
  setTokenSource(() => "tok-1", unauthorized);
});
afterEach(() => {
  server.resetHandlers();
  vi.restoreAllMocks();
  sessionStorage.clear();
  setTokenSource(
    () => null,
    () => {},
  );
});

/** Answers a POST, recording the body it got. */
function answerPost(action: string, respond: (body: unknown) => Response | Promise<Response>) {
  server.use(
    http.post(`/api/tier1/alerts/:id/${action}`, async ({ request }) => {
      const text = await request.text();
      const body: unknown = text === "" ? null : JSON.parse(text);
      record(`/${action}`, body);
      return respond(body);
    }),
  );
}

const clientOf = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });

function renderPanel(
  view: AlertView,
  { role = "tier1" as Session["role"], onDone = vi.fn(), client = clientOf() } = {},
) {
  const utils = render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <main>
          <DecisionPanel view={view} me={session(role)} onDone={onDone} />
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...utils, onDone, client };
}

/** The panel under a live view: what a decision refetches is what the panel then shows. */
function Host({ onDone }: { onDone: () => void }) {
  const q = useQuery({ queryKey: ["alert", "a1"], queryFn: () => fetchAlertView("a1") });
  return q.data ? <DecisionPanel view={q.data} me={session()} onDone={onDone} /> : null;
}
function renderHosted() {
  const onDone = vi.fn();
  const client = clientOf();
  const utils = render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <main>
          <Host onDone={onDone} />
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { ...utils, onDone, client };
}

/** Waits for the form of a held alert (the user id, from /me, is what says it is mine). */
const findDecideForm = () => screen.findByRole("radio", { name: S.decision.falsePositive });
const reasonBox = () => screen.getByLabelText(S.decision.reason);

/** Picks a decision, types a reason, and returns the user. */
async function fill(
  reason = "không có dấu hiệu tấn công",
  decision: string = S.decision.falsePositive,
) {
  const user = userEvent.setup();
  await user.click(await screen.findByRole("radio", { name: decision }));
  await user.type(reasonBox(), reason);
  return user;
}
const submit = () => screen.getByRole("button", { name: S.decision.submit });

describe("who sees what", () => {
  it("shows only 'Nhận xử lý' on a queued alert", async () => {
    renderPanel(
      mine({ status: "queued_tier1", acknowledged_by: null, acknowledged_by_name: null }),
    );
    expect(screen.getByRole("button", { name: S.decision.acknowledge })).toBeInTheDocument();
    expect(screen.getAllByRole("button")).toHaveLength(1);
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("posts the acknowledge once, refetches, and tells the page it is done", async () => {
    // Slow enough that the second click of the double click arrives while the first is still in flight.
    answerPost("acknowledge", async () => {
      await delay(120);
      return HttpResponse.json({ alert_id: "a1", status: "tier1_active", acknowledged_by: ME_ID });
    });
    const { onDone, client } = renderPanel(
      mine({ status: "queued_tier1", acknowledged_by: null, acknowledged_by_name: null }),
    );
    client.setQueryData(["queue", "x"], { rows: [] });
    const user = userEvent.setup();
    await user.dblClick(screen.getByRole("button", { name: S.decision.acknowledge }));
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(posts("/acknowledge")).toHaveLength(1);
    expect(onDone).toHaveBeenCalledWith(expect.objectContaining({ status: "tier1_active" }));
    expect(client.getQueryState(["queue", "x"])?.isInvalidated).toBe(true);
  });

  it("shows decide, escalate and the reason to the holder of an active alert", async () => {
    renderPanel(mine());
    expect(await findDecideForm()).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: S.decision.benign })).toBeInTheDocument();
    expect(reasonBox()).toBeInTheDocument();
    expect(submit()).toBeInTheDocument();
    expect(screen.getByLabelText(S.decision.caseTitle)).toHaveValue(
      "ssh_brute_force — lab-ubuntu-01",
    );
    expect(screen.getByLabelText(S.decision.severity)).toHaveValue("high");
    expect(screen.getByRole("button", { name: S.decision.escalate })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: S.decision.acknowledge })).not.toBeInTheDocument();
  });

  it("holds the decision until a reason and a choice are given", async () => {
    renderPanel(mine());
    await findDecideForm();
    expect(submit()).toBeDisabled();
    const user = userEvent.setup();
    await user.type(reasonBox(), "   ");
    await user.click(screen.getByRole("radio", { name: S.decision.benign }));
    expect(submit()).toBeDisabled();
    await user.type(reasonBox(), "lành tính");
    expect(submit()).toBeEnabled();
  });

  it("is read-only, naming who holds it, when someone else acknowledged it", async () => {
    renderPanel(mine({ acknowledged_by: "another-user-id", acknowledged_by_name: "Bình" }));
    expect(await screen.findByText(S.decision.heldBy("Bình"))).toBeInTheDocument();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("compares the user ids without regard to case", async () => {
    renderPanel(mine({ acknowledged_by: ME_ID.toUpperCase() }));
    expect(await findDecideForm()).toBeInTheDocument();
  });

  it("keeps who the user is under the one key ['me']: the cache goes with the token, so the key need not carry it", async () => {
    const { client } = renderPanel(mine());
    await findDecideForm();
    expect(client.getQueryData(["me"])).toEqual({ userId: ME_ID });
    expect(client.getQueryData(["me", "tok-1"])).toBeUndefined();
  });

  it.each(["tier2", "admin"] as const)(
    "shows nothing to %s, and does not ask who they are",
    async (role) => {
      const { container } = renderPanel(mine(), { role });
      await new Promise((r) => setTimeout(r, 50));
      expect(container.querySelector("main")).toBeEmptyDOMElement();
      expect(meCalls).toBe(0);
    },
  );

  it("waits for /me before it says whose alert this is", async () => {
    server.use(
      http.get("/api/auth/me", async () => {
        await delay(150);
        return HttpResponse.json({ user_id: ME_ID, username: "an", role: "tier1" });
      }),
    );
    renderPanel(mine());
    expect(screen.getByRole("status")).toHaveTextContent(S.decision.loadingMe);
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(await findDecideForm()).toBeInTheDocument();
  });

  it("offers a retry when /me fails, and never guesses that the alert is the user's", async () => {
    let fail = true;
    server.use(
      http.get("/api/auth/me", () =>
        fail
          ? HttpResponse.json({ detail: "boom" }, { status: 500 })
          : HttpResponse.json({ user_id: ME_ID, username: "an", role: "tier1" }),
      ),
    );
    renderPanel(mine());
    expect(await screen.findByText(S.decision.meFailed)).toBeInTheDocument();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    fail = false;
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: S.common.retry }));
    expect(await findDecideForm()).toBeInTheDocument();
  });

  it("reopens an auto-closed alert with a reason", async () => {
    answerPost("reopen", () => HttpResponse.json({ alert_id: "a1", status: "queued_tier1" }));
    const { onDone } = renderPanel(
      mine({ status: "auto_closed", acknowledged_by: null, acknowledged_by_name: null }),
    );
    expect(screen.getByText(S.decision.autoClosed)).toBeInTheDocument();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    const user = userEvent.setup();
    const reopen = screen.getByRole("button", { name: S.decision.reopen });
    expect(reopen).toBeDisabled();
    await user.type(screen.getByLabelText(S.decision.reopenReason), "cần xem lại");
    await user.click(reopen);
    await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
    expect(posts("/reopen")).toEqual([{ path: "/reopen", body: { reason: "cần xem lại" } }]);
    expect(await screen.findByRole("status")).toHaveTextContent(S.decision.reopened);
  });

  it("says what a closed alert was decided as, with the reason, and offers no action", () => {
    renderPanel(mine({ status: "closed_benign", close_reason: "máy quét nội bộ đã đăng ký" }));
    expect(screen.getByText(S.decision.decidedAs(S.status.closed_benign))).toBeInTheDocument();
    expect(screen.getByText("máy quét nội bộ đã đăng ký")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("unknown enum renders raw code: a status the UI has no label for", () => {
    renderPanel(mine({ status: "quantum_pending" }));
    expect(screen.getByText(S.decision.notActionable("quantum_pending"))).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});

describe("decide", () => {
  it("sends the count the page showed, not the server's current one", async () => {
    server.use(
      // The cluster has grown to 40 since the page was drawn; the analyst has read 37. A panel that asked the
      // server for the count now, and sent that, would send 40 and never be told the cluster had grown.
      http.get("/api/tier1/alerts/a1", () => HttpResponse.json(mine({ occurrence_count: 40 }))),
    );
    answerPost("decide", () =>
      HttpResponse.json({ alert_id: "a1", status: "closed_fp", closed_count: 1, case_id: null }),
    );
    renderPanel(mine({ occurrence_count: 37 }));
    expect(await findDecideForm()).toBeInTheDocument();
    expect(screen.getByText(S.decision.seenHint(37))).toBeInTheDocument();
    const user = await fill("không có dấu hiệu tấn công");
    await user.click(submit());
    await waitFor(() => expect(posts("/decide")).toHaveLength(1));
    expect(posts("/decide")[0]?.body).toEqual({
      decision: "false_positive",
      reason: "không có dấu hiệu tấn công",
      seen_occurrence_count: 37,
    });
  });

  it("sends 'benign' for the benign choice", async () => {
    answerPost("decide", () =>
      HttpResponse.json({
        alert_id: "a1",
        status: "closed_benign",
        closed_count: 1,
        case_id: null,
      }),
    );
    renderPanel(mine());
    const user = await fill("lành tính", S.decision.benign);
    await user.click(submit());
    await waitFor(() => expect(posts("/decide")).toHaveLength(1));
    expect(posts("/decide")[0]?.body).toMatchObject({ decision: "benign", reason: "lành tính" });
  });

  it("posts to the head of a duplicate, and refreshes the page it was asked for as well", async () => {
    answerPost("decide", () =>
      HttpResponse.json({ alert_id: "head1", status: "closed_fp", closed_count: 1, case_id: null }),
    );
    const client = clientOf();
    client.setQueryData(["alert", "dup9"], { alert_id: "head1" });
    client.setQueryData(["alert", "head1"], { alert_id: "head1" });
    let path = "";
    server.use(
      http.post("/api/tier1/alerts/:id/decide", ({ params }) => {
        path = String(params.id);
        return HttpResponse.json({
          alert_id: "head1",
          status: "closed_fp",
          closed_count: 1,
          case_id: null,
        });
      }),
    );
    const { onDone } = renderPanel(mine({ alert_id: "head1", requested_alert_id: "dup9" }), {
      client,
    });
    const user = await fill();
    await user.click(submit());
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(path).toBe("head1");
    expect(client.getQueryState(["alert", "dup9"])?.isInvalidated).toBe(true);
    expect(client.getQueryState(["alert", "head1"])?.isInvalidated).toBe(true);
  });

  it("shows the cluster size in a toast, refreshes the queue and the alert, and clears the draft", async () => {
    // The server counts the head with its duplicates: four closed alerts is a head and three more.
    answerPost("decide", () =>
      HttpResponse.json({ alert_id: "a1", status: "closed_fp", closed_count: 4, case_id: null }),
    );
    const client = clientOf();
    client.setQueryData(["queue", "q"], { rows: [] });
    client.setQueryData(["alert", "a1"], { alert_id: "a1" });
    const { onDone } = renderPanel(mine(), { client });
    const user = await fill();
    expect(sessionStorage.getItem("soc.draft.a1")).not.toBeNull();
    await user.click(submit());
    const toast = await screen.findByRole("status");
    expect(toast).toHaveTextContent(S.decision.recorded);
    expect(toast).toHaveTextContent("Đã đóng cụm (4 alert)");
    expect(toast).not.toHaveTextContent("thêm");
    expect(onDone).toHaveBeenCalledWith(expect.objectContaining({ closed_count: 4 }));
    expect(client.getQueryState(["queue", "q"])?.isInvalidated).toBe(true);
    expect(client.getQueryState(["alert", "a1"])?.isInvalidated).toBe(true);
    expect(sessionStorage.getItem("soc.draft.a1")).toBeNull();
  });

  it("names the case a decision landed in, without a link (tier 1 has no case pages)", async () => {
    answerPost("decide", () =>
      HttpResponse.json({ alert_id: "a1", status: "closed_fp", closed_count: 1, case_id: 4 }),
    );
    renderPanel(mine());
    const user = await fill();
    await user.click(submit());
    const toast = await screen.findByRole("status");
    expect(toast).toHaveTextContent(S.decision.caseNumber(4));
    expect(within(toast).queryByRole("link")).not.toBeInTheDocument();
  });

  it("says one alert was closed when the head had no duplicates, and the toast can be dismissed", async () => {
    // `closed_count` counts the alert itself: a head with no duplicates closes 1, never 0.
    answerPost("decide", () =>
      HttpResponse.json({ alert_id: "a1", status: "closed_fp", closed_count: 1, case_id: null }),
    );
    renderPanel(mine());
    const user = await fill();
    await user.click(submit());
    const toast = await screen.findByRole("status");
    expect(toast).toHaveTextContent(S.decision.recorded);
    expect(toast).toHaveTextContent("Đã đóng alert");
    expect(toast).not.toHaveTextContent("cụm");
    expect(toast).not.toHaveTextContent("thêm");
    await user.click(within(toast).getByRole("button", { name: S.common.close }));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("says nothing of a count the server did not send, or sent as zero", async () => {
    // Not a case the server produces: the toast must not claim a close it was not told of.
    for (const closed of [0, undefined]) {
      answerPost("decide", () =>
        HttpResponse.json({
          alert_id: "a1",
          status: "closed_fp",
          closed_count: closed,
          case_id: null,
        }),
      );
      const { unmount } = renderPanel(mine());
      const user = await fill();
      await user.click(submit());
      const toast = await screen.findByRole("status");
      expect(toast).toHaveTextContent(S.decision.recorded);
      expect(toast).not.toHaveTextContent("Đã đóng");
      unmount();
    }
  });

  it("disables the buttons while a request is in flight, and a double click posts once", async () => {
    answerPost("decide", async () => {
      await delay(120);
      return HttpResponse.json({
        alert_id: "a1",
        status: "closed_fp",
        closed_count: 1,
        case_id: null,
      });
    });
    renderPanel(mine());
    const user = await fill();
    await user.dblClick(submit());
    expect(submit()).toBeDisabled();
    expect(screen.getByRole("button", { name: S.decision.escalate })).toBeDisabled();
    await screen.findByRole("status");
    expect(posts("/decide")).toHaveLength(1);
  });
});

describe("escalate", () => {
  it("posts the title and the severity, and the toast names the new case", async () => {
    answerPost("escalate", () =>
      HttpResponse.json(
        { alert_id: "a1", case_id: 9, status: "escalated_tier2", head_count: 1, truncated: false },
        { status: 201 },
      ),
    );
    const { onDone } = renderPanel(mine());
    await findDecideForm();
    const user = userEvent.setup();
    const title = screen.getByLabelText(S.decision.caseTitle);
    await user.clear(title);
    await user.type(title, "SSH brute force vào lab-ubuntu-01");
    await user.selectOptions(screen.getByLabelText(S.decision.severity), "critical");
    await user.click(screen.getByRole("button", { name: S.decision.escalate }));
    const toast = await screen.findByRole("status");
    expect(toast).toHaveTextContent(S.decision.caseOpened);
    // Tier 1 has no case pages (they are Tier 2's): the case is named, not linked.
    expect(toast).toHaveTextContent(S.decision.caseNumber(9));
    expect(within(toast).queryByRole("link")).not.toBeInTheDocument();
    expect(posts("/escalate")).toEqual([
      {
        path: "/escalate",
        body: { title: "SSH brute force vào lab-ubuntu-01", severity: "critical" },
      },
    ]);
    expect(onDone).toHaveBeenCalledWith(expect.objectContaining({ case_id: 9 }));
  });

  it("does not send an empty title", async () => {
    renderPanel(mine());
    await findDecideForm();
    const user = userEvent.setup();
    await user.clear(screen.getByLabelText(S.decision.caseTitle));
    expect(screen.getByRole("button", { name: S.decision.escalate })).toBeDisabled();
  });
});

describe("errors", () => {
  it("shows the server's 409 with both counts, refetches the view, and asks again with the new count", async () => {
    let count = 37;
    server.use(
      http.get("/api/tier1/alerts/a1", () => HttpResponse.json(mine({ occurrence_count: count }))),
    );
    let attempts = 0;
    answerPost("decide", () => {
      attempts += 1;
      if (attempts > 1) {
        return HttpResponse.json({
          alert_id: "a1",
          status: "closed_fp",
          closed_count: 1,
          case_id: null,
        });
      }
      count = 40;
      return HttpResponse.json(
        {
          kind: "cluster_grew",
          occurrence_count: 40,
          seen_occurrence_count: 37,
          delta: 3,
          tolerance: 2,
          status: "tier1_active",
          decided_by: null,
          decision: null,
          decided_at: null,
          acknowledged_by: ME_ID,
        },
        { status: 409 },
      );
    });
    renderHosted();
    const user = await fill("không có dấu hiệu tấn công");
    await user.click(submit());
    expect(await screen.findByRole("alert")).toHaveTextContent(
      S.decision.conflict.clusterGrew(37, 40, 3, 2),
    );
    // the view is fetched again: the form now carries the new count, and keeps what was typed
    expect(await screen.findByText(S.decision.seenHint(40))).toBeInTheDocument();
    expect(reasonBox()).toHaveValue("không có dấu hiệu tấn công");
    expect(submit()).toBeEnabled();
    await user.click(submit());
    await waitFor(() => expect(posts("/decide")).toHaveLength(2));
    expect(
      posts("/decide").map(
        (c) => (c.body as { seen_occurrence_count: number }).seen_occurrence_count,
      ),
    ).toEqual([37, 40]);
  });

  it("says who decided it, and what, when the alert was decided first by someone else", async () => {
    // The page is drawn while the alert is still open; by the time the decision arrives someone else has closed it.
    let closed = false;
    server.use(
      http.get("/api/tier1/alerts/a1", () =>
        HttpResponse.json(mine(closed ? { status: "closed_benign" } : {})),
      ),
    );
    answerPost("decide", () => {
      closed = true;
      return HttpResponse.json(
        {
          kind: "already_decided",
          status: "closed_benign",
          decided_by: "Bình",
          decision: "closed_benign",
          decided_at: "2026-09-30T02:31:02Z",
          occurrence_count: 37,
        },
        { status: 409 },
      );
    });
    renderHosted();
    const user = await fill();
    await user.click(submit());
    expect(await screen.findByRole("alert")).toHaveTextContent(
      S.decision.conflict.alreadyDecided(
        "Bình",
        S.status.closed_benign,
        formatDateTime("2026-09-30T02:31:02Z"),
      ),
    );
    // and the page shows what it now is
    expect(
      await screen.findByText(S.decision.decidedAs(S.status.closed_benign)),
    ).toBeInTheDocument();
  });

  it("names the system when nobody decided (an automatic close)", async () => {
    answerPost("decide", () =>
      HttpResponse.json(
        {
          kind: "already_decided",
          status: "auto_closed",
          decided_by: null,
          decision: "auto_closed",
          decided_at: null,
        },
        { status: 409 },
      ),
    );
    renderPanel(mine());
    const user = await fill();
    await user.click(submit());
    expect(await screen.findByRole("alert")).toHaveTextContent(
      `Đã được ${S.decision.conflict.system} quyết ${S.status.auto_closed}`,
    );
  });

  it.each([
    ["already_in_case", S.decision.conflict.alreadyInCase],
    ["not_reopenable", S.decision.conflict.notReopenable],
    ["not_active", S.decision.conflict.notActive],
    ["a_kind_from_the_future", S.decision.conflict.notActive],
  ])("words a 409 of kind %s", async (kind, text) => {
    answerPost("decide", () =>
      HttpResponse.json({ kind, status: "queued_tier1" }, { status: 409 }),
    );
    renderPanel(mine());
    const user = await fill();
    await user.click(submit());
    expect(await screen.findByRole("alert")).toHaveTextContent(text);
  });

  it("shows a 422 at the reason field, and keeps what was typed", async () => {
    answerPost("decide", () =>
      HttpResponse.json({ detail: "reason: must be 1-500 characters" }, { status: 422 }),
    );
    renderPanel(mine());
    const user = await fill("x");
    await user.click(submit());
    await waitFor(() => expect(reasonBox()).toHaveAttribute("aria-invalid", "true"));
    expect(reasonBox()).toHaveAccessibleDescription(/reason: must be 1-500 characters/);
    expect(reasonBox()).toHaveValue("x");
    expect(submit()).toBeEnabled();
  });

  it("says the data is not valid when a 422 carries no message of the server's", async () => {
    answerPost("decide", () =>
      HttpResponse.json(
        { detail: [{ loc: ["body", "reason"], msg: "Field required" }] },
        { status: 422 },
      ),
    );
    renderPanel(mine());
    const user = await fill("x");
    await user.click(submit());
    await waitFor(() =>
      expect(reasonBox()).toHaveAccessibleDescription(new RegExp(S.decision.invalid)),
    );
  });

  it("shows S.decision.timeout for a 503, writes nothing, and lets the user try again", async () => {
    answerPost("decide", () =>
      HttpResponse.json({ detail: "fan-out timed out; nothing was written" }, { status: 503 }),
    );
    renderPanel(mine());
    const user = await fill();
    await user.click(submit());
    expect(await screen.findByRole("alert")).toHaveTextContent(S.decision.timeout);
    expect(submit()).toBeEnabled();
    expect(sessionStorage.getItem("soc.draft.a1")).not.toBeNull();
  });

  it("shows the message of a 422 of the escalate form at the title", async () => {
    answerPost("escalate", () =>
      HttpResponse.json({ detail: "title: must be 1-200 characters" }, { status: 422 }),
    );
    renderPanel(mine());
    await findDecideForm();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: S.decision.escalate }));
    await waitFor(() =>
      expect(screen.getByLabelText(S.decision.caseTitle)).toHaveAccessibleDescription(
        /title: must be 1-200 characters/,
      ),
    );
  });
});

describe("the count the decision is made on (ruling R19)", () => {
  const clusterGrew = (now: number) =>
    HttpResponse.json(
      {
        kind: "cluster_grew",
        occurrence_count: now,
        seen_occurrence_count: 37,
        delta: now - 37,
        tolerance: 2,
        status: "tier1_active",
        decided_by: null,
        decision: null,
        decided_at: null,
        acknowledged_by: ME_ID,
      },
      { status: 409 },
    );
  const closedFp = () =>
    HttpResponse.json({ alert_id: "a1", status: "closed_fp", closed_count: 1, case_id: null });
  const seenOf = (n: number) =>
    (posts("/decide")[n]?.body as { seen_occurrence_count: number }).seen_occurrence_count;

  /** A page whose alert the server answers with `count.now`; a live refetch is `client.invalidateQueries`. */
  function livePanel() {
    const count = { now: 37 };
    server.use(
      http.get("/api/tier1/alerts/a1", () =>
        HttpResponse.json(mine({ occurrence_count: count.now })),
      ),
    );
    const utils = renderHosted();
    const refetch = (n: number) => {
      count.now = n;
      return act(async () => {
        await utils.client.invalidateQueries({ queryKey: ["alert", "a1"] });
      });
    };
    return { ...utils, count, refetch };
  }

  it("keeps sending the count the form was drawn with when a live refetch brings a larger one", async () => {
    answerPost("decide", closedFp);
    const { refetch } = livePanel();
    const user = await fill();
    expect(screen.getByText(S.decision.seenHint(37))).toBeInTheDocument();
    await refetch(120);
    // the analyst has read 37: the form still says so, and the reason typed is still there
    expect(await screen.findByText(S.decision.seenChanged(37, 120))).toBeInTheDocument();
    expect(screen.getByText(S.decision.seenHint(37))).toBeInTheDocument();
    expect(screen.queryByText(S.decision.seenHint(120))).not.toBeInTheDocument();
    expect(reasonBox()).toHaveValue("không có dấu hiệu tấn công");
    await user.click(submit());
    await waitFor(() => expect(posts("/decide")).toHaveLength(1));
    expect(seenOf(0)).toBe(37);
  });

  it("holds the new count only when the server answers cluster_grew, and sends it on the next submit", async () => {
    let attempts = 0;
    answerPost("decide", () => {
      attempts += 1;
      return attempts === 1 ? clusterGrew(120) : closedFp();
    });
    const { refetch } = livePanel();
    const user = await fill();
    await refetch(120);
    expect(await screen.findByText(S.decision.seenChanged(37, 120))).toBeInTheDocument();
    await user.click(submit());
    expect(await screen.findByRole("alert")).toHaveTextContent(
      S.decision.conflict.clusterGrew(37, 120, 83, 2),
    );
    // now the form holds what the 409 told the analyst: 120, and there is nothing left to warn about
    expect(await screen.findByText(S.decision.seenHint(120))).toBeInTheDocument();
    expect(screen.queryByText(S.decision.seenChanged(37, 120))).not.toBeInTheDocument();
    expect(reasonBox()).toHaveValue("không có dấu hiệu tấn công");
    await user.click(submit());
    await waitFor(() => expect(posts("/decide")).toHaveLength(2));
    expect([seenOf(0), seenOf(1)]).toEqual([37, 120]);
  });

  it("warns again when the cluster grows once more after the 409, and still does not adopt it silently", async () => {
    let attempts = 0;
    answerPost("decide", () => {
      attempts += 1;
      return attempts === 1 ? clusterGrew(120) : closedFp();
    });
    const { refetch } = livePanel();
    const user = await fill();
    await refetch(120);
    await user.click(submit());
    expect(await screen.findByText(S.decision.seenHint(120))).toBeInTheDocument();
    await refetch(150);
    expect(await screen.findByText(S.decision.seenChanged(120, 150))).toBeInTheDocument();
    await user.click(submit());
    await waitFor(() => expect(posts("/decide")).toHaveLength(2));
    expect([seenOf(0), seenOf(1)]).toEqual([37, 120]);
  });

  it("does not adopt a count for a 409 that is not cluster_grew", async () => {
    let attempts = 0;
    answerPost("decide", () => {
      attempts += 1;
      return attempts === 1
        ? HttpResponse.json({ kind: "not_active", status: "tier1_active" }, { status: 409 })
        : closedFp();
    });
    const { refetch } = livePanel();
    const user = await fill();
    await refetch(120);
    await user.click(submit());
    expect(await screen.findByRole("alert")).toHaveTextContent(S.decision.conflict.notActive);
    await waitFor(() => expect(submit()).toBeEnabled());
    expect(screen.getByText(S.decision.seenHint(37))).toBeInTheDocument();
    expect(screen.getByText(S.decision.seenChanged(37, 120))).toBeInTheDocument();
    await user.click(submit());
    await waitFor(() => expect(posts("/decide")).toHaveLength(2));
    expect([seenOf(0), seenOf(1)]).toEqual([37, 37]);
  });

  it("words the notice and the hint as a possibility: the server has a tolerance, so a small rise posts with no review", async () => {
    // REVIEW_DELTA_TOLERANCE is 20 (backend infra/config.py): 37 → 40 is answered with no 409, so the page must
    // not promise a review. It does not show the tolerance either: the number is the server's to change.
    const { refetch } = livePanel();
    await fill();
    await refetch(40);
    const notice = await screen.findByText(S.decision.seenChanged(37, 40));
    expect(notice.textContent).toContain("có thể");
    expect(notice.textContent).not.toContain("sẽ yêu cầu");
    expect(notice.textContent?.match(/\d+/g)).toEqual(["37", "40"]);
    const hint = screen.getByText(S.decision.seenHint(37));
    expect(hint.textContent).toContain("có thể");
    expect(hint.textContent).not.toContain("sẽ yêu cầu");
    expect(hint.textContent?.match(/\d+/g)).toEqual(["37"]);
  });

  it("says nothing while the count on the server is the count the form holds", async () => {
    const { refetch } = livePanel();
    await fill();
    await refetch(37);
    expect(screen.getByText(S.decision.seenHint(37))).toBeInTheDocument();
    expect(screen.queryByText(S.decision.seenChanged(37, 37))).not.toBeInTheDocument();
    expect(document.body.textContent).not.toContain("→");
  });
});

describe("the reason draft (Review Focus 4)", () => {
  const key = "soc.draft.a1";
  const draft = () => JSON.parse(sessionStorage.getItem(key) ?? "null") as unknown;

  it("is stored under soc.draft.<alert_id> as {user_id, text} while it is typed", async () => {
    renderPanel(mine());
    await fill("đang gõ dở");
    expect(draft()).toEqual({ user_id: ME_ID, text: "đang gõ dở" });
  });

  it("is dropped when the box is emptied", async () => {
    renderPanel(mine());
    const user = await fill("abc");
    await user.clear(reasonBox());
    expect(sessionStorage.getItem(key)).toBeNull();
  });

  it("keeps the reason draft across a 401, and posts once", async () => {
    answerPost("decide", () => HttpResponse.json({ detail: "expired" }, { status: 401 }));
    const first = renderPanel(mine());
    const user = await fill("lý do gõ dở khi phiên hết hạn");
    await user.click(submit());
    expect(await screen.findByRole("alert")).toHaveTextContent(S.decision.sessionEnded);
    expect(unauthorized).toHaveBeenCalledTimes(1);
    expect(posts("/decide")).toHaveLength(1);
    expect(draft()).toEqual({ user_id: ME_ID, text: "lý do gõ dở khi phiên hết hạn" });

    // The session is gone, the page and the query cache with it; the user logs in again and comes back.
    first.unmount();
    answerPost("decide", () =>
      HttpResponse.json({ alert_id: "a1", status: "closed_fp", closed_count: 1, case_id: null }),
    );
    renderPanel(mine());
    await findDecideForm();
    expect(reasonBox()).toHaveValue("lý do gõ dở khi phiên hết hạn");
    const again = userEvent.setup();
    await again.click(screen.getByRole("radio", { name: S.decision.falsePositive }));
    await again.click(submit());
    await screen.findByRole("status");
    expect(sessionStorage.getItem(key)).toBeNull(); // removed after a successful decide
    // the 401 was one POST, the retry by the user another: nothing was sent behind their back
    expect(posts("/decide")).toHaveLength(2);
  });

  it("is restored only for the user who typed it", async () => {
    sessionStorage.setItem(
      key,
      JSON.stringify({ user_id: "someone-else", text: "lý do của người khác" }),
    );
    renderPanel(mine());
    await findDecideForm();
    expect(reasonBox()).toHaveValue("");
    expect(screen.queryByDisplayValue("lý do của người khác")).not.toBeInTheDocument();
  });

  it("is restored for the same user, and ignored when it is not readable", async () => {
    sessionStorage.setItem(key, JSON.stringify({ user_id: ME_ID, text: "lý do của tôi" }));
    const first = renderPanel(mine());
    await findDecideForm();
    expect(reasonBox()).toHaveValue("lý do của tôi");
    first.unmount();
    for (const junk of ["{not json", "42", "null", '{"user_id":1}', '{"text":"x"}']) {
      sessionStorage.setItem(key, junk);
      const again = renderPanel(mine());
      await findDecideForm();
      expect(reasonBox(), junk).toHaveValue("");
      again.unmount();
    }
  });

  it("is kept apart for each alert", async () => {
    sessionStorage.setItem("soc.draft.a2", JSON.stringify({ user_id: ME_ID, text: "của a2" }));
    renderPanel(mine());
    await findDecideForm();
    expect(reasonBox()).toHaveValue("");
  });

  it("never touches localStorage", async () => {
    const spy = vi.spyOn(Storage.prototype, "setItem");
    renderPanel(mine());
    await fill("abc");
    expect(spy).toHaveBeenCalledWith(key, expect.any(String));
    expect(localStorage.length).toBe(0);
  });
});

describe("accessibility", () => {
  const violations = async (container: HTMLElement) => {
    // jsdom computes no colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`);
  };

  it("has no axe violation in the queued, held-by-me, held-by-other and closed states", async () => {
    const queued = renderPanel(
      mine({ status: "queued_tier1", acknowledged_by: null, acknowledged_by_name: null }),
    );
    expect(await violations(queued.container)).toEqual([]);
    queued.unmount();

    const held = renderPanel(mine());
    await findDecideForm();
    expect(await violations(held.container)).toEqual([]);
    held.unmount();

    const other = renderPanel(mine({ acknowledged_by: "other", acknowledged_by_name: "Bình" }));
    await screen.findByText(S.decision.heldBy("Bình"));
    expect(await violations(other.container)).toEqual([]);
    other.unmount();

    const closed = renderPanel(mine({ status: "closed_fp", close_reason: "lý do" }));
    expect(await violations(closed.container)).toEqual([]);
    closed.unmount();

    const auto = renderPanel(mine({ status: "auto_closed" }));
    expect(await violations(auto.container)).toEqual([]);
  });

  it("has none with the notice that the cluster grew since the form was drawn", async () => {
    let now = 37;
    server.use(
      http.get("/api/tier1/alerts/a1", () => HttpResponse.json(mine({ occurrence_count: now }))),
    );
    const { container, client } = renderHosted();
    await findDecideForm();
    now = 120;
    await act(async () => {
      await client.invalidateQueries({ queryKey: ["alert", "a1"] });
    });
    expect(await screen.findByText(S.decision.seenChanged(37, 120))).toBeInTheDocument();
    expect(await violations(container)).toEqual([]);
  });

  it("has none while /me loads, after an error, and with a toast", async () => {
    server.use(
      http.get("/api/auth/me", async () => {
        await delay(100);
        return HttpResponse.json({ user_id: ME_ID, username: "an", role: "tier1" });
      }),
    );
    const loading = renderPanel(mine());
    expect(await violations(loading.container)).toEqual([]);
    await findDecideForm();
    answerPost("decide", () =>
      HttpResponse.json({ detail: "reason: must be 1-500 characters" }, { status: 422 }),
    );
    const user = await fill("x");
    await user.click(submit());
    await waitFor(() => expect(reasonBox()).toHaveAttribute("aria-invalid", "true"));
    expect(await violations(loading.container)).toEqual([]);
  });
});
