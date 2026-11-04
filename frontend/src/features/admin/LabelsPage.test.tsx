// src/features/admin/LabelsPage.test.tsx — `/admin/labels` (spec §4.6, P11-T16): blind labelling. MSW answers the
// three label routes and nothing else: an unhandled request fails the test, and every request is also logged,
// so "the page asks for nothing else while labelling" (plan Review Focus 5) is a list the tests compare.
import {
  focusManager,
  onlineManager,
  QueryClient,
  QueryClientProvider,
} from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { delay, http, HttpResponse, type JsonBodyType } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import ts from "typescript";
import {
  LABEL_CHOICES,
  LABEL_CONFIDENCES,
  type LabelChoice,
  type LabelCluster,
  type LabelsNext,
} from "../../api/admin";
import { AuthContext, type AuthState } from "../../auth/AuthProvider";
import { S } from "../../strings";
import { adminKeys } from "./adminKeys";
import { LabelsPage } from "./LabelsPage";

const L = S.admin.labelsPage;

const NEXT = "/api/admin/labels/next";
const LABELS = "/api/admin/labels";
const UNDO = "/api/admin/labels/undo";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterAll(() => server.close());

/** Every request the page makes, in order, as "METHOD /path". */
let log: string[] = [];
let nextQueries: (string | null)[] = [];
let posts: unknown[] = [];
let undos: { body: unknown; contentType: string | null }[] = [];

beforeEach(() => {
  log = [];
  nextQueries = [];
  posts = [];
  undos = [];
  server.events.on("request:start", ({ request }) => {
    log.push(`${request.method} ${new URL(request.url).pathname}`);
  });
});
afterEach(() => {
  server.events.removeAllListeners();
  server.resetHandlers();
});

// --- the data: the canvas's cluster, in the shape `labels/next` sends ---------------------------------------------

const USER_ID = "3f2c1c9e-7a53-4b8e-9c1d-0a4f5e6d7c8b";
const A = "1790411204.971380";
const B = "1790411555.100222";

const segment = (value: unknown): string =>
  btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
/** What the login answers: a JWT whose `sub` is the user id. The page reads the labeller from it. */
const tokenOf = (sub: string): string =>
  `${segment({ alg: "HS256", typ: "JWT" })}.${segment({ sub, role: "admin", iat: 1, exp: 2 })}.sig`;

const RAW_LOG = [
  "Sep 27 21:14:06 attt-m1-lab sshd[48211]: Invalid user admin from 192.168.56.20 port 51022",
  "Sep 27 21:14:06 attt-m1-lab sshd[48211]: Connection closed by invalid user admin 192.168.56.20 port 51022 [preauth]",
].join("\n");
const SAMPLE_LOG =
  "Sep 27 21:20:41 attt-m1-lab sshd[48302]: Accepted password for lab from 192.168.56.20 port 51388 ssh2";
const PLAYBOOK = [
  "# ssh_brute_force",
  "1. Có lần đăng nhập thành công từ cùng địa chỉ sau chuỗi thất bại không?",
  "2. Tài khoản bị thử có tồn tại, có đặc quyền không?",
].join("\n");

function cluster(over: Partial<LabelCluster> = {}): LabelCluster {
  return {
    alert_id: A,
    rule_id: "5710",
    rule_level: 5,
    severity: "medium",
    description: "sshd: Attempt to login using a non-existent user",
    agent_name: "attt-m1-lab",
    alert_time: "2026-09-27T14:14:06+00:00",
    alert_user: "admin",
    srcip: "192.168.56.20",
    dstip: "192.168.56.10",
    category: "ssh_brute_force",
    raw_log: RAW_LOG,
    raw_log_truncated_for_display: false,
    occurrence_count: 146,
    first_seen: "2026-09-27T14:14:00+00:00",
    last_seen: "2026-09-27T14:19:00+00:00",
    playbook: PLAYBOOK,
    correlation: {
      rows: [
        {
          rule_id: "5710",
          category: "ssh_brute_force",
          cluster_count: 1,
          alert_count: 146,
          first_seen: "2026-09-27T14:14:00+00:00",
          last_seen: "2026-09-27T14:19:00+00:00",
        },
        {
          rule_id: "5712",
          category: "ssh_brute_force",
          cluster_count: 2,
          alert_count: 12,
          first_seen: "2026-09-27T14:15:00+00:00",
          last_seen: "2026-09-27T14:18:00+00:00",
        },
      ],
      samples: [
        {
          alert_id: "1790411900.100001",
          rule_id: "5715",
          category: "suspicious_login",
          severity: "low",
          occurrence_count: 1,
          alert_time: "2026-09-27T14:20:41+00:00",
          description: "sshd: authentication success",
          raw_log: SAMPLE_LOG,
        },
      ],
    },
    gold_cluster_id: A,
    ...over,
  };
}

function clusterB(): LabelCluster {
  return cluster({
    alert_id: B,
    gold_cluster_id: B,
    rule_id: "40101",
    category: "port_scan",
    severity: "high",
    description: "Port scan from a lab host",
    raw_log: "Sep 27 21:30:11 attt-m1-lab kernel: SCAN SRC=192.168.56.20",
    correlation: { rows: [], samples: [] },
  });
}

function nextAnswer(over: Partial<LabelsNext> = {}): LabelsNext {
  return {
    cluster_id: A,
    done: 18,
    total: 60,
    cluster: cluster(),
    frozen: false,
    candidates_present: true,
    ...over,
  };
}

/** The labeller has labelled A and B is next. */
const afterA = (): LabelsNext =>
  nextAnswer({ cluster_id: B, done: 19, cluster: clusterB(), total: 60 });
const finished = (): LabelsNext =>
  nextAnswer({ cluster_id: null, cluster: null, done: 60, total: 60 });
/** What the server sends today: frozen, and a cluster still in the payload (an admin with clusters left). */
const frozenNext = (): LabelsNext => nextAnswer({ frozen: true, done: 56, total: 56 });

type Posted = { cluster_id: string; done: number; total: number; next: string | null };
const posted = (over: Partial<Posted> = {}): Posted => ({
  cluster_id: A,
  done: 19,
  total: 60,
  next: B,
  ...over,
});
const undone = (
  over: Partial<{ undone_cluster_id: string; done: number; total: number }> = {},
) => ({
  undone_cluster_id: A,
  done: 17,
  total: 60,
  ...over,
});

// --- the server ------------------------------------------------------------------------------------------------

type Failure = { status: number; body: JsonBodyType };
type Reply = LabelsNext | Posted | ReturnType<typeof undone> | Failure | "network";

const isFailure = (reply: Reply): reply is Failure =>
  typeof reply === "object" && "status" in reply && "body" in reply;

function answer(reply: Reply, status = 200) {
  if (reply === "network") return HttpResponse.error();
  if (isFailure(reply)) return HttpResponse.json(reply.body, { status: reply.status });
  return HttpResponse.json(reply, { status });
}

/** `labels/next` answers each reply in turn, and the last one for ever. */
function serveNext(...replies: Reply[]) {
  let i = 0;
  server.use(
    http.get(NEXT, ({ request }) => {
      nextQueries.push(new URL(request.url).searchParams.get("labeler"));
      return answer(replies[Math.min(i++, replies.length - 1)] as Reply);
    }),
  );
}

/**
 * `labels/next`: the first reply at once, every later one only after `release()` (a slow re-read after a write,
 * held shut by the test instead of a timer, so what is on screen meanwhile can be looked at without a race).
 */
function serveNextHeldAfterFirst(first: Reply, later: Reply) {
  let reads = 0;
  let release: () => void = () => {};
  const opened = new Promise<void>((resolve) => {
    release = resolve;
  });
  server.use(
    http.get(NEXT, async ({ request }) => {
      nextQueries.push(new URL(request.url).searchParams.get("labeler"));
      const read = reads++;
      if (read > 0) await opened;
      return answer(read === 0 ? first : later);
    }),
  );
  return { release: () => release() };
}

function servePost(reply: Reply = posted(), ms = 0) {
  server.use(
    http.post(LABELS, async ({ request }) => {
      posts.push(await request.json());
      if (ms > 0) await delay(ms);
      return answer(reply, 201);
    }),
  );
}

function serveUndo(reply: Reply = undone(), ms = 0) {
  server.use(
    http.post(UNDO, async ({ request }) => {
      undos.push({ body: await request.json(), contentType: request.headers.get("content-type") });
      if (ms > 0) await delay(ms);
      return answer(reply);
    }),
  );
}

// --- the page ---------------------------------------------------------------------------------------------------

function renderPage(opts: { token?: string | null; client?: QueryClient } = {}) {
  const token = opts.token === undefined ? tokenOf(USER_ID) : opts.token;
  const auth: AuthState = {
    session:
      token === null
        ? null
        : {
            token,
            role: "admin",
            username: "khanh-admin",
            expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
          },
    ready: true,
    signedOut: false,
    login: async () => {},
    logout: async () => {},
  };
  const client = opts.client ?? new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={client}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={["/admin/labels"]}>
          <header>
            <span>AI Support SOC</span>
          </header>
          <main>
            <LabelsPage />
          </main>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
  return { client, ...view };
}

/** The labelling screen is up once its form is. */
const ready = () => screen.findByRole("region", { name: L.form.title });
const form = () => screen.getByRole("region", { name: L.form.title });
const saveButton = () => screen.getByRole("button", { name: L.form.save });
const undoButton = () => screen.queryByRole("button", { name: L.form.undo });
const choose = (choice: LabelChoice) =>
  userEvent.click(screen.getByRole("radio", { name: new RegExp(`^${L.form.choices[choice]}`) }));
/** The text of a labelled row (`dt`) of the alert's description list. */
const rowOf = (term: string) => screen.getByText(term, { selector: "dt" }).nextElementSibling;

/** The line above the two columns: category, severity, rule and level, cluster id. */
const headText = () => screen.getByRole("region", { name: L.cluster.label }).textContent ?? "";

/** Choose a label, and save. */
async function save(choice: LabelChoice = "benign") {
  await choose(choice);
  await userEvent.click(saveButton());
}

const axeOf = async (container: HTMLElement) =>
  // jsdom computes no layout or colour, so the contrast rule cannot run here.
  (await axe.run(container, { rules: { "color-contrast": { enabled: false } } })).violations.map(
    (v) => v.id,
  );

// ==================================================================================================================

describe("the labelling screen of an unfrozen set", () => {
  it("asks for the labeller the session's token names, and nothing else", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    expect(nextQueries).toEqual([USER_ID]);
    expect(log).toEqual([`GET ${NEXT}`]);
  });

  it("shows the title, the subtitle and the progress, done over total", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    expect(screen.getByRole("heading", { level: 1, name: S.admin.title.labels })).toBeVisible();
    expect(screen.getByText(L.subtitle)).toBeVisible();
    expect(screen.getByText(L.progress.label)).toBeVisible();
    expect(screen.getByText("18 / 60")).toBeVisible();
    const bar = screen.getByRole("progressbar", { name: L.progress.bar }) as HTMLProgressElement;
    expect([bar.value, bar.max]).toEqual([18, 60]);
  });

  it("shows the cluster's own fields: category, severity, rule and level, cluster id", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    const head = screen.getByRole("region", { name: L.cluster.label });
    expect(within(head).getByText("ssh_brute_force")).toBeInTheDocument();
    expect(within(head).getByText("medium")).toBeInTheDocument();
    expect(within(head).getByText("5710")).toBeInTheDocument();
    expect(within(head).getByText(L.cluster.level("5"))).toBeInTheDocument();
    expect(within(head).getByText(A)).toBeInTheDocument();
  });

  it("shows the representative alert: time, agent, user, source to destination, description", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    const panel = screen.getByRole("region", { name: L.cluster.alertTitle });
    expect(panel).toBeVisible();
    // 14:14:06 UTC is 21:14:06 in Ho Chi Minh.
    expect(rowOf(L.cluster.time)).toHaveTextContent("27/09/2026 21:14:06");
    expect(rowOf(L.cluster.agent)).toHaveTextContent("attt-m1-lab");
    expect(rowOf(L.cluster.user)).toHaveTextContent("admin");
    expect(rowOf(L.cluster.route)).toHaveTextContent("192.168.56.20 → 192.168.56.10");
    expect(rowOf(L.cluster.description)).toHaveTextContent(
      "sshd: Attempt to login using a non-existent user",
    );
  });

  it("shows the raw log whole in a log block, and says nothing of a cut when there was none", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    const log_ = screen.getByRole("region", { name: S.alert.rawLog });
    expect(log_.textContent).toBe(RAW_LOG);
    expect(screen.getByRole("heading", { level: 3, name: L.cluster.rawLog })).toBeInTheDocument();
    expect(screen.queryByText(L.cluster.rawLogCut)).not.toBeInTheDocument();
    expect(screen.queryByText(S.alert.rawLogTruncated)).not.toBeInTheDocument();
  });

  it("says that the raw log was cut at 32 KB when the server says so", async () => {
    serveNext(nextAnswer({ cluster: cluster({ raw_log_truncated_for_display: true }) }));
    renderPage();
    await ready();
    expect(L.cluster.rawLogCut).toContain("đã cắt ở 32 KB");
    expect(screen.getByText(L.cluster.rawLogCut)).toBeVisible();
  });

  it("shows the occurrences and the time span", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    expect(screen.getByText(L.cluster.seen(146, "27/09 21:14", "27/09 21:19"))).toBeVisible();
  });

  it("shows the correlation rows of the two hours around it", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    const table = screen.getByRole("table", { name: L.correlation.table });
    const headers = within(table)
      .getAllByRole("columnheader")
      .map((th) => th.textContent);
    expect(headers).toEqual([
      L.correlation.colRule,
      L.correlation.colCategory,
      L.correlation.colClusters,
      L.correlation.colAlerts,
      L.correlation.colFirst,
      L.correlation.colLast,
    ]);
    const rows = within(table)
      .getAllByRole("row")
      .slice(1)
      .map((row) =>
        within(row)
          .getAllByRole("cell")
          .map((c) => c.textContent),
      );
    expect(rows).toEqual([
      ["5710", "ssh_brute_force", "1", "146", "27/09 21:14", "27/09 21:19"],
      ["5712", "ssh_brute_force", "2", "12", "27/09 21:15", "27/09 21:18"],
    ]);
  });

  it("keeps each sample collapsed, with its one-line summary and its raw log inside", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    const samples = screen.getByRole("region", { name: L.correlation.title });
    const details = samples.querySelectorAll("details");
    expect(details).toHaveLength(1);
    const sample = details[0] as HTMLDetailsElement;
    expect(sample.open).toBe(false);
    expect(sample.querySelector("summary")).toHaveTextContent(
      `${L.correlation.sample("5715", "suspicious_login", "low", 1, "27/09 21:20")} — sshd: authentication success`,
    );
    expect(sample.querySelector("pre")?.textContent).toBe(SAMPLE_LOG);
    await userEvent.click(sample.querySelector("summary") as HTMLElement);
    expect(sample.open).toBe(true);
  });

  it("says there is no correlation when there is none, and has no sample", async () => {
    serveNext(nextAnswer({ cluster: cluster({ correlation: { rows: [], samples: [] } }) }));
    renderPage();
    await ready();
    expect(screen.getByText(L.correlation.empty)).toBeVisible();
    expect(screen.queryByRole("table", { name: L.correlation.table })).not.toBeInTheDocument();
    expect(document.querySelector("details")).toBeNull();
  });

  it("shows the playbook as text", async () => {
    serveNext(nextAnswer({ cluster: cluster({ playbook: "# <b>x</b>\n1. mở alert" }) }));
    renderPage();
    await ready();
    const panel = screen.getByRole("region", { name: L.cluster.playbook });
    expect(panel.querySelector("pre")?.textContent).toBe("# <b>x</b>\n1. mở alert");
    expect(panel.querySelector("b")).toBeNull();
  });

  it("shows a dash for a field that came as null, never the word null", async () => {
    serveNext(
      nextAnswer({
        cluster: cluster({
          rule_id: null,
          rule_level: null,
          severity: null,
          description: null,
          agent_name: null,
          alert_time: null,
          alert_user: null,
          srcip: null,
          dstip: null,
          category: null,
          correlation: {
            rows: [],
            samples: [
              {
                alert_id: "x",
                rule_id: null,
                category: null,
                severity: null,
                occurrence_count: 2,
                alert_time: null,
                description: null,
                raw_log: null,
              },
            ],
          },
        }),
      }),
    );
    renderPage();
    await ready();
    expect(rowOf(L.cluster.time)).toHaveTextContent(S.common.missing);
    expect(rowOf(L.cluster.route)).toHaveTextContent(`${S.common.missing} → ${S.common.missing}`);
    const text = document.body.textContent ?? "";
    expect(text).not.toMatch(/\bnull\b|undefined|NaN/);
  });

  it("is free of axe violations", async () => {
    serveNext(nextAnswer());
    const { container } = renderPage();
    await ready();
    expect(await axeOf(container)).toEqual([]);
  });
});

describe("the form", () => {
  it("offers the labels of LABEL_CHOICES, in order, with none chosen", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    expect(Object.keys(L.form.choices)).toEqual([...LABEL_CHOICES]);
    const group = within(form()).getByRole("group", { name: L.form.label });
    const radios = within(group).getAllByRole("radio");
    expect(radios.map((r) => (r as HTMLInputElement).value)).toEqual([...LABEL_CHOICES]);
    expect(radios.map((r) => (r as HTMLInputElement).checked)).toEqual([false, false, false]);
    expect(radios.map((r) => r.closest("label")?.textContent)).toEqual([
      "Báo động giảfalse_positive",
      "Thật nhưng vô hạibenign",
      "Cần chuyển Tier 2escalate",
    ]);
  });

  it("offers the confidences of LABEL_CONFIDENCES, with 2 chosen", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    expect(Object.keys(L.form.confidences).map(Number)).toEqual([...LABEL_CONFIDENCES]);
    const group = within(form()).getByRole("group", { name: L.form.confidence });
    const radios = within(group).getAllByRole("radio") as HTMLInputElement[];
    expect(radios.map((r) => [r.value, r.checked])).toEqual([
      ["1", false],
      ["2", true],
      ["3", false],
    ]);
    expect(within(group).getByRole("radio", { name: "1 thấp" })).toBeInTheDocument();
    expect(within(group).getByRole("radio", { name: "3 cao" })).toBeInTheDocument();
  });

  it("counts the note against its 200 characters", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    const note = within(form()).getByRole("textbox", { name: L.form.note });
    // No `maxlength`: it counts UTF-16 units (100 emoji would fill it, and the server counts 100 of them as 100).
    // The counter and the error at the field are the limit, and they count as the server does.
    expect(note).not.toHaveAttribute("maxlength");
    expect(within(form()).getByText("0 / 200")).toBeVisible();
    await userEvent.type(note, "Quét từ máy lab");
    expect(within(form()).getByText("15 / 200")).toBeVisible();
  });

  it("posts the labeller, the cluster, the label, the confidence and the trimmed note", async () => {
    serveNext(nextAnswer(), afterA());
    servePost();
    renderPage();
    await ready();
    await choose("benign");
    await userEvent.click(screen.getByRole("radio", { name: "3 cao" }));
    await userEvent.type(
      within(form()).getByRole("textbox", { name: L.form.note }),
      "  Quét từ máy lab ",
    );
    await userEvent.click(saveButton());
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts).toEqual([
      {
        labeler: USER_ID,
        cluster_id: A,
        label: "benign",
        confidence: 3,
        note: "Quét từ máy lab",
      },
    ]);
  });

  it("leaves the note out of the body when it is empty, and sends the default confidence 2", async () => {
    serveNext(nextAnswer(), afterA());
    servePost();
    renderPage();
    await ready();
    await save("escalate");
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts).toEqual([{ labeler: USER_ID, cluster_id: A, label: "escalate", confidence: 2 }]);
  });

  it("saves from the note field with Enter", async () => {
    serveNext(nextAnswer(), afterA());
    servePost();
    renderPage();
    await ready();
    await choose("false_positive");
    await userEvent.type(within(form()).getByRole("textbox", { name: L.form.note }), "ok{Enter}");
    await waitFor(() => expect(posts).toHaveLength(1));
  });

  it("refuses to post with no label chosen, says so at the labels, and posts once one is chosen", async () => {
    serveNext(nextAnswer(), afterA());
    servePost();
    renderPage();
    await ready();
    await userEvent.click(saveButton());
    const alert = within(form()).getByRole("alert");
    expect(alert).toHaveTextContent(L.form.noLabel);
    expect(within(form()).getByRole("group", { name: L.form.label })).toHaveAccessibleDescription(
      L.form.noLabel,
    );
    expect(posts).toEqual([]);
    expect(log).toEqual([`GET ${NEXT}`]);
    await choose("benign");
    expect(within(form()).queryByRole("alert")).not.toBeInTheDocument();
    await userEvent.click(saveButton());
    await waitFor(() => expect(posts).toHaveLength(1));
  });

  it("refuses a note over 200 characters, at the note, and accepts exactly 200", async () => {
    serveNext(nextAnswer(), afterA());
    servePost();
    renderPage();
    await ready();
    await choose("benign");
    const note = within(form()).getByRole("textbox", { name: L.form.note });
    // Nothing stops the typing or the paste: the counter says it, and the save is refused at the field.
    fireEvent.change(note, { target: { value: "x".repeat(201) } });
    expect(within(form()).getByText("201 / 200")).toBeVisible();
    await userEvent.click(saveButton());
    expect(within(form()).getByRole("alert")).toHaveTextContent(S.admin.bounds.tooLong(200));
    expect(note).toHaveAccessibleDescription(new RegExp(S.admin.bounds.tooLong(200)));
    expect(posts).toEqual([]);
    fireEvent.change(note, { target: { value: "x".repeat(200) } });
    await userEvent.click(saveButton());
    await waitFor(() => expect(posts).toHaveLength(1));
    expect((posts[0] as { note: string }).note).toHaveLength(200);
  });

  it("counts a character as the server does, not as two when it is outside the first plane", async () => {
    serveNext(nextAnswer(), afterA());
    servePost();
    renderPage();
    await ready();
    await choose("benign");
    const note = within(form()).getByRole("textbox", { name: L.form.note });
    fireEvent.change(note, { target: { value: "😀".repeat(200) } });
    expect(within(form()).getByText("200 / 200")).toBeVisible();
    await userEvent.click(saveButton());
    await waitFor(() => expect(posts).toHaveLength(1));
  });

  it("refuses a note of 201 characters outside the first plane before any post, and takes 200 of them", async () => {
    serveNext(nextAnswer(), afterA());
    servePost();
    renderPage();
    await ready();
    await choose("benign");
    const note = within(form()).getByRole("textbox", { name: L.form.note });
    fireEvent.change(note, { target: { value: "😀".repeat(201) } });
    expect(within(form()).getByText("201 / 200")).toBeVisible();
    await userEvent.click(saveButton());
    expect(within(form()).getByRole("alert")).toHaveTextContent(S.admin.bounds.tooLong(200));
    expect(posts).toEqual([]);
    fireEvent.change(note, { target: { value: "😀".repeat(200) } });
    await userEvent.click(saveButton());
    await waitFor(() => expect(posts).toHaveLength(1));
    expect([...(posts[0] as { note: string }).note]).toHaveLength(200);
  });

  it("lets a paste of more than 200 characters in, to be counted and refused at the field", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    await choose("benign");
    const note = within(form()).getByRole("textbox", { name: L.form.note });
    await userEvent.click(note);
    await userEvent.paste("x".repeat(201));
    expect(within(form()).getByText("201 / 200")).toBeVisible();
    await userEvent.click(saveButton());
    expect(within(form()).getByRole("alert")).toHaveTextContent(S.admin.bounds.tooLong(200));
    expect(posts).toEqual([]);
  });

  it("says what was saved and who is next, reads the next cluster, and clears the form", async () => {
    serveNext(nextAnswer(), afterA());
    servePost(posted({ cluster_id: A, done: 19, total: 60, next: B }));
    renderPage();
    await ready();
    await choose("benign");
    await userEvent.type(within(form()).getByRole("textbox", { name: L.form.note }), "ghi chú");
    await userEvent.click(saveButton());
    expect(await screen.findByRole("status")).toHaveTextContent(L.notice.saved(A, 19, 60, B));
    // The next cluster is the one `labels/next` answers after the write, with a form of its own.
    await waitFor(() => expect(headText()).toContain("port_scan"));
    expect(log).toEqual([`GET ${NEXT}`, `POST ${LABELS}`, `GET ${NEXT}`]);
    const radios = within(form()).getAllByRole("radio") as HTMLInputElement[];
    expect(radios.filter((r) => r.checked).map((r) => r.value)).toEqual(["2"]);
    expect(within(form()).getByRole("textbox", { name: L.form.note })).toHaveValue("");
    expect(screen.getByText("19 / 60")).toBeVisible();
  });

  it("moves the focus to the new cluster, which the button it was on no longer exists to hold", async () => {
    serveNext(nextAnswer(), afterA());
    servePost();
    renderPage();
    await ready();
    await save("benign");
    await waitFor(() => expect(headText()).toContain("port_scan"));
    await waitFor(() =>
      expect(screen.getByRole("region", { name: L.cluster.label })).toHaveFocus(),
    );
  });

  it("moves the focus to the finished card after the last label, not to the page", async () => {
    serveNext(nextAnswer({ done: 59 }), finished());
    servePost(posted({ done: 60, next: null }));
    renderPage();
    await ready();
    await save("benign");
    const heading = await screen.findByRole("heading", { level: 2, name: L.finished.title(60) });
    await waitFor(() => expect(heading).toHaveFocus());
    expect(heading).toHaveAttribute("tabindex", "-1");
  });

  // The write answers, the notice is set, and the page renders once with the OLD screen still up: the re-read of
  // `labels/next` is on its way. The focus is asked for at the write but given only when the screen has changed
  // (`screenKey !== screenAtWrite`); an instant re-read (`serveNext`) never shows that render, so these two hold the
  // second read shut until the test has looked at it. Without the condition the request is spent on the stale
  // cluster's head at once, the next screen then replaces it, and the focus falls to <body> (P11-T16 review, round 2).
  describe("when the re-read after a write is slow", () => {
    it("moves the focus to the finished card after the last label, not to the stale cluster on the way", async () => {
      const second = serveNextHeldAfterFirst(nextAnswer({ done: 59 }), finished());
      servePost(posted({ done: 60, next: null }));
      renderPage();
      await ready();
      await save("benign");
      // The notice is up and the old cluster is still the screen: it must not take the focus.
      await screen.findByRole("status");
      expect(screen.getByRole("region", { name: L.cluster.label })).not.toHaveFocus();
      second.release();
      const heading = await screen.findByRole("heading", { level: 2, name: L.finished.title(60) });
      await waitFor(() => expect(heading).toHaveFocus());
    });

    it("moves the focus to the new cluster's head, not to the stale one on the way", async () => {
      const second = serveNextHeldAfterFirst(nextAnswer(), afterA());
      servePost();
      renderPage();
      await ready();
      await save("benign");
      await screen.findByRole("status");
      expect(headText()).toContain("ssh_brute_force");
      expect(screen.getByRole("region", { name: L.cluster.label })).not.toHaveFocus();
      second.release();
      await waitFor(() => expect(headText()).toContain("port_scan"));
      await waitFor(() =>
        expect(screen.getByRole("region", { name: L.cluster.label })).toHaveFocus(),
      );
    });

    it("gives the finished card the focus after a 150 ms re-read too (the timer the review used)", async () => {
      server.use(
        http.get(NEXT, async () => {
          nextQueries.push(USER_ID);
          if (nextQueries.length > 1) await delay(150);
          return answer(nextQueries.length === 1 ? nextAnswer({ done: 59 }) : finished());
        }),
      );
      servePost(posted({ done: 60, next: null }));
      renderPage();
      await ready();
      await save("benign");
      const heading = await screen.findByRole("heading", { level: 2, name: L.finished.title(60) });
      await waitFor(() => expect(heading).toHaveFocus());
    });
  });

  it("moves the focus back to the cluster after an undo from the finished card", async () => {
    serveNext(finished(), nextAnswer({ cluster_id: A, done: 59, total: 60 }));
    serveUndo(undone({ undone_cluster_id: A, done: 59, total: 60 }));
    renderPage();
    await screen.findByText(L.finished.body);
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    await ready();
    await waitFor(() =>
      expect(screen.getByRole("region", { name: L.cluster.label })).toHaveFocus(),
    );
  });

  it("does not move the focus when the page is opened, or when a save is refused", async () => {
    serveNext(nextAnswer());
    servePost({ status: 500, body: { detail: "boom" } });
    renderPage();
    await ready();
    expect(screen.getByRole("region", { name: L.cluster.label })).not.toHaveFocus();
    await save("benign");
    await within(form()).findByRole("alert");
    expect(screen.getByRole("region", { name: L.cluster.label })).not.toHaveFocus();
  });

  it("closes the confirmation note with its button", async () => {
    serveNext(nextAnswer(), afterA());
    servePost();
    renderPage();
    await ready();
    await save("benign");
    const toast = await screen.findByRole("status");
    await userEvent.click(within(toast).getByRole("button", { name: S.common.close }));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("disables both buttons while the label is being saved, and says so", async () => {
    serveNext(nextAnswer(), afterA());
    servePost(posted(), 150);
    renderPage();
    await ready();
    await save("benign");
    const busy = await screen.findByRole("button", { name: S.admin.common.saving });
    expect(busy).toBeDisabled();
    expect(busy).toHaveAttribute("aria-busy", "true");
    expect(screen.getByRole("button", { name: L.form.undo })).toBeDisabled();
    await waitFor(() => expect(headText()).toContain("port_scan"));
    expect(saveButton()).toBeEnabled();
  });

  it("marks the reads the save made stale through invalidateAfter: the labels and the audit", async () => {
    serveNext(nextAnswer(), afterA());
    servePost();
    const { client } = renderPage();
    client.setQueryData(adminKeys.audit({ range: "7d" }), { events: [] });
    await ready();
    await save("benign");
    await waitFor(() => expect(posts).toHaveLength(1));
    await waitFor(() =>
      expect(client.getQueryState(adminKeys.audit({ range: "7d" }))?.isInvalidated).toBe(true),
    );
    await waitFor(() => expect(log.filter((l) => l === `GET ${NEXT}`)).toHaveLength(2));
  });
});

/**
 * Two `fireEvent.click` with no await between them, in one `act`: React renders nothing between the two, as
 * it renders nothing between two clicks of one tick in a browser, so what the second click meets is the page
 * as the first one left it.
 */
function clickTwice(button: HTMLElement) {
  act(() => {
    fireEvent.click(button);
    fireEvent.click(button);
  });
}

describe("a second click in the same tick", () => {
  // TanStack Query tells React a mutation is pending only after a timer, so a guard on `isPending` lets two
  // clicks of one tick through. These two clicks have no await between them.
  it("posts the label once", async () => {
    serveNext(nextAnswer(), afterA());
    servePost(posted(), 40);
    renderPage();
    await ready();
    await choose("benign");
    const button = saveButton();
    clickTwice(button);
    await waitFor(() => expect(posts).toHaveLength(1));
    await waitFor(() => expect(headText()).toContain("port_scan"));
    await delay(60);
    expect(posts).toHaveLength(1);
    expect(log.filter((l) => l === `POST ${LABELS}`)).toHaveLength(1);
  });

  it("undoes once", async () => {
    serveNext(nextAnswer(), nextAnswer({ done: 17 }));
    serveUndo(undone(), 40);
    renderPage();
    await ready();
    const button = screen.getByRole("button", { name: L.form.undo });
    clickTwice(button);
    await waitFor(() => expect(undos).toHaveLength(1));
    await screen.findByText(L.notice.undone(A, 17, 60));
    await delay(60);
    expect(undos).toHaveLength(1);
  });

  // The undo of the finished card is the one used most, and each undo deletes the labeller's most recent label:
  // a double click that sent two would take two labels back and name only one of them.
  it("undoes once from the finished card", async () => {
    serveNext(finished(), nextAnswer({ cluster_id: A, done: 59, total: 60 }));
    serveUndo(undone({ undone_cluster_id: A, done: 59, total: 60 }), 40);
    renderPage();
    await screen.findByText(L.finished.body);
    clickTwice(screen.getByRole("button", { name: L.form.undo }));
    await waitFor(() => expect(undos).toHaveLength(1));
    await screen.findByText(L.notice.undone(A, 59, 60));
    await delay(60);
    expect(undos).toHaveLength(1);
    expect(log.filter((l) => l === `POST ${UNDO}`)).toHaveLength(1);
  });

  it("does not undo while a label is being saved, nor save while an undo is", async () => {
    serveNext(nextAnswer(), afterA());
    servePost(posted(), 40);
    serveUndo();
    renderPage();
    await ready();
    await choose("benign");
    const undoNow = screen.getByRole("button", { name: L.form.undo });
    const saveNow = saveButton();
    act(() => {
      fireEvent.click(saveNow);
      fireEvent.click(undoNow);
    });
    await waitFor(() => expect(posts).toHaveLength(1));
    await waitFor(() => expect(headText()).toContain("port_scan"));
    expect(undos).toEqual([]);
  });

  it("lets the next save through after the first one failed", async () => {
    serveNext(nextAnswer(), afterA());
    servePost({ status: 500, body: { detail: "boom" } });
    renderPage();
    await ready();
    await save("benign");
    await screen.findByText(L.notice.saveServer(500));
    await userEvent.click(saveButton());
    await waitFor(() => expect(posts).toHaveLength(2));
  });
});

// What each answer of `POST /api/admin/labels` says, and where (the routes' own texts: labels.py).
describe("a save the server refuses or cannot make", () => {
  const forcedFrozen = (): LabelsNext => frozenNext();

  it.each<[string, Failure, string, boolean]>([
    [
      "409 already labelled (the labeller did it in another tab)",
      { status: 409, body: { detail: "already labelled by this labeler" } },
      // Said beside the NEXT cluster's form, so it names the cluster it was about.
      L.notice.aboutCluster(A, S.admin.reason.already_labelled),
      true,
    ],
    [
      "404 not a candidate",
      { status: 404, body: { detail: "cluster is not a gold candidate" } },
      L.notice.aboutCluster(A, S.admin.reason.unknown_cluster),
      true,
    ],
    [
      "403 not the signed-in labeller",
      { status: 403, body: { detail: "labeler must be the current user" } },
      S.admin.reason.labeler_mismatch,
      false,
    ],
    [
      "403 no longer an admin",
      { status: 403, body: { detail: "forbidden" } },
      S.admin.reason.forbidden,
      false,
    ],
    [
      "422 from the body's own validation (a list)",
      {
        status: 422,
        body: { detail: [{ type: "literal_error", loc: ["body", "label"], msg: "bad" }] },
      },
      L.notice.invalid,
      false,
    ],
    [
      "422 with the logic's own text",
      { status: 422, body: { detail: "note: at most 200 characters" } },
      L.notice.invalid,
      false,
    ],
    [
      "503",
      { status: 503, body: { detail: "auth disabled: JWT_SECRET unset" } },
      L.notice.saveServer(503),
      false,
    ],
    [
      "500",
      { status: 500, body: { detail: "Internal Server Error" } },
      L.notice.saveServer(500),
      false,
    ],
  ])("%s: says %s at the form", async (_name, failure, text, rereads) => {
    serveNext(nextAnswer(), afterA());
    servePost(failure);
    renderPage();
    await ready();
    await save("escalate");
    const alert = await within(form()).findByRole("alert");
    expect(alert).toHaveTextContent(text);
    if (rereads) {
      // The screen was stale, so it is read again and moves on; the refusal stays beside the new cluster.
      await waitFor(() => expect(headText()).toContain("port_scan"));
      expect(log).toEqual([`GET ${NEXT}`, `POST ${LABELS}`, `GET ${NEXT}`]);
      expect(within(form()).getByRole("alert")).toHaveTextContent(text);
    } else {
      // Nothing changed on the server: the cluster, the label and the note stay as they were.
      expect(log).toEqual([`GET ${NEXT}`, `POST ${LABELS}`]);
      expect(headText()).toContain("ssh_brute_force");
      expect(
        (screen.getByRole("radio", { name: /^Cần chuyển Tier 2/ }) as HTMLInputElement).checked,
      ).toBe(true);
    }
    // Never the server's English text.
    expect(document.body.textContent).not.toMatch(
      /already labelled|not a gold candidate|labeler must|Internal Server Error|JWT_SECRET/,
    );
  });

  // After a stale refusal the page reads again and moves on to the next cluster: the form that had the focus is
  // replaced by another, so the focus is asked for on the new cluster's head, as after a save. The refusal is a
  // `role="alert"` beside the new form, so a screen reader hears it either way (P11-T16 review round 2, note 4).
  describe("after a stale refusal, which replaces the screen", () => {
    const stale: [string, Failure][] = [
      [
        "409 already labelled",
        { status: 409, body: { detail: "already labelled by this labeler" } },
      ],
      ["404 not a candidate", { status: 404, body: { detail: "cluster is not a gold candidate" } }],
    ];

    it.each(stale)("%s: moves the focus to the next cluster's head", async (_name, failure) => {
      serveNext(nextAnswer(), afterA());
      servePost(failure);
      renderPage();
      await ready();
      await save("escalate");
      await waitFor(() => expect(headText()).toContain("port_scan"));
      await waitFor(() =>
        expect(screen.getByRole("region", { name: L.cluster.label })).toHaveFocus(),
      );
      expect(within(form()).getByRole("alert")).toBeInTheDocument();
    });

    it.each(stale)(
      "%s: leaves the stale cluster's head alone while the re-read is on its way",
      async (_name, failure) => {
        const second = serveNextHeldAfterFirst(nextAnswer(), afterA());
        servePost(failure);
        renderPage();
        await ready();
        await save("escalate");
        await within(form()).findByRole("alert");
        expect(headText()).toContain("ssh_brute_force");
        expect(screen.getByRole("region", { name: L.cluster.label })).not.toHaveFocus();
        second.release();
        await waitFor(() => expect(headText()).toContain("port_scan"));
        await waitFor(() =>
          expect(screen.getByRole("region", { name: L.cluster.label })).toHaveFocus(),
        );
      },
    );

    it.each<[string, Failure]>([
      [
        "403 not the signed-in labeller",
        { status: 403, body: { detail: "labeler must be the current user" } },
      ],
      ["422", { status: 422, body: { detail: "note: at most 200 characters" } }],
      ["503", { status: 503, body: { detail: "auth disabled: JWT_SECRET unset" } }],
    ])("%s: asks for no focus, the screen is as it was", async (_name, failure) => {
      serveNext(nextAnswer(), afterA());
      servePost(failure);
      renderPage();
      await ready();
      await save("escalate");
      await within(form()).findByRole("alert");
      expect(headText()).toContain("ssh_brute_force");
      expect(screen.getByRole("region", { name: L.cluster.label })).not.toHaveFocus();
    });
  });

  it("409 frozen: says so in the neutral words, and the page becomes the frozen state", async () => {
    serveNext(nextAnswer(), forcedFrozen());
    servePost({ status: 409, body: { detail: "the gold set is frozen" } });
    renderPage();
    await ready();
    await save("benign");
    expect(await screen.findByText(L.frozen.badge)).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(S.admin.reason.frozen);
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(undoButton()).not.toBeInTheDocument();
    expect(log).toEqual([`GET ${NEXT}`, `POST ${LABELS}`, `GET ${NEXT}`]);
  });

  it("a network failure says the label was not saved, and keeps the form for another try", async () => {
    serveNext(nextAnswer(), afterA());
    servePost("network");
    renderPage();
    await ready();
    await choose("benign");
    await userEvent.type(within(form()).getByRole("textbox", { name: L.form.note }), "giữ lại");
    await userEvent.click(saveButton());
    expect(await within(form()).findByRole("alert")).toHaveTextContent(L.notice.saveOffline);
    expect(within(form()).getByRole("textbox", { name: L.form.note })).toHaveValue("giữ lại");
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("clears the refusal when the next save is made", async () => {
    serveNext(nextAnswer(), afterA());
    servePost({ status: 500, body: { detail: "boom" } });
    renderPage();
    await ready();
    await save("benign");
    await within(form()).findByRole("alert");
    servePost(posted());
    await userEvent.click(saveButton());
    await waitFor(() => expect(headText()).toContain("port_scan"));
    expect(screen.queryByText(L.notice.saveServer(500))).not.toBeInTheDocument();
  });

  it("is free of axe violations with a refusal on screen", async () => {
    serveNext(nextAnswer());
    servePost({ status: 500, body: { detail: "boom" } });
    const { container } = renderPage();
    await ready();
    await save("benign");
    await within(form()).findByRole("alert");
    expect(await axeOf(container)).toEqual([]);
  });
});

describe("undo", () => {
  it("is offered under the form when the labeller has labelled something", async () => {
    serveNext(nextAnswer({ done: 1 }));
    renderPage();
    await ready();
    expect(within(form()).getByRole("button", { name: L.form.undo })).toBeVisible();
    expect(within(form()).getByText(L.form.hint)).toBeVisible();
  });

  it("is not offered before the first label", async () => {
    serveNext(nextAnswer({ done: 0 }));
    renderPage();
    await ready();
    expect(undoButton()).not.toBeInTheDocument();
  });

  it("posts an empty JSON object, names the undone cluster and reads the next one again", async () => {
    serveNext(nextAnswer(), nextAnswer({ done: 17 }));
    serveUndo(undone({ undone_cluster_id: A, done: 17, total: 60 }));
    renderPage();
    await ready();
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    expect(await screen.findByRole("status")).toHaveTextContent(L.notice.undone(A, 17, 60));
    expect(undos).toEqual([{ body: {}, contentType: "application/json" }]);
    await waitFor(() => expect(screen.getByText("17 / 60")).toBeVisible());
    expect(log).toEqual([`GET ${NEXT}`, `POST ${UNDO}`, `GET ${NEXT}`]);
  });

  it("marks the reads the undo made stale through invalidateAfter", async () => {
    serveNext(nextAnswer(), nextAnswer({ done: 17 }));
    serveUndo();
    const { client } = renderPage();
    client.setQueryData(adminKeys.audit({ range: "24h" }), { events: [] });
    await ready();
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    await waitFor(() =>
      expect(client.getQueryState(adminKeys.audit({ range: "24h" }))?.isInvalidated).toBe(true),
    );
  });

  it("disables the buttons, and says it is working, while the undo is made", async () => {
    serveNext(nextAnswer(), nextAnswer({ done: 17 }));
    serveUndo(undone(), 150);
    renderPage();
    await ready();
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    const busy = await screen.findByRole("button", { name: L.form.undoing });
    expect(busy).toBeDisabled();
    expect(saveButton()).toBeDisabled();
    await screen.findByRole("status");
  });

  it.each<[string, Failure | "network", string, boolean]>([
    [
      "409 frozen",
      { status: 409, body: { detail: { reason: "frozen" } } },
      S.admin.reason.frozen,
      true,
    ],
    [
      "404 nothing to undo",
      { status: 404, body: { detail: { reason: "nothing_to_undo" } } },
      S.admin.reason.nothing_to_undo,
      true,
    ],
    [
      "403 no longer an admin",
      { status: 403, body: { detail: "forbidden" } },
      S.admin.reason.forbidden,
      false,
    ],
    [
      "503",
      { status: 503, body: { detail: "auth disabled: JWT_SECRET unset" } },
      L.notice.undoServer(503),
      false,
    ],
    [
      "422 (no JSON body)",
      {
        status: 422,
        body: { detail: [{ type: "missing", loc: ["body"], msg: "Field required" }] },
      },
      L.notice.undoServer(422),
      false,
    ],
    ["a network failure", "network", L.notice.undoOffline, false],
  ])("%s: says %s at the form", async (_name, failure, text, rereads) => {
    serveNext(nextAnswer(), nextAnswer());
    serveUndo(failure);
    renderPage();
    await ready();
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    expect(await within(form()).findByRole("alert")).toHaveTextContent(text);
    if (rereads) {
      await waitFor(() => expect(log.filter((l) => l === `GET ${NEXT}`)).toHaveLength(2));
    } else {
      expect(log).toEqual([`GET ${NEXT}`, `POST ${UNDO}`]);
    }
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/JWT_SECRET|Field required/);
  });

  it("409 frozen turns the page into the frozen state and keeps the refusal on it", async () => {
    serveNext(nextAnswer(), frozenNext());
    serveUndo({ status: 409, body: { detail: { reason: "frozen" } } });
    renderPage();
    await ready();
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    expect(await screen.findByText(L.frozen.badge)).toBeVisible();
    expect(screen.getByRole("alert")).toHaveTextContent(S.admin.reason.frozen);
    expect(undoButton()).not.toBeInTheDocument();
  });

  it("lets the undo be asked again after it failed", async () => {
    serveNext(nextAnswer());
    serveUndo({ status: 503, body: { detail: "down" } });
    renderPage();
    await ready();
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    await within(form()).findByRole("alert");
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    await waitFor(() => expect(undos).toHaveLength(2));
  });
});

describe("the frozen state (the current one: eval/gold_v1.sha256 exists)", () => {
  it("shows the frozen state with the progress, and no labelling and no undo", async () => {
    serveNext(frozenNext());
    renderPage();
    expect(await screen.findByRole("heading", { level: 2, name: L.frozen.title })).toBeVisible();
    expect(screen.getByText(L.frozen.badge)).toBeVisible();
    expect(screen.getByText(L.frozen.body(56))).toBeVisible();
    expect(screen.getByText("56 / 56")).toBeVisible();
    const bar = screen.getByRole("progressbar", { name: L.progress.bar }) as HTMLProgressElement;
    expect([bar.value, bar.max]).toEqual([56, 56]);
    expect(screen.getByRole("heading", { level: 1, name: S.admin.title.labels })).toBeVisible();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: L.form.save })).not.toBeInTheDocument();
    expect(undoButton()).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: L.form.title })).not.toBeInTheDocument();
  });

  it("ignores the cluster the server still sends: not one field of it reaches the page", async () => {
    const MARK = "FROZEN-CLUSTER-MARK";
    serveNext(
      nextAnswer({
        frozen: true,
        done: 56,
        total: 56,
        cluster_id: `id-${MARK}`,
        cluster: cluster({
          description: `desc ${MARK}`,
          raw_log: `raw ${MARK}`,
          playbook: `playbook ${MARK}`,
          category: `cat-${MARK}`,
          gold_cluster_id: `gold-${MARK}`,
          agent_name: `agent-${MARK}`,
        }),
      }),
    );
    const { container } = renderPage();
    await screen.findByText(L.frozen.badge);
    expect(container.innerHTML).not.toContain(MARK);
    expect(screen.queryByRole("region", { name: S.alert.rawLog })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: L.cluster.alertTitle })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: L.cluster.playbook })).not.toBeInTheDocument();
  });

  it("is frozen even when the labeller has not finished: done under total", async () => {
    serveNext(nextAnswer({ frozen: true, done: 3, total: 56 }));
    renderPage();
    await screen.findByText(L.frozen.badge);
    expect(screen.getByText("3 / 56")).toBeVisible();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
  });

  it("is the frozen state, not the empty one, when the candidates are missing too", async () => {
    serveNext(
      nextAnswer({
        frozen: true,
        candidates_present: false,
        cluster_id: null,
        cluster: null,
        done: 0,
        total: 0,
      }),
    );
    renderPage();
    await screen.findByText(L.frozen.badge);
    expect(screen.queryByText(L.noCandidates.title)).not.toBeInTheDocument();
  });

  it("is free of axe violations", async () => {
    serveNext(frozenNext());
    const { container } = renderPage();
    await screen.findByText(L.frozen.badge);
    expect(await axeOf(container)).toEqual([]);
  });
});

describe("finished", () => {
  it("says the labeller has labelled every cluster, and offers the undo", async () => {
    serveNext(finished());
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 2, name: L.finished.title(60) }),
    ).toBeVisible();
    expect(screen.getByText(L.finished.body)).toBeVisible();
    expect(screen.getByText("60 / 60")).toBeVisible();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: L.form.undo })).toBeEnabled();
  });

  it("undoes the last label from there, and reads the cluster that comes back", async () => {
    serveNext(finished(), nextAnswer({ cluster_id: A, done: 59, total: 60 }));
    serveUndo(undone({ undone_cluster_id: A, done: 59, total: 60 }));
    renderPage();
    await screen.findByText(L.finished.body);
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    expect(await screen.findByRole("status")).toHaveTextContent(L.notice.undone(A, 59, 60));
    await ready();
    expect(screen.getByText("59 / 60")).toBeVisible();
  });

  it("shows an undo refusal on the finished card", async () => {
    serveNext(finished());
    serveUndo({ status: 404, body: { detail: { reason: "nothing_to_undo" } } });
    renderPage();
    await screen.findByText(L.finished.body);
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    expect(await screen.findByRole("alert")).toHaveTextContent(S.admin.reason.nothing_to_undo);
  });

  it("says finished when the save was the last one, with the note that there is no one next", async () => {
    serveNext(nextAnswer({ done: 59 }), finished());
    servePost(posted({ done: 60, next: null }));
    renderPage();
    await ready();
    await save("benign");
    await screen.findByText(L.finished.body);
    expect(screen.getByRole("status")).toHaveTextContent(L.notice.saved(A, 60, 60, null));
    expect(L.notice.saved(A, 60, 60, null)).not.toContain("Cụm tiếp");
  });

  it("is free of axe violations", async () => {
    serveNext(finished());
    const { container } = renderPage();
    await screen.findByText(L.finished.body);
    expect(await axeOf(container)).toEqual([]);
  });
});

describe("no candidates", () => {
  it("says there is no candidate file, in place of the form, with no undo", async () => {
    serveNext(
      nextAnswer({ candidates_present: false, cluster_id: null, cluster: null, done: 0, total: 0 }),
    );
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 2, name: L.noCandidates.title }),
    ).toBeVisible();
    expect(screen.getByText(L.noCandidates.file)).toBeVisible();
    expect(screen.getByText(L.noCandidates.before, { exact: false })).toBeVisible();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(undoButton()).not.toBeInTheDocument();
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
  });

  it("says the same for a candidate file that is there and empty", async () => {
    serveNext(nextAnswer({ cluster_id: null, cluster: null, done: 0, total: 0 }));
    renderPage();
    await screen.findByRole("heading", { level: 2, name: L.noCandidates.title });
    expect(screen.queryByText(L.finished.body)).not.toBeInTheDocument();
  });

  it("is free of axe violations", async () => {
    serveNext(
      nextAnswer({ candidates_present: false, cluster_id: null, cluster: null, done: 0, total: 0 }),
    );
    const { container } = renderPage();
    await screen.findByText(L.noCandidates.title);
    expect(await axeOf(container)).toEqual([]);
  });
});

// The labeller is reading a cluster: the page must not read `labels/next` again behind their back (a cluster is
// read on entry and after the page's own writes). A read on focus and on reconnect is TanStack Query's default.
describe("a cluster is read on entry and after a write, never because the window came back", () => {
  afterEach(() => {
    focusManager.setFocused(undefined);
    onlineManager.setOnline(true);
  });

  it("does not read again when the window gets the focus back", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    act(() => {
      focusManager.setFocused(false);
      focusManager.setFocused(true);
    });
    await delay(60);
    expect(log).toEqual([`GET ${NEXT}`]);
  });

  it("does not read again when the connection comes back", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    act(() => {
      onlineManager.setOnline(false);
      onlineManager.setOnline(true);
    });
    await delay(60);
    expect(log).toEqual([`GET ${NEXT}`]);
  });
});

// Each labeller draws a cluster order of their own, and a cached answer is one labeller's: a second labeller on the
// same cache (a logout and another login in one tab; the cache is cleared then, but the page does not rely on it)
// must not be shown the first one's cluster, not even for the moment before their own answer comes.
describe("the cache is the labeller's own", () => {
  const OTHER_ID = "9a8b7c6d-1111-4222-8333-444455556666";

  it("does not show a labeller the cluster another labeller read into the same cache", async () => {
    server.use(
      http.get(NEXT, async ({ request }) => {
        const labeler = new URL(request.url).searchParams.get("labeler");
        if (labeler === OTHER_ID) await delay(150);
        return HttpResponse.json(
          labeler === OTHER_ID
            ? nextAnswer({ cluster_id: B, cluster: clusterB() })
            : nextAnswer({ cluster_id: A, cluster: cluster() }),
        );
      }),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const first = renderPage({ client });
    await ready();
    expect(headText()).toContain("ssh_brute_force");
    first.unmount();

    renderPage({ client, token: tokenOf(OTHER_ID) });
    // Before the second labeller's own answer: the skeleton, not the first labeller's cluster.
    expect(screen.getByRole("status")).toHaveTextContent(S.common.loading);
    expect(screen.queryByRole("region", { name: L.cluster.label })).not.toBeInTheDocument();
    await ready();
    expect(headText()).toContain("port_scan");
    expect(headText()).not.toContain("ssh_brute_force");
  });

  it("keeps one entry per labeller, under the labels key the writes invalidate by prefix", async () => {
    serveNext(nextAnswer());
    const { client } = renderPage();
    await ready();
    const keys = client
      .getQueryCache()
      .findAll({ queryKey: adminKeys.labels })
      .map((query) => query.queryKey);
    expect(keys).toEqual([[...adminKeys.labels, USER_ID]]);
  });
});

describe("loading and failing to load", () => {
  it("shows the title and a skeleton while the first answer is on its way, and no form", async () => {
    server.use(
      http.get(NEXT, async () => {
        await delay(100);
        return HttpResponse.json(nextAnswer());
      }),
    );
    const { container } = renderPage();
    expect(screen.getByRole("heading", { level: 1, name: S.admin.title.labels })).toBeVisible();
    const status = screen.getByRole("status");
    expect(status).toHaveAttribute("aria-busy", "true");
    expect(status).toHaveTextContent(S.common.loading);
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(await axeOf(container)).toEqual([]);
    await ready();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it.each<[string, Failure | "network", string]>([
    ["a 500", { status: 500, body: { detail: "Internal Server Error" } }, L.loadErrorServer(500)],
    [
      "a 503",
      { status: 503, body: { detail: "auth disabled: JWT_SECRET unset" } },
      L.loadErrorServer(503),
    ],
    ["a lost connection", "network", L.loadErrorOffline],
  ])(
    "shows the page error and a retry for %s, and the page when the retry works",
    async (_name, failure, hint) => {
      serveNext(failure);
      renderPage();
      const alert = await screen.findByRole("alert");
      expect(within(alert).getByRole("heading", { name: S.admin.common.loadError })).toBeVisible();
      expect(screen.getByText(hint)).toBeVisible();
      expect(screen.queryByRole("radio")).not.toBeInTheDocument();
      expect(document.body.textContent).not.toMatch(/JWT_SECRET|Internal Server Error/);
      serveNext(nextAnswer());
      await userEvent.click(within(alert).getByRole("button", { name: S.common.retry }));
      await ready();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    },
  );

  it.each<[string, string, string]>([
    ["a stale actor", "forbidden", S.admin.reason.forbidden],
    [
      "a labeller that is not the caller",
      "labeler must be the current user",
      S.admin.reason.labeler_mismatch,
    ],
  ])(
    "says %s at 403 in its own words, with no retry that cannot work",
    async (_name, detail, text) => {
      serveNext({ status: 403, body: { detail } });
      renderPage();
      expect(await screen.findByText(text)).toBeVisible();
      expect(screen.getByRole("heading", { name: S.admin.common.loadError })).toBeVisible();
      expect(screen.queryByRole("button", { name: S.common.retry })).not.toBeInTheDocument();
    },
  );

  it("stops, and asks for nothing, when the session's token holds no user id", async () => {
    renderPage({ token: "opaque" });
    expect(await screen.findByText(L.sessionUnreadable)).toBeVisible();
    expect(screen.getByRole("heading", { name: S.admin.common.loadError })).toBeVisible();
    await delay(30);
    expect(log).toEqual([]);
  });

  it("stops, and asks for nothing, when there is no session", async () => {
    renderPage({ token: null });
    expect(await screen.findByText(L.sessionUnreadable)).toBeVisible();
    await delay(30);
    expect(log).toEqual([]);
  });

  it("does not leave the cluster that was just labelled on screen when the read after the save fails", async () => {
    serveNext(nextAnswer(), { status: 500, body: { detail: "boom" } });
    servePost();
    renderPage();
    await ready();
    await save("benign");
    await screen.findByText(L.loadErrorServer(500));
    // The cluster is labelled: a form for it would only be refused, so none is left to press.
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: L.form.save })).not.toBeInTheDocument();
    serveNext(afterA());
    await userEvent.click(screen.getByRole("button", { name: S.common.retry }));
    await waitFor(() => expect(headText()).toContain("port_scan"));
  });

  // The write went through; only the read after it failed. The page error must not read as if nothing was saved.
  it("still says the label was saved, first under the page error, when the read after the save fails", async () => {
    serveNext(nextAnswer(), { status: 500, body: { detail: "boom" } });
    servePost(posted({ cluster_id: A, done: 19, total: 60, next: B }));
    renderPage();
    await ready();
    await save("benign");
    const saved = await screen.findByText(L.notice.saved(A, 19, 60, B));
    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent(S.admin.common.loadError);
    // First line under the page error, then why it failed.
    expect(alert.parentElement?.children[1]).toBe(saved);
    expect(alert.parentElement?.children[2]).toHaveTextContent(L.loadErrorServer(500));
    // The retry reads the next cluster, and the note goes with the error.
    serveNext(afterA());
    await userEvent.click(screen.getByRole("button", { name: S.common.retry }));
    await waitFor(() => expect(headText()).toContain("port_scan"));
    expect(screen.queryByText(L.loadErrorServer(500))).not.toBeInTheDocument();
  });

  it("still says the label was taken back, under the page error, when the read after the undo fails", async () => {
    serveNext(nextAnswer(), { status: 503, body: { detail: "down" } });
    serveUndo(undone({ undone_cluster_id: A, done: 17, total: 60 }));
    renderPage();
    await ready();
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    expect(await screen.findByText(L.notice.undone(A, 17, 60))).toBeVisible();
    expect(screen.getByText(L.loadErrorServer(503))).toBeVisible();
  });

  it("does not put a refusal under the page error: only a confirmation is carried over", async () => {
    // A refused save that left the screen as it was cannot fail the read, but a refusal that rereads can.
    serveNext(nextAnswer(), { status: 500, body: { detail: "boom" } });
    servePost({ status: 409, body: { detail: "already labelled by this labeler" } });
    renderPage();
    await ready();
    await save("benign");
    await screen.findByText(L.loadErrorServer(500));
    expect(
      screen.queryByText(S.admin.reason.already_labelled, { exact: false }),
    ).not.toBeInTheDocument();
  });

  it("asks again, and does not guess a cluster, when the server names one and sends none", async () => {
    serveNext(nextAnswer({ cluster: null }));
    renderPage();
    expect(await screen.findByText(L.clusterMissing)).toBeVisible();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: S.common.retry })).toBeVisible();
  });

  it("is free of axe violations on the page error", async () => {
    serveNext({ status: 500, body: { detail: "boom" } });
    const { container } = renderPage();
    await screen.findByRole("alert");
    expect(await axeOf(container)).toEqual([]);
  });
});

// ==== blind labelling (DEC-019, DEC-101; plan Review Focus 5) =====================================================

const THREE = [NEXT, LABELS, UNDO];

describe("the page stays blind", () => {
  it("makes no request but labels/next, labels and labels/undo, from the load to the end", async () => {
    // load A · label A · next B · undo · next A · label A again · next: finished
    serveNext(nextAnswer(), afterA(), nextAnswer({ done: 18 }), finished());
    servePost(posted({ done: 19 }));
    serveUndo(undone({ done: 18 }));
    renderPage();
    await ready();
    await save("benign");
    await waitFor(() => expect(headText()).toContain("port_scan"));
    await userEvent.click(screen.getByRole("button", { name: L.form.undo }));
    await screen.findByText(L.notice.undone(A, 18, 60));
    await waitFor(() => expect(headText()).toContain("ssh_brute_force"));
    servePost(posted({ done: 60, next: null }));
    await save("escalate");
    await screen.findByText(L.finished.body);
    expect(log).toEqual([
      `GET ${NEXT}`,
      `POST ${LABELS}`,
      `GET ${NEXT}`,
      `POST ${UNDO}`,
      `GET ${NEXT}`,
      `POST ${LABELS}`,
      `GET ${NEXT}`,
    ]);
    expect(new Set(log.map((entry) => entry.split(" ")[1]))).toEqual(new Set(THREE));
  });

  it("makes no request of its own from the frozen state, from no candidates, or from an error", async () => {
    for (const reply of [
      frozenNext(),
      nextAnswer({ candidates_present: false, cluster_id: null, cluster: null, done: 0, total: 0 }),
      { status: 500, body: { detail: "boom" } } as Failure,
    ]) {
      log = [];
      serveNext(reply);
      const { unmount } = renderPage();
      await waitFor(() => expect(log.length).toBeGreaterThan(0));
      await delay(20);
      expect(log).toEqual([`GET ${NEXT}`]);
      unmount();
    }
  });

  it("does not fetch the alert behind the cluster, the queue, the case, or who the caller is", async () => {
    serveNext(nextAnswer());
    renderPage();
    await ready();
    await userEvent.click(
      screen.getByText(L.correlation.sample("5715", "suspicious_login", "low", 1, "27/09 21:20"), {
        exact: false,
      }),
    );
    await delay(30);
    expect(log).toEqual([`GET ${NEXT}`]);
  });

  // The server never sends these (VIEW_KEYS is an allowlist), and a bug in it must not reach the page: the
  // page renders each allowed field by name, and nothing it was not told about.
  describe("a field outside VIEW_KEYS", () => {
    const MARK = "LEAKMARK-4f1c9a";
    const EXTRA = {
      source: `lab-${MARK}`,
      status: `escalated_tier2-${MARK}`,
      risk_score: `93-${MARK}`,
      suggested_action: `escalate-${MARK}`,
      suggestion_visible: `true-${MARK}`,
      triage_status: `ready-${MARK}`,
      note: `note-${MARK}`,
      verifier: `verdict-${MARK}`,
    };

    function leaky(): LabelsNext {
      const base = nextAnswer();
      const withExtra = {
        ...base,
        ...EXTRA,
        cluster: {
          ...cluster(),
          ...EXTRA,
          correlation: {
            rows: [{ ...cluster().correlation.rows[0], ...EXTRA }],
            samples: [{ ...cluster().correlation.samples[0], ...EXTRA }],
          },
        },
      };
      return withExtra as unknown as LabelsNext;
    }

    it("never reaches the page: not as text, not in an attribute", async () => {
      serveNext(leaky());
      const { container } = renderPage();
      await ready();
      await userEvent.click(container.querySelector("summary") as HTMLElement);
      const html = container.innerHTML;
      expect(html).not.toContain(MARK);
      for (const key of Object.keys(EXTRA)) {
        // The key names themselves are nowhere either: `note` and `source` are not words of this page.
        if (key === "note") continue;
        expect(html).not.toContain(key);
      }
      for (const value of Object.values(EXTRA))
        expect(document.body.textContent).not.toContain(value);
    });

    it("never reaches the page after a label is saved either", async () => {
      serveNext(leaky(), leaky());
      servePost({ ...posted(), ...EXTRA } as unknown as Posted);
      const { container } = renderPage();
      await ready();
      await save("benign");
      await screen.findByRole("status");
      expect(container.innerHTML).not.toContain(MARK);
    });

    it("is not in what the form posts", async () => {
      serveNext(leaky(), afterA());
      servePost();
      renderPage();
      await ready();
      await save("benign");
      await waitFor(() => expect(posts).toHaveLength(1));
      expect(Object.keys(posts[0] as object).sort()).toEqual(
        ["cluster_id", "confidence", "label", "labeler"].sort(),
      );
    });
  });

  it("has no link, in any state: nothing leads to an alert, a case or the queue", async () => {
    const states: Reply[] = [
      nextAnswer(),
      frozenNext(),
      finished(),
      nextAnswer({ candidates_present: false, cluster_id: null, cluster: null, done: 0, total: 0 }),
    ];
    for (const state of states) {
      serveNext(state);
      const { container, unmount } = renderPage();
      await waitFor(() => expect(container.querySelector("h2")).not.toBeNull());
      expect(container.querySelectorAll("a, [href]")).toHaveLength(0);
      unmount();
    }
  });

  it("names no model, suggestion, AI or alert page in any state", async () => {
    const states: Reply[] = [
      nextAnswer(),
      frozenNext(),
      finished(),
      nextAnswer({ candidates_present: false, cluster_id: null, cluster: null, done: 0, total: 0 }),
    ];
    for (const state of states) {
      serveNext(state);
      const { container, unmount } = renderPage();
      await waitFor(() => expect(container.querySelector("h2")).not.toBeNull());
      expect(container.querySelector("main")?.textContent).not.toMatch(
        /\bAI\b|\bLLM\b|model|mô hình|gợi ý|đề xuất|suggest|verifier|proposer|risk|điểm rủi ro/i,
      );
      unmount();
    }
    // The words of the page itself, all of them.
    expect(JSON.stringify(L)).not.toMatch(
      /\bAI\b|\bLLM\b|model|mô hình|gợi ý|đề xuất|suggest|verifier|proposer|risk/i,
    );
  });
});

// The page's own source is read, like guards.test.ts reads the whole of src: the blind page must render each
// field by name. A loop or a dump over the cluster would show any key the server added. The behaviour tests above
// (a planted key never reaches the DOM) are the real wall; this only keeps the obvious ways round it out.
//
// The source is read as TypeScript (a syntax tree), not as lines of text: a comment, a string that holds `//`,
// or a name written across lines cannot hide a call from it, and a comment that names a forbidden call is not one.
//
// What it reads is the four files, and the relative modules they may import are an allow-list (`ALLOWED_IMPORTS`):
// a new file next to them, imported, re-exported or imported on demand, fails until it is put on the list, and so
// read by this guard (P11-T16 review round 2, P11-T20 row 60).
//
// Known gaps, left to the DOM tests above (a planted marker never reaches the page, before and after a save),
// which are the real wall: the guard is name-based, so it does not see
//   - `(cluster.constructor as ObjectConstructor).keys(cluster)` (the `.constructor` of a value is `Object`);
//   - a renamed alias that is then spread, `const c = cluster; <i {...c} />` (the spread list is of names);
//   - `globalThis["Obj" + "ect"].keys(cluster)` (a name built at run time).
describe("the source of the page", () => {
  const FILES = ["LabelsPage.tsx", "LabelClusterView.tsx", "LabelForm.tsx", "labelerId.ts"];
  const source = (name: string) => readFileSync(join("src", "features", "admin", name), "utf8");

  /** Names the blind page must not use at all: ways to walk or copy the keys of an object, to navigate, to ask who. */
  const BANNED = new Set([
    "Object",
    "Reflect",
    "structuredClone",
    "navigate",
    "useNavigate",
    "useMe",
    "fetchMe",
    "dangerouslySetInnerHTML",
    "innerHTML",
  ]);
  /** The names the cluster and its parts go by in these files: spreading one would copy every key it carries. */
  const WHOLE = new Set(["cluster", "view", "data", "next", "row", "sample", "answer", "saved"]);
  const LINK_TAGS = new Set(["a", "Link", "NavLink", "Navigate"]);
  /**
   * Every relative module the four files may import, exactly as they spell it: the API (its routes are checked by
   * name below), the session, the shared components they draw with, the strings and the time module, the
   * console's cache keys and write latch, and the four files themselves. A relative module that is not here is
   * a new file this guard has never read (a helper of the same folder, a component), so it fails the guard until
   * someone puts it on the list, and so reads it.
   */
  const ALLOWED_IMPORTS = new Set([
    "../../api/admin",
    "../../api/types",
    "../../auth/AuthProvider",
    "../../components/Badge",
    "../../components/DataTable",
    "../../components/LogBlock",
    "../../components/PageError",
    "../../components/Toast",
    "../../format",
    "../../strings",
    "./adminKeys",
    "./useSubmitLatch",
    "./LabelsPage",
    "./LabelForm",
    "./LabelClusterView",
    "./labelerId",
  ]);
  const ALLOWED_IMPORT_LINES = [...ALLOWED_IMPORTS].map((from) => `import "${from}";`).join("\n");

  /** What a file does that the blind page must not. `[]` for a file that does none of it. */
  function violations(text: string, name = "scratch.tsx"): string[] {
    const file = ts.createSourceFile(name, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const found: string[] = [];
    const visit = (node: ts.Node): void => {
      if (ts.isForInStatement(node)) found.push("for…in");
      if (ts.isIdentifier(node)) {
        if (BANNED.has(node.text)) found.push(`the name ${node.text}`);
        // JSON is read (`JSON.parse` of the token); anything else of it can write the whole object out.
        const isParse =
          ts.isPropertyAccessExpression(node.parent) && node.parent.name.text === "parse";
        if (node.text === "JSON" && !isParse) found.push("JSON other than JSON.parse");
      }
      if (
        (ts.isSpreadAssignment(node) ||
          ts.isSpreadElement(node) ||
          ts.isJsxSpreadAttribute(node)) &&
        ts.isIdentifier(node.expression) &&
        WHOLE.has(node.expression.text)
      ) {
        found.push(`a spread of ${node.expression.text}`);
      }
      if (
        ts.isBindingElement(node) &&
        node.dotDotDotToken &&
        ts.isObjectBindingPattern(node.parent)
      ) {
        found.push("an object rest");
      }
      if (
        (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) &&
        LINK_TAGS.has(node.tagName.getText(file))
      ) {
        found.push(`a link, <${node.tagName.getText(file)}>`);
      }
      if (ts.isJsxAttribute(node) && ["href", "to"].includes(node.name.getText(file))) {
        found.push(`the attribute ${node.name.getText(file)}`);
      }
      if (
        (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
        node.moduleSpecifier !== undefined &&
        ts.isStringLiteral(node.moduleSpecifier)
      ) {
        const from = node.moduleSpecifier.text;
        if (/\/api\/(?!admin$|types$)/.test(from)) found.push(`the module ${from}`);
        if (/\/(tier1|tier2)\//.test(from)) found.push(`the module ${from}`);
        // A relative module off the list is a file this guard does not read: an import, a re-export of one.
        if (from.startsWith(".") && !ALLOWED_IMPORTS.has(from)) {
          found.push(`the module ${from}, which is not on the list`);
        }
      }
      // `import("./x")` names a module without an import declaration.
      if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        found.push("a dynamic import");
      }
      if (
        ts.isPropertyAccessExpression(node) &&
        ts.isIdentifier(node.expression) &&
        node.expression.text === "adminKeys" &&
        node.name.text !== "labels"
      ) {
        found.push(`the query key adminKeys.${node.name.text}`);
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
    return found;
  }

  /** The names a file imports from api/admin. */
  function importedFromAdminApi(text: string): string[] {
    const file = ts.createSourceFile(
      "scratch.tsx",
      text,
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.TSX,
    );
    const names: string[] = [];
    for (const statement of file.statements) {
      if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier))
        continue;
      if (!/\/api\/admin$/.test(statement.moduleSpecifier.text)) continue;
      const bindings = statement.importClause?.namedBindings;
      if (bindings !== undefined && ts.isNamedImports(bindings)) {
        for (const element of bindings.elements) names.push(element.name.text);
      }
    }
    return names;
  }

  it.each(FILES)("%s renders no object whole, links to nothing, asks for nothing else", (name) => {
    expect(violations(source(name), name)).toEqual([]);
  });

  it("calls three routes of api/admin.ts and no other", () => {
    const imported = FILES.flatMap((name) => importedFromAdminApi(source(name)))
      .filter((name) => /^[a-z]/.test(name))
      .sort();
    expect([...new Set(imported)]).toEqual([
      "adminErrorOf",
      "getLabelsNext",
      "postLabel",
      "undoLabel",
    ]);
  });

  // The checker is itself checked. Each of these is added to the real source of the page as a scratch copy in a
  // string, never to the file: the real source has none, the copy has one.
  describe("the checker", () => {
    const real = source("LabelClusterView.tsx");

    it("finds nothing in the real source it is given the scratch copies of", () => {
      expect(violations(real, "LabelClusterView.tsx")).toEqual([]);
    });

    it.each([
      ["a for…in loop", "for (const key in cluster) { void key; }"],
      ["Object.getOwnPropertyNames", "void Object.getOwnPropertyNames(cluster);"],
      ["Reflect.ownKeys", "void Reflect.ownKeys(cluster);"],
      ["structuredClone", "void structuredClone(cluster);"],
      ["Object.entries across two lines", "void Object\n  .entries(cluster);"],
      ["a // inside a string before JSON.stringify", 'void ["//", JSON.stringify(cluster)];'],
      ["JSON.stringify by another name", 'const j = JSON; void j["stringify"](cluster);'],
      ["a spread of the cluster", "void { ...cluster };"],
      ["a spread of the cluster in JSX", "void (<div {...cluster} />);"],
      [
        "an object rest of the cluster",
        "const { category, ...others } = cluster; void [category, others];",
      ],
      ["a link", 'void (<a href="/alerts/1">x</a>);'],
      ["a router link", 'void (<Link to="/cases/1">x</Link>);'],
      ["a navigation", "const go = useNavigate(); void go;"],
      [
        "dangerouslySetInnerHTML",
        "void (<div dangerouslySetInnerHTML={{ __html: cluster.raw_log }} />);",
      ],
      ["the caller's id from the server", "void useMe(true);"],
      ["another api module", 'import { fetchQueue } from "../../api/queue";\nvoid fetchQueue;'],
      ["another feature", 'import { x } from "../tier1/alertSections";\nvoid x;'],
      ["another query key", "void adminKeys.overviewAll;"],
      // The allow-list of relative imports: a new file next to these four would otherwise be read by nobody.
      ["a new helper of the same folder", 'import { helper } from "./labelHelpers";\nvoid helper;'],
      ["a helper of another admin page", 'import { rows } from "./overviewModel";\nvoid rows;'],
      [
        "a shared component that is not on the list",
        'import { Chip } from "../../components/Chip";\nvoid Chip;',
      ],
      ["a side-effect import of a new file", 'import "./labelHelpers";'],
      ["a re-export of a new file", 'export * from "./labelHelpers";'],
      ["a named re-export of a new file", 'export { helper } from "./labelHelpers";'],
      ["a dynamic import", 'void import("./labelHelpers");'],
    ])("finds %s", (_name, snippet) => {
      expect(violations(`${real}\n${snippet}\n`, "scratch.tsx")).not.toEqual([]);
    });

    it.each([
      [
        "a comment naming a forbidden call",
        "// Object.keys(cluster) and JSON.stringify(cluster) are not called here.",
      ],
      ["a block comment naming one", "/* for (const k in cluster) {} */"],
      ["a string that names one", 'void "Object.keys(cluster)";'],
      ["JSON.parse, which reads the token", 'void JSON.parse("{}");'],
      ["the labels query key, spread into a longer one", "void [...adminKeys.labels, 1];"],
      ["a spread of a name that is no whole object", "void { ...answerFields };"],
      ["an import of each file on the list", ALLOWED_IMPORT_LINES],
      ["a package import", 'import { useState } from "react";\nvoid useState;'],
      ["an export of its own name", "export const own = 1;"],
    ])("does not find %s", (_name, snippet) => {
      expect(violations(`${real}\n${snippet}\n`, "scratch.tsx")).toEqual([]);
    });
  });
});
