// src/features/admin/RulesPage.test.tsx — `/admin/rules` (P11-T14, spec §4.4): the six hard blocks, the rules
// table, the toggle dialog, the two-step create (a builder from the whitelist, then a preview), and every
// state of the AdminStates section. The backend is MSW; the page is the real one.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router";
import { HARD_BLOCK_CODES, type RuleRow, type SimulateResult } from "../../api/admin";
import { S } from "../../strings";
import { RulesPage } from "./RulesPage";
import { RULE_FIELDS, opsOf, type RuleField, type RuleOp } from "./ruleFields";

const R = S.admin.rulesPage;
const RULES_URL = "/api/admin/rules";
const SIMULATE_URL = "/api/admin/rules/simulate";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// --- fixtures ---------------------------------------------------------------------------------------------

const uuid = (n: number) => `5d1c9a50-0000-4000-8000-${String(n).padStart(12, "0")}`;

const rule = (n: number, over: Partial<RuleRow> = {}): RuleRow => ({
  rule_id: uuid(n),
  name: `Rule số ${n}`,
  enabled: true,
  match: [{ field: "category", op: "eq", value: "recon" }],
  match_json: '[{"field": "category", "op": "eq", "value": "recon"}]',
  reason: `Lý do của rule ${n}`,
  created_by: "9f5d1c9a-0000-4000-8000-000000000001",
  created_at: "2026-09-24T03:12:00+00:00",
  width_pct: null,
  width_threshold_pct: 30,
  ...over,
});

/** The three rules of the canvas: an ordinary one, a wide one, a disabled one. */
const SSH = rule(1, {
  name: "Đăng nhập SSH thành công từ máy quản trị",
  reason: "Máy nhảy của đội vận hành, đăng nhập theo ca",
  match: [
    { field: "rule_id", op: "in", value: ["5715"] },
    { field: "srcip", op: "cidr", value: "10.10.5.0/28" },
    { field: "alert_user", op: "eq", value: "ops" },
  ],
});
const LAB = rule(2, {
  name: "Cảnh báo dung lượng đĩa máy lab",
  reason: "Máy lab ghi log đầy đĩa mỗi đêm, đã có job dọn",
  match: [
    { field: "agent_name", op: "prefix", value: "lab-" },
    { field: "rule_id", op: "eq", value: "531" },
  ],
  created_at: "2026-09-25T09:40:00+00:00",
  width_pct: 34,
});
const DNS = rule(3, {
  name: "Thử nghiệm: quét DNS nội bộ",
  reason: "Tạm tắt sau khi digest báo một cụm đóng sai",
  enabled: false,
  match: [
    { field: "category", op: "eq", value: "recon" },
    { field: "dst_port", op: "eq", value: 53 },
  ],
  created_at: "2026-09-27T02:05:00+00:00",
});
const THREE = [SSH, LAB, DNS];

const PREVIEW: SimulateResult = {
  clusters: 37,
  alerts: 1204,
  by_severity: { low: 22, medium: 15 },
  by_asset_criticality: { low: 30, medium: 7 },
  samples: ["1727401201.662100", "1727401302.661877", "1727401455.661650"],
  hard_block_tally: null,
};

const ZERO = (tally: SimulateResult["hard_block_tally"]): SimulateResult => ({
  clusters: 0,
  alerts: 0,
  by_severity: {},
  by_asset_criticality: {},
  samples: [],
  hard_block_tally: tally,
});

const blocks = (counts: Partial<Record<(typeof HARD_BLOCK_CODES)[number], number>>) =>
  HARD_BLOCK_CODES.map((code) => ({ code, count: counts[code] ?? 0 })).sort(
    (a, b) => b.count - a.count,
  );

const detail = (body: unknown, status: number) => HttpResponse.json({ detail: body }, { status });
const WHITELIST_TEXT =
  "simulate: match is outside the whitelist or malformed: [{'field': 'category', 'op': 'cidr', 'value': 'recon'}]";

// --- the fake backend -------------------------------------------------------------------------------------

type Answer = (body: unknown) => Response | Promise<Response>;

type Calls = {
  list: number;
  simulate: unknown[];
  create: unknown[];
  toggle: unknown[];
  /** The Content-Type of every write, in order. */
  writes: (string | null)[];
  rules: RuleRow[];
};

function backend(
  rules: RuleRow[],
  over: {
    list?: () => Response | Promise<Response>;
    simulate?: Answer;
    create?: Answer;
    toggle?: Answer;
  } = {},
): Calls {
  const calls: Calls = {
    list: 0,
    simulate: [],
    create: [],
    toggle: [],
    writes: [],
    // A copy of every row: a toggle edits the backend's rows, never the fixtures the next test reads.
    rules: rules.map((r) => ({ ...r })),
  };
  server.use(
    http.get(RULES_URL, () => {
      calls.list += 1;
      return over.list ? over.list() : HttpResponse.json(calls.rules);
    }),
    http.post(SIMULATE_URL, async ({ request }) => {
      const body: unknown = await request.json();
      calls.simulate.push(body);
      calls.writes.push(request.headers.get("content-type"));
      return over.simulate ? over.simulate(body) : HttpResponse.json(PREVIEW);
    }),
    http.post(RULES_URL, async ({ request }) => {
      const body = (await request.json()) as {
        name: string;
        reason: string;
        match: RuleRow["match"];
      };
      calls.create.push(body);
      calls.writes.push(request.headers.get("content-type"));
      if (over.create) return over.create(body);
      const created = rule(calls.rules.length + 1, {
        ...body,
        match_json: JSON.stringify(body.match),
      });
      calls.rules.push(created);
      return HttpResponse.json(
        { rule_id: created.rule_id, name: created.name, enabled: true },
        { status: 201 },
      );
    }),
    http.patch(RULES_URL, async ({ request }) => {
      const body = (await request.json()) as { rule_id: string; enabled: boolean };
      calls.toggle.push(body);
      calls.writes.push(request.headers.get("content-type"));
      if (over.toggle) return over.toggle(body);
      const target = calls.rules.find((r) => r.rule_id === body.rule_id);
      if (!target) return detail("rule not found", 404);
      target.enabled = body.enabled;
      return HttpResponse.json({
        rule_id: target.rule_id,
        name: target.name,
        enabled: body.enabled,
      });
    }),
  );
  return calls;
}

// --- rendering and small helpers --------------------------------------------------------------------------

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/admin/rules"]}>
        <main>
          <RulesPage />
        </main>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const tableOf = () => screen.findByRole("table", { name: R.table.label });
const rowOf = async (name: string) => {
  const cell = await within(await tableOf()).findByText(name);
  return cell.closest("tr") as HTMLElement;
};
const hardBlockBox = () => screen.getByRole("region", { name: R.hardBlocks.label });
const builder = () => screen.getByRole("region", { name: R.create });
const previewBox = () => screen.getByRole("region", { name: R.preview.title });
const group = (n: number) => within(builder()).getByRole("group", { name: R.builder.group(n) });
const nameBox = () => within(builder()).getByLabelText(R.builder.name);
const reasonBox = () => within(builder()).getByLabelText(R.builder.reason);
const previewButton = () => within(builder()).getByRole("button", { name: R.builder.preview });
const createButton = () => within(builder()).getByRole("button", { name: R.builder.submit });
const valueOf = (n: number) => within(group(n)).getByLabelText(R.builder.value);

type User = ReturnType<typeof userEvent.setup>;

/**
 * Two clicks in ONE tick: both inside a single `act`, so React renders nothing between them and the second
 * lands on the same enabled button the first did. (TanStack Query 5 also tells React that a write is pending
 * only through a `setTimeout(0)`, so `disabled={mutation.isPending}` cannot stop the second by itself;
 * `userEvent`, which awaits between clicks, never reproduces it.)
 */
function clickTwiceInOneTick(button: HTMLElement) {
  act(() => {
    fireEvent.click(button);
    fireEvent.click(button);
  });
}

/** Sets the pieces of condition `n` of the builder that are given. */
async function condition(
  user: User,
  n: number,
  what: { field?: RuleField; op?: RuleOp; value?: string },
) {
  if (what.field)
    await user.selectOptions(within(group(n)).getByLabelText(R.builder.field), what.field);
  if (what.op) await user.selectOptions(within(group(n)).getByLabelText(R.builder.op), what.op);
  if (what.value !== undefined) {
    const box = valueOf(n);
    if (box.tagName === "SELECT") await user.selectOptions(box, what.value);
    else {
      await user.clear(box);
      if (what.value !== "") await user.type(box, what.value);
    }
  }
}

async function ready() {
  const user = userEvent.setup();
  renderPage();
  await tableOf();
  return user;
}

/** Previews the one condition `category eq recon` and waits for the answer. */
async function previewed(user: User, text = "recon") {
  await condition(user, 1, { field: "category", op: "eq", value: text });
  await user.click(previewButton());
  await within(previewBox()).findByText(R.preview.clusters);
}

async function fillNameAndReason(
  user: User,
  name = "Quét cổng",
  reason = "Máy giám sát quét theo lịch",
) {
  await user.type(nameBox(), name);
  await user.type(reasonBox(), reason);
}

// --- the page ---------------------------------------------------------------------------------------------

describe("the page", () => {
  it("has its h1, a count in words, and the button that opens the create form", async () => {
    backend(THREE);
    renderPage();
    expect(
      screen.getByRole("heading", { level: 1, name: S.admin.title.rules }),
    ).toBeInTheDocument();
    await tableOf();
    expect(screen.getByText(R.subtitle(3, 2))).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: R.create })).toHaveLength(1);
  });

  it("is the only h1: every other heading is below it", async () => {
    backend(THREE);
    renderPage();
    await tableOf();
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
  });

  it("counts the enabled rules from what the server sent", async () => {
    backend([SSH, { ...LAB, enabled: false }, { ...DNS, enabled: false }, rule(4)]);
    renderPage();
    await tableOf();
    expect(screen.getByText(R.subtitle(4, 2))).toBeInTheDocument();
  });
});

describe("the six hard blocks", () => {
  it("are shown in the order of HARD_BLOCK_CODES, with the texts of the server", async () => {
    backend(THREE);
    renderPage();
    await tableOf();
    const items = within(hardBlockBox()).getAllByRole("listitem");
    expect(items.map((li) => li.textContent)).toEqual(
      HARD_BLOCK_CODES.map((code) => S.admin.hardBlock[code]),
    );
    expect(items).toHaveLength(6);
    expect(
      within(hardBlockBox()).getByRole("heading", { level: 2, name: R.hardBlocks.title }),
    ).toBeInTheDocument();
    expect(within(hardBlockBox()).getByText(R.hardBlocks.note)).toBeInTheDocument();
  });

  it("are there while the rules load, when there are none, and when the list fails", async () => {
    // loading
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    backend(THREE, {
      list: async () => {
        await gate;
        return HttpResponse.json(THREE);
      },
    });
    const first = renderPage();
    expect(within(hardBlockBox()).getAllByRole("listitem")).toHaveLength(6);
    release();
    await tableOf();
    first.unmount();
    // none
    server.resetHandlers();
    backend([]);
    const second = renderPage();
    await screen.findByText(R.empty.title);
    expect(within(hardBlockBox()).getAllByRole("listitem")).toHaveLength(6);
    second.unmount();
    // failing
    server.resetHandlers();
    backend([], { list: () => detail("boom", 500) });
    renderPage();
    await screen.findByText(R.loadFailed);
    expect(within(hardBlockBox()).getAllByRole("listitem")).toHaveLength(6);
  });
});

describe("the rules table", () => {
  it("heads the six columns of the canvas", async () => {
    backend(THREE);
    renderPage();
    await tableOf();
    expect(screen.getAllByRole("columnheader").map((h) => h.textContent)).toEqual([
      R.table.nameAndReason,
      R.table.conditions,
      R.table.width,
      R.table.created,
      R.table.state,
      R.table.action,
    ]);
  });

  it("lists the rules in the order the server sent, each with its name and reason", async () => {
    backend(THREE);
    renderPage();
    const rows = within(await tableOf())
      .getAllByRole("row")
      .slice(1);
    expect(rows).toHaveLength(3);
    for (const [row, r] of rows.map((row, i) => [row, THREE[i]!] as const)) {
      expect(within(row).getByText(r.name)).toBeInTheDocument();
      expect(within(row).getByText(r.reason)).toBeInTheDocument();
    }
  });

  it("shows the conditions as field-operator-value chips", async () => {
    backend(THREE);
    renderPage();
    const chips = async (name: string) =>
      within(await rowOf(name))
        .getAllByRole("listitem")
        .map((li) => li.textContent);
    expect(await chips(SSH.name)).toEqual([
      'rule_id in ["5715"]',
      'srcip cidr "10.10.5.0/28"',
      'alert_user eq "ops"',
    ]);
    expect(await chips(LAB.name)).toEqual(['agent_name prefix "lab-"', 'rule_id eq "531"']);
    expect(await chips(DNS.name)).toEqual(['category eq "recon"', "dst_port eq 53"]);
  });

  it("says a rule with no condition matches every cluster", async () => {
    backend([rule(1, { name: "Mọi thứ", match: [] })]);
    renderPage();
    const row = await rowOf("Mọi thứ");
    expect(within(row).getByText(R.table.noConditions)).toBeInTheDocument();
    expect(within(row).queryAllByRole("listitem")).toHaveLength(0);
  });

  it("shows a stored condition of any shape, as text, without a crash", async () => {
    backend([
      rule(1, {
        name: "Lạ",
        match: [
          "not an object",
          { field: "x", op: "eq" },
          { field: "decoder", op: "eq", value: "<img src=x onerror=alert(1)>" },
        ] as unknown as RuleRow["match"],
      }),
    ]);
    const { container } = renderPage();
    const row = await rowOf("Lạ");
    expect(
      within(row)
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual([
      '"not an object"',
      '{"field":"x","op":"eq"}',
      'decoder eq "<img src=x onerror=alert(1)>"',
    ]);
    expect(container.querySelector("img")).toBeNull();
  });

  it("shows a hostile name and reason as text", async () => {
    backend([
      rule(1, {
        name: "<script>alert(1)</script> <b>đậm</b>",
        reason: "<a href='javascript:alert(1)'>bấm</a>",
      }),
    ]);
    const { container } = renderPage();
    await tableOf();
    expect(screen.getByText("<script>alert(1)</script> <b>đậm</b>")).toBeInTheDocument();
    expect(container.querySelector("script, b, a[href^='javascript']")).toBeNull();
  });

  it("shows the creation time in Ho Chi Minh time, and the state as bật or tắt", async () => {
    backend(THREE);
    renderPage();
    expect(within(await rowOf(SSH.name)).getByText("24/09 10:12")).toBeInTheDocument();
    expect(within(await rowOf(LAB.name)).getByText("25/09 16:40")).toBeInTheDocument();
    expect(within(await rowOf(DNS.name)).getByText("27/09 09:05")).toBeInTheDocument();
    expect(within(await rowOf(SSH.name)).getByText(R.table.on)).toBeInTheDocument();
    expect(within(await rowOf(DNS.name)).getByText(R.table.off)).toBeInTheDocument();
  });

  it("offers Tắt on an enabled rule and Bật on a disabled one, each named for its rule", async () => {
    backend(THREE);
    renderPage();
    const off = within(await rowOf(SSH.name)).getByRole("button", {
      name: R.table.turnOffLabel(SSH.name),
    });
    expect(off).toHaveTextContent(R.table.turnOff);
    const on = within(await rowOf(DNS.name)).getByRole("button", {
      name: R.table.turnOnLabel(DNS.name),
    });
    expect(on).toHaveTextContent(R.table.turnOn);
  });
});

describe("the width warning", () => {
  it("warns when width_pct is over width_threshold_pct, in the canvas's words", async () => {
    backend(THREE);
    renderPage();
    expect(within(await rowOf(LAB.name)).getByText("⚠ 34% > 30%")).toBeInTheDocument();
    expect(screen.getAllByText(/⚠/)).toHaveLength(1);
  });

  it("measures against the threshold the row carries, not a number of the page's own", async () => {
    backend([rule(1, { name: "A", width_pct: 26.5, width_threshold_pct: 25 })]);
    renderPage();
    expect(within(await rowOf("A")).getByText("⚠ 26,5% > 25%")).toBeInTheDocument();
  });

  it("warns for a rule whose width rounds to the threshold: a width the server sends is over it", async () => {
    // `rule_width_report` keeps a rule when its UNROUNDED share is over the threshold and sends `pct` rounded
    // to one decimal, so a share of 30.04 % arrives as 30.0 against 30. A non-null width is the warning
    // (spec §4.4, the Jinja page): the page does not compare the rounded figure again.
    backend([rule(1, { name: "Sát ngưỡng", width_pct: 30, width_threshold_pct: 30 })]);
    renderPage();
    expect(within(await rowOf("Sát ngưỡng")).getByText("⚠ 30% > 30%")).toBeInTheDocument();
  });

  it("shows a dash, and no warning, for a rule with no width", async () => {
    backend([rule(1, { name: "Không có", width_pct: null })]);
    renderPage();
    const row = await rowOf("Không có");
    expect(within(row).getByText(S.common.missing)).toBeInTheDocument();
    expect(screen.queryByText(/⚠/)).not.toBeInTheDocument();
  });

  it("explains the width under the table, with the threshold of the rows", async () => {
    backend(THREE);
    renderPage();
    await tableOf();
    expect(screen.getByText(R.table.widthNote("30"))).toBeInTheDocument();
  });
});

describe("loading, a failed list, and no rules", () => {
  it("shows a skeleton while the list loads, and the table when it has", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    backend(THREE, {
      list: async () => {
        await gate;
        return HttpResponse.json(THREE);
      },
    });
    renderPage();
    const status = screen.getByRole("status");
    expect(status).toHaveTextContent(S.common.loading);
    expect(status).toHaveAttribute("aria-busy", "true");
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.queryByText(R.empty.title)).not.toBeInTheDocument();
    release();
    await tableOf();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows PageError with a retry when the list cannot be read, and reads it again on retry", async () => {
    const user = userEvent.setup();
    let fail = true;
    const calls = backend(THREE, {
      list: () => (fail ? detail("boom", 500) : HttpResponse.json(THREE)),
    });
    renderPage();
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(R.loadFailed);
    expect(within(alert).getByRole("heading", { level: 1 })).toHaveTextContent(R.loadFailed);
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    fail = false;
    await user.click(within(alert).getByRole("button", { name: S.common.retry }));
    await tableOf();
    expect(calls.list).toBe(2);
    expect(screen.queryByText(R.loadFailed)).not.toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 1, name: S.admin.title.rules }),
    ).toBeInTheDocument();
  });

  it("fails alone: with the list down, the hard blocks and the whole create flow still work", async () => {
    const user = userEvent.setup();
    const calls = backend([], { list: () => detail("boom", 500) });
    renderPage();
    await screen.findByText(R.loadFailed);
    expect(within(hardBlockBox()).getAllByRole("listitem")).toHaveLength(6);
    await previewed(user);
    expect(within(previewBox()).getByText("37")).toBeInTheDocument();
    expect(calls.simulate).toEqual([{ match: [{ field: "category", op: "eq", value: "recon" }] }]);
    expect(screen.getByText(R.loadFailed)).toBeInTheDocument();
  });

  it("shows a 403 on the list as the same notice", async () => {
    backend([], { list: () => detail("forbidden", 403) });
    renderPage();
    expect(await screen.findByText(R.loadFailed)).toBeInTheDocument();
  });

  it("says there are no rules, and that the hard blocks still run, and offers to create one", async () => {
    const user = userEvent.setup();
    backend([]);
    renderPage();
    expect(await screen.findByText(R.empty.title)).toBeInTheDocument();
    expect(screen.getByText(R.empty.body)).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    const buttons = screen.getAllByRole("button", { name: R.create });
    expect(buttons.length).toBeGreaterThanOrEqual(1);
    await user.click(buttons[buttons.length - 1]!);
    expect(nameBox()).toHaveFocus();
  });

  it("moves the focus to the name field from the header button as well", async () => {
    const user = await ready_with(THREE);
    await user.click(screen.getByRole("button", { name: R.create }));
    expect(nameBox()).toHaveFocus();
  });
});

describe("the toggle dialog", () => {
  const open = async (user: User, name: string, label: string) => {
    await user.click(within(await rowOf(name)).getByRole("button", { name: label }));
    return screen.findByRole("dialog");
  };

  it("opens for an enabled rule with the words of the canvas, and cancel closes it without a request", async () => {
    const calls = backend(THREE);
    const user = userEvent.setup();
    renderPage();
    const dialog = await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    expect(dialog).toHaveAccessibleName(R.toggle.offTitle(LAB.name));
    expect(within(dialog).getByText(R.toggle.offBody)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: R.toggle.offConfirm })).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: S.admin.common.cancel }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(calls.toggle).toEqual([]);
    expect(calls.list).toBe(1);
  });

  it("closes on Esc without a request", async () => {
    const calls = backend(THREE);
    const user = userEvent.setup();
    renderPage();
    await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(calls.toggle).toEqual([]);
  });

  it("turns a rule off: PATCH {rule_id, enabled: false} as JSON, then the list is read again and a note says so", async () => {
    const calls = backend(THREE);
    const user = userEvent.setup();
    renderPage();
    const dialog = await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    await user.click(within(dialog).getByRole("button", { name: R.toggle.offConfirm }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(calls.toggle).toEqual([{ rule_id: LAB.rule_id, enabled: false }]);
    expect(calls.writes).toEqual(["application/json"]);
    expect(await screen.findByRole("status")).toHaveTextContent(R.toggle.doneOff(LAB.name));
    await waitFor(() => expect(calls.list).toBe(2));
    expect(within(await rowOf(LAB.name)).getByText(R.table.off)).toBeInTheDocument();
    expect(screen.getByText(R.subtitle(3, 1))).toBeInTheDocument();
  });

  it("turns a disabled rule on, with its own words", async () => {
    const calls = backend(THREE);
    const user = userEvent.setup();
    renderPage();
    const dialog = await open(user, DNS.name, R.table.turnOnLabel(DNS.name));
    expect(dialog).toHaveAccessibleName(R.toggle.onTitle(DNS.name));
    expect(within(dialog).getByText(R.toggle.onBody)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: R.toggle.onConfirm }));
    await waitFor(() => expect(calls.toggle).toEqual([{ rule_id: DNS.rule_id, enabled: true }]));
    expect(await screen.findByRole("status")).toHaveTextContent(R.toggle.doneOn(DNS.name));
    await waitFor(() => expect(screen.getByText(R.subtitle(3, 3))).toBeInTheDocument());
  });

  it("is busy while the write is in flight: no second click, no Esc", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const calls = backend(THREE, {
      toggle: async (body) => {
        await gate;
        return HttpResponse.json({
          rule_id: (body as { rule_id: string }).rule_id,
          name: "x",
          enabled: false,
        });
      },
    });
    const user = userEvent.setup();
    renderPage();
    const dialog = await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    await user.click(within(dialog).getByRole("button", { name: R.toggle.offConfirm }));
    const busy = await within(dialog).findByRole("button", { name: S.admin.common.working });
    expect(busy).toBeDisabled();
    await user.keyboard("{Escape}");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    release();
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(calls.toggle).toHaveLength(1);
  });

  it("sends one PATCH for two clicks of the confirm button in the same tick", async () => {
    const calls = backend(THREE);
    const user = userEvent.setup();
    renderPage();
    const dialog = await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    clickTwiceInOneTick(within(dialog).getByRole("button", { name: R.toggle.offConfirm }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(calls.toggle).toEqual([{ rule_id: LAB.rule_id, enabled: false }]);
  });

  it("can confirm again after a failed toggle: the latch is released", async () => {
    let fail = true;
    const calls = backend(THREE, {
      toggle: (body) => {
        if (fail) return detail("boom", 500);
        const { rule_id } = body as { rule_id: string };
        return HttpResponse.json({ rule_id, name: "x", enabled: false });
      },
    });
    const user = userEvent.setup();
    renderPage();
    const dialog = await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    await user.click(within(dialog).getByRole("button", { name: R.toggle.offConfirm }));
    await within(dialog).findByRole("alert");
    fail = false;
    await user.click(within(dialog).getByRole("button", { name: R.toggle.offConfirm }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(calls.toggle).toHaveLength(2);
  });

  it("on 404 rule_not_found closes the dialog, says the rule is gone, and reads the list again", async () => {
    const calls = backend(THREE, { toggle: () => detail("rule not found", 404) });
    const user = userEvent.setup();
    renderPage();
    const dialog = await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    await user.click(within(dialog).getByRole("button", { name: R.toggle.offConfirm }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(await screen.findByRole("alert")).toHaveTextContent(S.admin.reason.rule_not_found);
    expect(S.admin.reason.rule_not_found).toBe(
      "Không tìm thấy rule này. Danh sách đã được tải lại.",
    );
    await waitFor(() => expect(calls.list).toBe(2));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("shows the refusal in the dialog and keeps it open: 403 forbidden", async () => {
    const calls = backend(THREE, { toggle: () => detail("forbidden", 403) });
    const user = userEvent.setup();
    renderPage();
    const dialog = await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    await user.click(within(dialog).getByRole("button", { name: R.toggle.offConfirm }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(S.admin.reason.forbidden);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(calls.list).toBe(1);
    // the dialog can be tried again or given up
    expect(within(dialog).getByRole("button", { name: R.toggle.offConfirm })).toBeEnabled();
    await user.click(within(dialog).getByRole("button", { name: S.admin.common.cancel }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it.each([
    ["500", () => detail("boom", 500)],
    ["503 (auth disabled)", () => detail("auth disabled: JWT_SECRET unset", 503)],
    [
      "a list-shaped 422",
      () => detail([{ type: "uuid_parsing", loc: ["body", "rule_id"], msg: "bad" }], 422),
    ],
    ["a network failure", () => HttpResponse.error()],
  ])("says the toggle failed, in the dialog, on %s", async (_name, toggle) => {
    backend(THREE, { toggle });
    const user = userEvent.setup();
    renderPage();
    const dialog = await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    await user.click(within(dialog).getByRole("button", { name: R.toggle.offConfirm }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(R.toggle.failed);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("forgets the failure when the dialog is opened again", async () => {
    backend(THREE, { toggle: () => detail("boom", 500) });
    const user = userEvent.setup();
    renderPage();
    let dialog = await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    await user.click(within(dialog).getByRole("button", { name: R.toggle.offConfirm }));
    await within(dialog).findByRole("alert");
    await user.click(within(dialog).getByRole("button", { name: S.admin.common.cancel }));
    dialog = await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    expect(within(dialog).queryByRole("alert")).not.toBeInTheDocument();
  });

  it("leaves a toast that can be closed", async () => {
    backend(THREE);
    const user = userEvent.setup();
    renderPage();
    const dialog = await open(user, LAB.name, R.table.turnOffLabel(LAB.name));
    await user.click(within(dialog).getByRole("button", { name: R.toggle.offConfirm }));
    const toast = await screen.findByRole("status");
    await user.click(within(toast).getByRole("button", { name: S.common.close }));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});

describe("the condition builder", () => {
  it("starts with one empty condition: rule_id eq", async () => {
    await ready_with(THREE);
    expect(within(group(1)).getByLabelText(R.builder.field)).toHaveValue("rule_id");
    expect(within(group(1)).getByLabelText(R.builder.op)).toHaveValue("eq");
    expect(valueOf(1)).toHaveValue("");
    expect(screen.queryByRole("group", { name: R.builder.group(2) })).not.toBeInTheDocument();
  });

  it("lists the fourteen fields, in the whitelist's order", async () => {
    await ready_with(THREE);
    const options = within(within(group(1)).getByLabelText(R.builder.field)).getAllByRole("option");
    expect(options.map((o) => o.textContent)).toEqual(RULE_FIELDS);
  });

  it("offers each field exactly the operators the whitelist gives it, and no other", async () => {
    const user = await ready_with(THREE);
    for (const field of RULE_FIELDS) {
      await condition(user, 1, { field });
      const ops = within(within(group(1)).getByLabelText(R.builder.op)).getAllByRole("option");
      expect(
        ops.map((o) => o.textContent),
        field,
      ).toEqual([...opsOf(field)]);
    }
  });

  it("gives identity_privileged a true/false choice, never a text box", async () => {
    const user = await ready_with(THREE);
    await condition(user, 1, { field: "identity_privileged" });
    const box = valueOf(1);
    expect(box.tagName).toBe("SELECT");
    expect(
      within(box)
        .getAllByRole("option")
        .map((o) => o.textContent),
    ).toEqual(["true", "false"]);
    expect(box).toHaveValue("true");
    await condition(user, 1, { field: "category" });
    expect(valueOf(1).tagName).toBe("INPUT");
    expect(valueOf(1)).toHaveValue("");
  });

  it("drops an operator the new field does not allow, so a pair the server refuses cannot be built", async () => {
    const user = await ready_with(THREE);
    await condition(user, 1, { field: "srcip", op: "cidr", value: "10.0.0.0/8" });
    await condition(user, 1, { field: "category" });
    expect(within(group(1)).getByLabelText(R.builder.op)).toHaveValue("eq");
    expect(valueOf(1)).toHaveValue("10.0.0.0/8");
  });

  it("adds a condition and removes one, and says what a rule with none means", async () => {
    const user = await ready_with(THREE);
    await user.click(within(builder()).getByRole("button", { name: R.builder.add }));
    expect(group(2)).toBeInTheDocument();
    await condition(user, 2, { field: "dst_port", value: "443" });
    await user.click(within(group(1)).getByRole("button", { name: R.builder.remove }));
    // the second row is now the only one, and kept what was typed
    expect(group(1)).toBeInTheDocument();
    expect(screen.queryByRole("group", { name: R.builder.group(2) })).not.toBeInTheDocument();
    expect(within(group(1)).getByLabelText(R.builder.field)).toHaveValue("dst_port");
    expect(valueOf(1)).toHaveValue("443");
    expect(screen.queryByText(R.builder.none)).not.toBeInTheDocument();
    await user.click(within(group(1)).getByRole("button", { name: R.builder.remove }));
    expect(screen.getByText(R.builder.none)).toBeInTheDocument();
  });

  it("warns beside a condition that can never close a cluster, because a hard block runs first", async () => {
    const user = await ready_with(THREE);
    await condition(user, 1, { field: "asset_criticality", value: "high" });
    expect(
      within(group(1)).getByText(R.builder.neverCloses("asset_criticality", '"high"')),
    ).toBeInTheDocument();
    await condition(user, 1, { value: "low" });
    expect(within(group(1)).queryByText(/Chặn cứng chạy trước/)).not.toBeInTheDocument();
    await condition(user, 1, { field: "ioc_reputation", op: "in", value: "clean, malicious" });
    expect(
      within(group(1)).getByText(R.builder.neverCloses("ioc_reputation", '"malicious"')),
    ).toBeInTheDocument();
    await condition(user, 1, { field: "identity_privileged", value: "true" });
    expect(
      within(group(1)).getByText(R.builder.neverCloses("identity_privileged", "true")),
    ).toBeInTheDocument();
    await condition(user, 1, { value: "false" });
    expect(within(group(1)).queryByText(/Chặn cứng chạy trước/)).not.toBeInTheDocument();
  });

  it("says what an empty value means, for eq and prefix, and still lets it through", async () => {
    const user = await ready_with(THREE);
    expect(within(group(1)).getByText(R.builder.emptyEq)).toBeInTheDocument();
    await condition(user, 1, { field: "agent_name", op: "prefix" });
    expect(within(group(1)).getByText(R.builder.emptyPrefix)).toBeInTheDocument();
    await condition(user, 1, { value: "lab-" });
    expect(within(group(1)).queryByText(R.builder.emptyPrefix)).not.toBeInTheDocument();
    expect(within(group(1)).queryByText(R.builder.emptyEq)).not.toBeInTheDocument();
  });
});

/** The page, loaded, with a user; the builder is below the table. */
async function ready_with(rules: RuleRow[]) {
  backend(rules);
  return ready();
}

describe("the preview", () => {
  const CASES: [label: string, field: RuleField, op: RuleOp, text: string, sent: unknown][] = [
    ["a string", "category", "eq", "recon", "recon"],
    ["an eq string, trimmed of the spaces round it", "category", "eq", "  recon  ", "recon"],
    ["a port as a JSON number", "dst_port", "eq", "443", 443],
    ["rule_level eq as a JSON number", "rule_level", "eq", "12", 12],
    ["rule_level lte as a JSON number", "rule_level", "lte", "7", 7],
    ["a list of strings", "rule_id", "in", "5715, 531", ["5715", "531"]],
    ["a list of ports as numbers", "src_port", "in", "22,443", [22, 443]],
    ["a cidr", "srcip", "cidr", "10.0.0.0/8", "10.0.0.0/8"],
    ["a bare ip as a cidr", "dstip", "cidr", "10.0.0.1", "10.0.0.1"],
    ["a prefix", "agent_name", "prefix", "lab-", "lab-"],
    ["the empty prefix", "agent_id", "prefix", "", ""],
    ["a boolean true", "identity_privileged", "eq", "true", true],
    ["a boolean false", "identity_privileged", "eq", "false", false],
  ];

  it.each(CASES)(
    "sends %s exactly as the server types it",
    async (_label, field, op, text, sent) => {
      const calls = backend(THREE);
      const user = await ready();
      await condition(user, 1, { field, op, value: text });
      await user.click(previewButton());
      await within(previewBox()).findByText(R.preview.clusters);
      expect(calls.simulate).toEqual([{ match: [{ field, op, value: sent }] }]);
      expect(calls.writes).toEqual(["application/json"]);
    },
  );

  it("sends every condition, in order, and the whole body is {match}", async () => {
    const calls = backend(THREE);
    const user = await ready();
    await condition(user, 1, { field: "agent_name", op: "prefix", value: "mon-" });
    await user.click(within(builder()).getByRole("button", { name: R.builder.add }));
    await condition(user, 2, { field: "dst_port", op: "in", value: "53, 123" });
    await user.click(previewButton());
    await within(previewBox()).findByText(R.preview.clusters);
    expect(calls.simulate).toEqual([
      {
        match: [
          { field: "agent_name", op: "prefix", value: "mon-" },
          { field: "dst_port", op: "in", value: [53, 123] },
        ],
      },
    ]);
  });

  it("sends [] for no condition at all: the server accepts it, and it matches everything", async () => {
    const calls = backend(THREE);
    const user = await ready();
    await user.click(within(group(1)).getByRole("button", { name: R.builder.remove }));
    await user.click(previewButton());
    await within(previewBox()).findByText(R.preview.clusters);
    expect(calls.simulate).toEqual([{ match: [] }]);
  });

  it.each([
    ["443.5", "dst_port", "eq"],
    ["abc", "dst_port", "eq"],
    ["", "dst_port", "eq"],
    ["22, 44.5", "dst_port", "in"],
    ["seven", "rule_level", "lte"],
  ] as [string, RuleField, RuleOp][])(
    "does not send %j for %s %s: the value box says it is not a whole number",
    async (text, field, op) => {
      const calls = backend(THREE);
      const user = await ready();
      await condition(user, 1, { field, op, value: text });
      await user.click(previewButton());
      const box = valueOf(1);
      expect(box).toHaveAttribute("aria-invalid", "true");
      const message = within(group(1)).getByText(R.builder.problem.not_integer);
      expect(message.id).not.toBe("");
      expect(box.getAttribute("aria-describedby")).toContain(message.id);
      expect(calls.simulate).toEqual([]);
      // fixing it clears the message
      await condition(user, 1, { value: "53" });
      expect(box).not.toHaveAttribute("aria-invalid", "true");
      expect(within(group(1)).queryByText(R.builder.problem.not_integer)).not.toBeInTheDocument();
    },
  );

  it("refuses an empty list and a blank item in a list, at the value box", async () => {
    const calls = backend(THREE);
    const user = await ready();
    await condition(user, 1, { field: "rule_id", op: "in", value: "" });
    await user.click(previewButton());
    expect(within(group(1)).getByText(R.builder.problem.list_empty)).toBeInTheDocument();
    await condition(user, 1, { value: "a,,b" });
    expect(within(group(1)).getByText(R.builder.problem.list_blank_item)).toBeInTheDocument();
    expect(calls.simulate).toEqual([]);
  });

  it("does not shout about a value box before the admin has tried to preview", async () => {
    const user = await ready_with(THREE);
    await condition(user, 1, { field: "dst_port", value: "x" });
    expect(screen.queryByText(R.builder.problem.not_integer)).not.toBeInTheDocument();
    expect(valueOf(1)).not.toHaveAttribute("aria-invalid", "true");
  });

  it("starts idle, and says nothing is written", async () => {
    await ready_with(THREE);
    expect(within(previewBox()).getByText(R.preview.idle)).toBeInTheDocument();
    expect(within(previewBox()).getByText(R.preview.step)).toBeInTheDocument();
  });

  it("shows a running state while it waits, and disables the button against a second click", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const calls = backend(THREE, {
      simulate: async () => {
        await gate;
        return HttpResponse.json(PREVIEW);
      },
    });
    const user = await ready();
    await user.click(previewButton());
    const running = await within(previewBox()).findByRole("status");
    expect(running).toHaveTextContent(R.preview.running);
    const busy = within(builder()).getByRole("button", { name: R.builder.previewing });
    expect(busy).toBeDisabled();
    await user.click(busy);
    expect(calls.simulate).toHaveLength(1);
    release();
    await within(previewBox()).findByText(R.preview.clusters);
    expect(within(previewBox()).queryByRole("status")).not.toBeInTheDocument();
  });

  it("sends one preview for two clicks of the button in the same tick, before it is disabled", async () => {
    const calls = backend(THREE);
    await ready();
    clickTwiceInOneTick(previewButton());
    await within(previewBox()).findByText(R.preview.clusters);
    expect(calls.simulate).toHaveLength(1);
  });

  it("can preview again after a failed preview: the latch is released", async () => {
    let fail = true;
    const calls = backend(THREE, {
      simulate: () => (fail ? detail("boom", 500) : HttpResponse.json(PREVIEW)),
    });
    const user = await ready();
    await user.click(previewButton());
    await within(previewBox()).findByRole("alert");
    fail = false;
    await user.click(previewButton());
    await within(previewBox()).findByText(R.preview.clusters);
    expect(calls.simulate).toHaveLength(2);
  });

  it("shows the clusters and the alerts, with thousands separated the Vietnamese way", async () => {
    await ready_with(THREE);
    const user = userEvent.setup();
    await user.click(previewButton());
    const box = previewBox();
    const tile = (label: string) =>
      (within(box).getByText(label).closest("div") as HTMLElement).textContent;
    expect(tile(R.preview.clusters)).toBe(`${R.preview.clusters}37`);
    expect(tile(R.preview.alerts)).toBe(`${R.preview.alerts}1.204`);
  });

  it("shows the split by severity and by asset criticality, each as its codes and counts", async () => {
    const user = await ready_with(THREE);
    await user.click(previewButton());
    const box = previewBox();
    const split = (title: string) =>
      within(within(box).getByRole("heading", { name: title }).parentElement as HTMLElement)
        .getAllByRole("listitem")
        .map((li) => li.textContent);
    // worst first: medium before low, whatever order the server's object came in
    expect(split(R.preview.bySeverity)).toEqual(["medium15", "low22"]);
    expect(split(R.preview.byAsset)).toEqual(["low30", "medium7"]);
  });

  it("orders severities from the worst down, with a code it does not know last", async () => {
    backend(THREE, {
      simulate: () =>
        HttpResponse.json({
          ...PREVIEW,
          by_severity: { weird: 1, low: 2, critical: 3, medium: 4, high: 5 },
        }),
    });
    const user = await ready();
    await user.click(previewButton());
    const list = within(
      within(previewBox()).getByRole("heading", { name: R.preview.bySeverity })
        .parentElement as HTMLElement,
    ).getAllByRole("listitem");
    expect(list.map((li) => li.textContent)).toEqual([
      "critical3",
      "high5",
      "medium4",
      "low2",
      "weird1",
    ]);
  });

  it("links each sample to /alerts/:id, encoded, and shows no more than twenty", async () => {
    const samples = Array.from({ length: 25 }, (_, i) => `1727401${String(i).padStart(3, "0")}.66`);
    samples[0] = "a/b c?d";
    backend(THREE, { simulate: () => HttpResponse.json({ ...PREVIEW, samples }) });
    const user = await ready();
    await user.click(previewButton());
    const links = await within(previewBox()).findAllByRole("link");
    expect(links).toHaveLength(20);
    expect(links[0]).toHaveTextContent("a/b c?d");
    expect(links[0]).toHaveAttribute("href", "/alerts/a%2Fb%20c%3Fd");
    expect(links[1]).toHaveAttribute("href", "/alerts/1727401001.66");
    expect(
      within(previewBox()).getByRole("heading", { name: R.preview.samples }),
    ).toBeInTheDocument();
  });

  it("shows no sample list when there are no samples", async () => {
    backend(THREE, { simulate: () => HttpResponse.json({ ...PREVIEW, samples: [] }) });
    const user = await ready();
    await user.click(previewButton());
    await within(previewBox()).findByText(R.preview.clusters);
    expect(within(previewBox()).queryByRole("link")).not.toBeInTheDocument();
  });

  it("shows a hostile code and sample as text", async () => {
    backend(THREE, {
      simulate: () =>
        HttpResponse.json({
          ...PREVIEW,
          by_severity: { "<b>x</b>": 1 },
          samples: ["<img src=x onerror=alert(1)>"],
        }),
    });
    const user = await ready();
    await user.click(previewButton());
    expect(
      await within(previewBox()).findByText("<img src=x onerror=alert(1)>"),
    ).toBeInTheDocument();
    expect(document.body.querySelector("img, b")).toBeNull();
  });
});

describe("a preview that closes nothing: the tally", () => {
  const previewWith = async (result: SimulateResult) => {
    backend(THREE, { simulate: () => HttpResponse.json(result) });
    const user = await ready();
    await user.click(previewButton());
    await within(previewBox()).findByText(R.preview.clusters);
    return user;
  };

  it("says how many clusters matched and that all of them were hard-blocked, with the count of each block", async () => {
    await previewWith(
      ZERO({ matched: 12, blocks: blocks({ asset_high: 8, identity_privileged: 4 }) }),
    );
    const box = previewBox();
    expect(within(box).getByText("Rule khớp 12 cụm nhưng cả 12 bị chặn cứng:")).toBeInTheDocument();
    expect(R.preview.tallyMatched("12")).toBe("Rule khớp 12 cụm nhưng cả 12 bị chặn cứng:");
    const items = within(box)
      .getAllByRole("listitem")
      .map((li) => li.textContent);
    expect(items).toEqual([
      `${S.admin.hardBlock.asset_high}: 8`,
      `${S.admin.hardBlock.identity_privileged}: 4`,
    ]);
    expect(within(box).getByText(R.preview.tallyNote)).toBeInTheDocument();
  });

  it("keeps the order of the server (largest first) and leaves out the blocks that stopped none", async () => {
    await previewWith(
      ZERO({
        matched: 11,
        blocks: [
          { code: "ioc_bad", count: 6 },
          { code: "critical", count: 3 },
          { code: "asset_high", count: 2 },
          { code: "never_autoclose_agent", count: 0 },
          { code: "asset_not_in_inventory", count: 0 },
          { code: "identity_privileged", count: 0 },
        ],
      }),
    );
    expect(
      within(previewBox())
        .getAllByRole("listitem")
        .map((li) => li.textContent),
    ).toEqual([
      `${S.admin.hardBlock.ioc_bad}: 6`,
      `${S.admin.hardBlock.critical}: 3`,
      `${S.admin.hardBlock.asset_high}: 2`,
    ]);
  });

  it("never shows matched minus the sum of the counts: only what the server counted", async () => {
    await previewWith(ZERO({ matched: 12, blocks: blocks({ asset_high: 8, ioc_bad: 3 }) }));
    const box = previewBox();
    // 12 - (8 + 3) = 1 would be a made-up number: it appears nowhere in the tally
    expect(within(box).getAllByRole("listitem")).toHaveLength(2);
    expect(within(box).queryByText(/: 1$/)).not.toBeInTheDocument();
    expect(box.textContent).toContain("Rule khớp 12 cụm nhưng cả 12 bị chặn cứng:");
  });

  it("says no cluster matched when matched is 0", async () => {
    await previewWith(ZERO({ matched: 0, blocks: blocks({}) }));
    expect(within(previewBox()).getByText(R.preview.tallyNone)).toBeInTheDocument();
    expect(R.preview.tallyNone).toBe("Rule không khớp cụm nào trong 30 ngày qua.");
    expect(within(previewBox()).queryByRole("listitem")).not.toBeInTheDocument();
    expect(within(previewBox()).getByText(R.preview.tallyNote)).toBeInTheDocument();
  });

  it("says no cluster matched when the tally is null", async () => {
    await previewWith(ZERO(null));
    expect(within(previewBox()).getByText(R.preview.tallyNone)).toBeInTheDocument();
    expect(within(previewBox()).queryByText(/chặn cứng:/)).not.toBeInTheDocument();
  });

  it("shows no tally when the rule closes clusters", async () => {
    await previewWith({ ...PREVIEW, hard_block_tally: null });
    expect(within(previewBox()).queryByText(R.preview.tallyNone)).not.toBeInTheDocument();
    expect(within(previewBox()).queryByText(R.preview.tallyNote)).not.toBeInTheDocument();
    expect(within(previewBox()).queryByText(/bị chặn cứng:/)).not.toBeInTheDocument();
  });

  it("does not show a tally for a rule that closes clusters even if the server sent one", async () => {
    await previewWith({
      ...PREVIEW,
      hard_block_tally: { matched: 50, blocks: blocks({ asset_high: 13 }) },
    });
    expect(within(previewBox()).queryByText(/bị chặn cứng:/)).not.toBeInTheDocument();
  });
});

describe("Tạo rule: only for the conditions last previewed", () => {
  it("is disabled before any preview, and says why", async () => {
    await ready_with(THREE);
    expect(createButton()).toBeDisabled();
    expect(within(builder()).getByText(R.builder.hintIdle)).toBeInTheDocument();
    expect(createButton().getAttribute("aria-describedby")).toBeTruthy();
  });

  it("stays disabled after a preview until the rule has a name and a reason", async () => {
    const user = await ready_with(THREE);
    await previewed(user);
    expect(createButton()).toBeDisabled();
    expect(within(builder()).getByText(R.builder.hintNeedText)).toBeInTheDocument();
    await user.type(nameBox(), "Tên");
    expect(createButton()).toBeDisabled();
    await user.type(reasonBox(), "   ");
    expect(createButton()).toBeDisabled();
    await user.type(reasonBox(), "Lý do");
    expect(createButton()).toBeEnabled();
    expect(within(builder()).getByText(R.builder.hintReady)).toBeInTheDocument();
  });

  it("is enabled for the exact conditions previewed", async () => {
    const user = await ready_with(THREE);
    await fillNameAndReason(user);
    expect(createButton()).toBeDisabled();
    await previewed(user);
    expect(createButton()).toBeEnabled();
  });

  const EDITS: [string, (user: User) => Promise<void>][] = [
    ["the value", (user) => condition(user, 1, { value: "recon2" })],
    ["the field", (user) => condition(user, 1, { field: "decoder" })],
    ["the operator", (user) => condition(user, 1, { op: "in" })],
    [
      "a new condition",
      async (user) => {
        await user.click(within(builder()).getByRole("button", { name: R.builder.add }));
      },
    ],
    [
      "the removal of the only condition",
      async (user) => {
        await user.click(within(group(1)).getByRole("button", { name: R.builder.remove }));
      },
    ],
  ];

  it.each(EDITS)(
    "is disabled again by an edit of %s, until the next preview",
    async (_what, edit) => {
      const calls = backend(THREE);
      const user = await ready();
      await fillNameAndReason(user);
      await previewed(user);
      expect(createButton()).toBeEnabled();
      await edit(user);
      expect(createButton()).toBeDisabled();
      expect(within(builder()).getByText(R.builder.hintStale)).toBeInTheDocument();
      expect(within(previewBox()).getByText(R.preview.stale)).toBeInTheDocument();
      await user.click(createButton());
      expect(calls.create).toEqual([]);
      // the next preview opens it again
      await user.click(previewButton());
      await waitFor(() => expect(calls.simulate).toHaveLength(2));
      await waitFor(() => expect(createButton()).toBeEnabled());
      expect(within(previewBox()).queryByText(R.preview.stale)).not.toBeInTheDocument();
    },
  );

  it("is disabled by an edit that makes a row invalid, and by one that is reverted it is enabled again", async () => {
    const user = await ready_with(THREE);
    await fillNameAndReason(user);
    await previewed(user);
    await user.type(valueOf(1), "x");
    expect(createButton()).toBeDisabled();
    await user.type(valueOf(1), "{Backspace}");
    expect(valueOf(1)).toHaveValue("recon");
    expect(createButton()).toBeEnabled();
  });

  it("is not disabled by editing the name or the reason", async () => {
    const user = await ready_with(THREE);
    await fillNameAndReason(user);
    await previewed(user);
    await user.type(nameBox(), " mới");
    await user.type(reasonBox(), " mới");
    expect(createButton()).toBeEnabled();
  });

  it("stays disabled when a preview fails, even for conditions that were once previewed", async () => {
    let fail = false;
    const calls = backend(THREE, {
      simulate: () => (fail ? detail("boom", 500) : HttpResponse.json(PREVIEW)),
    });
    const user = await ready();
    await fillNameAndReason(user);
    await previewed(user);
    expect(createButton()).toBeEnabled();
    fail = true;
    await user.click(previewButton());
    await within(previewBox()).findByRole("alert");
    expect(createButton()).toBeDisabled();
    expect(calls.create).toEqual([]);
  });

  it("is disabled when the edit lands while the preview is still out, and the late answer does not open it", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    backend(THREE, {
      simulate: async () => {
        await gate;
        return HttpResponse.json(PREVIEW);
      },
    });
    const user = await ready();
    await fillNameAndReason(user);
    await condition(user, 1, { field: "category", value: "recon" });
    await user.click(previewButton());
    await within(previewBox()).findByRole("status");
    await condition(user, 1, { value: "recon-edited" });
    release();
    await within(previewBox()).findByText(R.preview.clusters);
    expect(createButton()).toBeDisabled();
    expect(within(previewBox()).getByText(R.preview.stale)).toBeInTheDocument();
  });

  it("creates the rule: POST {name, reason, match} as JSON, with the previewed conditions", async () => {
    const calls = backend(THREE);
    const user = await ready();
    await condition(user, 1, { field: "dst_port", op: "in", value: "53, 123" });
    await user.click(previewButton());
    await within(previewBox()).findByText(R.preview.clusters);
    await user.type(nameBox(), "  Quét DNS  ");
    await user.type(reasonBox(), " Máy giám sát ");
    await user.click(createButton());
    await waitFor(() => expect(calls.create).toHaveLength(1));
    expect(calls.create).toEqual([
      {
        name: "Quét DNS",
        reason: "Máy giám sát",
        match: [{ field: "dst_port", op: "in", value: [53, 123] }],
      },
    ]);
    expect(calls.writes.at(-1)).toBe("application/json");
  });

  it("says the rule was created, reads the list again, and starts a clean form", async () => {
    const calls = backend(THREE);
    const user = await ready();
    await fillNameAndReason(user, "Quét cổng nội bộ", "Máy giám sát quét theo lịch");
    await previewed(user, "scan");
    await user.click(createButton());
    expect(await screen.findByRole("status")).toHaveTextContent(
      R.builder.created("Quét cổng nội bộ"),
    );
    await waitFor(() => expect(calls.list).toBe(2));
    expect(await rowOf("Quét cổng nội bộ")).toBeInTheDocument();
    expect(screen.getByText(R.subtitle(4, 3))).toBeInTheDocument();
    // the form is empty again, with one blank condition, and nothing previewed
    expect(nameBox()).toHaveValue("");
    expect(reasonBox()).toHaveValue("");
    expect(valueOf(1)).toHaveValue("");
    expect(within(previewBox()).getByText(R.preview.idle)).toBeInTheDocument();
    expect(createButton()).toBeDisabled();
  });

  it("is busy while the create is in flight, and sends one request however often it is clicked", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const calls = backend(THREE, {
      create: async () => {
        await gate;
        return HttpResponse.json({ rule_id: uuid(9), name: "x", enabled: true }, { status: 201 });
      },
    });
    const user = await ready();
    await fillNameAndReason(user);
    await previewed(user);
    await user.click(createButton());
    const busy = await within(builder()).findByRole("button", { name: R.builder.submitting });
    expect(busy).toBeDisabled();
    await user.click(busy);
    release();
    await screen.findByRole("status");
    expect(calls.create).toHaveLength(1);
  });

  it("sends one create for two clicks of the button in the same tick, before it is disabled", async () => {
    const calls = backend(THREE);
    const user = await ready();
    await fillNameAndReason(user);
    await previewed(user);
    clickTwiceInOneTick(createButton());
    await screen.findByRole("status");
    expect(calls.create).toHaveLength(1);
  });

  it("can create again after a failed create: the latch is released", async () => {
    let fail = true;
    const calls = backend(THREE, {
      create: (body) => {
        if (fail) return detail("boom", 500);
        const { name } = body as { name: string };
        return HttpResponse.json({ rule_id: uuid(8), name, enabled: true }, { status: 201 });
      },
    });
    const user = await ready();
    await fillNameAndReason(user);
    await previewed(user);
    await user.click(createButton());
    await within(builder()).findByRole("alert");
    fail = false;
    await user.click(createButton());
    await screen.findByRole("status");
    expect(calls.create).toHaveLength(2);
  });

  it.each([
    ["500", () => detail("boom", 500)],
    ["503 (auth disabled)", () => detail("auth disabled: JWT_SECRET unset", 503)],
    ["a network failure", () => HttpResponse.error()],
  ])("keeps the whole form when the create fails: %s", async (_name, create) => {
    const calls = backend(THREE, { create });
    const user = await ready();
    await fillNameAndReason(user);
    await previewed(user);
    await user.click(createButton());
    expect(await within(builder()).findByRole("alert")).toHaveTextContent(R.builder.createFailed);
    expect(nameBox()).toHaveValue("Quét cổng");
    expect(valueOf(1)).toHaveValue("recon");
    expect(createButton()).toBeEnabled();
    expect(calls.list).toBe(1);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("still lets a rule be created when its preview closed nothing, as the canvas says", async () => {
    const calls = backend(THREE, {
      simulate: () => HttpResponse.json(ZERO({ matched: 12, blocks: blocks({ asset_high: 12 }) })),
    });
    const user = await ready();
    await fillNameAndReason(user);
    await previewed(user);
    expect(within(previewBox()).getByText(R.preview.tallyNote)).toBeInTheDocument();
    expect(createButton()).toBeEnabled();
    await user.click(createButton());
    await waitFor(() => expect(calls.create).toHaveLength(1));
  });

  it("says the account may not do it, at the form, on a 403", async () => {
    backend(THREE, { create: () => detail("forbidden", 403) });
    const user = await ready();
    await fillNameAndReason(user);
    await previewed(user);
    await user.click(createButton());
    expect(await within(builder()).findByRole("alert")).toHaveTextContent(S.admin.reason.forbidden);
  });
});

describe("422 at the condition", () => {
  const rejected = () => detail(WHITELIST_TEXT, 422);

  it("shows the whitelist's text under the conditions, keeps every input, and creates nothing", async () => {
    const calls = backend(THREE, { simulate: rejected });
    const user = await ready();
    await fillNameAndReason(user);
    await condition(user, 1, { field: "category", value: "recon" });
    await user.click(previewButton());
    const alert = await within(builder()).findByRole("alert");
    expect(alert).toHaveTextContent(R.builder.conditionRejected);
    expect(alert).toHaveTextContent(WHITELIST_TEXT);
    // at the condition: inside the form's conditions, not in the preview panel
    expect(within(previewBox()).queryByRole("alert")).not.toBeInTheDocument();
    expect(builder().contains(alert)).toBe(true);
    // nothing lost
    expect(nameBox()).toHaveValue("Quét cổng");
    expect(valueOf(1)).toHaveValue("recon");
    expect(createButton()).toBeDisabled();
    expect(calls.create).toEqual([]);
    expect(within(previewBox()).getByText(R.preview.idle)).toBeInTheDocument();
  });

  it("ties the message to the conditions, for a screen reader", async () => {
    backend(THREE, { simulate: rejected });
    const user = await ready();
    await user.click(previewButton());
    const alert = await within(builder()).findByRole("alert");
    const conditions = within(builder()).getByRole("group", { name: R.builder.conditions });
    expect(conditions.getAttribute("aria-describedby")).toContain(alert.id);
  });

  it("shows FastAPI's list-shaped detail too, with each message at its place", async () => {
    backend(THREE, {
      simulate: () =>
        detail(
          [
            {
              type: "list_type",
              loc: ["body", "match"],
              msg: "Input should be a valid list",
              input: {},
            },
            {
              type: "dict_type",
              loc: ["body", "match", 0],
              msg: "Input should be a valid dictionary",
            },
          ],
          422,
        ),
    });
    const user = await ready();
    await user.click(previewButton());
    const alert = await within(builder()).findByRole("alert");
    expect(alert).toHaveTextContent(R.builder.conditionMalformed);
    expect(alert).toHaveTextContent("body.match: Input should be a valid list");
    expect(alert).toHaveTextContent("body.match.0: Input should be a valid dictionary");
  });

  it("shows a list-shaped detail that carries no message as just the sentence", async () => {
    backend(THREE, { simulate: () => detail([{ unexpected: true }, 5, null], 422) });
    const user = await ready();
    await user.click(previewButton());
    const alert = await within(builder()).findByRole("alert");
    expect(alert).toHaveTextContent(R.builder.conditionMalformed);
  });

  it("shows a list of plain texts too (the shape of a refused file, in case a route ever sends it)", async () => {
    backend(THREE, { simulate: () => detail(["first problem", "second problem"], 422) });
    const user = await ready();
    await user.click(previewButton());
    const alert = await within(builder()).findByRole("alert");
    expect(alert).toHaveTextContent("first problem");
    expect(alert).toHaveTextContent("second problem");
  });

  it("shows a hostile detail as text", async () => {
    backend(THREE, {
      simulate: () => detail("<img src=x onerror=alert(1)> simulate: match is outside", 422),
    });
    const user = await ready();
    await user.click(previewButton());
    const alert = await within(builder()).findByRole("alert");
    expect(alert).toHaveTextContent("<img src=x onerror=alert(1)> simulate: match is outside");
    expect(alert.querySelector("img")).toBeNull();
  });

  it("takes the message away when the conditions are edited, and brings it back for the same ones", async () => {
    const calls = backend(THREE, { simulate: rejected });
    const user = await ready();
    await user.click(previewButton());
    await within(builder()).findByRole("alert");
    await user.type(valueOf(1), "x");
    expect(within(builder()).queryByRole("alert")).not.toBeInTheDocument();
    await user.type(valueOf(1), "{Backspace}");
    expect(within(builder()).getByRole("alert")).toHaveTextContent(R.builder.conditionRejected);
    expect(calls.simulate).toHaveLength(1);
  });

  it("answers a 422 on the create itself at the condition too, and leaves the form as it was", async () => {
    const calls = backend(THREE, { create: rejected });
    const user = await ready();
    await fillNameAndReason(user);
    await previewed(user);
    await user.click(createButton());
    const alert = await within(builder()).findByRole("alert");
    expect(alert).toHaveTextContent(R.builder.conditionRejected);
    expect(alert).toHaveTextContent(WHITELIST_TEXT);
    expect(nameBox()).toHaveValue("Quét cổng");
    expect(valueOf(1)).toHaveValue("recon");
    expect(calls.list).toBe(1);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("answers a 422 on a create with FastAPI's list at the condition as well", async () => {
    backend(THREE, {
      create: () =>
        detail([{ type: "missing", loc: ["body", "name"], msg: "Field required" }], 422),
    });
    const user = await ready();
    await fillNameAndReason(user);
    await previewed(user);
    await user.click(createButton());
    const alert = await within(builder()).findByRole("alert");
    expect(alert).toHaveTextContent(R.builder.conditionMalformed);
    expect(alert).toHaveTextContent("body.name: Field required");
  });
});

describe("a preview that fails for another reason", () => {
  it.each([
    ["500", () => detail("boom", 500)],
    ["503 (auth disabled)", () => detail("auth disabled: JWT_SECRET unset", 503)],
    ["a network failure", () => HttpResponse.error()],
  ])("fails alone, in the preview panel, on %s", async (_name, simulate) => {
    const calls = backend(THREE, { simulate });
    const user = await ready();
    await fillNameAndReason(user);
    await condition(user, 1, { field: "category", value: "recon" });
    await user.click(previewButton());
    const alert = await within(previewBox()).findByRole("alert");
    expect(alert).toHaveTextContent(R.builder.previewFailed);
    // the table, the hard blocks and the form are untouched
    expect(await tableOf()).toBeInTheDocument();
    expect(within(hardBlockBox()).getAllByRole("listitem")).toHaveLength(6);
    expect(nameBox()).toHaveValue("Quét cổng");
    expect(valueOf(1)).toHaveValue("recon");
    expect(within(builder()).queryByRole("alert")).not.toBeInTheDocument();
    expect(createButton()).toBeDisabled();
    expect(calls.list).toBe(1);
    // and a second try can succeed
    server.use(http.post(SIMULATE_URL, () => HttpResponse.json(PREVIEW)));
    await user.click(previewButton());
    await within(previewBox()).findByText(R.preview.clusters);
    expect(within(previewBox()).queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says a 403 in the account's own words", async () => {
    backend(THREE, { simulate: () => detail("forbidden", 403) });
    const user = await ready();
    await user.click(previewButton());
    expect(await within(previewBox()).findByRole("alert")).toHaveTextContent(
      S.admin.reason.forbidden,
    );
  });
});

describe("accessibility and the CSP", () => {
  const axeOf = async (container: HTMLElement) => {
    // jsdom computes no layout or colour, so the contrast rule cannot run here.
    const result = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
    return result.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target).join(" ")}`);
  };

  it("has no axe violation: the normal page", async () => {
    backend(THREE);
    const { container } = renderPage();
    await tableOf();
    expect(await axeOf(container)).toEqual([]);
  });

  it("has no axe violation: loading", async () => {
    backend(THREE, { list: () => new Promise<Response>(() => {}) });
    const { container } = renderPage();
    expect(screen.getByRole("status")).toBeInTheDocument();
    expect(await axeOf(container)).toEqual([]);
  });

  it("has no axe violation: a failed list", async () => {
    backend(THREE, { list: () => detail("boom", 500) });
    const { container } = renderPage();
    await screen.findByText(R.loadFailed);
    expect(await axeOf(container)).toEqual([]);
  });

  it("has no axe violation: no rules", async () => {
    backend([]);
    const { container } = renderPage();
    await screen.findByText(R.empty.title);
    expect(await axeOf(container)).toEqual([]);
  });

  it("has no axe violation: the toggle dialog, and the 404 notice after it", async () => {
    backend(THREE, { toggle: () => detail("rule not found", 404) });
    const user = userEvent.setup();
    const { container } = renderPage();
    await user.click(
      within(await rowOf(LAB.name)).getByRole("button", { name: R.table.turnOffLabel(LAB.name) }),
    );
    const dialog = await screen.findByRole("dialog");
    expect(await axeOf(container)).toEqual([]);
    await user.click(within(dialog).getByRole("button", { name: R.toggle.offConfirm }));
    await screen.findByRole("alert");
    expect(await axeOf(container)).toEqual([]);
  });

  it("has no axe violation: a builder with errors, and after a 422", async () => {
    backend(THREE, { simulate: () => detail(WHITELIST_TEXT, 422) });
    const user = await ready();
    await user.click(within(builder()).getByRole("button", { name: R.builder.add }));
    await condition(user, 1, { field: "dst_port", value: "x" });
    await condition(user, 2, { field: "asset_criticality", value: "high" });
    await user.click(previewButton());
    expect(await axeOf(document.body)).toEqual([]);
    await condition(user, 1, { value: "443" });
    await user.click(previewButton());
    await within(builder()).findByRole("alert");
    expect(await axeOf(document.body)).toEqual([]);
  });

  it("has no axe violation: a preview with results, a stale one, and the tally", async () => {
    const user = await ready_with(THREE);
    await user.click(previewButton());
    await within(previewBox()).findByText(R.preview.clusters);
    expect(await axeOf(document.body)).toEqual([]);
    await user.type(valueOf(1), "x");
    expect(await axeOf(document.body)).toEqual([]);
    server.use(
      http.post(SIMULATE_URL, () =>
        HttpResponse.json(ZERO({ matched: 3, blocks: blocks({ asset_high: 3 }) })),
      ),
    );
    await user.click(previewButton());
    await within(previewBox()).findByText(R.preview.tallyMatched("3"));
    expect(await axeOf(document.body)).toEqual([]);
  });

  it("puts no style attribute anywhere, in any state (the CSP forbids it)", async () => {
    const user = await ready_with(THREE);
    expect(document.body.querySelector("[style]")).toBeNull();
    await user.click(previewButton());
    await within(previewBox()).findByText(R.preview.clusters);
    expect(document.body.querySelector("[style]")).toBeNull();
    await user.click(
      within(await rowOf(LAB.name)).getByRole("button", { name: R.table.turnOffLabel(LAB.name) }),
    );
    await screen.findByRole("dialog");
    expect(document.body.querySelector("[style]")).toBeNull();
  });
});
