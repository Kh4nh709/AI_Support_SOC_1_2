// src/features/soar/SoarPage.safety.test.tsx — what n8n sends is TEXT. Hostile strings in every field a ticket carries (markup,
// event handlers, javascript: text, very long values) are shown as the characters they are: nothing is interpreted,
// nothing becomes a link, a class, an attribute that runs or an inline style, and a long value wraps inside its cell. Also
// the accessibility of the page's states (axe), and the contrast of the colours it uses against the tokens.
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { setupServer } from "msw/node";
import { afterEach } from "vitest";
import { S } from "../../strings";
import { detailOf, notice, review } from "./fixtures";
import { fake, renderSoar, serve } from "./testkit";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => {
  server.resetHandlers();
  delete (window as unknown as { __pwned?: unknown }).__pwned;
});
afterAll(() => server.close());

const IMG = '<img src=x onerror="window.__pwned=1">';
const SCRIPT = "<script>window.__pwned=1</script>";
const JS = "javascript:window.__pwned=1";
const LONG = "A".repeat(5000);

const hostile = () =>
  review({
    id: "H0STILE1",
    title: IMG,
    case_id: JS,
    action_text: `${SCRIPT}${LONG}`,
    action_target: JS,
    host: "<svg onload=window.__pwned=1>",
    scenario_name: LONG,
    scenario_id: IMG,
    user_name: `"><a href="javascript:window.__pwned=1">x</a>`,
    note: `${IMG}${LONG}`,
    result: IMG,
    decided_by: IMG,
    last_error: `<a href="javascript:window.__pwned=1">bấm vào</a>`,
    locked_by: JS,
    buttons: [
      { decision: "keep", label: `<b onclick="window.__pwned=1">Giữ</b>` },
      { decision: "undo", label: `${LONG}` },
    ],
    allowed_decisions: ["keep", "undo"],
    strong_warning: true,
  });

/** Everything that ran or linked would show up here. */
function expectInert(container: HTMLElement) {
  expect(
    container.querySelector("img, script, svg, iframe, object, embed, form[action], b, i, style"),
  ).toBeNull();
  expect((window as unknown as { __pwned?: unknown }).__pwned).toBeUndefined();
  for (const el of container.querySelectorAll("*")) {
    for (const name of el.getAttributeNames()) {
      expect(name.startsWith("on"), `${el.tagName} ${name}`).toBe(false);
      expect(
        ["style", "srcdoc", "formaction", "src", "srcset"].includes(name),
        `${el.tagName} ${name}`,
      ).toBe(false);
    }
  }
  for (const a of container.querySelectorAll("a")) {
    const href = a.getAttribute("href") ?? "";
    expect(href.startsWith("/"), href).toBe(true);
    expect(href).not.toMatch(/javascript:/i);
  }
}

describe("the table", () => {
  it("shows every hostile value as the text it is, and builds nothing from it", async () => {
    serve(
      server,
      fake({
        rows: [hostile()],
        notices: [notice({ id: "N1", title: IMG, note: JS, host: SCRIPT })],
      }),
    );
    const { container } = renderSoar();
    await screen.findByRole("button", { name: S.soar.detail.open("H0STILE1") });
    await screen.findByRole("region", { name: S.soar.notice.heading });
    expect(screen.getAllByText(IMG).length).toBeGreaterThan(0);
    expect(screen.getByText(`<b onclick="window.__pwned=1">Giữ</b>`)).toBeInTheDocument();
    expect(screen.getByText(/bấm vào/)).toBeInTheDocument();
    expectInert(container);
  });

  it("lets a long value wrap inside its cell, and scroll the table, never the page", async () => {
    serve(server, fake({ rows: [hostile()] }));
    const { container } = renderSoar();
    const row = (
      await screen.findByRole("button", { name: S.soar.detail.open("H0STILE1") })
    ).closest("tr") as HTMLElement;
    const cells = within(row).getAllByRole("cell");
    // id, scenario, host, target, action, status, buttons: the cells that hold what n8n wrote
    for (const at of [0, 3, 4, 5, 6, 8, 9]) {
      expect(cells[at]?.className, `cell ${at}`).toContain("wrap-anywhere");
      expect(cells[at]?.className, `cell ${at}`).toMatch(/max-w-/);
    }
    expect(container.querySelector("table")?.parentElement?.className).toContain("overflow-x-auto");
    // the buttons wrap their label too
    const long = within(row).getByRole("button", { name: LONG });
    expect(long.className).toContain("wrap-anywhere");
    expect(long.className).toContain("max-w-");
  });

  it("opens the detail of a hostile ticket: its fields, its history, its raw body and its alerts are text", async () => {
    const state = fake({ rows: [hostile()] });
    state.detail = () =>
      detailOf({
        ...hostile(),
        raw: { title: IMG, nested: { x: SCRIPT } },
        history: [
          {
            at: "2026-11-13T14:45:00+00:00",
            event: IMG,
            actor: SCRIPT,
            actor_role: JS,
            payload: {
              decision: IMG,
              note: IMG,
              outcome: SCRIPT,
              status_before: JS,
              status_after: IMG,
              message: `${IMG}${LONG}`,
            },
          },
        ],
        related_alerts: [
          {
            alert_id: `x"><img src=x onerror=window.__pwned=1>`,
            alert_time: "2026-11-13T14:30:00+00:00",
            agent_name: IMG,
            description: `${IMG}${LONG}`,
            severity: IMG,
            status: JS,
            occurrence_count: 1,
          },
        ],
        related_total: 1,
      });
    serve(server, state);
    const { container } = renderSoar();
    await userEvent.click(
      await screen.findByRole("button", { name: S.soar.detail.open("H0STILE1") }),
    );
    const panel = await screen.findByRole("region", { name: S.soar.detail.title("H0STILE1") });
    await within(panel).findByRole("link", { name: `${IMG}${LONG}` });
    const raw = panel.querySelector("details pre");
    expect(raw?.textContent).toContain(SCRIPT);
    expectInert(container);
    const link = within(panel).getByRole("link", { name: `${IMG}${LONG}` });
    expect(link.getAttribute("href")).toBe(
      `/alerts/${encodeURIComponent(`x"><img src=x onerror=window.__pwned=1>`)}`,
    );
    expect(panel.className).toMatch(/overflow|min-w-0|wrap-anywhere|break-words/);
  });

  it("opens the dialog of a hostile ticket with its text as text", async () => {
    serve(server, fake({ rows: [hostile()] }));
    const { container } = renderSoar();
    const row = (
      await screen.findByRole("button", { name: S.soar.detail.open("H0STILE1") })
    ).closest("tr") as HTMLElement;
    await userEvent.click(within(row).getByRole("button", { name: LONG }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent(S.soar.dialog.strong.undo("<svg onload=window.__pwned=1>"));
    expectInert(container);
  });
});

describe("an id that is a name of the prototype chain", () => {
  it("draws its row, its buttons and its detail like any other, and no state leaks from the prototype", async () => {
    serve(server, fake({ rows: [review({ id: "__proto__" }), review({ id: "constructor" })] }));
    renderSoar();
    for (const id of ["__proto__", "constructor"]) {
      const row = (await screen.findByRole("button", { name: S.soar.detail.open(id) })).closest(
        "tr",
      ) as HTMLElement;
      expect(within(row).getByRole("button", { name: "✅ Giữ chặn" })).toBeEnabled();
      expect(within(row).queryByText(S.soar.working)).not.toBeInTheDocument();
    }
  });
});

describe("the sources", () => {
  const dir = join("src", "features", "soar");
  const sources = readdirSync(dir)
    .filter(
      (name) =>
        /\.(ts|tsx)$/.test(name) &&
        !/\.test\./.test(name) &&
        name !== "testkit.tsx" &&
        name !== "fixtures.ts",
    )
    .map((name) => [name, readFileSync(join(dir, name), "utf8")] as const);
  const code = (text: string) =>
    text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

  it("reads the files of the page (a guard over none would pass for nothing)", () => {
    expect(sources.map(([name]) => name)).toEqual(
      expect.arrayContaining([
        "SoarPage.tsx",
        "DetailPanel.tsx",
        "RowActions.tsx",
        "DecisionDialog.tsx",
        "Notices.tsx",
        "storage.ts",
        "signal.ts",
      ]),
    );
  });

  it("has no dangerouslySetInnerHTML, no inline style, no href, no innerHTML and no eval", () => {
    for (const [name, text] of sources) {
      const c = code(text);
      expect(c, name).not.toMatch(
        /dangerouslySetInnerHTML|innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\s*\(|new Function/,
      );
      expect(c, name).not.toMatch(/\bstyle\s*=\s*[{"']/);
      expect(c, name).not.toMatch(/\bhref\s*=/);
      expect(c, name).not.toMatch(/\bsrc\s*=/);
      expect(c, name).not.toMatch(/window\.open|location\.(href|assign|replace)/);
    }
  });

  /** The expression of every `to={...}` attribute of a piece of code, found by matching its braces (not by its layout). */
  const targetsOf = (source: string): string[] => {
    const found: string[] = [];
    for (const start of source.matchAll(/\bto=\{/g)) {
      let depth = 1;
      let at = (start.index ?? 0) + start[0].length;
      const from = at;
      while (at < source.length && depth > 0) {
        if (source[at] === "{") depth += 1;
        else if (source[at] === "}") depth -= 1;
        at += 1;
      }
      found.push(source.slice(from, at - 1).trim());
    }
    return found;
  };

  it("finds the `to` of a link by its braces, however it is laid out", () => {
    expect(targetsOf("<Link to={{ search: a({ b: 1 }) }} x>")).toEqual(["{ search: a({ b: 1 }) }"]);
    expect(targetsOf("<Link\n  to={`/x/${f(y)}`}\n>")).toEqual(["`/x/${f(y)}`"]);
  });

  it("makes a link in two places only: to a view of this page, and to its own alert page with the id encoded", () => {
    const targets = sources.flatMap(([name, text]) =>
      targetsOf(code(text)).map((target) => ({ name, target })),
    );
    expect(targets.length).toBeGreaterThanOrEqual(3);
    const alerts = targets.filter((t) => t.target.includes("/alerts/"));
    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.name).toBe("DetailPanel.tsx");
    expect(alerts[0]?.target).toContain("encodeURIComponent(");
    for (const t of targets.filter((t) => !t.target.includes("/alerts/"))) {
      expect(t.target, `${t.name}: ${t.target}`).toMatch(/^\{ search: viewSearch\(/);
    }
  });
});

describe("accessibility", () => {
  const violationsIn = async (container: HTMLElement) =>
    (await axe.run(container, { rules: { "color-contrast": { enabled: false } } })).violations.map(
      (v) => `${v.id}: ${v.nodes.map((n) => n.html).join(" | ")}`,
    );

  const mixed = () => [
    review(),
    review({
      id: "KEPT0001",
      status: "kept",
      allowed_decisions: ["undo"],
      decided_by: "an",
      result: "Đã giữ",
    }),
    review({ id: "PROC0001", status: "processing", locked_by: "binh", allowed_decisions: [] }),
    review({ id: "SIMU0001", simulated: true, score: 85, last_error: "Hết thời gian chờ" }),
    review({
      id: "HOLD0001",
      action_type: "isolate_host",
      remind_every_minutes: 30,
      next_remind_at: "2026-11-13T14:00:00+00:00",
      strong_warning: true,
    }),
    review({ id: "LATE0001", auto_expire_at: "2026-11-13T14:00:00+00:00", score: null }),
  ];

  it("has no axe violation on the list, with every state of a row, a notice strip and the switch", async () => {
    serve(
      server,
      fake({
        rows: mixed(),
        notices: [
          notice({ id: "N1", severity: "error" }),
          notice({ id: "N2", severity: "warning" }),
          notice({ id: "N3" }),
        ],
      }),
    );
    const { container } = renderSoar();
    await screen.findByRole("button", { name: S.soar.detail.open("HOLD0001") });
    await screen.findByRole("region", { name: S.soar.notice.heading });
    expect(await violationsIn(container)).toEqual([]);
  });

  it("has none on the empty list, the error state and the notices tab", async () => {
    serve(server, fake());
    const empty = renderSoar();
    await screen.findByText(S.soar.empty.open);
    expect(await violationsIn(empty.container)).toEqual([]);
    empty.unmount();
    const broken = fake();
    broken.list = () => new Response(JSON.stringify({ detail: "x" }), { status: 500 });
    serve(server, broken);
    const failed = renderSoar();
    await screen.findByRole("alert");
    expect(await violationsIn(failed.container)).toEqual([]);
    failed.unmount();
    serve(server, fake({ notices: [notice({ id: "N1", severity: "error" })] }));
    const notices = renderSoar({ entry: "/soar?tab=notice" });
    await screen.findByRole("table", { name: S.soar.noticeTableLabel });
    expect(await violationsIn(notices.container)).toEqual([]);
  });

  it("has none with the dialog open, plain and strong", async () => {
    serve(server, fake({ rows: mixed() }));
    const { container } = renderSoar();
    const plain = (
      await screen.findByRole("button", { name: S.soar.detail.open("K7QM2XHP") })
    ).closest("tr") as HTMLElement;
    await userEvent.click(within(plain).getByRole("button", { name: "↩️ Gỡ chặn IP" }));
    await screen.findByRole("dialog");
    expect(await violationsIn(container)).toEqual([]);
    await userEvent.keyboard("{Escape}");
    const strong = (
      await screen.findByRole("button", { name: S.soar.detail.open("HOLD0001") })
    ).closest("tr") as HTMLElement;
    await userEvent.click(within(strong).getByRole("button", { name: "↩️ Gỡ chặn IP" }));
    await screen.findByRole("dialog", { name: S.soar.dialog.title.undoStrong });
    expect(await violationsIn(container)).toEqual([]);
  });

  it("has none with the detail panel open, history, alerts and raw body", async () => {
    const state = fake({ rows: mixed() });
    state.detail = () =>
      detailOf({
        history: [
          {
            at: "2026-11-13T14:40:05+00:00",
            event: "soar.review_received",
            actor: "system",
            actor_role: null,
            payload: { event: "created", outcome: "created", status: "open" },
          },
          {
            at: "2026-11-13T14:45:00+00:00",
            event: "soar.review_decided",
            actor: "an",
            actor_role: "tier2",
            payload: {
              decision: "undo",
              outcome: "failed",
              status_before: "open",
              status_after: "open",
              message: "x",
            },
          },
        ],
        related_alerts: [
          {
            alert_id: "a1",
            alert_time: "2026-11-13T14:30:00+00:00",
            agent_name: "h1",
            description: "d1",
            severity: "high",
            status: "queued_tier1",
            occurrence_count: 1,
          },
        ],
        related_total: 3,
      });
    serve(server, state);
    const { container } = renderSoar();
    await userEvent.click(
      await screen.findByRole("button", { name: S.soar.detail.open("K7QM2XHP") }),
    );
    const panel = await screen.findByRole("region", { name: S.soar.detail.title("K7QM2XHP") });
    await within(panel).findByRole("link", { name: "d1" });
    await waitFor(() =>
      expect(within(panel).getByText(S.soar.detail.history.heading)).toBeInTheDocument(),
    );
    expect(await violationsIn(container)).toEqual([]);
  });

  it("has a main heading, named tables and labelled controls, so a screen reader can find its way", async () => {
    serve(server, fake({ rows: mixed() }));
    renderSoar();
    await screen.findByRole("button", { name: S.soar.detail.open("K7QM2XHP") });
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    expect(screen.getByRole("table", { name: S.soar.tableLabel })).toBeInTheDocument();
    expect(screen.getByRole("searchbox", { name: S.soar.search.label })).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: S.soar.signal.label })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: S.soar.tabs.label })).toBeInTheDocument();
  });
});
