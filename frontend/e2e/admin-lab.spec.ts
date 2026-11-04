// The lab labelling pages on the real stack (P14-T10, DEC-213, spec §6): an admin records a lab run around three real
// alerts, labels two of them TP and FP, reloads and still sees both labels, takes one off; a window that overlaps the
// run is refused in words; and the page never shows ① — not on the page, not in any answer of the API it received,
// though ① ran on the first of the alerts and its verdict is visible to an analyst on that alert's own page.
//
// The alerts are real: posted through the webhook and taken by the worker, ① run on the first by the stack's stub.
// The run's window is read from their `received_at` in the scratch database and typed into the form in the console's
// zone (+07:00), to the second, so the run holds those three alerts and no other the suite posted.
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import {
  S,
  captureTraffic,
  claimToken,
  loginAs,
  postAlert,
  sql,
  waitForStatus,
  waitForTriage,
  type Posted,
} from "./fixtures";

const L = S.admin.lab;
const TP = L.runPage.action.true_positive;
const FP = L.runPage.action.false_positive;
const CLEAR = L.runPage.action.clear;

/** The keys the labelling filter drops (`LABELING_DENYLIST` of tier1/visibility.py), at any depth of an answer. */
const FORBIDDEN_KEYS = [
  "suggestion",
  "suggested_action",
  "confidence",
  "gate_forced",
  "gate_result",
  "verifier_result",
  "triage_status",
  "triaged_count",
  "needs_retriage",
  "risk_score",
  "risk_band",
  "status",
  "source",
  "soar",
  "case_id",
  "llm_stopped_by",
];

function keysOf(value: unknown, into: Set<string>): void {
  if (Array.isArray(value)) value.forEach((item) => keysOf(item, into));
  else if (typeof value === "object" && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      into.add(key);
      keysOf(item, into);
    }
  }
}

const literal = (text: string): string => `'${text.replace(/'/g, "''")}'`;

/** The three alerts of the run, posted and taken by the worker; the first has a ① answer in the database. */
async function threeAlerts(request: APIRequestContext): Promise<Posted[]> {
  // The first is on the arm where an analyst sees ①'s verdict: a labeller must not, whatever the arm.
  const first = await postAlert(request, { tag: "lab-a", arm: "visible" });
  await waitForStatus(first.id, "queued_tier1");
  await waitForTriage(first.id);
  const second = await postAlert(request, { tag: "lab-b" });
  await waitForStatus(second.id, "queued_tier1");
  const third = await postAlert(request, { tag: "lab-c" });
  await waitForStatus(third.id, "queued_tier1");
  return [first, second, third];
}

/** The window that holds exactly these alerts: whole seconds in the console's zone, `YYYY-MM-DDTHH:MM:SS`. */
function windowAround(alerts: readonly Posted[]): { starts: string; ends: string; total: number } {
  const ids = alerts.map((a) => literal(a.id)).join(", ");
  const format = `'YYYY-MM-DD"T"HH24:MI:SS'`;
  const answer = sql(
    `SELECT to_char(date_trunc('second', min(received_at)) AT TIME ZONE 'Asia/Ho_Chi_Minh', ${format}) || '|' || ` +
      `to_char((date_trunc('second', max(received_at)) + interval '1 second') AT TIME ZONE 'Asia/Ho_Chi_Minh', ${format}) ` +
      `FROM alerts WHERE alert_id IN (${ids})`,
  );
  const [starts, ends] = answer.split("|");
  if (starts === undefined || ends === undefined) throw new Error("no window");
  const total = Number(
    sql(
      `SELECT count(*) FROM alerts WHERE duplicate_of IS NULL AND ` +
        `received_at >= (${literal(starts)}::timestamp AT TIME ZONE 'Asia/Ho_Chi_Minh') AND ` +
        `received_at < (${literal(ends)}::timestamp AT TIME ZONE 'Asia/Ho_Chi_Minh')`,
    ),
  );
  return { starts, ends, total };
}

async function openLab(page: Page): Promise<void> {
  await page
    .getByRole("navigation", { name: S.admin.nav.label })
    .getByRole("link", { name: L.nav, exact: true })
    .click();
  await expect(page).toHaveURL(/\/admin\/lab$/);
  await expect(page.getByRole("heading", { level: 1, name: L.title.runs })).toBeVisible();
}

const create = (page: Page) => page.getByRole("region", { name: L.runsPage.create.title });
const rowOf = (page: Page, alert: Posted) =>
  page.getByRole("listitem", { name: L.runPage.alertLabel(alert.id) });
const labelOf = (alert: Posted) =>
  sql(`SELECT coalesce(max(label), '') FROM lab_labels WHERE alert_id = ${literal(alert.id)}`);

/** Fills the create form and presses the button. */
async function fillRun(
  page: Page,
  run: { name: string; purpose: "kb" | "test"; starts: string; ends: string },
): Promise<void> {
  const form = create(page);
  await form.getByLabel(L.runsPage.create.name).fill(run.name);
  await form.getByRole("radio", { name: new RegExp(`^${L.purpose[run.purpose]}`) }).check();
  await form.getByLabel(L.runsPage.create.starts).fill(run.starts);
  await form.getByLabel(L.runsPage.create.ends).fill(run.ends);
  await form.getByRole("button", { name: L.runsPage.create.submit }).click();
}

test("an admin records a lab run, labels two of its alerts, reloads and sees both, and the page shows nothing of ①", async ({
  page,
  request,
}) => {
  const alerts = await threeAlerts(request);
  const [a, b, c] = alerts as [Posted, Posted, Posted];
  const { starts, ends, total } = windowAround(alerts);
  expect(total, "the window holds the three alerts the spec posted").toBeGreaterThanOrEqual(3);
  const name = `E2E lab ${Date.now()}`;

  await loginAs(page, "admin");
  await openLab(page);
  // From here on: the overview the admin lands on has been read, and what follows is the lab's own traffic.
  const traffic = captureTraffic(page);

  // --- the run: made, and listed with its window and its counter
  await fillRun(page, { name, purpose: "test", starts, ends });
  await expect(page.getByText(L.runsPage.create.done(name))).toBeVisible();
  const row = page.getByRole("row").filter({ has: page.getByRole("link", { name, exact: true }) });
  await expect(row).toContainText(L.purpose.test);
  await expect(row).toContainText(L.progress(0, total));
  expect(sql(`SELECT purpose || '|' || name FROM lab_runs WHERE name = ${literal(name)}`)).toBe(
    `test|${name}`,
  );

  // --- a window that shares time with it is refused, in words, and nothing is written
  await fillRun(page, { name: `${name} (trùng)`, purpose: "kb", starts, ends });
  await expect(create(page).getByRole("alert")).toHaveText(L.runsPage.create.overlap);
  await expect(page.getByRole("link", { name: `${name} (trùng)` })).toHaveCount(0);
  expect(sql(`SELECT count(*) FROM lab_runs WHERE name = ${literal(`${name} (trùng)`)}`)).toBe("0");
  // and the form is as the admin left it
  await expect(create(page).getByLabel(L.runsPage.create.name)).toHaveValue(`${name} (trùng)`);

  // --- the run's page: its alerts, oldest first
  await page.getByRole("link", { name, exact: true }).click();
  await expect(page).toHaveURL(/\/admin\/lab\/[0-9a-f-]{36}$/);
  await expect(page.getByRole("heading", { level: 1, name })).toBeVisible();
  await expect(page.getByText(L.progress(0, total))).toBeVisible();
  const inOrder = sql(
    `SELECT string_agg(alert_id, ',' ORDER BY received_at, alert_id) FROM alerts ` +
      `WHERE duplicate_of IS NULL AND received_at >= (${literal(starts)}::timestamp AT TIME ZONE 'Asia/Ho_Chi_Minh') ` +
      `AND received_at < (${literal(ends)}::timestamp AT TIME ZONE 'Asia/Ho_Chi_Minh')`,
  ).split(",");
  const shown = await page
    .getByRole("list", { name: L.runPage.listLabel })
    .getByRole("listitem")
    .evaluateAll((items) => items.map((li) => li.getAttribute("aria-label") ?? ""));
  expect(shown).toEqual(inOrder.map((id) => L.runPage.alertLabel(id)));
  await expect(rowOf(page, a)).toContainText(a.description);
  await expect(rowOf(page, a)).toContainText("99001");
  await expect(rowOf(page, a)).toContainText(a.agent);
  await expect(rowOf(page, b)).toContainText(b.description);
  await expect(rowOf(page, c)).toContainText(c.description);

  // --- two labels: the counter and the row change, the database holds them
  await rowOf(page, a).getByRole("button", { name: TP, exact: true }).click();
  await expect(page.getByText(L.progress(1, total))).toBeVisible();
  await rowOf(page, b).getByRole("button", { name: FP, exact: true }).click();
  await expect(page.getByText(L.progress(2, total))).toBeVisible();
  await expect(rowOf(page, a).getByText(L.label.true_positive, { exact: true })).toBeVisible();
  await expect(rowOf(page, b).getByText(L.label.false_positive, { exact: true })).toBeVisible();
  await expect(rowOf(page, c).getByText(L.label.none, { exact: true })).toBeVisible();
  expect(labelOf(a)).toBe("true_positive");
  expect(labelOf(b)).toBe("false_positive");
  expect(labelOf(c)).toBe("");

  // --- reload: both labels are still there, and so is the counter
  await page.reload();
  await expect(page.getByText(L.progress(2, total))).toBeVisible();
  await expect(rowOf(page, a).getByText(L.label.true_positive, { exact: true })).toBeVisible();
  await expect(rowOf(page, a).getByRole("button", { name: TP, exact: true })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(rowOf(page, b).getByText(L.label.false_positive, { exact: true })).toBeVisible();
  await expect(rowOf(page, c).getByText(L.label.none, { exact: true })).toBeVisible();

  // --- changing a label, and taking one off
  await rowOf(page, a).getByRole("button", { name: FP, exact: true }).click();
  await expect(rowOf(page, a).getByText(L.label.false_positive, { exact: true })).toBeVisible();
  await expect(page.getByText(L.progress(2, total))).toBeVisible();
  expect(labelOf(a)).toBe("false_positive");
  await rowOf(page, b).getByRole("button", { name: CLEAR, exact: true }).click();
  await expect(page.getByText(L.progress(1, total))).toBeVisible();
  await expect(rowOf(page, b).getByText(L.label.none, { exact: true })).toBeVisible();
  expect(labelOf(b)).toBe("");
  expect(
    sql(
      `SELECT count(*) FROM lab_labels WHERE alert_id IN (${alerts.map((x) => literal(x.id)).join(", ")})`,
    ),
  ).toBe("1");

  // --- the audit trail: the run, and every label write (two sets, one change, one clear)
  expect(
    sql(
      `SELECT count(*) FROM audit_events WHERE event_type = 'lab.run_created' AND payload->>'name' = ${literal(name)}`,
    ),
  ).toBe("1");
  expect(
    sql(
      `SELECT count(*) FROM audit_events WHERE event_type = 'lab.labeled' AND subject_id IN (${alerts.map((x) => literal(x.id)).join(", ")})`,
    ),
  ).toBe("4");

  // --- BLIND. ① ran on the first alert (it has an answer in the database), and none of it is on the page.
  const main = page.getByRole("main");
  const shownText = await main.innerText();
  const text = shownText + "\n" + (await main.evaluate((el) => el.innerHTML));
  for (const forbidden of [
    "AI kết luận",
    S.alert.aiHeading,
    "Gợi ý ①",
    claimToken(a.id),
    "①",
    "②",
  ]) {
    expect(text, `the page holds ${forbidden}`).not.toContain(forbidden);
  }
  expect(shownText).not.toMatch(/%/);
  // Open the details of the first alert: the raw log is the alert's own, and ①'s reason is not in it.
  await rowOf(page, a).getByText(L.runPage.details).click();
  await expect(rowOf(page, a)).toContainText(`e2e raw log of ${a.agent}`);
  expect(await main.innerText()).not.toContain(claimToken(a.id));
  // Nothing on the page leads to an alert page, which would show what ① said.
  await expect(
    page.getByRole("list", { name: L.runPage.listLabel }).locator("a, [href]"),
  ).toHaveCount(0);
  await expect(page.getByRole("link", { name: L.runPage.back })).toHaveAttribute(
    "href",
    "/admin/lab",
  );

  // ... and not in what the browser received: only the lab routes were read, and no key of ① is in their answers.
  const answers = await traffic.answers();
  // (`/api/auth/me` is the app asking who the session is after the reload, not a page's read.)
  const paths = [...new Set(answers.map((x) => x.path.split("?")[0] as string))].filter(
    (path) => path !== "/api/auth/me",
  );
  expect(paths.length).toBeGreaterThan(2);
  for (const path of paths) {
    expect(path, "an API path the lab pages read").toMatch(
      /^\/api\/admin\/lab\/(runs|labels)(\/|$)/,
    );
  }
  expect(answers.some((x) => /\/api\/(tier1|tier2)\b|\/api\/admin\/knowledge/.test(x.path))).toBe(
    false,
  );
  const seen = new Set<string>();
  for (const answer of answers) {
    expect(answer.text, "an answer holds ①'s token").not.toContain(claimToken(a.id));
    try {
      keysOf(JSON.parse(answer.text) as unknown, seen);
    } catch {
      // a 204 has no body
    }
  }
  expect(FORBIDDEN_KEYS.filter((key) => seen.has(key))).toEqual([]);
  expect(seen.has("alert_id")).toBe(true);
  expect(seen.has("label")).toBe(true);
});

test("a run that is not there says so, and a Tier-1 user is turned away from the pages", async ({
  page,
}) => {
  await loginAs(page, "admin");
  await page.goto("/admin/lab/00000000-0000-4000-8000-000000000000");
  await expect(page.getByRole("heading", { level: 1, name: L.runPage.notFound })).toBeVisible();
  await page.goto("/admin/lab/not-a-run-id");
  await expect(page.getByRole("heading", { level: 1, name: L.runPage.notFound })).toBeVisible();
  await page.getByRole("link", { name: L.runPage.backToRuns }).click();
  await expect(page).toHaveURL(/\/admin\/lab$/);

  await page.getByRole("button", { name: S.nav.logout }).click();
  await expect(page).toHaveURL(/\/login$/);
  await loginAs(page, "t1");
  for (const path of ["/admin/lab", "/admin/lab/00000000-0000-4000-8000-000000000000"]) {
    await page.goto(path);
    await expect(page).toHaveURL(/\/queue$/);
    await expect(page.getByRole("alert")).toContainText(S.forbidden);
    await expect(page.getByRole("heading", { name: L.title.runs })).toHaveCount(0);
  }
});
