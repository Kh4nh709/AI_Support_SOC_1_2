// The admin console on the real stack (P11-T18, admin console v1.1 spec §7): the ten scenarios, one after the
// other, in a real browser, through the real client, against the real API, worker and database of the scratch
// stack (scripts/ui_e2e_stack.sh). One file, one run: the scenarios share what the earlier ones made (the account
// of scenario 2 is the one that is unlocked in 2b and whose role changes in 3, the alert the rule of scenario 6
// closes is the one the digest reopens in scenario 7, and the events of all of them are what the audit page lists
// in scenario 9), so the describe is serial and stops at the first that fails.
//
//   scenario 1   an admin logs in and lands on the overview
//   scenario 2   creates a Tier 1 user, who then logs in
//   scenario 2b  unlock goes through the real client, which sends `json: {}`
//   scenario 3   changes that user's role: their session and live socket end
//   scenario 4   demotes the last active admin: 409, and the dialog says why
//   scenario 4b  the same rule met by two admins demoting each other at once, with no help from the test
//   scenario 4c  the 409 that needs no race: an admin changing their own role or active flag (self_change)
//   scenario 5   lowers the cap below the month's spend: the next ① run stops with `stopped_by = 'cap'`
//   scenario 6   previews, creates and disables a rule
//   scenario 7   reviews a digest row "Sai": the alert is back in the Tier 1 queue
//   scenario 8   labels one cluster and undoes it on an unfrozen scratch set, then meets the frozen 409
//   scenario 9   the audit page shows the events of those steps, and no label or confidence of `label.created`
//   scenario 10  a Tier 1 user opening /admin/users gets the 403 notice, and the API refuses
//
// Nothing here prints a secret or a body: every call of the API goes through `guarded`, every password is typed
// by `fillSecret`, and `make ui-e2e` scans what the run leaves behind. The labelling scenario reads and writes a
// scratch `eval/` made by the stack, never the repository's own (adminFixtures.ts).
import { expect, test, type Locator, type Page } from "@playwright/test";
import {
  S,
  apiGet,
  apiLogin,
  apiPatch,
  apiPost,
  apiPut,
  apiWrongLogin,
  captureTraffic,
  claimToken,
  fillSecret,
  loginAs,
  newUserPassword,
  postAlert,
  signIn,
  sql,
  userIdOf,
  usernameOf,
  waitForStatus,
  waitForTriage,
  type Answer,
  type Posted,
  type Traffic,
} from "./fixtures";
import {
  clearingPasswords,
  emptyPasswords,
  eventCount,
  expectPasswordsEmpty,
  freezeMarkerExists,
  holdAdminLocks,
  openRecorded,
  seedMonthSpend,
  socketsSeen,
  trackSockets,
  waitForLockWaiters,
  writeCandidates,
  writeFreezeMarker,
  type Held,
} from "./adminFixtures";

const A = S.admin;
const U = A.usersPage;
const L = A.llmPage;
const R = A.rulesPage;
const D = A.digestPage;
const LB = A.labelsPage;
const P = A.auditPage;

test.describe.configure({ mode: "serial", timeout: 90_000 });

/** What the audit page puts in place of a value it hides (`REDACTED` of admin_audit.py). */
const HIDDEN_MARK = "[đã ẩn]";

/** The payload of a `label.created` event, as the audit page shows it. */
type Payload = {
  label?: unknown;
  confidence?: unknown;
  undo?: unknown;
  gold_set?: unknown;
  alert_id?: unknown;
  labeler_id?: unknown;
};

/** The account scenario 2 creates; it is Tier 1 until scenario 3. */
const NEW_USER = "e2e-newuser";
const NEW_NAME = "E2E New User";

/** What one scenario hands the next. */
const made: {
  newUserId?: string;
  rule?: { name: string; id: string };
  closed?: Posted;
  /** The cluster scenario 8 labelled, undid and labelled again: which of its two is the labeller's own order. */
  labelled?: Posted;
} = {};

const toast = (page: Page, text: string) => page.getByRole("status").filter({ hasText: text });
const dialogOf = (page: Page, title: string) => page.getByRole("dialog", { name: title });
const sidebar = (page: Page) => page.getByRole("navigation", { name: A.nav.label });
const userRow = (page: Page, username: string) =>
  page.getByRole("row").filter({ has: page.getByText(username, { exact: true }) });

/** Opens a page of the console through the sidebar, as a person does. */
async function openPage(page: Page, link: string, url: RegExp, title: string): Promise<void> {
  await sidebar(page).getByRole("link", { name: link, exact: true }).click();
  await expect(page).toHaveURL(url);
  await expect(page.getByRole("heading", { level: 1, name: title })).toBeVisible();
}

/** The status of the call a click is about to make, awaited before the click so that it is never missed. */
function responseOf(page: Page, method: string, path: RegExp) {
  return page.waitForResponse(
    (res) => res.request().method() === method && path.test(new URL(res.url()).pathname),
  );
}

/** What a refusal's JSON body says: `{detail: {reason}}` or a plain-text `detail`. Never printed. */
async function detailOf(res: { json: () => Promise<unknown> }): Promise<unknown> {
  const body = (await res.json().catch(() => null)) as { detail?: unknown } | null;
  return body?.detail;
}

// ---------------------------------------------------------------------------------------------------------
// Scenario 1

test("scenario 1: an admin logs in and lands on the overview", async ({ page }) => {
  const traffic = captureTraffic(page);
  await loginAs(page, "admin");
  await expect(page.getByRole("heading", { level: 1, name: A.title.overview })).toBeVisible();

  // The console's own navigation, in the canvas's order, with the page on view marked.
  const links = [
    A.nav.overview,
    A.nav.users,
    A.nav.llm,
    A.nav.rules,
    A.nav.digest,
    A.nav.labels,
    A.nav.knowledge,
    A.nav.audit,
  ];
  await expect(sidebar(page).getByRole("link")).toHaveText(links);
  await expect(sidebar(page).getByRole("link", { name: A.nav.overview })).toHaveAttribute(
    "aria-current",
    "page",
  );
  // The header says who is signed in, as what, and offers the console.
  const header = page.getByRole("banner");
  await expect(header.getByText(usernameOf("admin"), { exact: true })).toBeVisible();
  await expect(header.getByText(S.role.admin, { exact: true })).toBeVisible();
  await expect(header.getByRole("link", { name: S.nav.admin })).toBeVisible();
  // The page read its data. One read answers for the whole page: the cost card is the overview's own `llm_month`
  // (P11-T20 row 50), so the LLM page's usage route is not asked for.
  await expect
    .poll(async () => {
      const answer = (await traffic.answers()).find(
        (a) => a.status === 200 && a.path.startsWith("/api/admin/overview"),
      );
      const month =
        answer === undefined
          ? null
          : (JSON.parse(answer.text) as { llm_month?: unknown }).llm_month;
      return (
        typeof month === "object" && month !== null && "spent_usd" in month && "cap_usd" in month
      );
    })
    .toBe(true);
  expect(
    (await traffic.answers()).filter((a) => a.path.startsWith("/api/admin/llm/usage")),
    "the overview does not ask the LLM page's route for its cost card",
  ).toEqual([]);

  // `/admin` and `/` open the overview too (decision 7: the admin's home).
  await page.goto("/admin");
  await expect(page).toHaveURL(/\/admin\/overview$/);
  await page.goto("/");
  await expect(page).toHaveURL(/\/admin\/overview$/);
});

// ---------------------------------------------------------------------------------------------------------
// Scenario 2

/** Fills the create panel. The password is the run's (`newUserPassword`), typed by `fillSecret`. */
async function fillCreateForm(
  panel: Locator,
  username: string,
  name: string,
  role: "tier1" | "tier2" | "admin",
): Promise<void> {
  const C = U.create;
  await panel.getByLabel(C.username).fill(username);
  await panel.getByLabel(C.displayName).fill(name);
  await panel.getByRole("radio", { name: new RegExp(`^${role}`) }).check();
  await fillSecret(panel.getByLabel(C.password, { exact: true }), newUserPassword(), "password");
  await fillSecret(panel.getByLabel(C.repeat, { exact: true }), newUserPassword(), "repeat");
}

test("scenario 2: an admin creates a Tier 1 user, who then logs in", async ({
  page,
  browser,
  baseURL,
}) => {
  const C = U.create;
  await loginAs(page, "admin");
  await openPage(page, A.nav.users, /\/admin\/users$/, A.title.users);
  await expect(userRow(page, usernameOf("t1"))).toBeVisible();
  const panel = page.getByRole("region", { name: C.title });

  // Everything that types a password runs under `clearingPasswords`: a failure anywhere in it empties both
  // password fields before the page is snapshotted for the report.
  await clearingPasswords(panel, async () => {
    await fillCreateForm(panel, NEW_USER, NEW_NAME, "tier1");
    await panel.getByRole("button", { name: C.submit }).click();
    await expect(toast(page, U.done.create(NEW_USER, "tier1"))).toBeVisible();
    const row = userRow(page, NEW_USER);
    await expect(row).toBeVisible();
    await expect(row.getByText(NEW_NAME)).toBeVisible();
    await expect(row.getByText(U.neverLoggedIn)).toBeVisible();
    await expect(row.getByLabel(U.roleSelect(NEW_USER))).toHaveValue("tier1");
    // The form emptied itself: nothing typed stays on the page.
    await expect(panel.getByLabel(C.username)).toHaveValue("");
    await expectPasswordsEmpty(panel);

    // The server holds the account, and a hash, not the password.
    made.newUserId = sql(`SELECT user_id FROM users WHERE username = '${NEW_USER}'`);
    expect(made.newUserId).not.toBe("");
    expect(sql(`SELECT role, is_active FROM users WHERE username = '${NEW_USER}'`)).toBe("tier1|t");
    expect(sql(`SELECT left(password_hash, 9) FROM users WHERE username = '${NEW_USER}'`)).toBe(
      "$argon2id",
    );

    // The same name again is refused, at the field. The form keeps what was typed after a refusal, so the
    // password is emptied here, by the test, and not left in the page for the rest of it.
    await fillCreateForm(panel, NEW_USER, "Somebody Else", "tier2");
    await panel.getByRole("button", { name: C.submit }).click();
    await expect(
      panel.getByRole("alert").filter({ hasText: A.reason.username_taken }),
    ).toBeVisible();
    expect(sql(`SELECT count(*) FROM users WHERE username = '${NEW_USER}'`)).toBe("1");
    await emptyPasswords(panel);
    await expectPasswordsEmpty(panel);
  });

  // The new user logs in, in a browser of their own, and lands where Tier 1 starts.
  const context = await browser.newContext({ baseURL });
  try {
    const own = await context.newPage();
    await loginAs(own, { username: NEW_USER }, /\/queue$/);
    await expect(own.getByRole("heading", { name: S.queue.title })).toBeVisible();
    await expect(own.getByRole("banner").getByText(S.role.tier1, { exact: true })).toBeVisible();
    await expect(own.getByRole("link", { name: S.nav.admin })).toHaveCount(0);
  } finally {
    await context.close();
  }
  // The list now says they have been in.
  await page.reload();
  await expect(userRow(page, NEW_USER)).toBeVisible();
  await expect(userRow(page, NEW_USER).getByText(U.neverLoggedIn)).toHaveCount(0);
});

// ---------------------------------------------------------------------------------------------------------
// Scenario 2b

test("scenario 2b: unlock goes through the real client, which sends an empty JSON object", async ({
  page,
  request,
}) => {
  // Lock the account the real way: five wrong passwords (`LOGIN_MAX_FAILS`), the fifth is the 423.
  const statuses: number[] = [];
  for (let i = 0; i < 5; i += 1) statuses.push(await apiWrongLogin(request, NEW_USER));
  expect(statuses).toEqual([401, 401, 401, 401, 423]);

  const unlocks: { contentType: string | undefined; body: unknown }[] = [];
  page.on("request", (req) => {
    const path = new URL(req.url()).pathname;
    if (req.method() !== "POST" || !/^\/api\/admin\/users\/[^/]+\/unlock$/.test(path)) return;
    let body: unknown = "not json";
    try {
      body = req.postDataJSON();
    } catch {
      // left as the marker: the assertion below says what was sent was not JSON
    }
    unlocks.push({ contentType: req.headers()["content-type"], body });
  });

  await loginAs(page, "admin");
  await openPage(page, A.nav.users, /\/admin\/users$/, A.title.users);
  const row = userRow(page, NEW_USER);
  await expect(row.getByText(U.status.locked("").trim())).toBeVisible();
  const answered = responseOf(page, "POST", /^\/api\/admin\/users\/[^/]+\/unlock$/);
  await row.getByRole("button", { name: U.rowAction(U.action.unlock, NEW_USER) }).click();
  const dialog = dialogOf(page, U.dialog.unlock.title(NEW_USER));
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: U.dialog.unlock.confirm }).click();
  expect((await answered).status()).toBe(204);
  await expect(toast(page, U.done.unlock(NEW_USER))).toBeVisible();

  // One POST, with a JSON content type and `{}` as its body: not an empty body, not a form.
  expect(unlocks).toHaveLength(1);
  expect(unlocks[0]?.contentType ?? "").toContain("application/json");
  expect(unlocks[0]?.body).toEqual({});
  // The account works again, and the row is not locked.
  expect(
    sql(`SELECT failed_logins, locked_until IS NULL FROM users WHERE username = '${NEW_USER}'`),
  ).toBe("0|t");
  await apiLogin(request, { username: NEW_USER });
  await expect(userRow(page, NEW_USER).getByText(U.status.locked("").trim())).toHaveCount(0);
});

// ---------------------------------------------------------------------------------------------------------
// Scenario 3

test("scenario 3: a role change ends the user's open session and live socket", async ({
  page,
  browser,
  baseURL,
  request,
}) => {
  test.setTimeout(180_000);
  // The user has the queue open, with the live socket up, and holds a token of the API as well.
  const context = await browser.newContext({ baseURL });
  try {
    const own = await context.newPage();
    await trackSockets(own);
    await loginAs(own, { username: NEW_USER }, /\/queue$/);
    await expect(own.getByRole("status").filter({ hasText: S.live.on })).toBeVisible();
    expect((await socketsSeen(own)).opened).toBeGreaterThan(0);
    expect((await socketsSeen(own)).closed).toEqual([]);
    const token = await apiLogin(request, { username: NEW_USER });
    expect((await apiGet(request, "/api/auth/me", { token })).status).toBe(200);

    // The admin changes their role, in the dialog that says what it does.
    await loginAs(page, "admin");
    await openPage(page, A.nav.users, /\/admin\/users$/, A.title.users);
    await userRow(page, NEW_USER).getByLabel(U.roleSelect(NEW_USER)).selectOption("tier2");
    const dialog = dialogOf(page, U.dialog.role.title(NEW_USER));
    await expect(dialog.getByText(U.dialog.role.change("tier1", "tier2"))).toBeVisible();
    await expect(dialog.getByText(U.dialog.role.body(NEW_USER))).toBeVisible();
    await dialog.getByRole("button", { name: U.dialog.role.confirm }).click();
    await expect(toast(page, U.done.role(NEW_USER, "tier1", "tier2"))).toBeVisible();
    await expect(dialog).toHaveCount(0);
    const changed = Date.now();
    await expect(userRow(page, NEW_USER).getByLabel(U.roleSelect(NEW_USER))).toHaveValue("tier2");

    // The token is dead at once, and the server wrote what it did.
    expect((await apiGet(request, "/api/auth/me", { token })).status).toBe(401);
    expect(
      sql(`SELECT sessions_invalid_before IS NOT NULL FROM users WHERE username = '${NEW_USER}'`),
    ).toBe("t");
    expect(eventCount("admin.user_updated", made.newUserId)).toBeGreaterThanOrEqual(2);

    // The socket is closed by the server (4401, "sign in again": it re-checks the token each minute), and the
    // page, which did nothing meanwhile, is on the login page.
    await expect
      .poll(async () => (await socketsSeen(own)).closed, {
        message: "the server closed the user's live socket with 4401",
        timeout: 85_000,
        intervals: [1_000],
      })
      .toContain(4401);
    console.log(
      `role change: the live socket was closed ${Math.round((Date.now() - changed) / 1000)} s later`,
    );
    await expect(own).toHaveURL(/\/login$/);

    // The next login has the new role.
    await signIn(own, { username: NEW_USER });
    await expect(own.getByRole("banner").getByText(S.role.tier2, { exact: true })).toBeVisible();
    await own.goto("/");
    await expect(own).toHaveURL(/\/cases$/);
  } finally {
    await context.close();
  }
});

// ---------------------------------------------------------------------------------------------------------
// Scenario 4

test("scenario 4: demoting the last active admin gives 409, and the dialog says why", async ({
  page,
}) => {
  const other = usernameOf("admin2");
  const me = usernameOf("admin");
  const updatesBefore = eventCount("admin.user_updated");
  await loginAs(page, "admin");
  await openPage(page, A.nav.users, /\/admin\/users$/, A.title.users);
  await expect(userRow(page, other).getByLabel(U.roleSelect(other))).toHaveValue("admin");

  // Two admins, and the request of one of them (this page) reaches `update_user` when the other one's change
  // has been committed: the rows of the active admins are locked in a transaction that also takes this page's
  // user out of the admins (their session untouched), and the request waits on it. When the transaction commits,
  // the request finds one admin left, and it is the one it was asked to demote.
  const refused = responseOf(page, "PATCH", /^\/api\/admin\/users\/[^/]+$/);
  let held: Held | undefined = await holdAdminLocks(me);
  try {
    await userRow(page, other).getByLabel(U.roleSelect(other)).selectOption("tier2");
    const dialog = dialogOf(page, U.dialog.role.title(other));
    await dialog.getByRole("button", { name: U.dialog.role.confirm }).click();
    await waitForLockWaiters();
    await held.commit();
    held = undefined;

    const answer = await refused;
    expect(answer.status()).toBe(409);
    expect(await detailOf(answer)).toEqual({ reason: "last_active_admin" });
    // The dialog keeps its title and shows the refusal's text; "Đóng" is the only way on.
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("alert")).toHaveText(A.reason.last_active_admin);
    await expect(dialog.getByRole("button", { name: U.dialog.role.confirm })).toHaveCount(0);
    await dialog.getByRole("button", { name: S.common.close }).click();
    await expect(dialog).toHaveCount(0);
  } finally {
    await held?.abandon();
    // This page's user is an admin again (the transaction above is the test's, not a feature).
    sql(`UPDATE users SET role = 'admin' WHERE username = '${me}'`);
  }

  // Nothing was written for the refused change: the other admin is still one, and no event says otherwise.
  expect(sql(`SELECT role FROM users WHERE username = '${other}'`)).toBe("admin");
  expect(eventCount("admin.user_updated")).toBe(updatesBefore);
  await expect(userRow(page, other).getByLabel(U.roleSelect(other))).toHaveValue("admin");
});

test("scenario 4b: two admins demoting each other at once leave one, and the later request gets the 409", async ({
  request,
}) => {
  // The same rule met by two real requests and nothing else: each admin asks to demote the other, both are held
  // on the locks of the active admins, and the database lets one of them through first. Whichever it is, the
  // other finds one admin left and is refused. (Which of the two wins is not the test's to say.)
  const a = usernameOf("admin");
  const b = usernameOf("admin2");
  const tokenA = await apiLogin(request, "admin");
  const tokenB = await apiLogin(request, "admin2");
  const updatesBefore = eventCount("admin.user_updated");
  let held: Held | undefined = await holdAdminLocks();
  try {
    const race = Promise.all([
      apiPatch(request, `/api/admin/users/${userIdOf("admin2")}`, {
        token: tokenA,
        data: { role: "tier2" },
      }),
      apiPatch(request, `/api/admin/users/${userIdOf("admin")}`, {
        token: tokenB,
        data: { role: "tier2" },
      }),
    ]);
    await waitForLockWaiters(2);
    await held.commit();
    held = undefined;
    const answers = await race;
    expect(answers.map((answer) => answer.status).sort()).toEqual([200, 409]);
    const refused = answers.find((answer) => answer.status === 409);
    expect((refused?.body as { detail?: unknown } | null)?.detail).toEqual({
      reason: "last_active_admin",
    });
    expect(sql("SELECT count(*) FROM users WHERE role = 'admin' AND is_active")).toBe("1");
    expect(eventCount("admin.user_updated")).toBe(updatesBefore + 1);
  } finally {
    await held?.abandon();
    // Both are admins again for the scenarios that follow (the race left one of them a Tier 2 user).
    sql(`UPDATE users SET role = 'admin' WHERE username IN ('${a}', '${b}')`);
  }
});

test("scenario 4c: an admin changing their own role or active flag is refused with 409 self_change", async ({
  page,
  request,
}) => {
  // The 409 that needs no race: the row of the signed-in admin has its role select and its row menu switched off,
  // with the reason on them; and a request that gets round that (a tab with a stale page, a hand-made call) is
  // refused by the server, whose text the page shows in the dialog.
  const me = usernameOf("admin");
  const updatesBefore = eventCount("admin.user_updated");
  await loginAs(page, "admin");
  await openPage(page, A.nav.users, /\/admin\/users$/, A.title.users);
  const row = userRow(page, me);
  const select = row.getByLabel(U.roleSelect(me));
  await expect(select).toBeDisabled();
  await expect(select).toHaveAttribute("title", A.reason.self_change);
  await expect(row.getByRole("button", { name: U.moreActions(me) })).toBeDisabled();

  // Got round: the control is switched on in the DOM, as a page that had not been told would have it, and used.
  const refused = responseOf(page, "PATCH", /^\/api\/admin\/users\/[^/]+$/);
  await select.evaluate((element: HTMLSelectElement) => {
    element.disabled = false;
  });
  await select.selectOption("tier2");
  const dialog = dialogOf(page, U.dialog.role.title(me));
  await dialog.getByRole("button", { name: U.dialog.role.confirm }).click();
  const answer = await refused;
  expect(answer.status()).toBe(409);
  expect(await detailOf(answer)).toEqual({ reason: "self_change" });
  await expect(dialog.getByRole("alert")).toHaveText(A.reason.self_change);
  await expect(dialog.getByRole("button", { name: U.dialog.role.confirm })).toHaveCount(0);
  await dialog.getByRole("button", { name: S.common.close }).click();
  await expect(dialog).toHaveCount(0);

  // The active flag is the same rule, at the route (the page switches its menu item off with the row's).
  const token = await apiLogin(request, "admin");
  const deactivate = await apiPatch(request, `/api/admin/users/${userIdOf("admin")}`, {
    token,
    data: { is_active: false },
  });
  expect(deactivate.status).toBe(409);
  expect((deactivate.body as { detail?: unknown } | null)?.detail).toEqual({
    reason: "self_change",
  });

  // Nothing was written: still an active admin, no event.
  expect(sql(`SELECT role, is_active FROM users WHERE username = '${me}'`)).toBe("admin|t");
  expect(eventCount("admin.user_updated")).toBe(updatesBefore);
});

// ---------------------------------------------------------------------------------------------------------
// Scenario 5

test("scenario 5: a cap below the month's spend stops the next ① run with stopped_by = cap", async ({
  page,
  request,
}) => {
  seedMonthSpend(12.5);
  await loginAs(page, "admin");
  await openPage(page, A.nav.llm, /\/admin\/llm$/, A.title.llm);
  const cost = page.getByRole("region", { name: L.cost.title });
  await expect(cost).toHaveAttribute("data-cost", "ok");
  const cap = page.getByLabel(L.limits.field.cap_usd);
  await expect(cap).toHaveValue("30");

  let lifted = false;
  try {
    // Lower it to 10: below the 12.5 spent, so the confirmation warns and says it plainly.
    await cap.fill("10");
    await page.getByRole("button", { name: L.limits.save }).click();
    const dialog = dialogOf(page, L.confirm.title);
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole("alert")).toBeVisible();
    await dialog.getByRole("button", { name: L.confirm.confirmAnyway }).click();
    await expect(toast(page, L.limits.saved)).toBeVisible();
    await expect(cost).toHaveAttribute("data-cost", "stopped");
    await expect(cost.getByRole("alert")).toHaveText(L.cost.stopped);

    // The next ① run, on a new alert, is stopped by the cap: no model call, a row that says why. The alert is
    // of the visible arm: on a blind one, still undecided, the usage list ties the run to no alert (DEC-206),
    // and which arm an alert gets would otherwise be a coin the spec flips.
    const head = await postAlert(request, { tag: "cap", arm: "visible" });
    const stoppedOn = (id: string, extra: string) =>
      Number(
        sql(
          `SELECT count(*) FROM llm_runs WHERE pipeline = 'triage' AND subject_id = '${id}' ${extra}`,
        ),
      );
    const stopped = (extra: string) => stoppedOn(head.id, extra);
    await expect
      .poll(() => stopped("AND stopped_by = 'cap'"), {
        message: "① stopped by the cap",
        timeout: 30_000,
      })
      .toBeGreaterThan(0);
    expect(stopped("AND result IS NOT NULL")).toBe(0);
    // The usage page lists that run as stopped by the cap.
    await page.reload();
    const run = page.getByRole("row").filter({ has: page.locator(`a[href="/alerts/${head.id}"]`) });
    await expect(run.first()).toContainText(L.recent.stopped(L.stopped.cap));

    // The same on a blind alert, still undecided (context pack §6.4, DEC-206): the run is stopped and listed, and
    // the list says neither which alert it was nor how it ended: no link, no id anywhere in the page.
    const blind = await postAlert(request, { tag: "cap-blind", arm: "blind" });
    await expect
      .poll(() => stoppedOn(blind.id, "AND stopped_by = 'cap'"), {
        message: "① stopped by the cap on a blind alert",
        timeout: 30_000,
      })
      .toBeGreaterThan(0);
    await page.reload();
    await expect(page.getByRole("row").filter({ hasText: L.recent.hidden }).first()).toBeVisible();
    await expect(page.locator(`a[href="/alerts/${blind.id}"]`)).toHaveCount(0);
    expect(await page.content(), "the usage page names a blind alert").not.toContain(blind.id);
    await expect(run.first()).toContainText(L.recent.stopped(L.stopped.cap)); // the visible one still is

    // Raising the cap lifts it: the tile is back to ok, and a new alert gets both ① answers.
    await page.getByLabel(L.limits.field.cap_usd).fill("100");
    await page.getByRole("button", { name: L.limits.save }).click();
    await dialogOf(page, L.confirm.title)
      .getByRole("button", { name: L.confirm.confirm, exact: true })
      .click();
    await expect(toast(page, L.limits.saved)).toBeVisible();
    lifted = true;
    await expect(page.getByRole("region", { name: L.cost.title })).toHaveAttribute(
      "data-cost",
      "ok",
    );
    const after = await postAlert(request, { tag: "cap-lifted" });
    await waitForTriage(after.id);
    expect(
      Number(
        sql(
          `SELECT count(*) FROM llm_runs WHERE pipeline = 'triage' AND subject_id = '${after.id}' AND stopped_by IS NULL`,
        ),
      ),
    ).toBeGreaterThanOrEqual(2);
  } finally {
    // The specs after this one need the model: whatever happened above, the cap does not stay low.
    if (!lifted) {
      const token = await apiLogin(request, "admin");
      await apiPut(request, "/api/admin/llm/limits", { token, data: { cap_usd: 100 } });
    }
  }
});

// ---------------------------------------------------------------------------------------------------------
// Scenario 6

const RULE_ID = "99701";

test("scenario 6: an admin previews, creates and disables a rule", async ({ page, request }) => {
  // A head the rule would close: its agent is in the inventory (the hard block "asset not in inventory").
  const probe = await postAlert(request, { tag: "rule-probe", rule: RULE_ID, inventory: "low" });
  await waitForStatus(probe.id, "queued_tier1");

  await loginAs(page, "admin");
  await openPage(page, A.nav.rules, /\/admin\/rules$/, A.title.rules);
  // The six hard blocks are on the page whatever the rules are.
  await expect(
    page.getByRole("region", { name: R.hardBlocks.label }).getByRole("listitem"),
  ).toHaveCount(6);

  const name = `E2E rule ${RULE_ID} ${Date.now() % 100_000}`;
  const create = page.getByRole("region", { name: R.create });
  await create.getByLabel(R.builder.name, { exact: true }).fill(name);
  await create
    .getByLabel(R.builder.reason, { exact: true })
    .fill("Routine events of the e2e hosts.");
  const condition = create.getByRole("group", { name: R.builder.group(1) });
  await expect(condition.getByLabel(R.builder.field)).toHaveValue("rule_id");
  await expect(condition.getByLabel(R.builder.op)).toHaveValue("eq");
  await condition.getByLabel(R.builder.value).fill(RULE_ID);

  // "Tạo rule" is not open until the conditions have been previewed.
  const submit = create.getByRole("button", { name: R.builder.submit, exact: true });
  await expect(submit).toBeDisabled();
  await create.getByRole("button", { name: R.builder.preview, exact: true }).click();
  const preview = page.getByRole("region", { name: R.preview.title });
  const figure = (label: string) =>
    preview.locator("dt", { hasText: label }).locator("xpath=following-sibling::dd");
  await expect(figure(R.preview.clusters)).toHaveText("1");
  await expect(figure(R.preview.alerts)).toHaveText("1");
  await expect(preview.getByRole("link", { name: probe.id })).toHaveAttribute(
    "href",
    `/alerts/${probe.id}`,
  );
  await expect(submit).toBeEnabled();
  // The button is for the conditions that were previewed, no others: edit them and it closes, and the preview on
  // screen says it is of the conditions before the edit; put them back and it opens on that preview again.
  await condition.getByLabel(R.builder.value).fill(`${RULE_ID}0`);
  await expect(submit).toBeDisabled();
  await expect(preview.getByText(R.preview.stale)).toBeVisible();
  await condition.getByLabel(R.builder.value).fill(RULE_ID);
  await expect(submit).toBeEnabled();
  await expect(preview.getByText(R.preview.stale)).toHaveCount(0);

  const before = eventCount("admin.autoclose_rule_toggled");
  await submit.click();
  await expect(toast(page, R.builder.created(name))).toBeVisible();
  const table = page.getByRole("table", { name: R.table.label });
  const row = table.getByRole("row").filter({ hasText: name });
  await expect(row).toContainText(RULE_ID);
  await expect(row.getByText(R.table.on, { exact: true })).toBeVisible();
  const ruleId = sql(`SELECT autoclose_rule_id FROM autoclose_rules WHERE name = '${name}'`);
  expect(sql(`SELECT enabled FROM autoclose_rules WHERE name = '${name}'`)).toBe("t");
  expect(eventCount("admin.autoclose_rule_toggled")).toBe(before + 1);
  made.rule = { name, id: ruleId };

  // The rule is live at once: the next alert of that kind is closed by it, not queued.
  const closed = await postAlert(request, { tag: "rule-closed", rule: RULE_ID, inventory: "low" });
  await waitForStatus(closed.id, "auto_closed");
  expect(sql(`SELECT autoclose_rule_id FROM alerts WHERE alert_id = '${closed.id}'`)).toBe(ruleId);
  made.closed = closed;

  // Disabling it, in its dialog: the row says off, and the next alert is queued again.
  await row.getByRole("button", { name: R.table.turnOffLabel(name) }).click();
  const dialog = dialogOf(page, R.toggle.offTitle(name));
  await expect(dialog.getByText(R.toggle.offBody)).toBeVisible();
  await dialog.getByRole("button", { name: R.toggle.offConfirm }).click();
  await expect(toast(page, R.toggle.doneOff(name))).toBeVisible();
  await expect(row.getByText(R.table.off, { exact: true })).toBeVisible();
  await expect(row.getByRole("button", { name: R.table.turnOnLabel(name) })).toBeVisible();
  expect(sql(`SELECT enabled FROM autoclose_rules WHERE name = '${name}'`)).toBe("f");
  expect(eventCount("admin.autoclose_rule_toggled")).toBe(before + 2);
  const queued = await postAlert(request, { tag: "rule-off", rule: RULE_ID, inventory: "low" });
  await waitForStatus(queued.id, "queued_tier1");
});

// ---------------------------------------------------------------------------------------------------------
// Scenario 7

test("scenario 7: reviewing a digest row Sai puts the alert back in the Tier 1 queue", async ({
  page,
  browser,
  baseURL,
}) => {
  const closed = made.closed;
  expect(closed, "scenario 6 closed an alert by a rule").toBeDefined();
  if (closed === undefined) return;

  await loginAs(page, "admin");
  await openPage(page, A.nav.digest, /\/admin\/digest$/, A.title.digest);
  // The rule that closed it has been disabled since, and its row is there all the same.
  const row = page.locator(`tr[data-alert-id="${closed.id}"]`);
  await expect(row).toBeVisible();
  await expect(row).toHaveAttribute("data-state", "open");
  await expect(row).toContainText(made.rule?.name ?? "");
  await expect(row).toContainText(closed.agent);
  await row
    .getByRole("group", { name: D.group(closed.rule, closed.agent) })
    .getByRole("button", { name: A.verdict.wrong, exact: true })
    .click();
  await expect(row).toHaveAttribute("data-state", "reviewed");
  await expect(row).toContainText(D.reviewed(A.verdict.wrong));
  await expect(row).toContainText(D.reopened);
  // The server reopened it: status, and an event that carries the admin as its actor.
  expect(sql(`SELECT status FROM alerts WHERE alert_id = '${closed.id}'`)).toBe("queued_tier1");
  expect(sql(`SELECT verdict FROM autoclose_reviews WHERE alert_id = '${closed.id}'`)).toBe(
    "wrong",
  );
  expect(eventCount("alert.reopened", closed.id)).toBe(1);
  expect(eventCount("autoclose.reviewed", closed.id)).toBe(1);

  // Tier 1 sees it in the queue.
  const context = await browser.newContext({ baseURL });
  try {
    const analyst = await context.newPage();
    await loginAs(analyst, "t1");
    await expect(analyst.locator(`a[href="/alerts/${closed.id}"]`)).toBeVisible();
  } finally {
    await context.close();
  }
});

// ---------------------------------------------------------------------------------------------------------
// Scenario 8

/** What the labelling page may send of a cluster: `VIEW_KEYS` of backend/app/tier1/labels.py. */
const VIEW_KEYS = [
  "alert_id",
  "rule_id",
  "rule_level",
  "severity",
  "description",
  "agent_name",
  "alert_time",
  "alert_user",
  "srcip",
  "dstip",
  "category",
  "raw_log",
  "raw_log_truncated_for_display",
  "occurrence_count",
  "first_seen",
  "last_seen",
  "playbook",
  "correlation",
  "gold_cluster_id",
];
/** Everything `labels/next` answers with: the cluster, the progress and the two flags, nothing else. */
const NEXT_KEYS = ["candidates_present", "cluster", "cluster_id", "done", "frozen", "total"];

/** What the candidates file holds that a labeller must never see; each value is found nowhere in the browser. */
const HIDDEN = {
  source: "e2e-hidden-source",
  stratum: "e2e-hidden-stratum",
  scenario: "e2e-hidden-scenario",
  kind: "e2e-hidden-kind",
  truth: "e2e-hidden-truth",
};

const nextBodies = (answers: Answer[]): Record<string, unknown>[] =>
  answers
    .filter((a) => a.path.startsWith("/api/admin/labels/next") && a.status === 200)
    .map((a) => JSON.parse(a.text) as Record<string, unknown>);

/**
 * The page is blind: nothing of ①, of the candidates file's hidden columns or of the alerts' pages is in the page
 * or in any answer the browser received, and what `labels/next` sends is the allowlist and no more.
 */
async function expectBlind(
  page: Page,
  traffic: Traffic,
  candidates: readonly Posted[],
): Promise<void> {
  const needles = [
    ...Object.values(HIDDEN),
    ...candidates.map((c) => claimToken(c.id)),
    S.ai1.action.needs_review,
  ];
  const text = await page.locator("body").innerText();
  const html = await page.content();
  for (const needle of needles) {
    expect(text.includes(needle), "the page shows a hidden value").toBe(false);
    expect(html.includes(needle), "the markup holds a hidden value").toBe(false);
  }
  await expect(page.locator('a[href^="/alerts/"], a[href^="/cases/"]')).toHaveCount(0);
  const answers = await traffic.answers();
  for (const answer of answers) {
    for (const needle of needles) {
      expect(answer.text.includes(needle), `${answer.path} carries a hidden value`).toBe(false);
    }
  }
  for (const body of nextBodies(answers)) {
    expect(Object.keys(body).sort()).toEqual(NEXT_KEYS);
    const cluster = body.cluster;
    if (cluster !== null) {
      expect(Object.keys(cluster as Record<string, unknown>).sort()).toEqual([...VIEW_KEYS].sort());
    }
  }
}

test("scenario 8: labels one cluster and undoes it on an unfrozen scratch set, then meets the frozen 409", async ({
  page,
  request,
}) => {
  const traffic = captureTraffic(page);
  await trackSockets(page);
  await loginAs(page, "admin");

  // ---- Which set is this? Before anything is written: the repository's own is frozen and has candidates, the
  // scratch one has neither. A page that says anything else is reading the wrong `eval/`, and the test stops.
  // The log of the page's calls starts here, on the labelling page's own load (`openRecorded`): the overview that
  // `loginAs` leaves may still be starting reads of its own, and they are not this page's.
  const calls = await openRecorded(page, "/admin/labels");
  await expect(page.getByRole("heading", { level: 1, name: A.title.labels })).toBeVisible();
  await expect(page.getByRole("heading", { name: LB.noCandidates.title })).toBeVisible();
  await expect(page.getByRole("heading", { name: LB.frozen.title })).toHaveCount(0);
  expect(freezeMarkerExists()).toBe(false);

  // ---- Two heads with ① answers, made candidates of a scratch G2 set.
  const first = await postAlert(request, { tag: "label-a" });
  const second = await postAlert(request, { tag: "label-b" });
  for (const head of [first, second]) {
    await waitForStatus(head.id, "queued_tier1");
    await waitForTriage(head.id);
  }
  const candidates = [first, second];
  writeCandidates(
    candidates.map((head) => ({
      alertId: head.id,
      agent: head.agent,
      rule: head.rule,
      category: "c2_beacon",
      severity: "medium",
      hidden: HIDDEN,
    })),
  );

  await page.goto("/admin/labels");
  const head = page.getByRole("region", { name: LB.cluster.label });
  await expect(head).toBeVisible();
  const onScreen = async (): Promise<Posted> => {
    const text = await head.innerText();
    const found = candidates.find((c) => text.includes(c.id));
    expect(found, "the cluster on screen is a candidate").toBeDefined();
    return found ?? first;
  };
  const other = (p: Posted): Posted => (p === first ? second : first);
  const progress = (done: number) =>
    expect(page.getByRole("progressbar", { name: LB.progress.bar })).toHaveAttribute(
      "value",
      String(done),
    );
  const labelsOf = (p: Posted) =>
    Number(
      sql(
        `SELECT count(*) FROM triage_labels WHERE source = 'gold_offline' AND alert_id = '${p.id}'`,
      ),
    );

  const form = page.getByRole("region", { name: LB.form.title });
  const label = async (note: string): Promise<void> => {
    await form.getByLabel(LB.form.choices.benign).check();
    await form.getByLabel(LB.form.confidences[3]).check();
    await form.getByLabel(LB.form.note).fill(note);
    await form.getByRole("button", { name: LB.form.save }).click();
  };

  // ---- The cluster: its facts, the playbook of the file's category, and nothing blind to hide.
  // Which of the two comes first is the labeller's own order (a function of their id), so it is read, not assumed.
  const shown = await onScreen();
  made.labelled = shown;
  await expect(page.getByText(shown.description, { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: LB.cluster.playbook })).toBeVisible();
  await progress(0);
  await expectBlind(page, traffic, candidates);
  // Nothing is chosen yet: the save is refused at the form, and no request goes.
  await form.getByRole("button", { name: LB.form.save }).click();
  await expect(form.getByRole("alert").filter({ hasText: LB.form.noLabel })).toBeVisible();
  expect(labelsOf(shown)).toBe(0);
  await expect(form.getByRole("button", { name: LB.form.undo })).toHaveCount(0);

  // ---- Label it: the toast names the cluster, the progress and the next one.
  await label("e2e note");
  await expect(toast(page, LB.notice.saved(shown.id, 1, 2, other(shown).id))).toBeVisible();
  await progress(1);
  expect(await onScreen()).toBe(other(shown));
  expect(labelsOf(shown)).toBe(1);
  await expectBlind(page, traffic, candidates);

  // ---- Undo it: the same cluster comes back, and the row is gone.
  await form.getByRole("button", { name: LB.form.undo }).click();
  await expect(toast(page, LB.notice.undone(shown.id, 0, 2))).toBeVisible();
  await progress(0);
  expect(await onScreen()).toBe(shown);
  expect(labelsOf(shown)).toBe(0);
  expect(freezeMarkerExists()).toBe(false);

  // ---- Label it again, so there is something to take back when the set is frozen.
  await label("e2e note, again");
  await expect(toast(page, LB.notice.saved(shown.id, 1, 2, other(shown).id))).toBeVisible();
  await progress(1);
  expect(labelsOf(shown)).toBe(1);

  // ---- The set is frozen while the page is open: the undo is refused with 409 `frozen`, nothing is deleted, and
  // the page is the frozen one (progress only, no form), whatever cluster the server still sends.
  writeFreezeMarker();
  expect(freezeMarkerExists()).toBe(true);
  const refused = responseOf(page, "POST", /^\/api\/admin\/labels\/undo$/);
  await form.getByRole("button", { name: LB.form.undo }).click();
  const answer = await refused;
  expect(answer.status()).toBe(409);
  expect(await detailOf(answer)).toEqual({ reason: "frozen" });
  await expect(page.getByRole("alert").filter({ hasText: A.reason.frozen })).toBeVisible();
  await expect(page.getByRole("heading", { name: LB.frozen.title })).toBeVisible();
  await expect(page.getByText(LB.frozen.badge)).toBeVisible();
  await progress(1);
  await expect(page.getByRole("button", { name: LB.form.save })).toHaveCount(0);
  await expect(page.getByRole("button", { name: LB.form.undo })).toHaveCount(0);
  expect(labelsOf(shown)).toBe(1);
  // Whatever the server sends beside `frozen: true`, the page shows no cluster of it: the next one is not there.
  expect(await page.locator("body").innerText()).not.toContain(other(shown).agent);
  // A reload says the same, straight from `labels/next`; and the API refuses a second undo the same way.
  await page.reload();
  await expect(page.getByRole("heading", { name: LB.frozen.title })).toBeVisible();
  const token = await apiLogin(request, "admin");
  const again = await apiPost(request, "/api/admin/labels/undo", { token, data: {} });
  expect(again.status).toBe(409);
  expect((again.body as { detail: unknown }).detail).toEqual({ reason: "frozen" });

  // ---- Review Focus 5, in the browser: from the first load of the page to here, the only calls to the API were
  // the three label routes, the shell's own session read (`GET /api/auth/me`) and the live socket (`/api/ws`):
  // the last two carry nothing about a cluster. No alert, case or queue route was ever asked for.
  expect([...new Set(calls())].sort()).toEqual([
    "GET /api/admin/labels/next",
    "GET /api/auth/me",
    "POST /api/admin/labels",
    "POST /api/admin/labels/undo",
    "WS /api/ws",
  ]);
  // Each write went once: two saves, and two undos (the one that worked and the one the freeze refused).
  expect(calls().filter((call) => call === "POST /api/admin/labels")).toHaveLength(2);
  expect(calls().filter((call) => call === "POST /api/admin/labels/undo")).toHaveLength(2);
  expect((await socketsSeen(page)).opened).toBeGreaterThan(0);
});

// ---------------------------------------------------------------------------------------------------------
// Scenario 9

test("scenario 9: the audit page shows the events of the steps above, and no label or confidence", async ({
  page,
}) => {
  const labelled = made.labelled;
  expect(labelled, "scenario 8 labelled a cluster").toBeDefined();
  if (labelled === undefined) return;
  const traffic = captureTraffic(page);
  await loginAs(page, "admin");
  await openPage(page, A.nav.audit, /\/admin\/audit$/, A.title.audit);

  // Only this admin's events: the filter is in the URL, and the table is what it asked for.
  await page.getByLabel(P.actorLabel).fill(usernameOf("admin"));
  await page.getByRole("button", { name: P.apply, exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`actor=${usernameOf("admin")}`));
  const table = page.getByRole("table", { name: P.table });
  const rows = (type: string) => table.locator("tr[data-audit-id]").filter({ hasText: type });
  await expect(rows("admin.user_created")).toHaveCount(1);

  // Step 2: the account was created, and named.
  await expect(rows("admin.user_created")).toContainText(P.summary.userCreated(NEW_USER));
  await expect(rows("admin.user_created")).toContainText(made.newUserId ?? "");
  // Steps 2b and 3: an unlock and a role change of that account, which are both `admin.user_updated`.
  const updates = rows("admin.user_updated").filter({ hasText: made.newUserId ?? "" });
  await expect(updates.filter({ hasText: P.summary.userUnlock })).toHaveCount(1);
  // (the summary says the roles as the header chip does)
  await expect(
    updates.filter({ hasText: P.summary.userRole(S.role.tier1, S.role.tier2) }),
  ).toHaveCount(1);
  // Step 5: two limit changes, down and up, each naming the cap.
  const limits = rows("admin.settings_changed");
  await expect(limits).toHaveCount(2);
  await expect(limits.filter({ hasText: P.summary.limitName.LLM_MONTHLY_USD_CAP })).toHaveCount(2);
  // Step 6: the rule, created (off to on) and disabled.
  const rule = made.rule;
  expect(rule).toBeDefined();
  const toggles = rows("admin.autoclose_rule_toggled").filter({ hasText: rule?.id ?? "" });
  await expect(toggles).toHaveCount(2);
  await expect(
    toggles.filter({
      hasText: P.summary.ruleToggled(rule?.name ?? "", P.summary.off, P.summary.on),
    }),
  ).toHaveCount(1);
  await expect(
    toggles.filter({
      hasText: P.summary.ruleToggled(rule?.name ?? "", P.summary.on, P.summary.off),
    }),
  ).toHaveCount(1);
  // Step 7: the review and the reopening.
  await expect(rows("autoclose.reviewed")).toHaveCount(1);
  await expect(rows("autoclose.reviewed")).toContainText(made.closed?.id ?? "");
  await expect(rows("alert.reopened")).toHaveCount(1);
  // Step 8: three `label.created` events (a label, its undo, the label again), each naming the cluster.
  const created = rows("label.created");
  await expect(created).toHaveCount(3);
  await expect(created.filter({ hasText: P.summary.labelled(labelled.id) })).toHaveCount(2);
  await expect(created.filter({ hasText: P.summary.labelUndone(labelled.id) })).toHaveCount(1);

  // DEC-204: not what was chosen. The event stays in the log with its cluster, its labeller and its set, and
  // the two keys of the verdict are there with the server's mark in place of their values: in the payloads when
  // they are opened, in what the server sent, and nowhere else on the page.
  for (let i = 0; i < 3; i += 1) {
    await created.nth(i).locator('button[aria-expanded="false"]').click();
  }
  const payloads = page.locator('tr[id^="audit-payload-"]');
  await expect(payloads).toHaveCount(3);
  const opened = (await payloads.allInnerTexts()).map(
    (text) => JSON.parse(text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1)) as Payload,
  );
  const labelling = opened.filter((payload) => payload.undo !== true);
  const undo = opened.filter((payload) => payload.undo === true);
  expect(labelling).toHaveLength(2);
  expect(undo).toHaveLength(1);
  for (const payload of labelling) {
    expect(payload.label).toBe(HIDDEN_MARK);
    expect(payload.confidence).toBe(HIDDEN_MARK);
    expect(payload.gold_set).toBe("G2");
    expect(payload.alert_id).toBe(labelled.id);
    expect(payload.labeler_id).toMatch(/^[0-9a-f-]{36}$/);
  }
  // The undo carries no verdict to hide.
  expect(Object.keys(undo[0] ?? {}).sort()).toEqual(["alert_id", "labeler_id", "undo"]);
  const everything = await page.locator("body").innerText();
  for (const chosen of ["benign", LB.form.choices.benign, LB.form.confidences[3]]) {
    expect(everything.includes(chosen), "the audit page shows what was chosen").toBe(false);
  }
  const events = (await traffic.answers())
    .filter((a) => a.path.startsWith("/api/admin/audit") && a.status === 200)
    .flatMap(
      (a) => (JSON.parse(a.text) as { events: { event_type: string; payload: Payload }[] }).events,
    )
    .filter((event) => event.event_type === "label.created");
  expect(events.length).toBeGreaterThanOrEqual(3);
  for (const event of events) {
    for (const key of ["label", "confidence"] as const) {
      expect([undefined, HIDDEN_MARK], `${key} of a label.created event`).toContain(
        event.payload[key],
      );
    }
  }
  // The log did not lose the verdict: the database holds what was chosen, and the page is what hides it.
  expect(
    sql(
      `SELECT count(*) FROM audit_events WHERE event_type = 'label.created' AND payload->>'label' = 'benign' AND payload->>'confidence' = '3'`,
    ),
  ).toBe("2");
});

// ---------------------------------------------------------------------------------------------------------
// Scenario 10

test("scenario 10: a Tier 1 user opening /admin/users gets the 403 notice, and the API refuses", async ({
  page,
  request,
}) => {
  await loginAs(page, "t1");
  const calls = await openRecorded(page, "/admin/users");
  // The guard sends them to the queue and says why; the admin pages never asked the API for anything.
  await expect(page).toHaveURL(/\/queue$/);
  await expect(page.getByRole("alert").filter({ hasText: S.forbidden })).toBeVisible();
  await expect(page.getByRole("heading", { name: A.title.users })).toHaveCount(0);
  expect(calls().filter((call) => call.includes("/api/admin/"))).toEqual([]);
  await expect(page.getByRole("banner").getByRole("link", { name: S.nav.admin })).toHaveCount(0);

  // The API refuses on its own, for every route of the console, and writes what it refused.
  const token = await apiLogin(request, "t1");
  const t1 = userIdOf("t1");
  const users = sql("SELECT count(*) FROM users");
  const denied = eventCount("authz.denied");
  const reads = [
    "/api/admin/overview",
    "/api/admin/users",
    "/api/admin/llm/usage",
    "/api/admin/rules",
    "/api/admin/digest",
    "/api/admin/audit",
    `/api/admin/labels/next?labeler=${t1}`,
  ];
  for (const path of reads) {
    expect((await apiGet(request, path, { token })).status, `GET ${path}`).toBe(403);
  }
  const create = await apiPost(request, "/api/admin/users", {
    token,
    data: {
      username: "e2e-sneaky",
      display_name: "Sneaky",
      role: "admin",
      password: newUserPassword(),
    },
  });
  expect(create.status).toBe(403);
  expect(
    (await apiPatch(request, `/api/admin/users/${t1}`, { token, data: { role: "admin" } })).status,
  ).toBe(403);
  expect(
    (await apiPut(request, "/api/admin/llm/limits", { token, data: { cap_usd: 1 } })).status,
  ).toBe(403);
  expect((await apiPost(request, "/api/admin/labels/undo", { token, data: {} })).status).toBe(403);
  expect((await apiPost(request, "/api/admin/reload-inventory", { token, data: {} })).status).toBe(
    403,
  );
  // Nothing changed, and every refusal is an event.
  expect(sql("SELECT count(*) FROM users")).toBe(users);
  expect(sql(`SELECT role FROM users WHERE user_id = '${t1}'`)).toBe("tier1");
  expect(eventCount("authz.denied")).toBe(denied + reads.length + 5);
  expect(eventCount("authz.denied", "/api/admin/users")).toBeGreaterThanOrEqual(3);
});
