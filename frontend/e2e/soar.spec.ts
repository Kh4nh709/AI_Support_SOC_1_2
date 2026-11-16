// The page "Phản hồi SOAR" on the real stack (SR-T3): n8n pushes review tickets and a notice through the real webhook
// (`POST /webhook/soar-notices`, with the run's key), the analysts keep, undo and mark them false positive through the real page,
// and the web calls n8n's `soar-approval` webhook, which on this stack is a stand-in on a loopback port (scripts/ui_e2e_n8n.py: the
// stand-in of scripts/mock_n8n_approval.py, whose answer a spec sets through a file). Nothing is faked in the browser: the API, the
// database, the audit trail and the decision flow are the real ones.
//
// The tickets of each test are its own (an id of its own), so the tests do not depend on one another, but they share the one
// database: a count is always read before and after, never assumed.
import { expect, test, type Page } from "@playwright/test";
import { S, apiGet, apiLogin, apiPost, loginAs, sql } from "./fixtures";
import {
  blockIpBody,
  eventsOf,
  killProcessBody,
  n8nLog,
  newNoticeId,
  newReviewId,
  noticeBody,
  openCount,
  pressFromApi,
  pushNew,
  pushTicket,
  pushWithWrongKey,
  setN8nMode,
  stateOf,
} from "./soarFixtures";

/** The row of a ticket, found through the button that opens its detail. */
const rowOf = (page: Page, id: string) =>
  page.getByRole("button", { name: S.soar.detail.open(id) }).locator("xpath=ancestor::tr");
/** The cell of a row by its column (the table of the review tabs: Phiếu, Thời gian, Case, Kịch bản, Máy, Đối tượng, Hành động, Điểm, Trạng thái, Thao tác). */
const STATUS_CELL = 8;
const statusOf = (page: Page, id: string) => rowOf(page, id).getByRole("cell").nth(STATUS_CELL);
const navLink = (page: Page) =>
  page
    .getByRole("navigation", { name: S.nav.label })
    .getByRole("link", { name: new RegExp(S.nav.soar) });
/** What the Tier-2 analyst writes in the note of an undo. */
const NOTE = "e2e: máy sạch, đã kiểm tra với chủ máy";
const toast = (page: Page, text: string) => page.getByRole("status").filter({ hasText: text });

/** Every decision the page posts for `id`: the status it got and the outcome of the answer. */
function watchDecisions(page: Page, id: string): { status: number; outcome: string | null }[] {
  const seen: { status: number; outcome: string | null }[] = [];
  page.on("response", (res) => {
    if (
      res.request().method() !== "POST" ||
      new URL(res.url()).pathname !== `/api/soar/reviews/${id}/decision`
    )
      return;
    void res.json().then(
      (body: { outcome?: string }) =>
        seen.push({ status: res.status(), outcome: body.outcome ?? null }),
      () => seen.push({ status: res.status(), outcome: null }),
    );
  });
  return seen;
}

test("n8n pushes a block_ip review, a kill_process review and a notice: Tier 1 sees the three, the badge counts the reviews, and keeping the block calls n8n", async ({
  page,
  request,
}) => {
  const before = await openCount(request, "t1");
  const block = blockIpBody();
  const kill = killProcessBody();
  const notice = noticeBody({ title: "SOAR TẠM DỪNG E2E", note: "pfSense không phản hồi" });
  const blockId = await pushNew(request, block);
  const killId = await pushNew(request, kill);
  await pushNew(request, notice);

  // the webhook is guarded: a wrong key is refused, a resend is an update and not a second ticket
  expect(await pushWithWrongKey(request, block)).toBe(401);
  const again = await pushTicket(request, {
    ...block,
    event: "updated",
    sent_at: new Date(Date.now() + 1000).toISOString().replace("Z", "+00:00"),
  });
  expect(again.status).toBe(200);
  expect(again.body).toEqual({ id: blockId, created: false });

  await loginAs(page, "t1");
  // the badge of the header counts the open REVIEWS (not the notice), asked of the API at mount
  await expect(navLink(page)).toHaveAccessibleName(`${S.nav.soar} ${S.soar.badge.sr(before + 2)}`);

  await navLink(page).click();
  await expect(page).toHaveURL(/\/soar$/);
  await expect(page.getByRole("heading", { level: 1, name: S.soar.title })).toBeVisible();
  // the two reviews are rows, in the open tab, with the status Đang mở
  await expect(rowOf(page, blockId)).toBeVisible();
  await expect(rowOf(page, killId)).toBeVisible();
  await expect(statusOf(page, blockId)).toContainText(S.soar.status.open);
  await expect(rowOf(page, blockId)).toContainText("Chặn IP 79.79.78.202 trên pfSense");
  await expect(rowOf(page, blockId)).toContainText("Quét cổng từ bên ngoài");
  await expect(rowOf(page, killId)).toContainText("Kết thúc mimikatz.exe trên WIN-DC01");
  // the notice is a line above the table, with the word of its severity
  const strip = page.getByRole("region", { name: S.soar.notice.heading });
  await expect(strip.getByText("SOAR TẠM DỪNG E2E")).toBeVisible();
  await expect(strip.getByText(S.soar.severity.warning, { exact: true })).toBeVisible();

  // Tier 1 may keep, and may not undo (SOAR_ROLES_UNDO is tier2 and admin by default): the undo button is not there
  const blockRow = rowOf(page, blockId);
  await expect(blockRow.getByRole("button", { name: "✅ Giữ chặn" })).toBeEnabled();
  await expect(blockRow.getByRole("button", { name: "↩️ Gỡ chặn IP" })).toHaveCount(0);
  // the killed process offers keep and false positive, and nothing to undo
  await expect(rowOf(page, killId).getByRole("button", { name: "✅ Giữ (đã kill)" })).toBeEnabled();
  await expect(rowOf(page, killId).getByRole("button", { name: "🚫 Báo nhầm" })).toBeEnabled();

  const decisions = watchDecisions(page, blockId);
  await blockRow.getByRole("button", { name: "✅ Giữ chặn" }).click();
  await expect(statusOf(page, blockId)).toContainText(S.soar.status.kept);
  await expect(toast(page, S.soar.result.toast(blockId, S.soar.status.kept))).toBeVisible();
  await expect.poll(() => decisions).toEqual([{ status: 200, outcome: "ok" }]);
  // the badge follows the decision: one review fewer is open
  await expect(navLink(page)).toHaveAccessibleName(`${S.nav.soar} ${S.soar.badge.sr(before + 1)}`);
  // kept: the buttons that remain are the ones the role may press, and a Tier-1 user has none
  await expect(blockRow.getByRole("button", { name: "↩️ Gỡ chặn IP" })).toHaveCount(0);

  // the database, the audit trail and n8n's stand-in all say the same
  expect(stateOf(blockId)).toBe("kept|e2e-t1");
  expect(eventsOf(blockId)).toEqual([
    "soar.review_received|created||",
    "soar.review_received|updated||", // the resend of the push above
    "soar.review_decided|ok|keep|",
  ]);
  await expect
    .poll(() =>
      n8nLog().some((line) =>
        line.includes(`decision=keep review=${blockId} user=e2e-t1 role=tier1`),
      ),
    )
    .toBe(true);
});

test("Tier 2 undoes a kept block through the dialog with a note, the history shows both decisions and who took them, and marks the killed process a false positive", async ({
  page,
  request,
}) => {
  const block = blockIpBody();
  const blockId = await pushNew(request, block);
  const kill = killProcessBody();
  const killId = await pushNew(request, kill);
  // Tier 1 keeps the block, from outside the page, so that the page has a kept ticket to undo
  const kept = await pressFromApi(request, "t1", blockId, "keep");
  expect(kept.status).toBe(200);
  expect((kept.body as { outcome: string }).outcome).toBe("ok");

  await loginAs(page, "t2");
  await page.goto("/soar?tab=done");
  const row = rowOf(page, blockId);
  await expect(statusOf(page, blockId)).toContainText(S.soar.status.kept);
  // after Giữ the undo button is still there (Tier 2 may take it), and keep is not
  await expect(row.getByRole("button", { name: "↩️ Gỡ chặn IP" })).toBeEnabled();
  await expect(row.getByRole("button", { name: "✅ Giữ chặn" })).toHaveCount(0);

  await row.getByRole("button", { name: "↩️ Gỡ chặn IP" }).click();
  const dialog = page.getByRole("dialog", { name: S.soar.dialog.title.undo });
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByText(S.soar.dialog.subject(blockId, "Chặn IP 79.79.78.202 trên pfSense")),
  ).toBeVisible();
  await expect(dialog.getByText(S.soar.dialog.after.undo)).toBeVisible();
  // an ordinary ticket: no stronger warning, and the confirm is not shut
  await expect(dialog.getByRole("checkbox")).toHaveCount(0);
  const note = dialog.getByRole("textbox", { name: S.soar.dialog.note });
  await expect(note).toBeFocused();
  await note.fill(NOTE);
  await expect(dialog.getByText(S.soar.dialog.noteCount(NOTE.length, 500))).toBeVisible();
  const decisions = watchDecisions(page, blockId);
  await dialog.getByRole("button", { name: S.soar.dialog.confirm.undo }).click();
  await expect(dialog).toHaveCount(0);

  await expect(statusOf(page, blockId)).toContainText(S.soar.status.undone);
  await expect(row.getByText(S.soar.result.ok(S.soar.status.undone))).toBeVisible();
  await expect.poll(() => decisions).toEqual([{ status: 200, outcome: "ok" }]);
  expect(stateOf(blockId)).toBe("undone|e2e-t2");
  expect(eventsOf(blockId)).toEqual([
    "soar.review_received|created||",
    "soar.review_decided|ok|keep|",
    `soar.review_decided|ok|undo|${NOTE}`,
  ]);

  // the detail panel: the history, in Vietnamese, with who took each decision
  await row.getByRole("button", { name: S.soar.detail.open(blockId) }).click();
  const panel = page.getByRole("region", { name: S.soar.detail.title(blockId) });
  const history = panel.getByRole("table", { name: S.soar.detail.history.label });
  const rows = history.getByRole("row");
  await expect(rows).toHaveCount(4); // the header and three events
  const cells = async (index: number) =>
    (await rows.nth(index).getByRole("cell").allTextContents()).map((t) => t.trim());
  const first = await cells(1);
  expect(first.slice(1, 4)).toEqual(["Nhận phiếu từ SOAR", "Hệ thống", "Tạo mới"]);
  const second = await cells(2);
  expect(second.slice(1, 4)).toEqual(["Quyết định trên web", "e2e-t1 (Tier 1)", "Thành công"]);
  expect(second[4]).toContain("Quyết định: Giữ");
  const third = await cells(3);
  expect(third.slice(1, 4)).toEqual(["Quyết định trên web", "e2e-t2 (Tier 2)", "Thành công"]);
  expect(third[4]).toContain("Quyết định: Gỡ");
  expect(third[4]).toContain(`Ghi chú: ${NOTE}`);
  expect(third[4]).toContain("Đã giữ → Đã gỡ");
  await expect(panel.getByText(S.soar.detail.field.decidedBy, { exact: true })).toBeVisible();
  await expect(panel.getByText("e2e-t2", { exact: true }).first()).toBeVisible();
  // the raw body n8n sent is there, closed, as text
  await expect(panel.locator("details")).not.toHaveAttribute("open", "");
  await panel.getByRole("button", { name: S.soar.detail.close }).click();

  // the killed process: Tier 2 marks it a false positive, through the dialog (no note)
  await page.goto("/soar");
  const killRow = rowOf(page, killId);
  await expect(killRow.getByRole("button", { name: "🚫 Báo nhầm" })).toBeEnabled();
  await killRow.getByRole("button", { name: "🚫 Báo nhầm" }).click();
  const fpDialog = page.getByRole("dialog", { name: S.soar.dialog.title.fp });
  await expect(fpDialog.getByText(S.soar.dialog.after.fp)).toBeVisible();
  await fpDialog.getByRole("button", { name: S.soar.dialog.confirm.fp }).click();
  await expect(statusOf(page, killId)).toContainText(S.soar.status.false_positive);
  expect(stateOf(killId)).toBe("false_positive|e2e-t2");
  expect(eventsOf(killId)).toEqual([
    "soar.review_received|created||",
    "soar.review_decided|ok|fp|",
  ]);
});

test("with n8n failing, an undo shows the failure on the row and the buttons come back; once n8n answers, the next press goes through", async ({
  page,
  request,
}) => {
  const blockId = await pushNew(request, blockIpBody());
  expect((await pressFromApi(request, "t1", blockId, "keep")).status).toBe(200);

  await loginAs(page, "t2");
  await page.goto("/soar?tab=done");
  const row = rowOf(page, blockId);
  await expect(statusOf(page, blockId)).toContainText(S.soar.status.kept);

  setN8nMode("fail");
  try {
    await row.getByRole("button", { name: "↩️ Gỡ chặn IP" }).click();
    await page
      .getByRole("dialog", { name: S.soar.dialog.title.undo })
      .getByRole("button", { name: S.soar.dialog.confirm.undo })
      .click();
    // the message of n8n, in an error line on the row; the status is what it was, and the buttons are back
    const failure = row.getByRole("alert").filter({ hasText: "GIẢ LẬP THẤT BẠI" });
    await expect(failure).toBeVisible();
    await expect(failure).toContainText("người bấm: e2e-t2");
    await expect(statusOf(page, blockId)).toContainText(S.soar.status.kept);
    await expect(row.getByRole("button", { name: "↩️ Gỡ chặn IP" })).toBeEnabled();
    expect(stateOf(blockId)).toBe("kept|e2e-t1");
    const events = eventsOf(blockId);
    expect(events.at(-1)).toBe("soar.review_decided|failed|undo|");
    // the web stored what n8n said, so a reload shows it again
    expect(
      sql(`SELECT last_error LIKE 'GIẢ LẬP THẤT BẠI%' FROM soar_reviews WHERE id = '${blockId}'`),
    ).toBe("t");
    await page.reload();
    await expect(rowOf(page, blockId).getByText(/GIẢ LẬP THẤT BẠI/)).toBeVisible();
  } finally {
    setN8nMode("ok");
  }

  // n8n answers again: the same button now works
  await rowOf(page, blockId).getByRole("button", { name: "↩️ Gỡ chặn IP" }).click();
  await page
    .getByRole("dialog", { name: S.soar.dialog.title.undo })
    .getByRole("button", { name: S.soar.dialog.confirm.undo })
    .click();
  await expect(statusOf(page, blockId)).toContainText(S.soar.status.undone);
  expect(stateOf(blockId)).toBe("undone|e2e-t2");
  expect(sql(`SELECT last_error IS NULL FROM soar_reviews WHERE id = '${blockId}'`)).toBe("t");
});

test("a ticket handled elsewhere: n8n says so, and the row shows the status n8n gave", async ({
  page,
  request,
}) => {
  const blockId = await pushNew(request, blockIpBody());
  await loginAs(page, "t1");
  await page.goto("/soar");
  setN8nMode("conflict");
  try {
    await rowOf(page, blockId).getByRole("button", { name: "✅ Giữ chặn" }).click();
    // the stand-in answers 409 with the status `undone`: the web writes it down and says it was handled elsewhere
    await expect(statusOf(page, blockId)).toContainText(S.soar.status.undone);
    await expect(
      rowOf(page, blockId).getByText(S.soar.result.conflict(S.soar.status.undone)),
    ).toBeVisible();
    expect(stateOf(blockId)).toContain("undone|");
    expect(eventsOf(blockId).at(-1)).toContain("soar.review_decided|conflict|keep|");
  } finally {
    setN8nMode("ok");
  }
});

test("what n8n writes is text: a ticket whose labels and notice carry markup renders as characters, runs nothing, and opens no dialog", async ({
  page,
  request,
}) => {
  const IMG = "<img src=x onerror=window.__pwned=1>";
  const hostile = blockIpBody({
    title: IMG,
    actionText: `${IMG} Chặn IP javascript:window.__pwned=1`,
    host: "<svg onload=window.__pwned=1>",
    scenarioName: `${IMG}${"A".repeat(300)}`,
    note: IMG,
    buttons: [
      { decision: "keep", label: `${IMG}Giữ` },
      { decision: "undo", label: "<b onclick=window.__pwned=1>Gỡ</b>" },
    ],
  });
  const hostileId = await pushNew(request, hostile);
  const hostileNotice = noticeBody({
    id: newNoticeId(),
    title: IMG,
    note: "javascript:window.__pwned=1",
    severity: "error",
  });
  await pushNew(request, hostileNotice);

  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.name));
  await loginAs(page, "t1");
  await page.goto("/soar");
  const row = rowOf(page, hostileId);
  await expect(row).toBeVisible();
  // the characters are shown, as characters
  await expect(row.getByText(IMG, { exact: false }).first()).toBeVisible();
  await expect(row.getByRole("cell").nth(4)).toHaveText("<svg onload=window.__pwned=1>");
  await expect(
    page.getByRole("region", { name: S.soar.notice.heading }).getByText(IMG, { exact: true }),
  ).toBeVisible();
  // and nothing was made of them
  await expect(page.locator("main img, main svg, main script, main iframe, main b")).toHaveCount(0);
  await expect(
    page.locator("main [onerror], main [onload], main [onclick], main [style]"),
  ).toHaveCount(0);
  await expect(page.locator('main a[href^="javascript"]')).toHaveCount(0);
  expect(
    await page.evaluate(() => (window as unknown as { __pwned?: unknown }).__pwned),
  ).toBeUndefined();
  await expect(page.getByRole("dialog")).toHaveCount(0);

  // a press of the label that is markup is a press of a button, and keeps the ticket
  await row.getByRole("button", { name: `${IMG}Giữ` }).click();
  await expect(statusOf(page, hostileId)).toContainText(S.soar.status.kept);
  // the detail panel shows the body n8n sent as text too
  await row.getByRole("button", { name: S.soar.detail.open(hostileId) }).click();
  const panel = page.getByRole("region", { name: S.soar.detail.title(hostileId) });
  await panel.getByText(S.soar.detail.raw.summary).click();
  await expect(panel.locator("details pre")).toContainText(IMG);
  // the title of the ticket is one of its fields: text too
  await expect(panel.getByText(IMG, { exact: true }).first()).toBeVisible();
  await expect(page.locator("main img, main svg, main b")).toHaveCount(0);
  expect(
    await page.evaluate(() => (window as unknown as { __pwned?: unknown }).__pwned),
  ).toBeUndefined();
  expect(errors).toEqual([]);
  expect(stateOf(hostileId)).toBe("kept|e2e-t1");
});

test("the API agrees with the page: the roles of a press, the 409 of a second press, and the closed set of the webhook", async ({
  request,
}) => {
  const id = await pushNew(request, blockIpBody());
  // Tier 1 may not undo an open ticket: the web refuses before it calls n8n (403), and n8n is not asked
  const asked = n8nLog().length;
  const refused = await pressFromApi(request, "t1", id, "undo");
  expect(refused.status).toBe(403);
  expect(n8nLog().length).toBe(asked);
  // a second keep after the first is a 409 invalid_state with the ticket as it is
  expect((await pressFromApi(request, "t1", id, "keep")).status).toBe(200);
  const second = await pressFromApi(request, "t2", id, "keep");
  expect(second.status).toBe(409);
  const detail = (second.body as { detail: { reason: string; review: { status: string } } }).detail;
  expect(detail.reason).toBe("invalid_state");
  expect(detail.review.status).toBe("kept");
  // a note the database cannot store is refused (422) and nothing is sent to n8n
  const token = await apiLogin(request, "t2");
  const lengthBefore = n8nLog().length;
  const bad = await apiPost(request, `/api/soar/reviews/${id}/decision`, {
    token,
    data: { decision: "undo", note: "a\u0000b" },
  });
  expect(bad.status).toBe(422);
  expect(bad.body).toEqual({ detail: { field: "note", reason: "invalid" } });
  expect(n8nLog().length).toBe(lengthBefore);
  // the list the page reads, with the filters it sends
  const list = await apiGet(
    request,
    "/api/soar/reviews?kind=review&status=kept&q=" + encodeURIComponent("79.79"),
    { token },
  );
  expect(list.status).toBe(200);
  const rows = (
    list.body as { rows: { id: string; allowed_decisions: string[]; host_critical: boolean }[] }
  ).rows;
  const mine = rows.find((r) => r.id === id);
  expect(mine?.allowed_decisions).toEqual(["undo"]);
  expect(mine?.host_critical).toBe(false);
  // the ids of tickets of this test are unused elsewhere
  expect(newReviewId()).not.toBe(id);
});
