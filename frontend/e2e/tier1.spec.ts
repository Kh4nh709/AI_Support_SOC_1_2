// Tier 1 on the real stack (P10-T12): the whole decision from the queue to a closed alert and a logout, the
// count guard of ruling R19, and the 401 path, where the session ends under the analyst's hands.
import { expect, test, type Page } from "@playwright/test";
import {
  S,
  apiLogin,
  apiLogout,
  loginAs,
  occurrenceCount,
  postAlert,
  postDuplicates,
  reasonBox,
  signIn,
  waitForStatus,
  type Posted,
} from "./fixtures";

/** `REVIEW_DELTA_TOLERANCE` of the stack (scripts/ui_e2e_stack.sh): a growth past it asks for a second look. */
const TOLERANCE = 20;

const rowOf = (page: Page, id: string) => page.locator(`a[href="/alerts/${id}"]`);
const toast = (page: Page, text: string) => page.getByRole("status").filter({ hasText: text });

type Decide = { seen: number | undefined; status: number; body: unknown };

/** Every decision the page posts for `id`: the count it sent, the status it got, and the answer. */
function watchDecides(page: Page, id: string): Decide[] {
  const decides: Decide[] = [];
  const isDecide = (url: string) => new URL(url).pathname === `/api/tier1/alerts/${id}/decide`;
  page.on("response", (res) => {
    if (res.request().method() !== "POST" || !isDecide(res.url())) return;
    const sent = res.request().postDataJSON() as { seen_occurrence_count?: number };
    void res.json().then(
      (body: unknown) =>
        decides.push({ seen: sent.seen_occurrence_count, status: res.status(), body }),
      () => decides.push({ seen: sent.seen_occurrence_count, status: res.status(), body: null }),
    );
  });
  return decides;
}

/** A head in the queue and held by the signed-in Tier-1 user, on its page, with the decide form drawn. */
async function holdHead(page: Page, head: Posted): Promise<void> {
  await page.goto(`/alerts/${head.id}`);
  await page.getByRole("button", { name: S.decision.acknowledge }).click();
  await expect(toast(page, S.decision.acknowledged)).toBeVisible();
  await expect(page.getByRole("button", { name: S.decision.submit })).toBeVisible();
}

test("Tier 1 takes an alert, closes it as a false positive with a reason, and signs out", async ({
  page,
  request,
}) => {
  const head = await postAlert(request, { tag: "decide", arm: "visible" });
  await waitForStatus(head.id, "queued_tier1");

  await loginAs(page, "t1");
  await expect(page.getByRole("heading", { name: S.queue.title })).toBeVisible();
  await rowOf(page, head.id).click();
  await expect(page).toHaveURL(`/alerts/${head.id}`);

  await page.getByRole("button", { name: S.decision.acknowledge }).click();
  await expect(toast(page, S.decision.acknowledged)).toBeVisible();

  await page.getByLabel(S.decision.falsePositive).check();
  await reasonBox(page).fill("Routine noise of a test host, confirmed with its owner.");
  await page.getByRole("button", { name: S.decision.submit }).click();
  await expect(toast(page, S.decision.recorded)).toBeVisible();
  // The alert is closed: the page says how, and there is nothing left to decide.
  await expect(page.getByText(S.decision.decidedAs(S.status.closed_fp))).toBeVisible();
  await expect(page.getByRole("button", { name: S.decision.submit })).toHaveCount(0);

  // It has left the queue.
  await page
    .getByRole("navigation", { name: S.nav.label })
    .getByRole("link", { name: S.nav.queue })
    .click();
  await expect(page.getByRole("heading", { name: S.queue.title })).toBeVisible();
  await expect(rowOf(page, head.id)).toHaveCount(0);

  // Signing out is final: the logout has reached the server before the test ends (it would otherwise end a
  // later test's login), and going back does not show a page of the session that ended.
  const loggedOut = page.waitForResponse(
    (res) =>
      new URL(res.url()).pathname === "/api/auth/logout" && res.request().method() === "POST",
  );
  await page.getByRole("button", { name: S.nav.logout }).click();
  await expect(page).toHaveURL(/\/login$/);
  await loggedOut;
  await page.goBack();
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: S.login.title })).toBeVisible();
});

test("a cluster that grew past the tolerance is refused once, and the form then holds the new count (R19)", async ({
  page,
  request,
}) => {
  const head = await postAlert(request, { tag: "stale", arm: "visible" });
  await waitForStatus(head.id, "queued_tier1");
  await loginAs(page, "t1");
  const decides = watchDecides(page, head.id);
  await holdHead(page, head);

  // The form is drawn with one occurrence, and the analyst starts to answer.
  await expect(page.getByText(S.decision.seenHint(1))).toBeVisible();
  await page.getByLabel(S.decision.falsePositive).check();
  await reasonBox(page).fill("One event, read on the page; closing as noise.");

  // While they read, more than the tolerance of duplicates arrive.
  const grown = 1 + TOLERANCE + 1;
  await postDuplicates(request, head, TOLERANCE + 1);
  await expect.poll(() => occurrenceCount(head.id), { timeout: 30_000 }).toBe(grown);

  // The page is told through the socket. The form says so beside its count and does not change the count.
  await expect(page.getByText(S.decision.seenChanged(1, grown))).toBeVisible();
  await expect(page.getByText(S.decision.seenHint(1))).toBeVisible();

  // What is sent is what was read: the server refuses, and says what it found.
  await page.getByRole("button", { name: S.decision.submit }).click();
  await expect(
    page.getByText(S.decision.conflict.clusterGrew(1, grown, TOLERANCE + 1, TOLERANCE)),
  ).toBeVisible();
  // The analyst is now shown the new count, and only now does the form hold it.
  await expect(page.getByText(S.decision.seenHint(grown))).toBeVisible();
  await expect(page.getByText(S.decision.seenChanged(grown, grown))).toHaveCount(0);
  // Their answer was kept.
  await expect(reasonBox(page)).toHaveValue("One event, read on the page; closing as noise.");
  await expect(page.getByLabel(S.decision.falsePositive)).toBeChecked();

  await page.getByRole("button", { name: S.decision.submit }).click();
  await expect(toast(page, S.decision.recorded)).toBeVisible();

  await expect.poll(() => decides.length).toBe(2);
  expect(decides.map((d) => [d.seen, d.status])).toEqual([
    [1, 409],
    [grown, 200],
  ]);
});

test("a session ended under the analyst's hands: the 401 keeps the reason, and one decision goes through", async ({
  page,
  request,
}) => {
  const head = await postAlert(request, { tag: "expire", arm: "visible" });
  await waitForStatus(head.id, "queued_tier1");
  await loginAs(page, "t1");
  const decides = watchDecides(page, head.id);
  await holdHead(page, head);

  const reason = "Written before the session ended; it must still be here after the login.";
  await page.getByLabel(S.decision.falsePositive).check();
  await reasonBox(page).fill(reason);

  // Another login of the same user signs out: every token issued before now is dead, the page's too.
  await apiLogout(request, await apiLogin(request, "t1"));

  await page.getByRole("button", { name: S.decision.submit }).click();
  await expect(page).toHaveURL(/\/login$/);
  await expect.poll(() => decides.map((d) => d.status)).toEqual([401]);

  // The login returns to the alert, and the reason is still in the box; the answer is chosen again.
  await signIn(page, "t1");
  await expect(page).toHaveURL(`/alerts/${head.id}`);
  await expect(reasonBox(page)).toHaveValue(reason);
  await page.getByLabel(S.decision.falsePositive).check();
  await page.getByRole("button", { name: S.decision.submit }).click();
  await expect(toast(page, S.decision.recorded)).toBeVisible();

  // Two posts in all, and exactly one of them recorded a decision.
  await expect.poll(() => decides.map((d) => d.status)).toEqual([401, 200]);
  await expect(page.getByText(S.decision.decidedAs(S.status.closed_fp))).toBeVisible();
});
