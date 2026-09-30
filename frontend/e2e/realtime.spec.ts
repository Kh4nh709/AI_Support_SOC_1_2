// The live queue on the real stack (P10-T12, DEC-162): an alert that reaches the database appears in a queue
// that is already open, pushed by the socket. Nothing here sleeps or reloads, and while the socket is live the
// queue does not poll, so an alert that shows up has been announced: a missing NOTIFY is a row that never comes.
import { expect, test } from "@playwright/test";
import { S, captureTraffic, loginAs, postAlert } from "./fixtures";

/** From the moment the webhook has answered to the row on the screen (spec §3: real time, not a refresh). */
const APPEAR_WITHIN_MS = 2_000;

type Marked = Window & { __e2eOpened?: number };

test("a new alert appears in the open queue within 2 s, with no reload", async ({
  page,
  request,
}) => {
  const traffic = captureTraffic(page);
  const navigations: string[] = [];
  page.on("framenavigated", (frame) => {
    if (frame === page.mainFrame()) navigations.push(frame.url());
  });

  await loginAs(page, "t1");
  await expect(page.getByRole("heading", { name: S.queue.title })).toBeVisible();
  // The socket is open and has said it is ready: the header says so only then.
  await expect(page.getByRole("status").filter({ hasText: S.live.on })).toBeVisible();
  // A mark on this document: a reload, or a new document, would lose it.
  await page.evaluate(() => {
    (window as Marked).__e2eOpened = Date.now();
  });
  const opened = await page.evaluate(() => (window as Marked).__e2eOpened);
  const shownBefore = navigations.length;

  const alert = await postAlert(request, { tag: "live", arm: "visible" });
  const posted = Date.now();
  const row = page.locator(`a[href="/alerts/${alert.id}"]`);
  await expect(row).toBeVisible({ timeout: APPEAR_WITHIN_MS });
  // For the report: how much of the budget the push used (the worker's own poll is part of it).
  console.log(
    `realtime: the row was on screen ${Date.now() - posted} ms after the webhook answered`,
  );
  await expect(row).toHaveText(alert.description);

  // It was pushed, not fetched by a reload: the same document, and a frame of the socket named the alert.
  expect(await page.evaluate(() => (window as Marked).__e2eOpened)).toBe(opened);
  expect(navigations.length).toBe(shownBefore);
  const announced = traffic.frames().filter((frame) => frame.includes(`"${alert.id}"`));
  expect(announced.length, "a socket frame named the alert").toBeGreaterThan(0);
});
