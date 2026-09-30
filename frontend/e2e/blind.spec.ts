// The blind arm on the real stack (P10-T12, DEC-101, R12, R17). A head whose alert id falls in the blind arm
// has a ① answer in the database, and until a person decides it nothing of that answer may reach a browser:
// not the page, not any answer of the API, not a frame of the live socket. The keys of the answer are absent
// (not null), and so are `triaged_count` and `needs_retriage`, which would say that ① ran. After the decision
// the answer is shown.
import { expect, test } from "@playwright/test";
import {
  S,
  captureTraffic,
  claimToken,
  loginAs,
  postAlert,
  reasonBox,
  sql,
  waitForStatus,
  waitForTriage,
  type Answer,
} from "./fixtures";

/** The keys `visibility.strip` removes from an undecided blind head (with R17's two). */
const HIDDEN_KEYS = [
  "suggestion",
  "suggested_action",
  "confidence",
  "gate_forced",
  "triage_status",
  "run_id",
  "triaged_count",
  "needs_retriage",
] as const;

/** The value of ①'s verdict on this head: the one `suggested_action` the stub's proposer wrote. */
const VERDICT = "needs_review";

function walk(value: unknown, keys: Set<string>, strings: string[]): void {
  if (Array.isArray(value)) {
    for (const item of value) walk(item, keys, strings);
  } else if (typeof value === "object" && value !== null) {
    for (const [key, item] of Object.entries(value)) {
      keys.add(key);
      walk(item, keys, strings);
    }
  } else if (typeof value === "string") {
    strings.push(value);
  }
}

/** What an answer of the API says about one head: its row of a list, or the whole answer when it is the head's own. */
function aboutHead(answer: Answer, id: string): unknown[] {
  let body: unknown;
  try {
    body = JSON.parse(answer.text);
  } catch {
    return [];
  }
  if (typeof body !== "object" || body === null) return [];
  const rows = (body as { rows?: unknown }).rows;
  if (Array.isArray(rows)) {
    return rows.filter((row) => (row as { alert_id?: unknown } | null)?.alert_id === id);
  }
  return (body as { alert_id?: unknown }).alert_id === id ? [body] : [];
}

/**
 * What of ① is in what the browser received, by name: the hidden keys found in the head's own JSON, the
 * verdict as a value there, and the head's token anywhere at all (in an answer about another head, in a
 * frame). Names and counts only, never a body: a body carries the session's token.
 */
function leaks(answers: Answer[], frames: string[], id: string): string[] {
  const found: string[] = [];
  const token = claimToken(id);
  for (const answer of answers) {
    const keys = new Set<string>();
    const strings: string[] = [];
    for (const part of aboutHead(answer, id)) walk(part, keys, strings);
    for (const key of HIDDEN_KEYS) if (keys.has(key)) found.push(`${answer.path}: key ${key}`);
    if (strings.includes(VERDICT)) found.push(`${answer.path}: value ${VERDICT}`);
    if (answer.text.includes(token)) found.push(`${answer.path}: the token`);
  }
  for (const frame of frames) {
    for (const key of HIDDEN_KEYS)
      if (frame.includes(`"${key}"`)) found.push(`a frame: key ${key}`);
    if (frame.includes(token)) found.push("a frame: the token");
  }
  return found;
}

test("a blind head shows nothing of ① until it is decided, then shows it", async ({
  page,
  request,
}) => {
  const head = await postAlert(request, { tag: "blind", arm: "blind" });
  const token = claimToken(head.id);
  await waitForStatus(head.id, "queued_tier1");
  await waitForTriage(head.id);
  // ① has answered, and the answer is in the database: whatever the browser lacks is being withheld.
  expect(
    Number(
      sql(
        `SELECT count(*) FROM llm_runs WHERE pipeline = 'triage' AND subject_id = '${head.id}' ` +
          `AND result->>'suggested_action' = '${VERDICT}' AND result::text LIKE '%${token}%'`,
      ),
    ),
    "the proposer's answer for the blind head is in llm_runs",
  ).toBe(1);

  const traffic = captureTraffic(page);
  await loginAs(page, "t1");
  const link = page.locator(`a[href="/alerts/${head.id}"]`);
  const row = page.getByRole("row").filter({ has: link });
  await expect(row).toContainText(S.ai1.hidden);
  await expect(row).not.toContainText(S.ai1.action.needs_review);

  await link.click();
  await expect(page).toHaveURL(`/alerts/${head.id}`);
  await expect(page.getByText(S.ai1.hiddenBody)).toBeVisible();
  await page.getByRole("button", { name: S.decision.acknowledge }).click();
  await expect(page.getByRole("status").filter({ hasText: S.decision.acknowledged })).toBeVisible();
  await page.getByLabel(S.decision.falsePositive).check();
  await reasonBox(page).fill("Read the alert and its log; routine.");

  // Before the decision: the page, every answer of the API and every frame of the socket.
  const text = await page.locator("body").innerText();
  const html = await page.content();
  for (const seen of [text, html]) {
    expect(seen.includes(token), "the page holds the head's token").toBe(false);
    expect(seen.includes(S.ai1.action.needs_review), "the page words ①'s verdict").toBe(false);
  }
  const answers = await traffic.answers();
  // The traffic includes the queue (with the row of this head) and the head's own view, or the check is empty.
  expect(
    answers.some((a) => a.path.startsWith("/api/tier1/queue") && aboutHead(a, head.id).length > 0),
  ).toBe(true);
  expect(
    answers.some(
      (a) => a.path === `/api/tier1/alerts/${head.id}` && aboutHead(a, head.id).length > 0,
    ),
  ).toBe(true);
  expect(
    answers
      .filter(
        (a) => a.path.startsWith("/api/tier1/queue") || a.path === `/api/tier1/alerts/${head.id}`,
      )
      .flatMap((a) => aboutHead(a, head.id))
      .every((part) => (part as { suggestion_visible?: unknown }).suggestion_visible === false),
    "the server says the head is blind",
  ).toBe(true);
  expect(traffic.frames().length, "the socket delivered frames").toBeGreaterThan(0);
  expect(leaks(answers, traffic.frames(), head.id)).toEqual([]);
  const beforeDecision = answers.length;

  // The decision reveals it.
  await page.getByRole("button", { name: S.decision.submit }).click();
  await expect(page.getByRole("status").filter({ hasText: S.decision.recorded })).toBeVisible();
  await expect(page.getByText(S.ai1.decidedHeading)).toBeVisible();
  await expect(page.getByText(S.ai1.action.needs_review)).toBeVisible();
  await expect(page.getByText(S.ai1.match)).toBeVisible();
  const after = (await traffic.answers()).slice(beforeDecision);
  const revealed = after
    .filter((a) => a.path === `/api/tier1/alerts/${head.id}`)
    .flatMap((a) => aboutHead(a, head.id));
  expect(
    revealed.some((part) => {
      const keys = new Set<string>();
      const strings: string[] = [];
      walk(part, keys, strings);
      return (
        keys.has("suggestion") &&
        strings.includes(VERDICT) &&
        strings.some((s) => s.includes(token))
      );
    }),
    "the decided head's view carries ①'s answer",
  ).toBe(true);
});
