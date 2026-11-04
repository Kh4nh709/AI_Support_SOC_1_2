// The blind arm on the real stack (P10-T12, DEC-101, R12, R17). A head whose alert id falls in the blind arm
// has a ① answer in the database, and until a person decides it nothing of that answer may reach a browser:
// not the page, not any answer of the API, not a frame of the live socket. The keys of the answer are absent
// (not null), and so are `triaged_count` and `needs_retriage`, which would say that ① ran. After the decision
// the answer is shown.
//
// P14-T03 (DEC-213): ① always concludes `false_positive | true_positive`, and the alert page says what the AI
// concluded and why the system held it ("AI kết luận: FP ... — hệ thống giữ lại cho người xem vì: ..."). The
// stub's proposer concludes `false_positive`, which gate step 4 holds as `needs_review` (it cites no playbook
// rule), so a blind head carries both: the model's own answer (`proposed_action`) and the reasons (`held_by`).
// Neither may reach the browser, nor the sentence made of them.
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
import { wordsFound } from "../src/testing/containsWord";

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
  "proposed_action",
  "held_by",
] as const;

/** The value of ①'s verdict on this head: the one `suggested_action` the stub's proposer wrote. */
const VERDICT = "needs_review";

/** What the stub's proposer itself concluded (the gate then held it as `VERDICT`): ①'s answer, so also hidden. */
const PROPOSED = "false_positive";

/** A reason the gate held it for (`llm.verdicts.HELD_REASONS`): a closed code, ①'s account of itself. */
const HELD_REASON =
  /^(facts_mismatch|no_verified_quote|fp_policy:[a-z_]+|verifier_disagrees|verifier_invalid)$/;

/** What is distinctive of ①'s conclusion line, so it is looked for on the whole page: the line and its bold half. */
const CONCLUSION_PHRASES = [S.ai1.conclusion, S.ai1.held] as const;

/**
 * What a leak of the conclusion would put in the AI column, and only there: the words of every reason (an
 * alert's own text or a playbook line may say "tài khoản đặc quyền"; that is not a leak), and the two labels of a
 * verdict as WORDS ("SFTP" is not "TP").
 */
const COLUMN_MARKERS = [...Object.values(S.ai1.heldReason), "FP", "TP"] as const;

/** The labels of the reasons the gate held the stub's verdict for, read from the database (step 4's fields). */
function heldLabels(id: string): string[] {
  const fields = sql(
    "SELECT string_agg(m, ',' ORDER BY ord) FROM llm_runs r, " +
      "jsonb_array_elements_text(r.gate_result->'missing') WITH ORDINALITY AS t(m, ord) " +
      `WHERE r.pipeline = 'triage' AND r.role = 'proposer' AND r.subject_id = '${id}'`,
  ).split(",");
  expect(fields, "step 4 named the playbook rule the stub did not cite").toContain("playbook_rule");
  const wording = S.ai1.heldReason as Record<string, string>;
  const labels = fields.map((field) => wording[`fp_policy:${field}`]);
  expect(labels.every(Boolean), "every field step 4 named has a label").toBe(true);
  return labels as string[];
}

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
 * The answers that name the head (its alert id is in the body) but are not of a shape `aboutHead` reads: a row of
 * a list, or the head's own answer. The key check looks only at what `aboutHead` returns, so a new answer that
 * carries the head in another shape (a nested list, a wrapper) would skip it silently; this makes it fail here,
 * and whoever adds the shape teaches `aboutHead` to read it.
 */
function unchecked(answers: Answer[], id: string): string[] {
  return answers
    .filter((answer) => answer.text.includes(id) && aboutHead(answer, id).length === 0)
    .map((answer) => answer.path);
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
    if (strings.includes(PROPOSED)) found.push(`${answer.path}: value ${PROPOSED}`);
    if (strings.some((value) => HELD_REASON.test(value))) {
      found.push(`${answer.path}: a reason the verdict was held`);
    }
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
  await expect(row).not.toContainText(/\bFP\b/); // the AI's answer, as a word

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
    for (const phrase of CONCLUSION_PHRASES) {
      expect(seen.includes(phrase), `the page says "${phrase}" of a blind head's conclusion`).toBe(
        false,
      );
    }
  }
  await expect(page.getByText(/AI kết luận/)).toHaveCount(0);
  // The AI column itself: no reason, no verdict label as a word.
  const column = page.getByRole("region", { name: S.alert.aiHeading });
  for (const seen of [await column.innerText(), await column.innerHTML()]) {
    expect(wordsFound(seen, COLUMN_MARKERS), "the blind AI column names ①'s conclusion").toEqual(
      [],
    );
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
  expect(
    unchecked(answers, head.id),
    "every answer that names the head is of a shape the key check covers",
  ).toEqual([]);
  expect(leaks(answers, traffic.frames(), head.id)).toEqual([]);
  const beforeDecision = answers.length;

  // The decision reveals it.
  await page.getByRole("button", { name: S.decision.submit }).click();
  await expect(page.getByRole("status").filter({ hasText: S.decision.recorded })).toBeVisible();
  await expect(page.getByText(S.ai1.decidedHeading)).toBeVisible();
  // The decision lifts the arm: the AI column now says what the AI concluded and why the system held it
  // (fix round 1, I1), and "Khớp" compares the decision with the stored verdict, which was held: no verdict.
  await expect(column.getByText(/AI kết luận/)).toContainText(
    `AI kết luận: ${S.ai1.action.false_positive} (độ tin cậy trung bình) — ${S.ai1.held} vì: ${heldLabels(head.id).join(", ")}`,
  );
  // exact: the reason "không khớp bảng quyết định đã duyệt" says "khớp" too
  await expect(page.getByText(S.ai1.match, { exact: true })).toBeVisible();
  await expect(page.getByText(S.ai1.matchNoVerdict)).toBeVisible();
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

test("a visible head says what the AI concluded and why the system held it for a person", async ({
  page,
  request,
}) => {
  const head = await postAlert(request, { tag: "held", arm: "visible" });
  await waitForStatus(head.id, "queued_tier1");
  await waitForTriage(head.id);
  // The stub concludes false_positive; gate step 4 held it, and the database records which fields it named.
  const labels = heldLabels(head.id);

  await loginAs(page, "t1");
  const link = page.locator(`a[href="/alerts/${head.id}"]`);
  const row = page.getByRole("row").filter({ has: link });
  await expect(row).toContainText(S.ai1.action.needs_review); // the queue says what the system stored
  await link.click();
  await expect(page).toHaveURL(`/alerts/${head.id}`);

  const column = page.getByRole("region", { name: S.alert.aiHeading });
  await expect(column.getByText(/AI kết luận/)).toContainText(
    `AI kết luận: ${S.ai1.action.false_positive} (độ tin cậy trung bình) — ${S.ai1.held} vì: ${labels.join(", ")}`,
  );
  // the phrase is bold (spec 4.3)
  await expect(column.locator("strong", { hasText: S.ai1.held })).toHaveCount(1);
  await expect(column.getByText(S.ai1.hidden)).toHaveCount(0);
});
