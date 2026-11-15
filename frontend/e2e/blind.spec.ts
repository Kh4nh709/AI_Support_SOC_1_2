// The blind arm on the real stack (P10-T12, DEC-101, R12, R17). A head whose alert id falls in the blind arm
// has a ① answer in the database, and until a person decides it nothing of that answer may reach a browser:
// not the page, not any answer of the API, not a frame of the live socket. The keys of the answer are absent
// (not null), and so are `triaged_count` and `needs_retriage`, which would say that ① ran. After the decision
// the answer is shown.
//
// P14-T03 (DEC-213): ① always concludes `false_positive | true_positive`, and the alert page says what the AI
// concluded and which of the gate's checks warned about it ("AI kết luận: FP ... — có cảnh báo kiểm chứng: ...",
// DEC-217: the gate holds nothing back, its checks are warnings beside the verdict). The stub's proposer concludes
// `false_positive`, and gate step 4 raises a warning on it (it cites no playbook rule), so a blind head carries both:
// the model's own answer, which is also the stored verdict (`suggested_action`, `proposed_action`), and the warnings
// (`held_by`). None of them may reach the browser, nor the sentence made of them.
import { expect, test, type Locator } from "@playwright/test";
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
import { phrasesFound, wordsFound } from "../src/testing/containsWord";
import { MODEL_NAME } from "../src/testing/modelName";
import { seedFailedLookup, seedFoundLookup, seedRun } from "./ragFixtures";

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
  "rag", // P14-T07: the match percentage and the "RAG not applied" notice are ①'s account of itself
  "analysis", // DEC-221: the whole scorecard's data (checks, facts, the lookup, the history) is ①'s account of itself
] as const;

/**
 * The value of ①'s verdict on this head: the one `suggested_action` the stub's proposer wrote. DEC-217: the gate
 * keeps the model's own answer, so it is also what the model concluded (`proposed_action`).
 */
const VERDICT = "false_positive";

/** A check that raised a warning (`llm.verdicts.HELD_REASONS`): a closed code, ①'s account of itself. */
const HELD_REASON =
  /^(facts_mismatch|no_verified_quote|fp_policy:[a-z_]+|verifier_disagrees|verifier_invalid)$/;

/** What is distinctive of ①'s conclusion line, so it is looked for on the whole page: the line and its bold half. */
const CONCLUSION_PHRASES = [S.ai1.conclusion, S.ai1.held] as const;

/**
 * What a leak of the conclusion would put in the AI column, and only there: the words of every reason (an
 * alert's own text or a playbook line may say "tài khoản đặc quyền"; that is not a leak), found as plain
 * substrings, and the two labels of a verdict as WORDS ("SFTP" is not "TP").
 */
const COLUMN_LABELS = ["FP", "TP"] as const;

/**
 * What the scorecard of DEC-221 adds to the AI column, and only there (the page's other column and its decision form
 * say "dương tính giả" and "kết luận" in their own words): its tiles, its tabs, its headings and the line under the
 * conclusion. A blind column holds none of them.
 */
const PANEL = S.ai1.panel;
const PANEL_PHRASES = [
  PANEL.tile.confidence,
  PANEL.tile.rag,
  PANEL.tile.checks,
  PANEL.tabs.overview,
  PANEL.tabs.evidence,
  PANEL.tabs.knowledge,
  PANEL.tabs.tech,
  PANEL.overview.highlights,
  PANEL.overview.attack,
  PANEL.overview.benign,
  PANEL.overview.nextChecks,
  PANEL.tile.verdictNote.true_positive,
  PANEL.tile.verdictNote.false_positive,
  PANEL.history.heading,
  PANEL.playbook.heading,
  S.analysis.knowledge.heading,
];
const COLUMN_PHRASES = [...Object.values(S.ai1.heldReason), ...PANEL_PHRASES];

/** All a blind column says: its heading, the advisory line, the notice and what it explains, single-spaced. */
const BLIND_COLUMN_TEXT = [S.alert.aiHeading, S.alert.aiHint, S.ai1.hidden, S.ai1.hiddenBody].join(
  " ",
);

/** What a person reads in `where`, with every run of white space made one space. */
async function wholeText(where: Locator): Promise<string> {
  return (await where.innerText()).replace(/\s+/g, " ").trim();
}

/** The fields step 4 named as missing for the stub's verdict, read from the database. */
function missingFields(id: string): string[] {
  return sql(
    "SELECT string_agg(m, ',' ORDER BY ord) FROM llm_runs r, " +
      "jsonb_array_elements_text(r.gate_result->'missing') WITH ORDINALITY AS t(m, ord) " +
      `WHERE r.pipeline = 'triage' AND r.role = 'proposer' AND r.subject_id = '${id}'`,
  ).split(",");
}

/** The labels of the checks that warned about the stub's verdict, read from the database (step 4's fields). */
function heldLabels(id: string): string[] {
  const fields = missingFields(id);
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
    if (strings.some((value) => HELD_REASON.test(value))) {
      found.push(`${answer.path}: a check that raised a warning`);
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
    expect(
      [...phrasesFound(seen, COLUMN_PHRASES), ...wordsFound(seen, COLUMN_LABELS)],
      "the blind AI column names ①'s conclusion",
    ).toEqual([]);
  }
  // and the WHOLE text of the column is its heading, the advisory line and the notice: a leak of a number alone ("3/5",
  // "47%"), which no marker above lists, goes red here
  expect(await wholeText(column), "the blind AI column says more than its notice").toBe(
    BLIND_COLUMN_TEXT,
  );
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
  // The decision lifts the arm: the AI column now says what the AI concluded and which checks warned (fix round 1,
  // I1; DEC-217), and "Khớp" compares the decision (closed as a false positive) with the stored verdict, `false_positive`.
  await expect(column.getByText(/AI kết luận/)).toContainText(
    `AI kết luận: ${S.ai1.action.false_positive} (độ tin cậy trung bình) — ${S.ai1.held}${S.ai1.heldBecause(heldLabels(head.id))}`,
  );
  // exact: the reason "không khớp bảng quyết định đã duyệt" says "khớp" too
  await expect(page.getByText(S.ai1.match, { exact: true })).toBeVisible();
  // the whole row, by exact text: "có" is a substring of "không có đề xuất để so" (no verdict), so a substring would pass for both
  await expect(page.getByText(S.ai1.match, { exact: true }).locator("..")).toHaveText(
    `${S.ai1.match} ${S.ai1.matchAgree}`,
  );
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

test("a visible head says what the AI concluded and which of the gate's checks warned about it", async ({
  page,
  request,
}) => {
  const head = await postAlert(request, { tag: "held", arm: "visible" });
  await waitForStatus(head.id, "queued_tier1");
  await waitForTriage(head.id);
  // The stub concludes false_positive; gate step 4 raised a warning, and the database records which fields it named.
  const labels = heldLabels(head.id);

  await loginAs(page, "t1");
  const link = page.locator(`a[href="/alerts/${head.id}"]`);
  const row = page.getByRole("row").filter({ has: link });
  // the queue says the verdict (DEC-217): the model's own answer, never the system's Cần xem xét
  await expect(row).toContainText(S.ai1.action.false_positive);
  await expect(row).not.toContainText(S.ai1.action.needs_review);
  await link.click();
  await expect(page).toHaveURL(`/alerts/${head.id}`);

  // DEC-221: the column is the scorecard. The verdict is the first tile, the model's own answer (DEC-217); the checks
  // that warned about it are the last tile's count, a line of the Kiểm chứng tab and a highlight of the overview.
  const column = page.getByRole("region", { name: S.alert.aiHeading });
  const verdict = column.getByRole("group", { name: PANEL.tile.verdict });
  await expect(verdict).toContainText(S.ai1.action.false_positive);
  await expect(verdict).toContainText(PANEL.tile.verdictNote.false_positive);
  await expect(column.getByRole("group", { name: PANEL.tile.confidence })).toContainText(
    S.analysis.level.medium,
  );
  await expect(column.getByRole("group", { name: PANEL.tile.checks })).toContainText(
    /\d+ cảnh báo/,
  );
  // the flat line of before is not drawn beside the tiles, and nothing says ① is hidden
  await expect(column.getByText(/AI kết luận/)).toHaveCount(0);
  await expect(column.getByText(S.ai1.hidden)).toHaveCount(0);
  await expect(column.getByRole("tab")).toHaveText([
    PANEL.tabs.overview,
    PANEL.tabs.evidence,
    PANEL.tabs.knowledge,
    PANEL.tabs.checks,
    PANEL.tabs.tech,
  ]);

  // the Kiểm chứng tab: step 4's warning, in the closed word for what it named (no playbook rule cited, and maybe more)
  const detail = missingFields(head.id).every((field) => field === "playbook_rule")
    ? PANEL.checks.detail.fp_policy_playbook
    : PANEL.checks.detail.fp_policy_facts;
  await column.getByRole("tab", { name: PANEL.tabs.checks }).click();
  await expect(column.getByRole("tabpanel")).toContainText(
    `${PANEL.checks.step["4"]} ${PANEL.checks.dash} ${detail}`,
  );
  expect(labels.length, "step 4 named at least one field").toBeGreaterThan(0);
  // ... and WHICH reasons the gate held, in the words of the flat column the labels come from: under step 4's line
  const steps = column.getByRole("list", { name: PANEL.checks.listLabel });
  for (const label of labels) await expect(steps, `step 4 names "${label}"`).toContainText(label);

  // the same reasons on the default tab, in the line that lists every warning: it is not hidden behind a click
  await column.getByRole("tab", { name: PANEL.tabs.overview }).click();
  const overview = column.getByRole("tabpanel");
  for (const label of labels) {
    await expect(overview, `the overview names "${label}"`).toContainText(label);
  }
  await expect(overview).toContainText(S.ai1.panel.overview.held(labels).split(":")[0]!);

  // the tab strip never widens the column or the page, whatever the width the labels need
  const tablist = column.getByRole("tablist");
  expect(await tablist.evaluate((el) => getComputedStyle(el).overflowX)).toBe("auto");
  expect(await column.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );

  // G5 on the real page: no model's name in the column, on any tab, in its text or in any attribute
  for (const tab of [
    PANEL.tabs.overview,
    PANEL.tabs.evidence,
    PANEL.tabs.knowledge,
    PANEL.tabs.checks,
    PANEL.tabs.tech,
  ]) {
    await column.getByRole("tab", { name: tab }).click();
    const html = await column.innerHTML();
    expect(MODEL_NAME.test(html), `the ${tab} tab names a model`).toBe(false);
    expect(MODEL_NAME.test(await column.innerText()), `the ${tab} tab names a model`).toBe(false);
  }
});

// P14-T07 (DEC-213, spec 4.3): the percentage ("trùng 87% với tri thức đã duyệt") and the notice that the RAG was not
// applied are said beside ①'s conclusion, so on the blind arm they are ①'s verdict by another name: neither reaches
// the browser before the decision (not the page, not an answer of the API, not a frame of the socket), and both
// appear with the rest of the line after it. The lookups and the runs that name them are seeded (ragFixtures.ts): the
// stack runs with the RAG off and no Voyage key, and no request is sent to Voyage.
const SEEDED = [
  {
    name: "the percentage of a lookup that matched",
    tag: "blindmatch",
    seed: (id: string) => seedRun(id, { lookupId: seedFoundLookup(id, [0.61, 0.87]) }),
    shown: "trùng 87% với tri thức đã duyệt",
    value: 87,
    kind: null,
  },
  {
    name: "the notice of a lookup that failed",
    tag: "blindfail",
    seed: (id: string) => {
      seedRun(id, { warnings: ["rag_not_applied:quota"] });
      seedFailedLookup(id, "quota");
    },
    shown: "⚠ Không áp dụng RAG cho alert này: Voyage hết hạn mức",
    value: null,
    kind: "quota",
  },
] as const;

/**
 * What of the RAG is in a page: its words, found as plain substrings. "trùng" alone is left out on purpose: a playbook
 * of the page may say it ("trùng lịch bảo trì"); the sentences of the line and of the notice are what is looked for.
 */
const RAG_PHRASES = [
  "với tri thức đã duyệt",
  "Không áp dụng RAG",
  "tri thức tham khảo",
  "Voyage",
  "vector DB",
];

for (const seeded of SEEDED) {
  test(`a blind head shows ${seeded.name} only after it is decided`, async ({ page, request }) => {
    const head = await postAlert(request, { tag: seeded.tag, arm: "blind" });
    await waitForStatus(head.id, "queued_tier1");
    await waitForTriage(head.id);
    seeded.seed(head.id);

    const traffic = captureTraffic(page);
    await loginAs(page, "t1");
    await page.locator(`a[href="/alerts/${head.id}"]`).click();
    await expect(page).toHaveURL(`/alerts/${head.id}`);
    await expect(page.getByText(S.ai1.hiddenBody)).toBeVisible();
    await page.getByRole("button", { name: S.decision.acknowledge }).click();
    await expect(
      page.getByRole("status").filter({ hasText: S.decision.acknowledged }),
    ).toBeVisible();
    await page.getByLabel(S.decision.falsePositive).check();
    await reasonBox(page).fill("Read the alert and its log; routine.");

    // Before the decision: neither on the page nor in the AI column, in no answer, in no frame.
    const text = await page.locator("body").innerText();
    const html = await page.content();
    for (const seen of [text, html]) {
      expect(phrasesFound(seen, RAG_PHRASES), "the page words the RAG of a blind head").toEqual([]);
    }
    await expect(page.getByRole("note")).toHaveCount(0);
    const column = page.getByRole("region", { name: S.alert.aiHeading });
    expect(phrasesFound(await column.innerText(), RAG_PHRASES)).toEqual([]);
    expect(await wholeText(column), "the blind AI column says more than its notice").toBe(
      BLIND_COLUMN_TEXT,
    );
    const answers = await traffic.answers();
    expect(
      answers.some(
        (a) => a.path === `/api/tier1/alerts/${head.id}` && aboutHead(a, head.id).length > 0,
      ),
      "the head's own view was read",
    ).toBe(true);
    expect(unchecked(answers, head.id)).toEqual([]);
    expect(leaks(answers, traffic.frames(), head.id)).toEqual([]);
    const beforeDecision = answers.length;

    // The decision reveals it, in the same line as the rest.
    await page.getByRole("button", { name: S.decision.submit }).click();
    await expect(page.getByRole("status").filter({ hasText: S.decision.recorded })).toBeVisible();
    await expect(page.getByText(S.ai1.decidedHeading)).toBeVisible();
    if (seeded.kind === null) {
      await expect(column.getByText(/AI kết luận/)).toContainText(seeded.shown);
    } else {
      await expect(column.getByRole("note")).toContainText(seeded.shown);
    }
    const revealed = (await traffic.answers())
      .slice(beforeDecision)
      .filter((a) => a.path === `/api/tier1/alerts/${head.id}`)
      .flatMap((a) => aboutHead(a, head.id));
    expect(
      revealed.some((part) => {
        const rag = (part as { rag?: { best_pct?: unknown; not_applied?: unknown } }).rag;
        return rag?.best_pct === seeded.value && rag?.not_applied === seeded.kind;
      }),
      "the decided head's view carries the pair",
    ).toBe(true);
  });
}
