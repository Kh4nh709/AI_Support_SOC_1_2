// Tier 2 on the real stack (P10-T12): Tier 1 escalates an alert, Tier 2 finds the case, asks ② to analyse it
// (the worker runs the real investigate pipeline against the stub model), reads the marks on the evidence,
// adds a note and concludes, and a second conclusion of the same case is refused with the name of the first.
import { expect, test, type Page } from "@playwright/test";
import {
  S,
  apiLogin,
  apiPost,
  loginAs,
  postAlert,
  postCorrelated,
  sql,
  userIdOf,
  usernameOf,
  waitForStatus,
  openWorkspaceTab,
} from "./fixtures";

/** How the API and the page name the two Tier 2 users (the username: notes and conclusions carry it as `*_name`). */
const T2_NAME = usernameOf("t2");
const T2B_NAME = usernameOf("t2b");

const toast = (page: Page, text: string) => page.getByRole("status").filter({ hasText: text });

/** The conclusion form of the case page: the radio of a conclusion, the reason and the button. */
function conclusionForm(page: Page) {
  return {
    choose: (label: string) =>
      page.getByRole("group", { name: S.case.pickConclusion }).getByLabel(label),
    reason: page.getByLabel(S.case.reasonRequired),
    submit: page.getByRole("button", { name: S.case.concludeSubmit, exact: true }),
  };
}

test("Tier 1 escalates, Tier 2 analyses, notes and concludes, and a second conclusion gets a 409", async ({
  page,
  browser,
  baseURL,
  request,
}) => {
  // ---- Tier 1 hands the cluster over.
  const head = await postAlert(request, { tag: "case", arm: "visible" });
  // A correlated alert (same agent, another rule): escalating `head` must leave it in the queue (T2, DEC-215).
  const sibling = await postCorrelated(request, head, { arm: "visible" });
  await waitForStatus(head.id, "queued_tier1");
  await waitForStatus(sibling.id, "queued_tier1");
  const title = `E2E case for ${head.agent}`;

  await loginAs(page, "t1");
  await page.goto(`/alerts/${head.id}`);
  await openWorkspaceTab(page, S.workspace.alertDecision);
  await page.getByRole("button", { name: S.decision.acknowledge }).click();
  await expect(toast(page, S.decision.acknowledged)).toBeVisible();
  // The form says, before the button is pressed, that only this alert goes into the case.
  await expect(page.getByText(S.decision.escalateScope)).toBeVisible();
  await page.getByLabel(S.decision.caseTitle).fill(title);
  await page.getByRole("button", { name: S.decision.escalate, exact: true }).click();
  const opened = toast(page, S.decision.caseOpened);
  await expect(opened).toBeVisible();
  // Tier 1 is told which case it opened, by number, and has no link to it.
  const caseId = /case #([0-9a-f-]+)/.exec(await opened.innerText())?.[1];
  expect(caseId, "the toast names the case").toBeTruthy();
  const id = caseId ?? "";
  expect(sql(`SELECT status FROM alerts WHERE alert_id = '${head.id}'`)).toBe("escalated_tier2");
  // The case is that alert alone; the correlated one keeps its status and has no case.
  expect(sql(`SELECT alert_id FROM case_alerts WHERE case_id = '${id}'`)).toBe(head.id);
  expect(
    sql(
      `SELECT status, coalesce(case_id::text, 'none') FROM alerts WHERE alert_id = '${sibling.id}'`,
    ),
  ).toBe("queued_tier1|none");

  // Signing out has reached the server before the next login (it would otherwise end a later session).
  const loggedOut = page.waitForResponse(
    (res) =>
      new URL(res.url()).pathname === "/api/auth/logout" && res.request().method() === "POST",
  );
  await page.getByRole("button", { name: S.nav.logout }).click();
  await expect(page).toHaveURL(/\/login$/);
  await loggedOut;

  // ---- Tier 2 finds the case and asks ② to analyse it.
  await loginAs(page, "t2");
  await expect(page.getByRole("heading", { name: S.case.listTitle })).toBeVisible();
  await page.getByRole("link", { name: title, exact: true }).click();
  await expect(page).toHaveURL(`/cases/${id}`);
  await expect(page.getByRole("heading", { name: title })).toBeVisible();

  await openWorkspaceTab(page, S.workspace.analysis);
  await page.getByRole("button", { name: S.ai2.analyze, exact: true }).click();
  // The worker takes the job, the stub answers, and the page (polling while it runs) shows the scorecard of the
  // result (DEC-221): four tiles over five tabs. The panel is headed as the approved mock-up has it, with the case
  // line (the case, its clusters, the agent) at the right.
  const column = page.getByRole("region", { name: S.case.aiHeading });
  await expect(column.getByRole("tablist", { name: S.ai2.tabs.label })).toBeVisible({
    timeout: 60_000,
  });
  await expect(column.getByRole("heading", { name: S.case.aiHeading })).toHaveText(
    "PHÂN TÍCH AI · TIER 2",
  );
  await expect(
    column.getByText(
      [S.ai2.caseId(id.slice(0, 8)), S.case.clusterCount(1), head.agent].join(S.analysis.separator),
    ),
  ).toBeVisible();
  // The conclusion tile: what the AI suggests, and that it is only a suggestion. P14-T03 (DEC-213): one quote
  // verified, so the system held nothing back.
  const verdict = column.getByRole("group", { name: S.ai2.tile.verdict });
  await expect(
    verdict.getByText(S.ai2.suggestedConclusion.false_positive, { exact: true }),
  ).toBeVisible();
  await expect(verdict).toContainText(S.ai2.tile.verdictNote.plain);
  // The tile shows one short word; the conclusion's whole label is the first line of the overview (A).
  await expect(column.locator("[data-part='verdict']")).toHaveText(
    S.ai2.suggestedConclusion.false_positive,
  );
  await expect(column).not.toContainText("giữ lại");
  // The evidence tile: one of the stub's two quotes was found in the log.
  await expect(column.getByRole("group", { name: S.ai2.tile.evidence })).toContainText(
    `1/2${S.ai2.tile.evidenceNote}`,
  );
  // The quotes are on the Bằng chứng tab, each marked by what the server checked against the log, with the
  // server's reason for the one it did not find.
  await column.getByRole("tab", { name: S.ai2.tabs.evidence }).click();
  const verified = column.locator('[data-verified="true"]');
  const unverified = column.locator('[data-verified="false"]');
  await expect(verified.first()).toBeVisible();
  await expect(unverified.first()).toBeVisible();
  await expect(
    verified.first().getByRole("img", { name: S.analysis.evidence.verified }),
  ).toBeVisible();
  await expect(
    unverified.first().getByRole("img", { name: S.analysis.evidence.unverified }),
  ).toBeVisible();
  await expect(column.getByText(S.ai2.mark.quote_not_found)).toBeVisible();
  // The tab strip is a real tablist: the arrow keys move between the tabs.
  await column.getByRole("tab", { name: S.ai2.tabs.evidence }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(column.getByRole("tab", { name: S.ai2.tabs.tech })).toHaveAttribute(
    "aria-selected",
    "true",
  );
  // G5 (DEC-221, the Owner's requirement): the technical tab has its six rows and no model, and no tab of the
  // page names one, in its text or in a tooltip.
  await expect(column.getByRole("tabpanel").locator("dt")).toHaveText([
    S.analysis.tech.tokens,
    S.analysis.tech.time,
    S.analysis.tech.cost,
    S.analysis.tech.analysedAt,
    S.ai2.tech.playbook,
    S.ai2.tech.alertsRead,
  ]);
  const MODEL_NAME = /glm|gpt|deepseek|claude|model:/i;
  for (const name of Object.values(S.ai2.tabs).slice(1)) {
    await column.getByRole("tab", { name }).click();
    expect(await column.innerText()).not.toMatch(MODEL_NAME);
    expect(
      await column
        .locator("[title], [aria-label], [alt]")
        .evaluateAll((els) =>
          els
            .map((el) =>
              [
                el.getAttribute("title"),
                el.getAttribute("aria-label"),
                el.getAttribute("alt"),
              ].join(" "),
            )
            .join(" "),
        ),
    ).not.toMatch(MODEL_NAME);
  }
  await column.getByRole("tab", { name: S.ai2.tabs.overview }).click();

  // ---- A note.
  const note = `Checked with the owner of ${head.agent}: routine.`;
  await openWorkspaceTab(page, S.workspace.caseDecision);
  await page.getByLabel(S.case.addNote, { exact: true }).fill(note);
  await page.getByRole("button", { name: S.case.saveNote }).click();
  await expect(page.getByText(note)).toBeVisible();
  await expect(page.getByText(T2_NAME, { exact: true }).first()).toBeVisible();

  // ---- Two analysts (two users) have the case open, both with the conclusion written.
  const other = await browser.newContext({ baseURL });
  try {
    const second = await other.newPage();
    await loginAs(second, "t2b");
    await second.goto(`/cases/${id}`);
    await openWorkspaceTab(second, S.workspace.caseDecision);
    const later = conclusionForm(second);
    await later.choose(S.conclusion.concluded_fp).check();
    await later.reason.fill("Also read the case; closing as noise as well.");
    await expect(later.submit).toBeEnabled();

    const first = conclusionForm(page);
    await first.choose(S.conclusion.concluded_fp).check();
    await first.reason.fill("The alert is what the owner says it is; not an incident.");
    await first.submit.click();
    // The case is concluded: the form is gone and the page says by whom.
    await expect(page.getByText(`Đã được ${T2_NAME} kết luận lúc`)).toBeVisible();
    await expect(first.submit).toHaveCount(0);
    expect(sql(`SELECT status FROM cases WHERE case_id = '${id}'`)).toBe("concluded_fp");
    // Concluding closed the escalated alert and nothing else: the correlated one is still in the queue.
    expect(sql(`SELECT status FROM alerts WHERE alert_id = '${head.id}'`)).toBe("closed_fp");
    expect(sql(`SELECT status FROM alerts WHERE alert_id = '${sibling.id}'`)).toBe("queued_tier1");

    // The other user's form was drawn before: what it sends is refused, and the page names the user who got
    // there first (e2e-t2, not the user who is looking at it, e2e-t2b).
    await later.submit.click();
    const refused = second.getByRole("alert").filter({ hasText: S.case.conflict });
    await expect(refused).toBeVisible();
    await expect(refused).toContainText(`Đã được ${T2_NAME} kết luận lúc`);
    await expect(refused).not.toContainText(T2B_NAME);
  } finally {
    await other.close();
  }

  // The same at the API, for the record of what the 409 carries: a third conclusion, by the second user.
  const token = await apiLogin(request, "t2b");
  const again = await apiPost(request, `/api/tier2/cases/${id}/conclude`, {
    token,
    data: { conclusion: "concluded_fp", reason: "A third try, after the case was concluded." },
  });
  expect(again.status).toBe(409);
  const detail = (again.body as { detail: { status?: string; concluded_by?: string } }).detail;
  expect(detail.status).toBe("concluded_fp");
  expect(detail.concluded_by, "the 409 names the user who concluded first").toBe(userIdOf("t2"));
  expect(detail.concluded_by).not.toBe(userIdOf("t2b"));
});
