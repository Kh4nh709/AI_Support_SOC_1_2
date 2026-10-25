// The knowledge page on the real stack (P13-T06, DEC-210, spec §7.5): a pending draft of a real alert is edited and
// approved by an admin, found under Đã duyệt, and retired; a draft that breaks V1-V5 is refused at its field and then
// rejected with a reason; and a Tier-1 user is turned away from the page. The stack has no `rag-worker` and the RAG
// switches are off, so the drafts are rows the suite inserts (knowledgeFixtures.ts); everything else is the product:
// the routes of P13-T05, the publication of the file into the scratch repository, the audit trail.
import { existsSync } from "node:fs";
import { join } from "node:path";
import { expect, test, type Page, type Request } from "@playwright/test";
import { S, loginAs, sql, stateDir } from "./fixtures";
import { closedAlert, modelFields, seedPendingDraft } from "./knowledgeFixtures";

const K = S.admin.knowledgePage;
const D = K.draft;

/** `kb_learned/` of the scratch repository: where the API of this run publishes the files (`KB_LEARNED_ROOT`). */
const publishedRoot = () => join(stateDir(), "repo", "kb_learned");

const tab = (page: Page, name: string) => page.getByRole("tab", { name, exact: true });
const rowOf = (page: Page, title: string) =>
  page.getByRole("row").filter({ has: page.getByText(title, { exact: true }) });

/** Every POST the page sends to the knowledge routes: path, Content-Type and JSON body, in order. */
function watchWrites(page: Page): { path: string; contentType: string | null; body: unknown }[] {
  const writes: { path: string; contentType: string | null; body: unknown }[] = [];
  page.on("request", (req: Request) => {
    const url = new URL(req.url());
    if (req.method() !== "POST" || !url.pathname.startsWith("/api/admin/knowledge/")) return;
    writes.push({
      path: url.pathname.replace(/[0-9a-f]{8}-[0-9a-f-]{27}/g, ":id"),
      contentType: req.headers()["content-type"] ?? null,
      body: req.postDataJSON() as unknown,
    });
  });
  return writes;
}

async function openKnowledge(page: Page): Promise<void> {
  await page
    .getByRole("navigation", { name: S.admin.nav.label })
    .getByRole("link", { name: S.admin.nav.knowledge })
    .click();
  await expect(page).toHaveURL(/\/admin\/knowledge$/);
  await expect(
    page.getByRole("heading", { level: 1, name: S.admin.title.knowledge }),
  ).toBeVisible();
}

test("an admin edits and approves a pending draft, finds it under Đã duyệt, and retires it", async ({
  page,
  request,
}) => {
  const title = "E2E quét cổng định kỳ của máy giám sát";
  const edited = `${title} (đã sửa)`;
  const head = await closedAlert(request, "kn-approve");
  seedPendingDraft(head.id, modelFields(title));

  await loginAs(page, "admin");
  const writes = watchWrites(page);
  await openKnowledge(page);

  // Chờ duyệt: the draft is listed with its source and its conclusion.
  await expect(tab(page, K.tab.pending)).toHaveAttribute("aria-selected", "true");
  const pending = rowOf(page, title);
  await expect(pending).toBeVisible();
  await expect(pending).toContainText(head.id);
  await expect(pending).toContainText(S.status.closed_fp);

  // The draft opens on two columns: the analyst's work on the left, the draft on the right.
  await page.getByRole("button", { name: K.openDraft(title) }).click();
  // The view is in the URL: a reload opens it again, on the same tab, with focus on its title.
  await expect(page).toHaveURL(/\/admin\/knowledge\?tab=pending&draft=[0-9a-f-]{36}$/);
  await page.reload();
  await expect(page.getByRole("heading", { name: title })).toBeFocused();
  const left = page.getByRole("region", { name: D.left.heading });
  const right = page.getByRole("region", { name: D.right.heading });
  await expect(left.getByRole("region", { name: S.alert.summaryLabel })).toContainText("99001");
  await expect(left).toContainText(head.description);
  const decision = left.getByRole("region", { name: D.left.decision.heading });
  await expect(decision).toContainText(S.admin.eventType["tier1.decided"]);
  await expect(decision).toContainText("e2e-t1");
  await expect(decision).toContainText("Routine scan of the monitoring host (kn-approve)");
  // read-only: the decision form of Tier 1 is not there
  await expect(left.getByRole("button", { name: S.decision.submit })).toHaveCount(0);
  await expect(left.getByRole("textbox")).toHaveCount(0);

  // The closed fields come from the alert and cannot be edited; the form holds the model's text.
  await expect(right.getByLabel(D.right.field.title)).toHaveValue(title);
  await expect(right.getByRole("group", { name: D.right.closedHeading })).toContainText("99001");
  await expect(
    right
      .getByRole("group", { name: D.right.field.tags })
      .getByRole("checkbox", { name: "port_scan" }),
  ).toBeChecked();

  // Sửa rồi duyệt: only the title changed, so only the title is sent.
  await right.getByLabel(D.right.field.title).fill(edited);
  await expect(right.getByRole("button", { name: D.action.approve, exact: true })).toBeDisabled();
  await right.getByRole("button", { name: D.action.editApprove }).click();
  const dialog = page.getByRole("dialog", { name: D.action.editApproveTitle });
  await dialog.getByRole("button", { name: D.action.editApprove }).click();
  await expect(page.getByText(K.done.approved(edited))).toBeVisible();
  expect(writes).toEqual([
    {
      path: "/api/admin/knowledge/drafts/:id/approve",
      contentType: "application/json",
      body: { edited: { title: edited } },
    },
  ]);

  // The draft has left Chờ duyệt.
  await expect(rowOf(page, title)).toHaveCount(0);
  await expect(rowOf(page, edited)).toHaveCount(0);

  // Đã duyệt: the entry is there, with the approver, and opens whole, intact, with its Markdown as text.
  await tab(page, K.tab.active).click();
  const entry = rowOf(page, edited);
  await expect(entry).toBeVisible();
  await expect(entry).toContainText("e2e-admin");
  await page.getByRole("button", { name: K.openEntry(edited) }).click();
  const header = page.getByRole("region", { name: K.entry.header });
  await expect(header.getByRole("heading", { name: edited })).toBeVisible();
  await expect(page.getByRole("region", { name: K.entry.integrity.heading })).toContainText(
    K.entry.integrity.ok,
  );
  await expect(page.getByRole("region", { name: K.entry.content })).toContainText(`# ${edited}`);
  const filePath = (await header.getByText(/^entries\/.+\.md$/).textContent()) ?? "";
  expect(filePath).toMatch(/^entries\/[a-z0-9_]+\/[0-9a-f-]{36}\.md$/);
  expect(existsSync(join(publishedRoot(), filePath)), "the file was published").toBe(true);

  // Gỡ: a reason is required; the entry moves to Đã gỡ and its file to retired/.
  await header.getByRole("button", { name: K.entry.retire }).click();
  const retire = page.getByRole("dialog", { name: K.entry.retireTitle });
  await expect(retire.getByRole("button", { name: K.entry.retire })).toBeDisabled();
  await retire.getByLabel(K.entry.reasonLabel).fill("Không còn đúng sau khi đổi lịch quét.");
  await retire.getByRole("button", { name: K.entry.retire }).click();
  await expect(page.getByText(K.done.retired(edited))).toBeVisible();
  await expect(tab(page, K.tab.active)).toHaveAttribute("aria-selected", "true");
  await expect(rowOf(page, edited)).toHaveCount(0);
  await tab(page, K.tab.retired).click();
  await expect(rowOf(page, edited)).toBeVisible();
  expect(existsSync(join(publishedRoot(), filePath)), "the file left entries/").toBe(false);
  expect(existsSync(join(publishedRoot(), filePath.replace(/^entries\//, "retired/")))).toBe(true);

  // The same two writes are in the audit trail, by the admin: the approval under the source's id, the retirement
  // under the entry's.
  const retiredPath = filePath.replace(/^entries\//, "retired/");
  const entryId = sql(`SELECT entry_id FROM knowledge_entries WHERE file_path = '${retiredPath}'`);
  expect(entryId).toMatch(/^[0-9a-f-]{36}$/);
  const audited = (type: string, subject: string) =>
    sql(
      `SELECT count(*) FROM audit_events e JOIN users u ON u.user_id = e.actor_id` +
        ` WHERE e.event_type = '${type}' AND e.subject_id = '${subject}' AND u.username = 'e2e-admin'`,
    );
  expect(audited("knowledge.approved", head.id)).toBe("1");
  expect(audited("knowledge.retired", entryId)).toBe("1");
  expect(writes.map((w) => w.path)).toEqual([
    "/api/admin/knowledge/drafts/:id/approve",
    "/api/admin/knowledge/entries/:id/retire",
  ]);
  expect(writes[1]?.body).toEqual({ reason: "Không còn đúng sau khi đổi lịch quét." });
  expect(writes[1]?.contentType).toBe("application/json");
});

test("a draft that breaks V1-V5 is refused at its field, and a draft is rejected with a reason", async ({
  page,
  request,
}) => {
  const title = "E2E nháp bị từ chối";
  const head = await closedAlert(request, "kn-reject");
  seedPendingDraft(head.id, modelFields(title));

  await loginAs(page, "admin");
  const writes = watchWrites(page);
  await openKnowledge(page);
  await page.getByRole("button", { name: K.openDraft(title) }).click();
  const right = page.getByRole("region", { name: D.right.heading });
  await expect(right.getByLabel(D.right.field.title)).toHaveValue(title);

  // A literal address in the summary: V3 refuses the approval, at the summary, and nothing is stored.
  const summary = right.getByLabel(D.right.field.summary);
  await summary.fill("Máy 203.0.113.9 quét cổng định kỳ vào máy chủ nội bộ.");
  await right.getByRole("button", { name: D.action.editApprove }).click();
  await page
    .getByRole("dialog", { name: D.action.editApproveTitle })
    .getByRole("button", { name: D.action.editApprove })
    .click();
  await expect(summary).toHaveAccessibleDescription(new RegExp(K.fault.rule.v3_ipv4));
  await expect(summary).toHaveAttribute("aria-invalid", "true");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(right.getByLabel(D.right.field.title)).not.toHaveAttribute("aria-invalid", "true");
  expect(sql(`SELECT count(*) FROM knowledge_entries WHERE content LIKE '%${title}%'`)).toBe("0");
  expect(sql(`SELECT status FROM knowledge_drafts WHERE source_id = '${head.id}'`)).toBe("pending");

  // Từ chối needs a reason.
  await right.getByRole("button", { name: D.action.reject }).click();
  const dialog = page.getByRole("dialog", { name: D.action.rejectTitle });
  await expect(dialog.getByRole("button", { name: D.action.reject })).toBeDisabled();
  await dialog.getByLabel(D.action.reasonLabel).fill("Trùng với một bản đã duyệt từ trước.");
  await dialog.getByRole("button", { name: D.action.reject }).click();
  await expect(page.getByText(K.done.rejected(title))).toBeVisible();
  expect(writes.map((w) => [w.path, w.body])).toEqual([
    [
      "/api/admin/knowledge/drafts/:id/approve",
      { edited: { summary: "Máy 203.0.113.9 quét cổng định kỳ vào máy chủ nội bộ." } },
    ],
    ["/api/admin/knowledge/drafts/:id/reject", { reason: "Trùng với một bản đã duyệt từ trước." }],
  ]);

  // Từ chối: it is there with who and why, and it is gone from Chờ duyệt.
  await expect(rowOf(page, title)).toHaveCount(0);
  await tab(page, K.tab.rejected).click();
  const rejected = rowOf(page, title);
  await expect(rejected).toBeVisible();
  await expect(rejected).toContainText("e2e-admin");
  await expect(rejected).toContainText("Trùng với một bản đã duyệt từ trước.");
  expect(sql(`SELECT status FROM knowledge_drafts WHERE source_id = '${head.id}'`)).toBe(
    "rejected",
  );

  // A rejected draft opens read-only.
  await page.getByRole("button", { name: K.openDraft(title) }).click();
  await expect(
    page
      .getByRole("region", { name: D.right.heading })
      .getByRole("button", { name: D.action.approve, exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByRole("region", { name: D.right.heading }).getByLabel(D.right.field.title),
  ).not.toBeEditable();
});

test("every tab of the page answers, and Tier 1 is turned away from it", async ({ page }) => {
  await loginAs(page, "admin");
  await openKnowledge(page);
  // Whatever the other tests left, no tab fails: each is a table or the sentence for an empty one.
  for (const name of [K.tab.pending, K.tab.active, K.tab.merged, K.tab.rejected, K.tab.retired]) {
    await tab(page, name).click();
    await expect(tab(page, name)).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("tabpanel", { name })).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
  }
  await page.getByRole("button", { name: S.nav.logout }).click();
  await expect(page).toHaveURL(/\/login$/);

  await loginAs(page, "t1");
  await page.goto("/admin/knowledge");
  await expect(page).toHaveURL(/\/queue$/);
  await expect(page.getByRole("alert")).toContainText(S.forbidden);
  await expect(page.getByRole("heading", { name: S.admin.title.knowledge })).toHaveCount(0);
});
