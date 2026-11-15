// The RAG beside the AI's conclusion on the real stack (P14-T07, DEC-213, spec 4.3; the scorecard of DEC-221). On a
// visible head the alert page says how strongly the alert matched approved knowledge, on the RAG tile, and, when the
// lookup failed,
// the notice that the RAG was not applied, in the alert's words and with the closed kind worded. The blind head's
// side - neither before the decision - is in blind.spec.ts, beside the rest of what the blind arm hides.
//
// The stack runs with the RAG off and no Voyage key, so the lookups and the runs that name them are seeded
// (ragFixtures.ts) in the shape `rag/lookup.py` and `tier1/triage.py` write; no request is sent to Voyage. The
// sentences are written out in full on purpose: a label edited in strings.ts alone must fail here.
import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import {
  S,
  apiGet,
  apiLogin,
  loginAs,
  postAlert,
  waitForStatus,
  waitForTriage,
  type Posted,
} from "./fixtures";
import { seedFailedLookup, seedFoundLookup, seedRun } from "./ragFixtures";

const TAIL = "AI đã phân tích không có tri thức tham khảo.";

/** A visible-arm head ① has answered on. */
async function visibleHead(request: APIRequestContext, tag: string): Promise<Posted> {
  const head = await postAlert(request, { tag, arm: "visible" });
  await waitForStatus(head.id, "queued_tier1");
  await waitForTriage(head.id);
  return head;
}

const column = (page: Page) => page.getByRole("region", { name: S.alert.aiHeading });

test("an alert whose lookup failed says that the RAG was not applied, and why", async ({
  page,
  request,
}) => {
  const head = await visibleHead(request, "ragfail");
  seedRun(head.id, { warnings: ["rag_not_applied:auth"] });
  seedFailedLookup(head.id, "auth");

  await loginAs(page, "t1");
  await page.goto(`/alerts/${head.id}`);

  const col = column(page);
  await expect(col.getByRole("group", { name: S.ai1.panel.tile.verdict })).toContainText(
    S.ai1.action.false_positive,
  );
  await expect(col.getByRole("note")).toHaveText(
    `⚠ Không áp dụng RAG cho alert này: thiếu hoặc sai API key Voyage — ${TAIL}`,
  );
  // beside the conclusion, not instead of it; and no percentage for a lookup that did not happen: the RAG tile is a
  // dash with the failure kind in a short line (DEC-221)
  const tile = col.getByRole("group", { name: S.ai1.panel.tile.rag });
  await expect(tile).toContainText(S.analysis.ragNote.failedKind.auth);
  await expect(tile).not.toContainText("%");
  await expect(col.getByText(S.ai1.hidden)).toHaveCount(0);

  // the view says the same, in the API's words
  const token = await apiLogin(request, "t1");
  const view = await apiGet(request, `/api/tier1/alerts/${head.id}`, { token });
  expect((view.body as { rag?: unknown }).rag).toEqual({
    best_pct: null,
    not_applied: "auth",
    below_floor_pct: null,
    floor_pct: null,
  });
});

test("an alert that matched approved knowledge says how strongly, on the RAG tile and in the Tri thức tab", async ({
  page,
  request,
}) => {
  const head = await visibleHead(request, "ragfound");
  seedRun(head.id, { lookupId: seedFoundLookup(head.id, [0.61, 0.87, 0.72]) });

  await loginAs(page, "t1");
  await page.goto(`/alerts/${head.id}`);

  const col = column(page);
  // the best of the three matches, as a whole percentage, on the tile
  const tile = col.getByRole("group", { name: S.ai1.panel.tile.rag });
  await expect(tile).toContainText("87%");
  // the seeded entries have no stored conclusion, so the line says only that approved knowledge matched
  await expect(tile).toContainText(S.analysis.ragNote.matchedOther);
  // and the three candidates, best first, in the Tri thức tab (their entries are seeded without a title)
  await col.getByRole("tab", { name: S.ai1.panel.tabs.knowledge }).click();
  await expect(col.getByRole("tabpanel").getByText(/^\d+%$/)).toHaveText(["87%", "72%", "61%"]);
  await expect(col.getByRole("note")).toHaveCount(0);
  await expect(col.getByText(/Không áp dụng RAG/)).toHaveCount(0);

  const token = await apiLogin(request, "t1");
  const view = await apiGet(request, `/api/tier1/alerts/${head.id}`, { token });
  expect((view.body as { rag?: unknown }).rag).toEqual({
    best_pct: 87,
    not_applied: null,
    below_floor_pct: null,
    floor_pct: null,
  });
});

test("an alert whose RAG was not used says nothing of it", async ({ page, request }) => {
  const head = await visibleHead(request, "ragnone");

  await loginAs(page, "t1");
  await page.goto(`/alerts/${head.id}`);

  const col = column(page);
  await expect(col.getByRole("group", { name: S.ai1.panel.tile.verdict })).toContainText(
    S.ai1.action.false_positive,
  );
  // no lookup: a dash and a line saying so, and no percentage anywhere on the tile
  const tile = col.getByRole("group", { name: S.ai1.panel.tile.rag });
  await expect(tile).toContainText(S.analysis.ragNote.noLookup);
  await expect(tile).not.toContainText("%");
  await expect(col.getByRole("note")).toHaveCount(0);
  const token = await apiLogin(request, "t1");
  const view = await apiGet(request, `/api/tier1/alerts/${head.id}`, { token });
  expect((view.body as { rag?: unknown }).rag).toEqual({
    best_pct: null,
    not_applied: null,
    below_floor_pct: null,
    floor_pct: null,
  });
});

test("every closed failure kind is worded, and the provider's words are nowhere", async ({
  page,
  request,
}) => {
  const kinds: [string, string][] = [
    ["rate_limit", "Voyage vượt giới hạn tốc độ"],
    ["timeout", "Voyage quá thời gian chờ"],
    ["quota", "Voyage hết hạn mức"],
    ["provider_error", "lỗi phía Voyage"],
    ["vectordb_unreachable", "không kết nối được vector DB"],
  ];
  await loginAs(page, "t1");
  for (const [kind, label] of kinds) {
    const head = await visibleHead(request, `rag${kind.replaceAll("_", "")}`);
    seedRun(head.id, { warnings: [`rag_not_applied:${kind}`] });
    seedFailedLookup(head.id, kind);
    await page.goto(`/alerts/${head.id}`);
    await expect(column(page).getByRole("note")).toHaveText(
      `⚠ Không áp dụng RAG cho alert này: ${label} — ${TAIL}`,
    );
  }
});
