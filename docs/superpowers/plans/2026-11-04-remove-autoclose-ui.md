# Remove the auto-close UI (P15, DEC-214) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The React admin console no longer shows auto-close. The pages "Rules tự đóng" (`/admin/rules`) and "Digest hằng ngày" (`/admin/digest`) are removed, together with everything in `frontend/` that exists only for them. The backend is not changed.

**Architecture:** This is a removal from the frontend only.
- Auto-close has been off on live and on trial since 23/10 (`AUTOCLOSE_ENABLED=false`, DEC-207).
- The backend that DEC-207 kept stays exactly as it is: `ingest/autoclose.py`, `tier1/digest.py`, `/api/admin/rules`, `/api/admin/digest`, the `digest` job, the `digest_unreviewed` health check and the tables.
- Only the UI that calls those two API groups is removed.

**Tech Stack:** React and TypeScript, with the existing `frontend/` toolchain (Vite, Vitest, Playwright). Python is involved only for the one backend test that reads a removed frontend file.

**Spec:** DEC-214 in `docs/plan/DECISIONS.md`: the Owner's decision of 04/11/2026, with the scope the Owner chose. There is no separate design document.

## Global Constraints

- **Frontend only.** No file under `backend/app/`, `docs/Schema/`, `eval/` or `scripts/` changes, and neither do the compose files or `.env*`. The Owner, 04/11: "ko cần xóa code backend đâu. Xóa UI font-end là dc".
- **Only auto-close.** The Owner, 04/11: "Lưu ý chỉ xóa auto-close". These pages keep their behaviour:
  - every other admin page: Tổng quan, Người dùng & quyền, LLM & hạn mức, Gán nhãn, Tri thức, Nhật ký audit;
  - every Tier-1 and Tier-2 page.
- **Removed** (the Owner's choice "Rules + Digest", 04/11):
  - the two pages, with their routes, sidebar entries, API client, query keys, strings and tests;
  - the Users page's permission row `["Quản trị rules tự đóng, digest", false, false, true]`;
  - the Overview funnel's `auto_closed` row ("Tự động đóng (rules)").
- **Kept on purpose** (same choice):
  - How an alert whose status is `auto_closed` is shown:
    - the status label `auto_closed: "Tự động đóng"`;
    - the decision panel's auto-closed branch and `S.decision.autoClosed`;
    - `aiState.ts`, `agreement.ts` and `AiColumn.tsx`;
    - the status union of `api/tier1.ts`.
  - The audit page's summaries and labels of the auto-close events (`auditSummary.ts` and those labels in `strings.ts`), so that an old event still reads correctly.
  - The health check label `digest_unreviewed: "Digest hôm qua chưa duyệt"`, because the backend still reports that check.
  - The Overview inventory hint `hint: "Đọc lại tệp kiểm kê trên máy chủ. …"`.
- **A removed path is an unknown path.** `/admin/rules`, `/admin/digest` and anything under them go wherever an unknown path goes today (`<Route path="*">`). There is no redirect of their own and no "this page was removed" notice.
- **The sidebar keeps its order** for the pages that stay.
- **Vietnamese copy:** no string that stays is reworded.

## Review Focus

1. **A bookmark or an old link to `/admin/rules` or `/admin/digest`** (for example, from an admin's browser history). It lands where an unknown path lands, never on a blank page or an error boundary.
2. **A cache entry or invalidation left behind.** A remaining mutation (a label save, a user change, a knowledge action) never invalidates or reads a query key that no longer exists. No kept page imports a removed module, and the build passes with the lazy routes gone.
3. **The audit page reading an old auto-close event.** The events are `alert.auto_closed`, `alert.autoclose_blocked_critical`, `admin.autoclose_rule_toggled`, `autoclose.reviewed` and `rule.suspected_wrong`. The audit page still renders each one's summary, which is kept, and nothing on it links to a removed page.
4. **The Overview while the API's funnel object still carries an `auto_closed` count,** which the backend still sends. The page shows the four remaining rows and ignores the extra key. It does not crash and does not add that count to another row.
5. **A backend reason that only the removed pages handled** (`not_in_digest`, `not_auto_closed` and so on) but that a kept page can still receive. Its message stays if any route a kept page calls can return it.

---

### Task 1: P15-T01 — remove the auto-close pages from the frontend

**Files:**
- **Delete:**
  - in `frontend/src/features/admin/`: `RulesPage.tsx`, `RulesPage.test.tsx`, `RuleCreate.tsx`, `ruleErrors.ts`, `ruleFields.ts`, `ruleFields.test.ts`, `DigestPage.tsx`, `DigestPage.test.tsx`, `digestFigures.ts`, `digestFigures.test.ts`;
  - `backend/tests/test_rules_whitelist_pin.py`.
- **Modify:**
  - `frontend/src/routes.tsx`, with `routes.test.tsx` and `routesLazy.test.tsx`;
  - `frontend/src/features/admin/AdminLayout.tsx`, with `AdminLayout.test.tsx`;
  - `frontend/src/api/admin.ts`, with `admin.test.ts`;
  - `frontend/src/features/admin/adminKeys.ts`, with `adminKeys.test.ts`;
  - `frontend/src/strings.ts`;
  - `frontend/src/features/admin/overviewModel.ts`, with its tests and the Overview page's tests;
  - the tests of the Users page's permission matrix;
  - `frontend/src/features/admin/adminStrings.test.ts`;
  - `frontend/e2e/admin.spec.ts` and `frontend/e2e/adminFixtures.ts`;
  - `docs/runbook.md` and `docs/limitations.md`;
  - any `backend/tests/test_runbook_*.py` that pins a sentence you change.
- **Find the rest yourself:** every non-test file that imports a deleted module or names a removed key, route or string, and every test that pins one.

**Interfaces:** This task produces none. It consumes the backend as it is, unchanged.

- [ ] **Step 1: Write the failing tests.** They describe the state after the removal.
  - **Routes.** Signed in as an admin, each of `/admin/rules`, `/admin/rules/anything`, `/admin/digest` and `/admin/digest?day=2026-11-03` ends at the same final location as `/admin/no-such-page`, and nothing of either page renders.
  - **Sidebar.** The admin sidebar's links are the current ones minus `/admin/rules` and `/admin/digest`, in their current order. On `main` that is `/admin/overview`, `/admin/users`, `/admin/llm`, `/admin/labels`, `/admin/knowledge`, `/admin/audit`. If `AdminLayout.tsx`'s order differs from that list, keep its order and say so in the report.
  - **Funnel.**
    - `FUNNEL_STEPS.map((s) => s.key)` equals `["waiting", "active", "closed_by_tier1", "escalated"]`.
    - Given a funnel object that still carries an `auto_closed` count, `funnelCounts` returns those four rows only, and none of them includes that count.
  - **Permission matrix.** No row has a label containing "tự đóng" or "digest" (case-insensitive). Every other row is unchanged and in the same order.
  - **Query keys.** `adminKeys` has no `rules`, `digest` or `digestAll`. The invalidation map has no `createRule`, `toggleRule` or `reviewDigest`.
  - **Guard.** No non-test source file under `frontend/src` contains `admin/rules` or `admin/digest`. That text covers both the page paths and the API paths.
  - Run them and see them fail, for the right reason.
- [ ] **Step 2: Remove the two pages and every frontend part that exists only for them** (see **Files**). Treat the error reasons in `api/admin.ts` and the messages in `strings.ts` one at a time:
  - Remove one only when no kept page can still receive it.
  - To decide, read the backend routers that the kept pages call (`backend/app/web/routers/admin_*.py`, read only).
  - The report says, reason by reason, what you decided.
- [ ] **Step 3: `adminStrings.test.ts`.** It cross-checks the frontend strings with backend files. Drop its parts for `admin_rules.py` and `admin_digest.py`, because the UI no longer calls them, and keep the rest.
- [ ] **Step 4: `backend/tests/test_rules_whitelist_pin.py`.** Delete it. It pins the deleted `ruleFields.ts` to `ingest/autoclose._WHITELIST`, and nothing in the frontend mirrors the whitelist any more. No other backend file changes, apart from the runbook pins of Step 6.
- [ ] **Step 5: e2e.** Remove the scenarios of the two pages from `frontend/e2e/admin.spec.ts`, and their fixtures from `frontend/e2e/adminFixtures.ts`. The other scenarios stay unchanged.
- [ ] **Step 6: Docs.**
  - In `docs/runbook.md`:
    - **(a)** The page lists of the admin console, which today name "Rules, Digest", list only the pages that stay.
    - **(b)** The row of the key `AUTOCLOSE_ENABLED` adds that, since DEC-214, the UI has no rules page and no digest page. Turning auto-close on again would therefore close alerts by rules that no page shows and nobody can review in the UI. So it is not done unless the pages come back first.
    - **(c)** The alarm row `digest_unreviewed` says that with `AUTOCLOSE_ENABLED=false` no alert is auto-closed, so the check stays green, and that the review page is gone (DEC-214).
    - **(d)** Every other sentence that sends the operator to `/admin/rules` or `/admin/digest` is fixed.
  - In `docs/limitations.md`, the DEC-207 item reads "(the rules page and the `autoclose_rules` table stay)". It now says that the table and the backend stay and that the two pages are gone (DEC-214).
  - Update a `test_runbook_*.py` pin only where the sentence it pins changed.
  - Do not edit these historical records:
    - `docs/plan/DECISIONS.md` and `docs/plan/STATE.md`;
    - `docs/plan/tasks/**`, except your report;
    - `docs/superpowers/**`;
    - `docs/kien-truc-*.html` and `docs/phan-bien-*.md`;
    - `docs/plan/01-plan.md`, `docs/plan/00-context-pack.md` and `docs/plan/prompts/**`.
- [ ] **Step 7: Gates, all green.**
  - `make lint`, `make test`, `make ui-lint`, `make ui-test` and `make ui-build`.
  - `make ui-e2e`, if this host can run it. If it cannot, say why; the Director runs it at the merge.
- [ ] **Step 8: Commit.** Make small commits with the prefix `P15-T01:`.

---

### Task 2: P15-T02 — carry the removal onto the trial branch `director/voyage-rag`

Added 04/11 by the Director's ruling, after a probe merge. The Owner chose "Cả live và trial".

**Context.**
- `director/voyage-rag` holds P14 (DEC-213):
  - the Voyage vector RAG;
  - the definite verdicts of ① and ② (`true_positive`);
  - the admin page "Gán nhãn lab" (`/admin/lab`).
- It runs on the trial stack only and is never merged into `main`.
- It branched from `main` at `af56b13`, the same commit P15 started from.
- A probe merge of P15 into it conflicts in ten files:
  - `docs/plan/DECISIONS.md`, `docs/plan/STATE.md`, `docs/runbook.md`;
  - `frontend/src/api/admin.ts`, `frontend/src/routes.tsx`, `frontend/src/routesLazy.test.tsx`;
  - `frontend/src/features/admin/AdminLayout.tsx`, `AdminLayout.test.tsx`, `adminKeys.test.ts`;
  - `frontend/src/features/admin/DigestPage.test.tsx`, which P15 deleted and P14 modified.

**Files:** every conflicted file, and any file whose gate fails on the merged tree. Do not change P14's files beyond the merge and the test adaptations of Step 2.

**Interfaces:** this task consumes P15-T01 as reviewed (the tip of `director/remove-autoclose-ui` given at dispatch) and P14 as it is.

- [ ] **Step 1: Merge.** In your worktree, run `git merge --ff-only director/voyage-rag`, then `git merge --no-ff <P15 tip>`. Resolve every conflict by these rules:
  - **Everything P14 added stays:**
    - the page "Gán nhãn lab", with its sidebar entry at P14's position, its route, API client, query keys, strings and tests;
    - the runbook section "Voyage vector RAG (DEC-213)", and P14's other edits to the runbook and to limitations;
    - DEC-213 and P14's STATE rows;
    - the definite verdicts of ① and ②.
  - **Everything DEC-214 removes goes, also where P14 changed it.**
    - A file P15 deleted stays deleted, whatever P14 changed in it (`DigestPage.test.tsx`).
    - P14's edits inside a removed block go with the block.
  - **Both records stay whole.**
    - `DECISIONS.md` holds DEC-213, then DEC-214.
    - `STATE.md` holds the P14 phase row, then the P15 phase row.
    - It also holds P14-T01…T11, then P15-T01 and P15-T02.
  - **Where both sides changed the same runbook sentence, write one sentence that carries both changes.** For example, the admin console's page list names "Gán nhãn lab", and names neither Rules nor Digest.
  - **The merge commit's message lists every conflicted file** and how it was resolved.
- [ ] **Step 2: Adapt the P15 tests to the trial tree.**
  - The sidebar test expects the trial's list, with `/admin/lab` at P14's position.
  - The guard (`removedAutoclosePages.test.ts`) and the runbook pins must hold on the trial tree.
  - Any P14 test or file that names a removed key, route or string follows DEC-214.
  - Make these separate commits, after the merge commit.
- [ ] **Step 3: Gates on the merged tree, all green.**
  - Run `make lint`, `make test`, `make ui-lint`, `make ui-test`, `make ui-build` and `make ui-e2e`.
  - `make test-db` is not needed, because neither side of the merge changes `backend/app/` or the schema. Say so in the report.
- [ ] **Step 4: Report** in `docs/plan/tasks/P15/P15-T02.report.md`:
  - the conflicts and how each was resolved;
  - the test adaptations;
  - the verbatim summary line of every gate.
