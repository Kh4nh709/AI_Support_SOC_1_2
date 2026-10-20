# P11 report — admin console v1.1

Director: Opus 5.5 (DEC-200, DEC-201). Coders: Sonnet 5.5 xhigh subagents, one per task, each in its own worktree. Every task was checked by an independent Reviewer subagent before the Director merged it, and the Director ran one mutation of his own at every merge. 18–20/10/2026.

## What ships

**Branch `director/admin-v1-1`** (tip 17ae66c), based on `577ef18` (P10-T17's tip):
- **Seven React admin pages** at `:8080/admin`, lazy-loaded:
  - Tổng quan;
  - Người dùng và quyền;
  - LLM và hạn mức;
  - Rules tự đóng;
  - Digest;
  - Gán nhãn;
  - Nhật ký audit.
- **The admin APIs behind them:**
  - users and roles;
  - editable LLM limits, fail-closed, bounded by the job lock (DEC-202);
  - LLM usage;
  - overview with failed-job retry and inventory reload;
  - rules additions;
  - digest JSON;
  - labels undo;
  - a read-only audit log.
- **Migration 019:** the `settings` table, `users.last_login_at`, and a 28th event type.
- **The blind arm and blind labelling hold in every new answer:**
  - DEC-204: one labeller's verdict is never shown to the other;
  - DEC-206: no ① suggestion on a blind, undecided alert, in the audit, the usage list or the digest.
- **Audit redaction** of secret keys and of URLs carrying a password (DEC-203).
- **The Playwright suite** covers spec §7's ten scenarios, plus 2b, 4b and 4c. It runs on a scratch copy of the app with an empty `eval/`, so the real gold set is never touched.

**Branch `director/admin-v1-1-retire`** (tip 3833d19 plus this report), stacked on the v1.1 tip (DEC-205):
- the Jinja admin pages, `/login`, `/logout`, `/`, the templates and the session cookie are removed;
- port 8000 then serves `/api/*`, `/webhook/alerts` and `/health`, plus FastAPI's own docs routes (parked row 69).

## Decisions recorded

| DEC | What |
|---|---|
| DEC-200 | The spec, approved by the Owner |
| DEC-201 | Coder and independent Reviewer subagents; the Director only manages |
| DEC-202 | The web's model-timeout bound follows the job lock; a stored value is clamped |
| DEC-203 | `llm_month` on the overview; the audit redaction's value rule, `passwd`/`pwd`, flags never hidden (the URL rule amended: no anchor, matched in linear time) |
| DEC-204 | The audit hides `label` and `confidence` of `label.created` |
| DEC-205 | The retirement on its own stacked branch (Owner 20/10) |
| DEC-206 | The blind arm in the admin console, with two amendments: telling events left out; failed jobs stay visible |

## Suites

| Tip | lint | test | test-db | ui-lint | ui-test | ui-build | ui-e2e |
|---|---|---|---|---|---|---|---|
| v1.1 `17ae66c` | 0 | 2836 | 2165 + 2 known XML | 0 | 2709 | 0 (main chunk 427 kB) | 22 passed, no secret |
| retire `3833d19 plus this report` | 0 | 2827* | 2093 + 2 known XML | — | 2709 | — | 22 passed, no secret |

\* Without `TEST_DATABASE_URL` exported, 17 `test_investigate.py` cases are skipped. The XML pair (`test_backup_restore.py`) fails only on the scratch PostgreSQL, which has no libxml.

The real `eval/gold_v1.sha256` and `eval/gold_candidates.csv` kept their sha256, mtime, size and inode through every e2e run.

## Reviews

- **Per task:** `docs/plan/tasks/P11/P11-Txx.review.md`. Rounds needed:

  | Task | Rounds | Why the extra rounds |
  |---|---|---|
  | T10 | 2 | |
  | T12 | 2 | a password kept in the mutation cache |
  | T14 | 3 | a same-tick double submit, then the shared latch's release |
  | T16 | 2 | |
  | T18 | 2 | a flake, a password in failure output |
  | T19 | 3 | the stacked-branch rollback |

- **Whole branch:** `docs/plan/tasks/P11/P11-review.md`, three rounds. Round 1 found the blind arm in the audit and usage answers and the missing deploy order. Round 2 found that the bare presence of `llm.gate_forced` tells the verdict.

## Parked for after the release

`docs/plan/tasks/P11/P11-T20-parked.md` holds 74 rows. The whole-branch review judged that none of the open rows must be fixed before release. The open rows are:
- tests to strengthen;
- focus and wording;
- line lengths;
- a second redaction layer that no writer reaches today (row 62);
- disabling FastAPI's docs routes (row 69);
- rewriting `docs/demo.md` (row 70);
- statement timeouts on two pre-v1.1 reads (row 74).

## The Owner's steps

The runbook section `## Admin console v1.1 — deploy (DEC-205)` holds the same steps, pinned by tests. All commands run in the primary checkout, on `main`.

**Step 1: v1.1.**
1. Fast-forward `main` to the v1.1 tip: `git merge --ff-only director/admin-v1-1`.
2. Apply migration 019: `set -a; . ./.env; set +a; make migrate PY=.venv/bin/python`. Expect `migrate: 1 applied, 18 already present`.
3. Check the migration count: `psql "$DATABASE_URL_OWNER" -Atc "select count(*) from schema_migrations"` must print `19`. Do not go on before it does.
4. Rebuild the UI: `docker compose up -d --build ui`.
5. Restart the backend: `docker compose restart app worker`.

Migrate before any restart. Otherwise:
- every login fails (`last_login_at` is missing);
- ① runs in that window are recorded `stopped_by='cap'` and lose their suggestion;
- ② answers 503.

Step 4 can recreate `app`, so it too must come after step 3.

Then use the React console at `http://<host>:8080/admin`.

**Step 2: the retirement**, once satisfied with the React pages:
1. Fast-forward `main` to the retire tip: `git merge --ff-only director/admin-v1-1-retire`.
2. Restart the backend: `docker compose restart app worker`. No migration and no UI rebuild are needed.

**Rollback of step 2:**
1. Revert every commit after `0c6d7b9`, newest first.
2. Run `git revert --no-edit -m 2 0c6d7b9`.
3. Restart the backend: `docker compose restart app worker`.
