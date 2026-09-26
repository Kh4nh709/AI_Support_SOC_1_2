# Coder — P4-T09 · five malformed webhook bodies return 500; they must return 4xx

**Invocation (the Owner pastes this, nothing else — session name `coder-P4-T09`):**

```
Read docs/plan/prompts/coder-template.md and act as that Coder. Your task is P4-T09 and it has
no card: docs/plan/prompts/coder-P4-T09-webhook-hardening.md is the acceptance contract
(precedent DEC-018, DEC-032, DEC-055 — a one-file defect fix needs no card). Start with §0.
```

`prompts/coder-template.md` governs: you work in your own worktree, you commit only what §2 lists,
your report is an artifact. This contract comes from the P4-T08 Reviewer's non-blocking note 1,
recorded as a follow-up in **DEC-109** (bucket (b) — nothing here is charged to the P4-T08 Coder).
Written by the Support Agent at the Owner's instruction, 25/09.

## 0 · Read first

1. `backend/app/web/routers/webhook.py` — the route as it ships. It already maps: disabled → **503**
   (`:56`), bad key → **401** (`:60`), IP not allowed → **403** (`:65`), oversize → **413** (`:71`),
   missing required field → **400** with `{"missing": …}` (`:74`), duplicate → **409** (`:76`).
   The defect is what is **not** in that list.
2. `backend/app/infra/intake.py` — `receive()`, which the route calls.
3. `backend/tests/test_webhook.py` — 16 tests today, and the docstring rule at `:4`: *a `400` must
   leave its `rejected_alerts` row committed*. Whatever you add obeys the same rule.
4. `docs/plan/DECISIONS.md` **DEC-109** (this defect), **DEC-040** (`WEBHOOK_API_KEY`,
   `WEBHOOK_IP_ALLOWLIST`, both fail-closed), **DEC-025** (every acceptance needs a demonstrated
   failing case).
5. `docs/plan/00-context-pack.md` §6.1 (`intake` is append-only with a column-pinned UPDATE), §6.4
   (the API list), §2 invariants **G9** (byte-identical `raw_payload`) and **G12** (an `intake`
   receipt exists for every accepted body).

## 1 · The five bodies, from DEC-109

All five arrive **authenticated and from an allowed IP** — they pass every check the route already
has, then raise an unhandled exception and surface as **500**:

| # | body | today |
|---|---|---|
| 1 | no `timestamp` field at all | 500 |
| 2 | `timestamp` present but unparseable (e.g. `"not-a-date"`) | 500 |
| 3 | the request body is **UTF-16**-encoded JSON | 500 |
| 4 | `_source` present but **not a dict** (e.g. a list or a string) | 500 |
| 5 | a `\u0000` inside a JSON string value | 500 |

**Goal:** each returns a **4xx** that names what was wrong, writes the same `rejected_alerts`
receipt the existing `400` path writes, and never writes an `alerts` or `intake` row. A 500 on a
client-supplied body is an unhandled bug; a 4xx is a contract.

## 2 · Scope

- **Modify:** `backend/app/web/routers/webhook.py` and/or `backend/app/infra/intake.py` — whichever
  owns the failure; prefer the one where the existing `400` is raised, so all malformed-body answers
  live in one place. `backend/tests/test_webhook.py` gains the five cases.
- **Scope out:** the auth/allowlist/size/duplicate paths (they work), the parser's own field mapping
  (P2-T04), the pipeline, any migration, any config key. **No new §6.3 key and no schema change** —
  if you think you need either, stop and write an INBOX `DECISION_REQUEST` instead.
- Choose the status codes deliberately and justify each in the report: `400` for a body the client
  can fix, **`415`** for an encoding the endpoint does not accept (case 3 is the honest candidate),
  `422` only if you can say why it is not a `400`. Do not invent a sixth code for variety.

## 3 · Two traps measured in this codebase

1. **The `\u0000` case is not only a parse question.** PostgreSQL `text` rejects a NUL byte, so even
   a body that parses can fail at the INSERT — and the receipt write is what must survive. Decide
   where you reject it (before the INSERT) and prove the receipt still lands.
2. **`Conn` is `scope="function"` and rolls back on any exception including `HTTPException`**
   (`webhook.py:15` says so, and the memory of this project records the same thing about
   FastAPI 0.141). So a receipt written in the same transaction as the rejection **disappears**
   unless it is committed the way the existing `400` path commits it. Copy that mechanism; do not
   invent a second one.

## 4 · Acceptance — every line is a command you run and paste

1. `.venv/bin/python -m pytest -c backend/pyproject.toml backend/tests/test_webhook.py -rs` →
   passes, **≥ 21 tests** (16 today + your five), `skipped` absent.
2. For each of the five bodies, the status code and the receipt, from the test output: status is
   4xx (never 500), `rejected_alerts` has exactly one new row naming the reason, and
   `select count(*) from alerts` / `from intake` are **unchanged**. Paste the five rows.
3. **The red step (DEC-025), shown red once:** revert your handler for case 1 only (`git stash` the
   one hunk, or comment the branch), re-run that single test, paste the **500** it produces, then
   restore. A guard that cannot go red proves nothing — and this whole task exists because five
   such cases were never tested.
4. `make test` → exit 0 (expect **≥ 1048 passed** on top of `main`), `make test-db` → exit 0
   (expect **≥ 558 passed**), `make lint` → exit 0. `PY` defaults to the checkout's `.venv`
   (`Makefile:19`) — do not call bare `python3`, it is 3.14 here without pytest.
5. `git diff main...task/P4-T09 --stat` → only the files §2 names.
6. `grep -nE '\b500\b' backend/app/web/routers/webhook.py backend/app/infra/intake.py` → no new
   `500` is raised deliberately.

## 5 · First and last

- **First:** `cd ../AI_Support_SOC_1_2-P4-T09 && git merge main` — `main` moved on 25/09 (DEC-109,
  DEC-110) and P4-T08's webhook files are exactly what you are editing. If the worktree does not
  exist, the Director creates it (DEC-045); do not create it yourself.
- **Last:** `docs/plan/tasks/P4/P4-T09.report.md` — the five codes with the reason you chose each,
  the five receipts, the red step's 500, the four suite outputs, and any judgement you made that the
  contract did not settle. Set the `P4-T09` row in `docs/plan/STATE.md` to `review` and commit both
  on your branch. **Do not merge** — that is the Director's.
- This task is **last in P4** by the Owner's decision (25/09): if the schedule reaches 30/09 with it
  unstarted it is cut, and the five bodies are named in `docs/limitations.md` instead.
