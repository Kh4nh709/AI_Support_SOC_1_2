# INT-T03 review (independent Reviewer, verbatim)

APPROVE_WITH_NITS

I found no Blocker or Major issues. `archive_before`, migration 021, the readers, the CLI and the tests do what rulings 1–6 ask, and I checked the code itself, not only the Coder's report.

**Minor**
1. docs/runbook.md:165, DEC-212 step 1. It restarts only `app worker`. When the second compose file is in use, `rag-worker` also runs `rag/lookup.py`, and the runbook's own restart row says it must be restarted after any merge under backend/app. If it is not, a pending `rag_lookup` for an archived alert or case still runs the old code, calls the model and writes `rag_results`. That contradicts the section's own line 171 ("skipped when it runs"). Live has RAG off; the trial stack has it on. Fix: add "and `rag-worker`, when the second compose file is in use".
2. backend/tests/test_migration_021.py, `test_021_applies_on_a_database_at_020…`. This test applies 021 to an empty database at 020, so it does not show that the five ADD CONSTRAINT validations pass on rows like the live ones. I checked by hand: for every non-archived status each new CHECK gives the same answer as the old one, so a clean apply is certain. Seeding a concluded case, an unsealed escalated head, an unsealed auto_closed head and a duplicate before the 021 run would pin that.

**Nit**
3. backend/app/domain/archive.py: `--before` is not checked against now(). A typo such as 2026-11-30 run with `--apply` would also archive the live queue that arrived after the cutoff, and only the backup brings it back. Cheap guard: refuse, or demand an extra flag, when `before > now()`.
4. backend/app/domain/archive.py:122 only catches `OperationalError` on connect. A malformed DSN raises `psycopg.ProgrammingError("invalid dsn: …")` as a traceback, and libpq's text can echo a fragment of the DSN. Line 134's `conn.rollback()` can itself raise on a lost connection. Both are unlikely, since the app already runs on that DSN.
5. `_STATUS_PREDICATE` (correlation.py:44) is shared, so two more readers now leave archived neighbours out:
   - the Tier-1 alert page's correlation table (tier1/queue.py:650);
   - the G2 labelling view (tier1/labels.py:394). It drops `status`, so it would not crash either way, and the gold set is frozen.
   Neither is in DEC-212 item 7 or "Propagated to". Worth one line there.
6. Stale comments:
   - tier2/conclude.py:65 says a case that is not investigating is "always concluded" with a `concluded_by`; an archived case has none.
   - tier2_runs.py:52-54 still lists four case statuses.
7. On the visible arm, an archived alert whose ① never ran shows ① as "pending" for good (aiState.ts `aiStateOfView`). `archived` is not in DECIDED, and the skipped job leaves `triage_status='pending'`. Cosmetic only.
8. The concurrency tests in test_archive.py would still pass with either `FOR UPDATE` or the repeated status condition removed, because each one covers for the other. Both are in the code; the tests just cannot tell them apart.
9. Migration 021 holds an exclusive lock on `alerts` while it re-checks every row three times. A worker transaction left open across a model call would make `make migrate` wait, and the app's queries queue behind it. Earlier migrations had the same pattern. Stopping the workers during the migrate step, or `SET lock_timeout`, would avoid it.

**Coder's deviations: I agree with all four**
- **Dossier fix.** Without it, ② on a new case next to an archived alert crashes with `ValueError` from `AlertStatus`.
- **Decide attribution.** Without it, the 409 body would name the holder as the person who decided an archived alert.
- **Stray-job skip for archived only.** The card's "mirror the concluded case" assumed a skip that does not exist; adding one for concluded cases would change existing behaviour.
- **Agreement mapping returns null even with a case.** This matches SHOW_STATES. The UI cannot reach it today: AiColumn never renders the decided view for archived. The 110 escalations stay in the audit log and in eval's ops_export. One side effect: ① becomes hidden again on the blind arm for those 110 alerts, which is the safe direction.

**Checked and fine**
- **Scope and order:** cases, then their `escalated_tier2` alerts, then heads with `received_at < before`. The cutoff is strict and compared as an instant; a naive time is refused.
- **Duplicates:** never touched; both the SELECT and the UPDATE require `duplicate_of IS NULL`.
- **Writes:** one audit row per alert and case with the exact ruled payload (`case_id` added only on case alerts). No decision event, no label, no job, even with the RAG and draft switches on. A second run archives 0.
- **Locking:** cases, then alerts, in id order, with the status repeated in each UPDATE. No deadlock with `conclude_case`, `decide`, acknowledge or dedup's `FOR UPDATE`. A deadlock with `escalate` is possible but rolls back whole.
- **Size:** `db.connect` sets no statement or idle timeout, and there are none at role or server level. The ~7 000 NOTIFYs are coalesced by the hub (cap 200), and a dry run's are dropped on rollback. The audit trigger fires only on UPDATE and DELETE.
- **Migration 021:**
  - Each CHECK change is no wider than ruled; `concluded_by` may be NULL for `archived` only.
  - Migrations 001–020 are untouched, and nothing checksums applied migrations.
  - I re-ran `build_schema.py` in a scratch copy: `schema.sql` comes out byte-identical.
- **Readers:**
  - `rag/history.py`: its CASE has no ELSE, so archived counts as no decision.
  - Correlation and dossier leave archived out; `AlertStatus` lacks the value, and a test pins it.
  - Stray jobs: triage skips before the `llm_enabled` check; investigate and lookup skip too.
  - Visibility and blind arm: an archived head stays hidden.
  - Tier-1 actions: acknowledge, decide and escalate give `not_active`; reopen gives `not_reopenable`.
  - Tier 2: analyze and conclude give 409; the case list orders archived with the closed cases; `case_open` is False.
  - Dedup never finds an archived head (it is sealed).
  - UI: the overview has its own archived bucket; audit groups, labels and summaries are updated; a knowledge draft from an archived source is refused.
  - eval/ is unchanged and reads only audit events.
- **CLI:** a dry run rolls back; exit codes are 0, 1 and 2; the DSN comes from the container's `DATABASE_URL`, whose role has the needed rights; no DSN is printed.
- **Tests:** they pin the behaviour (whole-row equality, exact payloads, every guard shown red). The 36→38 and 20→21 count updates are justified, and no golden changed.
- **Non-DB suite** on a scratch copy of f2c1bb0: 4598 passed. The only failures were tests that need a git checkout (one test, plus two files I excluded), because the copy is not a repo.

## INT-T03 re-review of fix round 1 (independent Reviewer, verbatim)

APPROVE

Fix round 1 (`f2c1bb0..6e553df`, worktree /project/project/AI_Support_SOC_1_2/.claude/worktrees/agent-aed9d118f27aa55a7) does all seven rulings. I found no Blocker, Major, Minor or Nit. The round only adds tests; none was removed or weakened.

**The Coder's open concern (commit raises under `--apply`, CLI says "failed, nothing changed"):** acceptable for the live run, no fix needed first. With the installed psycopg 3.3.4 that message cannot be false, for two reasons:
- **Connection still up.** COMMIT raised because the server rejected it. PostgreSQL then aborts the whole transaction, so "nothing changed" is true.
- **Connection lost mid-commit**, the one case where the outcome is unknown. The follow-up `conn.rollback()` fails: the connection is BAD, so its first check raises `OperationalError`. The CLI then prints the other line (archive.py `_rollback_failed`), which claims nothing and tells the operator to run the dry run.
- A Ctrl-C during commit is not a `psycopg.Error`, so it surfaces as a traceback, not "nothing changed".

Runbook step 5 already re-runs the dry run (alerts 0 / cases 0 after a real apply), so the operator confirms the outcome either way. A wording tweak ("commit refused, nothing changed") would be cosmetic.

**The Coder's two deviations: I agree with both.**
- **R7 returns `none` for an archived alert with no verdict, whatever its `triage_status`.** No ① answer will ever arrive for that alert. Order in aiState.ts `aiStateOfView` / `aiStateOfRow`: decided → hidden (blind arm) → ready → unavailable → none. So the blind arm and `unavailable` are unchanged, and non-archived statuses still give pending (tested). The alert page polls only while the state is pending (AlertPage.tsx:45), so the endless poll stops too.
- **The R3 guard lives in the command, not in `archive_before`.** That is what ruling 3 says. `test_dedup`, `test_decide` and `test_queue` call `archive_before` with a cutoff in the future, so a guard there would break them.

**Checked and fine**
- **R1 (runbook step 1):**
  - It stops `worker`, and `rag-worker` when the second compose file is in use, before `make migrate`.
  - It then runs `restart app worker` and `restart rag-worker`. Compose v2 `restart` also starts stopped services.
  - `test_runbook_archive.py` pins the order and the conditional wording.
- **R2:** the new test seeds a database at 020 with every live shape, applies 021 through the real `migrate.sh`, and compares every row (whole `to_jsonb`) of alerts, cases, case_alerts, users and audit_events. The shapes are: received, queued, active, auto_closed (closed, unsealed), duplicate, the three closed_* heads, an unsealed escalated head in an investigating case, and a concluded case with `concluded_by`. The Coder's red step, a stricter H2 on a scratch copy, shows the test bites where the empty-database test did not.
- **R3:**
  - `SELECT now()` runs in the same transaction `archive_before` uses, and is compared as an aware time.
  - The refusal exits 2 with one stderr line and an empty stdout, and writes nothing.
  - A cutoff equal to `now()` is accepted.
  - Tested for both the dry run and `--apply`; the existing 2001-cutoff CLI tests are unaffected.
- **R4:** connect catches any `psycopg.Error`, and the rollbacks go through `_rollback`. Both failures print one generic line, exit 1, and the connection is closed in `finally`. A malformed DSN is tested in-process and as `python -m`; no secret, host or driver text appears.
- **R5:** DEC-212 item 7 and "Propagated to" now name `tier1/queue.py` and `tier1/labels.py`; item 5 states the future-cutoff refusal.
- **R6:** comments only, in tier2/conclude.py and web/routers/tier2_runs.py; both are now accurate.
- **Scope:** nothing under eval/, and no change to `archive_before`, migration 021 or the readers.
- **Tests I ran:** the new non-DB tests (test_archive_cli.py and test_runbook_archive.py, `-m "not db"`) pass, 31 passed. I ran them in the worktree with no bytecode or cache written, and the tree stayed clean. I did not run the DB suite or the UI gates; for those I rely on the Coder's reported counts and the Director's rehearsal.

## Director's check and rulings (30/10/2026)

**Rulings on the review.** Minor 1–2 and Nits 3–7 were fixed in fix round 1. A new Coder did it, because the first Coder's session had ended. The card is `INT-T03.fix1.card.md` in the Director's job directory. Nit 8 is accepted: the two concurrency tests cannot tell `FOR UPDATE` from the repeated status guard, and both are in the code.

**Re-review.** APPROVE. The Coder's open concern, a failed `--apply` commit printing "nothing changed", is accepted on the Reviewer's analysis. Runbook step 5 re-runs the dry run in any case. `director/integration` was fast-forwarded `0d1e40c` → `6e553df`.

**Rehearsal on the live data, at `f2c1bb0`.** A read-only `pg_dump` of the live DB (22:05) was restored into a private PostgreSQL 16.2.
- Migration 021 applied in 0.5 s, 21 migrations.
- `python -m app.domain.archive --before 2026-10-30T20:15:00+07:00`:
  - dry run: 7 194 alerts (received 48, queued_tier1 7 035, tier1_active 1, escalated_tier2 110) and 6 cases;
  - apply: the same counts, in 2.5 s.
- After apply:
  - 7 194 `archived` alerts and 6 `archived` cases; 0 open heads before the cutoff;
  - duplicates unchanged at 206 657, and jobs unchanged;
  - exactly 7 194 `alert.archived` and 6 `case.archived` events, all `system`, with the ruled payload;
  - no decision or label event, and every archived row closed and sealed with its reason.
- A second apply archived 0.

**Mutation checks at `6e553df`.** Private PostgreSQL 16.2; the target files at baseline were 267 passed. Each mutation was applied to a scratch worktree and restored; the tree was clean at the end.

| Mutation | Result |
|---|---|
| M1: archived removed from ①'s skip set | red, 1 |
| M2: correlation shows archived neighbours | red, 3 |
| M3: the head cutoff `<` becomes `<=` | red, 4 |
| M3b: the case cutoff dropped | red, 5 |
| M4: history counts archived as `tier1_closed_benign` | red, 2 |
| M5: the dry run commits | red, 4 |
| M6: a future cutoff is accepted | red, 2 |
| M7: the alert audit is written as `case.archived` | red, 2 |
| M8: 021 loosened so that a human conclusion may lack `concluded_by` | **survived** |
| UI: an archived alert shows ① as pending | red, 1 |

On M8: the rule is pinned only by `docs/Schema/test_constraints.py`, the docker-exec script outside pytest. 021 itself was read and is correct: `concluded_by` may be NULL only for `archived`. **Follow-up, not blocking:** a pytest pin that a database at 021 still refuses `concluded_fp`, `concluded_policy_violation` and `confirmed_incident` without `concluded_by`.
