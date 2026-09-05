# P1 · Smoke test + schema — task cards

Phase objective: retire the two biggest unknowns before product code — does the model behave,
and does the v3 schema apply cleanly.

---

## ⛔ Dispatch precondition — nothing in this phase dispatches until P0-T07 merges

`P0-T07` is on branch `task/P0-T07`, status `approved`, **not on `main`**. Until it merges:

- `main`'s `make test-db` still gates on `docker compose ps` and exits 1 on this host (measured
  on `main` today), so **every DB acceptance line in every card below is unrunnable**.
- Verified in the `task/P0-T07` worktree today: `TEST_DATABASE_URL=postgresql:///soc_test make test-db`
  → `test-db: using postgresql:///soc_test` · `3 passed, 77 deselected` · exit 0.

Six of the seven cards here end in a `make test-db` line. Dispatching before the merge would
produce six false failures. **Merge `task/P0-T07` into `main` first, then dispatch.**

---

## ⚠️ Budget note — this phase does not fit its day, and by a lot

| | |
|---|---|
| Sum of `must` estimates | **17 h** |
| Day budget (`01-plan.md`, D1) | 8 h |
| Overbooking | **+112 %** — the re-plan threshold is 30 % |
| Wall-clock at the 3-coder cap | ≈ 6.5 h, *if* three coders run continuously from hour one |
| Critical path | P1-T03 (2 h) → P1-T06 (2.5 h) → P1-T07 (1.5 h) = **6 h** |

Two things make the arithmetic worse than the ratio alone suggests:

1. **D1 is already spent.** `HUONG-DAN-VAN-HANH.md` §0 merged D0 and D1 into 05/09 ("Chạy P0
   buổi sáng, P1 buổi chiều"), and P0 consumed the whole day: P0's own budget note planned
   10 h in 8 h, then T07 was added on top and is still in review. P1 therefore starts on
   **06/09**, which is P2's D2.
2. **Seven tasks means seven dispatch → review → merge cycles**, and that is Owner time, not
   coder time. It is not in the 17 h.

### What I propose moves (Director/Owner call — I am not deciding it)

**Recommended: accept the overrun and run P1 as one full day on 06/09, cutting nothing.**
Nothing here is padding: five migrations are five disjoint DDL files that P2 cannot start
without, and the smoke test is the phase's other half. Compressing by merging cards saves
coordination, not hours.

**If D2 must be protected, the single designated lever is P1-T04 (migration 015).** It is the
only `must` in this phase that nothing reads before P4:

- `triage_labels`, `autoclose_reviews` → P6 labelling and P5 digest
- `case_notes` → P5 · `eval_runs` → P7 · `system_health` → P5 health job
- P2 needs 013 (enrichment upsert), 014 (intake/cursor/heartbeat), 016 (`alerts.manager_id`,
  `origin_host`, `source` CHECK, `suggestion_visible`, `jobs.job_type='pull'`) and 017
  (append-only on `intake`) — **and none of 015.**

Moving it saves 2.5 h (17 h → 14.5 h, still +81 %) and **requires amending P1's exit gate**
from "migrations 013–017 apply on a clean DB" to "013, 014, 016, 017 apply; 015 deferred to
P4". That is an exit-gate change, so it is the Director's to make and the Owner's to approve.

**Do not cut P1-T01 or P1-T06.** T01 is the model-acceptance evidence that gates P3 and is the
first evidence chapter of the report. T06 carries G2/G11 append-only enforcement, and DEC-016
states its TRUNCATE trigger is not optional.

---

## Critical path and waves

```
P1-T01  smoke test (4 h) ─────────────────────────────────── independent, dispatch first
P1-T02  013 assets_enrichment (1.5 h) ──┐
P1-T04  015 labels/reviews/… (2.5 h) ───┤
P1-T05  016 alter alerts/jobs/… (3 h) ──┼──▶ P1-T07  make migrate + schema.sql (1.5 h)
P1-T03  014 intake/cursor/hb (2 h) ──┬──┘
                                     └──▶ P1-T06  017 append_only_and_roles (2.5 h) ──▶ T07
```

**The suggested decomposition in `prompts/P1.md` says the critical path is T02 → T04 → T05 → T06.
Measured, it is not.** Migrations 013, 014, 015 and 016 touch disjoint objects and none reads
another's output:

- 013 alters `assets`, `identities`, `iocs` and drops `enrich_cache` — all v1 objects.
- 014 creates `intake`, `source_cursor`, `source_heartbeat` — no FK to anything 013/015/016 touch.
- 015 creates five tables whose FKs point at `alerts`, `users`, `cases` — all v1.
- 016 alters `alerts`, `jobs`, `llm_runs`, `users`, `audit_events` — all v1.
- **017 is the only real edge: it needs `intake` to exist, so it depends on 014 (T03).**

`scripts/migrate.sh` applies `[0-9][0-9][0-9]_*.sql` in filename order and skips anything already
in `schema_migrations`, so a worktree holding only its own migration migrates a fresh database
correctly. Proven today on a throwaway database with a stand-in `013`: clean DB → `applied
schema.sql, recorded 12 base migrations` → `applying 013_probe` → `1 applied, 12 already
present`; re-run → `0 applied, 13 already present`.

**Wave 1 (3 coders):** T01, T03, T05 — T03 is on the critical path, T05 is the largest migration.
**Wave 2 (3 coders):** T02, T04, T06 — T06 the moment T03 is merged.
**Wave 3:** T07, alone, after all five migrations are on `main`.

---

## Exit-gate coverage

| Gate item (`01-plan.md`) | Covered by | Notes |
|---|---|---|
| `docs/smoke-test-D1.md` with numbers | T01 | Not blocked — `.env` carries all six `LLM_*` keys and the model answered today |
| Migrations 013–017 apply on a clean DB | T02, T03, T04, T05, T06 — proven together by **T07** | Each card proves its own migration on a fresh database; T07 proves the five in order |
| DB tests green (`make test-db`) | every card's last acceptance line; **T07 runs the full suite** | Depends on P0-T07 |
| Model accepted or fallback chosen | **Owner action**, from T01's report | Not a task |

---

## Planning decisions (tactical — Director may promote to a DEC)

1. **`backend/tests/test_schema_v3.py` is split, and T07 owns the name.** The phase spec names
   one test file, but five coders working in five worktrees cannot share one file without
   guaranteed conflicts (DEC-010 gives each task its own worktree, and `HUONG-DAN` §5 requires
   disjoint file scope). Each migration task owns `backend/tests/test_schema_v3_0NN.py` for its
   own migration; **T07 owns `backend/tests/test_schema_v3.py`**, which is the cross-cutting
   test: every §6.1 table present, every migration recorded, `schema.sql` in sync. The spec's
   filename therefore exists and holds the phase-level assertions.

2. **`docs/Schema/schema.sql` is regenerated exactly once, by T07, and by nobody else.** It is a
   57 KB generated file; five tasks regenerating it is five conflicts. Measured today:
   `python3 build_schema.py --check` on `main` prints `schema.sql khớp migrations · 886 dòng`,
   so T07 starts from a clean baseline. **Consequence to expect and not panic about:** between
   the first migration merging and T07 merging, `build_schema.py --check` exits 1 on `main`.
   That is by design; T07 closes it. No card except T07 may run `build_schema.py` without
   `--check`.

3. **The smoke test validates `triage_v2` against a spec it carries itself, not against
   `output_schemas.json`.** §6.2 names `backend/app/llm/templates/output_schemas.json` as the
   only source, but that file is a P3 deliverable and does not exist; the legacy
   `llm/templates/output_schemas.json` holds the **v1** shape (`ly_do`, `bang_chung`), not
   `triage_v2`. P1 creating a P3-owned frozen-contract file would be Planner over-reach. T01
   therefore carries a module-level `TRIAGE_V2` spec dict transcribed from §6.2 and a
   hand-written validator, and its report prints the exact rules applied so **P3 lifts the dict
   verbatim** into `output_schemas.json`. Recorded in §Hand-off as a reconciliation duty.

4. **No new dependency for validation.** `jsonschema` 4.10.3 happens to be installed on this
   host but is **not** in `backend/requirements.txt`, so a coder could import it, pass locally,
   and ship a hidden dependency. T01's acceptance forbids it explicitly.

5. **New surrogate keys use `GENERATED BY DEFAULT AS IDENTITY`, never `serial`/`bigserial`.**
   Measured today on this cluster: with `GRANT SELECT, INSERT, UPDATE, DELETE` and no sequence
   grant, `INSERT` into an `IDENTITY` table as `app_rw` succeeds, and `INSERT` into a `bigserial`
   table fails with `permission denied for sequence t_serial_id_seq`. v1 uses `IDENTITY`
   throughout (`rejected_alerts`, `jobs`, `audit_events`). A `bigserial` in 014 or 015 would
   pass every P1 test — which all run as the owner — and break the application in P2. 017 also
   grants sequence usage as defence in depth.

6. **Every acceptance line sets its DSN inline.** `.env` is git-ignored, so a task worktree has
   none (DEC-018 recorded this biting the P0-T07 review). The Owner's `.env` also carries no
   `DATABASE_URL_OWNER` — measured: it has the six `LLM_*`, five `INDEXER_*`, `PULL_START` and
   `TEST_DATABASE_URL`, and nothing else. So every card writes
   `TEST_DATABASE_URL=postgresql:///soc_test make test-db` and passes the migration DSN as
   `scripts/migrate.sh`'s positional argument. No card depends on a file it cannot see.

7. **No task needs a daemon.** Context pack §3 as amended by DEC-018: local processes, native
   PostgreSQL 16 on `127.0.0.1:5432`, `grep -cE 'COMPOSE|docker compose' Makefile` → 0. The
   phrase "on a fresh container" in `prompts/P1.md` T07 is void.

8. **Each task creates and drops its own scratch database.** `soc_dev` is shared and
   `soc_test` belongs to the conftest fixture, which drops and recreates it every session.
   A card that needs a clean database creates `soc_p1t0N` with `createdb`, migrates it, asserts,
   and drops it. `CREATEDB` is granted (DEC-008, re-measured today: `rolcreatedb = t`).

---

## Environment measured today (2026-09-05), and where it contradicts the phase prompt

Everything below was measured on this host before these cards were written, per DEC-006.

| Claim in `prompts/P1.md` or handed to me | Measured | Consequence |
|---|---|---|
| "017 … `CREATE ROLE app_rw` and the owner role" | `app_rw` **already exists**: NOLOGIN, no attributes, `user1` is a member, `SET ROLE app_rw` succeeds. `user1` has `rolcreaterole = f`, so an unconditional `CREATE ROLE` **fails** | 017's role creation is a conditional `DO` block (DEC-016) |
| "`conftest.py` connects as `app_rw` for tests that exercise the application" | `app_rw` is **NOLOGIN** — nothing can connect as it | Void. Route D: connect as the owner, issue `SET ROLE app_rw`. Struck from T06's card |
| "`soc_dev` does not exist / `createdb soc_dev` belongs in the first migration task" | `soc_dev` **exists**, owner `user1`, 14 tables, 12 migrations recorded — DEC-015 created it | No card creates it. Cards create their own scratch databases instead |
| §6.1 "`alerts` + … `source ∈ wazuh|lab|replay`" | `alerts.source` **already exists** (`text NOT NULL DEFAULT 'wazuh'`, from 002), with **no CHECK** | 016 adds `ck_alerts_source` only. `ADD COLUMN source` would fail |
| §6.1 "drop `sampled_for_control`" | **No such column.** It is a jsonb *payload key* in `docs/phase-3-auto-close.md:166`, never a column | 016 uses `DROP COLUMN IF EXISTS` — a documented no-op. INBOX item filed |
| §6.1 "`assets/identities/iocs` + `source`, `loaded_at`, `active`" | `iocs.source` **already exists** and is **half the primary key**: `006_chot_hop_dong.sql:54-56`, `iocs_pkey PRIMARY KEY (value, source)` | 013 adds `source` to `assets` and `identities` only; `iocs` gets `loaded_at` and `active` |
| §6.1 "Dropped from v3: `enrich_cache`, `prompt_versions`" | `enrich_cache` exists (from 010), no FK or view depends on it. `prompt_versions` **never existed** | `DROP TABLE enrich_cache` assigned to 013. Nothing to do for `prompt_versions` |
| §6.1 "`jobs.job_type ∈ pipeline\|triage\|investigate\|digest\|health\|pull`" | current `ck_jobs_job_type` is **`('enrich','triage')`** — architecture §5's table says 5 values without `pull`; §6.1 says 6 | §6.1 wins (§0 precedence). 016 recreates over the 6 v3 values |
| §6.1 "`audit_events.event_type` CHECK set = 21 v1 names + 6" | `ck_audit_event_type` holds exactly **21** values — counted | New set = 27. The 21 are pasted verbatim into T05's card |
| Model unverified | Verified independently today: `deepseek-v4-flash`, HTTP 200, `json_object` honoured, content parsed as JSON, 1.33 s | T01 is not blocked |
| Indexer holds 7,451 documents | `_count` on `wazuh-alerts-*` = **7,495** (live and growing), **42 distinct `rule.id`**, 10 distinct `rule.level` (3–12) | Enough for 30, but see T01's stratification note |

---

## INBOX items raised by this plan

- `2026-09-05 · P1-T05 · DECISION_REQUEST` — §6.1 orders `alerts.sampled_for_control` dropped; the
  column does not exist. Recommended: `DROP COLUMN IF EXISTS` as a recorded no-op and strike the
  line from §6.1. Non-blocking — T05 ships either way.
- `2026-09-05 · P1-T02 · DECISION_REQUEST` — §6.1 orders `enrich_cache` dropped but no migration
  was assigned to it in `prompts/P1.md`'s decomposition. Assigned to 013 as the enrichment-tables
  migration (DEC-004's principle). Non-blocking; the Director may move it to 016.
- `2026-09-05 · P1-T01 · QUESTION` — `docs/smoke-test-D1.md` lands on a **public** GitHub remote
  (`github.com/Kh4nh709/AI_Support_SOC_1_2`). Full raw responses over 38 real alerts would
  publish live hostnames, usernames and internal IPs. Default taken: summary tables and the
  300-character excerpts the phase spec asks for are committed; full raw JSON goes to
  `eval/results/smoke/` (git-ignored) and the report names the path. Owner may widen it.

---

## Task table

| Task | Title | Priority | Est. | Depends on | Owner action? |
|---|---|---|---|---|---|
| P1-T01 | `eval/smoke_test.py` + `docs/smoke-test-D1.md` | must | 4 h | — | yes, after: read the report, accept the model |
| P1-T02 | Migration 013 `assets_enrichment` (+ drop `enrich_cache`) | must | 1.5 h | — | no |
| P1-T03 | Migration 014 `intake_cursor_heartbeat` | must | 2 h | — | no |
| P1-T04 | Migration 015 `labels_reviews_notes_eval_health` | must | 2.5 h | — | no |
| P1-T05 | Migration 016 `alter_alerts_jobs_llm_runs_users` | must | 3 h | — | no |
| P1-T06 | Migration 017 `append_only_and_roles` | must | 2.5 h | P1-T03 | no |
| P1-T07 | `make migrate` end-to-end, `schema.sql` regeneration, `make test-db` green | must | 1.5 h | T02–T06 | no |

File scope is disjoint by construction: one `.sql` file and one test file per migration task.
`docs/Schema/schema.sql` is touched only by T07.

---

### P1-T01 · `eval/smoke_test.py` + `docs/smoke-test-D1.md`
- Priority: must
- Goal: measure whether `deepseek-v4-flash` returns schema-valid `triage_v2` JSON on real alerts, on 30 KB prompts and under injection, with the numbers the report needs — including where the money actually goes.
- Scope in: the script; its offline test; the report. Scope out: `backend/app/llm/**` (P3); the typed builder (P3); `output_schemas.json` (P3).
- Files — create: `eval/smoke_test.py`, `backend/tests/test_smoke_test.py`, `docs/smoke-test-D1.md` / modify: —
- Contracts touched: none (reads §6.2 and §7.5; writes neither)
- Depends on: —
- Estimate: 4 h
- Acceptance: see the card. The wrapper rule (DEC-006) is met by acceptance 2, which runs the script's own `--offline` path rather than the functions beneath it.
- Risk / notes: 74 % of the index is rule `92601` — an unstratified sample measures one rule. Cost is dominated by reasoning tokens (measured: 35 of 41 completion tokens on a trivial prompt, output priced 47× input), so the report breaks them out. Estimated total spend for a full run ≈ **$0.04**, under 0.2 % of `LLM_MONTHLY_USD_CAP`.

### P1-T02 · Migration 013 `assets_enrichment`
- Priority: must
- Goal: the three enrichment tables carry §6.2's criticality vocabulary and the `source`/`loaded_at`/`active` columns the P2 loader upserts, and the dropped v3 table is gone.
- Scope in: `013_assets_enrichment.sql` + its tests. Scope out: the loader (P2); any other migration; `schema.sql` (T07).
- Files — create: `docs/Schema/013_assets_enrichment.sql`, `backend/tests/test_schema_v3_013.py` / modify: —
- Contracts touched: §6.1 — implements DEC-004. Settled; transcribe.
- Depends on: —
- Estimate: 1.5 h
- Risk / notes: `iocs.source` already exists and is half `iocs_pkey` — adding it again fails. All three tables are empty on `soc_dev`, `soc_test` and `soc`, so the CHECK swap needs no data migration.

### P1-T03 · Migration 014 `intake_cursor_heartbeat`
- Priority: must
- Goal: the intake ledger and the puller's two state tables exist with the UNIQUE that makes double-pull idempotent.
- Scope in: `014_intake_cursor_heartbeat.sql` + tests. Scope out: the puller (P2); `schema.sql` (T07).
- Files — create: `docs/Schema/014_intake_cursor_heartbeat.sql`, `backend/tests/test_schema_v3_014.py` / modify: —
- Contracts touched: §6.1 — new tables, transcribe.
- Depends on: —
- Estimate: 2 h
- Risk / notes: On the critical path — P1-T06 cannot start until this merges. `intake_id` must be `GENERATED BY DEFAULT AS IDENTITY` (planning decision 5).

### P1-T04 · Migration 015 `labels_reviews_notes_eval_health`
- Priority: must — **the designated cut if the day runs long** (see the budget note)
- Goal: the five tables P5, P6 and P7 write to exist with their closed sets enforced.
- Scope in: `015_labels_reviews_notes_eval_health.sql` + tests. Scope out: the labelling page (P6); `schema.sql` (T07).
- Files — create: `docs/Schema/015_labels_reviews_notes_eval_health.sql`, `backend/tests/test_schema_v3_015.py` / modify: —
- Contracts touched: §6.1 — new tables, transcribe.
- Depends on: —
- Estimate: 2.5 h
- Risk / notes: Nothing before P4 reads these tables, which is why it is the lever. `note_id` is `IDENTITY`, not `bigserial`.

### P1-T05 · Migration 016 `alter_alerts_jobs_llm_runs_users`
- Priority: must
- Goal: the five v1 tables carry their v3 columns and their CHECK sets are the v3 sets.
- Scope in: `016_alter_alerts_jobs_llm_runs_users.sql` + tests. Scope out: the enrichment tables (013 owns them); `schema.sql` (T07).
- Files — create: `docs/Schema/016_alter_alerts_jobs_llm_runs_users.sql`, `backend/tests/test_schema_v3_016.py` / modify: —
- Contracts touched: §6.1 — transcribe. The 21 v1 event names are pasted into the prompt.
- Depends on: —
- Estimate: 3 h
- Risk / notes: The largest card. `alerts.source` exists — add the CHECK, not the column. `sampled_for_control` does not exist — `DROP COLUMN IF EXISTS`. `ck_jobs_job_type` is currently `('enrich','triage')`, so `enrich` is dropped from the set as the phase spec requires.

### P1-T06 · Migration 017 `append_only_and_roles`
- Priority: must
- Goal: `audit_events`, `llm_runs` and `intake` are append-only against both the privilege layer and the trigger layer, TRUNCATE included.
- Scope in: `017_append_only_and_roles.sql` + tests. Scope out: `conftest.py` (unchanged — nothing connects as `app_rw`); `schema.sql` (T07).
- Files — create: `docs/Schema/017_append_only_and_roles.sql`, `backend/tests/test_schema_v3_017.py` / modify: —
- Contracts touched: §6.1 append-only clause — implements DEC-016 route D.
- Depends on: **P1-T03** (`intake` must exist)
- Estimate: 2.5 h
- Risk / notes: `CREATE ROLE` is conditional or the migration aborts here (`app_rw` exists; `user1` has no `CREATEROLE`). The BEFORE TRUNCATE statement-level trigger is **not optional** (DEC-016) and gets its own acceptance line on all three tables.

### P1-T07 · `make migrate` end to end, `schema.sql` regeneration, `make test-db` green
- Priority: must
- Goal: the five migrations apply in order on a database that has never seen them, `schema.sql` matches the migrations again, and the whole DB suite is green.
- Scope in: regenerating `schema.sql`; `backend/tests/test_schema_v3.py`. Scope out: editing any `NNN_*.sql`; editing `build_schema.py`; the `Makefile`.
- Files — create: `backend/tests/test_schema_v3.py` / modify: `docs/Schema/schema.sql` (regenerated, never hand-edited)
- Contracts touched: none
- Depends on: P1-T02, P1-T03, P1-T04, P1-T05, P1-T06 — all merged into `main`
- Estimate: 1.5 h
- Risk / notes: If a migration is broken this is where it shows. The task **reports** the failure and does not fix another task's `.sql` file; that goes back to its owner.

---

## Hand-off to P2 and beyond

1. **P3 must reconcile `triage_v2`.** T01 carries the `TRIAGE_V2` spec dict and its report prints
   the validation rules applied. P3's `backend/app/llm/templates/output_schemas.json` lifts that
   dict verbatim; if P3 makes it stricter, the smoke test's schema-valid rate stops being
   evidence for P3's gate step 1 and the report must say so.
2. **The reasoning-token cost shape is P3's sizing input.** Output is priced 47× input
   (`LLM_PRICE_OUT_PER_M=0.66` vs `LLM_PRICE_IN_PER_M=0.014`) and `usage.completion_tokens`
   *includes* `completion_tokens_details.reasoning_tokens`. Whatever ratio T01 measures is the
   number P3 uses to size `LLM_MONTHLY_USD_CAP`, together with P2's dedup measurement (DEC-014).
   Neither number alone answers the budget question.
3. **DeepSeek returns prompt-cache counters** (`prompt_cache_hit_tokens`,
   `prompt_cache_miss_tokens`, `usage.prompt_tokens_details.cached_tokens`) and `.env` has no
   cache price key. T01 records the counters; whether §6.3 needs a cache-price key is a P3
   decision, not P1's.
4. **DEC-004's two open follow-ups are still open** and are *not* P1's: the risk-score formula at
   `docs/phase-4-enrichment.md:170` (needs its own decision before `soar/risk.py` in P2) and the
   two playbooks branching on `crown_jewel` (`kb/playbooks/malware.md:36`,
   `kb/playbooks/ssh_brute_force.md:34`, rewritten at the P3 playbook review). 013 lands the
   column change; it does not settle either.
5. **`docs/limitations.md` (P8) owes one line from DEC-016**: the application session can
   `RESET ROLE` to `user1`, which owns the database and can `DROP TRIGGER`. Route D's residual,
   irreducible weakening.
6. **DEC-017 / DEC-019 — the G1 source — does not touch P1.** I was told it is still escalated;
   `main` @ `f1c7472` records DEC-019 as the Owner's answer ("both"). Either way nothing in this
   phase depends on it: no card here reads an alert source, and `alerts.source ∈ wazuh|lab|replay`
   was already provisioned in §6.1. Flagging the discrepancy rather than planning around either
   reading.
