# P13 report: learned knowledge and agentic RAG (DEC-210)

**Branch.** `director/rag-knowledge` at `70c9790`. It is built on `director/soar-intake` (P12) and is not merged to `main`. The Owner does that merge; nothing has been pushed.

**Spec and plan.**
- Spec: `docs/superpowers/specs/2026-10-24-learned-knowledge-rag-design.md` (rev 2).
- Plan: `docs/superpowers/plans/2026-10-25-learned-knowledge-rag.md`.

**How it was run.** Per DEC-201, every task had one Coder subagent (Sonnet 5.5, own worktree) and one independent Reviewer. Once all nine tasks were merged, the whole branch got a final review, then one fix wave, then a scoped re-review. The Director ran one mutation check at each merge.

## What was built

1. **Drafts from conclusions** (`KNOWLEDGE_DRAFT_ENABLED`). A Tier-1 close or a Tier-2 conclusion queues a `knowledge_draft` job. A separate DeepSeek agent on `rag-worker` then writes a draft from two inputs: the closed fields, and the analyst's notes, which are treated as untrusted.
   - The draft is validated by V1–V5:
     - the schema;
     - the closed fields;
     - no literal addresses, accounts, user names, hashes or hostnames;
     - the injection detector;
     - invisible and structure-forging characters.
   - A matching conclusion is merged into an existing entry. A disagreeing one is flagged as a conflict.
   - When the model cannot be asked:
     - over the monthly cap, or on a 429, the job is rescheduled;
     - on a 402 (no balance), a text-less draft is stored, and the admin can **Soạn lại** it later.
2. **Admin review on `/admin/knowledge`.**
   - Five tabs: Chờ duyệt, Đã duyệt, Đã gộp, Từ chối, Đã gỡ.
   - The left column shows the analyst's work: the alert or case, ①'s suggestion with its gate result and reasons, ②'s result, the decision, the notes, the SOAR block and any conflicting entry.
   - The right column holds the draft form: the model fields can be edited, and the closed fields are read-only.
   - Actions: Duyệt, Sửa rồi duyệt, Từ chối, Gỡ, Soạn lại.
3. **Publication.** An approved draft becomes an entry row plus a Markdown file at `kb_learned/entries/<category>/<id>.md`.
   - The file is rendered by the system, never written from raw admin Markdown, and its hash is stored.
   - `kb_learned/` sits beside `kb/` and never replaces it.
   - `python -m app.rag.publish --rebuild` rewrites the files from the database.
4. **A lookup on every ①/② run** (`RAG_ENABLED`). `rag-worker` builds two things:
   - the decision history: closed fields and counts, at six similarity levels;
   - up to 3 approved entries. DeepSeek ranks the candidates the database finds (overlap plus Postgres full-text search) as `rat_giong`, `giong` or `hoi_giong`. There are no embeddings.
5. **Into the prompt.** ① (as a section) and ② (as block 10 of the dossier) read the newest usable lookup and re-check every entry (still active, hash unchanged).
   - The history goes in as a `decision_history` block, and the entries as one numbered `kb_learned` block, each entry preceded by a closed level fact. Then comes the reference sentence, in the user message only.
   - Output schemas, linter and gate are unchanged.
   - ① is delayed by `RAG_TRIAGE_DELAY_S` (45 s) and never waits beyond that. ② never waits.
6. **Operations.**
   - The `docker-compose.rag.yml` override adds `rag-worker`. It mounts `kb_learned` read-only; `app` mounts it read-write.
   - Migration 020 adds the new tables.
   - Three health checks: `knowledge_queue`, `knowledge_integrity` and `rag_budget`.
   - The runbook gains the section "Learned knowledge and RAG (DEC-210)", and the limitations gain (xlvii)–(xlix).

**With both switches false (the default), ① and ② are byte-identical to P12.**
- The golden fixtures are built at the base commits and must match.
- The `llm_runs` INSERTs are pinned by their SQL text.
- A run on a schema without `llm_runs.rag_lookup_id` passes.
- The eval harness runs without RAG (`EvalSwitches.rag=False`).

## Tasks

| Task | Merge | Review | Director's merge check |
|---|---|---|---|
| T01 frozen contracts, migration 020, keys, typed reclaim | `ef32726` | APPROVE | red |
| T02 retrieval without AI | `949fb30` | 1 fix round | red |
| T03 ranking agent, budget, `rag_lookup`, `rag-worker` | `b681702` | 1 fix round | red |
| T04 drafts, merge and conflict, V1–V5 | `767a040` | 2 fix rounds (invisible characters) | FP family red; `Cf` alone survived, later pinned in the wave |
| T05 approval, publication, admin API, health | `92c9637` | APPROVE | `_CATEGORY` widened → red |
| T09 operations and docs | `9813bbe` | 1 fix round | `rag-worker` mount rw → red |
| T07 ① uses the lookup | `33fcd15` | APPROVE | `MAX_LEARNED_ENTRIES` 3 → 4 → red |
| T06 admin page | `6804cb8` | 1 fix round (①'s gate and reasons) | URL id regex `.+` → 2 red |
| T08 ② uses the lookup | `f870c54` | APPROVE | two pins needed a DB; the wave made them run in `make test` |
| Whole-branch review and fix wave (29 items) | `7bac383` | NEEDS FIXES → re-review APPROVE | `COMMON_ACCOUNTS` filter removed → 11 red |

**Final suites on the wave tip:**

| Suite | Result |
|---|---|
| `make lint` | clean |
| `make test` | 4544 passed |
| `make test-db` | 3159 passed + the 2 baseline libxml failures (scratch PostgreSQL 16.2) |
| `make ui-lint` | clean |
| `make ui-test` | 3109 passed |
| `make ui-build` | built |
| `make ui-e2e` | 25 passed (at T06) |

No test reaches DeepSeek: `live` is excluded, and the adapters run on injected clients.

Reports and reviews are in this folder: `P13-T0N.{report,review}.md` and `P13-wave.{items,report,review}.md`.

## The Owner's steps

The full steps are in `docs/runbook.md` → "Learned knowledge and RAG (DEC-210)". In order:

1. **Merge.** Merge `director/soar-intake`, then `director/rag-knowledge`, into `main` (`--ff-only` where possible).
2. **Migrate.** `set -a; . ./.env; set +a; make migrate PY=.venv/bin/python`. Then `select count(*) from schema_migrations` must return **20**. Do not go on before it does.
3. **Directory.** `mkdir -p kb_learned && ls -ldn kb_learned`. The owner must be `HOST_UID:HOST_GID`; if not, `sudo chown`.
4. **Second compose file.** `printf '\nCOMPOSE_FILE=docker-compose.yml:docker-compose.rag.yml\n' >> .env`. Then `grep -c '^COMPOSE_FILE=' .env` must print `1`, and `docker compose config --services` must list `rag-worker`.
5. **Containers.**
   - `docker compose up -d`;
   - `docker compose up -d --build ui`;
   - `curl … :8080/admin/overview` must return `200`;
   - `docker compose restart worker`.
6. **Top up the DeepSeek account** before any switch. Today it has no balance (see "Before switching on" 1).
7. **Drafts on.** Set `KNOWLEDGE_DRAFT_ENABLED=true`, then `docker compose up -d --force-recreate app worker rag-worker`.
8. **First entries.** Approve the first drafts on `/admin/knowledge`. Then `select count(*) from knowledge_entries where status='active'` must be ≥ 1, with one `.md` file per entry.
9. **Lookup on.** Set `RAG_ENABLED=true`, then recreate the same three containers.
10. **Checks.** Use the runbook's table:
    - `printenv` with named variables only;
    - the mount probes;
    - `rag_results` by status;
    - `llm_runs` by pipeline;
    - the knowledge counts;
    - the `rag-worker` logs;
    - the three health checks.

**Rollback.**
1. Set both switches false and recreate the three containers.
2. Drain the RAG queue. The count of `rag_lookup` and `knowledge_draft` jobs that are pending or running must reach 0.
   - A draft waiting for next month's budget does not drain. Wait for the month to turn, or run the runbook's `delete … scheduled_at > now()`.
3. `unset COMPOSE_FILE` (or use a fresh shell), delete the line from `.env`, then `docker compose up -d --remove-orphans`.

No data is removed.

**After `make db-restore`.** Stop `rag-worker`, restore, run `docker compose exec app python -m app.rag.publish --rebuild`, then start `rag-worker`. Before restoring a dump from before 020, set both switches false.

## What you need to know before switching on

1. **DeepSeek has no balance today.** This predates P13 and is not caused by it:
   - **①:** every alert fails permanently on 402. There is no `llm_runs` row, and `triage_status` stays `pending`. After the top-up, these alerts do not re-run on their own.
   - **②:** the run records `stopped_by='permanent'`. Run the analysis again after the top-up.
   - **P13:** with drafts on, a 402 stores a text-less draft (`llm_permanent`), and **Soạn lại** brings it back after the top-up. Top up before switching anything on.
2. **What analysts will notice with RAG on.**
   - Every ① starts 45 s later, even when `rag-worker` or the model is down.
   - A lookup that is not ready in time is not used. A lookup for an alert that ① has already handled is skipped, so it costs nothing.
   - ② uses the lookup from escalation, refreshed after 24 h, or sooner if the newest one failed.
3. **Spend.** The RAG's spend is not measured yet. Whether the $3 sub-cap lasts a month is unknown.
   - Once the cap is spent, lookups are stored as `budget`, and ①/② run without the section.
   - Drafts are rescheduled to the 1st of next month. They all come due at once then, and can spend much of the new month's cap.
4. **Measurement.**
   - B4 is not the live deployment.
   - With RAG on, online agreement figures are contaminated, the blind arm included, because ① is told about past decisions.
   - `prompt_version` does not change. Split runs by `rag_lookup_id` (filtering by `pipeline`) and by the dates the switches changed.
   - The 45 s delay also shifts ①'s correlation window.
5. **The real gate is the admin's approval.**
   - V4's detector mostly knows English phrases.
   - V3 knows the record's own users, but not names it was never shown.
   - The structure rule has residual bypasses: a combining mark before `[1]`, `【1】`, `⁽1⁾`, `LEVEL:`.
   - The ranking agent reads log text an attacker can shape, so it can be steered toward an entry, a level, a merge or a conflict. Audit the **Đã gộp** tab.
6. **Visible only in SQL.** No page shows a lookup's matches, its `match_notes`, or which runs used which entries.
7. **Entries cannot be edited, only retired.** The `knowledge_integrity` alarm lasts 24 h after its last event.
8. **One change does not depend on the switches.** ②'s repair line no longer fails permanently on a model key that contains `": "`. It sends a valid repair instead.
9. **On a 019 host** (code deployed, 020 not yet run, switches off):
   - ① and ② keep working;
   - `knowledge_queue` and `knowledge_integrity` alarm (fail-closed);
   - the overview's knowledge section shows an error;
   - `/admin/knowledge` answers 500.

## Limitations

These are in addition to (xlvii)–(xlix) in `docs/limitations.md`.

- **One `rag-worker` only.** Two workers would race on merge and draft, and a draft job can outlive `JOB_LOCK_TIMEOUT_S`, so it would be paid twice.
- **Integrity events** are duplicated on transient retries. The health check counts distinct entries.
- **The adapter** turns a 4xx into a permanent error with no queue retry. Inside `rag/`, 429 and budget are handled by rescheduling.
- **The admin page:**
  - it shows 200 rows per tab;
  - browser Back and the sidebar links do not guard a dirty form;
  - the Vietnamese copy awaits the Owner's review;
  - case drafts do not show ①'s suggestion for each head (that needs a payload change).
- **One role.** `app_rw` serves `app`, `worker` and `rag-worker`, and may delete drafts.

## Rulings the Director made

These are listed in full, with their reasons, in the reviews of this folder. The main ones:

1. **Reviewers.** Task reviews ran on Opus. The scoped re-reviews ran on Sonnet, and the wave's re-review on Opus.
2. **Parallel work, at the Owner's request** ("Đẩy nhanh tiến độ lên"). T05, T07 and T09 ran concurrently. T06 started on T05's tip and T08 on T07's tip, each while that task was still in review.
3. **T01** owns the audit labels and summaries for the 7 new events (36 after the wave). The payload keys are fixed.
4. **History.** The `unknown` category never counts as similarity. Descriptions are generalised, as the log is. `by_conclusion` always has all six keys.
5. **Integrity** is checked before a candidate enters the ranking prompt, and again at prompt time. The ranking prompt is bounded at 12k tokens.
6. **Invisible characters.** The Unicode `Default_Ignorable_Code_Point` set, plus Cf/Co/Cn, U+2800, U+1D159 and the Hangul fillers, is stripped from drafts and from admin edits and refused by V1. A soft hyphen or BOM pasted by the admin is removed, not refused.
7. **Conclusion families.** `closed_fp` and `concluded_fp` agree. A disagreeing `rat_giong` match makes a conflict, and a conflict wins over a merge.
8. **Publication.** Approved content is always the renderer's output. A closed field in an admin edit gets a strict 422.
9. **`rag_budget`** reports "n/a — RAG off" while both switches are off.
10. **`llm_runs.rag_lookup_id`** is named in the INSERT only when a lookup reached the prompt, so a 019 schema keeps working with the switches off.
11. **Shared ①/② contract.** One numbered block with level facts first. `isinstance(level, KbLearnedLevel)` raises. The contract lives in `llm/builder.py`.
12. **The wave's fixes:**
    - a structure-forging rule (`v4_structure`) plus a drop at prompt time;
    - a reference sentence that also forbids citing the section as a `source`;
    - drafts rescheduled on budget or 429 and redraftable on 402;
    - lookups claimed before drafts, and late lookups skipped;
    - bare user names refused by V3, except common accounts;
    - a savepoint around the lookup read;
    - `rag_results` append-only.
13. **DeepSeek out of balance** (26/10). No live tests anywhere. A 402 is never rescheduled.
14. **Ops on 26/10, at the Owner's request after the reboot.** `ui` had exited at boot because its host-port bind failed. It was recreated, with no rebuild. Its LAN bind in the primary checkout's `docker-compose.yml` moved from `79.79.79.14` to `79.79.78.119`, which is still an uncommitted Owner change.
