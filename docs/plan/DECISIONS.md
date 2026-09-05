# DECISIONS — ADR-lite log

One entry per decision. Only the Director (tactical) or the Owner (scope, contracts, model, evaluation validity) writes here. Reference the id from STATE.md, task reports and commit messages.

Format:

```
## DEC-<nnn> · <date> · <title>
Scope: tactical | contract | scope-cut | model | evaluation
Decided by: Director | Owner
Context: two sentences
Decision: one sentence
Consequences: what changes, what tests/contract files are updated
Supersedes: DEC-<nnn> | —
```

---

## DEC-000 · 2026-09-04 · Baseline
Scope: scope-cut
Decided by: Owner
Context: Architecture v3 (`docs/kien-truc-v3-14-ngay.html`) and `docs/chot-v3-14-ngay.md` incl. section F are the accepted baseline for the 14-day build.
Decision: Build exactly the D1–D20 + F1–F8 scope; cuts C1–C10 stand; cut order per context pack §10.
Consequences: All later decisions reference this baseline.
Supersedes: —

## DEC-001 · 2026-09-05 · Indexer environment corrected to the real IA1803 host
Scope: contract
Decided by: Owner
Context: The docs assumed the stock Wazuh layout (a `wazuh-indexer` service, CA at `/etc/wazuh-indexer/certs/root-ca.pem`). Verified on IA1803: `wazuh-indexer.service` is `inactive`/`disabled`; the alert store is a plain OpenSearch listening on `https://127.0.0.1:9400`; the manager's `alerts.json` is shipped by **Logstash** (`/etc/logstash/conf.d/wazuh-opensearch.conf`) into `wazuh-alerts-4.x-YYYY.MM.dd`; the root CA is `/etc/logstash/opensearch-certs/root-ca.pem` (world-readable, OpenSearch's bundled demo CA `CN = Example Com Inc. Root CA`, valid to 2034-02-17); `/var/ossec/logs/alerts/alerts.json` is not readable without root.
Decision: Correct the environment assumptions in place; no config key, index pattern, invariant or D-item changes.
Consequences: Context pack §6.3 gains a verified-environment note and `INDEXER_CA` now points at `conf/root-ca.pem`; §11 and `HUONG-DAN-VAN-HANH.md` §0.5 name the real CA path and OpenSearch instead of `wazuh-indexer`; `prompts/P2.md` calls it the OpenSearch root CA; `kien-truc-v3-14-ngay.html` §3 and §5 carry the same correction. `INDEXER_INDEX="wazuh-alerts-*"` is unchanged and still matches. Two follow-ups: the demo CA is a limitation to record in `docs/limitations.md` during P8, and the D3/F2 `alerts.json` file fallback is unavailable to the app user, so the puller is the only path to history. The `Final-Project` reuse QUESTION still open in INBOX becomes DEC-002.
Supersedes: —

## DEC-002 · 2026-09-05 · `Final-Project` reuse: port the two modules that measured clean, rewrite the two that did not
Scope: tactical
Decided by: Owner
Context: The Owner ran `Final-Project`'s `wazuh_ingest`, `category_resolver` and `prompt_guard` against the context-pack §8 document (Python 3.12, pydantic 2.13, no DB) and measured each one. Two carry reusable substance — `category_resolver`'s technique/group/decoder/port mapping tables, and `prompt_guard.detect_injection` (detection-only, stdlib, never mutates) — while the parser returns 12 of the 20 §8 fields with `alert_time` taken from the wrong source, and `wrap_untrusted` misses G6′ on six counts.
Decision: Option A — port the mapping tables into `ingest/category.py` and `detect_injection` into `security/detector.py`, and write `ingest/wazuh_parser.py` and `security/wrap.py` fresh against §7.1 and §8.
Consequences: P2's parser task is authored as new code against the §8 expected-parse table, not as a patch, and must produce all 20 fields with `alert_time` from `fields.timestamp[0]` (`2026-08-16T17:56:56.130Z`), not `_source.timestamp`. The ported category tables need the explicit priority table of phase-1 §Block 5 added on top, because `Final-Project` resolves in `rule.mitre.id` order and therefore yields `suspicious_login` where C5 requires `ssh_brute_force` (T1110 outranks T1078) — the canonical fixture is the regression test. `security/wrap.py` is written to §7.1 as specified: `<untrusted_data nonce=… source=…>` delimiters, `secrets.token_hex(8)`, NFKC then HTML-escape, nonce stripped from content, `[truncated]` inside the block, one typed builder — none of it inherited. `Final-Project` stays a read-only reference; nothing imports from it, and it is not vendored into the repo. Closes P0 exit gate item 5. Resolves INBOX 2026-09-05 · P0 · QUESTION.
Supersedes: —

## DEC-003 · 2026-09-05 · Three database connection keys enter §6.3; Compose variables stay out
Scope: contract
Decided by: Director
Context: Context pack §6.3 listed 50 configuration keys and none of them said how to reach PostgreSQL, while §6.1 already fixes that the application connects as `app_rw` and migrations run as the owner role. `.env.example`, `docker-compose.yml`, `scripts/migrate.sh` and `backend/tests/conftest.py` all need a DSN, and P0-T02 could not ship without inventing key names.
Decision: Add exactly three keys to §6.3 — `DATABASE_URL` (app runtime, role `app_rw`), `DATABASE_URL_OWNER` (migration execution, owner role), `TEST_DATABASE_URL` (tests only) — and keep `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `DB_PORT` out of the contract as Compose-only variables.
Consequences: Context pack §6.3 gains the three keys and a note stating that the four Compose variables live only in `docker-compose.yml` and `.env.example` and are never read by `backend/app/infra/config.py`. `.env.example` (P0-T02) therefore carries 53 contract keys plus 4 Compose-only ones, and its acceptance check expects exactly those four as "extra". `backend/tests/conftest.py` (P0-T03) enforces the `_test` suffix on `TEST_DATABASE_URL` as a safety rail. P1's `infra/config.py` reads the three keys and none of the four. Resolves INBOX 2026-09-05 · P0-T02 · DECISION_REQUEST (option A, narrowed).
Supersedes: —

## DEC-004 · 2026-09-05 · The database moves onto §6.2's criticality vocabulary; `assets` gains `owner` and `role`
Scope: contract
Decided by: Director
Context: `assets.criticality` was CHECKed against `crown_jewel|high|normal|low` while §6.2 `structured_basis.asset_criticality` is `high|medium|low|unknown`. Gate step 2 (§7.3) compares `structured_basis` against DB facts field by field, so two vocabularies mean a permanent mismatch on that field and every verdict degrading to `needs_review`. Separately, §7.1 names "inventory lookup values (owner, role text)" as text that must be wrapped, but no column held them.
Decision: Change the database to match §6.2 — never the reverse. In P1: alter `assets.criticality` to `CHECK (criticality IN ('high','medium','low','unknown'))` and add `owner text NULL`, `role text NULL`.
Carried by: `013_assets_enrichment.sql` — settled by the Owner on 2026-09-05, closing the open point that `P0-tasks.md` §Hand-off to P1 item 1 had left to the P1 Planner. 013 becomes the single enrichment-tables migration and carries **both** this ruling **and** §6.1's `source`, `loaded_at`, `active` on `assets`, `identities` and `iocs`; one table's DDL is therefore never split across two migrations. The four previously planned migrations each shift up by one: `014_intake_cursor_heartbeat.sql`, `015_labels_reviews_notes_eval_health.sql`, `016_alter_alerts_jobs_llm_runs_users.sql` (which loses its `assets/identities/iocs` line to 013), `017_append_only_and_roles.sql`. P1's exit gate reads "migrations 013–017 apply on a clean DB". Nothing is built against the old numbering yet, so the renumbering costs only the plan documents listed below.
Consequences:
  - **The DDL being replaced**, verbatim from `docs/Schema/001_bang_nen.sql:23-29` (identical at `schema.sql:42-48`):
    ```sql
    CREATE TABLE assets (
      hostname     text        PRIMARY KEY,
      criticality  text        NOT NULL,
      updated_at   timestamptz NOT NULL DEFAULT now(),
      CONSTRAINT ck_assets_criticality
        CHECK (criticality IN ('crown_jewel','high','normal','low'))
    );
    ```
    The P1 migration drops `ck_assets_criticality`, re-adds it over `('high','medium','low','unknown')`, and adds the two nullable text columns. `001_bang_nen.sql` is an applied migration and is **not** edited; `schema.sql` is regenerated by `build_schema.py` after the new migration lands.
  - `conf/inventory.yaml.example` and `enrichment/inventory.validate()` (P0-T05) use `high|medium|low|unknown`; no mapping table is written, because there is nothing left to map.
  - G8′ "asset.criticality = high" now reads literally as `high`, and "asset not in inventory" stays a separate hard block. A stored `unknown` and an absent row both resolve to `unknown` for the model.
  - `owner` and `role` are read only inside an `<untrusted_data nonce=…>` block (§7.1) and never appear outside one; the linter (§7.2) enforces it.
  - **Two follow-ups this creates, to be settled before the code that depends on them is written:** the risk-score formula `docs/phase-4-enrichment.md:170` weights four tiers (`crown_jewel: 30, high: 20, normal: 5, low: 0`) and must be re-weighted onto three plus `unknown` before `soar/risk.py` is written in P2; and `kb/playbooks/malware.md:36` and `kb/playbooks/ssh_brute_force.md:34` both branch on `asset_context.criticality = crown_jewel` and must be rewritten when the Owner and the advisor review the playbooks in P3.
  Resolves INBOX 2026-09-05 · P0-T05 / P1 · DECISION_REQUEST (neither option as filed: the ruling inverts option C's direction of change and keeps option A's columns).
Supersedes: —

## DEC-005 · 2026-09-05 · Two tactical calls from the Planner pinned: migration directory and pytest invocation
Scope: tactical
Decided by: Director
Context: `01-plan.md` and `prompts/P1.md` both left the migration directory open ("under `docs/Schema/migrations/` (or `backend/migrations/`)", "or wherever P0 decided"), and the P0 task cards had already committed to one answer in `scripts/migrate.sh` and the `Makefile`. Separately, `backend/pyproject.toml` is a tool-config file with no build backend, so pytest only resolves `app.*` when it is pointed at that file explicitly.
Decision: Migrations live flat in `docs/Schema/` next to `001`–`012`, and pytest is always invoked as `python3 -m pytest -c backend/pyproject.toml`.
Consequences: There is no `docs/Schema/migrations/` and no `backend/migrations/`; `MIGRATIONS_DIR ?= docs/Schema` in the `Makefile`, `MIG_DIR="${MIGRATIONS_DIR:-docs/Schema}"` in `scripts/migrate.sh`, and `build_schema.py`'s `^(\d{3})_.*\.sql$` glob picks up every new migration in that directory with no edit — which is also why `docs/Schema/schema.sql` stays regenerable and its 001–012 line numbers stay stable, since a new migration only ever appends. `PYTEST ?= $(PY) -m pytest -c backend/pyproject.toml` in the `Makefile`; every acceptance command in a task card, every CI step and every report uses that exact form, run from the repository root. `pythonpath = ["."]` resolves against rootdir `backend/`, so `backend/pyproject.toml` must not move to the repository root. `01-plan.md` line 46 and `prompts/P1.md` line 17 lose their "or" and name `docs/Schema/`.
Supersedes: —

## DEC-006 · 2026-09-05 · An acceptance command that cannot execute is the Director's defect, not the Coder's
Scope: tactical
Decided by: Director
Context: P0-T01 shipped a correct `.gitignore` and was still returned CHANGES because acceptance #5, `git check-ignore -q .env backups eval/results conf/inventory.yaml conf/root-ca.pem && echo IGNORED`, exits 128 with `fatal: --quiet is only valid with a single pathname` on any git — `-q` has never accepted more than one pathname. The Coder measured it before and after their change, reported it accurately, and could not fix it, because no `.gitignore` content can change a git CLI constraint.
Decision: Acceptance commands are part of the card and are the Director's to get right; a card whose acceptance line fails on its own syntax is corrected in the card, and the Coder neither works around it nor is held to it.
Consequences: Acceptance #5 is rewritten as a per-path loop in both `P0-T01.prompt.md` and `P0-tasks.md`. The rewrite keeps `backups/` and `eval/results/` **with** trailing slashes — measured: both `.gitignore` patterns are directory-only and neither directory exists on disk, so the bare names the Reviewer proposed in INBOX option A report *not ignored* and that loop still fails. Two further corrections ride along, both measured on a clean `git worktree` at `1bb33ba`: the P0-T01 design note that said to verify the negation with `git check-ignore -v` is wrong, because `-v` prints `!conf/*.example` and exits **0** for a path that is not ignored — only `-q`'s exit code is semantically correct, and `P0-T05.prompt.md:94` already had it right; and acceptance #8 moves from `git log --oneline -3` to `git log --oneline main..HEAD`, because the fixed `-3` window is unsatisfiable by construction for a small task — it only becomes all-yours once you happen to have made three commits, so P0-T01 failed it honestly at two commits, then chased its own tail to pass it (`4a94b1f` → `1bb33ba`, and the report is still one commit stale at HEAD). Measured at `1bb33ba`, the merge-base form returns all four branch commits, every one prefixed `P0-T01:`, and stays true no matter how many commits a task needs. Going forward every acceptance line in a card is executed once by its author before the card is dispatched. Resolves INBOX 2026-09-05 · P0-T01 · QUESTION (option A, corrected: the loop is right, its pathnames were not).
Supersedes: —

## DEC-007 · 2026-09-05 · The seven design questions the pre-dispatch audit left open
Scope: tactical
Decided by: Director
Context: The DEC-006 audit of P0-T03…T06 executed 37 acceptance commands and separated real defects (fixed under DEC-006) from seven questions that are design choices rather than errors. `README.md` §Conventions puts "minor design inside the frozen contracts" in the Director's sole rights, and none of the seven touches §6 — no schema, no `output_schemas.json`, no config **key**, no API route, no import rule, no job type, no event type.
Decision: Rule all seven now so the four cards dispatch without a Coder having to guess.
Consequences:
  1. **`conf/iocs.csv` comments are legal.** The loader skips blank lines and lines whose first non-space character is `#`, so the card's required note lives in the `.example` as a real comment. One condition in the reader, and it removes the footgun where an Owner comments their real `conf/iocs.csv` and silently gets a phantom IoC. A `#` inside a quoted field is not a comment; both cases are tested.
  2. **`INVENTORY_PATHS` is parsed with `json.loads`.** §6.3 and `.env.example` both store it as a JSON array, so it is read as one and must yield a list of `str`. Bad JSON, or JSON that is not a list of `str`, is a configuration error naming the key — never a silent fallback to the `conf/` defaults; only unset-or-empty falls back. This fixes how an existing §6.3 **value** is read; the key and its value are untouched, so §6.3 is not reopened.
  3. **`validate()` routes by content.** `.csv` → `validate_iocs`; a YAML file → `validate_assets` or `validate_identities` by its top-level key. Never by position (which mis-validates the moment `INVENTORY_PATHS` is reordered) and never by basename (which breaks on a rename). A file matching none returns one problem naming the path and the keys looked for.
  4. **`--save-samples` does not breach P0-T04's file scope.** "Do not touch any other file" governs files a Coder *authors*; `indexer_sample_rule<id>.json` is runtime output of the delivered tool, written only with that flag, only once credentials exist, and committed by the Owner. The Coder still authors exactly the four paths in "Files — create".
  5. **`--json` is defined**: the same three sections as the text report, as one JSON object on stdout and nothing else there. Exit codes unchanged (`0` ok, `2` config error), diagnostics stay on stderr, `INDEXER_PASSWORD` never appears in either form. It exists so P2's puller work and the Owner's retention answer can be scripted rather than retyped.
  6. **P0-T06 depends only on P0-T02.** The wave diagram in `P0-tasks.md` is scheduling preference, not dependency; T06's acceptance #1 already carries an escape hatch for P0-T03 being absent. Where the diagram and a card's `Depends on:` field disagree, the field wins. T06 may run in wave 2.
  7. **`<TASK_ID>.prompt.md` is the authoritative card.** DEC-006 makes the acceptance set the Director's deliverable, so it gets one home. `P0-tasks.md` is the Planner's index; where it restates an acceptance command that copy matches the prompt verbatim or is dropped. Coder executes the prompt, Reviewer verifies against the prompt, and a divergence is a Director defect, not a Coder's judgment call.
  Also corrected here: `STATE.md`'s status legend had dropped `approved`, contradicting `README.md` §Conventions (`approved` = Reviewer APPROVE, awaiting merge; `done` = merged by Director) and `prompts/reviewer.md`, which mandates it. The legend was the stale artefact, not the rows — and `approved` is what makes the approved-but-unmerged queue visible, which is exactly the state that let P0-T02 sit on a tree predating DEC-002…DEC-006. Legend restored; P0-T01 and P0-T02 stay `done` because they are merged.
Supersedes: —

## DEC-008 · 2026-09-05 · `CREATEDB` granted: the test database is real, and `make migrate` is broken
Scope: tactical
Decided by: Owner (grant) · Director (consequences)
Context: The Owner granted `CREATEDB` to `user1` and verified it end to end. Re-measured here before recording: `rolcreatedb = t`, and createdb → CREATE TABLE → INSERT → SELECT → dropdb all pass on PostgreSQL 16.15 with no docker. This closes the last blocker standing between P0-T03 and a real database.
Decision: Close INBOX `2026-09-05 · P0 / P1 · BLOCKER` as **option A**. P0-T03's acceptance becomes a real DB run; a skip is now a failure.
Consequences:
  - **The DSN in the grant report does not work as written.** `postgresql://user1@127.0.0.1:5432/soc_test` fails with `fe_sendauth: no password supplied` — TCP to localhost requires a password on this host. The socket form does not: `postgresql:///soc_test` connects as `user1` passwordless, as does `postgresql://user1@/soc_test?host=/var/run/postgresql`. **`TEST_DATABASE_URL=postgresql:///soc_test` is the recorded value.** `.env.example` keeps its compose default (still correct when docker is available) and gains one comment line naming the no-docker form; no key is added or renamed, so §6.3 stays closed.
  - **`make migrate` exits 3 on a clean database** — found within minutes of the grant, and invisible before it. `schema.sql` is migrations 001–012 concatenated, but only `001`–`007` carry an `INSERT INTO schema_migrations`; `008`–`012` never record themselves. The loop therefore re-applies `008` and PostgreSQL rejects it (`constraint "ck_audit_event_type" ... already exists`). This breaks P1's exit gate and P0-T03's `_test_database` fixture, which shells out to the script and asserts its return code. `scripts/migrate.sh` is not at fault; the missing `INSERT`s are a v1 artefact.
  - **The fix goes in `scripts/migrate.sh`, never in `docs/Schema/*.sql`.** Those files carry hundreds of line-number citations from the phase specs, and `schema.sql` is regenerated from them, so adding the missing `INSERT`s would shift every citation after migration 008. The script instead records the whole base set from `schema.sql`'s own `NGUỒN: migrations/<file>` banners. The exact block is in P0-T03's design note 7 and was run end to end before dispatch: clean DB → exit 0, 12 recorded, 14 tables; re-run → exit 0, `0 applied, 12 already present`. The pattern is `[0-9]{3}_[a-z0-9_]+` — a letters-only stem misses `005_index_lop_bao_ve_2`. P1's `013`–`017` are unaffected; they record themselves like `001`–`007`.
  - `scripts/migrate.sh` and `.env.example` join P0-T03's "Files — modify"; its acceptance gains item 9 (clean-DB migrate + idempotent re-run) and item 3 now requires DB tests to **pass**, with a second invocation proving the skip path still works where no database exists.
  - **Dispatch, at the standing cap of 3 concurrent coders** (`01-plan.md` cross-phase rules, `HUONG-DAN` §1 step B, `director.md` decision rights — ordering is the Director's, the cap is the Owner's and is not raised): **P0-T03, P0-T05, P0-T06** now; **P0-T04** takes the first slot that frees. The Owner's reasoning is recorded as the rationale: T03's acceptance is real for the first time today and it produces the canonical fixture every later phase builds on, while T04 accepts on recorded fixtures whenever it runs.
Supersedes: —

## DEC-009 · 2026-09-05 · DEC-007 item 7 propagated to the role prompts that agents actually read
Scope: tactical
Decided by: Director
Context: DEC-007 item 7 made `<TASK_ID>.prompt.md` the authoritative card and `<PHASE>-tasks.md` the Planner's index — but the ruling was recorded only in `DECISIONS.md` and the P0 card files. Every role prompt that tells an agent where to find the card still pointed at the index. The Owner caught it on `reviewer.md:7`; measuring it turned up three more sites, and the near-miss was live: P0-T03's prompt carries **9** acceptance items, the index restates **7**, and the two missing ones are exactly the pair added by DEC-008 — the real-database run and item 9, which is the only thing that exercises the `scripts/migrate.sh` fix. A Reviewer following `reviewer.md` today would have approved P0-T03 without ever running the fix that task exists to land.
Decision: A rule about which file is authoritative is worthless until the prompts that send agents to a file say so. Correct all four sites and treat "propagate to the role prompts" as part of any future ruling that changes where an agent looks.
Consequences:
  - `prompts/reviewer.md` §Read now names `<TASK_ID>.prompt.md` as the card, requires every acceptance command **in the prompt** to be run in order with real output pasted, and demotes the index to a cross-check whose shorter list must never define what was exercised. A divergence is a note to the Director, not something the Reviewer reconciles.
  - `prompts/coder-template.md` — the generator — no longer calls the index "your card". Since it is the template, this stops the error at source for P1–P8.
  - All six already-generated `P0-T0*.prompt.md` files carried the same line, including the three dispatched this afternoon (T03, T05, T06). Fixed in place; the coders now hold prompts that name themselves as the card.
  - `HUONG-DAN-VAN-HANH.md` §checklist told the Planner to prove no two tasks touch the same file by grepping `P<n>-tasks.md`. File scope lives in the prompt, so that check could pass while two prompts collide. It now greps `P<n>-T*.prompt.md`. (The T03/T05/T06 disjointness check run before dispatch was already done against the prompts, so the dispatch stands.)
  - Nothing about the acceptance sets themselves changed; this is a pointer fix. The underlying divergence between each prompt and its index entry remains, and stays a Director defect to reconcile per DEC-007 item 7.
Supersedes: — (extends DEC-007 item 7)

## DEC-010 · 2026-09-05 · One dedicated git worktree per task, from the moment it is dispatched
Scope: tactical
Decided by: Director
Context: The single shared checkout has now caused four incidents in one day, each costing real work. P0-T01's Coder measured `git status --porcelain` against a tree carrying the Director's uncommitted edits and honestly recorded acceptance 3 as FAIL when it passes cleanly. DEC-002…DEC-006 sat uncommitted in that same tree, invisible to any fresh clone, while P0-T02 was built and approved against a tree that predated them. HEAD then moved under the Director mid-edit, landing the DEC-009 planning commit on `task/P0-T05` and sweeping the T05 reviewer's verdict in with it — which would have failed T05 on the Reviewer's own checklist item 8 for a scope violation the Director introduced. The Reviewer independently reached the same recommendation while approving P0-T03, and the T03 and T04 sessions, which did use their own worktrees, hit none of it.
Decision: Every dispatched task gets its own `git worktree` at dispatch, and the Director's plan edits stay in the primary checkout on `main`. No agent shares a checkout with another.
Consequences:
  - `HUONG-DAN-VAN-HANH.md` §1 step B gains the worktree creation as part of dispatch, and step C removes it after merge. The Coder prompt and the Reviewer prompt both say to work only inside the worktree they were given.
  - A Reviewer already verifies in an isolated checkout; this makes the Coder's tree isolated too, so `git status --porcelain` is meaningful for the first time and acceptance items that depend on a clean tree stop producing false failures.
  - The Director never commits from a task worktree. Before any `git add`, confirm `git rev-parse --abbrev-ref HEAD` is `main` in the primary checkout — HEAD moving under a long edit is what caused the DEC-009 misplacement, and a one-line check catches it.
  - This is process only: no card, contract or acceptance command changes.
Supersedes: —

## DEC-011 · 2026-09-05 · `make test-db` hard-requires docker; fixed as P0-T07 before P1 dispatch
Scope: tactical
Decided by: Director
Context: The Owner measured `make test-db` on `main`: exit 1, "the docker daemon is unreachable", citing an INBOX blocker DEC-008 already closed. The tests underneath are fine — `TEST_DATABASE_URL=postgresql:///soc_test python3 -m pytest … -m db -q` gives 3 passed, and `scripts/migrate.sh` on a clean database gives 12 recorded, 14 tables, exit 0, idempotent. The target alone is at fault: it gates on `docker compose ps` before anything else and offers no path for an already-reachable `TEST_DATABASE_URL`. It survived P0-T02's review and P0-T03's because T03 acceptance #3 invokes pytest directly and never the target — a gap DEC-006's execute-every-acceptance-line rule does not close, because the defect is in a command no acceptance line runs. I had also called P1's exit gate "measurable"; with this target broken it is not.
Decision: Fix the target so a reachable `TEST_DATABASE_URL` is used directly and compose is the fallback, not the precondition. It ships as **P0-T07**, a P0 follow-up rather than a P1 task, and must land before P1 is dispatched.
Consequences:
  - **Why P0 and not P1.** `Makefile` is a P0-T02 deliverable and this is P0 scaffold debt; P1 is smoke test and schema, not repairing P0's scaffold. Two coder slots are free now (T03/T04/T05 merged, only T06 running), so it costs a slot today instead of delaying P1 tomorrow. It is **not** a P0 exit-gate item and does not hold T06 or P0 closure — but `coder-template.md` rule 3 and `reviewer.md` checklist item 1 both order every agent to run `make test-db`, and P1's gate reads "DB tests green", so P1 cannot dispatch over it.
  - **The Planner writes the card, not the Director** (`prompts/director.md`: the Director does not create task cards). This entry is the re-plan order and carries the verified fix so the Planner does not re-derive it.
  - **Verified fix** — prototyped and run before this was recorded, all three paths measured on this host:
    ```
    test-db:
    	@dsn="$${TEST_DATABASE_URL:-}"; \
    	if [ -z "$$dsn" ] && [ -f .env ]; then \
    	  dsn=$$(sed -n 's/^[[:space:]]*TEST_DATABASE_URL[[:space:]]*=[[:space:]]*//p' .env \
    	         | tail -1 | sed 's/[[:space:]][[:space:]]*#.*$$//'); \
    	fi; \
    	if [ -n "$$dsn" ] && psql "$$dsn" -tAc 'SELECT 1' >/dev/null 2>&1; then \
    	  echo "test-db: TEST_DATABASE_URL is reachable — running directly, no docker needed"; \
    	  TEST_DATABASE_URL="$$dsn" $(PYTEST) -m "db and not live" backend/tests; \
    	elif $(COMPOSE) ps >/dev/null 2>&1; then \
    	  <the existing compose-up + healthcheck-wait + pytest block, unchanged>; \
    	else \
    	  echo "test-db: no reachable TEST_DATABASE_URL and no docker daemon." >&2; \
    	  echo "  Set TEST_DATABASE_URL to a reachable database whose name ends in _test" >&2; \
    	  echo "  (on this host: postgresql:///soc_test — see DEC-008), or start docker." >&2; \
    	  exit 1; \
    	fi
    ```
    Path A, `TEST_DATABASE_URL=postgresql:///soc_test`: `3 passed, 77 deselected`, exit 0, no docker. Path B, unreachable DSN and no docker: the three-line message above, exit 1. Path C, variable unset: falls back to `.env`, and since the Owner's `.env` has no `TEST_DATABASE_URL` it lands on Path B's message rather than a stack trace. `make test`, `make lint` and `make -n migrate run-app run-worker backup` are unchanged. The comment strip requires whitespace before `#` so a `#` inside a DSN survives; the last assignment wins, matching the ten-line parser P0-T02 already uses.
  - **The stale message goes too.** The current text cites `docs/plan/INBOX.md (2026-09-05 · P0 / P1 · BLOCKER)`, closed by DEC-008. Pointing an agent at a closed blocker is its own defect.
  - **Acceptance must exercise the target itself**, not just the tests beneath it: `make test-db` with a reachable DSN → exit 0; with an unreachable DSN and no docker → exit 1 and a message naming `TEST_DATABASE_URL`; and `make test`/`make lint` unchanged. The lesson generalises — where a card ships a wrapper, at least one acceptance line runs the wrapper.
  - **Owner action:** the `.env` on this host predates DEC-003 and carries none of `DATABASE_URL`, `DATABASE_URL_OWNER`, `TEST_DATABASE_URL`. Add `TEST_DATABASE_URL=postgresql:///soc_test` so the target's `.env` fallback works without an exported variable.
Supersedes: —

## DEC-012 · 2026-09-05 · Real inventory landed; `user1` recorded as non-privileged, and what that gates
Scope: evaluation
Decided by: Owner
Context: The Owner wrote `conf/inventory.yaml`, `conf/identities.yaml` and `conf/iocs.csv` from real host data; `validate()` returns OK. Two things the `.example` files had implied are wrong and are now corrected: `agent_control -l` shows **two** agents, so `IA1803` (agent 000, the manager itself) was missing entirely; and `admin` does not exist on this host — the only human account is `user1`, with `root` as the real privileged identity. The Owner also made an explicit judgement call: `user1` is in group `sudo` but is recorded `is_privileged: false`, with `root` carrying the privileged case, and asked for it to be recorded either way. Under `README.md` §Conventions this touches evaluation validity, so it is the Owner's to decide and the Director's to record — which is how it happened.
Decision: Keep `user1` as `is_privileged: false`. The inventory stands as written.
Consequences:
  - **Adding `IA1803` swapped which G8′ clause fires; it did not unblock anything.** Before, agent 000 was blocked by "asset not in inventory"; now it is blocked by `asset.criticality = high`. Auto-close behaviour for agent 000 is unchanged and deliberately so — the file says as much. The real gain is different and worth naming: the model now receives `criticality`, `owner` and `role` facts for that host, so gate step 2 has something to compare `structured_basis` against instead of `unknown`.
  - **The whole auto-close path therefore runs through one agent and one flag.** Agent 000 is permanently blocked, so every auto-close, every D8 digest row and every digest-sourced label comes from agent 001 (`user1-IA1803`, `medium`) — and `user1` is named in almost every alert it produces. Had `is_privileged` been `true`, the privileged-identity clause would have blocked that path too, leaving auto-close dead estate-wide, the digest empty for the pilot, and B1 without the class it exists to separate. The Owner's reasoning holds; it is load-bearing rather than incidental, which is exactly why it is recorded here.
  - **What still blocks auto-close with `user1` non-privileged**, and this is what makes the call defensible: `severity = critical`, any `malicious`/`suspicious` IoC hit, `asset.criticality = high`, and any host absent from the inventory. The residual set is non-critical alerts, on the workstation, with no bad IoC.
  - **Auto-close is not terminal.** Per D8 (`docs/chot-v3-14-ngay.md:74`), ① runs on **100 %** of auto-closed alerts and the 08:00 digest puts every one in front of a human for a one-click verdict into `autoclose_reviews`, with "wrong" reopening the alert. So this flag does not create unreviewed closure; it creates closure reviewed the next morning. That distinction belongs in the write-up.
  - **Disclosure is mandatory, and is the only thing that makes this safe.** `docs/limitations.md` (P8) must carry it as a named limitation, and the evaluation chapter must state that auto-close volume and the B1 comparison depend on reading a `sudo`-capable account as non-privileged. A disclosed engineering trade-off is defensible; an undisclosed one would put the auto-close numbers in question the moment an examiner reads `conf/identities.yaml`.
  - **P6 sizing changes.** Digest-sourced labelling can only be counted on from agent 001. The Planner must not size P6's 400 clusters assuming both agents contribute, and should say in the P6 card where the shortfall is made up from (lab scenarios, G2).
  - **Reversal is one line plus `POST /api/admin/reload-inventory`**, no migration. Reverse if P6 finds digest labels dominated by alerts where `user1`'s sudo rights were actually material to the verdict — that is the signal the strict reading was right.
  - `admin` never existed; nothing in the repo depended on it. Note for readers: the `admin` in §6.4's role list (`tier1`, `tier2`, `admin`) is an application role, unrelated to any OS account.
Supersedes: —
