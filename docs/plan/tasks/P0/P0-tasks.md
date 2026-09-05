# P0 · Preparation — task cards

Phase objective: make the repo buildable and every later phase unblocked — environment, coordination files, canonical fixtures.
Day budget: 1 day (≈ 8 h), planned for 05/09/2026 (D0 and D1 are merged into one day, see `HUONG-DAN-VAN-HANH.md` §0).

## Budget note

Sum of `must` estimates = **10 h vs 8 h budget (+25 %)** — under the 30 % re-plan threshold, so nothing is moved to P1 up front. Wall-clock with 3 coders is ≈ 7 h because T03/T04/T05 run in parallel. If the day runs long, the lever is **P0-T06 (should, 1 h) → P1**; it is not part of any exit-gate item. Do not cut T01–T05: each one owns a gate item.

## Critical path

```
P0-T02 (3 h, build scaffold)  ──┬──▶ P0-T03 (3 h, test harness) ──▶ P0-T06 (1 h, skeletons)
                                ├──▶ P0-T04 (2 h, indexer probe)
P0-T01 (0.5 h, git hygiene) ────┴──▶ P0-T05 (1.5 h, conf examples)
```

Wave 1 (2 coders): T01, T02. Wave 2 (3 coders): T03, T04, T05. Wave 3: T06.
T02 is the root because the coder template requires `make lint` / `make test` before every report; T01 is exempted from that rule in its own prompt (it ships no code and must land before T03 so that `docs/Schema/` is tracked in a clean checkout).

## Exit-gate coverage

| Gate item | Covered by | Status after P0 |
|---|---|---|
| `make test` runs (0 tests is fine) | T02 (target) + T03 (real tests) | closable today |
| `eval/indexer_probe.py` returns document counts per day | T04 writes it; **live run is an Owner action** | **stays open** — `soc_ro` does not exist (INBOX 2026-09-05 BLOCKER) |
| `.env.example` complete (context pack §6.3) | T02 | closable today |
| `conf/*.example` present | T05 | closable today |
| `Final-Project` reuse decision recorded | Owner already answered (INBOX 2026-09-05 QUESTION); **Director records DEC-002** | Director action, not a task |
| `STATE.md` initialised | Planner (this run) | done |

## Planning decisions (tactical — Director may promote to a DEC)

1. **Migrations stay in `docs/Schema/`.** `build_schema.py` globs `NNN_*.sql` in its own directory and `schema.sql` is generated from them; moving to `backend/migrations/` would mean rewriting a working tool for no gain. P1's `013`–`016` are created as `docs/Schema/013_*.sql` … and must each end with `INSERT INTO schema_migrations (version) VALUES ('013_…');` like 001–012 do. This answers the open choice in `prompts/P1.md` line 17. `MIGRATIONS_DIR ?= docs/Schema` in the Makefile is the single knob.
2. **Test database is reached by DSN, never created by the test process on the host cluster.** `TEST_DATABASE_URL` defaults to the compose `db` service on host port `55432`. Neither docker nor `CREATE DATABASE` is available to an agent on this host (INBOX 2026-09-05 BLOCKER · DB access), so every DB test is marked `@pytest.mark.db`, `make test` excludes them, and the fixture **skips loudly** when the DSN is unreachable. `make test` is therefore green today; `make test-db` becomes real as soon as the Owner clears the blocker.
3. **`eval/` is a package** (`eval/__init__.py` with a docstring) per context pack §4, but its contents are run as scripts (`python3 eval/indexer_probe.py`), never imported by `backend/app/`.
4. **`pyproject.toml` lives in `backend/`** as the deliverable says; every tool is invoked from the repo root with an explicit config flag (`pytest -c backend/pyproject.toml`, `ruff check --config backend/pyproject.toml`). Verified working with `pythonpath = ["."]` (rootdir becomes `backend/`).

## INBOX items raised by this plan

- `2026-09-05 · P0-T02 · DECISION_REQUEST` — **resolved, DEC-003.** `DATABASE_URL`, `DATABASE_URL_OWNER`, `TEST_DATABASE_URL` enter §6.3 (53 keys now); `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `DB_PORT` stay out of the contract and live only in `docker-compose.yml` and `.env.example`. T02 transcribes §6.3; it does not extend it.
- `2026-09-05 · P0-T05 / P1 · DECISION_REQUEST` — **resolved, DEC-004.** §6.2 is untouched; the database moves onto its vocabulary. `assets.criticality` is re-CHECKed over `high|medium|low|unknown` and `owner text NULL`, `role text NULL` are added, in P1. T05 writes the format for the post-DEC-004 shape; `crown_jewel` and `normal` cease to exist.
- `2026-09-05 · P0 / P1 · BLOCKER` — **open.** No PostgreSQL an agent can use: docker socket unreachable and the account has no `CREATEDB`. Does not block task authoring; T03's DB fixture skips loudly until it clears.

## Hand-off to P1

DEC-004 lands in P1's migration set and pulls three things with it. The first is now settled; the other two are still open and must be placed before the code that reads them is written:

1. ~~**Which migration carries the `assets` change.**~~ **Settled 2026-09-05 by the Owner (DEC-004, "Carried by").** `013_assets_enrichment.sql` carries the whole of it — DEC-004's CHECK swap and `owner`/`role`, plus §6.1's `source`, `loaded_at`, `active` on all three enrichment tables — so no table's DDL is split across migrations. The four previously planned migrations shift up by one to `014`–`017` and `016_alter_alerts_jobs_llm_runs_users.sql` loses its `assets/identities/iocs` line. `01-plan.md` and `prompts/P1.md` carry the new numbering; P1's exit gate now reads "migrations 013–017". `001_bang_nen.sql` is an applied migration and is not edited; `schema.sql` is regenerated with `build_schema.py`.
2. **The risk-score formula loses a tier.** `docs/phase-4-enrichment.md:170` weights four values — `{"crown_jewel": 30, "high": 20, "normal": 5, "low": 0}` — and two of them no longer exist. The formula must be re-weighted onto `high|medium|low|unknown` before `soar/risk.py` is written in P2, and the worked examples at `docs/phase-4-enrichment.md:145` and `:183` re-derived. This is a v1-spec change, so it needs its own decision.
3. **Two playbooks branch on a value that is gone.** `kb/playbooks/malware.md:36` and `kb/playbooks/ssh_brute_force.md:34` both key on `asset_context.criticality = crown_jewel`. They are rewritten when the Owner and the advisor review the playbooks and fill `reviewed_by/at` in P3.

---

### P0-T01 · Repo hygiene and `.gitignore`
- Priority: must
- Goal: every design document, playbook and schema file that the later phases read is tracked in git, and nothing secret or regenerable is.
- Scope in: staging the untracked `docs/`, `kb/`, `llm/`, `docs/Schema/` trees; committing the two deletions already in the working tree; completing `.gitignore`; fixing the two `README.md` rows that point at deleted files.
  Scope out: any Python file; any file under `backend/`; the content of the documents themselves; `conf/` (T05 owns it); `.env.example` (T02 owns it).
- Files: create: — / modify: `.gitignore`, `README.md`; git-add (content unchanged): `docs/chot-v3-14-ngay.md`, `docs/kien-truc-v3-14-ngay.html`, `docs/kien-truc-tong-quat-va-chi-tiet.md`, `docs/luong-du-lieu-theo-package.md`, `docs/phan-bien-kien-truc-2026-09-04.md`, `docs/phan-bien-kien-truc-v2-2026-09-04.md`, `docs/phase-1-tiep-nhan-chuan-hoa.md` … `docs/phase-7-tier2.md`, `docs/Schema/**` (except `__pycache__`), `kb/playbooks/*.md`, `llm/prompt_builder.py`, `llm/templates/*`; git-rm: `docs/2026-08-19-soc-triage-rebuild-design.md`, `docs/audit-report.html`
- Contracts touched: none
- Depends on: —
- Acceptance (all must pass):
  - `git ls-files docs/Schema | grep -c '\.sql$'` → `14` (12 migrations + `schema.sql` + `load.sql`)
  - `git ls-files kb llm docs | wc -l` → ≥ `45`
  - `git status --porcelain` → empty
  - `git ls-files | grep -E '^\.env$|^conf/root-ca\.pem$|__pycache__'` → no output (exit 1)
  - `for p in .env backups/ eval/results/ conf/inventory.yaml conf/root-ca.pem; do git check-ignore -q "$p" || echo "NOT IGNORED: $p"; done` → no output. Two things are load-bearing here: `-q` accepts exactly **one** pathname per call (more than one is `fatal: --quiet is only valid with a single pathname`, exit 128), which is why this is a loop; and the trailing slashes on `backups/` and `eval/results/` are required, because both patterns are directory-only and neither directory exists on disk, so the bare names correctly report *not* ignored (DEC-006)
  - `git check-ignore -q conf/inventory.yaml.example; echo $?` → `1` (the `.example` files are **not** ignored)
  - `grep -c '2026-08-19-soc-triage-rebuild-design\|audit-report' README.md` → `0`
- Estimate: 0.5 h
- Risk / notes: The root-level `Bản đồ kiến trúc AI Support SOC.html` + `_files/` is a browser page-save superseded by `docs/kien-truc-v3-14-ngay.html` (different title, no `_files` sidecar) — add it to `.gitignore`, do **not** commit 732 KB of saved JS, and say so in the report so the Owner can overrule. The repo has a **public** GitHub remote: check the diff for secrets before committing. This task is exempt from coder rule 3 (`make lint` / `make test`) — those targets do not exist until T02 merges.

### P0-T02 · Build scaffold: requirements, pyproject, Makefile, compose, `.env.example`
- Priority: must
- Goal: `make test`, `make lint` and `docker compose config` work in a clean checkout, and `.env.example` documents every configuration key the system has.
- Scope in: pinned dependencies; ruff/black/pytest configuration; the seven Makefile targets; a three-service compose file; `.env.example`; the two shell scripts the Makefile calls.
  Scope out: any file under `backend/app/` or `backend/tests/`; `.gitignore` (T01); writing tests (T03).
- Files: create: `backend/requirements.txt`, `backend/pyproject.toml`, `backend/Dockerfile`, `Makefile`, `docker-compose.yml`, `.env.example`, `scripts/migrate.sh`, `scripts/backup.sh` / modify: —
- Contracts touched: config keys §6.3 → **DEC-003** (three database keys added to the contract; the four Compose variables stay out). Settled — transcribe, do not extend.
- Depends on: —
- Acceptance (all must pass):
  - `make test` → exit 0 (prints `no tests collected` while `backend/tests/` is still empty)
  - `make lint` → exit 0
  - `docker compose config --quiet` → exit 0 (no daemon needed; verified on this host)
  - `docker compose config | grep -E '^  (app|worker|db):' | wc -l` → `3`
  - `docker compose config | grep -c healthcheck` → ≥ `1`
  - `make -n migrate run-app run-worker backup` → exit 0, prints a command for each target
  - every one of the **53** keys of context pack §6.3 appears in `.env.example`, and the only extras are the four Compose-only variables — run the comparison in the prompt's design notes and paste both lists: `missing: []`, `extra: ['DB_PORT', 'POSTGRES_DB', 'POSTGRES_PASSWORD', 'POSTGRES_USER']`
  - `bash -n scripts/migrate.sh scripts/backup.sh` → exit 0
- Estimate: 3 h
- Risk / notes: 0 collected tests makes pytest exit 5 — the `test` recipe must translate 5 into 0 (see design notes in the prompt). Nothing in compose is runnable yet (`app.web.main` and `app.infra.worker` arrive in P2/P4); the acceptance is `config`, not `up`.

### P0-T03 · Test harness: DB fixture, fake LLM, import-rule scan, canonical fixture
- Priority: must
- Goal: the three test facilities every later phase depends on exist and are proven on the canonical alert.
- Scope in: `conftest.py` with the PostgreSQL fixture; the fake LLM adapter with canned §6.2 payloads; the G1 import-rule AST scan; `alert_40112.json` + its expected parse.
  Scope out: writing a parser (P2 consumes `alert_40112.expected.json`); DB tests of the schema itself (P1); anything under `backend/app/`.
- Files: create: `backend/tests/conftest.py`, `backend/tests/fakes/__init__.py`, `backend/tests/fakes/llm.py`, `backend/tests/test_import_rules.py`, `backend/tests/test_fakes_llm.py`, `backend/tests/test_conftest_helpers.py`, `backend/tests/fixtures/alert_40112.json`, `backend/tests/fixtures/alert_40112.expected.json` / modify: —
- Contracts touched: none (the import allowlist is *implemented* here for the first time, exactly as §2 G1 and §4 state it; any later change to it needs a DEC)
- Depends on: P0-T01, P0-T02
- Acceptance (all must pass):
  - `python3 -m pytest -c backend/pyproject.toml backend/tests -m "not db and not live" -q` → all pass, ≥ 8 tests
  - `python3 -m pytest -c backend/pyproject.toml backend/tests/test_import_rules.py -q` → passes
  - `python3 -m pytest -c backend/pyproject.toml backend/tests -m db -q` → skipped with the reason `TEST_DATABASE_URL unreachable`, exit 0 or 5 (no failures)
  - `python3 -c "import json;d=json.load(open('backend/tests/fixtures/alert_40112.json'));print(d['_source']['id'],d['fields']['timestamp'][0])"` → `1786903016.121311 2026-08-16T17:56:56.130Z`
  - `python3 -c "import json;e=json.load(open('backend/tests/fixtures/alert_40112.expected.json'));assert e['category']=='ssh_brute_force' and e['severity']=='critical' and e['dstip']=='' and e['srcip_is_private'] is True;print('OK')"` → `OK`
  - `make test` → exit 0
  - `make lint` → exit 0
- Estimate: 3 h
- Risk / notes: The DB fixture cannot be proven end-to-end today (INBOX BLOCKER · DB access); it must therefore be written so the skip path is the *only* untested path — the SQL-application helper is unit-tested against a temporary file list without a server. Do not weaken the skip into a silent pass: it must call `pytest.skip` with the DSN in the message.

### P0-T04 · `eval/indexer_probe.py` — offline-verifiable indexer probe
- Priority: must
- Goal: one script that, when the Owner has credentials, prints document counts per index day since `PULL_START`, the earliest index date, and one `search_after` page — with TLS verified against `INDEXER_CA` and no way to disable it.
- Scope in: the script, its offline test with recorded fixtures, the `--save-samples` path that writes fixture documents.
  Scope out: **running it against the live indexer** (Owner action — `soc_ro` does not exist yet); the puller itself (P2); `eval/__init__.py` (T06 owns it).
- Files: create: `eval/indexer_probe.py`, `backend/tests/test_indexer_probe.py`, `backend/tests/fixtures/indexer_cat_indices.json`, `backend/tests/fixtures/indexer_search_page.json` / modify: —
- Contracts touched: none (uses `INDEXER_*` and `PULL_START` from §6.3 unchanged)
- Depends on: P0-T02
- Acceptance (all must pass):
  - `python3 eval/indexer_probe.py --help` → exit 0; usage mentions `--save-samples` and `--env-file`
  - `grep -nE 'verify=False|verify=0|--insecure|--no-verify|ssl._create_unverified' eval/indexer_probe.py` → no output (exit 1)
  - `INDEXER_USER= INDEXER_PASSWORD= python3 eval/indexer_probe.py --env-file /dev/null; echo $?` → `2`, and stderr names `docs/plan/INBOX.md`
  - `INDEXER_CA=/nonexistent python3 eval/indexer_probe.py --env-file /dev/null; echo $?` → `2`, and stderr names `INDEXER_CA`
  - `python3 -m pytest -c backend/pyproject.toml backend/tests/test_indexer_probe.py -q` → passes; the test drives the script through `httpx.MockTransport` and asserts the per-day count table and the earliest index date parsed from `backend/tests/fixtures/indexer_cat_indices.json`
  - `make test` → exit 0 · `make lint` → exit 0
- Estimate: 2 h
- Risk / notes: The sort field is assumed to be `timestamp` (the sample document's `sort` value `1786903016130` is epoch-millis of `fields.timestamp[0]`); it can only be confirmed on the live index. Print the sort field in the header line so the Owner sees what was used, and record in the report that P2's puller inherits this assumption. Never print `INDEXER_PASSWORD`, and never write it into a saved fixture.

### P0-T05 · Inventory examples, format document, `inventory.validate()`
- Priority: must
- Goal: the Owner can write `conf/inventory.yaml`, `conf/identities.yaml` and `conf/iocs.csv` today from an example and a one-page format document, and a validator tells them whether the files are correct.
- Scope in: the three `.example` files; `docs/inventory-format.md`; `enrichment/inventory.py` containing `validate()` and nothing else.
  Scope out: loading into the database, the `active` / `loaded_at` upsert, `POST /api/admin/reload-inventory` (all P2); `enrichment/lookups.py` (T06); the real `conf/*.yaml` content (Owner).
- Files: create: `conf/inventory.yaml.example`, `conf/identities.yaml.example`, `conf/iocs.csv.example`, `docs/inventory-format.md`, `backend/app/enrichment/inventory.py`, `backend/tests/test_inventory_validate.py` / modify: —
- Contracts touched: schema §6.1 `assets` → **DEC-004** (criticality CHECK becomes `high|medium|low|unknown`; `owner text NULL`, `role text NULL` added). Settled — write the format for the post-DEC-004 shape; the migration itself is P1's.
- Depends on: P0-T02
- Acceptance (all must pass):
  - `python3 -m pytest -c backend/pyproject.toml backend/tests/test_inventory_validate.py -q` → passes, ≥ 10 tests
  - `python3 -c "import sys;sys.path.insert(0,'backend');from app.enrichment.inventory import validate;print(validate(['conf/inventory.yaml.example','conf/identities.yaml.example','conf/iocs.csv.example']))"` → `[]`
  - `grep -c 'user1-IA1803' conf/inventory.yaml.example` → ≥ `1` · `grep -c 'user1' conf/identities.yaml.example` → ≥ `1`
  - `python3 -c "import yaml;d=yaml.safe_load(open('conf/inventory.yaml.example'));assert all(a['criticality'] in ('high','medium','low','unknown') for a in d['assets']);print('OK')"` → `OK`
  - `grep -rn 'crown_jewel' conf/inventory.yaml.example docs/inventory-format.md` → no output (exit 1)
  - `git check-ignore -q conf/inventory.yaml.example; echo $?` → `1`
  - `make test` → exit 0 · `make lint` → exit 0
- Estimate: 1.5 h
- Risk / notes: `validate()` must not import `psycopg` or read a database — `enrichment/` may import `infra/` only, and the Owner runs this before any database exists. Every message it returns must name the file and the offending key.

### P0-T06 · Package skeletons per context pack §4
- Priority: should
- Goal: every module named in the §4 package map exists with a one-line docstring, so later phases add code instead of arguing about layout, and the import scan has something to scan.
- Scope in: empty modules with docstrings; the `web/` and `eval/` package files; correcting the stale import rule in `ingest/__init__.py`.
  Scope out: any implementation; `enrichment/inventory.py` (T05); `eval/indexer_probe.py` (T04); `kb/decision_tables/` (P3); moving the top-level `llm/` (P3).
- Files: create: `backend/app/web/__init__.py`, `eval/__init__.py`, and one docstring-only module for each entry of §4 not already present — `ingest/{wazuh_parser,category,dedup,autoclose}.py`, `soar/{pipeline,risk}.py`, `tier1/{queue,decide,triage,digest}.py`, `tier2/{dossier,investigate,conclude}.py`, `domain/{alert,transitions,correlation}.py`, `infra/{db,jobs,worker,auth,config,errors,puller,intake,health,notify}.py`, `audit/{events,llm_runs}.py`, `security/{wrap,linter,gate,detector,output_guard}.py`, `llm/{adapter,builder,triage,investigate}.py`, `kb/lookup.py`, `enrichment/lookups.py`, `eval/{build_gold,label_export,run_configs,report,regression_gate,smoke_test}.py` / modify: `backend/app/ingest/__init__.py`
- Contracts touched: none
- Depends on: P0-T02
- Acceptance (all must pass):
  - `python3 -m pytest -c backend/pyproject.toml backend/tests/test_import_rules.py -q` → passes (if T03 has merged; otherwise state so in the report)
  - `python3 -c "import sys;sys.path.insert(0,'backend');import importlib;[importlib.import_module(m) for m in ['app.web','app.infra.db','app.security.gate','app.llm.builder','app.tier2.dossier']];print('OK')"` → `OK`
  - `python3 - <<'PY'` … asserts every module listed in the card exists and its file is ≤ 3 lines → prints `OK`
  - `make test` → exit 0 · `make lint` → exit 0
- Estimate: 1 h
- Risk / notes: A skeleton module must contain **only** a docstring — no `pass`, no imports, no `TODO` code. `backend/app/ingest/__init__.py` currently claims it may import `security`, `llm` and `kb`; §4 allows only `domain`, `infra`, `audit`, `enrichment`. §4 wins — fix the docstring, change nothing else.
