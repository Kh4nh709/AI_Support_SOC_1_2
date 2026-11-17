# Threat Intel module (DEC-224) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A "Threat Intel" page in the AI SOC web that shows the abuse.ch IOCs the host's daily script collects, through CSV → importer → database → API → page.

**Architecture:** A numbered migration adds `ti_ioc` and `ti_import_log`; `backend/app/ti/` holds the importer (pure parsing + one upsert transaction) and the read queries; a router serves `/api/ti/*` behind the existing login; a React page under `frontend/src/features/ti/` renders it with the web's own components and hand-written SVG charts.

**Tech Stack:** Python 3.12, FastAPI, psycopg, PostgreSQL; React 19 + TypeScript, Vite, Tailwind 4, TanStack Query; pytest, vitest.

**Spec:** `docs/superpowers/specs/2026-11-17-threat-intel-design.md` (binding; read it before your task).

## Global Constraints

- Branch `feature/threat-intel`; trial only; never `main`, never the trial checkout, its containers or its database; never root's crontab or `/opt/abusech`.
- The Owner checks after every task: one task is dispatched at a time and the Director stops after its review.
- The web never reads the CSV (A1). `ti_ioc` is separate from the existing `iocs` table; nothing in triage reads it.
- Every SQL statement is parameterised; a sort column or direction comes from a closed list (A5).
- An IOC value is text everywhere: never markup, never a link, never fetched (A2, A3). No `innerHTML`, no `dangerouslySetInnerHTML`.
- No secret in code, logs, argv or a committed file (A6): the DSN comes from `DATABASE_URL` in an `--env-file`, and is never printed. The abuse.ch key is not this module's business.
- Committed sample data is made up: documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), `example.com` / `example.net` names, invented hashes. No real IOC, no lab address.
- Section 6 of the Owner's brief (log matching, AI summary, AI explanations) is not built; `hit_count` / `last_hit` only exist.
- Migrations already applied (001–025) are never edited. `app_rw` gets `SELECT, INSERT, UPDATE` and no `DELETE`.
- Commits `DEC-224 T<N>: …`, ending with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Db tests on a private throwaway PostgreSQL cluster (the coders' private binaries, outside the repository; 127.0.0.1, trust auth, data dir deleted afterwards), never `soc_test`, live or trial. `make` targets need `PY=../AI_Support_SOC_1_2/.venv/bin/python`.

## Review Focus

- A CSV row whose value holds a comma inside quotes, a newline inside quotes, a NUL or a control character, or 5 000 characters: skipped and counted, the run goes on.
- The same file imported twice, and two files of two days sharing an IOC: one row, `first_seen` the earlier, `last_seen` the later run.
- A value such as `=cmd|' /C calc'!A0` in a field: stored as text, shown as text, exported with the guard.
- A value such as `<img src=x onerror=…>` or `javascript:…` in `value` or `reference`: text on the page, never a link.
- `q=%` or `q=_` or `q='; drop table` in the list: a literal search, no error, no injection.

---

### Task 1: The migration (`ti_ioc`, `ti_import_log`)

**Files:**
- Create: `docs/Schema/026_threat_intel.sql`, `backend/tests/test_migration_026.py`
- Modify: `docs/Schema/schema.sql` (rebuilt by `docs/Schema/build_schema.py`, never by hand), and whatever pins the migration list or count (follow what `025_soar_reviews.sql` had to touch: `git show --stat` of the commit that added it)

**Interfaces:**
- Produces: table `ti_ioc(id bigint identity pk, source text, type text, value text, malware text, threat text, confidence smallint, tags text[] NOT NULL DEFAULT '{}', reference text, first_seen timestamptz, last_seen timestamptz NOT NULL, imported_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, hit_count integer NOT NULL DEFAULT 0, last_hit timestamptz)`; constraints `uq_ti_ioc_key UNIQUE (source, type, value)`, `ck_ti_ioc_source` (`threatfox`, `urlhaus`, `malwarebazaar`), `ck_ti_ioc_confidence` (NULL or 0–100), `ck_ti_ioc_hit_count` (>= 0); `source`, `type`, `value` NOT NULL; indexes `ix_ti_ioc_value (value)`, `ix_ti_ioc_first_seen (first_seen DESC)`, `ix_ti_ioc_source (source)`, `ix_ti_ioc_malware (malware)`.
- Produces: table `ti_import_log(id bigint identity pk, file text NOT NULL, started_at timestamptz NOT NULL, finished_at timestamptz NOT NULL, rows_total integer NOT NULL, rows_new integer NOT NULL, rows_updated integer NOT NULL, rows_error integer NOT NULL, status text NOT NULL, message text)`; `ck_ti_import_log_status` (`ok`, `partial`, `failed`); the four counts `>= 0`; index `ix_ti_import_log_finished_at (finished_at DESC)`.
- Grants on both: `GRANT SELECT, INSERT, UPDATE … TO app_rw; REVOKE DELETE, TRUNCATE … FROM app_rw`.

- [ ] **Step 1: Write the failing migration test**, in the shape of `backend/tests/test_migration_025.py`: both tables with exactly these columns, types, defaults and NOT NULLs; each constraint refuses what it should (a fourth source, confidence 101 and -1, a duplicate `(source, type, value)`, a negative count, an unknown status); the same value under another source or type is accepted; the indexes exist; `app_rw` can select, insert and update and cannot delete or truncate either table; the migration records itself in `schema_migrations` and a second `make migrate` applies nothing; 001–025 are byte for byte unchanged.
- [ ] **Step 2: Run it, see it fail.**
- [ ] **Step 3: Write `026_threat_intel.sql`** (one transaction, the header comment in the style of 025: what, why, DEC-224, "KHÔNG sửa 001-025"), rebuild `schema.sql`, update the pins.
- [ ] **Step 4: `make test`, the migration and schema db tests on a private cluster, `make lint`; commit.**

### Task 2: The importer

**Files:**
- Create: `backend/app/ti/__init__.py`, `backend/app/ti/importer.py`, `scripts/ti_import.py`, `backend/tests/test_ti_importer.py`, `backend/tests/fixtures/ti/ioc_sample.csv` (made-up values, all three sources, every type the feed uses)
- Modify: `docs/runbook.md` (the import command and the cron line)

**Interfaces:**
- Consumes: the tables of Task 1.
- Produces (`app.ti.importer`): `COLUMNS = ("source","first_seen","type","value","threat","malware","confidence","tags","reference")`; `@dataclass(frozen=True) class Ioc` (the nine fields normalised: `first_seen: datetime | None`, `confidence: int | None`, `tags: tuple[str, ...]`); `parse_row(row: Mapping[str, str]) -> Ioc` raising `RowError(reason)` with `reason` from the closed set `REASONS`; `read_file(path) -> Parsed(iocs: list[Ioc], errors: list[tuple[int, str]], total: int)` raising `HeaderError(missing: tuple[str, ...])`; `import_file(conn, path, *, now: datetime) -> Result(file, total, new, updated, errors, status, message)`; `EXPIRES_AFTER = timedelta(days=30)`; `normalise_value(type: str, value: str) -> str` (reused by Task 3's lookup).
- Produces (`scripts/ti_import.py`): `main(argv) -> int`: `[FILE] --env-file PATH [--dir DIR]`; exit 0 `ok` or `partial`, 1 `failed` (header, unreadable file, database), 2 usage.

- [ ] **Step 1: Write the failing tests** (spec §9): a valid file; a file missing a column → `HeaderError`, nothing loaded, a `failed` log row; bad rows (unknown source, empty value, a control character, value over 2 048 characters, confidence `abc` / 101, an unparsable date) skipped with their line number and reason, the rest loaded, status `partial`; the same file twice → the same row count, `rows_new` 0 and `rows_updated` N the second time, `first_seen` unchanged, `last_seen` and `expires_at` moved; both `first_seen` shapes; empty confidence → NULL; domain and hash lower-cased, a URL's case kept; a key repeated in one file counted once; quoted commas and quoted newlines in a field; the summary line and the log row's `message` carry no row text; the DSN never printed; a database error loads nothing.
- [ ] **Step 2: Run them, see them fail.**
- [ ] **Step 3: Implement** (spec §6): `csv.DictReader`, one transaction, `INSERT … ON CONFLICT (source, type, value) DO UPDATE` with parameters and `xmax = 0` (or `RETURNING`) to tell new from updated, the log row in its own statement so a failed run is logged too.
- [ ] **Step 4: `make test`, the covering db tests, `make lint`; commit.**

### Task 3: The API

**Files:**
- Create: `backend/app/ti/queries.py`, `backend/app/web/routers/ti.py`, `backend/tests/test_ti_api.py`
- Modify: whatever lists the routers or the served routes in tests (follow `soar_reviews.py`'s commit)

**Interfaces:**
- Consumes: the tables; `app.ti.importer.normalise_value`; `require_role` from `app.web.deps`.
- Produces: `GET /api/ti/iocs`, `/api/ti/stats`, `/api/ti/lookup`, `/api/ti/status`, `/api/ti/export` exactly as spec §7; `csv_cell(value: str) -> str` (the injection guard); JSON shapes named in the task's report for Task 4.

- [ ] **Step 1: Write the failing tests**: every filter alone and combined, paging bounds, the fixed sort, expired rows hidden unless asked, `q` with `%`, `_`, a quote and a backslash treated literally, stats numbers on a seeded set (per day and source in GMT+7, top 10, ≥ 75, hits, today), lookup (exact, normalised, IPv4 against `ip:port`, nothing), status and `stale` at 25 h and 27 h and with no import, each route refused without a login, export refused for `tier1` and `tier2` and served for `admin`, the CSV guard on `=`, `+`, `-`, `@`, tab, CR, the blocklist's content and de-duplication.
- [ ] **Step 2: Run them, see them fail.**
- [ ] **Step 3: Implement** (spec §7).
- [ ] **Step 4: `make test`, the covering db tests, `make lint`; commit.**

### Task 4: The page

**Files:**
- Create: `frontend/src/features/ti/` (page, table, filters, detail panel, charts, `defang.ts`, queries, tests), `frontend/src/api/ti.ts`
- Modify: `frontend/src/routes.tsx`, `frontend/src/components/AppHeader.tsx`, `frontend/src/strings.ts`, `docs/plan/DECISIONS.md` (DEC-224), `docs/runbook.md` (deploying the page)

**Interfaces:**
- Consumes: the API of Task 3.
- Produces: `defang(value: string, type: string): string`; `isAbuseChReference(url: string): boolean`; route `/threat-intel`.

- [ ] **Step 1: Write the failing tests**: `defang` (http and https URLs, a bare domain, IPv4, `ip:port`, IPv6, a value already defanged, a hash left alone, a value with markup); the copy button gives the original value and falls back to selecting text when the clipboard refuses; the reference is a link only for `https://` on the three abuse.ch hosts, else defanged text; no IOC field is rendered as markup; the stale banner; the KPI cards; the charts draw from the stats; filters, search and paging drive the query; the detail panel; the route's guard and the header link.
- [ ] **Step 2: Run them, see them fail.**
- [ ] **Step 3: Implement** (spec §8) with the web's components, tokens and `format.ts`; SVG charts, no new dependency.
- [ ] **Step 4: `make ui-lint`, `make ui-test`, `make test`, `make lint`; commit.**
