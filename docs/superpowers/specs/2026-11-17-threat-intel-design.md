# Threat Intel module (abuse.ch feed): design

Date: 17/11/2026. Branch: `feature/threat-intel`, cut from `feature/mitre-local-reference` @ `27edc6c` (itself a
fast-forward of the trial's `8c812c7`). Trial only for now; `main` and live are not touched. Decision number: DEC-224.

The requirements are the Owner's own brief of 17/11 (sections 1 to 5 of it; section 6 is not built). This document
records that brief against the codebase, the Owner's answers of 17/11, and the calls the Director made where the brief
leaves a choice.

## 1. Intent

A root cron on this host runs `/opt/abusech/abusech_daily100.py` at 07:00 and writes
`/var/lib/abusech/daily/ioc_YYYY-MM-DD.csv`: the 100 newest IOCs of each abuse.ch source (ThreatFox, URLhaus,
MalwareBazaar). The Owner wants a **Threat Intel** page in the AI SOC web that shows them. The web never reads the
CSV: the path is CSV → importer → database → API → page.

## 2. Goals, non-goals, anti-goals

**Goals** (the brief's sections 1 to 5)
- G1. An importer that validates, normalises and upserts a day's CSV, idempotently, and logs every run.
- G2. Two tables (`ti_ioc`, `ti_import_log`) by a numbered migration, as the project writes them.
- G3. A read-only API behind the web's login: list, stats, lookup, status; export for the admin only.
- G4. A page "Threat Intel" built from the web's own layout, components and style: status bar, KPI cards, two charts,
  a filtered table with a detail panel. Times in GMT+7.
- G5. The brief's security rules: defanged display, IOC values as plain text, CSV-injection guard on export,
  parameterised SQL, no abuse.ch key in code or logs.

**Non-goals** (the brief's section 6, and the Owner's answers)
- Matching IOCs against logs, an "IOC hit" alert, the AI morning summary, AI explanations. `hit_count` and
  `last_hit` exist and stay 0 / null; the "matched in logs" figures are served and shown as they are (0).
- A "Tìm trong log" button (Owner, 17/11: removed).
- Feeding `ti_ioc` into triage: the existing `iocs` table (the inventory behind `ioc_reputation`) is not touched,
  and nothing in ①, ② or the gate reads `ti_ioc`.
- Changing or fixing `/opt/abusech/abusech_daily100.py`. Deleting expired rows.

**Anti-goals** (a result with any of these is a failure)
- A1. The web reading the CSV, or the API reading a file.
- A2. An IOC URL, domain or IP rendered as a link, fetched, pre-loaded or previewed by the page.
- A3. An IOC value reaching the page as markup (`innerHTML`, `dangerouslySetInnerHTML`).
- A4. A second run of the same file creating a second row for an IOC.
- A5. SQL built by joining user input into the statement.
- A6. A secret (the abuse.ch key, a DSN, a password) in code, a log line, argv or a committed file.

## 3. What the codebase and the host give (facts, 17/11)

- Backend Python/FastAPI with psycopg and plain parameterised SQL; routers are files under
  `backend/app/web/routers/`, loaded by `iter_routers()`; `soar_reviews.py` is the newest and the pattern.
- Login and roles: `require_role(...)` in `backend/app/web/deps.py`; roles `tier1`, `tier2`, `admin`.
- Database PostgreSQL. Migrations are numbered SQL files in `docs/Schema/` (newest `025_soar_reviews.sql`), never
  edited once applied, each with its test (`backend/tests/test_migration_0NN.py`); `schema.sql` is rebuilt from
  them; applied with `make migrate` as the database owner. The app's role `app_rw` gets `SELECT, INSERT, UPDATE` and
  never `DELETE`.
- Frontend React 19 + TypeScript, Vite, Tailwind 4, TanStack Query, react-router; shared components `DataTable`,
  `KeyValueGrid`, `Badge`, `Toast`, `AppHeader`; visible strings in `frontend/src/strings.ts`; times through
  `frontend/src/format.ts` (GMT+7). No chart library: charts are hand-written SVG. The SOAR page
  (`frontend/src/features/soar/`) is the pattern for filters, pagination and a detail panel.
- The script and the web are on the same host. The cron line is root's:
  `0 7 * * * . /etc/abusech.env && /usr/bin/python3 /opt/abusech/abusech_daily100.py >> /var/log/abusech_daily.log 2>&1`.
- The CSV (UTF-8, header `source,first_seen,type,value,threat,malware,confidence,tags,reference`): on 17/11 it held
  200 rows (ThreatFox 100, MalwareBazaar 100, **URLhaus 0**: told to the Owner, the script's matter); types seen
  `ip:port`, `domain`, `url`, `sha256_hash`; `first_seen` as `YYYY-MM-DD HH:MM:SS` with and without ` UTC`;
  `confidence` empty on every MalwareBazaar row.

## 4. Owner's answers (17/11)

1. A new branch from the trial's newest commit; deployed on the trial first.
2. The importer writes to the **trial** database and reads its DSN from the trial's `.env`.
3. No "Tìm trong log" button.

## 5. Database (migration `026_threat_intel.sql`)

`ti_ioc`
- `id bigint` identity primary key; `source text` (`threatfox`, `urlhaus`, `malwarebazaar`: a CHECK); `type text`;
  `value text`; `malware text`; `threat text`; `confidence smallint` (0–100 or NULL: a CHECK); `tags text[]`;
  `reference text`; `first_seen timestamptz`; `last_seen timestamptz`; `imported_at timestamptz`;
  `expires_at timestamptz`; `hit_count integer NOT NULL DEFAULT 0`; `last_hit timestamptz`.
- Unique `(source, type, value)`. `first_seen` is NOT NULL (a row without a usable date is skipped by the importer).
- Indexes on `value`, `(first_seen DESC, id DESC)` (a stable order for the list), `source`, `malware`.
- Byte bounds, because `value`, `type` and `malware` sit in btree indexes whose entries hold at most 2 704 bytes:
  `value` 1–2 048 bytes, `type` 1–64 bytes, `malware` at most 256 bytes (each a CHECK).

`ti_import_log`
- `id bigint` identity; `file text` (the file's name, not its directory); `started_at`, `finished_at timestamptz`;
  `rows_total`, `rows_new`, `rows_updated`, `rows_error integer`; `status text` (`ok`, `partial`, `failed`: a CHECK);
  `message text` (a short closed-vocabulary reason, never a row's content); a CHECK that a run finishes at or after
  its start.

Grants: `app_rw` gets `SELECT, INSERT, UPDATE` on both and no `DELETE`, like every table. Nothing is deleted in
this phase: an expired row stays and is hidden by the API unless asked for.

## 6. Importer

- `scripts/ti_import.py [FILE] --env-file PATH`: a thin command over `backend/app/ti/importer.py`. Without `FILE`
  it takes the newest `ioc_*.csv` of `/var/lib/abusech/daily/` (`--dir` to change it). The DSN comes from
  `DATABASE_URL` in `--env-file`, never from argv, and is never printed.
- Header: the nine columns must all be present (order free, extra columns ignored). A missing column stops the run:
  nothing is loaded, the log row says `failed`, exit code 1.
- Each row: `source` one of the three; `type` lower-cased, a short token; `value` trimmed, not empty, at most
  2 048 **bytes** of UTF-8, no control character; `type` at most 64 bytes; `malware` at most 256 bytes; `threat` at
  most 256 bytes, `reference` at most 2 048 bytes, at most 32 tags of at most 64 bytes each (a longer field makes
  the row a bad row, never a database error); `domain` and every `*_hash` type lower-cased; `confidence` empty or an
  integer 0–100; `first_seen` required, parsed as UTC from `YYYY-MM-DD HH:MM:SS[ UTC]` or ISO-8601; `tags` split on commas,
  trimmed, empties dropped. A bad row is skipped and counted, and one line names its line number and a closed
  reason (never the row's text).
- Upsert on `(source, type, value)` with parameters: a new IOC is inserted (`imported_at` = the run's instant); an
  existing one gets `last_seen` = the run's instant, and its descriptive fields (malware, threat, confidence, tags,
  reference) refreshed; `first_seen` keeps the earlier of the two. `expires_at = last_seen + 30 days` in both cases.
  A key repeated inside one file counts once.
- One transaction for the whole file: a database error loads nothing. Then one `ti_import_log` row (also written
  for a failed header) and one summary line on stdout (counts only), which lands in the cron's log.
- Status: `ok` (no bad row), `partial` (some bad rows, the good ones loaded), `failed` (nothing loaded).
- The cron line becomes `… abusech_daily100.py && <venv python> /…/scripts/ti_import.py --env-file /…/trial/.env`
  (the Owner edits root's crontab; exact line in the hand-over).

## 7. API (read only, every route behind the login)

All three roles may read; export is `admin` only. Every query is parameterised; sort columns and directions come
from a closed list, never from the request's text.

- `GET /api/ti/iocs`: filters `source`, `type`, `malware`, `from` / `to` (on `first_seen`), `min_confidence`, `q`
  (a case-insensitive substring of `value`, `malware`, `threat`, a tag); `page`, `page_size` (default 50, at most
  200); sorted by `first_seen` descending. Expired rows (`expires_at` in the past) are left out unless
  `expired=true`. Returns the rows and the total.
- `GET /api/ti/stats?days=30` (1–90): IOCs per day and source (the day of `first_seen` in GMT+7), the top 10
  malware, the count with `confidence >= 75`, the count with `hit_count > 0`, the count imported today (GMT+7), and
  the newest three malware names for the KPI card.
- `GET /api/ti/lookup?value=`: the rows whose value equals the input after the importer's normalisation; an IPv4
  input also matches `ip:port` rows of that address. An empty list when nothing matches.
- `GET /api/ti/status`: the newest import-log row, the newest successful one, and `stale: true` when no successful
  import finished within the last 26 hours.
- `GET /api/ti/export?format=csv|blocklist` (admin): `csv` is the list's columns for the same filters, with a `'`
  put before any cell that begins with `=`, `+`, `-`, `@`, a tab or a carriage return; `blocklist` is plain text,
  one value per line, domains and IP addresses only (the port of an `ip:port` dropped), de-duplicated.

## 8. Page "Threat Intel" (`/threat-intel`, every role, a link in the header)

Top to bottom, with the web's own components and tokens:
1. Status bar: when the last import finished (GMT+7) and how many IOCs were new; a red banner when `stale`.
2. KPI cards: new today, confidence ≥ 75, top 3 malware, matched in logs.
3. Charts (SVG): IOCs per day for 30 days, stacked by source; top 10 malware as horizontal bars.
4. The IOC table: filters, a search box, pagination, a copy button per row. A row opens a detail panel with every
   field and a link to the IOC's abuse.ch page.

Security rules of the page (the brief's section 5):
- Every URL, domain and IP of an IOC is shown **defanged** (`hxxp://evil[.]com`, `1.2.3[.]4`), as text, never as a
  link, never fetched. The copy button copies the original value.
- Every IOC field is rendered as a text node.
- The abuse.ch link is the row's `reference`, and it is a link only when it is `https://` on one of abuse.ch's own
  hosts (`threatfox.abuse.ch`, `urlhaus.abuse.ch`, `bazaar.abuse.ch`); it opens in a new tab with
  `rel="noopener noreferrer"`. Any other reference is shown defanged, as text.

## 9. Order of work, and tests

Database → importer → API → page; the Director stops after each step for the Owner to check (the brief's rule).
- Migration: the project's migration test (tables, columns, constraints, indexes, grants; `app_rw` cannot delete;
  the unique key refuses a duplicate), and the rebuilt `schema.sql`.
- Importer (the brief's list): a valid file; a file missing a column (nothing loaded, `failed`); bad rows skipped
  and counted; the same file twice gives no duplicate. Plus: the two `first_seen` shapes, an empty confidence,
  normalisation of domains and hashes, a key repeated in one file, the summary line carrying no row text.
- API: each route's filters, paging, roles (a reader cannot export), the CSV guard, the blocklist's content.
- Page: the defang function (URL, domain, IPv4, `ip:port`, IPv6, an already defanged value, a value with markup),
  the copy button giving the original, the reference link's allow-list, the stale banner.
- A sample CSV with made-up values (documentation address ranges, `example.*` names) for the Owner's check.

## 10. Left to the builder

Module and component names beyond those given, the SVG charts' details, the Vietnamese wording of the page, and
how the page lays out on a narrow screen. Decisions the builder makes go in the plan's ledger as rulings.
