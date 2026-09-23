# P5 · Tier-2 + digest + ops — task cards

Phase objective: cases with ②, the digest loop, health alarms, backup.
Written **23/09/2026** (Planner P5, host ATTT-M1) against `prompts/P5.md`, `prompts/reload-run-2026-09-23-ATTT-M1.md` §2,
and **DEC-097** (the ② trigger, read before anything else was written). Where a DEC and the brief disagree,
the DEC wins and the divergence is named in §1.

**DEC-007 item 7 / DEC-009 — which copy of a card is authoritative.** Each task has a full
`docs/plan/tasks/P5/<TASK_ID>.prompt.md` and a shorter entry in this file. **The prompt is the card**;
this file is the Planner's index — estimates, waves, dependencies, the cut boundary, Owner actions and the
hand-off. Where this file restates an acceptance command it matches the prompt verbatim or does not appear.

---

## 0 · The one thing to read before dispatching anything: **the cut boundary is a file boundary**

> **Amended the same day it was written — read this first.** `DEC-108` (Director, 23/09, committed at `0fca637` while this plan was being written) **rules that DEC-097(ii) is false under every option but D, so ② falls at the 25/09 evening gate, applied without a further Owner turn.** The reason is not the archive (DEC-108 settled that: a database rebuild reproduces all three G1 artifacts byte-identically, option A taken) — it is **G2**: no Linux agent exists on this box, `conf/local_rules.xml` was never deployed to this manager, `eval/lab_windows.csv` is header-only and there are 0 `source='lab'` alerts, so the `--g2` half of the 25/09 run has nothing to select from. **Only the Owner's option D (restore the lab) can make (ii) true, and the deadline for that is the end of 24/09.**
>
> **What this changes for this plan: nothing structural, which is the point.** The four ② cards were already a separable set sharing no file with the rest of P5, so the expected outcome is four `cut` rows on 25/09 and no other edit anywhere. **The one judgement it does change is P5-T02's** — see §4.2.

DEC-097 arms ② on a condition that resolves **at the end of 25/09**: ② falls automatically, in §10 order, if
either half is false — (i) P6-T02 merged into `main`, (ii) `eval/gold_candidates.csv` built by the 25/09
`build_gold.py --g1 --g2` run. Both true → ② gets **one agent-day, 28/09**, after DEC-032's measurement at
its own prompt size.

So P5 is planned as **two disjoint sets of cards**, not one phase with a conditional paragraph:

| | Cards | `must` hours | If ② falls on 25/09 |
|---|---|---|---|
| **② bundle** (conditional) | **T02 · T03 · T04 · T05** | 13.5 h | all four are `cut` in STATE, nothing else moves |
| **The rest of P5** | T01 · T06 · T07 · T08 · T09 · T10 · T11 · T12 · T13 | 17 h `must` + 6 h `should` | unchanged, every file list already disjoint from the bundle |

**No file appears in both sets**, no card in the rest of P5 imports `tier2.dossier`, `llm.investigate` or
`tier2.investigate`, and the one place the two sets meet — the case detail page — meets through a Jinja
`{% include "_investigation.html" ignore missing %}` line that renders nothing when the bundle is absent
(planning decision 2). Cutting ② is `git rm` of four cards and four STATE rows; it is not a re-plan.

**§10 vs `prompts/P5.md` — a conflict, resolved toward §10.** Context pack §10 cuts *"② entirely (keep case
and manual conclude)"*; `prompts/P5.md:44` puts conclude (its T03) and the Tier-2 screens (its T04) **inside**
the bundle. §0 of the context pack makes §10 the higher authority, and §10 is also the coherent reading —
a case an analyst cannot conclude is not a "keep". **Conclude, notes, the case list and the case detail page
are therefore outside the bundle** (T06, T07) and the bundle is measurement → dossier → job → the ② half of
the screen. This is the only place this plan departs from the brief's suggested decomposition.

---

## 1 · What changed since the brief — measured on `main` and on the container's `soc_dev`, 23/09

| Fact | Measured 23/09 | What it changes |
|---|---|---|
| **The 60 k budget is unreachable on real data.** | The **200 largest heads in the whole corpus total 51,312 bytes ≈ 12,828 tokens** (`select sum(octet_length(raw_log)) from (… order by octet_length(raw_log) desc limit 200)`), and `MAX_ALERTS_PER_CASE = 200`. `raw_log` on heads: p50 **63 B**, p95 **217 B**, max **3,439 B**; only **11** heads are ≥ 1 KB, **579 of 606** are < 256 B. | **The largest dossier a real case on this corpus can produce is ≈ 12.8 k tokens — 21 % of `CASE_PROMPT_BUDGET_TOKENS`, and almost exactly the 12.8 k class DEC-032 already measured.** A measurement card that said "build a real case and measure" would re-measure the ① class, report green, and prove nothing about the 60 k class — DEC-025's exact defect shape. **T02 synthesises the prompt to the budget** and reports both numbers side by side. |
| **The G1 archive is not on this host — found independently, already ruled on, and one measurement corrects the ruling.** | `eval/build_gold.py:1063` makes `--archive-file` **required**; `/home/user1/archive/alerts-2026-08-08_09-07.jsonl` (113,379,904 bytes) is absent here and IA1803 is unreachable. **DEC-108 resolved it** — rebuild from `alerts.raw_payload`, all three artifacts byte-identical, option A. Measured here on `intake` instead: the **92,030** rows over the replay `sort_key` range are **113,287,874** bytes, `+ 92,030` newlines = **113,379,904**, the original **to the byte**, *including the 19 rejected lines DEC-108 states were never stored*. | **No P5 card depends on the archive** — P5-T02 builds from committed fixtures for exactly this reason, so this touches nothing here. Filed as `INBOX 2026-09-23 · P6 / gold build · NOTE` because DEC-108 binds the `archive:` provenance line to be committed verbatim and never tidied, and the `intake` rebuild supports the original's own headline (`lines 92030 / parsed 92011 / rejected 19`) rather than `rejected 0`. It changes the record, not the sample: DEC-108's *"provably inert"* finding holds either way. |
| **Zero auto-closed alerts; zero auto-close rules.** | `alerts.status` is `duplicate` **99,920** + `queued_tier1` **606** and nothing else; `autoclose_rules` **0 rows**; `autoclose_reviews` 0; `system_health` 0; `cases` 0; `case_alerts` 0; `case_notes` 0. | The digest has **no live content today**. Its exit-gate proof is a `db` test that creates the auto-closed cluster itself (T08), plus the Owner creating one rule through T10's screen. `prompts/P5.md:31`'s *"auto-close can fire only on agent 001 (`user1-IA1803`)"* is **stale** — that agent stopped reporting (DEC-106). |
| **86 % of heads are hard-blocked from auto-close.** | `asset_context->>'present'`: **false on 523 of 606 heads**, `true/medium` on 77, `true/high` on 6. | G8′ `asset_not_in_inventory` blocks 523; `asset_high` blocks 6. **At most 77 heads in the whole database can ever auto-close**, and none will until the Owner adds `Windows_Endpoint` to `conf/inventory.yaml` (already an open Owner action). The digest page is sized for **tens per day, not thousands** — T09 says so in the card, not in a comment. |
| **`domain.conclude_case` already exists.** | `backend/app/domain/transitions.py:575` — A13–A15 on `cases`, A16 fan-out over `case_id` **and** `duplicate_of IN (…)`, `tier2.concluded` written in the same transaction; 10 callers; covered by `test_transitions.py`. | **T06 is a thin guarded layer over it, exactly as `tier1/decide.py` is over `transitions.decide`** — and **P5 does not modify `domain/transitions.py` at all** (planning decision 4): it is P4-T03's file and P4-T03 is open. |
| **`simulate()` and `rule_width_report()` already exist.** | `backend/app/ingest/autoclose.py:401` and `:515`; the module comment at `:70` already reads *"P5's admin route calls `reload_rules()` on rule add/edit/toggle"*. | **T10 is a screen over three existing functions**, not new matching logic. No `ingest/` file is in any P5 Files list. |
| **`investigate_system.txt` on `main` is written for the cut tool loop.** | `backend/app/llm/templates/investigate_system.txt:20` — *"Bạn được gọi 8 tool CHỈ ĐỌC"*, and a whole TOOL section. §10 cuts the ② tool loop; §7.6 is single shot. `docs/phase-7-tier2.md` §P7-8 is the v1 spec that template came from. | **T04 rewrites the template** for the single shot (*"you have no tools; if data is missing answer `need_more_data`"*). `backend/tests/test_schemas.py:144` is the **only** test that reads the file (it asserts the literal word `JSON`). |
| **Every §6.3 key P5 needs already exists; no SMTP key does.** | `infra/config.py`: `CASE_PROMPT_BUDGET_TOKENS` **60_000** `:143`, `ANALYZE_QUOTA_PER_USER_DAY` **30** `:144`, `AUTOCLOSE_RULE_WIDTH_PCT` 30, `MAX_ALERTS_PER_CASE` 200, `RETENTION_DAYS` 365, `BACKUP_HOUR` 2, `NOTIFY_TELEGRAM_BOT_TOKEN`/`_CHAT_ID` `:159-160`. `grep -c NOTIFY_SMTP backend/app/infra/config.py` → **0**; the six SMTP names sit **commented** in `.env.example:139-144`. | **No §6.3 change for the whole phase except the notifier's second arm.** §8 raises one INBOX item; T11 is written for the recommended answer (Telegram + a log sink, no new key). |
| **Every audit event type P5 writes already exists.** | `ck_audit_event_type` (27 names) carries `case.analyzed`, `tier2.concluded`, `autoclose.reviewed`, `rule.suspected_wrong`, `admin.autoclose_rule_toggled`, `health.alarm`, `alert.reopened`. | **No new event type, no migration, in any P5 card.** There is deliberately **no** `case.note_added` name — a note is not a decision; T06's `POST notes` writes `case_notes` only, and says so. |
| **`system_health.checked_at` is the primary key.** | Migration 015's own note (5): *"Two health checks landing in the same microsecond would collide on insert; that is the contract's choice… Flagged for P5 in the task report."* | T11 writes **one row per run** with the database's `now()` and records the collision as a P8 limitation. Fixing it is a §6.1 change and is out of scope. |
| **Job registration is one shared file.** | `backend/app/web/worker.py:25` — `HANDLERS = {"pull": …, "pipeline": …, "triage": …}`, a literal. Three P5 cards need an entry (`investigate`, `digest`, `health`). `infra/worker.py:12` already anticipates P5: it takes an optional `timeouts` mapping *"for the job types that need longer than the 3 s default (P5's `conclude`, for `investigate`, asks for 5 s)"*. | **Planning decision 1: discovery, mirroring P4's planning decision 1 for routers.** T01 rewrites `web/worker.py` once into `app.web.handlers/`; every later card adds one module and touches no shared file. Without it, three cards collide on one dict literal — the collision E5 forbids and DEC-038 had to rule sequential in P2. |
| **Route listing on the pinned FastAPI.** | DEC-101 bucket (b): on `fastapi==0.141.1` `app.include_router` leaves a lazily-resolved node, so `app.routes` does **not** list mounted paths. | Every acceptance in this phase that lists routes uses `sorted(app.openapi()["paths"])`. Six P4 cards were amended for this; none of these thirteen carries the old form. |
| **Host (DEC-106).** | `python3` **3.14.4** with no pytest/ruff; `.venv/bin/python` **3.12.13**, pytest **9.1.1**. `make lint PY=.venv/bin/python` → **exit 0** (run 23/09). DB is the container on `127.0.0.1:55432`, DSNs from `.env`; `JWT_SECRET` is now **present** in `.env` (it was absent on 19/09). `/etc/hosts` has no `wazuh.indexer` line. | `PY=.venv/bin/python` on **every** make line in every acceptance. **No P5 card reaches the indexer from the host — and none needs to:** all ten health checks are DB-side, filesystem-side or `shutil.disk_usage`. The gate item *"health alarm fires with the indexer unreachable"* is proved by a **stale `source_heartbeat` row in a `db` test** (T11 acceptance 3), never by breaking a host path. |
| **Backups.** | `backups/` holds exactly one file, `latest.dump`, **22/09 20:06**; no timer and no crontab entry exists on this host; `scripts/backup.sh` exists (P0) and `scripts/restore.sh` does not; `pg_dump`/`pg_restore`/`psql` are on the host at `/usr/bin`. Disk `/` 26 % used, 647 G free. | Health's *"backup age > 36 h"* threshold **alarms from 24/09 08:06 (+07)** until T12 lands a schedule — the first real alarm this system will raise, and a good one to demonstrate. T12 is `must` and **P8's restore drill depends on it**. |

---

## 2 · Dispatch state — read this before dispatching anything

| | |
|---|---|
| **P5 has no day in the schedule.** | The 23/09 reload brief's remaining schedule is *P4 code → P6-T02 → labelling 26–27/09 → gold freeze 28/09 → P7 29/09 → P8 30/09–01/10 → submit 02/10*. **P5 does not appear in it.** DEC-090 said the non-② half *"remains unplanned"*; these cards make it plannable, they do not make room for it. **Naming the window is the Director's call and it is the first thing this plan asks for.** |
| Where the hours actually are | **26–27/09 are labelling days — human work (Owner + advisor).** Agent slots are idle then. That is the only window in the calendar that fits P5's non-② cards without displacing something already dated. |
| Dispatchable the moment a slot frees | **P5-T01** (1 h, no dependency, `web/worker.py` + a new package — disjoint from all eight open cards) · **P5-T02** (1.5 h, `eval/` and `docs/` only, no dependency) · **P5-T12** (2 h, `scripts/` only, no dependency) |
| **Dispatch T02 before the 25/09 gate, not after** | T02 is the DEC-032 measurement. It costs ≈ 1.5 h and **< $0.30**, touches no product code, and its result is an input to the 25/09 ② decision: if ② times out or blows the cost at 60 k tokens, the question answers itself and the 28/09 agent-day is freed for P7/P8. Holding it until 28/09 spends the day to learn the thing that decides whether to spend the day. |
| After P5-T01 merges | **P5-T08** (digest job) · **P5-T11** (health + notifier) · and, inside the bundle, **P5-T04** |
| After P4-T01 merges (it has) | **P5-T06** (tier2 REST + conclude + notes) |
| After P4-T04 merges | **P5-T07** (case pages) · **P5-T09** (digest page) · **P5-T10** (rules screen) |
| Blocked on an Owner action | nothing on the code. **The notifier** needs a Telegram bot token + chat id before T11's alarm can reach a human (it logs and counts until then, by design). **The digest** has nothing to review until `Windows_Endpoint` is in `conf/inventory.yaml` and one auto-close rule exists. |
| **② is expected to fall on 25/09** | **DEC-108** rules DEC-097(ii) false under options A–C; only the Owner's option D (restore the lab, deadline end of 24/09) can save it. Plan on the four ② cards being `cut` — the design in §0 makes that four STATE edits and nothing else. **Do not pre-dispatch T03, T04 or T05.** |
| INBOX items this plan raises (§8) | **two** — the notifier's second arm (`NOTIFY_SMTP_*` would be six new §6.3 keys; T11 is written for the recommended answer and is re-cut in one paragraph if refused), and the archive blocker above, which the Planner found while reading DEC-097 and which belongs to P6. |
| Open cards these file lists are disjoint from | P3-T11 · P4-T03 · P4-T04 · P4-T05 · P4-T06 · P4-T08 · P6-T02 · P6-T06 — checked path by path in §9. |

---

## 3 · Rules every card follows (so the Reviewer can grep for them)

1. **Every make line carries `PY=.venv/bin/python`** (DEC-106). This host's `python3` is 3.14.4 with no pytest and no ruff; a bare `make test` dies at *"No module named pytest"* and that is the environment, not a red suite. Reference green on `main` 22/09: lint clean · `test` 1042 passed / 1 skipped / 549 deselected / 2 xfailed · `test-db` 549 passed.
2. **Every card's Acceptance opens with the DEC-105 database preamble** deriving `TDB` from the **primary checkout's** `.env` into that card's **own** database on the container — never a socket `postgresql:///…` DSN (it reaches the frozen native fallback and silently tests a stale copy), never the shared `soc_test` (DEC-104's race).
3. Every pytest line is `python3 -m pytest -c backend/pyproject.toml …` (DEC-005). A named test is grepped with `-vv` (DEC-074). `db`-marked lines pass `-rs` and state `N passed` with **`skipped` absent for that file** (DEC-023 item 8). Whole-suite runs are judged on **exit 0** — `test_dispatch_state.py` skips off `main` on every branch (DEC-080).
4. **Every acceptance names its red step, and the red step discriminates** (DEC-025, DEC-027). A guard is not exempt from the discipline it enforces.
5. **No card reaches the indexer from the host** (DEC-106). `/etc/hosts` has no `wazuh.indexer` line and `soc_ro` is denied `_cat/indices`; an indexer command runs inside the worker container or not at all. **No P5 card contains one.**
6. **Routes are listed with `sorted(app.openapi()["paths"])`**, never `app.routes` (DEC-101 bucket (b)).
7. **No test opens a socket beyond the local PostgreSQL.** HTTP goes through `fastapi.testclient.TestClient` on `app.web.main.app` with `app.web.deps.get_conn` overridden to the `db` fixture; the LLM is the fake adapter (`backend/tests/fakes/llm.py`) — ② is never called live from a test. Live calls exist in exactly one place in this phase: **T02's measurement script**, which is `eval/` and not a test.
8. **No test reads the real `.env`** (DEC-047; `conftest.py:73` `_no_ambient_env_file` enforces it). Never point a test or a manual run at `soc_dev`.
9. **Only `domain/` writes `alerts.status` / `cases.status`** (G2). `tier2/conclude.py` and `tier1/digest.py` call `domain.transitions`; nothing in `tier2/` or `tier1/` issues an `UPDATE … status`.
10. Import rules hold (`ALLOWED` in `test_import_rules.py`): `infra → nothing`, `tier1 → domain|llm|kb|security|infra|audit`, `tier2 → domain|llm|kb|security|infra|audit|enrichment`, `web → everything`. **Consequence:** `infra/notify.py` and `infra/health.py` import no tier; the health job's handler module lives under `web/handlers/` (planning decision 1), which is a composition root.
11. **Frozen contracts:** no new §6.3 key (the one candidate is §8's INBOX item), no new event type (all seven exist), no new §6.4 operation (HTML pages are pages, not API operations — P4 planning decision 9 and P6-T02 took the same position), **no migration**.
12. **Every 4xx that must persist a write commits before it raises** (P4 planning decision 3): `get_conn` rolls back on any exception, including `HTTPException`. In P5 that applies to the analyze quota counter and to `authz.denied`.
13. `superseded.yaml` scans these cards (DEC-049): no bare `pytest`, no dead migration range, no retired host or service name, no indexer address form, no socket DSN.

---

## 4 · Critical path, waves and what fits

Estimates are for the card as written; dependencies are the `Depends on:` field of each prompt, and where this
diagram and a field disagree, the field wins (DEC-007 item 6).

```
② bundle (conditional until 25/09, one agent-day 28/09 if it survives — DEC-097)
  T02 measurement (1.5) ──► T03 dossier (5) ──► T04 job + API + template (5) ──► T05 ② screen half (2)
  └─ run T02 BEFORE the 25/09 gate; it is the input to the decision, not a consequence of it

the rest of P5 (no day allocated — §2; the labelling days 26–27/09 are the only idle window)
  T01 worker discovery (1) ─┬─► T08 digest job (3.5) ──► T09 digest page (2.5, should)
                            └─► T11 health + notify + /health (4)
  T06 tier2 REST + conclude + notes (3.5) ──► T07 case pages (3)
  T10 rules screen (2.5, should)        T12 restore + schedule (2)        T13 runbook (1, should)
```

| | |
|---|---|
| Sum of `must` estimates | **30.5 h** across 10 `must` cards |
| Day budget (`prompts/P5.md`: 1 day) | 8 h |
| Overbooking | **+281 %** against the 8 h day (30.5 h where the × 1.3 rule allows 10.4 h) — the re-plan threshold is 30 %, **so this note is required and present**. `prompts/P5.md:49` says the day is *"overbooked by design"*; this is how much |
| `should` | **6 h** — T09 digest page (2.5), T10 rules screen (2.5), T13 runbook (1). Total phase **36.5 h** |
| Longest chain | **T02 → T03 → T04 → T05 = 13.5 h**, the ② bundle, four review/merge gates — and DEC-097 gives it **one agent-day**. **13.5 h of carded work does not fit in one agent-day**, and that is a number the Director needs before 25/09, not on 28/09 |
| Longest non-② chain | T01 → T08 → T09 = 7 h; T06 → T07 = 6.5 h |
| **What fits if ② falls** | `must` drops to **17 h** (T01 1 · T06 3.5 · T07 3 · T08 3.5 · T11 4 · T12 2) ≈ **2 agent-days at two slots ≈ 1 working day** at three. That is a plausible ask for 26–27/09 |
| **What P8 cannot start without** | **T12.** `prompts/P5.md:37` — *"P8's restore drill depends on a real backup file existing"*. T12 is 2 h, has no dependency, and is dispatchable now. It is the one P5 card whose absence blocks a later phase's gate |

### 4.1 · Task table

| Task | Title | Set | Priority | Est. | Depends on | Owner action? |
|---|---|---|---|---|---|---|
| P5-T01 | Worker handler discovery — `web/handlers/` package (`iter_handlers`, `iter_timeouts`), `pull`/`pipeline`/`triage` moved into modules, `web/worker.py` rewritten to build both mappings | rest | must | 1 h | — | no |
| P5-T02 | **DEC-032 ② size-class measurement** — `eval/investigate_measure.py`: one real `investigate_v2` call at `CASE_PROMPT_BUDGET_TOKENS=60_000`, p50/p95, tokens, cost, JSON + schema validity, against the 12.8 k real-corpus ceiling → `docs/investigate-size-class.md` | **② head** | must | 1.5 h | — | no (Owner reads the result before the 25/09 gate) |
| P5-T03 | `tier2/dossier.py` — the nine blocks, entity extraction (IPv4/IPv6, md5/sha1/sha256, domains, usernames, hosts) with inventory lookups and 7-day per-entity history, ±2 h correlation rows, deterministic build, 60 k budget with the truncation order | **②** | must | 5 h | P5-T02 | no |
| P5-T04 | `llm/investigate.py` (single shot) + `tier2/investigate.py` job (quota, one-running-per-case, nonce per attempt, evidence check → `need_more_data`) + `investigate_system.txt` rewritten for the cut tool loop + `POST /api/tier2/cases/{id}/analyze`, `GET /api/tier2/runs/{run_id}` + the `investigate` handler module | **②** | must | 5 h | P5-T01, P5-T03 | no |
| P5-T05 | The ② half of the case screen — `_investigation.html` (② result, verified/unverified evidence marks, hypotheses with `evidence_against`), the analyse button and the "analysing…" polling partial | **②** | must | 2 h | P5-T04, P5-T07 | no |
| P5-T06 | `tier2/conclude.py` (guarded layer over `domain.conclude_case`, 5 s statement timeout, 409 on stale) + `case_notes` + `web/routers/tier2.py` (`GET /api/tier2/cases`, `GET …/{id}`, `POST …/notes`, `POST …/conclude`) | rest | must | 3.5 h | P4-T01 (merged) | no |
| P5-T07 | Case list + case detail pages — `templates/{cases,case,_case_notes}.html`, `web/routers/cases_pages.py`, the ongoing-cluster label, and the `{% include "_investigation.html" ignore missing %}` seam | rest | must | 3 h | P5-T06, P4-T04 | no |
| P5-T08 | `tier1/digest.py` — `build(day)` (every cluster auto-closed in 24 h with its ① verdict, disagreements first), `review(alert_id, verdict, reviewer)` → `autoclose_reviews` + `triage_labels(source='digest')`, `wrong` → `domain.reopen`, `rule.suspected_wrong` at ≥ 2 `wrong` in 7 days, the 17:00 reminder, CSV output + the `digest` handler module | rest | must | 3.5 h | P5-T01 | no |
| P5-T09 | Admin digest page — one-click `correct | wrong | unsure`, the reopen path through the page, idempotent per day | rest | **should** | 2.5 h | P5-T08, P4-T04 | **yes** — review the first digest |
| P5-T10 | Admin rules screen — create with simulate preview (`SimulateStats`: counts by severity and criticality + 20 samples), toggle enabled, `admin.autoclose_rule_toggled` with before/after, `reload_rules()` on every write, the width warning | rest | **should** | 2.5 h | P4-T04 | **yes** — create the first rule |
| P5-T11 | `infra/health.py` (ten thresholds, one `system_health` row per run, send on state change + 08:05 summary, `health.alarm`) + `infra/notify.py` (`send(level, text)`, Telegram or log sink, never raises) + `GET /health` (loopback open, `admin` otherwise) + the `health` handler module | rest | must | 4 h | P5-T01, §8 answered | **yes** — the bot token |
| P5-T12 | `scripts/restore.sh` + `scripts/backup.sh` extended + the **user crontab** entry (never a compose cron — DEC-018/DEC-021) + tests that a scheduled run produces a file | rest | must | 2 h | — | **yes** — install the crontab line |
| P5-T13 | `docs/runbook.md` — the alarm table (what each threshold means and what to do), backup/restore operation, the empty restore-drill section P8 fills, and the ② operating notes if ② survives | rest | **should** | 1 h | — | no |


### 4.2 · What DEC-108 changes about P5-T02, and the one recommendation that survives the cut

P5-T02 was carded as the head of the ② bundle because DEC-032 amendment (b) and DEC-097 both make the measurement precede any ② work. **With DEC-108 ruling that ② falls, there is no ② work for it to precede**, and by default it is `cut` with the rest of the bundle.

**The recommendation is to keep it anyway, as a standalone `should`.** It costs **1.5 h and < $0.10**, writes no product code, touches no database, and depends on nothing. What it buys once ② is cut is different from what it was carded for but is not smaller: **it is the only measurement of the 60 k class that will ever exist on this project**, and P8's limitations section has to say why ② was cut. *"It was cut under §10's order when the schedule squeezed"* is true and thin; *"it was cut under §10's order, and here is what it would have cost per case at its own prompt size, against a corpus whose largest possible dossier is 12.8 k tokens — 21 % of the budget the design reserved for it"* is the same decision with evidence behind it. The second sentence is also the one that answers the obvious examiner's question about a 60 k budget that was never exercised.

That is a recommendation, not a plan: **the Director decides**, and if the answer is no, T02 is `cut` with T03–T05 and nothing else in this plan moves.

**Why T01 heads two lanes.** `investigate`, `digest` and `health` all need a row in the worker's handler table,
and today that table is one dict literal in one file. One hour spent making it discovered buys three parallel
cards and makes the ② cut a file deletion instead of a merge conflict.

**Why T02 is first inside the bundle and not last.** It is the only card in this phase that answers a question
rather than building something, the question is the one DEC-097 resolves on 25/09, and it costs 1.5 h and
< $0.30 to answer. See §2.

---

## 5 · Environment measured today (23/09), and where it changes a card

| Claim | Measured | Consequence |
|---|---|---|
| `alerts` | **100,526** = `duplicate` 99,920 + `queued_tier1` 606. Heads by agent: `user1-IA1803` 164 (replay) + 58 (wazuh), `IA1803` 125, `HR-computer` 90, `Windows_Endpoint` 84, `DC01` 30, `DESKTOP-MIRSO17` 18, `DESKTOP-4OQGCVD` 16, `wazuh.manager` 11, `kali` 9, `pfSense.home.arpa` 1 | the case a Tier-2 analyst will first see is built from these 606 heads by P4-T03's `escalate`; **`cases` is 0 today**, so every P5 test builds its own case rows |
| `llm_runs` | **1,195** = `triage/proposer` 606 + `triage/verifier` 589. **`investigate` rows: 0** — no ② prompt has ever been sent, exactly as DEC-032 records | T04's tests insert their own `llm_runs` rows; T02's measurement writes **none** (it is `eval/`, it does not touch `soc_dev`) |
| `users` | **4 rows** (P4-T01's seed CLI ran; `JWT_SECRET` is in `.env`) | every page card can assume real accounts exist; T06/T07/T09/T10 carry no seeding step |
| `jobs` | 103,498 rows; `ck_jobs_job_type` already admits `investigate`, `digest`, `health` (migration 016) | no migration; `enqueue` validates against `JOB_TYPES` in `infra/jobs.py:29`, which already lists all six |
| `jobs` single-flight | `ON CONFLICT (job_type, subject_id) WHERE status IN ('pending','running') DO NOTHING` (`infra/jobs.py:76`) | `digest`'s `subject_id` is **the ISO date** (idempotent per day, `prompts/P5.md:55`); `health`'s is the constant **`"system"`**; `investigate`'s is the `case_id` — which is exactly the *"one running per case"* rule, enforced by the index rather than by a query (T04 design note 3) |
| `infra/worker.py` | `run_forever(conn_factory, handlers, *, once, sleep_s, timeouts)`; `Handler = Callable[[Connection, Job], Reschedule | None]`; default statement timeout **3 s** | T01's discovery builds both mappings; `investigate` declares **`"5s"`** and nothing else does (the docstring at `infra/worker.py:12` already predicted this) |
| `domain.conclude_case` | `(conn, case_id, user_id, *, conclusion, reason)`; `StaleState` when the case is not `investigating`; A16 fan-out covers `case_id` heads **and** `duplicate_of IN (…)`; writes `tier2.concluded` with payload `{conclusion, reason}` | T06 maps `StaleState` → **409** and `IllegalTransition` → **500**; the route sets `SET LOCAL statement_timeout = '5s'` first (`docs/phase-7-tier2.md` §Kết luận detail 3 — 5 s, longer than Tier-1's 3 s, because the `UPDATE` touches more rows) |
| the `tier2.concluded` payload | `{conclusion, reason}` — **no** `llm_suggestion` / `llm_confidence`, which `docs/phase-7-tier2.md:317` asks for | **planning decision 4: P5 does not add them.** `domain/transitions.py` is P4-T03's file and P4-T03 is open, so a P5 card touching it violates E5. P8's join reaches the ② suggestion through `llm_runs` (`pipeline='investigate' AND subject_id = case_id`, latest row) — the same place T04 writes it, and richer than two payload keys |
| `ingest/autoclose.simulate` | `(conn, match: list[dict]) -> SimulateStats(clusters, alerts, by_severity, by_asset_criticality, samples)`; 30-day window; hard blocks included; ≤ 20 sample ids | T10 renders exactly these five fields. The brief's *"counts by severity and criticality + 20 samples"* is already the return type |
| `ingest/autoclose.rule_width_report` | `(conn, days=7) -> list[dict]` over `AUTOCLOSE_RULE_WIDTH_PCT`, summing `occurrence_count` | T10 shows it on the rules screen as a width warning; **T08 does not** — `rule.suspected_wrong` is the digest's `wrong`-count trigger, a different signal, and conflating them is the mistake the card names |
| `tier1.queue.latest_suggestion` | `(conn, alert_id) -> Suggestion | None`; `visibility.SHOW_STATES` includes `auto_closed` **for exactly this reason** (P4 planning decision 7) | T08's digest reads ①'s verdict through `latest_suggestion`, not with its own SQL — one function, one place to change |
| `security/wrap.untrusted_block` | `new_nonce()`, `normalise()`, `strip_nonce()`, `truncate_block(text, limit_bytes) -> (text, truncated)` | T03's dossier wraps **every** free-text block through it — including analyst notes and the previous ② result, the two `docs/phase-7-tier2.md:250` flags as easiest to forget |
| `llm.adapter.complete` | `(*, system, user, response_format, timeout_s, model)`; raises `LLMPermanent` when the system prompt lacks the literal `JSON`; enforces the `LLM_TIMEOUT_S` wall-clock deadline (DEC-033) and the monthly cap | T04 inherits the deadline and classifies expiry as **transient** (job retry); `LLM_TIMEOUT_S` is **120 s** because `LLM_THINKING=disabled` is the default (DEC-042) — the 240 s branch of DEC-032 never applied |
| month spend | `audit/llm_runs.month_spend_usd`; ① has spent ≈ $0.28 of the $30 cap | T02's live measurement is bounded by `--max-spend-usd` (P1-T08's precedent) and cannot reach the cap |

---

## 6 · Planning decisions (tactical — the Director may promote any of these to a DEC)

1. **The worker's handler table is discovered, exactly as `web/main.py` discovers routers.** T01 creates
   `backend/app/web/handlers/` with `iter_handlers() -> dict[str, Handler]` and
   `iter_timeouts() -> dict[str, str]`: `pkgutil.iter_modules(__path__)` sorted by name,
   `importlib.import_module` each, and **every** module must expose `JOB_TYPE: str` and `handle` — a module
   without one is an `AttributeError` at import (fail fast, no `try/except ImportError`, the `routers/__init__.py`
   rule and DEC-039's lesson). `STATEMENT_TIMEOUT: str` is optional. The three handlers already on `main`
   (`pull`, `pipeline`, `triage`) move into modules in the same card, each a re-export of the tier function —
   **no tier code moves and no tier file is touched**, so `git diff --stat` on `soar/`, `infra/puller.py` and
   `tier1/triage.py` is empty. `web/worker.py` keeps `HANDLERS` as a module-level name (`HANDLERS = iter_handlers()`)
   so `test_jobs_worker.py` and `test_g7_llm_off.py` keep importing what they import. **Why:** three P5 cards need
   a handler row; the alternative is three cards editing one dict literal, which is the collision E5 forbids and
   DEC-038 had to serialise in P2 — and after the ② cut it would be a conflict in a file two surviving cards own.
2. **The case detail page has a seam, and the ② half lives on the far side of it.** T07 (not in the bundle)
   writes `templates/case.html` containing, at the point where the ② result belongs, exactly:
   `{% include "_investigation.html" ignore missing %}`. T05 (in the bundle) creates `_investigation.html` and
   the routes that feed it. With the bundle cut the include renders nothing and the page is a complete case
   screen with notes and a conclude form; with the bundle present it renders the ② block, the evidence marks
   and the "analysing…" poll target. **`ignore missing` is the whole mechanism** — it is one Jinja token, it is
   tested from both sides (T07 asserts the page renders with the partial absent; T05 asserts it renders with the
   partial present), and it is what makes DEC-097's *"separable rather than woven through"* true in the code
   rather than in a sentence.
3. **`GET /health` is open from loopback only, and it is the one unauthenticated route P5 adds.** §6.4 writes
   *"`GET /health` (no auth from localhost)"*. T11 implements it as: `request.client.host` in
   `{"127.0.0.1", "::1"}` → 200 with the last `system_health` row; anything else → the `require_role("admin")`
   dependency. It is **not** a blanket exemption and it is **not** a new config key; the allowlist is two
   literals with a comment naming §6.4. A `403` for a non-loopback caller without a session is the tested case.
4. **`domain/transitions.py` is untouched by this phase.** See §5. `tier2/conclude.py` guards and translates;
   it does not reimplement the fan-out, and the ② suggestion reaches P8 through `llm_runs`, not through the
   audit payload.
5. **The digest is two cards, split on the §10 cut line.** T08 is the job, the daily build, the CSV and
   `rule.suspected_wrong` — everything §10's *"digest UI (CSV instead)"* keeps. T09 is the page, the one-click
   review and the reopen path — everything §10 cuts. `digest.review(alert_id, verdict, reviewer)` lives in
   **T08's** `tier1/digest.py` (it is the domain call, and the CSV path needs it too); T09 is a screen over it.
   So the second cut in §10's order is also a whole card, not half of one.
6. **One notifier, one sink, and it never raises into the caller.** `infra/notify.py` exposes
   `send(level, text) -> bool`; it selects Telegram when `NOTIFY_TELEGRAM_BOT_TOKEN` **and** `NOTIFY_TELEGRAM_CHAT_ID`
   are both non-empty, and otherwise logs a structured line and counts it. Failures are caught, logged and
   counted — `prompts/P5.md:54`: *"`notify.send` never raises into the caller"*. The SMTP arm is §8's INBOX item.
   **The `log` sink is not a stub:** on this host, today, it is the only sink there is, and the health job must
   be demonstrable without a bot token.
7. **The health job sends on state change, never every five minutes.** One `system_health` row per run;
   `notify.send` only on `ok → alarm` and `alarm → ok` transitions, plus one daily summary at 08:05 —
   `prompts/P5.md:56`. The previous state is read from the newest `system_health` row, so a worker restart does
   not re-alarm. The alarm also writes `health.alarm` to `audit_events` (the event type exists).
8. **The ② measurement prompt is synthesised to the budget, and the card says why in the card.** See §1 row 1.
   T02 builds a real nine-block dossier shape from real alerts and pads `raw_log` blocks (reusing
   `eval/smoke_test.py:648`'s `pad_raw_log` idea, not the function) until the tokenised prompt is within 2 % of
   `CASE_PROMPT_BUDGET_TOKENS`. The report states **both** numbers — the 60 k synthetic measurement and the
   12.8 k real-corpus ceiling — because the second is the one that says what ② will actually cost in this
   deployment, and reporting only the first would be a different way of measuring the wrong thing.
9. **The analyze quota is counted from `llm_runs`, not from a new table.** `ANALYZE_QUOTA_PER_USER_DAY = 30`;
   the count is `llm_runs` rows with `pipeline='investigate'` whose triggering `case.analyzed` audit row names
   the actor, in the last 24 h — one SQL, no schema change, and it survives a worker restart. **429** on exceeded,
   **409** on a case already running (the `jobs` single-flight index, §5), **202** otherwise.
10. **Nothing in P5 modifies a file an open card owns.** Verified path by path in §9 against P3-T11, P4-T03,
    P4-T04, P4-T05, P4-T06, P4-T08, P6-T02 and P6-T06. Four P5 cards modify files that exist on `main` as
    one-line skeletons (`tier2/dossier.py`, `tier2/investigate.py`, `tier2/conclude.py`, `llm/investigate.py`,
    `tier1/digest.py`, `infra/health.py`, `infra/notify.py`) — all seven are unclaimed.

---

## 7 · Exit-gate coverage

`prompts/P5.md:48` — *"② runs on a real case with evidence check; digest reviews an auto-closed cluster and
reopens it; health alarm fires with the indexer unreachable; a backup file is produced."*

| Gate item | Covered by | Notes |
|---|---|---|
| ② runs on a real case with evidence check | **T03** (dossier) + **T04** (job, evidence check, `need_more_data`) + **T05** (the screen) | **Conditional on DEC-097.** "A real case" needs a case, and `cases` is 0 — P4-T03's `escalate` produces the first one. If ② falls, this gate item falls with it and the phase gate becomes 3/4 by decision, not by failure — say so in STATE rather than leaving it red |
| digest reviews an auto-closed cluster and reopens it | **T08** (`digest.build`, `digest.review`, reopen through `domain.reopen`) + **T09** (the one-click page) | **There are 0 auto-closed alerts and 0 rules today** (§1). The `db` test creates the cluster; the *live* proof needs the Owner to add `Windows_Endpoint` to the inventory and create one rule through T10's screen. Both are on the Owner list in §10 |
| health alarm fires with the indexer unreachable | **T11** acceptance 3 | Proved with a **stale `source_heartbeat` row** in a `db` test — the check is `now() - last_seen_at > HEARTBEAT_MAX_AGE_MIN`, which is what "the indexer stopped sending" means in this system. **No card touches the indexer** (rule 5); on this host the host-side path is dead anyway (DEC-106) |
| a backup file is produced | **T12** | `scripts/backup.sh` already writes one; T12 adds `restore.sh`, the schedule, and the test that the schedule's command actually produces a file. The gate is met by **yesterday's file existing in `backups/`**, not by reading the unit (`prompts/P5.md:37`) |

---

## 8 · INBOX items raised by this plan

- **`2026-09-23 · P5-T11 · DECISION_REQUEST` — the notifier's second arm.** §6.3 writes
  `NOTIFY_TELEGRAM_BOT_TOKEN  NOTIFY_TELEGRAM_CHAT_ID  (or NOTIFY_SMTP_*)`, and `prompts/P5.md:35` asks for
  *"one adapter, env-selected"*. Measured 23/09: `infra/config.py` reads the **two Telegram keys and no SMTP
  key** (`grep -c NOTIFY_SMTP backend/app/infra/config.py` → `0`); the six SMTP names sit commented at
  `.env.example:139-144` with a note that they stay prefixed *"so the §6.3 completeness check keeps reading
  them as absent"*. Implementing the SMTP arm therefore means **six new §6.3 keys** — a frozen-contract change,
  and rule 4's stop condition. Options: **A (recommended)** — Telegram plus a structured-log sink, no new key:
  `send()` picks Telegram when both Telegram keys are non-empty and otherwise logs and counts, so the health
  job is demonstrable on a host with no bot token (which is this host, today), and the SMTP arm is recorded as
  not implemented in the P8 limitations. **B** — add the six `NOTIFY_SMTP_*` keys to §6.3 and `config.py`,
  regenerate `.env.example`, and implement both arms: one more sink nobody on this project has credentials for,
  against a frozen contract, in a phase with no day allocated. Frozen contract affected: **§6.3 under B, none
  under A.** T11 is written for **A**; under B its Files list gains `backend/app/infra/config.py` and
  `.env.example` regenerates from it (`make lint` gates that), and the estimate goes 4 h → 5 h.
  **Needed by:** T11's dispatch.

- **`2026-09-23 · P6 / gold build · NOTE` — a correction to DEC-108, not a blocker.** The same archive gap was found here while reading DEC-097 as this brief instructs; **the Director found it first and ruled the same morning** (DEC-108, option A). One sentence of that ruling is falsified by measurement — the 19 parser-rejected lines **were** stored, in `intake.raw_text`, which is what G9 exists for — and a rebuild from `intake` reproduces the original archive byte for byte (92,030 rows, 113,287,874 bytes, + one newline each = 113,379,904). Consequence is confined to the provenance line DEC-108 binds to be committed verbatim. **No P5 card depends on it.**

---

## 9 · File-list disjointness — every path this phase claims, checked against the eight open cards

| Card | Creates | Modifies |
|---|---|---|
| T01 | `backend/app/web/handlers/{__init__,pull,pipeline,triage}.py`, `backend/tests/test_worker_handlers.py` | `backend/app/web/worker.py` |
| T02 | `eval/investigate_measure.py`, `docs/investigate-size-class.md`, `backend/tests/test_investigate_measure.py` | — |
| T03 | `backend/tests/test_dossier.py` | `backend/app/tier2/dossier.py` |
| T04 | `backend/app/web/routers/tier2_runs.py`, `backend/app/web/handlers/investigate.py`, `backend/tests/test_investigate.py` | `backend/app/llm/investigate.py`, `backend/app/tier2/investigate.py`, `backend/app/llm/templates/investigate_system.txt` |
| T05 | `backend/app/web/templates/_investigation.html`, `backend/app/web/routers/case_analyze_pages.py`, `backend/tests/test_pages_investigation.py` | — |
| T06 | `backend/app/web/routers/tier2.py`, `backend/tests/test_conclude.py`, `backend/tests/test_tier2_api.py` | `backend/app/tier2/conclude.py` |
| T07 | `backend/app/web/routers/cases_pages.py`, `backend/app/web/templates/{cases,case,_case_notes}.html`, `backend/tests/test_pages_cases.py` | — |
| T08 | `backend/app/web/handlers/digest.py`, `backend/tests/test_digest.py` | `backend/app/tier1/digest.py` |
| T09 | `backend/app/web/routers/admin_digest.py`, `backend/app/web/templates/digest.html`, `backend/tests/test_pages_digest.py` | — |
| T10 | `backend/app/web/routers/admin_rules.py`, `backend/app/web/templates/rules.html`, `backend/tests/test_pages_rules.py` | — |
| T11 | `backend/app/web/handlers/health.py`, `backend/app/web/routers/health.py`, `backend/tests/test_health.py`, `backend/tests/test_notify.py` | `backend/app/infra/health.py`, `backend/app/infra/notify.py` |
| T12 | `scripts/restore.sh`, `conf/soc-backup.cron`, `backend/tests/test_backup_restore.py` | `scripts/backup.sh` |
| T13 | — | `docs/runbook.md` |

**Against the open cards.** P3-T11 owns `backend/tests/test_triage_live.py`, `eval/triage_live.py` and the
deletion of the top-level `llm/` directory — **not** `backend/app/llm/`, which is where T04's template lives.
P4-T03 owns `web/routers/tier1.py`, `tier1/decide.py`, `domain/transitions.py`. P4-T04 owns `web/templating.py`,
`templates/{base,login,_flash}.html`, `web/routers/pages.py`, `backend/requirements.txt`. P4-T05 owns
`web/routers/alerts_pages.py` and `templates/{queue,alert,_decision_form,_suggestion}.html`. P4-T06 owns
`backend/tests/test_e2e_tier1.py`. P4-T08 owns `web/routers/webhook.py` and `infra/intake.py`. P6-T02 owns
`tier1/labels.py`, `web/routers/labels.py`, `templates/labels.html`, `backend/tests/test_labels.py`. P6-T06 owns
`eval/build_gold.py`, `backend/tests/test_build_gold.py`, `eval/gold_coverage.md`. **No path above appears in
any of those lists**, and no two P5 cards share a path. `backend/requirements.txt` is claimed by P4-T04 and by
no P5 card — **P5 adds no dependency** (the notifier uses `httpx`, already pinned and already used by the puller).

---

## 10 · Owner actions this phase (one line each, only what a human can do)

1. **Name P5's window.** There is no P5 day in the schedule (§2). The recommendation is the labelling days
   **26–27/09**, when the agent slots are idle because the work is human.
2. **A Telegram bot token and chat id** into `.env` (`NOTIFY_TELEGRAM_BOT_TOKEN`, `NOTIFY_TELEGRAM_CHAT_ID`) —
   until they are set, T11's alarms are logged and counted, never delivered. Check:
   `grep -c '^NOTIFY_TELEGRAM_BOT_TOKEN=.\+' .env` → `1`.
3. **`Windows_Endpoint` into `conf/inventory.yaml`** — already open, and it is what unblocks the digest: until
   it lands, G8′ hard-blocks 86 % of the live stream and the digest has nothing to review. Check:
   `.venv/bin/python -c "import sys;sys.path.insert(0,'backend');from app.enrichment.inventory import validate;print(validate() or 'OK')"`.
4. **Create one auto-close rule** through T10's screen (after T10 merges) so the digest's exit-gate item has
   live content, and **review the first digest** — `prompts/P5.md:59`.
5. **Run one manual `POST /api/tier2/cases/{id}/analyze`** on a real case — the ② gate item, and only if ②
   survives 25/09.
6. **Install the backup schedule** T12 writes (`crontab -l` must show the line; a user crontab needs the
   Owner's own account, not an agent's).

---

## 11 · Hand-off to P7 and P8

1. **P7's ablation is untouched by this phase.** No P5 card changes the eval cache key, `LLM_THINKING`, or any
   prompt ① sends. T04 adds a **second** `prompt_version` lineage (`investigate_v2`); P7's B0–B4 read `triage`
   rows and are unaffected.
2. **P8's restore drill starts from T12.** `scripts/restore.sh` + the schedule + a dump in `backups/` dated
   within 36 h is the precondition; the drill itself (restore into an empty database, run the DB suite, write
   the ten-line record into `docs/runbook.md`) is P8's, and T13 leaves the section headed and empty for it.
3. **P8's ② numbers, if ② survives**, come from `llm_runs` where `pipeline='investigate'`: `evidence_check`,
   `cost_usd`, `stopped_by`, `input_tokens`/`output_tokens`, `latency_ms`. **T02's report is the sizing
   evidence either way** — if ② is cut, `docs/investigate-size-class.md` is what the report cites for *why*,
   and it is the only measurement of the 60 k class that will ever exist on this project.
4. **Limitations this phase produces for P8:** `system_health.checked_at` is the primary key, so two health
   runs in the same microsecond collide (migration 015 note 5 — recorded, not fixed); the notifier has one
   sink and no SMTP arm (§8); `GET /health` trusts `request.client.host` for the loopback exemption, which is
   correct behind no proxy and would need revisiting behind one; the digest's daily volume is bounded by the
   77 heads that are not hard-blocked, and is **zero** until the inventory gains `Windows_Endpoint`; the real
   corpus cannot produce a dossier above ≈ 12.8 k tokens, so `CASE_PROMPT_BUDGET_TOKENS = 60_000` is a ceiling
   this deployment never approaches.
