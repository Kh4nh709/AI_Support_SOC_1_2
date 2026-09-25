# P6 · Lab data + labeling — task cards

Phase objective: build and freeze the gold sets G1 (history), G2 (lab), G3 (adversarial) with bias
controls, and hand the Owner a lab runbook and a labelling-day plan that make the human work fast
and bias-controlled.
Written **16/09/2026** (Planner P6), against `prompts/P6.md` as amended through 15/09 (DEC-084 is in
it) **and** against DEC-082/083/084 in full, which the brief cites but cannot carry. Where a DEC and
the brief disagree, the DEC wins and the divergence is named in §1.

**DEC-007 item 7 / DEC-009 — which copy of a card is authoritative.** Each task has a full
`docs/plan/tasks/P6/<TASK_ID>.prompt.md` and a shorter entry in this file. **The prompt is the
card**; this file is the Planner's index — estimates, waves, dependencies, risk notes, the labelling
day plan and the hand-off. Where this file restates an acceptance command it matches the prompt
verbatim or does not appear. A divergence is a Director defect, not a Coder's judgement call.

---

## ⚠️ Budget note — `must` is 20.5 h against the brief's ≈ 1 agent-day; wall-clock ≈ 10 h at three coders

| | |
|---|---|
| Sum of `must` estimates | **20.5 h** (5 cards; the brief's T06 report generator is folded into T03 — planning decision 6) |
| Day budget (`prompts/P6.md`: 3 days, ≈ 1 day agent work) | 8 h agent |
| Overbooking | **+156 %** against the 8 h agent day (20.5 h where the × 1.3 rule allows 10.4 h) — the re-plan threshold is 30 %, so this note is required and present |
| Wall-clock at the 3-coder cap | **≈ 10 h** — wave 1 (T01 ‖ T04 ‖ T05) ≈ 5 h, wave 2 (T02 ‖ T03) ≈ 4.5 h |
| Calendar available for the code | **16/09 → 23/09** — three of the five cards depend on nothing outside `main` today and can fill idle slots during P3/P4/P5 and the 20–21/09 buffer (DEC-071); T02 waits for P4 (18/09); T03 for T01 |
| Human days | 22–25/09 lab (Owner) · 26–27/09 labelling (two people) · 27/09 evening adjudication · 28/09 freeze — **none of these are agent hours and none moves** (DEC-071) |
| `should` | per-category κ inside T03 (the brief's own cut candidate); "undo last label" inside T02; ART test-id citations inside T05 (cited only where verifiable, never invented) |

**What the arithmetic means.** The 20.5 h are not a problem of the 22–25/09 window: they are
spread over the week before it. T01, T04 and T05 are dispatchable **today** (§2); T02 the day P4
merges; T03 the day T01 merges. If every card lands by **23/09** the human schedule holds with two
spare days. **Nothing in this phase is proposed for a cut today.** The brief's two cut candidates are
pre-cut into `should` (per-category κ) or are Owner-side ("G2 category coverage below 8 — report what
exists", which `build_gold.py` does by construction: a category with no lab cluster gets a zero row,
never a synthetic one — `01-plan.md:125`, `director.md`'s incident table).

**Does T01 fit the 25/09 window? Yes, with margin, and here is the arithmetic.** T01 is 5 h of code
whose only inputs are on `main` and on this host today (`eval/dedup_verify.py` @ P2-T15, the archive
at `/home/user1/archive/alerts-2026-08-08_09-07.jsonl`, 113,379,904 bytes, readable by `user1`). The
G1 half **runs in under a minute** (`eval/dedup_verify.py` over the 92,030-line archive: 23.1 s wall-clock here on 16/09, verdict `3051 vs 3070 (-0.62%) — PASS`) and does
not wait for the lab at all — the Coder runs it as an acceptance and commits G1's files on the task
branch. The G2 half is one more invocation on **25/09 afternoon**, after the last lab window is
tagged; it is bounded by the lab, not by the code. **Latest safe dispatch for T01: the morning of
22/09** (5 h + one review round + merge by 23/09 leaves 24/09 for the Owner's INBOX answer on the
sampling parameters and a re-run). Dispatching it this week removes the question.

---

## 1 · What changed since the brief — and the three things the brief cannot know

The brief was rewritten in place through 15/09 and already carries DEC-052…DEC-071 and DEC-084's
one-paragraph summary. Three things sit outside it and shape every card:

| Fact | Where it comes from | What it changes |
|---|---|---|
| **G1 is built from the offline fold, not from `alerts` (DEC-084, Route A, Owner 15/09).** The database's 307 replay heads are not G1 and are never quoted as a cluster count. G2 still comes from `alerts` (`source='lab'`), correctly — the lab runs in real time, so `now()`-anchored dedup is its right clock. | DEC-082 → DEC-084; `P2-tasks.md:270-275` predicted the 307 | T01's source; T02 reads two shapes of cluster (a fold cluster from a file, a DB cluster from `alerts`); P7's facts for G1 come from the file, not from `alerts.occurrence_count` (§12) |
| **What T01 must build, measured 16/09 on `main`:** `eval/dedup_verify.py` is read-only (`read_archive`, `fold_clusters`, `build_report`, `format_text/json`; no `psycopg`), and its `Cluster` holds `key, first_seen, last_seen, count, closed_by` — **no member-alert ids**. `eval/build_gold.py` is a one-line docstring. So T01 has two halves DEC-084 names: (a) emit per-cluster membership from the fold; (b) materialise the clusters where the labelling page can read them. | `eval/dedup_verify.py:83-95`, `eval/build_gold.py` (96 bytes) | T01 is written from scratch; planning decision 1 says what "materialise" means (files, not a table) and why |
| **Dates are fixed and tight (DEC-071):** lab 22–25/09; **labelling 26–27/09 (Sat–Sun), two people, blind, cannot move earlier** because the labelling page needs P4 (18/09); labellers booked by name on 20/09; gold freeze 28/09; P7 29/09. | DEC-071, `01-plan.md:13`, `STATE.md` Owner action dated 20/09 | §4's calendar; the Owner-action list in §11; the labelling day plan in §10 |

**And the fold's own numbers, measured 16/09 with `eval/dedup_verify.py`'s functions on the archive
(`config.load(env_file=".env")` ceilings 15 min / 4 h / 1000):** 92,030 lines · **92,011 parsed** ·
19 rejected (`rule.description`) · **3,051 clusters** · 30.2 : 1 · severity critical 25 · high 150 ·
medium 1,695 · low 1,181 → **crit+high 175** · category `unknown` 1,801 · `ssh_brute_force` 968 ·
`suspicious_login` 174 · `privilege_escalation` 108 (resolver `v3.2`, so `web_attack` is 0 — DEC-055)
· agents `IA1803` 1,970 · `user1-IA1803` 991 · `DESKTOP-MIRSO17` 23 · loopback `ssh_brute_force`
from `127.0.0.1` **67 clusters / 662 alerts** (10 critical, 28 high, 29 medium) → **G1 pool after the
DEC-053 exclusion: 2,984 clusters**, of which crit+high **137** (94 `unknown`, 43 classified).
**Denominator rule (DEC-052):** the published 1,812 / 1,820 `unknown` and the 3,070 come from
`scripts/measure_clusters.py`'s archive-order fold; this phase's are from `dedup_verify.py`'s
`alert_time`-sorted fold with the product parser (19 lines rejected). Both are right; each figure is
quoted with its own denominator and the two are never quoted against each other. **G1's denominator
from here on is 3,051 (DEC-084: "G1 and the verification become one measurement").**

**Stop condition (`prompts/P6.md:48`): cannot fire.** The G1 pool is 2,984 ≥ 200 before any lab
alert exists. Stated with the number rather than assumed.

**The pool grid the allocator sees (after the loopback exclusion; denominator 2,984):**

| category | critical | high | medium | low | total |
|---|---|---|---|---|---|
| `unknown` | 14 | 80 | 838 | 869 | 1,801 |
| `ssh_brute_force` | 1 | 11 | 817 | 72 | 901 |
| `suspicious_login` | 0 | 0 | 0 | 174 | 174 |
| `privilege_escalation` | 0 | 31 | 11 | 66 | 108 |

**STATE.md `## Agent actions` rows addressed to Planner P6 — swept, with the verdict:**
- **Planner P6 (DEC-035)** — say whether `lab` is tagged by widening `intake.via` or by adding `intake.source`, with an INBOX item: **absorbed as neither**, planning decision 3 + INBOX `2026-09-16 · P6 / lab tagging · DECISION_REQUEST` (option D: post-hoc time-window retag; the lab host is the production host, `docs/lab-run-log.md:8-11`, so no agent-name rule can separate them and no intake-time column can carry what is only known after the scenario ran). T05 carries the code.
- **Planner P6 (DEC-014)** — size G1 on the real cluster count, no padding: **absorbed**, T01 sizes G1 against the fold's **3,051 / pool 2,984** (not 3,070, and not the database's 307), target 300, floor 200; the stop condition cannot fire.
- **Planner P6 (DEC-012)** — do not size the 400 as if both agents feed the digest: **absorbed**, §10 — the 400 gold labels are all `triage_labels(source='gold_offline')` from the blind page; digest labels (`source='digest'`, agent 001 only, P5) contribute **zero** to the 400 and are not a gold source; the sample is G1 300 + G2 100 and the only shortfall that can exist is G2's, made up from G1 (pool 2,984) as the card says.
- **Planner P4/P6 (DEC-019)** — the forbidden-content test carries `source` with `replay`/`wazuh`/`lab`: **absorbed**, T02 design note 4 and acceptance 3 (the denylist includes exactly those tokens as *field values*, with the two free-text SIEM fields exempted and exercised).

---

## 2 · Dispatch state — read this before dispatching anything

**Precondition for T01, T04, T05: none.** Measured on `main` @ `319a10a` (16/09): P2 is closed
(DEC-079) — `eval/dedup_verify.py`, `ingest/wazuh_parser.py`, `ingest/category.py` (`v3.2`),
`domain/transitions.py`, `enrichment/lookups.py`, `soar/pipeline.py`, `soar/risk.py`,
`audit/events.py` are all on `main`; migration 015 (`triage_labels`) is applied. `git branch` has no
`task/P6-*`. P3-T02, T03, T06…T12 and P2-T07 are open on their own files; none of them touches a P6
file (§9's file table).

| | |
|---|---|
| Dispatchable now | **P6-T01** (5 h, chain head — dispatch first), **P6-T05** (3 h — its runbook must be on `main` before 22/09), **P6-T04** (3.5 h) |
| After P6-T01 merges | **P6-T03** (4.5 h) |
| After P6-T01 **and** P4's auth + visibility filter + base layout merge | **P6-T02** (4.5 h). P4 is not carded yet (`docs/plan/tasks/P4/` does not exist); the Director maps "P4 auth / `tier1/visibility.py` / base layout" to the P4 Planner's task ids when they exist. T02 also touches `backend/app/web/main.py` (one `include_router` line) — sequence it after any P4/P5 card on that file, or accept a one-line merge |
| Blocked on an Owner action | **nothing on the code.** T01's **G2 run** (25/09) needs the lab windows tagged; T03's runs (27–28/09) need the labels; T04's **loader run** happens in P7, never before |
| INBOX items this plan raises (§8) | two — the lab-tagging mechanism (closes DEC-035's open half; Director's to decide, no frozen contract) and the G1 sampling parameters (Owner's — evaluation validity; a default applies if unanswered by 24/09) |

---

## 3 · Rules every card follows (so the Reviewer can grep for them)

1. Every pytest line is `python3 -m pytest -c backend/pyproject.toml …` (DEC-005). Every db-marked line sets `TEST_DATABASE_URL=postgresql:///soc_p6t<nn>_test` inline, passes `-rs`, adds no `-q`, and states `N passed` with **`skipped` absent for that file** (DEC-023 item 8). Whole-suite runs (`make test`, `make test-db`, `make lint`) are judged on **exit 0** — `make test` carries `test_dispatch_state.py`'s off-`main` skip on every branch (DEC-080).
2. A named test is grepped with `-vv` (never `-v`: `addopts = -q` nets it to verbosity 0 — DEC-074).
3. Every acceptance names its **red step**, and the red step discriminates (DEC-025, DEC-077).
4. **No test touches the network, the indexer or DeepSeek.** The labelling page, the loader and the tagger are tested on `soc_p6t<nn>_test` with fixture alerts inserted through `domain.transitions.open_alert`; the fold is tested on JSONL files built in `tmp_path` from `backend/tests/fixtures/archive_line_5503.json` (the P2-T15 pattern).
5. No test reads the real `.env` except by naming it (DEC-047). No test uses the `db` fixture against a database not named `*_test`. **No card, no test and no script ever writes to `soc_dev` from a worktree** — the three Owner-run commands (`build_gold.py --g2`, `lab_tag.py`, `label_export.py`) run from the primary checkout with `.env`, and the cards say so.
6. `sklearn`, `numpy`, `pandas` are not imported anywhere — none is in `backend/requirements.txt`; κ is the ten-line 3 × 3 formula (`prompts/P6.md:31`), CSV is `csv`, randomness is `random.Random(seed)`.
7. Import rules hold (`ALLOWED` in `test_import_rules.py`): `tier1 → domain|llm|kb|security|infra|audit`, `web → everything`, `eval → everything`, **nothing in `backend/app/` imports `eval/`**. Consequence (planning decision 1): the labelling page reads `eval/gold_candidates.csv` and `eval/g1_clusters.csv` as **data files** through a repo-root path, exactly as `kb/lookup.py` reads `kb/` (P3 planning decision 5); it imports no module from `eval/`.
8. **Every acceptance in a card that reads `alerts` uses an explicit column list** (G10: no `SELECT *` on `alerts`), and the labelling page's list is an allowlist that a test pins (T02 design note 3).
9. `superseded.yaml` scans these cards (DEC-049). No bare `pytest`, no dead migration ranges, no retired host or service names, no withdrawn severity band, the dead cluster's port never named as live.
10. Seed all randomness with `EVAL_SEED = 20260904` (`prompts/P6.md:32`): a module constant in `eval/build_gold.py` and `LABEL_ORDER_SEED = 20260904` in `backend/app/tier1/labels.py` (two literals because rule 7 forbids the import; each carries a comment naming the other).

---

## 4 · Critical path, waves and the calendar

Estimates are for the card as written; dependencies are the `Depends on:` field of each prompt, and
where this diagram and a field disagree, the field wins (DEC-007 item 6). Review/merge cycles are
counted as zero, which they are not (DEC-048: batch them).

```
code (fills idle slots 16/09 → 23/09; three sessions max, shared with P3/P4/P5)
  wave 1   P6-T01 build_gold (5)     P6-T05 runbook + lab_tag (3)     P6-T04 adversarial (3.5)
  wave 2   P6-T03 label_export (4.5) ←T01          P6-T02 labelling page (4.5) ←T01, P4
humans (dates fixed by DEC-071)
  20/09    Owner books the two labellers by name (STATE.md); creates the advisor's admin account (P4 seed CLI)
  22–24/09 Owner runs docs/lab-scenarios.md (T05): attack + benign windows, seconds logged, lab_tag.py after each window
  25/09    Owner: last windows + lab_tag.py → build_gold.py --g1 --g2 → commit eval/gold_candidates.csv + coverage
  26/09    labelling session 1 (~200 clusters each, independent)         27/09 session 2 + adjudication meeting
  28/09    label_export.py kappa → disagreements → freeze → report → commit gold_v1.csv + .sha256   (gate)
  29/09    P7 — and only now: eval/adversarial/load.py (G3 enters the database)
```

**Why T01 heads everything.** T02 renders what T01 writes, T03 exports what T02 writes against
T01's candidate list, and the 25/09 run is T01's. Its 5 h are the only agent hours that sit on the
human critical path, and they sit there a week early — hence "dispatch first".

**Why T05 is `must` and early.** The runbook is what the Owner executes 22–24/09; a scenario run
without its expected rule ids and its window logged is lost for G2 (`docs/lab-run-log.md:12-14`). And
`eval/lab_tag.py` is the tag itself (planning decision 3) — without it, no row is `source='lab'` and
`build_gold.py --g2` refuses to select (exit 3, by design).

**Why T04 is early although its data enters the database last.** The fixtures and the manifest
are code and tests with no dependency; the **loader run** is a P7 step (standing rule: G3 is never
shown to the model before evaluation, and the loader is the only way it could be). Writing it now
means P7 starts on 29/09 with G3 ready and tested, not written that morning.

---

## 5 · Environment measured today (16/09), and where it changes a card

| Claim in the brief or a spec | Measured | Consequence |
|---|---|---|
| `eval/dedup_verify.py` reproduces DEC-053's 3,070 | **3,051** clusters from 92,011 parsed lines; `--expect 3070` → `-0.62 %`, PASS (DEC-077) | G1 = 3,051; the members the fold does not keep are T01's first half |
| Fold `Cluster` fields | `key, first_seen, last_seen, count, closed_by` — no ids; `fold_clusters` sorts by `(alert_time, alert_id)`, so the first alert of a cluster is its head by construction | T01 adds `members: list[str]` (head first); `count == len(members)` becomes a test |
| The fold's head alert is in `alerts` | every parsed archive line was ingested as `source='replay'` — `alerts` = 92,011 replay rows (DEC-079); the parser is the same, so the 19 rejected lines are the same 19 | `triage_labels.alert_id` **FK → `alerts(alert_id)`** (migration 015:59) holds for every fold head; T01 verifies it by SQL as an acceptance (`--check-db`) |
| `alerts.first_seen_at` / `last_seen_at` / `occurrence_count` on replay rows | DB-clock values from the replay afternoon (`dedup.py:105` writes `now()`); `occurrence_count` max **1000** on 307 heads | **Never shown, never used for G1.** Cluster-level numbers come from T01's files for G1 and from the DB for G2 (`max(alert_time)` over members, clock-free) |
| `domain/correlation.py` (P2-T07, open) | windows use `alert_time`; rows exclude duplicates (`duplicate_of IS NULL`), so on the replayed corpus it sees 307 heads, not 3,051 clusters; `CorrelationRow` carries `status` | For **G1** the page computes ±2 h correlation from `eval/g1_clusters.csv` (same three-way OR, over fold clusters); for **G2** it calls `summarize_for_prompt` and **drops `status`** (a pilot decision is human context the labeller must not see) |
| `triage_labels` | `PK (alert_id, labeler_id, source)`, `source ∈ gold_offline\|digest\|disagreement\|lab`, `label ∈ false_positive\|benign\|escalate`, `confidence text` (no closed set — migration 015 note (1)), `note text`; `labeler_id` FK → `users` | one row per labeller per cluster; a second POST is `409`, never an overwrite; `confidence` is stored as `'1'\|'2'\|'3'`; adjudicated labels get `source='disagreement'` (the value exists for this) |
| `audit_events.event_type` CHECK | carries `label.created` | `POST /api/admin/labels` writes it (architecture §5: every `admin.*` write is audited) — payload without the other labeller's label |
| `alerts.is_synthetic` | phase-1 §:82: *"true for alerts injected by a test-data script … excluded from every reported figure"*; the queue query (`phase-6-tier1.md:37`) and auto-close stats filter `NOT is_synthetic` | G3 rows are loaded with `is_synthetic = true`: invisible to the pilot queue, the digest and every reported figure; visible to P7 by `alert_id` from the manifest |
| Lab host | the only Linux agent on the rebuilt stack is **`user1-IA1803` (agent 001)** — 370 of 2,699 documents in the 14/09 sample (INBOX 14/09 part 1); `HR-computer` is Windows, `wazuh.manager` is the manager | every scenario in T05 runs on `user1-IA1803`; `docs/lab-run-log.md:8`: **the lab host is the production host**, so `source='lab'` is a time window, never an agent-name rule (planning decision 3) |
| `conf/local_rules.xml` on the manager | rules `100301` (T1486, level 12), `100302` (T1041/`exfiltration`, level 10), `100303` (T1071, level 12), `100999` — loaded and `100999` firing on a 600 s cadence (DEC-068); indexer `_count` with `{"query":{"prefix":{"rule.id":"1003"}}}` → **0 because no scenario has run** (was a `grep -c` on `alerts.json` until 19/09 — that file is unreadable by `user1` since the reboot; DEC-091 moved every check to the indexer) | T05's scenarios for `ransomware`, `data_exfiltration`, `c2_beacon` are written against those three rules' match conditions (auditd execve; `openssl enc -k`, `curl -T/-F @file`, `bash -c 'exec 3<>/dev/tcp/…'`), each with the benign twin that must **not** match |
| Inventory in `soc_dev` | `assets` 4 (`user1-IA1803` medium, `IA1803` high, `wazuh.manager` high, `HR-computer` medium), `identities` 2 (`root` privileged, `user1` not), `iocs` 0 (DEC-083) | G3's base alert is a `user1-IA1803` / `user1` / public-`srcip` / level-5 document so that `false_positive` is **structurally reachable** under `sbf-1` (T04 design note 2) — otherwise ASR would be 0 by construction and measure nothing |
| `kb/decision_tables/*.yaml` | not on `main` yet (P3-T06 `todo`); when merged, `reviewed_by: null` until the Owner's sitting | B1 on the frozen gold set needs authored tables (P7's dependency, not this gate); the G3 base is chosen so `sbf-1` from architecture §3.10 admits FP once the table is authored |
| Per-cluster labelling time | architecture §6: ~1 min/cluster → 400 clusters ≈ 7 h per person | two sessions of ≈ 200 (§10); `raw_log` p95 on the queue is 603 chars, so the page is one screen per cluster |

---

## 6 · Planning decisions (tactical — Director may promote to a DEC)

1. **"Materialise the clusters where the labelling page can read them" = two committed files under `eval/`, not a table.** `eval/g1_clusters.csv` (one row per fold cluster, 3,051 rows: `cluster_id` = head `alert_id`, key columns, `first_seen`, `last_seen`, `occurrence_count`, `closed_by`, `excluded_reason`) and `eval/g1_members.csv.gz` (`cluster_id, alert_id, alert_time` — 92,011 rows, gzip because 2.8 MB of plain text is not worth a public remote's history); the sample is `eval/gold_candidates.csv`. **Why files:** a `gold_clusters` table is a §6.1 change — migration 018, an Owner decision and a Coder round on the phase's only critical-path card — for nothing the page cannot read from a 3,051-row CSV in milliseconds; the files are what gets frozen (`sha256` in git), so G1's clustering is reproducible from the commit alone; P7 reads the same files for facts (§12); and `kb/` set the precedent for app code reading repo-root data by path (P3 planning decision 5). The page resolves `REPO_ROOT / "eval" / …` from `backend/app/tier1/labels.py`'s own location, overridable for tests. **What a file does not give:** SQL joins — P7's harness joins by `alert_id` in Python, which it does anyway for the cache.
2. **The G1 allocator, parameterised, with Director-chosen defaults pending the Owner's answer (INBOX §8 item 2).** Strata are `category × severity` on the DEC-053 band. Rule 1 (`--take-all-crit-high`, default on): every `critical`/`high` cluster of the pool enters the sample — 137 today (A1: the only design in which n_pos can pass 50 without G2). Rule 2 (`--unknown-cap-pct 40`, DEC-057's cap): `unknown`'s total share of the target is capped — 120 of 300, of which 94 are the crit+high already taken, so 26 medium/low `unknown` clusters are drawn. Rule 3: the remaining budget (137) is allocated across the **classified** medium/low strata proportionally to pool size, with a per-category floor (`--category-floor 25`, counting the category's crit+high clusters) topped up from the largest category. Rounding is largest-remainder so the sum is exact; draws within a stratum are `random.Random(EVAL_SEED).sample(sorted(ids), k)`. **Resulting default composition (300):** `unknown` 120 (14 crit · 80 high · 13 med · 13 low), `ssh_brute_force` 115 (1 · 11 · 95 · 8), `suspicious_login` 25 (0 · 0 · 0 · 25), `privilege_escalation` 40 (0 · 31 · 1 · 8). **Consequence the report must carry:** G1's severity mix is enriched by design (137/300 crit+high against 137/2,984 in the pool); every headline number is computed on that sample and says so, and per-severity rows are within-stratum. `--no-take-all-crit-high --unknown-cap-pct 20` is the pure-cap alternative; both are one flag away and the coverage table prints the parameters used.
3. **`source='lab'` is a time window applied after the fact, by `eval/lab_tag.py`, and not an intake-time rule — DEC-035's open half closed as option D.** The lab agent is `user1-IA1803`, which is also the estate's only Linux workstation and produces ≈ 34 alerts/hour of its own operating noise (`docs/lab-run-log.md:8-16`); an agent-name rule (`LAB_AGENTS`) would tag the P4 pilot's production traffic from that host as lab for the rest of the project, and an intake-time column (`intake.via='lab'` or `intake.source`) cannot carry a window that is only known once the Owner has written the seconds down. So: the Owner runs a scenario, logs `start`/`end` (the runbook's table), and runs `lab_tag.py --agent user1-IA1803 --since … --until … --scenario … --category … --kind attack|benign`, which executes `UPDATE alerts SET source = 'lab' WHERE agent_name = %s AND alert_time BETWEEN %s AND %s AND source = 'wazuh' AND NOT is_synthetic` and appends the window to `eval/lab_windows.csv` (the tag's provenance, committed). `build_gold.py --g2` selects heads **inside recorded windows** and refuses (exit 3) if any head in a window is still `wazuh` — a forgotten tag fails loudly instead of shrinking G2 silently. `alerts.source` is not `status` (G2's monopoly is untouched) and `alerts` is not append-only (§6.1 names `audit_events`, `llm_runs`, `intake`). No §6.1 or §6.3 change; no migration 018; the G3 loader sets `source='lab'` explicitly and never passes through `_derive_source`. **What the window buys P8:** the pilot export can exclude `source='lab'` rows, which is the one thing a tag at all is for. The INBOX item offers B and C for the record with their cost.
4. **G3 rows are `received` + `is_synthetic` and never enter the state machine, the queue or a job.** The loader parses each fixture with the product parser, inserts through `domain.transitions.open_alert(kind="received", source="lab", suggestion_visible=False)`, then writes `is_synthetic = true` and the four enrichment context columns plus `risk_score` with the product lookups (`enrichment.lookups`, `soar.risk.compute_risk_score`) in the same transaction — the same facts a real row gets at A5/A6, without A5/A6. It does **not** call `finish_enrichment` (which enqueues `triage` — and a `triage` job is exactly how the model would see G3 before P7), does not dedup (each G3 alert is its own head, `occurrence_count = 1`, so the vector-5 neighbour is a separate head the ±2 h query finds), does not evaluate auto-close, and does not write `intake` (a fixture was never received; G9/G12 are about received documents). `status = 'received'` also keeps them out of `correlated_cluster_ids` (`status IN ('queued_tier1','tier1_active')`), so a pilot escalate can never pull a G3 row into a case. P7 runs ① on them by `alert_id` from the manifest (§12).
5. **The G3 fixtures are pairs where the vector needs one, timestamps sit in a dead window, and the base is chosen so FP is reachable.** Base: `backend/tests/fixtures/indexer_sample_rule5503.json` (`user1-IA1803`, rule 5503 level 5 → medium, `ssh_brute_force`) with `data.dstuser` and the `user=` token of `full_log` set to `user1` (non-privileged — `root` would make step 4 forbid FP before any payload is read), `data.srcip` a distinct TEST-NET-3 address per fixture (no cross-fixture correlation by `srcip`), `_source.timestamp` (and `fields.timestamp[0]`) in **July 2026** — before the archive's 08/08 start, so no real alert is within ±2 h — spaced **5 h apart** so no fixture is inside another's window (`MAX_CLUSTER_AGE_HOURS` + the 2 h window), except vector 5's neighbour at target − 10 min. Vector 2 puts the payload in `data.srcuser` and keeps `dstuser = user1` (a payload in `dstuser` would make the identity lookup `not_found`, `identity_privileged = "unknown"`, and `sbf-1` would not hold — FP blocked by construction, ASR 0 for a structural reason, measuring nothing); vector 3 puts it in `predecoder.hostname` and keeps `agent.name` (same argument through `lookup_asset`); vector 5's neighbour carries it in `data.dstuser` **and** in its `full_log`'s `user=` token, because `CorrelationRow` carries no user field and the five correlation samples carry `description` and `raw_log` — that is the only path by which a neighbour's text reaches the prompt. Every choice is a design note in T04 so the evaluation chapter can say which vectors were structurally blocked and which were not.
6. **The brief's T06 (`docs/gold-v1-report.md` generator) is folded into T03 as `label_export.py report`.** It reads T03's own outputs (κ JSON, adjudication, gold CSV, sha) plus T01's coverage table, and it runs on **28/09**, the tightest human day — a separate dispatch → review → merge cycle for a 1.5 h card that cannot be tested until T03's formats exist is the DEC-048 shape. One card, one format contract, one run.
7. **The labelling routes are admin-group routes and both labellers need `admin` accounts.** Architecture §5 puts `GET /labels/next` and `POST /labels` in the `admin` group and §6.4's role set is `tier1|tier2|admin`; P4's auth gates a route by role. So the advisor gets an admin account (P4's `seed_users` or its CLI — Owner action, 20/09), and `labeler=<id>` is **bound to the session**: a request whose `labeler` is not the caller's `user_id` is `403`. One person can never draw the other's order or write the other's row.
8. **Per-labeler order is a seeded shuffle of the candidate list, computed on every request, never stored.** `random.Random(int(sha256(f"{LABEL_ORDER_SEED}:{labeler_id}").hexdigest()[:16], 16)).shuffle(sorted_cluster_ids)`; "next" is the first id in that order with no `triage_labels` row for `(cluster_id, labeler_id, 'gold_offline')`. Deterministic, restart-safe, needs no table, and a test asserts two labellers get different permutations of the same set.
9. **What the page shows is an allowlist, and the test pins it.** `alert_id, rule_id, rule_level, severity, description, agent_name, alert_time, alert_user, srcip, dstip, category, raw_log, occurrence_count, first_seen, last_seen, playbook, correlation, progress` — every rendered field carries `data-field="<name>"` and the test asserts the set of names rendered is a subset of this list. Not shown, and not selected from `alerts` at all: `source`, `status`, `triage_status`, `suggestion_visible`, `risk_score*`, `*_context`, `lookup_status`, `case_id`, `autoclose_rule_id`, `acknowledged_*`, `closed_*`, `close_reason`, `duplicate_of`, `occurrence_count` **from the DB** (the number shown is the file's / the members' — §5). The `false_positive` token appears in the page exactly once, as the label form's option value, and the substring test exempts only the `<form id="label-form">` element.
10. **G2's allocator is the same function with different parameters** (`--g2-target 100 --g2-floor 60 --g2-unknown-cap-pct 50 --no-take-all-crit-high --category-floor 5`): every playbook-category cluster the lab produced is precious (a scenario yields a handful), so playbook categories are allocated first and `unknown` — the host's own noise inside the windows, where most benign clusters live — fills to the target under its cap. "≥ 20 benign lab clusters" is a **label** count, checked after labelling by `label_export.py report` (`gold_set = G2 AND label IN ('benign','false_positive')`), not a selection rule: a selection rule would require knowing the answer before the blind labelling.
11. **`label.created` is written for every label; the label row itself is not append-only, and one undo exists (`should`).** `triage_labels` is a v3 table outside §6.1's append-only set; a labeller who mis-clicks may undo **their own most recent** label while `eval/gold_v1.sha256` does not exist (the page reads the file's absence; after the freeze the button is gone and the route answers `409`). The audit trail (`label.created`, append-only) keeps both events. This is the smallest thing that makes a 400-click session survivable without opening the door to post-hoc edits.
12. **Refuse-to-overwrite is version-by-existence.** `label_export.py freeze` writes `gold_v1.csv` + `gold_v1.sha256` if neither exists; if `gold_v1.csv` exists it writes `gold_v2.csv`, `gold_v2.sha256` and `gold_v1_to_v2.diff` (unified diff of the two CSVs) and never touches v1 — the standing rule's mechanism, not a flag. `--force` does not exist.

---

## 7 · Exit-gate coverage

| Gate item (`prompts/P6.md:25`, `01-plan.md:13`) | Covered by | Notes |
|---|---|---|
| `eval/gold_v1.csv` + `.sha256` committed | **P6-T03** (`freeze`) — the Owner runs it 28/09 and commits | the Director checks `git log -- eval/gold_v1.sha256` and `sha256sum -c eval/gold_v1.sha256` |
| κ reported in `docs/gold-v1-report.md` | **P6-T03** (`kappa` + `report`) | overall, per `gold_set`, per category (`should`) |
| ≥ 300 clusters | **P6-T01** (G1 target 300 from a pool of 2,984) | `report` prints `G1 = 300` and the floor check |
| G2 ≥ 60 incl. ≥ 20 benign lab clusters | **P6-T05** (the scenarios and the tag) + **P6-T01** (`--g2`) + **P6-T03** (`report` counts `benign`/`false_positive` labels in G2) | the brief's cut candidate ("report what exists") is built in: a category with no cluster is a zero row |
| G3 = 40 | **P6-T04** (manifest 40 rows, 5 × 8, a test) | the rows enter the database in P7 |
| Blind page: forbidden content, per-labeler order, progress | **P6-T02** | the tests the brief names, plus the allowlist test |

---

## 8 · INBOX items raised by this plan

- `2026-09-16 · P6 / lab tagging · DECISION_REQUEST` — **DEC-035's open half.** Options: **B** widen `intake.via` (§6.1, migration 018, Owner); **C** add `intake.source` (same cost); **D (recommended, taken by T05 unless overruled)** post-hoc time-window retag by `eval/lab_tag.py` with `eval/lab_windows.csv` as provenance, no contract change — because the lab host is the production host (`docs/lab-run-log.md:8-11`) and the window is only known after the run. Frozen contract affected: none under D. Needed before 22/09 (the first scenario); T05's code is written for D and would need a re-cut under B or C.
- `2026-09-16 · P6 / G1 sampling design · DECISION_REQUEST` — **A1 and DEC-057's cap value, both the Owner's.** The defaults T01 ships (`--take-all-crit-high`, `--unknown-cap-pct 40`, `--category-floor 25`) and the composition they produce (planning decision 2) against the two alternatives (proportional under a 20 % cap → ≈ 17 crit+high; proportional under a 33 % cap). Frozen contract affected: none. Needed by **24/09** (the day before the run); if unanswered, the defaults apply and `docs/gold-v1-report.md` says the Director chose them.

Not an INBOX item, but named: the labelling routes' role (`admin`) is architecture §5's grouping, not a contract change; the advisor's admin account is an Owner action (§11).

---

## 9 · Task table

| Task | Title | Priority | Est. | Depends on | Owner action? |
|---|---|---|---|---|---|
| P6-T01 | `eval/dedup_verify.py` gains per-cluster membership; `eval/build_gold.py` — G1 from the fold (files), G2 from `alerts` in the lab windows, the parameterised stratified allocator, `gold_candidates.csv` + coverage table | must | 5 h | — (P2-T15 merged; the archive on this host) | **yes** — run `--g1 --g2` on 25/09 from the primary checkout and commit; answer INBOX item 2 by 24/09 |
| P6-T02 | Blind labelling page — `tier1/labels.py`, `web/labels.py`, `templates/labels.html`: `GET /api/admin/labels/next`, `POST /api/admin/labels`, `GET/POST /admin/labels`; per-labeler order, progress, allowlist + forbidden-content tests | must (`undo last` `should`) | 4.5 h | P6-T01; P4's auth, `tier1/visibility.py` `labeling` mode, base layout | **yes** — admin account for the advisor (20/09); labelling 26–27/09 |
| P6-T03 | `eval/label_export.py` — `kappa` (3 × 3 Cohen's κ, overall / per `gold_set` / per category), `disagreements` (adjudication CSV), `freeze` (`gold_v1.csv` + `.sha256`, version-by-existence, `source='disagreement'` rows), `report` (`docs/gold-v1-report.md`) | must (per-category κ `should`) | 4.5 h | P6-T01 | **yes** — run 27–28/09; adjudicate; commit the sha |
| P6-T04 | `eval/adversarial/` — `generate.py` (5 vectors × 8 patterns from the 5503 base, 40 targets + 8 neighbours), `fixtures/*.json`, `manifest.csv`, `load.py` (`is_synthetic`, `source='lab'`, `_adversarial`, no job, no queue), tests | must | 3.5 h | — | **yes — in P7, not before**: run the loader after the freeze |
| P6-T05 | `docs/lab-scenarios.md` (8 categories: attack + benign twin, expected rule ids, pre-flight, per-window check, timestamp checklist) + `eval/lab_tag.py` + `eval/lab_windows.csv` + test | must (ART ids `should`, verified only) | 3 h | — (INBOX item 1 for the mechanism; written for option D) | **yes** — install ClamAV (sudo), run the scenarios 22–24/09, log seconds, run `lab_tag.py` after each window |
| P6-T06 | **RETIRED 25/09 (DEC-111) — do not dispatch; its content moves to P6-T07 note 5.** ~~Addendum 20/09 (DEC-100; DEC-096 (b) item 3):~~ `build_gold.py`'s `coverage_table` writes the DEC-086 sentence — *"This sample is stratified, not random: no rate computed from it is an estate-wide rate."* — immediately after the enrichment line of every sample section; two tests; `eval/gold_coverage.md` regenerated (+1 line, the other three generated files byte-identical) | must | 0.5 h | P6-T01 (merged `a9c667a`) | **yes** — the 25/09 `--g1 --g2` run must happen **after** this merges, or the regenerated file loses the sentence again |
| P6-T07 | **Addendum 25/09 (DEC-111, DEC-114):** `build_gold.py --g2` without `--archive-file` (G2-only mode; `g1_*` files untouched); `truth_label` from the window — attack → `escalate`, twin → `false_positive` — **only for heads whose `rule_id` is in the scenario's declared Expected rules** (parsed from `docs/lab-scenarios.md`, 19 ids / 8 categories); other in-window heads `in_window_unexpected`, excluded, counted per window in `gold_coverage.md`; overlapping windows exit 3; the (xii) sentence; `label_export.py freeze` takes `truth_label`, `kappa` adds `vs_truth` per labeller | must | 2.5 h | P6-T01, P6-T03 (both merged) | **yes** — 27/09 evening: the G2-only run (`docs/lab-scenarios.md` §6 after P6-T08) and commit |
| P6-T08 | **Addendum 25/09 (DEC-111, DEC-112/113/114):** `docs/lab-scenarios.md` re-hosted to `attt-m1-lab` on ATTT-M1 — this manager's pre-flight, login-shell rule, "run only the scenario", `srcip` rotation (`ssh -b` / LAN addresses), the interleaved two-day schedule (RW/DX/C2 first on 26/09) with a yield table, §6 = the G2-only command; every `#### Expected rules` table and `### <category>` heading byte-identical | must | 1.5 h | — (parallel with P6-T07) | **yes** — run it 26–27/09 |

File scope is disjoint by construction: **T01** owns `eval/dedup_verify.py`, `eval/build_gold.py`,
`backend/tests/test_dedup_verify.py`, `backend/tests/test_build_gold.py` and the four generated files
`eval/g1_clusters.csv`, `eval/g1_members.csv.gz`, `eval/gold_candidates.csv`, `eval/gold_coverage.md`;
**T02** owns `backend/app/tier1/labels.py`, `backend/app/web/labels.py`,
`backend/app/web/templates/labels.html`, `backend/tests/test_labels.py` and one line of
`backend/app/web/main.py`; **T03** owns `eval/label_export.py`, `backend/tests/test_label_export.py`;
**T04** owns everything under `eval/adversarial/` and `backend/tests/test_adversarial.py`; **T05** owns
`docs/lab-scenarios.md`, `eval/lab_tag.py`, `eval/lab_windows.csv`, `backend/tests/test_lab_tag.py`.
T01 **reads** `eval/lab_windows.csv` and `eval/adversarial/manifest.csv` (both optional at run time)
and does not list them. No file appears in two cards.
**Addendum 25/09:** **T07** owns `eval/build_gold.py`, `eval/label_export.py` and their two test files (T01/T03 are merged, so no live card shares them) and **reads** `docs/lab-scenarios.md`; **T08** owns `docs/lab-scenarios.md` alone. The coupling is one-way and pinned: T08 leaves the Expected-rules tables byte-identical (its acceptance 2), T07's test pins the parsed result to 19 ids (its acceptance 1/3). T06 is retired.

---

### P6-T01 · `build_gold.py` + fold membership + coverage table
- Priority: must · Estimate: 5 h · Depends on: — (P2-T15 merged @ `main`; archive readable)
- Goal: `Cluster.members` in the fold; `eval/build_gold.py` writes `eval/g1_clusters.csv`, `eval/g1_members.csv.gz`, `eval/gold_candidates.csv` (G1 300 from the fold's 2,984-cluster pool; G2 ≤ 100 from `alerts` inside `eval/lab_windows.csv`), `eval/gold_coverage.md`; the allocator of planning decision 2/10 with every parameter on the CLI; exit 1 on a floor miss (with the numbers), exit 3 on an untagged window; `--check-db` proves every G1 head exists in `alerts`.
- Files — modify: `eval/dedup_verify.py`, `eval/build_gold.py`, `backend/tests/test_dedup_verify.py`. Create: `backend/tests/test_build_gold.py`, and the four generated files (committed from the real G1 run).
- Contracts touched: none (reads `alerts` with an explicit column list; writes files).
- Risk / notes: the G1 run is deterministic and the Coder commits it; the G2 run is the Owner's on 25/09. The sampling parameters are Director defaults until INBOX item 2 is answered — the coverage table prints them, so a re-run with the ruled values is one command and one diff.

### P6-T02 · blind labelling page
- Priority: must (`undo last` `should`) · Estimate: 4.5 h · Depends on: P6-T01; P4 (auth dependency, `tier1/visibility.py` `labeling` mode, base template)
- Goal: `GET /api/admin/labels/next?labeler=<id>` → the next unlabelled cluster in that labeller's seeded order with `done/total`; `POST /api/admin/labels` → one `triage_labels(source='gold_offline')` row + `label.created`; `GET /admin/labels` the HTML page (representative alert, `raw_log`, ±2 h correlation, occurrence and span, category, playbook); allowlist of fields; the forbidden-content test with `suggestion_visible = true` and an `llm_runs` row present.
- Files — create: `backend/app/tier1/labels.py`, `backend/app/web/labels.py`, `backend/app/web/templates/labels.html`, `backend/tests/test_labels.py`. Modify: `backend/app/web/main.py` (one `include_router` line).
- Contracts touched: none (`GET /api/admin/labels/next`, `POST /api/admin/labels` are §6.4 routes being implemented; `label.created` exists).
- Risk / notes: the names of P4's auth dependency and visibility function are read from `main` at dispatch, not assumed — the card says which files to open. G1 correlation is computed from the file (§5), G2 from `domain.correlation` with `status` dropped.

### P6-T03 · `label_export.py` — κ, adjudication, freeze, report
- Priority: must (per-category κ `should`) · Estimate: 4.5 h · Depends on: P6-T01
- Goal: four subcommands over `triage_labels` and T01's files: `kappa` → `eval/kappa_v1.json`; `disagreements` → `eval/adjudication_v1.csv` with both notes and empty `final_label`/`final_note`; `freeze` → `eval/gold_v1.csv` + `eval/gold_v1.sha256` (version-by-existence: v2 + diff, never an overwrite), `triage_labels(source='disagreement')` for adjudicated rows; `report` → `docs/gold-v1-report.md` (counts, coverage, κ, freeze sha, the limitation lines).
- Files — modify: `eval/label_export.py`. Create: `backend/tests/test_label_export.py`.
- Contracts touched: none.
- Risk / notes: κ is the 3 × 3 formula, tested on a hand-computed 2 × 2 and on perfect agreement / independence; `freeze` refuses a disagreement without a `final_label` and refuses a candidate with fewer than two labels unless `--allow-partial` (then the report names the count).

### P6-T04 · adversarial fixtures + loader + manifest
- Priority: must · Estimate: 3.5 h · Depends on: —
- Goal: `eval/adversarial/generate.py` writes 40 target fixtures (5 vectors × 8 patterns) + 8 neighbours and `manifest.csv` deterministically from the 5503 base; `eval/adversarial/load.py` inserts them per planning decision 4 (idempotent, `--dry-run`); tests: 40 rows, 5 × 8 coverage, every fixture parses, the payload is in exactly the vector's field, timestamps ≥ 5 h apart and in July 2026, the loader creates no job and the queue predicate excludes the rows.
- Files — create: `eval/adversarial/__init__.py`, `eval/adversarial/generate.py`, `eval/adversarial/load.py`, `eval/adversarial/manifest.csv`, `eval/adversarial/fixtures/*.json` (48), `backend/tests/test_adversarial.py`.
- Contracts touched: none.
- Risk / notes: the loader is run **in P7 only**; the card says so in its first line and the Owner action repeats it. `_adversarial` lives in `_source`, so `raw_payload` carries it (G9: the fixture is the received document).

### P6-T05 · `docs/lab-scenarios.md` + `eval/lab_tag.py`
- Priority: must (ART ids `should`) · Estimate: 3 h · Depends on: — (INBOX item 1 names the mechanism; the card is written for option D)
- Goal: the runbook the Owner executes 22–24/09 — for each of the 8 reachable categories the attack scenario on `user1-IA1803` (manual command; ART test id only where verifiable), the benign twin on the same host, the expected rule ids and the negative check, a per-window checklist with `start`/`end` seconds, the pre-flight and the per-window indexer check; `eval/lab_tag.py` — the window retag + `eval/lab_windows.csv` provenance; the note that a category with no alert is excluded, never synthesised.
- Files — create: `docs/lab-scenarios.md`, `eval/lab_tag.py`, `eval/lab_windows.csv` (header row), `backend/tests/test_lab_tag.py`.
- Contracts touched: none (`alerts.source` stays inside its CHECK set; `status` untouched).
- Risk / notes: every scenario command must be one the Owner can paste; ClamAV install is `sudo` and Owner-only (`docs/wazuh-manager-changes.md` §4.2); rule `100301`–`100303` match conditions are quoted from `conf/local_rules.xml`, not paraphrased.

---

### P6-T06 · ~~the DEC-086 sentence in `eval/gold_coverage.md` (addendum, 20/09)~~ — RETIRED 25/09 (DEC-111)
- **Retired, not done.** G1 is void; the sentence described G1's stratified sample. P6-T07 writes the G2 corpus's (xii) sentence in the same position. The prompt carries a RETIRED banner; its worktree has 0 commits. Kept below as the record.
- Priority: must · Estimate: 0.5 h · Depends on: P6-T01 (merged)
- Goal: one `lines.append(f"- {DEC086_SENTENCE}")` in `coverage_table` after the enrichment branch (both G1 and G2 sample sections get it); `test_coverage_table_dec086_sentence_immediately_after_enrichment_line` (position, not presence — the red step moves the line above the branch) and `test_coverage_document_has_dec086_sentence_once_per_sample_section` (1 for `G1 only`, 2 for `G1 + G2`); regenerate with the P6-T01 acceptance-4 command and commit `eval/gold_coverage.md` (`git diff main --numstat` → `1 0`), the three CSV/gzip files unchanged.
- Files — modify: `eval/build_gold.py`, `backend/tests/test_build_gold.py`, `eval/gold_coverage.md` (regenerated). Create: none.
- Contracts touched: none.
- Risk / notes: dispatchable into an idle slot now (DEC-103: nothing else is legal); deadline **before the Owner's 25/09 run**. P6-T03's `report` copies the G1 sample section verbatim, so the sentence reaches `docs/gold-v1-report.md` without a P6-T03 change; `prompts/P7.md:18` and `prompts/P8.md` are DEC-086's other two homes and are the Director's sweeps, not code.


### P6-T07 · G2 from the lab alone — truth from the window, scoped to the declared rules (addendum, 25/09)
- Priority: must · Estimate: 2.5 h (DEC-111 said ≤ 1.5 h before DEC-114 added the scope) · Depends on: P6-T01, P6-T03 (merged) · **merge before 27/09 evening**
- Goal: `build_gold.py --g2` runs without `--archive-file` and writes G2-only `gold_candidates.csv` (+ `scenario_id, kind, truth_label`) and `gold_coverage.md` (per-window heads / in scope / `in_window_unexpected`, truth counts, benign ≥ 20 line, the (xii) sentence); `expected_rules()` parses the runbook; overlapping windows exit 3; `label_export.py freeze` writes `truth_label` as the gold label regardless of human agreement; `kappa` adds `vs_truth` (accuracy and κ per labeller, overall and per category).
- Files — modify: `eval/build_gold.py`, `eval/label_export.py`, `backend/tests/test_build_gold.py`, `backend/tests/test_label_export.py`. Create: none.
- Contracts touched: none (`truth_label` lives in a file).
- Risk / notes: scoping is by `rule_id`, never by the product's `category` (DEC-114); the G1 path is unchanged when an archive is given; `report` and `disagreements` still speak G1 / human-vs-human — named follow-ups in the card (note 8), the Director's to card before 28/09; the three new candidate columns never reach the page because P6-T02's view is an allowlist (note 7).

### P6-T08 · `docs/lab-scenarios.md` re-hosted to `attt-m1-lab` (addendum, 25/09)
- Priority: must · Estimate: 1.5 h · Depends on: — (parallel with P6-T07) · **merge 25/09 evening or first thing 26/09 — the Owner starts 07:05**
- Goal: the runbook the Owner executes 26–27/09 on ATTT-M1: this manager's pre-flight (`100999` ≥ 2 via the indexer, agent 004, `auid`-filtered `execve`, ClamAV check, sshd password auth), the login-shell and "run only the scenario" rules, non-overlapping windows, `srcip` rotation, the interleaved two-day schedule with RW/DX/C2 first, a yield table reaching ≥ 100 in-scope / ≥ 20 benign / 8 categories, §6 = the G2-only build.
- Files — modify: `docs/lab-scenarios.md`. Create: none.
- Contracts touched: none.
- Risk / notes: the Expected-rules tables, `**Expected label:**` lines and `### <category>` headings are frozen for this card (DEC-114); the Coder runs no scenario command (auditd records its shell); the primary checkout holds an uncommitted `## 0′` block in the same file — the Director reconciles it at merge, or the merge refuses.

## 9′ · Addendum 25/09 — planning decisions 13–16 (P6-T07/T08)

13. **G2-only output replaces two of the four generated files and leaves the other two.** The 27/09 run overwrites `eval/gold_candidates.csv` and `eval/gold_coverage.md` with G2-only content — P6-T02's page and `label_export.py` read those paths, and a second path would be a second contract. `eval/g1_clusters.csv` and `eval/g1_members.csv.gz` are never opened in G2-only mode. The G1 versions of the two overwritten files stay in git history (`git show pre-lab-reset:eval/gold_candidates.csv`) — DEC-111's "stay in git as the record … not deleted" read as "not removed from history", which is the only reading compatible with the page's fixed path. If the Director reads it as "present at HEAD", the fix is a `git mv` to `eval/g1_*` names before the 27/09 run, not a code change.
14. **The declared rules are parsed from the runbook, not copied into code, and they are 19, not 20.** DEC-114's heading says 20 ids; its own list, the file on `main` and the parser all give 19 (5 + 3 + 4 + 3 + 1 + 1 + 1 + 1). The cards assert 19 and report the discrepancy; nobody adds an id to match the heading.
15. **G2 sizing for the 27/09 run is passed on the command line, not changed in code:** `--g2-target 150 --g2-floor 100` (DEC-111: ≥ 100 clusters; ≈ 100–150 candidates for one labelling session each on 28/09). `--g2-unknown-cap-pct 50` and `--g2-category-floor 5` keep their defaults (planning decision 10). The coverage file prints the parameters used, so a different ruling is one re-run.
16. **Benign-twin truth is `false_positive`, per DEC-111 verbatim — and the runbook disagrees on five of eight twins.** `docs/lab-scenarios.md` §3 pre-declares `**Expected label:** benign` for the `ssh_brute_force`, `suspicious_login`, `privilege_escalation`, `recon` and `malware` twins and `benign / false_positive` for the three negative-check twins. Of those three, `malware`'s clean scan and the negative checks produce no in-scope head by design, so the conflict bites where twins do yield: `ssh_brute_force`, `suspicious_login`, `privilege_escalation`, `recon`. A labeller who picks `benign` for a legitimate admin `sudo` is marked wrong against `false_positive` truth, and the human baseline absorbs that. **This is an evaluation-validity question for the Director, needed before the 28/09 freeze** (not before the lab: it changes one constant, `TRUTH_BY_KIND["benign"]`, and one re-run of `build_gold.py`). Neither card resolves it; P6-T08 leaves the `Expected label` lines as written.

## 10 · Labelling day plan — 26–27/09 (Sat–Sun), Owner + advisor

**Who labels what.** Both labellers label the **same 400 clusters** (`eval/gold_candidates.csv`: G1
300 + G2 ≤ 100), each in their **own seeded random order**, each on their own admin account, on the
blind page. Neither sees the other's labels, any ① output, any pilot decision, or `alerts.source`.
**Digest labels (`triage_labels(source='digest')`, agent 001 only — DEC-012) are not part of the
400 and are not a gold source**: the 400 are all `source='gold_offline'`, written by the page. If G2
holds fewer than 100 clusters on 25/09 the sample is simply 300 + |G2| (floor 60); the shortfall is
**not** made up from the digest and **not** from live `wazuh` rows (G1 is frozen at 08/08–07/09,
DEC-066) — the report states |G2| with its category rows. If |G2| < 60 the exit gate is missed on that item and the
Director decides at the 25/09 gate — the phase's cut candidate (report what exists) or an escalation; the
files are valid either way and labelling proceeds on what exists.

| When | Owner | Advisor | Rule |
|---|---|---|---|
| **20/09** | book both names and dates into `STATE.md`; create the advisor's admin account; confirm the page opens (`GET /admin/labels`) with `eval/gold_candidates.csv` absent → "no candidates" | — | P4 must be merged (18/09) |
| **25/09 evening** | commit `eval/gold_candidates.csv`, `g1_*`, `gold_coverage.md`; open the page once and check `total` = 300 + \|G2\| | — | nobody labels before this commit |
| **26/09 session 1** (≈ 3.5 h, ≈ 200 clusters) | labels, alone | labels, alone, at their own pace | **independent, no chat, no shared screen**; ~1 min/cluster; confidence 1–3; a one-line note whenever the label is not obvious; `raw_log` is the evidence, the playbook the frame |
| **27/09 session 2** (≈ 3.5 h, the rest) | same | same | the page's counter shows `done/total`; both must reach `total` |
| **27/09 evening — adjudication meeting** (≈ 1 h) | run `label_export.py kappa` then `disagreements` → `eval/adjudication_v1.csv`; go through every disagreement with both notes visible; write `final_label` and a one-line `final_note` per row **in the file** | the same, together | the meeting decides only disagreements; agreed rows are not re-opened; if κ < 0.4 the report says so and only adjudicated labels are used (architecture §6) |
| **28/09** | `label_export.py freeze` → `eval/gold_v1.csv` + `.sha256`; `report` → `docs/gold-v1-report.md`; commit both; **the gate** | — | after this commit a label change means `gold_v2` (planning decision 12) |

**Bias controls in force, and where each lives:** blind page (T02: no ① output, no `source`, no
pilot decisions — allowlist + denylist tests); independent order (T02, planning decision 8);
two people, κ reported (T03); adjudication recorded with reasons (T03's CSV, `adjudicated = true`
rows); freeze before any eval run (T03 + the Director's gate; P7 stops without the sha); G3 never on
the page (T01 excludes `is_synthetic` and the manifest; the loader runs in P7). **Named, not
concealed:** the labellers can read dates in `raw_log`, so a G2 cluster is recognisable as September
lab traffic; the control against "lab host = escalate" is the ≥ 20 benign lab clusters on the same
host (architecture §6, `chot-v3-14-ngay.md` A2), not concealment. The author-as-labeller limitation
(A3) and the author-written detection rules (DEC-056 amendment 3) are P8 limitation sentences the
report generator already prints.

---

## 11 · Owner actions this phase (one line each, only what a human can do)

1. **By 20/09:** answer INBOX item 2 (sampling parameters; default applies otherwise) — the Director answers item 1; book the two labellers by name for 26–27/09 in `STATE.md`; create the advisor's `admin` account with P4's seed CLI.
2. **Before 22/09:** `sudo apt install clamav clamav-daemon` on `user1-IA1803` (DEC-056; `docs/wazuh-manager-changes.md` §4.2); confirm auditd is live and `conf/local_rules.xml` is loaded (`docs/lab-scenarios.md` pre-flight).
3. **22–24/09:** run `docs/lab-scenarios.md` — every attack scenario and its benign twin, seconds logged, `eval/lab_tag.py` after each window (or each day), `git add eval/lab_windows.csv`.
4. **25/09:** from the primary checkout: `PYTHONPATH=backend python3 eval/build_gold.py --archive-file /home/user1/archive/alerts-2026-08-08_09-07.jsonl --g1 --g2 --lab-windows eval/lab_windows.csv --env-file .env` (plus the ruled parameters), read `eval/gold_coverage.md`, commit the four files.
5. **26–27/09:** label (two people, blind, independent); **27/09 evening:** adjudicate.
6. **28/09:** `label_export.py freeze` + `report`; commit `eval/gold_v1.csv`, `eval/gold_v1.sha256`, `docs/gold-v1-report.md`.
7. **29/09 (P7), not before:** `eval/adversarial/load.py` from the primary checkout.

---

## 12 · Hand-off to P7 and P8

1. **G1 facts come from the files, not from `alerts` (DEC-084).** For a `gold_set = G1` row, `occurrence_count`, `first_seen`, `last_seen` are in `eval/gold_v1.csv` (copied from `gold_candidates.csv`), and the members are in `eval/g1_members.csv.gz`; `alerts.occurrence_count` / `first_seen_at` / `last_seen_at` on those heads are the replay afternoon's wall-clock values and must not enter a prompt or a B1 fact. P7's harness builds `facts` (P3 planning decision 7) from the row's enrichment columns **plus the file's cluster numbers**, and ±2 h correlation for G1 from `g1_clusters.csv` the way T02 does (a shared helper is P7's call — `tier1/labels.py` exposes `g1_correlation(clusters, head)` and P7 may import it, `eval → everything`). For `G2` rows the DB is right as it stands.
2. **G3 rows exist only after `eval/adversarial/load.py` runs, in P7.** They are `status = 'received'`, `is_synthetic = true`, `source = 'lab'`, `raw_payload->>'_adversarial'` = the pattern id, with enrichment context written and **no job**; the harness runs ① on them by `alert_id` from `eval/adversarial/manifest.csv` (enqueue `triage` at eval time or call `tier1.triage.run_triage_job`'s function directly — P7 decides), never through the pilot queue. Vector 5's neighbour is a second `received` head 10 min earlier on the same agent; nothing else is inside ±2 h of any fixture.
3. **`gold_v1.csv` columns:** `cluster_id, gold_set, alert_id, category, severity, source, label, adjudicated, note, confidence_a, confidence_b, occurrence_count, first_seen, last_seen` — `alert_id` = `cluster_id` = the head; `source ∈ replay|lab` is for scripts, never for a page; `label ∈ false_positive|benign|escalate`; `adjudicated` is `true|false`. `gold_v1.sha256` is `sha256sum` format over the CSV bytes. P7 records the sha it ran against.
4. **`model_wrong` is not a P6 artifact.** `triage_labels` has no such column (§6.1) and a blind labeller cannot mark it; P7's few-shot selector reads the digest path (`source='digest'`, P5) for that signal, and the exclusion "never a cluster present in `gold_v1.csv`" is by `alert_id`.
5. **G1's sample is severity-enriched by design** (planning decision 2): 137 of 300 crit+high against 137 of 2,984 in the pool. Headline metrics are on the sample and the chapter says so; per-severity rows are within-stratum; population-weighted figures, if wanted, use the pool grid printed in `eval/gold_coverage.md`.
6. **P8 limitation sentences this phase produces (the report generator prints them):** `unknown` = 1,801 of 3,051 fold clusters and its capped share in G1; B1's escalate-recall ceiling from the 94 `unknown` crit+high clusters in the pool (DEC-057 wording, re-derived on 3,051 — 137 crit+high in the pool after the loopback exclusion, 94 `unknown` → cap near 0.31 on the *pool*; the sample figure is printed beside it); the 67 loopback `ssh_brute_force` clusters excluded (DEC-053); `DESKTOP-MIRSO17`'s 23 clusters kept and pinned `needs_review` (DEC-058), with how many landed in the sample; `web_attack` and `policy_violation` at zero (DEC-055/057); `ransomware`, `data_exfiltration`, `c2_beacon` resting on author-written rules (DEC-056 amendment 3); author-as-labeller (A3) with κ; the lab host being the production host and `lab` being a time window (planning decision 3); G2's dates readable in `raw_log`.
