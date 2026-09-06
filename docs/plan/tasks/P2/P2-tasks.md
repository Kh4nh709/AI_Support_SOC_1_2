# P2 · Intake + pipeline — task cards

Phase objective: the deterministic core — indexer → intake → parse → dedup → internal enrichment →
auto-close → risk → `queued_tier1` — fully tested, with no LLM anywhere on the path.

**DEC-007 item 7 / DEC-009 — which copy of a card is authoritative.** Each task has a full
`docs/plan/tasks/P2/<TASK_ID>.prompt.md` and a shorter entry in this file. **The prompt is the
card**; this file is the Planner's index — estimates, waves, dependencies, risk notes. Where this
file restates an acceptance command it matches the prompt verbatim or does not appear. A divergence
is a Director defect, not a Coder's judgement call.

---

## Dispatch state — read this before dispatching anything

**Coders start 07/09, not today (DEC-030, DEC-031).** P2 was planned today, 06/09, so the day is not
lost twice; the P1 gate — `013, 014, 016, 017` on a clean `soc_dev` (DEC-029) — is due at tonight's
daily gate and **every card below assumes it is met**. Measured on `main` @ `a80483e` while planning:
only `013` and `014` are merged; `016` (P1-T05) and `017` (P1-T06) are in their worktrees. Nothing in
P2 can run against `main` until they land, because:

- `jobs.job_type` is still CHECKed to `('enrich','triage')` on `main` — every `jobs('pipeline')` and
  `jobs('pull')` insert P2 makes is rejected until **016** merges;
- `alerts.manager_id`, `origin_host`, `suggestion_visible` and `ck_alerts_source` do not exist until
  **016** merges — the parser's INSERT fails on the first column;
- the `app_rw` grants and the `intake` completion-write trigger arrive with **017** — the G12 path
  (`processed_at`/`outcome`) is untestable as the application role before it.

So the precondition for dispatching **any** P2 card is: `git log --oneline main | grep -E 'P1-T05|P1-T06'`
shows both merges. `P1-T04` (015) is **not** a P2 precondition (DEC-029: due before P4).

| | |
|---|---|
| Dispatchable on 07/09 once the P1 gate is met | P2-T01, P2-T03 (no dependencies); then the waves below |
| Blocked on a contract gap | **P2-T12** (webhook) — §6.3 has no webhook-auth key; INBOX filed |
| Blocked on an Owner action | **P2-T15** (dedup verification) and the archive half of **P2-T13** — the agent cannot read `/var/ossec/logs/` (measured: `sudo` needs a password, `user1` is not in group `wazuh`); the Owner exports the archive first |

---

## ⚠️ Budget note — this phase does not fit two days, on hours or on wall-clock

| | |
|---|---|
| Sum of `must` estimates | **39 h** (14 tasks; P2-T12 is `should`, 2 h, on top) |
| Day budget (`prompts/P2.md`: 2 days) | 16 h |
| Overbooking | **+144 %** — the re-plan threshold is 30 % |
| Wall-clock at the 3-coder cap | **≈ 19 h** — the dependency chain, not the hour sum, is the limit (see the wave table) |
| Longest chain | T03 (2 h) → T04 (3.5 h) → T08/T09 (3.5 h) → T10 (4 h) → T15 (2.5 h) = **15.5 h**, and T10 also waits on T06, which waits on T02, which waits on T01 |

What the arithmetic means, said plainly: **P2's coders need 07, 08 and most of 09/09** at three
concurrent sessions, with the Owner running fourteen dispatch → review → merge cycles in between
(P0 ran seven in a day and needed two review rounds on two of them). That collides with P3 (D4
08/09) and P4 (D5 09/09) as dated in `01-plan.md`. DEC-030 already spent one day of P8's buffer on
P1 and set the trigger: a slip beyond one day goes to the Owner with the playbook's recommendation
(cut ② in P5). This plan makes that trigger fire unless something moves.

### What I propose moves (Director/Owner call — I am not deciding it)

1. **P2-T12 (webhook, `should`, 2 h) → P4.** It is the *secondary* intake path (F1), nothing on the
   P2 gate needs it, and it is blocked on a contract gap anyway (INBOX: no `X-API-Key`/allowlist key
   in §6.3). P4 builds `web/` routes; the webhook belongs beside them.
2. **P2-T07 (correlation, 2 h) and P2-T15 (dedup verification, 2.5 h) run in P3's window.** Neither is
   on P2's exit gate: correlation's first consumer is P3's prompt builder, and T15 is a DEC-014 order
   whose input (the archive export) is an Owner action that can land any day. Moving them takes 4.5 h
   off P2's tail and shortens the longest chain to T10.
3. **Do not cut anything else.** Intake/puller and the pipeline are "never cut" (§10); the 18-edge
   transition test and the G7 test *are* the gate.

With 1 and 2: `must` in P2 proper = 34.5 h (+116 %), wall-clock ≈ 16.5 h — still two long days, not
three. **The recommendation is 1 + 2 and a recorded P3 start on 09/09**, which is the second slipped
day and therefore the Owner's decision under DEC-030, with the playbook's ② cut on the table. Saying
so now beats discovering it at the 08/09 evening gate.

---

## Critical path and waves

Estimates are for the card as written; dependencies are the `Depends on:` field of each prompt, and
where this diagram and a field disagree, the field wins (DEC-007 item 6).

```
t=0     P2-T01 config+errors (2 h)      P2-T03 category (2 h)              [third slot idle: nothing else is unblocked]
t=2     P2-T02 db+jobs+worker (3.5 h)   P2-T04 alert model+parser (3.5 h)  [idle until T04]
t=5.5   P2-T06 transitions (4 h)        P2-T11 puller (3.5 h)              P2-T05 dedup (3.5 h)
t=9     P2-T08 inventory+lookups (3 h)  P2-T09 autoclose (3.5 h)           P2-T07 correlation (2 h)
t=11                                                                        P2-T13 backfill CLI (2 h)
t=12.5  P2-T10 risk+pipeline+G7 (4 h)   ← waits on T05, T06, T08, T09, T11
t=16.5  P2-T15 dedup verification (2.5 h) ← waits on T10 and the Owner's archive export
t=19    done                            P2-T12 webhook — blocked, off the gate
```

**Why T04 waits on T03 and T09 does not wait on T08.** The parser calls `category.resolve()` and its
canonical-alert test asserts `ssh_brute_force`, so T04 needs T03 merged. Auto-close's hard blocks read
asset/identity/IoC facts — but they read them from an `AlertContext` value that **T04 defines in
`domain/alert.py`**, which T08's lookups *produce* and T09's matcher *consumes*. Both therefore depend
on T04 only, and T08/T09 run in parallel instead of in series (planning decision 4).

**Why T10 waits on T11.** G7 reads "a *pulled* alert reaches `queued_tier1` in < 30 s": the test drives
the puller against a recorded page, so the pull job must exist first.

---

## Exit-gate coverage

| Gate item (`prompts/P2.md`, `01-plan.md`) | Covered by | Notes |
|---|---|---|
| G7 test green (< 30 s with LLM off) | **P2-T10** — `backend/tests/test_g7_llm_off.py` | Puller (recorded page) → intake → `pipeline` job → `queued_tier1` + `jobs('triage')`, `LLM_MODEL_PROPOSER` unset, wall-clock asserted |
| Backfill lands from **both** sources (DEC-019) | **P2-T13** ships the CLI; the archive half is **Owner-run** (root) | Indexer from 02/09 (all it holds, DEC-017); archive lines as `source='replay'`, `sort_key` = epoch-millis of the alert's own timestamp. A `--since 2026-09-02` run is the live-source half; the archive half needs the Owner's export (Owner action) |
| dedup tests green | **P2-T05** (six predicates, two sessions on one cluster) | The DB-clock predicates, on a real database; **P2-T15** is the separate archive-scale verification against 2,778 |
| auto-close tests green | **P2-T09** (six hard blocks with a match-everything rule, ordered match, whitelist) | |
| simulate tests green | **P2-T09** (`simulate` API; counts on replayed fixtures) | The simulate **UI** is the brief's cut candidate; only the API is planned |
| 18 transitions tested | **P2-T06** (18 edges × guard-ok / guard-fail, fan-outs, escalate ③a/③b, rowcount, unique-index race) | |
| Wazuh heartbeat wodle + rule | **Owner action** | Measured today: rule `100999` has 0 documents in the index — the wodle is not installed. P2-T11's `is_heartbeat` is proven on a constructed fixture; the live path is proven the day the wodle lands |

---

## Planning decisions (tactical — Director may promote to a DEC)

1. **The worker's dispatch table lives in a composition-root module, `backend/app/web/worker.py`, and
   `make run-worker` changes to `python3 -m app.web.worker`.** `infra/worker.py` must call
   `soar.pipeline.run_pipeline_job` for `pipeline` jobs, and G1 says infrastructure never imports a
   tier — an import scan (`test_import_rules.py`) would reject `infra → soar` on sight. So
   `infra/worker.py` exposes `run_forever(conn_factory, handlers)` and knows no handler; the table
   `{"pull": …, "pipeline": …}` is built in `web/worker.py`, which §4 lets import everything. The
   Makefile line is a one-word change owned by P2-T10, the task that first has a real handler to wire.
   `web/__init__.py` already says `web/main.py` arrives in P2; `web/worker.py` sits beside it.

2. **No connection pool.** `psycopg_pool` is importable on this host but is **not** in
   `backend/requirements.txt` — the same hidden-dependency trap `jsonschema` was in P1. One worker
   process and one FastAPI process each hold plain `psycopg.connect()` connections; `infra/db.py`
   forbids the import by acceptance line. A pool is a P5/P8 question if the health job ever shows it
   is one.

3. **`alerts.source` for replay rows is derived, not stored on `intake`, and an INBOX item asks the
   Director whether that should become a column.** §6.1 gives `intake.via ∈ pull|webhook` and no third
   value; DEC-019 provisioned `alerts.source='replay'` but not where the pipeline learns it. Measured
   today: a live pull hit has the indexer envelope (`_index`, `_id`, `_score`, `_source`, `sort`),
   an archive line has none. Rule the pipeline applies: `source = 'replay'` when `via = 'pull'` and the
   stored document has no `_source` envelope, else `'wazuh'`. No contract change; the INBOX item
   offers the explicit column as the cleaner long-term answer, which matters again for P6's `lab`.

4. **`AlertContext` is a domain value.** `domain/alert.py` (P2-T04) defines
   `AlertContext(asset_present: bool, asset_criticality: str, identity_privileged: bool | None,
   ioc_reputation: str, lookup_status: dict)`; `enrichment/lookups.py` (P2-T08) fills it, `ingest/autoclose.py`
   (P2-T09) and `soar/risk.py` (P2-T10) read it. This is what lets T08 and T09 run in parallel, and it
   keeps the three-state lookup semantics (`found` / `not_found` / `skipped`, phase-4 §"Ba trạng thái")
   in one place. Import direction holds: `enrichment → domain` is not allowed by §4, so **lookups do
   not import the dataclass** — they return a plain dict and `soar/pipeline.py` (which may import
   both) constructs the `AlertContext`. Stated in both cards so neither Coder "fixes" it.

5. **`event_time` is always NULL in P2.** F4: `event_time ← predecoder.timestamp` **only when the
   agent's timezone is declared in the inventory** (field `tz`). `docs/inventory-format.md` (P0-T05)
   has no `tz` field and `inventory.validate()` rejects unknown keys. The parser therefore stores
   `event_time = NULL` and leaves `predecoder.timestamp` in `raw_payload`. Adding `tz` is an
   inventory-format change with its own validator and is not planned here.

6. **The puller requests `"fields": ["timestamp"]`.** Measured today on the live indexer: a plain
   `_search` returns hits with keys `_id, _index, _score, _source, sort` and **no `fields`**; the
   canonical fixture has `fields` only because it came from a dashboard export. With
   `"fields": ["timestamp"]` in the body the indexer returns `fields.timestamp[0]` in UTC, and on every
   hit checked `sort[0]` equals the epoch-millis of `_source.timestamp`. So the puller asks for
   `fields`, F4's primary path applies to live pulls, and F4's fallback (`_source.timestamp`, `+0700`)
   is both the replay path and the safety net — exactly DEC-019's reading.

7. **The 5 % control sample of phase-3 does not exist in v3.** D8 replaced it: ① runs on **100 %** of
   auto-closed alerts, and the digest is the human check. So `ingest/autoclose.py` writes no sample
   flag into the audit payload, has no sample-rate or per-rule-per-day counter, and every
   `auto_closed` alert gets `jobs('triage')` in the same transaction (the P3 handler picks them up).
   §6.3 has no sample-rate key, which is consistent.

8. **The risk formula is re-weighted onto the DEC-004 vocabulary, pending a DEC.** Phase-4's formula
   weights two asset tiers DEC-004 abolished; `P0-tasks.md` §Hand-off item 2 says it needs its own
   decision before `soar/risk.py` is written, and that decision was never taken. INBOX filed with a
   recommendation that keeps every worked example in phase-4's table unchanged (the cap binds:
   `high → 30, medium → 10, low → 0, unknown → 0`). P2-T10 carries the recommendation as its default
   and says so; if the DEC lands differently it is a four-number edit.

9. **The archive verification (P2-T15) is an offline fold over `alert_time`, not a pipeline replay.**
   The dedup predicates anchor on `last_seen_at >= now() − IDLE_GAP` (DB clock, B2/D9). Replaying 29
   days of history through the pipeline in an afternoon would put every alert of a key inside one
   15-minute window of *wall-clock* time — it cannot reproduce 2,778 and would measure nothing. The
   Owner's number was produced by applying the predicates over the alerts' own timestamps; T15 does the
   same with the **product parser and cluster-key code** imported from `backend/app` and the six
   predicates folded over `alert_time`, and states plainly that this is what it verifies. The DB-clock
   behaviour is T05's job, on a real database.

10. **P2-T14 (import rules) is folded into P2-T10.** The scanner and the `("soar.pipeline", "ingest")`
    allowlist already exist (P0-T03); `soar/pipeline.py` is the first module to exercise the
    allowlisted import, so T10's acceptance runs the scan and adds the one negative case that matters —
    a tier-to-tier import in a real file is caught. Nothing else was left to "finalise".

11. **Every db-marked pytest line sets a private DSN inline** — `soc_p2t<nn>_test` — passes `-rs`, adds
    no `-q`, and states `N passed` with `skipped` absent (DEC-023 item 8). Whole-suite runs go through
    `TEST_DATABASE_URL=postgresql:///soc_p2t<nn>_test make test-db`. `.env` is absent from every
    worktree, so no card relies on it; the two cards that talk to the indexer or the archive take an
    explicit path.

12. **Every acceptance has a demonstrated failing case (DEC-025), and the card names it.** Where a
    line's red step is not obvious, the card says what to break. A guard the Coder has never watched
    fail is an untested guard (DEC-027).

---

## Environment measured today (2026-09-06), and where it changes a card

| Claim in the brief or a spec | Measured | Consequence |
|---|---|---|
| `alert_time ← fields.timestamp[0]` on live pulls | A plain `_search` returns **no `fields`** key; requesting `"fields":["timestamp"]` returns it in UTC; `sort[0]` == epoch-millis of `_source.timestamp` on every hit checked | Puller requests `fields` (decision 6); parser keeps F4's fallback as a first-class path |
| Heartbeat via rule `HEARTBEAT_RULE_ID=100999` | `rule.id:100999` → **0** documents | Wodle not installed — Owner action; T11 proves `is_heartbeat` on a constructed fixture |
| Archive readable for T13/T15 | `sudo -n ls /var/ossec/…` → password required; `id user1` has no `wazuh` group | Owner exports the archive to a `user1`-readable JSONL (Owner action); T15 exits 2 naming it when absent |
| `jobs('pipeline')` / `jobs('pull')` insertable | `ck_jobs_job_type` on `main` is still `('enrich','triage')` | Precondition: 016 merged |
| One live job per subject | `ux_jobs_mot_job_song_moi_subject` UNIQUE `(job_type, subject_id) WHERE status IN ('pending','running')` — measured | `enqueue` uses `ON CONFLICT (job_type, subject_id) WHERE status IN ('pending','running') DO NOTHING`; the self-scheduled `pull` job is naturally single-flight |
| Dedup / correlation / queue indexes | `ix_alerts_dedup` (partial, matches the phase-2 predicate verbatim), `ix_alerts_corr_{agent,srcip,user}`, `ix_alerts_queue_tier1`, `ix_alerts_sweeper`, `ix_jobs_pending`, `ix_jobs_running_locked` all exist from v1 | P2 creates **no** index; T05's `EXPLAIN` acceptance names `ix_alerts_dedup` |
| `alerts` cross-column CHECKs | `ck_alerts_ban_sao_phai_seal_va_tro_goc`, `ck_alerts_g3_terminal_phai_co_closed_at`, `ck_alerts_h2_dong_boi_nguoi_phai_seal`, `ck_alerts_h3_escalate_khong_seal`, `ck_alerts_khong_tu_tro`, `ck_alerts_last_seen_khong_lui`, `ck_alerts_resolved_by` (`mitre|mitre_parent|rule_groups|decoder|dst_port|none`), `ck_alerts_hash_sha256_hex`, `ck_alerts_alert_user_khong_rong` | Pasted into T04/T05/T06 so a Coder does not discover them one rollback at a time |
| `intake` completion write | 017 (in flight): `app_rw` may UPDATE only `processed_at, outcome, error`, each pinned once set; `error` cannot be rewritten | Pipeline writes the receipt **once**, at the end, in the same transaction as the outcome; a retried job that already wrote `error` records the second failure in `jobs`/`audit_events`, never by rewriting `intake.error` |
| `mapping_version`, `resolved_by`, `event_bucket_hash`, `raw_payload` on `alerts` | all `NOT NULL`, no default | The parser must produce all four; `raw_payload` for a replay row is the archive line's object |
| `psycopg_pool`, `fastapi.testclient` | both importable; only `fastapi`/`httpx`/`psycopg` are pinned | Decision 2; `TestClient` is fine (it is FastAPI's, pinned) |
| Category vocabulary | `kb/playbooks/` holds exactly ten: `c2_beacon, data_exfiltration, malware, policy_violation, privilege_escalation, ransomware, recon, ssh_brute_force, suspicious_login, web_attack` | The `Final-Project` map is ported **onto these names** (rename table in T03); values with no playbook are dropped from the map, per phase-1 R5 |
| Leftover scratch databases | `soc_p1t06`, `soc_p1t06_test` exist (P1-T06 is in progress — not P2's) | Every P2 card `dropdb --if-exists` its own name first (DEC-024(e)) |

---

## INBOX items raised by this plan

- `2026-09-06 · P2-T12 · DECISION_REQUEST` — **§6.3 has no webhook-authentication key**, yet
  architecture §3.1 specifies `POST /webhook/alerts` with `X-API-Key + IP allowlist → 401/403`. Two
  keys are needed (`WEBHOOK_API_KEY`, `WEBHOOK_IP_ALLOWLIST`) or the route ships without authentication,
  which it must not. P2-T12 is `should`, off the gate, and blocked on this.
- `2026-09-06 · P2-T10 / P2-T13 · DECISION_REQUEST` — **`intake.via ∈ pull|webhook` cannot mark a
  replay row**, and nothing tells the pipeline to write `alerts.source='replay'`. Default taken
  (decision 3): derive from `via` + envelope shape. Options offered: keep the derivation; or widen
  `via` (§6.1, Owner); or add `intake.source`. The same question returns for `lab` in P6.
- `2026-09-06 · P2-T10 · DECISION_REQUEST` — **the risk formula still weights two abolished asset
  tiers** (`docs/phase-4-enrichment.md:170`; DEC-004 follow-up never taken). Recommended re-weighting
  keeps every worked example unchanged. P2-T10 carries it as the default.
- `2026-09-06 · P2-T15 / P2-T13 · BLOCKER` — **the agent cannot read the manager archive.** Owner
  action: export the 29 daily files as one JSONL readable by `user1`, at a git-ignored path the cards
  name. Without it T15 cannot run and the archive half of the backfill cannot be exercised.

---

## Task table

| Task | Title | Priority | Est. | Depends on | Owner action? |
|---|---|---|---|---|---|
| P2-T01 | `infra/config.py` + `infra/errors.py` | must | 2 h | — | no |
| P2-T02 | `infra/db.py`, `infra/jobs.py`, `infra/worker.py`, `audit/events.py` | must | 3.5 h | P2-T01 | no |
| P2-T03 | `ingest/category.py` — port of the `Final-Project` maps onto the ten playbooks, priority table | must | 2 h | — | no |
| P2-T04 | `domain/alert.py` (Alert, AlertContext, bucket hash) + `ingest/wazuh_parser.py` (three document shapes) | must | 3.5 h | P2-T03 | no |
| P2-T05 | `ingest/dedup.py` — six predicates, advisory lock in SQL, two concurrent sessions | must | 3.5 h | P2-T02, P2-T04 | no |
| P2-T06 | `domain/transitions.py` — 8 public functions, `_apply`, 18 edges, fan-outs, escalate ③a/③b | must | 4 h | P2-T02, P2-T04 | no |
| P2-T07 | `domain/correlation.py` — `summarize_for_prompt`, `correlated_cluster_ids` | must (movable to P3's window) | 2 h | P2-T02, P2-T04 | no |
| P2-T08 | `enrichment/inventory.load` + `enrichment/lookups.py` + `web/main.py` with `POST /api/admin/reload-inventory` | must | 3 h | P2-T02, P2-T04 | no |
| P2-T09 | `ingest/autoclose.py` — six hard blocks, whitelist + three internal fields, ordered match, `simulate` | must | 3.5 h | P2-T02, P2-T04 | no |
| P2-T10 | `soar/risk.py`, `soar/pipeline.py`, `web/worker.py`, G7 test | must | 4 h | P2-T05, P2-T06, P2-T08, P2-T09, P2-T11 | no (INBOX risk-formula default carried) |
| P2-T11 | `infra/puller.py` — `pull_once`, cursor, overlap, heartbeat, `pull` job, recorded fixtures | must | 3.5 h | P2-T02 | **yes** — heartbeat wodle + rule on the manager (live path only) |
| P2-T12 | `infra/intake.py` + `POST /webhook/alerts` | should — **blocked** (INBOX: auth keys) | 2 h | P2-T02, P2-T08, DEC | no |
| P2-T13 | backfill CLI: `--since` (indexer) and `--archive-file` (replay), Owner procedure | must | 2 h | P2-T11 | **yes** — the Owner runs the archive half as root |
| P2-T15 | `eval/dedup_verify.py` — the coded predicates over the archive vs 2,778 | must (movable to P3's window) | 2.5 h | P2-T10, Owner export | **yes** — the archive export |

P2-T14 is folded into P2-T10 (planning decision 10). File scope is disjoint by construction; the two
sequential pairs that touch one file (`web/main.py`: T08 creates, T12 modifies · `infra/puller.py`:
T11 creates, T13 modifies) are ordered by their `Depends on:` fields.

---

### P2-T01 · `infra/config.py` + `infra/errors.py`
- Priority: must · Estimate: 2 h · Depends on: —
- Goal: one typed `Config` object carrying every §6.3 key with its documented default and parse rule, and one error classifier every job handler uses.
- Files — modify: `backend/app/infra/config.py`, `backend/app/infra/errors.py` (docstring skeletons). Create: `backend/tests/test_config.py`, `backend/tests/test_errors.py`.
- Contracts touched: §6.3 — transcribe, do not extend. The key set is asserted against `scripts/gen_env_example.py`'s own extractor so there is one place to be wrong.
- Risk / notes: `LLM_MODEL_PROPOSER` may legitimately be empty in P2 (G7 runs with it unset) — empty means "LLM disabled", not a config error. JSON-valued keys follow DEC-007 item 2.

### P2-T02 · `infra/db.py`, `infra/jobs.py`, `infra/worker.py`, `audit/events.py`
- Priority: must · Estimate: 3.5 h · Depends on: P2-T01
- Goal: connections and transactions with `SET LOCAL statement_timeout`; the `jobs` table as the single queue — enqueue, claim with `SKIP LOCKED`, finish with backoff, reclaim stale locks; a worker loop that dispatches through a handler table it does not own; the audit writer.
- Files — modify: `backend/app/infra/db.py`, `backend/app/infra/jobs.py`, `backend/app/infra/worker.py`, `backend/app/audit/events.py`. Create: `backend/tests/test_db.py`, `backend/tests/test_jobs_worker.py`, `backend/tests/test_audit_events.py`.
- Contracts touched: §6.5 job semantics — transcribe.
- Risk / notes: the partial unique index on `jobs` is what makes the self-scheduled `pull` single-flight — use it, do not reimplement it. No `psycopg_pool`.

### P2-T03 · `ingest/category.py`
- Priority: must · Estimate: 2 h · Depends on: —
- Goal: one resolver, four signals, five tiers, an explicit priority table, `mapping_version`, and every mapped value backed by a playbook file.
- Files — modify: `backend/app/ingest/category.py`. Create: `backend/tests/test_category.py`.
- Contracts touched: none (`resolved_by` CHECK set transcribed from the DB).
- Risk / notes: the `Final-Project` maps are ported by value onto the ten playbook names; four of its values have no playbook and are dropped, recorded in the report for the P3 playbook review.

### P2-T04 · `domain/alert.py` + `ingest/wazuh_parser.py`
- Priority: must · Estimate: 3.5 h · Depends on: P2-T03
- Goal: the `Alert` and `AlertContext` values; a pure parser that accepts an indexer hit, a bare Logstash/`_source` document and a raw archive line, never raises on the classification path, and rejects only when identity is missing.
- Files — modify: `backend/app/domain/alert.py`, `backend/app/ingest/wazuh_parser.py`. Create: `backend/tests/test_wazuh_parser.py`, `backend/tests/test_alert_model.py`, `backend/tests/fixtures/indexer_hit_no_fields.json`.
- Contracts touched: none.
- Risk / notes: F4, DEC-014 (no-`agent` fallback, no frequency cited), DEC-019 (keep the `_source.timestamp` fallback). `event_time` is always NULL (planning decision 5).

### P2-T05 · `ingest/dedup.py`
- Priority: must · Estimate: 3.5 h · Depends on: P2-T02, P2-T04
- Goal: `cluster_lock`, `find_open_cluster`, `bump_parent` exactly as phase-2 specifies, with the lock key built in SQL and proven serialising across two sessions.
- Files — modify: `backend/app/ingest/dedup.py`. Create: `backend/tests/test_dedup.py`.
- Contracts touched: none.
- Risk / notes: `EXPLAIN` must show `ix_alerts_dedup`; `FOR UPDATE` repeats the partial predicate in `Filter` and that is not a miss (phase-2 D7 note).

### P2-T06 · `domain/transitions.py`
- Priority: must · Estimate: 4 h · Depends on: P2-T02, P2-T04
- Goal: the only place `status` changes — eight public functions over one `_apply()`, audit in the same transaction, fan-outs, the two-statement escalate with rowcount check, `StaleState` (409) and `IllegalTransition` (500).
- Files — modify: `backend/app/domain/transitions.py`. Create: `backend/tests/test_transitions.py`.
- Contracts touched: none (event types from the 27-set; `alerts` CHECKs transcribed).
- Risk / notes: the largest card. The 18 × 2 matrix is the gate item; the `alerts` cross-column CHECKs decide what each edge must write.

### P2-T07 · `domain/correlation.py`
- Priority: must (movable to P3's window) · Estimate: 2 h · Depends on: P2-T02, P2-T04
- Goal: `summarize_for_prompt` (grouped rows + ≤ 5 samples) and `correlated_cluster_ids` (status-filtered, LIMIT 200), read-only, using the three v1 indexes.
- Files — modify: `backend/app/domain/correlation.py`. Create: `backend/tests/test_correlation.py`.
- Contracts touched: none.
- Risk / notes: E4 — nothing is written; E5 — ≤ 20 grouped rows.

### P2-T08 · `enrichment/inventory.load` + `enrichment/lookups.py` + `web/main.py`
- Priority: must · Estimate: 3 h · Depends on: P2-T02, P2-T04
- Goal: the three files upsert into `assets`/`identities`/`iocs` with `source`, `loaded_at`, `active`, absent rows flipped inactive; three deterministic lookups with three-state results; the reload endpoint on a FastAPI app that now exists.
- Files — modify: `backend/app/enrichment/inventory.py`. Create: `backend/app/enrichment/lookups.py`, `backend/app/web/main.py`, `backend/tests/test_inventory_load.py`, `backend/tests/test_lookups.py`, `backend/tests/test_reload_inventory.py`.
- Contracts touched: §6.4 route `POST /api/admin/reload-inventory` — created as listed; its `admin` role dependency is P4's (hand-off).
- Risk / notes: `enrichment` may import only `infra` — lookups return dicts; the `AlertContext` is built in `soar/pipeline.py` (decision 4).

### P2-T09 · `ingest/autoclose.py`
- Priority: must · Estimate: 3.5 h · Depends on: P2-T02, P2-T04
- Goal: six hard blocks in the specified order before any rule; whitelist + `asset_criticality`, `identity_privileged`, `ioc_reputation`; deterministic ordered match; `simulate(match)` counts; fail-open.
- Files — modify: `backend/app/ingest/autoclose.py`. Create: `backend/tests/test_autoclose.py`.
- Contracts touched: none.
- Risk / notes: no 5 % sample, no sample flag (decision 7). The match-everything-rule test is the G8′ enforcement named in §2.

### P2-T10 · `soar/risk.py` + `soar/pipeline.py` + `web/worker.py` + G7
- Priority: must · Estimate: 4 h · Depends on: P2-T05, P2-T06, P2-T08, P2-T09, P2-T11
- Goal: one intake → one outcome in one transaction (advisory-lock region excepted); `jobs('triage')` in the same transaction as `queued_tier1` **and** as `auto_closed`; `intake` receipt written once; the worker wired; **G7 green**.
- Files — modify: `backend/app/soar/risk.py`, `backend/app/soar/pipeline.py`, `Makefile` (one line). Create: `backend/app/web/worker.py`, `backend/tests/test_risk.py`, `backend/tests/test_pipeline.py`, `backend/tests/test_g7_llm_off.py`.
- Contracts touched: none. Carries the INBOX risk-formula default and the `source` derivation default (decisions 3, 8).
- Risk / notes: E6 (kill between `queued_tier1` and `jobs('triage')` leaves nothing half-done) is a real crash test, not a mock.

### P2-T11 · `infra/puller.py`
- Priority: must · Estimate: 3.5 h · Depends on: P2-T02
- Goal: `pull_once`, the `search_after` cursor with 60 s overlap, idempotent intake, `is_heartbeat` updating `source_heartbeat` and creating nothing else, the self-scheduled `pull` job, TLS always verified.
- Files — modify: `backend/app/infra/puller.py`. Create: `backend/tests/test_puller.py`, `backend/tests/fixtures/indexer_search_page_2.json`, `backend/tests/fixtures/indexer_heartbeat_hit.json`.
- Contracts touched: none (§6.3 `INDEXER_*`, `PULL_*`, `HEARTBEAT_*` unchanged).
- Risk / notes: requests `"fields":["timestamp"]` (decision 6). The heartbeat fixture is constructed — the wodle is not installed (Owner action).

### P2-T12 · `infra/intake.py` + `POST /webhook/alerts`
- Priority: should — **blocked on INBOX (webhook auth keys)** · Estimate: 2 h · Depends on: P2-T02, P2-T08, the DEC
- Goal: the secondary intake path — ≤ 2 MB, authenticated, `201/401/403/413/409`, identical downstream behaviour.
- Files — modify: `backend/app/web/main.py`. Create: `backend/app/infra/intake.py`, `backend/tests/test_webhook.py`.
- Contracts touched: §6.3 — **needs two new keys** (the INBOX item). Do not dispatch before the DEC.
- Risk / notes: proposed to move to P4 (budget note, lever 1).

### P2-T13 · backfill CLI
- Priority: must · Estimate: 2 h · Depends on: P2-T11
- Goal: `python3 -m app.infra.puller backfill --since <date>` for the indexer and `--archive-file <jsonl>` for the manager archive, each line stored byte-identical as a replay intake row with `sort_key` = epoch-millis of its own timestamp; the Owner's exact procedure printed by `--help`.
- Files — modify: `backend/app/infra/puller.py`. Create: `backend/tests/test_backfill_cli.py`.
- Contracts touched: none.
- Risk / notes: the archive half is **Owner-run**; the agent proves it on `backend/tests/fixtures/archive_line_5503.json` and on a two-line synthetic file that is clearly marked.

### P2-T15 · `eval/dedup_verify.py`
- Priority: must (movable to P3's window) · Estimate: 2.5 h · Depends on: P2-T10, **Owner archive export**
- Goal: the product parser + cluster key + the six predicates folded over `alert_time` across the archive; prints total clusters, per-day clusters, the 16/08 storm's clusters; verdict against 2,778.
- Files — create: `eval/dedup_verify.py`, `backend/tests/test_dedup_verify.py`.
- Contracts touched: none.
- Risk / notes: decision 9 explains why this is not a pipeline replay. A material departure from 2,778 is a defect in the implementation, not a new fact about the data (`prompts/P2.md`).

---

## Hand-off to P3 and beyond

1. **P3 owns the `triage` handler.** P2's worker claims only job types it has a handler for
   (`pull`, `pipeline`); `triage` rows stay `pending` untouched. P3 registers its handler in
   `web/worker.py` and must not change how `claim_job` filters.
2. **P4 wraps `POST /api/admin/reload-inventory` with the `admin` role dependency.** P2 ships the
   route without authentication because `infra/auth.py` is P4's; the pilot does not start before P4.
   Named here so it is not forgotten.
3. **P4 gets the webhook (P2-T12) if the budget lever is taken**, together with the two §6.3 keys the
   INBOX item asks for.
4. **P6's `lab` source has the same problem `replay` had** (INBOX: `intake.via`). If the Director takes
   the derivation route for P2, P6 needs its own rule or the column; decide before P6's loader is
   carded.
5. **DEC-004's playbook follow-up is still P3's**: `kb/playbooks/malware.md:36` and
   `kb/playbooks/ssh_brute_force.md:34` branch on a criticality value that no longer exists; rewritten at
   the P3 playbook review. `ingest/category.py` (P2-T03) reports the four `Final-Project` categories it
   dropped for lack of a playbook — the same review decides whether any of them gets one.
6. **`CLOCK_SKEW_WARN_SECONDS` (phase-4 P4-3) is not a §6.3 key.** P2 does not implement the skew
   warning; P5's health job is where `|alert_time − received_at|` belongs, and adding the key is a P5
   INBOX item if the Owner wants it.
7. **P8 limitations inherited from this phase:** no connection pool (decision 2); the archive
   backfill is an Owner-run root operation, not an application path (DEC-019); rule-cache TTL 60 s
   means a disabled rule keeps closing for up to a minute (phase-3 AC-C4) — and C8 cut the sweeper,
   so the 30-minute auto-closed cluster cap is the only other bound.
