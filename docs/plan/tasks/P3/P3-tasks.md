# P3 · AI pipeline ① — task cards

Phase objective: proposer → gate → verifier, safe by construction, running live on replayed alerts.
Written **15/09/2026** (Planner P3), against `prompts/P3.md` as amended 07/09 **and** DEC-048…DEC-080,
none of which that brief had seen. Where a DEC and the brief disagree, the DEC wins and the
divergence is named in §1 below.

**DEC-007 item 7 / DEC-009 — which copy of a card is authoritative.** Each task has a full
`docs/plan/tasks/P3/<TASK_ID>.prompt.md` and a shorter entry in this file. **The prompt is the
card**; this file is the Planner's index — estimates, waves, dependencies, risk notes. Where this
file restates an acceptance command it matches the prompt verbatim or does not appear. A divergence
is a Director defect, not a Coder's judgement call.

---

## ⚠️ Budget note — `must` is 29 h against an 8 h day; wall-clock ≈ 15 h at three coders

| | |
|---|---|
| Sum of `must` estimates | **29 h** (12 cards: eleven P3 cards + P2-T07, which DEC-041 put in this window) |
| Day budget (`prompts/P3.md`: 1 day) | 8 h |
| Overbooking | **+263 %** — the re-plan threshold is 30 % |
| Wall-clock at the 3-coder cap | **≈ 15 h** — the chain, not the hour sum (wave table in §4) |
| Longest chain | T01 (1.5) → T02 (3) → T03 (2) → T09 (3) → T10 (4) → T11 (1.5) = **15 h** |
| Calendar available | **16/09 and 17/09** — DEC-071 dates P3 at 17/09 and P4 at 18/09; P2 closed the evening of 15/09 (DEC-079), five days before its trigger, so the day the schedule had lost is back |
| `should` | T12 playbook vocabulary (0.5 h) — and the detector's heuristics 4–8 inside T07 (the brief's own cut candidate) |

**What the arithmetic means.** Two full days at three concurrent sessions land every `must` card by
the **evening of 17/09** if intake runs are batched (DEC-048: 0.47 h per batched merge against 10 h
unbatched — with six sequential merge gates in this chain, batching is worth more than any cut).
Nothing is proposed for "next morning" by default; the two candidates if 17/09 runs long are **T11**
(the live run is the Owner's to execute anyway — the Coder's half is 1.5 h of test + script) and
**T12** (`should`). The one `should` to drop first is the detector's heuristics 4–8 (T07 ships the 20
regex patterns and heuristics 1–3 as `must`; 4–8 are marked `should` inside the card).
**P3's exit gate does not need the Owner's decision-table content** — the skeleton tables ship
unreviewed (`reviewed_by: null`), ① runs, `playbook_used` is forced null with a warning (architecture
§3.10), and `gate_result` is written. The authored tables are what B1 and gate step 4 need for P7,
not for this gate.

---

## 1 · What changed since the brief — DEC-048 → DEC-080, read before any card was written

The brief was last amended 07/09 and cites nothing past DEC-047. Thirty-three decisions have landed
since. Those that change this phase, and how:

| DEC | Changes this phase how | Where it landed |
|---|---|---|
| **DEC-071** (schedule) | **Contradicts the brief's dates.** "P3 starts 09/09" and "D4 08/09" are history: P3 is **17/09**, P4 **18/09**, deadline **02/10**. DEC-079 closed P2 on 15/09, so 16/09 is also P3's. Planned against 16–17/09. | header, budget note, waves |
| **DEC-079** (P2 gate met) | `alerts` holds **95,952** rows = `replay` 92,011 + `wazuh` 3,941; `queued_tier1` **383** (= 307 replay heads + 76 wazuh heads), `duplicate` 95,569; **383 `triage` jobs pending with no handler** (`web/worker.py:24` wires `pull`/`pipeline` only). T10 registers the handler. **The live gate item is satisfiable today** — the live task drives that queue, not fixtures. | T10, T11 |
| **DEC-079 (vi)** / **DEC-077** | **Denominators.** 19 of 92,030 archive lines were rejected (missing `rule.description`) and their jobs still `succeeded`; the replay corpus is **92,011** alerts. T15's fold: 3,051 clusters / 92,011 parsed; DEC-053's independent count: 3,070; the 29-day 2,778 is history. Every per-alert figure in a card uses 92,011; every cluster count names its corpus. | every card that quotes a number |
| **DEC-052 / DEC-057** | `unknown` is a first-class category (59.0 % of G1's 3,070 clusters; **190 of 383** queued heads today). `kb.get_playbook("unknown")` → `None`, no decision table; ① still runs with the no-playbook sentence outside the block; **`apply_table` is P7's B1 baseline** — its no-match answer is `needs_review`, and it must be a pure function P7 can call offline. | T06, T09 |
| **DEC-055** | `web_attack` has **zero** live clusters after the `attack` fix; the queue's classified heads are `ssh_brute_force` 146, `suspicious_login` 32, `privilege_escalation` 15 (of 383). The live run exercises those three tables plus `unknown`; skeletons ship for all ten regardless. DEC-055's "named, not fixed" `sudo → privilege_escalation` (57 clusters of rule 5402) is a decision-table matter for the Owner's authoring sitting, recorded in the Owner action. | T06, Owner action |
| **DEC-058 / DEC-066 / DEC-051** | `DESKTOP-MIRSO17` (18 of the 383 heads) stays out of the inventory → `asset_criticality = unknown` → step 4 forbids `false_positive`: **expected, and evidence**, not a defect. `HR-computer` and `wazuh.manager` are in `conf/inventory.yaml` — but see §5, finding 1: the inventory has never been loaded into `soc_dev`. | T11 expectations, INBOX |
| **DEC-054 / 067 / 072 / 074 / 077** (card defects, five in three days) | Card-writing rules this index applies: every acceptance names a **red step that discriminates** (DEC-025); use `-vv`, never `-v`, when a `PASSED` line is grepped (`addopts` carries `-q`); "`skipped` absent" is claimed only for the card's own files, never for a suite run (§3); a figure carries its denominator; when a design note changes what an acceptance measures, the acceptance is re-read. | every card |
| **DEC-073 / DEC-080** | `test_dispatch_state.py` invariant 3 now **skips off `main`** (committed `c522d9c`), so every task branch shows that skip in `make test`; `test_transitions.py` shows two `P2-T07 not merged` skips until P2-T07 lands. Suite-level acceptance therefore says **exit 0**, and per-file runs say `skipped` absent. | §3, every card |
| **DEC-048** | Batched intake. Cards are on disjoint files by construction (§6); the two files P3 touches that P2 owns (`web/worker.py`, `backend/tests/test_transitions.py`) are each in exactly one card. The Director's composition check before `main` is assumed for the T09+T10 batch. | §6, T10 |
| **DEC-049** | P2's cards left `superseded.yaml`'s scan on 15/09; **P3's cards are in scope.** Every card was checked against the 58 live patterns: the value DEC-004 abolished appears only in T12, on a line carrying the `superseded-ok` marker. | T12 |
| **DEC-047** (in the brief) + **DEC-054 item 6** | `output_schemas.json` is §6.2 copied into a file → T05 ships `scripts/check_output_schemas.py --check` in `make lint`. The `.env` rule holds: only the live test names `.env`, explicitly, and skips without it. | T05, T11 |
| **DEC-070 / DEC-065** | `.env` now carries the rebuilt stack's indexer values. P3's code never touches the indexer; the live run needs `DATABASE_URL` + `LLM_*` only — measured present 15/09 (`LLM_MODEL_PROPOSER=deepseek-v4-flash`, prices set, `LLM_THINKING` unset → default `disabled`). | T11 |
| **DEC-041** (in the brief, now half-stale) | Of the two P2 cards the brief expects in this window, **P2-T15 is `done`** (DEC-079). Only **P2-T07** remains: 2 h, dependencies merged, runs in parallel — not "≈ 4.5 h before P3's first card". Its card is amended (§2) so the two `test_transitions.py` skips retire with it. | §2, waves |

No DEC in 048–080 changes a §6 contract P3 reads: §6.2's three schemas, §6.3's `LLM_*` keys and
§6.5's `triage` job are as the brief describes. DEC-050, 056, 059–064, 068, 069, 075, 076, 078 do not
reach this phase.

**STATE.md `## Agent actions` rows addressed to a Planner — swept, with the verdict:**
- **Planner P3 (DEC-033)** — the adapter's wall-clock deadline with a fake that stalls past it: **absorbed**, T04 design note 3 + acceptance 4 (the Director's E5 check for that row).
- **P1 Planner (DEC-004), the surviving half** — the two playbook lines still branching on the abolished value: **absorbed**, T12 (`should`, 0.5 h, the exact two-line diff) + the Owner-action row for the content review and the dropped-category decision.
- Rows addressed to Planner P2 (DEC-014 ×2, DEC-019 — all closed by command 07/09), Planner P4/P6 (DEC-019), Planner P5 (DEC-032), Planner P6 (DEC-035, DEC-014, DEC-012), P8 (DEC-012): **not mine, not touched.**
- The Owner-action row asking to reopen Planner **P2** for two card fixes (P2-T09 acceptance 4, P2-T11's procedure block): not mine — both tasks are `done` and DEC-064/069/074 already carried the fixes.
- **Also absorbed from a task row, not the agent section:** P1-T01's Reviewer note (3) — `eval/smoke_test.py`'s `injection_outcome.quoted` reads the first response even after a repair, "must patch one line before any re-measurement in P3". **No P3 card re-measures with `smoke_test.py`** (the live run uses the product adapter), so the patch is not on this phase's path; carried to P7's hand-off in §8, where the paired ablation is.

---

## 2 · Dispatch state — read this before dispatching anything

**Precondition: none.** Measured on `main` @ `c522d9c` while planning: P2-T02, T04, T05, T06, T08,
T09, T10, T11, T13, T15, T16 are merged; `make test` 551 passed, 1 skipped (`test_dispatch_state.py`,
empty parameter set), 424 deselected, 3 xfailed; `make lint` exit 0. `git branch` has no
`task/P2-T07` and no `task/P3-*` — nothing has been dispatched.

| | |
|---|---|
| Dispatchable now | **P2-T07** (2 h, deps merged), **P3-T01**, **P3-T04**, **P3-T05**, **P3-T06**, **P3-T07**, **P3-T12** — all with no P3 dependency. Three slots → wave 1 is T01 + T04 + T05 (the chain head, the longest independent card, the file the chain reads). |
| Blocked on an Owner action | **nothing on the exit gate.** T11's live half is Owner-run (real key), but the Coder's half — the test, the runner, the deletion — needs nothing. |
| Owner actions this phase | (1) author the ten decision tables with the advisor and set `reviewed_by/at` (§11; needed by P7, not by this gate); (2) run T11's live test with the real key from the primary checkout; (3) answer the two INBOX questions in §5 before P4's pilot / P6's sizing. |

**P2-T07's card is amended, not rewritten** (banner dated 15/09 at the top of
`tasks/P2/P2-T07.prompt.md`): `backend/tests/test_transitions.py` enters its **Files — modify** list
so the two `@pytest.mark.skip(reason="P2-T07 not merged")` decorators at `:1274` and `:1292` are
removed on the same branch, and acceptance 1 gains the `0 skipped` line for that file. Without that
the two skips outlive the dependency they name — the DEC-072 shape.

---

## 3 · Rules every card follows (so the Reviewer can grep for them)

1. Every pytest line is `python3 -m pytest -c backend/pyproject.toml …` (DEC-005). Every db-marked line sets `TEST_DATABASE_URL=postgresql:///soc_p3t<nn>_test` inline, passes `-rs`, adds no `-q`, and states `N passed` with **`skipped` absent for that file** (DEC-023 item 8). Whole-suite runs (`make test`, `make test-db`, `make lint`) are judged on **exit 0** — `make test` carries `test_dispatch_state.py`'s off-`main` skip on every branch (DEC-080), and `make test-db` carries `test_transitions.py`'s two skips until P2-T07 merges.
2. A named test is grepped with `-vv` (never `-v`: `addopts = -q` nets it to verbosity 0 — DEC-074, P2-T09 and P2-T10 both hit it).
3. Every acceptance names its **red step**, and the red step discriminates (DEC-025, DEC-077).
4. LLM calls in tests go through `backend/tests/fakes/llm.py`'s `FakeLLM` or a fake OpenAI client injected into the real adapter; no test opens a socket to DeepSeek. The one `@pytest.mark.live` test skips, never fails, without `.env`.
5. No test reads the real `.env` except by naming it (`config.load(env_file=".env")` in the live test only) — DEC-047. No test uses the `db` fixture against a database not named `*_test`; **the live test never touches the `db` fixture at all** (it would drop `soc_dev`).
6. `jsonschema` is not imported anywhere (it is installed on this host and absent from `backend/requirements.txt` — the P1 trap); the validator is stdlib.
7. Import rules hold (`ALLOWED` in `test_import_rules.py`): `security → infra` only, `llm → security|infra|kb`, `kb → infra`, `audit → infra`, `tier1 → domain|llm|kb|security|infra|audit`. **Consequence (planning decision 2):** the gate cannot import `kb` or `llm`; the decision-table check and the verifier call reach it as injected callables from `tier1/triage.py`.
8. `superseded.yaml` scans these cards (DEC-049). No bare `pytest`, no dead migration ranges, no retired host or service names, and the abolished criticality value only on a line carrying the `superseded-ok` marker. This index was itself caught once by the scanner while being written (a dead migration range quoted as an example of what not to write) — the guard fires on the letter, not the intent.

---

## 4 · Critical path and waves

Estimates are for the card as written; dependencies are the `Depends on:` field of each prompt, and
where this diagram and a field disagree, the field wins (DEC-007 item 6). `t` = coder-hours from
16/09 08:00 at three concurrent sessions; review/merge cycles counted as zero, which they are not.

```
t=0     P3-T01 wrap (1.5)              P3-T04 adapter (3)               P3-T05 templates+schemas (2)
t=1.5   P3-T02 builder (3)  ←T01
t=2                                                                     P3-T06 kb+tables (2.5)  ←T05 slot
t=3                                    P3-T07 detector (1.5)
t=4.5   P3-T03 linter (2)   ←T02       P2-T07 correlation (2)           P3-T08 gate+guard (3)  ←T01,T05
t=6.5   P3-T09 llm/triage (3) ←T02,T03,T04,T05,T06,P2-T07
t=7.5                                  P3-T12 playbook lines (0.5, should)   [slot idle after]
t=9.5   P3-T10 tier1 job + llm_runs + worker (4) ←T07,T08,T09
t=13.5  P3-T11 live test + runner + delete top-level llm/ (1.5) ←T10
t=15    done — the Owner's live run and the Director's gate check follow
```

**Why T09 waits on six cards.** `llm/triage.py` renders the ① blocks with the builder (T02), must pass
the linter (T03), calls the adapter (T04), validates against the frozen schema (T05), reads the
playbook and table through `kb` (T06) and places `CorrelationRow`s as facts (P2-T07). It is the
integration point; everything before it is a leaf.

**Why the gate (T08) does not wait on T09.** Its inputs are data — the parsed proposer dict, the
facts dict, the `block_index` — plus two callables. It is proven on crafted JSON (the brief's test
list) with no prompt built at all, which is what lets it run in wave 2.

**Why T10 is 4 h.** It is the only card that touches a real database end to end with the fake
adapter, carries the idle-timeout proof (an 11-second test), wires the worker, and writes both
`llm_runs` rows; it is also where every other card's contract is first exercised together.

---

## 5 · Environment measured today (15/09, `soc_dev` through `config.load()`'s `DATABASE_URL`), and where it changes a card

| Claim in the brief or a spec | Measured | Consequence |
|---|---|---|
| "① runs live on ≥ 50 replayed alerts" is satisfiable | `alerts`: `replay` **92,011** + `wazuh` **3,941** = 95,952; `queued_tier1` **383** = **307 `replay` heads** + 76 `wazuh` heads; `jobs`: `triage|pending` **383**, no handler; `llm_runs` **0** rows; `triage_status` `pending` on all 95,952 | T11 drives the real queue, bounded at 150 claims, until ≥ 50 `replay` proposer rows exist |
| Categories on the queue | `unknown` 190 · `ssh_brute_force` 146 · `suspicious_login` 32 · `privilege_escalation` 15 (of 383; among the 307 replay heads: 143 / 125 / 26 / 13) | The live run exercises three tables + the no-playbook path; the other seven skeletons are exercised by the consistency test only |
| Severity on the queue | `low` 167 · `medium` 161 · `high` 45 · `critical` 10 (of 383) | ten alerts hit step 4's `severity = critical` bar live |
| **Finding 1 — the inventory was never loaded into `soc_dev`.** `assets`, `identities`, `iocs` are all **0 rows**; `conf/inventory.yaml` carries `IA1803`, `user1-IA1803`, `wazuh.manager`, `HR-computer` and `validate()` → `[]`, but nobody ran `inventory.load()` / `POST /api/admin/reload-inventory` against the application database | **`asset_context.criticality = 'unknown'` on all 383 heads** (`lookup_status.asset = not_found` on 383/383), including the 289 replay heads from `user1-IA1803`/`IA1803`, which *are* in the file; `identity_context.privileged` is `null` on 383/383. ① reads the facts stored at enrichment time (phase-5: `user_message` must reconstruct what the model saw), so loading the inventory now does not change them | **Step 4 forbids `false_positive` on every alert in the live run** (`asset ∈ {high, unknown}`), so the live run cannot exercise the FP-survives branch; the crafted-JSON tests do. T11 states the expected shape (0 FP survive, `missing` carries `asset_criticality`). **INBOX QUESTION filed** (evaluation validity: G8′ "fired" on 100 % of G1's stored heads, not on 0.7 %) — the Owner's, before P4's pilot and P6's sizing |
| **Finding 2 — the database holds 307 replay heads, not ≈ 3,051/3,070 clusters.** The replay ran the archive through the pipeline in one sitting, and the dedup predicates anchor on `now()` (P2-tasks.md planning decision 9 predicted exactly this: wall-clock windows collapse a month into a few hundred clusters; `occurrence_count` max is 1000 = `MAX_CLUSTER_SIZE`) | 307 heads ≥ 50, so P3's gate is unaffected | **P6 is affected**: `build_gold.py` sized against 3,070 clusters cannot draw them from this table. Same INBOX item, second question |
| `raw_log` size on the queue | p50 91 chars · p95 603 · max 3,439 | No block is truncated live (`PROMPT_LOG_MAX_BYTES` 32,768); truncation and the budget cut order are unit-tested only |
| `occurrence_count` on the queue | p50 12 · max 1000 | the `sbf-1`-style `occurrence_lt` conditions have live variance |
| `.env` for the live run | `LLM_BASE_URL=https://api.deepseek.com/`, `LLM_MODEL_PROPOSER=deepseek-v4-flash`, `LLM_MODEL_VERIFIER=deepseek-v4-flash`, `LLM_PRICE_IN_PER_M=0.014`, `LLM_PRICE_OUT_PER_M=0.66`, `LLM_MONTHLY_USD_CAP=30`, `LLM_API_KEY` set, `LLM_THINKING` unset → `disabled`, `DATABASE_URL` set | T11 needs no `.env` edit. Cost of the live run: ≤ 150 alerts × 2 calls × ≈ $0.00024 (P1-T08: $0.0091 / 38 calls) ≈ **$0.07** |
| `infra/db.py`'s transaction sets `idle_in_transaction_session_timeout = '10s'` | A second `SET LOCAL` inside the same transaction overrides it — measured 15/09 (`2s` then `6s` → `SHOW` = `6s`, session alive at 3.5 s) | The triage handler raises it to `JOB_LOCK_TIMEOUT_S` (300 s) for its own transaction and proves it with an 11-second stalled fake (T10) — without it, any model call over 10 s kills the session mid-job |
| Model latency (P1-T08, `LLM_THINKING=disabled`) | p50 1.83 s · p95 3.65 s · ≥ 30 KB class p95 2.82 s · 100 % JSON · 100 % schema-valid first try · 33,564 bytes ↔ 12,576 prompt tokens (2.67 B/token) | Token estimate uses 2.5 bytes/token (conservative); two calls per alert fit inside `JOB_LOCK_TIMEOUT_S` with two orders of magnitude to spare |
| `kb/playbooks/` location | ten files at the **repo root** `kb/playbooks/`, and `test_category.py:32` pins that path (`REPO_ROOT / "kb" / "playbooks"`); `backend/app/kb/` holds only `lookup.py` | `kb/decision_tables/*.yaml` sit beside the playbooks at the repo root; `lookup.py` resolves `REPO_ROOT` from its own path, overridable for tests (planning decision 5) |
| `Final-Project`'s detector | `/home/user1/Documents/Final-Project/backend/app/security/prompt_guard.py`: **19** regex patterns, a base64-run check, a verb/qualifier proximity check; stdlib; detection-only (DEC-002 measured it clean) | T07 ports the 19, adds one, and states the 8 heuristics — 3 ported, 5 new and `should` |
| `jsonschema` | importable on this host, **not** in `backend/requirements.txt` | rule 6 |

---

## 6 · Planning decisions (tactical — Director may promote to a DEC)

1. **`llm_runs.result` holds the gated result; the raw model output is kept in `gate_result.proposer_raw`.** G11 says a `false_positive` verdict exists only after all seven steps pass. If `result.suggested_action` carried the model's ungated verdict, every reader — P4's detail page, phase-5's auto-close comparison query (`r.result->>'suggested_action'`), P7's joins — would have to remember to read `gate_result.final_verdict` instead, and one of them would forget. So the proposer row's `result` is the `triage_v2` object with `suggested_action` = the final verdict and `reasons` = the surviving reasons; `gate_result` records `proposed_verdict`, `final_verdict`, `forced`, `forced_by`, `steps`, `missing`, `hallucination_flag`, `mismatched_fields`, `dropped_reasons`, `facts`, `warnings`, `verifier_verdict`, `prompt_version` and the untouched parsed model JSON as `proposer_raw`. P4's `tier1.decided` payload reads `gate_result.forced` (its brief says so); P7 re-gates from `proposer_raw`. **G11 holds on the column, structurally.**
2. **G1 forces dependency injection into the gate.** `security` may import only `infra`. Step 4 needs the decision table and step 6 needs a model call; neither `kb` nor `llm` is importable from `security/`. So `security/gate.py` is pure over data — the parsed dict, `facts`, `block_index` — plus two callables `tier1/triage.py` builds: `rule_check(rule_id) -> (holds: bool, why: str | None)` (wrapping `kb.rule_holds` and the `reviewed` gate) and the verifier result, which tier1 obtains from `llm.triage.verify()` and hands to `gate.step6()`. The brief's "orchestrating the verifier call for step 6" is satisfied by the gate deciding *when* and *against what* the verifier's answer is compared; the *call* is made one package up, where the import is legal.
3. **The handler owns the terminal outcome on the last attempt; it never raises there.** `infra/worker.py` rolls the handler's transaction back on any exception, so a handler that writes `unavailable` and then raises loses the write. Rule: on a transient failure with `job.attempts < JOB_MAX_ATTEMPTS` the handler raises `TransientError` (the job retries with backoff); on the last attempt it writes the `llm_runs` row with `result = NULL`, `stopped_by = 'transient'`, sets `triage_status = 'unavailable'`, writes `job.exhausted` and returns — the job records `succeeded` because the job's own contract (record an outcome) was met. `unavailable` is a valid state, not an error (phase-5).
4. **The handler raises its own idle-in-transaction timeout.** The worker wraps every handler in `transaction(conn, statement_timeout="3s")`, which also sets `idle_in_transaction_session_timeout = '10s'`. A model call is client-side idle time. The triage handler's first statement is `SET LOCAL idle_in_transaction_session_timeout = '<JOB_LOCK_TIMEOUT_S>s'` (300 s — the same bound after which `reclaim_stale` would hand the job to another worker, so the two limits agree by construction; measured p95 per call is 3.65 s). `infra/db.py` is not touched.
5. **Data under repo-root `kb/`, code under `backend/app/kb/`.** P2-T03 put the ten playbooks at `kb/playbooks/` and its test pins the path; the decision tables go beside them at `kb/decision_tables/<category>.yaml`. `backend/app/kb/lookup.py` computes `KB_ROOT = Path(__file__).resolve().parents[3] / "kb"` and every public function takes `root: Path = KB_ROOT` so tests point it at a temp dir. §4's package-map line lists the data files under the `kb/` *package*; the layout on disk is the one P2 established — an annotation for the context pack, not a contract change (nothing imports a playbook).
6. **The decision-table format.** One YAML per category: `category`, `playbook` (the `<category>_v1` name from the playbook's title), `reviewed_by: <string | null>`, `reviewed_at: <ISO date | null>`, `rules: [{id, if, then}]`. `id` matches `^[a-z]{2,6}-\d{1,2}$` (so it can stand outside a block as an `Id`); `if` keys ∈ {`severity`, `ioc_reputation`, `asset_criticality`, `identity_privileged`} (list membership over the §6.2 enums, `identity_privileged` over `true|false|unknown` as strings) ∪ {`occurrence_lt`, `occurrence_gte`, `rule_level_lt`, `rule_level_gte`} (ints); `then` ∈ `false_positive|needs_review|escalate`. First matching rule in file order wins. `apply_table(table, facts) -> (action, rule_id) | None` is pure and ignores review status; `rule_holds(table, rule_id, facts) -> bool | None`; `check_consistency(table) -> list[str]` walks the generated fact grid — `rule_level ∈ {0, 3, 5, 8, 12, 15}` with `severity` **derived** from it by the DEC-053 band (not a free axis: `severity=low` with `rule_level=12` is an impossible point and would make every FP rule contradict every `rule_level_gte: 12` rule) × 5 IoC × 4 asset × 3 identity × occurrence ∈ {1, 10, 49, 50, 100, 999, 1000} = 2,520 points — and names any two rules with different `then` that both hold at one point. Unreviewed table → the gate's `rule_check` answers "missing" and `gate_result.warnings` carries `decision_table_unreviewed:<category>`; the playbook *text* block is still sent (§3.10: ① still runs).
7. **The `facts` dict is built once, stored in `gate_result.facts`, and is what step 2, step 4, the verifier prompt and B1 all read.** Keys: `severity`, `category`, `rule_level`, `occurrence_count` (at build time), `ioc_reputation`, `asset_criticality`, `identity_privileged` (`"true"|"false"|"unknown"` from `identity_context.privileged` `true|false|null`), `correlated_clusters` (sum of `CorrelationRow.cluster_count`), `correlated_by_category` (`{category: cluster_count}`), `first_seen_at`, `last_seen_at` (ISO). All values are closed-set, int or ISO datetime — every one of them may stand outside a block.
8. **The ① prompt's block sources are exactly `triage_v2.reasons[].source`'s five values**, one block each: `rule_description`, `wazuh_raw_log`, `context`, `correlation_samples`, `kb_playbook`. The verifier prompt has one block, `source="proposer"`. `untrusted()` accepts the union; `build_proposer_prompt` uses only the five. A quote naming a source that was not emitted (no `context` block because every lookup was `not_found`) is dropped at step 3 as `unknown_source`.
9. **The repair round is a fresh single-turn call whose feedback names paths and expected kinds, never values.** `llm/schemas.py`'s error strings are of the form `structured_basis.asset_criticality: expected one of high|medium|low|unknown` — the offending value is never echoed — so the repair suffix is template constants + field paths + enum vocabularies and passes the linter without a block. The previous answer is not replayed (it would be free text outside a block).
10. **Cost is computed from `usage`, never from a character count**, with the P1-T08 formula: `cost_usd = usage.prompt_tokens/1e6 * LLM_PRICE_IN_PER_M + usage.completion_tokens/1e6 * LLM_PRICE_OUT_PER_M` (`completion_tokens` includes reasoning tokens, which are 0 in `disabled` mode and billed at the output price otherwise). The monthly cap check is `select coalesce(sum(cost_usd), 0) from llm_runs where created_at >= date_trunc('month', now())` ≥ `LLM_MONTHLY_USD_CAP` → `LLMBudgetExceeded` before any socket opens; the handler records `stopped_by = 'cap'` and `unavailable` (architecture §4.6: "vượt → ① unavailable"). The adapter takes the spend as an injected callable because `llm` may not import `audit`.
11. **Three `stopped_by` values plus two, all lower-case strings, no CHECK (§6.1 gives it none):** `schema` (invalid after one repair), `cap`, `linter` (builder violation — the prompt is recorded, no call is made), `transient` (last attempt exhausted), `disabled` (`LLM_MODEL_PROPOSER` empty — no row is written, only `triage_status`).
12. **`P3-T01` of the brief's decomposition (move the legacy files) is folded into T05.** Nothing under `backend/` imports the top-level `llm/`; the two system prompts move with `git mv` in the card that rewrites the templates directory, the v1 `output_schemas.json` and `tools.json` are deleted with the directory in T11. One fewer dispatch → review → merge cycle (DEC-048).
13. **The detector runs on block *contents*, never on the assembled prompt.** Run on the whole user message it would match the template's own instructions. `detector.scan(blocks) -> list[Finding]` takes `block_index`; findings carry the block `source`. Level `high` if any instruction-shaped category, `medium` if only obfuscation, `none` otherwise. It changes nothing (step 5; v3 §4.2 supersedes phase-5's T5 "ép needs_review" — the card says so in terms so nobody transcribes the v1 rule).
14. **The system prompt is the template file plus the rendered schema.** `triage_system.txt` (moved, Vietnamese, contains the literal word `JSON`) + `\n\n## Schema triage_v2\n` + `schemas.render("triage_v2")`. `prompt_version = "<git rev-parse --short HEAD at process start>+<sha256 of the template file>"`, `nogit` when there is no repository. The rendered schema is frozen with the JSON file, so the template hash is the version that matters.

---

## 7 · Exit-gate coverage

| Gate item (`prompts/P3.md`, `01-plan.md:11`) | Covered by | Notes |
|---|---|---|
| Linter rejects every legacy violation | **P3-T03** — four fixtures under `backend/tests/fixtures/linter/`, one per §7.4 violation, plus one valid v3 prompt | The fixtures are self-contained strings, not imports of the legacy builder (which needs `transformers`); T11 deletes that file |
| Gate tests green | **P3-T08** (steps 1–5, 7 on crafted JSON) + **P3-T09** (step 6 on canned verifier JSON) + **P3-T10** (E2E on a database with the fake adapter) | every branch the brief lists, each with its red step |
| ① runs live on ≥ 50 replayed alerts with `gate_result` written | **P3-T11** — `backend/tests/test_triage_live.py` (`@pytest.mark.live`) drives the real `triage` queue through `run_forever(once=True)` with the real adapter, bounded at 150 claims, until ≥ 50 rows where `llm_runs.role='proposer'` join `alerts.source='replay'` | **Owner runs it** from the primary checkout with `.env`; the Director re-derives the count by SQL (the command is in the card) |
| Cost recorded per run | **P3-T10** (`cost_usd` on every row, from `usage`) · **P3-T11** asserts `cost_usd > 0` on every live row and prints the sum with its denominator | P1-T08's per-call figure is the sanity bound |

---

## 8 · INBOX items raised by this plan

- `2026-09-15 · P3 / P4 / P6 · QUESTION` — **the enrichment facts stored on every replayed head say `asset = unknown` because the inventory was never loaded into `soc_dev`** (`assets`/`identities`/`iocs` all 0 rows; `lookup_status.asset = not_found` on 383/383 heads, including 289 from hosts the file names). Consequences named: step 4 cannot admit `false_positive` on any of them; B1 cannot either; G8′'s asset block "fired" on 100 % of stored heads, which is not the 0.7 % DEC-058 recorded. **And** the database holds 307 replay heads where DEC-053 counts 3,070 clusters (wall-clock dedup, planning decision 9 of P2). Options offered; P3 does not wait on the answer.
- No §6.2 change is needed: `gate_result`, `verifier_result`, `injection_findings`, `citation_warnings` are free `jsonb`; the verifier prompt's `proposer` block source is a prompt-side name, not a `reasons[].source` value.

---

## 9 · Task table

| Task | Title | Priority | Est. | Depends on | Owner action? |
|---|---|---|---|---|---|
| P2-T07 | `domain/correlation.py` — `summarize_for_prompt`, `correlated_cluster_ids` (card in `tasks/P2/`, amended 15/09) | must | 2 h | — (P2-T02, P2-T04 merged) | no |
| P3-T01 | `security/wrap.py` — nonce, NFKC → escape, nonce stripping, `truncate_block`, `untrusted_block` | must | 1.5 h | — | no |
| P3-T02 | `llm/builder.py` — `fact`, `untrusted`, `Id`, the closed-set Enums, `PromptBuilder.build()` | must | 3 h | P3-T01 | no |
| P3-T03 | `security/linter.py` + four legacy-violation fixtures | must | 2 h | P3-T02 | no |
| P3-T04 | `llm/adapter.py` — DeepSeek rules, wall-clock deadline, retries, cost, monthly cap; `FakeLLM` alignment | must | 3 h | — | no |
| P3-T05 | `llm/templates/` — move the two legacy system prompts, write `verifier_system.txt`, create the frozen `output_schemas.json` + `scripts/check_output_schemas.py --check`, `llm/schemas.py` validator | must | 2 h | — | no |
| P3-T06 | `kb/lookup.py` — playbook + decision-table loader, `apply_table`, `rule_holds`, `check_consistency`, ten skeleton YAMLs | must | 2.5 h | — | **yes** — author the tables with the advisor (content; after this card merges) |
| P3-T07 | `security/detector.py` — 20 regex patterns + 8 heuristics, flag only | must (heuristics 4–8 `should`) | 1.5 h | — | no |
| P3-T08 | `security/gate.py` steps 1–5, 7 + `security/output_guard.py` | must | 3 h | P3-T01, P3-T05 | no |
| P3-T09 | `llm/triage.py` — the ① proposer prompt from the five blocks, the verifier prompt, `propose()`/`verify()` with the repair round, step 6 | must | 3 h | P3-T02, P3-T03, P3-T04, P3-T05, P3-T06, P2-T07 | no |
| P3-T10 | `tier1/triage.py` job + `audit/llm_runs.py` + `web/worker.py` handler + E2E with the fake adapter | must | 4 h | P3-T07, P3-T08, P3-T09 | no |
| P3-T11 | `test_triage_live.py` (`@pytest.mark.live`) + `eval/triage_live.py` runner + delete top-level `llm/` | must | 1.5 h | P3-T10 | **yes** — run it with the real key |
| P3-T12 | `kb/playbooks/malware.md:36`, `ssh_brute_force.md:34` onto DEC-004's vocabulary | should | 0.5 h | — | **yes** — the content review and the dropped-category decision stay the Owner's |

File scope is disjoint by construction: `security/` is split T01 (`wrap.py`), T03 (`linter.py`),
T07 (`detector.py`), T08 (`gate.py`, `output_guard.py`); `llm/` is split T02 (`builder.py`), T04
(`adapter.py`), T05 (`templates/`, `schemas.py`), T09 (`triage.py`); `kb/` is T06 (`lookup.py`,
`kb/decision_tables/`) and T12 (`kb/playbooks/`, two lines); T10 owns `tier1/triage.py`,
`audit/llm_runs.py`, `web/worker.py`; T11 owns the live test, the runner and the deletion; P2-T07
owns `domain/correlation.py` and `backend/tests/test_transitions.py`. `Makefile` is touched by T05
only. No file appears in two cards.

---

### P2-T07 · `domain/correlation.py`
- Priority: must · Estimate: 2 h · Depends on: P2-T02, P2-T04 (both merged)
- Goal: `summarize_for_prompt` (≤ 20 grouped rows + ≤ 5 samples) and `correlated_cluster_ids` (status-filtered, `LIMIT MAX_ALERTS_PER_CASE`), read-only, on the three v1 indexes.
- Files — modify: `backend/app/domain/correlation.py`, **`backend/tests/test_transitions.py` (remove the two `P2-T07 not merged` skips — amendment 15/09)**. Create: `backend/tests/test_correlation.py`.
- Contracts touched: none.
- Risk / notes: the card in `tasks/P2/` is authoritative; P3-T09 places `CorrelationRow`'s eight fields outside blocks, so its closed-set/numeric shape (its acceptance 7) is load-bearing for G6′.

### P3-T01 · `security/wrap.py`
- Priority: must · Estimate: 1.5 h · Depends on: —
- Goal: `new_nonce()`, `normalise()` (NFKC), `strip_nonce()`, `truncate_block(text, limit_bytes)` (marker `[truncated]` inside), `untrusted_block(text, source, nonce, **attrs) -> Block` — the only code that emits an `<untrusted_data …>` boundary.
- Files — modify: `backend/app/security/wrap.py`. Create: `backend/tests/test_wrap.py`.
- Contracts touched: none.
- Risk / notes: written fresh to §7.1 (DEC-002: not a port). Escaping is `html.escape(quote=False)` after NFKC; attrs render `quote=True`. Nothing here parses.

### P3-T02 · `llm/builder.py`
- Priority: must · Estimate: 3 h · Depends on: P3-T01
- Goal: the typed builder — `fact(name, value)` accepts `Enum | int | datetime | Id` and rejects `str`/`bool`; `Id(kind, value)` with the four §7.1 regexes plus `rule_ref`; `untrusted(text, source, **attrs)`; `PromptBuilder(system, nonce).section(...)`, `.build() -> BuiltPrompt(system, user, nonce, block_index)`; `TEMPLATE_CONSTANTS` exported for the linter.
- Files — modify: `backend/app/llm/builder.py`. Create: `backend/tests/test_builder.py`.
- Contracts touched: none.
- Risk / notes: no code path emits a free string outside a block — that is the property, and the test suite is built around trying to.

### P3-T03 · `security/linter.py`
- Priority: must · Estimate: 2 h · Depends on: P3-T02
- Goal: `lint(user_message, *, nonce, constants, enums) -> list[Violation]`: strip every block carrying the nonce, strip allowed constants, then every residual token must be an enum value, an int, an ISO datetime, an `Id`, or punctuation.
- Files — modify: `backend/app/security/linter.py`. Create: `backend/tests/test_linter.py`, `backend/tests/fixtures/linter/{legacy_description_outside.txt, legacy_context_outside.txt, legacy_correlation_outside.txt, legacy_marker_outside.txt, v3_valid.txt}`.
- Contracts touched: none.
- Risk / notes: the fixtures reproduce `prompt_builder.py:134`, `:143–154`, `:152–154` and a `[truncated]` outside a block, as strings; the legacy file is deleted in T11.

### P3-T04 · `llm/adapter.py`
- Priority: must · Estimate: 3 h · Depends on: —
- Goal: `DeepSeekAdapter(cfg, *, client=None, spent_usd=..., sleep=...)` with `complete(*, system, user, response_format=None, timeout_s=None) -> LLMResult` — the same shape as `FakeLLM`; `json_object`; `extra_body={"thinking": {"type": cfg.LLM_THINKING}}`; reads `choices[0].message.content` only; wall-clock deadline via a daemon thread + `join(timeout)`; 2 retries on network/5xx; `cost_usd(usage, cfg)`; monthly cap before any call; `max_retries=0` on the SDK client.
- Files — modify: `backend/app/llm/adapter.py`. Create: `backend/tests/test_adapter.py`.
- Contracts touched: none (§6.3 `LLM_*` read, not extended).
- Risk / notes: the deadline test uses a fake client that stalls 3 s under `LLM_TIMEOUT_S=1` (DEC-033); a timeout is `TransientError` and is **not** retried inside the adapter — the job retries.

### P3-T05 · `llm/templates/` + `llm/schemas.py`
- Priority: must · Estimate: 2 h · Depends on: —
- Goal: `git mv` the two legacy system prompts; write `verifier_system.txt`; create `output_schemas.json` as §6.2 verbatim; `scripts/check_output_schemas.py --check` (parsed equality with the context pack's §6.2 block) wired into `make lint`; `llm/schemas.py` — `load()`, `validate(name, obj) -> list[str]` (value-free messages), `render(name) -> str`.
- Files — modify: `Makefile` (one `lint` line), `llm/templates/triage_system.txt` → `backend/app/llm/templates/triage_system.txt` and `llm/templates/investigate_system.txt` → `backend/app/llm/templates/investigate_system.txt` (moves). Create: `backend/app/llm/templates/output_schemas.json`, `backend/app/llm/templates/verifier_system.txt`, `backend/app/llm/schemas.py`, `scripts/check_output_schemas.py`, `backend/tests/test_schemas.py`.
- Contracts touched: **§6.2 — transcribed, not changed.** The `--check` is what proves it.
- Risk / notes: the legacy v1 `output_schemas.json` is *not* moved; it dies with the directory in T11.

### P3-T06 · `kb/lookup.py` + decision tables
- Priority: must · Estimate: 2.5 h · Depends on: —
- Goal: `get_playbook`, `get_decision_table`, `apply_table`, `rule_holds`, `check_consistency`, the `DecisionTable`/`Rule` dataclasses, the YAML format (planning decision 6), ten skeleton tables with §3.10's example rules, the two-way category ↔ playbook ↔ table test, the consistency test on the generated grid.
- Files — modify: `backend/app/kb/lookup.py`. Create: `kb/decision_tables/{c2_beacon,data_exfiltration,malware,policy_violation,privilege_escalation,ransomware,recon,ssh_brute_force,suspicious_login,web_attack}.yaml`, `backend/tests/test_kb_lookup.py`.
- Contracts touched: none.
- Risk / notes: content is the Owner's + advisor's (§11); the skeletons are `reviewed_by: null` and the card says so in the file header. B1 (P7) reads `apply_table` — keep it pure.

### P3-T07 · `security/detector.py`
- Priority: must (heuristics 4–8 `should`) · Estimate: 1.5 h · Depends on: —
- Goal: port `Final-Project`'s 19 regex patterns + 1 Vietnamese instruction-override pattern = 20; heuristics: (1) base64-like run ≥ 80, (2) verb/qualifier proximity, (3) zero-width/hidden characters — ported; (4) NFKC-folded delimiter look-alikes, (5) a 16-hex nonce-shaped token adjacent to `untrusted_data`, (6) a `[truncated]` marker inside content, (7) ≥ 3 role-marker lines, (8) an imperative-density score — new, `should`. `scan(blocks) -> list[Finding]`, `level(findings)`. Never mutates, never changes a verdict.
- Files — modify: `backend/app/security/detector.py`. Create: `backend/tests/test_detector.py`.
- Contracts touched: none.
- Risk / notes: the phase's cut candidate lives here and is pre-cut into `should`.

### P3-T08 · `security/gate.py` + `security/output_guard.py`
- Priority: must · Estimate: 3 h · Depends on: P3-T01, P3-T05
- Goal: `step1_schema`, `step2_basis`, `step3_quotes`, `step4_fp_policy`, `step5_detector`, `step6_verifier`, `step7_output_guard` as pure functions over a `GateState`, `run_steps_1_to_5(...)` and `finish(...)`; `gate_result` per planning decision 1; `output_guard.enforce(result) -> dict` (closed sets re-checked, unknown keys dropped, raises on violation). Tests: every branch the brief lists, on crafted proposer JSON.
- Files — modify: `backend/app/security/gate.py`, `backend/app/security/output_guard.py`. Create: `backend/tests/test_gate.py`.
- Contracts touched: none.
- Risk / notes: no import of `kb`, `llm`, `audit` (rule 7); `rule_check` and the verifier verdict are injected. Step 1's repair *decision* is here; the repair *call* is T09's.

### P3-T09 · `llm/triage.py`
- Priority: must · Estimate: 3 h · Depends on: P3-T02, P3-T03, P3-T04, P3-T05, P3-T06, P2-T07
- Goal: `build_facts(row, correlation)`, `build_proposer_prompt(...) -> BuiltPrompt` (the five blocks, the three mandatory sentences, the budget cut order, `citation_warnings`), `build_verifier_prompt(facts, rules, proposed) -> BuiltPrompt`, `propose(adapter, prompt) -> Proposal`, `verify(adapter, prompt) -> Verification` — each with one repair round (planning decision 9); `prompt_version()`.
- Files — modify: `backend/app/llm/triage.py`. Create: `backend/tests/test_llm_triage.py`.
- Contracts touched: none.
- Risk / notes: every built prompt is linted in the tests; `include_context`/`include_correlation` switches exist for P7's B2 and default to `True`.

### P3-T10 · `tier1/triage.py` + `audit/llm_runs.py` + `web/worker.py`
- Priority: must · Estimate: 4 h · Depends on: P3-T07, P3-T08, P3-T09
- Goal: `run_triage_job(conn, job, *, adapter=None)`: `SET LOCAL` idle timeout → load facts (explicit columns) → skip closed alerts → `disabled` path → correlation → playbook/table → build → detector → lint → propose → steps 1–5 → verifier prompt → verify → step 6 → step 7 → two `llm_runs` rows → `triage_status`/`triaged_count` → `triage.suggested` (+ `llm.gate_forced`). `audit/llm_runs.py`: `write_run(...)`, `month_spend_usd(conn)`. `web/worker.py`: `"triage": run_triage_job`.
- Files — modify: `backend/app/tier1/triage.py`, `backend/app/audit/llm_runs.py`, `backend/app/web/worker.py`. Create: `backend/tests/test_triage_job.py`, `backend/tests/test_llm_runs.py`.
- Contracts touched: none (`triage` job type, `triage.suggested`/`llm.gate_forced`/`llm.builder_violation`/`job.exhausted` event types all exist).
- Risk / notes: never writes `alerts.status` (G2 — a grep guard); the 11-second idle-timeout test is deliberate; auto-closed alerts take the same path.

### P3-T11 · live run + delete the legacy directory
- Priority: must · Estimate: 1.5 h · Depends on: P3-T10
- Goal: `backend/tests/test_triage_live.py` (`@pytest.mark.live`): `config.load(env_file=".env")` explicitly, skip without key/DSN, drive the real `triage` queue through `run_forever(once=True)` bounded at 150 claims until ≥ 50 `replay` proposer rows exist, assert `gate_result` and `cost_usd` on every row, print the summary with denominators; `eval/triage_live.py` — the same loop as a CLI for the Owner; `git rm -r llm/`.
- Files — create: `backend/tests/test_triage_live.py`, `eval/triage_live.py`. Delete: `llm/prompt_builder.py`, `llm/templates/output_schemas.json`, `llm/templates/tools.json` (the directory).
- Contracts touched: none.
- Risk / notes: the live test never uses the `db` fixture (it would drop `soc_dev`); the Owner runs it from the primary checkout; expected live shape stated in the card (0 `false_positive` survive — §5 finding 1).

### P3-T12 · playbook vocabulary
- Priority: should · Estimate: 0.5 h · Depends on: —
- Goal: the two lines that still branch on the criticality value DEC-004 abolished are rewritten onto `high|medium|low|unknown`; nothing else in the two files moves. <!-- superseded-ok: DEC-004 — names the value the task removes -->
- Files — modify: `kb/playbooks/malware.md`, `kb/playbooks/ssh_brute_force.md`.
- Contracts touched: none.
- Risk / notes: the Owner's playbook review (HUONG-DAN §4) may reword; the dropped-category decision (P2-T03 report: `rdp_brute_force`, `phishing`, `persistence`, `suspicious_execution`) is the Owner's and is not carded.

---

## 10 · Hand-off to P4 and beyond

1. **P4 reads `llm_runs.result` as the gated verdict and `gate_result.forced` as the forced flag** (planning decision 1). The latest proposer row per alert is `select … from llm_runs where subject_id = %s and pipeline = 'triage' and role = 'proposer' order by created_at desc limit 1`; `ix_llm_runs_subject` carries it. `gate_result.proposer_raw` is the ungated model output — the visibility filter strips it with everything else LLM-derived.
2. **P4's pilot inherits an unloaded inventory** unless the INBOX question is answered first: `assets` is empty on `soc_dev`, so every new alert enriches to `asset = unknown` and G8′ pins `needs_review` on the whole stream. One command (`inventory.load()` / `POST /api/admin/reload-inventory`) before the pilot; the 383 existing heads keep their stored facts either way.
3. **P5's ② reuses `security/wrap.py`, `llm/builder.py`, `llm/adapter.py`, `llm/schemas.py` (`investigate_v2`) and `audit/llm_runs.py`** unchanged; `investigate_system.txt` is already moved. The evidence check is P5's, in `tier2/`.
4. **P6's `build_gold.py` cannot draw 3,070 clusters from `soc_dev`** — the table holds 307 replay heads (wall-clock dedup). The INBOX question names the routes; P6's Planner reads the answer.
5. **P7's B1 is `kb.apply_table` on `gate_result.facts`**, B2/B3 re-gate from `gate_result.proposer_raw` with `gate.run_steps_1_to_5(...)` restricted, B4 is `tier1.triage.run_triage_job` as deployed; `build_proposer_prompt(include_context=False, include_correlation=False)` is B2's prompt. `eval/smoke_test.py`'s `injection_outcome.quoted` still reads the first response after a repair (P1-T01 review note 3) — patch it before any re-measurement through that script.
6. **P8 limitations inherited from this phase:** the decision tables shipped unreviewed until the Owner's sitting (every live `gate_result` before then carries `decision_table_unreviewed`); the inventory-unloaded corpus (finding 1) if the Owner accepts it rather than re-enriching; `JOB_LOCK_TIMEOUT_S` (300 s) bounds a triage job's two model calls and is the idle timeout the handler sets — at p95 3.65 s that is two orders of magnitude of margin, stated rather than assumed; the detector's level is a measurement only (v3 §4.2) — phase-5's "high level forbids FP" is not implemented, by design.
