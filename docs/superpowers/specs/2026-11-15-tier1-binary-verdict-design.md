# Tier 1 (①) gives only `true_positive` or `false_positive` — design

Date: 2026-11-15 · Trial only (branch `director/trial-binary-verdict`, cut from
`director/trial-category-v35` @ `f8bbc05`; never merged into `main`) · Decision: DEC-217

## 1 · Why

On the trial, 93.7 % of ① runs ended `needs_review` (1,400 of 1,494 runs, 14–15/11). The model
itself always answers `false_positive` or `true_positive` (DEC-213); `needs_review` is written
only by the gate (`backend/app/security/gate.py`, steps 2, 3, 4 and 6).

The Owner's requirement (15/11): **"Output ở tier 1 chỉ có TP và FP."** Asked which verdict a
flagged run should carry, the Owner chose: **keep the model's own verdict; every gate check
becomes a warning shown beside it.** The Owner was shown the gold v2 numbers first (model verdict
as is: 71.8 % accurate with RAG on, 17 of 36 real attacks labelled FP). ① stays recommend-only:
it never closes an alert, the Tier 1 analyst decides.

## 2 · Goals, non-goals

Goals

- G1. Every new ① run stores `result.suggested_action` ∈ {`false_positive`, `true_positive`} and
  it equals the model's answer. Nothing in the pipeline can write `needs_review` for ①.
- G2. Every gate check still runs and what it found is still recorded and shown, as a warning.
- G3. Alerts already triaged (stored runs whose `suggested_action` is `needs_review`) are served
  to Tier 1 with the model's own verdict, without a new LLM call and without touching `llm_runs`
  (it is immutable).
- G4. The blind arm leaks nothing new.

Non-goals (each would be its own decision)

- The verifier's vocabulary (`verifier_v2` keeps `needs_review`), the verifier prompt, and the
  proposer prompt. Another session is changing the proposer prompt (`llm/triage.py`,
  `llm/templates/*`): **do not edit those files.**
- Decision tables and playbooks (`kb/`), `kb/lookup.py`'s rule vocabulary (a rule may still say
  `needs_review`).
- ② (Tier 2, `need_more_data`).
- The database: no migration. `ck_llm_runs_suggested_action` keeps admitting the three values,
  because old rows hold `needs_review`.
- `soar/pipeline.py`, `tier1/triage.py::_load` and `_SOAR_ENRICHED_SQL` (another session's lane).

## 3 · The gate (backend)

`security/gate.py`. The checks of steps 2, 3, 4 and 6 are unchanged; what a failed check does
changes.

- A failed check **flags** the run: it appends its step name (`"step2"`, `"step3"`, `"step4"`,
  `"step6"`) to `state.flagged_by`. It never changes `state.verdict`. `state.verdict` is the
  model's answer from `start()` to the end. `_force_needs_review` goes.
- Step 2: as now (`hallucination_flag`, `mismatched_fields`), then flags.
- Step 3: as now. A reason whose quote is not verified is still removed from the reasons that
  leave the gate (`dropped_reasons` records it). No surviving reason → flag; the result then
  carries `reasons: []`.
- Step 4: runs for **every** `false_positive` answer (it can no longer be skipped because an
  earlier step forced the verdict). `missing` and the rule-check warning as now, then flags.
  `"n/a"` only for a `true_positive` answer.
- Step 5: unchanged.
- Step 6: the verifier prompt carries the model's verdict (`verdict_for_verifier` is always
  `false_positive` or `true_positive`). Unusable verifier answer → `steps["6"] = "invalid"`,
  flag. `agree` false, or `structured_only_verdict` different from the model's verdict →
  `"disagree"`, flag. Otherwise `"agree"`.
- Step 7: `suggested_action = state.verdict`, `reasons` = the survivors.
  `output_guard.SUGGESTED_ACTIONS` becomes the two values, so a `needs_review` can no longer
  leave the gate (`OutputGuardError`).

`gate_result` becomes **version 2**:

| key | version 2 |
| --- | --- |
| `version` | `2` |
| `proposed_verdict`, `final_verdict` | both the model's answer |
| `forced` | `false` |
| `forced_by` | `[]` |
| `flagged_by` | new: the step names that flagged, in step order |
| every other key | as in version 1 (`steps`, `missing`, `mismatched_fields`, `dropped_reasons`, `hallucination_flag`, `facts`, `warnings`, `verifier_verdict`, …) |

Version 1 documents stay in the database and every reader must still read them.

## 4 · Vocabulary (`llm/verdicts.py`)

- `GATED_ACTIONS` = `MODEL_ACTIONS` (the two values): what a new ① run may hold.
- New `STORED_ACTIONS` = the three values: what a stored ① row may hold (history) and what the
  CHECK admits. `tests/test_verdicts.py` ties the CHECK to this tuple, and
  `output_guard.SUGGESTED_ACTIONS` to `GATED_ACTIONS`.
- The verifier's answers and a decision-table rule's `then` keep their three values. Give that
  set its own name (`REVIEW_ACTIONS`) and tie `verifier_v2`, `builder.Verdict` and
  `kb.lookup._ACTIONS` to it instead of to `GATED_ACTIONS`.
- `held_reasons(gate_result)` returns the same closed codes (`HELD_REASONS`, unchanged) for both
  versions: it reads `flagged_by` when the document has it and `forced_by` otherwise. The codes
  now mean "the checks that raised a warning". The names `HELD_REASONS`, `held_reasons` and the
  wire field `held_by` are kept, so the API contract does not move.
- New `served_action(result, gate_result)`: the verdict Tier 1 is shown for a stored run — the
  stored `suggested_action` when it is one of the two; for a stored `needs_review`, the model's
  own answer (`proposed_action(gate_result)`); `None` when neither exists.

## 5 · What Tier 1 is served (G3)

Every place that hands ①'s verdict to Tier 1 uses the served verdict, never the raw stored one:

- `tier1/queue.py`: `Suggestion.suggested_action` (`_suggestion_of`), and the queue list's
  `suggested_action` column in `_QUEUE_SQL` (a `CASE` on the stored value that falls back to
  `gate_result->>'proposed_verdict'` when that is one of the two values, else NULL). Any filter or
  sort on the column follows the same expression.
- Whatever reads those two: the alert detail, `tier1/decide.py` (the `llm_suggestion` it records
  with a decision), `tier1/digest.py`.
- Not changed: the admin LLM page (`web/routers/admin_llm.py`) and the audit log show stored rows
  as they are; they are the record.

`gate.forced` served for a version 1 row stays what is stored.

## 6 · Events

- `llm.gate_forced` is not written for a new run (nothing is forced). The event type stays
  (old rows).
- `triage.suggested` keeps `forced` (now always `false`) and gains `flagged_by` (the list). The
  blind arm must not see it: treat it wherever `forced`/`gate_forced` is hidden or allow-listed
  today (`tier1/visibility.py`, `web/routers/admin_audit.py`).

## 7 · Evaluation code (`tier1/triage.py::TriageEvaluation`, `eval/`)

- `TriageEvaluation` gains `flagged_by: tuple[str, ...]`; `forced_by` stays and is `()` for a
  new run. `final_verdict` equals `proposed_verdict`.
- The eval switches keep their meaning (a restricted run still stops where it stopped).
- `eval/` readers keep working on both versions. Where a report lists the gate's `forced_by` per
  run, it lists `flagged_by` for a version 2 run. "Held" rates (`final_verdict == "needs_review"`)
  are not redefined: they read 0 for new runs. Do not invent a new metric.

## 8 · Frontend

The alert page already prints the model's own answer ("AI kết luận: **FP** (độ tin cậy cao) — …").

- `strings.ts` `ai1.held`: "hệ thống giữ lại cho người xem" → **"có cảnh báo kiểm chứng"**;
  `ai1.heldBecause`: "vì: a, b" → **": a, b"**, so the line reads
  "AI kết luận: **FP** (độ tin cậy cao) — **có cảnh báo kiểm chứng**: facts lệch, …".
  The reason labels (`ai1.heldReason`) keep their text unless one says the verdict was held.
- `heldOf(state)` stays `heldBy.length > 0 || action === "needs_review"`; the second half is now
  only a guard for an old client cache.
- The queue list shows the served verdict; no row shows "Cần xem xét" for ①. Keep the
  `needs_review` label in `strings.ts` (the admin LLM page shows stored rows).
- `agreement.ts`: unchanged logic; a comment that says ① may be `needs_review` is updated.
- The forced flag never shows for a new run; keep it for version 1 rows.

## 9 · Tests

- Red first: a test that fails on `f8bbc05` for each of G1 (a run flagged by each of steps 2, 3,
  4, 6 keeps the model's verdict; `flagged_by` lists the steps; step 4 is evaluated after a
  step 2 or step 3 flag), G3 (a stored version 1 `needs_review` row is served as its
  `proposed_verdict`, in the detail and in the queue list) and the output guard refusing
  `needs_review`.
- Existing tests that pin the old behaviour are rewritten to the new one, not deleted. A test of
  a version 1 reader keeps a version 1 fixture.
- `make lint`, `make test` (not db), `make ui-lint`, `make ui-test`, `make ui-build` green.
  **DB tests cannot run today**: `TEST_DATABASE_URL` in the primary `.env` does not authenticate.
  Write and update them anyway, and list in the report every db test touched and not run.

## 10 · Out of scope, recorded as follow-ups

- The verifier still answers `needs_review` on most alerts, so `verifier_disagrees` will be a
  frequent warning until the verifier is made definite or the tables are signed.
- `fp_policy:playbook_rule` is raised on every `false_positive` until ① is shown the rule ids
  (the proposer-prompt session) and the tables have rules a `skipped` IOC can satisfy.
- SOAR sends `user_is_admin=false` for 122 alerts whose account the inventory marks privileged;
  on those the `fp_policy:identity_privileged` warning is silent until the context merge lands.
