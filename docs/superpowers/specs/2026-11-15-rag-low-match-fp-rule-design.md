# ① answers `false_positive` when the RAG match is below a threshold — design

Date: 2026-11-15 · Trial only (branch `director/trial-binary-verdict`, on top of `8bd165f`;
never merged into `main`) · Decision: DEC-219

## 1 · Why

The Owner's request (15/11): **"Thêm 1 mục điều kiện alert đối chiếu rag < 80% trùng tri thức thì
xuất FP."** Asked how wide the rule is, with the trial's numbers in the question, the Owner chose:
**only when the RAG lookup returned a match and the best match is below 80 %**; with no match, no
lookup or a failed lookup, the model's verdict stays.

What the Director measured first (trial, 2,074 ① runs since 14/11, read-only): no run had a match
of 80 % or more; 133 had a best match of 50–79 % (22 of them answered `true_positive` by the
model); 212 lookups kept no match; 1,626 runs had no lookup; 103 lookups had failed. Of those 133
runs, the best match of 122 is an entry concluded `confirmed_incident` (18 of them answered
`true_positive`). Gold v2 cannot measure the rule: all 220 alerts match at 80 % or more.

DEC-217 made ①'s stored verdict the model's own. This rule is the one exception: below the
threshold `false_positive` is ①'s **default answer**, whatever the model answered.

**Amendment (the Owner, 15/11, after the first draft of this spec):** "Ở đây dưới 80% là mặc định
trả FP." The page must not present the verdict as the model's answer overridden by a rule: no
"(model kết luận TP)", no forced flag. Asked whether the LLM is still called for such an alert, the
Owner chose: **yes** — the reasons and evidence the model gives are still shown; the model's own
answer is kept in the stored run only. Sections 4, 5, 6 and 7 below are the amended text.

## 2 · The rule

For one ① run, let **`best_pct`** be the number the alert page shows as "trùng X% với tri thức đã
duyệt" for that run: `llm.rag_view.best_pct` of the matches of the lookup whose learned entries are
in the run's prompt. It is `None` when the run holds no lookup, the lookup failed or kept no match,
the token budget dropped the entries, or RAG is off (the switch, or an evaluation switch).

Let **`threshold`** be `TRIAGE_RAG_FP_BELOW_PCT` (section 3).

The rule **applies** when `threshold > 0` and `best_pct is not None` and `best_pct < threshold`.
When it applies, ①'s verdict is `false_positive`, whatever the model answered. When it does not
apply, nothing changes.

`best_pct == threshold` does not apply (80 is not below 80).

## 3 · The switch (`backend/app/infra/config.py`)

`TRIAGE_RAG_FP_BELOW_PCT`: an integer from 0 to 100, default `0` (off: the rule never applies and
a run is exactly what it is today). The trial sets `80`. Any other value is a configuration error
at load. It goes in `.env.example`, the context pack's key list and the runbook's environment
table (tests pin those lists); the runbook row says the containers must be recreated
(`docker compose up -d --force-recreate app worker rag-worker`), as the `LLM_RESPONSE_FORMAT` row
does.

## 4 · The gate (`backend/app/security/gate.py`, `backend/app/tier1/triage.py`)

`security` may import only `infra`, so the gate receives two plain integers (`best_pct | None`,
`threshold`); `tier1/triage.py` computes `best_pct` from what it already holds.

- A new step, **after step 3 and before step 4** (name it `step3r_rag_rule`; `steps["3r"]` is
  `"applied"`, `"changed"` or `"n/a"`): when the rule applies and the verdict is `true_positive`,
  the verdict becomes `false_positive` and the step is `"changed"`. When it applies and the model
  already answered `false_positive`, the step is `"applied"` and nothing else changes. Otherwise
  `"n/a"`. The rule is not a gate force: `forced` stays `false` and `forced_by` stays `[]`.
- It runs wherever step 3 runs, the restricted evaluation mode included.
- **Step 4 then evaluates the verdict it finds**: a `false_positive` the rule produced gets the
  same false-positive policy warnings (`missing`, `flagged_by` step 4) as one the model gave.
- **The verifier is sent the model's own verdict** (`proposed_verdict`) and its reasons, and step 6
  compares the verifier's answer with the model's own verdict. For a run the rule did not change
  this is exactly today's behaviour.
- Step 7 and the output guard are unchanged (`false_positive` is a legal verdict).
- `gate_result` (version stays 2) gains
  `rag_rule: {"threshold": int, "best_pct": int | null, "applied": bool, "changed": bool}`,
  present on every new run (with the switch off: `threshold` 0, `applied` and `changed` false).
  `proposed_verdict` stays the model's answer (the stored record of it), `final_verdict` is the
  verdict after the rule, so the two differ exactly when `rag_rule.changed` is true. `forced` is
  `false` and `forced_by` is `[]` on every new run, as since DEC-217. `flagged_by` is not touched by
  the rule: it is not a failed check.
- The reasons that leave the gate are the model's (step 3's survivors), also when the rule changed
  the verdict.
- `TriageEvaluation.forced_by` stays `()`; `final_verdict` and `proposed_verdict` differ when the
  rule changed the verdict.

## 5 · Stored rows, events, what Tier 1 is served

- `result.suggested_action` is the verdict after the rule.
- `llm.gate_forced` is still never written for a new run. `triage.suggested` keeps its keys
  (`forced` false) and its `suggested_action` is the verdict after the rule.
- `Suggestion.gate` (the alert view) gains the key `rag_rule`: `{"threshold", "best_pct", "applied"}`
  taken from the stored object, or `null` for a run that has none. The stored `changed` is NOT
  served: for an applied run it says what the model answered. The blind arm sees none of it: `rag_rule` is hidden wherever the suggestion
  and `rag` are hidden today.
- **Tier 1 is not served the model's own answer for a run the rule applied to.** Wherever the
  Tier 1 API returns the model's answer — `proposed_action` (the queue row and the alert view) and
  `Suggestion.gate.proposed_verdict` — a run whose `rag_rule.applied` is true returns the verdict ①
  ended with instead, and returns `confidence: null` (the queue row and the alert view): the
  confidence is the model's, in its own answer. The stored `gate_result.proposed_verdict` and
  `result.confidence` are untouched; the admin LLM page and the audit log show stored rows as they
  are.
- **Nor what would let a reader work the model's answer out.** Step 6 compares the verifier with
  the model's own verdict, so for a run the rule applied to the Tier 1 API returns
  `Suggestion.gate.verifier_verdict: null` and leaves `verifier_disagrees` out of `held_by` (the
  queue row and the alert view). Every other warning code stays, `verifier_invalid` included. The
  stored `gate_result` keeps the verifier's verdict, `steps["6"]` and `flagged_by` as they are.
- Stored runs are not re-judged: the rule applies to new runs only. `served_action` is unchanged.

## 6 · Frontend (`frontend/`)

- The conclusion the alert page prints is the verdict ① ended with: `conclusionOf` returns the
  action when it is one of the model's two values, and falls back to the model's own answer only
  when the action is not one (the old-client guard for a stored `needs_review`).
- When `gate.rag_rule.applied` is true (whether or not the model had answered `false_positive`
  itself) the line says the verdict is the default below the threshold, and prints no confidence
  note (the confidence is the model's, in its own answer):
  "AI kết luận: **FP** — trùng 62% với tri thức đã duyệt (dưới 80%: mặc định FP) — có cảnh báo
  kiểm chứng: …". The threshold and the percentage come from `rag_rule`; the words are new entries
  of `strings.ts`. The line never names the model's own answer.
- When the rule did not apply, or `rag_rule` is null, the line is exactly today's.
- No forced flag (⚑) for such a run: the server sends `gate_forced` false. The gate block shows
  what the server serves (section 5: the verdict ① ended with, in both places).
- "Khớp" compares the analyst's decision with the verdict ① ended with (the action), as today.
- The blind arm draws nothing new; its leak markers include the new phrase.

## 7 · Tests

Red first, then green.

Backend: the rule's truth table (threshold 0; `best_pct` `None`; below, equal, above; model TP and
FP); `steps["3r"]` and `rag_rule` in each case, `forced` false and `forced_by` empty in every
case; step 4 evaluated on a verdict the rule produced; the verifier sent the model's verdict and
step 6 compared with it; the stored `suggested_action` and the stored `proposed_verdict`;
`llm.gate_forced` never written; the served `proposed_action` and `gate.proposed_verdict` of a run
the rule applied to (queue row and alert view) are the verdict ① ended with, and the stored row is
untouched; the switch (default 0, range, lists); `best_pct` is `None` for each "no number" case of section 2 and equals what `rag_view`
gives the page; the blind arm hides `rag_rule`; with the switch off a run's stored rows are what
they are today plus the `rag_rule` key. DB tests are written, listed and not run
(`TEST_DATABASE_URL` does not authenticate on this host).

Frontend: the line of a run the rule applied to (with and without warnings; the same text whether
the model had answered FP or TP; no confidence note; no flag; the model's answer nowhere in the
line); the line when the rule did not apply equals today's; `conclusionOf` action-first and its
guard; Khớp; the blind arm.

`make lint`, `make test`, `make ui-lint`, `make ui-test`, `make ui-build` green.

## 8 · Known consequences (recorded for the Owner)

- A `true_positive` the model gave is replaced by `false_positive` on an alert that is 50–79 %
  like approved knowledge, whatever that knowledge concluded. On the trial today the nearest entry
  of 122 of the 133 such runs is a `confirmed_incident`.
- The page then shows `false_positive` as the default over the model's reasons, which may argue
  for `true_positive`; the model's own answer is only in the stored run (admin LLM page, audit).
- The rule fires only where a lookup ran and kept a match: 133 of 2,074 runs on the trial today.
