# The page shows the best knowledge candidate's percentage when it is under the floor — design

Date: 2026-11-15 · Trial only (branch `director/trial-binary-verdict`, on top of `fd561bc`; never
merged into `main`) · Decision: DEC-220

## 1 · Why

An alert's page showed no RAG percentage and the Owner had to ask for it. The lookup had run and
scored 23 knowledge entries; the best scored 47 %, under the 50 % floor (`RAG_MIN_SCORE`), so the
lookup kept no match and the page said nothing. On the trial since 14/11, 198 ① runs are in that
state.

The Owner (15/11), after the floor was explained: **"Quy tắc đó thì bây giờ dù đã ghi nhận là không
có mục trùng nhưng hãy hiện số % lên UI."** The rule of DEC-219 does not change: it still applies
only to a kept match (50–79 % with the trial's values). Only the display changes.

## 2 · What changes

**The number.** For a run whose lookup kept no match, the best score among the candidates the
rerank scored (`rag_results.ranked` of the run's own lookup, `llm_runs.rag_lookup_id`), as
`round(score * 100)`, by the same rule `llm.rag_view` already uses for a score (a number in
[0, 1]; anything else is not a score).

**The pair the pages read** (`llm.rag_view.rag_view`, served as `rag` in the alert view and the
case view) gains two keys:

- `below_floor_pct`: that number; `null` when the lookup kept a match (then `best_pct` is the
  number), when no candidate has a score, when the run names no lookup, and when the lookup failed
  (then `not_applied` says so).
- `floor_pct`: `round(RAG_MIN_SCORE * 100)` of the running configuration, present whenever
  `below_floor_pct` is.

`best_pct` and `not_applied` keep their exact meaning. `best_pct` and `below_floor_pct` are never
both set.

**The line.** Where the alert page and the case page print "— trùng 87% với tri thức đã duyệt"
for a kept match, a run with `below_floor_pct` prints, in the same place:

> — trùng cao nhất 47% với tri thức đã duyệt (dưới mức tối thiểu 50%)

for example "AI kết luận: **TP** (độ tin cậy trung bình) — trùng cao nhất 47% với tri thức đã
duyệt (dưới mức tối thiểu 50%) — có cảnh báo kiểm chứng: …". The words are a new function of
`frontend/src/strings.ts`. Nothing else on the pages moves.

## 3 · What must not change

- **The rule of DEC-219.** `_rag_best_pct` in `tier1/triage.py` and `gate_result.rag_rule.best_pct`
  keep reading kept matches only. A run with a 47 % candidate and a threshold of 80 keeps the
  model's verdict, `rag_rule.applied` false, `rag_rule.best_pct` null. A test pins this against
  the new number, so the two can never be confused.
- The prompt: candidates under the floor are still not given to the model.
- The blind arm: `rag` is already hidden whole; the new keys go with it.
- The queue list.
- Stored rows.

## 4 · Tests

Red first. Backend: `rag_view` for a kept match (unchanged), for candidates all under the floor,
for no candidate, for junk scores, for a failed lookup, for a run with no lookup; the alert view
and the case view carry the two keys; the blind arm hides them; the DEC-219 pin of section 3.
Frontend: the new line on the alert page and the case page (whole-string assertions), with and
without warnings, with the DEC-219 default clause absent (it cannot apply to such a run); a kept
match prints today's text; the blind arm draws nothing and its leak markers include the new
phrase. `make lint`, `make test`, `make test-db`, `make ui-lint`, `make ui-test`, `make ui-build`
green.
