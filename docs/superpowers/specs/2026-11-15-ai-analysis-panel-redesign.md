# The AI analysis panel of Tier 1 and Tier 2, redesigned (scorecard + tabs) — design

Date: 2026-11-15 · Trial only (branch `director/trial-binary-verdict`, on top of `1beb89a`; never
merged into `main`) · Decision: DEC-221 (to be written when built)

Mock-up the Owner approved: the canvas "Phân tích AI Tier 1 và Tier 2", option **C** (artboards
`T1-BangDiem` and `T2-BangDiem`), https://claude.ai/artifact/Swto1Mm8ANWuevPT16NVen

## 1 · Why

The Owner (15/11): "Thiết kế lại phần UI của chức năng này. Hiển thị đầy đủ và chi tiết các thông
tin cho SOC có thể đọc và đánh giá … dễ đọc, dễ sử dụng và thẩm mĩ", and the output schema of the
LLM with it. The trigger was an alert whose page could not answer two questions the Owner then had
to ask: why the AI said TP, and what the RAG match was. The data existed (the decision history
said 15 of 15 earlier alerts were incidents; the best knowledge candidate scored 47 %, under the
50 % floor) but the page showed neither.

Three mock-ups were shown. The Owner chose option C and asked for one change: no "Mô hình" and no
"Bộ kiểm chứng" row in the technical tab (the two rows that named the models).

## 2 · Goals, non-goals

Goals

- G1. One layout for both tiers: a row of four score tiles, then tabs. A reader gets the verdict
  and its standing at a glance and the detail one click away.
- G2. Everything the system knows about a run is on the page: every reason with its quote and
  whether the quote was verified; the facts beside what the model declared; the RAG outcome in
  every case (also "best 47 %, under the floor", "no candidate", "no lookup", "lookup failed");
  the decision history; each gate check with its outcome; the technical figures.
- G3. The model says more that an analyst can act on: a short summary, the attack and the benign
  reading, what would change the verdict, what to check next (Tier 1); a timeline, the scope, a
  likelihood per hypothesis, a priority per next step (Tier 2).
- G4. The rules already decided stay true: the blind arm sees nothing of ① (DEC-101); for a run
  the RAG default applied to, nothing served says or gives away the model's own answer (DEC-219);
  ① is recommend-only.

Non-goals

- The gate's checks, the verdict rules (DEC-217, DEC-219) and the RAG lookup itself.
- The queue list, the decision panel, the alert column, the admin pages.
- Re-running stored runs: a run stored before this change has none of the new model fields.
- The model names anywhere in the panel (the Owner's change).

## 3 · The layout (both tiers)

Follow the approved artboards for structure, spacing, colour and wording; they use the product's
own tokens (`frontend/src/styles.css`) and fonts.

- Header line: "PHÂN TÍCH AI · TIER 1" (or 2) and, at the right, the existing reminder that the
  suggestion is advisory (Tier 1) or the case line (Tier 2).
- Four tiles. Tier 1: **Kết luận** (TP/FP, coloured), **Độ tin cậy** (word + three-segment
  meter), **Tri thức (RAG)** (the number or the state, with one line under it), **Kiểm chứng**
  (checks passed / checks that apply, and the number of warnings). Tier 2: **Kết luận**,
  **Độ tin cậy**, **Tri thức (RAG)**, **Dẫn chứng** (verified / cited).
- Tabs, keyboard reachable (`role="tablist"`, arrow keys, one tab stop). Tier 1: Tổng quan · Bằng
  chứng · Tri thức · Kiểm chứng · Kỹ thuật. Tier 2: Tổng quan · Diễn biến · Giả thuyết · Bằng
  chứng · Kỹ thuật. The open tab is not kept across page loads.
- States the mock-up does not draw keep today's behaviour inside the new frame: pending,
  unavailable (with the stop reason), the blind arm's notice, a decided alert ("Đã quyết — so
  sánh", Khớp), an archived alert, a Tier 2 run that is running, stalled or failed.

### Tier 1 tabs

| tab | content |
| --- | --- |
| Tổng quan | the model's `summary`; "Điều nổi bật" (section 5); the two readings side by side; "Điều sẽ làm đổi kết luận"; "Nên kiểm tra tiếp" |
| Bằng chứng | every reason the model gave, in its order: claim, quote, source, and whether the quote was verified (and why not) |
| Tri thức | the RAG outcome (section 5), the decision history, the playbook and the decision-table rule that matched |
| Kiểm chứng | each gate check with its outcome and one line of explanation; the facts table (system · model · match) |
| Kỹ thuật | tokens in → out, time, cost, analysed at, answer format, the alert's MITRE ids, correlated clusters at analysis. No model name. |

### Tier 2 tabs

| tab | content |
| --- | --- |
| Tổng quan | `summary`; scope (hosts, accounts, MITRE steps); next steps with their priority; "Cần lưu ý" (unverified evidence, an overruled conclusion) |
| Diễn biến | the timeline: time, what happened, tactic and technique, the alert it comes from |
| Giả thuyết | each hypothesis with its likelihood, for and against; the knowledge matches |
| Bằng chứng | each cited quote with its alert and whether it was verified |
| Kỹ thuật | tokens, time, cost, analysed at, playbook, alerts read. No model name. |

## 4 · The model's output schemas (`backend/app/llm/templates/output_schemas.json`)

New versions; the old ones stay in the file for stored rows.

**`triage_v4`** = `triage_v3` plus:

```
"summary": "string",
"reading_attack": "string",
"reading_benign": "string",
"would_change": "string",
"next_checks": ["string (minItems 1)"]
```

**`investigate_v4`** = `investigate_v3` with:

```
"timeline": [{"alert_id": "string", "what": "string", "tactic": "string", "technique": "string|null"}],
"scope": {"hosts": ["string"], "accounts": ["string"]},
"gia_thuyet": [{ …, "likelihood": "low|medium|high"}],
"next_steps": [{"step": "string", "priority": "high|medium|low"}]
```

Rules

- The model writes text in Vietnamese, one or two sentences per field; `next_checks` has one to
  three items.
- The timeline carries no time of its own: the server takes each row's time from the alert it
  names (`alert_time`), drops a row whose `alert_id` is not in the case, and sorts by time. A model
  cannot then invent a clock.
- The new text fields are the model's words about untrusted data: they are rendered as text only,
  are never fed back into a prompt, and the injection detector's rules for model output apply as
  they do to `reasons`.
- The gate does not judge the new Tier 1 fields. Steps 2, 3, 4, 6 and the RAG default read what
  they read today.
- With `LLM_RESPONSE_FORMAT=json_schema` the new schemas are sent as they are (DEC-218's
  converter handles every notation used here).
- The prompts gain the sentences that ask for the new fields. This moves `prompt_version`, and a
  run with the new prompt is not comparable call for call with gold v2's runs: the DEC says so.

## 5 · What the server serves (new, in the alert view and the case view)

All of it is hidden from the blind arm exactly as the suggestion is today.

Tier 1 (`tier1/queue.py`, the alert view):

- `analysis.summary`, `reading_attack`, `reading_benign`, `would_change`, `next_checks`: from the
  stored result; `null` for a run that has none.
- `analysis.reasons`: every reason of the model's answer (not only step 3's survivors), each with
  `verified: bool` and, when not verified, a closed `why` (`not_substring`, `unknown_source`,
  `empty_quote`).
- `analysis.facts`: per field, the system's value, the model's declared value, `match: bool`.
- `analysis.checks`: one row per gate step in order, each `{id, outcome: pass|warn|na, detail}`
  with a closed `detail` code the UI words. The tile's figures are derived from it.
- `analysis.rag`: `{state, best_pct, floor_pct, threshold_pct, candidates: [{pct, title,
  conclusion}], scored}` where `state` is `matched` (a match at or above the floor), `below_floor`
  (candidates were scored, none reached the floor), `no_candidate`, `failed` (with the existing
  failure kind) or `no_lookup`. `candidates` is the top three of the rerank, each with the entry's
  title and conclusion. For `below_floor`, `best_pct` is the best candidate's score: this is the
  number the page was missing.
- `analysis.history`: `{key, total, by_conclusion, last_seen}` of the lookup, or `null`.
- `analysis.playbook`: the playbook name and the decision-table rule that matched the facts.
- `analysis.highlights`: built by the server, not the model, from the above: up to four rows of
  `{direction: up|down|warn, code, params}` (history majority, privileged identity, high or
  unknown asset, critical severity, RAG state, each warning). The UI words the codes.
- `analysis.tech`: tokens, latency, cost, analysed at, response format, MITRE ids, correlated
  clusters at analysis. No model id.

Tier 2 (`tier2/investigation_view.py`): `timeline` (with server times), `scope`, hypotheses with
`likelihood`, `next_steps` with `priority`, the knowledge candidates as above, `tech` without the
model id.

**For a run the RAG default applied to (DEC-219)** the Tier 1 view serves none of: the model's two
readings, `would_change`, the model's declared facts, the verifier's check row, the reasons'
verdict-bearing fields beyond what is served today. The Overview then shows the summary, the
highlights and the next checks; the tab "Bằng chứng" shows the reasons as today.

## 6 · Cards

1. **AP-T1 — schemas and prompts.** `triage_v4`, `investigate_v4`; the prompt sentences; the
   validator and the JSON-schema converter cover them; ① and ② ask for and store version 4; stored
   version 3 rows still read.
2. **AP-T2 — Tier 1 server view.** The `analysis` object of section 5, the blind arm, the DEC-219
   withholding.
3. **AP-T3 — Tier 2 server view.** The case view's additions.
4. **AP-T4 — Tier 1 UI.** Tiles and tabs in place of today's `AiColumn`, every existing state kept.
5. **AP-T5 — Tier 2 UI.** Tiles and tabs in place of today's `InvestigationColumn`.

AP-T1 first; then AP-T2 and AP-T3 in parallel; then AP-T4 and AP-T5 in parallel, each against its
server card's contract. One Coder per card (Sonnet 5.5), one independent Reviewer per card
(Opus 5.5), tests red first, `make lint`, `make test`, `make test-db`, `make ui-lint`,
`make ui-test`, `make ui-build`, `make ui-e2e` green.

## 7 · Calls the Director made (for the Owner to check)

- "Bộ kiểm chứng" was read as the technical row naming the verifier's model. The verifier's check
  result stays in the tab "Kiểm chứng".
- "Điều nổi bật" is computed by the server from data, not written by the model, so it cannot be
  wrong about the facts.
- The timeline's times come from the alerts, not from the model.
- A run stored before the change shows the new frame with the fields it has; the model-written
  parts are simply absent.
- A separate rule change the Owner was offered and has not answered — letting the RAG default
  also apply when the best candidate is under the 50 % floor — is not part of this design. The
  page will show that number either way.
