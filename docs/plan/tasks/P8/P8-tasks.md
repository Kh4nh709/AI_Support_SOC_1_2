# P8 · Stabilise + report — task cards

Written **26/09/2026 by the Director (DEC-129)**, under the Owner's delegation of 25/09 ("all
responsibility is yours"; DEC-116), against `prompts/P8.md` as swept 25/09 per DEC-111, and against
what actually exists on 26/09. Where this index and a card differ, **the card wins**. The prompt is the
card; this file is the index.

Phase objective (the brief's): close the operating period, prove recoverability, hand the Owner
everything the thesis report needs, tag the release. **Dates:** P8's agent work is built 26–30/09 in
parallel with the lab, the labelling and the P7 runs. **01/10** is close-out day (P8-T06) and the Owner's
writing day. **02/10** is submission.

---

## 0 · What changed since the brief, measured 26/09 — the brief cannot be executed as written

1. **The human pilot never ran.** The brief's `eval/pilot_export.py` measures decisions by branch
   (blind / visible) and by person, acknowledge → decide times, ① vs human agreement on the blind branch,
   the digest's auto-close error rate and ② ratings. Every one of them needs the Tier-1 console
   (P4-T03/T05/T06: decide, the queue and alert pages, the end-to-end test). That console was
   deprioritized and is cut if unstarted on 30/09 (DEC-116). ② is cut (DEC-097/111), and the digest (P5)
   is deprioritized. On 26/09 `soc_dev` holds **0** `triage_labels`, **0** `autoclose_reviews` and **0**
   `tier1.*` events. The DB was reset on 25/09 for the lab rebuild (DEC-113).
   → **P8-T01 replaces the pilot export with an operations export.** It reports what the system did
   online over the lab period: intake, dedup, the pull loop, ① online (the gate-forced rate the
   architecture asks for, latency, cost, failure classes), auto-close. It prints every human-decision
   metric of architecture §6 as **"not measured"** with its reason, never as a zero.
2. **`scripts/restore.sh` does not exist.** It was P5-T12, which DEC-128 promoted and dispatched on 26/09.
   The drill (P8-T02) waits for it.
3. **`docs/runbook.md` exists** with P4-T07's `## Pilot` section only (≈ 20 KB). That section describes
   a pilot that did not run. P8-T03 adds the operating sections and banners that section as history,
   without deleting it.
4. **No alarm exists.** `infra/health.py` (P5-T11) is deprioritized, so the runbook's "alarms" section
   is "what to watch, by command" (P8-T03 note 3).
5. **INBOX has 2 open items**, both overtaken by later decisions. They are closed at planning time (DEC-129):
   the 23/09 G1 provenance note is moot once G1 is void (DEC-111), and the 23/09 P5-T11 notifier question
   goes with P5-T11's cut. The brief's "bug-fix sweep" is then a re-check at close-out (P8-T06), not a card.
6. **The thesis text is the Owner's.** Agents produce the evidence documents: `docs/results/*`,
   `docs/limitations.md`, `docs/restore-drill.md`, the runbook and the demo script. They write no thesis
   prose (`prompts/P8.md`: "the rest is the Owner writing the thesis").

## 1 · Cards

| Card | Title | Priority | Estimate | Executed by | Depends on | Files (create **C** / modify **M**) | Dispatchable |
|---|---|---|---|---|---|---|---|
| **P8-T01** | `eval/ops_export.py` → `docs/results/operations.md`: the online operating period, human-decision metrics stated as not measured | must | 2.5 h | Coder | — | C `eval/ops_export.py` · C `backend/tests/test_ops_export.py` | **now** (fixtures); run in P8-T06 |
| **P8-T02** | Restore drill (run card) → `docs/restore-drill.md` | must | 1 h | Director; Owner signs | P5-T12 merged; after the last lab window of 27/09 | outputs only: `docs/restore-drill.md` | 28/09–30/09 |
| **P8-T03** | `docs/runbook.md` completed: start/stop, env keys, backup/restore, what to watch, common failures; the Pilot section bannered | must | 1.5 h | Coder (docs) | P5-T12 merged (its commands) | M `docs/runbook.md` | after P5-T12 |
| **P8-T04** | `docs/demo.md`: the 10-minute demo over what exists | should | 1 h | Coder (docs) | — | C `docs/demo.md` | **now** |
| **P8-T05** | `docs/limitations.md`: every limitation, numbered, each with its source | must | 2.5 h | Coder (docs) | — (G2 figures marked, filled in P8-T06) | C `docs/limitations.md` | **now** |
| **P8-T06** | Close-out (run card): the operations run, limitation figures filled, INBOX re-check, final suite, `STATE.md` closed, tag `v1.0` | must | 1.5 h | Director; Owner pushes the tag | P7-T08 done; P8-T01/T03/T05 merged; P8-T04 merged or cut; P8-T02 done | outputs: `docs/results/operations.md`, figures in `docs/limitations.md`, `STATE.md` | 30/09–01/10 |

`must` = 9.5 h (6.5 h Coder + 2.5 h Director run cards). `should` = 1 h. No file appears in two cards'
Files lists. Every Coder card also writes its report and its own `STATE.md` row.

## 2 · Order and parallelism (≤ 3 Coders, cross-phase rule)

- **26/09:** P7-T04 and P5-T12 are running. P8-T01 takes the third Coder slot when one frees; P8-T04 and
  P8-T05 follow.
- **27/09:** P8-T04 and P8-T05 run (docs only, no database); P8-T03 after P5-T12 merges.
- **28–30/09:** P8-T02 (the drill) runs on the database server, so never during a lab window. The
  labelling and the freeze take 28/09 and P7-T08 takes 29/09, so the drill goes on 28/09 after the
  freeze or on 30/09.
- **30/09–01/10:** P8-T06.

**Cut order if short:** P8-T04 (demo; `should`) → the demo-rehearsal item → P8-T03's "common failures"
table cut to four rows. **Never cut:** P8-T01, P8-T02, P8-T05, P8-T06. The exit gate lists them.

## 3 · Rules every P8 card follows

1. **Nothing new in the product.** No feature, no refactor, no change under `backend/app/`,
   `docs/Schema/`, `backend/app/llm/templates/`, config keys or the import rules. A "small improvement"
   becomes a line in `docs/limitations.md` (brief design note 1).
2. **The live database is read-only for agents.** Only run cards (P8-T02, P8-T06) touch `soc_dev`, and
   only read it, apart from the drill's restore into a *separate* database. Coders use private
   `soc_p8tNN_*_test` databases derived from `TEST_DATABASE_URL` (DEC-105).
3. **Every figure a document states is measured, with the command that measured it.** A metric that
   cannot be measured is written "not measured — <reason> (<DEC>)", never `0` and never omitted. That is
   the P6-T11 rule, applied to prose.
4. **G1 is history, G2 is the evaluated set (DEC-111).** A G1 figure appears only as the history of a
   corpus that was built and not evaluated. The evaluated corpus is described as *author-generated lab
   traffic*, never as an estate.
5. **Evaluation validity is never relaxed for schedule** (01-plan cross-phase rules): blind labelling,
   freeze before evaluation, no ① output on the labelling page.
6. **Host (DEC-106/113):** `python3` is `../AI_Support_SOC_1_2/.venv/bin/python` from a worktree, and
   every `make` target takes `PY=`. `make test` shows exactly one failure,
   `backend/tests/test_backfill_cli.py:184`.
7. **Credentials:** never print a DSN, key or password. Keep a `Config` repr out of assertions (the DEC-122
   incident).

## 4 · Exit gate (the brief's, as it can be met)

Restore drill report signed (`docs/restore-drill.md`) · `docs/results/operations.md` (in place of
`pilot.md`, §0 item 1) · `docs/runbook.md` · `docs/limitations.md` · tag `v1.0` · demo rehearsed
(Owner), or the demo cut and recorded.

## 5 · Owner actions

Sign the restore drill (P8-T02). Install the backup crontab line (P5-T12's report gives it). Rehearse
the demo (P8-T04) or say it is cut. Push the `v1.0` tag (P8-T06). Write the thesis chapters from
`docs/results/*.md`, `docs/limitations.md` and `docs/restore-drill.md`. Submit on 02/10.
