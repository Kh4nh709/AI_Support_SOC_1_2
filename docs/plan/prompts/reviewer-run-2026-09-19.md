# Reviewer — four round-1 reviews after the outage: P3-T03, P3-T07, P3-T08, P6-T05

One session per task, named `reviewer-<task>`. `prompts/reviewer.md` governs every one of them —
verify, never fix; the card is the contract; the verdict is an artifact on the task branch
(DEC-028). This note adds only what is specific to these four and to the three-day gap.

**Paste lines — one per session, nothing else:**

```
Read docs/plan/prompts/reviewer.md and act as the Reviewer. Then read
docs/plan/prompts/reviewer-run-2026-09-19.md §P3-T03. Task: P3-T03.
```
```
Read docs/plan/prompts/reviewer.md and act as the Reviewer. Then read
docs/plan/prompts/reviewer-run-2026-09-19.md §P3-T07. Task: P3-T07.
```
```
Read docs/plan/prompts/reviewer.md and act as the Reviewer. Then read
docs/plan/prompts/reviewer-run-2026-09-19.md §P3-T08. Task: P3-T08.
```
```
Read docs/plan/prompts/reviewer.md and act as the Reviewer. Then read
docs/plan/prompts/reviewer-run-2026-09-19.md §P6-T05. Task: P6-T05.
```

## Common to all four

- **The branches were cut on 16/09 and `main` is `ed970da` (16/09 08:02).** Measured 19/09:
  `git diff <merge-base>..main --name-only | grep '^backend/'` is **empty** for every one of
  them — `main` gained no code while they were open. So the DEC-046 shipping-state check is
  cheap this time: confirm the empty diff yourself, then review the branch as it stands. The
  composition risk is **between the four branches**, which the Director handles at merge
  (DEC-047); it is not yours.
- **The host rebooted on 16/09 22:24.** `/data/wazuh/logs/alerts/alerts.json` is now mode 640
  and **`user1` cannot read it**. If any acceptance line greps that file, it fails with
  `Permission denied` — that is the host, not the Coder: report it as bucket (c) with the
  indexer equivalent (`_count` on `wazuh-alerts-*` through `.env`'s `soc_ro`), and do not charge
  it.
- **`.env` is absent in a fresh worktree** (`reviewer.md`). Three of the four cards name
  `TEST_DATABASE_URL`; export it before `make test-db`, as the standing prompt says.
- **Bucket accounting.** All four are round 1. Name the bucket for every finding: (a) Coder,
  (b) card — the Director's, free to the Coder — or (c) contract/host.

## §P3-T03 — `security/linter.py`, the token-level G6′ linter

- Branch: `38298d9` (2 commits: `49ff8c7` code, `38298d9` report). Merge-base `f5f1a44`.
- Delta: `backend/app/security/linter.py`, `backend/tests/test_linter.py`, **five fixtures**
  under `backend/tests/fixtures/linter/` (`legacy_*_outside.txt` ×4, `v3_valid.txt`), the report.
  9 files, +526.
- Card: **8 acceptance items**. The P3 gate item this feeds is *"Linter rejects every legacy
  violation"* (`01-plan.md`, P3 row) — so the four `legacy_*` fixtures are the gate's evidence;
  make sure each one is actually **rejected** by the shipped linter, not merely present.
- Note: the branch's STATE row says `review` while `main`'s still says `todo`; the Director
  reconciles that, not you.

## §P3-T07 — `security/detector.py`

- Branch: `0d68887` (2 commits). Merge-base `f5f1a44`. Delta: `backend/app/security/detector.py`,
  `backend/tests/test_detector.py`, the report. 4 files, +858.
- Card: **8 acceptance items**; depends on nothing. `01-plan.md`'s P3 cut candidate is
  *"detector heuristics beyond the 20 regex patterns"* — if the diff carries more than the card
  scopes in, that is a scope finding, not a bonus.

## §P3-T08 — `security/gate.py` + `security/output_guard.py`

- Branch: `fb7cc6e` (3 commits). Merge-base `d2f4e4e`. Delta: `backend/app/security/gate.py`,
  `backend/app/security/output_guard.py`, `backend/tests/test_gate.py`, the report. 5 files,
  +1,175.
- Card: **9 acceptance items**; depends on **P3-T01, P3-T05** — both in `main` (merged 15/09
  23:50). Verify with `git log --oneline main | grep -E 'P3-T0[15] merged'`.
- The P3 gate item *"gate tests green"* is this task. Read the card's design notes on the
  `decision_table_unreviewed:<category>` path (`STATE.md:92`): the ten tables are still
  skeletons with `reviewed_by: null`, so the gate must treat them as absent and still run —
  a test that only passes with reviewed tables is a defect against the card.

## §P6-T05 — `docs/lab-scenarios.md` + `eval/lab_tag.py` + `eval/lab_windows.csv`

- Branch: `8a0cbbb` (4 commits). Merge-base `d2f4e4e`. Delta: `docs/lab-scenarios.md`,
  `eval/lab_tag.py`, `eval/lab_windows.csv`, `backend/tests/test_lab_tag.py`, the report.
  6 files, +2,079.
- Card: **8 acceptance items**; DB-backed (3 mentions of `TEST_DATABASE_URL`). This is the
  **DEC-085 option D** artifact: a post-hoc time-window retag to `source='lab'`, **no schema
  change, no migration** — a migration in this diff is a frozen-contract finding.
- The runbook is what the Owner executes on 22–24/09; its expected rule ids were to be checked
  against the archive and the three `1003xx` rules given a **negative** check. Read it as the
  Owner will: every step must be a command with an expected output, and the pre-flight must
  include *worker + puller running* — measured 19/09, **they are not** after the reboot.
- The three lab rules are live on the manager (`local_rules.xml` in the `wazuh_etc` volume,
  DEC-068/069); `100999` beats every 600 s through the reboot (521 in the indexer). The runbook
  may rely on that; it may not claim `1003xx` has ever fired — it has not.
- **Added by the Director 19/09 (DEC-091) — bucket (b), free to the Coder.** The card's pre-flight
  (`P6-T05.prompt.md:22`, as the Coder read it) prescribed `grep -c … /data/wazuh/logs/alerts/alerts.json`;
  the runbook on the branch carries that file grep in **7 places** (`docs/lab-scenarios.md:56, :60, :92,
  :93, :584, :647, :711` — the pre-flight and the three "Before:" baselines). The card is corrected: every
  check is the indexer `_count` (`term` on `rule.id` `100999`; `prefix` `1003`), the exact commands are in
  the card and in DEC-091. **Require the swap in the same round and classify it (b)**; that the runbook
  *also* has an indexer path at `:154-160`/`:213` does not cover the three baselines, which are file-only.
