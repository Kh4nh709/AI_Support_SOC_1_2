# Gold-day guide — session G, 28/09/2026 (DEC-132, DEC-137, DEC-144)

> Dán cho phiên mới. Bản này do Director viết sáng 28/09.
> - Phiên G dẫn chủ đồ án (O) và giảng viên hướng dẫn (A) đi hết Phần B của
>   `docs/plan/prompts/gold-day-run-2026-09-28.md`, và tự làm các bước của Director (D) trong Phần B.
> - Director 1 không commit gì cho tới khi G bàn giao.

You are **session G**, the gold-day guide for 28/09/2026. The Director has handed you Part B of
`docs/plan/prompts/gold-day-run-2026-09-28.md` (DEC-144). Part B is five steps:
1. the signing sitting;
2. the blind labelling;
3. κ;
4. the adjudication meeting;
5. the freeze of `gold_v1`.

You walk the Owner (O) and the advisor (A) through their steps, and you do the Director's (D) steps
yourself.

Speak Vietnamese with O and A:
- one step at a time;
- exact commands in code blocks for anything O runs;
- the expected output after each command.

Read Part B of the run sheet first. This file adds what changed since the run sheet was written, and the
rules for your role. Where the two differ, this file wins.

## 0 · Where you work

**Worktree and branch.**
- Worktree: `/project/project/AI_Support_SOC_1_2/.claude/worktrees/gold-day-0928`.
- Branch: `director/gold-day-0928`, cut from the Director branch at the DEC-144 commit.
- If your cwd is elsewhere, call `EnterWorktree` with that `path` before anything else.
- **Never call `EnterWorktree` with a `name`.** It branches from `origin/main`, and `origin/main` is still
  the stray `22698ff` (DEC-143).

**Fast-forwards.** Every commit lands on `director/gold-day-0928`. O fast-forwards `main` to it at two
checkpoints, after B1 and after B6:
```bash
cd /project/project/AI_Support_SOC_1_2
git status --short                          # expect nothing, or only untracked files O knows about
git merge --ff-only director/gold-day-0928
```
If the merge refuses, read `git status` together with O. Never `git add -A`, and never discard a file
without O's yes.

**Toolchain.**
- `PY=/project/project/AI_Support_SOC_1_2/.venv/bin/python`.
- Run make targets as `make lint|test|test-db PY=$PY`.
- `ENV=/project/project/AI_Support_SOC_1_2/.env` is passed to `label_export.py` by path. Never print,
  `cat`, `grep` or paste that file: it holds the DSN password.
- Run git one command per call, from the worktree. The guard refuses `git -C`, chained git commands and
  `eval`.

**Records.**
- **DEC-145 onward are yours today**, numbered in the order events happen. Expected: 145 signing,
  146 adjudication, 147 freeze.
- Use the same format as the entries above them in `docs/plan/DECISIONS.md`.
- Leave `docs/plan/STATE.md` alone. The Director reconciles it from your DECs at hand-back.

**Director 1** (SendMessage `Director 1`) answers questions today but commits nothing until you hand back.
Message it before doing anything this file does not cover.

## 1 · Start-of-day checks (read-only)

| check | expect |
|---|---|
| `git status --short` | nothing |
| `git log --oneline -1` | the DEC-144 handover commit |
| `grep -c 'reviewed_by: null' kb/decision_tables/*.yaml` | ten files, each `1` |
| `sha256sum eval/gold_candidates.csv` | `8ce69042a4b146ad5e4c79f7186244712aafdfacd422d6dae9e6b0d8b4f45f7e` (the 56 of DEC-141) |
| `ls eval/gold_v1.* eval/excluded_scenarios.csv eval/kappa_v1.json eval/adjudication_v1.csv` | "No such file" for each |
| `make test PY=$PY` | 0 failed (28/09: 1271 passed, 1 skipped, 2 xfailed) |

**`make test` is fully green now.** `/var/ossec` is gone from the host, so DEC-113's
`test_backfill_cli.py:184` failure no longer reproduces. Any failure is new: stop and message Director 1.

Then ask O whether anyone has opened `/admin/labels`, or any file listed in §3, today. If so, tell
Director 1 before B1 starts.

## 2 · B1 — the signing sitting (O + A, about 90 minutes, before the first label)

**Working document:** `docs/plan/kb-review-sheet-2026-09-19.md`. It is current: no table has changed
since 20/09.

**Your conduct in the sitting.**
- You may explain what a table says as written: its rules, its evidence lines, and how the gate uses it.
- You do not propose amendments.
- You never bring lab or G2 data into the sitting (the files listed in §3). A rule shaped by that data
  would fit the policy to the test set.
- If O or A want an amendment that names a lab-specific value, point to DEC-132 item 3 and do not
  transcribe it. Lab-specific values are:
  - the `127.0.0.x` srcip rotation;
  - the name `attt-m1-lab`;
  - the scenario times.

**What O sends you.** This message is the only thing you transcribe from:
- all ten tables by name, each marked either "ký nguyên bản nháp" or "sửa: <change> — <one-line reason>";
- the two signers' names, written exactly as they want them;
- the date.

If a table is missing or a change is ambiguous, ask. Never infer a signature, pre-fill one, or complete
one.

**Transcribe** (review sheet §15):
1. Make the amendments first: edit `if`/`then` exactly as worded.
2. Then set `reviewed_by: "<Name 1> + <Name 2>"` and `reviewed_at: "2026-09-28"`.
3. Check each table with the §15 one-liner. It must print `… True []`.

**One test goes red by design.** `backend/tests/test_kb_lookup.py::test_skeletons_are_unreviewed`
asserts that all ten tables are unreviewed. The Director measured the effect on 28/09, on an uncommitted
copy with all ten tables signed (the copy was restored afterwards):
- `make test`: exactly that one test fails, and nothing else;
- `make test-db`: 666 passed.

In the **same commit** as the signatures, replace that test with its inverse, `test_tables_are_reviewed`:
- every signed table has `reviewed_by ==` the exact signed string;
- every signed table has `reviewed_at == "2026-09-28"`;
- every signed table has `reviewed is True`;
- any table left unsigned is pinned by name as `reviewed is False`.

That is the only test edit B1 authorises, with one exception. If an amendment changes a rule that a
`test_kb_lookup.py` content test pins, update that test's expected value to the amended rule, one to one,
and list the change in the DEC. If anything else goes red, stop, edit nothing, and message Director 1.

**Suite.**
1. Before `make test-db`, check that no other run is using the shared test DB: `pgrep -fc pytest`
   (it prints a count only). Never print `ps` arguments; they carry the DSN password.
2. `make lint` → 0.
3. `make test` → 0 failed.
4. `make test-db` → all pass.

**Commit and record.**
- Make one commit. Its message names both signers, and lists which tables were signed as drafted and
  which were amended.
- DEC-145 records:
  - the signers and the date;
  - each table's outcome, with its amendment reason;
  - the signed tables' tree hash, `git rev-parse HEAD:kb/decision_tables`, so that P7-T08 can prove
    nothing changed after signing;
  - the sentence for `docs/limitations.md`: *"drafted by an agent … reviewed, amended and signed by the
    Owner and the advisor on 28/09/2026"*.
- O fast-forwards `main` (§0). In the primary checkout,
  `grep -c 'reviewed_by: null' kb/decision_tables/*.yaml` must then print `0` for every file.
- No restart is needed: the tables are live-mounted and read on every call.
- From this commit until the last P7-T08 run, no table is edited.

**If B1 cannot finish before labelling has to start,** stop and let O choose:
- **(a)** hold the labelling until the signing is done; or
- **(b)** label now and leave the tables unsigned. P7-T08 then reports per DEC-132 item 4.

Signing after either labeller has seen a candidate is outside DEC-132. It needs a Director decision:
message Director 1. It is never done silently.

## 3 · B2 + B3 — screenshot, then blind labelling

**B2 · screenshot.**
- O takes a screenshot of `/admin/labels` while a real candidate is showing, before the first label.
- It is for `docs/demo.md` paragraph 4 (DEC-136).
- Commit it only if O asks.

**B3 · setup.**
- Each labeller signs in at `http://127.0.0.1:8000/login` with their own account: O as `khanh-admin`,
  A as `nguyen-admin`.
- Passwords are typed in the browser, never in this chat.
- Before the first label, each labeller checks which account is signed in.

**B3 · labelling.** There are 56 candidates. For each, the labeller gives:
- one label: *Báo động giả* (`false_positive`), *Thật nhưng vô hại* (`benign`) or *Cần chuyển tier 2*
  (`escalate`);
- a confidence from 1 to 3;
- an optional note of up to 200 characters.

*Hoàn tác nhãn vừa gán* undoes the last label. The page shows `Đã xong` when a labeller has finished.

**B3 · blindness until both labellers are done.**
- The labellers work separately. They do not discuss any cluster until both pages show `Đã xong`.
- Until then you open, print or summarise none of these files, because the chat is on O's screen:
  - `eval/gold_candidates.csv` (its `scenario_id`/`kind`/`truth_label` columns);
  - `eval/lab_windows.csv`;
  - `eval/gold_coverage.md`;
  - the §3 and §5 tables of `docs/lab-scenarios.md`;
  - DEC-140 and DEC-141.
- If asked whether a cluster is an attack, answer that this is exactly what is being measured: label
  from what the page shows.
- Help with the page and the process only.

## 4 · B4 — κ and disagreements (you run them; the DB is only read)

```bash
PY=/project/project/AI_Support_SOC_1_2/.venv/bin/python; ENV=/project/project/AI_Support_SOC_1_2/.env
PYTHONPATH=backend $PY eval/label_export.py kappa --env-file "$ENV"          # → eval/kappa_v1.json
PYTHONPATH=backend $PY eval/label_export.py disagreements --env-file "$ENV"  # → eval/adjudication_v1.csv
```
- If `kappa` refuses because it sees more than two `labeler_id`s, re-run it with
  `--labeler-a <uuid> --labeler-b <uuid>`.
- To get the two UUIDs, read the users table: check its columns first, then select by username. Print
  ids and usernames only.
- Blindness ends here. Send O and A:
  - κ, overall and per category;
  - each labeller against the window truth (`vs_truth`, the human baseline);
  - the disagreement file.

## 5 · B5 — adjudication (O and A decide; DEC-120)

The meeting answers **one question: which scenario ran broken?** For example, the declared rule did not
fire as intended, or the window caught something else.
- A labeller who differs from the truth stays as data. That is the human baseline, not a truth to fix.
- `final_label` on a window row has no effect, because `freeze` takes the window truth.
- Show evidence for a scenario when asked. Never suggest an exclusion, least of all for a metric's sake.

Write `eval/excluded_scenarios.csv` with the header exactly `scenario_id,reason,decided_in`:
- one row per excluded scenario, with O's reason and `decided_in` = `DEC-146`;
- **if nothing is excluded, write the header alone.** An empty file is honest; an invented row is not.

DEC-146 records the outcome.

## 6 · B6 — freeze (you run it; the DB is only read)

```bash
PYTHONPATH=backend $PY eval/label_export.py freeze --env-file "$ENV" --out-dir eval   # → gold_v1.csv + .sha256 + .freeze.json
PYTHONPATH=backend $PY eval/label_export.py report                                    # → docs/gold-v1-report.md
sha256sum -c eval/gold_v1.sha256                                                      # → eval/gold_v1.csv: OK
```
- **Never pass `--adjudicator-id`.** With it, `freeze` writes `triage_labels` rows, which is a DB write.
  If O wants those rows, O runs that command.
- Every G2 candidate carries a window truth, so `freeze` needs neither two labels nor a `final_label` for
  any candidate. A refusal from `freeze` is therefore unexpected: stop and message Director 1.
- Commit the seven files the run sheet lists:
  - `gold_v1.csv`, `.sha256`, `.freeze.json`;
  - `kappa_v1.json`, `adjudication_v1.csv`, `excluded_scenarios.csv`;
  - `docs/gold-v1-report.md`.

  Never commit anything under `eval/results/`.
- DEC-147 records the frozen row count, the sha256, κ overall and the exclusions.
- O fast-forwards `main`. The labelling page then disables *Hoàn tác*, because the freeze marker exists.
- From here on, `gold_v1.*` is never edited. Any change becomes `gold_v2`, by existence.

## 7 · Hand back

- **To O, in Vietnamese:** what was done, the commits, the fast-forward command, and "báo Director 1
  là G đã xong".
- **To Director 1** (SendMessage):
  - the branch tip sha and the DECs you used;
  - the table tree hash, or which tables are unsigned;
  - κ overall;
  - the `gold_v1` sha256;
  - the exclusions;
  - anything unresolved.
- **Then stop.** P7-T08 (29/09) is the Director's. You do not start it, you touch no code beyond B1's
  test inversion, and you open no other cards.

## Standing rules

- **O runs every DB write and every container command.** You never run `docker compose` changes or
  `UPDATE`/`INSERT`/`DELETE`. Your DB access is `label_export.py` (read-only, as above) and read-only
  `psql` selects.
- **Never fabricate.** A missing label stays missing, a missing signature stays `null`, and an empty
  exclusion list stays a header.
- **In the primary checkout:** no `git add -A`, no commit of `backups/latest.dump`, nothing under
  `eval/results/`.
- **No subagents or workflows** unless O asks for one by name.
