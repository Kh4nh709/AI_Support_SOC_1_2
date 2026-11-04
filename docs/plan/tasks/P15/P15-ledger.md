# SDD ledger — plan: docs/superpowers/plans/2026-11-04-remove-autoclose-ui.md

- **Spec:** DEC-214 (docs/plan/DECISIONS.md, the last entry), with the Owner's quotes and the two answers: "Rules + Digest" and "Cả live và trial".
- **Director branch:** director/remove-autoclose-ui, in worktree /project/project/AI_Support_SOC_autoclose_ui, cut from main af56b13. The docs commit is 2c65bfc.
- **Process:** DEC-201. The Coder is coder-sonnet55, in its own worktree. The Reviewer runs on model "opus" (the Owner's rule of 04/11; never Fable or Mythos).

## Preflight scan

The plan has one task, so there are no task pairs.

| Row | What was checked | Found |
|---|---|---|
| T1 self | Step 1's tests against Steps 2–6's removals: routes, sidebar, funnel, permission row, query keys, guard | consistent |
| T1 self | Global "frontend only" against Step 4 (delete backend/tests/test_rules_whitelist_pin.py) and Step 6 (test_runbook_* pins) | consistent: these are tests and docs, not backend/app |
| T1 self | Guard ("no non-test file under frontend/src contains admin/rules or admin/digest") against what is kept: audit summaries, api/admin.ts:3's comment "admin_rules.py" | consistent: the kept text uses underscores (admin_rules, admin.autoclose_*), not "admin/rules" |
| T1 self | "Kept: the audit page's summaries" against "remove the digest/rules strings blocks" | possible coupling: a kept summary may read a string from a removed block (for example, verdict labels). See the ruling below. |
| T1 self | Overview: funnel row removed, while the backend still sends the auto_closed key | covered by Review Focus 4 and the Step 1 funnel test |

**Ruling:** a string, type or helper that a kept file uses stays, even when it lives in a removed block. It moves next to its user with its wording unchanged. Why: the plan keeps the audit summaries verbatim, and the Owner said "chỉ xóa auto-close". Cost if wrong: a few leftover string lines, which the reviewer will see.

**Ruling:** STATE phase P15 is numbered after P13 on main, with no P14 row there, because P14 lives on director/voyage-rag only. DEC-214 likewise follows DEC-212 on main. Why: one number on both branches lets the voyage merge carry the same IDs. Cost if wrong: a cosmetic gap on main.

## Tasks

- **Task 1 (P15-T01): dispatched 04/11.**
  - BASE is 2c65bfc. The coder agent is a172b799b55d6b4be (coder-sonnet55, isolation worktree). Its branch is worktree-agent-a172b799b55d6b4be, which task/P15-T01 points at.
  - The dispatch text is in the scratchpad, `p15-t01-dispatch.txt`.
  - **Ruling:** the STATE row stays `todo` on the director branch while the coder works, and the full row is written at the merge. Why: a commit on the director branch in the middle of the task would make the coder's branch diverge from BASE. Cost if wrong: the board shows `todo` for about an hour; the invariant holds, because `task/P15-T01` exists.
- **Task 1: coder DONE_WITH_CONCERNS.**
  - Tip 705b470: work commits daddd22..3775ad7, then the report.
  - The report is docs/plan/tasks/P15/P15-T01.report.md, in the coder's worktree.
  - Tests:
    - make lint clean;
    - make test 4820 passed, 1 warning;
    - ui-lint clean;
    - ui-test 62 files, 2871 tests;
    - ui-build OK;
    - ui-e2e 23 passed, secret scan clean.
  - Red shown first: 28 frontend tests and 6 backend pins.
  - **Director checks:**
    - backend/app, docs/Schema, eval, scripts, compose and .env are untouched (the diff is empty).
    - The backend changes are only the deletion of test_rules_whitelist_pin.py and 4 runbook pin tests.
    - Baseline make test at 2c65bfc: 4822 passed, with the same 1 warning (starlette's anyio DeprecationWarning). So the warning was already there; the change did not introduce it.
  - **Ruling C1:** accept the six-page lists with /admin/knowledge added. Why: the sentences had to be rewritten, and an accurate list includes the page P13 added. Cost if wrong: one extra page name in two runbook lists.
  - **Ruling C2:** accept the port-8000 history lines (runbook 24, 43, 56). They name the Jinja pages that P11-T19 retired, and the guard allows them only on port-8000 lines. Why: they are accurate history. Cost if wrong: a reader sees the old paths in that context.
  - **Ruling C3a:** keep the audit group label "Rules, digest, hạn mức". Why: the Owner's choice keeps the audit labels; only the "every trace" option, which was not chosen, removed them. Cost if wrong: one visible "Rules, digest" filter group name.
  - **Ruling C3b:** limitations.md:776 "the queue, the alert page and the digest show it" is stale, because the digest page is gone. This is Director finding D1, for the fix dispatch. limitations.md:795 and runbook 640/674 stay. Why: 795 describes backend tests of the digest API, which remain; 640/674 are the blind-arm rationale for reopened alerts, still true for any past reopen. Cost if wrong: two slightly dated sentences.
  - **Ruling C4:** accept the e2e/fixtures.ts helper removal. Why: those helpers served only the removed scenarios 6 and 7. Cost if wrong: none.
  - **Ruling C5:** the unit-level bookmark pin is enough. Why: the real stack's router is the same code. Cost if wrong: no real-browser proof of the redirect.
  - **Ruling (review seats):** one Opus review over the whole branch (af56b13..705b470, which includes the Director's docs commit 2c65bfc). It is both the task review and the final whole-branch review. Why: the plan has one task, so a second review of the same diff duplicates it. Cost if wrong: no separate whole-branch seat, but nothing crosses tasks.
  - Review package: review-af56b13..705b470.diff (8 commits, 527 KB, mostly the deleted files).
  - The reviewer is agent a150eebf53f76e24c (general-purpose, model opus), dispatched 04/11.
- **Probe merge into the trial (scratch worktree, aborted and removed): 3a144a7 + 705b470.** It gives 10 conflicts:
  - docs: DECISIONS, STATE, runbook;
  - frontend: api/admin.ts, AdminLayout.tsx, AdminLayout.test.tsx, adminKeys.test.ts, routes.tsx, routesLazy.test.tsx;
  - DigestPage.test.tsx: deleted on this branch, modified by P14 (UD).
  - The cause is P14's "Gán nhãn lab" page next to the removed pages, and P14's true_positive rename in the digest tests.
- **Task 1: review (Opus, a150eebf53f76e24c): Approved.**
  - Spec ✅. 0 Critical, 0 Important, 8 Minor, 3 ⚠️. Saved verbatim as task-1-review.md.
  - ⚠️ voyage merge → Task 2. ⚠️ bookmark on the real stack → an Owner check after the ui rebuild. ⚠️ wording outside the brief → D1 (limitations.md:776) and D2 (runbook.md:228).
  - **Ruling (final-review triage):** ONE fix dispatch to the original coder covers M1, M2, M4, M5, M6, D1, D2 and the report gap (adminFixtures.ts).
    - M3 is the Director's own record (DEC-214 item 3 and its Propagated list; the STATE row's "Owner action needed? no"). The Director fixes it after the ff, inside the re-review range.
    - M7 is parked: a nit, and the 8080 list is pinned by test_runbook_deploy.py.
    - M8 is parked: the warning was already there at the baseline (2c65bfc: 4822 passed, 1 warning).
    - Why: cheap, local fixes before a merge into main. Cost if wrong: one more coder round.
  - **Ruling M1:** remove the "not found" mapping, as Ruling 3 requires, unless the coder finds that Starlette's own `{"detail":"Not Found"}` for an unknown route reaches it (a case-insensitive lookup). In that case keep it on purpose, with that reason and a realistic test. Why: the reviewer saw only deps.py as a producer. Cost if wrong: an unknown-route 404 shows a generic message.
- **Task 1: fix round 1/5.**
  - All 8 items were sent to the coder; M3 was the Director's own.
  - Coder commits 11c18ee..3b58e80; the Director's M3 fix is a51b0fb.
  - The M1 check found the lookup is `Object.hasOwn`, an exact match, so Starlette's "Not Found" never reached it. The entry was removed, and an "as other" case was pinned.
  - Tests:
    - lint clean;
    - make test 4822 passed, 1 warning (pre-existing);
    - ui-test 62 files, 2870 tests;
    - ui-lint and ui-build clean;
    - ui-e2e 23 passed.
  - The director branch was fast-forwarded to 3b58e80, then a51b0fb was committed.
  - The re-review is agent ac50898fa7d19baba (opus), on review-705b470..a51b0fb.diff.
- **Director mutation check at a51b0fb (scratch worktree, removed afterwards):**
  - Baseline: 3 files, 75 passed.
  - M-a (the funnel row auto_closed restored): overviewModel.test 3 failed.
  - M-b (the sidebar link /admin/rules restored): AdminLayout.test 3 failed.
  - M-c ("/admin/digest" in a kept source file): removedAutoclosePages.test 1 failed.
  - All three red, so the guards bite.
- **Task 1: re-review (Opus, ac50898fa7d19baba):** all 9 items ADDRESSED, no new Critical or Important breakage. It found 2 new Minors in the fix diff, both test comments. Saved verbatim as task-1-rereview.md.
  - Task 1: parked. The admin.test.ts:582 comment says "the removed digest route" (the route stays; only its client was removed). Ruling: park. Why: a comment in a test, with no behaviour, and the SDD has no second fix wave. Cost if wrong: one misleading comment line until that file is next touched.
  - Task 1: parked. The adminStrings.test.ts:223-225 comment gives a false reason; the assertion itself holds, justified by the row-51 test. Ruling: park. Same why and cost.
  - Task 1: parked. M7, the per-line "8000" exemption in test_runbook_admin.py:85. Ruling: park. Why: a nit, and the 8080 list is pinned by test_runbook_deploy.py. Cost if wrong: a future /admin/rules on a line that also mentions 8000 would pass the guard.
  - Task 1: parked. M8, the 1 warning in make test. Ruling: park. Why: it was already there (the baseline 2c65bfc shows the same starlette/anyio DeprecationWarning). Cost if wrong: none.
- **Task 1: complete** (commits 2c65bfc..a51b0fb, review clean after fix round 1, 4 parked). The records P15-T01.review.md and P15-T01.rereview.md are committed with the STATE row done. Task 2 was added to the plan, and the P15-T02 row is todo.
- **main fast-forwarded af56b13 → ed5aa5f** in the primary checkout. Its local modifications (backups/latest.dump, docker-compose.yml) do not overlap P15 and were kept.
  - Director gate at ed5aa5f: lint clean; make test 4823 passed (+1: P15-T01's verdict artifact test); ui-lint clean; ui-test 62 files, 2870; ui-build OK.
- **Task 2 (P15-T02): dispatched 04/11.**
  - BASE is the trial tip 3a144a7, plus P15's tip ed5aa5f to merge.
  - The coder agent is ac4777a6046d57abf (coder-sonnet55, isolation worktree). Its branch is worktree-agent-ac4777a6046d57abf, which task/P15-T02 points at.
  - Correction sent right after the dispatch: the isolation worktree starts at the stale origin/main 22698ff, not at ed5aa5f. HEAD 22698ff is therefore expected, followed by `reset --hard director/voyage-rag`. The memory was updated.
- **Task 2: coder DONE.**
  - Merge cb35f9b; adaptations 7b15f93 (two runbook page-count pins) and a2b3234 (the adminKeys key list); tip 6adb018 (the report).
  - Gates:
    - lint green;
    - make test 5727 (trial baseline 5726);
    - ui-test 3397 in 70 files (baseline 3743 in 73);
    - ui-lint and ui-build green;
    - ui-e2e 32 passed.
  - Ruling 5 case: DigestPage.test.tsx stays deleted, and P14's "TP" digest test goes with it. The label stays pinned in strings/AlertPage/AiColumn tests.
  - Concerns:
    - e2e 32 against P14's recorded 14. Accepted: the full suite now, and P14's recorded run was narrower.
    - The "six links" comment on S.admin.nav. Accepted: true of that object, since the lab link lives in S.admin.lab.nav.
- **Task 2: Director checks.**
  - backend/app, Schema, eval, scripts, compose and .env are untouched.
  - The P14 lab UI files and eval/lab_measure.py are unchanged.
  - DEC-212, DEC-213 and DEC-214 are all present, and so is the runbook's DEC-213 section.
  - The file list 3a144a7..6adb018 equals main's af56b13..ed5aa5f, plus test_runbook_voyage_edits.py and the P15-T02 report.
- **Task 2 review package:**
  - review-3a144a7..6adb018.diff (19 commits, 561 KB);
  - remerge-cb35f9b.diff (10 files, 113 KB; `git show --remerge-diff`).
- **Task 2: review (Opus, aa07050feb11030d5): Needs fixes.** Saved verbatim as task-2-review.md.
  - Found: 0 Critical, 1 Important, 4 Minor, 3 ⚠️.
  - The reviewer verified:
    - all 25 P15-only files equal ed5aa5f, except one adapted pin;
    - all 229 P14-only files equal 3a144a7, except one adapted pin;
    - 11 of the 20 shared files are exact unions;
    - the records are whole and in order.
  - **I1:** runbook.md:24 (the UI section) on the trial omits /admin/lab, and test_runbook_deploy.py:207-214 pins that omission. This enters the fix loop.
  - m1 (the report contradicts itself about the sidebar pin): fix round 1.
  - m2 (the AdminLayout.tsx:1 comment "seven pages" should say "seven links"): fix round 1.
  - Task 2: parked. m3, the P15 phase row renders outside the table. Ruling: park. Why: P14's multi-line phase row breaks the table, the P14-then-P15 order forces the position, and P14's row format is out of scope. Cost if wrong: a cosmetic rendering glitch in STATE.md on the trial.
  - Task 2: parked. m4 / ⚠️1, the 1 warning. Ruling: park. Why: the Director ran make test at 3a144a7 and got "5726 passed, 20 skipped, 4290 deselected, 2 xfailed, 1 warning", the same starlette anyio.abc.BlockingPortal DeprecationWarning, so it predates the merge. Cost if wrong: none.
  - ⚠️2: task/P15-T02 re-pointed to the coder branch (6adb018).
  - ⚠️3: the bookmark check on the real trial ui goes into the Owner's deploy block.
  - Fix round 1 was sent to the coder (I1, m1, m2).
- **Task 2: fix round 1/5.**
  - Coder commits fa62a6a (I1, red first: "At index 4 diff: 'knowledge' != 'lab'"), d832e64 (m2), and be12069 (the report: m1 and the baseline line).
  - Tests: make test 5727 with 1 warning (pre-existing); lint and ui-lint green; ui-test 3397.
  - The re-review is agent a20a3e150e14d6c2c (opus), on review-6adb018..be12069.diff.
- **Director mutation check at be12069 (scratch worktree, removed afterwards):**
  - M-a, the lab link removed from the sidebar: AdminLayout.test 5 failed of 18.
  - M-b, /admin/lab dropped from runbook:24: test_runbook_deploy's UI-section test failed.
  - Both red, so P14's lab entry and the I1 pin are guarded.
- **Task 2: re-review (Opus, a20a3e150e14d6c2c):** I1, m1, m2 and m4 (the report part) are all ADDRESSED, with no new Critical or Important breakage. Two report-only Minors. Saved verbatim as task-2-rereview.md.
  - Task 2: parked. The report's "Gates after round 1" lists 4 of the 6 gates (ui-build and ui-e2e are not re-run). Ruling: park. Why: round 1 changed only a frontend comment, and the Director ran ui-build at the final trial tip 83f2d22 (OK). Cost if wrong: none for the code; the report reads slightly short.
  - Task 2: parked. Report nits: the route-pin wording, a stale heading, and the header commit list missing be12069. Ruling: park. Why: report text only; STATE names every commit. Cost if wrong: a reader of the report has to look at STATE for the round-1 tip.
- **Task 2: complete** (commits 3a144a7..be12069, with the merge cb35f9b; review clean after fix round 1; 4 parked).
  - director/voyage-rag was fast-forwarded 3a144a7 → be12069 in /project/project/AI_Support_SOC_voyage. The records commit there is 83f2d22, which is the trial branch's tip.
  - Director gate at 83f2d22: lint clean (335 files); make test 5728 passed, 1 warning (pre-existing); ui-build OK.
  - main: the records were copied in 391304a (docs only), and main was fast-forwarded to 391304a. make test 4824 passed.
- **Ruling (plan amendment):** add Task 2 (P15-T02). A Coder carries the reviewed P15 tip onto director/voyage-rag by a merge that resolves the conflicts, keeps everything P14 added, and adapts the new tests to the trial's sidebar (which includes /admin/lab). An Opus review of the resolution follows. Why: conflict resolution is code work, and the Director never codes (DEC-201). The Owner chose "Cả live và trial". Cost if wrong: one more card than a hand merge would take.
