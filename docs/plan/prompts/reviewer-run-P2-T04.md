# Reviewer — P2-T04, round 2

**Invocation (the Owner pastes this, nothing else):**

```
Read docs/plan/prompts/reviewer.md and act as the Reviewer. Then read
docs/plan/prompts/reviewer-run-P2-T04.md — it is this round's scope note. Task: P2-T04.
```

`prompts/reviewer.md` governs: you verify, you never fix code; the card is
`docs/plan/tasks/P2/P2-T04.prompt.md`; your verdict is an artifact or it did not happen
(DEC-028). This note only says what changed since round 1, so you spend the round on what is
actually new rather than re-deriving the parts that were already verified.

## 1 · Where this stands

Round 1 (`61cbb1a`) returned **CHANGES** with exactly **one** blocking finding, bucket (a): the
docstring at `backend/tests/test_wazuh_parser.py:157` asserted that `datetime.fromisoformat`
rejects `+0700` unnormalised — false on py312, and the Coder's own report §3 had measured it
false. No code was implicated; the parser's normalisation is correct and still required.

Since then, on `task/P2-T04`:

| commit | what |
|---|---|
| `23cd78d` | the docstring fix — the only charged finding |
| `1e998ea` | `git merge main` (the card's rule 1) |
| `57965d8` | report: "all 12 acceptances re-run green", STATE row → `review` |

Round 1's non-blocking notes **B and C are discharged and are not yours to re-raise**: the
Director took them as bucket (b) and recorded **DEC-067**. Nothing there is charged to the Coder.

## 2 · The card moved under the branch — read the current one

**DEC-067 corrected two items of `P2-T04.prompt.md` after the Coder reported.** The acceptance
**commands are unchanged**; only the prescribed *red steps* changed, so a completed pass was not
invalidated:

- **Acceptance 4** (`:117`) — the old failing case, *"break the `+0700` normalisation"*, cannot
  go red on py312 (same root cause as round 1's finding). It now reads: **break the no-`fields`
  fallback lookup** → the no-`fields` test goes red.
- **Acceptance 8** (`:121`) — had **no** red step. One was added: the obvious break (dropping
  `.astimezone(UTC)`) is a **provably equivalent mutant**, so the falsifiable break is to compute
  the hash **from the naive wall clock** → `test_cung_thoi_diem_khac_mui_gio_cung_hash` goes red.

**This is the one piece of genuinely new verification in the round, and it is the point of it.**
DEC-025 says every acceptance needs a demonstrated failing case; DEC-067 exists because two of
them asserted nothing. So do not take the new red steps on trust either — **run both breaks and
paste the red output**, then restore. If either cannot go red, that is a finding against the
card (bucket (b), Director's), not against the Coder.

## 3 · The shipping state — `main` has moved, prove it rather than assume

Measured before this note was written:

```
git merge-base task/P2-T04 main   → ca74502
git rev-parse main                → b576462
```

So the branch merged `main` at `ca74502`, and `main` has moved since. **Two of those commits
carry real code, not documentation** — I wrote "documentation-only" here first and the command
said otherwise, which is the whole reason this section exists:

```
git diff ca74502..main --name-only | grep '^backend/'
  backend/app/ingest/category.py
  backend/tests/test_category.py        ← P2-T16 merged (bd3f1b6, DEC-055)
```

**P2-T16 landed on `main` while this branch was in review.** Its files and P2-T04's are disjoint
(`ingest/category.py` against `ingest/wazuh_parser.py` + `domain/alert.py` + their tests —
verified with `comm -12` over the two name lists, no overlap), so the composition looks safe.
**"Looks safe" is not the standard here.** DEC-047 is exactly this shape: two separately-correct
branches, every command green on both sides, composed into a defect neither had — and the files
were disjoint there too. The suite is what catches it, not the file list.

So verify the state that will ship (DEC-043 as amended by DEC-046): merge `main` into a scratch
worktree and run the acceptance **there**, or verify by the merge route the card's rule 1 names.
Re-derive both hashes yourself before you start — `main` may have moved again since this note.

## 4 · What to run

All twelve acceptance items of the card, in an isolated worktree (DEC-010). They are cheap and
need no database — acceptance 12 states it: `make test-db` is **not** required for this card.
Then, beyond the list:

- **The fix itself.** Read the docstring as it now stands (`test_wazuh_parser.py`, the
  `test_timestamp_offset_khong_dau_hai_cham` docstring) and check it states something true and
  still explains why `_parse_iso` normalises anyway. A docstring that trades one false claim for
  another is the same defect.
- **Scope.** `git diff main...task/P2-T04 --stat` against the card's *Files — create/modify*.
  Round 1's fix should touch exactly one test file; anything else in the delta since `61cbb1a`
  that the report does not explain is a finding.
- **The report's claims.** `57965d8` says all twelve were re-run green. Spot-check the ones a
  merge could plausibly have broken rather than trusting the sentence — `prompts/reviewer.md`'s
  standing rule is that a report is not proof.
- **Frozen contracts.** No migration, config key, output schema, API route, job type or event
  type moves in this diff. If one does, it needs a `DEC-nnn` cited in the report.

## 5 · Bucket accounting — say it explicitly in the verdict

Round 1's single finding was **(a)**, and it is the only thing charged to P2-T04 so far.
DEC-067's two corrections are **(b)** — the Director's, free to the Coder. If round 2 produces
**new (a) findings**, that is the second genuine round on one card and
`prompts/director-optimized.md` requires split, cut, or a change of approach rather than a third
round — so name the bucket for every finding you raise, and be sure a finding is really the
Coder's before you charge it.

## 6 · Output

`docs/plan/tasks/P2/P2-T04.review.md` — verdict `APPROVE` or `CHANGES`, every acceptance item
with the command and its real output, the two DEC-067 red steps with their red output, and the
shipping-state check with both hashes. Then set the `P2-T04` row in `docs/plan/STATE.md` to
`approved` (APPROVE) or `changes` (CHANGES), and **commit both on the task branch** (DEC-028).
Do not merge — merging is the Director's.

**What an APPROVE here unlocks, so the round is worth finishing carefully:** T05, T06, T08 and
T09 all become dispatchable on disjoint files the moment this merges — the largest single unlock
left in P2.
