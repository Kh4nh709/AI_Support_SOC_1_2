# P0 pre-dispatch audit — T03, T04, T05, T06

Run 2026-09-05 by the Director, applying DEC-006 ("every acceptance line in a card is
executed once by its author before the card is dispatched"). This is the first
application of that rule; it exists because P0-T01 was returned CHANGES over an
acceptance line nobody had ever run.

## Method

A throwaway detached `git worktree` was built at `main` merged with the approved
`task/P0-T02`, i.e. the exact tree a Coder starts from (`Makefile`,
`backend/pyproject.toml`, `.env.example`, `scripts/` all present). Every acceptance
command in the four cards was **executed** there, not read. Each was classified
`OK` / `CLI_DEFECT` / `WRONG_EXPECTATION` / `NOT_YET_APPLICABLE`, where
`NOT_YET_APPLICABLE` means "fails only because the deliverable this task creates does
not exist yet" — expected, not a defect. Every claimed defect was then verified twice
by independent agents: once to reproduce it, once to prove the proposed fix actually
passes when run.

37 acceptance commands executed across the four cards.

## Result: 3 defects claimed, 1 survived

The adversarial pass refuted two of three. Both refutations were correct and are
recorded because they are as useful as the finding:

- **P0-T06 #3 (AST heredoc) — REFUTED, no change made.** The block does fail when the
  card's markdown list-continuation indentation is pasted into a shell, but that is
  true of every indented code block in every card, the heredoc itself is sound, and the
  repo already contains a merged, approved counter-example in the same style.
- **P0-T03 #6 (conftest grep) — REFUTED as a defect, but its patterns were stale.** It
  is a judgment probe with a stated criterion, not an exit-code gate, so "it produces
  output" is not a failure. Its `localhost:9400` pattern was still corrected: DEC-001
  fixes the host as `127.0.0.1:9400`, and an indexer pattern cannot occur in a psycopg
  conftest at all.
- **P0-T03 #3 — SURVIVED.** `-q` alone prints only `s` and never shows a skip reason, so
  the line asked the Reviewer to verify something the command does not display. `-rs`
  added. The counter-claim that a new file was needed was refuted: the db-marked test
  belongs in the already-authorized `backend/tests/test_conftest_helpers.py`.

## Corrections applied

| Card | What was wrong | Binding rule broken |
|---|---|---|
| T02, T03, T04, T05, T06 | working rule 6 invoked bare `pytest`, which does not resolve `app.*` | DEC-005 |
| T05 | design notes ordered a criticality mapping table "labelled as proposed" — contradicting DEC-004 *and* line 28 of the same card, which says to write none | DEC-004 |
| `P0-tasks.md` | planning decision 1 still read "P1's `013`–`016`", contradicting §Hand-off item 1 in the same file | DEC-004 |
| T03 | acceptance 6 greped for `localhost:9400` | DEC-001 |
| T03 | acceptance 3's skip reason was not displayable by its own command | DEC-006 |
| T03 | "exactly these 20 keys" followed by a 21st sibling key; "three §8 sentences" followed by four | internal |
| T04 | `PULL_PAGE` listed as required despite having a default, so acceptance 4 would exit 2 naming it instead of `INDEXER_CA` | internal |
| T06 | escape hatch said "run acceptance 2–5" on a card with 7 items | internal |
| T06 | working rule 2 demanded a failing→passing demo of a purity check that already passes on the pristine tree | internal |

## Still open — design judgments, not defects

These need a decision before or with dispatch; none blocks the others:

1. **T05 · `conf/iocs.csv.example`** — the card says to "note in a comment" that a missing
   value yields `not_found` and an unperformed lookup yields `skipped`. CSV has no comment
   syntax. Put it in `docs/inventory-format.md`, or agree a `#`-prefixed first line.
2. **T05 · `INVENTORY_PATHS`** — stored as a JSON array in `.env.example` and context pack
   §6.3. `validate(paths)` is said to default to it, but the card never says to `json.loads`
   it.
3. **T05 · path routing** — `validate()` takes three heterogeneous files but the card does
   not say whether they route to `validate_assets`/`_identities`/`_iocs` by position, by
   filename, or by sniffing the top-level key.
4. **T04 · `--save-samples`** — writes `backend/tests/fixtures/indexer_sample_*.json`, which
   is not in "Files — create", while "Do not touch any other file" stands.
5. **T04 · `--json`** — appears in the usage block; nothing says what it emits and no
   acceptance line covers it.
6. **T06 · dependency** — the critical-path diagram draws `P0-T02 → P0-T03 → P0-T06`; the
   `Depends on:` field, the `P0-tasks.md` entry and `STATE.md` all say only `P0-T02`.
7. **Card sync** — `P0-T03`, `P0-T04`, `P0-T05` and `P0-T06` each have a fuller
   `.prompt.md` and a shorter `P0-tasks.md` entry whose acceptance sets differ in count
   and wording. Under DEC-006 the acceptance set is the Director's deliverable, so one of
   the two must become authoritative.

## Dispatch prerequisite

Every one of T03–T06 carries `Depends on: P0-T02 — verify it is merged into main`.
`P0-T02` is approved but **not merged**; `Makefile`, `backend/pyproject.toml`,
`.env.example` and `scripts/` exist only on the branch. Merging it is the gate.
`docs/plan/STATE.md` is the only conflicting file and `main`'s copy wins wholesale.
