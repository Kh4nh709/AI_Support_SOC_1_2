# Director — the defect sweep of 25/09: one real exposure, three stale rows, two overdue decisions

**Invocation (the Owner pastes this, nothing else):**

```
Read docs/plan/prompts/director-optimized.md and act as the Director. Then read
docs/plan/prompts/director-run-2026-09-25-fixes.md and execute it in order — an intake run
(DEC-048 batching) that ends in the evening-gate row for 25/09.
```

Your standing prompt governs. This is the run after `29207a9` (DEC-110). Written by the Support
Agent at the Owner's instruction, 25/09 15:45; every figure was measured then — re-derive before you
record any of it.

## 1 · What is actually broken, and what only looks broken

**Broken — one item, and it outranks everything else on this board today.**
`backups/latest.dump` — 32,978,015 bytes, a `soc_dev` custom-format dump — is **in `origin/main` on
a public GitHub repository** (`api.github.com/repos/Kh4nh709/AI_Support_SOC_1_2` → **200**
unauthenticated), committed `5b1deb1` on 20/09, and `.gitignore:29` un-ignores it deliberately
(`!backups/latest.dump` under the `backups/*` rule). `pg_restore -l` lists **`TABLE DATA public
users`** and `TABLE DATA public identities`; the four pilot accounts were created 20/09 07:27 UTC
and the dump was committed 20/09 14:06 UTC, so **the four argon2id hashes and the whole real alert
corpus are published**. Local `main` is 15 commits ahead of `origin/main` and the dump is modified
in the working tree, so an ordinary `push`/`commit -a` publishes a second copy.

`STATE.md:122` already carries this as an Owner action. It is no longer a risk note: it is a
measured exposure, and it needs **a DEC of its own** plus two sentences in `docs/limitations.md`.
The remediation is being run from `prompts/secrets-remediation-run-2026-09-25.md`; the Owner picks
the route (private repo + rotate, versus a history rewrite that would land under four live
worktrees five days before the deadline). Record the decision, not a recommendation of your own
beyond what you can measure.

**Only looks broken — close these three rows rather than carrying them:**

- `STATE.md:115` "add `Windows_Endpoint` and `pfSense.home.arpa` to `conf/inventory.yaml`" — **done**: the file now has **6** `hostname:` rows including both, with the 23/09 `agent_control` comment (`conf/inventory.yaml:56-76`). Tick it.
- the failed `pull` job — historical, not live. `jobs` today: `pull` succeeded **4,652**, one `pending`, and the single `failed` (`job_id 101019`, `INDEXER_CA … not a readable file`) predates the compose cutover. Measured in the worker container: workdir `/srv`, `conf/root-ca.pem` present, and jobs `106327–106329` all **succeeded** one minute apart. Do not card it; note the cause in the gate row so nobody re-opens it.
- `.claude/` and `.codegraph/` — untracked and **not** ignored (`git check-ignore` silent). Not a defect yet; it becomes one the first time anybody runs `git add -A`. The `.gitignore` line is prepared in the remediation run; it is outside `docs/plan/`, so the Owner commits it.

## 2 · One correction to your own last dispatch line

You wrote that `P4-T03`, `P3-T11` and `P6-T06` need `git merge main` first and that `P6-T02` is at
`4e5a86c`. Measured: **`P6-T02` is 9 commits behind `main`**, and three of those commits carry
`backend/` files — `backend/app/infra/intake.py`, `backend/app/web/routers/webhook.py`,
`backend/tests/test_webhook.py` (P4-T08, `5dabd7e`). So **all four** branches merge `main` before a
Coder starts, not three. All four are `ahead=0`, i.e. no Coder has opened any of them yet.

## 3 · Two decisions the Owner owes, both past their date — put them in one place with their cost

- **G2: restore the lab, or declare G1-only.** Due **24/09** (`STATE.md:111`), unanswered. Measured on the new stack: `rule.id:100999` → **0**, `rule.id:1003*` → **0**, `eval/lab_windows.csv` is header-only, and `/home/user1/archive/` holds **only `README.md`** — the G1 export never came to ATTT-M1 (DEC-108). So G2 does not exist and the lab would have to be rebuilt — heartbeat, three local rules, three days of windows — with **seven days to 02/10**. `01-plan.md:125` already lists "G2 category coverage below 8 (report what exists)" as P6's own cut candidate, so G1-only is inside the plan's own cut order; carry that fact, and the cost of each route in days.
- **The two labellers, by name, with hours.** `STATE.md` contains **no name**. Labelling is dated 26–27/09 — **tomorrow** — and P6-T02 (the page) is `todo` with no Coder session opened. Either the names land today, or the date moves and you re-date P6/P7/P8 in the same DEC. One labeller means no κ and a named single-annotator limitation; say so in the row.

## 4 · P4-T09 — the Owner has answered: card it, and put it last

DEC-109's follow-up is accepted: five authenticated-but-malformed webhook bodies return **500**
instead of 4xx. One file plus tests, so it takes the card-free acceptance-contract form (DEC-018,
DEC-032, DEC-055 precedent) — the contract is written at
`prompts/coder-P4-T09-webhook-hardening.md`; record it as a DEC and add the `STATE.md` row at
`todo`, **behind P4-T03/T05/T06**. It does not take a slot this week; if 30/09 arrives with it
unstarted, cut it and name the five bodies in `docs/limitations.md`.

## 5 · The gate row for 25/09

P6 is the current phase. Measure its exit gate literally and expect it to be red: `eval/gold_v1.csv`
absent, `eval/lab_windows.csv` header-only, κ not computed, P6-T02 `todo`. Then the schedule
sentence: P4 3/8 → **4/8** after DEC-110, P5 **0/13**, and ② was pre-announced to fall at tonight's
gate — with P5 at zero cards built, applying it costs nothing built and returns a day. Say whether
it falls, and under which authority (DEC-071's A′, or the Owner tonight).

Commit `docs/plan/` by name — `director: 2026-09-25 pm (3)`.

## 6 · Do not

- Do not run, or ask an agent to run, any history rewrite, force-push, or repository-visibility
  change; do not read rows out of the dump. All of that is §4 of the remediation prompt.
- Do not re-open the P4-T04 merge-before-review question — DEC-110 closed it with an approval on
  record.
- Do not decide G2, the labellers, or the ② cut for the Owner; frame each with its measured cost and
  stop.
