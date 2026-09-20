# KB Drafter — draft the ten decision tables so the Owner + advisor sitting is review, not authorship

**Invocation (the Owner pastes this, nothing else — session name `kb-drafter`):**

```
Read docs/plan/prompts/kb-drafter-run-2026-09-19.md and act as the KB Drafter. Start with §0.
```

You draft content that two humans will review, amend and sign. You are not one of them. This is a
**card-free acceptance contract** (DEC-078 precedent): §5 is what you must prove, and the Director
records the outcome as a DEC. Written by the Support Agent at the Owner's instruction, 19/09.

## 0 · Read first, in this order

1. `backend/app/kb/lookup.py` — the whole file. It is the contract: `_VOCAB` (the four
   categorical facts and their exact values), `_INT_CONDITION_KEYS` (`occurrence_lt/gte`,
   `rule_level_lt/gte`), `_ACTIONS` (`false_positive` · `needs_review` · `escalate`),
   `_RULE_ID_RE`, `fact_grid()` (the 2,520-point consistency grid), `check_consistency()`,
   `apply_table()` — **read how rules are ordered and which one wins before you write a single
   rule**; `severity` is derived from `rule_level` (DEC-053 bands), never free.
2. `kb/decision_tables/*.yaml` — the ten skeletons P3-T06 shipped. Keep their header comments,
   `category`, `playbook`, and **`reviewed_by: null` / `reviewed_at: null` exactly as they are**.
3. `kb/playbooks/*.md` — the ten playbooks; a table must agree with its playbook's decision
   branches. Two lines are known-wrong and are P3-T12's to fix, not yours:
   `ssh_brute_force.md:34`, `malware.md:36` (`crown_jewel`, a vocabulary DEC-004 retired). <!-- superseded-ok: DEC-004 names the retired value to say it is retired -->
4. `docs/kien-truc-v3-14-ngay.html` §3.10 — the decision-table design and its worked examples.
5. `docs/plan/DECISIONS.md` — **DEC-034** (asset weights `high 30 · medium 10 · low 0 ·
   unknown 0`; `high` is a hard auto-close block, G8′), **DEC-052** (asset-hygiene alerts stay
   in, filtered nowhere), **DEC-053** (severity band), **DEC-055** (the `attack` mapping fix and
   the two content questions written into the `privilege_escalation` skeleton header),
   **DEC-058** (unlisted assets pin `needs_review`), **DEC-086** (G1's composition).
6. `docs/plan/tasks/P3/P3-T06.report.md` and `.prompt.md` design notes 2–5 — the format rules
   in the Coder's own words, including the `c2b` abbreviation deviation.
7. `backend/tests/test_kb_lookup.py` — the test that will judge you.

## 1 · What the tables are for — this decides where the effort goes

`kb.apply_table` is **B1**, the rule-only baseline P7 measures ① against. B1 runs on **G1**, and
G1 is fixed by DEC-086 at 300 clusters: `unknown` 120 · `ssh_brute_force` 115 ·
`suspicious_login` 25 · `privilege_escalation` 40. So **three tables carry the whole B1 number**
— `ssh_brute_force`, `suspicious_login`, `privilege_escalation` — and they must be drafted from
the archive's own statistics, not from intuition. The other seven serve G2 (the lab, 22–24/09) and
the live pilot; draft them from the playbooks and from what the lab runbook expects to fire
(`docs/lab-scenarios.md` on `task/P6-T05`, §3 per category, "expected rule ids").

The `unknown` stratum has no table by design (DEC-057, route 4) — do not invent one.

## 2 · Evidence — every rule cites a number or a line

Run, once, and keep the output:

```bash
python3 scripts/measure_clusters.py --archive /home/user1/archive/alerts-2026-08-08_09-07.jsonl --routes
```

That is the 30-day fold (3,070 clusters, DEC-053) through the real resolver. For each of the three
G1 categories, derive from it or from the archive directly: the rule ids that land there and their
cluster counts; the `rule_level` distribution (which bands the clusters sit in); occurrence sizes
(the fold gives cluster sizes); how many clusters come from hosts that are `high` in
`conf/inventory.yaml` (`IA1803`, `wazuh.manager`) versus `medium`/unlisted. The archive is
`user1`-readable; the resolver is `backend/app/ingest/category.py` @ `main`.

Every rule in every table gets a comment line **above it**, in this exact shape, so the sitting can
audit it in one glance:

```yaml
  # evidence: rule 5710 ×63 clusters, all level 5, 61/63 on user1-IA1803 (medium); playbook ssh_brute_force.md:18
  - id: sbf-1
```

For the seven lab/pilot tables the evidence line cites the playbook line and the runbook's expected
rule id (`lab-scenarios.md:<line>`), and says `(no archive clusters — lab category)` where true.
**A rule without an evidence line is a defect.**

## 3 · Rules of the draft

- **3 to 6 rules per table**, ids matching `_RULE_ID_RE` with the skeleton's abbreviation, unique
  per file, in the order `apply_table` evaluates them (state that order in your report after
  reading the code — do not assume "first match wins").
- Conditions use only `_VOCAB` keys/values and `_INT_CONDITION_KEYS`. Nothing else parses.
- **The grid must stay consistent**: `check_consistency()` over the 2,520 points must return `[]`
  for every table. `test_kb_lookup.py` enforces it; run it after every file.
- `false_positive` is the only outcome that lets a cluster leave the queue without a human; the
  hard blocks (G8′: `asset_criticality: high`, unlisted asset, `identity_privileged: true`, IOC
  hits…) are enforced **before** the table by `ingest/autoclose.py`, but a table that says
  `false_positive` on a `high` asset is still wrong on its face — do not write one.
- The `privilege_escalation` header carries two content questions from DEC-055 — rule `5402`
  (*successful sudo*, level 3, **57 G1 clusters**) and rootcheck `510`/`521`. Answer both **as
  PROPOSALS** with the archive numbers (how many clusters, which hosts, which identities), and
  write the rule the proposal implies. The sitting decides; you do not.
- The four `Final-Project` categories dropped in P2-T03 (`rdp_brute_force`, `phishing`,
  `persistence`, `suspicious_execution` — `tasks/P2/P2-T03.report.md:61–70`): count what the
  archive holds for each (rule ids, clusters) and propose keep-dropped or add, **as a PROPOSAL**.
  R5 binds: no category without a playbook, and a new playbook is not yours to write.
- **Never** fill `reviewed_by` / `reviewed_at`. **Never** edit `lookup.py`, the playbooks, the
  tests, or anything under `backend/`. No LLM calls. No commits to `main`.

## 4 · Deliverables

On a branch `kb/decision-tables-draft` cut from `main`, one commit per table plus one for the
sheet:

1. The ten `kb/decision_tables/*.yaml`, drafted per §2–§3, `reviewed_by: null` intact.
2. **`docs/plan/kb-review-sheet-2026-09-19.md`** — the document the 90-minute sitting works from:
   one section per table (rules, evidence, the question you could not settle, a `[ ] signed`
   line), then the three PROPOSALS (5402, 510/521, the four dropped categories), then the two
   playbook lines P3-T12 owns, then the exact command that turns a signature into the file
   (`reviewed_by: "<name>"`, `reviewed_at: "<ISO date>"`) and the test that proves it.
3. `docs/plan/kb-draft-report-2026-09-19.md` — what you ran, what each number came from, what
   you could not determine, in that order.

## 5 · Acceptance — every line is a command you run and paste

1. `python3 -m pytest -c backend/pyproject.toml backend/tests/test_kb_lookup.py -rs` → passes,
   `skipped` absent — the ten tables are consistent on the grid.
2. `grep -c "reviewed_by: null" kb/decision_tables/*.yaml` → **10 lines, each `:1`** — you signed
   nothing.
3. `for f in kb/decision_tables/*.yaml; do printf "%s %s\n" "$f" "$(grep -c '^  - id:' "$f")"; done`
   → every count in **3..6**.
4. `for f in kb/decision_tables/*.yaml; do printf "%s %s/%s\n" "$f" "$(grep -c '# evidence:' "$f")" "$(grep -c '^  - id:' "$f")"; done`
   → the two numbers **equal** on every line — one evidence line per rule.
5. `python3 -c "import sys; sys.path.insert(0,'backend'); from app.kb.lookup import get_decision_table, check_consistency; import pathlib; [print(p.stem, len(get_decision_table(p.stem).rules), check_consistency(get_decision_table(p.stem))) for p in sorted(pathlib.Path('kb/decision_tables').glob('*.yaml'))]"`
   → ten lines, each ending in `[]`.
6. **Failing case (DEC-025):** copy one table to `/tmp`, add a rule that contradicts an existing
   one on a shared grid point, run `check_consistency` on it → **non-empty**; paste it. A checker
   that cannot go red proves nothing.
7. `make lint` → exit 0.
8. `git diff main...kb/decision-tables-draft --stat` → only `kb/decision_tables/*.yaml` and the
   two `docs/plan/kb-*.md` files.

## 6 · What this changes in the record — for the Director, not for you

`01-plan.md:77` says the tables' content is *"authored by Owner + advisor"*. The Owner has chosen to
have them **drafted** by an agent and **reviewed, amended and signed** by the two humans; the
sitting is the act of authorship. That is a deviation to record as a DEC, and one sentence in
`docs/limitations.md` beside *author-as-labeler* and *author-written detection* (DEC-056
amendment 3): *"decision tables drafted by an agent from archive statistics; reviewed, amended and
signed by the Owner and the advisor on <date>."* Until `reviewed_by` is non-null, the gate treats
every table as absent (`decision_table_unreviewed:<category>`), so nothing you write reaches ①
before a human signs it.
