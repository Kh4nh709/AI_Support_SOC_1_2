# KB draft report · 14/11/2026 · DEC-216

## What I read

Run prompt §0–§9; lookup.py in full (vocabulary, integer keys, YAML actions, title/id validation, grid, apply_table and consistency); category.py module contract, PRIORITY and extended mapping; signed malware playbook/table; unsigned credential_access pair; DEC-034/053/058/145/208/213/215/216; 19/09 prompt §2–§3; category/R5, KB lookup and occurrence tests; lab-scenarios.md execution context.

§0: 1,631 trial alerts fall into the eight new categories without playbooks. These are firing counts, not verified attacks. Tier 6 preserves earlier resolutions. All sixteen new artifacts are drafts for the Owner/advisor. No network, database or LLM calls were made. Existing trial files and backup changes were left alone.

## What each rule came from

All evidence counts are the supplied 14/11 prompt §3, not a fresh measurement. Every YAML rule cites a concrete playbook line and its category's rule ids/counts. No new facts or FP rules; therefore the nine-occurrence-rule test pin is unchanged. Command/path/parent/task intent are unavailable to the categorical table facts, so even the low-level noise cannot safely become a structural FP rule.

apply_table returns the FIRST matching rule in file order. Bad IoC and critical-level rules can overlap with the same action; the review rule excludes both bad IoC and level ≥12. Severity follows DEC-053, not an independent axis. Unknown assets stay held (DEC-058); privileged identities are treated as exposed in every playbook. SOAR supplies context; skipped IoC is not benign.

- `impact`: 41 alerts: 110229 ×20 (level 3), 112524 ×15 (5), 751 ×2 (5), 597 ×2 (5), 60778 ×2 (5). `imp-1` is the bad-IoC policy; `imp-2` is the mandatory DEC-053 critical policy (future coverage if no critical trial rule is listed); `imp-3` holds noncritical alerts without bad IoC for content review. See the three evidence lines in `impact.yaml` and §3–§5 of its playbook.
- `collection`: 15 alerts: 110903 ×13 (level 8), 91820 ×2 (4). `col-1` is the bad-IoC policy; `col-2` is the mandatory DEC-053 critical policy (future coverage if no critical trial rule is listed); `col-3` holds noncritical alerts without bad IoC for content review. See the three evidence lines in `collection.yaml` and §3–§5 of its playbook.
- `lateral_movement`: 17 alerts: 92217 ×10 (level 6), 110814 ×3 (8), 110243 ×2 (8), 92650 ×2 (12). `lat-1` is the bad-IoC policy; `lat-2` is the mandatory DEC-053 critical policy (future coverage if no critical trial rule is listed); `lat-3` holds noncritical alerts without bad IoC for content review. See the three evidence lines in `lateral_movement.yaml` and §3–§5 of its playbook.
- `persistence`: 1,119 alerts: 112438 ×496 (level 5), 112533 ×201 (5), 92154 ×124 (4), 111810 ×56 (5), 111828 ×56 (12), 112430 ×50 (5), 110798 ×41 (8), 110437 ×22 (12); 11 other rules ×73, unspecified. `per-1` is the bad-IoC policy; `per-2` is the mandatory DEC-053 critical policy (future coverage if no critical trial rule is listed); `per-3` holds noncritical alerts without bad IoC for content review. See the three evidence lines in `persistence.yaml` and §3–§5 of its playbook.
- `defense_evasion`: 370 alerts: 110665 ×152 (level 8), 112519 ×50 (8), 110753 ×49 (3), 112466 ×34 (5), 110810 ×25 (8), 110915 ×22 (8), 92021 ×11 (3), 112520 ×6 (8); 6 other rules ×21, unspecified. `dfe-1` is the bad-IoC policy; `dfe-2` is the mandatory DEC-053 critical policy (future coverage if no critical trial rule is listed); `dfe-3` holds noncritical alerts without bad IoC for content review. See the three evidence lines in `defense_evasion.yaml` and §3–§5 of its playbook.
- `execution`: 0 alerts (no trial alert — ATT&CK only); lab-scenarios.md:476-527 describes malware execution, not an execution-labelled measurement. `exe-1` is the bad-IoC policy; `exe-2` is the mandatory DEC-053 critical policy (future coverage if no critical trial rule is listed); `exe-3` holds noncritical alerts without bad IoC for content review. See the three evidence lines in `execution.yaml` and §3–§5 of its playbook.
- `initial_access`: 19 alerts: 110464 ×19 (level 5). `ina-1` is the bad-IoC policy; `ina-2` is the mandatory DEC-053 critical policy (future coverage if no critical trial rule is listed); `ina-3` holds noncritical alerts without bad IoC for content review. See the three evidence lines in `initial_access.yaml` and §3–§5 of its playbook.
- `resource_development`: 50 alerts: 112431 ×33 (level 5), 110256 ×17 (3). `rsd-1` is the bad-IoC policy; `rsd-2` is the mandatory DEC-053 critical policy (future coverage if no critical trial rule is listed); `rsd-3` holds noncritical alerts without bad IoC for content review. See the three evidence lines in `resource_development.yaml` and §3–§5 of its playbook.

## What I could not determine

No analyst verdicts, gold examples, FP rates or effectiveness estimates are available for these categories. Execution has zero trial alerts; the existing lab execution chain is filed under malware and is not a measurement of this category. The 11 persistence and 6 defense_evasion rules in aggregate have no supplied ids/descriptions. We cannot assert their individual behavior. Policy escalation at level 12 and on bad IoC is implemented, not empirically validated. Unknown context remains unknown; no occurrence count is guessed.

No table is signed. The gate still treats each as absent (`decision_table_unreviewed:<category>`; step 4 `table_unreviewed`). Playbook availability fixes R5, not signing, model access to rule ids, auto-closure, deployment, or old-alert recategorization.

## Acceptance transcript

Interpreter: `PY=/project/project/AI_Support_SOC_1_2/.venv/bin/python` (this worktree has no local `.venv`). Branch created from `director/trial-category-v35`; Git metadata required sandbox approval because it lives outside this workspace. Eight category commits plus one sheet/report commit; no push.

### 1 · Before / after

```bash
$PY -m pytest -c backend/pyproject.toml -m "not db" backend/tests/test_category.py backend/tests/test_category_windows.py backend/tests/test_kb_lookup.py backend/tests/test_soar_occurrence.py backend/tests/test_rag_tags.py backend/tests/test_builder.py -q
```

Before (exit 1), exact failing-test summary:

```text
FAILED backend/tests/test_category.py::test_r5_every_mapped_value_has_a_real_playbook
FAILED backend/tests/test_category.py::test_priority_table_is_covered_by_playbooks_plus_unknown
FAILED backend/tests/test_category.py::test_ten_playbooks_exist_on_disk_matching_r5s_premise
FAILED backend/tests/test_kb_lookup.py::test_every_category_has_one_playbook_and_one_table
FAILED backend/tests/test_kb_lookup.py::test_skeletons_are_consistent - Attri...
FAILED backend/tests/test_kb_lookup.py::test_largest_playbook_under_3000_tokens
```

After (exit 0, 369 test dots; configured quiet output omits numerical summary):

```text
........................................................................ [ 19%]
........................................................................ [ 39%]
........................................................................ [ 58%]
........................................................................ [ 78%]
........................................................................ [ 97%]
.........                                                                [100%]
```

### 2–4 · Unsigned, evidence coverage and consistency

```bash
grep -c "reviewed_by: null" kb/decision_tables/{impact,collection,lateral_movement,persistence,defense_evasion,execution,initial_access,resource_development}.yaml
for f in kb/decision_tables/{impact,collection,lateral_movement,persistence,defense_evasion,execution,initial_access,resource_development}.yaml; do printf "%s %s/%s\n" "$f" "$(grep -c '# evidence:' "$f")" "$(grep -c '^  - id:' "$f")"; done
$PY -c "import sys; sys.path.insert(0,'backend'); from app.kb.lookup import get_decision_table, check_consistency; [print(c, len(get_decision_table(c).rules), check_consistency(get_decision_table(c))) for c in ('impact','collection','lateral_movement','persistence','defense_evasion','execution','initial_access','resource_development')]"
```

```text
kb/decision_tables/impact.yaml:1
kb/decision_tables/collection.yaml:1
kb/decision_tables/lateral_movement.yaml:1
kb/decision_tables/persistence.yaml:1
kb/decision_tables/defense_evasion.yaml:1
kb/decision_tables/execution.yaml:1
kb/decision_tables/initial_access.yaml:1
kb/decision_tables/resource_development.yaml:1
kb/decision_tables/impact.yaml 3/3
kb/decision_tables/collection.yaml 3/3
kb/decision_tables/lateral_movement.yaml 3/3
kb/decision_tables/persistence.yaml 3/3
kb/decision_tables/defense_evasion.yaml 3/3
kb/decision_tables/execution.yaml 3/3
kb/decision_tables/initial_access.yaml 3/3
kb/decision_tables/resource_development.yaml 3/3
impact 3 []
collection 3 []
lateral_movement 3 []
persistence 3 []
defense_evasion 3 []
execution 3 []
initial_access 3 []
resource_development 3 []
```

### 5 · Red control (DEC-025)

Copied impact playbook/table to a temporary scratch KB and appended imp-99 with `ioc_reputation: [malicious]`, `then: needs_review`; loaded that scratch table and ran check_consistency. Reproduce:

```python
import sys, tempfile, shutil
from pathlib import Path
sys.path.insert(0, 'backend')
from app.kb.lookup import get_decision_table, check_consistency
root = Path(tempfile.mkdtemp(dir='/tmp'))
for folder, ext in [('playbooks', 'md'), ('decision_tables', 'yaml')]:
    (root / folder).mkdir()
    shutil.copyfile(f'kb/{folder}/impact.{ext}', root / folder / f'impact.{ext}')
with (root / 'decision_tables/impact.yaml').open('a') as f:
    f.write('  - id: imp-99\n    if: {ioc_reputation: [malicious]}\n    then: needs_review\n')
problems = check_consistency(get_decision_table('impact', root=root))
assert problems
print(len(problems), problems[0])
```

Executed `$PY /tmp/kb-red.py`, exit 0:

```text
Scratch copied table; appended imp-99 malicious -> needs_review
contradictions: 672
imp-1 (true_positive) and imp-99 (needs_review) both hold at {'severity': 'low', 'rule_level': 0, 'ioc_reputation': 'malicious', 'asset_criticality': 'high', 'identity_privileged': 'true', 'occurrence_count': 1}
```

### 6 · Lint

`make lint PY=$PY` → exit 0 (outside sandbox after two sandbox Black stalls; both default and single-worker retries stalled):

```text
/project/project/AI_Support_SOC_1_2/.venv/bin/python scripts/gen_env_example.py --check
gen_env_example: .env.example matches §6.3 · 81 keys
/project/project/AI_Support_SOC_1_2/.venv/bin/python docs/Schema/build_schema.py --check
schema.sql khớp migrations · 2284 dòng
/project/project/AI_Support_SOC_1_2/.venv/bin/python scripts/check_output_schemas.py --check
output_schemas.json == context pack §6.2
/project/project/AI_Support_SOC_1_2/.venv/bin/python -m ruff check --config backend/pyproject.toml backend eval
All checks passed!
/project/project/AI_Support_SOC_1_2/.venv/bin/python -m black --check --config backend/pyproject.toml backend eval
All done! ✨ 🍰 ✨
335 files would be left unchanged.
```

### 7 · Scope

`git diff director/trial-category-v35...kb/v35-playbooks --stat`:

```text
 docs/plan/kb-draft-report-2026-11-14.md      | 175 +++++++++++++++++++++++++++
 docs/plan/kb-review-sheet-2026-11-14.md      | 156 ++++++++++++++++++++++++
 kb/decision_tables/collection.yaml           |  27 +++++
 kb/decision_tables/defense_evasion.yaml      |  27 +++++
 kb/decision_tables/execution.yaml            |  27 +++++
 kb/decision_tables/impact.yaml               |  27 +++++
 kb/decision_tables/initial_access.yaml       |  27 +++++
 kb/decision_tables/lateral_movement.yaml     |  27 +++++
 kb/decision_tables/persistence.yaml          |  27 +++++
 kb/decision_tables/resource_development.yaml |  27 +++++
 kb/playbooks/collection.md                   |  45 +++++++
 kb/playbooks/defense_evasion.md              |  45 +++++++
 kb/playbooks/execution.md                    |  45 +++++++
 kb/playbooks/impact.md                       |  45 +++++++
 kb/playbooks/initial_access.md               |  45 +++++++
 kb/playbooks/lateral_movement.md             |  45 +++++++
 kb/playbooks/persistence.md                  |  45 +++++++
 kb/playbooks/resource_development.md         |  45 +++++++
 18 files changed, 907 insertions(+)
```

### 8 · Address/account scan

```bash
grep -rnE "([0-9]{1,3}\.){3}[0-9]{1,3}|@[a-z0-9-]+\." kb/playbooks/{impact,collection,lateral_movement,persistence,defense_evasion,execution,initial_access,resource_development}.md
```

No output; exit 1 (grep found no match). `git diff --check` also produced no output.
