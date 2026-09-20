# KB decision-table signing checklist (sheet §15)

Run every command below **from the primary checkout** (`/project/project/AI_Support_SOC_1_2`, branch `main`) — never from an agent worktree. This is the Owner's / advisor's procedure, not an agent's: nothing in this file has been run against the real `kb/decision_tables/*.yaml` files, only against a scratch copy (§5 below proves the command is right).

The ten categories, in `kb/decision_tables/`:
`c2_beacon · data_exfiltration · malware · policy_violation · privilege_escalation · ransomware · recon · ssh_brute_force · suspicious_login · web_attack`

## 1 · Sign one table

Replace `<category>` with one of the ten names above. The names and date are fixed for this sitting; only `<category>` changes per run:

```bash
sed -i 's/^reviewed_by: null$/reviewed_by: "Nguyễn Chí Khanh + Mai Nam Nguyên"/; s/^reviewed_at: null$/reviewed_at: "2026-09-DD"/' kb/decision_tables/<category>.yaml
```

`2026-09-DD` is a literal placeholder — replace `DD` with the actual day the sitting lands (22 / 23 / 24 / 25) before running this for real. Do not run this against a table the sitting did not actually agree on: an unsigned `null`/`null` pair is the correct, honest state for a table left open — see `open-questions.md`.

Once every table on the agenda has a real decision, sign all ten in one pass (same expression, looped):

```bash
for c in c2_beacon data_exfiltration malware policy_violation privilege_escalation ransomware recon ssh_brute_force suspicious_login web_attack; do
  sed -i 's/^reviewed_by: null$/reviewed_by: "Nguyễn Chí Khanh + Mai Nam Nguyên"/; s/^reviewed_at: null$/reviewed_at: "2026-09-DD"/' "kb/decision_tables/$c.yaml"
done
```

## 2 · Prove it — per table

```bash
python3 -c "import sys; sys.path.insert(0,'backend'); from app.kb.lookup import get_decision_table, check_consistency; t=get_decision_table('<category>'); print(t.reviewed_by, t.reviewed_at, t.reviewed, check_consistency(t))"
```

Expected: `Nguyễn Chí Khanh + Mai Nam Nguyên 2026-09-DD True []` — the trailing `[]` is `check_consistency`'s conflict list. Every draft is already grid-consistent (DEC-100's E1 measured `check_consistency` empty on all ten before this sitting), so signing must not change that. A non-empty list here means an amendment made during the sitting broke disjointness — fix the `if:` conditions and re-run this before signing, not after.

## 3 · Test suite and lint

```bash
make lint
python3 -m pytest -c backend/pyproject.toml backend/tests/test_kb_lookup.py -q
```

**Known, expected consequence — read before running this.** `backend/tests/test_kb_lookup.py:418` (`test_skeletons_are_unreviewed`) asserts all ten tables are **unreviewed**. The moment the first table is signed, this test goes **red — by design** (sheet §15 point 1). This checklist does not fix that: `backend/` is out of scope for the sitting and for this checklist (hard limit). Per the sheet, a Coder card must replace that test with its inverse (`test_tables_are_reviewed`, or a per-table parametrisation) **in the same commit as the signatures**, or the suite stays red between the two. If that card is not ready the moment signing happens, the one red test is expected — do not edit the test yourself from here to make it pass.

## 4 · Commit

From the primary checkout, once all ten are signed (or as many as the sitting actually agreed — never commit a partial run silently; say in the commit message which categories, if any, are still `null`):

```bash
git add kb/decision_tables/c2_beacon.yaml kb/decision_tables/data_exfiltration.yaml kb/decision_tables/malware.yaml kb/decision_tables/policy_violation.yaml kb/decision_tables/privilege_escalation.yaml kb/decision_tables/ransomware.yaml kb/decision_tables/recon.yaml kb/decision_tables/ssh_brute_force.yaml kb/decision_tables/suspicious_login.yaml kb/decision_tables/web_attack.yaml
git commit -m "kb: sign ten decision tables at the Owner + advisor sitting (2026-09-DD)"
```

This checklist does not run `git commit`, `git add`, or the `sed`/pytest commands above for real against `kb/` — those are the Owner's actions to run after the sitting, per the hard limits this packet was written under.

## 5 · Dry run — proof the sed command is right (scratch copy only; real files never touched)

Done once already, on `ssh_brute_force.yaml`, entirely under this session's scratchpad. The real `kb/decision_tables/ssh_brute_force.yaml` was never edited — confirmed with `git status --short kb/decision_tables/ssh_brute_force.yaml` immediately after, which printed nothing.

**Before** (the two relevant lines, in context):

```yaml
category: ssh_brute_force
playbook: ssh_brute_force_v1
reviewed_by: null
reviewed_at: null
rules:
```

**Command run against the scratch copy** (identical to §1's expression, only the path differs):

```bash
sed -i 's/^reviewed_by: null$/reviewed_by: "Nguyễn Chí Khanh + Mai Nam Nguyên"/; s/^reviewed_at: null$/reviewed_at: "2026-09-DD"/' <scratch copy>/ssh_brute_force.yaml
```

**Diff, before → after** (only these two lines change — nothing else in the file moves):

```diff
--- ssh_brute_force.yaml.before
+++ ssh_brute_force.yaml
@@ -11,8 +11,8 @@
 category: ssh_brute_force
 playbook: ssh_brute_force_v1
-reviewed_by: null
-reviewed_at: null
+reviewed_by: "Nguyễn Chí Khanh + Mai Nam Nguyên"
+reviewed_at: "2026-09-DD"
 rules:
```

**Proof line (§2 above), run against the same scratch copy** (`get_decision_table('ssh_brute_force', root=<scratch dir>)`, with the playbook file mirrored alongside so the loader's playbook-name check passes):

- Before: `None None False []`
- After: `Nguyễn Chí Khanh + Mai Nam Nguyên 2026-09-DD True []`

Both lines match the sheet's own worked example exactly (`… → <names> 2026-09-DD True []`). The `sed` expression in §1 above is this same expression, unchanged, pointed at the real path — it is safe to run for real once a table's decision is actually settled.
