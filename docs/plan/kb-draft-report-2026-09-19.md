# KB Drafter report — ten decision tables drafted from the archive, 19/09/2026

Card-free contract: `docs/plan/prompts/kb-drafter-run-2026-09-19.md`. Branch `kb/decision-tables-draft`,
cut from `main` @ `6ffbecc`, worktree `../AI_Support_SOC_1_2-kb-draft`. Deliverables: the ten
`kb/decision_tables/*.yaml` (one commit each), `docs/plan/kb-review-sheet-2026-09-19.md` (the sitting's
document) and this report. `reviewed_by` / `reviewed_at` are `null` in all ten — I signed nothing.
No file under `backend/`, no playbook, no test was edited; no LLM call was made; nothing touched `main`.

## 1 · What I ran, in order

1. **§0 reading**, in the prompt's order: `backend/app/kb/lookup.py` (whole file), the ten skeletons, the
   ten playbooks (`cat -n`, so lines can be cited), architecture §3.10 (`docs/kien-truc-v3-14-ngay.html:619-635`
   through a tag-stripping `sed`), DEC-034/052/053/055/058/086 (`awk` over `docs/plan/DECISIONS.md`),
   `tasks/P3/P3-T06.report.md` + `.prompt.md` design notes 2–5, `backend/tests/test_kb_lookup.py`. Then the
   material §1–§3 point at: `docs/lab-scenarios.md` (§3 per category, §7), `conf/local_rules.xml`
   (100301 level 12 · 100302 level 10 · 100303 level 12), `docs/wazuh-manager-changes.md:278` (52502 level 8),
   `tasks/P2/P2-T03.report.md:61-70`, the real `conf/inventory.yaml` / `conf/identities.yaml` / `conf/iocs.csv`
   in the primary checkout (git-ignored; the worktree has only the `.example` files),
   `backend/app/ingest/autoclose.py:244-267` (G8′ order), `backend/app/security/gate.py:138-165` (step 4),
   `backend/app/enrichment/lookups.py:56-104` (how `identity_privileged` and `ioc_reputation` are derived),
   `backend/app/ingest/wazuh_parser.py:180` (`alert_user = dstuser ∥ srcuser`), `prompts/P7.md:17,31`
   (B1: `needs_review` when no rule matches; the strict three-class metric).

2. **The fold, once** (§2):
   `python3 scripts/measure_clusters.py --archive /home/user1/archive/alerts-2026-08-08_09-07.jsonl --routes`
   → kept at `scratchpad/measure_clusters_routes.txt`. Head of the output:
   ```
   alerts 92,030 · 2026-08-08 16:26:48.648000+07:00 → 2026-09-07 10:05:04.998000+07:00
   clusters, whole archive: 3,070 (denominator for every share below)
   severity by cluster, spec band (phase-1:148): critical 25, high 150, medium 1,695, low 1,200 — crit+high 175
   category by cluster: unknown 1,820, ssh_brute_force 968, suspicious_login 174, privilege_escalation 108
   playbook categories with zero live clusters: 7 of 10 — ransomware, malware, c2_beacon, data_exfiltration, web_attack, recon, policy_violation
   loopback ssh_brute_force: 662 alerts in 67 clusters
   clusters by agent: IA1803 1,986, user1-IA1803 1,061, DESKTOP-MIRSO17 23
   ```
   Every figure matches DEC-053/DEC-055 as recorded.

3. **Per-category statistics** (`scratchpad/kb_stats.py` → `kb_stats_out.txt`, `g1_category_facts.json`):
   re-loads the archive with two extra fields the measure script drops (`rule.description`,
   `data.dstuser ∥ data.srcuser`), re-uses `measure_clusters.fold()` (same predicates, same resolver; asserts
   3,070), and derives the four categorical facts per cluster head **the way the pipeline does**:
   `asset_criticality` from the real inventory (`IA1803` high · `user1-IA1803` medium · `wazuh.manager` high ·
   `HR-computer` medium · anything else `unknown`); `identity_privileged` from the real identities file
   (`user1` → `"false"`, `root` → `"true"`, else `"unknown"`); `ioc_reputation` = `not_found` if any of
   srcip/dstip is non-empty and not private/loopback, else `skipped` (`lookups.py:87-100`, IoC table empty);
   `severity` via `lookup.severity_for(rule_level)`; `occurrence_count` = cluster size. Prints, per category:
   rule id × level × description → clusters/alerts, agents, identities, IoC, occurrence bins; the
   severity × asset grid; the DEC-053 pool.

4. **Applying each draft to its clusters** (`scratchpad/apply_eval.py`): loads the real table through
   `get_decision_table`, runs `check_consistency`, then `apply_table` on every cluster's facts and reports
   the count per `(rule id, action)` with rule-id / agent / identity / severity breakdown, for all clusters
   and for the DEC-053 pool. **Every archive number in an evidence line was read off this output, not
   estimated** — two numbers I had written from the earlier summary were wrong on first measurement
   (`sul-4`'s host split, `sul-5`'s reported count) and were corrected before the files were committed.

5. **The dropped categories** (`scratchpad/dropped_cats.py` → `dropped_cats_out.txt`): for each of the four
   `Final-Project` categories, the fold's clusters whose head carries a MITRE id (exact or parent), a
   `rule.groups` key or the port that used to reach it (`P2-T03.report.md:61-70`).

6. **Acceptance §5**, items 1–8, pasted in §4 below.

## 2 · Where each number came from

**Contract facts** (`lookup.py`): `apply_table` = first match in **file order** (`:138-145`);
`check_consistency` = any two rules with different actions both holding at a grid point (`:157-172`) — so
different-action rules must be disjoint on the grid and order only picks the reported id among same-action
overlaps; grid = `rule_level ∈ {0,3,5,8,12,15}` × ioc 5 × asset 4 × identity 3 × `occurrence ∈
{1,10,49,50,100,999,1000}` = 2,520; `severity` derived, never free. B1 answers `needs_review` on no match
(`prompts/P7.md:17`), so tables need not cover the grid; the explicit `needs_review` rules in the three G1
tables exist so the sitting sees the groups they decide.

**Test constraint** (`test_kb_lookup.py:387-398`): at `{critical, 12, skipped, unknown, "unknown", 1}` the
first matching `ssh_brute_force` rule must be `sbf-3` → `escalate`, and `sbf-1` must not hold. Kept:
`sbf-3` is `rule_level_gte: 12`, nothing before it matches that point.

**G1 composition** (DEC-086, sampled from DEC-084's 3,051-cluster fold minus 67 loopback = 2,984):
`ssh_brute_force` 115 = 1 crit · 11 high · 95 med · 8 low; `suspicious_login` 25 all low;
`privilege_escalation` 40 = 0 · 31 · 1 · 8. Cross-checked against my 3,070-cluster fold's DEC-053 pool:
`ssh_brute_force` 901 = 1 crit · 11 high · 817 med · 72 low (crit+high **12** ✓), `suspicious_login` 174 all
low ✓, `privilege_escalation` 108 = 31 high · 11 med · 66 low (high **31** ✓). The two folds differ by 19
clusters in total (DEC-084 records 0.62 %); the crit+high counts the tables lean on agree exactly.

**Per-table numbers** — all from `apply_eval.py` (ALL clusters / DEC-053 pool):

| table | rule → action | ALL | pool | what it is |
|---|---|---|---|---|
| `ssh_brute_force` | `sbf-1` false_positive | 0 | 0 | every user1-targeted failure (25) is `skipped` (PAM no-IP, LAN 172.25.25.x) or on `IA1803` |
| | `sbf-3` escalate | 11 | 1 | 100101 ×7 (lvl 14), 40112 ×4 (lvl 12) |
| | `sbf-4` escalate | 39 | 11 | 5551 ×12, 5763 ×12, 5712 ×11, 2502 ×4 — all level 10, all `user1-IA1803` |
| | `sbf-5` needs_review | 543 | 514 | identity unknown: 5710 ×368, 2501 ×66, 5762 ×35, 5740 ×33, 5503 ×31, 5760 ×10 |
| | `sbf-6` needs_review | 350 | 350 | identity true (root): 5760 ×322, 5503 ×27, 5762 ×1 |
| | (none) | 25 | 25 | 5503 ×18, 5760 ×4, 5762 ×3 |
| `suspicious_login` | `sul-1` false_positive | 48 | 48 | user1 on `user1-IA1803`: 5715 ×30 (16 not_found, 14 skipped), 5501 ×18 |
| | `sul-4` needs_review | 32 | 32 | 5501 for root: `IA1803` 22 / `user1-IA1803` 10 |
| | `sul-5` needs_review | 93 | 93 | on `IA1803` (115 total; 22 root reported by `sul-4` first) |
| | (none) | 1 | 1 | 5501, service account, `user1-IA1803` |
| `privilege_escalation` | `pre-1` false_positive | 0 | 0 | no cluster has identity "false" |
| | `pre-4` escalate | 31 | 31 | 100205 ×18, 521 ×11, 5404 ×1, 513 ×1 |
| | `pre-5` needs_review | 63 | 63 | 5402 ×57, 5403 ×5, 5401 ×1 — all root |
| | (none) | 14 | 14 | 510 ×10, 5407 ×4 |

**Rule levels cited in the seven lab/pilot tables:** `100301` 12, `100302` 10, `100303` 12
(`conf/local_rules.xml:80,117,164`); `52502` 8 (`docs/wazuh-manager-changes.md:278`); `100112` 12
(DEC-055: "all 8 … critical"). Expected labels and rule ids per scenario: `docs/lab-scenarios.md` lines
246, 325-327, 361, 388-397, 449-461, 510-512, 565-567, 631-633, 695-697; the two absent scenarios
`:823-827`.

**Dropped categories** (`dropped_cats_out.txt`): `rdp_brute_force` 0 · `phishing` 0 · `persistence` 25
clusters / 33 alerts (5901 ×8 lvl 8, 5902 ×8 lvl 8, 5903 ×3 lvl 3, 5904 ×1 lvl 8, 100204 ×3 lvl 12, 100200
×1 lvl 10, 61138 ×1 lvl 5; 21 crit+high) · `suspicious_execution` 44 clusters / 181 alerts (92601 ×44, level
6, `T1059.006`, all `IA1803`).

**DEC-055 material:** `5402` ×57 / 704 alerts, `IA1803` 38 / `user1-IA1803` 19, `dstuser = root` on all
(→ identity "true"), `srcuser` user1 on 42 clusters (332 alerts) / root on 14 (371) / art on 1; `510` ×10
(lvl 7), `521` ×11 (lvl 11), all `IA1803`, identity unknown, `skipped`, occurrence 1–3; `513` "Windows malware
detected" ×1 (lvl 9, `DESKTOP-MIRSO17`) also reaches `privilege_escalation` via `rootcheck`.

**Design choices that are not numbers, and where they come from:**
- Evaluation order stated in every header: first match in file order; different-action rules disjoint.
- `false_positive` rules never admit asset `high`/`unknown`, identity `"true"`, IoC bad, or severity
  critical (G8′ + gate step 4). Checked by `apply_eval.py` on the three G1 tables and by reading the other
  seven.
- `skipped` in an FP rule: **out** where the playbook has a *lookup-missing → not harmless* clause
  (`ssh_brute_force.md:36`, `c2_beacon.md:37`, `web_attack.md:37`, `recon.md:38`) or makes the destination the
  question (`data_exfiltration.md:8,:15`); **in** for `suspicious_login` (`:23`, local origin blessed) and
  `privilege_escalation` (108/108 IP-less, no such clause). Each deviation from the §3.10 pattern is
  named in the evidence line and in the sheet.
- identity `"unknown"` in an FP rule only for user-less categories (`recon`, `web_attack`), where `"false"`
  alone is unreachable; the gate permits it (only `"true"` is blocked).
- `ransomware` has no FP rule (`ransomware.md:25`).
- High band (8 ≤ level < 12) → escalate in `ssh_brute_force` (runbook :246 + playbook :27),
  `privilege_escalation` (:28, :37; DEC-053/086), `ransomware` (:3), `data_exfiltration` (100302 is level 10),
  `malware` (52502 is level 8), `recon` (threshold rules); restricted to asset high in `web_attack` (:7 vs
  :35) and to asset high / identity true in `policy_violation` (:36, :37); absent in `suspicious_login`
  (no rule at that band; 40112 resolves elsewhere) and `c2_beacon` (only a level-12 rule exists).

## 3 · What I could not determine

1. **The stock levels of `5706`, `5731`, `40601`** (the `recon` scenario's expected rules). Not recorded
   anywhere in the repo, 0 archive hits, and the manager's ruleset is not readable from this session
   (`docker` socket: permission denied). `rec-4` assumes `5731`/`40601` sit in the high band as Wazuh
   frequency rules do; the sheet (§8 Q2) asks the sitting to confirm from the lab's per-window `by_rule`
   breakdown before signing.
2. **Whether the G1 replay's stored facts will carry the inventory.** `INBOX.md:383` records that on the
   live application database the inventory had never been loaded, so `asset_context.criticality` was
   `unknown` on 383/383 stored heads and B1 could not return `false_positive` on any of them. P7 runs B1
   "on DB facts"; if G1's facts are materialised without `inventory.load()`, every FP rule in these tables
   is dead on G1 regardless of content. Outside this contract; named for the Director.
3. **Gold-label semantics for `false_positive` vs `benign`.** `prompts/P7.md:18` scores three classes; the
   tables' `false_positive` follows the playbooks' "Nghiêng về FALSE POSITIVE" headings, which for a
   legitimate login (`sul-1`, 48 clusters) may be labelled `benign` by the labellers. A table cannot
   express `benign`; noted in sheet §2 Q4, not resolvable here.
4. **The two folds.** DEC-086 samples from DEC-084's 3,051-cluster fold (`eval/dedup_verify.py`); the prompt
   told me to run `scripts/measure_clusters.py` (3,070). The crit+high counts agree exactly (12 / 0 / 31);
   the medium/low totals differ by a few clusters, so the "X of 968" figures are the 3,070-fold's and the
   sample will be drawn from the other. Nothing in the tables depends on the difference.
5. **`sbf-1` catches nothing in G1** — a finding, not an indeterminacy, but the one the sitting most needs
   to know: with the architecture's own example rule unchanged, B1 never says `false_positive` on
   `ssh_brute_force`. The sheet quantifies the one-token variant (admit `skipped`: 14 clusters).
6. **How `100205` should be treated** (18 of `privilege_escalation`'s 31 high). An archive-era local rule
   (gone since 17/08) firing on the desktop login manager's setuid; playbook :22 reads it as FP, :28 as real.
   It differs from the rootkit rule `521` in exactly one fact, level 10 vs 11. The table escalates the band;
   the sheet (§3 Q2) offers the `rule_level_gte: 11` narrowing. Which is right is the sitting's call.
7. **Consistency vs. amendments at the sitting.** Every draft is disjoint by construction; the sheet marks
   which flips stay consistent (`sbf-6`, `sul-4`+`sul-5` together) — but any *new* condition the sitting adds
   must be re-run through acceptance 5 before signing. The command is in sheet §15.

## 4 · The verification pass, and what it corrected

Before writing the sheet I ran an adversarial pass over the ten drafts: one independent reviewer per table,
told to refute every cited playbook line, every archive number (recomputed from `g1_category_facts.json`
through `apply_table`), hard-block face validity and every runbook citation. Six reviewers finished
(`ssh_brute_force`, `suspicious_login`, `privilege_escalation`, `ransomware`, `data_exfiltration`,
`c2_beacon`); four (`malware`, `recon`, `web_attack`, `policy_violation`) and the cross-table check hit the
account's weekly usage limit and were done by hand instead (every cited line printed beside its claim;
header lines 1–3 and the four fields diffed against `main` for all ten; every `Sheet §N Qm` pointer resolved).
Every archive number in the three G1 tables reproduced. What did not, and was fixed before commit:

- **`sul-4`** said the 32 `root` sessions have occurrence 1–217; recomputed **1–49** (the 217 is a `user1`
  cluster on `IA1803`, which lands on `sul-5`). Blocking; fixed in the YAML and the sheet.
- **`pre-4`** said `100205` is separable from `521` "only by rule id"; false — `100205` is level 10, `521` level
  11, so `rule_level_gte: 11` separates them. Fixed; the sheet's §3 Q2 now offers exactly that.
- **`pre-1`** attributed all 44 identity-unknown clusters to rootcheck/auditd; 5 are sudo by unlisted service
  accounts (`5407` ×4) and `513`. Fixed. The 14 no-match clusters (`510` ×10, `5407` ×4) were mentioned
  nowhere; now in the header.
- **`sbf-5`** listed `oracle` among rule `5710`'s targets; `oracle` is rule `5712` (level 10 → `sbf-4`). Fixed.
- **`sbf-4`** cited the runbook's expected label as if the lab burst reached the rule; the burst's per-attempt
  rules (`5503`/`5760`/`5710`, level 5, loopback) match no rule — only the frequency rule `5712`/`5763` does.
  Fixed in the evidence line and sheet §1 Q4.
- **`sbf-2`** claimed to "serve G2"; the lab's srcip is loopback (`skipped`) and the runbook seeds no indicator.
  Fixed: pilot only.
- **`c2_beacon`** header cited "runbook §7" for the setup-not-periodicity statement; the sources are
  `lab-scenarios.md:659-661` and `conf/local_rules.xml:151-159`. **`c2b-3`** cited periodicity/process lines
  that one execve cannot carry; now cites the rule docstring and its authored level.
- **`dex-2`** cited destination-policy lines for an IoC rule; **`dex-4`** cited DNS/ICMP and asset lines that do not
  describe a curl upload — and the reviewer surfaced the rule's own docstring
  (`conf/local_rules.xml:113-114`: *a single upload is a lead an analyst confirms, not a confirmed incident*),
  which argues against the runbook's `escalate`. Now sheet §5 Q2.
- **`ran-4`** cited :37 (asset-scoped) for an asset-blind rule; :37 is now sheet §4 Q3. `ran-3` quoted a
  truncated description; now verbatim.
- `prompts/P7.md:17` → `docs/plan/prompts/P7.md:17` in every header.
- The seven template FP rules now say what they are — the *structural precondition* for an FP verdict
  (architecture §4), not detectors of the playbooks' §3 branches, which are text ① reads.

Reviewer findings I read and did **not** act on beyond the sheet: the `needs_review`-vs-`escalate` readings of
`ssh_brute_force.md:35`, `suspicious_login.md:34/:35` and `privilege_escalation.md:28` — each is already a
numbered question for the sitting, which is where that decision belongs.

## 5 · Acceptance (§5) — commands run from the worktree root, outputs pasted

```
### 1
$ python3 -m pytest -c backend/pyproject.toml backend/tests/test_kb_lookup.py -rs
.............................                                            [100%]
29 passed in 1.29s

### 2
$ grep -c "reviewed_by: null" kb/decision_tables/*.yaml
kb/decision_tables/policy_violation.yaml:1
kb/decision_tables/malware.yaml:1
kb/decision_tables/ransomware.yaml:1
kb/decision_tables/recon.yaml:1
kb/decision_tables/c2_beacon.yaml:1
kb/decision_tables/data_exfiltration.yaml:1
kb/decision_tables/ssh_brute_force.yaml:1
kb/decision_tables/web_attack.yaml:1
kb/decision_tables/privilege_escalation.yaml:1
kb/decision_tables/suspicious_login.yaml:1

### 3
$ for f in kb/decision_tables/*.yaml; do printf "%s %s\n" "$f" "$(grep -c '^  - id:' "$f")"; done
kb/decision_tables/c2_beacon.yaml 4
kb/decision_tables/data_exfiltration.yaml 4
kb/decision_tables/malware.yaml 4
kb/decision_tables/policy_violation.yaml 5
kb/decision_tables/privilege_escalation.yaml 5
kb/decision_tables/ransomware.yaml 4
kb/decision_tables/recon.yaml 5
kb/decision_tables/ssh_brute_force.yaml 6
kb/decision_tables/suspicious_login.yaml 5
kb/decision_tables/web_attack.yaml 5

### 4
$ for f in kb/decision_tables/*.yaml; do printf "%s %s/%s\n" "$f" "$(grep -c '# evidence:' "$f")" "$(grep -c '^  - id:' "$f")"; done
kb/decision_tables/c2_beacon.yaml 4/4
kb/decision_tables/data_exfiltration.yaml 4/4
kb/decision_tables/malware.yaml 4/4
kb/decision_tables/policy_violation.yaml 5/5
kb/decision_tables/privilege_escalation.yaml 5/5
kb/decision_tables/ransomware.yaml 4/4
kb/decision_tables/recon.yaml 5/5
kb/decision_tables/ssh_brute_force.yaml 6/6
kb/decision_tables/suspicious_login.yaml 5/5
kb/decision_tables/web_attack.yaml 5/5

### 5
$ python3 -c "import sys; sys.path.insert(0,'backend'); from app.kb.lookup import get_decision_table, check_consistency; import pathlib; [print(p.stem, len(get_decision_table(p.stem).rules), check_consistency(get_decision_table(p.stem))) for p in sorted(pathlib.Path('kb/decision_tables').glob('*.yaml'))]"
c2_beacon 4 []
data_exfiltration 4 []
malware 4 []
policy_violation 5 []
privilege_escalation 5 []
ransomware 4 []
recon 5 []
ssh_brute_force 6 []
suspicious_login 5 []
web_attack 5 []

### 6 (DEC-025 red step)
$ mkdir -p /tmp/kbred/decision_tables /tmp/kbred/playbooks && cp kb/decision_tables/ssh_brute_force.yaml /tmp/kbred/decision_tables/ && cp kb/playbooks/ssh_brute_force.md /tmp/kbred/playbooks/
$ cat >> /tmp/kbred/decision_tables/ssh_brute_force.yaml <<EOF
  # evidence: DELIBERATE CONTRADICTION for acceptance 6 — false_positive on the high band, which sbf-4 escalates
  - id: sbf-9
    if: {severity: [high], asset_criticality: [medium], identity_privileged: ["false"]}
    then: false_positive
EOF
$ python3 -c "import sys, pathlib; sys.path.insert(0,'backend'); from app.kb.lookup import get_decision_table, check_consistency; p = check_consistency(get_decision_table('ssh_brute_force', root=pathlib.Path('/tmp/kbred'))); print(len(p)); print(p[0]); print(p[-1])"
49
sbf-2 (escalate) and sbf-9 (false_positive) both hold at {'severity': 'high', 'rule_level': 8, 'ioc_reputation': 'malicious', 'asset_criticality': 'medium', 'identity_privileged': 'false', 'occurrence_count': 1}
sbf-4 (escalate) and sbf-9 (false_positive) both hold at {'severity': 'high', 'rule_level': 8, 'ioc_reputation': 'skipped', 'asset_criticality': 'medium', 'identity_privileged': 'false', 'occurrence_count': 1000}

### 7
$ make lint; echo exit=$?
All checks passed!
python3 -m black --check --config backend/pyproject.toml backend eval
All done! ✨ 🍰 ✨
116 files would be left unchanged.
exit=0
```

### 8
`git diff main...kb/decision-tables-draft --stat` — pasted after the commits, in §6.

## 6 · Acceptance 8 and the commits

```
$ git diff main...kb/decision-tables-draft --stat
 docs/plan/kb-draft-report-2026-09-19.md      | 293 ++++++++++++++++++
 docs/plan/kb-review-sheet-2026-09-19.md      | 440 +++++++++++++++++++++++++++
 kb/decision_tables/c2_beacon.yaml            |  17 ++
 kb/decision_tables/data_exfiltration.yaml    |  17 ++
 kb/decision_tables/malware.yaml              |  17 ++
 kb/decision_tables/policy_violation.yaml     |  22 ++
 kb/decision_tables/privilege_escalation.yaml |  24 +-
 kb/decision_tables/ransomware.yaml           |  23 +-
 kb/decision_tables/recon.yaml                |  25 +-
 kb/decision_tables/ssh_brute_force.yaml      |  23 ++
 kb/decision_tables/suspicious_login.yaml     |  23 +-
 kb/decision_tables/web_attack.yaml           |  23 +-
 12 files changed, 940 insertions(+), 7 deletions(-)

$ git log --oneline main..kb/decision-tables-draft
a538432 kb draft: review sheet for the Owner + advisor sitting and the drafter's report
e49829e kb draft: policy_violation — 5 rules: no-signal category (DEC-057); high band escalates on asset high / identity true
ac2614a kb draft: web_attack — 5 rules: FP admits identity unknown, high band escalates on asset high only (:35 vs :7), skipped -> needs_review
9ec635e kb draft: recon — 5 rules: FP admits identity unknown (no user on scan alerts), threshold rules -> escalate, private-source scan -> needs_review
d1b202a kb draft: malware — 4 rules: §3.10 FP pattern, 52502 level 8 -> escalate (runbook :512)
8635719 kb draft: c2_beacon — 4 rules: §3.10 FP pattern, 100303 level 12 -> escalate, skipped -> explicit needs_review (playbook :37)
cb123d1 kb draft: data_exfiltration — 4 rules: §3.10 FP pattern, 100302 level 10 -> escalate (runbook :633)
04f1d9d kb draft: ransomware — 4 rules: no FP rule (playbook :25), 100301 level 12 -> escalate, high band -> escalate
c06e954 kb draft: privilege_escalation — 5 rules: high band -> escalate (31 cl), identity true -> needs_review (63 cl, DEC-055 rule 5402 via the facts)
352b118 kb draft: suspicious_login — 5 rules: sul-1 FP admits skipped (48 cl, user1 on the lab host), root and high-asset logins -> explicit needs_review
2500be2 kb draft: ssh_brute_force — 6 rules: §3.10 sbf-1/2/3 kept, high band -> escalate (39 cl), identity unknown/true -> explicit needs_review (543/350 cl)
```

Only `kb/decision_tables/*.yaml` and the two `docs/plan/kb-*.md` files; one commit per table, one for the sheet + report. Nothing on `main`; `backend/`, the playbooks and the tests untouched.
