# A1 · A5 — decision material, 2026-09-07

Prepared for the Owner by Fable (the Director's second half, on the Owner's order of 07/09). **Nothing here decides.** Every table is the output of a command named above it; every share quotes its denominator, and both sides of every ratio were counted the same way — clusters over clusters, alerts over alerts. The two Owner decisions this serves are A5 (the `unknown` taxonomy) and A1 (escalate scarcity) in `INVENTORY-2026-09-07.md`; both are due before Planner P6 runs (12/09).

## 0 · Every figure re-derived by command

`python3 scripts/measure_clusters.py --archive /home/user1/archive/alerts-2026-08-08_09-07.jsonl --withdrawn-band`

Fold: cluster key `(rule_id, srcip, dstip, agent_name)`, `DEDUP_IDLE_GAP_MINUTES=15` on `last_seen`, `MAX_CLUSTER_AGE_HOURS=4` on `first_seen`, `MAX_CLUSTER_SIZE=1000`, alerts in archive order with the alert's own timestamp as the clock (P2-tasks.md planning decision 9 — a pipeline replay measures the database clock, not the data). Category from `backend/app/ingest/category.py`'s `resolve()` on the cluster head — the merged resolver. Severity from `rule.level` per `docs/phase-1-tiep-nhan-chuan-hoa.md:148`.

| figure | as reported (where) | re-derived 07/09 | denominator |
|---|---|---|---|
| clusters, 30-day export | 3,070 (Owner; DEC-052, DEC-053) | **3,070** | 92,030 alerts, 08/08 16:26 → 07/09 10:05 |
| clusters at 4 / 7 / 14 days | 363 / 466 / 1,132 (Owner, DEC-053) | **363 / 466 / 1,132** — windows of exactly N × 24 h before the last alert (calendar-day windows give 340 / 449 / 1,116, so the convention is stated) | same |
| severity by cluster, spec band ≥ 12 / ≥ 8 / ≥ 5 | critical 25, high 150, medium 1,695, low 1,200 → 175 crit+high, 5.7 % (DEC-053) | **identical** | 3,070 |
| severity by cluster, the withdrawn band ≥ 12 / ≥ 9 / ≥ 7 | high 133, 158 crit+high (the Owner's first figure) | critical 25, high 133, medium 274, low 2,638 → **158** | 3,070 |
| `unknown` clusters | 1,812 = 59.0 % (A2) | **1,812** (26,921 alerts = 29.3 % of alerts) | 3,070 / 92,030 |
| playbook categories with zero live clusters | 6 of 10 (A3) | **`ransomware`, `malware`, `c2_beacon`, `data_exfiltration`, `recon`, `policy_violation`** | 10 playbooks |
| loopback `ssh_brute_force` | 662 alerts, 1.1 % (DEC-053) | **662 alerts in 67 clusters**; 662 / 60,906 `ssh_brute_force` alerts = 1.1 % | 60,906 alerts |
| vulnerability-detector | 12,217 alerts / 24 clusters (DEC-052) | **12,217 / 24** | 92,030 / 3,070 |
| DESKTOP-MIRSO17 | 23 clusters, 0.7 % (DEC-051 as corrected) | **23** | 3,070 |
| out-of-order lines in the archive | — | 909 lines arrive before an earlier timestamp; folding in file order and in timestamp order both give 3,070 | 92,030 |

The category × severity grid as the corpus stands (route 4 below) has 13 non-empty cells, 11 of them with ≥ 10 clusters. The 10-cluster cell threshold is the Owner's stated threshold; architecture §6 defines the stratification (`category × severity`, 300 clusters, floor 200) without a per-cell rule.

## 1 · A5 — the four routes, computed

**The number to read first:** `syscheck` (151 clusters, 6,033 alerts) and `vulnerability-detector` (24 clusters, 12,217 alerts) are **175 of the 1,812 `unknown` clusters — 9.7 % of the stratum, 5.7 % of G1**. The other 1,637 are the estate's own operating noise: `ossec` 454 (Wazuh's status rules — 591 log rotation, 502 server start), `systemd` 428 (rule 40704), `audit` 287 (auditd 80730/80710/80711), `dpkg` 131, `pam` 107, `sca` 45, `adduser` 20, `stats` 19, `windows` 12, other 134. Routes 1 and 2 as framed therefore move `unknown` from 59.0 % to 53.3 %, not to a number that changes what B1 means. Two variants are added so the Owner can see the ends of the range: **3b** (exclude every `unknown` cluster) and **1-wide** (a new category for every family with ≥ 20 clusters).

Also load-bearing: **86 of the 175 crit+high clusters are `unknown`** — auditd 47 (80710 ×34, 80711 ×9, 100204 ×3, 100200 ×1), adduser 17 (5901/5902/5904), sca 11 (19011/19014), vulnerability-detector 6 (23505/23506), Windows 5. Under routes 1 and 2 as framed only the 6 vulnerability-detector ones leave `unknown`; B1 keeps answering `needs_review` on the other 80.

`python3 scripts/measure_clusters.py --archive /home/user1/archive/alerts-2026-08-08_09-07.jsonl --routes`

Route 2's mapping is an assumption stated for the computation: both families → `policy_violation`, the only existing playbook whose premise ("someone did something forbidden, not necessarily an attack") comes near asset hygiene. B1-expressible = clusters whose category has a decision table; route 1 counts its new tables as authored. "Unknown in a proportional 300" = what a proportional allocation would put in the sample; a capped allocation is P6's choice.

| route | G1 clusters | unknown (share) | B1 can express a rule for | crit+high | crit+high B1-expressible | non-empty cells | cells ≥ 10 | unknown in a proportional 300 | new categories |
|---|---|---|---|---|---|---|---|---|---|
| 4 keep unknown, report it (as-is) | 3,070 | 1,812 (59.0 %) | 1,258 (41.0 %) | 175 (5.7 %) | 89 of 175 | 13 | 11 | 177 | 0: — |
| 1 extend (as framed): syscheck, vulnerability-detector -> new categories | 3,070 | 1,637 (53.3 %) | 1,433 (46.7 %) | 175 (5.7 %) | 95 of 175 | 18 | 13 | 160 | 2: file_integrity, vulnerability |
| 2 map onto existing: syscheck, vulnerability-detector -> policy_violation | 3,070 | 1,637 (53.3 %) | 1,433 (46.7 %) | 175 (5.7 %) | 95 of 175 | 17 | 13 | 160 | 0: — |
| 3a exclude syscheck + vulnerability-detector clusters from G1 | 2,895 | 1,637 (56.5 %) | 1,258 (43.5 %) | 169 (5.8 %) | 89 of 169 | 13 | 11 | 170 | 0: — |
| 3b exclude every unknown cluster from G1 | 1,258 | 0 (0.0 %) | 1,258 (100.0 %) | 89 (7.1 %) | 89 of 89 | 9 | 8 | 0 | 0: — |
| 1-wide extend: a new category per family >= 20 clusters | 3,070 | 153 (5.0 %) | 2,917 (95.0 %) | 175 (5.7 %) | 175 of 175 | 33 | 23 | 15 | 10: account_change, auth_session, compliance_check, file_integrity, package_change, service_event, system_audit, vulnerability, wazuh_internal, windows_event |

### 4 keep unknown, report it (as-is) — category × severity (clusters; denominator 3,070)

| category | critical | high | medium | low | total | share |
|---|---|---|---|---|---|---|
| unknown | 6 · | 80 | 838 | 888 | 1812 | 59.0 % |
| ssh_brute_force | 11 | 39 | 846 | 72 | 968 | 31.5 % |
| suspicious_login | 0 · | 0 · | 0 · | 174 | 174 | 5.7 % |
| privilege_escalation | 0 · | 31 | 11 | 66 | 108 | 3.5 % |
| web_attack | 8 · | 0 · | 0 · | 0 · | 8 | 0.3 % |

(· = under 10 clusters; cells ≥ 10: 11 of 13 non-empty)

### 1 extend (as framed): syscheck, vulnerability-detector -> new categories — category × severity (clusters; denominator 3,070)

| category | critical | high | medium | low | total | share |
|---|---|---|---|---|---|---|
| unknown | 3 · | 77 | 681 | 876 | 1637 | 53.3 % |
| ssh_brute_force | 11 | 39 | 846 | 72 | 968 | 31.5 % |
| suspicious_login | 0 · | 0 · | 0 · | 174 | 174 | 5.7 % |
| file_integrity | 0 · | 0 · | 151 | 0 · | 151 | 4.9 % |
| privilege_escalation | 0 · | 31 | 11 | 66 | 108 | 3.5 % |
| vulnerability | 3 · | 3 · | 6 · | 12 | 24 | 0.8 % |
| web_attack | 8 · | 0 · | 0 · | 0 · | 8 | 0.3 % |

(· = under 10 clusters; cells ≥ 10: 13 of 18 non-empty)

### 2 map onto existing: syscheck, vulnerability-detector -> policy_violation — category × severity (clusters; denominator 3,070)

| category | critical | high | medium | low | total | share |
|---|---|---|---|---|---|---|
| unknown | 3 · | 77 | 681 | 876 | 1637 | 53.3 % |
| ssh_brute_force | 11 | 39 | 846 | 72 | 968 | 31.5 % |
| policy_violation | 3 · | 3 · | 157 | 12 | 175 | 5.7 % |
| suspicious_login | 0 · | 0 · | 0 · | 174 | 174 | 5.7 % |
| privilege_escalation | 0 · | 31 | 11 | 66 | 108 | 3.5 % |
| web_attack | 8 · | 0 · | 0 · | 0 · | 8 | 0.3 % |

(· = under 10 clusters; cells ≥ 10: 13 of 17 non-empty)

### 3a exclude syscheck + vulnerability-detector clusters from G1 — category × severity (clusters; denominator 2,895)

| category | critical | high | medium | low | total | share |
|---|---|---|---|---|---|---|
| unknown | 3 · | 77 | 681 | 876 | 1637 | 56.5 % |
| ssh_brute_force | 11 | 39 | 846 | 72 | 968 | 33.4 % |
| suspicious_login | 0 · | 0 · | 0 · | 174 | 174 | 6.0 % |
| privilege_escalation | 0 · | 31 | 11 | 66 | 108 | 3.7 % |
| web_attack | 8 · | 0 · | 0 · | 0 · | 8 | 0.3 % |

(· = under 10 clusters; cells ≥ 10: 11 of 13 non-empty)

### 3b exclude every unknown cluster from G1 — category × severity (clusters; denominator 1,258)

| category | critical | high | medium | low | total | share |
|---|---|---|---|---|---|---|
| ssh_brute_force | 11 | 39 | 846 | 72 | 968 | 76.9 % |
| suspicious_login | 0 · | 0 · | 0 · | 174 | 174 | 13.8 % |
| privilege_escalation | 0 · | 31 | 11 | 66 | 108 | 8.6 % |
| web_attack | 8 · | 0 · | 0 · | 0 · | 8 | 0.6 % |

(· = under 10 clusters; cells ≥ 10: 8 of 9 non-empty)

### 1-wide extend: a new category per family >= 20 clusters — category × severity (clusters; denominator 3,070)

| category | critical | high | medium | low | total | share |
|---|---|---|---|---|---|---|
| ssh_brute_force | 11 | 39 | 846 | 72 | 968 | 31.5 % |
| wazuh_internal | 0 · | 0 · | 0 · | 454 | 454 | 14.8 % |
| service_event | 0 · | 0 · | 428 | 0 · | 428 | 13.9 % |
| system_audit | 3 · | 44 | 1 · | 239 | 287 | 9.3 % |
| suspicious_login | 0 · | 0 · | 0 · | 174 | 174 | 5.7 % |
| unknown | 0 · | 0 · | 130 | 23 | 153 | 5.0 % |
| file_integrity | 0 · | 0 · | 151 | 0 · | 151 | 4.9 % |
| package_change | 0 · | 0 · | 103 | 28 | 131 | 4.3 % |
| privilege_escalation | 0 · | 31 | 11 | 66 | 108 | 3.5 % |
| auth_session | 0 · | 0 · | 0 · | 107 | 107 | 3.5 % |
| compliance_check | 0 · | 11 | 17 | 17 | 45 | 1.5 % |
| vulnerability | 3 · | 3 · | 6 · | 12 | 24 | 0.8 % |
| account_change | 0 · | 17 | 0 · | 3 · | 20 | 0.7 % |
| windows_event | 0 · | 5 · | 2 · | 5 · | 12 | 0.4 % |
| web_attack | 8 · | 0 · | 0 · | 0 · | 8 | 0.3 % |

(· = under 10 clusters; cells ≥ 10: 23 of 33 non-empty)

### The 86 `unknown` crit+high clusters, by rule

| rule.id | level | family | clusters |
|---|---|---|---|
| 80710 | 10 | audit | 34 |
| 19011 | 9 | sca | 9 |
| 80711 | 10 | audit | 9 |
| 5901 | 8 | adduser | 8 |
| 5902 | 8 | adduser | 8 |
| 100204 | 12 | audit | 3 |
| 23505 | 10 | vulnerability-detector | 3 |
| 23506 | 13 | vulnerability-detector | 3 |
| 19014 | 9 | sca | 2 |
| 61017 | 9 | windows | 2 |
| 60602 | 9 | windows | 2 |
| 100200 | 10 | audit | 1 |
| 61061 | 10 | windows | 1 |
| 5904 | 8 | adduser | 1 |

### What each route costs

| route | playbooks to author | decision tables (Owner + advisor) | merged code to change | other artifacts | limitation incurred |
|---|---|---|---|---|---|
| **4 keep `unknown`, report it** | 0 | 0 | **none** | none — P6.md and P8.md already say it (DEC-052; P6.md:17 corrected 07/09 to the measured 1,812) | B1 answers `needs_review` on 59.0 % of G1 and on 86 of the 175 crit+high clusters, so on the escalate pool B1's recall is capped near 0.51 before any rule fires and the B4 − B1 delta there measures taxonomy coverage as much as judgement; a proportional 300-sample is 177 `unknown` unless the allocation caps the stratum |
| **1 extend as framed** (`file_integrity`, `vulnerability`) | 2 | 2 | **`backend/app/ingest/category.py` — merged @ `98ffdbe` (P2-T03)**: `GROUP_TO_CATEGORY` + 2 keys, `PRIORITY` + 2 names, `MAPPING_VERSION` bump; `backend/tests/test_category.py:241–255` re-pins the table hash and `v3.1`; the R5 test refuses any mapped value without a `kb/playbooks/<name>.md`, so the playbooks land first | phase-1 §Khối 5's priority table gains two names; two `kb/decision_tables/*.yaml`; P6's lab scenarios and the G2 "≥ 8/10" rule become /12 | taxonomy diverges from the phase-1 ten; `file_integrity` is one medium cell (151, rules 550/553/554 — no crit/high); `vulnerability` is 24 clusters in four cells all under 10; `unknown` still 53.3 % |
| **2 map onto existing** (→ `policy_violation`) | 0 | 0 | same `category.py` edit (2 keys, no `PRIORITY` change) + the same hash/version re-pin | none | `policy_violation`'s playbook and table were written for people breaking rules, not for FIM churn or CVE resolutions — B1 applies a table to 175 clusters it does not describe, and `policy_violation` goes 0 → 175 live clusters by fiat, which inflates the coverage claim; `unknown` still 53.3 % |
| **3a exclude the two families from G1** | 0 | 0 | none in `category.py`; `eval/build_gold.py` (P6, unwritten) gains an exclusion list | a limitation sentence | reverses DEC-052's "keep everything, filter nowhere" for 175 clusters; G1 stops describing the estate; 6 crit+high clusters leave the escalate pool; `unknown` still 56.5 % of 2,895 |
| **3b exclude every `unknown`** | 0 | 0 | as 3a | a limitation sentence | G1 shrinks to 1,258 clusters over four categories; 86 of 175 crit+high clusters leave the escalate pool; contradicts DEC-052 outright |
| **1-wide** (ten new categories) | 10 | 10 | `category.py` + 10 keys / 10 names, same re-pins | ten playbooks and ten tables in the week the Owner and advisor already owe the existing ten | `unknown` → 5.0 % and B1 expresses 95 %, but ten "categories" of operating noise carry playbooks nobody would consult, and the ① prompt's playbook block grows with them |

**Which routes touch merged code, plainly:** 1, 2 and 1-wide edit `backend/app/ingest/category.py` (merged on `main` at `98ffdbe`, P2-T03 done) and `backend/tests/test_category.py`; that is a P2 deliverable re-opened after review, so it needs a DEC and a card. Routes 3a, 3b and 4 touch no merged code; 3a/3b touch P6's `build_gold.py`, which does not exist yet.

**Recommendation, not a decision.** Route 4, with two riders the Owner can take or leave: (i) P6 caps the `unknown` stratum's share of the sample rather than sampling it proportionally, so it is a bucket and not 59 % of the gold set; (ii) if B1 is to be a fair baseline on the escalate pool, the extension worth pricing is not `syscheck`/`vulnerability-detector` (6 of the 86 crit+high unknowns) but auditd + adduser + sca (75 of the 86) — a different question from the one A5 asks, so it is named here and not answered. Routes 1 and 2 as framed cost a merged-code change and buy 175 clusters, none of them the ones that matter for A1.

## 2 · A1 — what n escalate-positives support

**Where the positives come from.** 175 crit+high clusters, 5.7 % of 3,070. A proportional 300-cluster sample carries ≈ 17 of them; the Director's "15–30 escalate positives" assumes some escalate labels fall in medium/low or a mild oversampling. Because 175 < 300, a design that takes **every** crit+high cluster into the sample is available: n_pos = 175 × P(escalate | crit/high) — 35, 52, 88, 122 at 20 %, 30 %, 50 %, 70 %. That is a sampling-design choice, which is the Owner's; the metric is untouched. G2 (100 lab clusters, mostly attacks) is the other source, and it does not exist yet (A4).

`python3 scripts/escalate_power.py` — 300-cluster gold set, 1,000 seeded resamples as P7 specifies (`EVAL_SEED = 20260904`), McNemar on paired per-cluster correctness restricted to the escalate positives.

| n_pos | true recall | bootstrap CI | width | Wilson CI | width |
|---|---|---|---|---|---|
| 15 | 0.6 | 0.35–0.86 | 0.50 | 0.36–0.80 | 0.44 |
| 15 | 0.8 | 0.58–1.00 | 0.42 | 0.55–0.93 | 0.38 |
| 15 | 0.9 | 0.78–1.00 | 0.22 | 0.70–0.99 | 0.29 |
| 20 | 0.6 | 0.38–0.82 | 0.43 | 0.39–0.78 | 0.39 |
| 20 | 0.8 | 0.61–0.95 | 0.35 | 0.58–0.92 | 0.34 |
| 20 | 0.9 | 0.75–1.00 | 0.25 | 0.70–0.97 | 0.27 |
| 30 | 0.6 | 0.41–0.78 | 0.37 | 0.42–0.75 | 0.33 |
| 30 | 0.8 | 0.65–0.94 | 0.29 | 0.63–0.90 | 0.28 |
| 30 | 0.9 | 0.78–1.00 | 0.22 | 0.74–0.97 | 0.22 |
| 50 | 0.6 | 0.47–0.74 | 0.27 | 0.46–0.72 | 0.26 |
| 50 | 0.8 | 0.68–0.91 | 0.22 | 0.67–0.89 | 0.22 |
| 50 | 0.9 | 0.81–0.98 | 0.17 | 0.79–0.96 | 0.17 |
| 100 | 0.6 | 0.50–0.69 | 0.18 | 0.50–0.69 | 0.19 |
| 100 | 0.8 | 0.72–0.87 | 0.15 | 0.71–0.87 | 0.16 |
| 100 | 0.9 | 0.84–0.95 | 0.11 | 0.83–0.94 | 0.12 |

## Exact McNemar, best case: all discordant pairs favour B4 (c = 0) → b ≥ 6 (p = 0.0312)

| n_pos | minimum recall(escalate) gain B4 over B1 that can reach p < 0.05 |
|---|---|
| 15 | 0.40 |
| 20 | 0.30 |
| 30 | 0.20 |
| 50 | 0.12 |
| 100 | 0.06 |

## McNemar minimum detectable difference, power 0.80, α 0.05 (normal approximation), by discordance rate ψ

| n_pos | ψ = 0.2 | ψ = 0.3 | ψ = 0.5 |
|---|---|---|---|
| 15 | 0.20 | 0.30 | 0.47 |
| 20 | 0.20 | 0.30 | 0.42 |
| 30 | 0.20 | 0.27 | 0.35 |
| 50 | 0.17 | 0.21 | 0.27 |
| 100 | 0.12 | 0.15 | 0.20 |
| 175 | 0.09 | 0.12 | 0.15 |
| 300 | 0.07 | 0.09 | 0.11 |

## n_pos required (power 0.80)

| target difference | ψ = 0.2 | ψ = 0.3 | ψ = 0.5 |
|---|---|---|---|
| 0.10 | 155 | 234 | 391 |
| 0.15 | 68 | 103 | 173 |
| 0.20 | 37 | 57 | 96 |
| 0.30 | 15 | 24 | 42 |

## Simulated power of the exact test at the tabulated MDD (ψ = 0.3, 4,000 reps)

| n_pos | MDD | power |
|---|---|---|
| 15 | 0.30 | 0.28 |
| 20 | 0.30 | 0.58 |
| 30 | 0.27 | 0.78 |
| 50 | 0.21 | 0.76 |

**Reading the tables.**

- At n_pos ≤ 30 the 95 % CI on recall(escalate) is 0.22–0.50 wide: a reported recall of 0.80 at n = 20 is "somewhere between 0.61 and 0.95".
- For B4 to beat B1 on recall(escalate) at α = 0.05: in the best case (every disagreement in B4's favour) B4 must recover **≥ 6 escalates B1 misses** — a recall gain of 0.40 at n = 15, 0.30 at 20, 0.20 at 30, 0.12 at 50. At power 0.80 with a 30 % disagreement rate the minimum detectable gain is 0.30 / 0.30 / 0.27 / 0.21 at n = 15 / 20 / 30 / 50 — and the exact test's real power at n = 15–20 is only 0.28–0.58 even at that gain (last table), so **at n ≤ 20 the comparison cannot reach 0.80 power for any difference the estate could plausibly show.**
- **Whether the claim survives at the achievable n:** under proportional allocation (n ≈ 15–20) a B4-over-B1 claim on recall(escalate) survives only if B4's true recall exceeds B1's by ≥ 0.30 with B1 wrong on ≥ 6 positives that B4 gets right and none the other way. Under the take-every-crit+high design at a 30 % escalate rate (n ≈ 52) the threshold is ≈ 0.21; at 50 % (n ≈ 88) ≈ 0.16. With G2 adding ≈ 60 escalate positives on top, n ≈ 100–110 and the threshold is ≈ 0.15. A 0.10 difference needs 155–391 positives — more than the estate holds under any design.
- The A5 tie-in: 86 of the 175 crit+high clusters are `unknown`, where B1 can only answer `needs_review`. If those are labelled escalate, B1's recall is capped near 0.51 by construction, and the B4 − B1 gap on the escalate pool is partly the taxonomy's gap. Whichever way A1 is framed, the evaluation chapter has to say which of the two it is measuring.

## 3 · Commands

```
python3 scripts/measure_clusters.py --archive /home/user1/archive/alerts-2026-08-08_09-07.jsonl --withdrawn-band
python3 scripts/measure_clusters.py --archive /home/user1/archive/alerts-2026-08-08_09-07.jsonl --routes
python3 scripts/escalate_power.py
```
