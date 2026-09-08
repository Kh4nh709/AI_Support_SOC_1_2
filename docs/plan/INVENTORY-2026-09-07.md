# Inventory — 2026-09-07, before any further code

Ordered by the Owner: stop opening new work, list everything substantiable by command, then
triage. **This document is the list, not the fixes.** Every row carries the command that
establishes it. Two boundaries the Owner set: P2-T02 and P2-T04 are one-line reworks already in
flight and finish; "before coding continues" means **no new card is dispatched** until this is
triaged, not that running sessions stop.

Severity: **S1** = blocks a deliverable or the thesis claim · **S2** = blocks a phase or costs
rework if late · **S3** = tracked debt, no current blockage.

---

## A · Evaluation validity — the cluster that now dominates the project

| # | Sev | Finding | Evidence | Blocks | By when |
|---|---|---|---|---|---|
| A1 | **S1** | **Escalate scarcity.** Severity by cluster over 3,070: critical 25 (0.8 %), high 150 (4.9 %), medium 1,695, low 1,200 — **175 clusters (5.7 %) where an `escalate` label is plausible**. A 300-cluster stratified sample carries ≈ 15–30 escalate positives; `recall(escalate)` with bootstrap CIs over that many positives cannot separate B4 from B1. | resolver + dedup predicates over the archive; banding from `phase-1-tiep-nhan-chuan-hoa.md:148`; **sizing tables (bootstrap CI widths, McNemar MDD, sample designs): `A1-A5-decision-material-2026-09-07.md` §2, 07/09** | **P7's central comparison — the thesis claim itself** | before Planner P6 sizes G1 |
| A2 | **S1** | **`unknown` = 59.0 % of clusters** (1,812 of 3,070). B1 is `kb.apply_table` on DB facts and returns `needs_review` when no rule matches, so a majority-unknown corpus degrades the baseline the headline compares against. | `resolve()` run over all 3,070 clusters | **B1's meaning; the B4-vs-B1 delta** | before Planner P6 |
| A3 | **S1** | **7 of 10 playbook categories have zero live clusters** (re-counted 08/09, DEC-055): `c2_beacon`, `data_exfiltration`, `malware`, `policy_violation`, `ransomware`, `recon`, **and `web_attack`** — its 8 clusters were all local rule 100112 (audit log clearing) reaching `web_attack` through the over-broad `attack` group, so it is artifactual. Live categories are `ssh_brute_force` 968, `suspicious_login` 174, `privilege_escalation` 108 — **three**. | same run, compared against `kb/playbooks/*.md` | **category-coverage claim; G2 is the only remedy** | P6 planning |
| A4 | **S1** | **`docs/lab-scenarios.md` does not exist**, and G2 depends entirely on it. `chot-v3-14-ngay.md:30` already warns `c2_beacon` and `data_exfiltration` may be impossible with Wazuh alone (no Suricata) and says to drop the category if it cannot be generated. Running the scenarios is §11 human-only. | `ls docs/lab-scenarios.md` → absent | **G2 entirely, hence the only remedy for A1/A3** | before P6 (12/09) |
| A5 | **S1** | **Unknown-taxonomy question — Owner's.** Do `syscheck` and `vulnerability-detector` map onto existing categories, get their own, or stay `unknown`? At 59 % this choice sets what B1 can express. | A2's measurement; **the four routes computed side by side: `A1-A5-decision-material-2026-09-07.md` §1, 07/09 — `syscheck` + `vulnerability-detector` are 175 of the 1,812 `unknown` clusters, and 86 of the 175 crit+high clusters are `unknown`** | **P6 stratification and B1's baseline** | **before Planner P6 sizes G1** |
| A6 | **S2** | **DESKTOP-MIRSO17 — Owner's.** Agent 002, 2,472 alerts on one evening, 23 clusters (0.7 %). In or out of the inventory. Director recommends **B** (leave out; G8′ blocks; name it in limitations). | DEC-051, re-measured | **P2-T08/T09 carding** (they read the inventory) | before T08/T09 dispatch |
| A7 | **S3** | G1 window and the self-generated exclusion are decided (30 days; 662 loopback alerts out) but not yet recorded as limitations. | this turn | nothing, once recorded | with P8's limitations — **recorded in `prompts/P8.md:21`, 07/09** |
| A8 | **S1** | **G2's category ceiling, by construction (08/09).** Against the manager's real ruleset (168 stock files, read via `sg wazuh`; `/var/ossec/etc/rules` is empty since 17/08 — the 1001xx/1002xx local rules in the archive last fired 2026-08-17 and are gone) and the merged resolver: only **3** categories are live *and* correctly classified (`ssh_brute_force`, `suspicious_login`, `privilege_escalation`); `recon` needs one ssh scan (5706/5731/40601; nmap not installed, not needed); `malware` needs `apt install clamav` (decoder 0075 + rule 52502 stock; 80712/T1204 also maps to it on any abnormal exit) → **5/10 with no code change**. `ransomware` (T1486 only in MS Graph 99535/99594), `data_exfiltration` (T1041 only in Amazon Security Lake; no stock rule carries group `exfiltration`) and `c2_beacon` (the 5 Suricata rules decode as `json` and carry no MITRE — installing Suricata classifies nothing) are reachable only through **local rules** → 7–8/10 without touching `category.py`. `policy_violation` has no signal in the resolver or in any Linux stock rule — only A5 (e.g. `sca` → `policy_violation`, 45 clusters) or a resolver change reaches it. §C's ≥ 8/10 is not achievable as things stand; ClamAV, Suricata, nmap all absent (`command -v`). | `python3 -c` over `category.py` tables; `sg wazuh -c grep` over `/var/ossec/ruleset/rules`; `command -v clamscan suricata nmap` | **§C's coverage claim; which scenarios are worth writing** | **RULED 08/09 — DEC-056, route B + C:** three local rules in the `local_rules.xml` that `100999` needs anyway reach **8/10, meeting §C**; ClamAV and one ssh scan reach 5/10 with no new content; `policy_violation` goes to A5; the author-written-detection circularity is a named limitation. Owner action on the board. |
| A9 | **S2** | **`attack` group over-mapping in the merged resolver.** The 8 live `web_attack` clusters (all `critical`) are local rule **100112** — audit log clearing, T1070.002/003 — pulled into `web_attack` at tier 3 by `GROUP_TO_CATEGORY["attack"]`, ported from `Final-Project` as-is; no web server runs on this host, no stock web rule has ever fired, and rule 100112 itself no longer exists on the manager (last alert 2026-08-17). Every `web_attack` number in the inventory and the decision material inherits it. Fix is one key in `category.py` (merged, P2-T03) → DEC + card; until then `web_attack` is not a live category. | `scripts/measure_clusters.py` fold attributed per rule (08/09) | category-coverage claim; the `web_attack` cell in every grid | **RULED 08/09 — DEC-055**, raised on its own merits, not with A8. Simulated on all 3,070 clusters: exactly 8 move `web_attack` → `unknown`, nothing else moves; B1-expressible 1,258 → 1,250, `unknown` crit+high 86 → 94. The fix is not a deletion — dropping the key alone costs **9 stock web rules** their classification, so `sqlinjection` (tier 3) and `web-accesslog` (tier 4) are added with it. Card-free contract in DEC-055; STATE row P2-T16. |

## B · Schedule

| # | Sev | Finding | Evidence | Blocks | By when |
|---|---|---|---|---|---|
| B1 | **S1** | **Slack is exactly zero.** 07/09 → 18/09 is 11 days; phase days still required are 11 (P2 2, P3 1, P4 1, P5 1, P6 3, P7 1, P8 2). **Any further slip consumes a deliverable, not a buffer.** | STATE phase rows vs the deadline | everything downstream | tonight's gate |
| B2 | **S1** | **P2 fits two days only if intake is batched.** 28 h of `must` remain across 9 tasks; the critical path is ≈ 12.3 h at three coders (wave-2 17.5 h ÷ 3, then T10 4 h, then T15 2.5 h). Add merge gates: **≈ 2 h batched, 24–40 h unbatched** (DEC-048). Unbatched, P2 alone eats the remaining slack twice over. | `P2-tasks.md` estimates + DEC-048's measurement | P3's 09/09 start | continuously |
| B3 | **S2** | **The ② cut is still unspent** and is the designated lever (DEC-041), deferred to tonight's gate on real numbers. | DEC-041 | P5's shape | 08/09 gate |

## C · In flight, and composition risk

| # | Sev | Finding | Evidence | Blocks | By when |
|---|---|---|---|---|---|
| C1 | **S2** | **P2-T02's merge lands nothing.** Branch is an ancestor of `main` with content reverted out; `git merge` says "Already up to date." Route ruled (DEC-050, revert-the-revert **in the same run** as the fix) but **not yet executed**. | `git merge-base --is-ancestor task/P2-T02 main` → true; `main..task/P2-T02` → 0 commits | T05, T06, T07, T08, T09, T11 — six tasks | at T02's intake |
| C2 | **S2** | **A two-task frontier gates five.** T05, T06, T08, T09 all wait on T02 **and** T04; T11 waits on T02. Both are one-line reworks, so five tasks unblock at once — and will be reviewed and merged together. | dependency column | wave 2 | — |
| C3 | **S2** | **That simultaneous landing is the DEC-047 condition.** Five branches merging in one batch is exactly how two individually-correct branches composed into a defect neither had. Mitigation exists (`build_schema --check` in `lint`; merge-to-scratch-first) but has never been exercised on five. | DEC-047, DEC-048 | wave-2 merge | at that merge |
| C4 | **S3** | **P2-T12's card still lives in `tasks/P2/`** though DEC-041 moved the task to P4. Planner P4 must adopt it; until then the phase directory misrepresents the phase. | `ls docs/plan/tasks/P2/P2-T12.prompt.md` | nothing now; confusing at P4 planning | P4 planning |

## D · Board and propagation debt

| # | Sev | Finding | Evidence | Blocks | By when |
|---|---|---|---|---|---|
| D1 | **S2** | **12 open agent actions**, most of them instructions that must reach a phase brief **before that Planner runs** — Planner P2 ×3, P3, P4/P6, P5, P6 ×3, P8, Director. This is the DEC-026 channel, which has failed measurably before; DEC-031 fixed it for P2 and P3 by editing the briefs directly. **P4, P5, P6, P8 briefs have not had that treatment.** | `grep '^- \[ \] \*\*\(Planner\|Director\|P[0-9]\)'` → 12 | P4–P8 planning quality | before each Planner runs |
| D2 | **S3** | **One stale Owner action**: line 74 asks the Owner to re-open a Planner P2 session for the DEC-038 card fixes — **already applied** (P2-T09 acceptance 4 and P2-T11's note 9 are in the tree). | `grep` for the fix text in both cards → present | nothing; it wastes an Owner action slot | next board pass |
| D3 | **S3** | **8 open register rows**: `01-plan.md` ×2, `prompts/P8.md` ×2, `prompts/P6.md` ×1, canonical ×3. Two of the P8 ones are live debts (`dec-001-35`: four named limitations still absent from the P8 enumeration). | `superseded.yaml` status counts | P6/P8 brief accuracy | before those Planners |
| D4 | **S3** | **No exact heartbeat wodle command exists anywhere**; P2-T11's live path cannot be proven, only fixture-tested. Recorded honestly in the card. | DEC-051, `grep -rn wodle docs/` | P2-T11's live-path claim only | optional |

## E · Process gaps with no mechanism

| # | Sev | Finding | Evidence | Blocks | By when |
|---|---|---|---|---|---|
| E1 | **S2** | **The DEC-044 class has no mechanism.** Two locally correct rules that stop composing, with no artifact wrong in isolation — **three instances in three days** (DEC-044 card axes, DEC-046 the ff treadmill, DEC-047 schema.sql). `build_schema --check` closed it for generated files only. `Propagated to:` makes the overlaps computable but nothing computes them. | DEC-044/046/047 | recurs unpredictably; C3 is its next likely site | — |
| E2 | **S3** | **An `xpass` silences a guard as easily as a fix does.** A well-meant edit to a quoted line retired a live debt this morning (DEC-052 follow-up). Short canonical forms are the mitigation; long verbatim patterns remain in the register. | DEC-052 amendment | register reliability | ongoing |

---

## Triage

### Must be settled before any NEW card is dispatched

1. **A5 — the unknown-taxonomy call (Owner).** It sets what 59 % of the corpus means, and P2-T08/T09's enrichment cards read the category vocabulary. Cheapest of the three Owner items and unblocks the most.
2. **A6 — DESKTOP-MIRSO17 (Owner).** Directly gates P2-T08/T09, which are in wave 2.
3. **C1 — execute DEC-050's repair at T02's intake.** Not new work; it is the mechanics of finishing an in-flight task, and six tasks sit behind it.
4. **B1/B2 — accept batching as the operating mode for wave 2**, i.e. one intake for all five. With zero slack this is the difference between P2 in two days and P2 in four.

### Rides alongside — no need to block on these

- **C3** — mitigate at the wave-2 merge by building the five-way merge in a scratch tree first. Costs minutes, not a decision.
- **D1** — correct the P4/P5/P6/P8 briefs as each Planner is about to run, exactly as DEC-031 did for P2 and P3. It is per-phase work, not a batch.
- **D2, C4** — one-line board corrections at the next pass.
- **A7** — record the two decisions taken today (below) with the limitations they imply.

### Deferrable, with the cost named

- **A3/A4 (G2 and lab scenarios)** — deferrable to P6 planning **only** if the Owner accepts that six categories may end with zero coverage and the thesis reports coverage over four. **Cost if deferred past 12/09: G2 cannot be built at all**, because running scenarios is human-only work needing a day, and P6 is three days that already include two days of labelling.
- **A1 (escalate scarcity)** — cannot be *fixed* by scheduling; it is a property of the estate. Deferrable only as a **framing** decision: either G2 supplies escalate-positives, or P7's headline metric changes from `recall(escalate)` to something the sample can support. **Cost if deferred: it is discovered at P7 on 15/09, with two days left and no way to regenerate data.**
- **E1** — no mechanism this week. Cost: the class recurs; C3 is the likely next site, and the mitigation is manual.
- **D3, D4, E2** — genuine debt, no current blockage.

### The one thing I would put above all others

**A1 and A4 together.** Everything else on this list is recoverable inside the schedule. Those two are not: escalate-positives and lab data can only come from scenario runs that need a human day, and the last day that can happen is 12/09 without displacing labelling. If the Owner defers only one thing, it should not be these.
