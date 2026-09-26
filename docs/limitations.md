# Limitations register — AI Support SOC v3

Evidence file for the thesis's limitations section (P8-T05, DEC-129). Written 26/09/2026 against the
director branch at `82d0783`. It is a register, not thesis prose: the Owner writes the chapter from it.

**How to read an item.** Each item has four labelled parts: Statement (what the limit is), Measured (the
figure and how it was measured, or "not measured" and why), Source (the DECs and architecture sections),
Affects (the thesis claim or table it qualifies). Roman numerals (i)–(xiv) are the anchors the P8 brief
gives (`docs/plan/prompts/P8.md`, the `docs/limitations.md` bullet); (xv) onward number the items the brief
or the card gives without one, in the order they appear here. (iii) and (viii) described G1 and the
database that was reset on 25/09, so they appear inside (ix); (ii) and (v) share one item.

**Figures.** Every figure is copied from the DEC that measured it, with that DEC cited, and dated to the
host it was measured on. The few facts read for this file from the tree itself (line numbers, one-line
modules, the tables' review fields) say "at `82d0783`" and name their command. A figure that exists only
after the 28/09 freeze, the 29/09 evaluation run or the close-out is a marked placeholder in double
brackets, naming the figure and where it comes from; the Director fills each one in P8-T06.

**G1 and G2.** The evaluated corpus is G2: author-generated lab traffic from 26–27/09. G1, the history
corpus of the first host, was built and not evaluated (DEC-111). G1's figures appear in one place only,
the Measured paragraph of item (ix) in section B.

## A. The evaluated corpus (G2)

### (xii) · The gold set is author-generated lab traffic on the author's host

- **Statement.** Every alert in the gold set (G2) was generated on the author's own host, `attt-m1-lab`
  (agent 004, the native Wazuh agent on ATTT-M1), on 26–27/09, by scenarios the author ran; G3, the
  adversarial set, is synthetic (xxviii). The author also declared the rules that set each window's truth,
  and is one of the two labellers. DEC-111: "author-as-labeler (DEC-056) now compounds with
  author-as-attacker and author-as-truth".
- **Measured.** By construction. The corpus starts at `PULL_START=2026-09-26` (00:00 UTC) on a database
  reset on 25/09: `alerts|users|assets|schema_migrations` = `0|4|7|17` (DEC-113, block 5). The
  lab agent is `attt-m1-lab`, agent 004 (DEC-112; DEC-113, block 2). Truth is derived from the windows the
  Owner logged, not from adjudication (DEC-111). The labellers are the author and one other person
  (DEC-104). `eval/build_gold.py:139-142` writes this sentence into `eval/gold_coverage.md`: "This corpus
  is author-generated lab traffic on the author's host with window-known truth: no rate computed from it
  is an estate rate, of any estate." Size: ⟦G2: lab windows run, attack and benign, and the number of
  gold_v1 clusters, from eval/lab_windows.csv and eval/gold_v1.csv⟧.
- **Source.** DEC-111 (the "what the thesis loses" bullet), DEC-104, DEC-112, DEC-113, DEC-114;
  `docs/kien-truc-v3-14-ngay.html` §6 ("G2 là lab, không phải phân phối thật") and §9 ("Hai analyst là
  người xây và người hướng dẫn").
- **Affects.** Every G2 table in `docs/results/ablation.md` and `docs/results/per_category.md`, the
  human baseline, and any sentence that generalises beyond this host.

### (xv) · Truth is the window, scoped to the scenario's pre-declared Expected rules

- **Statement.** A head inside an attack window gets a truth label only if its `rule_id` is one of that
  scenario's Expected rules, declared in `docs/lab-scenarios.md` §3 before any window ran. Every other
  head in the window is `in_window_unexpected`: excluded from the gold set and counted per window. Truth
  therefore covers the alerts the author declared for each scenario, not every alert the scenario caused.
  The scope also cuts the other way: an unrelated event inside a window that matches a declared rule is
  counted as the attack (DEC-114's example: an unrelated `sudo` inside a `privilege_escalation` window
  matching 5402).
- **Measured.** By construction: 19 Expected rule ids over 8 scenarios (DEC-114, whose "20 ids" DEC-115's
  erratum corrects to 19) — `ssh_brute_force` 5710 5712 5760 5503 2501 · `suspicious_login` 5715 5501
  40112 · `privilege_escalation` 5401 5402 510 521 · `recon` 5706 5731 40601 · `malware` 52502 ·
  `ransomware` 100301 · `data_exfiltration` 100302 · `c2_beacon` 100303. The scope is applied by `rule_id`
  at `eval/build_gold.py:526` (DEC-118, item 3). Excluded heads: ⟦G2: the in_window_unexpected total and
  the heads found, from the totals line under the per-window table of eval/gold_coverage.md⟧.
- **Source.** DEC-114 (the scope bullet and its erratum), DEC-115 ruling 2, DEC-118 item 3;
  `docs/lab-scenarios.md` §3, the "Expected rules" tables.
- **Affects.** recall(escalate) and every per-category figure: they are measured on the declared rules'
  heads only.

### (xvi) · A benign window's truth is `benign`, so no truth row is `false_positive`

- **Statement.** A benign window's truth is `benign` (DEC-115), so the gold truth is two-valued:
  `escalate` or `benign`. In DEC-115's words, "`false_positive` remains a label a human can give; it is no
  longer a truth value". The architecture's headline "precision(false_positive)" is therefore reported as
  precision of `close`, P(truth `benign` | outcome `close`), where `close` is a `false_positive` or
  `benign` answer (DEC-121 Q1; `docs/plan/tasks/P7/P7-T03.prompt.md`, `precision_close`). The
  once-a-day benign block declares no Expected rules, so every head of `attt-m1-lab` inside its window
  becomes a `benign` truth row, including container background that happens to fall in it.
- **Measured.** By construction: `TRUTH_BY_KIND` at `eval/build_gold.py:129` maps attack → `escalate`,
  benign → `benign` (DEC-118, item 3); the benign block is the one unscoped window
  (`eval/build_gold.py:524`, DEC-114). Its share: ⟦G2: in-scope heads of the benign-block windows BB-D1
  and BB-D2, against all benign truth rows, from the per-window table of eval/gold_coverage.md⟧.
- **Source.** DEC-115 ruling 1 (withdraws DEC-111's "benign twin → `false_positive`"), DEC-114, DEC-121
  Q1; `docs/plan/tasks/P7/P7-tasks.md` §3 item 4 (the precision-of-`close` mapping); architecture §6
  ("recall(escalate) và precision(false_positive) — hai số quan trọng nhất").
- **Affects.** The architecture's two headline numbers; the `close` columns of `docs/results/ablation.md`.

### (x) · The lab tag is applied after the fact, by time window

- **Statement.** `source='lab'` is set after each scenario by `eval/lab_tag.py`, from the start and end
  seconds the Owner logged, because the lab host is also a host of the estate: ATTT-M1 also runs the MISP,
  TheHive, Cortex, Graylog, n8n and Elasticsearch containers, whose background reaches the same indexer
  (DEC-114). A scenario whose seconds were not written down cannot be recovered for G2.
- **Measured.** By construction. The safeguard: `build_gold.py --g2` exits 3 on a head inside a recorded
  window that is still marked `wazuh` (DEC-085), and on overlapping windows of one agent (DEC-118, item
  3). Windows: ⟦G2: windows recorded in eval/lab_windows.csv, and any scenario run whose seconds were not
  recorded, from eval/lab_windows.csv and docs/lab-run-log.md⟧.
- **Source.** DEC-085, DEC-111, DEC-114, DEC-118.
- **Affects.** G2's completeness; the split of lab heads from background in `docs/results/operations.md`.

### (xvii) · Author-written detection for `ransomware`, `data_exfiltration` and `c2_beacon`

- **Statement.** These three categories produce no alert through any stock Wazuh rule on this estate, so
  G2 reaches them only through three local rules the author wrote: `100301` (T1486, `ransomware`),
  `100302` (T1041, `data_exfiltration`) and `100303` (T1071, `c2_beacon`). The behaviour the lab generates
  is real; the detection logic that classifies it was written by the same person whose system is being
  evaluated. Every per-category figure for these three categories rests on those rules (DEC-056,
  amendment 3).
- **Measured.** The 08/09 grep over the 168 stock rule files of IA1803's manager (DEC-056; the INBOX
  2026-09-08 "P6 / G2" request it resolved): "the only stock rules carrying T1486 are Microsoft Graph
  99535/99594"; "T1041 only in 0990-amazon-security-lake"; "T1071 only in named/osquery/proftpd rules
  (services absent)"; "the 5 Suricata rules `decoded_as json`, carry no MITRE and no mapped group". Not
  re-measured on the ATTT-M1 manager. The three rules are loaded on the
  ATTT-M1 manager (`local_rules.xml` md5 `afd2ef60…`, DEC-113, block 1). Before the audit filter of
  (xiv), `100303` fired on background, not on an attack (DEC-113). Whether each fires in its own windows:
  ⟦G2: in-scope heads of rule 100301 in the RW windows, 100302 in the DX windows and 100303 in the C2
  windows, from the per-window table of eval/gold_coverage.md⟧.
- **Source.** DEC-056 (amendment 3), DEC-068 (the rule ids and their techniques), DEC-113, DEC-114.
- **Affects.** The `ransomware`, `data_exfiltration` and `c2_beacon` rows of `docs/results/per_category.md`.
  The evaluation chapter names these three as resting on author-written detection.

### (xviii) · Category coverage: eight of ten playbook categories; `web_attack` and `policy_violation` absent

- **Statement.** G2 has scenarios for eight of the ten playbook categories; `web_attack` and
  `policy_violation` have none (DEC-111, which names DEC-055 and DEC-057). `policy_violation` has no signal
  at all: no Linux stock rule carries a fitting group, and there is no lab route (DEC-057). A category
  with no gold cluster is dropped from the result tables and named as dropped, never synthesised.
- **Measured.** By construction for the two absent categories. DEC-057: route 4 leaves `policy_violation`
  "a category with **no signal at all** — neither live clusters nor a lab route". For `web_attack`, the
  reason DEC-056 recorded on 08/09 ("`web_attack` needs a web server (none here)") described IA1803. The
  ATTT-M1 runbook notes that web services do run on this host (MISP's nginx, n8n; `docs/lab-scenarios.md`
  §7), and no `web_attack` scenario was written for them. Its only history was an artifact of a
  mis-mapping (DEC-055; the figures are in (ix)). Categories that ran and produced nothing:
  ⟦G2: playbook categories with zero clusters in the G2 pool, from the "zero clusters" line of
  eval/gold_coverage.md⟧.
- **Source.** DEC-111, DEC-055, DEC-056, DEC-057; architecture §6 (the G2 target "phủ ≥ 8/10 category"
  and the note "bỏ khỏi bảng kết quả, không giả"); `docs/plan/tasks/P7/P7-tasks.md` §3 item 5.
- **Affects.** `docs/results/per_category.md`: the rows that exist and the rows named as dropped; any
  claim about the ten-category taxonomy as a whole.

### (xix) · The class balance is the schedule's; no rate is an estate rate

- **Statement.** The mix of `escalate` and `benign` truth in G2 was set by the author's two-day schedule
  (attack windows, benign twins, one benign block a day), not by any estate's traffic. Prevalence-dependent
  figures (precision, macro-F1, accuracy) therefore describe this schedule, and no rate from G2 is an
  estate rate, of any estate (DEC-111).
- **Measured.** Planned: 103 in-scope clusters, 24 of them benign, over 8 of 8 categories
  (`docs/lab-scenarios.md` §5 "Yield", recorded at DEC-119 as "yield 103 in-scope / 24 benign ≥ the
  floors"). Realised: ⟦G2: gold_v1 truth balance, escalate n and benign n, overall and per
  category_expected, from the "truth in the sample" line of eval/gold_coverage.md⟧.
- **Source.** DEC-111; the second half of the brief's (xii); `docs/plan/prompts/P7.md:18` ("the class
  balance is the schedule's, not nature's"); DEC-119.
- **Affects.** Every G2 rate in `docs/results/ablation.md` and `docs/results/per_category.md`; see (xxxix).

### (xx) · Labeller agreement (κ), and each labeller against the window truth

- **Statement.** The two labellers label the G2 candidates blind and independently on 28/09 (P6-T02's
  page: no ① output, `source` hidden, each in their own random order). Their labels are a second result,
  not the gold: κ between them is reported, and each labeller's agreement with the window truth is the
  human baseline that ① is compared against (DEC-111). One labeller is the author, who also ran the
  scenarios and declared the rules that set their truth (xii). Architecture §6 set a κ target ("mục tiêu κ ≥
  0,6") and §9 R4 names "κ < 0,4" as a risk; under DEC-111 κ qualifies the human baseline, not the gold.
- **Measured.** ⟦G2: Cohen's κ overall with n labelled by both, κ by category, and each labeller's
  vs_truth accuracy with its n, from eval/kappa_v1.json⟧. A labeller with no label against a window truth
  prints "not available", never 0 (DEC-120, item 2).
- **Source.** DEC-111, DEC-104, DEC-117 and DEC-118 item 4 (the blindness input-boundary test, P6-T10),
  DEC-120, DEC-131 item 4 (the labeller pairing); architecture §6 (the labelling protocol; "κ thấp làm mờ
  mọi số phía sau"), §9 R4.
- **Affects.** The human-baseline rows beside ①'s figures in `docs/results/ablation.md`;
  `docs/gold-v1-report.md`.

### (xxi) · Misfired scenarios are excluded at adjudication

- **Statement.** A scenario that misfired is excluded at the 28/09 adjudication through a committed
  `eval/excluded_scenarios.csv` (`scenario_id,reason,decided_in`), and `freeze` drops all its candidates.
  This includes a negative-check twin in which an in-scope head appears (DEC-115 ruling 1). A human who
  disagrees with a window's truth is kept as data, as part of the human-baseline figure; that
  disagreement never overwrites the truth (DEC-120, item 3). G2 is therefore made of the scenarios that
  were not excluded.
- **Measured.** ⟦G2: the excluded scenarios, each with scenario_id, reason, decided_in and the number of
  candidates dropped, from eval/excluded_scenarios.csv and the freeze output⟧. A malformed exclusion file
  makes `freeze` refuse, exit 2, before any connection (DEC-120, item 2).
- **Source.** DEC-115 rulings 1 and 3, DEC-119 item 4, DEC-120.
- **Affects.** G2's size and category coverage; every G2 table.

## B. What was built and not evaluated, or not built

### (ix) · G1, the history corpus, was built and not evaluated

- **Statement.** G1 was the gold set planned from the first host's alert history. It was built and
  sampled, and then the Owner dropped it on 25/09, before any labelling or evaluation.
  The gold set was rebuilt from the author-run lab corpus (G2), and DEC-084 and DEC-086 are void
  (DEC-111). G1's figures describe a corpus that was not evaluated. They are never a property of what was.
- **Measured.** G1 was IA1803's manager archive export: 92,030 lines over 30 distinct days, 2026-08-08 →
  2026-09-07, with one gap, 02/09, whose source file is 0 bytes (DEC-051), and 113,379,904 bytes
  (DEC-061). Folded with the real dedup predicates it gave 3,070 clusters (DEC-053). Severity by cluster
  was critical 25 · high 150 · medium 1,695 · low 1,200 of 3,070, so 175 clusters (5.7 %) were crit+high
  (DEC-053, DEC-066). `unknown` was 1,812 of 3,070 clusters (59.0 %), and B1 answered `needs_review` on
  86 of the 175 crit+high clusters, which capped its recall on the escalate pool near 0.51
  ((175 − 86) / 175) before any rule fired (DEC-057). Asset-hygiene events (vulnerability-detector
  resolutions, CIS benchmark checks) were kept rather than filtered: 12,217 alerts collapsing to 24
  clusters, 0.8 % of 3,070 (DEC-052). The 662 loopback `ssh_brute_force` alerts from `127.0.0.1` were
  excluded as a named limitation; the rest of the August brute-force data stayed, as an external
  campaign and not the author's testing (DEC-053). The window was frozen at 08/08–07/09 with no day added
  (DEC-066). (iii) `DESKTOP-MIRSO17`, an agent outside `conf/inventory.yaml`, kept its 23 clusters (0.7 %
  of 3,070), every one `needs_review` by construction (DEC-058). `HR-computer` and `wazuh.manager`, added
  to the inventory for a pilot that never ran, are not in G1 (DEC-066). `web_attack`'s 8 archive clusters
  were all local rule 100112 (audit-log clearing), reached through the over-broad `attack` group, and the
  fix made `web_attack` a zero-cluster category (DEC-055). (ix) The 300-cluster sample took every
  crit+high cluster from a pool of 2,984 (the offline fold's 3,051 clusters minus 67 loopback clusters):
  137 crit+high clusters, 4.6 % of the pool and 45.7 % of the sample, a ≈ 10× oversample, with `unknown`
  capped from 60.4 % of the pool to 40 % of the sample (DEC-086). (vi) On the replay of this archive, 19
  of 96,019 intake rows (0.02 %) were rejected for a missing `rule.description` while their jobs recorded
  `succeeded`; `replay` 92,011 + 19 `rejected_alerts` = 92,030 reconciled only because the rejections were
  counted separately (DEC-079). (viii) The 383 heads stored on 15/09 carried `criticality` `unknown` and
  `lookup_status.asset` `not_found` on 383 of 383, because the inventory was loaded after they were
  enriched (DEC-082, DEC-083); that database was reset on 25/09 (DEC-113). The installation that produced
  G1 no longer exists: the Owner rebuilt IA1803's Wazuh on 14/09, and the old host installation and its
  `:9400` alert store are gone (DEC-061, DEC-064, DEC-065), so the corpus could not be re-queried or
  extended. The archive never came to ATTT-M1, and a database rebuild reproduced the three G1 artifacts
  byte-identically (DEC-108). The G1 artifacts stay in git as the record of what was built and not used
  (DEC-111).
- **Source.** DEC-051, DEC-052, DEC-053, DEC-055, DEC-057, DEC-058, DEC-061, DEC-064, DEC-065, DEC-066,
  DEC-079, DEC-082, DEC-083, DEC-086, DEC-108, DEC-111; the preface of the brief's `docs/limitations.md`
  bullet.
- **Affects.** Nothing in `docs/results/*`: G1 has no evaluation run. It qualifies the method history (why
  the gold set is a lab corpus) and the provenance of the decision tables (xi).

### (xiii) · No human-decision pilot ran: the Tier-1/Tier-2 console was deprioritized

- **Statement.** The Tier-1/Tier-2 console (P4-T03/T05/T06 and all of P5) was deprioritized behind the
  P6 → P7 → P8 spine, and is cut if still unstarted at the 30/09 morning gate (DEC-116). So no
  human-decision pilot ran, and the product chapter describes "a triage engine evaluated offline with a
  blind-labelling console, not a full two-tier SOC application" (DEC-116). DEC-116 names the cut, for this
  file, "operational console not completed within the evaluation window". Architecture §6's online
  metrics are not measured; the gate-forced rate is.
- **Measured.** On 26/09 `soc_dev` held 0 `tier1.*` events, 0 `triage_labels` and 0 `autoclose_reviews`
  (DEC-129). Five of the six online metrics of architecture §6 are not measured, because no human-decision
  pilot ran (DEC-116): decisions by branch and by person; acknowledge → decide by branch; ① agreement with
  human decisions on the blind branch; the auto-close wrong-close rate from the digest (Wilson CI); ②
  usefulness 1–5. The operations export prints each one as "not measured" with its reason and its counted
  evidence, never as a zero (`docs/plan/tasks/P8/P8-T01.prompt.md`, note 2, section 6). The sixth is
  measured: ⟦G2: the gate-forced needs_review rate over the lab period, forced ÷ proposer rows where the
  gate ran, from the "① online" section of docs/results/operations.md⟧. Above 0.60 the export prints the
  architecture's sentence ("cổng đang bóp ①") and names R5. The console at the gate: ⟦G2: whether
  P4-T03/T05/T06 and the P5 rows other than P5-T12 were cut at the 30/09 morning gate, and the DEC that
  cut them, from STATE.md⟧.
- **Source.** DEC-116, DEC-129; `docs/plan/tasks/P8/P8-tasks.md` §0 item 1;
  `docs/plan/tasks/P8/P8-T01.prompt.md` note 2 (section 6); architecture §6 (the "Trực tuyến … (mô tả)"
  block), §9 R5 and R6.
- **Affects.** The product chapter's scope; the pilot chapter, whose source is `docs/results/operations.md`
  in place of `docs/results/pilot.md` (DEC-129).

### (xxii) · The auto-close control "digest 100 %" was not built

- **Statement.** Auto-close is the product's only automatic action. Architecture §9 lists its controls
  as "chặn cứng, simulate, digest 100 %". The digest is what puts every auto-closed alert in front of a
  human the next morning (DEC-012: "Auto-close is not terminal"). It is P5 work, deprioritized
  (DEC-116), so no auto-closure in the lab period was reviewed by a human, and the wrong-close rate is not
  measured. The hard blocks and `simulate` exist.
- **Measured.** `backend/app/tier1/digest.py` is a one-line module at `82d0783` (`wc -l`), and
  `autoclose_reviews` held 0 rows on 26/09 10:50 (DEC-127). The blocks and `simulate` are tested:
  `test_autoclose.py` 41 passed, 3 of them `simulate` tests (DEC-079, 15/09). Auto-closures in the lab
  period: ⟦G2: alert.auto_closed events and heads with autoclose_rule_id set, over the lab period, from the
  "Auto-close" section of docs/results/operations.md⟧.
- **Source.** Architecture §9 (the list "Giới hạn phải tự nêu trong báo cáo", last bullet) and §6; DEC-012,
  DEC-079, DEC-116, DEC-127; `docs/plan/tasks/P7/P7-tasks.md` §3 item 10 (auto-close is not part of the
  ablation).
- **Affects.** Any auto-close claim; architecture §6's "tỉ lệ đóng nhầm auto-close từ digest, khoảng tin
  cậy Wilson".

### (xxiii) · ②, the Tier-2 investigator, was cut

- **Statement.** ②, the one-pass Tier-2 investigation over a case dossier (D11), was cut on 25/09 by the
  dated trigger of DEC-097. It was never built and never evaluated. Auto-close was kept (DEC-111).
- **Measured.** DEC-097's two conditions were both false at 17:00 on 25/09: P6-T02 was `todo` and no lab
  window existed (DEC-111). No ② prompt was ever sent (DEC-032: "no ② prompt has ever been sent").
  `backend/app/tier2/investigate.py` and `backend/app/llm/investigate.py` are one-line modules at
  `82d0783` (`wc -l`), and the worker's handler table is `{pull, pipeline, triage}`
  (`backend/app/web/worker.py:25`).
- **Source.** DEC-097, DEC-108 (the trigger read as written), DEC-111; DEC-032 (the size-class measurement
  ② was gated on).
- **Affects.** Architecture §3.7 and the investigator contract of §4.4; any Tier-2 claim.

### (xxiv) · Prompt v1.1 was not built

- **Statement.** The design allows at most two prompt changes, each its own `eval_runs` row behind the
  regression gate (architecture §6: "tối đa 2 lần đổi prompt"). v1.1, the few-shot prompt built from human
  corrections of ①, was cut because no human correction of ① exists to learn from (DEC-127). The regression
  gate itself (P7-T06) is built and tested, and it is the activation mechanism the design describes.
- **Measured.** On 26/09 10:50: `triage_labels` 0 rows of any source, `autoclose_reviews` 0 rows, and no
  code path writes `triage_labels(source='digest')` (DEC-127). Two upper-bound counts are recorded at the
  P7 run: ⟦G2: the counts of digest labels and of auto-close reviews marked wrong at the P7 run, from the
  v1.1 line of docs/results/ablation.md⟧. A count of 0 proves the cut lost nothing; a non-zero count is
  reported as candidate rows that "existed and were not examined" (DEC-127, item 2).
- **Source.** DEC-127, DEC-121 Q2, DEC-124 item 3; architecture §6.
- **Affects.** The v1.1 line of `docs/results/ablation.md`; any claim of prompt iteration.

### (xxv) · Online recall is meaningless with ≈ 0 real incidents

- **Statement.** Architecture §6, "Phải tự nêu trước hội đồng": "sự cố thật trong 7 ngày ≈ 0 → recall
  trực tuyến không có ý nghĩa". The live stream from 26/09 carries no known truth outside the lab windows,
  so no online recall, precision or miss rate is reported.
- **Measured.** Not measured: heads outside every lab window have no known truth and stay out of the gold
  set (DEC-111). Their count: ⟦G2: heads with source 'wazuh', outside every lab window, over the lab
  period, from the "Intake and dedup" section of docs/results/operations.md⟧.
- **Source.** Architecture §6; DEC-111.
- **Affects.** `docs/results/operations.md`, which is "an operating record, not a controlled experiment"
  (P8-T01, note 2); see (xl).

## C. The AI layer

### (xxvi) · The proposer and the verifier share one provider (R7)

- **Statement.** ①'s proposer and its verifier call the same provider through one adapter, so a bias the
  two share cannot be told apart from agreement. Architecture §9 R7, "Proposer và verifier cùng thiên lệch
  (cùng nhà cung cấp)", is rated "Chắc chắn" and answered by stating it and by gate step 4, which depends on
  no model ("cổng bước 4 không phụ thuộc model nào").
- **Measured.** By construction: one `LLM_BASE_URL` and one `LLM_API_KEY` serve both roles
  (`backend/app/infra/config.py:132-135`). An empty `LLM_MODEL_VERIFIER` resolves to the proposer's model
  (`config.py:211-213`), and `.env.example:52-55` ships `LLM_BASE_URL=https://api.deepseek.com/`,
  `LLM_MODEL_PROPOSER=deepseek-v4-flash` and an empty `LLM_MODEL_VERIFIER`. The proposer model is
  `deepseek-v4-flash` (DEC-042). The correlated error itself is not measured, because no second provider
  was configured.
- **Source.** Architecture §9 R7, §4.3 (what the verifier sees), §4.5; DEC-042.
- **Affects.** The B3 → B4 difference in `docs/results/ablation.md` (the verifier's contribution); any
  claim that the verifier is an independent check.

### (xxvii) · Alert data is sent to an external LLM provider

- **Statement.** Every proposer call sends the alert's content (raw log, rule description, correlation
  samples, each inside an untrusted block) to DeepSeek's API, outside the organisation; the verifier call
  sends database facts and the proposer's reasons, which may quote that content (architecture §4.3).
  Architecture §9: "Dữ liệu alert gửi tới nhà cung cấp LLM ngoài tổ chức; là giả định được đơn vị chấp
  nhận". §4.5: "Dữ liệu alert đi tới máy chủ DeepSeek: ghi thành giả định tường minh của đồ án."
- **Measured.** By construction: the adapter is the OpenAI SDK with DeepSeek's `base_url` (architecture
  §4.5), and the proposer's reasons cite the blocks `wazuh_raw_log`, `rule_description` and
  `correlation_samples` (§4.4). Volume: ⟦G2: proposer rows online over the lab period, from the "① online"
  section of docs/results/operations.md, and the live calls of the P7 runs, from
  docs/plan/tasks/P7/P7-T08.report.md⟧.
- **Source.** Architecture §9, §4.4, §4.5; `.env.example:52`.
- **Affects.** Any deployment claim; any data-protection statement.

### (xxviii) · Quote-check can be fooled by "evidence" planted in a log (R8)

- **Statement.** Gate step 3 only checks that a quoted reason is a substring (after NFKC and whitespace
  folding) of its named block, so text an attacker plants in a log can be quoted back as evidence.
  Architecture §9 R8 answers that the gate stands only on its structural conditions ("Cổng chỉ đứng vững
  nhờ điều kiện cấu trúc"). G3 measures this as the ASR: the share of the 40 adversarial targets that leave
  the gate as `false_positive`, for B3 (gate steps 1–3 only) and for B4 (as deployed). G3 is 40 fixtures
  generated from one base alert (rule 5503) by eight written patterns over five vectors (P6-T04). Vector 2
  (`data.srcuser`) never reaches a prompt, by construction, and is reported as blocked at the parser, not
  as a model or gate success (DEC-096, item 6).
- **Measured.** ⟦G2: ASR on G3 for B3 and B4, targets whose final verdict is false_positive out of 40,
  overall and per vector, from docs/results/adversarial.md⟧. B4's ASR is informative only where step 4 can
  keep `false_positive` at all. The fixtures are built so that its clauses hold (asset `medium`, `user1`
  not privileged, IoC `not_found`, the `ssh_brute_force` rule `sbf-1`; P6-T04 note 2). But while
  `kb/decision_tables/ssh_brute_force.yaml` is unsigned, the gate treats the table as absent (DEC-098,
  item 4), and step 4 then answers `needs_review` before any payload is read. The signing state at the
  run is (xi)'s placeholder.
- **Source.** Architecture §9 R8, §4.2 (steps 3 and 4), §6 (G3: 5 vectors × 8 samples; "kỳ vọng: B3 > 0,
  B4 ≈ 0 cho false_positive"); DEC-096; DEC-098; DEC-126 item 1 (B3 drops steps 4 and 6);
  `docs/plan/tasks/P6/P6-T04.prompt.md` notes 1–3; `docs/plan/tasks/P7/P7-tasks.md` §3 item 8.
- **Affects.** `docs/results/adversarial.md`; any claim that the gate resists injection.

### (vii) · One of the four risk addends is structurally dead: IoC reputation

- **Statement.** `conf/iocs.csv` carries no data rows, so every alert resolves `ioc_reputation =
  'not_found'`, which the risk formula scores 0. No `risk_score` this project reports is sensitive to IoC
  reputation, and the IoC path is never exercised end to end. This is a property of the estate, not a
  defect (DEC-083).
- **Measured.** DEC-083 (15/09, IA1803): `conf/iocs.csv` is 31 lines, of which the data rows are 0, and
  `iocs` loaded 0 rows; `soar/risk.py` scores `not_found` 0 and sums `asset + identity + ioc + occurrence`
  (at `82d0783`: `backend/app/soar/risk.py:22` and `:34`, by `grep -n`). After the 25/09 reset: ⟦G2: the row count of
  the iocs table in soc_dev, from a read-only select count(*) from iocs at P8-T06⟧.
- **Source.** DEC-083.
- **Affects.** Every `risk_score` figure; the four-addend risk formula; the G3 design, where IoC is
  `not_found` on every target (P6-T04, note 2).

### (xi) · The decision tables were drafted by an agent; signing them is the act of authorship

- **Statement.** The ten `kb/decision_tables/*.yaml` were drafted by an agent from the archive statistics
  behind G1 (item (ix)). They become policy only when the Owner and the advisor review, amend and sign
  them at one sitting, and that sitting is the act of authorship (DEC-098, a recorded deviation from
  `01-plan.md:77`). The chapter states it beside author-as-labeller and author-written detection:
  "decision tables drafted by an agent from archive statistics; reviewed, amended and signed by the Owner
  and the advisor on <date>." While `reviewed_by` is null the gate treats a table as absent
  (`decision_table_unreviewed:<category>`), so no drafted rule reaches ① unsigned. B1 is different:
  `kb.apply_table` ignores the review state on purpose, so B1 scores the tables in whatever state they are
  in at the run.
- **Measured.** At `82d0783`: all ten tables read `reviewed_by: null` and `reviewed_at: null`
  (`grep -H reviewed_by kb/decision_tables/*.yaml`), as DEC-107 recorded on 23/09; by `grep -n`, the
  gate's rule check returns `table_unreviewed` (`backend/app/tier1/triage.py:208-209`), the proposer's
  prompt omits an unreviewed table (`backend/app/llm/triage.py:389`, `:524`), and B1's `apply_table`
  ignores the flag (`backend/app/kb/lookup.py:6`, `:140`). B1's `prompt_version` is `kb:` plus the tables' hash
  (`docs/plan/tasks/P7/P7-tasks.md` §3 item 9). DEC-098 item 4 says the draft "cannot leak into ① or into
  P7's B1 arm before the sitting"; the code enforces the first half only. At the P7 run: ⟦G2: the date of
  the signing sitting, or "not held", and reviewed_by / reviewed_at of each of the ten tables at the
  commit P7-T08 ran from, from git⟧.
- **Source.** DEC-098 (items 1 and 4), DEC-107; `01-plan.md:77`; architecture §3.10, §4.2 step 4.
- **Affects.** B1 in `docs/results/ablation.md` (what its tables are); whether ① can keep a
  `false_positive` at all, on G2 and on G3 (xxviii); the claim that the tables are authored by the Owner
  and the advisor.

## D. The estate and the lab stack

### (i) · The host relocation: two moves, both deliberate

- **Statement.** The project's alert source changed twice. On 14/09 the Owner rebuilt IA1803's Wazuh as a
  Docker stack, deliberately (DEC-064, quoting the Owner: "Cố ý — tôi dựng lại lab thành Docker stack tối
  14/09"), and the original host installation with its `:9400` store is gone (DEC-061, DEC-065). On 22/09
  the project moved to ATTT-M1, where a second, independent Wazuh stack runs; no Wazuh data came across,
  and IA1803 is not reachable from it (DEC-106). G2 was generated on that second stack (DEC-111,
  DEC-112). The consequences for G1 are in (ix).
- **Measured.** 14/09 (DEC-064): manager container `8e3772d039ed`, indexer `005bea3363a9`, dashboard
  `af6ba99bcec7`; start times "indexer `19:55:57`, dashboard `19:56:04`, manager daemons
  `19:56:14`–`19:56:25`" (`ps -o lstart=`). `manager.name` became `wazuh.manager` in 2,699 of 2,699
  documents (08/09: `IA1803`) (DEC-063). The alert store moved from the dead `:9400` cluster to the Wazuh
  indexer, `INDEXER_URL=https://wazuh.indexer:19200` (DEC-065, DEC-070). 22/09 (DEC-106): the ATTT-M1
  stack's history begins 22/09; the four `INDEXER_*` values are unchanged but reach a different cluster;
  the live stream has "a 38 h 41 m hole" that nothing can backfill (last IA1803 alert
  `2026-09-20 17:00:11.278Z`, first ATTT-M1 alert `2026-09-22 07:41:28.868Z`, 0 rows between); IA1803's
  compose is "presumed down", not verified, because there is no network path to it. The lab agent is
  `attt-m1-lab` on ATTT-M1 itself (DEC-112).
- **Source.** DEC-061, DEC-063, DEC-064, DEC-065, DEC-070, DEC-106, DEC-111, DEC-112.
- **Affects.** Any reproducibility claim (no earlier corpus can be re-queried); the continuity of the
  live stream (the operating record starts 26/09); the description of the lab host in the method chapter.

### (ii) · (v) · The heartbeat: its mechanism, and liveness dated to a manager

- **Statement.** The pipeline heartbeat (`rule.id` `100999`) is a Wazuh `localfile` `full_command`
  stanza, not the `command` wodle the architecture review note anticipated
  (`phan-bien-kien-truc-v2-2026-09-04.md:169`, DEC-059). Its liveness has been measured
  on three managers in turn, with silences between them, so any liveness or uptime claim names the manager
  it was measured on.
- **Measured.**
  - IA1803, native manager, 08/09: three documents, at 16:27:51, 16:28:53 and 16:38:53, the third at
    exactly +600 s (DEC-059).
  - IA1803, rebuilt Docker manager: `100999` → 0 over 2 h 44 min on 14/09 (DEC-063); from 15/09
    05:16:48.595Z, six beats, with four intervals of 600.223 s · 600.252 s · 600.186 s · 600.227 s and
    one of 94.8 s that is a restart beat (DEC-068).
  - ATTT-M1: 0 `heartbeat` rows in `intake` since 20/09 17:08:01Z, because `local_rules.xml` had never
    been deployed on that manager (DEC-107). On 25/09 the marker `soc_heartbeat_2026-09-25T10:35:21Z`
    reached `intake` at 10:35:54Z, ending "a five-day silence" since `2026-09-20T17:07:28Z` (DEC-113,
    block 1). DEC-112 records the ATTT-M1 stanza at `ossec.conf:250-255` and calls it a "heartbeat wodle".
  - The lab period: ⟦G2: intake rows with outcome heartbeat over the lab period, from the "Intake and
    dedup" section of docs/results/operations.md⟧.
- **Source.** DEC-059, DEC-063, DEC-064, DEC-068, DEC-107, DEC-112, DEC-113.
- **Affects.** Any source-liveness or uptime figure; the pull-loop section of `docs/results/operations.md`.

### (iv) · The lab stack runs on demo credentials and demo certificates; where `soc_ro` lives

- **Statement.** The lab's Wazuh stack is the official `wazuh-docker` single-node 4.14.7 (DEC-069,
  DEC-112). On IA1803 it ran on the distribution's demo credentials and demo certificates, written in
  plaintext in a world-readable compose file: acceptable for a single-operator lab, and to be stated
  rather than discovered (DEC-070). On
  IA1803's stack the application's `soc_ro` account lived in the security index while
  `internal_users.yml` was bind-mounted from the host, so re-running `securityadmin.sh` from those files
  would have deleted the account (DEC-070).
- **Measured.** IA1803, 15/09: the compose file `/opt/wazuh/wazuh-docker/single-node/docker-compose.yml`
  is `root:root`, mode 644 (DEC-069); `soc_ro`'s write and security-index reads return 403 through the
  application's own `config.load()` values (DEC-070). ATTT-M1, 22/09: the certificate material was copied
  from IA1803's `single-node-config.tgz`, not regenerated (DEC-106). `soc_ro` there is a different,
  narrower account (roles `own_index`, `soc_ro_role`); `wazuh-monitoring-*`, `/.opendistro_security`,
  `_cat/indices` and a scratch-index write all return 403 (DEC-106). Not measured on ATTT-M1: whether its
  stack still runs the demo credentials, and where its `soc_ro` is stored.
- **Source.** DEC-069, DEC-070, DEC-106, DEC-112.
- **Affects.** The security posture of the lab the evaluation ran on; the method chapter's description of
  the stack.

### (xxix) · The indexer's trust anchor has been a demo CA, and TLS cannot tell the two stacks apart

- **Statement.** On IA1803's original alert store (OpenSearch on `:9400`) the root CA was OpenSearch's
  bundled demo CA, `CN = Example Com Inc. Root CA`, valid to 2034-02-17 (DEC-001). That cluster is gone,
  and the limitation survives as history (DEC-065). The current trust anchor is the `wazuh-docker` stack's
  own CA, part of the stack's demo certificates (DEC-070). ATTT-M1's stack carries the same CA, copied
  from IA1803, so "a successful TLS handshake proves nothing about which stack answered" (DEC-106).
- **Measured.** `conf/root-ca.pem`: `subject=OU=Wazuh, O=Wazuh, L=California`,
  `notBefore=Sep 14 12:47:26 2026 GMT`, `notAfter=Sep 11 12:47:26 2036 GMT`. The indexer's certificate:
  `CN=wazuh.indexer`, SAN `DNS:wazuh.indexer`, `notBefore=Sep 14 12:47:27 2026 GMT`, one second after the
  CA (DEC-106; DEC-070 recorded the same CA on 15/09).
- **Source.** DEC-001, DEC-065, DEC-070, DEC-106.
- **Affects.** Any claim that TLS verification identifies the alert source; the security-posture paragraph.

### (xiv) · The `auid` filter leaves a shell started by a service account unaudited

- **Statement.** Both `execve` audit rules on the lab host carry `-F auid>=1000 -F auid!=4294967295`, so
  only processes of a real login session are audited. A shell spawned by a service account or a daemon has
  no login uid, is not `execve`-audited, and so cannot be seen by rules `100301`–`100303`. The G2 scenarios
  do not exercise this gap, because every one is run from a login terminal (DEC-113;
  `docs/lab-scenarios.md` §0, rule 1).
- **Measured.** DEC-113 (25/09): before the filter, `100303` fired "about 123 times a minute" (measured
  120–125) on `attt-m1-lab` from 11:04 to 11:14 with no scenario running, from three MISP containers'
  healthchecks; after it, 0 in every minute from 11:15Z through 11:23Z, nine consecutive minutes. DEC-113's
  addendum states what is not measured: that `100301`–`100303` still fire end to end on a scenario under
  the filter. The first RW, DX and C2 windows measure it; see (xvii)'s placeholder.
- **Source.** DEC-113 (the decision, its cost bullet, and the addendum).
- **Affects.** The detection coverage of the three author-written rules; any claim about `ransomware`,
  `data_exfiltration` or `c2_beacon` detection outside login sessions.

## E. The product's own posture

### (xxx) · `user1` holds `sudo` but is recorded `is_privileged: false`

- **Statement.** `user1` is in group `sudo` but is recorded `is_privileged: false`, with `root` carrying
  the privileged case: the Owner's explicit call (DEC-012). Auto-close volume and the B1 comparison depend
  on reading a `sudo`-capable account as non-privileged, and the evaluation chapter says so in terms
  (DEC-012). On ATTT-M1, `user1` has sudo (DEC-112; "passwordless sudo", DEC-113), and every G2 scenario
  is run as `user1` from a login terminal (`docs/lab-scenarios.md` §0, rule 1).
- **Measured.** DEC-012 (05/09, IA1803): `conf/identities.yaml` as the Owner wrote it, `validate()` OK.
  DEC-083 (15/09): the
  `identities` table held 2 rows, `root|privileged|active` and `user1|not privileged|active`. After the
  25/09 reset: ⟦G2: is_privileged of username user1 in the identities table of soc_dev, from a read-only
  select at P8-T06⟧.
- **Source.** DEC-012, DEC-083, DEC-112, DEC-113.
- **Affects.** Gate step 4's identity clause and every B1 rule conditioned on `identity_privileged`, for
  G2's `user1` alerts; auto-close volume; the G3 design (P6-T04 note 2 relies on `user1` not privileged).

### (xxxi) · Append-only binds the application, not the table owner

- **Statement.** Migration 017's append-only protection binds `app_rw`, not whoever holds the owner's
  credentials. DEC-023 left two limitations: (a) `app_rw` keeps pre-existing grants on the legacy `soc`
  database, which only `postgres` can revoke and which making `app_rw` a LOGIN role exposes to the same
  password; (b) the owner's socket session is passwordless and can `DROP TRIGGER`. In DEC-023's words,
  "append-only is enforced against the application, not against whoever holds the `user1` OS account".
- **Measured.** Both measured on 05/09 on IA1803's native PostgreSQL cluster (DEC-023). PostgreSQL moved
  into docker compose on 20/09, with the triggers and grants carried over ("7 triggers · 75 grants —
  identical", the Owner's cutover figures in DEC-105). ATTT-M1 has no native cluster (`pg_lsclusters` → 0
  clusters; DEC-107). Not re-measured on the container: (a)'s legacy grants and (b)'s owner session.
- **Source.** DEC-023 (its Supersedes line), DEC-024, DEC-105, DEC-107.
- **Affects.** The append-only claim for `audit_events`, `llm_runs` and `intake`.

### (xxxii) · DEC-024(b): the three-way delete result, verbatim

- **Statement.** On one table carrying both layers exactly as migration 017 builds them, three deletes
  were run (DEC-024(b)). The privilege layer no longer binds the owner; the trigger still does, and
  defeating it takes one deliberately named statement, so "the owner cannot breach append-only by
  accident".
- **Measured.** Verbatim from DEC-024(b), 05/09, IA1803's native cluster:
  1. as `app_rw` → `permission denied for table t`
  2. as `user1`, **superuser, no trick** → `append-only table: t is immutable (DELETE)` — **the trigger fires**
  3. as `user1` with an explicit `SET session_replication_role = 'replica'` → `DELETE 3`, 0 rows left
- **Source.** DEC-024(b).
- **Affects.** The append-only claim; together with (xxxi), what an operator holding the owner role can do.

### (vi) · A rejection is invisible to the job table

- **Statement.** When the parser rejects an intake row, the pipeline writes it to `rejected_alerts` and
  returns normally, so the row's job records `succeeded`. `failed = 0` in `jobs` is therefore not evidence
  that nothing was dropped; only counting `rejected_alerts` separately shows the loss (DEC-079).
- **Measured.** By construction: `soar/pipeline.py:81-83` routes a rejection through `_reject` and returns
  normally rather than raising (DEC-079); at `82d0783` the `_reject` call and its `return` are
  `backend/app/soar/pipeline.py:82-83` (`grep -n _reject`). It was measured once, on the G1 replay; the count and its
  denominator are in (ix). Over the lab period: ⟦G2: rejected_alerts rows over the lab period, from the
  "Intake and dedup" section of docs/results/operations.md⟧.
- **Source.** DEC-079; DEC-129 item 6 (keeps the 23/09 INBOX correction as history for (vi)).
- **Affects.** Any per-alert denominator; the intake figures of `docs/results/operations.md`.

### (xxxiii) · No HA, no hash-chain audit, no MFA

- **Statement.** Architecture §9: "Không HA, không hash-chain audit, không MFA; nêu như việc tiếp theo."
  The system is one database, one worker and one application instance. `audit_events` is append-only by
  privilege and trigger (migration 017) but carries no hash chain. The accounts log in with a password and
  no second factor.
- **Measured.** Not measured: these are properties by construction (architecture §9). One container each
  for the database, the application and the worker, `ai_support_soc_1_2-db-1`, `-app-1` and `-worker-1`
  (DEC-105); four password accounts, re-seeded on 25/09 (DEC-112; `users` 4 after the reset, DEC-113).
- **Source.** Architecture §9; DEC-023, DEC-105, DEC-112, DEC-113.
- **Affects.** Any availability, tamper-evidence or authentication claim.

### (xxxiv) · A partial database password reached an agent transcript; the Makefile mask stops at the first `@`

- **Statement.** During development, a truncated prefix of the `soc` role's password appeared once in a
  Coder session's output, printed by a failing assertion that rendered the `Config` object. It is in no
  file and no commit (DEC-122, item 6). The `Makefile`'s `test-db` mask stops at the first `@`, so a
  password containing `@` is partly printed to the terminal: a second route to the same leak (DEC-123,
  item 3). A raw DSN among a failing test's arguments is a third (DEC-130, item 4).
- **Measured.** DEC-122 item 6 (25/09), DEC-123 item 3 (26/09), DEC-130 item 4 (the `conftest.py` DSN
  fixtures, measured by P5-T12's Coder). Rotation: ⟦G2: rotation of the soc role's password, done with
  its date or pending, from the Owner at P8-T06⟧. The fixes: ⟦G2: whether P8-T07 (the whole-password mask
  and the redacted DSN repr) is merged, from STATE.md at P8-T06⟧.
- **Source.** DEC-122, DEC-123, DEC-130; `docs/plan/tasks/P8/P8-tasks.md` §3 rule 7.
- **Affects.** The development process's security record; nothing in the evaluation.

### (xxxv) · The database and the application answer on every interface of the lab host

- **Statement.** The compose stack publishes PostgreSQL on `0.0.0.0:55432` and the application (plain
  HTTP, session cookie not `Secure`) on `0.0.0.0:8000`, where `docs/db-docker.md` says `127.0.0.1`.
  Docker's published ports bypass a host firewall (DEC-114). On the same host `/home/user1` has mode 777,
  and the host has a second local account (DEC-113).
- **Measured.** `docker ps` on 25/09 (DEC-114). `/home/user1` mode 777 (DEC-113), still 777 on 25/09
  (DEC-114). At close-out: ⟦G2: the host addresses the db and app ports are published on at P8-T06,
  127.0.0.1 or 0.0.0.0, from docker ps⟧.
- **Source.** DEC-114, DEC-113; DEC-122 item 6 (the recommended bind).
- **Affects.** The security posture of the deployment the evaluation ran on; the exposure behind (xxxiv).

### (xxxvi) · A database dump with the accounts' password hashes is tracked on the public remote

- **Statement.** `backups/latest.dump`, holding real alerts and the accounts' argon2id hashes, is tracked
  in git on a public remote, by the Owner's decision (DEC-105). The four accounts were re-seeded with new
  passwords on 25/09 (DEC-112; `users` 4 after the reset, DEC-113). That makes the published hashes
  useless against the new database, but it does not close the exposure (DEC-112).
- **Measured.** 32,566,681 bytes when committed (DEC-105, 20/09). ⟦G2: the outcome of the
  secrets-remediation run for the published dump, from the Owner at P8-T06⟧.
- **Source.** DEC-105, DEC-112, DEC-113, DEC-130 items 5 and 6.
- **Affects.** The development process's data-handling record.

### (xxxvii) · Multi-worker operation is not validated

- **Statement.** In the 25/09 load test, one of three 4-worker runs failed 2 of 5,000 `pipeline` jobs on
  the check constraint `ck_alerts_last_seen_khong_lui`, classified permanent. The root cause was not found,
  and the failure did not reproduce with one worker. DEC-111 asks for "a card before any multi-worker
  deployment", and the deployment runs one worker. The four-worker throughput figure carries this defect.
- **Measured.** DEC-111 (load test, 25/09, 5,000 real intake lines into a throwaway database): one worker
  → 5,000 alerts in 33.2 s = 150/s; four workers → 13.9–14.1 s = ≈ 355/s (three runs); 2 of 5,000 failed
  in one four-worker run and 0/10,000 in the two re-runs. One worker container (DEC-105).
- **Source.** DEC-111; DEC-105.
- **Affects.** Any throughput or scalability claim for intake and dedup.

## F. What the thesis must not claim

### (xxxviii) · Only Wazuh, no detection; no "MTTD", no "ATT&CK coverage"

- **Statement.** Architecture §9: “Chỉ Wazuh, không phát hiện; không dùng "MTTD" hay "độ phủ ATT&CK"
  trong luận điểm.” The product triages Wazuh alerts and detects nothing itself. The three local rules of
  (xvii) were written for the lab (DEC-056) and run on the Wazuh manager, not in the product.
- **Measured.** Not measured: this is a scope rule, not a quantity (architecture §9).
- **Source.** Architecture §9; DEC-056.
- **Affects.** Every chapter's claims; the terms "MTTD" and "ATT&CK coverage".

### (xxxix) · No estate rate from G2

- **Statement.** No rate computed from G2 is an estate rate, of any estate (DEC-111). The sentence is
  written into `eval/gold_coverage.md` (`eval/build_gold.py:139-142`), and every `docs/results` file opens
  with the DEC-111 caveat (DEC-125, item 1).
- **Measured.** By construction; see (xii) and (xix).
- **Source.** DEC-111, DEC-125.
- **Affects.** Every rate in `docs/results/ablation.md`, `docs/results/per_category.md` and
  `docs/results/adversarial.md`.

### (xl) · No controlled online result

- **Statement.** The online period is an operating record, not an experiment. Architecture §6: "Thí điểm
  trực tuyến 7 ngày là mô tả, không phải kiểm định." The pilot that would have supplied even the
  descriptive decision metrics did not run (xiii). No online figure is presented as a tested effect.
- **Measured.** Not measured; see (xiii) and (xxv).
- **Source.** Architecture §6; DEC-116, DEC-129.
- **Affects.** `docs/results/operations.md` and the chapter built on it.

### (xli) · The v1 system's "measured" numbers were on synthetic data

- **Statement.** Architecture §9: “Mọi số "đo được" của tài liệu v1 là trên dữ liệu tổng hợp; bản v3 thay
  bằng G1/G2/G3 thật.” G1 is void (DEC-111), so v3's measured numbers come from G2 and G3 only, and no v1
  figure is cited as measured.
- **Measured.** Not measured: this is a citation rule, not a quantity.
- **Source.** Architecture §9; DEC-111.
- **Affects.** Any comparison with the v1 system.
