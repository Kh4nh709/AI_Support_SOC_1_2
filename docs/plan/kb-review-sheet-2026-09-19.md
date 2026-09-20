# KB review sheet — the ten decision tables, drafted 19/09/2026 for the Owner + advisor sitting

**What this is.** The working document for the 90-minute sitting that reviews, amends and signs
`kb/decision_tables/*.yaml`. Drafted by the KB Drafter under
`docs/plan/prompts/kb-drafter-run-2026-09-19.md`; branch `kb/decision-tables-draft` (cut from `main`
@ `6ffbecc`). Nothing in the tables is policy until `reviewed_by` / `reviewed_at` are filled by the two
humans — §15 has the exact command. How the numbers were produced: `docs/plan/kb-draft-report-2026-09-19.md`.

**Budget.** §1–§3 are the three tables that carry the whole B1 number (G1 = 300 clusters, DEC-086:
`ssh_brute_force` 115 · `suspicious_login` 25 · `privilege_escalation` 40 · `unknown` 120, no table by
design) — spend ~15 min each. §4–§10 serve the lab (22–24/09) and the pilot — ~4 min each. §11–§13 are
proposals (~10 min). §14–§15 are mechanics (~5 min).

## 0 · The contract, in six lines (from `backend/app/kb/lookup.py`)

1. **Facts a rule can see:** `severity` (derived from `rule_level`: ≥12 critical · ≥8 high · ≥5 medium · else
   low, DEC-053), `rule_level`, `ioc_reputation` ∈ {malicious, suspicious, clean, not_found, skipped},
   `asset_criticality` ∈ {high, medium, low, unknown}, `identity_privileged` ∈ {"true", "false", "unknown"}
   (strings), `occurrence_count`. **Nothing else** — not the rule id, not the host name, not the account.
2. **Actions:** `false_positive` · `needs_review` · `escalate`. `false_positive` is the only outcome that
   lets a cluster leave the queue without a human.
3. **Evaluation:** `apply_table` returns the **first rule in file order** whose every condition holds.
4. **Consistency:** `check_consistency` walks 2,520 grid points; any two rules with **different** actions
   that both hold at one point is a contradiction (the test fails). Same-action overlap is fine. So order
   never changes an outcome — it only picks which same-action id is reported — and every draft below is
   already disjoint; a flip of one rule's `then` is safe exactly where the sheet says so.
5. **No match → `needs_review`** (B1, `prompts/P7.md:17`). A table does not have to cover the grid; the
   explicit `needs_review` rules below exist so the sitting *sees* the large groups they decide, not because
   the code needs them.
6. **What an FP rule is, in the seven lab/pilot tables.** The playbooks' §3 branches (quarantine folder, vendor IP range, approved ticket …) are not table facts. There the `<abbr>-1` rule is the *structural precondition* under which ① may say `false_positive` at all (architecture §4: *false_positive only on structural evidence the attacker cannot steer*); the branches are the text ① reads. Judge those rules as preconditions, not as detectors.
7. **Hard blocks run before the table** (`ingest/autoclose.py:244-267`, gate step 4 `security/gate.py:138-165`):
   severity critical · asset `high` · asset absent (`unknown`) · identity `"true"` · IoC malicious/suspicious.
   A `false_positive` rule that admits any of those is wrong on its face; none of the drafts does.

**How each fact is derived on this estate** (so the sitting can read the numbers): `asset_criticality` from
`conf/inventory.yaml` — `IA1803` (the manager) **high**, `user1-IA1803` (lab workstation) **medium**,
`DESKTOP-MIRSO17` unlisted → **unknown** (DEC-058). `identity_privileged` from `conf/identities.yaml` over
`data.dstuser` ∥ `data.srcuser` — `user1` → `"false"`, `root` → `"true"`, any other or absent name →
`"unknown"`. `ioc_reputation`: `conf/iocs.csv` is empty by design, so a public srcip/dstip → `not_found`,
a private/loopback/absent IP → `skipped`; `malicious`/`suspicious` cannot occur in G1 at all.
`occurrence_count` = the fold's cluster size.

**The fold** (`python3 scripts/measure_clusters.py --archive /home/user1/archive/alerts-2026-08-08_09-07.jsonl --routes`):
92,030 alerts → 3,070 clusters; `unknown` 1,820 · `ssh_brute_force` 968 · `suspicious_login` 174 ·
`privilege_escalation` 108; seven playbook categories at zero. DEC-053 removes 67 loopback
`ssh_brute_force` clusters (662 alerts) from the G1 pool → 901 for that category. `IA1803` 1,986 clusters ·
`user1-IA1803` 1,061 · `DESKTOP-MIRSO17` 23.

---

## 1 · `ssh_brute_force` — 968 clusters (G1 pool 901; sampled 115 = 1 crit · 11 high · 95 med · 8 low)

| id | if | then | evidence (fold) |
|---|---|---|---|
| `sbf-1` | severity low/medium · ioc not_found/clean · asset low/medium · identity "false" · occurrence < 50 | **false_positive** | §3.10 example verbatim; playbook :20, :22, :36. **0 clusters** — every user1-targeted failure (25) is `skipped` or on `IA1803` |
| `sbf-2` | ioc malicious/suspicious | escalate | playbook :28. 0 (IoC list empty); G2/pilot |
| `sbf-3` | rule_level ≥ 12 | escalate | playbook :26 (success after failures). 11 (100101 ×7, 40112 ×4); 1 in the pool |
| `sbf-4` | 8 ≤ rule_level < 12 | escalate | playbook :27, :14; runbook :246 expects escalate. 39 (5551 ×12, 5763 ×12, 5712 ×11, 2502 ×4), all `user1-IA1803`; 11 in the pool |
| `sbf-5` | severity low/medium · ioc not bad · identity "unknown" | needs_review | playbook :8, :20 — FP needs a REAL account. **543** (514 in pool): 5710 ×368, 2501 ×66, 5762 ×35, 5740 ×33, 5503 ×31, 5760 ×10 |
| `sbf-6` | severity low/medium · ioc not bad · identity "true" | needs_review | playbook :35 (privileged target → raise). **350**: 5760 ×322, 5503 ×27, 5762 ×1 — all `root` |

Default (no rule): 25 clusters (5503 ×18, 5760 ×4, 5762 ×3 — user1-targeted, `skipped` or on `IA1803`) → needs_review.

**B1 on this category, G1 pool of 901:** escalate 12 (1.3 %) · false_positive 0 · needs_review 889.

Questions the draft could not settle:

- **Q1 — `sbf-1` never fires.** The §3.10 rule requires `ioc ∈ {not_found, clean}`; a real user's mistyped
  password on this estate arrives as PAM `5503` with no srcip, or from the LAN `172.25.25.28/.29` — both
  `skipped`. Playbook :36 (*lookup missing → not harmless*) argues for keeping `skipped` out; :9 and :21
  (*internal brute force is usually a broken script or expired credentials; internal srcip matching a known
  app server → FP*) argue for admitting it. Admitting `skipped` catches **14** clusters (5503 ×8, 5760 ×3,
  5762 ×3, all user1 on `user1-IA1803`). With the draft as-is, **B1 never says false_positive on
  `ssh_brute_force` in G1** and `precision(false_positive)` is undefined for the category.
  Decision: ☐ keep §3.10 verbatim  ☐ add `skipped` to `sbf-1`'s ioc list (stays grid-consistent).
- **Q2 — `sbf-5`, the largest group in G1 (514 of 901).** `5710` ×358 in the pool is an Internet campaign
  against `admin1`/`admin`/`namnguyen` — accounts that do not exist (164 of the 543 carry no account name at all:
  2501/5740/5503 without a user, and 5762's `by` parser artefact; 68 are level-4 connection resets). Playbook §3 makes a *real* account a
  precondition of the FP branch, so the draft says needs_review. The alternative reading — "external +
  non-existent account + medium asset + no success = Internet background noise" — would need an FP rule on
  identity `"unknown"`, which the gate permits (only `"true"` is blocked) but the playbook does not say.
  Playbook §4 :27 leans the *other* way (dictionary order → REAL); the draft stops at needs_review because 514
  escalates would be 57 % of the pool.
  Decision: ☐ needs_review (draft)  ☐ carve an FP rule for identity "unknown" · ioc not_found · asset
  low/medium · occurrence < N (choose N; note `5710` clusters reach 1,000)  ☐ escalate (per :27).
- **Q3 — `sbf-6`, `root` targeted (350 clusters, 39 % of the pool).** Playbook :35 says *raise the level
  even without a success*. The draft raises from FP-eligible to needs_review, not to escalate: root's
  password login is locked (`conf/identities.yaml:16`), so the class cannot succeed, and 350 escalates
  would swamp `recall(escalate)`'s denominator. Flipping `then: escalate` is grid-safe (disjoint from
  `sbf-1` by identity, from `sbf-5` by identity).
  Decision: ☐ needs_review (draft)  ☐ escalate.
- **Q4 — `sbf-4` escalates the high band unconditionally** (39 clusters, all level-10 frequency rules on
  the lab workstation; 25 target non-existent accounts, 12 target `user1`, 2 target `root`). The runbook's
  expected label for the burst is escalate (:246); the playbook's :27 supports it for dictionary attacks.
  A narrower variant — escalate only identity `"true"`, needs_review otherwise — is one condition away.
  Note for the lab: the burst's *per-attempt* rules (runbook :210 — `5503`/`5760`/`5710`, level 5, `user1`,
  loopback → `skipped`) match **no rule** and get needs_review; only if the frequency rule `5712`/`5763`
  fires (:261-264) does the burst reach `sbf-4`.
  Decision: ☐ escalate all (draft)  ☐ narrow to identity "true".

`[ ] signed — ssh_brute_force` · amendments: ______________________________________________

---

## 2 · `suspicious_login` — 174 clusters, all level 3 (low); sampled 25, all low

Only two stock rules reach this category here — `5501` "PAM: Login session opened" ×94 and `5715` "sshd:
authentication success" ×80 — so every live cluster is a *plain successful login*
(`docs/lab-scenarios.md:303-306` says so in as many words). The playbook's "suspicious" is not something
the stock rules detect.

| id | if | then | evidence (fold) |
|---|---|---|---|
| `sul-1` | severity low/medium · ioc not_found/clean/**skipped** · asset low/medium · identity "false" · occurrence < 50 | **false_positive** | playbook :21, :22, :23. **48** — all `user1` on `user1-IA1803`: 5715 ×30 (16 from VN ISP ranges = not_found, 14 from the LAN = skipped), 5501 ×18 (no IP) |
| `sul-2` | ioc malicious/suspicious | escalate | playbook :27. 0 |
| `sul-3` | rule_level ≥ 12 | escalate | playbook :29. 0 — `40112` resolves `ssh_brute_force` (runbook :325) |
| `sul-4` | severity low/medium · ioc not bad · identity "true" | needs_review | playbook :34. **32** — 5501 for `root`: `IA1803` 22 / `user1-IA1803` 10; occurrence 1–49 |
| `sul-5` | severity low/medium · ioc not bad · asset high/unknown | needs_review | playbook :35, DEC-034, DEC-058. 115 on `IA1803` (user1 ×91, root ×22, other ×2); reported on **93** (the 22 root go to `sul-4` first) |

Default: 1 cluster (5501, a service account on `user1-IA1803`) → needs_review.

**B1 on this category (174):** false_positive 48 (27.6 %) · escalate 0 · needs_review 126.

- **Q1 — `sul-1` admits `skipped` (a deviation from the §3.10 pattern).** This playbook has no
  *lookup-missing → not harmless* clause; :23 (*service account logging in from the host it runs on*) is a
  local-origin FP branch (though it names a *service* account; the 32 admitted `skipped` clusters are the human
  `user1`). Without `skipped` the rule catches **16** (the external-ISP logins only), not 48. On those 16, :21
  (remote-work user, domestic range) and :27 (*from a place where the unit has no activity*) read the same
  fact set in opposite directions — the grid has no geography.
  Decision: ☐ keep `skipped` (draft)  ☐ remove it.
- **Q2 — `sul-4`: :34 says *"coi như mức cao cho tới khi loại trừ được"*.** The draft reads "until
  excluded" as needs_review (an analyst does the excluding). The 32 clusters are `root` PAM sessions with
  occurrence 1–49 (12 of them ≥ 10) — the shape of sudo/cron sessions, not of a person. Flipping to escalate is grid-safe against `sul-1`
  but **overlaps `sul-5` at (identity true, asset high)** — flip both or neither.
  Decision: ☐ needs_review (draft)  ☐ escalate (then `sul-5` must also be escalate, or exclude identity "true").
- **Q3 — `sul-5`: :35 says one odd login on a high asset is *"đủ để mở case"*.** 115 of 174 clusters are on
  the manager, 91 of them `user1`'s own logins. The rule fires on every login, not on odd ones, so the draft
  says needs_review. Same coupling with `sul-4` as above.
  Decision: ☐ needs_review (draft)  ☐ escalate.
- **Q4 — the gold vocabulary.** Labellers choose among `false_positive` / `benign` / `escalate`
  (`prompts/P7.md:18`). A legitimate login is arguably `benign` (real, allowed), not `false_positive`
  (rule wrong). `sul-1` follows the playbook's own heading ("Nghiêng về FALSE POSITIVE khi"). Nothing to
  change in the table — but the sitting should know B1's `false_positive` will be scored against gold
  `benign` on most of these 48.

`[ ] signed — suspicious_login` · amendments: ______________________________________________

---

## 3 · `privilege_escalation` — 108 clusters; sampled 40 = 0 crit · 31 high · 1 med · 8 low

Every cluster is IP-less (`ioc = skipped` on 108/108). Sudo alerts name the **target** account
(`data.dstuser = root` → identity `"true"`); rootcheck/auditd alerts name nobody (`"unknown"`). No
cluster has identity `"false"`.

| id | if | then | evidence (fold) |
|---|---|---|---|
| `pre-1` | severity low/medium · ioc not_found/clean/skipped · asset low/medium · identity "false" · occurrence < 50 | **false_positive** | playbook :21–:23. **0** — structurally: no cluster has identity "false". The lab's benign twin `sudo true` (runbook :402-406, rule 5402 → root) cannot reach it either |
| `pre-2` | ioc malicious/suspicious | escalate | §3.10 pattern; :29 nearest. 0, unreachable (no IP) — may be struck |
| `pre-3` | rule_level ≥ 12 | escalate | §3.10 pattern; :32. 0 — max level here is 11 |
| `pre-4` | 8 ≤ rule_level < 12 | escalate | playbook :28, :37; DEC-053/086. **31** = 100205 ×18 (level 10, archive-era local rule, `IA1803`) · 521 ×11 (level 11 rootkit, `IA1803`) · 5404 ×1 · 513 ×1 (`DESKTOP-MIRSO17`) |
| `pre-5` | severity low/medium · ioc not bad · identity "true" | needs_review | DEC-055 Q1 through the facts. **63** = 5402 ×57 (704 alerts; `IA1803` 38 / `user1-IA1803` 19) · 5403 ×5 · 5401 ×1 |

Default: 14 clusters (510 ×10 rootcheck level 7 on `IA1803`; 5407 ×4 sudo by service accounts) → needs_review.

**B1 on this category (108):** escalate 31 (28.7 %) · false_positive 0 · needs_review 77. All 31 escalates
are in G1 (DEC-086 takes every crit+high).

- **Q1 — `pre-1` is unreachable on this estate**, and so is any FP for `sudo`: a successful sudo names
  `root`, `root` is `"true"`, and `"true"` is a G8′ hard block (`autoclose.py:263`) that gate step 4
  repeats. The playbook (:24 *unfiltered sudo is a rule to fix*, :36 *already-privileged → may be normal*)
  leans FP for exactly this class. The table cannot express that without being wrong on its face; the
  lever is elsewhere — see PROPOSAL §11. Decision on the table: ☐ keep `pre-1` as the pattern  ☐ strike it.
- **Q2 — `pre-4` escalates `100205` (18 of the 31).** It is "Audit: privilege change via
  `/usr/libexec/gdm-session-worker` by auid" — the desktop login manager's setuid, level 10 as authored, an
  archive-era local rule that no longer exists on the rebuilt manager. Playbook :22 (*automation running
  privileged by design*) reads it as FP at least as well as :28 reads it as real. It **is** separable from the
  rootkit rule `521` by level (10 vs 11) — the only fact that differs.
  Decision: ☐ escalate the band (draft)  ☐ narrow `pre-4` to `rule_level_gte: 11` (keeps 521 ×11, drops 100205 ×18, 5404, 513).
- **Q3 — the lab's attack is level 5.** `5401` "Failed attempt to run sudo" (runbook :361, expected label
  escalate) is medium; B1 answers needs_review for it unless the medium band escalates, which would also
  escalate `510` and the one `5401` in the archive. Decision: ☐ accept (B1 misses the lab attack by design)
  ☐ add a medium-band escalate for asset high only (:37) — note the lab host is medium, so that does not help the lab.

`[ ] signed — privilege_escalation` · amendments: ______________________________________________

---

## 4 · `ransomware` — 0 archive clusters; lab rule `100301` level 12

| id | if | then | evidence |
|---|---|---|---|
| `ran-1` | severity low/medium · ioc not bad | needs_review | playbook :25 (*never close silently, even a likely FP*), :3. **Replaces the §3.10 FP rule** |
| `ran-2` | ioc malicious/suspicious | escalate | :32, :33 nearest; no IoC line of its own |
| `ran-3` | rule_level ≥ 12 | escalate | runbook :565-567 — `100301`, level 12, expected escalate; playbook :29–:31, :39 |
| `ran-4` | 8 ≤ rule_level < 12 | escalate | playbook :3 (lowest threshold of all types), :37 |

- **Q1 — no `false_positive` rule at all.** Drafted from :25. The benign twin (interactive `openssl enc`,
  runbook :571-583) fires no rule, so nothing is lost in the lab. Decision: ☐ no FP rule (draft)  ☐ restore the §3.10 FP rule.
- **Q2 — `ran-4`** escalates a band no rule occupies today. Decision: ☐ keep  ☐ strike.
- **Q3 — :37 is asset-scoped** (*any file or DB server hit → highest level*) and is not encoded: `ran-1` leaves a
  low/medium ransomware alert on a `high` asset at needs_review. Adding `{severity: [low, medium],
  asset_criticality: [high]} → escalate` requires narrowing `ran-1` to asset low/medium/unknown first (it has
  no asset term today, so the two would overlap). Decision: ☐ leave (draft)  ☐ add it and narrow `ran-1`.

`[ ] signed — ransomware` · amendments: ______________________________________________

---

## 5 · `data_exfiltration` — 0 archive clusters; lab rule `100302` level 10

| id | if | then | evidence |
|---|---|---|---|
| `dex-1` | §3.10 FP pattern (ioc not_found/clean) | false_positive | playbook :21, :22, :24; `skipped` kept out because :8/:15 make the destination the question |
| `dex-2` | ioc malicious/suspicious | escalate | :15, :30 |
| `dex-3` | rule_level ≥ 12 | escalate | :36 |
| `dex-4` | 8 ≤ rule_level < 12 | escalate | runbook :631-633 — `100302`, level 10, expected escalate; playbook :29, :36, :38 |

- **Q1 — `dex-1` and the lab.** `100302`'s auditd records carry no IP → `skipped`, and level 10 → `dex-4`;
  the FP rule is never reached in the lab (the benign download fires nothing). `skipped` also covers :24's
  approved *internal* destination (a private IP is skipped, `lookups.py:77-92`). Decision: ☐ keep as pattern  ☐ admit `skipped`.
- **Q2 — `dex-4` follows the runbook (:633 escalate), against the rule's own docstring.**
  `conf/local_rules.xml:113-114`: *"Level 10 = high … Not critical: a single upload is a lead an analyst
  confirms, not a confirmed incident"*; playbook :23 leans FP for a confirmable bulk upload. needs_review is
  the docstring's reading; escalate is the runbook's expected label. Decision: ☐ escalate (draft)  ☐ needs_review.

`[ ] signed — data_exfiltration` · amendments: ______________________________________________

---

## 6 · `c2_beacon` — 0 archive clusters; lab rule `100303` level 12

| id | if | then | evidence |
|---|---|---|---|
| `c2b-1` | §3.10 FP pattern | false_positive | playbook :21–:24; :37 keeps `skipped` out |
| `c2b-2` | ioc malicious/suspicious | escalate | :15, :29 |
| `c2b-3` | rule_level ≥ 12 | escalate | runbook :695-697 — `100303`, level 12, expected escalate; playbook :28, :30, :36 |
| `c2b-4` | severity low/medium · ioc skipped | needs_review | :37 written as an explicit floor |

- **Q1 — `c2b-4`** is the only rule that *names* :37; it changes no outcome (needs_review is the default).
  Decision: ☐ keep (visible)  ☐ strike (implicit).
- **Q2 — :36 (*privileged host or sensitive data → raise at once*) has no rule.** A low/medium beacon alert on
  a `high` asset or with identity `"true"` gets the default needs_review. `{severity: [low, medium],
  asset_criticality: [high]} → escalate` would be disjoint from `c2b-1` (asset) but overlaps `c2b-4`, which would
  then need to exclude asset high. Decision: ☐ leave (draft)  ☐ add it.

`[ ] signed — c2_beacon` · amendments: ______________________________________________

---

## 7 · `malware` — 0 archive clusters; lab rule `52502` level 8

| id | if | then | evidence |
|---|---|---|---|
| `mal-1` | §3.10 FP pattern | false_positive | playbook :21, :22, :24 |
| `mal-2` | ioc malicious/suspicious | escalate | :15, :30 |
| `mal-3` | rule_level ≥ 12 | escalate | :36 (written `crown_jewel` — P3-T12, §14), :38 |
| `mal-4` | 8 ≤ rule_level < 12 | escalate | runbook :510-512 — `52502` "ClamAV: Virus detected", level 8 (`docs/wazuh-manager-changes.md:278`), expected escalate; playbook :28, :37 |

- **Q1 — `mal-4` escalates every high-band malware alert**, including an AV *detection at scan time* (:7
  asks "on disk or running?"; :21 says a file already in quarantine is FP). The table cannot tell the two
  apart. Decision: ☐ escalate (draft)  ☐ needs_review for the band.

`[ ] signed — malware` · amendments: ______________________________________________

---

## 8 · `recon` — 0 archive clusters; lab expects `5706` (per probe), `5731` / `40601` (threshold)

In this category `skipped` = **private srcip = internal scanner**, the dangerous case (:7, :28);
`not_found` = external = Internet background noise (:23).

| id | if | then | evidence |
|---|---|---|---|
| `rec-1` | severity low/medium · ioc not_found/clean · asset low/medium · identity "false"/**"unknown"** · occurrence < 50 | false_positive | playbook :23, :21, :22. Identity admits "unknown" because scan alerts carry no user |
| `rec-2` | ioc malicious/suspicious | escalate | :38 only; kept as G8′ counterpart |
| `rec-3` | rule_level ≥ 12 | escalate | :31 |
| `rec-4` | 8 ≤ rule_level < 12 | escalate | runbook :449-461 — the threshold rules, expected escalate; playbook :28, :29. **Levels of 5731/40601 unverified in this repo** |
| `rec-5` | severity low/medium · ioc skipped | needs_review | :7, :28, :36, :38 — an internal low/medium scan never leaves the queue on its own; the single self-scan (:463-470) lands here |

- **Q1 — identity "unknown" in an FP rule.** Scan alerts have no user, so `"false"` alone would make
  `rec-1` unreachable. The gate permits FP on "unknown". Decision: ☐ keep  ☐ restrict to "false" (FP then never fires for recon).
- **Q2 — the levels of `5731` / `40601` are not recorded anywhere in the repo** and the archive has 0 hits.
  `rec-4` assumes the high band, as Wazuh frequency rules usually are. Confirm from the lab's per-window
  `by_rule` breakdown (runbook §2 step 5) before signing, or sign with the assumption written in.

`[ ] signed — recon` · amendments: ______________________________________________

---

## 9 · `web_attack` — 0 clusters after DEC-055; no lab scenario (runbook :823-825)

| id | if | then | evidence |
|---|---|---|---|
| `web-1` | §3.10 FP pattern, identity "false"/"unknown" | false_positive | playbook :21–:23; :37 keeps `skipped` out; access-log alerts name no user |
| `web-2` | ioc malicious/suspicious | escalate | :16 |
| `web-3` | rule_level ≥ 12 | escalate | :28, :30 |
| `web-4` | 8 ≤ rule_level < 12 · asset **high** | escalate | :35 + DEC-034; restricted to asset high because :7 says mass 4xx is a scanner missing |
| `web-5` | severity low/medium · ioc skipped | needs_review | :37 |

- **Q1 — identity "unknown" in `web-1`**, same reasoning as recon. ☐ keep  ☐ restrict.
- **Q2 — `web-4` only on asset high.** The alternative (whole band) escalates every "multiple web attacks"
  frequency rule (31151–31153, level 10) on any host. ☐ asset high only (draft)  ☐ whole band.

`[ ] signed — web_attack` · amendments: ______________________________________________

---

## 10 · `policy_violation` — no signal at all (DEC-057; runbook :826-827)

The playbook's usual conclusion is `concluded_policy_violation` (:3) — neither incident nor FP — which the
three actions cannot express; needs_review is the closest.

| id | if | then | evidence |
|---|---|---|---|
| `pol-1` | §3.10 FP pattern | false_positive | playbook :21–:23; :25 (*FP means the rule is wrong*) |
| `pol-2` | ioc malicious/suspicious | escalate | :32 nearest; may be struck |
| `pol-3` | rule_level ≥ 12 | escalate | :29 — `100112` "audit log cleared" (level 12) is this shape, and resolves `unknown` since DEC-055 |
| `pol-4` | 8 ≤ rule_level < 12 · asset high | escalate | :37 + DEC-034 |
| `pol-5` | 8 ≤ rule_level < 12 · identity "true" | escalate | :36, :30 |

- **Q1** — a table for a category nothing reaches: ☐ sign as drafted (harmless, documents intent)  ☐ sign
  with `pol-2` struck.
- **Q2** — `pol-4`/`pol-5` both escalate; the band without either condition is needs_review. ☐ keep  ☐ whole band.

`[ ] signed — policy_violation` · amendments: ______________________________________________

---

## 11 · PROPOSAL — DEC-055 Q1: rule `5402` (*successful sudo to ROOT*, level 3)

**The numbers.** 57 clusters = 704 alerts, `IA1803` 38 / `user1-IA1803` 19; `data.dstuser = root` on all 57
(→ identity `"true"`); `srcuser` is `user1` on 42 clusters (332 alerts), `root` on 14 (371 alerts — sudo from an already-root context), `art` on 1; occurrence 1–206 (20 clusters of 1, 24 of 2–9, 10 of 10–49, 3 of
50+); level 3 → low; no IP → `skipped`. Companions on the same path: `5403` ×5 (first sudo, level 4),
`5407` ×4 (sudo by `otelcol-contrib`/`xrdp`/`gawa` → identity unknown), `5401` ×1 (failed, level 5),
`5404` ×1 (three failures, level 10). In G1 (DEC-086), 8 of the category's 66 low clusters are sampled —
statistically ~7 of them will be `5402`.

**What the playbook says.** :24 *a rule that catches every `sudo` unfiltered is configuration noise — fix
the rule*; :36 *identity already privileged → may just be normal activity*; :21 *admin, right procedure,
familiar host → FP*.

**What the code says.** A table cannot name a rule id. `5402`'s facts are (low, skipped, high|medium,
**"true"**, any). `identity_privileged is True` is G8′ block 5 (`ingest/autoclose.py:263`) and gate step
4 forbids `false_positive` on it (`security/gate.py:155`). So `5402` **cannot be auto-closed and cannot
be labelled `false_positive` by ① on this estate, whatever the table says**; the draft's `pre-5` makes
the resulting `needs_review` explicit.

**Options** (the sitting decides; none is mine):
- **A — accept** (draft). `pre-5` stays; `docs/limitations.md` gains one sentence: *successful `sudo` by
  the only human account is an un-auto-closable class because sudo alerts name the privileged target*.
  Cost: ~57 needs_review clusters per 30 days in the pilot queue (≈2/day).
- **B — identity from `srcuser` for sudo.** Change `wazuh_parser.py:180` to prefer `srcuser` when the
  decoder is `sudo` → identity `user1` → `"false"` on the 42 user1-invoked clusters (14 of them on
  `user1-IA1803`, medium → `pre-1` reachable; 28 on `IA1803` stay blocked by asset high); the 14 root-invoked
  clusters stay `"true"`. The lab's benign twin `sudo true` becomes FP-eligible. A code change with a DEC and
  a card; changes what "identity" means for one decoder; **not** a table change.
- **C — resolver: drop `sudo` group → `privilege_escalation`** (DEC-055's "named, not fixed" candidate).
  Moves `5402`/`5403`/`5407` **and** `5401`/`5404` to `unknown` — the lab's attack scenario relies on `5401`
  resolving here (runbook :361), so C breaks the G2 scenario. Not recommended.
- **D — lower `5402`'s level** in `local_rules.xml` (an `<overwrite>`): changes nothing for the table (it is
  already low) — irrelevant.
Lean: **A**, with **B** recorded as the follow-up if the pilot queue proves it worth a card.

☐ A  ☐ B  ☐ C  ☐ other: ______________________

## 12 · PROPOSAL — DEC-055 Q2: rootcheck `510` / `521` → `privilege_escalation`

**The numbers.** `521` "Possible kernel level rootkit" ×11 clusters (13 alerts), level 11 → high; `510`
"Host-based anomaly detection event (rootcheck)" ×10 (12 alerts), level 7 → medium. All 21 on `IA1803`
(asset high), identity unknown, `skipped`, occurrence 1–3. Also on the `rootcheck` path: `513` "Windows
malware detected" ×1 (level 9, `DESKTOP-MIRSO17`) — a *malware* rule reaching `privilege_escalation`.
Under the draft: `521` → `pre-4` escalate (11 of the 31 high), `510` → default needs_review.

**Fit.** The `privilege_escalation` playbook is about *a subject gaining more rights than it should* (:3);
rootcheck's rootkit/anomaly findings answer `malware.md`'s questions (:3 *has it run, has it spread*; :32
*persistence mechanism*). `malware` has a playbook, so re-homing is R5-compliant.

**Options:**
- **A — leave as is** (draft; DEC-055 said "neither is measurably wrong").
- **B — resolver: `rootcheck` group → `malware`.** 21 clusters move (+1 for `513`); `privilege_escalation`
  high drops 31 → 20; `malware` becomes a live G1 category with 22 clusters (11 high). **G1 is not drawn
  yet** (P6-T01 runs 25/09), so the move lands before sampling — but it **amends DEC-086's recorded
  composition** (40 = 0/31/1/8 → smaller) and needs a `MAPPING_VERSION` bump + `test_category.py` re-pin
  (DEC-055 precedent). A DEC, not a table edit.
Lean: **A** for this sitting; record B as a DEC-055 follow-up candidate with the numbers above.

☐ A  ☐ B  ☐ other: ______________________

## 13 · PROPOSAL — the four `Final-Project` categories dropped in P2-T03 (`tasks/P2/P2-T03.report.md:61-70`)

Measured on the fold: clusters whose head alert carries a signal that used to reach the category
(`scratchpad/dropped_cats.py`, reproduced in the report).

| dropped category | what the archive holds | today | proposal |
|---|---|---|---|
| `rdp_brute_force` | **0** clusters (no `win_authentication_failed`/`rdp` group, no port 3389) | — | **keep dropped** — nothing to classify; `HR-computer` (Windows, enrolled 14/09) may change this in the pilot |
| `phishing` | **0** clusters (no `T1566`) | — | **keep dropped** — no mail path on this estate |
| `persistence` | **25** clusters / 33 alerts: `5901` new group ×8 (level 8) · `5902` new user ×8 (level 8, T1136) · `5903` group/user deleted ×3 (level 3) · `5904` user info changed ×1 (level 8, T1098) · `100204` kernel module ×3 (level 12, archive-era local) · `100200` /etc/passwd edited ×1 (level 10, archive-era local) · `61138` new Windows service ×1 (level 5, T1543.003, `DESKTOP-MIRSO17`); **21 of 25 are crit+high** and are today inside `unknown`'s 94 crit+high (P6.md:17 names `adduser 5901/5902`) | `unknown` | **the only candidate worth the sitting's time.** R5 forbids a category without a playbook and a new playbook is not the Drafter's to write. Two routes: **(i) add `persistence`** — Owner + advisor write `kb/playbooks/persistence.md`, resolver adds `T1136/T1098/T1543/T1053` + groups `adduser/account_changed/persistence`, a table follows; recovers 21 crit+high from `unknown` (B1's escalate ceiling, P6.md:17). **(ii) map `adduser`/`account_changed` → `privilege_escalation`** — playbook :30 (*ordinary account suddenly in the admin group*) and :31 (*right after: a new account*) already describe it; cheapest, R5-compliant, but "new user added" is persistence, not escalation. Either route changes the pool before G1 is drawn (25/09) and amends DEC-086 |
| `suspicious_execution` | **44** clusters / 181 alerts, one rule: `92601` "Executed python script from /tmp/ folder", level 6 (medium), `T1059.006`, all on `IA1803` | `unknown` | **keep dropped** — one rule, one host (the manager), medium band, almost certainly the operator's own tooling; nothing in the escalate pool. If the sitting wants it seen, it is a `needs_review` family inside `unknown` already |

☐ persistence (i)  ☐ persistence (ii)  ☐ keep all four dropped  ☐ other: ______________________

## 14 · Two playbook lines P3-T12 owns (not this draft's)

- `kb/playbooks/ssh_brute_force.md:34` — `asset_context.criticality = crown_jewel` → DEC-004 retired
  `crown_jewel`; DEC-034 makes `high` the tier that inherited its role. `sbf-*` reads it as `asset high`.
- `kb/playbooks/malware.md:36` — same value, same reading (`mal-3`'s evidence line says so).
The tables cite the lines as they stand; when P3-T12 lands, the evidence text needs no change.

## 15 · Turning a signature into the file, and the test that proves it

Per table, after the sitting agrees its content (edit `then`/`if` first, then sign):

```bash
# one table — replace <category>, the names and the ISO date; the header comments are untouched
sed -i 's/^reviewed_by: null$/reviewed_by: "<Owner name> + <advisor name>"/; s/^reviewed_at: null$/reviewed_at: "2026-09-DD"/' kb/decision_tables/<category>.yaml

# prove it: the loader accepts the file, the grid is still consistent, and `reviewed` is True
python3 -c "import sys; sys.path.insert(0,'backend'); from app.kb.lookup import get_decision_table, check_consistency; t=get_decision_table('<category>'); print(t.reviewed_by, t.reviewed_at, t.reviewed, check_consistency(t))"
# → <names> 2026-09-DD True []
```

Two things the signature changes in the suite, neither of which this draft may touch (`backend/` is out
of scope):

1. `backend/tests/test_kb_lookup.py:418` `test_skeletons_are_unreviewed` asserts **all ten** are
   unreviewed — it goes red on the first signature **by design**. A Coder card must replace it with its
   inverse (`test_tables_are_reviewed`, or a per-table parametrisation) in the same commit as the
   signatures, or the suite is red between the two.
2. Nothing on `main` @ `6ffbecc` reads `DecisionTable.reviewed` yet; the consumer is the gate's
   `rule_check` (P3-T09/P3-T10), which answers "missing" and records
   `decision_table_unreviewed:<category>` while a table is unreviewed. Until it lands, signing changes
   what the *files* say and nothing at runtime.

Commit the ten signatures on `kb/decision-tables-draft` (or a branch cut from it), run
`python3 -m pytest -c backend/pyproject.toml backend/tests/test_kb_lookup.py -rs` and `make lint`, and hand
the Director the DEC that `docs/plan/prompts/kb-drafter-run-2026-09-19.md` §6 asks for (the
*"drafted by an agent … reviewed, amended and signed by the Owner and the advisor on <date>"* sentence for
`docs/limitations.md`).
